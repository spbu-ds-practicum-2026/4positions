import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from threading import Lock

import jwt
import pytest
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

import main as auth_module
from main import create_app as auth_app
from database import PostgresUsers, DatabaseUnavailable
from auth import ISSUER, AUDIENCE, issue_token, verify_token

CREDS = {'login': 'test_user', 'password': 'test-password-123'}


class MemoryUsers:
    def __init__(self):
        self.rows = {}
        self.lock = Lock()

    def create(self, login, password_hash):
        with self.lock:
            if login in self.rows:
                return None
            user_id = len(self.rows) + 1
            self.rows[login] = (user_id, password_hash)
            return user_id

    def find(self, login):
        return self.rows.get(login)


@pytest.fixture(scope='module')
def key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def auth(key):
    repo = MemoryUsers()
    with TestClient(auth_app(repo, key)) as client:
        yield client, repo


def test_register_and_login(auth, key):
    client, repo = auth
    registered = client.post('/auth/register', json=CREDS)
    assert registered.status_code == 201
    data = registered.json()
    assert verify_token(data['access_token'], key.public_key()) == data['user_id'] == 1
    stored = repo.rows[CREDS['login']][1]
    assert stored.startswith('$argon2id$') and stored != CREDS['password']
    assert PasswordHasher().verify(stored, CREDS['password'])
    login = client.post('/auth/login', json=CREDS)
    assert login.status_code == 200 and verify_token(login.json()['access_token'], key.public_key()) == 1


def test_duplicate(auth):
    client, _ = auth
    assert client.post('/auth/register', json=CREDS).status_code == 201
    assert client.post('/auth/register', json=CREDS).status_code == 409


@pytest.mark.parametrize('change', [{'password': 'wrong-password'}, {'login': 'unknown'}])
def test_invalid_credentials(auth, change):
    client, _ = auth
    client.post('/auth/register', json=CREDS)
    r = client.post('/auth/login', json={**CREDS, **change})
    assert r.status_code == 401 and r.json()['detail'] == 'invalid_credentials'


def test_invalid_input(auth):
    client, _ = auth
    r = client.post('/auth/register', json={'login': 'bad login', 'password': 'secret'})
    assert r.status_code == 422 and 'secret' not in r.text


def test_db_unavailable(key):
    class Broken(MemoryUsers):
        def find(self, login):
            raise DatabaseUnavailable()
    with TestClient(auth_app(Broken(), key)) as client:
        assert client.post('/auth/login', json=CREDS).status_code == 503


@pytest.mark.parametrize('mode', ['expired','wrong_issuer','wrong_audience','wrong_key','bad_sub','missing_exp','wrong_algorithm','tampered'])
def test_reject_tokens(key, mode):
    now = datetime.now(timezone.utc)
    claims = {'sub': '1', 'iss': ISSUER, 'aud': AUDIENCE, 'iat': now, 'exp': now + timedelta(minutes=5)}
    signing_key, alg = key, 'RS256'
    if mode == 'expired': claims.update(iat=now-timedelta(minutes=2), exp=now-timedelta(minutes=1))
    if mode == 'wrong_issuer': claims['iss'] = 'other'
    if mode == 'wrong_audience': claims['aud'] = 'other'
    if mode == 'wrong_key': signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    if mode == 'bad_sub': claims['sub'] = '-1'
    if mode == 'missing_exp': claims.pop('exp')
    if mode == 'wrong_algorithm': signing_key, alg = 'x'*32, 'HS256'
    token = jwt.encode(claims, signing_key, algorithm=alg)
    if mode == 'tampered':
        import base64, json
        head, _, sig = token.split('.')
        claims['sub'] = '999'
        payload = base64.urlsafe_b64encode(json.dumps(claims, default=str).encode()).decode().rstrip('=')
        token = f'{head}.{payload}.{sig}'
    with pytest.raises(jwt.InvalidTokenError):
        verify_token(token, key.public_key())


def test_issue_and_verify_token(key):
    token = issue_token(7, key, 1800)
    assert verify_token(token, key.public_key()) == 7


def test_health(auth):
    client, _ = auth
    response = client.get('/health')
    assert response.status_code == 200
    assert response.json() == {'status': 'ok', 'service': 'auth'}


def test_token_response_no_cache(auth):
    client, _ = auth
    assert client.post('/auth/register', json=CREDS).headers['Cache-Control'] == 'no-store'
    assert client.post('/auth/login', json=CREDS).headers['Cache-Control'] == 'no-store'


@pytest.mark.skipif(not os.getenv('TEST_AUTH_DATABASE_URL'), reason='Requires a real dedicated PostgreSQL database')
def test_postgres_concurrent_registration(key):
    from uuid import uuid4
    repo = PostgresUsers(os.environ['TEST_AUTH_DATABASE_URL'])
    repo.initialize()
    credentials = {**CREDS, 'login': 'test_' + uuid4().hex}
    try:
        with TestClient(auth_app(repo, key)) as client:
            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(lambda _: client.post('/auth/register', json=credentials), range(2)))
            assert sorted(r.status_code for r in results) == [201, 409]
            row = repo.find(credentials['login'])
            assert row and PasswordHasher().verify(row[1], credentials['password'])
            assert client.post('/auth/login', json=credentials).status_code == 200
    finally:
        repo._query('DELETE FROM users WHERE login = %s', (credentials['login'],), fetch=False)


def test_startup_initializes_database(monkeypatch, key):
    calls = []

    class FakePostgres(MemoryUsers):
        def __init__(self, dsn):
            super().__init__()
            calls.append(dsn)

        def initialize(self):
            calls.append('initialize')

    monkeypatch.setenv('AUTH_DATABASE_URL', 'test-dsn')
    monkeypatch.setattr(auth_module, 'PostgresUsers', FakePostgres)
    with TestClient(auth_app(private_key=key, ttl=1800)) as client:
        assert client.get('/health').status_code == 200
    assert calls == ['test-dsn', 'initialize']


def test_initialize_contains_safe_schema(monkeypatch):
    repo = PostgresUsers('test-dsn')
    calls = []
    monkeypatch.setattr(repo, '_query', lambda sql, fetch: calls.append((sql, fetch)))
    repo.initialize()
    sql, fetch = calls[0]
    assert 'CREATE TABLE IF NOT EXISTS users' in sql
    assert 'NOT NULL UNIQUE' in sql
    assert 'DROP' not in sql.upper()
    assert fetch is False


@pytest.mark.parametrize('body, message', [
    ({'login': 'Makar', 'password': 'short'}, 'Пароль должен содержать не менее 8 символов.'),
    ({'login': 'Makar', 'password': 'x' * 129}, 'Пароль должен содержать не более 128 символов.'),
    ({'login': 'a', 'password': 'valid1234'}, 'Логин должен содержать не менее 3 символов.'),
    ({'login': 'x' * 65, 'password': 'valid1234'}, 'Логин должен содержать не более 64 символов.'),
    ({'login': 'bad login', 'password': 'valid1234'}, 'Логин может содержать только латинские буквы'),
    ({'login': 'Makar'}, 'Введите пароль.'),
    ({'password': 'valid1234'}, 'Введите логин.'),
    ({'login': 'Makar', 'password': 12345}, 'Пароль должен быть строкой.'),
    ({'login': 'Makar', 'password': 'valid1234', 'secret-extra': 'secret-value'}, 'В запросе присутствует лишнее поле.'),
])
def test_readable_validation(auth, body, message):
    client, repo = auth
    for path in ('/auth/register', '/auth/login'):
        r = client.post(path, json=body)
        assert r.status_code == 422
        assert any(message in error['msg'] for error in r.json()['detail'])
        assert all(set(error) == {'loc', 'type', 'msg'} for error in r.json()['detail'])
        assert 'secret-extra' not in r.text and 'secret-value' not in r.text
        assert not repo.rows


def test_readable_console(auth, capsys):
    from test import request
    client, _ = auth
    r = request(client, 'POST', '/auth/register', {'login': 'Makar', 'password': 'short'})
    out = capsys.readouterr().out
    assert r.status_code == 422
    assert 'Пароль должен содержать не менее 8 символов.' in out
    assert 'short' not in out and '"detail"' not in out
    request(client, 'POST', '/auth/login', CREDS)
    assert 'Неверный логин или пароль.' in capsys.readouterr().out


def test_readable_invalid_json(auth):
    client, _ = auth
    r = client.post('/auth/register', content='{"password":', headers={'Content-Type': 'application/json'})
    assert r.status_code == 422
    assert r.json()['detail'][0]['msg'] == 'Некорректный формат JSON.'
