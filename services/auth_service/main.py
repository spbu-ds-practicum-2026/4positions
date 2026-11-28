import os
from pathlib import Path
from dotenv import load_dotenv

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

if __package__:
    from .auth import Credentials, TokenResponse, issue_token, safe_validation_error
    from .database import PostgresUsers, DatabaseUnavailable
else:
    from auth import Credentials, TokenResponse, issue_token, safe_validation_error
    from database import PostgresUsers, DatabaseUnavailable


ROOT = Path(__file__).resolve().parent


def load_config():
    load_dotenv(ROOT / '.env')


def key_path(variable: str, default: str) -> Path:
    path = Path(os.getenv(variable, default))
    return path if path.is_absolute() else ROOT / path

def create_app(repository=None, private_key=None, ttl=None):
    load_config()
    # При обычном запуске создаём таблицу, если её ещё нет.
    # В тестах можно передать собственное хранилище без PostgreSQL.
    initialize_db = repository is None
    if initialize_db:
        repository = PostgresUsers(os.environ['AUTH_DATABASE_URL'])
    if private_key is None:
        private_key = serialization.load_pem_private_key(
            key_path('JWT_PRIVATE_KEY_FILE', 'keys/private.pem').read_bytes(), password=None)
    if not isinstance(private_key, rsa.RSAPrivateKey) or private_key.key_size < 2048:
        raise ValueError('RSA private key of at least 2048 bits required')
    ttl = int(os.getenv('JWT_TTL_SECONDS', '1800')) if ttl is None else ttl
    if not 1 <= ttl <= 86400:
        raise ValueError('JWT_TTL_SECONDS must be between 1 and 86400')

    if initialize_db:
        repository.initialize()

    hasher = PasswordHasher()  # Argon2id with library defaults and random salt
    dummy_hash = hasher.hash('dummy-password-not-a-real-account')
    app = FastAPI(title='TimeBook Auth Service', version='0.1.0')
    app.add_exception_handler(RequestValidationError, safe_validation_error)

    @app.exception_handler(DatabaseUnavailable)
    async def unavailable(request: Request, exc: DatabaseUnavailable):
        return JSONResponse(status_code=503, content={'detail': 'auth_db_unavailable'})

    def token(user_id):
        return TokenResponse(user_id=user_id, access_token=issue_token(user_id, private_key, ttl), expires_in=ttl)

    @app.get('/health')
    def health():
        return {'status': 'ok', 'service': 'auth'}  # liveness, not database readiness

    @app.post('/auth/register', status_code=201, response_model=TokenResponse)
    def register(body: Credentials, response: Response):
        response.headers['Cache-Control'] = 'no-store'
        password_hash = hasher.hash(body.password.get_secret_value())
        user_id = repository.create(body.login, password_hash)
        if user_id is None:
            raise HTTPException(409, detail='login_taken')
        return token(user_id)

    @app.post('/auth/login', response_model=TokenResponse)
    def login(body: Credentials, response: Response):
        response.headers['Cache-Control'] = 'no-store'
        row = repository.find(body.login)
        stored_hash = row[1] if row else dummy_hash
        try:
            valid = hasher.verify(stored_hash, body.password.get_secret_value())
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            valid = False
        if row is None or not valid:
            raise HTTPException(401, detail='invalid_credentials', headers={'WWW-Authenticate': 'Bearer'})
        return token(row[0])

    return app


if __name__ == '__main__':
    import uvicorn
    try:
        app = create_app()
    except DatabaseUnavailable:
        raise SystemExit('Не удалось инициализировать БД. Проверь PostgreSQL, AUTH_DATABASE_URL и права auth_user.') from None
    except KeyError:
        raise SystemExit('Укажи AUTH_DATABASE_URL в файле .env.') from None
    except FileNotFoundError:
        raise SystemExit('Приватный ключ не найден. Запусти python generate_keys.py или проверь путь в .env.') from None
    uvicorn.run(app, host='127.0.0.1', port=8002)
