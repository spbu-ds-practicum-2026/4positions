import datetime as dt
from uuid import uuid4
import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from main import create_app

@pytest.fixture(scope='module')
def key(): return rsa.generate_private_key(public_exponent=65537,key_size=2048)

def token(key, **overrides):
    now=dt.datetime.now(dt.timezone.utc)
    return jwt.encode({'sub':'7','iss':'timebook-auth','aud':'timebook-api','iat':now,'exp':now+dt.timedelta(minutes=30),**overrides},key,algorithm='RS256')

@pytest.fixture
def setup(key):
    seen=[]
    def handler(req):
        seen.append(req)
        if req.url.path.startswith('/auth'):
            import json
            data=json.loads(req.content)
            if data['login']=='taken': return httpx.Response(409,json={'detail':'login_taken'})
            return httpx.Response(201 if req.url.path.endswith('register') else 200,json={'user_id':7,'access_token':token(key),'token_type':'bearer','expires_in':1800})
        if req.url.path=='/booking': return httpx.Response(201,json={'booking_id':42})
        if req.url.path=='/booking/42/cancel': return httpx.Response(200,json={'status':'cancelled'})
        return httpx.Response(200,json={'partial':True,'items':[]})
    t=httpx.MockTransport(handler)
    with TestClient(create_app(key.public_key(),auth_url='http://auth',timebook_urls=['http://node1','http://node2'],transport=t,auth_transport=t)) as client:
        yield client,seen

@pytest.mark.parametrize('path,status',[('/api/auth/register',201),('/api/auth/login',200)])
def test_auth(setup,path,status):
    import json
    c,seen=setup; r=c.post(path,json={'login':'demo','password':'Password123'})
    assert r.status_code==status and r.json()['user_id']==7 and r.headers['Cache-Control']=='no-store'
    assert seen[-1].url.host=='auth' and json.loads(seen[-1].content)['password']=='Password123'

def test_auth_error(setup):
    c,_=setup; r=c.post('/auth/register',json={'login':'taken','password':'Password123'})
    assert r.status_code==409 and r.json()=={'detail':'login_taken'}

def test_validation(setup):
    c,seen=setup; r=c.post('/auth/login',json={'login':'demo','password':'abc'})
    assert r.status_code==422 and '8 символов' in r.text and 'abc' not in r.text and not seen

def headers(key):
    return {'Authorization': 'Bearer ' + token(key)}


def test_catalog_round_robin(setup, key):
    c, seen = setup
    for _ in range(3):
        assert c.get('/api/resources', headers=headers(key)).json()['partial'] is True
    assert [r.url.host for r in seen] == ['node1', 'node2', 'node1']
    assert all(r.url.path == '/resources' for r in seen)


@pytest.mark.parametrize('method,path', [('GET','/api/resources'), ('POST','/api/bookings'), ('POST','/api/bookings/42/cancel')])
def test_no_token(setup, method, path):
    c, seen = setup
    kwargs = {'json': {'resource_id': 7, 'request_id': 'example'}} if method == 'POST' else {}
    assert c.request(method, path, headers={'X-User-ID': '999'}, **kwargs).status_code == 401
    assert not seen


@pytest.mark.parametrize('claims',[{'sub':'0'},{'sub':'abc'},{'iss':'other'},{'aud':'other'},{'exp':1}])
def test_invalid_token(setup,key,claims):
    c,seen=setup; assert c.get('/api/resources',headers={'Authorization':'Bearer '+token(key,**claims)}).status_code==401 and not seen


def test_wrong_signature(setup):
    c,seen=setup; other=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    assert c.get('/api/resources',headers={'Authorization':'Bearer '+token(other)}).status_code==401 and not seen


def test_book_cancel(setup,key):
    import json
    c,seen=setup; h={**headers(key), 'X-User-ID':'999'}
    body={'resource_id':7,'request_id':'opaque-request-001'}
    assert c.post('/api/bookings',headers=h,json=body).status_code==201
    assert seen[-1].url.path == '/booking'
    assert json.loads(seen[-1].content)=={'res_id':7,'usr_id':7,'request_id':body['request_id']}
    assert seen[-1].headers['X-User-ID']=='7' and 'Authorization' not in seen[-1].headers
    cancel={'resource_id':7,'request_id':str(uuid4())}
    assert c.post('/api/bookings/42/cancel',headers=h,json=cancel).status_code==200
    assert seen[-1].url.path == '/booking/42/cancel'
    assert json.loads(seen[-1].content)==cancel and seen[-1].headers['X-User-ID']=='7'


@pytest.mark.parametrize('body',[{'resource_id':7}, {'resource_id':0,'request_id':'a'}, {'resource_id':7,'request_id':' '}, {'resource_id':7,'request_id':'a','usr_id':999}, {'resource_id':7,'request_id':'a','user_id':999}])
def test_booking_validation(setup,key,body):
    c,seen=setup
    assert c.post('/api/bookings',headers=headers(key),json=body).status_code==422 and not seen


def test_removed_routes(setup,key):
    c,seen=setup
    for path in ['/bookings/history','/api/bookings/history','/coaches','/api/resources/7/schedule']:
        assert c.get(path,headers=headers(key)).status_code==404
    assert not seen


def test_short_aliases(setup,key):
    c,seen=setup
    assert c.get('/resources',headers=headers(key)).status_code==200
    assert c.post('/booking',headers=headers(key),json={'resource_id':7,'request_id':'x'}).status_code==201
    assert c.post('/booking/42/cancel',headers=headers(key),json={'resource_id':7,'request_id':'y'}).status_code==200


def test_pending_response(key):
    t=httpx.MockTransport(lambda req: httpx.Response(202,json={'status':'processing'},headers={'Retry-After':'2'}))
    with TestClient(create_app(key.public_key(),timebook_urls=['http://node'],transport=t)) as c:
        r=c.post('/api/bookings',headers=headers(key),json={'resource_id':7,'request_id':'same'})
        assert r.status_code==202 and r.json()=={'status':'processing'} and r.headers['Retry-After']=='2'

def test_network_failure(key):
    seen=[]
    def fail(req):
        seen.append(req); raise httpx.ReadTimeout('test',request=req)
    t=httpx.MockTransport(fail)
    with TestClient(create_app(key.public_key(),timebook_urls=['http://node1','http://node2'],transport=t,auth_transport=t)) as c:
        assert c.get('/api/resources',headers=headers(key)).status_code==503
        r=c.post('/api/bookings',headers=headers(key),json={'resource_id':7,'request_id':str(uuid4())})
        assert r.status_code==503 and r.json()['result']=='unknown' and r.json()['retry_with_same_request_id'] is True
        assert len(seen)==2  # нет скрытых повторов
        assert c.post('/auth/login',json={'login':'demo','password':'Password123'}).json()['detail']=='auth_service_unavailable'


def test_catalog_preserves_slot_intervals(key):
    from mock_timebook import app as mock_app
    with TestClient(mock_app) as mock:
        catalog = mock.get('/resources').json()
    assert catalog['items'] == [
        {'res_id': 7, 'date': '2026-12-01', 'time': '10:00-11:00'},
        {'res_id': 8, 'date': '2026-12-01', 'time': '11:00-12:00'},
    ]
    transport = httpx.MockTransport(lambda req: httpx.Response(200, json=catalog))
    with TestClient(create_app(key.public_key(), timebook_urls=['http://node'], transport=transport)) as c:
        result = c.get('/api/resources', headers=headers(key))
        assert result.status_code == 200
        assert result.json() == catalog
