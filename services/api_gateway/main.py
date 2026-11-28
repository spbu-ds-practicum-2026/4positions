"""Самостоятельный API Gateway TimeBook. Запуск: python main.py."""
import os
from contextlib import asynccontextmanager, AsyncExitStack
from itertools import cycle
from pathlib import Path
from typing import Annotated

import httpx
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Path as ApiPath, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

if __package__:
    from .models import Credentials, TokenResponse, CreateBooking, CancelBooking, verify_token, safe_validation_error
else:
    from models import Credentials, TokenResponse, CreateBooking, CancelBooking, verify_token, safe_validation_error

ROOT = Path(__file__).resolve().parent
PositiveID = Annotated[int, ApiPath(gt=0, le=2**63 - 1)]

def create_app(public_key=None, auth_url=None, timebook_urls=None, transport=None, auth_transport=None):
    load_dotenv(ROOT / '.env')
    if public_key is None:
        path = ROOT / os.getenv('JWT_PUBLIC_KEY_FILE', '../auth_service/keys/public.pem')
        public_key = serialization.load_pem_public_key(path.read_bytes())
    if not isinstance(public_key, rsa.RSAPublicKey) or public_key.key_size < 2048:
        raise ValueError('Нужен публичный RSA-ключ размером не менее 2048 бит.')
    auth_url = auth_url if auth_url is not None else os.getenv('AUTH_URL','http://127.0.0.1:8002')
    urls = list(timebook_urls) if timebook_urls is not None else os.getenv('TIMEBOOK_URLS','http://127.0.0.1:8001').split(',')
    urls = [url.strip().rstrip('/') for url in urls if url.strip()]
    if not urls: raise ValueError('Укажите хотя бы один адрес TIMEBOOK_URLS.')
    for address in [auth_url, *urls]:
        url = httpx.URL(address)
        if url.scheme not in ('http','https') or not url.host or url.path not in ('','/') or url.query or url.fragment or url.username or url.password:
            raise ValueError('Адрес сервиса должен иметь вид http://host:port.')
    # Тайм-ауты по этапам HTTP, не общий дедлайн операции.
    @asynccontextmanager
    async def lifespan(app):
        async with AsyncExitStack() as stack:
            app.state.auth = await stack.enter_async_context(httpx.AsyncClient(
                base_url=auth_url, timeout=10, transport=auth_transport, trust_env=False, follow_redirects=False))
            clients = [await stack.enter_async_context(httpx.AsyncClient(
                base_url=url, timeout=10, transport=transport, trust_env=False, follow_redirects=False)) for url in urls]
            app.state.nodes = cycle(clients)
            yield

    app = FastAPI(title='TimeBook API Gateway', lifespan=lifespan)
    app.add_exception_handler(RequestValidationError, safe_validation_error)
    bearer = HTTPBearer(auto_error=False)

    def current_user(credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)]) -> int:
        if credentials is None:
            raise HTTPException(401, detail='missing_token', headers={'WWW-Authenticate':'Bearer'})
        try:
            return verify_token(credentials.credentials, public_key)
        except jwt.InvalidTokenError:
            raise HTTPException(401, detail='invalid_token', headers={'WWW-Authenticate':'Bearer'}) from None

    UserID = Annotated[int, Depends(current_user)]

    async def forward(request, path, *, method='GET', body=None, params=None, user_id=None, auth=False):
        client = request.app.state.auth if auth else next(request.app.state.nodes)
        headers = {'Accept':'application/json'}
        if user_id is not None:
            headers['X-User-ID'] = str(user_id)
        # Не копируем входящие Authorization, X-User-ID и другие заголовки клиента.
        try:
            upstream = await client.request(method, path, json=body, params=params, headers=headers)
        except httpx.RequestError:
            if auth:
                data = {'detail':'auth_service_unavailable'}
            else:
                data = {'code':'timebook_unavailable'}
                if method != 'GET':
                    data.update(result='unknown', retry_with_same_request_id=True)
            return JSONResponse(status_code=503, content=data, headers={'Cache-Control':'no-store'})
        response_headers = {name: upstream.headers[name] for name in ('content-type','retry-after','www-authenticate') if name in upstream.headers}
        response_headers['Cache-Control'] = 'no-store'
        return Response(content=upstream.content, status_code=upstream.status_code, headers=response_headers)

    @app.get('/health')
    async def health():
        return {'status':'ok','service':'api-gateway'}

    @app.post('/auth/register', status_code=201, response_model=TokenResponse, include_in_schema=False)
    @app.post('/api/auth/register', status_code=201, response_model=TokenResponse)
    async def register(request: Request, body: Credentials):
        return await forward(request, '/auth/register', method='POST', auth=True,
                             body={'login':body.login,'password':body.password.get_secret_value()})

    @app.post('/auth/login', response_model=TokenResponse, include_in_schema=False)
    @app.post('/api/auth/login', response_model=TokenResponse)
    async def login(request: Request, body: Credentials):
        return await forward(request, '/auth/login', method='POST', auth=True,
                             body={'login':body.login,'password':body.password.get_secret_value()})

    @app.get('/resources', include_in_schema=False)
    @app.get('/api/resources')
    async def resources(request: Request, user_id: UserID):
        return await forward(request, '/resources', user_id=user_id)

    @app.post('/booking', status_code=201, include_in_schema=False)
    @app.post('/api/bookings', status_code=201)
    async def book(request: Request, body: CreateBooking, user_id: UserID):
        # usr_id comes exclusively from a verified JWT, never from client JSON.
        return await forward(request, '/booking', method='POST', user_id=user_id,
                             body={'res_id': body.resource_id, 'usr_id': user_id,
                                   'request_id': body.request_id})

    @app.post('/booking/{booking_id}/cancel', include_in_schema=False)
    @app.post('/api/bookings/{booking_id}/cancel')
    async def cancel(request: Request, booking_id: PositiveID, body: CancelBooking, user_id: UserID):
        return await forward(request, f'/booking/{booking_id}/cancel', method='POST', user_id=user_id,
                             body=body.model_dump(mode='json'))
    return app

if __name__ == '__main__':
    import uvicorn
    try:
        app = create_app()
    except (OSError, ValueError) as exc:
        raise SystemExit('Не удалось настроить Gateway. Проверь публичный ключ Auth Service и адреса в .env.') from None
    uvicorn.run(app, host='127.0.0.1', port=8000)
