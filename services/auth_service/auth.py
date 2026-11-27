"""Authentication contract and JWT helpers; only Auth Service signs tokens."""
from datetime import datetime, timedelta, timezone
from typing import Annotated

import jwt
from pydantic import BaseModel, ConfigDict, SecretStr, StringConstraints, Field
from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

ISSUER = 'timebook-auth'
AUDIENCE = 'timebook-api'
ALGORITHM = 'RS256'


class Credentials(BaseModel):
    model_config = ConfigDict(extra='forbid')
    login: Annotated[str, StringConstraints(min_length=3, max_length=64, pattern=r'^[A-Za-z0-9_.-]+$')]
    password: Annotated[SecretStr, Field(min_length=8, max_length=128)]


class TokenResponse(BaseModel):
    user_id: int
    access_token: str
    token_type: str = 'bearer'
    expires_in: int


def issue_token(user_id: int, private_key, ttl: int) -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode({'sub': str(user_id), 'iss': ISSUER, 'aud': AUDIENCE,
                       'iat': now, 'exp': now + timedelta(seconds=ttl)},
                      private_key, algorithm=ALGORITHM)


def verify_token(token: str, public_key) -> int:
    claims = jwt.decode(token, public_key, algorithms=[ALGORITHM],
                        issuer=ISSUER, audience=AUDIENCE,
                        options={'require': ['sub', 'iss', 'aud', 'iat', 'exp']})
    sub = claims['sub']
    if not isinstance(sub, str) or not sub.isascii() or not sub.isdecimal() or len(sub) > 19:
        raise jwt.InvalidTokenError('Invalid subject')
    user_id = int(sub)
    if not 0 < user_id <= 2**63 - 1 or str(user_id) != sub:
        raise jwt.InvalidTokenError('Invalid subject')
    return user_id


async def safe_validation_error(request: Request, exc: RequestValidationError):
    # Default validation output may echo raw invalid credentials. Do not return input.
    return JSONResponse(status_code=422, content={'detail': [
        {'loc': list(e['loc']), 'type': e['type'], 'msg': 'Invalid field'}
        for e in exc.errors()]})
