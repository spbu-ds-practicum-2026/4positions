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


def validation_message(field, error_type):
    """Понятные сообщения без исходных данных пользователя."""
    messages = {
        ('login', 'missing'): 'Введите логин.',
        ('login', 'string_too_short'): 'Логин должен содержать не менее 3 символов.',
        ('login', 'string_too_long'): 'Логин должен содержать не более 64 символов.',
        ('login', 'string_pattern_mismatch'): 'Логин может содержать только латинские буквы, цифры, точку, дефис и нижнее подчёркивание.',
        ('login', 'string_type'): 'Логин должен быть строкой.',
        ('password', 'missing'): 'Введите пароль.',
        ('password', 'too_short'): 'Пароль должен содержать не менее 8 символов.',
        ('password', 'too_long'): 'Пароль должен содержать не более 128 символов.',
        ('password', 'string_type'): 'Пароль должен быть строкой.',
    }
    # В разных версиях Pydantic строковые ограничения могут иметь разные коды.
    if field == 'password':
        error_type = {'string_too_short': 'too_short', 'string_too_long': 'too_long'}.get(error_type, error_type)
    if error_type == 'json_invalid':
        return 'Некорректный формат JSON.'
    if error_type == 'extra_forbidden':
        return 'В запросе присутствует лишнее поле.'
    if field == 'body':
        return 'Передайте логин и пароль в теле JSON-запроса.'
    return messages.get((field, error_type), 'Некорректное значение поля.')


async def safe_validation_error(request: Request, exc: RequestValidationError):
    errors = []
    for error in exc.errors():
        loc = error['loc']
        error_type = error['type']
        field = loc[1] if len(loc) > 1 and loc[0] == 'body' and loc[1] in ('login', 'password') else 'body'
        # Не возвращаем input, ctx, исходный msg и произвольные имена полей:
        # в них могут оказаться пароли или другие пользовательские данные.
        errors.append({
            'loc': ['body', field] if field != 'body' else ['body'],
            'type': error_type,
            'msg': validation_message(field, error_type),
        })
    return JSONResponse(status_code=422, content={'detail': errors})
