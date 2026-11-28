"""Контракт запросов, проверка JWT и безопасная валидация."""
from typing import Annotated
import jwt
from pydantic import (BaseModel, ConfigDict, Field,
                      SecretStr, StringConstraints)
from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

class Credentials(BaseModel):
    model_config = ConfigDict(extra='forbid')
    login: Annotated[str, StringConstraints(min_length=3, max_length=64, pattern=r'^[A-Za-z0-9_.-]+$')]
    password: Annotated[SecretStr, Field(min_length=8, max_length=128)]

class TokenResponse(BaseModel):
    user_id: int
    access_token: str
    token_type: str = 'bearer'
    expires_in: int

class Operation(BaseModel):
    model_config = ConfigDict(extra='forbid')
    resource_id: Annotated[int, Field(strict=True, gt=0, le=2**63 - 1)]
    request_id: Annotated[str, StringConstraints(min_length=1, max_length=128, pattern=r'\S')]

class CreateBooking(Operation):
    pass

class CancelBooking(Operation):
    pass

def verify_token(token, public_key):
    claims = jwt.decode(token, public_key, algorithms=['RS256'],
                        issuer='timebook-auth', audience='timebook-api',
                        options={'require': ['sub', 'iss', 'aud', 'iat', 'exp']})
    sub = claims['sub']
    if not isinstance(sub, str) or not sub.isascii() or not sub.isdecimal() or len(sub) > 19:
        raise jwt.InvalidTokenError('Invalid subject')
    user_id = int(sub)
    if not 0 < user_id <= 2**63 - 1 or str(user_id) != sub:
        raise jwt.InvalidTokenError('Invalid subject')
    return user_id

def validation_message(field, kind):
    if kind == 'json_invalid': return 'Некорректный формат JSON.'
    if kind == 'extra_forbidden': return 'В запросе присутствует лишнее поле.'
    if field == 'password':
        kind = {'string_too_short':'too_short','string_too_long':'too_long'}.get(kind, kind)
    messages = {
        ('login','missing'):'Введите логин.',
        ('login','string_too_short'):'Логин должен содержать не менее 3 символов.',
        ('login','string_too_long'):'Логин должен содержать не более 64 символов.',
        ('login','string_pattern_mismatch'):'Логин может содержать только латинские буквы, цифры, точку, дефис и нижнее подчёркивание.',
        ('login','string_type'):'Логин должен быть строкой.',
        ('password','missing'):'Введите пароль.',
        ('password','too_short'):'Пароль должен содержать не менее 8 символов.',
        ('password','too_long'):'Пароль должен содержать не более 128 символов.',
        ('password','string_type'):'Пароль должен быть строкой.',
    }
    if (field, kind) in messages: return messages[field, kind]
    if field in ('resource_id','res_id','booking_id'): return f'{field}: укажите положительное целое число.'
    if field == 'request_id': return 'Укажите непустой request_id длиной до 128 символов.'
    return 'Некорректное значение поля.'

async def safe_validation_error(request: Request, exc: RequestValidationError):
    errors = []
    for err in exc.errors():
        loc = err['loc']
        source = loc[0] if loc and loc[0] in ('body','path','query') else 'body'
        field = loc[1] if len(loc)>1 and loc[1] in ('login','password','resource_id','res_id','booking_id','request_id') else 'body'
        errors.append({'loc':[source,field] if field != 'body' else [source],
                       'type':err['type'],'msg':validation_message(field,err['type'])})
    return JSONResponse(status_code=422, content={'detail':errors}, headers={'Cache-Control':'no-store'})
