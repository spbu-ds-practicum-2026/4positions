"""Консольная демонстрация TimeBook Auth Service. Запуск: python test.py"""

import argparse
import base64
import json
from concurrent.futures import ThreadPoolExecutor
from getpass import getpass
from pathlib import Path
from uuid import uuid4

import httpx
import jwt
if __package__:
    from .auth import verify_token, validation_message
    from .main import load_config, key_path
else:
    from auth import verify_token, validation_message
    from main import load_config, key_path


LINE = '─' * 64


def heading(title):
    print(f'\n{LINE}\n  {title}\n{LINE}')


def credentials():
    return {'login': input('Логин: '), 'password': getpass('Пароль: ')}


def show_error(status, data):
    """Выводит понятную ошибку вместо технического JSON."""
    detail = data.get('detail') if isinstance(data, dict) else None
    if status == 422 and isinstance(detail, list):
        print('Проверьте введённые данные:')
        for error in detail:
            if not isinstance(error, dict):
                continue
            loc = error.get('loc', [])
            field = loc[-1] if isinstance(loc, list) and loc and loc[-1] in ('login', 'password') else 'body'
            error_type = error.get('type')
            if not isinstance(error_type, str):
                error_type = ''
            # Не печатаем произвольные данные сервера. Это работает и со старым API.
            print('  - ' + validation_message(field, error_type))
        return

    messages = {
        'login_taken': 'Этот логин уже занят. Выберите другой или войдите в аккаунт.',
        'invalid_credentials': 'Неверный логин или пароль.',
        'auth_db_unavailable': 'База данных временно недоступна. Попробуйте позже.',
    }
    fallback = {
        400: 'Некорректный запрос.',
        401: 'Не удалось подтвердить учётные данные.',
        403: 'Доступ запрещён.',
        404: 'Запрашиваемый адрес не найден.',
        409: 'Конфликт данных.',
        422: 'Проверьте введённые данные.',
        429: 'Слишком много запросов. Попробуйте позже.',
        503: 'Сервис временно недоступен. Попробуйте позже.',
    }
    default = 'Внутренняя ошибка сервера. Попробуйте позже.' if status >= 500 else 'Не удалось выполнить операцию.'
    print('Ошибка: ' + messages.get(detail if isinstance(detail, str) else '', fallback.get(status, default)))


def request(client, method, path, body=None, show=True):
    """Отправляет настоящий HTTP-запрос и показывает ответ без полного JWT."""
    if show:
        print(f'\n>>> {method} {str(client.base_url).rstrip("/")}/{path.lstrip("/")}')
        if body is not None:
            print(json.dumps({**body, 'password': '********'}, ensure_ascii=False))
    response = client.request(method, path, json=body) if body is not None else client.request(method, path)
    if show:
        print(f'<<< HTTP {response.status_code} {response.reason_phrase}')
        try:
            data = response.json()
        except ValueError:
            if response.is_error:
                show_error(response.status_code, None)
            else:
                print('[Ответ не в формате JSON]')
        else:
            if response.is_error:
                show_error(response.status_code, data)
                return response
            if isinstance(data, dict) and 'access_token' in data:
                data = {**data, 'access_token': str(data['access_token'])[:30] + '... [скрыт]'}
            print(json.dumps(data, ensure_ascii=False, indent=2))
    return response


def checked_token(response, key):
    """Проверяет подпись и claims с помощью функции из нашего проекта."""
    data = response.json()
    user_id = verify_token(data['access_token'], key)
    if type(data['user_id']) is not int or user_id != data['user_id']:
        raise ValueError('user_id в ответе и JWT не совпадают')
    if data['token_type'] != 'bearer' or type(data['expires_in']) is not int or data['expires_in'] <= 0:
        raise ValueError('Некорректный формат ответа с токеном')
    return user_id, data['access_token']


def tamper_token(token):
    """Меняет sub, сохраняя исходную подпись: такой JWT должен быть отвергнут."""
    header, payload, signature = token.split('.')
    claims = json.loads(base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4)))
    claims['sub'] = '999999' if claims['sub'] != '999999' else '999998'
    changed = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip('=')
    return f'{header}.{changed}.{signature}'


def rejects_tampered(token, key):
    verify_token(token, key)  # Сначала убеждаемся, что исходный токен действителен.
    try:
        verify_token(tamper_token(token), key)
    except jwt.InvalidSignatureError:
        return True
    return False


def run_suite(client, key):
    """Повторяемый сценарий с уникальными логинами; не трогает чужие записи."""
    heading('АВТОМАТИЧЕСКАЯ ПРОВЕРКА AUTH SERVICE')
    print('Будут созданы два тестовых пользователя. Записи останутся в БД.')
    creds = {'login': 'demo_' + uuid4().hex, 'password': 'DemoPass_' + uuid4().hex}
    race_creds = {**creds, 'login': 'race_' + uuid4().hex}
    print('Тестовый логин:', creds['login'])
    results = []
    state = {}

    def check(name, action):
        try:
            passed, detail = action()
        except Exception as exc:
            passed, detail = False, f'{type(exc).__name__}'
        results.append(passed)
        print(f'[{"OK" if passed else "FAIL"}] {name} — {detail}')

    def expect(method, path, status, body=None, detail=None):
        r = request(client, method, path, body, show=False)
        ok = r.status_code == status
        if detail is not None:
            ok = ok and r.json().get('detail') == detail
        return ok, f'HTTP {r.status_code} (ожидался {status})'

    def health():
        r = request(client, 'GET', '/health', show=False)
        return r.status_code == 200 and r.json() == {'status': 'ok', 'service': 'auth'}, f'HTTP {r.status_code}'

    def register():
        r = request(client, 'POST', '/auth/register', creds, show=False)
        if r.status_code != 201:
            return False, f'HTTP {r.status_code}, ожидался 201'
        state['registered'] = r
        return True, 'HTTP 201'

    def signature():
        if 'registered' not in state:
            return False, 'нет результата регистрации'
        state['uid'], state['token'] = checked_token(state['registered'], key)
        return True, f'RS256, user_id={state["uid"]}'

    def login():
        r = request(client, 'POST', '/auth/login', creds, show=False)
        if r.status_code != 200:
            return False, f'HTTP {r.status_code}, ожидался 200'
        uid, _ = checked_token(r, key)
        return uid == state.get('uid'), f'HTTP 200, user_id={uid}'

    def tampered():
        if 'token' not in state:
            return False, 'нет проверенного JWT'
        return rejects_tampered(state['token'], key), 'проверка изменённого sub'

    def concurrency():
        def send(_):
            return request(client, 'POST', '/auth/register', race_creds, show=False)
        with ThreadPoolExecutor(max_workers=2) as pool:
            replies = list(pool.map(send, range(2)))
        statuses = sorted(r.status_code for r in replies)
        ok = statuses == [201, 409]
        if ok:
            created = next(r for r in replies if r.status_code == 201)
            rejected = next(r for r in replies if r.status_code == 409)
            uid, _ = checked_token(created, key)
            r = request(client, 'POST', '/auth/login', race_creds, show=False)
            ok = (rejected.json().get('detail') == 'login_taken' and r.status_code == 200
                  and checked_token(r, key)[0] == uid)
        return ok, f'HTTP {statuses}, ожидались [201, 409] и успешный вход'

    check('Доступность сервиса', health)
    check('Регистрация', register)
    check('Подпись JWT и идентификатор', signature)
    check('Повторная регистрация', lambda: expect('POST', '/auth/register', 409, creds, 'login_taken'))
    check('Правильный пароль', login)
    check('Неверный пароль', lambda: expect('POST', '/auth/login', 401, {**creds, 'password': 'WrongPassword123'}, 'invalid_credentials'))
    check('Неизвестный логин', lambda: expect('POST', '/auth/login', 401, {**creds, 'login': 'missing_' + uuid4().hex}, 'invalid_credentials'))
    check('Некорректные данные', lambda: expect('POST', '/auth/register', 422, {'login': 'bad login', 'password': 'short'}))
    check('Защита от подделки JWT', tampered)
    check('Две конкурентные регистрации', concurrency)
    print(LINE)
    print(f'ИТОГ: {sum(results)} / {len(results)} успешно; ошибок: {len(results) - sum(results)}')
    print('Конкурентный логин:', race_creds['login'])
    return all(results)


def menu(client, key_path):
    session = None  # Только последний успешно полученный токен, в памяти клиента.
    while True:
        heading('TIMEBOOK | AUTH SERVICE | ТЕСТОВЫЙ КЛИЕНТ')
        print(f'  Сервер: {client.base_url}')
        print('  Сессия: ' + (f'логин {session[0]}, user_id={session[1]}' if session else 'нет токена'))
        print(LINE)
        print('''  1. Проверить доступность сервиса (GET /health)
  2. Зарегистрировать пользователя
  3. Войти в систему
  4. Показать содержимое и проверить подпись JWT
  5. Продемонстрировать подделку JWT
  6. Показать полный JWT (внимание: секретный токен)
  7. Выйти из аккаунта (удалить локальный токен)
  8. Запустить все автоматические проверки
  0. Закрыть программу''')
        print(LINE)
        choice = input('Выбери действие: ').strip()
        try:
            if choice == '0':
                return
            if choice == '1':
                request(client, 'GET', '/health')
            elif choice in ('2', '3'):
                body = credentials()
                r = request(client, 'POST', '/auth/register' if choice == '2' else '/auth/login', body)
                if r.status_code == (201 if choice == '2' else 200):
                    data = r.json()
                    session = (body['login'], data['user_id'], data['access_token'])
                    print('JWT сохранён в памяти клиента.')
                else:
                    print('Операция отклонена. Предыдущая сессия не изменена.')
            elif choice in ('4', '5', '6'):
                if session is None:
                    print('Сначала зарегистрируйся или войди.')
                elif choice == '6':
                    if input('Показать полный токен на экране? [y/N]: ').lower() == 'y':
                        print(session[2])
                else:
                    key = key_path.read_bytes()
                    uid = verify_token(session[2], key)
                    if uid != session[1]:
                        raise ValueError('user_id в ответе и токене не совпадают')
                    if choice == '4':
                        print('Подпись, срок действия, издатель и получатель: OK')
                        print('Header:', json.dumps(jwt.get_unverified_header(session[2]), indent=2))
                        # Payload показываем только после полноценной проверки выше.
                        claims = jwt.decode(session[2], options={'verify_signature': False})
                        print('Payload:', json.dumps(claims, indent=2))
                        print('Подтверждённый user_id:', uid)
                    else:
                        print('Изменяем sub в JWT, не меняя подпись.')
                        print('Исходный JWT: действителен.')
                        print('Изменённый JWT: ' + ('отклонён (InvalidSignatureError)' if rejects_tampered(session[2], key) else 'ОШИБКА: подделка не отклонена'))
            elif choice == '7':
                session = None
                print('Локальный токен удалён. Серверный JWT не отозван.')
            elif choice == '8':
                if input('Создать тестовые записи в БД? [y/N]: ').lower() == 'y':
                    run_suite(client, key_path.read_bytes())
            else:
                print('Неизвестный пункт меню.')
        except httpx.RequestError as exc:
            print(f'Ошибка соединения ({type(exc).__name__}). Проверь, запущен ли Auth Service. При тайм-ауте результат операции может быть неизвестен.')
        except FileNotFoundError:
            print('Публичный ключ не найден:', key_path)
            print('Проверь папку keys и используй публичный ключ работающего Auth Service.')
        except jwt.ExpiredSignatureError:
            print('Срок действия JWT истёк. Войди снова.')
        except jwt.InvalidTokenError as exc:
            print('JWT отклонён:', type(exc).__name__)
        except (ValueError, KeyError, TypeError, OSError) as exc:
            print('Ошибка обработки ответа или ключа:', type(exc).__name__)
        input('\nEnter — вернуться в меню...')


def main():
    load_config()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url', default='http://127.0.0.1:8002', help='Адрес Auth Service')
    parser.add_argument('--public-key', type=Path, default=key_path('JWT_PUBLIC_KEY_FILE', 'keys/public.pem'))
    parser.add_argument('--auto', action='store_true', help='Запустить тесты без меню (создаёт записи в БД)')
    args = parser.parse_args()
    try:
        with httpx.Client(base_url=args.url, timeout=15, trust_env=False) as client:
            if args.auto:
                return 0 if run_suite(client, args.public_key.read_bytes()) else 1
            menu(client, args.public_key)
    except (KeyboardInterrupt, EOFError):
        print('\nРабота завершена.')
    except OSError as exc:
        print('Не удалось прочитать ключ или открыть ресурс:', type(exc).__name__)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
