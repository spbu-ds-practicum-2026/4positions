"""Консольный клиент Gateway. Пароли и токены не выводятся."""
import argparse
import json
from getpass import getpass
from uuid import uuid4
import httpx
if __package__:
    from .models import validation_message
else:
    from models import validation_message

MESSAGES = {
    'missing_token':'Сначала войдите в аккаунт.',
    'invalid_token':'Токен недействителен или просрочен. Войдите заново.',
    'login_taken':'Логин уже занят.',
    'invalid_credentials':'Неверный логин или пароль.',
    'auth_db_unavailable':'База пользователей временно недоступна.',
    'auth_service_unavailable':'Auth Service недоступен. Если регистрация прервалась, попробуйте войти.',
    'timebook_unavailable':'TimeBook временно недоступен.',
    'resource_not_found':'Ресурс не найден.',
    'booking_not_found':'Бронирование не найдено.',
    'no_free_places':'Нет свободных мест.',
    'booking_not_owned':'Это бронирование принадлежит другому пользователю.',
    'idempotency_conflict':'Этот request_id уже использован для другой операции.',
}

def show_error(status, data):
    data = data if isinstance(data, dict) else {}
    detail = data.get('detail')
    if status == 422 and isinstance(detail, list):
        print('Проверьте введённые данные:')
        for error in detail:
            if not isinstance(error, dict): continue
            loc = error.get('loc', [])
            field = loc[-1] if isinstance(loc, list) and loc and isinstance(loc[-1], str) else 'body'
            kind = error.get('type')
            print(' - ' + validation_message(field, kind if isinstance(kind,str) else ''))
    else:
        code = detail if isinstance(detail,str) else data.get('code')
        print(MESSAGES.get(code if isinstance(code,str) else '', {401:'Не удалось подтвердить пользователя.',403:'Доступ запрещён.',404:'Ресурс не найден.',409:'Конфликт данных.',503:'Сервис временно недоступен.'}.get(status,'Не удалось выполнить операцию.')))
    if data.get('result') == 'unknown':
        print('Результат операции неизвестен. Повторите исходный запрос с тем же request_id.')

def send(client, method, path, body=None, token=None, params=None):
    print(f'\n>>> {method} {path}')
    if body is not None:
        print(json.dumps({k:('********' if k=='password' else v) for k,v in body.items()},ensure_ascii=False))
    try:
        response = client.request(method,path,json=body,params=params,headers={'Authorization':f'Bearer {token}'} if token else {})
    except httpx.RequestError:
        print('Gateway недоступен или ответ не получен.')
        if path.startswith('/api/bookings') and method=='POST': print('Повторите исходный запрос с тем же request_id.')
        return None
    print(f'<<< HTTP {response.status_code}')
    try: data=response.json()
    except ValueError: data=None
    if not response.is_success:
        show_error(response.status_code,data)
    else:
        shown = {**data,'access_token':'[скрыт]'} if isinstance(data,dict) and 'access_token' in data else data
        print(json.dumps(shown,ensure_ascii=False,indent=2))
    return response

def menu(client):
    token = user_id = last = None
    while True:
        print('\n' + '='*58 + '\n TIMEBOOK | API GATEWAY\n' + '='*58)
        print(f'Сессия: user_id={user_id}' if token else 'Сессия: не авторизован')
        print('1. Проверить Gateway\n2. Регистрация\n3. Вход\n4. Список ресурсов\n5. Бронирование\n6. Отмена\n7. Повтор последней операции\n8. Выход из аккаунта\n9. Проверка запроса без JWT\n0. Закрыть')
        choice = input('Выберите действие: ').strip()
        if choice == '0': return
        if choice == '1': send(client, 'GET', '/health')
        elif choice in ('2', '3'):
            body = {'login': input('Логин: '), 'password': getpass('Пароль: ')}
            r = send(client, 'POST', '/api/auth/register' if choice == '2' else '/api/auth/login', body)
            if r is not None and r.is_success:
                data = r.json(); token = data['access_token']; user_id = data['user_id']; last = None
                print('JWT сохранён в памяти.')
        elif choice == '9': send(client, 'GET', '/api/resources')
        elif choice == '8': token = user_id = last = None; print('Локальная сессия удалена.')
        elif choice in ('4', '5', '6', '7'):
            if not token: print('Сначала войдите в аккаунт.'); continue
            if choice == '4':
                send(client, 'GET', '/api/resources', token=token); continue
            if choice == '7':
                if last is None: print('Нет операции для повтора.'); continue
                path, body = last
            else:
                try:
                    resource_id = int(input('resource_id (res_id из списка): '))
                    if resource_id <= 0: raise ValueError
                    if choice == '6':
                        booking_id = int(input('booking_id: '))
                        if booking_id <= 0: raise ValueError
                except ValueError:
                    print('Введите положительное целое число.'); continue
                body = {'resource_id': resource_id, 'request_id': str(uuid4())}
                path = '/api/bookings' if choice == '5' else f'/api/bookings/{booking_id}/cancel'
                last = (path, body.copy())
            r = send(client, 'POST', path, body, token)
            if r is not None and r.is_success:
                data = r.json()
                if r.status_code == 202 or (isinstance(data, dict) and data.get('status') in ('processing', 'pending')):
                    print('Запрос обрабатывается. Для проверки повторите исходную операцию.')
        else: print('Неизвестный пункт.')

def main():
    parser=argparse.ArgumentParser(); parser.add_argument('--url',default='http://127.0.0.1:8000'); args=parser.parse_args()
    with httpx.Client(base_url=args.url,timeout=15,trust_env=False) as client:
        try: menu(client)
        except (KeyboardInterrupt,EOFError): print('\nВыход.')

if __name__=='__main__': main()
