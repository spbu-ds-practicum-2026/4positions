# TimeBook API Gateway

Самостоятельный сервис FastAPI. Использует HTTP/JSON, проверяет JWT RS256 локально публичным ключом Auth Service, распределяет запросы между экземплярами TimeBook по Round Robin. База данных Gateway не нужна.

## Запуск (Windows PowerShell, из корня 4positions)

```powershell
.\.venv\Scripts\python.exe -m pip install -r api_gateway/requirements.txt
```

В отдельных терминалах:

```powershell
.\.venv\Scripts\python.exe auth_service/main.py
.\.venv\Scripts\python.exe api_gateway/main.py
.\.venv\Scripts\python.exe api_gateway/mock_timebook.py
.\.venv\Scripts\python.exe api_gateway/test.py
```

Auth Service должен быть настроен и иметь пару RSA-ключей. Gateway по умолчанию использует `../auth_service/keys/public.pem` относительно собственной папки. Приватный ключ Gateway не нужен. При необходимости скопируйте `.env.example` в `.env` рядом с `main.py` и измените адреса и путь к публичному ключу. `TIMEBOOK_URLS` — список адресов через запятую. Сервер слушает 127.0.0.1:8000. Swagger: http://127.0.0.1:8000/docs.

## Контракт

| Клиент → Gateway | Gateway → сервис | JWT |
|---|---|---|
| GET /health | локально | нет |
| POST /api/auth/register | Auth: POST /auth/register | нет |
| POST /api/auth/login | Auth: POST /auth/login | нет |
| GET /api/resources | TimeBook: GET /resources | да |
| POST /api/bookings | TimeBook: POST /booking | да |
| POST /api/bookings/{booking_id}/cancel | TimeBook: POST /booking/{booking_id}/cancel | да |

Короткие маршруты `/auth/register`, `/auth/login`, `/resources`, `/booking`, `/booking/{booking_id}/cancel` также поддерживаются Gateway (тот же формат клиентского тела). Старые маршруты тренеров, расписания и истории удалены. Для защищённых запросов: `Authorization: Bearer <JWT>`.

Регистрация и вход используют JSON `{"login":"demo","password":"TestPassword123"}`. Auth Service выпускает JWT, Gateway возвращает его и HTTP-код без изменения.

Каталог: TimeBook возвращает, например, `{"items":[{"res_id":7,"date":"2026-12-01","time":"10:00-11:00"}],"partial":false}`. Каждый ресурс — конкретное занятие (временной слот); `date` содержит дату в формате YYYY-MM-DD, `time` — строковый интервал HH:MM-HH:MM (начало и конец в рамках указанной даты). `res_id` однозначно идентифицирует занятие. Gateway передаёт ответ без преобразований, включая `partial`, если он есть.

Клиентское тело для создания: `{"resource_id":7,"request_id":"unique-request"}`. Gateway преобразует его в `{"res_id":7,"usr_id":3,"request_id":"unique-request"}` (3 — пример ID из проверенного JWT). Ответ TimeBook, например `{"booking_id":42,"status":"confirmed"}`, передаётся без изменения.

Отмена: клиент и Gateway используют `{"resource_id":7,"request_id":"another-request"}`. Ответ TimeBook, например `{"booking_id":42,"resource_id":7,"status":"cancelled"}`. Для всех защищённых запросов Gateway самостоятельно добавляет `X-User-ID`. В частности, TimeBook должен использовать этот заголовок при проверке владельца отменяемой брони. Не копируются пользовательские заголовки Authorization и X-User-ID; поля usr_id/user_id в клиентском JSON запрещены. TimeBook должен быть доступен только доверенным сервисам, иначе заголовок можно подделать при прямом обращении.

Идентификаторы ресурса и бронирования — положительные целые до 2^63-1. `request_id` — непустая строка до 128 символов (клиент генерирует UUID). Gateway не изменяет её и не делает скрытых повторов. При тайм-ауте POST возвращается 503 с неизвестным результатом; повторять следует исходный запрос с тем же request_id. Ответы TimeBook, в том числе 202 и Retry-After, сохраняются. Заглушка не выполняет реальные операции.

## Тесты

Из папки api_gateway:

```powershell
..\.venv\Scripts\python.exe -m pytest -v test_gateway.py
```

Тесты используют MockTransport и не требуют запущенных серверов. Консольный клиент `test.py` работает с настоящим HTTP Gateway, для повтора последней операции сохраняет её параметры в памяти текущей сессии. Для заглушки используйте res_id 7 или 8 и booking_id 42.

## Что ещё согласовать

В рукописном контракте создание использует res_id/usr_id, отмена resource_id. Сохранены именно эти имена. В ТР есть отдельное расписание и slot_id, которых нет в последнем контракте; по уточнённому контракту ресурс уже обозначает конкретный временной слот (занятие), поэтому отдельный slot_id не нужен. Уточнить с TimeBook формат статусов/ошибок, проверку X-User-ID при отмене и семантику частичного каталога. JWT для каталога обязателен, поскольку он включает расписание. Ограничение частоты запросов, heartbeat и исключение недоступных инстансов из Round Robin пока не реализованы. Нет проверки реальной TimeBook DB/идемпотентности/репликации: это ответственность TimeBook. Для развёртывания вне локального компьютера нужны TLS и защита внутренней сети.
