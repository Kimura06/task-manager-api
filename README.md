Task Manager API
Простой REST API для управления задачами, созданный с использованием FastAPI, SQLAlchemy и SQLite. Проект демонстрирует навыки работы с Python, SQL, FastAPI и REST API.
Особенности

RESTful API с использованием FastAPI,
Аутентификация с использованием JWT токенов,
База данных SQLite с ORM (SQLAlchemy),
CRUD операции для задач,
Фильтрация задач по статусу и приоритету,
Автоматическая документация API (Swagger UI).

Установка и запуск

Установите зависимости:

bashpip install -r requirements.txt

Запустите сервер:

bashpython app.py
Сервер будет запущен по адресу http://localhost:8000, а документация API будет доступна по адресу http://localhost:8000/docs.
API Endpoints
Аутентификация

POST /token - Получение JWT токена
POST /api/users/ - Регистрация нового пользователя
GET /api/users/me/ - Получение данных текущего пользователя

Управление задачами

POST /api/tasks/ - Создание новой задачи
GET /api/tasks/ - Получение списка задач (с фильтрацией)
GET /api/tasks/{task_id} - Получение конкретной задачи
PUT /api/tasks/{task_id} - Обновление задачи
DELETE /api/tasks/{task_id} - Удаление задачи

Пример использования API
Создание пользователя
bashcurl -X 'POST' \
  'http://localhost:8000/api/users/' \
  -H 'Content-Type: application/json' \
  -d '{
  "username": "testuser",
  "email": "test@example.com",
  "password": "password123"
}'
Получение токена
bashcurl -X 'POST' \
  'http://localhost:8000/token' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'username=testuser&password=password123'
Создание задачи
bashcurl -X 'POST' \
  'http://localhost:8000/api/tasks/' \
  -H 'Authorization: Bearer YOUR_TOKEN' \
  -H 'Content-Type: application/json' \
  -d '{
  "title": "Изучить FastAPI",
  "description": "Прочитать документацию и создать тестовый проект",
  "status": "pending",
  "priority": 3
}'
Технологии

Python 3.8+
FastAPI
SQLAlchemy
Pydantic
SQLite
JWT Authentication
