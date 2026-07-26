"""
UniHomos — серверна частина (backend)
=======================================

Що робить цей файл:
- Приймає запити від додатку (реєстрація нового користувача)
- Перевіряє, чи вільний хендл (@nickname)
- Зберігає користувача в базу даних MongoDB
- Дозволяє знайти користувача/канал/чат за хендлом (для пошуку)

Як запустити локально (для перевірки на своєму комп'ютері):
    pip install -r requirements.txt
    uvicorn main:app --reload

Потім відкрити в браузері: http://127.0.0.1:8000/docs
Там буде автоматична сторінка, де можна "потикати" всі функції руками.
"""

import os
import re
import uuid

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from pymongo import MongoClient

# ---------------------------------------------------------------------------
# 1. Підключення до бази даних MongoDB
# ---------------------------------------------------------------------------
# MONGO_URI не пишемо прямо в код (це небезпечно — логін/пароль від бази).
# Замість цього значення береться зі "змінної середовища" (environment variable).
# На Render це буде налаштовано в розділі "Environment" — покажу окремо, коли дійдемо.
#
# Для локальної перевірки на своєму комп'ютері можна тимчасово підставити
# рядок підключення прямо у змінну нижче (MONGO_URI = "mongodb+srv://...").

MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017")

client = MongoClient(MONGO_URI)
db = client["unihomos"]          # назва бази даних
users = db["users"]              # колекція (як таблиця) для користувачів


# ---------------------------------------------------------------------------
# 2. Створюємо сам сервер (FastAPI)
# ---------------------------------------------------------------------------
app = FastAPI(title="UniHomos API")

# CORS — дозволяє нашому фронтенду (HTML-сторінкам) звертатися до цього сервера.
# Без цього браузер заблокує запити з іншого домену. Поки що дозволяємо всім (*),
# пізніше звузимо тільки до нашого реального сайту.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# 3. Правила валідації хендла (той самий формат, що і в дизайні:
#    тільки латинські літери, цифри, "_" та "-")
# ---------------------------------------------------------------------------
HANDLE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{3,24}$")


def validate_handle(handle: str):
    if not HANDLE_PATTERN.match(handle):
        raise HTTPException(
            status_code=400,
            detail="Handle must be 3-24 characters: Latin letters, numbers, _ or - only",
        )


# ---------------------------------------------------------------------------
# 4. Опис даних, які очікуємо отримати від додатку (реєстрація)
# ---------------------------------------------------------------------------
class RegisterRequest(BaseModel):
    name: str      # ім'я — будь-яка мова
    handle: str    # @хендл — тільки латиниця


class RegisterResponse(BaseModel):
    user_id: str
    name: str
    handle: str


# ---------------------------------------------------------------------------
# 5. Маршрути (endpoints) — те, до чого звертається додаток
# ---------------------------------------------------------------------------

@app.get("/")
def health_check():
    """Проста перевірка, що сервер живий."""
    return {"status": "ok", "service": "UniHomos API"}


@app.post("/register", response_model=RegisterResponse)
def register_user(payload: RegisterRequest):
    name = payload.name.strip()
    handle = payload.handle.strip().lower()

    if len(name) < 2:
        raise HTTPException(status_code=400, detail="Name is too short")

    validate_handle(handle)

    # Перевіряємо, чи хендл вже зайнятий
    existing = users.find_one({"handle": handle})
    if existing:
        raise HTTPException(status_code=409, detail="This handle is already taken")

    user_id = str(uuid.uuid4())
    users.insert_one({
        "user_id": user_id,
        "name": name,
        "handle": handle,
    })

    return RegisterResponse(user_id=user_id, name=name, handle=handle)


@app.get("/users/{handle}")
def find_user(handle: str):
    """Пошук користувача за хендлом (для функції пошуку в додатку)."""
    handle = handle.strip().lower().lstrip("@")
    user = users.find_one({"handle": handle}, {"_id": 0})
    if not user:
        raise HTTPException(status_code=404, detail="Not found")
    return user
