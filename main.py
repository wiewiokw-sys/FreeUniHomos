"""
UniHomos — серверна частина (backend)
=======================================

Що робить цей файл:
- Реєстрація нового користувача (ім'я + @хендл + пароль)
- Хендл (@...) — це і є унікальний ID користувача, окремого ID більше немає
- Вхід в акаунт (по @хендлу + пароль)
- Зберігає користувача в базу даних MongoDB (пароль зберігається НЕ як текст,
  а як хеш — навіть якщо хтось побачить базу даних, пароль вкрасти не можна)
- Дозволяє знайти користувача/канал/чат за хендлом (для пошуку)

Як запустити локально (для перевірки на своєму комп'ютері):
    pip install -r requirements.txt
    uvicorn main:app --reload

Потім відкрити в браузері: http://127.0.0.1:8000/docs
Там буде автоматична сторінка, де можна "потикати" всі функції руками.
"""

import hashlib
import os
import re
import secrets
import uuid

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from pymongo import MongoClient

# ---------------------------------------------------------------------------
# 1. Підключення до бази даних MongoDB
# ---------------------------------------------------------------------------
MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017")

client = MongoClient(MONGO_URI)
db = client["unihomos"]          # назва бази даних
users = db["users"]              # колекція (як таблиця) для користувачів


# ---------------------------------------------------------------------------
# 2. Створюємо сам сервер (FastAPI)
# ---------------------------------------------------------------------------
app = FastAPI(title="UniHomos API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# 3. Правила валідації хендла
#    (тільки латинські літери, цифри, "_" та "-", 3-20 символів)
#    Хендл — це одночасно і унікальний ID користувача.
# ---------------------------------------------------------------------------
HANDLE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{3,20}$")


def validate_handle(handle: str):
    if not HANDLE_PATTERN.match(handle):
        raise HTTPException(
            status_code=400,
            detail="Handle must be 3-20 characters: Latin letters, numbers, _ or - only",
        )


# ---------------------------------------------------------------------------
# 4. Паролі: зберігаємо не сам пароль, а його "хеш" + сіль (salt).
#    Це стандартний безпечний підхід (PBKDF2-SHA256).
# ---------------------------------------------------------------------------
def hash_password(password: str, salt: str = None) -> tuple[str, str]:
    if salt is None:
        salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), 200_000
    )
    return digest.hex(), salt


def verify_password(password: str, salt: str, expected_hash: str) -> bool:
    digest, _ = hash_password(password, salt)
    return secrets.compare_digest(digest, expected_hash)


# ---------------------------------------------------------------------------
# 5. Моделі даних (те, що приходить від додатку / йде у відповідь)
# ---------------------------------------------------------------------------
class RegisterRequest(BaseModel):
    name: str
    handle: str
    password: str


class RegisterResponse(BaseModel):
    user_id: str
    name: str
    handle: str


class LoginRequest(BaseModel):
    identifier: str   # @хендл (він же ID)
    password: str


class LoginResponse(BaseModel):
    user_id: str
    name: str
    handle: str


# ---------------------------------------------------------------------------
# 6. Маршрути (endpoints)
# ---------------------------------------------------------------------------

@app.get("/")
def health_check():
    """Проста перевірка, що сервер живий."""
    return {"status": "ok", "service": "UniHomos API"}


@app.post("/register", response_model=RegisterResponse)
def register_user(payload: RegisterRequest):
    name = payload.name.strip()
    handle = payload.handle.strip().lstrip("@").lower()
    password = payload.password

    if len(name) < 2:
        raise HTTPException(status_code=400, detail="Name is too short")

    validate_handle(handle)

    if len(password) < 4:
        raise HTTPException(status_code=400, detail="Password is too short")

    existing = users.find_one({"handle": handle})
    if existing:
        raise HTTPException(status_code=409, detail="This handle is already taken")

    user_id = str(uuid.uuid4())
    password_hash, salt = hash_password(password)

    users.insert_one({
        "user_id": user_id,
        "name": name,
        "handle": handle,
        "password_hash": password_hash,
        "salt": salt,
    })

    return RegisterResponse(user_id=user_id, name=name, handle=handle)


@app.post("/login", response_model=LoginResponse)
def login_user(payload: LoginRequest):
    identifier = payload.identifier.strip().lstrip("@").lower()
    password = payload.password

    user = users.find_one({"handle": identifier})

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if not verify_password(password, user["salt"], user["password_hash"]):
        raise HTTPException(status_code=401, detail="Wrong password")

    return LoginResponse(
        user_id=user["user_id"],
        name=user["name"],
        handle=user["handle"],
    )


@app.get("/users/{handle}")
def find_user(handle: str):
    """Пошук користувача за хендлом (для функції пошуку в додатку)."""
    handle = handle.strip().lower().lstrip("@")
    user = users.find_one(
        {"handle": handle},
        {"_id": 0, "password_hash": 0, "salt": 0},
    )
    if not user:
        raise HTTPException(status_code=404, detail="Not found")
    return user
