"""
FreeUniHomos — серверна частина (backend)
============================================

Що робить цей файл:
- Реєстрація / вхід (хендл @... = унікальний ID користувача)
- Особисті повідомлення між двома людьми (текст/фото/голос), статуси sent/read
- Список "Чатів" з непрочитаними — /conversations/{handle}
- "Збережене" тепер зберігається на сервері (видно з будь-якого пристрою)
- Канали / чати / войси — тепер СПІЛЬНІ на сервері (глобально унікальний хендл
  серед усіх трьох типів, будь-хто може знайти і приєднатись)
- Пошук людей + каналів/чатів/войсів одним запитом, з поміткою типу
- Оновлення профілю (ім'я, хендл, аватар) — видно всім одразу
- Зміна пароля

Як запустити локально:
    pip install -r requirements.txt
    uvicorn main:app --reload
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
db = client["unihomos"]
users = db["users"]
messages = db["messages"]            # особисті повідомлення (DM)
saved = db["saved_messages"]         # "Збережене" кожного користувача
entities = db["entities"]            # канали / чати / войси
entity_messages = db["entity_messages"]  # повідомлення всередині каналу/чату/войсу

app = FastAPI(title="FreeUniHomos API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# 2. Валідація хендлів
# ---------------------------------------------------------------------------
HANDLE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{3,20}$")


def validate_handle(handle: str):
    if not HANDLE_PATTERN.match(handle):
        raise HTTPException(
            status_code=400,
            detail="Handle must be 3-20 characters: Latin letters, numbers, _ or - only",
        )


def clean_handle(h: str) -> str:
    return h.strip().lstrip("@").lower()


# ---------------------------------------------------------------------------
# 3. Паролі
# ---------------------------------------------------------------------------
def hash_password(password: str, salt: str = None) -> tuple[str, str]:
    if salt is None:
        salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 200_000)
    return digest.hex(), salt


def verify_password(password: str, salt: str, expected_hash: str) -> bool:
    digest, _ = hash_password(password, salt)
    return secrets.compare_digest(digest, expected_hash)


def public_user(u: dict) -> dict:
    return {
        "user_id": u["user_id"],
        "name": u["name"],
        "handle": u["handle"],
        "avatar": u.get("avatar", ""),
    }


# ---------------------------------------------------------------------------
# 4. Моделі даних
# ---------------------------------------------------------------------------
class RegisterRequest(BaseModel):
    name: str
    handle: str
    password: str


class LoginRequest(BaseModel):
    identifier: str
    password: str


class SendMessageRequest(BaseModel):
    from_handle: str
    to_handle: str
    type: str
    content: str
    time: str
    duration: str = ""


class MarkReadRequest(BaseModel):
    reader_handle: str
    other_handle: str


class SavedMessageRequest(BaseModel):
    owner_handle: str
    type: str
    content: str
    time: str
    duration: str = ""


class CreateEntityRequest(BaseModel):
    kind: str          # "channel" | "chat" | "voice"
    name: str
    handle: str
    creator_handle: str


class JoinEntityRequest(BaseModel):
    handle: str          # хендл сутності (без префікса типу)
    member_handle: str   # хто приєднується


class EntityMessageRequest(BaseModel):
    entity_handle: str
    from_handle: str
    type: str
    content: str
    time: str
    duration: str = ""


class UpdateProfileRequest(BaseModel):
    handle: str            # поточний хендл (для пошуку кого редагувати)
    new_name: str = ""
    new_handle: str = ""
    new_avatar: str = ""   # base64 dataURL картинки, або "" щоб не міняти


class ChangePasswordRequest(BaseModel):
    handle: str
    old_password: str
    new_password: str


# ---------------------------------------------------------------------------
# 5. Базові маршрути
# ---------------------------------------------------------------------------

@app.get("/")
def health_check():
    return {"status": "ok", "service": "FreeUniHomos API"}


@app.post("/register")
def register_user(payload: RegisterRequest):
    name = payload.name.strip()
    handle = clean_handle(payload.handle)
    password = payload.password

    if len(name) < 2:
        raise HTTPException(status_code=400, detail="Name is too short")
    validate_handle(handle)
    if len(password) < 4:
        raise HTTPException(status_code=400, detail="Password is too short")
    if users.find_one({"handle": handle}):
        raise HTTPException(status_code=409, detail="This handle is already taken")

    user_id = str(uuid.uuid4())
    password_hash, salt = hash_password(password)
    users.insert_one({
        "user_id": user_id, "name": name, "handle": handle,
        "password_hash": password_hash, "salt": salt, "avatar": "",
    })
    return {"user_id": user_id, "name": name, "handle": handle, "avatar": ""}


@app.post("/login")
def login_user(payload: LoginRequest):
    identifier = clean_handle(payload.identifier)
    user = users.find_one({"handle": identifier})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if not verify_password(payload.password, user["salt"], user["password_hash"]):
        raise HTTPException(status_code=401, detail="Wrong password")
    return public_user(user)


@app.get("/users/{handle}")
def find_user(handle: str):
    user = users.find_one({"handle": clean_handle(handle)})
    if not user:
        raise HTTPException(status_code=404, detail="Not found")
    return public_user(user)


# ---------------------------------------------------------------------------
# 6. Профіль
# ---------------------------------------------------------------------------

@app.post("/profile/update")
def update_profile(payload: UpdateProfileRequest):
    handle = clean_handle(payload.handle)
    user = users.find_one({"handle": handle})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    update = {}
    if payload.new_name.strip():
        update["name"] = payload.new_name.strip()

    new_handle = handle
    if payload.new_handle.strip():
        candidate = clean_handle(payload.new_handle)
        validate_handle(candidate)
        if candidate != handle and users.find_one({"handle": candidate}):
            raise HTTPException(status_code=409, detail="This handle is already taken")
        update["handle"] = candidate
        new_handle = candidate

    if payload.new_avatar:
        update["avatar"] = payload.new_avatar

    if update:
        users.update_one({"handle": handle}, {"$set": update})
        # якщо хендл змінився — оновлюємо його всюди, де він фігурує
        if "handle" in update:
            messages.update_many({"from_handle": handle}, {"$set": {"from_handle": new_handle}})
            messages.update_many({"to_handle": handle}, {"$set": {"to_handle": new_handle}})
            saved.update_many({"owner_handle": handle}, {"$set": {"owner_handle": new_handle}})
            entities.update_many({"creator_handle": handle}, {"$set": {"creator_handle": new_handle}})
            entities.update_many({"members": handle}, {"$set": {"members.$": new_handle}})

    user = users.find_one({"handle": new_handle})
    return public_user(user)


@app.post("/profile/change-password")
def change_password(payload: ChangePasswordRequest):
    handle = clean_handle(payload.handle)
    user = users.find_one({"handle": handle})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if not verify_password(payload.old_password, user["salt"], user["password_hash"]):
        raise HTTPException(status_code=401, detail="Old password is wrong")
    if len(payload.new_password) < 4:
        raise HTTPException(status_code=400, detail="New password is too short")
    password_hash, salt = hash_password(payload.new_password)
    users.update_one({"handle": handle}, {"$set": {"password_hash": password_hash, "salt": salt}})
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# 7. Особисті повідомлення (DM) + список розмов з непрочитаними
# ---------------------------------------------------------------------------

def chat_key(a: str, b: str) -> str:
    return "|".join(sorted([a, b]))


@app.post("/messages/send")
def send_message(payload: SendMessageRequest):
    from_handle = clean_handle(payload.from_handle)
    to_handle = clean_handle(payload.to_handle)

    if not users.find_one({"handle": from_handle}):
        raise HTTPException(status_code=404, detail="Sender not found")
    if not users.find_one({"handle": to_handle}):
        raise HTTPException(status_code=404, detail="Recipient not found")

    message_id = str(uuid.uuid4())
    messages.insert_one({
        "message_id": message_id,
        "chat_key": chat_key(from_handle, to_handle),
        "from_handle": from_handle, "to_handle": to_handle,
        "type": payload.type, "content": payload.content,
        "time": payload.time, "duration": payload.duration,
        "status": "sent",
    })
    return {"message_id": message_id, "status": "sent"}


@app.get("/messages/{handle_a}/{handle_b}")
def get_conversation(handle_a: str, handle_b: str):
    key = chat_key(clean_handle(handle_a), clean_handle(handle_b))
    docs = messages.find({"chat_key": key}, {"_id": 0}).sort("_id", 1)
    return list(docs)


@app.post("/messages/mark_read")
def mark_read(payload: MarkReadRequest):
    reader = clean_handle(payload.reader_handle)
    other = clean_handle(payload.other_handle)
    key = chat_key(reader, other)
    messages.update_many(
        {"chat_key": key, "to_handle": reader, "status": {"$ne": "read"}},
        {"$set": {"status": "read"}},
    )
    return {"status": "ok"}


@app.get("/conversations/{handle}")
def list_conversations(handle: str):
    """Всі люди, з якими є листування + останнє повідомлення + скільки непрочитано."""
    handle = clean_handle(handle)
    docs = list(messages.find(
        {"$or": [{"from_handle": handle}, {"to_handle": handle}]}, {"_id": 0}
    ).sort("_id", 1))

    by_partner = {}
    for d in docs:
        partner = d["to_handle"] if d["from_handle"] == handle else d["from_handle"]
        by_partner.setdefault(partner, []).append(d)

    result = []
    for partner, msgs in by_partner.items():
        last = msgs[-1]
        unread = sum(1 for m in msgs if m["to_handle"] == handle and m["status"] != "read")
        partner_user = users.find_one({"handle": partner})
        result.append({
            "handle": partner,
            "name": partner_user["name"] if partner_user else partner,
            "avatar": partner_user.get("avatar", "") if partner_user else "",
            "last_type": last["type"],
            "last_content_preview": last["content"][:60] if last["type"] == "text" else "",
            "last_time": last["time"],
            "unread": unread,
        })
    return result


# ---------------------------------------------------------------------------
# 8. Збережене (на сервері — видно з будь-якого пристрою)
# ---------------------------------------------------------------------------

@app.post("/saved/send")
def send_saved(payload: SavedMessageRequest):
    owner_handle = clean_handle(payload.owner_handle)
    message_id = str(uuid.uuid4())
    saved.insert_one({
        "message_id": message_id, "owner_handle": owner_handle,
        "type": payload.type, "content": payload.content,
        "time": payload.time, "duration": payload.duration,
    })
    return {"message_id": message_id}


@app.get("/saved/{handle}")
def get_saved(handle: str):
    docs = saved.find({"owner_handle": clean_handle(handle)}, {"_id": 0}).sort("_id", 1)
    return list(docs)


# ---------------------------------------------------------------------------
# 9. Канали / чати / войси (спільні, глобально унікальний хендл)
# ---------------------------------------------------------------------------

VALID_KINDS = {"channel", "chat", "voice"}


@app.post("/entities/create")
def create_entity(payload: CreateEntityRequest):
    if payload.kind not in VALID_KINDS:
        raise HTTPException(status_code=400, detail="Invalid kind")
    handle = clean_handle(payload.handle)
    validate_handle(handle)
    name = payload.name.strip()
    if len(name) < 2:
        raise HTTPException(status_code=400, detail="Name is too short")

    creator = clean_handle(payload.creator_handle)
    if not users.find_one({"handle": creator}):
        raise HTTPException(status_code=404, detail="Creator not found")

    if entities.find_one({"handle": handle}):
        raise HTTPException(status_code=409, detail="This @handle is already taken (by a channel, chat or voice)")

    entity_id = str(uuid.uuid4())
    entities.insert_one({
        "entity_id": entity_id, "kind": payload.kind, "name": name, "handle": handle,
        "creator_handle": creator, "members": [creator],
    })
    return {"entity_id": entity_id, "kind": payload.kind, "name": name, "handle": handle}


@app.post("/entities/join")
def join_entity(payload: JoinEntityRequest):
    handle = clean_handle(payload.handle)
    member = clean_handle(payload.member_handle)
    entity = entities.find_one({"handle": handle})
    if not entity:
        raise HTTPException(status_code=404, detail="Not found")
    entities.update_one({"handle": handle}, {"$addToSet": {"members": member}})
    entity = entities.find_one({"handle": handle}, {"_id": 0})
    return entity


@app.get("/entities/mine/{handle}")
def my_entities(handle: str):
    """Канали/чати/войси, до яких приєднаний користувач."""
    handle = clean_handle(handle)
    docs = entities.find({"members": handle}, {"_id": 0})
    return list(docs)


@app.get("/entities/{handle}")
def get_entity(handle: str):
    entity = entities.find_one({"handle": clean_handle(handle)}, {"_id": 0})
    if not entity:
        raise HTTPException(status_code=404, detail="Not found")
    return entity


@app.post("/entities/messages/send")
def send_entity_message(payload: EntityMessageRequest):
    handle = clean_handle(payload.entity_handle)
    entity = entities.find_one({"handle": handle})
    if not entity:
        raise HTTPException(status_code=404, detail="Entity not found")
    message_id = str(uuid.uuid4())
    entity_messages.insert_one({
        "message_id": message_id, "entity_handle": handle,
        "from_handle": clean_handle(payload.from_handle),
        "type": payload.type, "content": payload.content,
        "time": payload.time, "duration": payload.duration,
    })
    return {"message_id": message_id}


@app.get("/entities/messages/{handle}")
def get_entity_messages(handle: str):
    docs = entity_messages.find({"entity_handle": clean_handle(handle)}, {"_id": 0}).sort("_id", 1)
    return list(docs)


# ---------------------------------------------------------------------------
# 10. Об'єднаний пошук: люди + канали/чати/войси, з поміткою типу
# ---------------------------------------------------------------------------

@app.get("/search")
def search_all(q: str):
    q = q.strip().lstrip("@").lower()
    if not q:
        return {"people": [], "entities": []}

    people = list(users.find(
        {"handle": {"$regex": "^" + re.escape(q)}},
        {"_id": 0, "password_hash": 0, "salt": 0},
    ).limit(15))

    ent = list(entities.find(
        {"handle": {"$regex": "^" + re.escape(q)}},
        {"_id": 0},
    ).limit(15))

    return {"people": people, "entities": ent}
