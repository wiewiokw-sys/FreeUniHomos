"""
FreeUniHomos — серверна частина (backend), версія 4
=======================================================

Нове порівняно з v3:
- Мировий чат (worldchat) — спеціальний чат, який автоматично є у КОЖНОГО користувача
- Авто-join у worldchat при реєстрації та логіні
- max_members для войсів (за замовчуванням 10)
- Заготовки під пости профілю (posts)
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

MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017")

client = MongoClient(MONGO_URI)
db = client["unihomos"]
users = db["users"]
messages = db["messages"]
saved = db["saved_messages"]
entities = db["entities"]
entity_messages = db["entity_messages"]

app = FastAPI(title="FreeUniHomos API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

HANDLE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{3,30}$")

WORLD_HANDLE = "worldchat"
WORLD_NAME = "Мировий чат"


def ensure_world_chat():
    """Створює мировий чат, якщо його ще немає."""
    if not entities.find_one({"handle": WORLD_HANDLE}):
        entities.insert_one({
            "entity_id": str(uuid.uuid4()),
            "kind": "chat",
            "name": WORLD_NAME,
            "handle": WORLD_HANDLE,
            "creator_handle": "system",
            "members": [],
            "is_world": True,
        })


def join_world(handle: str):
    """Додає користувача в мировий чат (якщо ще не там)."""
    ensure_world_chat()
    entities.update_one(
        {"handle": WORLD_HANDLE},
        {"$addToSet": {"members": handle}},
    )


def validate_handle(handle: str):
    if not HANDLE_PATTERN.match(handle):
        raise HTTPException(status_code=400, detail="Invalid handle format")


def clean_handle(h: str) -> str:
    return h.strip().lstrip("@").lower()


def hash_password(password: str, salt: str = None):
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
        "tag_emoji": u.get("tag_emoji", ""),
    }


def user_lookup_map(handles: set) -> dict:
    """Швидкий довідник handle -> {name, avatar, tag_emoji} для підпису повідомлень."""
    result = {}
    for u in users.find({"handle": {"$in": list(handles)}}, {"_id": 0, "handle": 1, "name": 1, "avatar": 1, "tag_emoji": 1}):
        result[u["handle"]] = {"name": u["name"], "avatar": u.get("avatar", ""), "tag_emoji": u.get("tag_emoji", "")}
    return result


# ---------------------------------------------------------------------------
# Моделі
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
    reply_to: str = ""            # message_id повідомлення, на яке відповідаємо
    reply_preview: str = ""       # короткий текст того повідомлення (для показу без зайвих запитів)
    forwarded_from: str = ""      # handle оригінального автора, якщо це пересилка


class MarkReadRequest(BaseModel):
    reader_handle: str
    other_handle: str


class SavedMessageRequest(BaseModel):
    owner_handle: str
    type: str
    content: str
    time: str
    duration: str = ""
    reply_to: str = ""
    reply_preview: str = ""
    forwarded_from: str = ""


class CreateEntityRequest(BaseModel):
    kind: str
    name: str
    handle: str            # вже БЕЗ префікса — сервер сам додасть kind+handle
    creator_handle: str


class JoinEntityRequest(BaseModel):
    handle: str
    member_handle: str


class EntityMessageRequest(BaseModel):
    entity_handle: str
    from_handle: str
    type: str
    content: str
    time: str
    duration: str = ""
    reply_to: str = ""
    reply_preview: str = ""
    forwarded_from: str = ""


class EditMessageRequest(BaseModel):
    message_id: str
    editor_handle: str
    new_content: str


class DeleteMessageRequest(BaseModel):
    message_id: str
    requester_handle: str


class UpdateProfileRequest(BaseModel):
    handle: str
    new_name: str = ""
    new_handle: str = ""
    new_avatar: str = ""
    new_tag_emoji: str = ""
    clear_tag_emoji: bool = False


class ChangePasswordRequest(BaseModel):
    handle: str
    old_password: str
    new_password: str


class DeleteAccountRequest(BaseModel):
    handle: str
    password: str


# ---------------------------------------------------------------------------
# Базові маршрути
# ---------------------------------------------------------------------------

@app.get("/")
def health_check():
    ensure_world_chat()
    return {"status": "ok", "service": "FreeUniHomos API", "version": 4}


@app.post("/register")
def register_user(payload: RegisterRequest):
    name = payload.name.strip()
    handle = clean_handle(payload.handle)
    password = payload.password

    if len(name) < 2:
        raise HTTPException(status_code=400, detail="Name is too short")
    if not re.match(r"^[A-Za-z0-9_-]{3,20}$", handle):
        raise HTTPException(status_code=400, detail="Handle must be 3-20 characters: Latin letters, numbers, _ or -")
    if len(password) < 4:
        raise HTTPException(status_code=400, detail="Password is too short")
    if users.find_one({"handle": handle}):
        raise HTTPException(status_code=409, detail="This handle is already taken")

    user_id = str(uuid.uuid4())
    password_hash, salt = hash_password(password)
    users.insert_one({
        "user_id": user_id, "name": name, "handle": handle,
        "password_hash": password_hash, "salt": salt, "avatar": "", "tag_emoji": "",
    })
    join_world(handle)
    return {"user_id": user_id, "name": name, "handle": handle, "avatar": "", "tag_emoji": ""}


@app.post("/login")
def login_user(payload: LoginRequest):
    identifier = clean_handle(payload.identifier)
    user = users.find_one({"handle": identifier})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if not verify_password(payload.password, user["salt"], user["password_hash"]):
        raise HTTPException(status_code=401, detail="Wrong password")
    join_world(identifier)  # на випадок, якщо старий акаунт ще не в мировому чаті
    return public_user(user)


@app.get("/users/{handle}")
def find_user(handle: str):
    user = users.find_one({"handle": clean_handle(handle)})
    if not user:
        raise HTTPException(status_code=404, detail="Not found")
    return public_user(user)


@app.get("/users/by-id/{user_id}")
def find_user_by_id(user_id: str):
    """Дозволяє пристрою звірити свій акаунт з сервером (виправляє розсинхрон хендла)."""
    user = users.find_one({"user_id": user_id})
    if not user:
        raise HTTPException(status_code=404, detail="Not found")
    return public_user(user)


# ---------------------------------------------------------------------------
# Профіль
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
        if not re.match(r"^[A-Za-z0-9_-]{3,20}$", candidate):
            raise HTTPException(status_code=400, detail="Invalid handle format")
        if candidate != handle and users.find_one({"handle": candidate}):
            raise HTTPException(status_code=409, detail="This handle is already taken")
        update["handle"] = candidate
        new_handle = candidate

    if payload.new_avatar:
        update["avatar"] = payload.new_avatar

    if payload.clear_tag_emoji:
        update["tag_emoji"] = ""
    elif payload.new_tag_emoji:
        update["tag_emoji"] = payload.new_tag_emoji

    if update:
        users.update_one({"handle": handle}, {"$set": update})
        if "handle" in update:
            messages.update_many({"from_handle": handle}, {"$set": {"from_handle": new_handle}})
            messages.update_many({"to_handle": handle}, {"$set": {"to_handle": new_handle}})
            saved.update_many({"owner_handle": handle}, {"$set": {"owner_handle": new_handle}})
            entities.update_many({"creator_handle": handle}, {"$set": {"creator_handle": new_handle}})
            entities.update_many({"members": handle}, {"$set": {"members.$": new_handle}})
            entity_messages.update_many({"from_handle": handle}, {"$set": {"from_handle": new_handle}})
            # перерахувати chat_key для DM (вони містять старий хендл)
            for doc in messages.find({"$or": [{"from_handle": new_handle}, {"to_handle": new_handle}]}):
                correct_key = chat_key(doc["from_handle"], doc["to_handle"])
                if doc.get("chat_key") != correct_key:
                    messages.update_one({"_id": doc["_id"]}, {"$set": {"chat_key": correct_key}})

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


@app.post("/profile/delete-account")
def delete_account(payload: DeleteAccountRequest):
    handle = clean_handle(payload.handle)
    user = users.find_one({"handle": handle})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if not verify_password(payload.password, user["salt"], user["password_hash"]):
        raise HTTPException(status_code=401, detail="Wrong password")

    users.delete_one({"handle": handle})
    messages.delete_many({"$or": [{"from_handle": handle}, {"to_handle": handle}]})
    saved.delete_many({"owner_handle": handle})
    entities.update_many({"members": handle}, {"$pull": {"members": handle}})
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Особисті повідомлення (DM)
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
        "status": "sent", "edited": False,
        "reply_to": payload.reply_to, "reply_preview": payload.reply_preview,
        "forwarded_from": payload.forwarded_from,
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


@app.post("/messages/edit")
def edit_message(payload: EditMessageRequest):
    doc = messages.find_one({"message_id": payload.message_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Message not found")
    if doc["from_handle"] != clean_handle(payload.editor_handle):
        raise HTTPException(status_code=403, detail="You can only edit your own messages")
    messages.update_one({"message_id": payload.message_id}, {"$set": {"content": payload.new_content, "edited": True}})
    return {"status": "ok"}


@app.post("/messages/delete")
def delete_message(payload: DeleteMessageRequest):
    doc = messages.find_one({"message_id": payload.message_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Message not found")
    if doc["from_handle"] != clean_handle(payload.requester_handle):
        raise HTTPException(status_code=403, detail="You can only delete your own messages")
    messages.delete_one({"message_id": payload.message_id})
    return {"status": "ok"}


@app.get("/conversations/{handle}")
def list_conversations(handle: str):
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
            "tag_emoji": partner_user.get("tag_emoji", "") if partner_user else "",
            "last_type": last["type"],
            "last_content_preview": last["content"][:60] if last["type"] == "text" else "",
            "last_time": last["time"],
            "unread": unread,
        })
    return result


# ---------------------------------------------------------------------------
# Збережене
# ---------------------------------------------------------------------------

@app.post("/saved/send")
def send_saved(payload: SavedMessageRequest):
    owner_handle = clean_handle(payload.owner_handle)
    message_id = str(uuid.uuid4())
    saved.insert_one({
        "message_id": message_id, "owner_handle": owner_handle,
        "type": payload.type, "content": payload.content,
        "time": payload.time, "duration": payload.duration, "edited": False,
        "reply_to": payload.reply_to, "reply_preview": payload.reply_preview,
        "forwarded_from": payload.forwarded_from,
    })
    return {"message_id": message_id}


@app.get("/saved/{handle}")
def get_saved(handle: str):
    docs = saved.find({"owner_handle": clean_handle(handle)}, {"_id": 0}).sort("_id", 1)
    return list(docs)


@app.post("/saved/edit")
def edit_saved(payload: EditMessageRequest):
    doc = saved.find_one({"message_id": payload.message_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Message not found")
    if doc["owner_handle"] != clean_handle(payload.editor_handle):
        raise HTTPException(status_code=403, detail="Not yours")
    saved.update_one({"message_id": payload.message_id}, {"$set": {"content": payload.new_content, "edited": True}})
    return {"status": "ok"}


@app.post("/saved/delete")
def delete_saved(payload: DeleteMessageRequest):
    doc = saved.find_one({"message_id": payload.message_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Message not found")
    if doc["owner_handle"] != clean_handle(payload.requester_handle):
        raise HTTPException(status_code=403, detail="Not yours")
    saved.delete_one({"message_id": payload.message_id})
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Канали / чати / войси
# ---------------------------------------------------------------------------

VALID_KINDS = {"channel", "chat", "voice"}


@app.post("/entities/create")
def create_entity(payload: CreateEntityRequest):
    if payload.kind not in VALID_KINDS:
        raise HTTPException(status_code=400, detail="Invalid kind")

    suffix = clean_handle(payload.handle)
    if not re.match(r"^[A-Za-z0-9_-]{2,20}$", suffix):
        raise HTTPException(status_code=400, detail="Invalid handle format")

    full_handle = payload.kind + suffix   # напр. "chat" + "123" = "chat123"
    validate_handle(full_handle)

    name = payload.name.strip()
    if len(name) < 2:
        raise HTTPException(status_code=400, detail="Name is too short")

    creator = clean_handle(payload.creator_handle)
    if not users.find_one({"handle": creator}):
        raise HTTPException(status_code=404, detail="Creator not found")

    if entities.find_one({"handle": full_handle}):
        raise HTTPException(status_code=409, detail="This @handle is already taken")

    entity_id = str(uuid.uuid4())
    doc = {
        "entity_id": entity_id, "kind": payload.kind, "name": name, "handle": full_handle,
        "creator_handle": creator, "members": [creator],
    }
    if payload.kind == "voice":
        doc["max_members"] = 10
    entities.insert_one(doc)
    return {"entity_id": entity_id, "kind": payload.kind, "name": name, "handle": full_handle}


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


@app.post("/entities/leave")
def leave_entity(payload: JoinEntityRequest):
    handle = clean_handle(payload.handle)
    member = clean_handle(payload.member_handle)
    entities.update_one({"handle": handle}, {"$pull": {"members": member}})
    return {"status": "ok"}


@app.get("/entities/mine/{handle}")
def my_entities(handle: str):
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
        "time": payload.time, "duration": payload.duration, "edited": False,
        "reply_to": payload.reply_to, "reply_preview": payload.reply_preview,
        "forwarded_from": payload.forwarded_from,
    })
    return {"message_id": message_id}


@app.get("/entities/messages/{handle}")
def get_entity_messages(handle: str):
    docs = list(entity_messages.find({"entity_handle": clean_handle(handle)}, {"_id": 0}).sort("_id", 1))
    senders = user_lookup_map({d["from_handle"] for d in docs})
    for d in docs:
        info = senders.get(d["from_handle"], {})
        d["from_name"] = info.get("name", d["from_handle"])
        d["from_avatar"] = info.get("avatar", "")
        d["from_tag_emoji"] = info.get("tag_emoji", "")
    return docs


@app.post("/entities/messages/edit")
def edit_entity_message(payload: EditMessageRequest):
    doc = entity_messages.find_one({"message_id": payload.message_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Message not found")
    if doc["from_handle"] != clean_handle(payload.editor_handle):
        raise HTTPException(status_code=403, detail="Not yours")
    entity_messages.update_one({"message_id": payload.message_id}, {"$set": {"content": payload.new_content, "edited": True}})
    return {"status": "ok"}


@app.post("/entities/messages/delete")
def delete_entity_message(payload: DeleteMessageRequest):
    doc = entity_messages.find_one({"message_id": payload.message_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Message not found")
    if doc["from_handle"] != clean_handle(payload.requester_handle):
        raise HTTPException(status_code=403, detail="Not yours")
    entity_messages.delete_one({"message_id": payload.message_id})
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Пошук
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
