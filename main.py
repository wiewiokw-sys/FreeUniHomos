"""
FreeUniHomos — серверна частина (backend), версія 6
=======================================================

Нове порівняно з v5:
- Профілі інших користувачів
- Пости (фото + текст ≤300 символів)
- Реакції на пости (👍 ❤️ 👎 🔥) — одна реакція на користувача
- Коментарі до постів (≤200 символів)
- Налаштування приватності постів (перегляд / реакції / коментарі)
"""

import hashlib
import os
import re
import secrets
import time
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
voice_ephemeral = db["voice_ephemeral"]
posts = db["posts"]
post_comments = db["post_comments"]

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
ONLINE_SECONDS = 120
EPHEMERAL_TTL = 50
RESERVED_HANDLE_PREFIXES = ("voice", "channel", "groupe", "chat")


def ensure_world_chat():
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
    last_seen = u.get("last_seen", 0)
    return {
        "user_id": u["user_id"],
        "name": u["name"],
        "handle": u["handle"],
        "avatar": u.get("avatar", ""),
        "tag_emoji": u.get("tag_emoji", ""),
        "online": (time.time() - last_seen) < ONLINE_SECONDS if last_seen else False,
        "last_seen": last_seen,
        "allow_view_posts": u.get("allow_view_posts", True),
        "allow_reactions": u.get("allow_reactions", True),
        "allow_comments": u.get("allow_comments", True),
    }


def touch_presence(handle: str):
    users.update_one({"handle": clean_handle(handle)}, {"$set": {"last_seen": time.time()}})


def user_lookup_map(handles: set) -> dict:
    result = {}
    now = time.time()
    for u in users.find({"handle": {"$in": list(handles)}}, {"_id": 0, "handle": 1, "name": 1, "avatar": 1, "tag_emoji": 1, "last_seen": 1}):
        ls = u.get("last_seen", 0)
        result[u["handle"]] = {
            "name": u["name"],
            "avatar": u.get("avatar", ""),
            "tag_emoji": u.get("tag_emoji", ""),
            "online": (now - ls) < ONLINE_SECONDS if ls else False,
        }
    return result


def cleanup_ephemeral(entity_handle: str = None):
    q = {"expires_at": {"$lt": time.time()}}
    if entity_handle:
        q["entity_handle"] = clean_handle(entity_handle)
    voice_ephemeral.delete_many(q)


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
    reply_to: str = ""
    reply_preview: str = ""
    forwarded_from: str = ""


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
    handle: str
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
    allow_view_posts: bool | None = None
    allow_reactions: bool | None = None
    allow_comments: bool | None = None


class CreatePostRequest(BaseModel):
    owner_handle: str
    text: str = ""
    photo: str = ""


class DeletePostRequest(BaseModel):
    post_id: str
    requester_handle: str


class ReactPostRequest(BaseModel):
    post_id: str
    reactor_handle: str
    reaction: str  # one of: like, heart, dislike, fire


class CommentPostRequest(BaseModel):
    post_id: str
    from_handle: str
    content: str


class DeleteCommentRequest(BaseModel):
    comment_id: str
    requester_handle: str


class ChangePasswordRequest(BaseModel):
    handle: str
    old_password: str
    new_password: str


class DeleteAccountRequest(BaseModel):
    handle: str
    password: str


class PresenceRequest(BaseModel):
    handle: str


class VoiceTalkRequest(BaseModel):
    handle: str
    member_handle: str
    talking: bool


class VoiceEphemeralRequest(BaseModel):
    entity_handle: str
    from_handle: str
    content: str
    kind: str = "emoji"


@app.get("/")
def health_check():
    ensure_world_chat()
    return {"status": "ok", "service": "FreeUniHomos API", "version": 6}


@app.post("/register")
def register_user(payload: RegisterRequest):
    name = payload.name.strip()
    handle = clean_handle(payload.handle)
    password = payload.password

    if len(name) < 2:
        raise HTTPException(status_code=400, detail="Name is too short")
    if not re.match(r"^[A-Za-z0-9_-]{3,20}$", handle):
        raise HTTPException(status_code=400, detail="Handle must be 3-20 characters: Latin letters, numbers, _ or -")
    if any(handle.startswith(p) for p in RESERVED_HANDLE_PREFIXES):
        raise HTTPException(status_code=400, detail="Handle cannot start with reserved prefix (voice/channel/groupe/chat)")
    if len(password) < 4:
        raise HTTPException(status_code=400, detail="Password is too short")
    if users.find_one({"handle": handle}):
        raise HTTPException(status_code=409, detail="This handle is already taken")

    user_id = str(uuid.uuid4())
    password_hash, salt = hash_password(password)
    users.insert_one({
        "user_id": user_id, "name": name, "handle": handle,
        "password_hash": password_hash, "salt": salt, "avatar": "", "tag_emoji": "",
        "last_seen": time.time(),
        "allow_view_posts": True,
        "allow_reactions": True,
        "allow_comments": True,
    })
    join_world(handle)
    return public_user(users.find_one({"handle": handle}))


@app.post("/login")
def login_user(payload: LoginRequest):
    identifier = clean_handle(payload.identifier)
    user = users.find_one({"handle": identifier})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if not verify_password(payload.password, user["salt"], user["password_hash"]):
        raise HTTPException(status_code=401, detail="Wrong password")
    users.update_one({"handle": identifier}, {"$set": {"last_seen": time.time()}})
    join_world(identifier)
    return public_user(users.find_one({"handle": identifier}))


@app.post("/presence")
def presence(payload: PresenceRequest):
    handle = clean_handle(payload.handle)
    if not users.find_one({"handle": handle}):
        raise HTTPException(status_code=404, detail="User not found")
    touch_presence(handle)
    return {"status": "ok"}


@app.get("/users/{handle}")
def find_user(handle: str):
    user = users.find_one({"handle": clean_handle(handle)})
    if not user:
        raise HTTPException(status_code=404, detail="Not found")
    return public_user(user)


@app.get("/users/by-id/{user_id}")
def find_user_by_id(user_id: str):
    user = users.find_one({"user_id": user_id})
    if not user:
        raise HTTPException(status_code=404, detail="Not found")
    return public_user(user)


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
        if any(candidate.startswith(p) for p in RESERVED_HANDLE_PREFIXES):
            raise HTTPException(status_code=400, detail="Handle cannot start with reserved prefix (voice/channel/groupe/chat)")
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

    if payload.allow_view_posts is not None:
        update["allow_view_posts"] = bool(payload.allow_view_posts)
    if payload.allow_reactions is not None:
        update["allow_reactions"] = bool(payload.allow_reactions)
    if payload.allow_comments is not None:
        update["allow_comments"] = bool(payload.allow_comments)

    if update:
        users.update_one({"handle": handle}, {"$set": update})
        if "handle" in update:
            messages.update_many({"from_handle": handle}, {"$set": {"from_handle": new_handle}})
            messages.update_many({"to_handle": handle}, {"$set": {"to_handle": new_handle}})
            saved.update_many({"owner_handle": handle}, {"$set": {"owner_handle": new_handle}})
            entities.update_many({"creator_handle": handle}, {"$set": {"creator_handle": new_handle}})
            entities.update_many({"members": handle}, {"$set": {"members.$": new_handle}})
            entity_messages.update_many({"from_handle": handle}, {"$set": {"from_handle": new_handle}})
            posts.update_many({"owner_handle": handle}, {"$set": {"owner_handle": new_handle}})
            post_comments.update_many({"from_handle": handle}, {"$set": {"from_handle": new_handle}})
            # update reaction keys inside posts
            for p in posts.find({f"reactions.{handle}": {"$exists": True}}):
                reactions = p.get("reactions") or {}
                if handle in reactions:
                    reactions[new_handle] = reactions.pop(handle)
                    posts.update_one({"_id": p["_id"]}, {"$set": {"reactions": reactions}})
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
    post_ids = [p["post_id"] for p in posts.find({"owner_handle": handle}, {"post_id": 1})]
    posts.delete_many({"owner_handle": handle})
    if post_ids:
        post_comments.delete_many({"post_id": {"$in": post_ids}})
    post_comments.delete_many({"from_handle": handle})
    return {"status": "ok"}


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

    touch_presence(from_handle)
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
    touch_presence(handle)
    docs = list(messages.find(
        {"$or": [{"from_handle": handle}, {"to_handle": handle}]}, {"_id": 0}
    ).sort("_id", 1))

    by_partner = {}
    for d in docs:
        partner = d["to_handle"] if d["from_handle"] == handle else d["from_handle"]
        by_partner.setdefault(partner, []).append(d)

    result = []
    now = time.time()
    for partner, msgs in by_partner.items():
        last = msgs[-1]
        unread = sum(1 for m in msgs if m["to_handle"] == handle and m["status"] != "read")
        partner_user = users.find_one({"handle": partner})
        ls = partner_user.get("last_seen", 0) if partner_user else 0
        result.append({
            "handle": partner,
            "name": partner_user["name"] if partner_user else partner,
            "avatar": partner_user.get("avatar", "") if partner_user else "",
            "tag_emoji": partner_user.get("tag_emoji", "") if partner_user else "",
            "last_type": last["type"],
            "last_content_preview": last["content"][:60] if last["type"] == "text" else "",
            "last_time": last["time"],
            "unread": unread,
            "online": (now - ls) < ONLINE_SECONDS if ls else False,
        })
    return result


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


VALID_KINDS = {"channel", "chat", "voice", "groupe"}
# "chat" kept for legacy worldchat / old groups; new groups use "groupe"


@app.post("/entities/create")
def create_entity(payload: CreateEntityRequest):
    kind = payload.kind
    if kind == "chat":
        kind = "groupe"  # rename: groups are @groupe…
    if kind not in {"channel", "voice", "groupe"}:
        raise HTTPException(status_code=400, detail="Invalid kind")

    suffix = clean_handle(payload.handle)
    if not re.match(r"^[A-Za-z0-9_-]{2,20}$", suffix):
        raise HTTPException(status_code=400, detail="Invalid handle format")

    full_handle = kind + suffix
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
        "entity_id": entity_id, "kind": kind, "name": name, "handle": full_handle,
        "creator_handle": creator, "members": [creator],
    }
    if kind == "voice":
        doc["max_members"] = 10
        doc["talking"] = {}
    entities.insert_one(doc)
    return {"entity_id": entity_id, "kind": kind, "name": name, "handle": full_handle}


@app.post("/entities/join")
def join_entity(payload: JoinEntityRequest):
    handle = clean_handle(payload.handle)
    member = clean_handle(payload.member_handle)
    entity = entities.find_one({"handle": handle})
    if not entity:
        raise HTTPException(status_code=404, detail="Not found")

    if entity.get("kind") == "voice":
        max_m = entity.get("max_members", 10)
        members = entity.get("members") or []
        if member not in members and len(members) >= max_m:
            raise HTTPException(status_code=403, detail="Voice room is full")

    entities.update_one({"handle": handle}, {"$addToSet": {"members": member}})
    entity = entities.find_one({"handle": handle}, {"_id": 0})
    return entity


@app.post("/entities/leave")
def leave_entity(payload: JoinEntityRequest):
    handle = clean_handle(payload.handle)
    member = clean_handle(payload.member_handle)
    entities.update_one({"handle": handle}, {"$pull": {"members": member}})
    entities.update_one({"handle": handle}, {"$unset": {f"talking.{member}": ""}})
    return {"status": "ok"}


@app.get("/entities/mine/{handle}")
def my_entities(handle: str):
    handle = clean_handle(handle)
    docs = list(entities.find({"members": handle}, {"_id": 0}))
    return docs


@app.get("/entities/{handle}")
def get_entity(handle: str):
    entity = entities.find_one({"handle": clean_handle(handle)}, {"_id": 0})
    if not entity:
        raise HTTPException(status_code=404, detail="Not found")
    return entity


@app.get("/entities/voices/list")
def list_voices():
    docs = list(entities.find({"kind": "voice"}, {"_id": 0}))
    result = []
    for e in docs:
        members = e.get("members") or []
        talking = e.get("talking") or {}
        result.append({
            "entity_id": e.get("entity_id"),
            "name": e["name"],
            "handle": e["handle"],
            "member_count": len(members),
            "max_members": e.get("max_members", 10),
            "talking_count": sum(1 for v in talking.values() if v),
        })
    return result


@app.post("/entities/voice/talk")
def voice_talk(payload: VoiceTalkRequest):
    handle = clean_handle(payload.handle)
    member = clean_handle(payload.member_handle)
    entity = entities.find_one({"handle": handle})
    if not entity or entity.get("kind") != "voice":
        raise HTTPException(status_code=404, detail="Voice not found")
    entities.update_one(
        {"handle": handle},
        {"$set": {f"talking.{member}": bool(payload.talking)}},
    )
    touch_presence(member)
    return {"status": "ok"}


@app.get("/entities/voice/state/{handle}")
def voice_state(handle: str):
    handle = clean_handle(handle)
    entity = entities.find_one({"handle": handle})
    if not entity or entity.get("kind") != "voice":
        raise HTTPException(status_code=404, detail="Voice not found")

    cleanup_ephemeral(handle)
    members = entity.get("members") or []
    talking = entity.get("talking") or {}
    lookup = user_lookup_map(set(members))
    member_list = []
    for m in members:
        info = lookup.get(m, {})
        member_list.append({
            "handle": m,
            "name": info.get("name", m),
            "avatar": info.get("avatar", ""),
            "tag_emoji": info.get("tag_emoji", ""),
            "talking": bool(talking.get(m)),
            "online": info.get("online", False),
        })

    eph = list(voice_ephemeral.find(
        {"entity_handle": handle, "expires_at": {"$gt": time.time()}},
        {"_id": 0},
    ).sort("created_at", 1))
    for e in eph:
        info = lookup.get(e["from_handle"], {})
        e["from_name"] = info.get("name", e["from_handle"])
        e["from_avatar"] = info.get("avatar", "")

    return {
        "name": entity["name"],
        "handle": entity["handle"],
        "max_members": entity.get("max_members", 10),
        "members": member_list,
        "ephemeral": eph,
    }


@app.post("/entities/voice/ephemeral")
def send_ephemeral(payload: VoiceEphemeralRequest):
    handle = clean_handle(payload.entity_handle)
    from_handle = clean_handle(payload.from_handle)
    content = (payload.content or "").strip()
    if not content or len(content) > 100:
        raise HTTPException(status_code=400, detail="Content must be 1-100 characters")
    entity = entities.find_one({"handle": handle})
    if not entity or entity.get("kind") != "voice":
        raise HTTPException(status_code=404, detail="Voice not found")
    if from_handle not in (entity.get("members") or []):
        raise HTTPException(status_code=403, detail="Not a member")

    cleanup_ephemeral(handle)
    msg_id = str(uuid.uuid4())
    now = time.time()
    doc = {
        "message_id": msg_id,
        "entity_handle": handle,
        "from_handle": from_handle,
        "kind": payload.kind if payload.kind in ("emoji", "text") else "text",
        "content": content,
        "created_at": now,
        "expires_at": now + EPHEMERAL_TTL,
    }
    voice_ephemeral.insert_one(doc)
    touch_presence(from_handle)
    return {"message_id": msg_id, "expires_at": doc["expires_at"]}


@app.post("/entities/messages/send")
def send_entity_message(payload: EntityMessageRequest):
    handle = clean_handle(payload.entity_handle)
    entity = entities.find_one({"handle": handle})
    if not entity:
        raise HTTPException(status_code=404, detail="Entity not found")
    touch_presence(payload.from_handle)
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


VALID_REACTIONS = {"like", "heart", "dislike", "fire"}
REACTION_EMOJI = {"like": "👍", "heart": "❤️", "dislike": "👎", "fire": "🔥"}


@app.post("/posts/create")
def create_post(payload: CreatePostRequest):
    owner = clean_handle(payload.owner_handle)
    if not users.find_one({"handle": owner}):
        raise HTTPException(status_code=404, detail="User not found")
    text = (payload.text or "").strip()
    photo = payload.photo or ""
    if not text and not photo:
        raise HTTPException(status_code=400, detail="Post must have text or photo")
    if len(text) > 300:
        raise HTTPException(status_code=400, detail="Text max 300 characters")
    post_id = str(uuid.uuid4())
    now = time.time()
    doc = {
        "post_id": post_id,
        "owner_handle": owner,
        "text": text,
        "photo": photo,
        "created_at": now,
        "reactions": {},  # handle -> reaction key
    }
    posts.insert_one(doc)
    touch_presence(owner)
    return {
        "post_id": post_id,
        "owner_handle": owner,
        "text": text,
        "photo": photo,
        "created_at": now,
        "reactions": {},
        "reaction_counts": {},
        "my_reaction": None,
        "comments_count": 0,
    }


@app.get("/posts/{handle}")
def get_posts(handle: str, viewer: str = ""):
    handle = clean_handle(handle)
    viewer = clean_handle(viewer) if viewer else ""
    owner = users.find_one({"handle": handle})
    if not owner:
        raise HTTPException(status_code=404, detail="User not found")

    is_owner = viewer == handle
    if not is_owner and not owner.get("allow_view_posts", True):
        return {"posts": [], "allowed": False}

    docs = list(posts.find({"owner_handle": handle}, {"_id": 0}).sort("created_at", -1))
    result = []
    for d in docs:
        reactions = d.get("reactions") or {}
        counts = {}
        for r in reactions.values():
            counts[r] = counts.get(r, 0) + 1
        my_r = reactions.get(viewer) if viewer else None
        cc = post_comments.count_documents({"post_id": d["post_id"]})
        result.append({
            "post_id": d["post_id"],
            "owner_handle": d["owner_handle"],
            "text": d.get("text", ""),
            "photo": d.get("photo", ""),
            "created_at": d.get("created_at", 0),
            "reaction_counts": counts,
            "my_reaction": my_r,
            "comments_count": cc,
        })
    return {
        "posts": result,
        "allowed": True,
        "allow_reactions": owner.get("allow_reactions", True) if not is_owner else True,
        "allow_comments": owner.get("allow_comments", True) if not is_owner else True,
    }


@app.post("/posts/delete")
def delete_post(payload: DeletePostRequest):
    doc = posts.find_one({"post_id": payload.post_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Post not found")
    if doc["owner_handle"] != clean_handle(payload.requester_handle):
        raise HTTPException(status_code=403, detail="Not yours")
    posts.delete_one({"post_id": payload.post_id})
    post_comments.delete_many({"post_id": payload.post_id})
    return {"status": "ok"}


@app.post("/posts/react")
def react_post(payload: ReactPostRequest):
    if payload.reaction not in VALID_REACTIONS:
        raise HTTPException(status_code=400, detail="Invalid reaction")
    post = posts.find_one({"post_id": payload.post_id})
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    reactor = clean_handle(payload.reactor_handle)
    if not users.find_one({"handle": reactor}):
        raise HTTPException(status_code=404, detail="User not found")
    owner = users.find_one({"handle": post["owner_handle"]})
    if reactor != post["owner_handle"] and owner and not owner.get("allow_reactions", True):
        raise HTTPException(status_code=403, detail="Reactions disabled")

    reactions = post.get("reactions") or {}
    # one reaction per user: set or replace
    reactions[reactor] = payload.reaction
    posts.update_one({"post_id": payload.post_id}, {"$set": {"reactions": reactions}})
    touch_presence(reactor)

    counts = {}
    for r in reactions.values():
        counts[r] = counts.get(r, 0) + 1
    return {"status": "ok", "reaction_counts": counts, "my_reaction": payload.reaction}


@app.post("/posts/unreact")
def unreact_post(payload: ReactPostRequest):
    post = posts.find_one({"post_id": payload.post_id})
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    reactor = clean_handle(payload.reactor_handle)
    reactions = post.get("reactions") or {}
    if reactor in reactions:
        del reactions[reactor]
        posts.update_one({"post_id": payload.post_id}, {"$set": {"reactions": reactions}})
    counts = {}
    for r in reactions.values():
        counts[r] = counts.get(r, 0) + 1
    return {"status": "ok", "reaction_counts": counts, "my_reaction": None}


@app.post("/posts/comment")
def comment_post(payload: CommentPostRequest):
    content = (payload.content or "").strip()
    if not content or len(content) > 200:
        raise HTTPException(status_code=400, detail="Comment must be 1-200 characters")
    post = posts.find_one({"post_id": payload.post_id})
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    from_handle = clean_handle(payload.from_handle)
    if not users.find_one({"handle": from_handle}):
        raise HTTPException(status_code=404, detail="User not found")
    owner = users.find_one({"handle": post["owner_handle"]})
    if from_handle != post["owner_handle"] and owner and not owner.get("allow_comments", True):
        raise HTTPException(status_code=403, detail="Comments disabled")

    comment_id = str(uuid.uuid4())
    now = time.time()
    doc = {
        "comment_id": comment_id,
        "post_id": payload.post_id,
        "from_handle": from_handle,
        "content": content,
        "created_at": now,
    }
    post_comments.insert_one(doc)
    touch_presence(from_handle)
    u = users.find_one({"handle": from_handle})
    return {
        "comment_id": comment_id,
        "post_id": payload.post_id,
        "from_handle": from_handle,
        "from_name": u["name"] if u else from_handle,
        "from_avatar": u.get("avatar", "") if u else "",
        "content": content,
        "created_at": now,
    }


@app.get("/posts/comments/{post_id}")
def get_comments(post_id: str):
    docs = list(post_comments.find({"post_id": post_id}, {"_id": 0}).sort("created_at", 1))
    handles = {d["from_handle"] for d in docs}
    lookup = user_lookup_map(handles)
    for d in docs:
        info = lookup.get(d["from_handle"], {})
        d["from_name"] = info.get("name", d["from_handle"])
        d["from_avatar"] = info.get("avatar", "")
    return docs


@app.post("/posts/comment/delete")
def delete_comment(payload: DeleteCommentRequest):
    doc = post_comments.find_one({"comment_id": payload.comment_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Comment not found")
    requester = clean_handle(payload.requester_handle)
    post = posts.find_one({"post_id": doc["post_id"]})
    # author of comment OR owner of post can delete
    if doc["from_handle"] != requester and (not post or post["owner_handle"] != requester):
        raise HTTPException(status_code=403, detail="Not allowed")
    post_comments.delete_one({"comment_id": payload.comment_id})
    return {"status": "ok"}


@app.get("/search")
def search_all(q: str):
    q = q.strip().lstrip("@").lower()
    if not q:
        return {"people": [], "entities": []}

    now = time.time()
    people = list(users.find(
        {"handle": {"$regex": "^" + re.escape(q)}},
        {"_id": 0, "password_hash": 0, "salt": 0},
    ).limit(15))
    for p in people:
        ls = p.get("last_seen", 0)
        p["online"] = (now - ls) < ONLINE_SECONDS if ls else False
        p.pop("last_seen", None)

    ent = list(entities.find(
        {"handle": {"$regex": "^" + re.escape(q)}},
        {"_id": 0},
    ).limit(15))

    return {"people": people, "entities": ent}
