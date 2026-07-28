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
pins = db["pins"]

app = FastAPI(title="FreeUniHomos API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

HANDLE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{3,30}$")

# User handles cannot start with these (entity prefixes)
RESERVED_HANDLE_PREFIXES = ("voice", "channel", "groupe", "chat")

WORLD_HANDLE = "worldchat"
WORLD_NAME = "Мировий чат"
ONLINE_SECONDS = 120
EPHEMERAL_TTL = 50


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


def is_reserved_user_handle(handle: str) -> bool:
    h = clean_handle(handle)
    for prefix in RESERVED_HANDLE_PREFIXES:
        if h == prefix or h.startswith(prefix):
            return True
    return False


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
        "is_moderator": bool(u.get("is_moderator", False)),
        "name_color": u.get("name_color", "") or "",
    }


def touch_presence(handle: str):
    users.update_one({"handle": clean_handle(handle)}, {"$set": {"last_seen": time.time()}})


def user_lookup_map(handles: set) -> dict:
    result = {}
    now = time.time()
    for u in users.find({"handle": {"$in": list(handles)}}, {"_id": 0, "handle": 1, "name": 1, "avatar": 1, "tag_emoji": 1, "last_seen": 1, "name_color": 1, "is_moderator": 1}):
        ls = u.get("last_seen", 0)
        result[u["handle"]] = {
            "name": u["name"],
            "avatar": u.get("avatar", ""),
            "tag_emoji": u.get("tag_emoji", ""),
            "online": (now - ls) < ONLINE_SECONDS if ls else False,
            "name_color": u.get("name_color", "") or "",
            "is_moderator": bool(u.get("is_moderator", False)),
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
    name_color: str = ""


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
    if is_reserved_user_handle(handle):
        raise HTTPException(status_code=400, detail="This handle is reserved (cannot start with voice/channel/groupe/chat)")
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
        if is_reserved_user_handle(candidate):
            raise HTTPException(status_code=400, detail="This handle is reserved (cannot start with voice/channel/groupe/chat)")
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

    if payload.name_color is not None and payload.name_color != "":
        # only moderators may set custom name color
        if user.get("is_moderator"):
            c = payload.name_color.strip()[:20]
            update["name_color"] = c
        # non-mods: ignore silently

    if update:
        users.update_one({"handle": handle}, {"$set": update})
        if "handle" in update:
            messages.update_many({"from_handle": handle}, {"$set": {"from_handle": new_handle}})
            messages.update_many({"to_handle": handle}, {"$set": {"to_handle": new_handle}})
            saved.update_many({"owner_handle": handle}, {"$set": {"owner_handle": new_handle}})
            entities.update_many({"creator_handle": handle}, {"$set": {"creator_handle": new_handle}})
            # fix all memberships (not only first match)
            for ent in entities.find({"members": handle}):
                members = [new_handle if m == handle else m for m in (ent.get("members") or [])]
                entities.update_one({"_id": ent["_id"]}, {"$set": {"members": members}})
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


VALID_KINDS = {"channel", "chat", "groupe", "voice"}


@app.post("/entities/create")
def create_entity(payload: CreateEntityRequest):
    kind = payload.kind
    if kind not in VALID_KINDS:
        raise HTTPException(status_code=400, detail="Invalid kind")
    # new groups use kind "groupe" (legacy "chat" still accepted and remapped)
    if kind == "chat":
        kind = "groupe"

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
        "created_at": time.time(),
        "auto_delete_minutes": 0,
        "background": "",
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
    fh = clean_handle(payload.from_handle)
    if is_muted(handle, fh):
        raise HTTPException(status_code=403, detail="You are muted in this chat")
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
        d["from_name_color"] = info.get("name_color", "") or ""
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




class PinMessageRequest(BaseModel):
    kind: str  # dm | entity | saved
    chat_handle: str  # other handle / entity handle / owner handle
    message_id: str
    requester_handle: str


def pin_scope_key(kind: str, chat_handle: str, requester: str) -> str:
    kind = (kind or "").strip().lower()
    h = clean_handle(chat_handle)
    req = clean_handle(requester)
    if kind == "dm":
        return "dm:" + chat_key(req, h)
    if kind == "entity":
        return "entity:" + h
    if kind == "saved":
        return "saved:" + req
    return kind + ":" + h


@app.post("/pins/set")
def set_pin(payload: PinMessageRequest):
    requester = clean_handle(payload.requester_handle)
    if not users.find_one({"handle": requester}):
        raise HTTPException(status_code=404, detail="User not found")
    kind = (payload.kind or "").strip().lower()
    if kind not in ("dm", "entity", "saved"):
        raise HTTPException(status_code=400, detail="Invalid kind")
    scope = pin_scope_key(kind, payload.chat_handle, requester)
    msg_id = payload.message_id
    # verify message exists in the right collection
    doc = None
    if kind == "dm":
        doc = messages.find_one({"message_id": msg_id})
    elif kind == "entity":
        doc = entity_messages.find_one({"message_id": msg_id})
    else:
        doc = saved.find_one({"message_id": msg_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Message not found")
    preview = ""
    mtype = doc.get("type", "text")
    if mtype == "text":
        preview = (doc.get("content") or "")[:120]
    elif mtype == "photo":
        preview = "Фото"
    elif mtype == "voice":
        preview = "Голосове"
    pins.update_one(
        {"scope": scope},
        {"$set": {
            "scope": scope,
            "kind": kind,
            "chat_handle": clean_handle(payload.chat_handle),
            "message_id": msg_id,
            "preview": preview,
            "msg_type": mtype,
            "pinned_by": requester,
            "pinned_at": time.time(),
        }},
        upsert=True,
    )
    return {"status": "ok", "message_id": msg_id, "preview": preview, "msg_type": mtype}


@app.post("/pins/clear")
def clear_pin(payload: PinMessageRequest):
    requester = clean_handle(payload.requester_handle)
    kind = (payload.kind or "").strip().lower()
    scope = pin_scope_key(kind, payload.chat_handle, requester)
    pins.delete_one({"scope": scope})
    return {"status": "ok"}


@app.get("/pins/get")
def get_pin(kind: str, chat_handle: str, requester_handle: str = ""):
    kind = (kind or "").strip().lower()
    scope = pin_scope_key(kind, chat_handle, requester_handle or chat_handle)
    doc = pins.find_one({"scope": scope}, {"_id": 0})
    if not doc:
        return {"pinned": False}
    return {
        "pinned": True,
        "message_id": doc.get("message_id"),
        "preview": doc.get("preview", ""),
        "msg_type": doc.get("msg_type", "text"),
        "pinned_by": doc.get("pinned_by", ""),
        "pinned_at": doc.get("pinned_at", 0),
    }




MOD_SECRET_CODE = "237360049320122092250232257"
mutes = db["mutes"]
reports = db["reports"]
message_reactions = db["message_reactions"]


class BecomeModRequest(BaseModel):
    handle: str
    code: str


class ModDeleteUserRequest(BaseModel):
    requester_handle: str
    target_handle: str


class ModDeleteEntityRequest(BaseModel):
    requester_handle: str
    entity_handle: str


class ModMuteRequest(BaseModel):
    requester_handle: str
    target_handle: str
    entity_handle: str
    minutes: int  # 1 .. 48*60


class ModDeleteMessageRequest(BaseModel):
    requester_handle: str
    message_id: str
    kind: str  # dm | entity | saved


def require_mod(handle: str) -> dict:
    u = users.find_one({"handle": clean_handle(handle)})
    if not u or not u.get("is_moderator"):
        raise HTTPException(status_code=403, detail="Moderator only")
    return u


def is_muted(entity_handle: str, member_handle: str) -> bool:
    doc = mutes.find_one({
        "entity_handle": clean_handle(entity_handle),
        "target_handle": clean_handle(member_handle),
        "until": {"$gt": time.time()},
    })
    return bool(doc)


@app.post("/mod/become")
def become_moderator(payload: BecomeModRequest):
    handle = clean_handle(payload.handle)
    user = users.find_one({"handle": handle})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if (payload.code or "").strip() != MOD_SECRET_CODE:
        raise HTTPException(status_code=403, detail="Wrong code")
    users.update_one({"handle": handle}, {"$set": {"is_moderator": True}})
    return public_user(users.find_one({"handle": handle}))


@app.post("/mod/delete-user")
def mod_delete_user(payload: ModDeleteUserRequest):
    require_mod(payload.requester_handle)
    handle = clean_handle(payload.target_handle)
    if handle == clean_handle(payload.requester_handle):
        raise HTTPException(status_code=400, detail="Cannot delete yourself via mod")
    user = users.find_one({"handle": handle})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    users.delete_one({"handle": handle})
    messages.delete_many({"$or": [{"from_handle": handle}, {"to_handle": handle}]})
    saved.delete_many({"owner_handle": handle})
    entities.update_many({"members": handle}, {"$pull": {"members": handle}})
    post_ids = [p["post_id"] for p in posts.find({"owner_handle": handle}, {"post_id": 1})]
    posts.delete_many({"owner_handle": handle})
    if post_ids:
        post_comments.delete_many({"post_id": {"$in": post_ids}})
    post_comments.delete_many({"from_handle": handle})
    mutes.delete_many({"$or": [{"target_handle": handle}, {"requester_handle": handle}]})
    return {"status": "ok"}


@app.post("/mod/delete-entity")
def mod_delete_entity(payload: ModDeleteEntityRequest):
    require_mod(payload.requester_handle)
    handle = clean_handle(payload.entity_handle)
    entity = entities.find_one({"handle": handle})
    if not entity:
        raise HTTPException(status_code=404, detail="Not found")
    if entity.get("is_world"):
        raise HTTPException(status_code=403, detail="Cannot delete world chat")
    entities.delete_one({"handle": handle})
    entity_messages.delete_many({"entity_handle": handle})
    voice_ephemeral.delete_many({"entity_handle": handle})
    mutes.delete_many({"entity_handle": handle})
    return {"status": "ok"}


@app.post("/mod/mute")
def mod_mute(payload: ModMuteRequest):
    require_mod(payload.requester_handle)
    minutes = int(payload.minutes)
    if minutes < 1 or minutes > 48 * 60:
        raise HTTPException(status_code=400, detail="Mute must be 1 minute to 48 hours")
    entity_handle = clean_handle(payload.entity_handle)
    target = clean_handle(payload.target_handle)
    entity = entities.find_one({"handle": entity_handle})
    if not entity:
        raise HTTPException(status_code=404, detail="Entity not found")
    until = time.time() + minutes * 60
    mutes.update_one(
        {"entity_handle": entity_handle, "target_handle": target},
        {"$set": {
            "entity_handle": entity_handle,
            "target_handle": target,
            "until": until,
            "by": clean_handle(payload.requester_handle),
            "minutes": minutes,
        }},
        upsert=True,
    )
    return {"status": "ok", "until": until}


@app.post("/mod/delete-message")
def mod_delete_message(payload: ModDeleteMessageRequest):
    require_mod(payload.requester_handle)
    kind = (payload.kind or "").strip().lower()
    mid = payload.message_id
    if kind == "dm":
        messages.delete_one({"message_id": mid})
    elif kind == "entity":
        entity_messages.delete_one({"message_id": mid})
    elif kind == "saved":
        saved.delete_one({"message_id": mid})
    else:
        raise HTTPException(status_code=400, detail="Invalid kind")
    return {"status": "ok"}


@app.post("/mod/delete-post")
def mod_delete_post(payload: DeletePostRequest):
    require_mod(payload.requester_handle)
    posts.delete_one({"post_id": payload.post_id})
    post_comments.delete_many({"post_id": payload.post_id})
    return {"status": "ok"}


@app.post("/mod/delete-comment")
def mod_delete_comment(payload: DeleteCommentRequest):
    require_mod(payload.requester_handle)
    post_comments.delete_one({"comment_id": payload.comment_id})
    return {"status": "ok"}




class ReportCreateRequest(BaseModel):
    from_handle: str
    target_type: str  # user | entity | message | post
    target_handle: str = ""
    target_id: str = ""
    reason: str


class ReportReplyRequest(BaseModel):
    report_id: str
    requester_handle: str
    reply: str


class MsgReactRequest(BaseModel):
    message_id: str
    reactor_handle: str
    emoji: str
    kind: str  # dm | entity | saved


class EntityUpdateRequest(BaseModel):
    entity_handle: str
    requester_handle: str
    new_name: str = ""
    new_handle_suffix: str = ""
    auto_delete_minutes: int | None = None
    background: str = ""


@app.post("/reports/create")
def create_report(payload: ReportCreateRequest):
    reason = (payload.reason or "").strip()
    if not reason or len(reason) > 300:
        raise HTTPException(status_code=400, detail="Reason must be 1-300 characters")
    fh = clean_handle(payload.from_handle)
    if not users.find_one({"handle": fh}):
        raise HTTPException(status_code=404, detail="User not found")
    rid = str(uuid.uuid4())
    doc = {
        "report_id": rid,
        "from_handle": fh,
        "target_type": payload.target_type,
        "target_handle": clean_handle(payload.target_handle) if payload.target_handle else "",
        "target_id": payload.target_id or "",
        "reason": reason,
        "created_at": time.time(),
        "status": "open",
        "mod_reply": "",
        "replied_by": "",
        "replied_at": 0,
    }
    reports.insert_one(doc)
    return {"status": "ok", "report_id": rid}


@app.get("/reports/list")
def list_reports(requester_handle: str = ""):
    require_mod(requester_handle)
    docs = list(reports.find({}, {"_id": 0}).sort("created_at", -1).limit(100))
    handles = set()
    for d in docs:
        handles.add(d.get("from_handle", ""))
        if d.get("target_handle"):
            handles.add(d["target_handle"])
    lookup = user_lookup_map(handles)
    for d in docs:
        fi = lookup.get(d.get("from_handle", ""), {})
        d["from_name"] = fi.get("name", d.get("from_handle", ""))
        ti = lookup.get(d.get("target_handle", ""), {})
        d["target_name"] = ti.get("name", d.get("target_handle", ""))
    return docs


@app.get("/reports/mine")
def my_reports(handle: str = ""):
    h = clean_handle(handle)
    docs = list(reports.find({"from_handle": h}, {"_id": 0}).sort("created_at", -1).limit(50))
    return docs


@app.post("/reports/reply")
def reply_report(payload: ReportReplyRequest):
    require_mod(payload.requester_handle)
    reply = (payload.reply or "").strip()
    if not reply or len(reply) > 200:
        raise HTTPException(status_code=400, detail="Reply 1-200 characters")
    doc = reports.find_one({"report_id": payload.report_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Report not found")
    reports.update_one({"report_id": payload.report_id}, {"$set": {
        "mod_reply": reply,
        "status": "answered",
        "replied_by": clean_handle(payload.requester_handle),
        "replied_at": time.time(),
    }})
    return {"status": "ok"}


@app.get("/entities/stats/{handle}")
def entity_stats(handle: str):
    handle = clean_handle(handle)
    entity = entities.find_one({"handle": handle}, {"_id": 0})
    if not entity:
        raise HTTPException(status_code=404, detail="Not found")
    msg_count = entity_messages.count_documents({"entity_handle": handle})
    members = entity.get("members") or []
    created = entity.get("created_at") or 0
    return {
        **entity,
        "member_count": len(members),
        "message_count": msg_count,
        "created_at": created,
    }


@app.post("/entities/update")
def update_entity(payload: EntityUpdateRequest):
    handle = clean_handle(payload.entity_handle)
    entity = entities.find_one({"handle": handle})
    if not entity:
        raise HTTPException(status_code=404, detail="Not found")
    req = clean_handle(payload.requester_handle)
    is_mod = bool(users.find_one({"handle": req, "is_moderator": True}))
    is_creator = entity.get("creator_handle") == req
    members = entity.get("members") or []
    is_member = req in members or entity.get("is_world")
    if not is_mod and not is_creator and not is_member:
        raise HTTPException(status_code=403, detail="Not allowed")
    update = {}
    # rename / auto-delete: creator or mod only (worldchat locked for rename)
    if payload.new_name.strip():
        if entity.get("is_world"):
            raise HTTPException(status_code=403, detail="Cannot rename world chat")
        if not is_mod and not is_creator:
            raise HTTPException(status_code=403, detail="Only creator/mod can rename")
        update["name"] = payload.new_name.strip()[:40]
    if payload.auto_delete_minutes is not None:
        if not is_mod and not is_creator:
            raise HTTPException(status_code=403, detail="Only creator/mod can set auto-delete")
        adm = int(payload.auto_delete_minutes)
        if adm not in (0, 1, 3, 5, 10):
            raise HTTPException(status_code=400, detail="auto_delete must be 0,1,3,5,10")
        update["auto_delete_minutes"] = adm
    # background: any member (shared for everyone)
    if payload.background is not None and payload.background != "":
        # allow clearing with special token
        if payload.background == "__clear__":
            update["background"] = ""
        else:
            # limit size roughly (~2.5MB base64)
            if len(payload.background) > 3_500_000:
                raise HTTPException(status_code=400, detail="Image too large")
            update["background"] = payload.background
    if update:
        entities.update_one({"handle": handle}, {"$set": update})
    return entities.find_one({"handle": handle}, {"_id": 0})


# Shared backgrounds for DMs / saved (keyed)
chat_settings = db["chat_settings"]


class ChatBgRequest(BaseModel):
    requester_handle: str
    kind: str  # dm | saved | entity
    peer_handle: str = ""  # for dm: other user; for entity: entity handle; for saved: own handle
    background: str = ""  # data url or "__clear__"


def dm_settings_key(a: str, b: str) -> str:
    xs = sorted([clean_handle(a), clean_handle(b)])
    return "dm:" + xs[0] + ":" + xs[1]


@app.post("/chat/background")
def set_chat_background(payload: ChatBgRequest):
    req = clean_handle(payload.requester_handle)
    if not users.find_one({"handle": req}):
        raise HTTPException(status_code=404, detail="User not found")
    kind = (payload.kind or "").strip().lower()
    bg = payload.background or ""
    if bg and bg != "__clear__" and len(bg) > 3_500_000:
        raise HTTPException(status_code=400, detail="Image too large")
    if bg == "__clear__":
        bg = ""

    if kind == "entity":
        handle = clean_handle(payload.peer_handle)
        entity = entities.find_one({"handle": handle})
        if not entity:
            raise HTTPException(status_code=404, detail="Entity not found")
        members = entity.get("members") or []
        is_mod = bool(users.find_one({"handle": req, "is_moderator": True}))
        if req not in members and not entity.get("is_world") and not is_mod:
            raise HTTPException(status_code=403, detail="Not a member")
        entities.update_one({"handle": handle}, {"$set": {"background": bg}})
        return {"status": "ok", "background": bg, "key": "entity:" + handle}

    if kind == "dm":
        peer = clean_handle(payload.peer_handle)
        if not users.find_one({"handle": peer}):
            raise HTTPException(status_code=404, detail="Peer not found")
        key = dm_settings_key(req, peer)
        chat_settings.update_one(
            {"key": key},
            {"$set": {"key": key, "kind": "dm", "background": bg, "updated_by": req, "updated_at": time.time()}},
            upsert=True,
        )
        return {"status": "ok", "background": bg, "key": key}

    if kind == "saved":
        key = "saved:" + req
        chat_settings.update_one(
            {"key": key},
            {"$set": {"key": key, "kind": "saved", "background": bg, "updated_by": req, "updated_at": time.time()}},
            upsert=True,
        )
        return {"status": "ok", "background": bg, "key": key}

    raise HTTPException(status_code=400, detail="Invalid kind")


@app.get("/chat/background")
def get_chat_background(kind: str = "", requester_handle: str = "", peer_handle: str = ""):
    req = clean_handle(requester_handle)
    kind = (kind or "").strip().lower()
    if kind == "entity":
        handle = clean_handle(peer_handle)
        entity = entities.find_one({"handle": handle}, {"background": 1})
        return {"background": (entity or {}).get("background", "") or ""}
    if kind == "dm":
        peer = clean_handle(peer_handle)
        key = dm_settings_key(req, peer)
        doc = chat_settings.find_one({"key": key}, {"_id": 0, "background": 1})
        return {"background": (doc or {}).get("background", "") or ""}
    if kind == "saved":
        key = "saved:" + req
        doc = chat_settings.find_one({"key": key}, {"_id": 0, "background": 1})
        return {"background": (doc or {}).get("background", "") or ""}
    raise HTTPException(status_code=400, detail="Invalid kind")


@app.post("/messages/react")
def msg_react(payload: MsgReactRequest):
    emoji = (payload.emoji or "").strip()[:8]
    if not emoji:
        raise HTTPException(status_code=400, detail="Empty emoji")
    reactor = clean_handle(payload.reactor_handle)
    mid = payload.message_id
    # store as message_id + reactor -> emoji (one per user)
    message_reactions.update_one(
        {"message_id": mid, "reactor_handle": reactor},
        {"$set": {"message_id": mid, "reactor_handle": reactor, "emoji": emoji, "kind": payload.kind, "ts": time.time()}},
        upsert=True,
    )
    # aggregate
    rows = list(message_reactions.find({"message_id": mid}, {"_id": 0, "emoji": 1, "reactor_handle": 1}))
    counts = {}
    my = None
    for r in rows:
        counts[r["emoji"]] = counts.get(r["emoji"], 0) + 1
        if r["reactor_handle"] == reactor:
            my = r["emoji"]
    return {"status": "ok", "counts": counts, "my_reaction": my}


@app.get("/messages/reactions/{message_id}")
def get_msg_reactions(message_id: str, viewer: str = ""):
    rows = list(message_reactions.find({"message_id": message_id}, {"_id": 0, "emoji": 1, "reactor_handle": 1}))
    counts = {}
    my = None
    viewer = clean_handle(viewer) if viewer else ""
    for r in rows:
        counts[r["emoji"]] = counts.get(r["emoji"], 0) + 1
        if viewer and r["reactor_handle"] == viewer:
            my = r["emoji"]
    return {"counts": counts, "my_reaction": my}


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
