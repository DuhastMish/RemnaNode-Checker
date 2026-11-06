"""Реестр чекеров: регистрация, токены (в базе только хэш), online/offline."""

import hashlib
import hmac
import secrets
import time
import uuid

from . import db, settings

TOKEN_PREFIX = "nck_"


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _new_token() -> str:
    return TOKEN_PREFIX + secrets.token_urlsafe(32)


def create(name):
    """Новый чекер. Возвращает (checker_id, token) — токен показывается один раз."""
    token = _new_token()
    checker_id = str(uuid.uuid4())
    db.x(
        "INSERT INTO checkers(id, name, token_hash, enabled, created_at) VALUES(?,?,?,1,?)",
        (checker_id, name, _hash(token), int(time.time())),
    )
    return checker_id, token


def regenerate(checker_id):
    token = _new_token()
    db.x("UPDATE checkers SET token_hash=? WHERE id=?", (_hash(token), checker_id))
    return token


def set_enabled(checker_id, enabled: bool):
    db.x("UPDATE checkers SET enabled=? WHERE id=?", (1 if enabled else 0, checker_id))


def delete(checker_id):
    db.x("DELETE FROM checkers WHERE id=?", (checker_id,))
    db.x("DELETE FROM node_checker_state WHERE checker_id=?", (checker_id,))
    db.x("DELETE FROM job_checkers WHERE checker_id=?", (checker_id,))


def by_token(token):
    """Чекер по токену (включая отключённые — решение принимает вызывающий)."""
    if not token or not token.startswith(TOKEN_PREFIX):
        return None
    h = _hash(token)
    row = db.q1("SELECT * FROM checkers WHERE token_hash=?", (h,))
    if row and hmac.compare_digest(row["token_hash"], h):
        return dict(row)
    return None


def touch(checker_id, version=None, public_ip=None):
    now = int(time.time())
    if version is not None:
        db.x(
            "UPDATE checkers SET last_seen_at=?, version=?, public_ip=? WHERE id=?",
            (now, version[:40], (public_ip or "")[:64], checker_id),
        )
    else:
        db.x("UPDATE checkers SET last_seen_at=? WHERE id=?", (now, checker_id))


def is_online(row, now=None) -> bool:
    now = now or time.time()
    return (
        bool(row["enabled"])
        and bool(row["last_seen_at"])
        and now - row["last_seen_at"] <= settings.get("checker_offline_sec")
    )


def online_ids():
    now = time.time()
    return [r["id"] for r in db.q("SELECT * FROM checkers") if is_online(r, now)]


def all_checkers():
    now = time.time()
    rows = [dict(r) for r in db.q("SELECT * FROM checkers ORDER BY created_at")]
    for r in rows:
        r["is_online"] = is_online(r, now)
    return rows
