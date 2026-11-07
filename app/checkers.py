"""Реестр чекеров: регистрация, токены (в базе только хэш), online/offline, геолокация IP.

Страна чекера: если IP чекера не из стран настройки checker_countries (на домашнем ПК включили VPN),
чекер «заблокирован» — считается offline, задания ему не выдаются, его результаты отбрасываются.
После возврата в свою страну (valid_since) принимаются только результаты, снятые после этого момента:
то, что проверялось ещё через VPN, но отправлено уже без него, не учитывается.
"""

import hashlib
import hmac
import json
import secrets
import time
import uuid

from . import db, geoip, settings

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


def touch(checker_id, version=None):
    now = int(time.time())
    if version is not None:
        db.x("UPDATE checkers SET last_seen_at=?, version=? WHERE id=?", (now, version[:40], checker_id))
    else:
        db.x("UPDATE checkers SET last_seen_at=? WHERE id=?", (now, checker_id))


def allowed_countries():
    raw = settings.get("checker_countries") or ""
    return {c.strip().upper() for c in raw.replace(";", ",").split(",") if c.strip()}


def geo(row) -> dict:
    try:
        return json.loads(row["geo"] or "{}")
    except (TypeError, ValueError, KeyError, IndexError):
        return {}


def blocked(row) -> bool:
    """IP чекера из страны вне checker_countries. Страна неизвестна (частный IP, базы нет) — не блокируем."""
    allowed = allowed_countries()
    country = row["geo_country"] or ""
    return bool(allowed and country and country not in allowed)


def observe(row: dict, ip: str) -> dict:
    """Каждый запрос чекера: запомнить IP и его геолокацию. Пересчёт — только при смене IP или баз."""
    ip = (ip or "")[:64]
    ver = geoip.version()
    g = geo(row)
    if ip == row["public_ip"] and g.get("ip") == ip and g.get("db") == ver:
        return row
    info = geoip.lookup(ip) or {}
    was = blocked(row)
    row.update(public_ip=ip, geo=json.dumps({**info, "ip": ip, "db": ver}, ensure_ascii=False))
    row["geo_country"] = info.get("country") or ""
    if was and not blocked(row):
        row["valid_since"] = int(time.time())
    db.x(
        "UPDATE checkers SET public_ip=?, geo=?, geo_country=?, valid_since=? WHERE id=?",
        (row["public_ip"], row["geo"], row["geo_country"], row["valid_since"], row["id"]),
    )
    return row


def is_online(row, now=None) -> bool:
    now = now or time.time()
    return (
        bool(row["enabled"])
        and bool(row["last_seen_at"])
        and now - row["last_seen_at"] <= settings.get("checker_offline_sec")
        and not blocked(row)
    )


def offline_reason(row) -> str:
    """Почему чекер не online — для алертов и списка оповещений."""
    if blocked(row):
        where = geoip.place(geo(row)) or row["geo_country"]
        return f"IP {row['public_ip']} вне {', '.join(sorted(allowed_countries()))} ({where}) — VPN? результаты не учитываются"
    return "нет heartbeat" if row["last_seen_at"] else "ещё не подключался"


def online_ids():
    now = time.time()
    return [r["id"] for r in db.q("SELECT * FROM checkers") if is_online(r, now)]


def all_checkers():
    now = time.time()
    rows = [dict(r) for r in db.q("SELECT * FROM checkers ORDER BY created_at")]
    for r in rows:
        r["is_online"] = is_online(r, now)
        r["blocked"] = blocked(r)
        g = geo(r)
        r["place"] = geoip.place(g) if g.get("ip") == r["public_ip"] else ""
        r["operator"] = geoip.operator(g) if g.get("ip") == r["public_ip"] else ""
    return rows
