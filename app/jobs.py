"""Ручные задания на проверку.

Цель задания: {"node_id": <uuid>|None, "address": str, "port": int|None}.
node_id=None — разовая цель (adhoc): в nodes не попадает, домен резолвит сам чекер.
"""

import json
import re
import time

from . import db

TARGET_RE = re.compile(r"^(?P<host>[A-Za-z0-9.\-]{1,253})(?::(?P<port>\d{1,5}))?$")


def parse_target(text):
    """'host', 'ip' или 'host:port' → (host, port|None). None — если мусор."""
    m = TARGET_RE.match((text or "").strip())
    if not m:
        return None
    port = int(m.group("port")) if m.group("port") else None
    if port is not None and not (1 <= port <= 65535):
        return None
    return m.group("host").lower(), port


def target_for_node(node_id):
    n = db.q1("SELECT id, address, fresh_port FROM nodes WHERE id=?", (node_id,))
    if not n or not n["address"]:
        return None
    return {"node_id": n["id"], "address": n["address"], "port": n["fresh_port"]}


def target_from_text(text):
    """Строка из формы → цель. Если адрес совпадает с целью проверки — берём её (с её портом,
    если порт не указан явно)."""
    parsed = parse_target(text)
    if not parsed:
        return None
    host, port = parsed
    n = db.q1("SELECT id, fresh_port FROM nodes WHERE address=? ORDER BY is_active DESC LIMIT 1", (host,))
    if n:
        return {"node_id": n["id"], "address": host, "port": port or n["fresh_port"]}
    return {"node_id": None, "address": host, "port": port}


def create(targets, requested_by):
    targets = [t for t in targets if t]
    if not targets:
        return None
    return db.x(
        "INSERT INTO jobs(targets, requested_by, created_at) VALUES(?,?,?)",
        (json.dumps(targets), requested_by, int(time.time())),
    )


def get(job_id):
    j = db.q1("SELECT * FROM jobs WHERE id=?", (job_id,))
    if not j:
        return None
    j = dict(j)
    j["targets"] = json.loads(j["targets"])
    return j


def pending_with_target(address):
    """Незавершённое задание, в котором уже есть этот адрес (чтобы не плодить дубли со status-страницы)."""
    for j in db.q("SELECT id, targets FROM jobs WHERE status='pending'"):
        if any(t["address"] == address for t in json.loads(j["targets"])):
            return j["id"]
    return None


def results(job_id):
    return [
        dict(r)
        for r in db.q(
            "SELECT r.*, c.name AS checker_name FROM results r LEFT JOIN checkers c ON c.id = r.checker_id "
            "WHERE r.job_id=? ORDER BY r.id",
            (job_id,),
        )
    ]
