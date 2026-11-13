"""Ручные задания на проверку.

Цель задания: {"node_id": <uuid>|None, "address": str, "port": int|None}.
node_id=None — разовая цель (adhoc): в nodes не попадает, домен резолвит сам чекер.

Задание получают все online-чекеры на момент создания (job_checkers). Чекер забирает его из ответа на
heartbeat, подтверждает taken/done. Задание завершается, когда ответили все, или по job_timeout_sec.
Результаты ручных заданий учитываются в состоянии нод так же, как плановые.
"""

import json
import re
import time

from . import checkers, db, settings

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
    n = db.q1(
        "SELECT id, fresh_port FROM nodes WHERE address=? ORDER BY parent_id IS NOT NULL, is_active DESC LIMIT 1",
        (host,),
    )
    if n:
        return {"node_id": n["id"], "address": host, "port": port or n["fresh_port"]}
    return {"node_id": None, "address": host, "port": port}


def create(targets, requested_by):
    targets = [t for t in targets if t]
    if not targets:
        return None
    now = int(time.time())
    job_id = db.x(
        "INSERT INTO jobs(targets, requested_by, created_at) VALUES(?,?,?)",
        (json.dumps(targets), requested_by, now),
    )
    for cid in checkers.online_ids():
        db.x(
            "INSERT OR IGNORE INTO job_checkers(job_id, checker_id, status, updated_at) VALUES(?,?,'pending',?)",
            (job_id, cid, now),
        )
    return job_id


def pending_for(checker_id):
    """Задания для чекера (ответ на heartbeat). Цели — с актуальной ревизией ноды."""
    out = []
    for j in db.q(
        "SELECT j.id, j.targets FROM job_checkers jc JOIN jobs j ON j.id = jc.job_id "
        "WHERE jc.checker_id=? AND jc.status='pending' AND j.status='pending' ORDER BY j.id",
        (checker_id,),
    ):
        targets = []
        for t in json.loads(j["targets"]):
            item = {"node_id": t.get("node_id"), "address": t["address"], "port": t.get("port"), "rev": None}
            if item["node_id"]:
                n = db.q1("SELECT rev FROM nodes WHERE id=?", (item["node_id"],))
                item["rev"] = n["rev"] if n else None
            targets.append(item)
        out.append({"job_id": j["id"], "targets": targets})
    return out


def ack(job_id, checker_id, status):
    if status not in ("taken", "done"):
        return False
    cur = db.conn().execute(
        "UPDATE job_checkers SET status=?, updated_at=? WHERE job_id=? AND checker_id=?",
        (status, int(time.time()), job_id, checker_id),
    )
    db.conn().commit()
    if status == "done":
        finish_due()
    return cur.rowcount > 0


def finish_due():
    """Завершить задания: ответили все назначенные чекеры или истёк таймаут."""
    now = int(time.time())
    timeout = settings.get("job_timeout_sec")
    for j in db.q("SELECT id, created_at FROM jobs WHERE status='pending'"):
        left = db.q1("SELECT COUNT(*) AS c FROM job_checkers WHERE job_id=? AND status != 'done'", (j["id"],))["c"]
        assigned = db.q1("SELECT COUNT(*) AS c FROM job_checkers WHERE job_id=?", (j["id"],))["c"]
        if (assigned and left == 0) or now - j["created_at"] >= timeout:
            db.x("UPDATE jobs SET status='done', finished_at=? WHERE id=?", (now, j["id"]))


def progress(job_id):
    r = db.q1("SELECT COUNT(*) AS total, SUM(status='done') AS done FROM job_checkers WHERE job_id=?", (job_id,))
    return {"checkers_total": r["total"] or 0, "checkers_done": r["done"] or 0}


def summary(job):
    """Итог по каждой цели без разбивки по чекерам: green — все видят, red — никто, orange — часть.

    Если никто не видит и у всех только прокси не работает — yellow (SSH жив).
    """
    by_target = {}
    for r in results(job["id"]):
        by_target.setdefault((r["node_id"], r["target_address"]), []).append(r)
    out = []
    for t in job["targets"]:
        rows = by_target.get((t.get("node_id"), t["address"]), [])
        up = [r for r in rows if r["state"] == "green"]
        down = [r for r in rows if r["state"] != "green"]
        if not rows:
            color = "grey"
        elif not down:
            color = "green"
        elif up:
            color = "orange"
        else:
            color = "yellow" if all(r["state"] == "yellow" for r in down) else "red"
        sample = (down or up or [None])[0]
        out.append(
            {
                "node_id": t.get("node_id"),
                "address": t["address"],
                "port": t.get("port"),
                "color": color,
                "seen_by": len(up),
                "answered": len(rows),
                "ssh_status": sample["ssh_status"] if sample else "",
                "proxy_status": (sample["proxy_status"] or "") if sample else "",
                "latency_ms": sample["latency_ms"] if sample else None,
            }
        )
    return out


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
