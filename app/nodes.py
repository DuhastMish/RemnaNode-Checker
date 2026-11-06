"""Цели проверки (nodes) и их связь с нодами источников (source_nodes).

По умолчанию у каждой ноды источника своя цель. Пользователь может связать несколько нод источников
в одну цель: тогда проверка одна, а атрибуты цели считаются так:
  address    — у основной ноды источника (is_primary=1);
  fresh_port — у основной, а если у неё нет — первый непустой у связанных (Open60 даёт порт прокси);
  is_active  — активна, если активна хоть одна связанная.
Любое изменение этих атрибутов повышает nodes.rev и глобальный nodes_revision.
"""

import threading
import time
import uuid

from . import db

# все изменения nodes/source_nodes идут под этим локом (синхронизация, связывание из UI)
lock = threading.RLock()


def revision() -> int:
    return int(db.kv_get("nodes_revision", "0"))


def _bump_revision():
    db.kv_set("nodes_revision", revision() + 1)


def create_target(now=None) -> str:
    now = now or int(time.time())
    node_id = str(uuid.uuid4())
    db.x(
        "INSERT INTO nodes(id, address, fresh_port, is_active, rev, created_at, updated_at) "
        "VALUES(?, '', NULL, 0, 0, ?, ?)",
        (node_id, now, now),
    )
    return node_id


def _delete_target(node_id):
    for sql in (
        "DELETE FROM nodes WHERE id=?",
        "DELETE FROM node_state WHERE node_id=?",
        "DELETE FROM node_checker_state WHERE node_id=?",
        "UPDATE incidents SET closed_at=? WHERE node_id=? AND closed_at IS NULL",
    ):
        if sql.startswith("UPDATE"):
            db.x(sql, (int(time.time()), node_id))
        else:
            db.x(sql, (node_id,))


def recompute(node_id):
    """Пересчитать атрибуты цели по её нодам источников.

    Возвращает dict(changed, deleted, old_address, new_address).
    """
    with lock:
        sns = [
            dict(r) for r in db.q("SELECT * FROM source_nodes WHERE node_id=? ORDER BY is_primary DESC, id", (node_id,))
        ]
        node = db.q1("SELECT * FROM nodes WHERE id=?", (node_id,))
        if not sns:
            if node:
                _delete_target(node_id)
                _bump_revision()
            return {
                "changed": True,
                "deleted": True,
                "old_address": node["address"] if node else None,
                "new_address": None,
            }
        # ровно одна основная
        primary = sns[0]
        if not primary["is_primary"] or sum(s["is_primary"] for s in sns) != 1:
            db.x("UPDATE source_nodes SET is_primary = (id = ?) WHERE node_id=?", (primary["id"], node_id))
        address = primary["address"] or ""
        port = primary["fresh_port"] or next((s["fresh_port"] for s in sns if s["fresh_port"]), None)
        active = 1 if any(s["is_active"] for s in sns) else 0
        if not node:
            return {"changed": False, "deleted": False, "old_address": None, "new_address": address}
        if (node["address"], node["fresh_port"], node["is_active"]) == (address, port, active):
            return {"changed": False, "deleted": False, "old_address": address, "new_address": address}
        db.x(
            "UPDATE nodes SET address=?, fresh_port=?, is_active=?, rev=rev+1, updated_at=? WHERE id=?",
            (address, port, active, int(time.time()), node_id),
        )
        _bump_revision()
        return {"changed": True, "deleted": False, "old_address": node["address"], "new_address": address}


def link(node_id, other_node_id):
    """Присоединить все ноды источников цели other к цели node_id. Основная остаётся у node_id."""
    if node_id == other_node_id:
        return False
    with lock:
        if not db.q1("SELECT 1 FROM nodes WHERE id=?", (node_id,)) or not db.q1(
            "SELECT 1 FROM nodes WHERE id=?", (other_node_id,)
        ):
            return False
        db.x("UPDATE source_nodes SET node_id=?, is_primary=0 WHERE node_id=?", (node_id, other_node_id))
        recompute(other_node_id)  # пустая → удалится
        recompute(node_id)
        return True


def unlink(source_node_id):
    """Отделить ноду источника в собственную цель проверки."""
    with lock:
        sn = db.q1("SELECT * FROM source_nodes WHERE id=?", (source_node_id,))
        if not sn:
            return None
        if db.q1("SELECT COUNT(*) AS c FROM source_nodes WHERE node_id=?", (sn["node_id"],))["c"] < 2:
            return sn["node_id"]  # и так одна
        new_id = create_target()
        db.x("UPDATE source_nodes SET node_id=?, is_primary=1 WHERE id=?", (new_id, source_node_id))
        recompute(sn["node_id"])
        recompute(new_id)
        return new_id


def set_primary(source_node_id):
    with lock:
        sn = db.q1("SELECT * FROM source_nodes WHERE id=?", (source_node_id,))
        if not sn:
            return None
        db.x("UPDATE source_nodes SET is_primary = (id = ?) WHERE node_id=?", (source_node_id, sn["node_id"]))
        recompute(sn["node_id"])
        return sn["node_id"]


def linked(node_id):
    """Ноды источников, входящие в цель, с именем источника."""
    return [
        dict(r)
        for r in db.q(
            "SELECT sn.*, s.name AS source_name, s.type AS source_type FROM source_nodes sn "
            "JOIN sources s ON s.id = sn.source_id WHERE sn.node_id=? ORDER BY sn.is_primary DESC, sn.id",
            (node_id,),
        )
    ]


def address_mismatch(node_id) -> bool:
    addrs = {r["address"] for r in db.q("SELECT address FROM source_nodes WHERE node_id=?", (node_id,))}
    return len(addrs) > 1


def same_address_targets(node_id):
    """Другие цели с тем же адресом — кандидаты на связывание (панель только подсказывает)."""
    node = db.q1("SELECT address FROM nodes WHERE id=?", (node_id,))
    if not node or not node["address"]:
        return []
    return [
        dict(r)
        for r in db.q(
            "SELECT n.id, n.address, GROUP_CONCAT(s.name || ': ' || sn.name, ', ') AS label "
            "FROM nodes n JOIN source_nodes sn ON sn.node_id = n.id JOIN sources s ON s.id = sn.source_id "
            "WHERE n.address = ? AND n.id != ? GROUP BY n.id",
            (node["address"], node_id),
        )
    ]


def duplicate_addresses() -> set:
    """Адреса, которые встречаются у нескольких разных целей."""
    return {
        r["address"] for r in db.q("SELECT address FROM nodes WHERE address != '' GROUP BY address HAVING COUNT(*) > 1")
    }


def link_candidates(node_id):
    """Все остальные цели для выпадающего списка «связать с…»."""
    return [
        dict(r)
        for r in db.q(
            "SELECT n.id, n.address, GROUP_CONCAT(s.name || ': ' || sn.name, ', ') AS label "
            "FROM nodes n JOIN source_nodes sn ON sn.node_id = n.id JOIN sources s ON s.id = sn.source_id "
            "WHERE n.id != ? GROUP BY n.id ORDER BY label",
            (node_id,),
        )
    ]
