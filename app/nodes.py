"""Цели проверки (nodes) и их связь с нодами источников (source_nodes).

По умолчанию у каждой ноды источника своя цель. Пользователь может связать несколько нод источников
в одну цель: тогда проверка одна, а атрибуты цели считаются так:
  address    — у основной ноды источника (is_primary=1);
  fresh_port — у основной, а если у неё нет — первый непустой у связанных (Open60 даёт порт прокси);
  is_active  — активна, если активна хоть одна связанная.
Любое изменение этих атрибутов повышает nodes.rev и глобальный nodes_revision.
Смена адреса сбрасывает node_checker_state.seen_alive: новый адрес ещё никто не видел живым.

Доп. адреса VPS (Remnawave: поле ips у ноды) — отдельные цели проверки с parent_id = основная цель.
Чекеру они не отличимы от обычных (агент не меняется), но у них нет инцидентов и своих алертов.
Множество: доп. адреса всех связанных нод без повторов и без адреса основной цели — один адрес
проверяется один раз. IPv6 не проверяется: чекер резолвит только IPv4. Статус адреса в Remnawave
не фильтрует проверку, хранится только для показа (ip_status).
Основной адрес сменили на доп. (переключили ноду): состояние чекеров доп. цели переносится в основную —
она сразу видна живой, инцидент закрывается без ожидания; прежний основной, оставшись в доп., получает
состояние основной.
"""

import ipaddress
import json
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


def norm_address(address):
    """IP — в каноническом виде (IPv6 сокращается одинаково), домен — в нижнем регистре."""
    a = (address or "").strip()
    try:
        return str(ipaddress.ip_address(a))
    except ValueError:
        return a.lower()


def extra_addresses(sns, primary_address):
    """Доп. адреса для набора нод источников (основная цель + связанные).

    Возвращает (checked, skipped): checked — {адрес: статус} к проверке, skipped — [{ip, status, reason}]
    с причиной, почему адрес не проверяется отдельно.
    """
    primary = norm_address(primary_address)
    checked, skipped = {}, []
    for sn in sns:
        try:
            items = json.loads(sn.get("ips") or "[]")
        except ValueError:
            items = []
        for i in items:
            ip, status = norm_address(i.get("ip")), i.get("status") or ""
            if ip in checked:
                continue
            if ip == primary:
                skipped.append({"ip": ip, "status": status, "reason": "основной адрес — проверяется один раз"})
            elif ":" in ip:
                skipped.append({"ip": ip, "status": status, "reason": "IPv6 — чекер проверяет только IPv4"})
            else:
                checked[ip] = status
    # один и тот же адрес у нескольких связанных нод — одна строка
    seen, uniq = set(), []
    for s in skipped:
        if s["ip"] not in seen:
            seen.add(s["ip"])
            uniq.append(s)
    return checked, uniq


def extras(node_id):
    """Доп. цели основной цели (с состоянием) — для карточки и плиток."""
    return [
        dict(r)
        for r in db.q(
            "SELECT n.*, COALESCE(ns.probe_color, 'grey') AS probe_color, COALESCE(ns.ok_streak, 0) AS ok_streak, "
            "ns.ok_since, ns.up_count, ns.down_count, ns.updated_at AS checked_at "
            "FROM nodes n LEFT JOIN node_state ns ON ns.node_id = n.id WHERE n.parent_id=? ORDER BY n.created_at, n.id",
            (node_id,),
        )
    ]


def _delete_target(node_id):
    for child in db.q("SELECT id FROM nodes WHERE parent_id=?", (node_id,)):
        _delete_target(child["id"])
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


def _copy_state(rows, to_id):
    for r in rows:
        db.x(
            "INSERT OR REPLACE INTO node_checker_state(node_id, checker_id, last_state, fail_streak, seen_alive, "
            "ok_streak, ok_since, last_ts) VALUES(?,?,?,?,?,?,?,?)",
            (
                to_id,
                r["checker_id"],
                r["last_state"],
                r["fail_streak"],
                r["seen_alive"],
                r["ok_streak"],
                r["ok_since"],
                r["last_ts"],
            ),
        )


def _sync_extras(node_id, sns, address, active, carry=None):
    """Доп. цели основной цели по множеству доп. адресов. carry — (адрес, строки node_checker_state):
    состояние для доп. цели с этим адресом, если она создаётся (прежний основной адрес).

    Возвращает (изменился ли набор целей для чекеров, id новых доп. целей).
    """
    want, _ = extra_addresses(sns, address)
    have = {r["address"]: dict(r) for r in db.q("SELECT * FROM nodes WHERE parent_id=?", (node_id,))}
    changed, new = False, []
    now = int(time.time())
    for addr, row in have.items():
        if addr not in want:
            _delete_target(row["id"])
            changed = True
    for addr, status in want.items():
        row = have.get(addr)
        if not row:
            extra_id = str(uuid.uuid4())
            db.x(
                "INSERT INTO nodes(id, address, fresh_port, is_active, rev, parent_id, ip_status, created_at, "
                "updated_at) VALUES(?,?,NULL,?,1,?,?,?,?)",
                (extra_id, addr, active, node_id, status, now, now),
            )
            if carry and carry[0] == addr:
                _copy_state(carry[1], extra_id)
            new.append(extra_id)
            changed = True
            continue
        if row["ip_status"] != status:
            db.x("UPDATE nodes SET ip_status=? WHERE id=?", (status, row["id"]))  # чекеру не нужен — без ревизии
        if row["is_active"] != active:
            db.x("UPDATE nodes SET is_active=?, rev=rev+1, updated_at=? WHERE id=?", (active, now, row["id"]))
            changed = True
    return changed, new


def recompute(node_id):
    """Пересчитать атрибуты цели и её доп. цели по её нодам источников.

    Возвращает dict(changed, deleted, old_address, new_address, extras_changed, new_extras);
    changed — изменилась сама цель, new_extras — id новых доп. целей (их стоит проверить сразу).
    """
    with lock:
        node = db.q1("SELECT * FROM nodes WHERE id=?", (node_id,))
        if node and node["parent_id"]:
            # доп. цель пересчитывается только вместе с основной
            res = recompute(node["parent_id"])
            return {**res, "changed": False, "deleted": False}
        sns = [
            dict(r) for r in db.q("SELECT * FROM source_nodes WHERE node_id=? ORDER BY is_primary DESC, id", (node_id,))
        ]
        if not sns:
            if node:
                _delete_target(node_id)
                _bump_revision()
            return {
                "changed": True,
                "deleted": True,
                "old_address": node["address"] if node else None,
                "new_address": None,
                "extras_changed": False,
                "new_extras": [],
            }
        # ровно одна основная
        primary = sns[0]
        if not primary["is_primary"] or sum(s["is_primary"] for s in sns) != 1:
            db.x("UPDATE source_nodes SET is_primary = (id = ?) WHERE node_id=?", (primary["id"], node_id))
        address = primary["address"] or ""
        port = primary["fresh_port"] or next((s["fresh_port"] for s in sns if s["fresh_port"]), None)
        active = 1 if any(s["is_active"] for s in sns) else 0
        if not node:
            return {
                "changed": False,
                "deleted": False,
                "old_address": None,
                "new_address": address,
                "extras_changed": False,
                "new_extras": [],
            }
        changed = (node["address"], node["fresh_port"], node["is_active"]) != (address, port, active)
        carry = None
        if changed:
            db.x(
                "UPDATE nodes SET address=?, fresh_port=?, is_active=?, rev=rev+1, updated_at=? WHERE id=?",
                (address, port, active, int(time.time()), node_id),
            )
            if node["address"] != address:
                carry = _switch_address(node_id, node["address"], address)
        extras_changed, new = _sync_extras(node_id, sns, address, active, carry)
        if changed or extras_changed:
            _bump_revision()
        return {
            "changed": changed,
            "deleted": False,
            "old_address": node["address"],
            "new_address": address,
            "extras_changed": extras_changed,
            "new_extras": new,
        }


def _switch_address(node_id, old_address, new_address):
    """Основной адрес сменился. Если новый был доп. адресом — его состояние чекеров переходит основной цели
    (нода сразу видна живой); иначе новый адрес ещё никто не видел живым (seen_alive=0).

    Возвращает (прежний адрес, прежнее состояние основной) — для доп. цели, если прежний адрес остался в доп.
    """
    prev = [dict(r) for r in db.q("SELECT * FROM node_checker_state WHERE node_id=?", (node_id,))]
    extra = db.q1("SELECT id FROM nodes WHERE parent_id=? AND address=?", (node_id, norm_address(new_address)))
    if extra:
        db.x("DELETE FROM node_checker_state WHERE node_id=?", (node_id,))
        db.x("UPDATE node_checker_state SET node_id=? WHERE node_id=?", (node_id, extra["id"]))
    else:
        db.x("UPDATE node_checker_state SET seen_alive=0 WHERE node_id=?", (node_id,))
    return norm_address(old_address), prev


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
        r["address"]
        for r in db.q(
            "SELECT address FROM nodes WHERE address != '' AND parent_id IS NULL GROUP BY address HAVING COUNT(*) > 1"
        )
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
