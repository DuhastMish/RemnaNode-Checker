"""Источники нод — экземпляры панелей Remnawave / Open60 (таблица sources).

Синхронизация только pull: по расписанию, «Синхронизировать все» для одного источника и
«Синхронизировать ноду» для одной ноды. Ключ ноды источника — (source_id, external_id).
Новая нода источника получает собственную цель проверки; связывание — только вручную (nodes.link).
"""

import json
import time
import urllib.error
import urllib.parse
import urllib.request

from . import db, nodes

TYPES = {"remnawave": "Remnawave", "open60": "Open60"}


class NotFound(Exception):
    """Источник ответил, что такой ноды нет."""


def _get_json(url, token, timeout=15):
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.load(resp)


# ---------- адаптеры типов: всё приводится к {external_id, name, address, flags, fresh_port, is_active} ----------


def _remnawave_item(n):
    flags = []
    if n.get("isDisabled"):
        flags.append("disabled")
    if not n.get("isConnected"):
        flags.append("offline")
    return {
        "external_id": str(n.get("uuid") or ""),
        "name": n.get("name") or "",
        "address": (n.get("address") or "").strip(),
        "flags": ", ".join(flags),
        "fresh_port": None,
        "is_active": 0 if n.get("isDisabled") else 1,
    }


def _open60_item(n):
    active = n.get("is_active", True)
    flags = []
    if not active:
        flags.append("inactive")
    if n.get("quarantined_until"):
        flags.append("quarantine")
    elif n.get("probation_until"):
        flags.append("probation")
    if active and not n.get("has_fresh_port"):
        flags.append("no-port")
    return {
        "external_id": str(n.get("id") or ""),
        "name": f"#{n.get('id')} {n.get('country', '')} {n.get('city') or ''}".strip(),
        "address": (n.get("ip_address") or "").strip(),
        "flags": ", ".join(flags),
        "fresh_port": n.get("fresh_port"),
        "is_active": 1 if active else 0,
    }


def fetch_all(src):
    base = (src["url"] or "").rstrip("/")
    if not base or not src["token"]:
        raise RuntimeError("не заданы URL или токен")
    if src["type"] == "remnawave":
        items = [_remnawave_item(n) for n in _get_json(f"{base}/api/nodes", src["token"]).get("response", [])]
    elif src["type"] == "open60":
        items = [_open60_item(n) for n in _get_json(f"{base}/admin/nodes", src["token"]).get("nodes", [])]
    else:
        raise RuntimeError(f"неизвестный тип {src['type']}")
    return [i for i in items if i["external_id"]]


def fetch_one(src, external_id):
    """Одна нода. Remnawave умеет GET /api/nodes/{uuid}; для Open60 — полный список и выбор из него."""
    base = (src["url"] or "").rstrip("/")
    if src["type"] == "remnawave":
        try:
            data = _get_json(f"{base}/api/nodes/{urllib.parse.quote(external_id)}", src["token"])
        except urllib.error.HTTPError as e:
            if e.code in (400, 404):
                raise NotFound() from e
            raise
        item = _remnawave_item(data.get("response") or {})
        if not item["external_id"]:
            raise NotFound()
        return item
    for item in fetch_all(src):
        if item["external_id"] == external_id:
            return item
    raise NotFound()


# ---------- запись в базу ----------


def _upsert(source_id, item, now):
    """Записать ноду источника. Возвращает node_id её цели проверки."""
    row = db.q1(
        "SELECT id, node_id FROM source_nodes WHERE source_id=? AND external_id=?", (source_id, item["external_id"])
    )
    if row:
        db.x(
            "UPDATE source_nodes SET name=?, address=?, flags=?, fresh_port=?, is_active=?, last_seen_at=? "
            "WHERE id=?",
            (item["name"], item["address"], item["flags"], item["fresh_port"], item["is_active"], now, row["id"]),
        )
        return row["node_id"]
    node_id = nodes.create_target(now)
    db.x(
        "INSERT INTO source_nodes(source_id, external_id, name, address, flags, fresh_port, is_active, "
        "node_id, is_primary, last_seen_at) VALUES(?,?,?,?,?,?,?,?,1,?)",
        (
            source_id,
            item["external_id"],
            item["name"],
            item["address"],
            item["flags"],
            item["fresh_port"],
            item["is_active"],
            node_id,
            now,
        ),
    )
    return node_id


def _set_status(source_id, ok, msg):
    db.x(
        "UPDATE sources SET last_sync_at=?, last_sync_ok=?, last_sync_msg=? WHERE id=?",
        (int(time.time()), 1 if ok else 0, msg[:300], source_id),
    )


def sync_source(source_id):
    """Полная синхронизация одного источника. Возвращает (ok, msg, changed_node_ids)."""
    src = db.q1("SELECT * FROM sources WHERE id=?", (source_id,))
    if not src:
        return False, "источник не найден", []
    try:
        items = fetch_all(src)
    except urllib.error.HTTPError as e:
        _set_status(source_id, False, f"HTTP {e.code}")
        return False, f"HTTP {e.code}", []
    except Exception as e:
        _set_status(source_id, False, str(e))
        return False, str(e)[:200], []

    now = int(time.time())
    touched, changed = set(), []
    with nodes.lock:
        for item in items:
            touched.add(_upsert(source_id, item, now))
        # пропавшие из источника (источник ответил успешно — можно удалять)
        seen = {i["external_id"] for i in items}
        for r in db.q("SELECT id, node_id, external_id FROM source_nodes WHERE source_id=?", (source_id,)):
            if r["external_id"] not in seen:
                db.x("DELETE FROM source_nodes WHERE id=?", (r["id"],))
                touched.add(r["node_id"])
        for node_id in touched:
            if nodes.recompute(node_id)["changed"]:
                changed.append(node_id)
    msg = f"{len(items)} нод, изменилось целей: {len(changed)}"
    _set_status(source_id, True, msg)
    return True, msg, changed


def sync_node(source_node_id):
    """Перезапросить одну ноду из её источника. Возвращает (ok, msg, changed_node_ids)."""
    sn = db.q1("SELECT * FROM source_nodes WHERE id=?", (source_node_id,))
    if not sn:
        return False, "нода не найдена", []
    src = db.q1("SELECT * FROM sources WHERE id=?", (sn["source_id"],))
    try:
        item = fetch_one(src, sn["external_id"])
    except NotFound:
        with nodes.lock:
            db.x("DELETE FROM source_nodes WHERE id=?", (source_node_id,))
            nodes.recompute(sn["node_id"])
        return True, "нода удалена в источнике — убрана из списка", [sn["node_id"]]
    except urllib.error.HTTPError as e:
        return False, f"HTTP {e.code}", []
    except Exception as e:
        return False, str(e)[:200], []
    with nodes.lock:
        node_id = _upsert(src["id"], item, int(time.time()))
        res = nodes.recompute(node_id)
    if res["changed"]:
        msg = "обновлена"
        if res["old_address"] != res["new_address"]:
            msg += f", адрес изменён {res['old_address']} → {res['new_address']}"
        return True, msg, [node_id]
    return True, "без изменений", []


def sync_all():
    """Все источники по очереди (для планировщика). Возвращает сводку и изменённые цели."""
    parts, changed = [], []
    for s in db.q("SELECT id, name FROM sources ORDER BY id"):
        ok, msg, ch = sync_source(s["id"])
        parts.append(f"{s['name']}: {msg if ok else 'ошибка — ' + msg}")
        changed += ch
    return "; ".join(parts) or "источников нет", changed


# ---------- CRUD источников ----------


def all_sources():
    return [dict(r) for r in db.q("SELECT * FROM sources ORDER BY id")]


def get(source_id):
    r = db.q1("SELECT * FROM sources WHERE id=?", (source_id,))
    return dict(r) if r else None


def save(source_id, data):
    """Создать (source_id=None) или обновить источник. Пустой токен при обновлении — не менять."""
    fields = ("type", "name", "url", "token", "export_url", "export_token")
    if source_id is None:
        return db.x(
            "INSERT INTO sources(type, name, url, token, export_url, export_token, created_at) "
            "VALUES(?,?,?,?,?,?,?)",
            (*[data.get(f, "") for f in fields], int(time.time())),
        )
    cur = get(source_id)
    if not cur:
        return None
    upd = {f: data.get(f, cur[f]) for f in fields}
    for secret in ("token", "export_token"):
        if not data.get(secret):
            upd[secret] = cur[secret]
    upd["type"] = cur["type"]  # тип не меняется: external_id разных типов несовместимы
    db.x(
        "UPDATE sources SET name=?, url=?, token=?, export_url=?, export_token=? WHERE id=?",
        (upd["name"], upd["url"], upd["token"], upd["export_url"], upd["export_token"], source_id),
    )
    return source_id


def delete(source_id):
    with nodes.lock:
        ids = [r["node_id"] for r in db.q("SELECT DISTINCT node_id FROM source_nodes WHERE source_id=?", (source_id,))]
        db.x("DELETE FROM source_nodes WHERE source_id=?", (source_id,))
        db.x("DELETE FROM sources WHERE id=?", (source_id,))
        for node_id in ids:
            nodes.recompute(node_id)


def test(source_id):
    src = get(source_id)
    if not src:
        return False, "источник не найден"
    try:
        return True, f"{len(fetch_all(src))} нод"
    except urllib.error.HTTPError as e:
        return False, f"HTTP {e.code}"
    except Exception as e:
        return False, str(e)[:200]
