"""Источники нод: панель Remnawave и Open60 (те же ноды + проверка через прокси)."""
import json
import time
import urllib.error
import urllib.request

from . import db, settings

last_sync = {"ts": None, "msg": ""}


def _get_json(url, headers, timeout=15):
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.load(resp)


def fetch_remnawave():
    token = settings.get("remnawave_token")
    if not token:
        raise RuntimeError("Remnawave: токен не задан")
    data = _get_json(f"{settings.get('remnawave_url').rstrip('/')}/api/nodes", {
        "Authorization": f"Bearer {token}", "Accept": "application/json",
    })
    out = []
    for n in data.get("response", []):
        addr = n.get("address")
        if not addr:
            continue
        flags = []
        if n.get("isDisabled"):
            flags.append("disabled")
        if not n.get("isConnected"):
            flags.append("offline")
        out.append({
            "ip": addr, "project": "remnawave", "name": n.get("name", "") or "",
            "flags": ", ".join(flags), "fresh_port": None,
            "is_active": 0 if n.get("isDisabled") else 1,
        })
    return out


def fetch_open60():
    token = settings.get("open60_token")
    if not token:
        raise RuntimeError("Open60: токен не задан")
    data = _get_json(f"{settings.get('open60_url').rstrip('/')}/admin/nodes", {
        "Authorization": f"Bearer {token}", "Accept": "application/json",
    })
    out = []
    for n in data.get("nodes", []):
        ip = n.get("ip_address")
        if not ip:
            continue
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
        out.append({
            "ip": ip, "project": "open60",
            "name": f"#{n.get('id')} {n.get('country', '')} {n.get('city') or ''}".strip(),
            "flags": ", ".join(flags), "fresh_port": n.get("fresh_port"),
            "is_active": 1 if active else 0,
        })
    return out


def sync_nodes():
    found: dict = {}
    ok = {"remnawave": False, "open60": False}
    errors = []

    for project, fn in (("remnawave", fetch_remnawave), ("open60", fetch_open60)):
        try:
            for n in fn():
                ip = n["ip"]
                if ip in found:
                    cur = found[ip]
                    cur["project"] = f"{cur['project']},{n['project']}"
                    cur["name"] = cur["name"] or n["name"]
                    cur["flags"] = ", ".join(x for x in (cur["flags"], n["flags"]) if x)
                    cur["fresh_port"] = cur["fresh_port"] or n["fresh_port"]
                    cur["is_active"] = cur["is_active"] or n["is_active"]
                else:
                    found[ip] = dict(n)
            ok[project] = True
        except urllib.error.HTTPError as e:
            errors.append(f"{project}: HTTP {e.code}")
        except Exception as e:
            errors.append(f"{project}: {e}")

    now = int(time.time())
    c = db.conn()
    for ip, n in found.items():
        c.execute(
            "INSERT INTO nodes(ip, project, name, flags, fresh_port, is_active, updated_at) "
            "VALUES(?,?,?,?,?,?,?) ON CONFLICT(ip) DO UPDATE SET project=excluded.project, "
            "name=excluded.name, flags=excluded.flags, fresh_port=excluded.fresh_port, "
            "is_active=excluded.is_active, updated_at=excluded.updated_at",
            (ip, n["project"], n["name"], n["flags"], n["fresh_port"], n["is_active"], now),
        )
    # Удаляем ноды, которых больше нет в источнике — только если источник ответил
    for project, good in ok.items():
        if good:
            c.execute(
                "DELETE FROM nodes WHERE project LIKE ? AND updated_at < ?",
                (f"%{project}%", now),
            )
    c.commit()

    counts = {p: sum(1 for n in found.values() if p in n["project"]) for p in ok}
    msg = f"Remnawave: {counts['remnawave']}, Open60: {counts['open60']}"
    if errors:
        msg += " | ошибки: " + "; ".join(errors)
    last_sync["ts"] = now
    last_sync["msg"] = msg
    return msg
