"""Приём результатов чекеров и состояние нод.

Результат одного чекера: green / yellow / red. Негативный — всё, что не green.
Чекер считает ноду упавшей после двух негативных подряд (fail_streak >= 2), один green сбрасывает счётчик.
Защита от разовых сбоев — только для адреса, который этот чекер уже видел живым (seen_alive: SSH прошёл,
green или yellow). Пока не видел — упавшей считается с первого же негативного результата.
Агрегат (цвет плитки) по живым (online) чекерам со свежим результатом:
  нет свежих результатов           → grey
  никто не считает упавшей         → green
  часть считает упавшей            → orange
  все считают упавшей              → red
Неактивная нода (отключена в источнике) тоже проверяется, но цвет плитки у неё всегда grey: инцидентов и
алертов нет. То, что видят чекеры, лежит в node_state.probe_color — по нему видно, можно ли вернуть ноду в дело.
node_state.ok_streak — green подряд у всех online-чекеров; от него зависит оповещение «можно вернуть» (views).
Результат по устаревшей ревизии / не тому адресу сохраняется (stale=1), но в состоянии не учитывается.

Инциденты и алерты (по агрегату):
  orange/red и нет открытого инцидента → открыть, алерт down;
  orange ↔ red при открытом инциденте   → алерт changed;
  green при открытом инциденте          → закрыть, алерт up (с адресом на момент открытия);
  grey (нет данных)                      → инциденты не трогаем и не шлём ничего — пропажу чекеров
                                           покрывает отдельный алерт checker offline/online.
"""

import threading
import time

from . import alerts, checkers, db, settings

FAIL_THRESHOLD = 2
DOWN_COLORS = ("orange", "red")
COLOR_TEXT = {"green": "работает", "orange": "недоступна у части чекеров", "red": "недоступна у всех чекеров"}
_lock = threading.RLock()


def _int(v):
    return v if isinstance(v, int) and not isinstance(v, bool) else None


def _fresh_after(now):
    return now - 3 * settings.get("check_interval_min") * 60


def ingest(checker_id, items):
    """Записать батч результатов. Возвращает (принято, дубли, устаревшие)."""
    accepted = dupes = stale_n = 0
    touched = set()
    with _lock:
        for it in items:
            node_id = it.get("node_id") if isinstance(it.get("node_id"), str) else None
            node = db.q1("SELECT id, address, rev FROM nodes WHERE id=?", (node_id,)) if node_id else None
            if node_id and not node:
                node_id = None  # цели уже нет — сохраняем как разовый результат
            stale = 0
            if node and (it.get("node_rev") != node["rev"] or it.get("target_address") != node["address"]):
                stale = 1
            ts = min(_int(it.get("ts")) or int(time.time()), int(time.time()) + 60)
            ssh = it.get("ssh") if isinstance(it.get("ssh"), dict) else {}
            proxy = it.get("proxy") if isinstance(it.get("proxy"), dict) else {}
            state = it.get("state") if it.get("state") in ("green", "yellow", "red") else "red"
            c = db.conn()
            cur = c.execute(
                "INSERT OR IGNORE INTO results(result_uid, node_id, checker_id, job_id, ts, node_rev, target_address, "
                "target_port, ssh_status, ssh_ok, proxy_status, proxy_ok, latency_ms, state, stale) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    str(it.get("result_uid") or "")[:64] or None,
                    node_id,
                    checker_id,
                    _int(it.get("job_id")),
                    ts,
                    _int(it.get("node_rev")),
                    str(it.get("target_address") or "")[:253],
                    _int(it.get("target_port")),
                    str(ssh.get("status") or "")[:80],
                    1 if ssh.get("ok") else 0,
                    str(proxy.get("status") or "")[:80],
                    None if proxy.get("ok") is None else (1 if proxy.get("ok") else 0),
                    _int(proxy.get("latency_ms")),
                    state,
                    stale,
                ),
            )
            c.commit()
            if cur.rowcount == 0:
                dupes += 1
                continue
            accepted += 1
            if stale:
                stale_n += 1
                continue
            if node:
                _update_checker_state(node_id, checker_id, state, ts)
                touched.add(node_id)
    for node_id in touched:
        recompute(node_id)
    return accepted, dupes, stale_n


def _update_checker_state(node_id, checker_id, state, ts):
    row = db.q1("SELECT * FROM node_checker_state WHERE node_id=? AND checker_id=?", (node_id, checker_id))
    if row and row["last_ts"] and ts < row["last_ts"]:
        return  # пришёл старее уже учтённого
    streak = 0 if state == "green" else ((row["fail_streak"] if row else 0) + 1)
    alive = 1 if state in ("green", "yellow") or (row and row["seen_alive"]) else 0
    prev_ok = row["ok_streak"] if row else 0
    ok = prev_ok + 1 if state == "green" else 0
    ok_since = (row["ok_since"] if prev_ok else ts) if ok else None
    db.x(
        "INSERT INTO node_checker_state(node_id, checker_id, last_state, fail_streak, seen_alive, ok_streak, "
        "ok_since, last_ts) VALUES(?,?,?,?,?,?,?,?) "
        "ON CONFLICT(node_id, checker_id) DO UPDATE SET last_state=excluded.last_state, "
        "fail_streak=excluded.fail_streak, seen_alive=excluded.seen_alive, ok_streak=excluded.ok_streak, "
        "ok_since=excluded.ok_since, last_ts=excluded.last_ts",
        (node_id, checker_id, state, streak, alive, ok, ok_since, ts),
    )


def aggregate(node_id, online=None, now=None):
    """(color, up_count, down_count, last_ts, (ok_streak, ok_since)) по живым чекерам со свежими результатами.

    ok_streak — сколько green подряд у самого «отстающего» из этих чекеров (0, если у кого-то последний не green),
    ok_since — с какого момента все они видят ноду рабочей.
    """
    now = now or time.time()
    online = set(checkers.online_ids() if online is None else online)
    fresh = _fresh_after(now)
    up = down = 0
    last_ts = None
    oks, since = [], []
    for r in db.q("SELECT * FROM node_checker_state WHERE node_id=?", (node_id,)):
        last_ts = max(last_ts or 0, r["last_ts"] or 0) or None
        if r["checker_id"] not in online or not r["last_ts"] or r["last_ts"] < fresh:
            continue
        oks.append(r["ok_streak"] or 0)
        since.append(r["ok_since"])
        if r["fail_streak"] >= (FAIL_THRESHOLD if r["seen_alive"] else 1):
            down += 1
        else:
            up += 1
    ok_streak = min(oks) if oks else 0
    ok_since = max(since) if ok_streak and all(since) else None
    if up + down == 0:
        color = "grey"
    elif down == 0:
        color = "green"
    elif up == 0:
        color = "red"
    else:
        color = "orange"
    return color, up, down, last_ts, (ok_streak, ok_since)


def recompute(node_id, online=None, now=None):
    """Пересчитать агрегат ноды. Возвращает (old_color, new_color).

    node_state.updated_at — время последнего результата (для «проверена N мин назад»).
    """
    probe, up, down, last_ts, (ok_streak, ok_since) = aggregate(node_id, online, now)
    node = db.q1("SELECT is_active FROM nodes WHERE id=?", (node_id,))
    color = probe if node and node["is_active"] else "grey"
    with _lock:
        row = db.q1("SELECT color FROM node_state WHERE node_id=?", (node_id,))
        old = row["color"] if row else "grey"
        db.x(
            "INSERT INTO node_state(node_id, color, probe_color, ok_streak, ok_since, up_count, down_count, "
            "updated_at) VALUES(?,?,?,?,?,?,?,?) "
            "ON CONFLICT(node_id) DO UPDATE SET color=excluded.color, probe_color=excluded.probe_color, "
            "ok_streak=excluded.ok_streak, ok_since=excluded.ok_since, "
            "up_count=excluded.up_count, down_count=excluded.down_count, updated_at=excluded.updated_at",
            (node_id, color, probe, ok_streak, ok_since, up, down, last_ts),
        )
        _incident_step(node_id, old, color, up, down)
    return old, color


def _node_label(node_id):
    rows = db.q(
        "SELECT s.name AS source, sn.source_id, sn.name, sn.external_id, sn.country FROM source_nodes sn "
        "JOIN sources s ON s.id = sn.source_id "
        "WHERE sn.node_id=? ORDER BY sn.is_primary DESC, sn.id",
        (node_id,),
    )
    return [dict(r) for r in rows]


def _incident_step(node_id, old, color, up, down):
    if color == "grey":
        return
    now = int(time.time())
    inc = db.q1("SELECT * FROM incidents WHERE node_id=? AND closed_at IS NULL ORDER BY id DESC LIMIT 1", (node_id,))
    node = db.q1("SELECT address FROM nodes WHERE id=?", (node_id,))
    address = node["address"] if node else ""
    if color in DOWN_COLORS:
        if not inc:
            inc_id = db.x(
                "INSERT INTO incidents(node_id, opened_at, address_at_open, color) VALUES(?,?,?,?)",
                (node_id, now, address, color),
            )
            db.x("UPDATE node_state SET incident_id=? WHERE node_id=?", (inc_id, node_id))
            _alert_node("down", node_id, inc_id, color, old, address, address, up, down)
        elif inc["color"] != color:
            db.x("UPDATE incidents SET color=? WHERE id=?", (color, inc["id"]))
            _alert_node("changed", node_id, inc["id"], color, inc["color"], address, inc["address_at_open"], up, down)
    elif color == "green" and inc:
        db.x("UPDATE incidents SET closed_at=? WHERE id=?", (now, inc["id"]))
        db.x("UPDATE node_state SET incident_id=NULL WHERE node_id=?", (node_id,))
        _alert_node(
            "up",
            node_id,
            inc["id"],
            color,
            inc["color"],
            address,
            inc["address_at_open"],
            up,
            down,
            duration=now - inc["opened_at"],
        )


def _alert_node(event, node_id, incident_id, color, prev, address, address_at_open, up, down, duration=None):
    names = _node_label(node_id)
    title = ", ".join(f"{n['name'] or n['external_id']} ({n['source']})" for n in names) or node_id
    if event == "down":
        text = f"[DOWN] {title} {address}: {COLOR_TEXT[color]} (видят {up} из {up + down})"
    elif event == "changed":
        text = f"[CHANGED] {title} {address}: {COLOR_TEXT.get(prev, prev)} → {COLOR_TEXT[color]} (видят {up} из {up + down})"
    else:
        text = f"[UP] {title} {address}: снова работает, инцидент #{incident_id} длился {max(1, (duration or 0) // 60)} мин"
        if address_at_open and address_at_open != address:
            text += f"; адрес изменён {address_at_open} → {address}"
    alerts.send_alert(
        {
            "type": "node",
            "event": event,
            "text": text,
            "node_id": node_id,
            "incident_id": incident_id,
            "color": color,
            "prev_color": prev,
            "address": address,
            "address_at_open": address_at_open,
            "checkers_up": up,
            "checkers_down": down,
            "sources": names,
            "ts": int(time.time()),
        }
    )


def checker_transitions(now=None):
    """online/offline чекеров: запомнить и прислать алерт (только для включённых)."""
    now = now or time.time()
    for r in db.q("SELECT * FROM checkers"):
        on = checkers.is_online(r, now)
        if bool(r["online"]) == on:
            continue
        db.x("UPDATE checkers SET online=? WHERE id=?", (1 if on else 0, r["id"]))
        if not r["enabled"]:
            continue
        event = "online" if on else "offline"
        vpn = not on and checkers.blocked(r)
        if on:
            detail = " на связи"
        elif vpn:
            detail = f": {checkers.offline_reason(r)}"
        else:
            detail = f" пропал: нет heartbeat с {time.strftime('%H:%M:%S', time.localtime(r['last_seen_at'] or now))}"
        alerts.send_alert(
            {
                "type": "checker",
                "event": event,
                "reason": "country" if vpn else ("" if on else "heartbeat"),
                "text": f"[CHECKER {event.upper()}] {r['name']}{detail}",
                "checker_id": r["id"],
                "name": r["name"],
                "public_ip": r["public_ip"],
                "country": r["geo_country"],
                "last_seen_at": r["last_seen_at"],
                "ts": int(now),
            }
        )


def recompute_all():
    """Периодически: чекеры уходят в offline, результаты устаревают — цвет должен это отражать."""
    now = time.time()
    checker_transitions(now)
    online = checkers.online_ids()
    for r in db.q("SELECT id FROM nodes"):
        recompute(r["id"], online, now)
