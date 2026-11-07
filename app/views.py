"""Общее для роутов: шаблоны, выборка нод с текущим состоянием, фильтры."""

import os
import time

from fastapi.templating import Jinja2Templates

from . import auth, checkers, db, nodes, settings, state

templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))

# цвета агрегата (плитка); yellow встречается только в отдельных результатах чекеров
COLORS = ("green", "orange", "red", "grey")
COLOR_LABEL = {
    "green": "работает",
    "orange": "недоступна у части чекеров",
    "red": "недоступна",
    "grey": "нет данных",
    "yellow": "жив, прокси нет",
}


def ago(ts):
    if not ts:
        return "—"
    d = int(time.time() - ts)
    if d < 0:
        d = 0
    if d < 60:
        return f"{d} с назад"
    if d < 3600:
        return f"{d // 60} мин назад"
    if d < 86400:
        return f"{d // 3600} ч назад"
    return f"{d // 86400} дн назад"


def until(ts):
    if not ts:
        return "—"
    d = int(ts - time.time())
    if d <= 0:
        return "сейчас"
    if d < 60:
        return f"через {d} с"
    if d < 3600:
        return f"через {d // 60} мин"
    return f"через {d // 3600} ч"


def duration(ts):
    """Сколько прошло с ts: «5 мин», «2 ч 10 мин», «3 дн»."""
    if not ts:
        return "—"
    d = max(0, int(time.time() - ts))
    if d < 60:
        return f"{d} с"
    if d < 3600:
        return f"{d // 60} мин"
    if d < 86400:
        return f"{d // 3600} ч {d % 3600 // 60} мин"
    return f"{d // 86400} дн"


def dt(ts):
    if not ts:
        return "—"
    return time.strftime("%d.%m %H:%M:%S", time.localtime(ts))


def human_bytes(n):
    n = n or 0
    for unit in ("Б", "КБ", "МБ", "ГБ"):
        if n < 1024:
            return f"{n:.0f} {unit}"
        n /= 1024
    return f"{n:.1f} ТБ"


templates.env.filters.update(ago=ago, until=until, dt=dt, hbytes=human_bytes, duration=duration)
templates.env.globals.update(COLORS=COLORS, COLOR_LABEL=COLOR_LABEL)


def render(request, name, **ctx):
    ctx.setdefault("title", "nodecheck")
    ctx.update(request=request, mode=auth.mode(request), msg=request.query_params.get("msg"))
    return templates.TemplateResponse(request, name, ctx)


def nodes_with_state(source_id=None):
    """Ноды источников (плитки) с агрегированным состоянием их цели проверки."""
    sql = (
        "SELECT sn.id AS sn_id, sn.source_id, sn.external_id, sn.name, sn.address, sn.flags, sn.is_active, "
        "sn.is_primary, n.id AS node_id, n.address AS target_address, n.fresh_port, n.rev, "
        "COALESCE(ns.color, 'grey') AS color, COALESCE(ns.probe_color, 'grey') AS probe_color, "
        "n.is_active AS target_active, ns.updated_at AS checked_at, ns.up_count, ns.down_count, "
        "(SELECT opened_at FROM incidents i WHERE i.id = ns.incident_id AND i.closed_at IS NULL) AS incident_since, "
        "(SELECT COUNT(*) FROM source_nodes x WHERE x.node_id = n.id) AS linked_count "
        "FROM source_nodes sn JOIN nodes n ON n.id = sn.node_id "
        "LEFT JOIN node_state ns ON ns.node_id = n.id"
    )
    args = ()
    if source_id is not None:
        sql += " WHERE sn.source_id = ?"
        args = (source_id,)
    sql += " ORDER BY sn.name, sn.address"
    rows = [dict(r) for r in db.q(sql, args)]
    dups = nodes.duplicate_addresses()
    hist = history([r["node_id"] for r in rows])
    for r in rows:
        r["dup"] = r["address"] in dups
        r["mismatch"] = r["linked_count"] > 1 and r["address"] != r["target_address"]
        r.update(hist.get(r["node_id"]) or EMPTY_HISTORY)
        r["view"] = view_state(r)
    return rows


# ---------- история для полосы на карточке ----------

BARS = 30  # палочек в полосе; одна палочка — один интервал плановой проверки
EMPTY_HISTORY = {"bars": [], "uptime": None, "latency": None}


def view_state(r):
    """Для фильтра на странице: up | down | inactive | unknown."""
    if not r.get("target_active", 1):
        return "inactive"
    return {"green": "up", "orange": "down", "red": "down"}.get(r["color"], "unknown")


def _bar(states):
    if not states:
        return "grey"
    ok = sum(1 for s in states if s == "green")
    bad = sum(1 for s in states if s == "red")
    if ok == len(states):
        return "green"
    if bad == len(states):
        return "red"
    if ok == 0 and bad == 0:
        return "yellow"  # SSH есть, прокси нет — у всех чекеров
    return "orange"


def _pct(part, total):
    """99.4 / 100 — без «.0» у целых."""
    v = round(100 * part / total, 1)
    return int(v) if v == int(v) else v


def history(node_ids, now=None):
    """node_id → {bars: [{color, ts, n, ok}], uptime: % ok результатов, latency: средняя задержка прокси, мс}.

    Окно — BARS интервалов плановой проверки; результаты по устаревшей ревизии не учитываются.
    """
    if not node_ids:
        return {}
    now = int(now or time.time())
    step = max(1, settings.get("check_interval_min")) * 60
    start = now - BARS * step
    by_node = {}
    ids = list(dict.fromkeys(node_ids))
    for i in range(0, len(ids), 500):
        chunk = ids[i : i + 500]
        marks = ",".join("?" * len(chunk))
        for r in db.q(
            f"SELECT node_id, ts, state, latency_ms FROM results WHERE node_id IN ({marks}) AND ts > ? AND stale = 0",
            (*chunk, start),
        ):
            by_node.setdefault(r["node_id"], []).append(r)
    out = {}
    for node_id, res in by_node.items():
        buckets = [[] for _ in range(BARS)]
        for r in res:
            buckets[min(BARS - 1, max(0, (r["ts"] - start) // step))].append(r["state"])
        lat = [r["latency_ms"] for r in res if r["latency_ms"] is not None and r["state"] == "green"]
        out[node_id] = {
            "bars": [
                {"color": _bar(b), "ts": start + k * step, "n": len(b), "ok": sum(1 for s in b if s == "green")}
                for k, b in enumerate(buckets)
            ],
            "uptime": _pct(sum(1 for r in res if r["state"] == "green"), len(res)),
            "latency": round(sum(lat) / len(lat)) if lat else None,
        }
    return out


# ---------- «Все системы» и «Активные оповещения» ----------


def stats(rows):
    """Счётчики для плиток «Все системы»: по нодам источника (связанные считаются в каждом своём источнике)."""
    st = {"total": len(rows), "up": 0, "down": 0, "inactive": 0, "unknown": 0}
    for r in rows:
        st[r["view"]] += 1
    lat = [r["latency"] for r in rows if r.get("latency") is not None]
    st["latency"] = round(sum(lat) / len(lat)) if lat else None
    return st


def checker_stats():
    rows = [c for c in checkers.all_checkers() if c["enabled"]]
    return {"online": sum(1 for c in rows if c["is_online"]), "total": len(rows)}


def active_alerts():
    """Открытые инциденты активных нод (по всем источникам) и пропавшие чекеры — для блока на главной."""
    out = []
    for r in db.q(
        "SELECT i.id AS incident_id, i.opened_at, n.id AS node_id, n.address, ns.color, ns.up_count, ns.down_count "
        "FROM incidents i JOIN nodes n ON n.id = i.node_id LEFT JOIN node_state ns ON ns.node_id = n.id "
        "WHERE i.closed_at IS NULL AND n.is_active = 1 ORDER BY i.opened_at DESC"
    ):
        names = state._node_label(r["node_id"])
        up, down = r["up_count"] or 0, r["down_count"] or 0
        out.append(
            {
                "kind": "node",
                "color": r["color"] or "red",
                "title": ", ".join(f"{n['name'] or n['external_id']}" for n in names) or r["address"],
                "sources": ", ".join(dict.fromkeys(n["source"] for n in names)),
                "address": r["address"],
                "text": f"не видят {down} из {up + down} чекеров" if up + down else "нет свежих данных",
                "since": r["opened_at"],
                "href": f"/node/{r['node_id']}",
            }
        )
    for c in checkers.all_checkers():
        if c["enabled"] and not c["is_online"]:
            out.append(
                {
                    "kind": "checker",
                    "color": "red",
                    "title": f"Чекер «{c['name']}»",
                    "sources": "",
                    "address": c["public_ip"] or "",
                    "text": "нет heartbeat" if c["last_seen_at"] else "ещё не подключался",
                    "since": c["last_seen_at"],
                    "href": "/checkers",
                }
            )
    return out


def counts(rows):
    c = {k: 0 for k in COLORS}
    for r in rows:
        c[r["color"]] = c.get(r["color"], 0) + 1
    c["total"] = len(rows)
    return c


def tabs():
    out = []
    for s in db.q("SELECT id, name FROM sources ORDER BY id"):
        out.append({"key": s["id"], "label": s["name"], "counts": counts(nodes_with_state(s["id"]))})
    return out


def current_tab(request, tabs_list):
    """id выбранного источника из ?source=, по умолчанию — первый."""
    try:
        sid = int(request.query_params.get("source", ""))
    except ValueError:
        sid = None
    keys = [t["key"] for t in tabs_list]
    if sid in keys:
        return sid
    return keys[0] if keys else None
