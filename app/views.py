"""Общее для роутов: шаблоны, выборка нод с текущим состоянием, фильтры."""

import os
import time

from fastapi.templating import Jinja2Templates

from . import auth, db, nodes

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


templates.env.filters.update(ago=ago, until=until, dt=dt, hbytes=human_bytes)
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
        "COALESCE(ns.color, 'grey') AS color, ns.updated_at AS checked_at, ns.up_count, ns.down_count, "
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
    for r in rows:
        r["dup"] = r["address"] in dups
        r["mismatch"] = r["linked_count"] > 1 and r["address"] != r["target_address"]
    return rows


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
