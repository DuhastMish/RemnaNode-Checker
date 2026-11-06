"""Общее для роутов: шаблоны, выборка нод с текущим состоянием, фильтры."""
import hashlib
import os
import time

from fastapi.templating import Jinja2Templates

from . import auth, db, settings

templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))

COLORS = ("green", "yellow", "red", "grey")
COLOR_LABEL = {"green": "работает", "yellow": "жив, прокси нет", "red": "недоступен", "grey": "нет данных"}


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


def nid(ip: str) -> str:
    """Публичный идентификатор ноды для status-страницы (IP не светим)."""
    return hashlib.sha1(ip.encode()).hexdigest()[:12]


def ip_by_nid(n: str):
    for r in db.q("SELECT ip FROM nodes"):
        if nid(r["ip"]) == n:
            return r["ip"]
    return None


def nodes_with_state(project=None):
    sql = (
        "SELECT n.*, r.state, r.ts AS checked_at, r.ssh_status, r.proxy_status, r.latency_ms "
        "FROM nodes n LEFT JOIN results r ON r.id = "
        "(SELECT id FROM results WHERE ip = n.ip ORDER BY id DESC LIMIT 1)"
    )
    args = ()
    if project:
        sql += " WHERE n.project LIKE ?"
        args = (f"%{project}%",)
    sql += " ORDER BY n.name, n.ip"
    rows = [dict(r) for r in db.q(sql, args)]
    stale_after = settings.get("check_interval_min") * 60 * 3
    now = time.time()
    for r in rows:
        if not r["state"] or (now - (r["checked_at"] or 0)) > stale_after:
            r["color"] = "grey"
        else:
            r["color"] = r["state"]
        r["nid"] = nid(r["ip"])
    return rows


def counts(rows):
    c = {k: 0 for k in COLORS}
    for r in rows:
        c[r["color"]] = c.get(r["color"], 0) + 1
    c["total"] = len(rows)
    return c


def tabs():
    out = []
    for key, label in (("remnawave", "Remnawave"), ("open60", "Open60")):
        rows = nodes_with_state(key)
        out.append({"key": key, "label": label, "counts": counts(rows)})
    return out
