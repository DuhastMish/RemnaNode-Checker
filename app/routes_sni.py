"""Дашборд доменов хостов (SNI и «Адрес»), admin и status-режим: вкладки по источникам Remnawave, плитки,
полоса истории, uptime. Без алертов. Состояние домена общее; вкладка показывает домены хостов своего источника."""

from urllib.parse import quote

from fastapi import APIRouter, Form, Request
from fastapi.responses import RedirectResponse

from . import auth, sni, views

router = APIRouter()

LABEL = {"green": "отвечает 200", "orange": "недоступен у части чекеров", "red": "недоступен", "grey": "нет данных"}


def _unicode(domain):
    """xn--e1afmkfd.xn--p1ai → пример.рф (для показа; чекер ходит по punycode)."""
    try:
        return domain.encode("ascii").decode("idna")
    except UnicodeError:
        return domain


def rows():
    """Все домены с состоянием и историей; хосты — по всем источникам (вкладку выбирает for_source)."""
    start, step = views.history_window()
    by_id: dict = {}
    for r in sni.results_since(start):
        by_id.setdefault(r["sni_id"], []).append(r)
    st = sni.states()
    out = []
    for d in sni.domains():
        s = st.get(d["id"]) or {"color": "grey", "up": 0, "down": 0, "checked_at": None, "status": ""}
        hist = views.summarize(by_id[d["id"]], start, step) if d["id"] in by_id else views.EMPTY_HISTORY
        out.append(
            {
                **d,
                **hist,
                "probe_color": s["color"],
                "up": s["up"],
                "down": s["down"],
                "checked_at": s["checked_at"],
                "status": s["status"],
                "display": _unicode(d["domain"]),
            }
        )
    return out


def for_source(all_rows, source_id):
    """Домены вкладки: те, что есть у хостов этого источника. Активность, хосты и поля — по нему же."""
    out = []
    for r in all_rows:
        hosts = [h for h in r["hosts"] if h.get("source_id") == source_id]
        if not hosts:
            continue
        active = any(not h.get("disabled") for h in hosts)
        color = r["probe_color"] if active else "grey"
        fields = {h.get("field") or "sni" for h in hosts}
        out.append(
            {
                **r,
                "is_active": active,
                "color": color,
                "fields": [sni.FIELD_LABEL[f] for f in sni.FIELDS if f in fields],
                "remarks": list(dict.fromkeys(h["remark"] or "без названия" for h in hosts)),
                "view": "inactive" if not active else views.view_state({"color": color}),
            }
        )
    return out


def tabs(all_rows):
    out = []
    for s in sni.remnawave_sources():
        counts = views.counts(for_source(all_rows, s["id"]))
        out.append({"key": s["id"], "label": s["name"], "counts": counts})
    return out


@router.get("/sni")
def sni_page(request: Request):
    admin = auth.mode(request) == "admin"
    if admin:
        auth.require_admin(request)
    else:
        auth.require_status(request)
        if not sni.enabled():
            return RedirectResponse("/", status_code=303)
    all_rows = rows()
    tab_list = tabs(all_rows)
    source_id = views.current_tab(request, tab_list)
    data = for_source(all_rows, source_id) if source_id is not None else []
    last = sni.last_sync
    return views.render(
        request,
        "sni.html",
        rows=data,
        tabs=tab_list,
        source_id=source_id,
        stats=views.stats(data),
        checkers=views.checker_stats() if admin else None,
        enabled=sni.enabled(),
        last_sync=last,
        no_access=[n for n in last.get("no_access", []) if n["source_id"] == source_id],
        invalid=[i for i in last.get("invalid", []) if source_id in i["source_ids"]],
        admin=admin,
        LABEL=LABEL,
        no_access_hint=sni.NO_ACCESS_HINT,
        title="SNI",
    )


@router.post("/sni/sync")
def sni_sync(request: Request, source_id: str = Form("")):
    auth.require_admin(request)
    back = f"/sni?source={quote(source_id)}&" if source_id.isdigit() else "/sni?"
    if not sni.enabled():
        return RedirectResponse(back + "msg=" + quote("Проверка SNI выключена в настройках"), status_code=303)
    return RedirectResponse(back + "msg=" + quote("Сбор доменов: " + sni.sync_all()), status_code=303)
