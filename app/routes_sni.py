"""Дашборд SNI-доменов хостов (admin и status-режим): плитки, полоса истории, uptime. Без алертов."""

from urllib.parse import quote

from fastapi import APIRouter, Request
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
    start, step = views.history_window()
    by_id: dict = {}
    for r in sni.results_since(start):
        by_id.setdefault(r["sni_id"], []).append(r)
    st = sni.states()
    out = []
    for d in sni.domains():
        s = st.get(d["id"]) or {"color": "grey", "up": 0, "down": 0, "checked_at": None, "status": ""}
        probe = s["color"]
        color = probe if d["is_active"] else "grey"
        hist = views.summarize(by_id[d["id"]], start, step) if d["id"] in by_id else views.EMPTY_HISTORY
        remarks = list(dict.fromkeys(h["remark"] or "без названия" for h in d["hosts"]))
        out.append(
            {
                **d,
                **hist,
                "color": color,
                "probe_color": probe,
                "up": s["up"],
                "down": s["down"],
                "checked_at": s["checked_at"],
                "status": s["status"],
                "remarks": remarks,
                "display": _unicode(d["domain"]),
                "sources": list(dict.fromkeys(h["source"] for h in d["hosts"])),
                "view": "inactive" if not d["is_active"] else views.view_state({"color": color}),
            }
        )
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
    data = rows()
    return views.render(
        request,
        "sni.html",
        rows=data,
        stats=views.stats(data),
        checkers=views.checker_stats() if admin else None,
        enabled=sni.enabled(),
        last_sync=sni.last_sync,
        admin=admin,
        LABEL=LABEL,
        no_access_hint=sni.NO_ACCESS_HINT,
        title="SNI",
    )


@router.post("/sni/sync")
def sni_sync(request: Request):
    auth.require_admin(request)
    if not sni.enabled():
        return RedirectResponse("/sni?msg=Проверка SNI выключена в настройках", status_code=303)
    return RedirectResponse(f"/sni?msg={quote('Сбор SNI-доменов: ' + sni.sync_all())}", status_code=303)
