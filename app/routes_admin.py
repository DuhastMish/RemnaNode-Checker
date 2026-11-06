"""Логин, admin-режим: плитки по источникам, карточка ноды и связывание, задания, терминал.
`/` и `/check` диспетчеризуются по режиму."""

from fastapi import APIRouter, Form, Request
from fastapi.responses import JSONResponse, RedirectResponse

from . import auth, db, jobs, nodes, routes_status, settings, sources, views

router = APIRouter()


# ---------- логин ----------


@router.get("/login")
def login_page(request: Request):
    return views.render(request, "login.html", title="Вход")


@router.post("/login")
def login_post(request: Request, credential: str = Form(""), next: str = Form("/")):
    if not auth.login_limit.allow(auth.client_ip(request)):
        return views.render(request, "login.html", error="Слишком много попыток, подожди минуту", title="Вход")
    role = "status" if auth.mode(request) == "status" else "admin"
    if not auth.check_credential(role, credential.strip()):
        return views.render(request, "login.html", error="Неверно", title="Вход")
    if not next.startswith("/") or next.startswith("//"):
        next = "/"
    resp = RedirectResponse(next, status_code=303)
    resp.set_cookie(
        auth.COOKIE, auth.cookie_value(role), max_age=settings.get("cookie_days") * 86400, httponly=True, samesite="lax"
    )
    return resp


@router.get("/logout")
def logout(request: Request):
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie(auth.COOKIE)
    return resp


# ---------- главная (диспетчер по режиму) ----------


@router.get("/")
def index(request: Request):
    if auth.mode(request) == "status":
        return routes_status.index(request)
    auth.require_admin(request)
    tabs = views.tabs()
    source_id = views.current_tab(request, tabs)
    rows = views.nodes_with_state(source_id) if source_id is not None else []
    return views.render(
        request,
        "admin.html",
        source=sources.get(source_id) if source_id else None,
        rows=rows,
        counts=views.counts(rows),
        tabs=tabs,
        refresh=30,
        title="Ноды",
    )


@router.get("/check")
def check_get(request: Request):
    if auth.mode(request) == "status":
        return routes_status.check_page(request)
    return RedirectResponse("/", status_code=303)


@router.post("/check")
def check_post(request: Request, source_id: str = Form(""), node_id: str = Form(""), target: str = Form("")):
    if auth.mode(request) == "status":
        return routes_status.check_post(request, target)
    auth.require_admin(request)
    if target.strip():
        t = jobs.target_from_text(target)
        if not t:
            return RedirectResponse(f"/?source={source_id}&msg=Введи домен, IP или IP:порт", status_code=303)
        targets = [t]
    elif node_id:
        targets = [jobs.target_for_node(node_id)]
    elif source_id:
        ids = [
            r["node_id"]
            for r in db.q(
                "SELECT DISTINCT n.id AS node_id FROM source_nodes sn JOIN nodes n ON n.id = sn.node_id "
                "WHERE sn.source_id=? AND n.is_active=1",
                (source_id,),
            )
        ]
        targets = [jobs.target_for_node(i) for i in ids]
    else:
        targets = []
    job_id = jobs.create(targets, "admin")
    if not job_id:
        return RedirectResponse("/?msg=Нет нод для проверки", status_code=303)
    return RedirectResponse(f"/jobs/{job_id}", status_code=303)


@router.get("/check/json")
def check_json(request: Request, job: int):
    if auth.mode(request) == "status":
        return routes_status.check_json(request, job)
    auth.require_admin(request)
    return job_json(request, job)


# ---------- admin: синхронизация ----------


@router.post("/sync")
def sync(request: Request, source_id: int = Form(...)):
    auth.require_admin(request)
    ok, msg, _changed = sources.sync_source(source_id)
    return RedirectResponse(
        f"/?source={source_id}&msg=Синхронизация: {msg if ok else 'ошибка — ' + msg}", status_code=303
    )


@router.post("/sn/{sn_id}/sync")
def sync_one(request: Request, sn_id: int):
    auth.require_admin(request)
    sn = db.q1("SELECT node_id FROM source_nodes WHERE id=?", (sn_id,))
    ok, msg, _changed = sources.sync_node(sn_id)
    still = db.q1("SELECT node_id FROM source_nodes WHERE id=?", (sn_id,))
    target = f"/node/{still['node_id']}" if still else "/"
    return RedirectResponse(
        f"{target}?msg=Синхронизация ноды: {msg if ok else 'ошибка — ' + msg}" if sn else "/?msg=Нода не найдена",
        status_code=303,
    )


# ---------- admin: карточка цели проверки и связывание ----------


@router.get("/node/{node_id}")
def node_page(request: Request, node_id: str):
    auth.require_admin(request)
    node = db.q1(
        "SELECT n.*, COALESCE(ns.color, 'grey') AS color, ns.updated_at AS checked_at, "
        "ns.up_count, ns.down_count FROM nodes n LEFT JOIN node_state ns ON ns.node_id = n.id "
        "WHERE n.id=?",
        (node_id,),
    )
    if not node:
        return RedirectResponse("/?msg=Нода не найдена", status_code=303)
    hist = [
        dict(r)
        for r in db.q(
            "SELECT r.*, c.name AS checker_name FROM results r LEFT JOIN checkers c ON c.id = r.checker_id "
            "WHERE r.node_id=? ORDER BY r.id DESC LIMIT 50",
            (node_id,),
        )
    ]
    return views.render(
        request,
        "node.html",
        node=dict(node),
        linked=nodes.linked(node_id),
        hist=hist,
        mismatch=nodes.address_mismatch(node_id),
        same=nodes.same_address_targets(node_id),
        candidates=nodes.link_candidates(node_id),
        title=node["address"] or node_id[:8],
    )


@router.post("/node/{node_id}/link")
def node_link(request: Request, node_id: str, other: str = Form("")):
    auth.require_admin(request)
    ok = nodes.link(node_id, other)
    return RedirectResponse(f"/node/{node_id}?msg={'Связано' if ok else 'Не удалось связать'}", status_code=303)


@router.post("/sn/{sn_id}/unlink")
def sn_unlink(request: Request, sn_id: int):
    auth.require_admin(request)
    sn = db.q1("SELECT node_id FROM source_nodes WHERE id=?", (sn_id,))
    if not sn:
        return RedirectResponse("/?msg=Нода не найдена", status_code=303)
    nodes.unlink(sn_id)
    return RedirectResponse(f"/node/{sn['node_id']}?msg=Связь разорвана", status_code=303)


@router.post("/sn/{sn_id}/primary")
def sn_primary(request: Request, sn_id: int):
    auth.require_admin(request)
    node_id = nodes.set_primary(sn_id)
    if not node_id:
        return RedirectResponse("/?msg=Нода не найдена", status_code=303)
    return RedirectResponse(f"/node/{node_id}?msg=Основная нода изменена", status_code=303)


# ---------- admin: задания ----------


@router.get("/jobs/{job_id}")
def job_page(request: Request, job_id: int):
    auth.require_admin(request)
    j = jobs.get(job_id)
    if not j:
        return RedirectResponse("/?msg=Задание не найдено", status_code=303)
    return views.render(request, "job.html", job=j, title=f"Проверка #{job_id}")


@router.get("/jobs/{job_id}/json")
def job_json(request: Request, job_id: int):
    auth.require_admin(request)
    j = jobs.get(job_id)
    if not j:
        return JSONResponse({"error": "not found"}, status_code=404)
    return JSONResponse({"status": j["status"], "targets": j["targets"], "results": jobs.results(job_id)})


@router.get("/terminal")
def terminal(request: Request):
    auth.require_admin(request)
    return views.render(request, "terminal.html", ttyd_url=settings.get("ttyd_url"), title="Терминал")
