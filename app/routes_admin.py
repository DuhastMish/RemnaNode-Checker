"""Логин, admin-режим: плитки, нода, задания, терминал. `/` и `/check` диспетчеризуются по режиму."""
import json
import time

from fastapi import APIRouter, Form, Request
from fastapi.responses import JSONResponse, RedirectResponse

from . import auth, checker, db, routes_status, settings, sources, views

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
    resp.set_cookie(auth.COOKIE, auth.cookie_value(role), max_age=settings.get("cookie_days") * 86400,
                    httponly=True, samesite="lax")
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
    project = request.query_params.get("project", "remnawave")
    if project not in ("remnawave", "open60"):
        project = "remnawave"
    rows = views.nodes_with_state(project)
    return views.render(request, "admin.html", project=project, rows=rows, counts=views.counts(rows),
                        tabs=views.tabs(), running=checker.running, last_sync=sources.last_sync,
                        refresh=30, title="Ноды")


@router.get("/check")
def check_get(request: Request):
    if auth.mode(request) == "status":
        return routes_status.check_page(request)
    return RedirectResponse("/", status_code=303)


@router.post("/check")
def check_post(request: Request, project: str = Form(""), ips: str = Form(""), target: str = Form("")):
    if auth.mode(request) == "status":
        return routes_status.check_post(request, target)
    auth.require_admin(request)
    if target.strip() and not checker.parse_target(target):
        return RedirectResponse(f"/?project={project}&msg=Введи домен, IP или IP:порт", status_code=303)
    if target.strip():
        ip_list = [target.strip()]
    elif ips.strip():
        ip_list = [x.strip() for x in ips.split(",") if x.strip()]
    elif project in ("remnawave", "open60"):
        ip_list = [r["ip"] for r in db.q("SELECT ip FROM nodes WHERE project LIKE ? AND is_active=1", (f"%{project}%",))]
    else:
        ip_list = None
    if ip_list is not None and not ip_list:
        return RedirectResponse(f"/?project={project}&msg=Нет нод для проверки", status_code=303)
    job_id = db.x("INSERT INTO jobs(ips, requested_by, created_at) VALUES(?,?,?)",
                  ("*" if ip_list is None else json.dumps(ip_list), "admin", int(time.time())))
    return RedirectResponse(f"/jobs/{job_id}", status_code=303)


@router.get("/check/json")
def check_json(request: Request, job: int):
    if auth.mode(request) == "status":
        return routes_status.check_json(request, job)
    auth.require_admin(request)
    return job_json(request, job)


# ---------- admin ----------

@router.post("/sync")
def sync(request: Request):
    auth.require_admin(request)
    msg = sources.sync_nodes()
    return RedirectResponse(f"/?msg=Синхронизация: {msg}", status_code=303)


@router.get("/node/{ip}")
def node_page(request: Request, ip: str):
    auth.require_admin(request)
    node = db.q1("SELECT * FROM nodes WHERE ip=?", (ip,))
    if not node:
        return RedirectResponse("/?msg=Нода не найдена", status_code=303)
    hist = [dict(r) for r in db.q("SELECT * FROM results WHERE ip=? ORDER BY id DESC LIMIT 50", (ip,))]
    return views.render(request, "node.html", node=dict(node), hist=hist, title=ip)


@router.get("/jobs/{job_id}")
def job_page(request: Request, job_id: int):
    auth.require_admin(request)
    j = db.q1("SELECT * FROM jobs WHERE id=?", (job_id,))
    if not j:
        return RedirectResponse("/?msg=Задание не найдено", status_code=303)
    return views.render(request, "job.html", job=dict(j), title=f"Проверка #{job_id}")


@router.get("/jobs/{job_id}/json")
def job_json(request: Request, job_id: int):
    auth.require_admin(request)
    j = db.q1("SELECT * FROM jobs WHERE id=?", (job_id,))
    if not j:
        return JSONResponse({"error": "not found"}, status_code=404)
    res = [dict(r) for r in db.q(
        "SELECT r.*, n.name, n.flags FROM results r LEFT JOIN nodes n ON n.ip=r.ip "
        "WHERE r.job_id=? ORDER BY r.id", (job_id,))]
    return JSONResponse({"status": j["status"], "total": j["total"], "done": j["done"], "results": res})


@router.get("/terminal")
def terminal(request: Request):
    auth.require_admin(request)
    return views.render(request, "terminal.html", ttyd_url=settings.get("ttyd_url"), title="Терминал")
