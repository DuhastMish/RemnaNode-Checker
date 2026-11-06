"""Status-режим (PIN): плитки без IP и ручная проверка одной ноды."""
import json
import time

from fastapi import Request
from fastapi.responses import JSONResponse, RedirectResponse

from . import auth, checker, db, settings, views

VERDICT = {"green": "Работает", "yellow": "Жив, но прокси лежит", "red": "Не работает", "grey": "Неизвестно"}


def _public(rows):
    """Срезаем всё, что не нужно публике."""
    return [{"nid": r["nid"], "name": r["name"] or "нода", "project": r["project"], "ip": r["ip"],
             "color": r["color"], "checked_at": r["checked_at"], "flags": r["flags"]} for r in rows]


def index(request: Request):
    auth.require_status(request)
    project = request.query_params.get("project", "remnawave")
    if project not in ("remnawave", "open60"):
        project = "remnawave"
    rows = views.nodes_with_state(project)
    return views.render(request, "status.html", project=project, rows=_public(rows),
                        counts=views.counts(rows), tabs=views.tabs(), refresh=30, title="Статус")


def check_page(request: Request):
    auth.require_status(request)
    rows = _public(views.nodes_with_state())
    job_id = request.query_params.get("job")
    return views.render(request, "status_check.html", rows=rows, job_id=job_id, title="Проверить")


def check_post(request: Request, target: str):
    auth.require_status(request)
    parsed = checker.parse_target(target)
    if not parsed:
        return RedirectResponse("/check?msg=Введи домен, IP или IP:порт", status_code=303)
    host, port = parsed
    ip = checker.resolve(host)
    if not ip:
        return RedirectResponse(f"/check?msg=Не удалось разрешить имя {host}", status_code=303)

    # свежий результат — отдаём его, проверку не запускаем
    cache = settings.get("status_cache_sec")
    last = db.q1("SELECT job_id, ts FROM results WHERE ip=? ORDER BY id DESC LIMIT 1", (ip,))
    if last and last["job_id"] and time.time() - last["ts"] < cache:
        return RedirectResponse(f"/check?job={last['job_id']}&msg=Показан результат проверки меньше {cache} с назад", status_code=303)

    # уже стоит в очереди — ведём туда
    for j in db.q("SELECT id, ips FROM jobs WHERE status IN ('pending','running') AND ips != '*'"):
        for t in json.loads(j["ips"]):
            p = checker.parse_target(t)
            if p and p[0] in (host, ip):
                return RedirectResponse(f"/check?job={j['id']}", status_code=303)

    if not auth.status_check_limit.allow(auth.client_ip(request)):
        return RedirectResponse("/check?msg=Слишком часто. Подожди минуту", status_code=303)
    pending = db.q1("SELECT COUNT(*) AS c FROM jobs WHERE status='pending'")["c"]
    if pending >= 20:
        return RedirectResponse("/check?msg=Очередь заполнена, попробуй позже", status_code=303)

    job_id = db.x("INSERT INTO jobs(ips, requested_by, created_at) VALUES(?,?,?)",
                  (json.dumps([target.strip()]), "status", int(time.time())))
    return RedirectResponse(f"/check?job={job_id}", status_code=303)


def check_json(request: Request, job: int):
    auth.require_status(request)
    j = db.q1("SELECT * FROM jobs WHERE id=?", (job,))
    if not j:
        return JSONResponse({"error": "not found"}, status_code=404)
    res = []
    for r in db.q("SELECT r.*, n.name FROM results r LEFT JOIN nodes n ON n.ip=r.ip WHERE r.job_id=? ORDER BY r.id", (job,)):
        res.append({"name": r["name"] or r["label"] or r["ip"], "ip": r["ip"], "state": r["state"],
                    "verdict": VERDICT.get(r["state"], "Неизвестно"),
                    "ssh": r["ssh_status"], "proxy": r["proxy_status"] or "", "ts": r["ts"]})
    return JSONResponse({"status": j["status"], "total": j["total"], "done": j["done"], "results": res})
