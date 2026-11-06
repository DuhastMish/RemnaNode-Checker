"""Status-режим (PIN): плитки по источникам и ручная проверка одной цели."""
import time

from fastapi import Request
from fastapi.responses import JSONResponse, RedirectResponse

from . import auth, db, jobs, settings, views

VERDICT = {"green": "Работает", "yellow": "Жив, но прокси лежит", "orange": "Доступна не у всех чекеров",
           "red": "Не работает", "grey": "Неизвестно"}


def _public(rows):
    """Срезаем всё, что не нужно публике."""
    return [{"name": r["name"] or "нода", "address": r["address"], "color": r["color"],
             "checked_at": r["checked_at"], "flags": r["flags"]} for r in rows]


def index(request: Request):
    auth.require_status(request)
    tabs = views.tabs()
    source_id = views.current_tab(request, tabs)
    rows = views.nodes_with_state(source_id) if source_id is not None else []
    return views.render(request, "status.html", source_id=source_id, rows=_public(rows),
                        counts=views.counts(rows), tabs=tabs, refresh=30, title="Статус")


def check_page(request: Request):
    auth.require_status(request)
    rows = _public(views.nodes_with_state())
    return views.render(request, "status_check.html", rows=rows, job_id=request.query_params.get("job"),
                        title="Проверить")


def check_post(request: Request, target: str):
    auth.require_status(request)
    t = jobs.target_from_text(target)
    if not t:
        return RedirectResponse("/check?msg=Введи домен, IP или IP:порт", status_code=303)

    # свежий результат ручной проверки — отдаём его, новую не запускаем
    cache = settings.get("status_cache_sec")
    last = db.q1("SELECT job_id, ts FROM results WHERE target_address=? AND job_id IS NOT NULL "
                 "ORDER BY id DESC LIMIT 1", (t["address"],))
    if last and time.time() - last["ts"] < cache:
        return RedirectResponse(f"/check?job={last['job_id']}&msg=Показан результат проверки меньше {cache} с назад",
                                status_code=303)

    # уже стоит в очереди — ведём туда
    existing = jobs.pending_with_target(t["address"])
    if existing:
        return RedirectResponse(f"/check?job={existing}", status_code=303)

    if not auth.status_check_limit.allow(auth.client_ip(request)):
        return RedirectResponse("/check?msg=Слишком часто. Подожди минуту", status_code=303)
    if db.q1("SELECT COUNT(*) AS c FROM jobs WHERE status='pending'")["c"] >= 20:
        return RedirectResponse("/check?msg=Очередь заполнена, попробуй позже", status_code=303)

    job_id = jobs.create([t], "status")
    return RedirectResponse(f"/check?job={job_id}", status_code=303)


def check_json(request: Request, job: int):
    auth.require_status(request)
    j = jobs.get(job)
    if not j:
        return JSONResponse({"error": "not found"}, status_code=404)
    res = [{"name": t["address"], "ip": t["address"], "state": "grey", "verdict": "Ждём чекеры",
            "ssh": "", "proxy": "", "ts": None} for t in j["targets"]]
    by_addr = {}
    for r in jobs.results(job):
        by_addr.setdefault(r["target_address"], []).append(r)
    for item in res:
        rows = by_addr.get(item["ip"])
        if rows:
            last = rows[-1]
            item.update(state=last["state"], verdict=VERDICT.get(last["state"], "Неизвестно"),
                        ssh=last["ssh_status"], proxy=last["proxy_status"] or "", ts=last["ts"])
    return JSONResponse({"status": j["status"], "results": res})
