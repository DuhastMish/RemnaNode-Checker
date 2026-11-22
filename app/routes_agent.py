"""API для чекеров: /api/v1/agent/*. Авторизация — Bearer-токен чекера.

Токен даёт доступ только сюда (не к UI). Отключённый чекер получает 403, его результаты не принимаются.
Чекер с IP вне checker_countries (VPN) получает 200, но его результаты отбрасываются (ignored), а задания
не выдаются — для панели он offline (см. checkers.blocked).
Чекеру отдаётся только нужное для проверки: node_id, адрес, порт, ревизия. Без имён, источников, флагов.
"""

import hashlib
import json

from fastapi import APIRouter, HTTPException, Request

from . import auth, checkers, db, jobs, nodes, settings, sni, state

router = APIRouter(prefix="/api/v1/agent")

HEARTBEAT_SEC = 15  # ручные задания доходят до чекера не дольше чем за этот интервал
CONFIG_KEYS = ("check_interval_min", "max_workers", "probes", "proxy_timeout_sec", "proxy_probe_url")

api_limit = auth.RateLimit(240, 60)  # на чекер
bad_token_limit = auth.RateLimit(30, 60)  # на IP с неверным токеном


def _checker(request: Request):
    ip = auth.client_ip(request)
    header = request.headers.get("authorization", "")
    token = header[7:].strip() if header.lower().startswith("bearer ") else ""
    row = checkers.by_token(token)
    if not row:
        if not bad_token_limit.allow(ip):
            raise HTTPException(429, "too many requests")
        raise HTTPException(401, "invalid token")
    if not row["enabled"]:
        raise HTTPException(403, "checker disabled")
    if not api_limit.allow(row["id"]):
        raise HTTPException(429, "too many requests")
    return checkers.observe(row, ip)


def config_payload():
    cfg = {k: settings.get(k) for k in CONFIG_KEYS}
    cfg["heartbeat_sec"] = HEARTBEAT_SEC
    rev = hashlib.sha256(json.dumps(cfg, sort_keys=True).encode()).hexdigest()[:12]
    return rev, cfg


def _revisions():
    return {"config_revision": config_payload()[0], "nodes_revision": nodes.revision()}


async def _body(request: Request):
    try:
        data = await request.json()
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


@router.post("/hello")
async def hello(request: Request):
    ch = _checker(request)
    data = await _body(request)
    checkers.touch(ch["id"], version=str(data.get("version") or ""))
    return {"checker_id": ch["id"], "name": ch["name"], "heartbeat_sec": HEARTBEAT_SEC, **_revisions()}


@router.post("/heartbeat")
def heartbeat(request: Request):
    ch = _checker(request)
    checkers.touch(ch["id"])
    # вне своей страны (VPN) заданий не выдаём: их результаты всё равно будут отброшены
    return {**_revisions(), "jobs": [] if checkers.blocked(ch) else jobs.pending_for(ch["id"])}


@router.get("/config")
def config(request: Request):
    _checker(request)
    rev, cfg = config_payload()
    return {"revision": rev, **cfg}


@router.get("/nodes")
def nodes_list(request: Request):
    _checker(request)
    rows = db.q("SELECT id, address, rev, fresh_port, is_active FROM nodes WHERE address != '' ORDER BY id")
    return {
        "revision": nodes.revision(),
        "nodes": [
            {
                "node_id": r["id"],
                "address": r["address"],
                "rev": r["rev"],
                "fresh_port": r["fresh_port"],
                "is_active": bool(r["is_active"]),
            }
            for r in rows
        ],
    }


@router.post("/results")
async def results(request: Request):
    ch = _checker(request)
    data = await _body(request)
    items = data.get("results")
    if not isinstance(items, list) or len(items) > 5000:
        raise HTTPException(400, "results: list expected (<= 5000)")
    items = [i for i in items if isinstance(i, dict)]
    checkers.touch(ch["id"])
    # вне своей страны (VPN) — не обрабатываем; после возврата — только снятое после возврата
    if checkers.blocked(ch):
        return {"accepted": 0, "duplicates": 0, "stale": 0, "ignored": len(items), "reason": "checker country"}
    since = ch["valid_since"] or 0
    fresh = [i for i in items if not (isinstance(i.get("ts"), int) and i["ts"] < since)]
    ignored = len(items) - len(fresh)
    items = fresh
    # job_id принимаем только для заданий, назначенных этому чекеру
    mine = {r["job_id"] for r in db.q("SELECT job_id FROM job_checkers WHERE checker_id=?", (ch["id"],))}
    for i in items:
        if i.get("job_id") not in mine:
            i["job_id"] = None
    accepted, dupes, stale = state.ingest(ch["id"], items)
    return {"accepted": accepted, "duplicates": dupes, "stale": stale, "ignored": ignored}


@router.post("/jobs/{job_id}/ack")
async def job_ack(request: Request, job_id: int):
    ch = _checker(request)
    data = await _body(request)
    if not jobs.ack(job_id, ch["id"], data.get("status")):
        raise HTTPException(404, "job not assigned to this checker")
    return {"ok": True}


# ---------- SNI-домены (с агента 2.4.0) ----------
# Отдельные эндпоинты: существующий контракт (hello/heartbeat/config/nodes/results) не меняется, старые
# чекеры о SNI не знают и работают как раньше. Новый чекер сам запрашивает /sni перед каждой плановой
# проверкой; у старой панели /sni нет (404) — чекер SNI не проверяет.


@router.get("/sni")
def sni_list(request: Request):
    _checker(request)
    if not sni.enabled():
        return {"enabled": False, "revision": sni.revision(), "timeout_sec": 0, "domains": []}
    return {
        "enabled": True,
        "revision": sni.revision(),
        "timeout_sec": settings.get("sni_timeout_sec"),
        "domains": sni.for_agent(),
    }


def _acceptable(ch, items):
    """SNI-результаты, которые можно учесть (те же правила, что в /results): (items, ignored).

    items=None — чекер вне своей страны (VPN); после возврата принимается только снятое после возврата."""
    items = [i for i in items if isinstance(i, dict)]
    if checkers.blocked(ch):
        return None, len(items)
    since = ch["valid_since"] or 0
    fresh = [i for i in items if not (isinstance(i.get("ts"), int) and i["ts"] < since)]
    return fresh, len(items) - len(fresh)


@router.post("/sni/results")
async def sni_results(request: Request):
    """{results: [{result_uid, sni_id, domain, ts, ok, http_status, status, latency_ms}]}"""
    ch = _checker(request)
    data = await _body(request)
    items = data.get("results")
    if not isinstance(items, list) or len(items) > 5000:
        raise HTTPException(400, "results: list expected (<= 5000)")
    checkers.touch(ch["id"])
    items, ignored = _acceptable(ch, items)
    if items is None:
        return {"accepted": 0, "duplicates": 0, "unknown": 0, "ignored": ignored, "reason": "checker country"}
    accepted, dupes, unknown = sni.ingest(ch["id"], items)
    return {"accepted": accepted, "duplicates": dupes, "unknown": unknown, "ignored": ignored}
