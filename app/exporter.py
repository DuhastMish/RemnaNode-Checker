"""Отправка результатов проверки в бэкенды Remnawave и Open60 (через исходящий VPS, если задан)."""
import time
from collections import deque

import httpx

from . import egress, settings

log = deque(maxlen=20)

TARGETS = (
    ("remnawave", "export_remnawave_url", "export_remnawave_token"),
    ("open60", "export_open60_url", "export_open60_token"),
)


def _item(r):
    return {
        "ip": r["ip"], "name": r.get("name", ""), "state": r["state"],
        "ssh_ok": bool(r["ssh_ok"]), "ssh_status": r["ssh_status"],
        "proxy_ok": None if r["proxy_ok"] is None else bool(r["proxy_ok"]),
        "proxy_status": r["proxy_status"], "latency_ms": r["latency_ms"], "ts": r["ts"],
    }


def push(results, vantage):
    if not settings.get("export_enabled"):
        return
    for project, url_key, tok_key in TARGETS:
        url = settings.get(url_key)
        items = [_item(r) for r in results if project in (r.get("project") or "")]
        if not url or not items:
            continue
        payload = {"vantage": vantage, "ts": int(time.time()), "results": items}
        headers = {"Authorization": f"Bearer {settings.get(tok_key)}"} if settings.get(tok_key) else {}
        entry = {"ts": int(time.time()), "project": project, "count": len(items)}
        try:
            r = httpx.post(url, json=payload, headers=headers, proxy=egress.proxy_url(), timeout=20)
            entry["status"] = f"HTTP {r.status_code}"
            entry["ok"] = r.is_success
        except Exception as e:
            entry["status"] = str(e)[:120]
            entry["ok"] = False
        log.appendleft(entry)
