"""Исходящие уведомления: вебхук-алерты и экспорт в источники.

Отправка идёт фоновой очередью (чтобы приём результатов не ждал сеть) и через исходящий VPS, если он задан.
Последние отправки хранятся в памяти и видны в настройках / на странице источников.
"""

import queue
import threading
import time
from collections import deque

import httpx

from . import egress, settings

log = deque(maxlen=30)
_q: "queue.Queue[tuple]" = queue.Queue(maxsize=1000)
_started = False
_start_lock = threading.Lock()


def post_json(url, token, payload, kind, label):
    """Синхронная отправка с записью в лог. Возвращает True при 2xx."""
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    entry = {"ts": int(time.time()), "kind": kind, "label": label}
    try:
        r = httpx.post(url, json=payload, headers=headers, proxy=egress.proxy_url(), timeout=20)
        status = f"HTTP {r.status_code}"
        if not r.is_success:
            body = " ".join(r.text.split())[:100]
            status += f": {body}" if body else ""
        entry.update(ok=r.is_success, status=status)
    except Exception as e:
        entry.update(ok=False, status=str(e)[:120])
    log.appendleft(entry)
    return entry["ok"]


def _worker():
    while True:
        url, token, payload, kind, label = _q.get()
        try:
            post_json(url, token, payload, kind, label)
        finally:
            _q.task_done()


def _ensure_worker():
    global _started
    with _start_lock:
        if not _started:
            threading.Thread(target=_worker, daemon=True, name="alerts").start()
            _started = True


def enqueue(url, token, payload, kind, label):
    if not url:
        return
    _ensure_worker()
    try:
        _q.put_nowait((url, token, payload, kind, label))
    except queue.Full:
        log.appendleft({"ts": int(time.time()), "kind": kind, "label": label, "ok": False, "status": "очередь полна"})


def send_test(url, token):
    """Тестовый вебхук синхронно (кнопка в настройках). Возвращает запись журнала."""
    payload = {
        "type": "test",
        "event": "test",
        "text": "[TEST] nodecheck: проверка вебхука",
        "ts": int(time.time()),
    }
    post_json(url, token, payload, "alert", payload["text"])
    return log[0]


def send_alert(payload):
    """Вебхук-алерт (нода / чекер) на адрес из настроек."""
    label = payload.get("text", "")[:80]
    enqueue(settings.get("alert_webhook_url"), settings.get("alert_webhook_token"), payload, "alert", label)
