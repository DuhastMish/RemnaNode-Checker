"""Исходящие уведомления: алерты (вебхук и Telegram) и экспорт в источники.

Каналы алертов настраиваются у каждого источника, оба необязательны и работают параллельно:
  вебхук   — sources.alert_url / alert_token: POST JSON;
  Telegram — sources.tg_token (бот) + tg_chat (@username, @канал или chat_id): тот же text обычным сообщением.
Куда уходят алерты:
  по нодам (инциденты, обрыв трафика) — в каналы каждого источника, где есть нода; у источника ничего не
    задано — его алерты не отправляются;
  по чекерам (offline/online) — в каналы всех источников: без чекеров не проверяются ноды ни одного источника.
Один и тот же адресат (URL+токен, бот+чат) у нескольких источников получает одно сообщение.

Telegram: бот не может написать человеку по @username, пока тот не написал боту (/start), — нужен числовой
chat_id. Его ищем в getUpdates бота по username (Telegram хранит апдейты ~сутки) и запоминаем в tg_chat_id.
Не нашли — шлём на @username: так работает для каналов и публичных групп, где бот — участник/админ.

Отправка идёт фоновой очередью (чтобы приём результатов не ждал сеть) и через исходящий VPS, если он задан
(api.telegram.org из РФ может быть недоступен напрямую). Журнал последних отправок — в памяти.
"""

import queue
import re
import threading
import time
from collections import deque, namedtuple

import httpx

from . import db, egress

TG_API = "https://api.telegram.org"

# channel: webhook | telegram; target: (url, token) | (bot_token, chat); sources: [{id, name, …}]
Route = namedtuple("Route", "channel target sources")

log = deque(maxlen=30)
last_by_source: dict = {}  # (source_id, channel) → последняя отправка алерта
_q: "queue.Queue[tuple]" = queue.Queue(maxsize=1000)
_started = False
_start_lock = threading.Lock()


def _mask(text):
    """Токен бота в URL Telegram не должен попасть в журнал."""
    return re.sub(r"bot\d+:[A-Za-z0-9_-]+", "bot***", str(text))


def post_json(url, token, payload, kind, label, source_ids=(), channel="webhook", source=None):
    """Синхронная отправка с записью в журнал. Возвращает True при 2xx."""
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    entry = {
        "ts": int(time.time()),
        "kind": kind,
        "channel": channel,
        "label": label,
        "source": payload.get("source", "") if source is None else source,
    }
    try:
        r = httpx.post(url, json=payload, headers=headers, proxy=egress.proxy_url(), timeout=20)
        status = f"HTTP {r.status_code}"
        if not r.is_success:
            try:
                body = r.json().get("description") if channel == "telegram" else None
            except Exception:
                body = None
            body = body or " ".join(r.text.split())[:100]
            status += f": {body}" if body else ""
        entry.update(ok=r.is_success, status=_mask(status))
    except Exception as e:
        entry.update(ok=False, status=_mask(e)[:120] or type(e).__name__)
    log.appendleft(entry)
    for sid in source_ids:
        last_by_source[(sid, channel)] = entry
    return entry["ok"]


# ---------- Telegram ----------


def tg_normalize(chat):
    """'@user' / 'user' / 'https://t.me/user' → 'user'; chat_id ('123', '-100…') — как есть."""
    c = (chat or "").strip()
    c = re.sub(r"^(https?://)?t\.me/", "", c)
    return c.lstrip("@").strip()


def tg_target(chat):
    """Куда слать без известного chat_id: chat_id как есть, иначе @username."""
    c = tg_normalize(chat)
    return c if re.fullmatch(r"-?\d+", c) else "@" + c


def tg_resolve(bot, chat):
    """chat_id по username из getUpdates бота. (chat_id | None, ошибка | None); None без ошибки — не нашли."""
    c = tg_normalize(chat)
    if not c:
        return None, "не указано, кому слать"
    if re.fullmatch(r"-?\d+", c):
        return c, None
    try:
        r = httpx.get(f"{TG_API}/bot{bot}/getUpdates", proxy=egress.proxy_url(), timeout=20)
        data = r.json()
    except Exception as e:
        return None, _mask(e)[:120] or type(e).__name__
    if not data.get("ok"):
        return None, data.get("description") or f"HTTP {r.status_code}"
    for upd in reversed(data.get("result") or []):
        for m in upd.values():
            if not isinstance(m, dict):
                continue
            ch, fr = m.get("chat") or {}, m.get("from") or {}
            if (ch.get("username") or "").lower() == c.lower():
                return str(ch["id"]), None
            if ch.get("type") == "private" and (fr.get("username") or "").lower() == c.lower():
                return str(ch["id"]), None
    return None, None


def _remember_chat(source_ids, chat_id):
    for sid in source_ids:
        db.x("UPDATE sources SET tg_chat_id=? WHERE id=?", (chat_id, sid))


def tg_send(bot, chat, text, label, source_ids=(), source=""):
    """Сообщение в Telegram (синхронно). @username без известного chat_id сначала пробуем найти в getUpdates."""
    if not re.fullmatch(r"-?\d+", chat):
        chat_id, _ = tg_resolve(bot, chat)
        if chat_id:
            _remember_chat(source_ids, chat_id)
            chat = chat_id
    payload = {"chat_id": chat, "text": text, "disable_web_page_preview": True}
    return post_json(f"{TG_API}/bot{bot}/sendMessage", None, payload, "alert", label, source_ids, "telegram", source)


def tg_test(src, bot, chat):
    """Кнопка «Проверить Telegram» у источника: найти chat_id, отправить тест. (ok, сообщение)."""
    chat_id, err = tg_resolve(bot, chat)
    if err:
        return False, err
    text = f"[TEST] nodecheck ({src['name']}): проверка Telegram"
    ok = tg_send(bot, chat_id or tg_target(chat), text, text, [src["id"]], src["name"])
    status = log[0]["status"]
    if ok:
        if chat_id:
            _remember_chat([src["id"]], chat_id)
        return True, f"доставлено (chat_id {chat_id})" if chat_id else "доставлено"
    if "chat not found" in status.lower() and not chat_id:
        status += f" — напиши боту /start с аккаунта @{tg_normalize(chat)} и нажми ещё раз"
    return False, status


# ---------- очередь и маршруты ----------


def _deliver(route, payload, label):
    ids = [s["id"] for s in route.sources]
    if route.channel == "telegram":
        bot, chat = route.target
        tg_send(bot, chat, payload.get("text", ""), label, ids, payload.get("source", ""))
    else:
        url, token = route.target
        post_json(url, token, payload, "alert", label, ids)


def _worker():
    while True:
        route, payload, label = _q.get()
        try:
            _deliver(route, payload, label)
        except Exception as e:
            log.appendleft({"ts": int(time.time()), "kind": "alert", "label": label, "ok": False, "status": _mask(e)})
        finally:
            _q.task_done()


def _ensure_worker():
    global _started
    with _start_lock:
        if not _started:
            threading.Thread(target=_worker, daemon=True, name="alerts").start()
            _started = True


def source_routes(source_ids):
    """Адресаты алерта для этих источников: [Route].

    Один адресат у нескольких источников — один Route. Источники без вебхука и без Telegram пропускаются.
    """
    web: dict = {}
    tg: dict = {}
    for sid in dict.fromkeys(source_ids):
        s = db.q1("SELECT * FROM sources WHERE id=?", (sid,))
        if not s:
            continue
        s = dict(s)
        if s["alert_url"]:
            web.setdefault((s["alert_url"], s["alert_token"] or ""), []).append(s)
        if s["tg_token"] and tg_normalize(s["tg_chat"]):
            tg.setdefault((s["tg_token"], s["tg_chat_id"] or tg_target(s["tg_chat"])), []).append(s)
    return [Route("webhook", k, v) for k, v in web.items()] + [Route("telegram", k, v) for k, v in tg.items()]


def send_routed(route, payload):
    """Поставить алерт в очередь для адресата из source_routes."""
    payload = {
        **payload,
        "source": ", ".join(s["name"] for s in route.sources),
        "source_ids": [s["id"] for s in route.sources],
    }
    _ensure_worker()
    label = payload.get("text", "")[:80]
    try:
        _q.put_nowait((route, payload, label))
    except queue.Full:
        entry = {"ts": int(time.time()), "kind": "alert", "label": label, "ok": False, "status": "очередь полна"}
        log.appendleft(entry)


def send_alert(payload):
    """Алерт по чекерам — во все каналы всех источников."""
    for route in source_routes(r["id"] for r in db.q("SELECT id FROM sources ORDER BY id")):
        send_routed(route, payload)


def send_test(url, token, source):
    """Тестовый вебхук источника синхронно (кнопка у источника). Возвращает запись журнала."""
    payload = {
        "type": "test",
        "event": "test",
        "text": f"[TEST] nodecheck ({source['name']}): проверка вебхука",
        "source": source["name"],
        "source_ids": [source["id"]],
        "ts": int(time.time()),
    }
    post_json(url, token, payload, "alert", payload["text"], [source["id"]])
    return log[0]
