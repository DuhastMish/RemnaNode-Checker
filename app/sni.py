"""SNI-домены хостов Remnawave: доступны ли они из сетей чекеров (GET https://домен/ → 200).

Включается настройкой sni_check_enabled. Панель забирает GET {url}/api/hosts у каждого источника Remnawave,
берёт поле sni (несколько значений через запятую/пробел — каждое отдельно), отбрасывает всё, что не является
корректным доменным именем (IP, wildcard, порт, схема, путь, недопустимые символы), и сводит домены без
повторов в sni_domains. Домен неактивен, если все хосты с ним отключены (isDisabled) — проверяется всё равно,
но плитка серая.

Ключ источника может не иметь прав на хосты (в Remnawave у API-ключа свои зоны/scopes; без зоны хостов —
HTTP 403). Это не ошибка: ноды источника синхронизируются как обычно, а здесь показывается подсказка выпустить
новый ключ с зоной хостов. Уже собранные домены такого источника остаются как были.

Чекеру — только {sni_id, domain} через отдельный GET /api/v1/agent/sni (существующий контракт hello/heartbeat/
config/nodes/results не меняется — старые чекеры о SNI не знают). Чекер 2.4.0+ запрашивает список перед каждой
плановой проверкой; выключено — enabled=false и пустой список. kv.sni_revision меняется вместе с набором доменов
(чекеру — только для лога).
Состояние — как у нод, но без инцидентов и алертов: по каждому чекеру fail_streak, упавшим домен считается
после down_fail_streak неудач подряд (если чекер ни разу не видел его рабочим — с первой).
"""

import ipaddress
import json
import re
import threading
import time
import urllib.error
import urllib.parse

from . import checkers, db, settings, sources

_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_lock = threading.RLock()

last_sync = {"ts": None, "ok": None, "msg": "", "invalid": [], "no_access": []}

NO_ACCESS_HINT = (
    "у API-ключа нет прав на хосты — выпусти в Remnawave новый ключ с зоной хостов (Hosts) "
    "и укажи его в источнике; ноды синхронизируются и со старым"
)


def enabled():
    return bool(settings.get("sni_check_enabled"))


def revision() -> int:
    return int(db.kv_get("sni_revision", "0"))


# ---------- домены ----------


def normalize(value):
    """Строка из поля sni → (домен, None) или (None, причина). Домен годится для https://домен/."""
    v = str(value or "").strip().lower().rstrip(".")
    if not v:
        return None, "пусто"
    if "*" in v:
        return None, "wildcard"
    if "://" in v or "/" in v or ":" in v:
        return None, "не домен: схема, порт или путь"
    try:
        ipaddress.ip_address(v)
        return None, "IP-адрес, не домен"
    except ValueError:
        pass
    try:
        v = v.encode("idna").decode("ascii")  # кириллица → punycode
    except UnicodeError:
        return None, "некорректный домен"
    labels = v.split(".")
    if len(v) > 253 or len(labels) < 2 or not all(_LABEL.match(x) for x in labels):
        return None, "некорректный домен"
    if labels[-1].isdigit():
        return None, "некорректный домен"
    if urllib.parse.urlsplit(f"https://{v}/").hostname != v:
        return None, "некорректный домен"
    return v, None


def _split(raw):
    return [p for p in re.split(r"[,\s]+", str(raw or "")) if p]


def fetch_hosts(src):
    base = (src["url"] or "").rstrip("/")
    if not base or not src["token"]:
        raise RuntimeError("не заданы URL или токен")
    data = sources._get_json(f"{base}/api/hosts", src["token"])
    items = data.get("response") if isinstance(data, dict) else data
    if isinstance(items, dict):
        items = items.get("hosts")
    return [h for h in items or [] if isinstance(h, dict)]


def sync_all():
    """Собрать SNI-домены хостов всех источников Remnawave. Выключено — ничего не делает."""
    if not enabled():
        return "выключено"
    want: dict = {}  # домен → [{source_id, source, remark, disabled}]
    invalid: dict = {}  # значение → (причина, [подписи хостов])
    failed, parts, no_access, total_hosts = set(), [], [], 0
    for src in db.q("SELECT * FROM sources WHERE type='remnawave' ORDER BY id"):
        try:
            hosts = fetch_hosts(src)
        except urllib.error.HTTPError as e:
            failed.add(src["id"])
            if e.code in (401, 403):
                # ключ выпущен без зоны хостов — нормальная ситуация, не ошибка синхронизации
                no_access.append({"source_id": src["id"], "source": src["name"], "code": e.code})
            else:
                parts.append(f"{src['name']}: HTTP {e.code}")
            continue
        except Exception as e:
            failed.add(src["id"])
            parts.append(f"{src['name']}: {str(e)[:120]}")
            continue
        total_hosts += len(hosts)
        for h in hosts:
            label = f"{h.get('remark') or h.get('uuid') or '?'} ({src['name']})"
            for raw in _split(h.get("sni")):
                domain, reason = normalize(raw)
                if not domain:
                    invalid.setdefault(raw[:120], (reason, []))[1].append(label)
                    continue
                want.setdefault(domain, []).append(
                    {
                        "source_id": src["id"],
                        "source": src["name"],
                        "remark": str(h.get("remark") or "")[:100],
                        "disabled": bool(h.get("isDisabled")),
                    }
                )
    now = int(time.time())
    with _lock:
        have = {r["domain"]: dict(r) for r in db.q("SELECT * FROM sni_domains")}
        # источник не ответил — его хосты оставляем как были, а не удаляем
        for domain, row in have.items():
            for h in json.loads(row["hosts"] or "[]"):
                if h.get("source_id") in failed:
                    want.setdefault(domain, []).append(h)
        changed = False
        for domain, row in have.items():
            if domain not in want:
                db.x("DELETE FROM sni_domains WHERE id=?", (row["id"],))
                db.x("DELETE FROM sni_checker_state WHERE sni_id=?", (row["id"],))
                changed = True
        for domain, hosts in want.items():
            active = 1 if any(not h["disabled"] for h in hosts) else 0
            hosts_json = json.dumps(hosts, ensure_ascii=False)
            row = have.get(domain)
            if not row:
                db.x(
                    "INSERT INTO sni_domains(domain, is_active, hosts, created_at, updated_at) VALUES(?,?,?,?,?)",
                    (domain, active, hosts_json, now, now),
                )
                changed = True
            elif (row["is_active"], row["hosts"]) != (active, hosts_json):
                db.x(
                    "UPDATE sni_domains SET is_active=?, hosts=?, updated_at=? WHERE id=?",
                    (active, hosts_json, now, row["id"]),
                )
        if changed:
            db.kv_set("sni_revision", revision() + 1)
    msg = f"{len(want)} доменов из {total_hosts} хостов"
    if invalid:
        msg += f", некорректных SNI: {len(invalid)}"
    if no_access:
        msg += "; нет прав на хосты у ключа: " + ", ".join(n["source"] for n in no_access)
    if parts:
        msg += "; ошибки — " + "; ".join(parts)
    last_sync.update(
        ts=now,
        ok=not parts,
        msg=msg,
        no_access=no_access,
        invalid=[{"value": v, "reason": r, "hosts": hs} for v, (r, hs) in sorted(invalid.items())],
    )
    return msg


def for_agent():
    return [{"sni_id": r["id"], "domain": r["domain"]} for r in db.q("SELECT id, domain FROM sni_domains ORDER BY id")]


# ---------- результаты чекеров ----------


def _int(v):
    return v if isinstance(v, int) and not isinstance(v, bool) else None


def ingest(checker_id, items):
    """Записать батч результатов. Возвращает (принято, дубли, неизвестные домены)."""
    accepted = dupes = unknown = 0
    now = int(time.time())
    known = {r["id"]: r["domain"] for r in db.q("SELECT id, domain FROM sni_domains")}
    c = db.conn()
    with _lock:
        for it in items:
            sni_id = _int(it.get("sni_id"))
            if sni_id not in known or it.get("domain") != known[sni_id]:
                unknown += 1  # домен убран или пересоздан — результат по нему не нужен
                continue
            ts = min(_int(it.get("ts")) or now, now + 60)
            ok = it.get("ok") is True
            cur = c.execute(
                "INSERT OR IGNORE INTO sni_results(result_uid, sni_id, checker_id, ts, http_status, status, "
                "latency_ms, state) VALUES(?,?,?,?,?,?,?,?)",
                (
                    str(it.get("result_uid") or "")[:64] or None,
                    sni_id,
                    checker_id,
                    ts,
                    _int(it.get("http_status")),
                    str(it.get("status") or "")[:80],
                    _int(it.get("latency_ms")),
                    "green" if ok else "red",
                ),
            )
            if cur.rowcount == 0:
                dupes += 1
                continue
            accepted += 1
            row = c.execute(
                "SELECT * FROM sni_checker_state WHERE sni_id=? AND checker_id=?", (sni_id, checker_id)
            ).fetchone()
            if row and row["last_ts"] and ts < row["last_ts"]:
                continue  # старее уже учтённого
            c.execute(
                "INSERT INTO sni_checker_state(sni_id, checker_id, last_state, last_status, fail_streak, seen_ok, "
                "last_ts) VALUES(?,?,?,?,?,?,?) ON CONFLICT(sni_id, checker_id) DO UPDATE SET "
                "last_state=excluded.last_state, last_status=excluded.last_status, fail_streak=excluded.fail_streak, "
                "seen_ok=excluded.seen_ok, last_ts=excluded.last_ts",
                (
                    sni_id,
                    checker_id,
                    "green" if ok else "red",
                    str(it.get("status") or "")[:80],
                    0 if ok else (row["fail_streak"] if row else 0) + 1,
                    1 if ok or (row and row["seen_ok"]) else 0,
                    ts,
                ),
            )
        c.commit()
    return accepted, dupes, unknown


# ---------- для дашборда ----------


def states(now=None):
    """sni_id → {color, up, down, checked_at, status} по online-чекерам со свежими результатами."""
    now = now or time.time()
    online = set(checkers.online_ids())
    fresh = now - 3 * settings.get("check_interval_min") * 60
    threshold = max(1, settings.get("down_fail_streak"))
    out: dict = {}
    for r in db.q("SELECT * FROM sni_checker_state"):
        s = out.setdefault(r["sni_id"], {"up": 0, "down": 0, "checked_at": None, "bad": "", "good": ""})
        s["checked_at"] = max(s["checked_at"] or 0, r["last_ts"] or 0) or None
        if r["checker_id"] not in online or not r["last_ts"] or r["last_ts"] < fresh:
            continue
        if r["fail_streak"] >= (threshold if r["seen_ok"] else 1):
            s["down"] += 1
            s["bad"] = s["bad"] or r["last_status"]
        else:
            s["up"] += 1
            s["good"] = s["good"] or r["last_status"]
    for s in out.values():
        up, down = s["up"], s["down"]
        s["color"] = "grey" if up + down == 0 else ("green" if not down else ("red" if not up else "orange"))
        bad, good = s.pop("bad"), s.pop("good")
        s["status"] = bad or good  # пример статуса: у кого не работает, а если у всех работает — ответ
    return out


def domains():
    rows = []
    for r in db.q("SELECT * FROM sni_domains ORDER BY domain"):
        d = dict(r)
        d["hosts"] = json.loads(d["hosts"] or "[]")
        rows.append(d)
    return rows


def results_since(start):
    return db.q("SELECT sni_id, ts, state, latency_ms FROM sni_results WHERE ts > ?", (start,))


def cleanup(cutoff):
    db.x("DELETE FROM sni_results WHERE ts < ?", (cutoff,))
