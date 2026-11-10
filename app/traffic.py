"""Пассивная проверка «обрыв трафика» по данным Remnawave (замедление ТСПУ / fair-use хостера).

Раз в минуту панель забирает GET /api/nodes каждого источника Remnawave и сохраняет по ноде источника
system.stats.interface.rxTotal / txTotal и usersOnline. Это счётчики ядра (/proc/net/dev) основного
интерфейса сервера: нода читает их раз в секунду, бэкенд Remnawave обновляет кэш раз в 10 с.
Обнуляются только при перезагрузке сервера — такой интервал (счётчик уменьшился) пропускается.

Скорость — исходящий трафик сервера (tx), средняя за последние RATE_WINDOW секунд по разнице счётчиков.
База — медиана этой средней за предыдущий час (без последних RATE_WINDOW секунд).
Обрыв: средняя < traffic_drop_pct % от базы дольше traffic_drop_min минут → событие throughput_drop
(«Активные оповещения» + вебхук). Восстановление: средняя ≥ RESTORE_PCT % от базы на момент обрыва →
throughput_restored. Пустые ноды (база < traffic_min_mbps), неактивные и красные (не видит ни один чекер —
об этом уже алерт [DOWN]) не проверяются; уже открытый обрыв у красной ноды закрывается как обычно.
"""

import time
import urllib.error

from . import alerts, db, settings, sources

RATE_WINDOW = 300  # с — окно средней скорости
BASELINE_WINDOW = 3600  # с — окно базы
BASELINE_MIN_POINTS = 20  # точек средней в окне базы, иначе истории мало — не оцениваем
MAX_GAP = 180  # с — разрыв между замерами больше этого не используется для скорости
RESTORE_PCT = 70
KEEP_SEC = 2 * 86400

last_poll = {"ts": None, "msg": ""}


# ---------- опрос ----------


def _interface(n):
    stats = ((n.get("system") or {}).get("stats") or {}) if isinstance(n, dict) else {}
    iface = stats.get("interface") if isinstance(stats, dict) else None
    if not isinstance(iface, dict):
        return None
    rx, tx = iface.get("rxTotal"), iface.get("txTotal")
    if not isinstance(rx, (int, float)) or not isinstance(tx, (int, float)):
        return None
    return int(rx), int(tx)


def poll():
    """Задача планировщика (раз в минуту): замер по всем источникам Remnawave и оценка обрыва."""
    now = int(time.time())
    parts = []
    for src in db.q("SELECT * FROM sources WHERE type='remnawave' ORDER BY id"):
        base = (src["url"] or "").rstrip("/")
        if not base or not src["token"]:
            continue
        try:
            items = sources._get_json(f"{base}/api/nodes", src["token"]).get("response", [])
        except urllib.error.HTTPError as e:
            parts.append(f"{src['name']}: HTTP {e.code}")
            continue
        except Exception as e:
            parts.append(f"{src['name']}: {str(e)[:80]}")
            continue
        sn_by_ext = {
            r["external_id"]: r
            for r in db.q(
                "SELECT sn.id, sn.external_id, sn.is_active, ns.color FROM source_nodes sn "
                "LEFT JOIN node_state ns ON ns.node_id = sn.node_id WHERE sn.source_id=?",
                (src["id"],),
            )
        }
        got = 0
        for n in items:
            sn = sn_by_ext.get(str(n.get("uuid") or ""))
            totals = _interface(n)
            if not sn or not totals:
                continue
            users = n.get("usersOnline")
            db.x(
                "INSERT OR REPLACE INTO traffic_samples(sn_id, ts, rx_total, tx_total, users_online) VALUES(?,?,?,?,?)",
                (sn["id"], now, totals[0], totals[1], int(users) if isinstance(users, (int, float)) else None),
            )
            got += 1
            evaluate(sn["id"], bool(sn["is_active"]), now, node_red=sn["color"] == "red")
        parts.append(f"{src['name']}: {got} нод")
    last_poll.update(ts=now, msg="; ".join(parts) or "источников Remnawave нет")


# ---------- скорость ----------


def _deltas(samples):
    """[(ts_конца, байт tx, секунд, users)] по соседним замерам; сброс счётчика и большие разрывы пропускаются."""
    out = []
    for a, b in zip(samples, samples[1:]):
        dt = b["ts"] - a["ts"]
        d = b["tx_total"] - a["tx_total"]
        if dt <= 0 or dt > MAX_GAP or d < 0:
            continue
        out.append((b["ts"], d, dt, b["users_online"]))
    return out


def _avg_at(deltas, t):
    """Средняя скорость (бит/с) за RATE_WINDOW до момента t; None — данных меньше чем на 60% окна."""
    got = [(d, dt) for ts, d, dt, _ in deltas if t - RATE_WINDOW < ts <= t]
    secs = sum(dt for _, dt in got)
    if secs < RATE_WINDOW * 0.6:
        return None
    return sum(d for d, _ in got) * 8 / secs


def _median(xs):
    xs = sorted(xs)
    n = len(xs)
    return (xs[n // 2] if n % 2 else (xs[n // 2 - 1] + xs[n // 2]) / 2) if n else None


def _samples(sn_id, since):
    return db.q(
        "SELECT ts, tx_total, users_online FROM traffic_samples WHERE sn_id=? AND ts>=? ORDER BY ts", (sn_id, since)
    )


def mbps(bps):
    """бит/с → Мбит/с с одним знаком."""
    return None if bps is None else round(bps / 1e6, 1)


# ---------- обрыв ----------


def evaluate(sn_id, is_active, now=None, node_red=False):
    """Пересчитать скорость и базу ноды источника, открыть/закрыть обрыв и отправить событие.

    node_red — цель красная (не видит ни один чекер): новый обрыв не открываем, об этом уже есть [DOWN].
    """
    now = int(now or time.time())
    pct = settings.get("traffic_drop_pct")
    row = db.q1("SELECT below_since, drop_at, drop_base_bps FROM traffic_state WHERE sn_id=?", (sn_id,))
    st = {
        "below_since": row["below_since"] if row else None,
        "drop_at": row["drop_at"] if row else None,
        "drop_base": row["drop_base_bps"] if row else None,
    }

    deltas = _deltas(_samples(sn_id, now - BASELINE_WINDOW - 2 * RATE_WINDOW))
    rate = _avg_at(deltas, now)
    lo, hi = now - BASELINE_WINDOW - RATE_WINDOW, now - RATE_WINDOW
    points = [v for v in (_avg_at(deltas, ts) for ts, *_ in deltas if lo < ts <= hi) if v is not None]
    base = _median(points) if len(points) >= BASELINE_MIN_POINTS else None
    users = deltas[-1][3] if deltas else None
    st.update(rate=rate, base=base, users=users, updated_at=now)

    if not is_active or pct <= 0:
        # отключённая в источнике нода или проверка выключена: трафик и так падает — без событий
        st.update(below_since=None, drop_at=None, drop_base=None)
    elif st["drop_at"]:
        if rate is not None and rate >= st["drop_base"] * RESTORE_PCT / 100:
            _alert(sn_id, "throughput_restored", rate, st["drop_base"], users, st["drop_at"], now)
            st.update(below_since=None, drop_at=None, drop_base=None)
    elif node_red:
        # нода лежит у всех чекеров — трафик падает сам собой, обрыв был бы дублем [DOWN]
        st["below_since"] = None
    elif rate is not None and base is not None and base >= settings.get("traffic_min_mbps") * 1e6:
        if rate < base * pct / 100:
            st["below_since"] = st["below_since"] or now
            if now - st["below_since"] >= settings.get("traffic_drop_min") * 60:
                st.update(drop_at=st["below_since"], drop_base=base)
                _alert(sn_id, "throughput_drop", rate, base, users, st["drop_at"], now)
        else:
            st["below_since"] = None
    else:
        st["below_since"] = None

    db.x(
        "INSERT INTO traffic_state(sn_id, rate_bps, base_bps, users_online, below_since, drop_at, drop_base_bps, "
        "updated_at) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(sn_id) DO UPDATE SET rate_bps=excluded.rate_bps, "
        "base_bps=excluded.base_bps, users_online=excluded.users_online, below_since=excluded.below_since, "
        "drop_at=excluded.drop_at, drop_base_bps=excluded.drop_base_bps, updated_at=excluded.updated_at",
        (sn_id, st["rate"], st["base"], st["users"], st["below_since"], st["drop_at"], st["drop_base"], now),
    )


def _alert(sn_id, event, rate, base, users, drop_at, now):
    sn = db.q1(
        "SELECT sn.*, s.name AS source FROM source_nodes sn JOIN sources s ON s.id = sn.source_id WHERE sn.id=?",
        (sn_id,),
    )
    if not sn:
        return
    title = f"{sn['name'] or sn['external_id']} ({sn['source']}) {sn['address']}"
    r, b = mbps(rate), mbps(base)
    if event == "throughput_drop":
        text = f"[THROUGHPUT DROP] {title}: трафик {b} → {r} Мбит/с (−{round(100 - 100 * rate / base)}%)"
    else:
        mins = max(1, (now - drop_at) // 60)
        text = f"[THROUGHPUT RESTORED] {title}: трафик снова {r} Мбит/с (было {b}), падение длилось {mins} мин"
    payload = {
        "type": "traffic",
        "event": event,
        "text": text,
        "node_id": sn["node_id"],
        "name": sn["name"],
        "external_id": sn["external_id"],
        "country": sn["country"],
        "address": sn["address"],
        "rate_mbps": r,
        "baseline_mbps": b,
        "users_online": users,
        "drop_started_at": drop_at,
        "ts": now,
    }
    for route in alerts.source_routes([sn["source_id"]]):
        alerts.send_routed(route, payload)


# ---------- для страниц ----------


def open_drops():
    """Открытые обрывы активных нод — для «Активных оповещений»."""
    return [
        dict(r)
        for r in db.q(
            "SELECT t.*, sn.node_id, sn.source_id, sn.name, sn.external_id, sn.address, sn.country, s.name AS source "
            "FROM traffic_state t JOIN source_nodes sn ON sn.id = t.sn_id JOIN sources s ON s.id = sn.source_id "
            "WHERE t.drop_at IS NOT NULL AND sn.is_active = 1 ORDER BY t.drop_at DESC"
        )
    ]


def chart(sn_id, hours=24, now=None):
    """Точки для графика в карточке ноды: средняя за RATE_WINDOW шагом 5 минут + онлайн."""
    now = int(now or time.time())
    start = now - hours * 3600
    deltas = _deltas(_samples(sn_id, start - RATE_WINDOW))
    if not deltas:
        return None
    points = []
    for t in range(start + RATE_WINDOW, now + 1, RATE_WINDOW):
        users = next((u for ts, _, _, u in reversed(deltas) if ts <= t), None)
        points.append({"ts": t, "mbps": mbps(_avg_at(deltas, t)), "users": users})
    st = db.q1("SELECT * FROM traffic_state WHERE sn_id=?", (sn_id,))
    return {"points": points, "start": start, "end": now, "state": dict(st) if st else None}


def svg_paths(ch, width=1000, height=120):
    """SVG-пути для графика: трафик (линия + заливка) и онлайн (пунктир), разрывы там, где нет данных."""
    pts = ch["points"]
    span = max(1, ch["end"] - ch["start"])
    top_mbps = max([p["mbps"] for p in pts if p["mbps"] is not None] or [1]) * 1.1 or 1
    top_users = max([p["users"] for p in pts if p["users"] is not None] or [1]) * 1.1 or 1

    def path(key, top):
        d, segs, cur = [], [], []
        for p in pts:
            if p[key] is None:
                if cur:
                    segs.append(cur)
                cur = []
                continue
            x = (p["ts"] - ch["start"]) / span * width
            y = height - p[key] / top * height
            cur.append((round(x, 1), round(y, 1)))
        if cur:
            segs.append(cur)
        for seg in segs:
            d.append("M" + " L".join(f"{x},{y}" for x, y in seg))
        fill = " ".join(
            f"M{seg[0][0]},{height} L" + " L".join(f"{x},{y}" for x, y in seg) + f" L{seg[-1][0]},{height} Z"
            for seg in segs
            if len(seg) > 1
        )
        return " ".join(d), fill

    line, fill = path("mbps", top_mbps)
    users, _ = path("users", top_users)
    return {
        "line": line,
        "fill": fill,
        "users": users,
        "top_mbps": round(top_mbps / 1.1, 1),
        "top_users": round(top_users / 1.1),
    }


def cleanup():
    """Замеры старше 2 суток и данные удалённых нод."""
    db.x("DELETE FROM traffic_samples WHERE ts < ?", (int(time.time()) - KEEP_SEC,))
    db.x("DELETE FROM traffic_samples WHERE sn_id NOT IN (SELECT id FROM source_nodes)")
    db.x("DELETE FROM traffic_state WHERE sn_id NOT IN (SELECT id FROM source_nodes)")
