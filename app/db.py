"""SQLite панели. Схема v2: источники → ноды источников → цели проверки (nodes) → результаты чекеров."""

import os
import sqlite3
import threading

from . import config

_local = threading.local()

SCHEMA = """
-- экземпляры панелей-источников
CREATE TABLE IF NOT EXISTS sources (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    type          TEXT NOT NULL,              -- remnawave | open60
    name          TEXT NOT NULL,              -- имя вкладки
    url           TEXT NOT NULL DEFAULT '',
    token         TEXT NOT NULL DEFAULT '',
    export_url    TEXT NOT NULL DEFAULT '',
    export_token  TEXT NOT NULL DEFAULT '',
    alert_url     TEXT NOT NULL DEFAULT '',   -- вебхук алертов по нодам источника; пусто — не слать
    alert_token   TEXT NOT NULL DEFAULT '',
    tg_token      TEXT NOT NULL DEFAULT '',   -- Telegram: токен бота
    tg_chat       TEXT NOT NULL DEFAULT '',   -- Telegram: кому (@username, @канал, chat_id); пусто — не слать
    tg_chat_id    TEXT NOT NULL DEFAULT '',   -- Telegram: найденный chat_id для tg_chat
    created_at    INTEGER NOT NULL,
    last_sync_at  INTEGER,
    last_sync_ok  INTEGER,
    last_sync_msg TEXT DEFAULT ''
);

-- нода в конкретном источнике; ключ (source_id, external_id)
CREATE TABLE IF NOT EXISTS source_nodes (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id     INTEGER NOT NULL,
    external_id   TEXT NOT NULL,              -- uuid в Remnawave, id в Open60
    name          TEXT DEFAULT '',
    address       TEXT DEFAULT '',
    flags         TEXT DEFAULT '',
    country       TEXT DEFAULT '',            -- ISO 3166-1 alpha-2 (DE) — флаг; Remnawave: countryCode
    fresh_port    INTEGER,
    is_active     INTEGER DEFAULT 1,
    node_id       TEXT NOT NULL,              -- цель проверки
    is_primary    INTEGER DEFAULT 1,          -- адрес цели берётся у основной ноды
    ips           TEXT DEFAULT '[]',          -- Remnawave: доп. адреса VPS, JSON [{"ip", "status"}]
    last_seen_at  INTEGER,
    UNIQUE (source_id, external_id)
);
CREATE INDEX IF NOT EXISTS idx_sn_node ON source_nodes(node_id);

-- цель проверки: то, что проверяют чекеры.
-- parent_id NULL — основная цель (адрес основной ноды источника); иначе доп. адрес VPS этой основной цели
CREATE TABLE IF NOT EXISTS nodes (
    id          TEXT PRIMARY KEY,             -- UUID
    address     TEXT NOT NULL DEFAULT '',
    fresh_port  INTEGER,
    is_active   INTEGER DEFAULT 1,
    rev         INTEGER NOT NULL DEFAULT 1,
    parent_id   TEXT,                         -- доп. адрес: id основной цели
    ip_status   TEXT DEFAULT '',              -- доп. адрес: метка из Remnawave (BLOCKED, RESERVE…), только для показа
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS checkers (
    id            TEXT PRIMARY KEY,           -- UUID
    name          TEXT NOT NULL,
    token_hash    TEXT NOT NULL UNIQUE,
    enabled       INTEGER NOT NULL DEFAULT 1,
    version       TEXT DEFAULT '',
    public_ip     TEXT DEFAULT '',
    geo           TEXT DEFAULT '',            -- JSON геолокации public_ip (geoip.lookup + ip, версия баз)
    geo_country   TEXT DEFAULT '',            -- ISO-код страны public_ip; вне checker_countries — VPN
    valid_since   INTEGER,                    -- вернулся в свою страну: результаты старше не принимаем
    online        INTEGER NOT NULL DEFAULT 0, -- последнее известное состояние (для алертов о смене)
    created_at    INTEGER NOT NULL,
    last_seen_at  INTEGER
);

CREATE TABLE IF NOT EXISTS results (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    result_uid      TEXT UNIQUE,
    node_id         TEXT,                     -- NULL для разовых целей
    checker_id      TEXT NOT NULL,
    job_id          INTEGER,
    ts              INTEGER NOT NULL,
    node_rev        INTEGER,
    target_address  TEXT,
    target_port     INTEGER,
    ssh_status      TEXT,
    ssh_ok          INTEGER,
    proxy_status    TEXT,
    proxy_ok        INTEGER,
    latency_ms      INTEGER,
    state           TEXT,
    stale           INTEGER NOT NULL DEFAULT 0 -- 1: по устаревшей ревизии, в состоянии не учтён
);
CREATE INDEX IF NOT EXISTS idx_results_node ON results(node_id, id);
CREATE INDEX IF NOT EXISTS idx_results_job ON results(job_id);

-- состояние ноды глазами одного чекера
CREATE TABLE IF NOT EXISTS node_checker_state (
    node_id      TEXT NOT NULL,
    checker_id   TEXT NOT NULL,
    last_state   TEXT,
    fail_streak  INTEGER NOT NULL DEFAULT 0,
    seen_alive   INTEGER NOT NULL DEFAULT 0,  -- чекер хоть раз видел адрес живым (SSH прошёл: green/yellow)
    ok_streak    INTEGER NOT NULL DEFAULT 0,  -- green подряд
    ok_since     INTEGER,                     -- ts первого green в текущей серии
    last_ts      INTEGER,
    PRIMARY KEY (node_id, checker_id)
);

-- агрегированное состояние ноды (цвет плитки)
CREATE TABLE IF NOT EXISTS node_state (
    node_id      TEXT PRIMARY KEY,
    color        TEXT NOT NULL DEFAULT 'grey',  -- цвет плитки: у неактивной ноды всегда grey
    probe_color  TEXT,                          -- что видят чекеры (агрегат), в т.ч. у неактивной ноды
    ok_streak    INTEGER NOT NULL DEFAULT 0,    -- min green подряд по online-чекерам (0, если кто-то не green)
    ok_since     INTEGER,                       -- с какого момента все эти чекеры видят ноду рабочей
    up_count     INTEGER DEFAULT 0,
    down_count   INTEGER DEFAULT 0,
    incident_id  INTEGER,
    updated_at   INTEGER
);

-- замеры трафика нод Remnawave (раз в минуту, хранятся 2 суток): счётчики интерфейса сервера и онлайн
CREATE TABLE IF NOT EXISTS traffic_samples (
    sn_id         INTEGER NOT NULL,           -- source_nodes.id
    ts            INTEGER NOT NULL,
    rx_total      INTEGER,
    tx_total      INTEGER,
    users_online  INTEGER,
    PRIMARY KEY (sn_id, ts)
);
-- состояние проверки «обрыв трафика» по ноде источника
CREATE TABLE IF NOT EXISTS traffic_state (
    sn_id          INTEGER PRIMARY KEY,
    rate_bps       REAL,                      -- средняя за 5 мин
    base_bps       REAL,                      -- медиана средней за предыдущий час
    users_online   INTEGER,
    below_since    INTEGER,                   -- с какого момента ниже порога (ещё не обрыв)
    drop_at        INTEGER,                   -- открытый обрыв: начало
    drop_base_bps  REAL,                      -- база на момент обрыва
    updated_at     INTEGER
);

CREATE TABLE IF NOT EXISTS incidents (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id          TEXT NOT NULL,
    opened_at        INTEGER NOT NULL,
    closed_at        INTEGER,
    address_at_open  TEXT,
    color            TEXT,
    extra_announced  TEXT DEFAULT '[]'        -- доп. адреса, о которых уже был алерт [ADDR UP] (JSON)
);
CREATE INDEX IF NOT EXISTS idx_incidents_node ON incidents(node_id, id);

-- ручные задания; targets — JSON [{"node_id"|null, "address", "port"}]
CREATE TABLE IF NOT EXISTS jobs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    targets       TEXT NOT NULL,
    requested_by  TEXT NOT NULL,
    created_at    INTEGER NOT NULL,
    finished_at   INTEGER,
    status        TEXT NOT NULL DEFAULT 'pending'   -- pending | done
);
-- какие чекеры должны выполнить задание
CREATE TABLE IF NOT EXISTS job_checkers (
    job_id      INTEGER NOT NULL,
    checker_id  TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'pending',    -- pending | taken | done
    updated_at  INTEGER,
    PRIMARY KEY (job_id, checker_id)
);

CREATE TABLE IF NOT EXISTS kv (
    key    TEXT PRIMARY KEY,
    value  TEXT
);

CREATE TABLE IF NOT EXISTS settings (
    key         TEXT PRIMARY KEY,
    value       TEXT,
    updated_at  INTEGER
);
CREATE TABLE IF NOT EXISTS settings_history (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    key        TEXT NOT NULL,
    old_value  TEXT,
    new_value  TEXT,
    ts         INTEGER NOT NULL
);
"""


def conn() -> sqlite3.Connection:
    c = getattr(_local, "c", None)
    if c is None:
        c = sqlite3.connect(config.DB_PATH, timeout=30, check_same_thread=False)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA synchronous=NORMAL")
        _local.c = c
    return c


def q(sql, args=()):
    return conn().execute(sql, args).fetchall()


def q1(sql, args=()):
    return conn().execute(sql, args).fetchone()


def x(sql, args=()):
    c = conn()
    cur = c.execute(sql, args)
    c.commit()
    return cur.lastrowid


def kv_get(key, default=None):
    r = q1("SELECT value FROM kv WHERE key=?", (key,))
    return r["value"] if r else default


def kv_set(key, value):
    x("INSERT INTO kv(key, value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, str(value)))


def init():
    os.makedirs(config.DATA_DIR, exist_ok=True)
    c = conn()
    c.executescript(SCHEMA)
    # миграции существующих баз
    for table, col, ddl in (
        ("node_state", "probe_color", "TEXT"),
        ("node_state", "ok_streak", "INTEGER NOT NULL DEFAULT 0"),
        ("node_state", "ok_since", "INTEGER"),
        ("node_checker_state", "ok_streak", "INTEGER NOT NULL DEFAULT 0"),
        ("node_checker_state", "ok_since", "INTEGER"),
        ("sources", "tg_token", "TEXT NOT NULL DEFAULT ''"),
        ("sources", "tg_chat", "TEXT NOT NULL DEFAULT ''"),
        ("sources", "tg_chat_id", "TEXT NOT NULL DEFAULT ''"),
        ("checkers", "geo", "TEXT DEFAULT ''"),
        ("checkers", "geo_country", "TEXT DEFAULT ''"),
        ("checkers", "valid_since", "INTEGER"),
        ("nodes", "parent_id", "TEXT"),
        ("nodes", "ip_status", "TEXT DEFAULT ''"),
        ("source_nodes", "ips", "TEXT DEFAULT '[]'"),
        ("incidents", "extra_announced", "TEXT DEFAULT '[]'"),
    ):
        if col not in {r[1] for r in c.execute(f"PRAGMA table_info({table})")}:
            c.execute(f"ALTER TABLE {table} ADD COLUMN {col} {ddl}")
    c.execute("CREATE INDEX IF NOT EXISTS idx_nodes_parent ON nodes(parent_id)")
    cols = {r[1] for r in c.execute("PRAGMA table_info(sources)")}
    if "alert_url" not in cols:
        # раньше вебхук был один на всю панель (настройки alert_webhook_*) — переносим его во все источники,
        # чтобы алерты не пропали молча; лишние источники потом очищаются вручную
        c.execute("ALTER TABLE sources ADD COLUMN alert_url TEXT NOT NULL DEFAULT ''")
        c.execute("ALTER TABLE sources ADD COLUMN alert_token TEXT NOT NULL DEFAULT ''")
        c.execute(
            "UPDATE sources SET "
            "alert_url = COALESCE((SELECT value FROM settings WHERE key='alert_webhook_url'), ''), "
            "alert_token = COALESCE((SELECT value FROM settings WHERE key='alert_webhook_token'), '')"
        )
    cols = {r[1] for r in c.execute("PRAGMA table_info(source_nodes)")}
    if "country" not in cols:
        c.execute("ALTER TABLE source_nodes ADD COLUMN country TEXT DEFAULT ''")
    cols = {r[1] for r in c.execute("PRAGMA table_info(node_checker_state)")}
    if "seen_alive" not in cols:
        c.execute("ALTER TABLE node_checker_state ADD COLUMN seen_alive INTEGER NOT NULL DEFAULT 0")
        # по истории: был ли от этого чекера живой результат по текущему адресу цели
        c.execute(
            "UPDATE node_checker_state SET seen_alive = 1 WHERE EXISTS (SELECT 1 FROM results r "
            "JOIN nodes n ON n.id = r.node_id WHERE r.node_id = node_checker_state.node_id "
            "AND r.checker_id = node_checker_state.checker_id AND r.stale = 0 "
            "AND r.target_address = n.address AND r.state IN ('green', 'yellow'))"
        )
    c.commit()
