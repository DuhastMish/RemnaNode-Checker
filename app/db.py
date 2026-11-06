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
    fresh_port    INTEGER,
    is_active     INTEGER DEFAULT 1,
    node_id       TEXT NOT NULL,              -- цель проверки
    is_primary    INTEGER DEFAULT 1,          -- адрес цели берётся у основной ноды
    last_seen_at  INTEGER,
    UNIQUE (source_id, external_id)
);
CREATE INDEX IF NOT EXISTS idx_sn_node ON source_nodes(node_id);

-- цель проверки: то, что проверяют чекеры
CREATE TABLE IF NOT EXISTS nodes (
    id          TEXT PRIMARY KEY,             -- UUID
    address     TEXT NOT NULL DEFAULT '',
    fresh_port  INTEGER,
    is_active   INTEGER DEFAULT 1,
    rev         INTEGER NOT NULL DEFAULT 1,
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
    last_ts      INTEGER,
    PRIMARY KEY (node_id, checker_id)
);

-- агрегированное состояние ноды (цвет плитки)
CREATE TABLE IF NOT EXISTS node_state (
    node_id      TEXT PRIMARY KEY,
    color        TEXT NOT NULL DEFAULT 'grey',
    up_count     INTEGER DEFAULT 0,
    down_count   INTEGER DEFAULT 0,
    incident_id  INTEGER,
    updated_at   INTEGER
);

CREATE TABLE IF NOT EXISTS incidents (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id          TEXT NOT NULL,
    opened_at        INTEGER NOT NULL,
    closed_at        INTEGER,
    address_at_open  TEXT,
    color            TEXT
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
    c.commit()
