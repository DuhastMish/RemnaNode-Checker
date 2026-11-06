import os
import sqlite3
import threading

from . import config

_local = threading.local()

SCHEMA = """
CREATE TABLE IF NOT EXISTS nodes (
    ip          TEXT PRIMARY KEY,
    project     TEXT NOT NULL,
    name        TEXT DEFAULT '',
    flags       TEXT DEFAULT '',
    fresh_port  INTEGER,
    is_active   INTEGER DEFAULT 1,
    updated_at  INTEGER
);
CREATE TABLE IF NOT EXISTS results (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ip            TEXT NOT NULL,
    vantage       TEXT NOT NULL,
    job_id        INTEGER,
    ts            INTEGER NOT NULL,
    ssh_status    TEXT,
    ssh_ok        INTEGER,
    proxy_status  TEXT,
    proxy_ok      INTEGER,
    state         TEXT,
    latency_ms    INTEGER
);
CREATE INDEX IF NOT EXISTS idx_results_ip ON results(ip, id);
CREATE INDEX IF NOT EXISTS idx_results_job ON results(job_id);
CREATE TABLE IF NOT EXISTS jobs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ips           TEXT NOT NULL,
    requested_by  TEXT NOT NULL,
    created_at    INTEGER NOT NULL,
    started_at    INTEGER,
    finished_at   INTEGER,
    status        TEXT NOT NULL DEFAULT 'pending',
    total         INTEGER DEFAULT 0,
    done          INTEGER DEFAULT 0
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


def init():
    os.makedirs(config.DATA_DIR, exist_ok=True)
    c = conn()
    c.executescript(SCHEMA)
    # миграции "добавить колонку" — безопасны при повторном запуске
    for sql in ("ALTER TABLE results ADD COLUMN label TEXT",):
        try:
            c.execute(sql)
        except sqlite3.OperationalError:
            pass
    # ноды с неизвестным проектом (старые ключи) — удаляем, следующий sync загрузит заново
    c.execute("DELETE FROM nodes WHERE project NOT LIKE '%remnawave%' AND project NOT LIKE '%open60%'")
    c.commit()
