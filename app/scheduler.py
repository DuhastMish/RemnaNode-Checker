"""Фоновые задачи панели (APScheduler). Сама панель ничего не проверяет — это делают чекеры."""

import threading
import time
from datetime import datetime, timedelta, timezone

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

from . import db, egress, export, geoip, jobs, settings, sources, state, traffic, tunnel

sched = BackgroundScheduler(
    timezone="UTC",
    job_defaults={"coalesce": True, "max_instances": 1, "misfire_grace_time": 120},
)
last_run: dict = {}
last_error: dict = {}


last_sync = {"ts": None, "msg": ""}


def sync_nodes():
    msg, _changed = sources.sync_all()
    last_sync.update(ts=int(time.time()), msg=msg)


def cleanup():
    cutoff = int(time.time()) - settings.get("retention_days") * 86400
    db.x("DELETE FROM results WHERE ts < ?", (cutoff,))
    old = int(time.time()) - 7 * 86400
    db.x(
        "DELETE FROM job_checkers WHERE job_id IN (SELECT id FROM jobs WHERE status='done' AND finished_at < ?)", (old,)
    )
    db.x("DELETE FROM jobs WHERE status='done' AND finished_at < ?", (old,))
    traffic.cleanup()


TASKS = {
    "sync_nodes": ("Синхронизация нод из источников", sync_nodes),
    "cleanup": ("Очистка истории", cleanup),
    "recompute_state": ("Пересчёт состояния нод (offline-чекеры, устаревание)", state.recompute_all),
    "finish_jobs": ("Завершение ручных заданий по таймауту", jobs.finish_due),
    "traffic_poll": ("Трафик нод Remnawave (обрыв скорости)", traffic.poll),
    "export": ("Экспорт состояния в источники", export.export_all),
    "egress_watchdog": ("Исходящий VPS (watchdog)", egress.watchdog),
    "tunnel_watchdog": ("Туннель к VPS (watchdog)", tunnel.watchdog),
    "geoip_update": ("Базы геолокации DB-IP (раз в месяц)", geoip.update),
}


def _wrap(name, fn):
    def inner():
        last_run[name] = int(time.time())
        try:
            fn()
            last_error.pop(name, None)
        except Exception as e:
            last_error[name] = str(e)[:200]

    return inner


def _triggers():
    return {
        "sync_nodes": IntervalTrigger(minutes=max(1, settings.get("sync_interval_min"))),
        "cleanup": IntervalTrigger(days=1),
        "recompute_state": IntervalTrigger(seconds=30),
        "finish_jobs": IntervalTrigger(seconds=5),
        "traffic_poll": IntervalTrigger(minutes=1),
        "export": IntervalTrigger(minutes=max(1, settings.get("check_interval_min"))),
        "egress_watchdog": IntervalTrigger(seconds=30),
        "tunnel_watchdog": IntervalTrigger(seconds=30),
        "geoip_update": IntervalTrigger(hours=12),
    }


def setup():
    now = datetime.now(timezone.utc)
    first = {
        "sync_nodes": 5,
        "cleanup": 60,
        "recompute_state": 30,
        "finish_jobs": 5,
        "traffic_poll": 20,
        "export": 120,
        "egress_watchdog": 15,
        "tunnel_watchdog": 20,
        "geoip_update": 30,
    }
    for name, trig in _triggers().items():
        sched.add_job(_wrap(name, TASKS[name][1]), trig, id=name, next_run_time=now + timedelta(seconds=first[name]))
    sched.start()


def apply_intervals():
    for name, trig in _triggers().items():
        sched.reschedule_job(name, trigger=trig)


def run_now(name):
    if name in TASKS:
        threading.Thread(target=_wrap(name, TASKS[name][1]), daemon=True).start()


def info():
    out = []
    for name, (label, _) in TASKS.items():
        job = sched.get_job(name)
        nxt = job.next_run_time.timestamp() if job and job.next_run_time else None
        out.append(
            {
                "name": name,
                "label": label,
                "last": last_run.get(name),
                "next": int(nxt) if nxt else None,
                "error": last_error.get(name),
            }
        )
    return out
