"""Фоновые задачи внутри процесса (APScheduler). Интервалы — из настроек, меняются на лету."""
import json
import threading
import time
from datetime import datetime, timedelta, timezone

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

from . import checker, db, egress, settings, sources, tunnel

sched = BackgroundScheduler(
    timezone="UTC",
    job_defaults={"coalesce": True, "max_instances": 1, "misfire_grace_time": 120},
)
last_run: dict = {}
last_error: dict = {}


def run_jobs():
    job = db.q1("SELECT * FROM jobs WHERE status='pending' ORDER BY id LIMIT 1")
    if not job:
        return
    ips = None if job["ips"] == "*" else json.loads(job["ips"])
    checker.run(ips, job_id=job["id"])


def cleanup():
    cutoff = int(time.time()) - settings.get("retention_days") * 86400
    db.x("DELETE FROM results WHERE ts < ?", (cutoff,))
    db.x("DELETE FROM jobs WHERE status='done' AND finished_at < ?", (int(time.time()) - 7 * 86400,))
    # застрявшие задания (например, после перезапуска контейнера)
    db.x("UPDATE jobs SET status='done', finished_at=? WHERE status='running' AND started_at < ?",
         (int(time.time()), int(time.time()) - 3600))


TASKS = {
    "sync_nodes": ("Синхронизация нод", sources.sync_nodes),
    "scheduled_check": ("Плановая проверка", lambda: checker.run()),
    "run_jobs": ("Очередь ручных заданий", run_jobs),
    "cleanup": ("Очистка истории", cleanup),
    "egress_watchdog": ("Исходящий VPS (watchdog)", egress.watchdog),
    "tunnel_watchdog": ("Туннель к VPS (watchdog)", tunnel.watchdog),
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
        "scheduled_check": IntervalTrigger(minutes=max(1, settings.get("check_interval_min"))),
        "run_jobs": IntervalTrigger(seconds=max(1, settings.get("jobs_poll_sec"))),
        "cleanup": IntervalTrigger(days=1),
        "egress_watchdog": IntervalTrigger(seconds=30),
        "tunnel_watchdog": IntervalTrigger(seconds=30),
    }


def setup():
    now = datetime.now(timezone.utc)
    first = {"sync_nodes": 5, "scheduled_check": 30, "run_jobs": 10, "cleanup": 60, "egress_watchdog": 15, "tunnel_watchdog": 20}
    for name, trig in _triggers().items():
        sched.add_job(_wrap(name, TASKS[name][1]), trig, id=name,
                      next_run_time=now + timedelta(seconds=first[name]))
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
        out.append({"name": name, "label": label, "last": last_run.get(name),
                    "next": int(nxt) if nxt else None, "error": last_error.get(name)})
    return out
