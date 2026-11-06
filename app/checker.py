"""Прогон проверок по списку нод. Используется и планировщиком, и ручными заданиями."""
import re
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from . import config, db, exporter, probes, settings

_lock = threading.Lock()
running = {"active": False, "total": 0, "done": 0, "started": None, "job_id": None}


def state_of(ssh_ok, proxy_ok):
    """green — прокси работает; yellow — сервер жив, прокси нет; red — недоступен."""
    if proxy_ok is True:
        return "green"
    if proxy_ok is False:
        return "yellow" if ssh_ok else "red"
    return "green" if ssh_ok else "red"


TARGET_RE = re.compile(r"^(?P<host>[A-Za-z0-9.\-]{1,253})(?::(?P<port>\d{1,5}))?$")


def parse_target(text):
    """'host', 'ip' или 'host:port' → (host, port|None). None — если мусор."""
    m = TARGET_RE.match((text or "").strip())
    if not m:
        return None
    port = int(m.group("port")) if m.group("port") else None
    if port is not None and not (1 <= port <= 65535):
        return None
    return m.group("host"), port


def resolve(host):
    try:
        for fam, _, _, _, addr in socket.getaddrinfo(host, None, socket.AF_INET):
            return addr[0]
    except socket.gaierror:
        return None
    return None


def _node_for(target):
    """Цель из списка нод — берём ноду; иначе — разовая цель (adhoc)."""
    parsed = parse_target(target)
    if not parsed:
        return None
    host, port = parsed
    ip = resolve(host)
    if not ip:
        return None
    row = db.q1("SELECT * FROM nodes WHERE ip=?", (ip,))
    if row:
        n = dict(row)
        if port:
            n["fresh_port"] = port
        n["label"] = n["name"]
        return n
    label = target if host == ip else f"{target} ({ip})"
    return {"ip": ip, "project": "adhoc", "name": "", "flags": "", "fresh_port": port, "label": label}


def _one(node, cfg):
    ip = node["ip"]
    ssh = probes.check_ssh(ip, cfg["probes"])
    ssh_ok = probes.is_reachable(ssh)
    proxy_ok, proxy, ms = None, "", None
    if node["fresh_port"]:
        proxy_ok, proxy, ms = probes.check_proxy(
            ip, node["fresh_port"], cfg["probe_url"], cfg["proxy_timeout"])
    return {
        "ip": ip, "project": node["project"], "name": node["name"], "label": node.get("label") or node["name"],
        "ssh_status": ssh, "ssh_ok": 1 if ssh_ok else 0,
        "proxy_status": proxy, "proxy_ok": None if proxy_ok is None else (1 if proxy_ok else 0),
        "state": state_of(ssh_ok, proxy_ok), "latency_ms": ms,
    }


def run(ips=None, job_id=None, vantage=None):
    vantage = vantage or config.VANTAGE
    with _lock:
        if ips:
            nodes = [n for n in (_node_for(t) for t in ips) if n]
        else:
            nodes = [dict(r) for r in db.q("SELECT * FROM nodes WHERE is_active=1")]
        cfg = {
            "probes": settings.get("probes"),
            "probe_url": settings.get("open60_probe_url"),
            "proxy_timeout": settings.get("proxy_timeout_sec"),
        }
        now = int(time.time())
        running.update(active=True, total=len(nodes), done=0, started=now, job_id=job_id)
        if job_id:
            db.x("UPDATE jobs SET status='running', started_at=?, total=? WHERE id=?",
                 (now, len(nodes), job_id))

        results = []
        try:
            with ThreadPoolExecutor(max_workers=max(1, settings.get("max_workers"))) as pool:
                futs = [pool.submit(_one, n, cfg) for n in nodes]
                for fut in as_completed(futs):
                    r = fut.result()
                    r["ts"] = int(time.time())
                    r["vantage"] = vantage
                    db.x(
                        "INSERT INTO results(ip, vantage, job_id, ts, ssh_status, ssh_ok, "
                        "proxy_status, proxy_ok, state, latency_ms, label) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                        (r["ip"], vantage, job_id, r["ts"], r["ssh_status"], r["ssh_ok"],
                         r["proxy_status"], r["proxy_ok"], r["state"], r["latency_ms"], r["label"]),
                    )
                    results.append(r)
                    running["done"] += 1
                    if job_id:
                        db.x("UPDATE jobs SET done=? WHERE id=?", (running["done"], job_id))
        finally:
            running.update(active=False, job_id=None)
            if job_id:
                db.x("UPDATE jobs SET status='done', finished_at=? WHERE id=?",
                     (int(time.time()), job_id))

        if results:
            exporter.push(results, vantage)
        return results
