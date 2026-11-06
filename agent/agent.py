"""Чекер nodecheck: забирает у панели список нод, проверяет их из своей сети, отправляет результаты.

Окружение:
  PANEL_URL      адрес панели (https://…; http разрешён только для localhost)
  CHECKER_TOKEN  токен чекера из панели (раздел «Чекеры»)

Работает только исходящими запросами (за NAT — нормально). Список нод и конфиг — только в памяти.
Если панель недоступна — проверяет по кэшу, но результаты не буферизует (неотправленные теряются).
В логи адреса нод не пишутся — только node_id и счётчики.
"""

import json
import logging
import os
import signal
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor

import probes

VERSION = "2.0.0"
BATCH = 200

log = logging.getLogger("agent")
stop = threading.Event()


class ApiError(Exception):
    def __init__(self, status, text=""):
        super().__init__(f"HTTP {status} {text[:120]}")
        self.status = status


class Panel:
    def __init__(self, url, token):
        self.url = url.rstrip("/") + "/api/v1/agent"
        self.token = token

    def call(self, method, path, body=None, timeout=30):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            self.url + path,
            data=data,
            method=method,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": f"nodecheck-agent/{VERSION}",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.load(resp)
        except urllib.error.HTTPError as e:
            raise ApiError(e.code, e.read().decode(errors="ignore")) from None


# ---------- проверка одной цели ----------


def state_of(ssh_ok, proxy_ok):
    """green — прокси работает (или его нет, а SSH отвечает); yellow — SSH есть, прокси нет; red — ничего."""
    if proxy_ok is True:
        return "green"
    if proxy_ok is False:
        return "yellow" if ssh_ok else "red"
    return "green" if ssh_ok else "red"


def resolve(host):
    try:
        for *_, addr in socket.getaddrinfo(host, None, socket.AF_INET):
            return addr[0]
    except (socket.gaierror, UnicodeError):
        return None
    return None


def check_target(t, cfg, job_id=None):
    """t: {node_id|None, address, rev|None, fresh_port|port}. Возвращает результат для панели."""
    address = t["address"]
    port = t.get("fresh_port") if "fresh_port" in t else t.get("port")
    ip = resolve(address)
    proxy_ok, proxy_status, ms = None, "", None
    if not ip:
        ssh_status, ssh_ok = "DNS FAIL", False
    else:
        ssh_status = probes.check_ssh(ip, cfg.get("probes", 2))
        ssh_ok = probes.is_reachable(ssh_status)
        if port:
            proxy_ok, proxy_status, ms = probes.check_proxy(
                ip, port, cfg.get("proxy_probe_url"), cfg.get("proxy_timeout_sec", 8)
            )
    return {
        "result_uid": str(uuid.uuid4()),
        "node_id": t.get("node_id"),
        "node_rev": t.get("rev"),
        "target_address": address,
        "target_port": port,
        "ts": int(time.time()),
        "job_id": job_id,
        "ssh": {"status": ssh_status, "ok": ssh_ok},
        "proxy": {"status": proxy_status, "ok": proxy_ok, "latency_ms": ms},
        "state": state_of(ssh_ok, proxy_ok),
    }


# ---------- агент ----------


class Agent:
    def __init__(self, panel):
        self.panel = panel
        self.config = {}
        self.config_rev = None
        self.nodes = []
        self.nodes_rev = None
        self.heartbeat_sec = 30
        self.check_running = threading.Event()

    # --- синхронизация с панелью ---

    def hello(self):
        """Регистрация с backoff до успеха. Без связи с панелью проверять нечего."""
        delay = 5
        while not stop.is_set():
            try:
                r = self.panel.call("POST", "/hello", {"version": VERSION})
                self.heartbeat_sec = int(r.get("heartbeat_sec") or 30)
                log.info("подключён к панели как «%s» (%s)", r.get("name"), r.get("checker_id"))
                self.refresh(r.get("config_revision"), r.get("nodes_revision"), force=True)
                return True
            except ApiError as e:
                if e.status in (401, 403):
                    log.error("панель отклонила токен (%s): чекер отключён или токен отозван", e.status)
                else:
                    log.warning("hello: %s", e)
            except OSError as e:
                log.warning("панель недоступна: %s", e)
            stop.wait(delay)
            delay = min(delay * 2, 60)
        return False

    def refresh(self, config_rev, nodes_rev, force=False):
        if force or config_rev != self.config_rev:
            cfg = self.panel.call("GET", "/config")
            self.config, self.config_rev = cfg, cfg.get("revision")
            log.info("конфиг обновлён (ревизия %s)", self.config_rev)
        if force or nodes_rev != self.nodes_rev:
            data = self.panel.call("GET", "/nodes")
            self.nodes, self.nodes_rev = data.get("nodes") or [], data.get("revision")
            active = sum(1 for n in self.nodes if n.get("is_active"))
            log.info("список нод обновлён: %d, активных %d (ревизия %s)", len(self.nodes), active, self.nodes_rev)

    def heartbeat(self):
        r = self.panel.call("POST", "/heartbeat", {})
        self.refresh(r.get("config_revision"), r.get("nodes_revision"))
        return r.get("jobs") or []

    # --- проверки ---

    def send(self, results):
        sent = 0
        for i in range(0, len(results), BATCH):
            try:
                self.panel.call("POST", "/results", {"results": results[i : i + BATCH]})
                sent += len(results[i : i + BATCH])
            except (ApiError, OSError) as e:
                log.warning("результаты не отправлены (%d шт., без буферизации): %s", len(results) - sent, e)
                break
        return sent

    def run_check(self, targets, job_id=None):
        cfg = dict(self.config)
        t0 = time.time()
        with ThreadPoolExecutor(max_workers=max(1, int(cfg.get("max_workers") or 15))) as pool:
            results = list(pool.map(lambda t: check_target(t, cfg, job_id), targets))
        stats = {s: sum(1 for r in results if r["state"] == s) for s in ("green", "yellow", "red")}
        sent = self.send(results)
        log.info(
            "%s: %d целей за %.0f с — green %d, yellow %d, red %d; отправлено %d",
            f"задание #{job_id}" if job_id else "плановая проверка",
            len(results),
            time.time() - t0,
            stats["green"],
            stats["yellow"],
            stats["red"],
            sent,
        )

    def scheduled_check(self):
        try:
            self.run_check([n for n in self.nodes if n.get("is_active")])
        except Exception:
            log.exception("плановая проверка упала")
        finally:
            self.check_running.clear()

    # --- главный цикл ---

    def loop(self):
        if not self.hello():
            return
        next_hb = time.time() + self.heartbeat_sec
        next_check = time.time()
        while not stop.is_set():
            now = time.time()
            if now >= next_hb:
                next_hb = now + self.heartbeat_sec
                try:
                    self.heartbeat()
                except ApiError as e:
                    if e.status in (401, 403):
                        log.error("токен отклонён (%s) — переподключение", e.status)
                        if not self.hello():
                            return
                    else:
                        log.warning("heartbeat: %s", e)
                except OSError as e:
                    log.warning("heartbeat: панель недоступна (%s), работаю по кэшу", e)
            if now >= next_check and not self.check_running.is_set():
                interval = max(1, int(self.config.get("check_interval_min") or 5)) * 60
                next_check = now + interval
                self.check_running.set()
                threading.Thread(target=self.scheduled_check, daemon=True).start()
            stop.wait(1)


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    url = os.environ.get("PANEL_URL", "").strip()
    token = os.environ.get("CHECKER_TOKEN", "").strip()
    if not url or not token:
        raise SystemExit("нужны переменные PANEL_URL и CHECKER_TOKEN")
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" and parsed.hostname not in ("localhost", "127.0.0.1", "::1"):
        raise SystemExit("PANEL_URL должен быть https:// (http разрешён только для localhost)")
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    log.info("nodecheck-agent %s, панель %s", VERSION, url)
    Agent(Panel(url, token)).loop()
    log.info("остановлен")


if __name__ == "__main__":
    main()
