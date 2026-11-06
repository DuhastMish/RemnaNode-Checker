"""Исходящий VPS: через него уходят запросы наружу (экспорт статусов и т.п.).

Типы:
  none   — напрямую
  ssh    — поднимаем ssh -D (SOCKS) к VPS по логину/паролю, ходим через него
  socks5 — готовый SOCKS5-прокси на VPS
  http   — готовый HTTP-прокси на VPS
"""

import os
import subprocess

import httpx

from . import settings

_proc: subprocess.Popen | None = None
last_error = ""


def proxy_url():
    t = settings.get("egress_type") or "none"
    if t == "none" or not settings.get("egress_host"):
        return None
    if t == "ssh":
        return f"socks5h://127.0.0.1:{settings.get('egress_local_port')}"
    user, pw = settings.get("egress_user"), settings.get("egress_password")
    auth = f"{user}:{pw}@" if user else ""
    scheme = "socks5h" if t == "socks5" else "http"
    return f"{scheme}://{auth}{settings.get('egress_host')}:{settings.get('egress_port')}"


def stop():
    global _proc
    if _proc and _proc.poll() is None:
        _proc.terminate()
        try:
            _proc.wait(5)
        except subprocess.TimeoutExpired:
            _proc.kill()
    _proc = None


def ensure():
    """Привести состояние в соответствие настройкам (вызывать после сохранения)."""
    global _proc, last_error
    stop()
    if settings.get("egress_type") != "ssh" or not settings.get("egress_host"):
        return
    env = dict(os.environ, SSHPASS=settings.get("egress_password") or "")
    cmd = [
        "sshpass",
        "-e",
        "ssh",
        "-N",
        "-D",
        f"127.0.0.1:{settings.get('egress_local_port')}",
        "-p",
        str(settings.get("egress_port")),
        "-o",
        "ServerAliveInterval=30",
        "-o",
        "ServerAliveCountMax=3",
        "-o",
        "ExitOnForwardFailure=yes",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        f"{settings.get('egress_user')}@{settings.get('egress_host')}",
    ]
    try:
        _proc = subprocess.Popen(cmd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        last_error = ""
    except Exception as e:
        last_error = str(e)


def watchdog():
    """Планировщик дёргает раз в 30 с: если ssh-туннель упал — поднять."""
    if settings.get("egress_type") == "ssh" and settings.get("egress_host"):
        if _proc is None or _proc.poll() is not None:
            ensure()


def alive():
    t = settings.get("egress_type") or "none"
    if t == "none" or not settings.get("egress_host"):
        return None
    if t == "ssh":
        return _proc is not None and _proc.poll() is None
    return True


def test():
    """Возвращает внешний IP, который видит мир при выходе через egress."""
    r = httpx.get("https://api.ipify.org?format=json", proxy=proxy_url(), timeout=15)
    r.raise_for_status()
    return r.json().get("ip")
