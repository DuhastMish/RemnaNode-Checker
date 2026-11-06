"""Пробы: SSH-попытка и проба через прокси."""

import json
import subprocess
import time
import urllib.error
import urllib.request


def one_probe(ip):
    try:
        result = subprocess.run(
            [
                "ssh",
                "-vv",
                "-o",
                "ConnectTimeout=5",
                "-o",
                "BatchMode=yes",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                f"root@{ip}",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except subprocess.TimeoutExpired:
        return "TIMEOUT (ssh завис)"
    output = result.stderr
    if "Connection reset by peer" in output:
        return "RESET"
    if "Connection timed out" in output:
        return "TIMEOUT"
    if "Connection refused" in output:
        return "REFUSED"
    if "Authentications that can continue" in output:
        return "SSH OK"
    return "UNKNOWN"


def is_reachable(status):
    return status.startswith("SSH OK") or status.startswith("REFUSED")


def check_ssh(ip, probes=2):
    status = one_probe(ip)
    if is_reachable(status):
        return status
    for _ in range(max(0, probes - 1)):
        status = one_probe(ip)
        if is_reachable(status):
            return status
    return status


def check_proxy(ip, port, probe_url, timeout=8):
    """Возвращает (ok, статус, ms). ok=None — проба не делалась."""
    if not port:
        return None, "no fresh_port", None
    if not probe_url:
        return None, "probe url not set", None
    proxy = f"http://{ip}:{port}"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    t0 = time.time()
    try:
        with opener.open(probe_url, timeout=timeout) as resp:
            body = json.load(resp)
        ms = int((time.time() - t0) * 1000)
        if body.get("ok") and body.get("ip") == ip:
            return True, f"PROXY OK {ms}ms", ms
        return False, f"PROXY WRONG IP {body.get('ip')} {ms}ms", ms
    except urllib.error.HTTPError as e:
        return False, f"PROXY HTTP {e.code}", int((time.time() - t0) * 1000)
    except Exception as e:
        ms = int((time.time() - t0) * 1000)
        msg = str(e).split("]")[-1].strip()[:40]
        if "timed out" in msg:
            return False, f"PROXY TIMEOUT {ms}ms", ms
        return False, f"PROXY FAIL {msg}", ms
