"""Два режима по Host: admin (токен) и status (PIN). Cookie подписывается
HMAC'ом текущего секрета — смена токена/пина сразу разлогинивает всех."""
import hashlib
import hmac
import threading
import time

from fastapi import HTTPException, Request

from . import config, settings

COOKIE = "nc_auth"


class AuthRequired(Exception):
    pass


def mode(request: Request) -> str:
    host = request.headers.get("host", "").split(":")[0].lower()
    if config.STATUS_HOST and host == config.STATUS_HOST:
        return "status"
    return "admin"


def _secret(role):
    return settings.get("admin_token") if role == "admin" else settings.get("pin")


def cookie_value(role):
    sig = hmac.new((_secret(role) or "x").encode(), role.encode(), hashlib.sha256).hexdigest()
    return f"{role}:{sig}"


def is_authed(request: Request, role: str) -> bool:
    return hmac.compare_digest(request.cookies.get(COOKIE, ""), cookie_value(role))


def check_credential(role, value) -> bool:
    return bool(value) and hmac.compare_digest(value, _secret(role) or "")


def require_admin(request: Request):
    if mode(request) != "admin":
        raise HTTPException(404)
    if not is_authed(request, "admin"):
        raise AuthRequired()


def require_status(request: Request):
    if not is_authed(request, "status"):
        raise AuthRequired()


def client_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "?"


class RateLimit:
    """Скользящее окно: не больше `limit` событий за `window` секунд на ключ."""

    def __init__(self, limit, window):
        self.limit, self.window = limit, window
        self._hits: dict = {}
        self._lock = threading.Lock()

    def allow(self, key) -> bool:
        now = time.time()
        with self._lock:
            hits = [t for t in self._hits.get(key, []) if now - t < self.window]
            if len(hits) >= self.limit:
                self._hits[key] = hits
                return False
            hits.append(now)
            self._hits[key] = hits
            if len(self._hits) > 5000:
                self._hits = {k: v for k, v in self._hits.items() if v and now - v[-1] < self.window}
            return True


login_limit = RateLimit(10, 60)
status_check_limit = RateLimit(5, 60)
