"""Настройки в таблице settings: кэш в памяти, история изменений, дефолты."""
import json
import secrets
import threading
import time

from . import config, db

# (section, key, label, type, default, help)
# type: int | str | bool | secret
FIELDS = [
    # --- планировщик ---
    ("scheduler", "sync_interval_min", "Синхронизация нод из панелей, мин", "int", 10, ""),
    ("scheduler", "check_interval_min", "Плановая проверка всех нод, мин", "int", 5, ""),
    ("scheduler", "jobs_poll_sec", "Опрос очереди ручных заданий, с", "int", 3, ""),
    ("scheduler", "retention_days", "Хранить историю результатов, дней", "int", 30, ""),
    ("scheduler", "max_workers", "Воркеров в пуле", "int", 15, "сколько нод проверяется одновременно"),
    ("scheduler", "probes", "Попыток SSH на ноду", "int", 2, ""),
    ("scheduler", "proxy_timeout_sec", "Таймаут пробы через прокси, с", "int", 8, ""),
    ("scheduler", "status_cache_sec", "Кэш результата для status-страницы, с", "int", 60, "повторная ручная проверка раньше этого срока отдаёт кэш"),
    # --- источники ---
    ("sources", "remnawave_url", "Remnawave URL", "str", "", "например https://panel.example.com"),
    ("sources", "remnawave_token", "Remnawave токен", "secret", "", ""),
    ("sources", "open60_url", "Open60 URL", "str", "", "например https://api.example.com"),
    ("sources", "open60_token", "Open60 ADMIN_TOKEN", "secret", "", ""),
    ("sources", "open60_probe_url", "URL пробы через прокси", "str", "", "ответ должен содержать ip ноды, например https://api.example.com/probe"),
    # --- туннель ---
    ("tunnel", "tunnel_mode", "Транспорт", "str", "ssh", "ssh — обратный SSH-туннель, провайдеры не режут; wireguard — быстрее, но ТСПУ блокирует"),
    ("tunnel", "wg_vps_host", "VPS: IP для SSH", "str", "", "обычно тот же, что исходящий"),
    ("tunnel", "wg_vps_ssh_port", "VPS: порт SSH", "int", 22, ""),
    ("tunnel", "wg_vps_user", "VPS: логин", "str", "root", "root или пользователь с sudo без пароля"),
    ("tunnel", "wg_vps_password", "VPS: пароль", "secret", "", "используется только при автонастройке"),
    ("tunnel", "ssh_bind_addr", "SSH: адрес на VPS для пробросов", "str", "172.18.0.1", "адрес, по которому nginx в docker видит хост (gateway его сети); 127.0.0.1 если nginx на хосте"),
    ("tunnel", "ssh_app_port", "SSH: порт приложения на VPS", "int", 18000, "nginx → proxy_pass на этот порт"),
    ("tunnel", "ssh_ttyd_port", "SSH: порт терминала на VPS", "int", 17681, ""),
    ("tunnel", "wg_port", "WG: порт WireGuard на VPS", "int", 4443, "не 51820 — его режут первым"),
    ("tunnel", "wg_endpoint", "WG: адрес VPS (IP:порт)", "str", "", "заполнится автонастройкой; или вручную 1.2.3.4:51820"),
    ("tunnel", "wg_server_pubkey", "WG: публичный ключ VPS", "str", "", "заполнится автонастройкой; или содержимое server.pub"),
    ("tunnel", "wg_server_addr", "WG: адрес VPS в туннеле", "str", "10.8.0.1", ""),
    ("tunnel", "wg_client_addr", "WG: адрес чекера в туннеле", "str", "10.8.0.2", ""),
    ("tunnel", "wg_keepalive", "WG: PersistentKeepalive, с", "int", 25, "обязателен за NAT провайдера"),
    ("tunnel", "wg_client_privkey", "WG: приватный ключ чекера", "secret", "", "генерируется автоматически"),
    ("tunnel", "wg_client_pubkey", "WG: публичный ключ чекера", "str", "", ""),
    # --- исходящий VPS ---
    ("egress", "egress_type", "Тип", "str", "none", "none | ssh | socks5 | http"),
    ("egress", "egress_host", "Хост", "str", "", ""),
    ("egress", "egress_port", "Порт", "int", 22, "22 для ssh, 1080 для socks5, 3128 для http"),
    ("egress", "egress_user", "Логин", "str", "", ""),
    ("egress", "egress_password", "Пароль", "secret", "", ""),
    ("egress", "egress_local_port", "Локальный порт SOCKS (для ssh)", "int", 1080, ""),
    # --- экспорт ---
    ("export", "export_enabled", "Отправлять результаты в бэкенды", "bool", False, ""),
    ("export", "export_remnawave_url", "Remnawave: URL приёма", "str", "", "POST JSON после каждой проверки"),
    ("export", "export_remnawave_token", "Remnawave: токен", "secret", "", "Authorization: Bearer"),
    ("export", "export_open60_url", "Open60: URL приёма", "str", "", ""),
    ("export", "export_open60_token", "Open60: токен", "secret", "", ""),
    # --- доступ ---
    ("access", "admin_token", "Admin-токен", "secret", "", "пусто — не менять"),
    ("access", "pin", "PIN для status-страницы", "secret", "", "пусто — не менять"),
    ("access", "cookie_days", "Время жизни сессии, дней", "int", 30, ""),
    ("access", "ttyd_url", "URL веб-терминала", "str", "/ttyd/", "как его проксирует Caddy"),
]

SECTIONS = [
    ("scheduler", "Планировщик"),
    ("sources", "Источники нод"),
    ("tunnel", "Туннель чекер ↔ VPS"),
    ("egress", "Исходящий VPS"),
    ("export", "Экспорт статусов"),
    ("access", "Доступ"),
]

META = {f[1]: {"section": f[0], "label": f[2], "type": f[3], "default": f[4], "help": f[5]} for f in FIELDS}

_cache: dict = {}
_lock = threading.Lock()


def _parse(key, raw):
    t = META[key]["type"]
    if raw is None:
        return META[key]["default"]
    if t == "int":
        try:
            return int(raw)
        except (TypeError, ValueError):
            return META[key]["default"]
    if t == "bool":
        return str(raw).lower() in ("1", "true", "yes", "on")
    return raw


def _dump(key, value):
    t = META[key]["type"]
    if t == "bool":
        return "1" if value else "0"
    return "" if value is None else str(value)


def load():
    with _lock:
        _cache.clear()
        stored = {r["key"]: r["value"] for r in db.q("SELECT key, value FROM settings")}
        for key in META:
            _cache[key] = _parse(key, stored.get(key))


def get(key):
    return _cache[key]


def all_values():
    return dict(_cache)


def set_many(values: dict, history=True):
    """Записывает изменившиеся ключи, пишет историю, обновляет кэш."""
    now = int(time.time())
    changed = []
    with _lock:
        c = db.conn()
        for key, value in values.items():
            if key not in META:
                continue
            new = _dump(key, value)
            old = _dump(key, _cache.get(key))
            if new == old:
                continue
            c.execute(
                "INSERT INTO settings(key, value, updated_at) VALUES(?,?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
                (key, new, now),
            )
            if history:
                is_secret = META[key]["type"] == "secret"
                c.execute(
                    "INSERT INTO settings_history(key, old_value, new_value, ts) VALUES(?,?,?,?)",
                    (key, "***" if is_secret else old, "***" if is_secret else new, now),
                )
            _cache[key] = _parse(key, new)
            changed.append(key)
        c.commit()
    return changed


def seed():
    """Первый старт: токен и пин из .env, либо сгенерировать токен."""
    load()
    upd = {}
    if not get("admin_token"):
        upd["admin_token"] = config.ENV_ADMIN_TOKEN or secrets.token_urlsafe(32)
        if not config.ENV_ADMIN_TOKEN:
            print(f"\n=== ADMIN_TOKEN сгенерирован: {upd['admin_token']} ===\n", flush=True)
    if not get("pin"):
        upd["pin"] = config.ENV_PIN or f"{secrets.randbelow(10**6):06d}"
        if not config.ENV_PIN:
            print(f"\n=== PIN сгенерирован: {upd['pin']} ===\n", flush=True)
    if upd:
        set_many(upd, history=False)


def history(limit=20):
    return [dict(r) for r in db.q(
        "SELECT * FROM settings_history ORDER BY id DESC LIMIT ?", (limit,))]
