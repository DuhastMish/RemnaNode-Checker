import os

DATA_DIR = os.environ.get("DATA_DIR", "/data")
DB_PATH = os.path.join(DATA_DIR, "panel.db")

WG_DIR = os.environ.get("WG_DIR", "/etc/wireguard")
WG_IFACE = os.environ.get("WG_IFACE", "wg0")

# По Host запроса приложение понимает, в каком режиме работать: STATUS_HOST — режим status,
# всё остальное (admin-домен, доступ по IP) — режим admin.
STATUS_HOST = os.environ.get("STATUS_HOST", "").strip().lower()
# Домен admin: на него Caddy получает сертификат, его же панель подставляет в команду запуска чекера
ADMIN_HOST = os.environ.get("ADMIN_HOST", "").strip().lower()

# Начальные значения; после первого старта живут в таблице settings
ENV_ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "").strip()
ENV_PIN = os.environ.get("PIN", "").strip()
