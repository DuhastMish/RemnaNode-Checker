"""WireGuard-туннель чекер → VPS. Контейнер управляет интерфейсом сам
(network_mode: host + NET_ADMIN), конфиг лежит в /etc/wireguard/wg0.conf."""
import os
import re
import subprocess
import threading
import time

from . import config, settings

CONF = os.path.join(config.WG_DIR, f"{config.WG_IFACE}.conf")
IFACE = config.WG_IFACE

last_apply = {"ts": None, "ok": None, "msg": "", "busy": False}


def sh(args, timeout=30, input=None):
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout, input=input)
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return subprocess.CompletedProcess(args, 127, "", f"{args[0]}: {e}")


def genkey():
    priv = sh(["wg", "genkey"]).stdout.strip()
    pub = sh(["wg", "pubkey"], input=priv + "\n").stdout.strip()
    return priv, pub


def ensure_keys():
    if not settings.get("wg_client_privkey") or not settings.get("wg_client_pubkey"):
        priv, pub = genkey()
        settings.set_many({"wg_client_privkey": priv, "wg_client_pubkey": pub}, history=False)


def regen_keys():
    priv, pub = genkey()
    settings.set_many({"wg_client_privkey": priv, "wg_client_pubkey": pub})
    return pub


def _network():
    a = settings.get("wg_server_addr").split(".")
    return ".".join(a[:3]) + ".0/24"


def build_conf():
    return (
        "[Interface]\n"
        f"Address = {settings.get('wg_client_addr')}/24\n"
        f"PrivateKey = {settings.get('wg_client_privkey')}\n\n"
        "[Peer]\n"
        f"PublicKey = {settings.get('wg_server_pubkey')}\n"
        f"Endpoint = {settings.get('wg_endpoint')}\n"
        f"AllowedIPs = {_network()}\n"
        f"PersistentKeepalive = {settings.get('wg_keepalive')}\n"
    )


def peer_block():
    return (
        "[Peer]\n"
        "# чекер (nodecheck)\n"
        f"PublicKey = {settings.get('wg_client_pubkey')}\n"
        f"AllowedIPs = {settings.get('wg_client_addr')}/32\n"
    )


def validate():
    errs = []
    if not re.match(r"^[\w.\-\[\]:]+:\d{1,5}$", settings.get("wg_endpoint") or ""):
        errs.append("адрес VPS должен быть вида IP:порт")
    if not re.match(r"^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw480]=$", settings.get("wg_server_pubkey") or ""):
        errs.append("публичный ключ VPS выглядит некорректно")
    for k in ("wg_server_addr", "wg_client_addr"):
        if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", settings.get(k) or ""):
            errs.append(f"{settings.META[k]['label']}: не IPv4")
    return errs


def is_up():
    return sh(["ip", "link", "show", IFACE]).returncode == 0


def status():
    if not is_up():
        return {"up": False, "peers": []}
    out = sh(["wg", "show", IFACE, "dump"]).stdout.strip().splitlines()
    info = {"up": True, "peers": []}
    if out:
        p = out[0].split("\t")
        info["pubkey"] = p[1] if len(p) > 1 else ""
        info["port"] = p[2] if len(p) > 2 else ""
    for line in out[1:]:
        p = line.split("\t")
        if len(p) < 8:
            continue
        hs = int(p[4] or 0)
        info["peers"].append({
            "pubkey": p[0], "endpoint": p[2], "allowed": p[3],
            "handshake": hs, "handshake_age": None if hs == 0 else int(time.time() - hs),
            "rx": int(p[5] or 0), "tx": int(p[6] or 0), "keepalive": p[7],
        })
    return info


def handshake_age():
    st = status()
    if not st["up"] or not st["peers"]:
        return None
    return st["peers"][0]["handshake_age"]


def up():
    r = sh(["wg-quick", "up", IFACE], timeout=60)
    return r.returncode == 0, (r.stderr or r.stdout).strip()[-400:]


def down():
    if is_up():
        sh(["wg-quick", "down", IFACE], timeout=60)


def wait_ok(timeout=30):
    deadline = time.time() + timeout
    while time.time() < deadline:
        sh(["ping", "-c", "1", "-W", "2", settings.get("wg_server_addr")], timeout=5)
        age = handshake_age()
        if age is not None and age < 60:
            return True
        time.sleep(2)
    return False


def _write(text):
    os.makedirs(config.WG_DIR, exist_ok=True)
    with open(CONF, "w") as f:
        f.write(text)
    os.chmod(CONF, 0o600)


def apply():
    """Записать конфиг, перезапустить, дождаться handshake; иначе откатить."""
    errs = validate()
    if errs:
        return False, "; ".join(errs)
    old = open(CONF).read() if os.path.exists(CONF) else None
    down()
    _write(build_conf())
    ok, err = up()
    if ok and wait_ok():
        return True, "Туннель поднят, handshake с VPS получен"
    down()
    if old is not None:
        _write(old)
        up()
        return False, f"Нет handshake за 30 с — вернул предыдущий конфиг. {err}"
    os.remove(CONF)
    return False, f"Нет handshake за 30 с — конфиг удалён. Проверь ключи, адрес и [Peer] на VPS. {err}"


def apply_async():
    """Применение идёт в фоне: во время перезапуска туннеля HTTP-ответ через него не доставить."""
    if last_apply["busy"]:
        return
    last_apply.update(busy=True, ts=int(time.time()), ok=None, msg="применяю…")

    def _run():
        try:
            ok, msg = apply_any()
        except Exception as e:
            ok, msg = False, f"ошибка: {e}"
        last_apply.update(busy=False, ts=int(time.time()), ok=ok, msg=msg)

    threading.Thread(target=_run, daemon=True).start()


def up_if_configured():
    if os.path.exists(CONF) and not is_up():
        up()


# ---------- автонастройка VPS по SSH ----------

last_provision = {"ts": None, "ok": None, "msg": "", "busy": False}

# Скрипт выполняется на VPS под root. Идемпотентен: ключи и Interface создаёт только если их нет,
# свой [Peer] заменяет по маркерам, чужие записи в wg0.conf не трогает.
REMOTE_SCRIPT = r"""
set -e
export DEBIAN_FRONTEND=noninteractive
if ! command -v wg >/dev/null 2>&1; then
  apt-get update -qq >/dev/null
  apt-get install -y -qq wireguard >/dev/null
fi
mkdir -p /etc/wireguard && cd /etc/wireguard
umask 077
[ -s server.key ] || wg genkey > server.key
[ -s server.pub ] || wg pubkey < server.key > server.pub
if [ ! -f wg0.conf ]; then
  printf '[Interface]\nAddress = %s/24\nListenPort = %s\nPrivateKey = %s\n' "__SERVER_ADDR__" "__PORT__" "$(cat server.key)" > wg0.conf
fi
# заменить свой блок
awk '/^# nodecheck-peer-begin/{skip=1} !skip{print} /^# nodecheck-peer-end/{skip=0}' wg0.conf > wg0.conf.new
printf '\n# nodecheck-peer-begin\n[Peer]\nPublicKey = %s\nAllowedIPs = %s/32\n# nodecheck-peer-end\n' "__CLIENT_PUB__" "__CLIENT_ADDR__" >> wg0.conf.new
mv wg0.conf.new wg0.conf
chmod 600 wg0.conf server.key
systemctl enable wg-quick@wg0 >/dev/null 2>&1 || true
systemctl restart wg-quick@wg0
command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active' && ufw allow __PORT__/udp >/dev/null 2>&1 || true
echo "NODECHECK_SERVER_PUB=$(cat server.pub)"
"""


def provision():
    """Зайти на VPS по SSH, настроить там WireGuard-сервер, забрать его ключ, поднять туннель у себя."""
    host = settings.get("wg_vps_host").strip()
    user = settings.get("wg_vps_user").strip() or "root"
    pw = settings.get("wg_vps_password")
    if not host or not pw:
        return False, "Заполни IP, логин и пароль VPS в блоке «Туннель» и сохрани"
    ensure_keys()
    script = (REMOTE_SCRIPT
              .replace("__SERVER_ADDR__", settings.get("wg_server_addr"))
              .replace("__PORT__", str(settings.get("wg_port")))
              .replace("__CLIENT_PUB__", settings.get("wg_client_pubkey"))
              .replace("__CLIENT_ADDR__", settings.get("wg_client_addr")))
    remote_cmd = "bash -s" if user == "root" else "sudo -n bash -s"
    cmd = [
        "sshpass", "-e", "ssh",
        "-p", str(settings.get("wg_vps_ssh_port")),
        "-o", "ConnectTimeout=15",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "LogLevel=ERROR",
        f"{user}@{host}", remote_cmd,
    ]
    env = dict(os.environ, SSHPASS=pw)
    try:
        r = subprocess.run(cmd, input=script, capture_output=True, text=True, timeout=240, env=env)
    except subprocess.TimeoutExpired:
        return False, "VPS не ответил за 4 минуты (apt завис?)"
    except FileNotFoundError as e:
        return False, f"нет {e.filename} в контейнере"
    if r.returncode != 0:
        err = (r.stderr or r.stdout).strip()[-500:]
        if "Permission denied" in err:
            err = "SSH: неверный логин/пароль (или вход по паролю запрещён в sshd_config)"
        elif "sudo" in err and "password" in err:
            err = "у пользователя нет sudo без пароля — используй root"
        return False, f"VPS: {err}"
    m = re.search(r"NODECHECK_SERVER_PUB=(\S+)", r.stdout)
    if not m:
        return False, f"VPS не вернул ключ: {r.stdout[-300:]}"
    settings.set_many({
        "wg_server_pubkey": m.group(1),
        "wg_endpoint": f"{host}:{settings.get('wg_port')}",
    })
    ok, msg = apply()
    return ok, ("VPS настроен, " + msg) if ok else ("VPS настроен, но " + msg)


def provision_async():
    if last_provision["busy"]:
        return
    last_provision.update(busy=True, ts=int(time.time()), ok=None, msg="настраиваю VPS…")

    def _run():
        try:
            ok, msg = provision_any()
        except Exception as e:
            ok, msg = False, f"ошибка: {e}"
        last_provision.update(busy=False, ts=int(time.time()), ok=ok, msg=msg)

    threading.Thread(target=_run, daemon=True).start()


# ---------- режим SSH: обратный туннель ssh -R ----------
# Чекер держит SSH-сессию к VPS и пробрасывает на него свои порты 8000 (приложение)
# и 7681 (ttyd). На VPS порты открываются на ssh_bind_addr — адресе, который видит
# nginx в docker. Провайдерские DPI SSH не режут, в отличие от WireGuard.

_ssh_proc: subprocess.Popen | None = None
_ssh_log = os.path.join(config.DATA_DIR, "ssh-tunnel.log")
ssh_state = {"started": None, "restarts": 0}


def mode():
    return settings.get("tunnel_mode") or "ssh"


def _ssh_base(extra_opts=()):
    return [
        "sshpass", "-e", "ssh",
        "-p", str(settings.get("wg_vps_ssh_port")),
        "-o", "ConnectTimeout=15",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "LogLevel=ERROR",
        *extra_opts,
        f"{(settings.get('wg_vps_user') or 'root').strip()}@{settings.get('wg_vps_host').strip()}",
    ]


def _ssh_env():
    return dict(os.environ, SSHPASS=settings.get("wg_vps_password") or "")


def ssh_creds_ok():
    return bool(settings.get("wg_vps_host").strip() and settings.get("wg_vps_password"))


def ssh_start():
    global _ssh_proc
    ssh_stop()
    if not ssh_creds_ok():
        return
    b = settings.get("ssh_bind_addr").strip() or "127.0.0.1"
    cmd = _ssh_base([
        "-N",
        "-o", "ServerAliveInterval=20",
        "-o", "ServerAliveCountMax=3",
        "-o", "ExitOnForwardFailure=yes",
        "-R", f"{b}:{settings.get('ssh_app_port')}:127.0.0.1:8000",
        "-R", f"{b}:{settings.get('ssh_ttyd_port')}:127.0.0.1:7681",
    ])
    os.makedirs(config.DATA_DIR, exist_ok=True)
    log = open(_ssh_log, "ab")
    log.write(f"\n--- {time.strftime('%Y-%m-%d %H:%M:%S')} start\n".encode())
    _ssh_proc = subprocess.Popen(cmd, env=_ssh_env(), stdout=log, stderr=log)
    ssh_state["started"] = int(time.time())


def ssh_stop():
    global _ssh_proc
    if _ssh_proc and _ssh_proc.poll() is None:
        _ssh_proc.terminate()
        try:
            _ssh_proc.wait(5)
        except subprocess.TimeoutExpired:
            _ssh_proc.kill()
    _ssh_proc = None


def ssh_alive():
    return _ssh_proc is not None and _ssh_proc.poll() is None


def ssh_log_tail(n=6):
    try:
        with open(_ssh_log, "rb") as f:
            return [l.decode(errors="ignore").rstrip() for l in f.readlines()[-n:]]
    except OSError:
        return []


def ssh_test():
    """С VPS: отвечает ли проброшенный порт приложения."""
    url = f"http://{settings.get('ssh_bind_addr')}:{settings.get('ssh_app_port')}/login"
    r = subprocess.run(_ssh_base() + [f"curl -s -m 5 -o /dev/null -w '%{{http_code}}' {url}"],
                       capture_output=True, text=True, timeout=40, env=_ssh_env())
    code = r.stdout.strip().strip("'")
    if r.returncode != 0:
        return False, f"SSH до VPS не прошёл: {(r.stderr or r.stdout).strip()[-200:]}"
    if code == "200":
        return True, f"VPS видит приложение на {url}"
    return False, f"VPS не достучался до {url} (curl: {code or 'нет ответа'}). Туннель запущен? Адрес bind верный?"


SSHD_SCRIPT = r"""
set -e
f=/etc/ssh/sshd_config
if grep -qE '^\s*GatewayPorts' $f; then
  sed -i 's/^\s*GatewayPorts.*/GatewayPorts clientspecified/' $f
else
  echo 'GatewayPorts clientspecified' >> $f
fi
(systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || service ssh reload)
echo NODECHECK_SSHD_OK
"""


def ssh_provision():
    """Разрешить на VPS привязку пробросов к не-localhost адресу, затем поднять туннель."""
    if not ssh_creds_ok():
        return False, "Заполни IP, логин и пароль VPS и сохрани"
    user = (settings.get("wg_vps_user") or "root").strip()
    remote_cmd = "bash -s" if user == "root" else "sudo -n bash -s"
    try:
        r = subprocess.run(_ssh_base() + [remote_cmd], input=SSHD_SCRIPT, capture_output=True,
                           text=True, timeout=60, env=_ssh_env())
    except subprocess.TimeoutExpired:
        return False, "VPS не ответил за минуту"
    if r.returncode != 0 or "NODECHECK_SSHD_OK" not in r.stdout:
        err = (r.stderr or r.stdout).strip()[-300:]
        if "Permission denied" in err:
            err = "SSH: неверный логин/пароль (или вход по паролю запрещён в sshd_config)"
        return False, f"VPS: {err}"
    ssh_start()
    time.sleep(6)
    if not ssh_alive():
        return False, "sshd на VPS настроен, но туннель упал сразу: " + " | ".join(ssh_log_tail(3))
    ok, msg = ssh_test()
    return ok, ("sshd настроен, туннель поднят. " + msg) if ok else ("туннель поднят, но " + msg)


def watchdog():
    """Раз в 30 с из планировщика: в режиме ssh перезапускать упавший туннель."""
    if mode() == "ssh" and ssh_creds_ok() and not ssh_alive():
        ssh_state["restarts"] += 1
        ssh_start()


def start_if_configured():
    if mode() == "ssh":
        if ssh_creds_ok():
            ssh_start()
    else:
        up_if_configured()


def provision_any():
    return ssh_provision() if mode() == "ssh" else provision()


def apply_any():
    if mode() == "ssh":
        ssh_start()
        time.sleep(6)
        if not ssh_alive():
            return False, "туннель не поднялся: " + " | ".join(ssh_log_tail(3))
        return ssh_test()
    return apply()


def ui_status():
    if mode() == "ssh":
        return {"mode": "ssh", "up": ssh_alive(), "since": ssh_state["started"],
                "restarts": ssh_state["restarts"], "log": ssh_log_tail(), "peers": []}
    st = status()
    st["mode"] = "wireguard"
    return st
