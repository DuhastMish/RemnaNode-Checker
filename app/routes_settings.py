"""Страница настроек: по форме на секцию, плюс действия (применить туннель, тесты, запустить задачу)."""

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse

from . import alerts, auth, egress, scheduler, settings, tunnel, views

router = APIRouter()


def _back(section, msg):
    return RedirectResponse(f"/settings?msg={msg}#{section}", status_code=303)


@router.get("/settings")
def settings_page(request: Request):
    auth.require_admin(request)
    values = settings.all_values()
    for key, meta in settings.META.items():
        if meta["type"] == "secret":
            values[key] = ""
    return views.render(
        request,
        "settings.html",
        title="Настройки",
        sections=settings.SECTIONS,
        fields=settings.FIELDS,
        values=values,
        meta=settings.META,
        tunnel=tunnel.ui_status(),
        tunnel_apply=tunnel.last_apply,
        tunnel_provision=tunnel.last_provision,
        peer_block=tunnel.peer_block(),
        client_pubkey=settings.get("wg_client_pubkey"),
        tasks=scheduler.info(),
        egress_alive=egress.alive(),
        egress_error=egress.last_error,
        last_sync=scheduler.last_sync,
        history=settings.history(15),
        alert_log=[e for e in alerts.log if e["kind"] == "alert"],
    )


@router.post("/settings")
async def settings_save(request: Request):
    auth.require_admin(request)
    form = await request.form()
    section = form.get("section", "")
    upd = {}
    for s, key, label, typ, default, _ in settings.FIELDS:
        if s != section:
            continue
        if typ == "bool":
            upd[key] = key in form
            continue
        if key not in form:  # поле скрыто по режиму — не трогаем
            continue
        raw = (form.get(key) or "").strip()
        if typ == "secret":
            if raw:
                upd[key] = raw
            continue
        if typ == "int":
            try:
                upd[key] = int(raw)
            except ValueError:
                return _back(section, f"«{label}»: нужно число")
            continue
        upd[key] = raw

    if section == "egress" and upd.get("egress_type") not in ("none", "ssh", "socks5", "http"):
        return _back(section, "Тип: none, ssh, socks5 или http")

    changed = settings.set_many(upd)
    if section in ("scheduler", "checks"):
        scheduler.apply_intervals()
    elif section == "egress":
        egress.ensure()
    elif (
        section == "tunnel"
        and tunnel.mode() == "ssh"
        and any(k.startswith(("wg_vps_", "ssh_", "tunnel_mode")) for k in changed)
    ):
        tunnel.ssh_start()

    resp = _back(section, "Сохранено" if changed else "Без изменений")
    if "admin_token" in changed:  # не разлогинивать самого себя
        resp.set_cookie(
            auth.COOKIE,
            auth.cookie_value("admin"),
            max_age=settings.get("cookie_days") * 86400,
            httponly=True,
            samesite="lax",
        )
    return resp


@router.post("/settings/tunnel/apply")
def tunnel_apply(request: Request):
    auth.require_admin(request)
    if tunnel.mode() == "wireguard":
        errs = tunnel.validate()
        if errs:
            return _back("tunnel", "; ".join(errs))
    tunnel.apply_async()
    return _back("tunnel", "Перезапускаю туннель. Обнови страницу через 15–60 с")


@router.post("/settings/tunnel/provision")
def tunnel_provision(request: Request):
    auth.require_admin(request)
    if not settings.get("wg_vps_host") or not settings.get("wg_vps_password"):
        return _back("tunnel", "Сначала заполни IP, логин и пароль VPS и нажми «Сохранить»")
    tunnel.provision_async()
    return _back("tunnel", "Настраиваю VPS по SSH и поднимаю туннель. Обнови страницу через 20–60 с")


@router.post("/settings/tunnel/test")
def tunnel_test(request: Request):
    auth.require_admin(request)
    try:
        ok, msg = (
            tunnel.ssh_test()
            if tunnel.mode() == "ssh"
            else (tunnel.handshake_age() is not None, "handshake: " + str(tunnel.handshake_age()))
        )
    except Exception as e:
        ok, msg = False, str(e)[:200]
    return _back("tunnel", ("OK: " if ok else "Проблема: ") + msg)


@router.post("/settings/tunnel/genkey")
def tunnel_genkey(request: Request):
    auth.require_admin(request)
    tunnel.regen_keys()
    return _back("tunnel", "Ключи перегенерированы. Обнови [Peer] на VPS и нажми «Применить»")


@router.post("/settings/alerts/test")
async def alerts_test(request: Request):
    """Тестовая отправка: URL и токен из формы (можно до сохранения), пустые — из сохранённых настроек."""
    auth.require_admin(request)
    form = await request.form()
    url = (form.get("alert_webhook_url") or "").strip() or settings.get("alert_webhook_url")
    token = (form.get("alert_webhook_token") or "").strip() or settings.get("alert_webhook_token")
    if not url:
        return _back("alerts", "Вебхук: укажи URL")
    e = alerts.send_test(url, token)
    return _back("alerts", f"Тестовый вебхук: {'доставлен' if e['ok'] else 'не доставлен'} — {e['status']}")


@router.post("/settings/egress/test")
def egress_test(request: Request):
    auth.require_admin(request)
    try:
        ip = egress.test()
        return _back("egress", f"Внешний IP через исходящий VPS: {ip}")
    except Exception as e:
        return _back("egress", f"Не сработало: {str(e)[:120]}")


@router.post("/settings/run/{task}")
def run_task(request: Request, task: str):
    auth.require_admin(request)
    if task not in scheduler.TASKS:
        return _back("scheduler", "Нет такой задачи")
    scheduler.run_now(task)
    return _back("scheduler", f"Запущено: {scheduler.TASKS[task][0]}")
