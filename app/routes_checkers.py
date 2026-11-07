"""Admin: реестр чекеров — список, добавление (токен показывается один раз), отключение, перевыпуск токена."""

from fastapi import APIRouter, Form, Request
from fastapi.responses import RedirectResponse

from . import auth, checkers, config, settings, views

router = APIRouter()

LOCAL_HOSTS = ("localhost", "127.0.0.1", "::1")


def _panel_arg(request: Request):
    """Первый аргумент команды чекера: домен из ADMIN_HOST, иначе адрес, по которому открыта панель.

    Возвращает (аргумент, предупреждение | None). Домен без схемы чекер понимает как https://домен.
    """
    if config.ADMIN_HOST:
        return config.ADMIN_HOST, None
    url = request.base_url
    if url.scheme == "https":
        return url.netloc, "ADMIN_HOST в .env не задан — домен взят из адреса, по которому открыта панель."
    base = str(url).rstrip("/")
    if url.hostname in LOCAL_HOSTS:
        return base, "Локальный адрес панели — с другой машины чекер до него не достучится. Задай ADMIN_HOST в .env."
    return base, "Панель открыта по http — чекер откажется подключаться. Задай ADMIN_HOST в .env или, в доверенной локальной сети, добавь -e ALLOW_HTTP=1."


def _page(request: Request, new_token=None, **extra):
    ctx = dict(checkers=checkers.all_checkers(), image=settings.get("agent_image"), title="Чекеры")
    if new_token:
        panel, warning = _panel_arg(request)
        ctx.update(new_token=new_token, panel_arg=panel, panel_warning=warning)
    return views.render(request, "checkers.html", **ctx, **extra)


@router.get("/checkers")
def checkers_page(request: Request):
    auth.require_admin(request)
    return _page(request)


@router.post("/checkers")
def checker_create(request: Request, name: str = Form("")):
    auth.require_admin(request)
    name = name.strip()[:60]
    if not name:
        return RedirectResponse("/checkers?msg=Укажи имя чекера", status_code=303)
    checker_id, token = checkers.create(name)
    # токен в ответе один раз — без редиректа, чтобы не попал в URL и историю
    return _page(request, new_token=token, new_name=name)


@router.post("/checkers/{checker_id}/token")
def checker_token(request: Request, checker_id: str):
    auth.require_admin(request)
    row = next((c for c in checkers.all_checkers() if c["id"] == checker_id), None)
    if not row:
        return RedirectResponse("/checkers?msg=Чекер не найден", status_code=303)
    return _page(request, new_token=checkers.regenerate(checker_id), new_name=row["name"])


@router.post("/checkers/{checker_id}/enable")
def checker_enable(request: Request, checker_id: str):
    auth.require_admin(request)
    checkers.set_enabled(checker_id, True)
    return RedirectResponse("/checkers?msg=Чекер включён", status_code=303)


@router.post("/checkers/{checker_id}/disable")
def checker_disable(request: Request, checker_id: str):
    auth.require_admin(request)
    checkers.set_enabled(checker_id, False)
    return RedirectResponse("/checkers?msg=Чекер отключён: его запросы и результаты отклоняются", status_code=303)


@router.post("/checkers/{checker_id}/delete")
def checker_delete(request: Request, checker_id: str):
    auth.require_admin(request)
    checkers.delete(checker_id)
    return RedirectResponse("/checkers?msg=Чекер удалён", status_code=303)
