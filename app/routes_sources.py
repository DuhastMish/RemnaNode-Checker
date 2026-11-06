"""Admin: источники нод — список, добавление, изменение, удаление, проверка подключения, синхронизация."""

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse

from . import auth, db, export, sources, views

router = APIRouter()


def _back(msg, anchor=""):
    return RedirectResponse(f"/sources?msg={msg}{'#' + anchor if anchor else ''}", status_code=303)


@router.get("/sources")
def sources_page(request: Request):
    auth.require_admin(request)
    rows = sources.all_sources()
    for s in rows:
        s["count"] = db.q1("SELECT COUNT(*) AS c FROM source_nodes WHERE source_id=?", (s["id"],))["c"]
        s["last_export"] = export.last.get(s["id"])
    return views.render(request, "sources.html", sources=rows, types=sources.TYPES, title="Источники")


async def _form(request):
    f = await request.form()
    return {k: (f.get(k) or "").strip() for k in ("type", "name", "url", "token", "export_url", "export_token")}


@router.post("/sources")
async def source_create(request: Request):
    auth.require_admin(request)
    data = await _form(request)
    if data["type"] not in sources.TYPES:
        return _back("Выбери тип источника")
    if not data["name"] or not data["url"] or not data["token"]:
        return _back("Нужны имя, URL и токен")
    sid = sources.save(None, data)
    ok, msg, _ = sources.sync_source(sid)
    return _back(f"Источник добавлен. Синхронизация: {msg if ok else 'ошибка — ' + msg}", f"s{sid}")


@router.post("/sources/{sid}")
async def source_update(request: Request, sid: int):
    auth.require_admin(request)
    data = await _form(request)
    if not data["name"] or not data["url"]:
        return _back("Нужны имя и URL", f"s{sid}")
    if sources.save(sid, data) is None:
        return _back("Источник не найден")
    return _back("Сохранено", f"s{sid}")


@router.post("/sources/{sid}/delete")
def source_delete(request: Request, sid: int):
    auth.require_admin(request)
    sources.delete(sid)
    return _back("Источник удалён вместе с его нодами")


@router.post("/sources/{sid}/test")
def source_test(request: Request, sid: int):
    auth.require_admin(request)
    ok, msg = sources.test(sid)
    return _back(("Подключение работает: " if ok else "Ошибка: ") + msg, f"s{sid}")


@router.post("/sources/{sid}/sync")
def source_sync(request: Request, sid: int):
    auth.require_admin(request)
    ok, msg, _ = sources.sync_source(sid)
    return _back(f"Синхронизация: {msg if ok else 'ошибка — ' + msg}", f"s{sid}")
