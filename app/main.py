import threading
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse

from . import auth, db, egress, routes_admin, routes_settings, scheduler, settings, tunnel


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init()
    settings.seed()
    try:
        tunnel.ensure_keys()
    except Exception as e:
        print(f"wg genkey недоступен: {e}", flush=True)
    threading.Thread(target=tunnel.start_if_configured, daemon=True).start()
    egress.ensure()
    scheduler.setup()
    yield
    egress.stop()
    tunnel.ssh_stop()
    scheduler.sched.shutdown(wait=False)


app = FastAPI(title="nodecheck", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)


@app.exception_handler(auth.AuthRequired)
async def _auth_required(request: Request, exc: auth.AuthRequired):
    return RedirectResponse(f"/login?next={request.url.path}", status_code=303)


app.include_router(routes_admin.router)
app.include_router(routes_settings.router)
