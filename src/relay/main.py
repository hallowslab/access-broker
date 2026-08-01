import asyncio
from pathlib import Path

import aiosqlite
import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from . import db as dblib
from .config import Config, load_config
from .models import RegisterRequest, to_view

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES = Jinja2Templates(directory=str(BASE_DIR / "templates"))

VALID_HEX = set("0123456789abcdef")


def _validate_public_key(public_key: str) -> str:
    key = public_key.strip().lower()
    if len(key) != 64 or any(c not in VALID_HEX for c in key):
        raise HTTPException(status_code=400, detail="public_key must be 64 hex chars (Ed25519)")
    return key


def _client_ip(request: Request, trust_proxy: bool) -> str:
    if trust_proxy:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def create_api_app(config: Config, db: aiosqlite.Connection) -> FastAPI:
    app = FastAPI(title="ExifFlow Relay API")

    @app.post("/api/devices/register", status_code=201)
    async def register(req: RegisterRequest, request: Request):
        key = _validate_public_key(req.public_key)
        ip = _client_ip(request, config.trust_proxy)
        status, _ = await dblib.register_device(db, key, req.device_info, ip)
        message = (
            "device registered, pending approval"
            if status == "pending"
            else "device re-registered"
        )
        return {
            "device_id": key[:16],
            "public_key": key,
            "status": status,
            "message": message,
        }

    @app.get("/api/devices/status")
    async def device_status(public_key: str):
        key = _validate_public_key(public_key)
        device = await dblib.get_device(db, key)
        if device is None:
            raise HTTPException(status_code=404, detail="device not registered")
        return {"status": device["status"]}

    return app


def create_ui_app(config: Config, db: aiosqlite.Connection) -> FastAPI:
    app = FastAPI(title="ExifFlow Relay UI")

    @app.get("/", response_class=HTMLResponse)
    async def dashboard(request: Request):
        devices = await dblib.get_devices(db)
        return TEMPLATES.TemplateResponse(
            request,
            "dashboard.html",
            {"devices": [to_view(d) for d in devices], "counts": _counts(devices)},
        )

    @app.get("/dashboard/table", response_class=HTMLResponse)
    async def dashboard_table(request: Request):
        devices = await dblib.get_devices(db)
        return TEMPLATES.TemplateResponse(
            request,
            "partials/device_table.html",
            {"devices": [to_view(d) for d in devices]},
        )

    return app


def _counts(devices: list[dict]) -> dict[str, int]:
    pending = sum(1 for d in devices if d["status"] == "pending")
    approved = sum(1 for d in devices if d["status"] == "approved")
    return {"pending": pending, "approved": approved, "total": len(devices)}


async def _serve(config: Config) -> None:
    Path(config.db).parent.mkdir(parents=True, exist_ok=True)
    await dblib.init_db(config.db)
    db = await aiosqlite.connect(config.db)
    db.row_factory = aiosqlite.Row
    try:
        servers = [
            uvicorn.Server(
                uvicorn.Config(create_api_app(config, db), host=config.host, port=config.port)
            )
        ]
        if config.ui_enabled:
            servers.append(
                uvicorn.Server(
                    uvicorn.Config(
                        create_ui_app(config, db), host=config.ui_host, port=config.ui_port
                    )
                )
            )
        await asyncio.gather(*(server.serve() for server in servers))
    finally:
        await db.close()


def run() -> None:
    config = load_config()
    asyncio.run(_serve(config))
