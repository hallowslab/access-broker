import asyncio
import time
from pathlib import Path

import aiosqlite
import uvicorn
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from . import audit
from . import db as dblib
from . import vault
from .auth import AuthStore
from .config import Config, load_config
from .models import ChallengeRequest, RegisterRequest, VerifyRequest, to_view
from .ratelimit import RateLimiter, RateLimitConfig

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES = Jinja2Templates(directory=str(BASE_DIR / "templates"))

VALID_HEX = set("0123456789abcdef")

LONG_POLL_TIMEOUT = 60
CLOCK_SKEW = 120

# Global rate limiter instance
_rate_limiter = RateLimiter(RateLimitConfig())


def _validate_public_key(public_key: str) -> str:
    key = public_key.strip().lower()
    if len(key) != 64 or any(c not in VALID_HEX for c in key):
        raise HTTPException(status_code=400, detail="public_key must be 64 hex chars (Ed25519)")
    return key


def _validate_signature(signature: str) -> str:
    sig = signature.strip().lower()
    if len(sig) != 128 or any(c not in VALID_HEX for c in sig):
        raise HTTPException(status_code=400, detail="signature must be 128 hex chars (Ed25519)")
    return sig


def _client_ip(request: Request, trust_proxy: bool) -> str:
    if trust_proxy:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.rsplit(",", 1)[-1].strip()
    return request.client.host if request.client else "unknown"


def create_api_app(
    config: Config,
    db: aiosqlite.Connection,
    auth: AuthStore,
    master_key: bytes | None,
) -> FastAPI:
    app = FastAPI(title="ExifFlow Broker API")

    @app.post("/api/devices/register", status_code=201)
    async def register(req: RegisterRequest, request: Request):
        key = _validate_public_key(req.public_key)
        ip = _client_ip(request, config.trust_proxy)
        
        # Rate limit check
        allowed, error = _rate_limiter.check_register(ip)
        if not allowed:
            await audit.log_event(
                db, "register_rate_limit", ip, key, key[:16],
                {"reason": error}, "warning", Path(config.audit_log)
            )
            raise HTTPException(status_code=429, detail=error)
        
        status, _ = await dblib.register_device(db, key, req.device_info, ip)
        message = (
            "device registered, pending approval"
            if status == "pending"
            else "device re-registered"
        )
        
        # Audit log
        await audit.log_event(
            db, "device_register", ip, key, key[:16],
            {"status": status, "device_info": req.device_info}, "info", Path(config.audit_log)
        )
        
        return {
            "device_id": key[:16],
            "public_key": key,
            "status": status,
            "message": message,
        }

    @app.get("/api/devices/status")
    async def device_status(public_key: str, request: Request):
        key = _validate_public_key(public_key)
        ip = _client_ip(request, config.trust_proxy)
        device = await dblib.get_device(db, key)
        if device is None:
            raise HTTPException(status_code=404, detail="device not registered")
        deadline = time.monotonic() + LONG_POLL_TIMEOUT
        while time.monotonic() < deadline:
            device = await dblib.get_device(db, key)
            status = dblib.effective_status(device, ip)
            if status != "pending":
                return _status_response(device, status, ip)
            await asyncio.sleep(2)
        return _status_response(device, "pending", ip)

    @app.post("/api/auth/challenge", status_code=200)
    async def challenge(req: ChallengeRequest, request: Request):
        key = _validate_public_key(req.public_key)
        ip = _client_ip(request, config.trust_proxy)
        
        # Rate limit check
        allowed, error = _rate_limiter.check_challenge(ip)
        if not allowed:
            await audit.log_event(
                db, "challenge_rate_limit", ip, key, key[:16],
                {"reason": error}, "warning", Path(config.audit_log)
            )
            raise HTTPException(status_code=429, detail=error)
        
        device = await dblib.get_device(db, key)
        if device is None:
            await audit.log_event(
                db, "challenge_failure", ip, key, key[:16],
                {"reason": "device not registered"}, "warning", Path(config.audit_log)
            )
            raise HTTPException(status_code=404, detail="device not registered")
        
        nonce, ttl = auth.create_challenge(key)
        
        await audit.log_event(
            db, "challenge_success", ip, key, key[:16],
            {"ttl": ttl}, "info", Path(config.audit_log)
        )
        
        return {"challenge": nonce, "expires_in": ttl}

    @app.post("/api/auth/verify", status_code=200)
    async def verify(req: VerifyRequest, request: Request):
        key = _validate_public_key(req.public_key)
        sig = _validate_signature(req.signature)
        ip = _client_ip(request, config.trust_proxy)
        
        # Rate limit check with backoff
        allowed, error = _rate_limiter.check_verify(ip, key)
        if not allowed:
            await audit.log_event(
                db, "verify_rate_limit", ip, key, key[:16],
                {"reason": error}, "warning", Path(config.audit_log)
            )
            raise HTTPException(status_code=429, detail=error)
        
        if abs(time.time() - req.timestamp) > CLOCK_SKEW:
            _rate_limiter.record_verify_failure(ip, key)
            await audit.log_event(
                db, "verify_failure", ip, key, key[:16],
                {"reason": "timestamp not fresh"}, "warning", Path(config.audit_log)
            )
            raise HTTPException(status_code=401, detail="timestamp not fresh")
        
        device = await dblib.get_device(db, key)
        if device is None:
            _rate_limiter.record_verify_failure(ip, key)
            await audit.log_event(
                db, "verify_failure", ip, key, key[:16],
                {"reason": "device not registered"}, "warning", Path(config.audit_log)
            )
            raise HTTPException(status_code=404, detail="device not registered")
        
        if dblib.effective_status(device, ip) != "approved":
            _rate_limiter.record_verify_failure(ip, key)
            await audit.log_event(
                db, "verify_failure", ip, key, key[:16],
                {"reason": "device not approved for this IP", "device_status": device["status"]},
                "warning", Path(config.audit_log)
            )
            raise HTTPException(
                status_code=403, detail="device not approved for this IP"
            )
        
        nonce = auth.consume_nonce(key)
        if nonce is None:
            _rate_limiter.record_verify_failure(ip, key)
            await audit.log_event(
                db, "verify_failure", ip, key, key[:16],
                {"reason": "no active challenge or expired"}, "warning", Path(config.audit_log)
            )
            raise HTTPException(status_code=401, detail="no active challenge or expired")
        
        message = (nonce + key + str(req.timestamp)).encode()
        try:
            public_key_obj = Ed25519PublicKey.from_public_bytes(bytes.fromhex(key))
            public_key_obj.verify(bytes.fromhex(sig), message)
        except Exception:
            _rate_limiter.record_verify_failure(ip, key)
            await audit.log_event(
                db, "verify_failure", ip, key, key[:16],
                {"reason": "invalid signature"}, "warning", Path(config.audit_log)
            )
            raise HTTPException(status_code=401, detail="invalid signature")
        
        token, ttl = auth.issue_token(key, ip)
        _rate_limiter.record_verify_success(ip, key)
        
        await audit.log_event(
            db, "verify_success", ip, key, key[:16],
            {"token_ttl": ttl}, "info", Path(config.audit_log)
        )
        
        return {
            "session_token": token,
            "expires_in": ttl,
            "device_id": key[:16],
        }

    @app.post("/api/credentials/fetch", status_code=200)
    async def fetch(request: Request):
        token = _bearer_token(request)
        if token is None:
            await audit.log_event(
                db, "fetch_failure", _client_ip(request, config.trust_proxy),
                None, None, {"reason": "missing bearer token"}, "warning", Path(config.audit_log)
            )
            raise HTTPException(status_code=401, detail="missing bearer token")
        
        ip = _client_ip(request, config.trust_proxy)
        public_key = auth.verify_token(token, ip)
        if public_key is None:
            await audit.log_event(
                db, "fetch_failure", ip, None, None,
                {"reason": "invalid or expired session token"}, "warning", Path(config.audit_log)
            )
            raise HTTPException(status_code=401, detail="invalid or expired session token")
        
        device = await dblib.get_device(db, public_key)
        if device is None:
            await audit.log_event(
                db, "fetch_failure", ip, public_key, public_key[:16],
                {"reason": "invalid session"}, "warning", Path(config.audit_log)
            )
            raise HTTPException(status_code=401, detail="invalid session")
        
        if dblib.effective_status(device, ip) != "approved":
            await audit.log_event(
                db, "fetch_failure", ip, public_key, public_key[:16],
                {"reason": "device not approved for this IP"}, "warning", Path(config.audit_log)
            )
            raise HTTPException(status_code=403, detail="device not approved for this IP")
        
        creds, error = vault.load_storage(config.toml, master_key)
        if error:
            await audit.log_event(
                db, "fetch_failure", ip, public_key, public_key[:16],
                {"reason": "storage config error", "error": error}, "error", Path(config.audit_log)
            )
            raise HTTPException(status_code=503, detail=error)
        
        await audit.log_event(
            db, "fetch_success", ip, public_key, public_key[:16],
            {"backend_type": creds.get("backend", {}).get("type", "unknown")},
            "info", Path(config.audit_log)
        )
        
        return {**creds, "device_id": public_key[:16]}

    return app


def _status_response(device: dict, status: str, ip: str) -> dict:
    return {
        "device_id": device["public_key"][:16],
        "status": status,
        "approved_ips": device["approved_ips"],
        "current_ip": ip,
    }


def _bearer_token(request: Request) -> str | None:
    header = request.headers.get("authorization", "")
    if header.lower().startswith("bearer "):
        return header[7:].strip()
    return None


def _storage_view(creds: dict | None) -> dict:
    if not creds:
        return {"backend_type": "ftps"}
    backend = creds.get("backend")
    if isinstance(backend, dict):
        view = dict(backend)
        view["backend_type"] = backend.get("type", "ftps")
        return view
    view = dict(creds)
    view["backend_type"] = "ftps"
    return view


def _existing_value(existing: dict | None, key: str):
    if not existing:
        return None
    backend = existing.get("backend")
    if isinstance(backend, dict):
        return backend.get(key, existing.get(key))
    return existing.get(key)


def _ftps_from_form(form, existing: dict | None) -> dict:
    protocol = str(form.get("protocol", "ftps")).strip().lower()
    if protocol not in ("ftp", "ftps"):
        raise HTTPException(status_code=400, detail="protocol must be ftp or ftps")
    host = str(form.get("host", "")).strip()
    user = str(form.get("user", "")).strip()
    if not host or not user:
        raise HTTPException(status_code=400, detail="host and user are required")
    try:
        port = int(str(form.get("port") or (990 if protocol == "ftps" else 21)))
    except ValueError:
        raise HTTPException(status_code=400, detail="invalid port")
    password = str(form.get("password", "")) or _existing_value(existing, "password") or ""
    root = str(form.get("root", "")).strip() or None
    ca_cert = str(form.get("ca_cert", "")).strip() or _existing_value(existing, "ca_cert") or None
    return {
        "version": 1,
        "backend": {
            "type": "ftps",
            "protocol": protocol,
            "host": host,
            "port": port,
            "user": user,
            "password": password,
            "root": root,
            "ca_cert": ca_cert,
        },
    }


def _s3_from_form(form, existing: dict | None) -> dict:
    endpoint = str(form.get("endpoint", "")).strip()
    bucket = str(form.get("bucket", "")).strip()
    access_key_id = str(form.get("access_key_id", "")).strip()
    if not endpoint or not bucket or not access_key_id:
        raise HTTPException(status_code=400, detail="endpoint, bucket and access key id are required")
    if not endpoint.startswith("https://"):
        raise HTTPException(status_code=400, detail="endpoint must be https (S3 over TLS is mandatory)")
    secret_access_key = str(form.get("secret_access_key", "")) or _existing_value(existing, "secret_access_key") or ""
    if not secret_access_key:
        raise HTTPException(status_code=400, detail="secret access key is required")
    region = str(form.get("region", "")).strip() or None
    session_token = str(form.get("session_token", "")).strip() or _existing_value(existing, "session_token") or None
    path_style = form.get("path_style") is not None
    root = str(form.get("root", "")).strip() or None
    ca_cert = str(form.get("ca_cert", "")).strip() or _existing_value(existing, "ca_cert") or None
    multipart_threshold = str(form.get("multipart_threshold_bytes", "")).strip()
    multipart_threshold_bytes = None
    if multipart_threshold:
        try:
            multipart_threshold_bytes = int(multipart_threshold)
        except ValueError:
            raise HTTPException(status_code=400, detail="multipart threshold must be an integer (bytes)")
    immutable_naming = form.get("immutable_naming") is not None
    return {
        "version": 1,
        "backend": {
            "type": "s3",
            "endpoint": endpoint,
            "region": region,
            "bucket": bucket,
            "path_style": path_style,
            "access_key_id": access_key_id,
            "secret_access_key": secret_access_key,
            "session_token": session_token,
            "root": root,
            "ca_cert": ca_cert,
            "multipart_threshold_bytes": multipart_threshold_bytes,
            "immutable_naming": immutable_naming,
        },
    }


def create_ui_app(
    config: Config,
    db: aiosqlite.Connection,
    auth: AuthStore,
    master_key: bytes | None,
) -> FastAPI:
    app = FastAPI(title="ExifFlow Broker UI")

    @app.get("/", response_class=HTMLResponse)
    async def dashboard(request: Request):
        devices = await dblib.get_devices(db)
        return TEMPLATES.TemplateResponse(
            request,
            "dashboard.html",
            {"devices": [to_view(d) for d in devices], "counts": _counts(devices)},
        )

    @app.get("/dashboard/storage", response_class=HTMLResponse)
    async def storage_page(request: Request):
        creds, error = vault.load_storage(config.toml, master_key)
        return TEMPLATES.TemplateResponse(
            request,
            "storage.html",
            {"creds": _storage_view(creds), "error": error, "notice": None, "config_toml": config.toml},
        )

    @app.post("/dashboard/storage", response_class=HTMLResponse)
    async def storage_save(request: Request):
        form = await request.form()
        backend = str(form.get("backend", "ftps")).strip().lower()
        existing, _ = vault.load_storage(config.toml, master_key)
        if backend == "ftps":
            creds = _ftps_from_form(form, existing)
        elif backend == "s3":
            creds = _s3_from_form(form, existing)
        else:
            raise HTTPException(status_code=400, detail="backend must be ftps or s3")
        if master_key is None:
            return TEMPLATES.TemplateResponse(
                request,
                "storage.html",
                {
                    "creds": _storage_view(creds),
                    "error": "BROKER_MASTER_KEY (or file) missing — set it and restart the broker",
                    "notice": None, "config_toml": config.toml,
                },
            )
        vault.write_storage(config.toml, master_key, creds)
        return TEMPLATES.TemplateResponse(
            request,
            "storage.html",
            {"creds": _storage_view(creds), "error": None, "notice": "storage credentials saved", "config_toml": config.toml},
        )

    @app.post("/dashboard/storage/clear", response_class=HTMLResponse)
    async def storage_clear(request: Request):
        vault.storage_clear(config.toml)
        return TEMPLATES.TemplateResponse(
            request,
            "storage.html",
            {"creds": _storage_view({}), "error": None, "notice": "storage config cleared", "config_toml": config.toml},
        )

    @app.get("/dashboard/audit", response_class=HTMLResponse)
    async def audit_log_page(request: Request, limit: int = 100, event_type: str = None, ip: str = None):
        entries = await audit.get_audit_log(db, limit=limit, event_type=event_type, ip=ip)
        return TEMPLATES.TemplateResponse(
            request,
            "audit.html",
            {"entries": entries, "limit": limit, "event_type": event_type, "ip": ip, "audit_log_file": config.audit_log},
        )

    @app.get("/dashboard/table", response_class=HTMLResponse)
    async def dashboard_table(request: Request):
        devices = await dblib.get_devices(db)
        return TEMPLATES.TemplateResponse(
            request,
            "partials/device_table.html",
            {"devices": [to_view(d) for d in devices]},
        )

    @app.post("/dashboard/devices/{device_id}/approve", response_class=HTMLResponse)
    async def ui_approve(request: Request, device_id: int):
        device = await dblib.get_device_by_id(db, device_id)
        if device is None:
            raise HTTPException(status_code=404, detail="device not found")
        device = await dblib.approve_ip(db, device["public_key"], device["ip"])
        
        await audit.log_event(
            db, "device_approve", device["ip"], device["public_key"], device["public_key"][:16],
            {"source": "dashboard"}, "info", Path(config.audit_log)
        )
        
        return TEMPLATES.TemplateResponse(
            request,
            "partials/device_row.html",
            {"d": to_view(device)},
        )

    @app.post("/dashboard/devices/{device_id}/deauthorize", response_class=HTMLResponse)
    async def ui_deauthorize(request: Request, device_id: int):
        device = await dblib.get_device_by_id(db, device_id)
        if device is None:
            raise HTTPException(status_code=404, detail="device not found")
        device = await dblib.deauthorize_device(db, device["public_key"])
        auth.revoke_public_key(device["public_key"])
        
        await audit.log_event(
            db, "device_deauthorize", device["ip"], device["public_key"], device["public_key"][:16],
            {"source": "dashboard"}, "warning", Path(config.audit_log)
        )
        
        return TEMPLATES.TemplateResponse(
            request,
            "partials/device_row.html",
            {"d": to_view(device)},
        )

    @app.delete("/dashboard/devices/{device_id}", response_class=HTMLResponse)
    async def ui_delete(request: Request, device_id: int):
        device = await dblib.get_device_by_id(db, device_id)
        if device is None:
            raise HTTPException(status_code=404, detail="device not found")
        
        await audit.log_event(
            db, "device_delete", device["ip"], device["public_key"], device["public_key"][:16],
            {"source": "dashboard"}, "warning", Path(config.audit_log)
        )
        
        await dblib.delete_device(db, device["public_key"])
        auth.revoke_public_key(device["public_key"])
        return HTMLResponse("")

    @app.post("/admin/devices/approve", status_code=200)
    async def admin_approve(req: RegisterRequest, request: Request):
        key = _validate_public_key(req.public_key)
        ip = _client_ip(request, config.trust_proxy)
        device = await dblib.approve_ip(db, key, ip)
        if device is None:
            raise HTTPException(status_code=404, detail="device not registered")
        return _status_response(device, "approved", ip)

    @app.post("/admin/devices/deauthorize", status_code=200)
    async def admin_deauthorize(req: RegisterRequest, request: Request):
        key = _validate_public_key(req.public_key)
        device = await dblib.deauthorize_device(db, key)
        if device is None:
            raise HTTPException(status_code=404, detail="device not registered")
        auth.revoke_public_key(key)
        ip = _client_ip(request, config.trust_proxy)
        return _status_response(device, "deauthorized", ip)

    @app.delete("/admin/devices/{public_key}", status_code=200)
    async def admin_delete(public_key: str, request: Request):
        key = _validate_public_key(public_key)
        if not await dblib.delete_device(db, key):
            raise HTTPException(status_code=404, detail="device not registered")
        auth.revoke_public_key(key)
        return {"device_id": key[:16], "status": "deleted"}

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
    auth = AuthStore()
    master_key = vault.load_master_key()
    try:
        servers = [
            uvicorn.Server(
                uvicorn.Config(
                    create_api_app(config, db, auth, master_key),
                    host=config.host,
                    port=config.port,
                )
            )
        ]
        if config.ui_enabled:
            servers.append(
                uvicorn.Server(
                    uvicorn.Config(
                        create_ui_app(config, db, auth, master_key),
                        host=config.ui_host,
                        port=config.ui_port,
                    )
                )
            )
        await asyncio.gather(*(server.serve() for server in servers))
    finally:
        await db.close()


def run() -> None:
    import sys

    from dotenv import load_dotenv

    load_dotenv()
    args = sys.argv[1:]
    if not args or args[0] == "serve":
        config = load_config()
        asyncio.run(_serve(config))
        return

    cmd = args[0]
    if cmd == "keygen":
        print(vault.generate_key())
        return
    if cmd == "storage":
        config = load_config()
        sub = args[1] if len(args) > 1 else "show"
        if sub == "set":
            if "--from-json" in args:
                idx = args.index("--from-json")
                if idx + 1 >= len(args):
                    sys.exit("--from-json requires a file path")
                vault.storage_set_from_json(config.toml, args[idx + 1])
            else:
                vault.storage_set(config.toml)
        elif sub == "show":
            vault.storage_show(config.toml)
        elif sub == "clear":
            vault.storage_clear(config.toml)
        else:
            sys.exit(f"unknown storage subcommand: {sub}")
        return
    sys.exit(f"unknown command: {cmd}")
