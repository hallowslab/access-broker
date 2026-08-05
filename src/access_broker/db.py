import json
from datetime import datetime, timezone

import aiosqlite

from . import audit

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    public_key TEXT NOT NULL UNIQUE,
    device_info TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'pending',
    ip TEXT NOT NULL DEFAULT '',
    ip_history TEXT NOT NULL DEFAULT '[]',
    approved_ips TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    approved_at TEXT
);
"""


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def init_db(path: str) -> None:
    db = await aiosqlite.connect(path)
    try:
        await db.execute(SCHEMA)
        cols = [r[1] for r in await (await db.execute("PRAGMA table_info(devices)")).fetchall()]
        if "approved_ips" not in cols:
            await db.execute(
                "ALTER TABLE devices ADD COLUMN approved_ips TEXT NOT NULL DEFAULT '[]'"
            )
        await audit.init_audit_db(db)
        await db.commit()
    finally:
        await db.close()


def effective_status(device: dict, ip: str) -> str:
    if device["status"] == "deauthorized":
        return "deauthorized"
    approved = json.loads(device["approved_ips"] or "[]")
    return "approved" if ip in approved else "pending"


async def register_device(
    db: aiosqlite.Connection,
    public_key: str,
    device_info: dict,
    ip: str,
) -> tuple[str, bool]:
    now = now_iso()
    row = await (
        await db.execute(
            "SELECT id, status, ip_history, approved_ips FROM devices WHERE public_key = ?",
            (public_key,),
        )
    ).fetchone()

    if row is None:
        await db.execute(
            "INSERT INTO devices (public_key, device_info, status, ip, ip_history, created_at, last_seen) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (public_key, json.dumps(device_info or {}), "pending", ip, json.dumps([ip]), now, now),
        )
        await db.commit()
        return "pending", True

    history = json.loads(row["ip_history"])
    if ip not in history:
        history.append(ip)

    status = effective_status(row, ip)

    if row["status"] == "deauthorized":
        status = "deauthorized"

    await db.execute(
        "UPDATE devices SET last_seen = ?, ip = ?, ip_history = ?, status = ? WHERE id = ?",
        (now, ip, json.dumps(history), status, row["id"]),
    )
    await db.commit()
    return status, False


async def approve_ip(db: aiosqlite.Connection, public_key: str, ip: str) -> dict | None:
    row = await (
        await db.execute("SELECT * FROM devices WHERE public_key = ?", (public_key,))
    ).fetchone()
    if row is None:
        return None
    device = dict(row)
    approved = json.loads(device["approved_ips"] or "[]")
    if ip not in approved:
        approved.append(ip)
    history = json.loads(device["ip_history"])
    if ip not in history:
        history.append(ip)
    now = now_iso()
    await db.execute(
        "UPDATE devices SET approved_ips = ?, ip_history = ?, status = 'approved', approved_at = ? "
        "WHERE id = ?",
        (json.dumps(approved), json.dumps(history), now, device["id"]),
    )
    await db.commit()
    device["approved_ips"] = json.dumps(approved)
    device["ip_history"] = json.dumps(history)
    device["status"] = "approved"
    device["approved_at"] = now
    return device


async def deauthorize_device(db: aiosqlite.Connection, public_key: str) -> dict | None:
    row = await (
        await db.execute("SELECT * FROM devices WHERE public_key = ?", (public_key,))
    ).fetchone()
    if row is None:
        return None
    device = dict(row)
    await db.execute(
        "UPDATE devices SET approved_ips = '[]', status = 'deauthorized' WHERE id = ?",
        (device["id"],),
    )
    await db.commit()
    device["approved_ips"] = "[]"
    device["status"] = "deauthorized"
    return device


async def delete_device(db: aiosqlite.Connection, public_key: str) -> bool:
    cur = await db.execute("DELETE FROM devices WHERE public_key = ?", (public_key,))
    await db.commit()
    return cur.rowcount > 0


async def get_devices(db: aiosqlite.Connection, status: str | None = None) -> list[dict]:
    if status is None:
        cur = await db.execute("SELECT * FROM devices ORDER BY created_at DESC")
    else:
        cur = await db.execute(
            "SELECT * FROM devices WHERE status = ? ORDER BY created_at DESC", (status,)
        )
    rows = await cur.fetchall()
    return [dict(r) for r in rows]


async def get_device(db: aiosqlite.Connection, public_key: str) -> dict | None:
    row = await (
        await db.execute("SELECT * FROM devices WHERE public_key = ?", (public_key,))
    ).fetchone()
    return dict(row) if row else None


async def get_device_by_id(db: aiosqlite.Connection, device_id: int) -> dict | None:
    row = await (
        await db.execute("SELECT * FROM devices WHERE id = ?", (device_id,))
    ).fetchone()
    return dict(row) if row else None
