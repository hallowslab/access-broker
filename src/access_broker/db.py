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
    approved_at TEXT,
    storage_config_id INTEGER
);
"""

STORAGE_CONFIGS_SCHEMA = """
CREATE TABLE IF NOT EXISTS storage_configs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    encrypted TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def init_db(path: str) -> None:
    db = await aiosqlite.connect(path)
    try:
        await db.execute(SCHEMA)
        await db.execute(STORAGE_CONFIGS_SCHEMA)
        cols = [r[1] for r in await (await db.execute("PRAGMA table_info(devices)")).fetchall()]
        if "approved_ips" not in cols:
            await db.execute(
                "ALTER TABLE devices ADD COLUMN approved_ips TEXT NOT NULL DEFAULT '[]'"
            )
        if "storage_config_id" not in cols:
            await db.execute(
                "ALTER TABLE devices ADD COLUMN storage_config_id INTEGER"
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


async def list_storage_configs(db: aiosqlite.Connection) -> list[dict]:
    rows = await (
        await db.execute(
            "SELECT sc.*, "
            "(SELECT COUNT(*) FROM devices d WHERE d.storage_config_id = sc.id) AS in_use "
            "FROM storage_configs sc ORDER BY sc.name ASC"
        )
    ).fetchall()
    return [dict(r) for r in rows]


async def get_storage_config(db: aiosqlite.Connection, config_id: int) -> dict | None:
    row = await (
        await db.execute("SELECT * FROM storage_configs WHERE id = ?", (config_id,))
    ).fetchone()
    return dict(row) if row else None


async def get_storage_config_by_name(db: aiosqlite.Connection, name: str) -> dict | None:
    row = await (
        await db.execute("SELECT * FROM storage_configs WHERE name = ?", (name,))
    ).fetchone()
    return dict(row) if row else None


async def create_storage_config(
    db: aiosqlite.Connection, name: str, encrypted: str
) -> dict:
    now = now_iso()
    cur = await db.execute(
        "INSERT INTO storage_configs (name, encrypted, created_at, updated_at) "
        "VALUES (?, ?, ?, ?)",
        (name, encrypted, now, now),
    )
    await db.commit()
    config_id = cur.lastrowid
    return await get_storage_config(db, config_id)


async def update_storage_config_encrypted(
    db: aiosqlite.Connection, config_id: int, name: str, encrypted: str
) -> dict | None:
    now = now_iso()
    cur = await db.execute(
        "UPDATE storage_configs SET name = ?, encrypted = ?, updated_at = ? WHERE id = ?",
        (name, encrypted, now, config_id),
    )
    await db.commit()
    if cur.rowcount == 0:
        return None
    return await get_storage_config(db, config_id)


async def delete_storage_config(db: aiosqlite.Connection, config_id: int) -> bool:
    cur = await db.execute("DELETE FROM storage_configs WHERE id = ?", (config_id,))
    await db.commit()
    return cur.rowcount > 0


async def storage_config_usage_count(db: aiosqlite.Connection, config_id: int) -> int:
    row = await (
        await db.execute(
            "SELECT COUNT(*) AS n FROM devices WHERE storage_config_id = ?", (config_id,)
        )
    ).fetchone()
    return row["n"] if row else 0


async def assign_storage_config(
    db: aiosqlite.Connection, device_id: int, config_id: int | None
) -> dict | None:
    await db.execute(
        "UPDATE devices SET storage_config_id = ? WHERE id = ?", (config_id, device_id)
    )
    await db.commit()
    return await get_device_by_id(db, device_id)


async def get_storage_config_for_device(
    db: aiosqlite.Connection, public_key: str
) -> dict | None:
    row = await (
        await db.execute(
            "SELECT sc.* FROM storage_configs sc "
            "JOIN devices d ON d.storage_config_id = sc.id "
            "WHERE d.public_key = ?",
            (public_key,),
        )
    ).fetchone()
    return dict(row) if row else None


async def assign_storage_config_to_all(
    db: aiosqlite.Connection, config_id: int
) -> None:
    await db.execute("UPDATE devices SET storage_config_id = ?", (config_id,))
    await db.commit()
