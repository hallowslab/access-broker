import json
from datetime import datetime, timezone

import aiosqlite

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    public_key TEXT NOT NULL UNIQUE,
    device_info TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'pending',
    ip TEXT NOT NULL DEFAULT '',
    ip_history TEXT NOT NULL DEFAULT '[]',
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
        await db.commit()
    finally:
        await db.close()


async def register_device(
    db: aiosqlite.Connection,
    public_key: str,
    device_info: dict,
    ip: str,
) -> tuple[str, bool]:
    now = now_iso()
    row = await (
        await db.execute(
            "SELECT id, status, ip_history FROM devices WHERE public_key = ?",
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
    is_new_ip = ip not in history
    if is_new_ip:
        history.append(ip)

    status = row["status"]
    if is_new_ip:
        status = "pending"
        await db.execute(
            "UPDATE devices SET last_seen = ?, ip = ?, ip_history = ?, status = ? WHERE id = ?",
            (now, ip, json.dumps(history), status, row["id"]),
        )
    else:
        await db.execute(
            "UPDATE devices SET last_seen = ?, ip = ? WHERE id = ?",
            (now, ip, row["id"]),
        )
    await db.commit()
    return status, False


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
