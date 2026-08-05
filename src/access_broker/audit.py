import json
import logging
from datetime import datetime, timezone
from pathlib import Path

import aiosqlite

logger = logging.getLogger("exifflow.audit")

AUDIT_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    event_type TEXT NOT NULL,
    ip TEXT NOT NULL,
    public_key TEXT,
    device_id TEXT,
    details TEXT NOT NULL DEFAULT '{}',
    severity TEXT NOT NULL DEFAULT 'info'
);
"""


async def init_audit_db(db: aiosqlite.Connection) -> None:
    await db.execute(AUDIT_SCHEMA)
    await db.commit()


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


async def log_event(
    db: aiosqlite.Connection,
    event_type: str,
    ip: str,
    public_key: str | None = None,
    device_id: str | None = None,
    details: dict | None = None,
    severity: str = "info",
    log_file: Path | None = None,
) -> None:
    """Log an audit event to database and optionally to fail2ban-compatible log file."""
    timestamp = now_iso()
    details_json = json.dumps(details or {})
    
    # Write to database
    await db.execute(
        "INSERT INTO audit_log (timestamp, event_type, ip, public_key, device_id, details, severity) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (timestamp, event_type, ip, public_key, device_id, details_json, severity),
    )
    await db.commit()
    
    # Write fail2ban-compatible log line
    # Format: YYYY-MM-DD HH:MM:SS <ip> <event_type> <device_id> <details>
    device_id_short = device_id or (public_key[:16] if public_key else "unknown")
    log_line = f"{timestamp} {ip} {event_type} {device_id_short} {details_json}"
    
    if log_file:
        try:
            with open(log_file, "a") as f:
                f.write(log_line + "\n")
        except Exception as e:
            logger.error(f"Failed to write audit log file: {e}")
    
    # Also log to Python logger
    log_func = getattr(logger, severity if severity in ("debug", "info", "warning", "error", "critical") else "info")
    log_func(log_line)


async def get_audit_log(
    db: aiosqlite.Connection,
    limit: int = 100,
    event_type: str | None = None,
    ip: str | None = None,
    public_key: str | None = None,
) -> list[dict]:
    """Retrieve audit log entries with optional filters."""
    query = "SELECT * FROM audit_log WHERE 1=1"
    params = []
    
    if event_type:
        query += " AND event_type = ?"
        params.append(event_type)
    if ip:
        query += " AND ip = ?"
        params.append(ip)
    if public_key:
        query += " AND public_key = ?"
        params.append(public_key)
    
    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)
    
    cur = await db.execute(query, params)
    rows = await cur.fetchall()
    return [dict(r) for r in rows]


async def get_failed_auth_count(
    db: aiosqlite.Connection,
    ip: str,
    minutes: int = 15,
) -> int:
    """Count failed authentication attempts from an IP in the last N minutes."""
    from datetime import timedelta
    
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).strftime("%Y-%m-%d %H:%M:%S")
    
    cur = await db.execute(
        "SELECT COUNT(*) FROM audit_log WHERE ip = ? AND event_type LIKE '%_failure' AND timestamp >= ?",
        (ip, cutoff),
    )
    row = await cur.fetchone()
    return row[0] if row else 0
