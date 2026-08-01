import json

from pydantic import BaseModel


class RegisterRequest(BaseModel):
    public_key: str
    device_info: dict | None = None


class ChallengeRequest(BaseModel):
    public_key: str


class VerifyRequest(BaseModel):
    public_key: str
    signature: str
    timestamp: int


class DeviceView(BaseModel):
    id: int
    public_key: str
    device_id: str
    status: str
    ip: str
    device_info: dict
    approved_ips: list[str]
    created_at: str
    last_seen: str
    approved_at: str | None


def to_view(row: dict) -> DeviceView:
    info = row.get("device_info") or "{}"
    if isinstance(info, str):
        try:
            info = json.loads(info)
        except ValueError:
            info = {}
    approved = row.get("approved_ips") or "[]"
    if isinstance(approved, str):
        try:
            approved = json.loads(approved)
        except ValueError:
            approved = []
    return DeviceView(
        id=row["id"],
        public_key=row["public_key"],
        device_id=row["public_key"][:16],
        status=row["status"],
        ip=row["ip"],
        device_info=info or {},
        approved_ips=approved,
        created_at=row["created_at"],
        last_seen=row["last_seen"],
        approved_at=row.get("approved_at"),
    )
