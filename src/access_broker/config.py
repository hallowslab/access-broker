import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Config:
    host: str
    port: int
    db: str
    toml: str
    trust_proxy: bool
    ui_enabled: bool
    ui_host: str
    ui_port: int
    audit_log: str


def load_config() -> Config:
    def env(key: str, default: str) -> str:
        return os.environ.get(key, default)

    return Config(
        host=env("BROKER_HOST", "0.0.0.0"),
        port=int(env("BROKER_PORT", "8700")),
        db=env("BROKER_DB", "data/access-broker.db"),
        toml=env("BROKER_TOML", "data/access-broker.toml"),
        trust_proxy=env("BROKER_TRUST_PROXY", "0") in ("1", "true", "yes"),
        ui_enabled=env("BROKER_UI_ENABLED", "1") in ("1", "true", "yes"),
        ui_host=env("BROKER_UI_HOST", "127.0.0.1"),
        ui_port=int(env("BROKER_UI_PORT", "8701")),
        audit_log=env("BROKER_AUDIT_LOG_FILE", "data/audit.log"),
    )
