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


def load_config() -> Config:
    def env(key: str, default: str) -> str:
        return os.environ.get(key, default)

    return Config(
        host=env("RELAY_HOST", "0.0.0.0"),
        port=int(env("RELAY_PORT", "8700")),
        db=env("RELAY_DB", "data/relay.db"),
        toml=env("RELAY_TOML", "data/relay.toml"),
        trust_proxy=env("RELAY_TRUST_PROXY", "0") in ("1", "true", "yes"),
        ui_enabled=env("RELAY_UI_ENABLED", "1") in ("1", "true", "yes"),
        ui_host=env("RELAY_UI_HOST", "127.0.0.1"),
        ui_port=int(env("RELAY_UI_PORT", "8701")),
    )
