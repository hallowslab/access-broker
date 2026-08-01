import getpass
import json
import os
import sys
import tomllib
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken


def load_master_key() -> bytes | None:
    raw = os.environ.get("RELAY_MASTER_KEY")
    if raw:
        return raw.strip().encode()
    key_file = os.environ.get("RELAY_MASTER_KEY_FILE")
    if key_file:
        path = Path(key_file)
        if path.exists():
            return path.read_text().strip().encode()
    return None


def generate_key() -> str:
    return Fernet.generate_key().decode()


def write_storage(toml_path: str, master_key: bytes, creds: dict) -> None:
    token = Fernet(master_key).encrypt(json.dumps(creds).encode()).decode()
    path = Path(toml_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f'[storage]\nencrypted = "{token}"\n')


def load_storage(toml_path: str, master_key: bytes | None) -> tuple[dict | None, str | None]:
    path = Path(toml_path)
    if not path.exists():
        return None, "storage not configured"
    try:
        data = tomllib.loads(path.read_text())
    except (tomllib.TOMLDecodeError, OSError):
        return None, "cannot read storage config"
    token = data.get("storage", {}).get("encrypted")
    if not token:
        return None, "storage not configured"
    if master_key is None:
        return None, "RELAY_MASTER_KEY (or RELAY_MASTER_KEY_FILE) missing"
    try:
        creds = json.loads(Fernet(master_key).decrypt(token.encode()))
    except (InvalidToken, ValueError):
        return None, "cannot decrypt storage config (bad master key?)"
    return creds, None


def storage_set(toml_path: str) -> None:
    master_key = load_master_key()
    if master_key is None:
        sys.exit(
            "no master key set — set RELAY_MASTER_KEY or RELAY_MASTER_KEY_FILE "
            "(generate one with: relay keygen)"
        )
    protocol = input("protocol (ftp/ftps) [ftp]: ").strip().lower() or "ftp"
    if protocol not in ("ftp", "ftps"):
        sys.exit("protocol must be ftp or ftps")
    host = input("host: ").strip()
    if not host:
        sys.exit("host is required")
    default_port = "990" if protocol == "ftps" else "21"
    port = input(f"port [{default_port}]: ").strip() or default_port
    user = input("user: ").strip()
    if not user:
        sys.exit("user is required")
    password = getpass.getpass("password: ")
    root = input("root dir (optional): ").strip() or None
    ca_path = input("ca cert PEM file (self-signed trust, optional): ").strip()
    ca_cert = None
    if ca_path:
        try:
            ca_cert = Path(ca_path).read_text()
        except OSError:
            sys.exit(f"cannot read CA cert file: {ca_path}")
    creds = {
        "protocol": protocol,
        "host": host,
        "port": int(port),
        "user": user,
        "password": password,
        "root": root,
        "ca_cert": ca_cert,
    }
    write_storage(toml_path, master_key, creds)
    print(f"storage credentials written to {toml_path} (encrypted)")


def storage_show(toml_path: str) -> None:
    master_key = load_master_key()
    creds, error = load_storage(toml_path, master_key)
    if error:
        sys.exit(error)
    redacted = dict(creds)
    redacted["password"] = "*" * 8
    print(json.dumps(redacted, indent=2))


def storage_clear(toml_path: str) -> None:
    path = Path(toml_path)
    if not path.exists():
        sys.exit("no storage config file")
    data = tomllib.loads(path.read_text())
    data.pop("storage", None)
    path.write_text("")
    print(f"storage config cleared from {toml_path}")
