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
    backend = input("backend (ftps/s3) [ftps]: ").strip().lower() or "ftps"
    if backend == "ftps":
        creds = _prompt_ftps()
    elif backend == "s3":
        creds = _prompt_s3()
    else:
        sys.exit("backend must be ftps or s3")
    write_storage(toml_path, master_key, creds)
    print(f"storage credentials written to {toml_path} (encrypted)")


def storage_set_from_json(toml_path: str, data_path: str) -> None:
    master_key = load_master_key()
    if master_key is None:
        sys.exit(
            "no master key set — set RELAY_MASTER_KEY or RELAY_MASTER_KEY_FILE "
            "(generate one with: relay keygen)"
        )
    try:
        creds = json.loads(Path(data_path).read_text())
    except OSError as exc:
        sys.exit(f"cannot read storage JSON: {exc}")
    except json.JSONDecodeError as exc:
        sys.exit(f"invalid storage JSON: {exc}")
    _validate_record(creds)
    write_storage(toml_path, master_key, creds)
    print(f"storage credentials written to {toml_path} (encrypted)")


def _validate_record(creds: dict) -> None:
    if creds.get("version") != 1:
        sys.exit('storage JSON must be a versioned record: {"version": 1, "backend": {...}}')
    backend = creds.get("backend")
    if not isinstance(backend, dict):
        sys.exit("storage JSON must contain a 'backend' object")
    kind = backend.get("type")
    if kind == "s3":
        endpoint = backend.get("endpoint")
        if not endpoint:
            sys.exit("s3 backend requires endpoint")
        if not str(endpoint).startswith("https://"):
            sys.exit("s3 endpoint must be https (S3 over TLS is mandatory)")
        for field in ("bucket", "access_key_id", "secret_access_key"):
            if not backend.get(field):
                sys.exit(f"s3 backend requires {field}")
    elif kind == "ftps":
        for field in ("host", "user"):
            if not backend.get(field):
                sys.exit(f"ftps backend requires {field}")
    else:
        sys.exit("backend type must be 'ftps' or 's3'")


def _prompt_ftps() -> dict:
    host = input("host: ").strip()
    if not host:
        sys.exit("host is required")
    port = input("port [990]: ").strip() or "990"
    user = input("user: ").strip()
    if not user:
        sys.exit("user is required")
    password = getpass.getpass("password: ")
    root = input("root dir (optional): ").strip() or None
    ca_cert = _prompt_ca_cert()
    return {
        "version": 1,
        "backend": {
            "type": "ftps",
            "host": host,
            "port": int(port),
            "user": user,
            "password": password,
            "root": root,
            "ca_cert": ca_cert,
        },
    }


def _prompt_s3() -> dict:
    endpoint = input("endpoint: ").strip()
    if not endpoint:
        sys.exit("endpoint is required")
    if not endpoint.startswith("https://"):
        sys.exit("endpoint must be https (S3 over TLS is mandatory)")
    bucket = input("bucket: ").strip()
    if not bucket:
        sys.exit("bucket is required")
    access_key_id = input("access key id: ").strip()
    if not access_key_id:
        sys.exit("access key id is required")
    secret_access_key = getpass.getpass("secret access key: ")
    region = input("region (optional): ").strip() or None
    path_style = _prompt_yes_no("path-style endpoint (default true)", default=True)
    session_token = None
    if input("session token (reserved for STS, optional)? [y/N]: ").strip().lower() == "y":
        session_token = getpass.getpass("session token: ")
    root = input("object prefix (optional): ").strip() or None
    ca_cert = _prompt_ca_cert()
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
        },
    }


def _prompt_ca_cert() -> str | None:
    ca_path = input("ca cert PEM file (self-signed trust, optional): ").strip()
    if not ca_path:
        return None
    try:
        return Path(ca_path).read_text()
    except OSError:
        sys.exit(f"cannot read CA cert file: {ca_path}")


def _prompt_yes_no(prompt: str, default: bool) -> bool:
    suffix = " [Y/n]" if default else " [y/N]"
    answer = input(f"{prompt}{suffix}: ").strip().lower()
    if not answer:
        return default
    return answer in ("y", "yes")


def storage_show(toml_path: str) -> None:
    master_key = load_master_key()
    creds, error = load_storage(toml_path, master_key)
    if error:
        sys.exit(error)
    redacted = _redact(creds)
    print(json.dumps(redacted, indent=2))


def _redact(creds: dict) -> dict:
    redacted = dict(creds)
    backend = redacted.get("backend")
    if isinstance(backend, dict):
        redacted["backend"] = dict(backend)
        for key in ("password", "secret_access_key"):
            if key in redacted["backend"]:
                redacted["backend"][key] = "*" * 8
    for key in ("password", "secret_access_key"):
        if key in redacted:
            redacted[key] = "*" * 8
    return redacted


def storage_clear(toml_path: str) -> None:
    path = Path(toml_path)
    if not path.exists():
        sys.exit("no storage config file")
    data = tomllib.loads(path.read_text())
    data.pop("storage", None)
    path.write_text("")
    print(f"storage config cleared from {toml_path}")
