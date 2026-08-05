import secrets
import time


class AuthStore:
    def __init__(self, nonce_ttl: int = 60, token_ttl: int = 900) -> None:
        self._nonce_ttl = nonce_ttl
        self._token_ttl = token_ttl
        self._nonces: dict[str, dict] = {}
        self._tokens: dict[str, dict] = {}

    def create_challenge(self, public_key: str) -> tuple[str, int]:
        nonce = secrets.token_hex(16)
        self._nonces[public_key] = {
            "nonce": nonce,
            "expires": time.time() + self._nonce_ttl,
        }
        return nonce, self._nonce_ttl

    def consume_nonce(self, public_key: str) -> str | None:
        entry = self._nonces.pop(public_key, None)
        if entry is None or entry["expires"] < time.time():
            return None
        return entry["nonce"]

    def issue_token(self, public_key: str, ip: str) -> tuple[str, int]:
        token = secrets.token_hex(32)
        self._tokens[token] = {
            "public_key": public_key,
            "ip": ip,
            "expires": time.time() + self._token_ttl,
        }
        return token, self._token_ttl

    def verify_token(self, token: str, ip: str) -> str | None:
        entry = self._tokens.get(token)
        if entry is None:
            return None
        if entry["expires"] < time.time():
            self._tokens.pop(token, None)
            return None
        if entry["ip"] != ip:
            return None
        return entry["public_key"]

    def revoke_public_key(self, public_key: str) -> None:
        self._nonces.pop(public_key, None)
        self._tokens = {
            token: entry
            for token, entry in self._tokens.items()
            if entry["public_key"] != public_key
        }
