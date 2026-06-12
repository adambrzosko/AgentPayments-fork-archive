import hashlib
import hmac
import json
import uuid
from pathlib import Path

_constants = json.loads((Path(__file__).resolve().parent.parent.parent / "constants.json").read_text())
KEY_PREFIX = _constants["KEY_PREFIX"]
MAX_KEY_LENGTH = _constants["MAX_KEY_LENGTH"]


def hmac_sign(data: str, secret: str) -> str:
    return hmac.new(secret.encode(), data.encode(), hashlib.sha256).hexdigest()


def sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()


def client_id_for_ip(ip: str, secret: str) -> str:
    """Short HMAC of the client IP. Used to bind nonces and cookies to the
    client that solved the challenge, so a captured cookie is useless from
    another IP."""
    return hmac_sign(f"client:{ip}", secret)[:16]


def generate_agent_key(secret: str) -> str:
    random_part = uuid.uuid4().hex[:16]
    sig = hmac_sign(random_part, secret)
    return f"{KEY_PREFIX}{random_part}_{sig[:16]}"


def is_valid_agent_key(key: str, secret: str) -> bool:
    if not key or len(key) > MAX_KEY_LENGTH or not key.startswith(KEY_PREFIX):
        return False
    rest = key[len(KEY_PREFIX):]
    i = rest.find("_")
    if i == -1:
        return False
    random_part = rest[:i]
    sig = rest[i + 1:]
    expected = hmac_sign(random_part, secret)
    return hmac.compare_digest(sig, expected[:16])
