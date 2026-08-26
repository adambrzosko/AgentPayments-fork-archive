import hmac
import json
import time
from pathlib import Path

from .crypto import client_id_for_ip, hmac_sign

_constants = json.loads((Path(__file__).resolve().parent / "constants.json").read_text())
COOKIE_NAME = _constants["COOKIE_NAME"]
COOKIE_MAX_AGE = _constants["COOKIE_MAX_AGE"]


def make_cookie(secret: str, client_ip: str) -> str:
    """Cookie format: <ts>.<sig>, signature bound to the client IP that
    solved the challenge, so a captured cookie is useless from another IP."""
    now_ms = str(int(time.time() * 1000))
    client_id = client_id_for_ip(client_ip, secret)
    return f"{now_ms}.{hmac_sign(f'cookie:{now_ms}:{client_id}', secret)}"


def is_valid_cookie_value(cookie_value: str, secret: str, client_ip: str) -> bool:
    if not cookie_value:
        return False
    i = cookie_value.find(".")
    if i == -1:
        return False
    ts_str = cookie_value[:i]
    sig = cookie_value[i + 1:]
    try:
        ts = int(ts_str)
    except ValueError:
        return False
    if int(time.time() * 1000) - ts > COOKIE_MAX_AGE * 1000:
        return False
    client_id = client_id_for_ip(client_ip, secret)
    expected = hmac_sign(f"cookie:{ts_str}:{client_id}", secret)
    return hmac.compare_digest(sig, expected)
