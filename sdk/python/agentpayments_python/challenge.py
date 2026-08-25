import hmac
import json
import re
import secrets as _secrets
import threading
import time
from pathlib import Path

from .crypto import client_id_for_ip, hmac_sign, sha256_hex

_constants = json.loads((Path(__file__).resolve().parent.parent.parent / "constants.json").read_text())
POW_DIFFICULTY = _constants["POW_DIFFICULTY"]
MAX_POW_LENGTH = _constants["MAX_POW_LENGTH"]
NONCE_TTL_MS = _constants["NONCE_TTL_MS"]

# Canvas fingerprints are a base64 slice of a data URL. Reject anything that
# isn't base64 or is degenerate (e.g. a single repeated character).
_FP_RE = re.compile(r"^[A-Za-z0-9+/]{10,}$")
_POW_RE = re.compile(r"^\d{1,20}$")


def make_nonce(secret: str, client_ip: str) -> str:
    """Nonce format: <ts>.<rand>.<sig>, signature bound to the client IP."""
    ts = str(int(time.time() * 1000))
    rand = _secrets.token_hex(8)
    client_id = client_id_for_ip(client_ip, secret)
    sig = hmac_sign(f"nonce:{ts}:{rand}:{client_id}", secret)
    return f"{ts}.{rand}.{sig}"


def _is_plausible_fingerprint(fp: str) -> bool:
    return bool(_FP_RE.match(fp)) and len(set(fp)) >= 4


def _verify_pow(nonce: str, pow_value: str, difficulty: int) -> bool:
    """Proof-of-work: sha256(f"{nonce}:{pow}") must start with `difficulty`
    zero hex chars. Verification is one hash; solving costs ~16^difficulty."""
    if not _POW_RE.match(pow_value):
        return False
    return sha256_hex(f"{nonce}:{pow_value}").startswith("0" * difficulty)


class _ConsumedNonces:
    """Single-use nonce tracking (best-effort, in-memory, thread-safe)."""

    def __init__(self, ttl_ms: int = NONCE_TTL_MS, max_size: int = 10000):
        self.ttl = ttl_ms / 1000.0
        self.max_size = max_size
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()

    def consume(self, sig: str) -> bool:
        """Returns True if the nonce was fresh (and marks it consumed)."""
        now = time.time()
        with self._lock:
            exp = self._seen.get(sig)
            if exp is not None and exp > now:
                return False
            if len(self._seen) >= self.max_size:
                expired = [k for k, v in self._seen.items() if v <= now]
                for k in expired:
                    del self._seen[k]
                if len(self._seen) >= self.max_size:
                    del self._seen[next(iter(self._seen))]
            self._seen[sig] = now + self.ttl
            return True


_consumed_nonces = _ConsumedNonces()


def validate_challenge_submission(
    nonce: str,
    fp: str,
    pow_value: str,
    secret: str,
    client_ip: str,
    difficulty: int = POW_DIFFICULTY,
) -> bool:
    """Full server-side validation of a challenge form submission.

    Checks: nonce structure and expiry, IP-bound HMAC signature, plausible
    fingerprint, proof-of-work, and single use.
    """
    parts = nonce.split(".")
    if len(parts) != 3 or not _is_plausible_fingerprint(fp):
        return False
    nonce_ts, nonce_rand, nonce_sig = parts
    try:
        ts = int(nonce_ts)
    except ValueError:
        return False
    if int(time.time() * 1000) - ts > NONCE_TTL_MS:
        return False
    client_id = client_id_for_ip(client_ip, secret)
    expected = hmac_sign(f"nonce:{nonce_ts}:{nonce_rand}:{client_id}", secret)
    if not hmac.compare_digest(nonce_sig, expected):
        return False
    if not _verify_pow(nonce, pow_value, difficulty):
        return False
    return _consumed_nonces.consume(nonce_sig)


def challenge_html(return_to: str, nonce: str, pow_difficulty: int = POW_DIFFICULTY) -> str:
    # Reject protocol-relative URLs (e.g. //attacker.com) which start with '/'
    # but are treated as external by browsers.
    safe_path = return_to if (return_to.startswith("/") and not return_to.startswith("//")) else "/"
    nonce_json = json.dumps(nonce)
    safe_path_json = json.dumps(safe_path)
    target_json = json.dumps("0" * pow_difficulty)
    return (
        "<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1.0'>"
        "<title>Verifying your access...</title>"
        "<style>body{font-family:system-ui,sans-serif;display:flex;justify-content:center;"
        "align-items:center;min-height:100vh;margin:0;background:#fafafa;color:#333}"
        "main{text-align:center;padding:2rem}"
        ".spinner{width:40px;height:40px;border:4px solid #e0e0e0;border-top-color:#333;"
        "border-radius:50%;animation:spin .8s linear infinite;margin:1rem auto}"
        "@keyframes spin{to{transform:rotate(360deg)}}</style>"
        "</head><body>"
        "<main role='status' aria-live='polite'>"
        "<div class='spinner' aria-hidden='true'></div>"
        "<p>Verifying your access&hellip;</p>"
        "<noscript><p><strong>JavaScript is required to verify your access. "
        "Please enable JavaScript and reload this page.</strong></p></noscript>"
        "</main>"
        "<script>(function(){"
        "if(navigator.webdriver)return;"
        "if(!window.crypto||!window.crypto.subtle)return;"
        "var c=document.createElement('canvas');c.width=200;c.height=50;"
        "var ctx=c.getContext('2d');if(!ctx)return;"
        "ctx.font='18px Arial';ctx.fillStyle='#1a1a2e';ctx.fillText('verify',10,30);"
        "var data=c.toDataURL();if(!data||data.length<100)return;"
        "if(typeof window.innerWidth==='undefined'||window.innerWidth===0)return;"
        f"var nonce={nonce_json};var target={target_json};"
        "var enc=new TextEncoder();var i=0;"
        "function submit(pow){"
        "var form=document.createElement('form');form.method='POST';form.action='/__challenge/verify';"
        f"var fields={{nonce:nonce,return_to:{safe_path_json},fp:data.slice(22,86),pow:pow}};"
        "for(var k in fields){var input=document.createElement('input');"
        "input.type='hidden';input.name=k;input.value=fields[k];form.appendChild(input);}"
        "document.body.appendChild(form);form.submit();}"
        "function mine(){window.crypto.subtle.digest('SHA-256',enc.encode(nonce+':'+i)).then(function(buf){"
        "var b=new Uint8Array(buf);var h='';"
        "for(var j=0;j<4;j++)h+=(b[j]<16?'0':'')+b[j].toString(16);"
        "if(h.slice(0,target.length)===target)return submit(String(i));"
        "i++;mine();});}"
        "mine();})();</script>"
        "</body></html>"
    )
