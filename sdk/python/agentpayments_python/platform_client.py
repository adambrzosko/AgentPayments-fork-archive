"""
AgentPayments Platform Client

Thin HTTP client for the AgentPayments Platform API.

Usage:
    client = PlatformClient(api_key="ap_live_...")
    key = client.issue_key()          # returns 'agp_...'
    secret = client.verification_secret  # cached after first call

The verificationSecret is fetched once per client instance and cached in memory.
Agent keys are verified locally using is_valid_hosted_key() — no per-request
platform round-trip is needed.
"""

from __future__ import annotations

import hashlib
import hmac as _hmac
import json
import threading
import urllib.request
import urllib.error

from pathlib import Path as _Path

_constants = json.loads((_Path(__file__).resolve().parent / "constants.json").read_text())
PLATFORM_API_URL: str = _constants["PLATFORM_API_URL"]
HOSTED_KEY_PREFIX: str = _constants["HOSTED_KEY_PREFIX"]


def _hmac_hex(data: str, key: str) -> str:
    return _hmac.new(key.encode(), data.encode(), hashlib.sha256).hexdigest()


def is_valid_hosted_key(key: str, verification_secret: str) -> bool:
    """
    Verify a platform-issued agent key locally.

    Key format: agp_${vendorId8}_${nonce16}_${sig16}
    sig = hmac('agp:vendorId:nonce', verificationSecret).slice(0,16)
    """
    if not key or not key.startswith(HOSTED_KEY_PREFIX):
        return False
    parts = key.split("_")
    # ['agp', vendorId(8), nonce(16), sig(16)]
    if len(parts) != 4:
        return False
    _, vendor_id, nonce, sig = parts
    if not vendor_id or not nonce or not sig or len(sig) != 16:
        return False
    expected = _hmac_hex(f"agp:{vendor_id}:{nonce}", verification_secret)[:16]
    return _hmac.compare_digest(sig, expected)


class PlatformClient:
    """
    Manages communication with the AgentPayments Platform API.

    Thread-safe: the verificationSecret is fetched once and cached for the
    lifetime of the process.
    """

    def __init__(self, api_key: str, platform_url: str = PLATFORM_API_URL) -> None:
        self.api_key = api_key
        # Callers (django/fastapi/flask adapters) often pass platform_url=None
        # explicitly when no override was configured, which bypasses this
        # parameter's own default — fall back to PLATFORM_API_URL here too.
        self.platform_url = (platform_url or PLATFORM_API_URL).rstrip("/")
        self._verification_secret: str | None = None
        self._platform_fee_info: dict | None = None
        self._account_fetched = False
        self._lock = threading.Lock()

    def _auth_headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    def _get(self, path: str) -> dict:
        req = urllib.request.Request(
            f"{self.platform_url}{path}",
            headers=self._auth_headers(),
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"Platform API {path} returned {exc.code}") from exc

    def _post(self, path: str, body: dict | None = None) -> dict:
        data = json.dumps(body or {}).encode()
        req = urllib.request.Request(
            f"{self.platform_url}{path}",
            data=data,
            headers=self._auth_headers(),
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"Platform API {path} returned {exc.code}") from exc

    def _ensure_account_fetched(self) -> None:
        """Fetch + cache the /v1/account response once (thread-safe, double-checked)."""
        if self._account_fetched:
            return
        with self._lock:
            if self._account_fetched:
                return
            data = self._get("/v1/account")
            self._verification_secret = data["verificationSecret"]
            fee_wallet = data.get("platformFeeWallet")
            self._platform_fee_info = (
                {"wallet": fee_wallet, "rate_pct": data.get("platformFeeRatePct")}
                if fee_wallet
                else None
            )
            self._account_fetched = True

    @property
    def verification_secret(self) -> str:
        """Fetch + cache verificationSecret from /v1/account (thread-safe)."""
        self._ensure_account_fetched()
        return self._verification_secret

    def get_platform_fee_info(self) -> dict | None:
        """
        Fetch + cache the on-chain platform fee config from /v1/account (same
        request as verification_secret — no extra round trip if already fetched).
        Returns {"wallet": str, "rate_pct": float} or None if no fee is configured.
        """
        self._ensure_account_fetched()
        return self._platform_fee_info

    def issue_key(self) -> str:
        """Issue a single platform-signed agent key (agp_...). Metered."""
        data = self._post("/v1/keys/issue")
        return data["key"]
