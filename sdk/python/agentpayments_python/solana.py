import json
import logging
import re
import threading
import time as _time
from collections import OrderedDict
from pathlib import Path

import requests

logger = logging.getLogger(__name__)

PAYMENT_CACHE_TTL = 10 * 60      # 10 minutes in seconds
NEGATIVE_CACHE_TTL = 30          # 30 seconds for negative results
PAYMENT_CACHE_MAX = 1000


class _PaymentCache:
    """Caches both positive (True) and negative (False) payment results with per-entry TTLs."""

    def __init__(self, max_size: int = PAYMENT_CACHE_MAX):
        self.max_size = max_size
        # stores (value: bool, ts: float, ttl: int)
        self._cache: OrderedDict[str, tuple[bool, float, int]] = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key: str):
        """Returns True, False, or None (not cached / expired)."""
        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                return None
            value, ts, ttl = entry
            if _time.time() - ts > ttl:
                del self._cache[key]
                return None
            return value

    def set(self, key: str, value: bool, ttl: int) -> None:
        with self._lock:
            if len(self._cache) >= self.max_size:
                self._cache.popitem(last=False)
            self._cache[key] = (value, _time.time(), ttl)


_payment_cache = _PaymentCache()

BASE58_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")

_constants = json.loads((Path(__file__).resolve().parent / "constants.json").read_text())
MIN_PAYMENT_MICRO = round(_constants["MIN_PAYMENT"] * 1_000_000)  # integer micro-USDC threshold
USDC_MINT_DEVNET = _constants["USDC_MINT_DEVNET"]
USDC_MINT_MAINNET = _constants["USDC_MINT_MAINNET"]
RPC_DEVNET = _constants["RPC_DEVNET"]
RPC_MAINNET = _constants["RPC_MAINNET"]
MEMO_PROGRAM = _constants["MEMO_PROGRAM"]
MIN_PAYMENT = _constants["MIN_PAYMENT"]
MAX_TRANSACTIONS_PER_VERIFY = _constants["MAX_TRANSACTIONS_PER_VERIFY"]


def _rpc_call(rpc_url: str, method: str, params: list, retries: int = 2, backoff: float = 0.3) -> dict:
    last_error: Exception = RuntimeError("RPC call failed before any attempt")
    for attempt in range(retries + 1):
        if attempt > 0:
            import time as _sleep_time
            _sleep_time.sleep(backoff * attempt)
        try:
            resp = requests.post(rpc_url, json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params}, timeout=30)
            # Only retry on 5xx (transient server errors); 4xx are permanent.
            if resp.status_code >= 500:
                last_error = requests.HTTPError(f"RPC {method} failed: {resp.status_code}", response=resp)
                continue
            resp.raise_for_status()
            return resp.json()
        except requests.HTTPError:
            raise  # permanent 4xx — don't retry
        except Exception as exc:
            last_error = exc
    raise last_error


def _rpc_call_with_fallback(rpc_urls: list[str], method: str, params: list, **kwargs) -> dict:
    """Try each RPC URL in order; move to the next on network/5xx failure."""
    last_error: Exception = RuntimeError("No RPC URLs provided")
    for url in rpc_urls:
        try:
            return _rpc_call(url, method, params, **kwargs)
        except Exception as exc:
            last_error = exc
            if len(rpc_urls) > 1:
                logger.warning("[gate] RPC endpoint failed, trying fallback: url=%s error=%s", url, exc)
    raise last_error


def is_valid_solana_address(address: str) -> bool:
    return bool(address and BASE58_RE.match(address))


def verify_payment_on_chain(agent_key: str, wallet_address: str, rpc_url, usdc_mint: str) -> bool:
    """Verify payment on-chain. rpc_url may be a string or list of strings (fallback URLs)."""
    # Normalise to list so _rpc_call_with_fallback always gets a list.
    rpc_urls: list[str] = rpc_url if isinstance(rpc_url, list) else [rpc_url]

    cached = _payment_cache.get(agent_key)
    if cached is True:
        return True
    if cached is False:
        return False  # negative cached — skip RPC until TTL expires
    if not is_valid_solana_address(wallet_address):
        logger.error("[gate] Invalid wallet address: %s", wallet_address)
        return False
    try:
        # commitment: 'finalized' — confirmed blocks can be rolled back (rare but possible).
        # Finalized adds ~10-20 s latency vs confirmed but guarantees irreversibility.
        ata_data = _rpc_call_with_fallback(rpc_urls, "getTokenAccountsByOwner", [wallet_address, {"mint": usdc_mint}, {"encoding": "jsonParsed", "commitment": "finalized"}])
        token_accounts = [a["pubkey"] for a in ata_data.get("result", {}).get("value", [])]
        # Only transfers landing in one of the vendor's USDC token accounts count as
        # payment. Token accounts are mint-bound, so membership also guarantees the
        # token is USDC for plain `transfer` instructions (which carry no mint field).
        vendor_usdc_accounts = set(token_accounts)
        if not vendor_usdc_accounts:
            return False  # vendor has no USDC account yet — no payment possible

        addresses_to_scan = [wallet_address] + token_accounts
        seen = set()
        all_signatures = []

        for addr in addresses_to_scan:
            sigs_data = _rpc_call_with_fallback(rpc_urls, "getSignaturesForAddress", [addr, {"limit": 100, "commitment": "finalized"}])
            for sig in sigs_data.get("result", []):
                if sig["signature"] not in seen:
                    seen.add(sig["signature"])
                    all_signatures.append(sig)

        tx_call_count = 0
        for sig_info in all_signatures:
            if tx_call_count >= MAX_TRANSACTIONS_PER_VERIFY:
                logger.warning("[gate] getTransaction cap reached (key=%s..., cap=%d)", agent_key[:12], MAX_TRANSACTIONS_PER_VERIFY)
                break
            if sig_info.get("err"):
                continue
            tx_call_count += 1

            tx_data = _rpc_call_with_fallback(rpc_urls, "getTransaction", [sig_info["signature"], {"encoding": "jsonParsed", "commitment": "finalized", "maxSupportedTransactionVersion": 0}])
            tx = tx_data.get("result")
            if not tx:
                continue

            instructions = tx.get("transaction", {}).get("message", {}).get("instructions", [])
            inner_instructions = tx.get("meta", {}).get("innerInstructions", [])
            all_ix = list(instructions)
            for group in inner_instructions:
                all_ix.extend(group.get("instructions", []))

            has_memo = False
            has_payment = False

            for ix in all_ix:
                program = ix.get("program", "")
                program_id = ix.get("programId", "")
                if program == "spl-memo" or program_id == MEMO_PROGRAM:
                    parsed = ix.get("parsed", "")
                    memo_text = parsed if isinstance(parsed, str) else str(parsed)
                    if agent_key in memo_text:
                        has_memo = True

                if program == "spl-token":
                    parsed = ix.get("parsed", {})
                    tx_type = parsed.get("type", "")
                    if tx_type in ("transfer", "transferChecked"):
                        info = parsed.get("info", {})
                        # Payment must be delivered to one of the vendor's USDC token accounts.
                        if info.get("destination") not in vendor_usdc_accounts:
                            continue
                        if tx_type == "transferChecked" and info.get("mint") != usdc_mint:
                            continue
                        # Integer base-unit comparison — avoids float precision issues at
                        # the payment threshold. tokenAmount.amount and amount are both
                        # integer strings in micro-USDC (base units).
                        token_amount = info.get("tokenAmount") or {}
                        amount_str = token_amount.get("amount") or info.get("amount", "0")
                        try:
                            amount_micro = int(amount_str)
                        except (ValueError, TypeError):
                            amount_micro = 0
                        if amount_micro >= MIN_PAYMENT_MICRO:
                            has_payment = True

            if has_memo and has_payment:
                _payment_cache.set(agent_key, True, PAYMENT_CACHE_TTL)
                return True
    except Exception:
        logger.exception("[gate] Solana RPC error")

    _payment_cache.set(agent_key, False, NEGATIVE_CACHE_TTL)
    return False
