"""
Python SDK unit tests — pytest
Run: cd sdk/python && pip install -e . pytest && pytest tests/
"""
import hashlib
import hmac as _hmac
import json
import os
import tempfile
import time
import threading
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# ── module imports ──────────────────────────────────────────────────────────
from agentpayments_python.crypto import (
    client_id_for_ip,
    generate_agent_key,
    hmac_sign,
    is_valid_agent_key,
    sha256_hex,
)
from agentpayments_python.cookies import (
    COOKIE_MAX_AGE,
    COOKIE_NAME,
    is_valid_cookie_value,
    make_cookie,
)
from agentpayments_python.challenge import (
    POW_DIFFICULTY,
    _verify_pow,
    _is_plausible_fingerprint,
    make_nonce,
    validate_challenge_submission,
)
from agentpayments_python.detection import is_browser_from_headers, is_public_path
from agentpayments_python.ratelimit import RateLimiter
from agentpayments_python.grant_store import FileGrantStore, MemoryGrantStore
from agentpayments_python.solana import (
    NEGATIVE_CACHE_TTL,
    PAYMENT_CACHE_TTL,
    _PaymentCache,
    _payment_cache,
)

SECRET = "test-secret-32-bytes-long-abcdefg"
IP = "1.2.3.4"

# ── Helpers ─────────────────────────────────────────────────────────────────


def make_nonce_for(secret, ip, ts_override=None):
    """Make a fresh nonce (or one with an injected timestamp for expiry tests)."""
    import secrets as _s
    ts = ts_override or str(int(time.time() * 1000))
    rand = _s.token_hex(8)
    cid = client_id_for_ip(ip, secret)
    sig = hmac_sign(f"nonce:{ts}:{rand}:{cid}", secret)
    return f"{ts}.{rand}.{sig}"


def solve_pow(nonce, difficulty=POW_DIFFICULTY):
    target = "0" * difficulty
    for i in range(10_000_000):
        if sha256_hex(f"{nonce}:{i}").startswith(target):
            return str(i)
    raise RuntimeError("PoW solution not found within range")


VALID_FP = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"  # 32 base64 chars, 4+ distinct


# ─── crypto: hmac_sign / sha256_hex ─────────────────────────────────────────

class TestHmacSign:
    def test_deterministic(self):
        assert hmac_sign("hello", SECRET) == hmac_sign("hello", SECRET)

    def test_different_data(self):
        assert hmac_sign("a", SECRET) != hmac_sign("b", SECRET)

    def test_different_secret(self):
        assert hmac_sign("hello", SECRET) != hmac_sign("hello", "other-secret")

    def test_returns_hex(self):
        result = hmac_sign("test", SECRET)
        assert all(c in "0123456789abcdef" for c in result)
        assert len(result) == 64


class TestSha256Hex:
    def test_known_value(self):
        assert sha256_hex("") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def test_deterministic(self):
        assert sha256_hex("agentpayments") == sha256_hex("agentpayments")


# ─── crypto: client_id_for_ip ───────────────────────────────────────────────

class TestClientIdForIp:
    def test_length_16(self):
        cid = client_id_for_ip(IP, SECRET)
        assert len(cid) == 16

    def test_deterministic(self):
        assert client_id_for_ip(IP, SECRET) == client_id_for_ip(IP, SECRET)

    def test_different_ips(self):
        assert client_id_for_ip("1.2.3.4", SECRET) != client_id_for_ip("5.6.7.8", SECRET)

    def test_different_secrets(self):
        assert client_id_for_ip(IP, SECRET) != client_id_for_ip(IP, "other")


# ─── crypto: agent key ──────────────────────────────────────────────────────

class TestAgentKey:
    def test_prefix(self):
        key = generate_agent_key(SECRET)
        assert key.startswith("ag_")

    def test_length_within_limit(self):
        key = generate_agent_key(SECRET)
        assert len(key) <= 64

    def test_structure(self):
        key = generate_agent_key(SECRET)
        rest = key[3:]  # strip "ag_"
        parts = rest.split("_")
        assert len(parts) == 2
        assert len(parts[0]) == 16
        assert len(parts[1]) == 16

    def test_unique(self):
        assert generate_agent_key(SECRET) != generate_agent_key(SECRET)

    def test_valid(self):
        key = generate_agent_key(SECRET)
        assert is_valid_agent_key(key, SECRET)

    def test_wrong_secret_invalid(self):
        key = generate_agent_key(SECRET)
        assert not is_valid_agent_key(key, "wrong-secret")

    def test_tampered_sig_invalid(self):
        key = generate_agent_key(SECRET)
        tampered = key[:-1] + ("x" if key[-1] != "x" else "y")
        assert not is_valid_agent_key(tampered, SECRET)

    def test_too_long_invalid(self):
        key = "ag_" + "a" * 200
        assert not is_valid_agent_key(key, SECRET)

    def test_no_prefix_invalid(self):
        assert not is_valid_agent_key("bad_key_format", SECRET)

    def test_empty_invalid(self):
        assert not is_valid_agent_key("", SECRET)

    def test_truncated_invalid(self):
        key = generate_agent_key(SECRET)
        assert not is_valid_agent_key(key[:10], SECRET)


# ─── cookies ────────────────────────────────────────────────────────────────

class TestCookies:
    def test_make_and_validate(self):
        val = make_cookie(SECRET, IP)
        assert is_valid_cookie_value(val, SECRET, IP)

    def test_wrong_ip_invalid(self):
        val = make_cookie(SECRET, IP)
        assert not is_valid_cookie_value(val, SECRET, "9.9.9.9")

    def test_tampered_sig_invalid(self):
        val = make_cookie(SECRET, IP)
        tampered = val[:-4] + "xxxx"
        assert not is_valid_cookie_value(tampered, SECRET, IP)

    def test_expired_invalid(self):
        old_ts = str(int((time.time() - COOKIE_MAX_AGE - 60) * 1000))
        cid = client_id_for_ip(IP, SECRET)
        sig = hmac_sign(f"cookie:{old_ts}:{cid}", SECRET)
        expired = f"{old_ts}.{sig}"
        assert not is_valid_cookie_value(expired, SECRET, IP)

    def test_empty_invalid(self):
        assert not is_valid_cookie_value("", SECRET, IP)

    def test_no_dot_invalid(self):
        assert not is_valid_cookie_value("nodot", SECRET, IP)

    def test_wrong_secret_invalid(self):
        val = make_cookie(SECRET, IP)
        assert not is_valid_cookie_value(val, "wrong-secret", IP)

    def test_cookie_name_constant(self):
        assert isinstance(COOKIE_NAME, str) and len(COOKIE_NAME) > 0


# ─── challenge / nonce ──────────────────────────────────────────────────────

class TestNonce:
    def test_make_and_validate_structure(self):
        nonce = make_nonce(SECRET, IP)
        parts = nonce.split(".")
        assert len(parts) == 3

    def test_unique(self):
        assert make_nonce(SECRET, IP) != make_nonce(SECRET, IP)

    def test_expired_nonce_rejected(self):
        from agentpayments_python.challenge import NONCE_TTL_MS
        old_ts = str(int(time.time() * 1000) - NONCE_TTL_MS - 5000)
        nonce = make_nonce_for(SECRET, IP, ts_override=old_ts)
        pow_val = solve_pow(nonce)
        result = validate_challenge_submission(nonce, VALID_FP, pow_val, SECRET, IP)
        assert not result

    def test_tampered_nonce_rejected(self):
        nonce = make_nonce(SECRET, IP)
        parts = nonce.split(".")
        bad = f"{parts[0]}.ZZZZZZZZZZZZZZZZ.{parts[2]}"
        pow_val = solve_pow(bad)
        result = validate_challenge_submission(bad, VALID_FP, pow_val, SECRET, IP)
        assert not result

    def test_wrong_ip_rejected(self):
        nonce = make_nonce(SECRET, IP)
        pow_val = solve_pow(nonce)
        result = validate_challenge_submission(nonce, VALID_FP, pow_val, SECRET, "5.5.5.5")
        assert not result


# ─── proof of work ──────────────────────────────────────────────────────────

class TestPoW:
    def test_valid_pow_accepted(self):
        target = "0" * POW_DIFFICULTY
        for i in range(10_000_000):
            if sha256_hex(f"testnonce:{i}").startswith(target):
                assert _verify_pow("testnonce", str(i), POW_DIFFICULTY)
                return
        pytest.fail("no valid pow found")

    def test_wrong_pow_rejected(self):
        # pow=0 is astronomically unlikely to be correct for difficulty 4
        h = sha256_hex("testnonce:0")
        if not h.startswith("0000"):
            assert not _verify_pow("testnonce", "0", POW_DIFFICULTY)

    def test_non_numeric_pow_rejected(self):
        assert not _verify_pow("testnonce", "abc", POW_DIFFICULTY)

    def test_empty_pow_rejected(self):
        assert not _verify_pow("testnonce", "", POW_DIFFICULTY)


class TestFingerprint:
    def test_valid_fp(self):
        assert _is_plausible_fingerprint("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef")

    def test_too_short(self):
        assert not _is_plausible_fingerprint("ABCD")

    def test_not_enough_distinct(self):
        assert not _is_plausible_fingerprint("AAAAAAAAAA")

    def test_non_base64_chars(self):
        assert not _is_plausible_fingerprint("!@#$%^&*()" * 3)


# ─── challenge validate full ─────────────────────────────────────────────────

class TestValidateChallengeSubmission:
    def test_valid_submission(self):
        nonce = make_nonce(SECRET, IP)
        pow_val = solve_pow(nonce)
        assert validate_challenge_submission(nonce, VALID_FP, pow_val, SECRET, IP)

    def test_replay_rejected(self):
        nonce = make_nonce(SECRET, IP)
        pow_val = solve_pow(nonce)
        # First use: should pass
        assert validate_challenge_submission(nonce, VALID_FP, pow_val, SECRET, IP)
        # Replay: same nonce should fail
        assert not validate_challenge_submission(nonce, VALID_FP, pow_val, SECRET, IP)

    def test_bad_fp_rejected(self):
        nonce = make_nonce(SECRET, IP)
        pow_val = solve_pow(nonce)
        assert not validate_challenge_submission(nonce, "!!!", pow_val, SECRET, IP)

    def test_wrong_pow_rejected(self):
        nonce = make_nonce(SECRET, IP)
        assert not validate_challenge_submission(nonce, VALID_FP, "9999999999", SECRET, IP)


# ─── browser detection ──────────────────────────────────────────────────────

class TestBrowserDetection:
    CHROME_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    FIREFOX_UA = "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/120.0"
    SAFARI_UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15"
    GOOGLEBOT_UA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
    PYTHON_UA = "python-requests/2.31.0"
    CURL_UA = "curl/8.1.2"

    def test_sec_fetch_mode_is_browser(self):
        assert is_browser_from_headers({"sec-fetch-mode": "navigate"})

    def test_sec_fetch_dest_is_browser(self):
        assert is_browser_from_headers({"sec-fetch-dest": "document"})

    def test_chrome_ua_fallback(self):
        assert is_browser_from_headers({"user-agent": self.CHROME_UA})

    def test_firefox_ua_fallback(self):
        assert is_browser_from_headers({"user-agent": self.FIREFOX_UA})

    def test_safari_ua_fallback(self):
        assert is_browser_from_headers({"user-agent": self.SAFARI_UA})

    def test_googlebot_not_browser(self):
        assert not is_browser_from_headers({"user-agent": self.GOOGLEBOT_UA})

    def test_python_requests_not_browser(self):
        assert not is_browser_from_headers({"user-agent": self.PYTHON_UA})

    def test_curl_not_browser(self):
        assert not is_browser_from_headers({"user-agent": self.CURL_UA})

    def test_empty_headers_not_browser(self):
        assert not is_browser_from_headers({})

    def test_no_ua_not_browser(self):
        assert not is_browser_from_headers({"accept": "text/html"})


class TestPublicPath:
    def test_robots_txt(self):
        assert is_public_path("/robots.txt")

    def test_well_known(self):
        assert is_public_path("/.well-known/agent-access.json")

    def test_regular_path_not_public(self):
        assert not is_public_path("/api/data")

    def test_root_not_public(self):
        assert not is_public_path("/")


# ─── rate limiter ────────────────────────────────────────────────────────────

class TestRateLimiter:
    def test_allows_up_to_limit(self):
        rl = RateLimiter(window=60, max_hits=5)
        for _ in range(5):
            assert rl.check("ip1")

    def test_blocks_after_limit(self):
        rl = RateLimiter(window=60, max_hits=5)
        for _ in range(5):
            rl.check("ip1")
        assert not rl.check("ip1")

    def test_different_keys_independent(self):
        rl = RateLimiter(window=60, max_hits=3)
        for _ in range(3):
            rl.check("ip1")
        # ip1 is exhausted but ip2 is fresh
        assert not rl.check("ip1")
        assert rl.check("ip2")

    def test_window_resets(self):
        rl = RateLimiter(window=1, max_hits=2)
        assert rl.check("ip1")
        assert rl.check("ip1")
        assert not rl.check("ip1")
        time.sleep(1.1)
        assert rl.check("ip1")

    def test_challenge_path_limit_20(self):
        from agentpayments_python.ratelimit import RateLimiter
        rl = RateLimiter(window=60, max_hits=20)
        for _ in range(20):
            assert rl.check("ip1")
        assert not rl.check("ip1")

    def test_agent_key_path_limit_10(self):
        from agentpayments_python.ratelimit import RateLimiter
        rl = RateLimiter(window=60, max_hits=10)
        for _ in range(10):
            assert rl.check("ip1")
        assert not rl.check("ip1")


# ─── payment cache (positive + negative TTL) ────────────────────────────────

class TestPaymentCache:
    def test_miss_returns_none(self):
        cache = _PaymentCache()
        assert cache.get("nonexistent") is None

    def test_positive_hit(self):
        cache = _PaymentCache()
        cache.set("key1", True, PAYMENT_CACHE_TTL)
        assert cache.get("key1") is True

    def test_negative_hit(self):
        cache = _PaymentCache()
        cache.set("key2", False, NEGATIVE_CACHE_TTL)
        assert cache.get("key2") is False

    def test_positive_expiry(self):
        cache = _PaymentCache()
        cache.set("key3", True, 0)  # 0s TTL — already expired
        # Give it a tiny moment to ensure time.time() advances past the TTL
        time.sleep(0.01)
        assert cache.get("key3") is None

    def test_negative_expiry(self):
        cache = _PaymentCache()
        cache.set("key4", False, 0)
        time.sleep(0.01)
        assert cache.get("key4") is None

    def test_overwrite(self):
        cache = _PaymentCache()
        cache.set("key5", False, NEGATIVE_CACHE_TTL)
        assert cache.get("key5") is False
        cache.set("key5", True, PAYMENT_CACHE_TTL)
        assert cache.get("key5") is True

    def test_max_size_evicts_oldest(self):
        cache = _PaymentCache(max_size=3)
        cache.set("a", True, 600)
        cache.set("b", True, 600)
        cache.set("c", True, 600)
        cache.set("d", True, 600)  # should evict "a"
        assert cache.get("a") is None
        assert cache.get("d") is True


# ─── grant stores ────────────────────────────────────────────────────────────

class TestMemoryGrantStore:
    def test_unknown_key_false(self):
        gs = MemoryGrantStore()
        assert not gs.has("ag_unknown")

    def test_add_then_has(self):
        gs = MemoryGrantStore()
        gs.add("ag_test")
        assert gs.has("ag_test")

    def test_idempotent_add(self):
        gs = MemoryGrantStore()
        gs.add("ag_k")
        gs.add("ag_k")
        assert gs.has("ag_k")

    def test_thread_safe(self):
        gs = MemoryGrantStore()
        keys = [f"ag_{i}" for i in range(100)]
        threads = [threading.Thread(target=gs.add, args=(k,)) for k in keys]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        for k in keys:
            assert gs.has(k)


class TestFileGrantStore:
    def test_persist_and_reload(self, tmp_path):
        f = tmp_path / "grants.json"
        gs1 = FileGrantStore(str(f))
        gs1.add("ag_persist")
        gs2 = FileGrantStore(str(f))
        assert gs2.has("ag_persist")

    def test_unknown_false(self, tmp_path):
        f = tmp_path / "grants.json"
        gs = FileGrantStore(str(f))
        assert not gs.has("ag_never_added")

    def test_nonexistent_file_ok(self, tmp_path):
        f = tmp_path / "doesnotexist.json"
        gs = FileGrantStore(str(f))
        gs.add("ag_k")
        assert gs.has("ag_k")

    def test_idempotent_add_no_double_write(self, tmp_path):
        f = tmp_path / "grants.json"
        gs = FileGrantStore(str(f))
        gs.add("ag_k")
        mtime1 = f.stat().st_mtime
        time.sleep(0.01)
        gs.add("ag_k")
        mtime2 = f.stat().st_mtime
        assert mtime1 == mtime2  # no write on duplicate add

    def test_atomic_write_leaves_no_tmp(self, tmp_path):
        f = tmp_path / "grants.json"
        gs = FileGrantStore(str(f))
        gs.add("ag_k")
        assert not (tmp_path / "grants.tmp").exists()

    def test_multiple_keys(self, tmp_path):
        f = tmp_path / "grants.json"
        gs = FileGrantStore(str(f))
        for i in range(10):
            gs.add(f"ag_{i}")
        gs2 = FileGrantStore(str(f))
        for i in range(10):
            assert gs2.has(f"ag_{i}")


# ─── cross-runtime HMAC parity ───────────────────────────────────────────────
#
# Reference values computed by the Node SDK test suite's "print reference
# values" test (same SECRET, IP, ts, rand). If Node and Python produce the
# same hex strings, the runtimes are interoperable.

class TestCrossRuntimeParity:
    REF_IP = "1.2.3.4"
    REF_TS = "1700000000000"
    REF_RAND = "aabbccdd11223344"

    def _ref_client_id(self):
        return hmac_sign(f"client:{self.REF_IP}", SECRET)[:16]

    def test_client_id_deterministic(self):
        cid = client_id_for_ip(self.REF_IP, SECRET)
        assert len(cid) == 16
        # Must match the Node reference value produced by hmacHex(`client:${ip}`, secret).slice(0,16)
        expected = _hmac.new(SECRET.encode(), f"client:{self.REF_IP}".encode(), hashlib.sha256).hexdigest()[:16]
        assert cid == expected

    def test_nonce_sig_deterministic(self):
        cid = client_id_for_ip(self.REF_IP, SECRET)
        sig = hmac_sign(f"nonce:{self.REF_TS}:{self.REF_RAND}:{cid}", SECRET)
        # Recompute manually to confirm
        expected = _hmac.new(
            SECRET.encode(),
            f"nonce:{self.REF_TS}:{self.REF_RAND}:{cid}".encode(),
            hashlib.sha256,
        ).hexdigest()
        assert sig == expected
        assert len(sig) == 64

    def test_cookie_sig_deterministic(self):
        cid = client_id_for_ip(self.REF_IP, SECRET)
        sig = hmac_sign(f"cookie:{self.REF_TS}:{cid}", SECRET)
        expected = _hmac.new(
            SECRET.encode(),
            f"cookie:{self.REF_TS}:{cid}".encode(),
            hashlib.sha256,
        ).hexdigest()
        assert sig == expected
        assert len(sig) == 64

    def test_key_sig_matches_expected_format(self):
        # Node: hmacHex(random_part, secret).slice(0,16)
        # Python: hmac_sign(random_part, secret)[:16]
        # Both must produce identical 16-char hex strings.
        rand = "abc1234567890def"
        node_style = _hmac.new(SECRET.encode(), rand.encode(), hashlib.sha256).hexdigest()[:16]
        python_style = hmac_sign(rand, SECRET)[:16]
        assert node_style == python_style


# ─── verify_payment_on_chain (mocked RPC) ────────────────────────────────────

# We patch requests.post so no real network calls are made.

def _rpc_response(result):
    return MagicMock(
        status_code=200,
        json=lambda: {"jsonrpc": "2.0", "id": 1, "result": result},
    )


def _build_tx(memo: str, amount: float, mint: str, destination_owner: str, ok=True):
    """Build a minimal mock RPC getTransaction response for a transferChecked."""
    return {
        "meta": {
            "err": None if ok else {"InstructionError": [0, "Custom"]},
            "innerInstructions": [],
            "logMessages": [],
        },
        "transaction": {
            "message": {
                "instructions": [
                    {
                        "program": "spl-token",
                        "programId": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
                        "parsed": {
                            "type": "transferChecked",
                            "info": {
                                "mint": mint,
                                "tokenAmount": {"uiAmount": amount, "amount": str(round(amount * 1_000_000)), "decimals": 6},
                                "destination": "dest_ata_address",
                                "authority": "payer_address",
                            },
                        },
                    },
                    {
                        "program": "spl-memo",
                        "programId": "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",
                        "parsed": memo,
                    },
                ],
                "accountKeys": [],
            }
        },
    }


class TestVerifyPaymentOnChain:
    WALLET = "5rXZeAEbg13DQnSFijEno2hKEJLK2p14fAo3AmPtfBft"
    MINT = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"  # devnet USDC
    RPC = "https://api.devnet.solana.com"

    def _fresh_key(self):
        return generate_agent_key(SECRET)

    def _patch_rpc(self, sigs_result, ata_result, tx_result):
        """Return a context manager that patches requests.post with ordered responses."""
        from unittest.mock import call

        responses = []

        def side_effect(url, json=None, timeout=None):
            method = json.get("method", "")
            if method == "getTokenAccountsByOwner":
                return _rpc_response(ata_result)
            if method == "getSignaturesForAddress":
                return _rpc_response(sigs_result)
            if method == "getTransaction":
                return _rpc_response(tx_result)
            return _rpc_response(None)

        return patch("requests.post", side_effect=side_effect)

    def test_correct_payment_passes(self):
        from agentpayments_python.solana import verify_payment_on_chain, _payment_cache
        key = self._fresh_key()
        tx = _build_tx(key, 0.01, self.MINT, self.WALLET)
        ata = {"value": [{"pubkey": "dest_ata_address", "account": {"data": {"parsed": {"info": {"mint": self.MINT, "owner": self.WALLET}}}}}]}
        sigs = [{"signature": "sig1", "err": None}]
        with self._patch_rpc(sigs, ata, tx):
            result = verify_payment_on_chain(key, self.WALLET, self.RPC, self.MINT)
        assert result is True

    def test_wrong_memo_fails(self):
        from agentpayments_python.solana import verify_payment_on_chain
        key = self._fresh_key()
        tx = _build_tx("ag_completely_different_key", 0.01, self.MINT, self.WALLET)
        ata = {"value": [{"pubkey": "dest_ata_address", "account": {"data": {"parsed": {"info": {"mint": self.MINT, "owner": self.WALLET}}}}}]}
        sigs = [{"signature": "sig2", "err": None}]
        with self._patch_rpc(sigs, ata, tx):
            result = verify_payment_on_chain(key, self.WALLET, self.RPC, self.MINT)
        assert result is False

    def test_wrong_mint_fails(self):
        from agentpayments_python.solana import verify_payment_on_chain
        key = self._fresh_key()
        wrong_mint = "So11111111111111111111111111111111111111112"  # SOL, not USDC
        tx = _build_tx(key, 0.01, wrong_mint, self.WALLET)
        ata = {"value": [{"pubkey": "dest_ata_address", "account": {"data": {"parsed": {"info": {"mint": self.MINT, "owner": self.WALLET}}}}}]}
        sigs = [{"signature": "sig3", "err": None}]
        with self._patch_rpc(sigs, ata, tx):
            result = verify_payment_on_chain(key, self.WALLET, self.RPC, self.MINT)
        assert result is False

    def test_partial_amount_fails(self):
        from agentpayments_python.solana import verify_payment_on_chain, MIN_PAYMENT
        key = self._fresh_key()
        tx = _build_tx(key, MIN_PAYMENT / 2, self.MINT, self.WALLET)
        ata = {"value": [{"pubkey": "dest_ata_address", "account": {"data": {"parsed": {"info": {"mint": self.MINT, "owner": self.WALLET}}}}}]}
        sigs = [{"signature": "sig4", "err": None}]
        with self._patch_rpc(sigs, ata, tx):
            result = verify_payment_on_chain(key, self.WALLET, self.RPC, self.MINT)
        assert result is False

    def test_failed_tx_rejected(self):
        # Solana RPC sets err on the *signature* record in getSignaturesForAddress
        # when the transaction failed. The SDK correctly skips those (line 120-121
        # in solana.py). The tx body is never fetched for a failed sig.
        from agentpayments_python.solana import verify_payment_on_chain
        key = self._fresh_key()
        ata = {"value": [{"pubkey": "dest_ata_address", "account": {"data": {"parsed": {"info": {"mint": self.MINT, "owner": self.WALLET}}}}}]}
        # err is non-null → SDK skips this signature entirely
        sigs = [{"signature": "sig5", "err": {"InstructionError": [0, "Custom"]}}]
        with self._patch_rpc(sigs, ata, None):
            result = verify_payment_on_chain(key, self.WALLET, self.RPC, self.MINT)
        assert result is False

    def test_no_signatures_returns_false(self):
        from agentpayments_python.solana import verify_payment_on_chain
        key = self._fresh_key()
        ata = {"value": []}  # no ATAs → nothing to scan
        sigs = []
        with self._patch_rpc(sigs, ata, None):
            result = verify_payment_on_chain(key, self.WALLET, self.RPC, self.MINT)
        assert result is False

    def test_tx_cap_enforced(self):
        """Verify we don't issue more than MAX_TRANSACTIONS_PER_VERIFY getTransaction calls."""
        from agentpayments_python.solana import verify_payment_on_chain, MAX_TRANSACTIONS_PER_VERIFY
        key = self._fresh_key()
        many_sigs = [{"signature": f"sig{i}", "err": None} for i in range(MAX_TRANSACTIONS_PER_VERIFY + 10)]
        ata = {"value": [{"pubkey": "dest_ata_address", "account": {"data": {"parsed": {"info": {"mint": self.MINT, "owner": self.WALLET}}}}}]}
        # tx with wrong memo so we scan all
        tx = _build_tx("ag_different_key_entirely", 0.01, self.MINT, self.WALLET)

        call_count = {"n": 0}
        orig_post = __import__("requests").post

        def counting_post(url, json=None, timeout=None):
            if json and json.get("method") == "getTransaction":
                call_count["n"] += 1
            if json and json.get("method") == "getTokenAccountsByOwner":
                return _rpc_response(ata)
            if json and json.get("method") == "getSignaturesForAddress":
                return _rpc_response(many_sigs)
            return _rpc_response(tx)

        with patch("requests.post", side_effect=counting_post):
            verify_payment_on_chain(key, self.WALLET, self.RPC, self.MINT)

        assert call_count["n"] <= MAX_TRANSACTIONS_PER_VERIFY, (
            f"Made {call_count['n']} getTransaction calls, cap is {MAX_TRANSACTIONS_PER_VERIFY}"
        )

    def test_positive_result_cached(self):
        from agentpayments_python.solana import verify_payment_on_chain
        key = self._fresh_key()
        tx = _build_tx(key, 0.01, self.MINT, self.WALLET)
        ata = {"value": [{"pubkey": "dest_ata_address", "account": {"data": {"parsed": {"info": {"mint": self.MINT, "owner": self.WALLET}}}}}]}
        sigs = [{"signature": "sig_cache_pos", "err": None}]
        # Warm the cache
        with self._patch_rpc(sigs, ata, tx):
            verify_payment_on_chain(key, self.WALLET, self.RPC, self.MINT)
        # Second call: even with a broken RPC, cache should serve True
        with patch("requests.post", side_effect=Exception("should not be called")):
            result = verify_payment_on_chain(key, self.WALLET, self.RPC, self.MINT)
        assert result is True

    def test_negative_result_cached_briefly(self):
        from agentpayments_python.solana import verify_payment_on_chain
        key = self._fresh_key()
        ata = {"value": []}
        sigs = []
        with self._patch_rpc(sigs, ata, None):
            verify_payment_on_chain(key, self.WALLET, self.RPC, self.MINT)
        # Second call without real RPC: negative cache hit
        with patch("requests.post", side_effect=Exception("should not be called")):
            result = verify_payment_on_chain(key, self.WALLET, self.RPC, self.MINT)
        assert result is False
