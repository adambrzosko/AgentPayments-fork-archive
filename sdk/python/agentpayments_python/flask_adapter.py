from flask import jsonify, make_response, redirect, request

from .challenge import POW_DIFFICULTY, challenge_html, make_nonce, validate_challenge_submission
from .cookies import COOKIE_MAX_AGE, COOKIE_NAME, is_valid_cookie_value, make_cookie
from .crypto import generate_agent_key, is_valid_agent_key
from .detection import is_browser_from_headers, is_public_path
from .ratelimit import _challenge_limiter, _agent_key_limiter
from .crawler import is_verified_crawler
from .solana import MIN_PAYMENT, RPC_DEVNET, RPC_MAINNET, USDC_MINT_DEVNET, USDC_MINT_MAINNET, is_valid_solana_address, verify_payment_on_chain

import json as _json
from pathlib import Path as _Path
_constants = _json.loads((_Path(__file__).resolve().parent.parent.parent / "constants.json").read_text())
MAX_NONCE_LENGTH = _constants["MAX_NONCE_LENGTH"]
MAX_RETURN_TO_LENGTH = _constants["MAX_RETURN_TO_LENGTH"]
MAX_FP_LENGTH = _constants["MAX_FP_LENGTH"]
MAX_POW_LENGTH = _constants["MAX_POW_LENGTH"]


def _client_ip() -> str:
    return request.headers.get("X-Forwarded-For", "").split(",")[0].strip() or request.remote_addr or "unknown"


def register_agentpayments(app, *, challenge_secret: str, home_wallet_address: str, debug: bool = True, solana_rpc_url: str = "", usdc_mint: str = "", pow_difficulty: int = POW_DIFFICULTY, verify_crawlers: bool = True, grant_store=None):
    if challenge_secret == "default-secret-change-me":
        import logging
        logger = logging.getLogger("agentpayments")
        if debug:
            logger.warning("Using default CHALLENGE_SECRET. Set a strong secret before deploying to production.")
        else:
            raise RuntimeError("CHALLENGE_SECRET is set to the insecure default. Set a strong, unique secret for production.")
    if home_wallet_address and not is_valid_solana_address(home_wallet_address):
        raise ValueError(f"HOME_WALLET_ADDRESS '{home_wallet_address}' is not a valid Solana public key (expected 32-44 base58 characters).")
    rpc_url = solana_rpc_url or (RPC_DEVNET if debug else RPC_MAINNET)
    mint = usdc_mint or (USDC_MINT_DEVNET if debug else USDC_MINT_MAINNET)

    @app.before_request
    def _gate():
        path = request.path
        if is_public_path(path):
            return None
        if path == "/__challenge/verify" and request.method == "POST":
            return None

        # Verified search crawlers bypass the gate entirely.
        if verify_crawlers:
            ua = request.headers.get("User-Agent", "")
            if is_verified_crawler(_client_ip(), ua):
                return None

        if not is_browser_from_headers(request.headers):
            key = request.headers.get("X-Agent-Key")
            network = "devnet" if debug else "mainnet-beta"
            if not key:
                new_key = generate_agent_key(challenge_secret)
                return jsonify({
                    "error": "payment_required",
                    "message": "Access requires a paid API key. A key has been generated for you below. Send a USDC payment on Solana with this key as the memo to activate it, then retry your request with the X-Agent-Key header.",
                    "your_key": new_key,
                    "payment": {
                        "chain": "solana",
                        "network": network,
                        "token": "USDC",
                        "amount": str(MIN_PAYMENT),
                        "wallet_address": home_wallet_address,
                        "memo": new_key,
                        "instructions": f'Send {MIN_PAYMENT} USDC on Solana {network} to {home_wallet_address} with memo "{new_key}". Then include the header X-Agent-Key: {new_key} on all subsequent requests.',
                    },
                }), 402
            if not is_valid_agent_key(key, challenge_secret):
                return jsonify({"error": "forbidden", "message": "Invalid API key."}), 403
            if not _agent_key_limiter.check(_client_ip()):
                return jsonify({"error": "rate_limited", "message": "Too many payment verification requests. Please wait and try again."}), 429
            if not home_wallet_address:
                return jsonify({"error": "server_error", "message": "Payment verification unavailable."}), 500
            if grant_store and grant_store.has(key):
                return None
            paid = verify_payment_on_chain(key, home_wallet_address, rpc_url, mint)
            if paid and grant_store:
                grant_store.add(key)
            if not paid:
                return jsonify({
                    "error": "payment_required",
                    "message": "Key is valid but payment has not been verified on-chain yet.",
                    "your_key": key,
                    "payment": {"chain": "solana", "network": network, "token": "USDC", "amount": str(MIN_PAYMENT), "wallet_address": home_wallet_address, "memo": key},
                }), 402
            return None

        client_ip = _client_ip()
        cookie_val = request.cookies.get(COOKIE_NAME, "")
        if is_valid_cookie_value(cookie_val, challenge_secret, client_ip):
            return None

        nonce = make_nonce(challenge_secret, client_ip)
        return make_response(challenge_html(request.full_path or request.path, nonce, pow_difficulty), 200, {"Content-Type": "text/html", "Cache-Control": "no-store"})

    @app.post("/__challenge/verify")
    def _verify():
        client_ip = _client_ip()
        if not _challenge_limiter.check(client_ip):
            return jsonify({"error": "rate_limited", "message": "Too many verification attempts. Please wait and try again."}), 429
        nonce = request.form.get("nonce", "")[:MAX_NONCE_LENGTH]
        return_to = request.form.get("return_to", "/")[:MAX_RETURN_TO_LENGTH]
        fp = request.form.get("fp", "")[:MAX_FP_LENGTH]
        pow_value = request.form.get("pow", "")[:MAX_POW_LENGTH]
        if not validate_challenge_submission(nonce, fp, pow_value, challenge_secret, client_ip, pow_difficulty):
            return jsonify({"error": "forbidden", "message": "Challenge verification failed."}), 403
        safe = return_to if return_to.startswith("/") else "/"
        resp = redirect(safe, code=302)
        resp.set_cookie(COOKIE_NAME, make_cookie(challenge_secret, client_ip), max_age=COOKIE_MAX_AGE, path='/', httponly=True, secure=True, samesite='Lax')
        return resp
