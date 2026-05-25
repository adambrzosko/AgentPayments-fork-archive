import asyncio
import hmac
import json
import time
from urllib.parse import urlencode

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from .challenge import challenge_html
from .cookies import COOKIE_MAX_AGE, COOKIE_NAME, is_valid_cookie_value, make_cookie
from .crypto import generate_agent_key, hmac_sign, is_valid_agent_key
from .detection import is_browser_from_headers, is_public_path
from .ratelimit import _challenge_limiter
from .solana import MIN_PAYMENT, RPC_DEVNET, RPC_MAINNET, USDC_MINT_DEVNET, USDC_MINT_MAINNET, is_valid_solana_address, verify_payment_on_chain

import json as _json
from pathlib import Path as _Path
_constants = _json.loads((_Path(__file__).resolve().parent.parent.parent / "constants.json").read_text())
MAX_NONCE_LENGTH = _constants["MAX_NONCE_LENGTH"]
MAX_RETURN_TO_LENGTH = _constants["MAX_RETURN_TO_LENGTH"]
MAX_FP_LENGTH = _constants["MAX_FP_LENGTH"]


class AgentPaymentsASGIMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, *, challenge_secret: str, home_wallet_address: str, debug: bool = True, solana_rpc_url: str = "", usdc_mint: str = ""):
        super().__init__(app)
        if challenge_secret == "default-secret-change-me":
            import logging
            logger = logging.getLogger("agentpayments")
            if debug:
                logger.warning("Using default CHALLENGE_SECRET. Set a strong secret before deploying to production.")
            else:
                raise RuntimeError("CHALLENGE_SECRET is set to the insecure default. Set a strong, unique secret for production.")
        if home_wallet_address and not is_valid_solana_address(home_wallet_address):
            raise ValueError(f"HOME_WALLET_ADDRESS '{home_wallet_address}' is not a valid Solana public key (expected 32-44 base58 characters).")
        self.challenge_secret = challenge_secret
        self.home_wallet_address = home_wallet_address
        self.debug = debug
        self.solana_rpc_url = solana_rpc_url or (RPC_DEVNET if debug else RPC_MAINNET)
        self.usdc_mint = usdc_mint or (USDC_MINT_DEVNET if debug else USDC_MINT_MAINNET)

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if is_public_path(path):
            return await call_next(request)

        if path == "/__challenge/verify" and request.method == "POST":
            return await call_next(request)

        if not is_browser_from_headers(dict(request.headers)):
            agent_key = request.headers.get("x-agent-key")
            network = "devnet" if self.debug else "mainnet-beta"
            if not agent_key:
                new_key = generate_agent_key(self.challenge_secret)
                return JSONResponse({
                    "error": "payment_required",
                    "message": "Access requires a paid API key. A key has been generated for you below. Send a USDC payment on Solana with this key as the memo to activate it, then retry your request with the X-Agent-Key header.",
                    "your_key": new_key,
                    "payment": {
                        "chain": "solana",
                        "network": network,
                        "token": "USDC",
                        "amount": str(MIN_PAYMENT),
                        "wallet_address": self.home_wallet_address,
                        "memo": new_key,
                        "instructions": f'Send {MIN_PAYMENT} USDC on Solana {network} to {self.home_wallet_address} with memo "{new_key}". Then include the header X-Agent-Key: {new_key} on all subsequent requests.',
                    },
                }, status_code=402)

            if not is_valid_agent_key(agent_key, self.challenge_secret):
                return JSONResponse({"error": "forbidden", "message": "Invalid API key."}, status_code=403)

            if not self.home_wallet_address:
                return JSONResponse({"error": "server_error", "message": "Payment verification unavailable."}, status_code=500)

            # verify_payment_on_chain is synchronous (uses requests). Run it in a
            # thread-pool executor so it doesn't block the async event loop.
            loop = asyncio.get_event_loop()
            paid = await loop.run_in_executor(
                None, verify_payment_on_chain, agent_key, self.home_wallet_address, self.solana_rpc_url, self.usdc_mint
            )
            if not paid:
                return JSONResponse({
                    "error": "payment_required",
                    "message": "Key is valid but payment has not been verified on-chain yet.",
                    "your_key": agent_key,
                    "payment": {"chain": "solana", "network": network, "token": "USDC", "amount": str(MIN_PAYMENT), "wallet_address": self.home_wallet_address, "memo": agent_key},
                }, status_code=402)

            return await call_next(request)

        cookie_val = request.cookies.get(COOKIE_NAME, "")
        if is_valid_cookie_value(cookie_val, self.challenge_secret):
            return await call_next(request)

        nonce_ts = str(int(time.time() * 1000))
        nonce = f"{nonce_ts}.{hmac_sign(f'nonce:{nonce_ts}', self.challenge_secret)}"
        return HTMLResponse(challenge_html(str(request.url.path), nonce), headers={"Cache-Control": "no-store"})


async def challenge_verify_endpoint(request: Request, challenge_secret: str):
    client_ip = (request.headers.get("x-forwarded-for", "").split(",")[0].strip()
                 or request.client.host if request.client else "unknown")
    if not _challenge_limiter.check(client_ip):
        return JSONResponse({"error": "rate_limited", "message": "Too many verification attempts. Please wait and try again."}, status_code=429)
    form = await request.form()
    nonce = str(form.get("nonce", ""))[:MAX_NONCE_LENGTH]
    return_to = str(form.get("return_to", "/"))[:MAX_RETURN_TO_LENGTH]
    fp = str(form.get("fp", ""))[:MAX_FP_LENGTH]

    i = nonce.find(".")
    if i == -1 or not fp or len(fp) < 10:
        return JSONResponse({"error": "forbidden", "message": "Challenge verification failed."}, status_code=403)

    nonce_ts = nonce[:i]
    nonce_sig = nonce[i + 1:]
    try:
        ts = int(nonce_ts)
    except ValueError:
        return JSONResponse({"error": "forbidden", "message": "Challenge verification failed."}, status_code=403)

    if int(time.time() * 1000) - ts > 300000:
        return JSONResponse({"error": "forbidden", "message": "Challenge expired."}, status_code=403)

    if not hmac.compare_digest(nonce_sig, hmac_sign(f"nonce:{nonce_ts}", challenge_secret)):
        return JSONResponse({"error": "forbidden", "message": "Invalid challenge."}, status_code=403)

    safe_path = return_to if return_to.startswith("/") else "/"
    resp = RedirectResponse(url=safe_path, status_code=302)
    resp.set_cookie(COOKIE_NAME, make_cookie(challenge_secret), max_age=COOKIE_MAX_AGE, path="/", httponly=True, secure=True, samesite="lax")
    return resp
