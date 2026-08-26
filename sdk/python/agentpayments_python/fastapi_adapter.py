import asyncio

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse

from .challenge import POW_DIFFICULTY, challenge_html, make_nonce, validate_challenge_submission
from .cookies import COOKIE_MAX_AGE, COOKIE_NAME, is_valid_cookie_value, make_cookie
from .crypto import generate_agent_key, is_valid_agent_key
from .detection import is_browser_from_headers, is_public_path
from .ratelimit import _challenge_limiter, _agent_key_limiter, _challenge_issue_limiter
from .crawler import is_verified_crawler
from .solana import MIN_PAYMENT, RPC_DEVNET, RPC_MAINNET, USDC_MINT_DEVNET, USDC_MINT_MAINNET, is_valid_solana_address, verify_payment_on_chain
from .x402 import build_payment_object, build_payment_requirements, enrich_402_body, payment_required_header
from .platform_client import HOSTED_KEY_PREFIX, PlatformClient, is_valid_hosted_key

import json as _json
from pathlib import Path as _Path
_constants = _json.loads((_Path(__file__).resolve().parent / "constants.json").read_text())
MAX_NONCE_LENGTH = _constants["MAX_NONCE_LENGTH"]
MAX_RETURN_TO_LENGTH = _constants["MAX_RETURN_TO_LENGTH"]
MAX_FP_LENGTH = _constants["MAX_FP_LENGTH"]
MAX_POW_LENGTH = _constants["MAX_POW_LENGTH"]


def _payment_required_response(body: dict, *, wallet_address: str, mint: str, min_payment: float, debug: bool, agent_key: str = "", resource: str = "") -> JSONResponse:
    """Return a Starlette JSONResponse (402) enriched with x402-standard fields and header."""
    pay_req = build_payment_requirements(wallet_address=wallet_address, mint=mint, min_payment=min_payment, debug=debug, agent_key=agent_key, resource=resource)
    return JSONResponse(
        content=enrich_402_body(body, pay_req),
        status_code=402,
        headers={"X-PAYMENT-REQUIRED": payment_required_header(pay_req)},
    )


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
    if forwarded:
        return forwarded
    return request.client.host if request.client else "unknown"


class AgentPaymentsASGIMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, *, challenge_secret: str, home_wallet_address: str, debug: bool = True, solana_rpc_url=None, usdc_mint: str = "", pow_difficulty: int = POW_DIFFICULTY, verify_crawlers: bool = True, grant_store=None, require_https: bool = None, api_key: str = None, platform_url: str = None):
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
        raw_rpc = solana_rpc_url or (RPC_DEVNET if debug else RPC_MAINNET)
        self.solana_rpc_url = raw_rpc if isinstance(raw_rpc, list) else [raw_rpc]
        self.usdc_mint = usdc_mint or (USDC_MINT_DEVNET if debug else USDC_MINT_MAINNET)
        self.pow_difficulty = pow_difficulty
        self.verify_crawlers = verify_crawlers
        self.grant_store = grant_store
        self.require_https = (not debug) if require_https is None else require_https
        self._platform_client = PlatformClient(api_key, platform_url) if api_key else None

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if is_public_path(path):
            return await call_next(request)

        if path == "/__challenge/verify" and request.method == "POST":
            return await call_next(request)

        # Reject plaintext HTTP in production.
        if self.require_https and request.url.scheme != "https":
            return JSONResponse({"error": "https_required", "message": "This service requires a secure HTTPS connection."}, status_code=400)

        # Verified search crawlers bypass the gate entirely.
        # is_verified_crawler is blocking I/O — run in executor to avoid blocking the event loop.
        if self.verify_crawlers:
            client_ip_early = _client_ip(request)
            ua = request.headers.get("user-agent", "")
            loop = asyncio.get_event_loop()
            if await loop.run_in_executor(None, is_verified_crawler, client_ip_early, ua):
                return await call_next(request)

        if not is_browser_from_headers(dict(request.headers)):
            agent_key = request.headers.get("x-agent-key")
            network = "devnet" if self.debug else "mainnet-beta"
            loop = asyncio.get_event_loop()

            # Resolve the on-chain platform fee requirement once (hosted-platform
            # mode only — always None for self-hosted vendors with no platform client).
            fee_info = None
            if self._platform_client:
                try:
                    fee_info = await loop.run_in_executor(None, self._platform_client.get_platform_fee_info)
                except Exception as exc:
                    import logging as _log
                    _log.getLogger("agentpayments").warning("Failed to fetch platform fee info, proceeding without fee enforcement: %s", exc)

            if not agent_key:
                if self._platform_client:
                    try:
                        new_key = await loop.run_in_executor(None, self._platform_client.issue_key)
                    except Exception as exc:
                        import logging as _log
                        _log.getLogger("agentpayments").warning("Platform key issuance failed, falling back to local key: %s", exc)
                        new_key = generate_agent_key(self.challenge_secret)
                else:
                    new_key = generate_agent_key(self.challenge_secret)
                if fee_info:
                    no_key_instructions = (
                        f'Send {MIN_PAYMENT} USDC on Solana {network} to {self.home_wallet_address} with memo "{new_key}", '
                        f'AND in the SAME transaction send the platform fee (see platform_fee below) to {fee_info["wallet"]}. '
                        f'Then include the header X-Agent-Key: {new_key} on all subsequent requests.'
                    )
                else:
                    no_key_instructions = f'Send {MIN_PAYMENT} USDC on Solana {network} to {self.home_wallet_address} with memo "{new_key}". Then include the header X-Agent-Key: {new_key} on all subsequent requests.'
                return _payment_required_response(
                    {
                        "error": "payment_required",
                        "message": "Access requires a paid API key. A key has been generated for you below. Send a USDC payment on Solana with this key as the memo to activate it, then retry your request with the X-Agent-Key header.",
                        "your_key": new_key,
                        "payment": build_payment_object(network=network, min_payment=MIN_PAYMENT, wallet_address=self.home_wallet_address, memo=new_key, fee_info=fee_info, instructions=no_key_instructions),
                    },
                    wallet_address=self.home_wallet_address, mint=self.usdc_mint, min_payment=MIN_PAYMENT,
                    debug=self.debug, agent_key=new_key, resource=path,
                )

            if agent_key.startswith(HOSTED_KEY_PREFIX):
                if not self._platform_client:
                    return JSONResponse({"error": "forbidden", "message": "Platform-issued keys (agp_) require api_key to be configured."}, status_code=403)
                try:
                    ver_sec = await loop.run_in_executor(None, lambda: self._platform_client.verification_secret)
                except Exception as exc:
                    import logging as _log
                    _log.getLogger("agentpayments").error("Failed to fetch verificationSecret: %s", exc)
                    return JSONResponse({"error": "service_unavailable", "message": "Key verification temporarily unavailable."}, status_code=503)
                if not is_valid_hosted_key(agent_key, ver_sec):
                    return JSONResponse({"error": "forbidden", "message": "Invalid API key."}, status_code=403)
            elif not is_valid_agent_key(agent_key, self.challenge_secret):
                return JSONResponse({"error": "forbidden", "message": "Invalid API key."}, status_code=403)

            if not _agent_key_limiter.check(_client_ip(request)):
                return JSONResponse({"error": "rate_limited", "message": "Too many payment verification requests. Please wait and try again."}, status_code=429)

            if not self.home_wallet_address:
                return JSONResponse({"error": "server_error", "message": "Payment verification unavailable."}, status_code=500)

            # Durable grant check — bypasses RPC scan entirely for known-paid keys.
            if self.grant_store and self.grant_store.has(agent_key):
                return await call_next(request)

            # verify_payment_on_chain is synchronous (uses requests). Run it in a
            # thread-pool executor so it doesn't block the async event loop.
            paid = await loop.run_in_executor(
                None, lambda: verify_payment_on_chain(agent_key, self.home_wallet_address, self.solana_rpc_url, self.usdc_mint, fee_info=fee_info)
            )
            if paid and self.grant_store:
                self.grant_store.add(agent_key)
            if not paid:
                return _payment_required_response(
                    {
                        "error": "payment_required",
                        "message": "Key is valid but payment has not been verified on-chain yet.",
                        "your_key": agent_key,
                        "payment": build_payment_object(network=network, min_payment=MIN_PAYMENT, wallet_address=self.home_wallet_address, memo=agent_key, fee_info=fee_info),
                    },
                    wallet_address=self.home_wallet_address, mint=self.usdc_mint, min_payment=MIN_PAYMENT,
                    debug=self.debug, agent_key=agent_key, resource=path,
                )

            return await call_next(request)

        client_ip = _client_ip(request)
        cookie_val = request.cookies.get(COOKIE_NAME, "")
        if is_valid_cookie_value(cookie_val, self.challenge_secret, client_ip):
            return await call_next(request)

        if not _challenge_issue_limiter.check(client_ip):
            return JSONResponse({"error": "rate_limited", "message": "Too many requests. Please try again later."}, status_code=429)

        nonce = make_nonce(self.challenge_secret, client_ip)
        return HTMLResponse(challenge_html(str(request.url.path), nonce, self.pow_difficulty), headers={
            "Cache-Control": "no-store",
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; form-action 'self'",
        })


async def challenge_verify_endpoint(request: Request, challenge_secret: str, pow_difficulty: int = POW_DIFFICULTY):
    client_ip = _client_ip(request)
    if not _challenge_limiter.check(client_ip):
        return JSONResponse({"error": "rate_limited", "message": "Too many verification attempts. Please wait and try again."}, status_code=429)
    form = await request.form()
    nonce = str(form.get("nonce", ""))[:MAX_NONCE_LENGTH]
    return_to = str(form.get("return_to", "/"))[:MAX_RETURN_TO_LENGTH]
    fp = str(form.get("fp", ""))[:MAX_FP_LENGTH]
    pow_value = str(form.get("pow", ""))[:MAX_POW_LENGTH]

    if not validate_challenge_submission(nonce, fp, pow_value, challenge_secret, client_ip, pow_difficulty):
        return JSONResponse({"error": "forbidden", "message": "Challenge verification failed."}, status_code=403)

    safe_path = return_to if (return_to.startswith("/") and not return_to.startswith("//")) else "/"
    resp = RedirectResponse(url=safe_path, status_code=302)
    resp.set_cookie(COOKIE_NAME, make_cookie(challenge_secret, client_ip), max_age=COOKIE_MAX_AGE, path="/", httponly=True, secure=True, samesite="lax")
    return resp
