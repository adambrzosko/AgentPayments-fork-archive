import logging

from django.conf import settings
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

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

logger = logging.getLogger("agentpayments")


def _payment_required_response(body: dict, *, wallet_address: str, mint: str, min_payment: float, debug: bool, agent_key: str = "", resource: str = "") -> JsonResponse:
    """Return a 402 JsonResponse enriched with x402-standard fields and header."""
    pay_req = build_payment_requirements(wallet_address=wallet_address, mint=mint, min_payment=min_payment, debug=debug, agent_key=agent_key, resource=resource)
    resp = JsonResponse(enrich_402_body(body, pay_req), status=402, json_dumps_params={"indent": 2})
    resp["X-PAYMENT-REQUIRED"] = payment_required_header(pay_req)
    return resp


def _client_ip(request):
    return request.META.get("HTTP_X_FORWARDED_FOR", "").split(",")[0].strip() or request.META.get("REMOTE_ADDR", "unknown")


class GateMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

        # Resolve and validate config once at startup, not per-request.
        secret = settings.CHALLENGE_SECRET
        if secret == "default-secret-change-me":
            if settings.DEBUG:
                logger.warning("Using default CHALLENGE_SECRET. Set a strong secret before deploying to production.")
            else:
                raise RuntimeError("CHALLENGE_SECRET is set to the insecure default. Set a strong, unique secret for production.")
        wallet_address = getattr(settings, "HOME_WALLET_ADDRESS", None)
        if wallet_address and not is_valid_solana_address(wallet_address):
            raise ValueError(f"HOME_WALLET_ADDRESS '{wallet_address}' is not a valid Solana public key (expected 32-44 base58 characters).")
        debug = settings.DEBUG
        raw_rpc = getattr(settings, "SOLANA_RPC_URL", None) or (RPC_DEVNET if debug else RPC_MAINNET)
        rpc_url = raw_rpc if isinstance(raw_rpc, list) else [raw_rpc]
        self.require_https = getattr(settings, "AGENTPAYMENTS_REQUIRE_HTTPS", not debug)
        # Hosted key-issuance mode. Set AGENTPAYMENTS_API_KEY in settings.py.
        # When set, keys are issued via the platform (metered) and carry the agp_ prefix.
        api_key = getattr(settings, "AGENTPAYMENTS_API_KEY", None)
        platform_url = getattr(settings, "AGENTPAYMENTS_PLATFORM_URL", None)
        self._platform_client = PlatformClient(api_key, platform_url) if api_key else None
        usdc_mint = getattr(settings, "USDC_MINT", None) or (USDC_MINT_DEVNET if debug else USDC_MINT_MAINNET)

        self.secret = secret
        self.wallet_address = wallet_address
        self.debug = debug
        self.rpc_url = rpc_url
        self.usdc_mint = usdc_mint
        self.network = "devnet" if debug else "mainnet-beta"
        self.pow_difficulty = getattr(settings, "POW_DIFFICULTY", POW_DIFFICULTY)
        self.verify_crawlers = getattr(settings, "AGENTPAYMENTS_VERIFY_CRAWLERS", True)
        # Optional grant store for durable paid-key persistence. Set
        # AGENTPAYMENTS_GRANT_STORE to a GrantStore instance in settings.py.
        self.grant_store = getattr(settings, "AGENTPAYMENTS_GRANT_STORE", None)

    def __call__(self, request):
        secret = self.secret
        wallet_address = self.wallet_address
        network = self.network

        pathname = request.path
        if is_public_path(pathname):
            return self.get_response(request)

        if pathname == "/__challenge/verify" and request.method == "POST":
            return self.get_response(request)

        # Reject plaintext HTTP in production. Behind a reverse proxy, Django
        # uses X-Forwarded-Proto via SECURE_PROXY_SSL_HEADER in settings.
        if self.require_https and not request.is_secure():
            return JsonResponse({"error": "https_required", "message": "This service requires a secure HTTPS connection."}, status=400)

        # Verified search crawlers bypass the gate entirely.
        if self.verify_crawlers:
            client_ip_early = _client_ip(request)
            ua = request.META.get("HTTP_USER_AGENT", "")
            if is_verified_crawler(client_ip_early, ua):
                return self.get_response(request)

        headers = {
            "sec-fetch-mode": request.META.get("HTTP_SEC_FETCH_MODE"),
            "sec-fetch-dest": request.META.get("HTTP_SEC_FETCH_DEST"),
        }
        if not is_browser_from_headers(headers):
            agent_key = request.META.get("HTTP_X_AGENT_KEY")

            # Resolve the on-chain platform fee requirement once (hosted-platform
            # mode only — always None for self-hosted vendors with no platform client).
            fee_info = None
            if self._platform_client:
                try:
                    fee_info = self._platform_client.get_platform_fee_info()
                except Exception as exc:
                    logger.warning("Failed to fetch platform fee info, proceeding without fee enforcement: %s", exc)

            if not agent_key:
                # Hosted mode: issue metered platform key (agp_).
                # Local mode: generate self-signed key (ag_).
                if self._platform_client:
                    try:
                        new_key = self._platform_client.issue_key()
                    except Exception as exc:
                        logger.warning("Platform key issuance failed, falling back to local key: %s", exc)
                        new_key = generate_agent_key(secret)
                else:
                    new_key = generate_agent_key(secret)
                if fee_info:
                    no_key_instructions = (
                        f'Send {MIN_PAYMENT} USDC on Solana {network} to {wallet_address} with memo "{new_key}", '
                        f'AND in the SAME transaction send the platform fee (see platform_fee below) to {fee_info["wallet"]}. '
                        f'Then include the header X-Agent-Key: {new_key} on all subsequent requests.'
                    )
                else:
                    no_key_instructions = f'Send {MIN_PAYMENT} USDC on Solana {network} to {wallet_address} with memo "{new_key}". Then include the header X-Agent-Key: {new_key} on all subsequent requests.'
                return _payment_required_response(
                    {
                        "error": "payment_required",
                        "message": "Access requires a paid API key. A key has been generated for you below. Send a USDC payment on Solana with this key as the memo to activate it, then retry your request with the X-Agent-Key header.",
                        "your_key": new_key,
                        "payment": build_payment_object(network=network, min_payment=MIN_PAYMENT, wallet_address=wallet_address, memo=new_key, fee_info=fee_info, instructions=no_key_instructions),
                    },
                    wallet_address=wallet_address, mint=self.usdc_mint, min_payment=MIN_PAYMENT,
                    debug=self.debug, agent_key=new_key, resource=pathname,
                )

            # Validate the key. Platform-issued (agp_) use verificationSecret;
            # local keys (ag_) use challengeSecret.
            if agent_key.startswith(HOSTED_KEY_PREFIX):
                if not self._platform_client:
                    return JsonResponse({"error": "forbidden", "message": "Platform-issued keys (agp_) require AGENTPAYMENTS_API_KEY to be configured."}, status=403)
                try:
                    ver_sec = self._platform_client.verification_secret
                except Exception as exc:
                    logger.error("Failed to fetch verificationSecret from platform: %s", exc)
                    return JsonResponse({"error": "service_unavailable", "message": "Key verification temporarily unavailable."}, status=503)
                if not is_valid_hosted_key(agent_key, ver_sec):
                    return JsonResponse({"error": "forbidden", "message": "Invalid API key."}, status=403)
            elif not is_valid_agent_key(agent_key, secret):
                return JsonResponse({"error": "forbidden", "message": "Invalid API key. Keys must be issued by this server."}, status=403)

            if not _agent_key_limiter.check(_client_ip(request)):
                return JsonResponse({"error": "rate_limited", "message": "Too many payment verification requests. Please wait and try again."}, status=429)

            if not wallet_address:
                return JsonResponse({"error": "server_error", "message": "Payment verification unavailable."}, status=500)

            # Durable grant check — bypasses RPC scan entirely for known-paid keys.
            if self.grant_store and self.grant_store.has(agent_key):
                return self.get_response(request)

            paid = verify_payment_on_chain(agent_key, wallet_address, self.rpc_url, self.usdc_mint, fee_info=fee_info)
            if paid and self.grant_store:
                self.grant_store.add(agent_key)
            if not paid:
                return _payment_required_response(
                    {
                        "error": "payment_required",
                        "message": "Key is valid but payment has not been verified on-chain yet.",
                        "your_key": agent_key,
                        "payment": build_payment_object(network=network, min_payment=MIN_PAYMENT, wallet_address=wallet_address, memo=agent_key, fee_info=fee_info),
                    },
                    wallet_address=wallet_address, mint=self.usdc_mint, min_payment=MIN_PAYMENT,
                    debug=self.debug, agent_key=agent_key, resource=pathname,
                )

            return self.get_response(request)

        client_ip = _client_ip(request)
        cookie_val = request.COOKIES.get(COOKIE_NAME, "")
        if is_valid_cookie_value(cookie_val, secret, client_ip):
            return self.get_response(request)

        # Rate-limit challenge page issuance to prevent unlimited nonce harvesting.
        if not _challenge_issue_limiter.check(client_ip):
            return JsonResponse({"error": "rate_limited", "message": "Too many requests. Please try again later."}, status=429)

        nonce = make_nonce(secret, client_ip)
        resp = HttpResponse(challenge_html(request.get_full_path(), nonce, self.pow_difficulty), content_type="text/html")
        resp["Cache-Control"] = "no-store"
        resp["X-Frame-Options"] = "DENY"
        resp["Content-Security-Policy"] = "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; form-action 'self'"
        return resp


@csrf_exempt
@require_POST
def challenge_verify(request):
    client_ip = _client_ip(request)
    if not _challenge_limiter.check(client_ip):
        return JsonResponse({"error": "rate_limited", "message": "Too many verification attempts. Please wait and try again."}, status=429)
    secret = settings.CHALLENGE_SECRET
    nonce = request.POST.get("nonce", "")[:MAX_NONCE_LENGTH]
    return_to = request.POST.get("return_to", "/")[:MAX_RETURN_TO_LENGTH]
    fp = request.POST.get("fp", "")[:MAX_FP_LENGTH]
    pow_value = request.POST.get("pow", "")[:MAX_POW_LENGTH]

    difficulty = getattr(settings, "POW_DIFFICULTY", POW_DIFFICULTY)
    if not validate_challenge_submission(nonce, fp, pow_value, secret, client_ip, difficulty):
        return JsonResponse({"error": "forbidden", "message": "Challenge verification failed."}, status=403)

    safe_path = return_to if (return_to.startswith("/") and not return_to.startswith("//")) else "/"
    response = HttpResponseRedirect(safe_path)
    secure_cookie = request.is_secure()
    response.set_cookie(
        COOKIE_NAME,
        make_cookie(secret, client_ip),
        max_age=COOKIE_MAX_AGE,
        path="/",
        httponly=True,
        secure=secure_cookie,
        samesite="Lax",
    )
    return response
