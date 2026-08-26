"""
x402 protocol compatibility helpers.

Builds x402-standard PaymentRequirements objects and the X-PAYMENT-REQUIRED
header value so that x402-aware AI agent clients can parse the payment
requirements from our 402 responses.

Spec: https://github.com/x402-foundation/x402/blob/main/specs/schemes/exact/scheme_exact_svm.md
"""
from __future__ import annotations

import base64
import json as _json
import math
from pathlib import Path as _Path

_constants = _json.loads((_Path(__file__).resolve().parent / "constants.json").read_text())

USDC_DECIMALS: int = _constants["USDC_DECIMALS"]
X402_VERSION: int = _constants["X402_VERSION"]
SOLANA_CHAIN_ID_MAINNET: str = _constants["SOLANA_CHAIN_ID_MAINNET"]
SOLANA_CHAIN_ID_DEVNET: str = _constants["SOLANA_CHAIN_ID_DEVNET"]


def build_payment_requirements(
    *,
    wallet_address: str,
    mint: str,
    min_payment: float,
    debug: bool,
    agent_key: str = "",
    resource: str = "",
) -> dict:
    """
    Build an x402-standard PaymentRequirements dict for the Solana exact scheme.

    Args:
        wallet_address: Merchant wallet public key (payTo).
        mint:           USDC mint address.
        min_payment:    Human-readable amount (e.g. 0.01 for 0.01 USDC).
        debug:          True → use devnet chain ID.
        agent_key:      If set, included as extra.memo so x402 clients know
                        which key to reference in their transaction memo.
        resource:       URL path of the gated resource (optional).

    Returns:
        PaymentRequirements dict per the x402 SVM exact scheme spec.
    """
    chain_id = SOLANA_CHAIN_ID_DEVNET if debug else SOLANA_CHAIN_ID_MAINNET
    base_units = str(math.floor(min_payment * (10 ** USDC_DECIMALS) + 0.5))  # round half-up
    req: dict = {
        "scheme": "exact",
        "network": chain_id,
        "amount": base_units,
        "asset": mint,
        "payTo": wallet_address,
        "maxTimeoutSeconds": 300,
        "extra": {
            "name": "USDC",
            "decimals": USDC_DECIMALS,
            **({"memo": agent_key} if agent_key else {}),
        },
    }
    if resource:
        req["resource"] = resource
    return req


def build_payment_object(
    *,
    network: str,
    min_payment: float,
    wallet_address: str,
    memo: str,
    fee_info: dict | None = None,
    instructions: str = "",
) -> dict:
    """
    Build the custom `payment` dict for a 402 body — NOT part of the x402 spec
    (that's build_payment_requirements above, which stays vendor-leg-only). When
    fee_info is set (hosted-platform mode with an on-chain fee configured), adds
    a platform_fee field describing the second required transfer. Deliberately
    not added as a second x402 accepts[] entry — that would read to a
    spec-compliant client as an alternative payment method, not an additional
    requirement.

    fee_info: {"wallet": str, "rate_pct": float} or None.
    """
    payment: dict = {
        "chain": "solana",
        "network": network,
        "token": "USDC",
        "amount": str(min_payment),
        "wallet_address": wallet_address,
        "memo": memo,
    }
    if fee_info:
        fee_amount_micro = round(round(min_payment * 1_000_000) * fee_info["rate_pct"] / 100)
        payment["platform_fee"] = {
            "wallet_address": fee_info["wallet"],
            "amount": str(fee_amount_micro / 1_000_000),
            "token": "USDC",
            "rate_pct": fee_info["rate_pct"],
            "note": "Must be a second USDC transfer inside the SAME Solana transaction as the payment above, or access will be denied.",
        }
    if instructions:
        payment["instructions"] = instructions
    return payment


def payment_required_header(payment_requirements: dict) -> str:
    """
    Return the value for the X-PAYMENT-REQUIRED response header.
    The spec requires the PaymentRequirements to be base64-encoded JSON.
    """
    return base64.b64encode(_json.dumps(payment_requirements).encode()).decode()


def enrich_402_body(body: dict, payment_requirements: dict) -> dict:
    """
    Prepend x402Version and accepts[] to a 402 response body dict,
    keeping all existing fields for backward compatibility.
    """
    return {
        "x402Version": X402_VERSION,
        "accepts": [payment_requirements],
        **body,
    }
