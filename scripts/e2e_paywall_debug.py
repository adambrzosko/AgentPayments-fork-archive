#!/usr/bin/env python3
"""
End-to-end debugger for AgentPayments paywall flows.

Usage:
  python scripts/e2e_paywall_debug.py --url https://nextjsdeployment-five.vercel.app
  python scripts/e2e_paywall_debug.py --url https://nextjsdeployment-five.vercel.app \
      --wallet-tool-key "$WALLET_TOOL_KEY"

Optional:
  --wallet-hub-url https://llmwallethub.vercel.app
  --poll-seconds 60

What it does:
1) Hits paywalled URL without X-Agent-Key and parses 402 payload.
2) Retries with X-Agent-Key before payment (expected: 402).
3) If wallet tool key provided, submits payment to wallet hub with exact memo.
4) Polls target URL with X-Agent-Key until access is granted (200) or timeout.

This script is intentionally verbose for diagnosis.
"""

from __future__ import annotations

import argparse
import json
import time
from typing import Any

import requests


def short(s: str, n: int = 28) -> str:
    return s if len(s) <= n else s[:n] + "..."


def get_json(url: str, headers: dict[str, str] | None = None) -> tuple[int, dict[str, Any] | None, str]:
    r = requests.get(url, headers=headers or {}, timeout=30)
    body = r.text
    try:
        data = r.json()
    except Exception:
        data = None
    return r.status_code, data, body


def submit_payment(wallet_hub_url: str, tool_key: str, recipient: str, amount: float, memo: str, resource_url: str, network: str | None) -> dict[str, Any]:
    endpoint = wallet_hub_url.rstrip("/") + "/api/tool/pay"
    payload = {
        "recipient": recipient,
        "amountUsdc": amount,
        "token": "USDC",
        "memo": memo,
        "reason": "AgentPayments paywall verification test",
        "resourceUrl": resource_url,
    }
    if network:
        payload["network"] = network

    resp = requests.post(
        endpoint,
        headers={
            "Content-Type": "application/json",
            "x-wallet-tool-key": tool_key,
        },
        data=json.dumps(payload),
        timeout=60,
    )
    out = {"status": resp.status_code, "text": resp.text}
    try:
        out["json"] = resp.json()
    except Exception:
        out["json"] = None
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True, help="Paywalled URL to test")
    ap.add_argument("--wallet-tool-key", default="", help="Optional llm_wallet_hub tool key (ak_...) for live payment")
    ap.add_argument("--wallet-hub-url", default="https://llmwallethub.vercel.app", help="Wallet hub base URL")
    ap.add_argument("--poll-seconds", type=int, default=60)
    args = ap.parse_args()

    print("=" * 72)
    print("STEP 1: Initial request (no X-Agent-Key)")
    print("=" * 72)
    status, data, body = get_json(args.url)
    print(f"HTTP {status}")

    if status != 402 or not data:
        print("Expected 402 JSON challenge but got something else.")
        print(body[:1200])
        return 2

    key = str(data.get("your_key") or "")
    payment = data.get("payment") or {}
    memo = str(payment.get("memo") or "")
    recipient = str(payment.get("wallet_address") or "")
    network = str(payment.get("network") or "")
    amount_str = str(payment.get("amount") or "0")

    try:
        amount = float(amount_str)
    except Exception:
        amount = 0.0

    print(f"key:      {key}")
    print(f"memo:     {memo}")
    print(f"recipient:{recipient}")
    print(f"network:  {network}")
    print(f"amount:   {amount}")

    if not key or not memo or not recipient or amount <= 0:
        print("Challenge payload missing key fields; cannot continue.")
        return 3

    print("\n" + "=" * 72)
    print("STEP 2: Retry with key BEFORE payment (should still be 402)")
    print("=" * 72)
    status2, data2, body2 = get_json(args.url, headers={"X-Agent-Key": key})
    print(f"HTTP {status2}")
    if data2:
        print(json.dumps(data2, indent=2)[:1200])
    else:
        print(body2[:600])

    if not args.wallet_tool_key:
        print("\nNo --wallet-tool-key supplied, stopping after pre-payment diagnostics.")
        return 0

    print("\n" + "=" * 72)
    print("STEP 3: Submit payment to wallet hub")
    print("=" * 72)
    pay = submit_payment(
        wallet_hub_url=args.wallet_hub_url,
        tool_key=args.wallet_tool_key,
        recipient=recipient,
        amount=amount,
        memo=memo,
        resource_url=args.url,
        network=network or None,
    )
    print(f"wallet hub HTTP {pay['status']}")
    if pay.get("json") is not None:
        j = pay["json"]
        sig = (j.get("signature") if isinstance(j, dict) else None) or ""
        print(f"signature: {short(sig, 64)}")
        print(json.dumps(j, indent=2)[:1800])
    else:
        print(pay.get("text", "")[:1200])

    print("\n" + "=" * 72)
    print("STEP 4: Poll protected URL with X-Agent-Key")
    print("=" * 72)
    deadline = time.time() + max(5, args.poll_seconds)
    attempt = 0
    while time.time() < deadline:
        attempt += 1
        st, dt, bd = get_json(args.url, headers={"X-Agent-Key": key})
        print(f"attempt {attempt:02d}: HTTP {st}")
        if st == 200:
            print("SUCCESS: access granted.")
            print((bd or "")[:500])
            return 0
        if dt:
            pm = (dt.get("payment") or {}) if isinstance(dt, dict) else {}
            print(f"  message: {dt.get('message')}")
            if pm:
                print(f"  expected memo now: {pm.get('memo')}")
                print(f"  expected network:  {pm.get('network')}")
        else:
            print((bd or "")[:300])
        time.sleep(3)

    print("TIMEOUT: payment still not verified after polling window.")
    print("Likely causes: network mismatch (devnet/mainnet), wrong recipient, memo mismatch, or verifier RPC issues.")
    return 4


if __name__ == "__main__":
    raise SystemExit(main())
