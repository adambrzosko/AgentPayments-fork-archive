import logging

import requests

logger = logging.getLogger(__name__)

USDC_MINT_DEVNET = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"
USDC_MINT_MAINNET = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
RPC_DEVNET = "https://api.devnet.solana.com"
RPC_MAINNET = "https://api.mainnet-beta.solana.com"
MEMO_PROGRAM = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
MIN_PAYMENT = 0.01


def _rpc_call(rpc_url: str, method: str, params: list) -> dict:
    resp = requests.post(
        rpc_url,
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()


def verify_payment_on_chain(
    agent_key: str,
    wallet_address: str,
    rpc_url: str,
    usdc_mint: str,
) -> bool:
    """
    Scan recent transactions to wallet_address (and its token accounts)
    for a USDC payment with agent_key as the memo.
    """
    try:
        # Find token accounts (ATAs) for this wallet
        ata_data = _rpc_call(rpc_url, "getTokenAccountsByOwner", [
            wallet_address,
            {"mint": usdc_mint},
            {"encoding": "jsonParsed"},
        ])
        token_accounts = [
            a["pubkey"]
            for a in ata_data.get("result", {}).get("value", [])
        ]
        # Only transfers landing in one of the vendor's USDC token accounts count as
        # payment. Token accounts are mint-bound, so membership also guarantees the
        # token is USDC for plain `transfer` instructions (which carry no mint field).
        vendor_usdc_accounts = set(token_accounts)
        if not vendor_usdc_accounts:
            return False  # vendor has no USDC account yet — no payment possible

        addresses_to_scan = [wallet_address] + token_accounts

        # Collect unique signatures across all addresses
        seen = set()
        all_signatures = []

        for addr in addresses_to_scan:
            sigs_data = _rpc_call(rpc_url, "getSignaturesForAddress", [
                addr, {"limit": 50},
            ])
            for sig in sigs_data.get("result", []):
                if sig["signature"] not in seen:
                    seen.add(sig["signature"])
                    all_signatures.append(sig)

        for sig_info in all_signatures:
            if sig_info.get("err"):
                continue

            tx_data = _rpc_call(rpc_url, "getTransaction", [
                sig_info["signature"],
                {"encoding": "jsonParsed", "maxSupportedTransactionVersion": 0},
            ])
            tx = tx_data.get("result")
            if not tx:
                continue

            instructions = (
                tx.get("transaction", {}).get("message", {}).get("instructions", [])
            )
            inner_instructions = tx.get("meta", {}).get("innerInstructions", [])

            # Flatten all instructions (top-level + inner)
            all_ix = list(instructions)
            for group in inner_instructions:
                all_ix.extend(group.get("instructions", []))

            has_memo = False
            has_payment = False

            for ix in all_ix:
                # Check for memo matching the agent key
                program = ix.get("program", "")
                program_id = ix.get("programId", "")
                if program == "spl-memo" or program_id == MEMO_PROGRAM:
                    parsed = ix.get("parsed", "")
                    memo_text = parsed if isinstance(parsed, str) else str(parsed)
                    if agent_key in memo_text:
                        has_memo = True

                # Check for USDC transfer to our wallet
                if program == "spl-token":
                    parsed = ix.get("parsed", {})
                    tx_type = parsed.get("type", "")
                    if tx_type in ("transfer", "transferChecked"):
                        info = parsed.get("info", {})

                        # Payment must be delivered to one of the vendor's USDC token accounts.
                        if info.get("destination") not in vendor_usdc_accounts:
                            continue

                        # For transferChecked, verify it's USDC
                        if tx_type == "transferChecked" and info.get("mint") != usdc_mint:
                            continue

                        # Parse amount
                        token_amount = info.get("tokenAmount", {})
                        ui_amount = token_amount.get("uiAmount")
                        if ui_amount is None:
                            raw = info.get("amount", "0")
                            ui_amount = int(raw) / 1e6

                        if ui_amount >= MIN_PAYMENT:
                            has_payment = True

            if has_memo and has_payment:
                return True

    except Exception:
        logger.exception("[gate] Solana RPC error")

    return False
