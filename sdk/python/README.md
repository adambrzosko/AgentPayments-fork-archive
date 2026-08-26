# agentpayments-python

Python adapters for the AgentPayments gate. Supports Django, FastAPI/Starlette, and Flask.

## Install

```bash
pip install agentpayments-python
# or, in this monorepo:
# pip install -e sdk/python
```

## Django

```python
# settings.py
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "agentpayments_python.django_adapter.GateMiddleware",
    # ... other middleware
]

# Required settings
CHALLENGE_SECRET = os.environ["CHALLENGE_SECRET"]
HOME_WALLET_ADDRESS = os.environ["HOME_WALLET_ADDRESS"]

# Optional settings
SOLANA_RPC_URL = os.environ.get("SOLANA_RPC_URL")
USDC_MINT = os.environ.get("USDC_MINT")
DEBUG = True  # True = devnet, False = mainnet
```

## FastAPI

```python
from fastapi import FastAPI, Request
from agentpayments_python.fastapi_adapter import (
    AgentPaymentsASGIMiddleware,
    challenge_verify_endpoint,
)

app = FastAPI()

app.add_middleware(
    AgentPaymentsASGIMiddleware,
    challenge_secret=os.environ["CHALLENGE_SECRET"],
    home_wallet_address=os.environ["HOME_WALLET_ADDRESS"],
    debug=True,
)

@app.post("/__challenge/verify")
async def verify(request: Request):
    return await challenge_verify_endpoint(
        request,
        challenge_secret=os.environ["CHALLENGE_SECRET"],
    )
```

## Flask

```python
from flask import Flask
from agentpayments_python.flask_adapter import register_agentpayments

app = Flask(__name__)
register_agentpayments(
    app,
    challenge_secret=os.environ["CHALLENGE_SECRET"],
    home_wallet_address=os.environ["HOME_WALLET_ADDRESS"],
    debug=True,
)
```

## Configuration

| Parameter | Required | Default | Description |
|---|---|---|---|
| `challenge_secret` | Yes (production) | `'default-secret-change-me'` | HMAC secret for signing cookies, nonces, and agent keys. |
| `home_wallet_address` | Yes | `''` | Solana wallet address to receive USDC payments. |
| `solana_rpc_url` | No | Auto (devnet/mainnet) | Custom Solana RPC endpoint. |
| `usdc_mint` | No | Auto (devnet/mainnet) | Custom USDC mint address. |
| `debug` | No | `True` | `True` = devnet. `False` = mainnet + strict mode. |

Django reads these from `settings.*` (e.g., `settings.CHALLENGE_SECRET`). FastAPI and Flask accept them as constructor arguments.

## Security Features

- **Timing-safe HMAC comparison** — uses `hmac.compare_digest()` for all signature checks
- **Payment verification cache** — 10-minute TTL, 1000-entry max (thread-safe)
- **Rate limiting** — 20 challenge verifications per minute per IP (thread-safe)
- **Input size limits** — key (64 chars), nonce (128), return URL (2048), fingerprint (128)
- **Wallet address validation** — base58 format, 32-44 chars, validated at init
- **Default secret detection** — warns in debug, raises `RuntimeError` in production
- **Secure cookies** — Django auto-detects HTTPS via `request.is_secure()`

## Module Structure

```
agentpayments_python/
  __init__.py
  django_adapter.py      Django middleware (GateMiddleware)
  fastapi_adapter.py     FastAPI/Starlette ASGI middleware
  flask_adapter.py       Flask integration (before_request hook)
  challenge.py           Shared challenge HTML generation
  cookies.py             Cookie creation and validation
  crypto.py              HMAC signing and agent key management
  detection.py           Browser detection and public path checks
  solana.py              On-chain payment verification + caching
  ratelimit.py           Shared IP-based rate limiter
```

## Notes
- Constants loaded from `sdk/constants.json` via `pathlib`.
- Logging uses Python stdlib `logging` module.
- All shared modules are framework-agnostic; adapters are thin wiring.
