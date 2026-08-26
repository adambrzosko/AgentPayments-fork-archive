# Adapters are optional: each import succeeds only if its framework is
# installed. ImportError (missing framework) is expected; any other exception
# is a real bug and should propagate.

# x402 helpers are always available (no framework dependency).
from .x402 import build_payment_requirements, enrich_402_body, payment_required_header

__all__ = [
    "build_payment_requirements",
    "enrich_402_body",
    "payment_required_header",
]

try:
    from .django_adapter import GateMiddleware, challenge_verify
    __all__ += ["GateMiddleware", "challenge_verify"]
except ImportError:
    pass

try:
    from .fastapi_adapter import AgentPaymentsASGIMiddleware, challenge_verify_endpoint as fastapi_challenge_verify
    __all__ += ["AgentPaymentsASGIMiddleware", "fastapi_challenge_verify"]
except ImportError:
    pass

try:
    from .flask_adapter import register_agentpayments
    __all__ += ["register_agentpayments"]
except ImportError:
    pass
