"""
Grant stores for durable paid-key persistence (P0 #5).

Once a key is added to a grant store it is never re-scanned on-chain, making
paid access durable even after the vendor wallet accumulates 100+ newer
transactions that would push the original payment out of the scan window.

Usage — pass to any adapter as ``grant_store``:

    from agentpayments_python.grant_store import FileGrantStore

    # Django settings.py
    AGENTPAYMENTS_GRANT_STORE = FileGrantStore("/var/data/agp_grants.json")

    # FastAPI / Flask constructor arg
    register_agentpayments(app, ..., grant_store=FileGrantStore("/var/data/agp_grants.json"))

Grant store interface (implement your own for Redis, Postgres, etc.):

    class GrantStore(Protocol):
        def has(self, agent_key: str) -> bool: ...
        def add(self, agent_key: str) -> None: ...
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path


class MemoryGrantStore:
    """In-memory grant store. Does not survive restarts."""

    def __init__(self) -> None:
        self._grants: set[str] = set()
        self._lock = threading.Lock()

    def has(self, agent_key: str) -> bool:
        with self._lock:
            return agent_key in self._grants

    def add(self, agent_key: str) -> None:
        with self._lock:
            self._grants.add(agent_key)


class FileGrantStore:
    """
    File-backed grant store. Persists grants to a JSON file so they survive
    process restarts. Writes are atomic (write to temp file, os.replace).

    Not suitable for multi-process deployments — use a database or Redis there.
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path).resolve()
        self._grants: set[str] = set()
        self._lock = threading.Lock()
        self._load()

    def _load(self) -> None:
        try:
            keys = json.loads(self._path.read_text())
            if isinstance(keys, list):
                self._grants.update(keys)
        except FileNotFoundError:
            pass  # will be created on first write

    def _save(self) -> None:
        tmp = self._path.with_suffix(".tmp")
        tmp.write_text(json.dumps(sorted(self._grants), indent=2))
        os.replace(tmp, self._path)

    def has(self, agent_key: str) -> bool:
        with self._lock:
            return agent_key in self._grants

    def add(self, agent_key: str) -> None:
        with self._lock:
            if agent_key in self._grants:
                return
            self._grants.add(agent_key)
            self._save()
