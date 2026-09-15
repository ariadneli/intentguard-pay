"""Nonce registry for replay protection.

The v1 public demo used an in-memory set (process-local). Research-v2 introduces
an optional durable store (SQLite) so replay denial can persist across restarts.

This file is intentionally dependency-free: SQLite is in the Python stdlib.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from dataclasses import dataclass
from typing import Protocol


class NonceStore(Protocol):
    """Abstract nonce registry.

    The key is always payer-scoped: (payer, nonce).
    """

    def label(self) -> str:
        ...

    def is_unused(self, payer: str, nonce: str) -> bool:
        ...

    def consume(self, payer: str, nonce: str) -> bool:
        """Consume a nonce.

        Returns True iff this call consumed an unused nonce.
        """

    def reset(self) -> None:
        ...


@dataclass
class InMemoryNonceStore:
    """Fast process-local nonce registry."""

    def __post_init__(self) -> None:
        self._lock = threading.Lock()
        self._used: set[tuple[str, str]] = set()

    def label(self) -> str:
        return "Replay protection (process-local)"

    def is_unused(self, payer: str, nonce: str) -> bool:
        key = (payer.lower(), nonce)
        with self._lock:
            return key not in self._used

    def consume(self, payer: str, nonce: str) -> bool:
        key = (payer.lower(), nonce)
        with self._lock:
            if key in self._used:
                return False
            self._used.add(key)
            return True

    def reset(self) -> None:
        with self._lock:
            self._used.clear()


class SQLiteNonceStore:
    """Durable nonce registry backed by SQLite.

    This store is appropriate for a single-host prototype where a lightweight
    persistent replay registry is sufficient.
    """

    def __init__(self, path: str) -> None:
        self._path = path
        # check_same_thread=False allows multi-threaded use with a Python lock.
        self._conn = sqlite3.connect(self._path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA synchronous=NORMAL;")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS used_nonces (
              payer TEXT NOT NULL,
              nonce TEXT NOT NULL,
              consumed_at REAL NOT NULL,
              PRIMARY KEY (payer, nonce)
            );
            """
        )
        self._conn.commit()
        self._lock = threading.Lock()

    def label(self) -> str:
        return "Replay protection (durable sqlite)"

    def is_unused(self, payer: str, nonce: str) -> bool:
        payer = payer.lower()
        with self._lock:
            cur = self._conn.execute(
                "SELECT 1 FROM used_nonces WHERE payer=? AND nonce=? LIMIT 1;",
                (payer, nonce),
            )
            row = cur.fetchone()
            return row is None

    def consume(self, payer: str, nonce: str) -> bool:
        payer = payer.lower()
        with self._lock:
            cur = self._conn.execute(
                "INSERT OR IGNORE INTO used_nonces(payer, nonce, consumed_at) VALUES(?,?,?);",
                (payer, nonce, time.time()),
            )
            self._conn.commit()
            # rowcount == 1 means we inserted (consumed) a fresh nonce.
            return cur.rowcount == 1

    def reset(self) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM used_nonces;")
            self._conn.commit()
