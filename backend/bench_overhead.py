"""Microbenchmarks for IntentGuard Pay verification overhead.

This script measures server-side validation cost (digest reconstruction, signer
recovery, binding checks, and optional nonce consumption).

Usage:
  python3 bench_overhead.py --n 500 --store memory
  python3 bench_overhead.py --n 200 --store sqlite --sqlite-path /tmp/nonces.sqlite3

The signing step is performed only to generate input fixtures and is excluded
from the timed region.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import statistics
import sys
import time
from dataclasses import asdict, dataclass

from eth_account import Account

from eip712 import (
    EXPECTED_DOMAIN,
    EIP712Domain,
    EIP712PaymentIntent,
    SignedPaymentIntent,
    SignedProposedExecution,
    build_signable_message,
)
from intent_engine import IntentEngine
from nonce_store import InMemoryNonceStore, SQLiteNonceStore


TEST_PRIVATE_KEY = "0x" + "11" * 32
TEST_ACCOUNT = Account.from_key(TEST_PRIVATE_KEY)


def pct(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    values = sorted(values)
    k = (len(values) - 1) * percentile
    f = int(k)
    c = min(f + 1, len(values) - 1)
    if f == c:
        return float(values[f])
    return float(values[f] * (c - k) + values[c] * (k - f))


@dataclass
class BenchResult:
    store: str
    consume_nonce: bool
    n: int
    p50_ms: float
    p95_ms: float
    mean_ms: float


def make_signed_fixture(i: int, domain: EIP712Domain) -> tuple[SignedPaymentIntent, SignedProposedExecution]:
    nonce = "0x" + f"{(i + 1):064x}"
    intent = EIP712PaymentIntent(
        intentId="0x" + "01" * 32,
        payer=TEST_ACCOUNT.address,
        recipient="0x3333333333333333333333333333333333333333",
        chainId=11155111,
        asset="ETH",
        amountWei=20_000_000_000_000_000,
        maxAmountWei=20_000_000_000_000_000,
        purpose="Pay approved merchant",
        expiry=1_893_456_000,
        nonce=nonce,
        resourceHash="0x" + "03" * 32,
    )
    raw_sig = Account.sign_message(
        build_signable_message(intent, domain), private_key=TEST_PRIVATE_KEY
    ).signature.hex()
    signature = "0x" + raw_sig
    signed = SignedPaymentIntent(intent=intent, domain=domain, signature=signature)
    execution = SignedProposedExecution(
        recipient=intent.recipient,
        chainId=intent.chain_id,
        asset=intent.asset,
        amountWei=intent.amount_wei,
        calldataHash=intent.resource_hash,
    )
    return signed, execution


def run_bench(store: str, consume_nonce: bool, n: int, sqlite_path: str | None) -> BenchResult:
    domain = EXPECTED_DOMAIN

    fixtures = [make_signed_fixture(i, domain) for i in range(n)]

    if store == "sqlite":
        if sqlite_path is None:
            sqlite_path = "/tmp/intentguard_nonces.sqlite3"
        if os.path.exists(sqlite_path):
            os.remove(sqlite_path)
        nonce_store = SQLiteNonceStore(sqlite_path)
    else:
        nonce_store = InMemoryNonceStore()

    engine = IntentEngine(nonce_store=nonce_store)

    timings_ms: list[float] = []
    for signed, execution in fixtures:
        t0 = time.perf_counter_ns()
        engine.validate_signed(signed, execution, consume_nonce=consume_nonce)
        t1 = time.perf_counter_ns()
        timings_ms.append((t1 - t0) / 1e6)

    return BenchResult(
        store=store,
        consume_nonce=consume_nonce,
        n=n,
        p50_ms=pct(timings_ms, 0.50),
        p95_ms=pct(timings_ms, 0.95),
        mean_ms=float(statistics.mean(timings_ms)),
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--n", type=int, default=300)
    parser.add_argument("--store", choices=["memory", "sqlite"], default="memory")
    parser.add_argument("--consume-nonce", action="store_true")
    parser.add_argument("--sqlite-path", default=None)
    args = parser.parse_args()

    result = run_bench(args.store, args.consume_nonce, args.n, args.sqlite_path)

    payload = {
        "result": asdict(result),
        "runtime": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "processor": platform.processor(),
        },
        "notes": {
            "timed_region": "IntentEngine.validate_signed only; input signing excluded",
            "consume_nonce": args.consume_nonce,
        },
    }
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
