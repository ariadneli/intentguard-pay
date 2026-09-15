"""Overhead experiment matrix for IntentGuard Pay (research-v2).

Goal: strengthen evidence beyond a single microbenchmark snapshot.

This script measures IntentEngine.validate_signed only:
- Includes: digest reconstruction, signer recovery, comparisons, and optional nonce consume.
- Excludes: signature creation (only for input generation), wallet UI, and network/RPC I/O.

Example:
  python3 backend/bench_overhead_matrix.py --out-dir docs/research-v2

Notes:
- The concurrency experiment uses multiple threads and multiple SQLite connections
  pointing to the same DB file to model multi-replica contention on a shared store.
- Numbers are platform-dependent; interpret deltas, not absolutes.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import statistics
import sys
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path

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
class MatrixRow:
    config: str
    store: str
    consume_nonce: bool
    concurrency: int
    n: int
    denies: int
    mean_ms: float
    p50_ms: float
    p95_ms: float
    throughput_rps: float


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
    signed = SignedPaymentIntent(intent=intent, domain=domain, signature="0x" + raw_sig)
    execution = SignedProposedExecution(
        recipient=intent.recipient,
        chainId=intent.chain_id,
        asset=intent.asset,
        amountWei=intent.amount_wei,
        calldataHash=intent.resource_hash,
    )
    return signed, execution


def _run_serial(*, store: str, consume_nonce: bool, n: int, sqlite_path: str | None) -> MatrixRow:
    domain = EXPECTED_DOMAIN
    fixtures = [make_signed_fixture(i, domain) for i in range(n)]

    if store == "sqlite":
        assert sqlite_path is not None
        if os.path.exists(sqlite_path):
            os.remove(sqlite_path)
        nonce_store = SQLiteNonceStore(sqlite_path)
    else:
        nonce_store = InMemoryNonceStore()

    engine = IntentEngine(nonce_store=nonce_store)

    timings_ms: list[float] = []
    denies = 0
    started = time.perf_counter()
    for signed, execution in fixtures:
        t0 = time.perf_counter_ns()
        receipt = engine.validate_signed(signed, execution, consume_nonce=consume_nonce)
        t1 = time.perf_counter_ns()
        timings_ms.append((t1 - t0) / 1e6)
        if receipt.decision != "AUTO_APPROVE":
            denies += 1
    elapsed = time.perf_counter() - started

    return MatrixRow(
        config=f"{store}-{'consume' if consume_nonce else 'verify-only'}",
        store=store,
        consume_nonce=consume_nonce,
        concurrency=1,
        n=n,
        denies=denies,
        mean_ms=float(statistics.mean(timings_ms)),
        p50_ms=pct(timings_ms, 0.50),
        p95_ms=pct(timings_ms, 0.95),
        throughput_rps=(n / elapsed) if elapsed > 0 else 0.0,
    )


def _run_sqlite_concurrent(*, n_total: int, workers: int, sqlite_path: str) -> MatrixRow:
    domain = EXPECTED_DOMAIN
    fixtures = [make_signed_fixture(i, domain) for i in range(n_total)]

    if os.path.exists(sqlite_path):
        os.remove(sqlite_path)

    barrier = threading.Barrier(workers)
    lock = threading.Lock()
    timings_ms: list[float] = []
    denies = 0

    chunks: list[list[tuple[SignedPaymentIntent, SignedProposedExecution]]] = [
        fixtures[i::workers] for i in range(workers)
    ]

    def _worker(chunk: list[tuple[SignedPaymentIntent, SignedProposedExecution]]) -> None:
        nonlocal denies
        store = SQLiteNonceStore(sqlite_path)
        engine = IntentEngine(nonce_store=store)
        barrier.wait()
        for signed, execution in chunk:
            t0 = time.perf_counter_ns()
            receipt = engine.validate_signed(signed, execution, consume_nonce=True)
            t1 = time.perf_counter_ns()
            with lock:
                timings_ms.append((t1 - t0) / 1e6)
                if receipt.decision != "AUTO_APPROVE":
                    denies += 1

    threads = [threading.Thread(target=_worker, args=(chunk,)) for chunk in chunks]
    started = time.perf_counter()
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    elapsed = time.perf_counter() - started

    return MatrixRow(
        config=f"sqlite-consume-concurrent-{workers}w",
        store="sqlite",
        consume_nonce=True,
        concurrency=workers,
        n=n_total,
        denies=denies,
        mean_ms=float(statistics.mean(timings_ms)) if timings_ms else 0.0,
        p50_ms=pct(timings_ms, 0.50),
        p95_ms=pct(timings_ms, 0.95),
        throughput_rps=(n_total / elapsed) if elapsed > 0 else 0.0,
    )


def to_markdown(rows: list[MatrixRow]) -> str:
    lines = []
    lines.append("# research-v2 · overhead experiment matrix\n")
    lines.append("> Timed region: `IntentEngine.validate_signed` only. Signing and all wallet/RPC I/O are excluded.\n")
    lines.append("\n")
    lines.append("| Config | n | Concurrency | Denies | Mean (ms) | p50 (ms) | p95 (ms) | Throughput (req/s) |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|---:|")
    for r in rows:
        lines.append(
            "| {config} | {n} | {conc} | {denies} | {mean:.2f} | {p50:.2f} | {p95:.2f} | {rps:.1f} |".format(
                config=r.config,
                n=r.n,
                conc=r.concurrency,
                denies=r.denies,
                mean=r.mean_ms,
                p50=r.p50_ms,
                p95=r.p95_ms,
                rps=r.throughput_rps,
            )
        )
    lines.append("\n")
    lines.append(
        "Interpretation: focus on deltas across configurations. SQLite concurrency models contention on a shared durable nonce registry; it is not a production benchmark.\n"
    )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out-dir", default="docs/research-v2")
    parser.add_argument("--n", type=int, default=300)
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--n-concurrent", type=int, default=400)
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    sqlite_path = str(out_dir / "intentguard_nonces_matrix.sqlite3")

    rows: list[MatrixRow] = []
    rows.append(_run_serial(store="memory", consume_nonce=False, n=args.n, sqlite_path=None))
    rows.append(_run_serial(store="memory", consume_nonce=True, n=args.n, sqlite_path=None))
    rows.append(_run_serial(store="sqlite", consume_nonce=True, n=min(args.n, 250), sqlite_path=sqlite_path))
    rows.append(
        _run_sqlite_concurrent(
            n_total=args.n_concurrent,
            workers=args.concurrency,
            sqlite_path=sqlite_path,
        )
    )

    payload = {
        "rows": [asdict(r) for r in rows],
        "runtime": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "processor": platform.processor(),
        },
        "notes": {
            "timed_region": "IntentEngine.validate_signed only; signing excluded; no wallet/RPC I/O",
            "concurrency": "threads + multiple SQLite connections to a shared DB file",
        },
    }

    (out_dir / "overhead_matrix.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8"
    )
    (out_dir / "overhead_matrix.md").write_text(to_markdown(rows), encoding="utf-8")
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
