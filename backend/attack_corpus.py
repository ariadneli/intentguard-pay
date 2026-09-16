"""Deterministic payment-authorization mutation corpus and baseline evaluator.

PAACT-Core v1 deliberately targets the controls exposed by the legacy unsigned
mechanism benchmark: intent policy, execution scope/exact-amount binding,
expiry, and payer-scoped replay. Signature/domain and calldata-commitment
mutations remain in the signed-intent property/state-machine suite; this module
does not pretend that unsigned mechanism profiles evaluate those dimensions.
"""

from __future__ import annotations

import json
import math
import random
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Sequence, Tuple

from intent_engine import (
    BASELINE_DEFINITIONS,
    FixtureCase,
    _evaluate_profile,
    _resolve_check_codes,
)

SCHEMA_VERSION = "paact-core-v1"
DEFAULT_SEED = 20260916
DEFAULT_COUNTS: Dict[str, int] = {
    "benign": 80,
    "recipient_in_allowlist": 100,
    "recipient_external": 100,
    "amount_within_ceiling": 120,
    "amount_over_ceiling": 120,
    "chain_switch": 100,
    "asset_switch": 100,
    "expired_intent": 80,
    "replay": 100,
    "policy_allowlist": 50,
    "compositional": 50,
}

ALLOWED_RECIPIENTS = (
    "0x3333333333333333333333333333333333333333",
    "0x4444444444444444444444444444444444444444",
)
ALLOWED_ASSETS = ("SEP", "ETH", "USDC")
EXTERNAL_CHAINS = (1, 10, 137, 8453, 42161)
EXTERNAL_ASSETS = ("DAI", "USDT", "WBTC", "ARB", "OP")
PAST_EXPIRY = "2020-01-01T00:00:00+00:00"


@dataclass(frozen=True)
class CorpusManifest:
    schema_version: str
    seed: int
    total_cases: int
    counts: Dict[str, int]
    scope: List[str]
    excluded_dimensions: List[str]


TAXONOMY: Dict[str, Dict[str, str]] = {
    "benign": {
        "label": "Benign boundary cases",
        "security_property": "utility / false-rejection control",
    },
    "recipient": {
        "label": "Recipient mutation",
        "security_property": "execution scope and policy allowlists",
    },
    "amount": {
        "label": "Amount mutation",
        "security_property": "exact binding and authorization ceiling",
    },
    "chain": {
        "label": "Chain mutation",
        "security_property": "execution scope and chain allowlists",
    },
    "asset": {
        "label": "Asset mutation",
        "security_property": "execution scope and asset allowlists",
    },
    "expiry": {
        "label": "Expired authorization",
        "security_property": "freshness",
    },
    "replay": {
        "label": "Replay",
        "security_property": "payer-scoped at-most-once release",
    },
    "policy": {
        "label": "Unauthorized intent envelope",
        "security_property": "intent-time policy",
    },
    "compositional": {
        "label": "Compositional mutation",
        "security_property": "multiple simultaneous authorization violations",
    },
}


def _external_address(value: int) -> str:
    # Keep addresses syntactically uniform and outside the two-entry allowlist.
    return "0x" + f"{value + 0x5000:040x}"[-40:]


def _base_amount(index: int) -> float:
    # 0.0020 .. 0.0400 ETH-equivalent, always below the auto-approval limit.
    return round(0.002 + (index % 39) * 0.001, 6)


def _max_amount(amount: float, index: int) -> float:
    return round(min(0.05, amount + 0.003 + (index % 5) * 0.001), 6)


def _fixture(
    case_id: str,
    kind: str,
    family: str,
    operator: str,
    *,
    intent_patch: Dict | None = None,
    execution_patch: Dict | None = None,
    replay: bool = False,
    severity: str = "high",
) -> FixtureCase:
    return FixtureCase(
        case_id=case_id,
        kind=kind,
        intent_patch=intent_patch or {},
        execution_patch=execution_patch or {},
        replay=replay,
        family=family,
        mutation_operator=operator,
        severity=severity,
    )


def generate_corpus(
    *,
    seed: int = DEFAULT_SEED,
    counts: Dict[str, int] | None = None,
) -> Tuple[CorpusManifest, List[FixtureCase]]:
    """Generate a stable corpus; identical seed/config produces identical JSONL."""

    selected = dict(DEFAULT_COUNTS if counts is None else counts)
    unknown = set(selected) - set(DEFAULT_COUNTS)
    if unknown:
        raise ValueError(f"unknown corpus families: {sorted(unknown)}")
    if any(value < 0 for value in selected.values()):
        raise ValueError("corpus counts must be non-negative")

    rng = random.Random(seed)
    cases: List[FixtureCase] = []

    for i in range(selected.get("benign", 0)):
        amount = 0.05 if i % 10 == 0 else _base_amount(i)
        max_amount = 0.05 if i % 10 == 0 else _max_amount(amount, i)
        recipient = ALLOWED_RECIPIENTS[i % len(ALLOWED_RECIPIENTS)]
        token = ALLOWED_ASSETS[i % len(ALLOWED_ASSETS)]
        operator = (
            "exact_ceiling_boundary"
            if i % 10 == 0
            else "alternate_allowed_scope"
            if i % 2
            else "ordinary_valid"
        )
        cases.append(
            _fixture(
                f"benign-{i:04d}",
                "legitimate",
                "benign",
                operator,
                intent_patch={
                    "recipient": recipient,
                    "token": token,
                    "amount": amount,
                    "max_amount": max_amount,
                    "purpose": f"approved-corpus-payment-{i:04d}",
                },
                execution_patch={
                    "recipient": recipient,
                    "token": token,
                    "amount": amount,
                },
                severity="none",
            )
        )

    for i in range(selected.get("recipient_in_allowlist", 0)):
        cases.append(
            _fixture(
                f"recipient-in-allowlist-{i:04d}",
                "attack",
                "recipient",
                "substitute_with_allowed_recipient",
                intent_patch={"recipient": ALLOWED_RECIPIENTS[0]},
                execution_patch={"recipient": ALLOWED_RECIPIENTS[1]},
            )
        )

    for i in range(selected.get("recipient_external", 0)):
        cases.append(
            _fixture(
                f"recipient-external-{i:04d}",
                "attack",
                "recipient",
                "substitute_with_external_recipient",
                execution_patch={"recipient": _external_address(i)},
                severity="critical",
            )
        )

    for i in range(selected.get("amount_within_ceiling", 0)):
        amount = _base_amount(i)
        max_amount = _max_amount(amount, i)
        delta = max(0.000001, round((max_amount - amount) * (0.25 + 0.1 * (i % 5)), 6))
        executed = round(min(max_amount, amount + delta), 6)
        if executed == amount:
            executed = round(amount + 0.000001, 6)
        cases.append(
            _fixture(
                f"amount-within-ceiling-{i:04d}",
                "attack",
                "amount",
                "exact_amount_drift_within_ceiling",
                intent_patch={"amount": amount, "max_amount": max_amount},
                execution_patch={"amount": executed},
            )
        )

    for i in range(selected.get("amount_over_ceiling", 0)):
        amount = _base_amount(i)
        max_amount = _max_amount(amount, i)
        cross_policy_limit = i % 2 == 1
        executed = round((0.051 + (i % 10) * 0.001) if cross_policy_limit else min(0.05, max_amount + 0.001), 6)
        if executed <= max_amount:
            max_amount = round(max(0.001, executed - 0.001), 6)
        operator = "over_intent_and_execution_policy" if cross_policy_limit else "over_intent_within_execution_policy"
        cases.append(
            _fixture(
                f"amount-over-ceiling-{i:04d}",
                "attack",
                "amount",
                operator,
                intent_patch={"amount": amount, "max_amount": max_amount},
                execution_patch={"amount": executed},
                severity="critical",
            )
        )

    for i in range(selected.get("chain_switch", 0)):
        cases.append(
            _fixture(
                f"chain-switch-{i:04d}",
                "attack",
                "chain",
                "execution_chain_substitution",
                execution_patch={"chain_id": EXTERNAL_CHAINS[i % len(EXTERNAL_CHAINS)]},
                severity="critical",
            )
        )

    for i in range(selected.get("asset_switch", 0)):
        cases.append(
            _fixture(
                f"asset-switch-{i:04d}",
                "attack",
                "asset",
                "execution_asset_substitution",
                execution_patch={"token": EXTERNAL_ASSETS[i % len(EXTERNAL_ASSETS)]},
                severity="critical",
            )
        )

    for i in range(selected.get("expired_intent", 0)):
        cases.append(
            _fixture(
                f"expired-intent-{i:04d}",
                "attack",
                "expiry",
                "reuse_after_expiry",
                intent_patch={"expiry": PAST_EXPIRY},
            )
        )

    for i in range(selected.get("replay", 0)):
        cases.append(
            _fixture(
                f"replay-{i:04d}",
                "attack",
                "replay",
                "repeat_identical_authorization",
                replay=True,
                severity="critical",
            )
        )

    for i in range(selected.get("policy_allowlist", 0)):
        recipient = _external_address(10_000 + i)
        cases.append(
            _fixture(
                f"policy-allowlist-{i:04d}",
                "attack",
                "policy",
                "authorize_unapproved_recipient",
                intent_patch={"recipient": recipient},
                execution_patch={"recipient": recipient},
            )
        )

    for i in range(selected.get("compositional", 0)):
        amount = _base_amount(i)
        max_amount = _max_amount(amount, i)
        operators = ["recipient+amount", "chain+asset", "recipient+chain+amount"]
        operator = operators[i % len(operators)]
        intent_patch = {"amount": amount, "max_amount": max_amount}
        execution_patch: Dict = {}
        if "recipient" in operator:
            execution_patch["recipient"] = _external_address(20_000 + i)
        if "chain" in operator:
            execution_patch["chain_id"] = rng.choice(EXTERNAL_CHAINS)
        if "asset" in operator:
            execution_patch["token"] = rng.choice(EXTERNAL_ASSETS)
        if "amount" in operator:
            execution_patch["amount"] = round(min(0.05, amount + 0.001), 6)
        cases.append(
            _fixture(
                f"compositional-{i:04d}",
                "attack",
                "compositional",
                operator,
                intent_patch=intent_patch,
                execution_patch=execution_patch,
                severity="critical",
            )
        )

    rng.shuffle(cases)
    family_counts = Counter(case.family if case.kind == "attack" else "benign" for case in cases)
    manifest = CorpusManifest(
        schema_version=SCHEMA_VERSION,
        seed=seed,
        total_cases=len(cases),
        counts=dict(sorted(family_counts.items())),
        scope=[
            "intent allowlists",
            "execution recipient/chain/asset binding",
            "exact amount and amount ceiling",
            "expiry",
            "payer-scoped replay",
            "compositional mutations",
            "benign boundary cases",
        ],
        excluded_dimensions=[
            "EIP-712 signer/domain mutations (covered by signed property/state tests)",
            "calldata semantic equivalence (only hash commitment is modeled)",
            "distributed nonce consensus and wallet-broadcast atomicity",
        ],
    )
    return manifest, cases


def fixture_to_record(case: FixtureCase, *, seed: int) -> Dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "seed": seed,
        **asdict(case),
        "expected_decision": "ALLOW" if case.kind == "legitimate" else "DENY",
    }


def write_corpus_jsonl(path: Path, manifest: CorpusManifest, cases: Sequence[FixtureCase]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for case in cases:
            handle.write(json.dumps(fixture_to_record(case, seed=manifest.seed), sort_keys=True) + "\n")


def load_corpus_jsonl(path: Path) -> Tuple[CorpusManifest, List[FixtureCase]]:
    records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not records:
        raise ValueError("corpus JSONL is empty")
    versions = {record["schema_version"] for record in records}
    seeds = {record["seed"] for record in records}
    if versions != {SCHEMA_VERSION} or len(seeds) != 1:
        raise ValueError("corpus must use one supported schema version and one seed")
    cases = [
        FixtureCase(
            case_id=record["case_id"],
            kind=record["kind"],
            intent_patch=record["intent_patch"],
            execution_patch=record["execution_patch"],
            replay=record["replay"],
            family=record["family"],
            mutation_operator=record["mutation_operator"],
            severity=record["severity"],
        )
        for record in records
    ]
    family_counts = Counter(case.family if case.kind == "attack" else "benign" for case in cases)
    manifest = CorpusManifest(
        schema_version=SCHEMA_VERSION,
        seed=next(iter(seeds)),
        total_cases=len(cases),
        counts=dict(sorted(family_counts.items())),
        scope=[],
        excluded_dimensions=[],
    )
    return manifest, cases


def wilson_interval(successes: int, total: int, z: float = 1.959963984540054) -> Tuple[float, float]:
    if total == 0:
        return (0.0, 0.0)
    p = successes / total
    denominator = 1 + z * z / total
    center = (p + z * z / (2 * total)) / denominator
    margin = z * math.sqrt((p * (1 - p) + z * z / (4 * total)) / total) / denominator
    return (round(100 * max(0.0, center - margin), 2), round(100 * min(1.0, center + margin), 2))


def _group_metrics(rows: Iterable[Dict]) -> Dict:
    rows = list(rows)
    attacks = [row for row in rows if row["type"] == "attack"]
    benign = [row for row in rows if row["type"] == "legitimate"]
    blocked = sum(bool(row["correct"]) for row in attacks)
    completed = sum(bool(row["correct"]) for row in benign)
    return {
        "total": len(rows),
        "attacks": len(attacks),
        "benign": len(benign),
        "blocked_attacks": blocked,
        "completed_benign": completed,
        "attack_block_rate": round(100 * blocked / len(attacks), 2) if attacks else None,
        "attack_block_rate_wilson_95": wilson_interval(blocked, len(attacks)) if attacks else None,
        "benign_completion_rate": round(100 * completed / len(benign), 2) if benign else None,
        "benign_completion_rate_wilson_95": wilson_interval(completed, len(benign)) if benign else None,
        "false_rejection_rate": round(100 * (len(benign) - completed) / len(benign), 2) if benign else None,
    }


def evaluate_corpus(manifest: CorpusManifest, cases: Sequence[FixtureCase]) -> Dict:
    """Run every mechanism-level baseline on exactly the same ordered corpus."""

    results: List[Dict] = []
    for baseline in BASELINE_DEFINITIONS:
        enabled = _resolve_check_codes(baseline["controls"])
        _, outcomes = _evaluate_profile(
            enabled_checks=enabled,
            state_model=baseline["state_model"],
            consume_nonce="NONCE_UNUSED" in enabled,
            fixtures=list(cases),
        )
        by_family: Dict[str, List[Dict]] = defaultdict(list)
        by_operator: Dict[str, List[Dict]] = defaultdict(list)
        for row in outcomes:
            by_family[row["family"]].append(row)
            by_operator[f'{row["family"]}/{row["mutation_operator"]}'].append(row)
        results.append(
            {
                "mode": baseline["id"],
                "label": baseline["label"],
                "state_model": baseline["state_model"],
                "controls": baseline["controls"],
                "overall": _group_metrics(outcomes),
                "by_family": {key: _group_metrics(value) for key, value in sorted(by_family.items())},
                "by_operator": {key: _group_metrics(value) for key, value in sorted(by_operator.items())},
            }
        )

    return {
        "manifest": asdict(manifest),
        "taxonomy": TAXONOMY,
        "baseline_results": results,
        "interpretation_boundary": [
            "Mechanism profiles are evaluated on identical deterministic cases; they are not external project reproductions.",
            "Confidence intervals quantify finite-corpus uncertainty, not real-world attack prevalence.",
            "Signer/domain and calldata-semantics claims remain outside this corpus.",
        ],
    }
