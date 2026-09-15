"""Deterministic intent validation for the IntentGuard Pay research prototype.

This repository is intentionally *not* a full reproduction of any upstream system.
Instead, it provides:

- A payment-specific threat model and adversarial fixtures.
- A deterministic policy / binding / replay gate between agent proposals and
  simulated execution.
- A mechanism-level benchmark that compares *controls* (not projects).

The execution-integrity checks and benchmark profiles are native components of
IntentGuard Pay and are evaluated only through this repository's fixture runner.
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Set, Tuple

from pydantic import BaseModel, Field

from eip712 import (
    SignedPaymentIntent,
    SignedProposedExecution,
    domain_matches_expected,
    recover_signer,
    typed_data_digest,
)


class PaymentIntent(BaseModel):
    intent_id: str
    payer: str
    recipient: str
    chain_id: int
    token: str
    amount: float = Field(gt=0)
    max_amount: float = Field(gt=0)
    purpose: str
    expiry: str
    nonce: str
    resource_hash: str


class ProposedExecution(BaseModel):
    recipient: str
    chain_id: int
    token: str
    amount: float = Field(gt=0)
    calldata_hash: str


class PolicyCheck(BaseModel):
    code: str
    label: str
    passed: bool
    detail: str
    severity: str = "critical"


class AuditReceipt(BaseModel):
    receipt_id: str
    intent_hash: str
    intent_hash_kind: str
    execution_hash: str
    decision: str
    policy_checks: List[PolicyCheck]
    tx_hash: Optional[str]
    evidence_hash: str
    timestamp: str
    network: str
    attestation_status: str
    typed_data_digest: Optional[str] = None
    recovered_signer: Optional[str] = None
    signature_scheme: Optional[str] = None


class DemoResult(BaseModel):
    scenario_id: str
    title: str
    summary: str
    decision: str
    intent: PaymentIntent
    proposed_execution: ProposedExecution
    policy_checks: List[PolicyCheck]
    timeline: List[Dict[str, str]]
    audit_receipt: AuditReceipt
    replay_receipt: Optional[AuditReceipt] = None


def _canonical_hash(payload: Dict) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "0x" + hashlib.sha256(encoded).hexdigest()


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _future_expiry(minutes: int = 30) -> str:
    return (_utc_now() + timedelta(minutes=minutes)).isoformat()


def _past_expiry() -> str:
    return (_utc_now() - timedelta(minutes=5)).isoformat()


def _is_expired(expiry: str) -> bool:
    parsed = datetime.fromisoformat(expiry.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed <= _utc_now()


# Default check set used by demo scenarios (IntentGuard full).
# Intentionally excludes the execution-time policy-module checks, which are
# modeled as a separate baseline (`smart-account-policy`) in the benchmark.
INTENTGUARD_FULL_CHECKS: Set[str] = {
    "CHAIN_ALLOWED",
    "TOKEN_ALLOWED",
    "RECIPIENT_ALLOWED",
    "AMOUNT_WITHIN_INTENT",
    "EXECUTION_SCOPE_MATCH",
    "EXECUTION_AMOUNT_EXACT",
    "INTENT_FRESH",
    "NONCE_UNUSED",
}


class IntentEngine:
    """In-memory policy engine suitable for a deterministic public research build."""

    # NOTE: These are *prototype policy constants*, not production recommendations.
    allowed_chain_ids = {11155111}
    allowed_tokens = {"SEP", "ETH", "USDC"}
    allowed_recipients = {
        "0x3333333333333333333333333333333333333333",
        "0x4444444444444444444444444444444444444444",
    }

    # AUTO_APPROVE vs HUMAN_REVIEW threshold (not used as a hard deny policy).
    auto_approval_limit = 0.05
    auto_approval_limit_wei = 50_000_000_000_000_000

    # A *separate* hard limit used only for the smart-account-policy baseline.
    # Chosen to keep the included benign fixtures non-denying.
    execution_policy_tx_limit = 0.05

    def __init__(self) -> None:
        self.used_nonces: Set[str] = set()

    def reset(self) -> None:
        self.used_nonces.clear()

    def validate(
        self,
        intent: PaymentIntent,
        execution: ProposedExecution,
        consume_nonce: bool = True,
        enabled_checks: Optional[Set[str]] = None,
    ) -> AuditReceipt:
        checks = [
            # Intent-time policy gates
            PolicyCheck(
                code="CHAIN_ALLOWED",
                label="Approved network (intent)",
                passed=intent.chain_id in self.allowed_chain_ids,
                detail="Sepolia chain ID 11155111 is authorized."
                if intent.chain_id in self.allowed_chain_ids
                else "The requested chain is outside the authorization boundary.",
            ),
            PolicyCheck(
                code="TOKEN_ALLOWED",
                label="Approved asset (intent)",
                passed=intent.token.upper() in self.allowed_tokens,
                detail="The asset is on the policy allowlist."
                if intent.token.upper() in self.allowed_tokens
                else "The asset is not on the policy allowlist.",
            ),
            PolicyCheck(
                code="RECIPIENT_ALLOWED",
                label="Recipient allowlist (intent)",
                passed=intent.recipient.lower() in self.allowed_recipients,
                detail="Recipient is approved by the treasury policy."
                if intent.recipient.lower() in self.allowed_recipients
                else "Recipient is unknown or untrusted.",
            ),
            PolicyCheck(
                code="AMOUNT_WITHIN_INTENT",
                label="Amount ceiling",
                passed=execution.amount <= intent.max_amount,
                detail="Proposed amount stays within the authorized ceiling."
                if execution.amount <= intent.max_amount
                else "Proposed amount exceeds the authorized maximum.",
            ),
            # Execution binding (cross-layer intent → execution)
            PolicyCheck(
                code="EXECUTION_SCOPE_MATCH",
                label="Execution scope binding",
                passed=(
                    execution.recipient.lower() == intent.recipient.lower()
                    and execution.chain_id == intent.chain_id
                    and execution.token.upper() == intent.token.upper()
                ),
                detail="Recipient, chain and token match the authorized intent envelope."
                if (
                    execution.recipient.lower() == intent.recipient.lower()
                    and execution.chain_id == intent.chain_id
                    and execution.token.upper() == intent.token.upper()
                )
                else "Observed execution scope differs from the authorized envelope.",
            ),
            PolicyCheck(
                code="EXECUTION_AMOUNT_EXACT",
                label="Exact amount binding",
                passed=execution.amount == intent.amount,
                detail="The executed amount exactly matches the authorized payment amount."
                if execution.amount == intent.amount
                else "Executed amount differs from the authorized payment amount.",
            ),
            # Expiry + replay
            PolicyCheck(
                code="INTENT_FRESH",
                label="Intent expiry",
                passed=not _is_expired(intent.expiry),
                detail="Intent is still valid."
                if not _is_expired(intent.expiry)
                else "Intent has expired and cannot be executed.",
            ),
            PolicyCheck(
                code="NONCE_UNUSED",
                label="Replay protection (process-local)",
                passed=intent.nonce not in self.used_nonces,
                detail="Nonce has not been consumed."
                if intent.nonce not in self.used_nonces
                else "Nonce was already consumed by an earlier execution.",
            ),
            # Execution-time policy module (smart account / module style)
            PolicyCheck(
                code="EXEC_CHAIN_ALLOWED",
                label="Approved network (execution)",
                passed=execution.chain_id in self.allowed_chain_ids,
                detail="Execution chain is on the allowlist."
                if execution.chain_id in self.allowed_chain_ids
                else "Execution chain is not on the allowlist.",
            ),
            PolicyCheck(
                code="EXEC_TOKEN_ALLOWED",
                label="Approved asset (execution)",
                passed=execution.token.upper() in self.allowed_tokens,
                detail="Execution token is on the allowlist."
                if execution.token.upper() in self.allowed_tokens
                else "Execution token is not on the allowlist.",
            ),
            PolicyCheck(
                code="EXEC_RECIPIENT_ALLOWED",
                label="Recipient allowlist (execution)",
                passed=execution.recipient.lower() in self.allowed_recipients,
                detail="Execution recipient is on the allowlist."
                if execution.recipient.lower() in self.allowed_recipients
                else "Execution recipient is not on the allowlist.",
            ),
            PolicyCheck(
                code="EXEC_AMOUNT_WITHIN_POLICY",
                label="Execution-time spend limit",
                passed=execution.amount <= self.execution_policy_tx_limit,
                detail=(
                    f"Execution amount is within the configured limit ({self.execution_policy_tx_limit})."
                    if execution.amount <= self.execution_policy_tx_limit
                    else f"Execution amount exceeds the configured limit ({self.execution_policy_tx_limit})."
                ),
            ),
        ]

        if enabled_checks is not None:
            checks = [c for c in checks if c.code in enabled_checks]

        critical_failure = any(not check.passed for check in checks)
        if critical_failure:
            decision = "DENY"
        elif execution.amount > self.auto_approval_limit:
            decision = "HUMAN_REVIEW"
        else:
            decision = "AUTO_APPROVE"

        intent_hash = _canonical_hash(intent.model_dump())
        execution_hash = _canonical_hash(execution.model_dump())

        tx_hash = None
        if decision != "DENY":
            if consume_nonce:
                self.used_nonces.add(intent.nonce)
            tx_hash = _canonical_hash(
                {
                    "intent_hash": intent_hash,
                    "execution_hash": execution_hash,
                    "nonce": intent.nonce,
                }
            )

        evidence_hash = _canonical_hash(
            {
                "intent_hash": intent_hash,
                "execution_hash": execution_hash,
                "decision": decision,
                "checks": [check.model_dump() for check in checks],
            }
        )
        return AuditReceipt(
            receipt_id="rcpt_" + uuid.uuid4().hex[:12],
            intent_hash=intent_hash,
            intent_hash_kind="sha256-canonical-json",
            execution_hash=execution_hash,
            decision=decision,
            policy_checks=checks,
            tx_hash=tx_hash,
            evidence_hash=evidence_hash,
            timestamp=_utc_now().isoformat(),
            network="Sepolia simulation (chain ID 11155111)",
            attestation_status="READY_FOR_SEPOLIA",
        )

    def validate_signed(
        self,
        signed_intent: SignedPaymentIntent,
        execution: SignedProposedExecution,
        consume_nonce: bool = True,
    ) -> AuditReceipt:
        """Verify EIP-712 authorization before policy, binding, and replay checks."""
        intent = signed_intent.intent
        recovered = recover_signer(
            intent,
            signed_intent.signature,
            signed_intent.domain,
        )
        expected_signer = intent.payer.lower()
        domain_ok = domain_matches_expected(signed_intent.domain)
        signature_ok = recovered is not None
        signer_ok = signature_ok and recovered == expected_signer
        fresh = intent.expiry > int(_utc_now().timestamp())
        replay_key = f"{expected_signer}:{intent.nonce}"
        nonce_unused = replay_key not in self.used_nonces
        scope_matches = (
            execution.recipient.lower() == intent.recipient.lower()
            and execution.chain_id == intent.chain_id
            and execution.asset.upper() == intent.asset.upper()
        )
        resource_matches = execution.calldata_hash.lower() == intent.resource_hash.lower()

        checks = [
            PolicyCheck(
                code="DOMAIN_MATCH",
                label="EIP-712 domain separation",
                passed=domain_ok,
                detail="The signed domain matches IntentGuard Pay v1 on Sepolia."
                if domain_ok
                else "The supplied EIP-712 domain is not the expected application domain.",
            ),
            PolicyCheck(
                code="SIGNATURE_VALID",
                label="EIP-712 signature recovery",
                passed=signature_ok,
                detail="The signature is recoverable over the typed payment intent."
                if signature_ok
                else "The EIP-712 signature could not be recovered.",
            ),
            PolicyCheck(
                code="SIGNER_MATCH",
                label="Payer authorization",
                passed=bool(signer_ok),
                detail="The recovered signer matches the declared payer."
                if signer_ok
                else "The recovered signer does not match the declared payer.",
            ),
            PolicyCheck(
                code="CHAIN_ALLOWED",
                label="Approved network (intent)",
                passed=intent.chain_id in self.allowed_chain_ids,
                detail="Sepolia chain ID 11155111 is authorized."
                if intent.chain_id in self.allowed_chain_ids
                else "The requested chain is outside the authorization boundary.",
            ),
            PolicyCheck(
                code="TOKEN_ALLOWED",
                label="Approved asset (intent)",
                passed=intent.asset.upper() in self.allowed_tokens,
                detail="The asset is on the policy allowlist."
                if intent.asset.upper() in self.allowed_tokens
                else "The asset is not on the policy allowlist.",
            ),
            PolicyCheck(
                code="RECIPIENT_ALLOWED",
                label="Recipient allowlist (intent)",
                passed=intent.recipient.lower() in self.allowed_recipients,
                detail="Recipient is approved by the treasury policy."
                if intent.recipient.lower() in self.allowed_recipients
                else "Recipient is unknown or untrusted.",
            ),
            PolicyCheck(
                code="AMOUNT_WITHIN_INTENT",
                label="Amount ceiling",
                passed=execution.amount_wei <= intent.max_amount_wei,
                detail="Proposed amount stays within the authorized ceiling."
                if execution.amount_wei <= intent.max_amount_wei
                else "Proposed amount exceeds the authorized maximum.",
            ),
            PolicyCheck(
                code="EXECUTION_SCOPE_MATCH",
                label="Execution scope binding",
                passed=scope_matches,
                detail="Recipient, chain and asset match the signed intent envelope."
                if scope_matches
                else "Observed execution scope differs from the signed intent envelope.",
            ),
            PolicyCheck(
                code="RESOURCE_HASH_MATCH",
                label="Calldata commitment",
                passed=resource_matches,
                detail="The proposed calldata hash matches the signed resource commitment."
                if resource_matches
                else "Proposed calldata differs from the signed resource commitment.",
            ),
            PolicyCheck(
                code="EXECUTION_AMOUNT_EXACT",
                label="Exact amount binding",
                passed=execution.amount_wei == intent.amount_wei,
                detail="The executed amount exactly matches the signed amount."
                if execution.amount_wei == intent.amount_wei
                else "Executed amount differs from the signed amount.",
            ),
            PolicyCheck(
                code="INTENT_FRESH",
                label="Signed intent expiry",
                passed=fresh,
                detail="The signed intent is still valid."
                if fresh
                else "The signed intent has expired.",
            ),
            PolicyCheck(
                code="NONCE_UNUSED",
                label="Replay protection (process-local)",
                passed=nonce_unused,
                detail="Nonce has not been consumed."
                if nonce_unused
                else "Nonce was already consumed by an earlier execution.",
            ),
        ]

        decision = "DENY" if any(not check.passed for check in checks) else (
            "HUMAN_REVIEW"
            if execution.amount_wei > self.auto_approval_limit_wei
            else "AUTO_APPROVE"
        )
        digest = typed_data_digest(intent, signed_intent.domain)
        execution_hash = _canonical_hash(execution.model_dump(by_alias=True))

        tx_hash = None
        if decision == "AUTO_APPROVE":
            if consume_nonce:
                self.used_nonces.add(replay_key)
            tx_hash = _canonical_hash(
                {
                    "typed_data_digest": digest,
                    "execution_hash": execution_hash,
                    "nonce": intent.nonce,
                }
            )

        evidence_hash = _canonical_hash(
            {
                "typed_data_digest": digest,
                "execution_hash": execution_hash,
                "recovered_signer": recovered,
                "decision": decision,
                "checks": [check.model_dump() for check in checks],
            }
        )
        attestation_status = (
            "EIP712_VERIFIED"
            if decision == "AUTO_APPROVE"
            else "PENDING_REVIEW"
            if decision == "HUMAN_REVIEW"
            else "REJECTED"
        )
        return AuditReceipt(
            receipt_id="rcpt_" + uuid.uuid4().hex[:12],
            intent_hash=digest,
            intent_hash_kind="eip712-digest",
            execution_hash=execution_hash,
            decision=decision,
            policy_checks=checks,
            tx_hash=tx_hash,
            evidence_hash=evidence_hash,
            timestamp=_utc_now().isoformat(),
            network="Sepolia signed-intent simulation (chain ID 11155111)",
            attestation_status=attestation_status,
            typed_data_digest=digest,
            recovered_signer=recovered,
            signature_scheme="EIP-712/secp256k1",
        )


def _base_intent(nonce: str) -> PaymentIntent:
    return PaymentIntent(
        intent_id="intent_" + nonce[-6:],
        payer="0x2222222222222222222222222222222222222222",
        recipient="0x3333333333333333333333333333333333333333",
        chain_id=11155111,
        token="SEP",  # nosec B106 - asset symbol, not a password
        amount=0.008,
        max_amount=0.01,
        purpose="Purchase a verified research dataset for the AI agent",
        expiry=_future_expiry(),
        nonce=nonce,
        resource_hash="sha256:7f9b6d2f43a34c5d9a0c18b66a4c8aa9",
    )


def _timeline(receipt: AuditReceipt) -> List[Dict[str, str]]:
    allowed = receipt.decision != "DENY"
    return [
        {
            "stage": "01",
            "title": "Intent captured",
            "status": "PASS",
            "detail": "Payment request normalized into a machine-checkable envelope for the deterministic fixture path.",
        },
        {
            "stage": "02",
            "title": "Policy boundary",
            "status": "PASS" if allowed else "BLOCKED",
            "detail": "Deterministic controls evaluate recipient, value, network, expiry and nonce.",
        },
        {
            "stage": "03",
            "title": "Execution gate",
            "status": "PASS" if allowed else "NOT_EXECUTED",
            "detail": "Wallet execution is released only when the proposed call matches the intent.",
        },
        {
            "stage": "04",
            "title": "Evidence sealed",
            "status": "PASS",
            "detail": "Intent, execution and policy outcome are bound into an auditable evidence hash.",
        },
    ]


def run_demo(engine: IntentEngine, scenario_id: str) -> DemoResult:
    nonce = "nonce-" + scenario_id + "-001"
    intent = _base_intent(nonce)
    execution = ProposedExecution(
        recipient=intent.recipient,
        chain_id=intent.chain_id,
        token=intent.token,
        amount=intent.amount,
        calldata_hash="0x" + "34" * 32,
    )
    replay_receipt = None

    if scenario_id == "tampered":
        execution.recipient = "0x1111111111111111111111111111111111111111"
        execution.amount = 0.8
        title = "Prompt-injected payment"
        summary = "Recipient substitution and 100× amount escalation are blocked before wallet release."
    elif scenario_id == "replay":
        title = "Replay attempt"
        summary = "The first authorized payment consumes the in-memory nonce state; an identical second request is denied."
    elif scenario_id == "normal":
        title = "Authorized agent purchase"
        summary = "A bounded Sepolia payment passes intent, policy and execution-integrity checks."
    else:
        raise ValueError("Unknown scenario")

    receipt = engine.validate(
        intent,
        execution,
        consume_nonce=True,
        enabled_checks=INTENTGUARD_FULL_CHECKS,
    )
    if scenario_id == "replay":
        replay_receipt = engine.validate(
            intent,
            execution,
            consume_nonce=True,
            enabled_checks=INTENTGUARD_FULL_CHECKS,
        )
        final_receipt = replay_receipt
        decision = replay_receipt.decision
        policy_checks = replay_receipt.policy_checks
        timeline = _timeline(replay_receipt)
    else:
        final_receipt = receipt
        decision = receipt.decision
        policy_checks = receipt.policy_checks
        timeline = _timeline(receipt)

    return DemoResult(
        scenario_id=scenario_id,
        title=title,
        summary=summary,
        decision=decision,
        intent=intent,
        proposed_execution=execution,
        policy_checks=policy_checks,
        timeline=timeline,
        audit_receipt=final_receipt,
        replay_receipt=replay_receipt,
    )


# --------------------------
# Deterministic Benchmarking
# --------------------------


@dataclass(frozen=True)
class FixtureCase:
    case_id: str
    kind: str  # "legitimate" | "attack"
    intent_patch: Dict
    execution_patch: Dict
    replay: bool = False


CONTROL_DEFINITIONS: List[Dict] = [
    {
        "id": "intent-allowlists",
        "label": "Intent-time allowlists",
        "description": "Check that the *authorized envelope* targets an approved chain/token/recipient allowlist.",
        "check_codes": ["CHAIN_ALLOWED", "TOKEN_ALLOWED", "RECIPIENT_ALLOWED"],
    },
    {
        "id": "intent-max-amount",
        "label": "Intent-time amount ceiling",
        "description": "Enforce execution.amount ≤ intent.max_amount (bounded authorization).",
        "check_codes": ["AMOUNT_WITHIN_INTENT"],
    },
    {
        "id": "intent-expiry",
        "label": "Intent expiry",
        "description": "Enforce deadline/expiry on the authorization envelope.",
        "check_codes": ["INTENT_FRESH"],
    },
    {
        "id": "execution-scope-binding",
        "label": "Cross-layer intent→execution binding (scope)",
        "description": "Bind recipient/token/chain of execution to the authorized envelope (prevents TOCTOU scope substitution).",
        "check_codes": ["EXECUTION_SCOPE_MATCH"],
    },
    {
        "id": "execution-amount-exact",
        "label": "Cross-layer intent→execution binding (exact amount)",
        "description": "Bind the exact payment amount at execution time (dynamic-linking style).",
        "check_codes": ["EXECUTION_AMOUNT_EXACT"],
    },
    {
        "id": "replay-guard-process-local",
        "label": "Replay guard (process-local)",
        "description": "Consume-once semantics via an in-memory nonce registry (prototype scope: one process lifetime).",
        "check_codes": ["NONCE_UNUSED"],
    },
    {
        "id": "execution-policy-allowlists",
        "label": "Execution-time allowlists",
        "description": "Smart-account/module style policy that checks chain/token/recipient against allowlists at execution time.",
        "check_codes": ["EXEC_CHAIN_ALLOWED", "EXEC_TOKEN_ALLOWED", "EXEC_RECIPIENT_ALLOWED"],
    },
    {
        "id": "execution-policy-max-amount",
        "label": "Execution-time spend limit",
        "description": "Smart-account/module style per-call amount limit (independent of per-intent authorization).",
        "check_codes": ["EXEC_AMOUNT_WITHIN_POLICY"],
    },
]

_CONTROL_MAP = {item["id"]: set(item["check_codes"]) for item in CONTROL_DEFINITIONS}


def _resolve_check_codes(control_ids: List[str]) -> Set[str]:
    codes: Set[str] = set()
    for cid in control_ids:
        codes |= _CONTROL_MAP[cid]
    return codes


BASELINE_DEFINITIONS: List[Dict] = [
    {
        "id": "policy-gate-only",
        "label": "Policy gate only",
        "state_model": "stateless",
        "controls": ["intent-allowlists", "intent-max-amount", "intent-expiry"],
    },
    {
        "id": "smart-account-policy",
        "label": "Smart account policy only",
        "state_model": "stateless",
        "controls": ["execution-policy-allowlists", "execution-policy-max-amount"],
    },
    {
        "id": "stateless-intent-execution-binding",
        "label": "Stateless intent/execution binding",
        "state_model": "stateless",
        "controls": ["execution-scope-binding", "intent-max-amount", "intent-expiry"],
    },
    {
        "id": "intentguard-full",
        "label": "IntentGuard full",
        "state_model": "process-local",
        "controls": [
            "intent-allowlists",
            "intent-max-amount",
            "intent-expiry",
            "execution-scope-binding",
            "execution-amount-exact",
            "replay-guard-process-local",
        ],
    },
]


ABLATION_DEFINITIONS: List[Dict] = [
    {
        "id": "full_without_execution_binding",
        "label": "w/o Execution binding",
        "removed_control": "Execution binding (scope + exact)",
        "base": "intentguard-full",
        "controls": [
            "intent-allowlists",
            "intent-max-amount",
            "intent-expiry",
            "replay-guard-process-local",
        ],
    },
    {
        "id": "full_without_exact_amount_binding",
        "label": "w/o Exact amount binding",
        "removed_control": "Exact amount binding",
        "base": "intentguard-full",
        "controls": [
            "intent-allowlists",
            "intent-max-amount",
            "intent-expiry",
            "execution-scope-binding",
            "replay-guard-process-local",
        ],
    },
    {
        "id": "full_without_replay_guard",
        "label": "w/o Replay guard",
        "removed_control": "Process-local nonce registry",
        "base": "intentguard-full",
        "controls": [
            "intent-allowlists",
            "intent-max-amount",
            "intent-expiry",
            "execution-scope-binding",
            "execution-amount-exact",
        ],
    },
    {
        "id": "full_without_intent_allowlists",
        "label": "w/o Intent allowlists",
        "removed_control": "Intent-time allowlists",
        "base": "intentguard-full",
        "controls": [
            "intent-max-amount",
            "intent-expiry",
            "execution-scope-binding",
            "execution-amount-exact",
            "replay-guard-process-local",
        ],
    },
]


FIXTURES: List[FixtureCase] = [
    FixtureCase("legitimate-small", "legitimate", {}, {}),
    FixtureCase(
        "legitimate-large",
        "legitimate",
        {"amount": 0.04, "max_amount": 0.05},
        {"amount": 0.04},
    ),
    FixtureCase(
        "recipient-substitution-within-allowlist",
        "attack",
        {},
        {"recipient": "0x4444444444444444444444444444444444444444"},
    ),
    FixtureCase(
        "recipient-substitution-external",
        "attack",
        {},
        {"recipient": "0x1111111111111111111111111111111111111111"},
    ),
    FixtureCase("over-ceiling-amount", "attack", {"max_amount": 0.01}, {"amount": 0.011}),
    FixtureCase(
        "subtle-amount-mutation-within-ceiling",
        "attack",
        {"amount": 0.008, "max_amount": 0.01},
        {"amount": 0.009},
    ),
    FixtureCase("execution-chain-switch", "attack", {}, {"chain_id": 1}),
    FixtureCase("execution-token-switch", "attack", {}, {"token": "DAI"}),  # nosec B105 - token symbol, not a password
    FixtureCase("expired-intent", "attack", {"expiry": _past_expiry()}, {}),
    FixtureCase("replay-attempt", "attack", {}, {}, replay=True),
    FixtureCase(
        "unapproved-recipient-intent",
        "attack",
        {"recipient": "0xdeadbeef"},
        {"recipient": "0xdeadbeef"},
    ),
]


def _evaluate_profile(
    *,
    enabled_checks: Set[str],
    state_model: str,
    consume_nonce: bool,
) -> Tuple[Dict, List[Dict]]:
    outcomes: List[Dict] = []

    # process-local baseline keeps state across fixtures
    shared_engine = IntentEngine() if state_model == "process-local" else None

    for index, fixture in enumerate(FIXTURES):
        expected = "ALLOW" if fixture.kind == "legitimate" else "DENY"

        if fixture.replay:
            # Replay fixture uses the *same intent* twice.
            replay_intent = _base_intent("replay-nonce").model_copy(update=fixture.intent_patch)

            def _run_attempt(engine: IntentEngine) -> AuditReceipt:
                return engine.validate(
                    replay_intent,
                    ProposedExecution(
                        recipient=replay_intent.recipient,
                        chain_id=replay_intent.chain_id,
                        token=replay_intent.token,
                        amount=replay_intent.amount,
                        calldata_hash="0x" + "aa" * 32,
                    ),
                    consume_nonce=consume_nonce,
                    enabled_checks=enabled_checks,
                )

            if state_model == "process-local":
                engine = shared_engine
                _run_attempt(engine)
                receipt = _run_attempt(engine)
            else:
                # stateless baseline cannot carry consume-once authorization state
                _run_attempt(IntentEngine())
                receipt = _run_attempt(IntentEngine())
        else:
            engine = shared_engine if shared_engine is not None else IntentEngine()

            intent = _base_intent("bench-%02d" % index).model_copy(update=fixture.intent_patch)
            execution = ProposedExecution(
                recipient=intent.recipient,
                chain_id=intent.chain_id,
                token=intent.token,
                amount=intent.amount,
                calldata_hash="0x" + "56" * 32,
            ).model_copy(update=fixture.execution_patch)

            receipt = engine.validate(
                intent,
                execution,
                consume_nonce=consume_nonce,
                enabled_checks=enabled_checks,
            )

        blocked = receipt.decision == "DENY"
        correct = blocked if fixture.kind == "attack" else not blocked

        outcomes.append(
            {
                "case": fixture.case_id,
                "type": fixture.kind,
                "decision": receipt.decision,
                "expected": expected,
                "correct": correct,
            }
        )

    attack_rows = [row for row in outcomes if row["type"] == "attack"]
    benign_rows = [row for row in outcomes if row["type"] == "legitimate"]

    summary = {
        "attack_block_rate": round(
            100 * sum(row["correct"] for row in attack_rows) / len(attack_rows)
        )
        if attack_rows
        else 0,
        "benign_completion_rate": round(
            100 * sum(row["correct"] for row in benign_rows) / len(benign_rows)
        )
        if benign_rows
        else 0,
        "false_rejection_rate": round(
            100 * sum(not row["correct"] for row in benign_rows) / len(benign_rows)
        )
        if benign_rows
        else 0,
        "blocked_attacks": sum(row["correct"] for row in attack_rows),
        "total_attacks": len(attack_rows),
    }

    return summary, outcomes


def benchmark() -> Dict:
    started = time.perf_counter()

    baselines = []
    baseline_comparison = []

    # Compute baseline results
    for baseline in BASELINE_DEFINITIONS:
        enabled = _resolve_check_codes(baseline["controls"])
        consume_nonce = "NONCE_UNUSED" in enabled
        summary, _ = _evaluate_profile(
            enabled_checks=enabled,
            state_model=baseline["state_model"],
            consume_nonce=consume_nonce,
        )
        baselines.append(
            {
                "id": baseline["id"],
                "label": baseline["label"],
                "state_model": baseline["state_model"],
                "controls": baseline["controls"],
                "enabled_check_codes": sorted(enabled),
            }
        )
        baseline_comparison.append(
            {
                "mode": baseline["id"],
                "label": baseline["label"],
                **summary,
            }
        )

    # Compute full IntentGuard (for outcomes + ablation deltas)
    full = next(b for b in BASELINE_DEFINITIONS if b["id"] == "intentguard-full")
    full_enabled = _resolve_check_codes(full["controls"])
    full_consume_nonce = "NONCE_UNUSED" in full_enabled
    full_summary, full_outcomes = _evaluate_profile(
        enabled_checks=full_enabled,
        state_model=full["state_model"],
        consume_nonce=full_consume_nonce,
    )

    # Ablations
    ablations = []
    for ab in ABLATION_DEFINITIONS:
        enabled = _resolve_check_codes(ab["controls"])
        consume_nonce = "NONCE_UNUSED" in enabled
        summary, _ = _evaluate_profile(
            enabled_checks=enabled,
            state_model="process-local" if consume_nonce else "stateless",
            consume_nonce=consume_nonce,
        )
        ablations.append(
            {
                "mode": ab["id"],
                "label": ab["label"],
                "attack_block_rate": summary["attack_block_rate"],
                "delta_vs_full_pp": summary["attack_block_rate"] - full_summary["attack_block_rate"],
                "removed_control": ab["removed_control"],
            }
        )

    elapsed_ms = round((time.perf_counter() - started) * 1000, 3)

    return {
        "total_cases": len(FIXTURES),
        "attack_block_rate": full_summary["attack_block_rate"],
        "benign_completion_rate": full_summary["benign_completion_rate"],
        "false_rejection_rate": full_summary["false_rejection_rate"],
        "evaluation_time_ms": elapsed_ms,
        "methodology": {
            "benchmark_type": "Deterministic synthetic fixtures",
            "profile_scope": "Mechanism-level control baselines (not upstream projects)",
            "state_model": "In-memory engine; process-local replay state only when enabled",
            "network_scope": "Sepolia domain signing and read-only receipt checks; no transaction broadcast",
        },
        "control_definitions": CONTROL_DEFINITIONS,
        "baseline_definitions": baselines,
        "baseline_comparison": baseline_comparison,
        "ablations": ablations,
        "outcomes": full_outcomes,
        "limitations": [
            "The deterministic benchmark remains intentionally small (11 fixtures) and does not cover every payment threat.",
            "EIP-712 verification is implemented as a separate signed-intent path; the dashboard does not yet expose the wallet signing flow.",
            "Replay guard is process-local; no persistent used-intent registry is provided.",
            "Results are computed from local fixtures and property tests and should not be interpreted as external product scores.",
        ],
    }
