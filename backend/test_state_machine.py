"""State-machine properties for signed payment authorization.

The model generates operation sequences over a fixed pool of pre-signed intents.
Signatures are precomputed once so Hypothesis spends its budget exploring state
transitions (valid release, replay, drift, signature/domain mutation, and review)
rather than repeatedly performing setup cryptography.
"""

import os
from dataclasses import dataclass

from hypothesis import settings, strategies as st
from hypothesis.stateful import RuleBasedStateMachine, invariant, rule

from eip712 import EXPECTED_DOMAIN, SignedPaymentIntent, SignedProposedExecution
from intent_engine import AuditReceipt, IntentEngine
from test_eip712 import (
    TEST_PRIVATE_KEY,
    failed_codes,
    make_intent,
    matching_execution,
    sign_intent,
)


SECOND_PRIVATE_KEY = "0x" + "22" * 32
STATEFUL_EXAMPLES = int(os.getenv("HYPOTHESIS_STATEFUL_EXAMPLES", "200"))
STATEFUL_STEPS = int(os.getenv("HYPOTHESIS_STATEFUL_STEPS", "25"))


@dataclass(frozen=True)
class SignedCase:
    label: str
    signed: SignedPaymentIntent
    execution: SignedProposedExecution
    expected: str  # AUTO_APPROVE | HUMAN_REVIEW | DENY


def _case(
    label: str,
    *,
    nonce_byte: int,
    private_key: str = TEST_PRIVATE_KEY,
    amount_wei: int = 20_000_000_000_000_000,
    expiry: int = 1_893_456_000,
    expected: str = "AUTO_APPROVE",
) -> SignedCase:
    intent = make_intent(
        private_key=private_key,
        nonce="0x" + f"{nonce_byte:02x}" * 32,
        amount_wei=amount_wei,
        expiry=expiry,
    )
    return SignedCase(
        label=label,
        signed=sign_intent(intent, private_key=private_key),
        execution=matching_execution(intent),
        expected=expected,
    )


# Includes two payers sharing one nonce to exercise payer-scoped replay state.
CASES = (
    _case("payer-a-0", nonce_byte=0x40),
    _case("payer-a-1", nonce_byte=0x41),
    _case("payer-a-2", nonce_byte=0x42),
    _case(
        "payer-b-shared-nonce",
        nonce_byte=0x40,
        private_key=SECOND_PRIVATE_KEY,
    ),
    _case(
        "review-only",
        nonce_byte=0x43,
        amount_wei=60_000_000_000_000_000,
        expected="HUMAN_REVIEW",
    ),
    _case("expired", nonce_byte=0x44, expiry=1, expected="DENY"),
)
CASE_INDEX = st.integers(min_value=0, max_value=len(CASES) - 1)
BINDING_CODES = {
    "DOMAIN_MATCH",
    "SIGNATURE_VALID",
    "SIGNER_MATCH",
    "EXECUTION_SCOPE_MATCH",
    "RESOURCE_HASH_MATCH",
    "EXECUTION_AMOUNT_EXACT",
    "INTENT_FRESH",
    "NONCE_UNUSED",
}


class SignedReleaseStateMachine(RuleBasedStateMachine):
    """Model consume-as-commit over generated adversarial operation sequences."""

    def __init__(self) -> None:
        super().__init__()
        self.engine = IntentEngine()
        self.approvals: dict[tuple[str, str], int] = {}
        self.consumed: set[tuple[str, str]] = set()

    @staticmethod
    def _key(case: SignedCase) -> tuple[str, str]:
        intent = case.signed.intent
        return (intent.payer.lower(), intent.nonce)

    def _assert_auto_approve_safety(
        self,
        case: SignedCase,
        execution: SignedProposedExecution,
        receipt: AuditReceipt,
    ) -> None:
        if receipt.decision != "AUTO_APPROVE":
            return
        intent = case.signed.intent
        assert receipt.recovered_signer == intent.payer.lower()
        assert execution.recipient.lower() == intent.recipient.lower()
        assert execution.chain_id == intent.chain_id
        assert execution.asset.upper() == intent.asset.upper()
        assert execution.amount_wei == intent.amount_wei
        assert execution.calldata_hash.lower() == intent.resource_hash.lower()
        checks = {check.code: check.passed for check in receipt.policy_checks}
        assert all(checks.get(code, False) for code in BINDING_CODES)

    def _record_approval(
        self,
        case: SignedCase,
        execution: SignedProposedExecution,
        receipt: AuditReceipt,
    ) -> None:
        self._assert_auto_approve_safety(case, execution, receipt)
        if receipt.decision == "AUTO_APPROVE":
            key = self._key(case)
            self.approvals[key] = self.approvals.get(key, 0) + 1
            self.consumed.add(key)

    @rule(index=CASE_INDEX)
    def submit_canonical_execution(self, index: int) -> None:
        case = CASES[index]
        key = self._key(case)
        was_unused = self.engine.nonce_store.is_unused(*key)
        receipt = self.engine.validate_signed(case.signed, case.execution)
        self._record_approval(case, case.execution, receipt)

        if case.expected == "AUTO_APPROVE" and was_unused:
            assert receipt.decision == "AUTO_APPROVE"
        elif case.expected == "AUTO_APPROVE":
            assert receipt.decision == "DENY"
            assert "NONCE_UNUSED" in failed_codes(receipt)
        else:
            assert receipt.decision == case.expected
            assert self.engine.nonce_store.is_unused(*key) == was_unused

    @rule(index=CASE_INDEX, delta=st.integers(min_value=1, max_value=10**12))
    def submit_execution_drift(self, index: int, delta: int) -> None:
        case = CASES[index]
        key = self._key(case)
        was_unused = self.engine.nonce_store.is_unused(*key)
        drifted = case.execution.model_copy(
            update={"amount_wei": case.execution.amount_wei + delta}
        )
        receipt = self.engine.validate_signed(case.signed, drifted)

        assert receipt.decision == "DENY"
        assert "EXECUTION_AMOUNT_EXACT" in failed_codes(receipt)
        assert self.engine.nonce_store.is_unused(*key) == was_unused

    @rule(index=CASE_INDEX)
    def submit_wrong_domain(self, index: int) -> None:
        case = CASES[index]
        key = self._key(case)
        was_unused = self.engine.nonce_store.is_unused(*key)
        wrong_domain = EXPECTED_DOMAIN.model_copy(update={"version": "state-machine-v2"})
        changed = case.signed.model_copy(update={"domain": wrong_domain})
        receipt = self.engine.validate_signed(changed, case.execution)

        assert receipt.decision == "DENY"
        assert "DOMAIN_MATCH" in failed_codes(receipt)
        assert self.engine.nonce_store.is_unused(*key) == was_unused

    @rule(index=CASE_INDEX, delta=st.integers(min_value=1, max_value=10**12))
    def submit_post_signature_mutation(self, index: int, delta: int) -> None:
        case = CASES[index]
        key = self._key(case)
        was_unused = self.engine.nonce_store.is_unused(*key)
        intent = case.signed.intent
        mutated_intent = intent.model_copy(update={"amount_wei": intent.amount_wei + delta})
        mutated_signed = case.signed.model_copy(update={"intent": mutated_intent})
        mutated_execution = matching_execution(mutated_intent)
        receipt = self.engine.validate_signed(mutated_signed, mutated_execution)

        assert receipt.decision == "DENY"
        assert "SIGNER_MATCH" in failed_codes(receipt)
        assert self.engine.nonce_store.is_unused(*key) == was_unused

    @invariant()
    def every_authorization_is_approved_at_most_once(self) -> None:
        assert all(count <= 1 for count in self.approvals.values())

    @invariant()
    def model_and_nonce_store_agree(self) -> None:
        for case in CASES:
            key = self._key(case)
            assert self.engine.nonce_store.is_unused(*key) == (key not in self.consumed)


TestSignedReleaseStateMachine = SignedReleaseStateMachine.TestCase
TestSignedReleaseStateMachine.settings = settings(
    max_examples=STATEFUL_EXAMPLES,
    stateful_step_count=STATEFUL_STEPS,
    deadline=None,
)
