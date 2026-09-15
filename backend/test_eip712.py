import json
import os
import unittest
from pathlib import Path

from eth_account import Account
from hypothesis import given, settings, strategies as st
from pydantic import ValidationError

from eip712 import (
    EXPECTED_DOMAIN,
    EIP712Domain,
    EIP712PaymentIntent,
    SignedPaymentIntent,
    SignedProposedExecution,
    build_signable_message,
    recover_signer,
    typed_data_digest,
)
from intent_engine import IntentEngine


# Public deterministic test vector only. Never fund or reuse this key outside tests.
TEST_PRIVATE_KEY = "0x" + "11" * 32
TEST_ACCOUNT = Account.from_key(TEST_PRIVATE_KEY)
MAX_EXAMPLES = int(os.getenv("HYPOTHESIS_MAX_EXAMPLES", "1000"))
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def make_intent(
    *,
    private_key: str = TEST_PRIVATE_KEY,
    nonce: str = "0x" + "02" * 32,
    amount_wei: int = 20_000_000_000_000_000,
    expiry: int = 1_893_456_000,
) -> EIP712PaymentIntent:
    account = Account.from_key(private_key)
    return EIP712PaymentIntent(
        intentId="0x" + "01" * 32,
        payer=account.address,
        recipient="0x" + "33" * 20,
        chainId=11_155_111,
        asset="ETH",
        amountWei=amount_wei,
        maxAmountWei=amount_wei,
        purpose="Pay approved merchant",
        expiry=expiry,
        nonce=nonce,
        resourceHash="0x" + "03" * 32,
    )


def sign_intent(
    intent: EIP712PaymentIntent,
    *,
    private_key: str = TEST_PRIVATE_KEY,
    domain: EIP712Domain = EXPECTED_DOMAIN,
) -> SignedPaymentIntent:
    signature = Account.sign_message(
        build_signable_message(intent, domain), private_key=private_key
    ).signature.hex()
    return SignedPaymentIntent(
        domain=domain,
        intent=intent,
        signature="0x" + signature,
    )


def matching_execution(intent: EIP712PaymentIntent) -> SignedProposedExecution:
    return SignedProposedExecution(
        recipient=intent.recipient,
        chainId=intent.chain_id,
        asset=intent.asset,
        amountWei=intent.amount_wei,
        calldataHash=intent.resource_hash,
    )


def failed_codes(receipt) -> set[str]:
    return {check.code for check in receipt.policy_checks if not check.passed}


class EIP712GoldenVectorTest(unittest.TestCase):
    def test_python_matches_public_golden_vector(self):
        path = Path(__file__).parent.parent / "fixtures" / "eip712-golden-vector.json"
        vector = json.loads(path.read_text())
        intent = EIP712PaymentIntent(**vector["intent"])
        domain = EIP712Domain(**vector["domain"])

        self.assertEqual(typed_data_digest(intent, domain), vector["digest"])
        self.assertEqual(
            recover_signer(intent, vector["signature"], domain),
            vector["recoveredSigner"].lower(),
        )

    def test_valid_signed_intent_is_approved_and_consumed_once(self):
        engine = IntentEngine()
        intent = make_intent()
        signed = sign_intent(intent)
        execution = matching_execution(intent)

        first = engine.validate_signed(signed, execution)
        second = engine.validate_signed(signed, execution)

        self.assertEqual(first.decision, "AUTO_APPROVE")
        self.assertEqual(first.typed_data_digest, typed_data_digest(intent))
        self.assertEqual(first.recovered_signer, intent.payer)
        self.assertEqual(second.decision, "DENY")
        self.assertIn("NONCE_UNUSED", failed_codes(second))

    def test_nonce_is_scoped_to_payer(self):
        engine = IntentEngine()
        shared_nonce = "0x" + "07" * 32
        first = make_intent(private_key=TEST_PRIVATE_KEY, nonce=shared_nonce)
        second_key = "0x" + "22" * 32
        second = make_intent(private_key=second_key, nonce=shared_nonce)

        first_receipt = engine.validate_signed(
            sign_intent(first), matching_execution(first)
        )
        second_receipt = engine.validate_signed(
            sign_intent(second, private_key=second_key), matching_execution(second)
        )

        self.assertEqual(first_receipt.decision, "AUTO_APPROVE")
        self.assertEqual(second_receipt.decision, "AUTO_APPROVE")

    def test_malformed_signature_is_rejected_at_schema_boundary(self):
        with self.assertRaises(ValidationError):
            SignedPaymentIntent(
                domain=EXPECTED_DOMAIN,
                intent=make_intent(),
                signature="0x1234",
            )


class SignedIntentProperties(unittest.TestCase):
    @settings(max_examples=MAX_EXAMPLES, deadline=None)
    @given(
        private_key_int=st.integers(min_value=1, max_value=SECP256K1_N - 1),
        amount_wei=st.integers(min_value=1, max_value=50_000_000_000_000_000),
        nonce_bytes=st.binary(min_size=32, max_size=32),
    )
    def test_valid_signed_intent_completes(
        self, private_key_int: int, amount_wei: int, nonce_bytes: bytes
    ):
        private_key = "0x" + private_key_int.to_bytes(32, "big").hex()
        intent = make_intent(
            private_key=private_key,
            amount_wei=amount_wei,
            nonce="0x" + nonce_bytes.hex(),
        )
        receipt = IntentEngine().validate_signed(
            sign_intent(intent, private_key=private_key),
            matching_execution(intent),
        )
        self.assertEqual(receipt.decision, "AUTO_APPROVE")
        self.assertEqual(receipt.recovered_signer, intent.payer)

    @settings(max_examples=MAX_EXAMPLES, deadline=None)
    @given(delta=st.integers(min_value=1, max_value=10**12))
    def test_signed_amount_mutation_is_rejected(self, delta: int):
        original = make_intent()
        signed = sign_intent(original)
        tampered = original.model_copy(update={"amount_wei": original.amount_wei + delta})
        tampered_signed = signed.model_copy(update={"intent": tampered})

        receipt = IntentEngine().validate_signed(
            tampered_signed,
            matching_execution(tampered),
        )
        self.assertEqual(receipt.decision, "DENY")
        self.assertIn("SIGNER_MATCH", failed_codes(receipt))

    @settings(max_examples=MAX_EXAMPLES, deadline=None)
    @given(field_name=st.sampled_from(["recipient", "asset", "expiry", "nonce", "resource_hash"]))
    def test_any_signed_field_mutation_is_rejected(self, field_name: str):
        original = make_intent()
        signed = sign_intent(original)
        mutations = {
            "recipient": "0x" + "44" * 20,
            "asset": "USDC",
            "expiry": original.expiry + 1,
            "nonce": "0x" + "05" * 32,
            "resource_hash": "0x" + "06" * 32,
        }
        tampered = original.model_copy(update={field_name: mutations[field_name]})
        receipt = IntentEngine().validate_signed(
            signed.model_copy(update={"intent": tampered}),
            matching_execution(tampered),
        )
        self.assertEqual(receipt.decision, "DENY")
        self.assertIn("SIGNER_MATCH", failed_codes(receipt))

    @settings(max_examples=MAX_EXAMPLES, deadline=None)
    @given(private_key_int=st.integers(min_value=2, max_value=SECP256K1_N - 1))
    def test_wrong_signer_is_rejected(self, private_key_int: int):
        wrong_key = "0x" + private_key_int.to_bytes(32, "big").hex()
        if Account.from_key(wrong_key).address.lower() == TEST_ACCOUNT.address.lower():
            self.skipTest("Generated the fixed test signer")
        intent = make_intent()
        receipt = IntentEngine().validate_signed(
            sign_intent(intent, private_key=wrong_key),
            matching_execution(intent),
        )
        self.assertEqual(receipt.decision, "DENY")
        self.assertIn("SIGNER_MATCH", failed_codes(receipt))

    @settings(max_examples=MAX_EXAMPLES, deadline=None)
    @given(version=st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=1, max_size=8).filter(lambda value: value != "1"))
    def test_domain_separation_rejects_modified_version(self, version: str):
        intent = make_intent()
        signed = sign_intent(intent)
        changed_domain = EXPECTED_DOMAIN.model_copy(update={"version": version})
        receipt = IntentEngine().validate_signed(
            signed.model_copy(update={"domain": changed_domain}),
            matching_execution(intent),
        )
        self.assertEqual(receipt.decision, "DENY")
        self.assertIn("DOMAIN_MATCH", failed_codes(receipt))

    @settings(max_examples=MAX_EXAMPLES, deadline=None)
    @given(delta=st.integers(min_value=1, max_value=10**12))
    def test_failed_execution_does_not_consume_nonce(self, delta: int):
        engine = IntentEngine()
        intent = make_intent()
        signed = sign_intent(intent)
        bad_execution = matching_execution(intent).model_copy(
            update={"amount_wei": intent.amount_wei + delta}
        )

        rejected = engine.validate_signed(signed, bad_execution)
        accepted = engine.validate_signed(signed, matching_execution(intent))

        self.assertEqual(rejected.decision, "DENY")
        self.assertEqual(accepted.decision, "AUTO_APPROVE")

    @settings(max_examples=MAX_EXAMPLES, deadline=None)
    @given(amount_wei=st.integers(min_value=50_000_000_000_000_001, max_value=10**19))
    def test_human_review_does_not_consume_nonce(self, amount_wei: int):
        engine = IntentEngine()
        intent = make_intent(amount_wei=amount_wei)
        signed = sign_intent(intent)
        execution = matching_execution(intent)

        first = engine.validate_signed(signed, execution)
        second = engine.validate_signed(signed, execution)

        self.assertEqual(first.decision, "HUMAN_REVIEW")
        self.assertEqual(second.decision, "HUMAN_REVIEW")
        self.assertIsNone(first.tx_hash)
        self.assertTrue(engine.nonce_store.is_unused(intent.payer, intent.nonce))

    @settings(max_examples=MAX_EXAMPLES, deadline=None)
    @given(
        field_name=st.sampled_from(["recipient", "chain_id", "asset", "amount_wei", "calldata_hash"]),
        delta=st.integers(min_value=1, max_value=10**12),
    )
    def test_execution_drift_is_rejected(self, field_name: str, delta: int):
        intent = make_intent()
        signed = sign_intent(intent)
        mutations = {
            "recipient": "0x" + f"{delta % (1 << 160):040x}",
            "chain_id": 11_155_111 + delta,
            "asset": f"TOKEN{delta}",
            "amount_wei": intent.amount_wei + delta,
            "calldata_hash": "0x" + f"{delta % (1 << 256):064x}",
        }
        execution = matching_execution(intent).model_copy(
            update={field_name: mutations[field_name]}
        )
        receipt = IntentEngine().validate_signed(signed, execution)
        self.assertEqual(receipt.decision, "DENY")
        self.assertTrue(
            {"EXECUTION_SCOPE_MATCH", "EXECUTION_AMOUNT_EXACT", "RESOURCE_HASH_MATCH"}
            & failed_codes(receipt)
        )

    @settings(max_examples=MAX_EXAMPLES, deadline=None)
    @given(mixed_case=st.booleans())
    def test_address_representation_is_normalized(self, mixed_case: bool):
        intent = make_intent()
        recipient = Account.from_key(TEST_PRIVATE_KEY).address if mixed_case else intent.recipient
        if mixed_case:
            intent = intent.model_copy(update={"recipient": recipient.lower()})
            signed = sign_intent(intent)
            execution = matching_execution(intent).model_copy(update={"recipient": recipient})
            engine = IntentEngine()
            engine.allowed_recipients = {recipient.lower()}
        else:
            signed = sign_intent(intent)
            execution = matching_execution(intent)
            engine = IntentEngine()

        receipt = engine.validate_signed(signed, execution)
        self.assertEqual(receipt.decision, "AUTO_APPROVE")
