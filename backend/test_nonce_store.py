import json
import os
import tempfile
import unittest
from pathlib import Path

from eip712 import EIP712Domain, EIP712PaymentIntent, SignedPaymentIntent, SignedProposedExecution
from intent_engine import IntentEngine
from nonce_store import SQLiteNonceStore


class DurableNonceStoreTest(unittest.TestCase):
    def test_replay_is_denied_after_engine_restart_with_sqlite_store(self):
        vector_path = Path(__file__).resolve().parent.parent / "fixtures" / "eip712-golden-vector.json"
        payload = json.loads(vector_path.read_text(encoding="utf-8"))

        intent = EIP712PaymentIntent(**payload["intent"])
        domain = EIP712Domain(**payload["domain"])
        signed = SignedPaymentIntent(intent=intent, domain=domain, signature=payload["signature"])
        execution = SignedProposedExecution(
            recipient=intent.recipient,
            chainId=intent.chain_id,
            asset=intent.asset,
            amountWei=intent.amount_wei,
            calldataHash=intent.resource_hash,
        )

        tmp = tempfile.NamedTemporaryFile(prefix="intentguard_nonces_", suffix=".sqlite3", delete=False)
        tmp.close()
        try:
            store1 = SQLiteNonceStore(tmp.name)
            engine1 = IntentEngine(nonce_store=store1)
            first = engine1.validate_signed(signed, execution)
            self.assertEqual(first.decision, "AUTO_APPROVE")

            # Simulate a restart: new engine instance, new SQLite connection, same file.
            store2 = SQLiteNonceStore(tmp.name)
            engine2 = IntentEngine(nonce_store=store2)
            second = engine2.validate_signed(signed, execution)
            self.assertEqual(second.decision, "DENY")
            failed = {c.code for c in second.policy_checks if not c.passed}
            self.assertIn("NONCE_UNUSED", failed)
        finally:
            os.unlink(tmp.name)
