import json
import os
import tempfile
import threading
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

    def test_concurrent_validation_consumes_nonce_atomically_under_sqlite(self):
        """Regression test: avoid TOCTOU where two replicas both approve the same nonce."""

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

        tmp = tempfile.NamedTemporaryFile(prefix="intentguard_nonces_conc_", suffix=".sqlite3", delete=False)
        tmp.close()
        try:
            engine1 = IntentEngine(nonce_store=SQLiteNonceStore(tmp.name))
            engine2 = IntentEngine(nonce_store=SQLiteNonceStore(tmp.name))

            barrier = threading.Barrier(2)
            receipts = []
            lock = threading.Lock()

            def _run(engine: IntentEngine) -> None:
                barrier.wait()
                r = engine.validate_signed(signed, execution)
                with lock:
                    receipts.append(r)

            t1 = threading.Thread(target=_run, args=(engine1,))
            t2 = threading.Thread(target=_run, args=(engine2,))
            t1.start()
            t2.start()
            t1.join(timeout=5)
            t2.join(timeout=5)

            decisions = sorted(r.decision for r in receipts)
            self.assertEqual(decisions, ["AUTO_APPROVE", "DENY"])

            denied = next(r for r in receipts if r.decision == "DENY")
            failed = {c.code for c in denied.policy_checks if not c.passed}
            self.assertIn("NONCE_UNUSED", failed)
        finally:
            os.unlink(tmp.name)
