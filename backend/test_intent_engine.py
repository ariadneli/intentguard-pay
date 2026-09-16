import unittest

from intent_engine import IntentEngine, benchmark, run_demo


class IntentEngineTest(unittest.TestCase):
    def setUp(self):
        self.engine = IntentEngine()

    def test_normal_payment_is_approved(self):
        result = run_demo(self.engine, "normal")
        self.assertEqual(result.decision, "AUTO_APPROVE")
        self.assertIsNotNone(result.audit_receipt.tx_hash)
        self.assertTrue(all(check.passed for check in result.policy_checks))

    def test_tampered_payment_is_denied(self):
        result = run_demo(self.engine, "tampered")
        failed_codes = {check.code for check in result.policy_checks if not check.passed}

        self.assertEqual(result.decision, "DENY")
        # Recipient substitution + amount escalation should fail both ceiling + binding.
        self.assertIn("AMOUNT_WITHIN_INTENT", failed_codes)
        self.assertIn("EXECUTION_SCOPE_MATCH", failed_codes)
        self.assertIn("EXECUTION_AMOUNT_EXACT", failed_codes)
        self.assertIsNone(result.audit_receipt.tx_hash)

    def test_replay_is_denied(self):
        result = run_demo(self.engine, "replay")
        failed_codes = {check.code for check in result.policy_checks if not check.passed}

        self.assertEqual(result.decision, "DENY")
        self.assertIn("NONCE_UNUSED", failed_codes)
        self.assertIsNotNone(result.replay_receipt)

    def test_benchmark_comparative_logic(self):
        result = benchmark()

        # 1. Assert full mode performance
        self.assertEqual(result["total_cases"], 1000)
        self.assertEqual(result["attack_block_rate"], 100)
        self.assertEqual(result["benign_completion_rate"], 100)
        self.assertEqual(result["false_rejection_rate"], 0)
        self.assertEqual(result["schema_version"], "paact-core-v1")

        # 2. Assert baseline differentiation (mechanism-level, not project labels)
        comp_by_mode = {row["mode"]: row for row in result["baseline_comparison"]}
        for mode in [
            "policy-gate-only",
            "smart-account-policy",
            "stateless-intent-execution-binding",
            "intentguard-full",
        ]:
            self.assertIn(mode, comp_by_mode)

        self.assertEqual(comp_by_mode["intentguard-full"]["attack_block_rate"], 100)

        # Binding should outperform a pure policy gate on substitution/TOCTOU fixtures.
        self.assertGreater(
            comp_by_mode["stateless-intent-execution-binding"]["attack_block_rate"],
            comp_by_mode["policy-gate-only"]["attack_block_rate"],
        )

        # Full should be strictly better or equal to all baselines.
        for mode, row in comp_by_mode.items():
            self.assertGreaterEqual(result["attack_block_rate"], row["attack_block_rate"])

        # 3. Assert ablation impact
        ab_by_mode = {row["mode"]: row for row in result["ablations"]}
        self.assertIn("full_without_execution_binding", ab_by_mode)
        self.assertIn("full_without_exact_amount_binding", ab_by_mode)
        self.assertIn("full_without_replay_guard", ab_by_mode)
        self.assertIn("full_without_intent_allowlists", ab_by_mode)

        # All ablations should not exceed full.
        for row in result["ablations"]:
            self.assertLessEqual(row["delta_vs_full_pp"], 0)

    def test_benchmark_determinism(self):
        r1 = benchmark()
        r2 = benchmark()

        # Ignore runtime-dependent field.
        r1.pop("evaluation_time_ms")
        r2.pop("evaluation_time_ms")

        self.assertEqual(r1, r2)


if __name__ == "__main__":
    unittest.main()
