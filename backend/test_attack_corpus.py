import json
import tempfile
import unittest
from pathlib import Path

from attack_corpus import (
    DEFAULT_COUNTS,
    DEFAULT_SEED,
    SCHEMA_VERSION,
    evaluate_corpus,
    fixture_to_record,
    generate_corpus,
    load_corpus_jsonl,
    wilson_interval,
    write_corpus_jsonl,
)


class AttackCorpusTest(unittest.TestCase):
    def test_default_corpus_is_deterministic_balanced_and_unique(self):
        manifest_a, cases_a = generate_corpus(seed=DEFAULT_SEED)
        manifest_b, cases_b = generate_corpus(seed=DEFAULT_SEED)

        self.assertEqual(manifest_a, manifest_b)
        self.assertEqual(cases_a, cases_b)
        self.assertEqual(manifest_a.schema_version, SCHEMA_VERSION)
        self.assertEqual(manifest_a.total_cases, 1000)
        self.assertEqual(sum(DEFAULT_COUNTS.values()), 1000)
        self.assertEqual(len({case.case_id for case in cases_a}), 1000)
        self.assertEqual(sum(case.kind == "attack" for case in cases_a), 920)
        self.assertEqual(sum(case.kind == "legitimate" for case in cases_a), 80)

        manifest_c, cases_c = generate_corpus(seed=DEFAULT_SEED + 1)
        self.assertEqual(manifest_c.total_cases, manifest_a.total_cases)
        self.assertNotEqual(cases_c, cases_a)

    def test_jsonl_round_trip_preserves_cases(self):
        manifest, cases = generate_corpus(seed=DEFAULT_SEED)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "corpus.jsonl"
            write_corpus_jsonl(path, manifest, cases)
            loaded_manifest, loaded_cases = load_corpus_jsonl(path)

        self.assertEqual(loaded_manifest.schema_version, manifest.schema_version)
        self.assertEqual(loaded_manifest.seed, manifest.seed)
        self.assertEqual(loaded_manifest.total_cases, manifest.total_cases)
        self.assertEqual(loaded_manifest.counts, manifest.counts)
        self.assertEqual(loaded_cases, cases)

    def test_record_schema_is_self_describing(self):
        manifest, cases = generate_corpus(
            counts={key: (1 if key == "replay" else 0) for key in DEFAULT_COUNTS}
        )
        record = fixture_to_record(cases[0], seed=manifest.seed)
        self.assertEqual(record["schema_version"], SCHEMA_VERSION)
        self.assertEqual(record["expected_decision"], "DENY")
        json.dumps(record)

    def test_every_baseline_consumes_same_corpus_and_full_blocks_all(self):
        manifest, cases = generate_corpus(seed=DEFAULT_SEED)
        report = evaluate_corpus(manifest, cases)

        totals = {row["overall"]["total"] for row in report["baseline_results"]}
        self.assertEqual(totals, {manifest.total_cases})
        full = next(row for row in report["baseline_results"] if row["mode"] == "intentguard-full")
        self.assertEqual(full["overall"]["attack_block_rate"], 100.0)
        self.assertEqual(full["overall"]["benign_completion_rate"], 100.0)
        self.assertEqual(full["overall"]["false_rejection_rate"], 0.0)
        self.assertEqual(set(full["by_family"]), {
            "amount",
            "asset",
            "benign",
            "chain",
            "compositional",
            "expiry",
            "policy",
            "recipient",
            "replay",
        })

    def test_wilson_interval_is_bounded_and_non_degenerate(self):
        low, high = wilson_interval(920, 920)
        self.assertGreater(low, 99.0)
        self.assertEqual(high, 100.0)
        self.assertEqual(wilson_interval(0, 0), (0.0, 0.0))


if __name__ == "__main__":
    unittest.main()
