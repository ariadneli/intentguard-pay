# PAACT-Core v1: Payment-Authorization Attack Corpus

## Purpose

PAACT-Core is a deterministic mutation corpus for comparing IntentGuard's existing **mechanism-level profiles** on a common workload. It expands the historical 11-fixture regression suite without changing those historical results. The corpus is author-generated and is not presented as a standard benchmark, an incident dataset, or a reproduction of named external systems.

## Reproduction

```bash
cd backend
python generate_attack_corpus.py
```

Default seed: `20260916`.

Generated artifacts:

- `fixtures/paact-core-v1.jsonl` — 1,000 self-describing cases.
- `docs/research-v3/paact-core-v1-results.json` — full overall/family/operator metrics.
- `docs/research-v3/paact-core-v1-results.md` — compact comparison tables.

The same seed and generator version produce byte-stable corpus ordering and content.

## Corpus composition

| Generator bucket | Taxonomy family | Cases | Representative mutation |
|---|---|---:|---|
| benign | benign | 80 | ordinary valid, alternate allowed scope, exact ceiling boundary |
| recipient_in_allowlist | recipient | 100 | execution recipient changed to another allowed recipient |
| recipient_external | recipient | 100 | execution recipient changed outside the allowlist |
| amount_within_ceiling | amount | 120 | exact amount drift that remains below `max_amount` |
| amount_over_ceiling | amount | 120 | execution exceeds intent ceiling, with/without crossing execution policy limit |
| chain_switch | chain | 100 | execution moved to a different chain |
| asset_switch | asset | 100 | execution asset substituted |
| expired_intent | expiry | 80 | stale authorization reused |
| replay | replay | 100 | identical payer-scoped nonce submitted twice |
| policy_allowlist | policy | 50 | intent and execution agree on an unapproved recipient |
| compositional | compositional | 50 | two or three simultaneous scope/amount mutations |
| **Total** |  | **1,000** | **920 attacks + 80 benign** |

Each record includes:

```json
{
  "schema_version": "paact-core-v1",
  "seed": 20260916,
  "case_id": "amount-within-ceiling-0001",
  "kind": "attack",
  "family": "amount",
  "mutation_operator": "exact_amount_drift_within_ceiling",
  "severity": "high",
  "intent_patch": {},
  "execution_patch": {},
  "replay": false,
  "expected_decision": "DENY"
}
```

## Evaluation protocol

Every profile in `BASELINE_DEFINITIONS` receives the identical ordered corpus. The evaluator reports:

- attack block rate (ABR);
- benign completion rate (BCR);
- false rejection rate (FRR);
- blocked/total counts;
- 95% Wilson score intervals;
- breakdowns by mutation family and operator.

The profiles remain mechanism abstractions:

- `policy-gate-only`;
- `smart-account-policy`;
- `stateless-intent-execution-binding`;
- `intentguard-full`.

They are not branded-product reproductions. Wilson intervals describe uncertainty for this finite generated corpus; they do not estimate real-world attack prevalence.

## Mutation validity controls

The generator prevents common evaluation errors:

1. every case has a unique stable `case_id` and payer nonce through the runner;
2. benign cases remain inside chain, asset, recipient, amount, and freshness policy;
3. exact-amount drift remains positive and differs from the authorized amount;
4. over-ceiling cases always exceed the generated intent ceiling;
5. replay cases reuse the identical authorization exactly twice;
6. compositional cases contain at least two independently meaningful mutations;
7. generated order is shuffled only by a local fixed-seed RNG.

## Scope boundary

PAACT-Core v1 covers the dimensions representable by the historical unsigned mechanism runner: intent allowlists, recipient/chain/asset execution binding, exact amount, authorization ceiling, expiry, replay, compositional mutations, and benign boundaries.

It deliberately excludes:

- EIP-712 signer and domain mutation, which remain covered by the signed property/state-machine suite;
- semantic equivalence of arbitrary calldata, because the prototype models only a hash commitment;
- prompt-injection provenance and natural-language intent extraction;
- distributed nonce consensus;
- atomic coupling to an external wallet broadcast;
- observed fraud prevalence or user usability.

A later external corpus can preserve this JSONL contract while adding provenance, source references, semantic contract-call labels, and held-out incident-derived cases.
