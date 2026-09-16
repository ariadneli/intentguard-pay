# IntentGuard Pay — Final Research Version

**Repository:** https://github.com/ariadneli/intentguard-pay  
**Live demo:** https://intentguard-pay.netlify.app/

IntentGuard Pay is a public, self-contained research prototype for deterministic authorization around agentic payments. It studies whether an autonomous payment planner can remain useful when money only moves after a separate, machine-checkable layer validates a signed payment envelope, binds it to the proposed execution, consumes replay state, and emits auditable evidence.

This repository is the **final course research version**. Earlier public-demo and intermediate research versions are historical only.

## What is included

- React + TypeScript + Vite dashboard for the public demo.
- FastAPI backend with deterministic authorization checks.
- EIP-712 signed `PaymentIntent` verification path with signer recovery and domain separation.
- Payer-scoped replay protection with in-memory and SQLite nonce-store implementations.
- PAACT-Core v1: a deterministic 1,000-case payment-authorization mutation corpus.
- Mechanism-level baseline matrix, family/operator breakdown, Wilson intervals, property/state-machine tests, and overhead/replay experiments.

## Research question

> Can a deterministic authorization boundary prevent agentic payment execution from drifting away from what the user authorized, while preserving benign completion?

The project focuses on the gap between:

1. what the user meant to authorize,
2. what an agent proposes,
3. what a wallet signs or releases,
4. what the chain records, and
5. what an auditor can reconstruct later.

## Core mechanism

IntentGuard validates an explicit payment authorization before release:

1. Recover the signer from EIP-712 typed data.
2. Check the expected signing domain.
3. Enforce intent-time policy: chain, asset, recipient, amount ceiling, expiry.
4. Bind proposed execution to the signed intent: recipient, chain, asset, amount, calldata/resource commitment.
5. Consume a payer-scoped nonce at the release commit point.
6. Emit evidence for later reconstruction.

## PAACT-Core v1 evaluation

PAACT-Core v1 is a fixed-seed, author-generated corpus with:

- **1,000 total cases**
- **920 attacks** across eight mutation families
- **80 benign boundary cases**

The attack families are:

- recipient mutation
- amount mutation
- chain mutation
- asset mutation
- expiry mutation
- replay
- unauthorized intent policy
- compositional mutation

### Overall mechanism-profile results

| Profile | Attack block rate | 95% Wilson CI | Benign completion | False rejection |
|---|---:|---:|---:|---:|
| `policy-gate-only` | 27.17% (250/920) | [24.40, 30.14] | 100% | 0% |
| `smart-account-policy` | 50.00% (460/920) | [46.78, 53.22] | 100% | 0% |
| `stateless-intent-execution-binding` | 70.65% (650/920) | [67.63, 73.50] | 100% | 0% |
| `intentguard-full` | 100.00% (920/920) | [99.58, 100] | 100% | 0% |

Interpretation boundary: these profiles are mechanism-level control combinations implemented in this repository. They are not product-level scores for external systems, and PAACT-Core v1 is not a real-world attack-prevalence estimate.

## Reproducibility

### Frontend demo

```bash
npm install
npm run build
npm run dev
```

Optional public configuration:

```bash
cp .env.example .env.local
# edit VITE_SEPOLIA_RPC_URL if you want another public Sepolia RPC endpoint
```

### Backend tests

```bash
cd backend
python -m pip install -r requirements-dev.txt
HYPOTHESIS_MAX_EXAMPLES=1000 HYPOTHESIS_STATEFUL_EXAMPLES=200 HYPOTHESIS_STATEFUL_STEPS=25 python -m unittest discover -v
PORT=8000 python main.py
```

### Regenerate PAACT-Core v1

```bash
cd backend
python generate_attack_corpus.py
```

Generated outputs:

- `fixtures/paact-core-v1.jsonl`
- `docs/research-final/paact-core-v1-results.json`
- `docs/research-final/paact-core-v1-results.md`

## Replay-store configuration

By default, the demo uses in-memory replay state. To use the durable SQLite store:

```bash
export INTENTGUARD_NONCE_STORE=sqlite
export INTENTGUARD_NONCE_SQLITE_PATH=/tmp/intentguard_nonces.sqlite3
PORT=8000 python backend/main.py
```

The SQLite implementation uses an atomic `(payer, nonce)` uniqueness constraint as the consume-as-commit point. Tests cover restart, thread, and spawned-process replay races under a shared SQLite database.

## What this project does not claim

IntentGuard Pay does **not** claim:

- production wallet security;
- private-key custody;
- transaction broadcast or real fund movement;
- real-world attack prevalence;
- superiority over external products;
- a community-standard benchmark;
- distributed replay consensus;
- full semantic calldata interpretation;
- on-chain smart-account enforcement.

It is a bounded research artifact for studying authorization preservation in agentic payments.

## Repository map

```text
backend/
  intent_engine.py             # deterministic authorization engine and API benchmark
  eip712.py                    # signed PaymentIntent validation
  nonce_store.py               # in-memory and SQLite nonce stores
  attack_corpus.py             # PAACT-Core generator/evaluator
  generate_attack_corpus.py    # corpus/result regeneration CLI
  test_*.py                    # unit, property, state-machine, replay, and corpus tests
fixtures/
  paact-core-v1.jsonl          # fixed-seed corpus
src/
  components/                  # dashboard UI
  lib/demo.ts                  # local self-contained demo/evaluation data
  lib/eip712.ts                # TypeScript EIP-712 helpers
docs/
  research-final/              # PAACT-Core design and results
```
