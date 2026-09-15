# IntentGuard Pay

**Repository:** https://github.com/ariadneli/intentguard-pay

**Live demo:** https://intentguard-pay.netlify.app/

IntentGuard Pay is a public, self-contained research prototype for deterministic authorization around agentic payments. It asks whether an autonomous payment planner can remain useful when money only moves after a separate, machine-checkable layer validates a declared payment envelope, matches the proposed execution, and emits auditable evidence.

The repository contains:

- A React + TypeScript + Vite dashboard with deterministic fixture runs and a read-only Sepolia receipt verifier.
- A FastAPI backend with EIP-712 signer recovery, deterministic authorization checks, and benchmark endpoints.
- A shared TypeScript/Python EIP-712 golden vector.
- Unit and Hypothesis property tests for signed-intent integrity, domain separation, execution drift, replay handling, and state isolation.

## Research question

**Can deterministic intent validation prevent unauthorized agentic payments without blocking legitimate autonomy?**

IntentGuard studies a narrow boundary: the agent may plan a payment, but execution is released only if the proposed call stays within an authorized envelope and deterministic policy checks. The prototype is designed to clarify what this layer can prove, and what it cannot.

## Threat model

### In scope

- **Model/tool misuse:** prompt injection, excessive agency, or confused-deputy behavior can cause an agent to propose a syntactically valid but semantically unauthorized payment. See [OWASP Prompt Injection](https://owasp.org/www-community/attacks/PromptInjection), [OWASP LLM Top 10 2025 / LLM06 Excessive Agency](https://owasp.org/www-project-top-10-for-large-language-model-applications/assets/PDF/OWASP-Top-10-for-LLMs-v2025.pdf), and [Intent-Governed Tool Authorization for AI Agents](https://arxiv.org/abs/2606.22916).
- **Authorization mismatch:** recipient substitution, amount escalation, chain/token switching, expiry abuse, and replay against a previously authorized payment envelope. See the [OWASP Transaction Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transaction_Authorization_Cheat_Sheet.html).
- **Execution/evidence mismatch:** a receipt can confirm that something executed on-chain, but not by itself prove why it was authorized. See [Ethereum JSON-RPC receipts](https://ethereum.org/en/developers/docs/apis/json-rpc/#eth_gettransactionreceipt).

### Out of scope

- Compromised private keys, compromised wallet binaries, or malicious browser extensions.
- Production custody, treasury operations, or real-fund settlement.
- Chain-level consensus failures, reorg handling beyond the read-only verifier's receipt checks, or malicious RPC infrastructure.
- The prototype focuses on deterministic validation for the stated payment threat model; it does not claim exhaustive production-wallet coverage.

## Defense landscape / related work

### Structured signing and readable review

- [EIP-712](https://eips.ethereum.org/EIPS/eip-712) standardizes typed structured signing and domain separation, which helps wallets render what is being authorized. However, the standard explicitly does **not** provide replay protection.
- [EIP-2612](https://eips.ethereum.org/EIPS/eip-2612) shows the usual pattern: typed signing becomes useful only when the application also tracks nonce and deadline state.
- Wallet review systems such as [Rabby transaction simulation](https://support.rabby.io/en/articles/14124199-understanding-rabby-s-transaction-simulation) and [Tenderly Transaction Preview](https://docs.tenderly.co/simulations/transaction-preview) improve pre-sign human inspection, but preview is not the same as execution-time enforcement.

### Smart accounts and on-chain policy

- [EIP-4337](https://eips.ethereum.org/EIPS/eip-4337) and the [ERC-4337 Smart Accounts documentation](https://docs.erc4337.io/smart-accounts/index.html) make programmable validation possible, but the actual authorization semantics depend on the account implementation.
- Modular-account standards and modules such as [ERC-7579 / ERC-6900 overview](https://docs.erc4337.io/smart-accounts/modular-accounts.html), [Safe AI spending limits](https://docs.safe.global/home/ai-agent-quickstarts/agent-with-spending-limit), and [Zodiac Roles](https://docs.zodiac.eco/faq) show how allowlists, limits, and execution-time policies can be enforced.
- This repository does **not** implement smart accounts, session keys, paymasters, or on-chain policy modules. Those are comparative context and future-work targets.

### Agent tool security

- The core research gap is not only "can the wallet sign?" but also "should this tool-triggered payment be allowed to execute at all?"
- That framing is motivated by [OWASP Prompt Injection](https://owasp.org/www-community/attacks/PromptInjection), [LLM06 Excessive Agency](https://owasp.org/www-project-top-10-for-large-language-model-applications/assets/PDF/OWASP-Top-10-for-LLMs-v2025.pdf), and [Capability Gates Are Not Authorization](https://arxiv.org/html/2606.28679v1), which distinguish capability exposure from per-call authorization.

### Post-execution evidence

- [Ethereum receipts](https://ethereum.org/en/developers/docs/apis/json-rpc/#eth_gettransactionreceipt), logs, and traces can reconstruct **what executed**.
- They do not, by themselves, prove the original human-readable request, the UI the user saw, or whether the agent was semantically aligned when it proposed the call.

For the expanded threat taxonomy, coverage taxonomy, and related-work notes, see [docs/research-context.md](docs/research-context.md).

## Architecture

```text
User request -> EIP-712 PaymentIntent -> Signature recovery -> Policy + execution binding
                                                              -> Wallet release / deny
                                                              -> Typed evidence receipt
```

Core controls in this prototype:

1. **Signed payment envelope**: payer, recipient, chain, asset, integer-denominated amount, maximum amount, expiry, nonce, and resource hash are encoded and verified as EIP-712 typed data.
2. **Domain and signer validation**: the backend reconstructs the typed-data digest, enforces the IntentGuard Pay Sepolia domain, and requires the recovered signer to equal the declared payer.
3. **Deterministic policy checks**: chain allowlist, token allowlist, recipient allowlist, amount ceiling, execution match, expiry, and replay-state checks.
4. **Execution matching**: the proposed call must match the signed envelope before the wallet-release step.
5. **Replay guard (nonce store)**: `AUTO_APPROVE` consumes a payer-scoped nonce via a pluggable `NonceStore` (default: in-memory; optional: SQLite durable store so replay denial persists across restarts). `DENY` and `HUMAN_REVIEW` do not consume state.
6. **Audit receipt**: typed-data digest, recovered signer, execution hash, policy outcome, timestamp, and evidence hash.
7. **Read-only Sepolia verifier**: browser-only reconstruction of public transaction and receipt evidence from a public RPC endpoint.

## Design claims vs non-claims

| This repository claims | This repository does **not** claim |
| --- | --- |
| Verification of EIP-712 signed `PaymentIntent` envelopes with signer recovery, domain separation, integer-denominated amounts, and typed evidence. | Production wallet security, private-key custody, or transaction broadcasting. |
| **Mechanism-level baseline comparisons** (policy gates, execution binding, replay state), computed from a shared deterministic fixture runner. | Any external product performance claim or end-to-end equivalence to Safe, Permit2, ZeroDev, or other mature systems. |
| A deterministic adversarial fixture benchmark with fixed, reproducible numbers. | Production security, live-fund safety, or exhaustive coverage of the attack space. |
| Read-only receipt reconstruction for Sepolia transactions. | Smart-account / [EIP-4337](https://eips.ethereum.org/EIPS/eip-4337) deployment, paymasters, session keys, or on-chain enforcement. |
| A payer-scoped consume-once nonce store with optional SQLite durability (research-v2). | Distributed replay atomicity across replicas, coupling nonce consumption to on-chain execution, or production-grade durability guarantees. |

## Benchmark results

The included deterministic synthetic benchmark reports (see [docs/evaluation-methodology.md](docs/evaluation-methodology.md)):

| Baseline (mechanism) | Attack block rate | Benign completion | Notes |
| --- | ---: | ---: | --- |
| `policy-gate-only` | 33% | 100% | Intent-time allowlists + ceiling + expiry; no intent→execution binding; no replay state. |
| `smart-account-policy` | 44% | 100% | Execution-time allowlists + per-call spend limit; no pre-execution intent object; no authorization replay guard. |
| `stateless-intent-execution-binding` | 67% | 100% | Scope binding + ceiling + expiry; no intent allowlists; no exact-amount binding; no replay state. |
| `intentguard-full` | 100% | 100% | Policy + scope binding + exact-amount binding + process-local replay guard. |

Ablation summary (relative to `intentguard-full`):

| Ablation | Attack block rate | Delta vs full |
| --- | ---: | ---: |
| w/o execution binding | 44% | -56 pp |
| w/o exact amount binding | 89% | -11 pp |
| w/o replay guard | 89% | -11 pp |
| w/o intent allowlists | 89% | -11 pp |

These are deterministic fixture results, not live-chain security claims.

## Live Sepolia verifier

The frontend includes a read-only Sepolia verifier. Users can paste a transaction hash and optional expected sender, recipient, and ETH value. The verifier fetches the transaction and receipt through `VITE_SEPOLIA_RPC_URL` or the public fallback, then reconstructs:

- network and receipt-status checks,
- sender / recipient / value integrity checks when expected values are provided,
- an evidence hash over transaction and receipt fields,
- gas, fee, block, and confirmation metadata.

No wallet is connected and no user data is persisted.

## Reproducibility

### Frontend

```bash
npm install
npm run build
npm run dev
```

Optional public configuration:

```bash
cp .env.example .env.local
# edit VITE_SEPOLIA_RPC_URL if you want to use another public Sepolia RPC endpoint
```

### Backend

```bash
cd backend
python -m pip install -r requirements-dev.txt
HYPOTHESIS_MAX_EXAMPLES=1000 python -m unittest
PORT=8000 python main.py
```

Replay store configuration (research-v2):

- Default (process-local): `INTENTGUARD_NONCE_STORE=memory`
- Durable across restarts: `INTENTGUARD_NONCE_STORE=sqlite` with `INTENTGUARD_NONCE_SQLITE_PATH=/path/to/intentguard_nonces.sqlite3`

Example:

```bash
INTENTGUARD_NONCE_STORE=sqlite \
INTENTGUARD_NONCE_SQLITE_PATH=/tmp/intentguard_nonces.sqlite3 \
PORT=8000 python main.py
```

The API accepts browser requests from `http://localhost:5173` and `http://127.0.0.1:5173` by default. For another frontend origin, set the comma-separated `INTENTGUARD_ALLOWED_ORIGINS` environment variable explicitly.

Cross-language EIP-712 vector:

```bash
npm run verify:eip712
```

### What is reproducible here

- The deterministic fixture scenarios exposed by the frontend and backend.
- The original 11-fixture benchmark and mechanism-level baseline comparison.
- EIP-712 typed-data hashing and signer recovery against a shared TypeScript/Python golden vector.
- An observed MetaMask `eth_signTypedData_v4` flow during a controlled local dashboard run: the first reviewed intent returned `AUTO_APPROVE`, while replaying the same signature returned `DENY` because the payer--nonce was already consumed (in-memory by default; optionally durable via SQLite in research-v2).
- Property-based checks for signed-field immutability, signer identity, domain separation, execution drift, replay, and failure-state isolation. See [Signed-Intent Evaluation](docs/signed-intent-evaluation.md).
- research-v2 verification-kernel microbenchmarks (memory vs SQLite nonce store) and durable replay tests under `docs/research-v2/`.
- The read-only Sepolia receipt verification workflow.

### What is deliberately not claimed

- Production wallet custody guarantees; the dashboard can request and verify `eth_signTypedData_v4` signatures, but it never sends transactions or handles private keys.
- Distributed replay atomicity across replicas; research-v2 demonstrates durable replay denial across restarts using SQLite, but not a replicated deployment guarantee.
- Live smart-account or on-chain enforcement.
- Product-level equivalence to mature external payment or wallet systems.

## API overview

- `GET /api` — service metadata.
- `GET /api/v1/ping` — health check.
- `GET /api/v1/demo/scenarios` — supported local fixture scenarios.
- `POST /api/v1/demo/run` — run `normal`, `tampered`, or `replay`.
- `POST /api/v1/signed-intents/validate` — recover and verify an EIP-712 signer, then apply policy, execution-binding, expiry, and replay checks.
- `POST /api/v1/demo/reset` — reset the current replay state (memory or SQLite nonce store).
- `GET /api/v1/evaluation` — run deterministic benchmark fixtures.
- `GET /api/v1/about` — project metadata and attribution.

OpenAPI docs are available at `/docs` when the backend is running.

## Repository structure

```text
intentguard-pay-public/
├── backend/
│   ├── bench_overhead.py
│   ├── eip712.py
│   ├── intent_engine.py
│   ├── main.py
│   ├── nonce_store.py
│   ├── requirements.txt
│   ├── requirements-dev.txt
│   ├── test_eip712.py
│   ├── test_intent_engine.py
│   └── test_nonce_store.py
├── fixtures/
│   └── eip712-golden-vector.json
├── scripts/
│   └── verify-eip712-vector.mjs
├── docs/
│   ├── evaluation-methodology.md
│   ├── research-context.md
│   ├── signed-intent-evaluation.md
│   └── research-v2/
│       └── overhead_*.json
├── src/
│   ├── App.tsx
│   ├── main.tsx
│   ├── components/
│   │   ├── IntentGuardDashboard.tsx
│   │   ├── LiveSepoliaVerifier.tsx
│   │   └── SignedIntentDemo.tsx
│   ├── lib/
│   │   ├── api.ts
│   │   ├── demo.ts
│   │   ├── eip712.ts
│   │   └── sepolia.ts
│   └── routes/
│       └── index.css
├── .env.example
├── .gitignore
├── LICENSE
├── THIRD_PARTY_NOTICES.md
├── SECURITY.md
├── README.md
├── index.html
├── package.json
├── tsconfig.json
├── tsconfig.app.json
├── tsconfig.node.json
└── vite.config.ts
```

## Future work

- Harden the implemented review-and-sign flow with multi-wallet discovery, transaction simulation, accessibility testing, and production custody controls.
- Add a persistent consume-once nonce / used-intent registry instead of process-local replay state.
- Integrate [EIP-4337](https://eips.ethereum.org/EIPS/eip-4337) smart accounts or on-chain policy modules for execution-time enforcement.
- Connect wallet transaction simulation / human-readable review more tightly to the authorized envelope.
- Extend the current Hypothesis properties with state-machine testing, calldata-aware mutations, and smart-contract fuzzing.

## Integrated IntentGuard components

The repository presents structured intent, policy validation, execution matching, replay handling, receipt reconstruction, and evidence hashing as one IntentGuard Pay system. The benchmark decomposes that system only into neutral control profiles for ablation and causal comparison; it does not split the implementation into separately branded subprojects.

## License

MIT. See [LICENSE](LICENSE).
