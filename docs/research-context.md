# Research Context for IntentGuard Pay

This note explains the final research version's scope, related layers, and conservative interpretation boundary.

## 1. Research position

IntentGuard studies a five-stage authorization chain:

1. **Pre-execution intent** — what the user is actually authorizing.
2. **Policy** — machine-checkable constraints over recipients, assets, amounts, chains, and timing.
3. **Execution binding** — whether the call that is about to execute still matches the authorized object.
4. **Replay control** — whether an authorization can be consumed more than once.
5. **Post-execution evidence** — what a third party can reconstruct after execution.

The claim is deliberately bounded: IntentGuard is a research prototype for studying this chain, not a production wallet, custody system, or on-chain payment protocol.

## 2. Threat taxonomy

| Layer | Representative threats | Why it matters to IntentGuard |
| --- | --- | --- |
| Model / tool layer | indirect prompt injection, excessive agency, confused-deputy tool use | An agent can produce a syntactically valid payment call without that call being semantically authorized by the user. |
| Authorization layer | recipient substitution, amount escalation, TOCTOU, expiry, replay, delegated-authorization mismatch | Payment authorization must stay bound to the recipient, amount, scope, time window, and use count. |
| Wallet review layer | human sees a preview, but preview is not execution-time enforcement | Readable review improves visibility, but does not by itself guarantee consume-once semantics or tool-level authorization. |
| Smart-account / policy layer | policy modules constrain execution without necessarily proving the original user intent | On-chain enforcement is powerful, but the authorized semantics come from the module design, not automatically from the standard. |
| Post-execution evidence layer | receipts, logs, and traces prove what executed, not why it was authorized | A receipt is execution evidence, not a complete authorization proof. |

## 3. Coverage taxonomy

| Mechanism / system | Pre-execution intent | Policy | Execution binding | Replay | Evidence | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| Wallet simulation / readable review | Partial | No-evidence | No-evidence | No-evidence | No-evidence | Improves visibility but is not a consume-once authorization object. |
| Spending limits / allowlists / session permissions | No-evidence | Yes | Partial | Implementation-dependent | No-evidence | Strong for quotas and recipient controls; weaker for proving original user intent. |
| Smart-account + on-chain policy module | No-evidence | Yes | Yes | Implementation-dependent | Partial | Strong execution gate, but semantics depend on the account/module implementation. |
| Transaction receipts / traces | No | No | No | No | Yes | Good for reconstructing what executed; weak for proving original authorization. |
| IntentGuard final prototype | Yes | Yes | Yes | Yes under one replay authority | Partial | Verifies signed intent, policy, execution binding, consume-once replay state, corpus evaluation, and evidence reconstruction. |

## 4. Related work by layer

- **Typed signing:** EIP-712 helps wallets and verifiers process structured fields, but replay protection and application-level authorization semantics still need additional state and checks.
- **Smart accounts:** EIP-4337 and modular account systems motivate future on-chain enforcement, but this repository studies a pre-release authorization boundary.
- **Wallet simulation:** transaction previews improve human visibility, but preview is not the same as a deterministic authorization gate.
- **Agent security:** prompt-injection and confused-deputy literature motivates the need to distinguish tool access from per-action authorization.
- **Payment protocols:** AP2-like mandate work is adjacent to IntentGuard's replay and context-binding focus, but external implementations are not used as product-level baselines here.

## 5. Mechanism baselines used in this repository

The final benchmark compares mechanism-level control compositions using PAACT-Core v1, a deterministic 1,000-case corpus.

Baseline names are neutral and describe what is actually implemented in this repository:

- `policy-gate-only` — intent-time allowlists + ceiling + expiry; no intent→execution binding; no replay state.
- `smart-account-policy` — execution-time allowlists + per-call spend limit; no pre-execution intent object; no authorization replay guard.
- `stateless-intent-execution-binding` — scope binding + ceiling + expiry; no intent allowlists; no exact-amount binding; no replay state.
- `intentguard-full` — policy + scope binding + exact-amount binding + payer-scoped consume-once replay guard.

The reported percentages must not be interpreted as external product scores.

## 6. Scope boundary of this repository

Implemented here:

- EIP-712 signed payment envelopes with signer and domain verification.
- Deterministic local policy checks.
- Local execution matching before release.
- Payer-scoped replay tracking, including SQLite durable nonce-store tests.
- PAACT-Core v1 corpus generation and mechanism-level evaluation.
- Read-only public receipt reconstruction.

Not implemented here:

- Production wallet custody guarantees.
- Transaction broadcast or real fund movement.
- EIP-4337 smart-account deployment.
- On-chain policy enforcement.
- Distributed replay consensus.
- Full semantic interpretation of arbitrary smart-contract calldata.
- User-comprehension study.

That boundary is deliberate: the repository is a rigorous research prototype, not an over-claimed production system.
