# Research Context for IntentGuard Pay

This note expands the public research context behind IntentGuard Pay. It is intentionally broader than the repository README but narrower than a full survey. The goal is to explain **which layer this prototype studies, which layers it does not implement, and how the mechanism baselines are used conservatively**.

## 1. Research position

IntentGuard studies a five-stage chain:

1. **Pre-execution intent** — what the user is actually authorizing.
2. **Policy** — machine-checkable constraints over recipients, assets, amounts, chains, and timing.
3. **Execution binding** — whether the call that is about to execute still matches the authorized object.
4. **Replay control** — whether an authorization can be consumed more than once.
5. **Post-execution evidence** — what a third party can reconstruct after execution.

The motivating claim is modest: public mechanisms often cover **some** of these stages, but not all five with one independently verifiable object.

## 2. Threat taxonomy

| Layer | Representative threats | Public evidence | Why it matters to IntentGuard |
| --- | --- | --- | --- |
| Model / tool layer | Indirect prompt injection, excessive agency, confused-deputy tool use | [OWASP Prompt Injection](https://owasp.org/www-community/attacks/PromptInjection), [OWASP LLM Top 10 2025 / LLM06](https://owasp.org/www-project-top-10-for-large-language-model-applications/assets/PDF/OWASP-Top-10-for-LLMs-v2025.pdf), [Capability Gates Are Not Authorization](https://arxiv.org/html/2606.28679v1) | An agent can produce a syntactically valid payment or tool call without that call being semantically authorized by the user. |
| Authorization layer | Recipient substitution, amount escalation, TOCTOU, replay, delegated-authorization mismatch | [OWASP Transaction Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transaction_Authorization_Cheat_Sheet.html), [PSD2 dynamic linking](https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=PI_COM%3AC%282017%297782), [EIP-712 security considerations](https://eips.ethereum.org/EIPS/eip-712#security-considerations) | Payment authorization must stay bound to the exact recipient, amount, scope, time window, and use count. |
| Wallet review layer | Human sees a preview, but preview is not execution-time enforcement | [Rabby transaction simulation](https://support.rabby.io/en/articles/14124199-understanding-rabby-s-transaction-simulation), [Tenderly Transaction Preview](https://docs.tenderly.co/simulations/transaction-preview) | Human-readable review improves visibility, but does not by itself guarantee consume-once semantics or tool-level authorization. |
| Smart-account / policy layer | Policy modules may constrain execution without proving the user's original natural-language intent | [EIP-4337](https://eips.ethereum.org/EIPS/eip-4337), [ERC-4337 Smart Accounts docs](https://docs.erc4337.io/smart-accounts/index.html), [ERC-7579 / ERC-6900 overview](https://docs.erc4337.io/smart-accounts/modular-accounts.html), [Zodiac Roles](https://docs.zodiac.eco/faq) | On-chain enforcement is powerful, but the semantics come from the account/module implementation, not automatically from the standard. |
| Post-execution evidence layer | Receipts, logs, and traces prove what executed, not why it was authorized | [Ethereum JSON-RPC receipts](https://ethereum.org/en/developers/docs/apis/json-rpc/#eth_gettransactionreceipt), [OWASP EVM forensics handbook](https://scs.owasp.org/handbooks/04-evm-forensics-defi-recovery/part2-evidence-collection-and-preservation/), [AI agent execution evidence draft](https://datatracker.ietf.org/doc/html/draft-emirdag-scitt-ai-agent-execution-00) | A receipt is execution evidence, not a complete authorization proof. |

## 3. Coverage taxonomy

The table below uses **Yes / Partial / No-evidence** to summarize what the reviewed public materials establish.

- **Yes** = the cited material explicitly supports the capability.
- **Partial** = the capability is present only in a narrower or incomplete sense.
- **No-evidence** = the reviewed public material does not establish the capability; this is **not** proof of absence.

| Mechanism / system | Pre-execution intent | Policy | Execution binding | Replay | Post-execution evidence | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| Wallet simulation / readable review | Partial | No-evidence | No-evidence | No-evidence | No-evidence | Review surfaces improve visibility of predicted effects, but preview is not a consume-once authorization object. |
| Spending limits / allowlists / session permissions | No-evidence | Yes | Partial | Implementation-dependent | No-evidence | Strong for quotas and recipient controls; weaker for proving original user intent. |
| Smart account + on-chain policy module | No-evidence | Yes | Yes | Implementation-dependent | Partial | Policy-to-call enforcement can be strong, but the meaning of the authorized action depends on the account/module design. |
| Transaction receipts / traces | No | No | No | No | Yes | Good for reconstructing what executed; weak for proving original authorization semantics. |
| IntentGuard prototype (this repo) | Yes | Yes | Yes (local gate) | Partial | Partial | The prototype verifies EIP-712 signed intents, signer/domain binding, execution-integrity checks, in-memory replay state, and receipt evidence; persistent nonce storage and on-chain enforcement remain out of scope. |

A useful shorthand is the five-stage chain:

**pre-execution intent → policy → execution binding → replay → post-execution evidence**

IntentGuard is designed around that chain rather than around a single standard or wallet feature.

## 4. Related work by layer

### 4.1 EIP-712 and replay boundaries

[EIP-712](https://eips.ethereum.org/EIPS/eip-712) standardizes typed structured data signing and domain separation, which makes it easier for wallets to display fields such as recipient, amount, chain, or contract domain. However, the standard explicitly states that it does **not** provide replay protection. That is why application-level state still matters.

[EIP-2612](https://eips.ethereum.org/EIPS/eip-2612) is a useful concrete example: it combines typed signing with explicit `nonce` and `deadline` semantics. The lesson for IntentGuard is straightforward: structured signing helps, but it is not enough without consume-once or time-bound state.

### 4.2 EIP-4337, smart accounts, and policy modules

[EIP-4337](https://eips.ethereum.org/EIPS/eip-4337) introduces `UserOperation`-based account abstraction without changing consensus-layer transaction types. The standard enables programmable validation, but it does not itself define universal user-intent semantics.

The [ERC-4337 smart account documentation](https://docs.erc4337.io/smart-accounts/index.html), [modular account overview](https://docs.erc4337.io/smart-accounts/modular-accounts.html), [Safe AI spending limits](https://docs.safe.global/home/ai-agent-quickstarts/agent-with-spending-limit), and [Zodiac Roles](https://docs.zodiac.eco/faq) show that limit policies, allowlists, and execution-time modules are practical. They are important context for future IntentGuard extensions, but **they are not implemented in this repository**.

### 4.3 Wallet transaction simulation and human-readable review

[Rabby transaction simulation](https://support.rabby.io/en/articles/14124199-understanding-rabby-s-transaction-simulation) and [Tenderly Transaction Preview](https://docs.tenderly.co/simulations/transaction-preview) represent a different layer of defense: improving what a human can inspect before signing. This is valuable, but it is still different from a deterministic authorization gate that compares an agent proposal with a previously authorized object.

### 4.4 Agent tool security and delegated authorization

Agentic payment systems inherit risks from both traditional payment authorization and LLM-agent tooling.

- [OWASP Prompt Injection](https://owasp.org/www-community/attacks/PromptInjection) explains how untrusted content can redirect model behavior.
- [OWASP LLM06 Excessive Agency](https://owasp.org/www-project-top-10-for-large-language-model-applications/assets/PDF/OWASP-Top-10-for-LLMs-v2025.pdf) highlights the risk of giving agents too much tool power.
- [Capability Gates Are Not Authorization](https://arxiv.org/html/2606.28679v1) argues directly that exposing a tool is not the same as authorizing every valid call to that tool.
- [AP2 runtime validation](https://arxiv.org/html/2602.06345) and [Beyond the Mandate](https://arxiv.org/html/2608.23858v1) further suggest that a formally valid delegated payment object can still be created or used in semantically unintended ways if the agent is manipulated.

IntentGuard takes this literature as motivation for a narrow question: how much can be gained by inserting a deterministic authorization layer between agent planning and wallet release?

### 4.5 Post-execution evidence and audit objects

[Ethereum receipts](https://ethereum.org/en/developers/docs/apis/json-rpc/#eth_gettransactionreceipt), logs, and traces are essential for reconstruction after the fact, but they only prove execution facts. The [OWASP EVM forensics handbook](https://scs.owasp.org/handbooks/04-evm-forensics-defi-recovery/part2-evidence-collection-and-preservation/) is useful for that evidence-collection viewpoint.

For agent systems more broadly, the [AI agent execution evidence Internet-Draft](https://datatracker.ietf.org/doc/html/draft-emirdag-scitt-ai-agent-execution-00) and [Agent-to-Agent Finance](https://arxiv.org/html/2607.00245v1) motivate treating execution evidence, interaction receipts, and intent/accountability objects as different artifacts rather than as one interchangeable proof.

## 5. Mechanism baselines used in this repository

The benchmark in this repository compares **mechanism-level control compositions** using the *same deterministic fixture suite* (11 fixtures).

Baseline names are neutral and describe what is actually implemented in this repository:

- `policy-gate-only` — intent-time allowlists + ceiling + expiry; **no** intent→execution binding; **no** replay state.
- `smart-account-policy` — execution-time allowlists + per-call spend limit; **no** pre-execution intent object; **no** authorization replay guard.
- `stateless-intent-execution-binding` — scope binding + ceiling + expiry; **no** intent allowlists; **no** exact-amount binding; **no** replay state.
- `intentguard-full` — policy + scope binding + exact-amount binding + process-local replay guard.

The reported percentages are computed from the local fixtures and **must not be interpreted as external product scores**.

### 5.1 Why the comparison is intentionally narrow

The benchmark scores in this repository are a **fixture-scored control simulation**, not an external-product-equivalence claim.

- **Included:** deterministic control compositions that map directly onto the implemented checks in this repo.
- **Not included:** full production deployment assumptions, hidden integrations, operator procedures, external services, or claims about systems that are not reproduced (Permit2 transfer execution, Safe/Zodiac policies, ZeroDev permissions, wallet simulation, etc.).

## 6. Scope boundary of this repository

Implemented here:

- EIP-712 signed payment envelopes with signer and domain verification.
- Deterministic local policy checks.
- Local execution matching before release.
- Process-local replay tracking.
- Read-only public receipt reconstruction.

Not implemented here:

- Production wallet custody guarantees; the dashboard requests and verifies typed-data signatures but does not send transactions or access private keys.
- Persistent nonce / used-intent storage.
- [EIP-4337](https://eips.ethereum.org/EIPS/eip-4337) smart-account deployment.
- On-chain policy enforcement.
- Production deployment coverage beyond the controls explicitly implemented and tested in this repository.

That boundary is deliberate: the repository is meant to present a rigorous **research prototype**, not an over-claimed production system.
