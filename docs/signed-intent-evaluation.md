# Signed-Intent Evaluation

## Scope

This evaluation is separate from the original 11-fixture mechanism benchmark. It tests the cryptographic authorization boundary added by the EIP-712 signed-intent path without changing the historical baseline numbers.

## EIP-712 boundary

- Domain: `IntentGuardPay`, version `1`, Sepolia chain ID `11155111`, application salt `keccak256("intentguard-pay/sepolia/v1")`.
- Signed fields: intent ID, payer, recipient, chain, asset, exact amount, maximum amount, purpose, expiry, nonce, and resource hash.
- Verification order: domain check → signature recovery → signer match → policy checks → execution binding → expiry → replay check.
- State rule: a nonce is consumed only after all checks pass.

## Cross-language golden vector

`fixtures/eip712-golden-vector.json` contains one public test signature, expected digest, and expected signer. The test key is deterministic and must never hold funds.

- Python checks the vector in `backend/test_eip712.py`.
- TypeScript checks the same vector with viem through `npm run verify:eip712`.
- Verified digest: `0x57f94aed39d13942c32688f73809ddbc79eebcb021a93804b9391cc9519a92cb`.

## Property-based evaluation

Hypothesis generates signed intents, keys, amounts, nonces, domain variants, signed-field mutations, and execution mutations. The suite checks these invariants:

1. A valid signature, matching execution, fresh nonce, and unexpired intent completes.
2. Any tested signed-field mutation without re-signing is rejected.
3. A signer different from the declared payer is rejected.
4. A modified EIP-712 domain is rejected.
5. Recipient, chain, asset, amount, or calldata-resource execution drift is rejected.
6. A consumed nonce cannot authorize a second execution, and the same nonce is independently scoped by payer.
7. A rejected or pending-review attempt does not consume the nonce.
8. Equivalent Ethereum address casing does not change authorization semantics.

The default profile sets `HYPOTHESIS_MAX_EXAMPLES=1000` per property. Hypothesis may stop earlier for finite strategies after exhausting their complete candidate space.

## Stateful authorization evaluation

`backend/test_state_machine.py` uses Hypothesis `RuleBasedStateMachine` to generate sequences over pre-signed intents from two payers. Its rules mix canonical release, replay, execution-amount drift, wrong-domain submission, post-signature mutation, expiry, and human-review routing. After every transition, the model checks:

1. every `AUTO_APPROVE` is field-equal to its signed authorization and recovers the declared payer;
2. each payer-scoped nonce is approved at most once;
3. denied and review-routed attempts leave nonce state unchanged; and
4. the model's consumed set agrees with the implementation's nonce store.

The recorded profile uses 200 state-machine examples with up to 25 operations per sequence. This explores up to 5,000 ordered transitions in addition to the independent properties; it is generated test evidence, not exhaustive model checking.

## Observed run

Command:

```bash
cd backend
HYPOTHESIS_MAX_EXAMPLES=1000 HYPOTHESIS_STATEFUL_EXAMPLES=200 HYPOTHESIS_STATEFUL_STEPS=25 python -m unittest discover -v
```

Observed on 2026-09-16:

- 27 test methods passed in the research-v3 full suite, including the rule-based state machine and five corpus tests.
- 0 failures and 0 errors.
- Runtime: 167.718 seconds in the recorded environment.
- The TypeScript/Python golden-vector verification also passed.

## Observed MetaMask flow

The prototype dashboard was exercised locally with a dedicated empty MetaMask account on the Sepolia domain. The account reviewed and signed the structured `PaymentIntent` through `eth_signTypedData_v4`; the dashboard recovered the declared payer and returned `AUTO_APPROVE`. Replaying the same signature preserved the signer, domain, execution, resource-hash, and freshness checks but failed `NONCE_UNUSED`, returning `DENY`. This manual smoke test broadcasts no transaction and adds no benchmark points.

## Claim boundary

Passing these generated tests is evidence that the implemented invariants held over the exercised input and transition space. The restart and spawned-process tests additionally support durable, single-host at-most-once release under one shared SQLite authority. These results are not exhaustive model checking, an independent audit, a production-wallet guarantee, geo-distributed replay consensus, or atomic coupling between nonce commit and wallet broadcast.
