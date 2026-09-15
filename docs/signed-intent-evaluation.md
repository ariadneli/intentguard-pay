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

## Observed run

Command:

```bash
cd backend
HYPOTHESIS_MAX_EXAMPLES=1000 python -m unittest -v
```

Observed on 2026-09-14:

- 18 test methods passed.
- 0 failures and 0 errors.
- Runtime: 131.444 seconds in the recorded environment.
- The TypeScript/Python golden-vector verification also passed.

## Observed MetaMask flow

The prototype dashboard was exercised locally with a dedicated empty MetaMask account on the Sepolia domain. The account reviewed and signed the structured `PaymentIntent` through `eth_signTypedData_v4`; the dashboard recovered the declared payer and returned `AUTO_APPROVE`. Replaying the same signature preserved the signer, domain, execution, resource-hash, and freshness checks but failed `NONCE_UNUSED`, returning `DENY`. This manual smoke test broadcasts no transaction and adds no benchmark points.

## Claim boundary

Passing these generated tests is evidence that the implemented invariants held over the exercised input space. It is not a formal proof, an audit, a production-wallet guarantee, or evidence of persistent replay safety across process restarts.
