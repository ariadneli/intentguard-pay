# IntentGuard Pay Final Evaluation Methodology

本文档说明 final research version 的评测口径：PAACT-Core v1、机制级 baseline、统计指标与局限性。

## 1. 评测对象

IntentGuard Pay 研究的问题是：在 agentic payment 中，如何防止最终支付执行偏离用户授权的 intent。

评测对象不是外部产品，而是四个在同一 runner 中实现的机制级 profile：

1. `policy-gate-only`
2. `smart-account-policy`
3. `stateless-intent-execution-binding`
4. `intentguard-full`

这些 profile 用来拆解控制机制的贡献，不代表 Safe、Permit2、AP2、AuthGraph 或其他外部系统的产品级分数。

## 2. PAACT-Core v1

PAACT-Core v1 是固定 seed 的 author-generated payment-authorization attack corpus。

- Total cases: 1,000
- Attacks: 920
- Benign boundary cases: 80
- Schema: JSONL
- Seed: 20260916

攻击 family：

- recipient
- amount
- chain
- asset
- expiry
- replay
- policy
- compositional

PAACT-Core v1 的目标是可复现地衡量机制覆盖边界，而不是估计真实世界攻击率。

## 3. Metrics

- **Attack Block Rate (ABR)**: attack cases 中被正确拒绝的比例。
- **Benign Completion Rate (BCR)**: benign cases 中被正确允许的比例。
- **False Rejection Rate (FRR)**: benign cases 中被错误拒绝的比例。
- **Wilson 95% CI**: 描述有限 corpus 上比例估计的不确定性；不表示真实世界分布置信区间。

## 4. Overall results

| Profile | Attack block rate | 95% Wilson CI | Benign completion | False rejection |
|---|---:|---:|---:|---:|
| `policy-gate-only` | 27.17% (250/920) | [24.40, 30.14] | 100% | 0% |
| `smart-account-policy` | 50.00% (460/920) | [46.78, 53.22] | 100% | 0% |
| `stateless-intent-execution-binding` | 70.65% (650/920) | [67.63, 73.50] | 100% | 0% |
| `intentguard-full` | 100.00% (920/920) | [99.58, 100] | 100% | 0% |

## 5. Family-wise interpretation

- Policy-only catches expiry and unauthorized intent-policy violations, but misses most execution drift and all replay.
- Smart-account-style execution policy catches chain and asset substitution, but does not model stale authorization or replay.
- Stateless binding catches proposal-to-execution drift, but has no consumed-nonce state.
- Full IntentGuard combines signed intent validation, policy, exact execution binding, and consume-once replay protection.

## 6. Reproducibility

```bash
cd backend
python generate_attack_corpus.py
HYPOTHESIS_MAX_EXAMPLES=1000 HYPOTHESIS_STATEFUL_EXAMPLES=200 HYPOTHESIS_STATEFUL_STEPS=25 python -m unittest discover -v
```

Expected test result for the final research version: 27 tests pass.

## 7. Boundaries

This evaluation does not claim:

- real-world attack prevalence;
- a community-standard benchmark;
- product-level comparison with external systems;
- arbitrary smart-contract semantic coverage;
- distributed replay consensus;
- production wallet security;
- user comprehension guarantees.

这些限制应在 report、slides、demo 和答辩中保持一致。
