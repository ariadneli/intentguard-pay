# PAACT-Core v1 Results

- Seed: `20260916`
- Total cases: **1000**
- Schema: `paact-core-v1`
- All mechanism-level baselines consume the identical ordered corpus.

## Overall baseline comparison

| Mechanism profile | Attack block | 95% Wilson CI | Benign completion | False rejection |
|---|---:|---:|---:|---:|
| `policy-gate-only` | 27.17% (250/920) | [24.40, 30.14] | 100.00% | 0.00% |
| `smart-account-policy` | 50.00% (460/920) | [46.78, 53.22] | 100.00% | 0.00% |
| `stateless-intent-execution-binding` | 70.65% (650/920) | [67.63, 73.50] | 100.00% | 0.00% |
| `intentguard-full` | 100.00% (920/920) | [99.58, 100.00] | 100.00% | 0.00% |

## Attack block rate by mutation family

| Family | `policy-gate-only` | `smart-account-policy` | `stateless-intent-execution-binding` | `intentguard-full` |
|---|---:|---:|---:|---:|
| amount | 50.00% | 25.00% | 50.00% | 100.00% |
| asset | 0.00% | 100.00% | 100.00% | 100.00% |
| chain | 0.00% | 100.00% | 100.00% | 100.00% |
| compositional | 0.00% | 100.00% | 100.00% | 100.00% |
| expiry | 100.00% | 0.00% | 100.00% | 100.00% |
| policy | 100.00% | 100.00% | 0.00% | 100.00% |
| recipient | 0.00% | 50.00% | 100.00% | 100.00% |
| replay | 0.00% | 0.00% | 0.00% | 100.00% |

## Interpretation boundary

- Mechanism profiles are evaluated on identical deterministic cases; they are not external project reproductions.
- Confidence intervals quantify finite-corpus uncertainty, not real-world attack prevalence.
- Signer/domain and calldata-semantics claims remain outside this corpus.
