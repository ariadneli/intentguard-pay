# research-v2 · overhead experiment matrix

> Timed region: `IntentEngine.validate_signed` only. Signing and all wallet/RPC I/O are excluded.



| Config | n | Concurrency | Denies | Mean (ms) | p50 (ms) | p95 (ms) | Throughput (req/s) |
|---|---:|---:|---:|---:|---:|---:|---:|
| memory-verify-only | 250 | 1 | 0 | 7.90 | 7.70 | 9.15 | 126.6 |
| memory-consume | 250 | 1 | 0 | 7.94 | 7.77 | 9.49 | 125.8 |
| sqlite-consume | 250 | 1 | 0 | 8.16 | 7.89 | 10.02 | 122.6 |
| sqlite-consume-concurrent-4w | 320 | 4 | 0 | 35.49 | 32.46 | 62.99 | 110.6 |


Interpretation: focus on deltas across configurations. SQLite concurrency models contention on a shared durable nonce registry; it is not a production benchmark.
