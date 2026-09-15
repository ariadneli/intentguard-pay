# research-v2 · overhead experiment matrix

> Timed region: `IntentEngine.validate_signed` only. Signing and all wallet/RPC I/O are excluded.



| Config | n | Concurrency | Denies | Mean (ms) | p50 (ms) | p95 (ms) | Throughput (req/s) |
|---|---:|---:|---:|---:|---:|---:|---:|
| memory-verify-only | 250 | 1 | 0 | 7.94 | 7.74 | 9.53 | 125.9 |
| memory-consume | 250 | 1 | 0 | 7.99 | 7.77 | 9.86 | 125.1 |
| sqlite-consume | 250 | 1 | 0 | 8.79 | 8.26 | 12.01 | 113.7 |
| sqlite-consume-concurrent-4w | 320 | 4 | 0 | 35.33 | 33.07 | 62.79 | 111.7 |
| sqlite-consume-multiprocess-4p | 320 | 4 | 0 | 7.99 | 7.85 | 8.85 | 430.5 |


Interpretation: focus on deltas across configurations. SQLite concurrency models contention on a shared durable nonce registry; it is not a production benchmark.
