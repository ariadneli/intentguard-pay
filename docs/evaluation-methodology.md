# IntentGuard Pay 评测方法学（Evaluation Methodology）

> 本文档解释：IntentGuard Pay 的基准（baseline）为何是“机制级”（mechanism-level）可辩护构念、11 个 fixtures 如何映射到能力、当前分数的边界与局限、以及如何复现。

## 1. 基准设计原则（Construct Validity）

1. **只比较机制，不比较项目**
   - 本仓库的 benchmark 标签（例如 `policy-gate-only`）描述的是**本仓库真实实现**的控制组合。
   - 这些分数是**本仓库 deterministic fixtures** 的计算结果，**不能**解读为任何外部第三方系统的产品级分数。

2. **同一 fixture runner 真实计算，禁止手填**
   - 所有 baseline / ablation 共享同一套 fixtures 与同一套 runner 逻辑；结果由代码执行得到。
   - 后端实现位于 `backend/intent_engine.py::benchmark()`；前端本地 fallback 逻辑在 `src/lib/demo.ts::computeEvaluation()`（用于离线可视化，不依赖后端）。

3. **显式的能力定义（Capability / Control Primitives）**
   - 每个 baseline 由若干个“控制原语（control primitives）”组成，每个原语在代码中对应明确的 check code（例如 `EXECUTION_SCOPE_MATCH`）。
   - baseline 的可辩护性来自：**baseline 名称 ↔ 控制原语 ↔ check code ↔ fixture 触发点** 可追溯。

## 2. Fixtures 套件概览（11 个）

本仓库的评测集是“合成但可复现”的 adversarial fixtures：

- **Benign（2）**：应当允许执行（`expected=ALLOW`）。
- **Attack（9）**：应当阻止执行（`expected=DENY`）。

> 说明：评测以 `decision == "DENY"` 作为“阻止”。`HUMAN_REVIEW` 在本仓库里代表“需要人工复核但不应被硬拒绝”，在 benchmark 的“benign completion”统计中按 **允许** 处理。

### 2.1 Fixture → 主要构念映射

| Fixture | 主要威胁/构念 | 期望阻断依赖的关键控制 |
| --- | --- | --- |
| `legitimate-small` | 合法小额支付 | 不应触发硬拒绝 |
| `legitimate-large` | 合法较大金额（应允许但可触发复核） | 不应触发硬拒绝 |
| `recipient-substitution-within-allowlist` | allowlist 内收款人替换（TOCTOU / prompt injection） | `EXECUTION_SCOPE_MATCH` |
| `recipient-substitution-external` | allowlist 外收款人替换 | `EXECUTION_SCOPE_MATCH` 或 `EXEC_RECIPIENT_ALLOWED` |
| `over-ceiling-amount` | 超过授权上限（max_amount） | `AMOUNT_WITHIN_INTENT` |
| `subtle-amount-mutation-within-ceiling` | 上限内的“微调金额”（dynamic linking / exactness） | `EXECUTION_AMOUNT_EXACT` |
| `execution-chain-switch` | 执行链切换 | `EXECUTION_SCOPE_MATCH` 或 `EXEC_CHAIN_ALLOWED` |
| `execution-token-switch` | 执行资产切换 | `EXECUTION_SCOPE_MATCH` 或 `EXEC_TOKEN_ALLOWED` |
| `expired-intent` | 过期授权 | `INTENT_FRESH` |
| `replay-attempt` | 同一授权二次执行（consume-once） | `NONCE_UNUSED`（+ 状态更新） |
| `unapproved-recipient-intent` | 授权对象本身指向非批准收款人 | `RECIPIENT_ALLOWED`（intent-time allowlist） |

## 3. 控制原语（Capability / Control Primitives）

以下原语在 `backend/intent_engine.py` 与前端本地引擎中均有对应 check code：

- `intent-allowlists`：授权 envelope 的 chain/token/recipient allowlist（`CHAIN_ALLOWED`, `TOKEN_ALLOWED`, `RECIPIENT_ALLOWED`）
- `intent-max-amount`：执行金额不得超过 envelope 的上限（`AMOUNT_WITHIN_INTENT`）
- `intent-expiry`：授权过期（`INTENT_FRESH`）
- `execution-scope-binding`：recipient/chain/token 的 intent→execution 绑定（`EXECUTION_SCOPE_MATCH`）
- `execution-amount-exact`：金额 exact binding（`EXECUTION_AMOUNT_EXACT`）
- `replay-guard-process-local`：进程内 nonce consume-once（`NONCE_UNUSED`）
- `execution-policy-allowlists`：执行时 allowlist（`EXEC_CHAIN_ALLOWED`, `EXEC_TOKEN_ALLOWED`, `EXEC_RECIPIENT_ALLOWED`）
- `execution-policy-max-amount`：执行时单笔限额（`EXEC_AMOUNT_WITHIN_POLICY`）

## 4. Baseline 集合（机制级，命名中性）

> 这些 baseline 的名字是“本仓库实现的机制组合”，不是任何外部项目的别名。

### 4.1 `policy-gate-only`
- **包含原语**：`intent-allowlists` + `intent-max-amount` + `intent-expiry`
- **不包含**：任何 intent→execution binding、任何 replay state
- **对应现实类比**：离线/中间层的策略闸门（policy gate），但假设在 gate 之后仍可能发生执行时 TOCTOU。

### 4.2 `smart-account-policy`
- **包含原语**：`execution-policy-allowlists` + `execution-policy-max-amount`
- **不包含**：pre-execution intent 对象、intent→execution binding、authorization replay guard
- **对应现实类比**：Safe/Zodiac/Smart Account policy module 风格的执行时策略，但本仓库**未实现** ERC-4337、模块部署、session key、paymaster 等。

### 4.3 `stateless-intent-execution-binding`
- **包含原语**：`execution-scope-binding` + `intent-max-amount` + `intent-expiry`
- **不包含**：`intent-allowlists`、`execution-amount-exact`、`replay-guard-process-local`
- **对应现实类比**：一种“无状态”的 envelope→execution 绑定。该 baseline 保留原有 unsigned fixture 口径；真实 EIP-712 签名验证通过独立的 signed-intent path 和属性测试评估，避免改变原 11-case benchmark 的构念。

### 4.4 `intentguard-full`
- **包含原语**：`intent-allowlists` + `intent-max-amount` + `intent-expiry` + `execution-scope-binding` + `execution-amount-exact` + `replay-guard-process-local`
- **强调贡献点**：payment-specific threat model、cross-layer binding、stateful replay guard、adversarial fixtures、ablation、receipt evidence。

## 5. 指标与统计口径

- **Attack block rate**：9 个 attack fixtures 中，正确阻止（`DENY`）的比例。
- **Benign completion**：2 个 benign fixtures 中，未被硬拒绝（`decision != DENY`）的比例。
- **False rejection rate**：benign fixtures 被硬拒绝的比例。

> 注意：`HUMAN_REVIEW` 被视为“仍可完成但需人工复核”，因此在 benign completion 中算作通过。这是支付场景下常见的风控口径选择；如果未来需要严格可用性指标，可新增“无需人工介入完成率”等指标。

## 6. Signed-intent 属性评测

独立路径使用 EIP-712 typed data、secp256k1 signer recovery 和 Hypothesis 生成式测试，覆盖：

- 合法签名与匹配执行可完成；
- 签名后字段篡改和错误 signer 被拒绝；
- domain version 变化被拒绝；
- recipient、chain、asset、amount 或 calldata-resource 的执行漂移被拒绝；
- 同一 payer/nonce 只能成功一次，不同 payer 的同值 nonce 不会互相阻塞；
- 被拒绝或等待人工审核的请求不会提前消费 nonce；
- 地址大小写表示差异不改变授权语义。

默认 `HYPOTHESIS_MAX_EXAMPLES=1000`。有限离散策略可能在穷尽全部候选后提前结束，因此该参数表示每个 property 的上限，而不是伪造的固定样本总数。

## 7. 局限性（Limitations）

- **deterministic fixtures 数量有限**：原有 11 个 case 只能覆盖部分支付威胁；其结果与 signed-intent 属性测试分开报告。
- **钱包流程是研究原型**：dashboard 已暴露 MetaMask review-and-sign、typed-data signer recovery 与会话内 replay 演示，但不提供生产 custody 保证、交易广播或持久化 nonce。
- **Replay guard 仅进程内**：重启进程即丢失 used-nonce 状态；未提供持久化 used-intent registry。
- **未覆盖的能力示例**（需扩展 tests 才能公平比较）：
  - calldata 语义级别解析（合约方法/参数级），
  - paymaster / bundler / AA 费用路径，
  - wallet simulation / trace-based preview 的真实误差与对抗，
  - 多链/多 token 的跨域授权与回滚语义，
  - on-chain policy module 的原子性与链上可验证性。

## 8. 可复现性（Reproducibility）

在仓库根目录：

- 前端：`npm install && npm run build`
- 跨语言签名向量：`npm run verify:eip712`
- 后端：`cd backend && python -m pip install -r requirements-dev.txt && HYPOTHESIS_MAX_EXAMPLES=1000 python -m unittest`

评测入口：
- 后端：`GET /api/v1/evaluation`（返回原有 deterministic baseline 定义与结果的 JSON）
- 签名验证：`POST /api/v1/signed-intents/validate`
- 前端：Dashboard 会使用本地 engine 计算并渲染原有 baseline 对比结果（离线可用）。
