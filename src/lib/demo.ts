export type ScenarioId = 'normal' | 'tampered' | 'replay';

export interface Scenario {
  id: ScenarioId;
  title: string;
  description: string;
  eyebrow: string;
}

export interface PolicyCheck {
  code: string;
  label: string;
  passed: boolean;
  detail: string;
  severity: string;
}

export interface PaymentIntent {
  intent_id: string;
  payer: string;
  recipient: string;
  chain_id: number;
  token: string;
  amount: number;
  max_amount: number;
  purpose: string;
  expiry: string;
  nonce: string;
  resource_hash: string;
}

export interface ProposedExecution {
  recipient: string;
  chain_id: number;
  token: string;
  amount: number;
  calldata_hash: string;
}

export interface AuditReceipt {
  receipt_id: string;
  intent_hash: string;
  intent_hash_kind?: 'sha256-canonical-json' | 'eip712-digest';
  execution_hash: string;
  decision: string;
  policy_checks: PolicyCheck[];
  tx_hash: string | null;
  evidence_hash: string;
  timestamp: string;
  network: string;
  attestation_status: string;
  typed_data_digest?: string | null;
  recovered_signer?: string | null;
  signature_scheme?: string | null;
}

export interface DemoResult {
  scenario_id: ScenarioId;
  title: string;
  summary: string;
  decision: string;
  intent: PaymentIntent;
  proposed_execution: ProposedExecution;
  policy_checks: PolicyCheck[];
  timeline: Array<{
    stage: string;
    title: string;
    status: string;
    detail: string;
  }>;
  audit_receipt: AuditReceipt;
  replay_receipt?: AuditReceipt | null;
}

export interface Methodology {
  benchmark_type: string;
  profile_scope: string;
  state_model: string;
  network_scope: string;
}

export interface ControlDefinition {
  id: string;
  label: string;
  description: string;
  check_codes: string[];
}

export interface BaselineDefinition {
  id: string;
  label: string;
  state_model: string;
  controls: string[];
  enabled_check_codes: string[];
}

export interface BaselineComparison {
  mode: string;
  label: string;
  attack_block_rate: number;
  benign_completion_rate: number;
  false_rejection_rate: number;
  blocked_attacks: number;
  total_attacks: number;
}

export interface AblationStudy {
  mode: string;
  label: string;
  attack_block_rate: number;
  delta_vs_full_pp: number;
  removed_control: string;
}

export interface Evaluation {
  total_cases: number;
  attack_block_rate: number;
  benign_completion_rate: number;
  false_rejection_rate: number;
  evaluation_time_ms: number;
  methodology: Methodology;
  control_definitions: ControlDefinition[];
  baseline_definitions: BaselineDefinition[];
  baseline_comparison: BaselineComparison[];
  ablations: AblationStudy[];
  outcomes: Array<{
    case: string;
    type: string;
    decision: string;
    expected: string;
    correct: boolean;
  }>;
  limitations: string[];
}

export const scenarios: Scenario[] = [
  {
    id: 'normal',
    title: 'Authorized purchase',
    description: 'A bounded Sepolia payment matches the authorized intent envelope.',
    eyebrow: 'Happy path',
  },
  {
    id: 'tampered',
    title: 'Prompt injection',
    description: 'Recipient substitution and amount escalation are blocked.',
    eyebrow: 'Integrity attack',
  },
  {
    id: 'replay',
    title: 'Replay attempt',
    description: 'A process-local nonce guard prevents the same intent from paying twice.',
    eyebrow: 'Ephemeral replay guard',
  },
];

const payer = '0x2222222222222222222222222222222222222222';
const defaultRecipient = '0x3333333333333333333333333333333333333333';

function canonicalStringify(value: unknown): string {
  if (value === null || value === undefined) return String(value);
  if (typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map(item => canonicalStringify(item)).join(',')}]`;
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return `{${keys
    .map(key => `${JSON.stringify(key)}:${canonicalStringify(obj[key])}`)
    .join(',')}}`;
}

function rightRotate32(value: number, amount: number): number {
  return (value >>> amount) | (value << (32 - amount));
}

const SHA256_K = [
  0x428a2f98,
  0x71374491,
  0xb5c0fbcf,
  0xe9b5dba5,
  0x3956c25b,
  0x59f111f1,
  0x923f82a4,
  0xab1c5ed5,
  0xd807aa98,
  0x12835b01,
  0x243185be,
  0x550c7dc3,
  0x72be5d74,
  0x80deb1fe,
  0x9bdc06a7,
  0xc19bf174,
  0xe49b69c1,
  0xefbe4786,
  0x0fc19dc6,
  0x240ca1cc,
  0x2de92c6f,
  0x4a7484aa,
  0x5cb0a9dc,
  0x76f988da,
  0x983e5152,
  0xa831c66d,
  0xb00327c8,
  0xbf597fc7,
  0xc6e00bf3,
  0xd5a79147,
  0x06ca6351,
  0x14292967,
  0x27b70a85,
  0x2e1b2138,
  0x4d2c6dfc,
  0x53380d13,
  0x650a7354,
  0x766a0abb,
  0x81c2c92e,
  0x92722c85,
  0xa2bfe8a1,
  0xa81a664b,
  0xc24b8b70,
  0xc76c51a3,
  0xd192e819,
  0xd6990624,
  0xf40e3585,
  0x106aa070,
  0x19a4c116,
  0x1e376c08,
  0x2748774c,
  0x34b0bcb5,
  0x391c0cb3,
  0x4ed8aa4a,
  0x5b9cca4f,
  0x682e6ff3,
  0x748f82ee,
  0x78a5636f,
  0x84c87814,
  0x8cc70208,
  0x90befffa,
  0xa4506ceb,
  0xbef9a3f7,
  0xc67178f2,
];

function sha256(message: Uint8Array): Uint8Array {
  // FIPS 180-4 SHA-256.
  const bitLength = message.length * 8;

  // Pre-processing (padding)
  const withOne = new Uint8Array(message.length + 1);
  withOne.set(message, 0);
  withOne[message.length] = 0x80;

  let paddedLength = withOne.length;
  while ((paddedLength % 64) !== 56) paddedLength += 1;
  const padded = new Uint8Array(paddedLength + 8);
  padded.set(withOne, 0);

  // Append length (big-endian 64-bit)
  const view = new DataView(padded.buffer);
  // High 32 bits are zero for messages < 2^32 bits (true here).
  view.setUint32(padded.length - 8, Math.floor(bitLength / 2 ** 32));
  view.setUint32(padded.length - 4, bitLength >>> 0);

  // Initial hash values
  let h0 = 0x6a09e667;
  let h1 = 0xbb67ae85;
  let h2 = 0x3c6ef372;
  let h3 = 0xa54ff53a;
  let h4 = 0x510e527f;
  let h5 = 0x9b05688c;
  let h6 = 0x1f83d9ab;
  let h7 = 0x5be0cd19;

  const w = new Uint32Array(64);

  for (let offset = 0; offset < padded.length; offset += 64) {
    // Message schedule
    for (let i = 0; i < 16; i += 1) {
      const idx = offset + i * 4;
      w[i] =
        ((padded[idx] << 24) |
          (padded[idx + 1] << 16) |
          (padded[idx + 2] << 8) |
          padded[idx + 3]) >>> 0;
    }
    for (let i = 16; i < 64; i += 1) {
      const s0 =
        (rightRotate32(w[i - 15], 7) ^
          rightRotate32(w[i - 15], 18) ^
          (w[i - 15] >>> 3)) >>> 0;
      const s1 =
        (rightRotate32(w[i - 2], 17) ^
          rightRotate32(w[i - 2], 19) ^
          (w[i - 2] >>> 10)) >>> 0;
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }

    // Working variables
    let a = h0;
    let b = h1;
    let c = h2;
    let d = h3;
    let e = h4;
    let f = h5;
    let g = h6;
    let h = h7;

    for (let i = 0; i < 64; i += 1) {
      const S1 =
        (rightRotate32(e, 6) ^ rightRotate32(e, 11) ^ rightRotate32(e, 25)) >>>
        0;
      const ch = ((e & f) ^ (~e & g)) >>> 0;
      const temp1 = (h + S1 + ch + SHA256_K[i] + w[i]) >>> 0;
      const S0 =
        (rightRotate32(a, 2) ^ rightRotate32(a, 13) ^ rightRotate32(a, 22)) >>>
        0;
      const maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
      const temp2 = (S0 + maj) >>> 0;

      h = g;
      g = f;
      f = e;
      e = (d + temp1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) >>> 0;
    }

    // Add to hash state
    h0 = (h0 + a) >>> 0;
    h1 = (h1 + b) >>> 0;
    h2 = (h2 + c) >>> 0;
    h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0;
    h5 = (h5 + f) >>> 0;
    h6 = (h6 + g) >>> 0;
    h7 = (h7 + h) >>> 0;
  }

  const out = new Uint8Array(32);
  const outView = new DataView(out.buffer);
  outView.setUint32(0, h0);
  outView.setUint32(4, h1);
  outView.setUint32(8, h2);
  outView.setUint32(12, h3);
  outView.setUint32(16, h4);
  outView.setUint32(20, h5);
  outView.setUint32(24, h6);
  outView.setUint32(28, h7);
  return out;
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

function hashLike(payload: unknown): string {
  // Deterministic SHA-256 over canonical JSON (mirrors backend hashing intent).
  const input = canonicalStringify(payload);
  const bytes = new TextEncoder().encode(input);
  return `0x${toHex(sha256(bytes))}`;
}

function utcNowIso(): string {
  return new Date().toISOString();
}

function futureExpiry(minutes = 30): string {
  return new Date(Date.now() + minutes * 60 * 1000).toISOString();
}

function pastExpiry(): string {
  return new Date(Date.now() - 5 * 60 * 1000).toISOString();
}

function isExpired(expiry: string): boolean {
  return new Date(expiry).getTime() <= Date.now();
}

class IntentEngine {
  static allowedChainIds = new Set([11155111]);
  static allowedTokens = new Set(['SEP', 'ETH', 'USDC']);
  static allowedRecipients = new Set([
    '0x3333333333333333333333333333333333333333',
    '0x4444444444444444444444444444444444444444',
  ]);

  static autoApprovalLimit = 0.05;
  static executionPolicyTxLimit = 0.05;

  usedNonces = new Set<string>();

  reset() {
    this.usedNonces.clear();
  }

  validate(
    intent: PaymentIntent,
    execution: ProposedExecution,
    opts?: {
      consumeNonce?: boolean;
      enabledChecks?: Set<string> | null;
    },
  ): AuditReceipt {
    const consumeNonce = opts?.consumeNonce ?? true;
    const enabledChecks = opts?.enabledChecks ?? null;

    const checks: PolicyCheck[] = [
      {
        code: 'CHAIN_ALLOWED',
        label: 'Approved network (intent)',
        passed: IntentEngine.allowedChainIds.has(intent.chain_id),
        detail: IntentEngine.allowedChainIds.has(intent.chain_id)
          ? 'Sepolia chain ID 11155111 is authorized.'
          : 'The requested chain is outside the authorization boundary.',
        severity: 'critical',
      },
      {
        code: 'TOKEN_ALLOWED',
        label: 'Approved asset (intent)',
        passed: IntentEngine.allowedTokens.has(intent.token.toUpperCase()),
        detail: IntentEngine.allowedTokens.has(intent.token.toUpperCase())
          ? 'The asset is on the policy allowlist.'
          : 'The asset is not on the policy allowlist.',
        severity: 'critical',
      },
      {
        code: 'RECIPIENT_ALLOWED',
        label: 'Recipient allowlist (intent)',
        passed: IntentEngine.allowedRecipients.has(intent.recipient.toLowerCase()),
        detail: IntentEngine.allowedRecipients.has(intent.recipient.toLowerCase())
          ? 'Recipient is approved by the treasury policy.'
          : 'Recipient is unknown or untrusted.',
        severity: 'critical',
      },
      {
        code: 'AMOUNT_WITHIN_INTENT',
        label: 'Amount ceiling',
        passed: execution.amount <= intent.max_amount,
        detail:
          execution.amount <= intent.max_amount
            ? 'Proposed amount stays within the authorized ceiling.'
            : 'Proposed amount exceeds the authorized maximum.',
        severity: 'critical',
      },
      {
        code: 'EXECUTION_SCOPE_MATCH',
        label: 'Execution scope binding',
        passed:
          execution.recipient.toLowerCase() === intent.recipient.toLowerCase() &&
          execution.chain_id === intent.chain_id &&
          execution.token.toUpperCase() === intent.token.toUpperCase(),
        detail:
          execution.recipient.toLowerCase() === intent.recipient.toLowerCase() &&
          execution.chain_id === intent.chain_id &&
          execution.token.toUpperCase() === intent.token.toUpperCase()
            ? 'Recipient, chain and token match the authorized intent envelope.'
            : 'Observed execution scope differs from the authorized envelope.',
        severity: 'critical',
      },
      {
        code: 'EXECUTION_AMOUNT_EXACT',
        label: 'Exact amount binding',
        passed: execution.amount === intent.amount,
        detail:
          execution.amount === intent.amount
            ? 'The executed amount exactly matches the authorized payment amount.'
            : 'Executed amount differs from the authorized payment amount.',
        severity: 'critical',
      },
      {
        code: 'INTENT_FRESH',
        label: 'Intent expiry',
        passed: !isExpired(intent.expiry),
        detail: !isExpired(intent.expiry)
          ? 'Intent is still valid.'
          : 'Intent has expired and cannot be executed.',
        severity: 'critical',
      },
      {
        code: 'NONCE_UNUSED',
        label: 'Replay protection (process-local)',
        passed: !this.usedNonces.has(intent.nonce),
        detail: !this.usedNonces.has(intent.nonce)
          ? 'Nonce has not been consumed.'
          : 'Nonce was already consumed by an earlier execution.',
        severity: 'critical',
      },
      {
        code: 'EXEC_CHAIN_ALLOWED',
        label: 'Approved network (execution)',
        passed: IntentEngine.allowedChainIds.has(execution.chain_id),
        detail: IntentEngine.allowedChainIds.has(execution.chain_id)
          ? 'Execution chain is on the allowlist.'
          : 'Execution chain is not on the allowlist.',
        severity: 'critical',
      },
      {
        code: 'EXEC_TOKEN_ALLOWED',
        label: 'Approved asset (execution)',
        passed: IntentEngine.allowedTokens.has(execution.token.toUpperCase()),
        detail: IntentEngine.allowedTokens.has(execution.token.toUpperCase())
          ? 'Execution token is on the allowlist.'
          : 'Execution token is not on the allowlist.',
        severity: 'critical',
      },
      {
        code: 'EXEC_RECIPIENT_ALLOWED',
        label: 'Recipient allowlist (execution)',
        passed: IntentEngine.allowedRecipients.has(execution.recipient.toLowerCase()),
        detail: IntentEngine.allowedRecipients.has(execution.recipient.toLowerCase())
          ? 'Execution recipient is on the allowlist.'
          : 'Execution recipient is not on the allowlist.',
        severity: 'critical',
      },
      {
        code: 'EXEC_AMOUNT_WITHIN_POLICY',
        label: 'Execution-time spend limit',
        passed: execution.amount <= IntentEngine.executionPolicyTxLimit,
        detail:
          execution.amount <= IntentEngine.executionPolicyTxLimit
            ? `Execution amount is within the configured limit (${IntentEngine.executionPolicyTxLimit}).`
            : `Execution amount exceeds the configured limit (${IntentEngine.executionPolicyTxLimit}).`,
        severity: 'critical',
      },
    ];

    const filteredChecks = enabledChecks
      ? checks.filter(check => enabledChecks.has(check.code))
      : checks;

    const criticalFailure = filteredChecks.some(check => !check.passed);
    const decision = criticalFailure
      ? 'DENY'
      : execution.amount > IntentEngine.autoApprovalLimit
        ? 'HUMAN_REVIEW'
        : 'AUTO_APPROVE';

    const intent_hash = hashLike(intent);
    const execution_hash = hashLike(execution);

    let tx_hash: string | null = null;
    if (decision !== 'DENY') {
      if (consumeNonce) {
        this.usedNonces.add(intent.nonce);
      }
      tx_hash = hashLike({ intent_hash, execution_hash, nonce: intent.nonce });
    }

    const evidence_hash = hashLike({
      intent_hash,
      execution_hash,
      decision,
      checks: filteredChecks,
    });

    return {
      receipt_id: `rcpt_${hashLike({ scenario: intent.intent_id }).slice(2, 10)}`,
      intent_hash,
      execution_hash,
      decision,
      policy_checks: filteredChecks,
      tx_hash,
      evidence_hash,
      timestamp: utcNowIso(),
      network: 'Sepolia simulation (chain ID 11155111)',
      attestation_status: 'READY_FOR_SEPOLIA',
    };
  }
}

function baseIntent(nonce: string): PaymentIntent {
  return {
    intent_id: `intent_${nonce.slice(-6)}`,
    payer,
    recipient: defaultRecipient,
    chain_id: 11155111,
    token: 'SEP',
    amount: 0.008,
    max_amount: 0.01,
    purpose: 'Purchase a verified research dataset for the AI agent',
    expiry: futureExpiry(),
    nonce,
    resource_hash: 'sha256:7f9b6d2f43a34c5d9a0c18b66a4c8aa9',
  };
}

function timeline(receipt: AuditReceipt) {
  const allowed = receipt.decision !== 'DENY';
  return [
    {
      stage: '01',
      title: 'Intent captured',
      status: 'PASS',
      detail:
        'Payment request normalized into a machine-checkable envelope for the deterministic fixture path.',
    },
    {
      stage: '02',
      title: 'Policy boundary',
      status: allowed ? 'PASS' : 'BLOCKED',
      detail:
        'Deterministic controls evaluate recipient, value, network, expiry and nonce.',
    },
    {
      stage: '03',
      title: 'Execution gate',
      status: allowed ? 'PASS' : 'NOT_EXECUTED',
      detail:
        'Wallet execution is released only when the proposed call matches the intent.',
    },
    {
      stage: '04',
      title: 'Evidence sealed',
      status: 'PASS',
      detail:
        'Intent, execution and policy outcome are bound into an auditable evidence hash.',
    },
  ];
}

export function fallbackResult(id: ScenarioId): DemoResult {
  const engine = new IntentEngine();
  const nonce = `nonce-${id}-001`;
  const intent = baseIntent(nonce);

  const execution: ProposedExecution = {
    recipient: intent.recipient,
    chain_id: intent.chain_id,
    token: intent.token,
    amount: intent.amount,
    calldata_hash: hashLike({ seed: id, tag: 'calldata' }),
  };

  let title = 'Authorized agent purchase';
  let summary =
    'A bounded Sepolia payment passes intent, policy and execution-integrity checks.';

  if (id === 'tampered') {
    execution.recipient = '0x1111111111111111111111111111111111111111';
    execution.amount = 0.8;
    title = 'Prompt-injected payment';
    summary =
      'Recipient substitution and 100× amount escalation are blocked before wallet release.';
  }

  if (id === 'replay') {
    title = 'Replay attempt';
    summary =
      'The first authorized payment consumes the in-memory nonce state; an identical second request is denied.';
  }

  const intentGuardFullChecks = new Set([
    'CHAIN_ALLOWED',
    'TOKEN_ALLOWED',
    'RECIPIENT_ALLOWED',
    'AMOUNT_WITHIN_INTENT',
    'EXECUTION_SCOPE_MATCH',
    'EXECUTION_AMOUNT_EXACT',
    'INTENT_FRESH',
    'NONCE_UNUSED',
  ]);

  const firstReceipt = engine.validate(intent, execution, {
    enabledChecks: intentGuardFullChecks,
  });
  let receipt = firstReceipt;
  let replayReceipt: AuditReceipt | null = null;
  if (id === 'replay') {
    replayReceipt = engine.validate(intent, execution, {
      enabledChecks: intentGuardFullChecks,
    });
    receipt = replayReceipt;
  }

  return {
    scenario_id: id,
    title,
    summary,
    decision: receipt.decision,
    intent,
    proposed_execution: execution,
    policy_checks: receipt.policy_checks,
    timeline: timeline(receipt),
    audit_receipt: receipt,
    replay_receipt: replayReceipt,
  };
}

type FixtureCase = {
  case_id: string;
  kind: 'legitimate' | 'attack';
  intent_patch: Partial<PaymentIntent>;
  execution_patch: Partial<ProposedExecution>;
  replay?: boolean;
};

export const controlDefinitions: ControlDefinition[] = [
  {
    id: 'intent-allowlists',
    label: 'Intent-time allowlists',
    description:
      'Check that the authorized envelope targets an approved chain/token/recipient allowlist.',
    check_codes: ['CHAIN_ALLOWED', 'TOKEN_ALLOWED', 'RECIPIENT_ALLOWED'],
  },
  {
    id: 'intent-max-amount',
    label: 'Intent-time amount ceiling',
    description: 'Enforce execution.amount ≤ intent.max_amount.',
    check_codes: ['AMOUNT_WITHIN_INTENT'],
  },
  {
    id: 'intent-expiry',
    label: 'Intent expiry',
    description: 'Enforce deadline/expiry on the authorization envelope.',
    check_codes: ['INTENT_FRESH'],
  },
  {
    id: 'execution-scope-binding',
    label: 'Cross-layer intent→execution binding (scope)',
    description:
      'Bind recipient/token/chain of execution to the authorized envelope (prevents TOCTOU scope substitution).',
    check_codes: ['EXECUTION_SCOPE_MATCH'],
  },
  {
    id: 'execution-amount-exact',
    label: 'Cross-layer intent→execution binding (exact amount)',
    description:
      'Bind the exact payment amount at execution time (dynamic-linking style).',
    check_codes: ['EXECUTION_AMOUNT_EXACT'],
  },
  {
    id: 'replay-guard-process-local',
    label: 'Replay guard (process-local)',
    description:
      'Consume-once semantics via an in-memory nonce registry (prototype scope: one process lifetime).',
    check_codes: ['NONCE_UNUSED'],
  },
  {
    id: 'execution-policy-allowlists',
    label: 'Execution-time allowlists',
    description:
      'Smart-account/module style policy that checks chain/token/recipient allowlists at execution time.',
    check_codes: ['EXEC_CHAIN_ALLOWED', 'EXEC_TOKEN_ALLOWED', 'EXEC_RECIPIENT_ALLOWED'],
  },
  {
    id: 'execution-policy-max-amount',
    label: 'Execution-time spend limit',
    description:
      'Smart-account/module style per-call amount limit (independent of per-intent authorization).',
    check_codes: ['EXEC_AMOUNT_WITHIN_POLICY'],
  },
];

const controlMap = new Map(
  controlDefinitions.map(item => [item.id, new Set(item.check_codes)]),
);

function resolveCheckCodes(controls: string[]): Set<string> {
  const codes = new Set<string>();
  controls.forEach(control => {
    const bucket = controlMap.get(control);
    if (!bucket) return;
    bucket.forEach(code => codes.add(code));
  });
  return codes;
}

const baselineTemplates = [
  {
    id: 'policy-gate-only',
    label: 'Policy gate only',
    state_model: 'stateless',
    controls: ['intent-allowlists', 'intent-max-amount', 'intent-expiry'],
  },
  {
    id: 'smart-account-policy',
    label: 'Smart account policy only',
    state_model: 'stateless',
    controls: ['execution-policy-allowlists', 'execution-policy-max-amount'],
  },
  {
    id: 'stateless-intent-execution-binding',
    label: 'Stateless intent/execution binding',
    state_model: 'stateless',
    controls: ['execution-scope-binding', 'intent-max-amount', 'intent-expiry'],
  },
  {
    id: 'intentguard-full',
    label: 'IntentGuard full',
    state_model: 'process-local',
    controls: [
      'intent-allowlists',
      'intent-max-amount',
      'intent-expiry',
      'execution-scope-binding',
      'execution-amount-exact',
      'replay-guard-process-local',
    ],
  },
] as const;

const ablationTemplates = [
  {
    mode: 'full_without_execution_binding',
    label: 'w/o Execution binding',
    removed_control: 'Execution binding (scope + exact)',
    controls: ['intent-allowlists', 'intent-max-amount', 'intent-expiry', 'replay-guard-process-local'],
  },
  {
    mode: 'full_without_exact_amount_binding',
    label: 'w/o Exact amount binding',
    removed_control: 'Exact amount binding',
    controls: [
      'intent-allowlists',
      'intent-max-amount',
      'intent-expiry',
      'execution-scope-binding',
      'replay-guard-process-local',
    ],
  },
  {
    mode: 'full_without_replay_guard',
    label: 'w/o Replay guard',
    removed_control: 'Process-local nonce registry',
    controls: [
      'intent-allowlists',
      'intent-max-amount',
      'intent-expiry',
      'execution-scope-binding',
      'execution-amount-exact',
    ],
  },
  {
    mode: 'full_without_intent_allowlists',
    label: 'w/o Intent allowlists',
    removed_control: 'Intent-time allowlists',
    controls: [
      'intent-max-amount',
      'intent-expiry',
      'execution-scope-binding',
      'execution-amount-exact',
      'replay-guard-process-local',
    ],
  },
] as const;

const fixtures: FixtureCase[] = [
  { case_id: 'legitimate-small', kind: 'legitimate', intent_patch: {}, execution_patch: {} },
  {
    case_id: 'legitimate-large',
    kind: 'legitimate',
    intent_patch: { amount: 0.04, max_amount: 0.05 },
    execution_patch: { amount: 0.04 },
  },
  {
    case_id: 'recipient-substitution-within-allowlist',
    kind: 'attack',
    intent_patch: {},
    execution_patch: { recipient: '0x4444444444444444444444444444444444444444' },
  },
  {
    case_id: 'recipient-substitution-external',
    kind: 'attack',
    intent_patch: {},
    execution_patch: { recipient: '0x1111111111111111111111111111111111111111' },
  },
  {
    case_id: 'over-ceiling-amount',
    kind: 'attack',
    intent_patch: { max_amount: 0.01 },
    execution_patch: { amount: 0.011 },
  },
  {
    case_id: 'subtle-amount-mutation-within-ceiling',
    kind: 'attack',
    intent_patch: { amount: 0.008, max_amount: 0.01 },
    execution_patch: { amount: 0.009 },
  },
  {
    case_id: 'execution-chain-switch',
    kind: 'attack',
    intent_patch: {},
    execution_patch: { chain_id: 1 },
  },
  {
    case_id: 'execution-token-switch',
    kind: 'attack',
    intent_patch: {},
    execution_patch: { token: 'DAI' },
  },
  {
    case_id: 'expired-intent',
    kind: 'attack',
    intent_patch: { expiry: pastExpiry() },
    execution_patch: {},
  },
  {
    case_id: 'replay-attempt',
    kind: 'attack',
    intent_patch: {},
    execution_patch: {},
    replay: true,
  },
  {
    case_id: 'unapproved-recipient-intent',
    kind: 'attack',
    intent_patch: { recipient: '0xdeadbeef' },
    execution_patch: { recipient: '0xdeadbeef' },
  },
];

function evaluateProfile(opts: {
  enabledChecks: Set<string>;
  stateModel: 'stateless' | 'process-local';
  consumeNonce: boolean;
}): { summary: Omit<BaselineComparison, 'mode' | 'label'>; outcomes: Evaluation['outcomes'] } {
  const outcomes: Evaluation['outcomes'] = [];
  const sharedEngine = opts.stateModel === 'process-local' ? new IntentEngine() : null;

  fixtures.forEach((fixture, index) => {
    const expected = fixture.kind === 'legitimate' ? 'ALLOW' : 'DENY';

    let receipt: AuditReceipt;

    if (fixture.replay) {
      const replayIntent = { ...baseIntent('replay-nonce'), ...fixture.intent_patch };
      const mkExecution = (): ProposedExecution => ({
        recipient: replayIntent.recipient,
        chain_id: replayIntent.chain_id,
        token: replayIntent.token,
        amount: replayIntent.amount,
        calldata_hash: '0x' + 'aa'.repeat(32),
      });

      const runAttempt = (engine: IntentEngine) =>
        engine.validate(replayIntent, mkExecution(), {
          consumeNonce: opts.consumeNonce,
          enabledChecks: opts.enabledChecks,
        });

      if (sharedEngine) {
        runAttempt(sharedEngine);
        receipt = runAttempt(sharedEngine);
      } else {
        runAttempt(new IntentEngine());
        receipt = runAttempt(new IntentEngine());
      }
    } else {
      const engine = sharedEngine ?? new IntentEngine();
      const intent = { ...baseIntent(`bench-${String(index).padStart(2, '0')}`), ...fixture.intent_patch };
      const execution: ProposedExecution = {
        recipient: intent.recipient,
        chain_id: intent.chain_id,
        token: intent.token,
        amount: intent.amount,
        calldata_hash: '0x' + '56'.repeat(32),
        ...fixture.execution_patch,
      };

      receipt = engine.validate(intent, execution, {
        consumeNonce: opts.consumeNonce,
        enabledChecks: opts.enabledChecks,
      });
    }

    const blocked = receipt.decision === 'DENY';
    const correct = fixture.kind === 'attack' ? blocked : !blocked;

    outcomes.push({
      case: fixture.case_id,
      type: fixture.kind,
      decision: receipt.decision,
      expected,
      correct,
    });
  });

  const attack = outcomes.filter(row => row.type === 'attack');
  const benign = outcomes.filter(row => row.type === 'legitimate');

  const summary = {
    attack_block_rate: attack.length
      ? Math.round((100 * attack.filter(row => row.correct).length) / attack.length)
      : 0,
    benign_completion_rate: benign.length
      ? Math.round((100 * benign.filter(row => row.correct).length) / benign.length)
      : 0,
    false_rejection_rate: benign.length
      ? Math.round((100 * benign.filter(row => !row.correct).length) / benign.length)
      : 0,
    blocked_attacks: attack.filter(row => row.correct).length,
    total_attacks: attack.length,
  };

  return { summary, outcomes };
}

export function computeEvaluation(): Evaluation {
  const started = performance.now();

  const baseline_definitions: BaselineDefinition[] = baselineTemplates.map(item => {
    const enabled = resolveCheckCodes([...item.controls]);
    return {
      id: item.id,
      label: item.label,
      state_model: item.state_model,
      controls: [...item.controls],
      enabled_check_codes: [...enabled].sort(),
    };
  });

  const baseline_comparison: BaselineComparison[] = baselineTemplates.map(item => {
    const enabled = resolveCheckCodes([...item.controls]);
    const consumeNonce = enabled.has('NONCE_UNUSED');
    const { summary } = evaluateProfile({
      enabledChecks: enabled,
      stateModel: item.state_model,
      consumeNonce,
    });

    return {
      mode: item.id,
      label: item.label,
      ...summary,
    };
  });

  const full = baselineTemplates.find(item => item.id === 'intentguard-full');
  if (!full) {
    throw new Error('intentguard-full baseline missing');
  }
  const fullEnabled = resolveCheckCodes([...full.controls]);
  const fullConsumeNonce = fullEnabled.has('NONCE_UNUSED');
  const { summary: fullSummary, outcomes } = evaluateProfile({
    enabledChecks: fullEnabled,
    stateModel: 'process-local',
    consumeNonce: fullConsumeNonce,
  });

  const ablations: AblationStudy[] = ablationTemplates.map(item => {
    const enabled = resolveCheckCodes([...item.controls]);
    const consumeNonce = enabled.has('NONCE_UNUSED');
    const { summary } = evaluateProfile({
      enabledChecks: enabled,
      stateModel: consumeNonce ? 'process-local' : 'stateless',
      consumeNonce,
    });

    return {
      mode: item.mode,
      label: item.label,
      attack_block_rate: summary.attack_block_rate,
      delta_vs_full_pp: summary.attack_block_rate - fullSummary.attack_block_rate,
      removed_control: item.removed_control,
    };
  });

  const evaluation_time_ms = Math.round((performance.now() - started) * 1000) / 1000;

  return {
    total_cases: fixtures.length,
    attack_block_rate: fullSummary.attack_block_rate,
    benign_completion_rate: fullSummary.benign_completion_rate,
    false_rejection_rate: fullSummary.false_rejection_rate,
    evaluation_time_ms,
    methodology: {
      benchmark_type: 'Deterministic synthetic fixtures',
      profile_scope: 'Mechanism-level control baselines (not upstream projects)',
      state_model: 'In-memory engine; process-local replay state only when enabled',
      network_scope: 'Sepolia domain signing and read-only receipt checks; no transaction broadcast',
    },
    control_definitions: controlDefinitions,
    baseline_definitions,
    baseline_comparison,
    ablations,
    outcomes,
    limitations: [
      'The deterministic benchmark remains intentionally small (11 fixtures) and does not cover every payment threat.',
      'The dashboard exposes a MetaMask review-and-sign flow with local signer recovery and session-local replay denial, but it does not broadcast transactions or provide production custody controls.',
      'Replay guard is process-local; no persistent used-intent registry is provided.',
      'Results are computed from local fixtures and property tests and should not be interpreted as external product scores.',
    ],
  };
}

export const fallbackEvaluation: Evaluation = computeEvaluation();
