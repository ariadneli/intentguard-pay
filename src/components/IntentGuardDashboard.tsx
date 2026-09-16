import { loadEvaluation, runScenario } from '@/lib/api';
import {
  type DemoResult,
  type Evaluation,
  type ScenarioId,
  fallbackEvaluation,
  fallbackResult,
  scenarios,
} from '@/lib/demo';
import {
  Activity,
  ArrowDown,
  ArrowRight,
  BadgeCheck,
  Ban,
  Blocks,
  Bot,
  Check,
  ChevronRight,
  Fingerprint,
  Gauge,
  KeyRound,
  LockKeyhole,
  Network,
  Play,
  RefreshCcw,
  ScanSearch,
  ShieldCheck,
  Sparkles,
  TriangleAlert,
  WalletCards,
  Zap,
} from 'lucide-react';
import { useEffect, useState } from 'react';
import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import LiveSepoliaVerifier from './LiveSepoliaVerifier';
import SignedIntentDemo from './SignedIntentDemo';

const shortHash = (value: string | null) =>
  value ? `${value.slice(0, 10)}…${value.slice(-8)}` : 'Not emitted';

const decisionCopy: Record<string, string> = {
  AUTO_APPROVE: 'Execution authorized',
  HUMAN_REVIEW: 'Human review required',
  DENY: 'Execution blocked',
};

function MiniTag({ children }: { children: React.ReactNode }) {
  return <span className="mini-tag">{children}</span>;
}

function ValueRow({
  label,
  value,
  danger = false,
}: {
  label: string;
  value: string;
  danger?: boolean;
}) {
  return (
    <div className={`value-row ${danger ? 'value-row-danger' : ''}`}>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function LogoMark() {
  return (
    <div className="logo-mark" aria-hidden="true">
      <Fingerprint size={21} />
    </div>
  );
}

export default function IntentGuardDashboard() {
  const [activeScenario, setActiveScenario] = useState<ScenarioId>('normal');
  const [result, setResult] = useState<DemoResult>(() =>
    fallbackResult('normal'),
  );
  const [evaluation, setEvaluation] = useState<Evaluation>(fallbackEvaluation);
  const [runCount, setRunCount] = useState(1);
  const [isPending, setIsPending] = useState(false);

  useEffect(() => {
    loadEvaluation()
      .then(setEvaluation)
      .catch(() => setEvaluation(fallbackEvaluation));
  }, []);

  const handleRun = async (id: ScenarioId) => {
    setActiveScenario(id);
    setIsPending(true);
    try {
      const response = await runScenario(id);
      setResult(response.result);
      setRunCount(count => count + 1);
    } finally {
      setIsPending(false);
    }
  };

  const isDenied = result.decision === 'DENY';
  const recipientChanged =
    result.intent.recipient.toLowerCase() !==
    result.proposed_execution.recipient.toLowerCase();
  const amountChanged =
    result.intent.amount !== result.proposed_execution.amount;
  const passedChecks = result.policy_checks.filter(
    check => check.passed,
  ).length;
  const comparisonData = evaluation.baseline_comparison.map(b => ({
    name: b.label,
    block: b.attack_block_rate,
    benign: b.benign_completion_rate,
  }));

  return (
    <main className="app-shell">
      <div className="ambient ambient-one" />
      <div className="ambient ambient-two" />

      <header className="site-header">
        <a className="brand" href="#top" aria-label="IntentGuard Pay home">
          <LogoMark />
          <div>
            <strong>IntentGuard</strong>
            <span>PAY</span>
          </div>
        </a>
        <nav>
          <a href="#research">Research context</a>
          <a href="#sign-intent">Sign intent</a>
          <a href="#console">Fixture console</a>
          <a href="#evaluation">Evaluation</a>
          <a href="#architecture">Architecture</a>
        </nav>
        <div className="network-pill">
          <span className="pulse-dot" />
          Sepolia · 11155111
        </div>
      </header>

      <section className="hero" id="top">
        <div className="hero-copy">
          <div className="eyebrow">
            <Sparkles size={14} /> Public research prototype
          </div>
          <h1>
            Research prototype for
            <span>agentic payment authorization.</span>
          </h1>
          <p>
            IntentGuard studies whether an agent can remain useful while payment
            release is delegated to a deterministic, machine-checkable boundary.
            The prototype compares mechanism baselines, validates proposed
            calls before wallet release, and reconstructs evidence after
            execution.
          </p>
          <div className="hero-actions">
            <a className="primary-action" href="#console">
              Inspect fixture runs <ArrowDown size={17} />
            </a>
            <div className="hero-proof">
              <ShieldCheck size={18} />
              <span>
                <strong>Deterministic controls</strong> between probabilistic AI
                and irreversible money
              </span>
            </div>
          </div>
        </div>

        <aside className="thesis-card">
          <div className="thesis-topline">
            <MiniTag>RESEARCH QUESTION</MiniTag>
            <span>01 / 03</span>
          </div>
          <blockquote>
            Can deterministic intent validation prevent unauthorized agentic
            payments
            <em> without blocking legitimate autonomy?</em>
          </blockquote>
          <div className="thesis-divider" />
          <div className="thesis-metrics">
            <div>
              <span>Boundary</span>
              <strong>Intent → Execution</strong>
            </div>
            <div>
              <span>Fixtures</span>
              <strong>9 attack / 11 total</strong>
            </div>
            <div>
              <span>Evidence</span>
              <strong>Pre + post validation</strong>
            </div>
          </div>
        </aside>
      </section>

      <section className="research-section" id="research">
        <div className="section-heading">
          <div>
            <MiniTag>RESEARCH CONTEXT</MiniTag>
            <h2>Where IntentGuard sits in the defense landscape.</h2>
            <p className="section-description">
              EIP-712, wallet simulation, smart-account policies, and receipts
              each protect a different layer. IntentGuard studies the gap
              between an agent&apos;s proposed payment and the bounded execution the
              user actually meant to authorize.
            </p>
          </div>
          <div className="runtime-state">
            <ScanSearch size={16} />
            <span>5-stage coverage chain</span>
            <small>intent → policy → execution → replay → evidence</small>
          </div>
        </div>

        <div className="research-grid">
          {[
            {
              icon: WalletCards,
              title: 'Readable review',
              label: 'EIP-712 / wallet simulation',
              detail:
                'Improves what humans can inspect before signing, but does not by itself consume authorization or bind every agent tool call.',
            },
            {
              icon: Bot,
              title: 'Agent tool security',
              label: 'Prompt injection / confused deputy',
              detail:
                'An agent can produce a syntactically valid payment that is still outside the user-authorized outcome.',
            },
            {
              icon: ShieldCheck,
              title: 'Policy enforcement',
              label: 'Smart accounts / modular policies',
              detail:
                'Execution-time rules can be strong, but this repository does not claim ERC-4337 or on-chain enforcement is implemented.',
            },
            {
              icon: KeyRound,
              title: 'Execution evidence',
              label: 'Receipts / logs / traces',
              detail:
                'Post-execution artifacts reconstruct what happened on-chain, not why the payment was originally authorized.',
            },
          ].map(item => (
            <article className="research-card" key={item.title}>
              <item.icon size={18} />
              <small>{item.label}</small>
              <strong>{item.title}</strong>
              <p>{item.detail}</p>
            </article>
          ))}
        </div>

        <div className="research-note">
          <strong>IntentGuard gap:</strong> EIP-712 signer recovery +
          deterministic policy + exact execution binding + consume-once replay
          state. PAACT-Core v1 evaluates 1,000 deterministic corpus cases under
          the same mechanism-level runner.
        </div>
      </section>

      <SignedIntentDemo />

      <section className="demo-section" id="console">
        <div className="section-heading">
          <div>
            <MiniTag>FIXTURE CONSOLE</MiniTag>
            <h2>Deterministic scenarios at one authorization boundary.</h2>
          </div>
          <div className="runtime-state">
            <Activity size={16} />
            <span>Self-contained research build</span>
            <small>Run #{String(runCount).padStart(2, '0')}</small>
          </div>
        </div>

        <div className="scenario-grid">
          {scenarios.map((scenario, index) => {
            const selected = scenario.id === activeScenario;
            return (
              <button
                className={`scenario-card ${selected ? 'scenario-active' : ''}`}
                key={scenario.id}
                onClick={() => handleRun(scenario.id)}
                type="button"
              >
                <span className="scenario-number">0{index + 1}</span>
                <div>
                  <small>{scenario.eyebrow}</small>
                  <strong>{scenario.title}</strong>
                  <p>{scenario.description}</p>
                </div>
                <span className="scenario-play">
                  {selected && isPending ? (
                    <RefreshCcw className="spin" size={16} />
                  ) : (
                    <Play size={16} />
                  )}
                </span>
              </button>
            );
          })}
        </div>

        <div
          className={`decision-banner ${isDenied ? 'decision-denied' : 'decision-approved'}`}
        >
          <div className="decision-icon">
            {isDenied ? <Ban size={25} /> : <BadgeCheck size={25} />}
          </div>
          <div>
            <span>POLICY DECISION</span>
            <h3>{decisionCopy[result.decision] ?? result.decision}</h3>
            <p>{result.summary}</p>
          </div>
          <div className="decision-score">
            <strong>
              {passedChecks}/{result.policy_checks.length}
            </strong>
            <span>checks passed</span>
          </div>
        </div>

        <div className="execution-grid">
          <div className="flow-panel glass-panel">
            <div className="panel-title">
              <div>
                <Network size={18} />
                <span>Execution trace</span>
              </div>
              <MiniTag>LIVE</MiniTag>
            </div>
            <div className="timeline">
              {result.timeline.map((step, index) => (
                <div className="timeline-step" key={step.stage}>
                  <div
                    className={`timeline-node ${step.status === 'BLOCKED' || step.status === 'NOT_EXECUTED' ? 'node-blocked' : ''}`}
                  >
                    {step.status === 'BLOCKED' ||
                    step.status === 'NOT_EXECUTED' ? (
                      <Ban size={15} />
                    ) : (
                      <Check size={15} />
                    )}
                  </div>
                  {index < result.timeline.length - 1 && (
                    <div className="timeline-line" />
                  )}
                  <div className="timeline-copy">
                    <span>
                      {step.stage} · {step.status}
                    </span>
                    <strong>{step.title}</strong>
                    <p>{step.detail}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="compare-panel glass-panel">
            <div className="panel-title">
              <div>
                <ScanSearch size={18} />
                <span>Intent ↔ execution diff</span>
              </div>
              <MiniTag>
                {recipientChanged || amountChanged ? 'MISMATCH' : 'EXACT MATCH'}
              </MiniTag>
            </div>
            <div className="compare-columns">
              <div>
                <small>AUTHORIZED INTENT</small>
                <ValueRow label="Network" value="Sepolia" />
                <ValueRow
                  label="Recipient"
                  value={shortHash(result.intent.recipient)}
                />
                <ValueRow
                  label="Amount"
                  value={`${result.intent.amount} ${result.intent.token}`}
                />
                <ValueRow
                  label="Ceiling"
                  value={`${result.intent.max_amount} ${result.intent.token}`}
                />
                <ValueRow label="Nonce" value={result.intent.nonce} />
              </div>
              <div className="compare-arrow">
                <ArrowRight size={18} />
              </div>
              <div>
                <small>PROPOSED EXECUTION</small>
                <ValueRow
                  label="Network"
                  value={String(result.proposed_execution.chain_id)}
                />
                <ValueRow
                  label="Recipient"
                  value={shortHash(result.proposed_execution.recipient)}
                  danger={recipientChanged}
                />
                <ValueRow
                  label="Amount"
                  value={`${result.proposed_execution.amount} ${result.proposed_execution.token}`}
                  danger={amountChanged}
                />
                <ValueRow
                  label="Call data"
                  value={shortHash(result.proposed_execution.calldata_hash)}
                />
                <ValueRow
                  label="Wallet"
                  value={isDenied ? 'Never invoked' : 'Released'}
                  danger={isDenied}
                />
              </div>
            </div>
          </div>
        </div>

        <div className="policy-panel glass-panel">
          <div className="panel-title">
            <div>
              <LockKeyhole size={18} />
              <span>Deterministic policy firewall</span>
            </div>
            <span className="policy-caption">
              No LLM decides whether money moves.
            </span>
          </div>
          <div className="check-grid">
            {result.policy_checks.map(check => (
              <article
                className={`check-card ${check.passed ? '' : 'check-failed'}`}
                key={check.code}
              >
                <span className="check-icon">
                  {check.passed ? (
                    <Check size={15} />
                  ) : (
                    <TriangleAlert size={15} />
                  )}
                </span>
                <div>
                  <small>{check.code.replaceAll('_', ' ')}</small>
                  <strong>{check.label}</strong>
                  <p>{check.detail}</p>
                </div>
              </article>
            ))}
          </div>
        </div>

        <div className="receipt-panel">
          <div className="receipt-head">
            <div>
              <MiniTag>AUDIT RECEIPT</MiniTag>
              <h3>Cryptographic evidence, not a success toast.</h3>
            </div>
            <div className={`receipt-stamp ${isDenied ? 'stamp-denied' : ''}`}>
              {isDenied ? 'BLOCKED' : 'VERIFIED'}
            </div>
          </div>
          <div className="receipt-grid">
            <div>
              <span>Receipt ID</span>
              <strong>{result.audit_receipt.receipt_id}</strong>
            </div>
            <div>
              <span>Intent hash</span>
              <strong>{shortHash(result.audit_receipt.intent_hash)}</strong>
            </div>
            <div>
              <span>Execution hash</span>
              <strong>{shortHash(result.audit_receipt.execution_hash)}</strong>
            </div>
            <div>
              <span>Transaction</span>
              <strong>{shortHash(result.audit_receipt.tx_hash)}</strong>
            </div>
            <div>
              <span>Evidence hash</span>
              <strong>{shortHash(result.audit_receipt.evidence_hash)}</strong>
            </div>
            <div>
              <span>Attestation</span>
              <strong>{result.audit_receipt.attestation_status}</strong>
            </div>
          </div>
        </div>
      </section>

      <section className="evaluation-section" id="evaluation">
        <div className="section-heading">
          <div>
            <MiniTag>DETERMINISTIC EVALUATION</MiniTag>
            <h2>Mechanism baselines & benchmarks.</h2>
            <p className="evaluation-disclaimer">
              Deterministic synthetic benchmark / mechanism-level control
              baselines, not upstream reimplementations / no live-chain
              performance claim.
            </p>
          </div>
          <div className="methodology-badge">
            <div className="methodology-item">
              <span>Benchmark</span>
              <strong>{evaluation.methodology.benchmark_type}</strong>
            </div>
            <div className="methodology-item">
              <span>Network</span>
              <strong>{evaluation.methodology.network_scope}</strong>
            </div>
          </div>
        </div>

        <div className="evaluation-grid">
          <div className="metric-stack">
            <article>
              <ShieldCheck size={20} />
              <span>Attack block rate</span>
              <strong>{evaluation.attack_block_rate}%</strong>
              <small>920 / 920 adversarial cases</small>
            </article>
            <article>
              <Zap size={20} />
              <span>Benign completion</span>
              <strong>{evaluation.benign_completion_rate}%</strong>
              <small>80 / 80 benign boundaries</small>
            </article>
            <article>
              <Gauge size={20} />
              <span>False rejection</span>
              <strong>{evaluation.false_rejection_rate}%</strong>
              <small>Intent/Policy suite</small>
            </article>
          </div>

          <div className="chart-panel glass-panel">
            <div className="panel-title">
              <div>
                <Activity size={18} />
                <span>Baseline comparison</span>
              </div>
              <MiniTag>PROFILES</MiniTag>
            </div>
            <div className="chart-container">
              <ResponsiveContainer height={200} width="100%">
                <BarChart
                  data={comparisonData}
                  layout="vertical"
                  margin={{ left: -10, right: 20 }}
                >
                  <CartesianGrid
                    horizontal={false}
                    stroke="#26324a"
                    strokeDasharray="3 3"
                  />
                  <XAxis
                    axisLine={false}
                    domain={[0, 100]}
                    tick={{ fill: '#8794ad', fontSize: 10 }}
                    type="number"
                  />
                  <YAxis
                    axisLine={false}
                    dataKey="name"
                    tick={{ fill: '#cbd4e6', fontSize: 10 }}
                    tickLine={false}
                    type="category"
                    width={100}
                  />
                  <Tooltip
                    cursor={{ fill: 'rgba(255,255,255,.03)' }}
                    contentStyle={{
                      backgroundColor: '#11192a',
                      border: '1px solid #26324a',
                      fontSize: '10px',
                    }}
                  />
                  <Bar
                    dataKey="block"
                    fill="#68f6c4"
                    name="Attack Block"
                    radius={[0, 4, 4, 0]}
                    barSize={12}
                  />
                  <Bar
                    dataKey="benign"
                    fill="#8b7dff"
                    name="Benign Pass"
                    radius={[0, 4, 4, 0]}
                    barSize={12}
                  />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div className="ablation-panel glass-panel">
            <div className="panel-title">
              <div>
                <Zap size={18} />
                <span>Ablation study</span>
              </div>
              <MiniTag>DELTA</MiniTag>
            </div>
            <div className="ablation-list">
              {evaluation.ablations.map(item => (
                <div key={item.mode} className="ablation-row">
                  <div className="ablation-meta">
                    <strong>{item.label}</strong>
                    <small>Removed: {item.removed_control}</small>
                  </div>
                  <div className="ablation-stats">
                    <span className="ablation-delta">
                      {item.delta_vs_full_pp} pp
                    </span>
                    <span className="ablation-rate">
                      {item.attack_block_rate}% block
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="fixture-panel glass-panel">
            <div className="panel-title">
              <div>
                <Blocks size={18} />
                <span>Corpus family outcomes</span>
              </div>
              <MiniTag>{evaluation.total_cases} CASES</MiniTag>
            </div>
            <div className="fixture-list">
              {evaluation.outcomes.map(row => (
                <div key={row.case}>
                  <span
                    className={
                      row.type === 'attack'
                        ? 'fixture-attack'
                        : 'fixture-benign'
                    }
                  >
                    {row.type}
                  </span>
                  <strong>{row.case.replaceAll('-', ' ')}</strong>
                  <small>{row.decision}</small>
                  <Check size={15} />
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      <LiveSepoliaVerifier />

      <section className="architecture-section" id="architecture">
        <div className="section-heading centered-heading">
          <MiniTag>SYSTEM ARCHITECTURE</MiniTag>
          <h2>Probabilistic planning. Deterministic money.</h2>
          <p className="section-description">
            We preserve the usefulness of an AI planner while removing its
            authority to unilaterally redefine the payment boundary.
          </p>
        </div>
        <div className="architecture-flow">
          {[
            {
              icon: Bot,
              label: 'AI planner',
              note: 'Probabilistic',
              tone: 'violet',
            },
            {
              icon: Fingerprint,
              label: 'Payment envelope',
              note: 'EIP-712 signed',
              tone: 'blue',
            },
            {
              icon: ShieldCheck,
              label: 'Policy gate',
              note: 'Deterministic',
              tone: 'mint',
            },
            {
              icon: WalletCards,
              label: 'Wallet',
              note: 'Least privilege',
              tone: 'amber',
            },
            {
              icon: KeyRound,
              label: 'Evidence',
              note: 'Post-validated',
              tone: 'rose',
            },
          ].map((item, index, all) => (
            <div className="architecture-item-wrap" key={item.label}>
              <div className={`architecture-item architecture-${item.tone}`}>
                <item.icon size={24} />
                <span>{item.label}</span>
                <small>{item.note}</small>
              </div>
              {index < all.length - 1 && (
                <ChevronRight className="architecture-arrow" size={19} />
              )}
            </div>
          ))}
        </div>
        <div className="contribution-grid">
          <article>
            <ShieldCheck size={21} />
            <span>Authorization boundary</span>
            <p>
              A canonical PaymentIntent captures recipient, amount, chain, token,
              expiry, nonce, and resource context before wallet release.
            </p>
          </article>
          <article>
            <Fingerprint size={21} />
            <span>Execution-integrity validation</span>
            <p>
              Deterministic checks bind the proposed execution to the authorized
              envelope and reject scope drift or replay.
            </p>
          </article>
          <article>
            <KeyRound size={21} />
            <span>Checkable evidence</span>
            <p>
              Receipt reconstruction and stable hashes make both the decision path
              and observable execution independently auditable.
            </p>
          </article>
        </div>
      </section>

      <footer>
        <div className="brand">
          <LogoMark />
          <div>
            <strong>IntentGuard</strong>
            <span>PAY</span>
          </div>
        </div>
        <p>Public research prototype · read-only Sepolia verifier · no live wallet control</p>
      </footer>
    </main>
  );
}
