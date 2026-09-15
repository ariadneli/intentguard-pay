import { type LiveVerification, verifySepoliaTx } from '@/lib/sepolia';
import {
  Activity,
  Check,
  ExternalLink,
  Fingerprint,
  RefreshCcw,
  ScanSearch,
  TriangleAlert,
} from 'lucide-react';
import { useState } from 'react';

function MiniTag({ children }: { children: React.ReactNode }) {
  return <span className="mini-tag">{children}</span>;
}

export default function LiveSepoliaVerifier() {
  const [txHash, setTxHash] = useState('');
  const [expectedFrom, setExpectedFrom] = useState('');
  const [expectedTo, setExpectedTo] = useState('');
  const [expectedAmount, setExpectedAmount] = useState('');

  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<LiveVerification | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!txHash) return;

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const data = await verifySepoliaTx(txHash.trim(), {
        from: expectedFrom.trim() || undefined,
        to: expectedTo.trim() || undefined,
        amountEth: expectedAmount.trim() || undefined,
      });
      setResult(data);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Verification failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <section className="live-verifier-section glass-panel" id="live-verifier">
      <div className="panel-title">
        <div>
          <Activity size={18} />
          <span>Live Sepolia Evidence</span>
        </div>
        <MiniTag>RESEARCH ONLY</MiniTag>
      </div>

      <p className="section-description" style={{ marginBottom: '24px' }}>
        Provide a transaction hash to reconstruct cryptographic evidence
        directly from the Sepolia testnet. This module validates live deployment
        case-studies against their intended parameters.
      </p>

      <form className="verifier-form" onSubmit={handleVerify}>
        <div className="input-group">
          <label htmlFor="tx-hash">Transaction Hash</label>
          <input
            id="tx-hash"
            placeholder="0x..."
            value={txHash}
            onChange={e => setTxHash(e.target.value)}
            required
          />
        </div>

        <div className="input-grid">
          <div className="input-group">
            <label htmlFor="exp-from">Expected Sender (Optional)</label>
            <input
              id="exp-from"
              placeholder="0x..."
              value={expectedFrom}
              onChange={e => setExpectedFrom(e.target.value)}
            />
          </div>
          <div className="input-group">
            <label htmlFor="exp-to">Expected Recipient (Optional)</label>
            <input
              id="exp-to"
              placeholder="0x..."
              value={expectedTo}
              onChange={e => setExpectedTo(e.target.value)}
            />
          </div>
          <div className="input-group">
            <label htmlFor="exp-amount">Expected Amount ETH (Optional)</label>
            <input
              id="exp-amount"
              placeholder="0.01"
              value={expectedAmount}
              onChange={e => setExpectedAmount(e.target.value)}
            />
          </div>
        </div>

        <button
          className="primary-action"
          type="submit"
          disabled={loading || !txHash}
          style={{ marginTop: '16px', width: '100%', justifyContent: 'center' }}
        >
          {loading ? (
            <RefreshCcw className="spin" size={16} />
          ) : (
            <ScanSearch size={16} />
          )}
          <span>Verify public receipt</span>
        </button>
      </form>

      <div className="verifier-disclaimer">
        <TriangleAlert size={12} />
        <span>
          Read-only public RPC · No wallet connection · No data persisted
        </span>
      </div>

      {error && (
        <div className="verifier-error">
          <TriangleAlert size={16} />
          <span>{error}</span>
        </div>
      )}

      {result && (
        <div className="verifier-result">
          <div className="result-header">
            <div className="status-badge">
              <Check size={14} />
              Confirmed in Block #{result.blockNumber}
            </div>
            <a
              href={`https://sepolia.etherscan.io/tx/${txHash}`}
              target="_blank"
              rel="noreferrer"
              className="etherscan-link"
            >
              View on Etherscan <ExternalLink size={12} />
            </a>
          </div>

          <div
            className="check-grid"
            style={{
              marginTop: '20px',
              gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
            }}
          >
            {result.checks.map(check => (
              <div
                key={check.code}
                className={`check-card ${check.passed ? '' : 'check-failed'}`}
                style={{ minHeight: 'auto' }}
              >
                <span className="check-icon">
                  {check.passed ? (
                    <Check size={14} />
                  ) : (
                    <TriangleAlert size={14} />
                  )}
                </span>
                <div>
                  <strong>{check.label}</strong>
                  <p>{check.detail}</p>
                </div>
              </div>
            ))}
          </div>

          <div className="evidence-footer">
            <div className="evidence-hash-box">
              <Fingerprint size={16} />
              <div>
                <span>Reconstructed Evidence Hash</span>
                <strong>{result.evidenceHash}</strong>
              </div>
            </div>
            <div className="stat-row">
              <span>Gas Used: {result.gasUsed}</span>
              <span>Price: {result.effectiveGasPriceGwei} Gwei</span>
              <span>Confirms: {result.confirmations}</span>
            </div>
          </div>
        </div>
      )}
    </section>
  );
}
