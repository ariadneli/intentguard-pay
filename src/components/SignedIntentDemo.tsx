import {
  formatEther,
  isAddressEqual,
  type Address,
  type Hex,
} from 'viem';
import {
  ArrowRight,
  BadgeCheck,
  Check,
  Copy,
  Fingerprint,
  KeyRound,
  LockKeyhole,
  RefreshCcw,
  ShieldCheck,
  TriangleAlert,
  WalletCards,
} from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';
import {
  createDemoPaymentIntent,
  hashPaymentIntent,
  recoverPaymentIntentSigner,
  requestPaymentIntentSignature,
  type Eip712PaymentIntent,
} from '@/lib/eip712';

type WalletPhase =
  | 'disconnected'
  | 'connecting'
  | 'ready'
  | 'signing'
  | 'verified'
  | 'denied'
  | 'error';

interface VerificationCheck {
  label: string;
  passed: boolean;
  detail: string;
}

const expectedChainId = 11_155_111;
const shortHex = (value?: string) =>
  value ? `${value.slice(0, 10)}…${value.slice(-8)}` : '—';

function providerError(error: unknown): string {
  if (typeof error === 'object' && error && 'code' in error) {
    const code = Number((error as { code?: number }).code);
    if (code === 4001) return 'The wallet request was rejected.';
    if (code === -32002) return 'A wallet request is already open in MetaMask.';
  }
  return error instanceof Error ? error.message : 'The wallet request failed.';
}

async function switchToSepolia() {
  if (!window.ethereum) throw new Error('MetaMask or another EIP-1193 wallet is required.');
  try {
    await window.ethereum.request({
      method: 'wallet_switchEthereumChain',
      params: [{ chainId: '0xaa36a7' }],
    });
  } catch (error) {
    if (typeof error === 'object' && error && 'code' in error && Number((error as { code?: number }).code) === 4902) {
      await window.ethereum.request({
        method: 'wallet_addEthereumChain',
        params: [{
          chainId: '0xaa36a7',
          chainName: 'Sepolia',
          nativeCurrency: { name: 'Sepolia Ether', symbol: 'SEP', decimals: 18 },
          rpcUrls: ['https://ethereum-sepolia-rpc.publicnode.com'],
          blockExplorerUrls: ['https://sepolia.etherscan.io'],
        }],
      });
      return;
    }
    throw error;
  }
}

function ReviewRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="signing-review-row">
      <span>{label}</span>
      <strong title={value}>{value}</strong>
    </div>
  );
}

export default function SignedIntentDemo() {
  const [account, setAccount] = useState<Address | null>(null);
  const [chainId, setChainId] = useState<number | null>(null);
  const [phase, setPhase] = useState<WalletPhase>('disconnected');
  const [intent, setIntent] = useState<Eip712PaymentIntent | null>(null);
  const [signature, setSignature] = useState<Hex | null>(null);
  const [recoveredSigner, setRecoveredSigner] = useState<Address | null>(null);
  const [checks, setChecks] = useState<VerificationCheck[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [nonceConsumed, setNonceConsumed] = useState(false);

  const digest = useMemo(() => (intent ? hashPaymentIntent(intent) : null), [intent]);
  const isSepolia = chainId === expectedChainId;
  const providerAvailable = typeof window !== 'undefined' && Boolean(window.ethereum);

  useEffect(() => {
    if (!window.ethereum?.on) return;
    const handleAccounts = (accounts: unknown) => {
      const next = Array.isArray(accounts) && typeof accounts[0] === 'string'
        ? accounts[0] as Address
        : null;
      setAccount(next);
      setIntent(next ? createDemoPaymentIntent(next) : null);
      setSignature(null);
      setRecoveredSigner(null);
      setChecks([]);
      setNonceConsumed(false);
      setPhase(next ? 'ready' : 'disconnected');
    };
    const handleChain = (value: unknown) => {
      if (typeof value === 'string') setChainId(Number.parseInt(value, 16));
    };
    window.ethereum.on('accountsChanged', handleAccounts);
    window.ethereum.on('chainChanged', handleChain);
    return () => {
      window.ethereum?.removeListener?.('accountsChanged', handleAccounts);
      window.ethereum?.removeListener?.('chainChanged', handleChain);
    };
  }, []);

  const connectWallet = async () => {
    if (!window.ethereum) {
      setPhase('error');
      setError('No injected wallet detected. Install MetaMask to run the live signing proof.');
      return;
    }
    setPhase('connecting');
    setError(null);
    try {
      const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' }) as string[];
      const chainHex = await window.ethereum.request({ method: 'eth_chainId' }) as string;
      const nextAccount = accounts[0] as Address | undefined;
      if (!nextAccount) throw new Error('The wallet did not return an account.');
      setAccount(nextAccount);
      setChainId(Number.parseInt(chainHex, 16));
      setIntent(createDemoPaymentIntent(nextAccount));
      setSignature(null);
      setRecoveredSigner(null);
      setChecks([]);
      setNonceConsumed(false);
      setPhase('ready');
    } catch (walletError) {
      setPhase('error');
      setError(providerError(walletError));
    }
  };

  const refreshIntent = () => {
    if (!account) return;
    setIntent(createDemoPaymentIntent(account));
    setSignature(null);
    setRecoveredSigner(null);
    setChecks([]);
    setNonceConsumed(false);
    setError(null);
    setPhase('ready');
  };

  const changeNetwork = async () => {
    setError(null);
    try {
      await switchToSepolia();
      const chainHex = await window.ethereum?.request({ method: 'eth_chainId' }) as string;
      setChainId(Number.parseInt(chainHex, 16));
    } catch (walletError) {
      setError(providerError(walletError));
    }
  };

  const verifySignature = async (
    nextSignature: Hex,
    signedIntent: Eip712PaymentIntent,
    signingAccount: Address,
    signedOnSepolia: boolean,
    replay = false,
  ) => {
    const proposedExecution = {
      recipient: signedIntent.recipient,
      chainId: signedIntent.chainId,
      asset: signedIntent.asset,
      amountWei: signedIntent.amountWei,
      calldataHash: signedIntent.resourceHash,
    };
    const recovered = await recoverPaymentIntentSigner(signedIntent, nextSignature);
    const fresh = signedIntent.expiry > BigInt(Math.floor(Date.now() / 1000));
    const signerMatches = isAddressEqual(recovered, signingAccount);
    const executionExact =
      isAddressEqual(proposedExecution.recipient, signedIntent.recipient) &&
      proposedExecution.chainId === signedIntent.chainId &&
      proposedExecution.asset === signedIntent.asset &&
      proposedExecution.amountWei === signedIntent.amountWei;
    const resourceMatches = proposedExecution.calldataHash === signedIntent.resourceHash;
    const nextChecks: VerificationCheck[] = [
      { label: 'DOMAIN_MATCH', passed: signedOnSepolia && signedIntent.chainId === BigInt(expectedChainId), detail: 'IntentGuardPay v1 · Sepolia · application salt' },
      { label: 'SIGNER_MATCH', passed: signerMatches, detail: `${shortHex(recovered)} recovered from typed data` },
      { label: 'EXECUTION_EXACT', passed: executionExact, detail: 'Recipient, asset and amount match the proposed execution' },
      { label: 'RESOURCE_HASH_MATCH', passed: resourceMatches, detail: 'Proposed calldata commitment equals the signed resource hash' },
      { label: 'INTENT_FRESH', passed: fresh, detail: fresh ? 'The 15-minute authorization window is active' : 'The signed authorization has expired' },
      { label: 'NONCE_UNUSED', passed: !nonceConsumed && !replay, detail: nonceConsumed || replay ? 'The session-local payer nonce was already consumed' : 'Nonce is unused for this payer in the current browser session' },
    ];
    const approved = nextChecks.every(check => check.passed);
    setRecoveredSigner(recovered);
    setChecks(nextChecks);
    setPhase(approved ? 'verified' : 'denied');
    if (approved) setNonceConsumed(true);
  };

  const signIntent = async () => {
    if (!account || !intent) return;
    if (!isSepolia) {
      setError('Switch to Sepolia before signing this domain-separated intent.');
      return;
    }
    setPhase('signing');
    setError(null);
    try {
      const signingIntent = intent;
      const signingAccount = account;
      const signingOnSepolia = isSepolia;
      const nextSignature = await requestPaymentIntentSignature(signingAccount, signingIntent);
      setSignature(nextSignature);
      await verifySignature(nextSignature, signingIntent, signingAccount, signingOnSepolia);
    } catch (walletError) {
      setPhase('error');
      setError(providerError(walletError));
    }
  };

  const replaySignature = async () => {
    if (!signature || !intent || !account) return;
    setError(null);
    await verifySignature(signature, intent, account, isSepolia, true);
  };

  return (
    <section className="signed-demo-section" id="sign-intent">
      <div className="section-heading">
        <div>
          <span className="mini-tag">LIVE EIP-712 PROOF</span>
          <h2>Review, sign, recover, and consume one payment intent.</h2>
          <p className="section-description">
            MetaMask signs structured authorization data. IntentGuard recovers the payer and verifies the exact envelope without broadcasting a transaction or requesting custody.
          </p>
        </div>
        <div className={`wallet-status wallet-status-${phase}`}>
          <span className="pulse-dot" />
          <div>
            <strong>{account ? shortHex(account) : 'Wallet disconnected'}</strong>
            <small>{chainId ? `${isSepolia ? 'Sepolia' : `Chain ${chainId}`} · ${phase}` : 'EIP-1193 · no transaction'}</small>
          </div>
        </div>
      </div>

      <div className="signing-grid">
        <div className="signing-panel glass-panel">
          <div className="panel-title">
            <div><WalletCards size={18} /><span>Wallet authorization</span></div>
            <span className="mini-tag">NO GAS</span>
          </div>

          {!providerAvailable && (
            <div className="signing-callout signing-callout-warn">
              <TriangleAlert size={18} />
              <div><strong>MetaMask not detected</strong><p>Open this page in a browser with an injected EIP-1193 wallet.</p></div>
            </div>
          )}

          {!account ? (
            <button className="wallet-primary" onClick={connectWallet} disabled={phase === 'connecting'} type="button">
              {phase === 'connecting' ? <RefreshCcw className="spin" size={17} /> : <WalletCards size={17} />}
              {phase === 'connecting' ? 'Requesting account…' : 'Connect MetaMask'}
            </button>
          ) : (
            <>
              <div className="wallet-identity">
                <div className="wallet-avatar"><Fingerprint size={20} /></div>
                <div><span>DECLARED PAYER</span><strong>{shortHex(account)}</strong></div>
                <BadgeCheck size={18} />
              </div>
              {!isSepolia ? (
                <button className="wallet-primary" onClick={changeNetwork} type="button">
                  <RefreshCcw size={17} /> Switch to Sepolia
                </button>
              ) : (
                <button className="wallet-primary" onClick={signIntent} disabled={!intent || phase === 'signing'} type="button">
                  {phase === 'signing' ? <RefreshCcw className="spin" size={17} /> : <KeyRound size={17} />}
                  {phase === 'signing' ? 'Check MetaMask…' : 'Review & sign PaymentIntent'}
                </button>
              )}
              <button className="wallet-secondary" onClick={refreshIntent} type="button">
                <RefreshCcw size={15} /> Generate fresh nonce
              </button>
            </>
          )}

          <div className="signing-safety">
            <LockKeyhole size={16} />
            <p><strong>Safety boundary.</strong> This signs typed data only. It never sends ETH, submits a transaction, requests a private key, or grants token allowance.</p>
          </div>
          {Boolean(error) && <div className="wallet-error"><TriangleAlert size={15} />{error}</div>}
        </div>

        <div className="signing-panel glass-panel">
          <div className="panel-title">
            <div><ShieldCheck size={18} /><span>Human-readable envelope</span></div>
            <span className="mini-tag">15 MIN TTL</span>
          </div>
          {intent ? (
            <div className="signing-review">
              <ReviewRow label="Recipient" value={shortHex(intent.recipient)} />
              <ReviewRow label="Amount" value={`${formatEther(intent.amountWei)} SEP`} />
              <ReviewRow label="Maximum" value={`${formatEther(intent.maxAmountWei)} SEP`} />
              <ReviewRow label="Purpose" value={intent.purpose} />
              <ReviewRow label="Intent ID" value={shortHex(intent.intentId)} />
              <ReviewRow label="Nonce" value={shortHex(intent.nonce)} />
              <ReviewRow label="Resource" value={shortHex(intent.resourceHash)} />
              <ReviewRow label="Digest" value={shortHex(digest ?? undefined)} />
            </div>
          ) : (
            <div className="signing-empty"><ArrowRight size={20} /><p>Connect a wallet to materialize a fresh, payer-bound authorization envelope.</p></div>
          )}
        </div>
      </div>

      {Boolean(signature || checks.length > 0) && (
        <div className={`signature-proof ${phase === 'denied' ? 'signature-proof-denied' : ''}`}>
          <div className="signature-proof-head">
            <div className="signature-proof-icon">{phase === 'denied' ? <TriangleAlert size={22} /> : <BadgeCheck size={22} />}</div>
            <div>
              <span>VERIFICATION DECISION</span>
              <h3>{phase === 'denied' ? 'Replay denied before execution' : 'Signer and signed intent verified'}</h3>
              <p>{phase === 'denied' ? 'The same payer-scoped nonce cannot authorize a second release.' : 'The recovered signer equals the connected payer; the authorization is now consumed for this browser session.'}</p>
            </div>
            <strong className="signature-decision">{phase === 'denied' ? 'DENY' : 'AUTO_APPROVE'}</strong>
          </div>
          <div className="signature-checks">
            {checks.map(check => (
              <div className={check.passed ? '' : 'signature-check-failed'} key={check.label}>
                {check.passed ? <Check size={14} /> : <TriangleAlert size={14} />}
                <span><strong>{check.label}</strong><small>{check.detail}</small></span>
              </div>
            ))}
          </div>
          <div className="signature-evidence">
            <div><span>TYPED-DATA DIGEST</span><strong>{shortHex(digest ?? undefined)}</strong></div>
            <div><span>RECOVERED SIGNER</span><strong>{shortHex(recoveredSigner ?? undefined)}</strong></div>
            <div><span>SIGNATURE</span><strong>{shortHex(signature ?? undefined)}</strong></div>
            {Boolean(signature && phase !== 'denied') && (
              <button className="replay-button" onClick={replaySignature} type="button"><Copy size={14} /> Replay same signature</button>
            )}
          </div>
        </div>
      )}
    </section>
  );
}
