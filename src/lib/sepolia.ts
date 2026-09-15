const RPC_URL =
  import.meta.env.VITE_SEPOLIA_RPC_URL ||
  'https://ethereum-sepolia-rpc.publicnode.com';

type RpcParam = string | number | boolean | null | RpcParam[] | { [key: string]: RpcParam };
type RpcResult = unknown;

interface JsonRpcResponse {
  jsonrpc: string;
  id: number;
  result?: RpcResult;
  error?: {
    code: number;
    message: string;
  };
}

interface SepoliaTransaction {
  from: string;
  to: string | null;
  value: string;
  chainId?: string;
}

interface SepoliaReceipt {
  blockNumber: string;
  status: string;
  gasUsed: string;
  effectiveGasPrice?: string;
}

export interface VerificationCheck {
  code: string;
  label: string;
  passed: boolean;
  detail: string;
}

export interface LiveVerification {
  blockNumber: number;
  gasUsed: string;
  effectiveGasPriceGwei: string;
  confirmations: number;
  observed: {
    from: string;
    to: string;
    valueEth: string;
    chainId: number;
  };
  checks: VerificationCheck[];
  evidenceHash: string;
}

function assertRecord(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`Invalid ${label} response from Sepolia RPC.`);
  }
  return value as Record<string, unknown>;
}

function asString(value: unknown, label: string): string {
  if (typeof value !== 'string') {
    throw new Error(`Invalid ${label} field from Sepolia RPC.`);
  }
  return value;
}

async function rpcCall(method: string, params: RpcParam[]): Promise<RpcResult> {
  const response = await fetch(RPC_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: Date.now(),
      method,
      params,
    }),
  });

  if (!response.ok) {
    throw new Error(`Sepolia RPC request failed with HTTP ${response.status}.`);
  }

  const data = (await response.json()) as JsonRpcResponse;
  if (data.error) throw new Error(data.error.message);
  return data.result;
}

function parseTransaction(value: unknown): SepoliaTransaction | null {
  if (value === null) return null;
  const tx = assertRecord(value, 'transaction');
  return {
    from: asString(tx.from, 'transaction.from'),
    to: tx.to === null ? null : asString(tx.to, 'transaction.to'),
    value: asString(tx.value, 'transaction.value'),
    chainId: typeof tx.chainId === 'string' ? tx.chainId : undefined,
  };
}

function parseReceipt(value: unknown): SepoliaReceipt | null {
  if (value === null) return null;
  const receipt = assertRecord(value, 'receipt');
  return {
    blockNumber: asString(receipt.blockNumber, 'receipt.blockNumber'),
    status: asString(receipt.status, 'receipt.status'),
    gasUsed: asString(receipt.gasUsed, 'receipt.gasUsed'),
    effectiveGasPrice:
      typeof receipt.effectiveGasPrice === 'string'
        ? receipt.effectiveGasPrice
        : undefined,
  };
}

function toWei(eth: string | number): bigint {
  const s = String(eth).trim();
  if (!/^\d+(\.\d+)?$/.test(s)) {
    throw new Error('Expected amount must be a non-negative decimal ETH value.');
  }
  const [int, dec = ''] = s.split('.');
  const weiStr = int + dec.padEnd(18, '0').slice(0, 18);
  return BigInt(weiStr);
}

function formatUnits(value: bigint, decimals: number, fractionDigits = 6): string {
  const base = 10n ** BigInt(decimals);
  const whole = value / base;
  const fraction = value % base;
  const fractionText = fraction
    .toString()
    .padStart(decimals, '0')
    .slice(0, fractionDigits)
    .replace(/0+$/, '');
  return fractionText ? `${whole}.${fractionText}` : whole.toString();
}

async function computeEvidenceHash(payload: Record<string, unknown>): Promise<string> {
  const msgUint8 = new TextEncoder().encode(JSON.stringify(payload));
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgUint8);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return `0x${hashArray.map(b => b.toString(16).padStart(2, '0')).join('')}`;
}

export async function verifySepoliaTx(
  txHash: string,
  expected?: {
    from?: string;
    to?: string;
    amountEth?: string;
  },
): Promise<LiveVerification> {
  if (!/^0x([A-Fa-f0-9]{64})$/.test(txHash)) {
    throw new Error('Invalid transaction hash format.');
  }

  const [txResult, receiptResult, latestBlockResult] = await Promise.all([
    rpcCall('eth_getTransactionByHash', [txHash]),
    rpcCall('eth_getTransactionReceipt', [txHash]),
    rpcCall('eth_blockNumber', []),
  ]);

  const tx = parseTransaction(txResult);
  const receipt = parseReceipt(receiptResult);
  const latestBlockHex = asString(latestBlockResult, 'latest block');

  if (!tx || !receipt) {
    throw new Error('Transaction not found on Sepolia.');
  }

  if (receipt.status !== '0x1') {
    throw new Error('Transaction failed on-chain (status 0).');
  }

  const blockNumber = parseInt(receipt.blockNumber, 16);
  const latestBlock = parseInt(latestBlockHex, 16);
  const confirmations = Math.max(1, latestBlock - blockNumber + 1);

  const observedValueWei = BigInt(tx.value);
  const observedValueEth = formatUnits(observedValueWei, 18, 8);
  const chainId = parseInt(tx.chainId || '0x0', 16);

  const checks: VerificationCheck[] = [
    {
      code: 'NETWORK_MATCH',
      label: 'Network validation',
      passed: chainId === 11155111,
      detail:
        chainId === 11155111
          ? 'Verified on Sepolia (11155111).'
          : `Chain ID mismatch: ${chainId}`,
    },
    {
      code: 'RECEIPT_STATUS',
      label: 'Execution status',
      passed: true,
      detail: 'Transaction successfully included in block.',
    },
  ];

  if (expected?.from) {
    const match = tx.from.toLowerCase() === expected.from.toLowerCase();
    checks.push({
      code: 'SENDER_MATCH',
      label: 'Sender integrity',
      passed: match,
      detail: match
        ? 'Sender matches expected intent.'
        : 'Sender address mismatch.',
    });
  }

  if (expected?.to) {
    const match = (tx.to || '').toLowerCase() === expected.to.toLowerCase();
    checks.push({
      code: 'RECIPIENT_MATCH',
      label: 'Recipient integrity',
      passed: match,
      detail: match
        ? 'Recipient matches expected intent.'
        : 'Recipient address mismatch.',
    });
  }

  if (expected?.amountEth) {
    const expectedWei = toWei(expected.amountEth);
    const match = observedValueWei === expectedWei;
    checks.push({
      code: 'VALUE_MATCH',
      label: 'Value integrity',
      passed: match,
      detail: match
        ? 'Amount matches expected intent.'
        : `Value mismatch: observed ${observedValueEth} ETH.`,
    });
  }

  const evidencePayload = {
    txHash,
    blockNumber,
    from: tx.from,
    to: tx.to,
    value: tx.value,
    status: receipt.status,
    chainId,
  };

  const evidenceHash = await computeEvidenceHash(evidencePayload);

  return {
    blockNumber,
    gasUsed: BigInt(receipt.gasUsed).toString(),
    effectiveGasPriceGwei: formatUnits(
      BigInt(receipt.effectiveGasPrice || '0x0'),
      9,
      2,
    ),
    confirmations,
    observed: {
      from: tx.from,
      to: tx.to || 'Contract Creation',
      valueEth: observedValueEth,
      chainId,
    },
    checks,
    evidenceHash,
  };
}
