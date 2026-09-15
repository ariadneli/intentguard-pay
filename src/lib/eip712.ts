import {
  hashTypedData,
  keccak256,
  recoverTypedDataAddress,
  stringToHex,
  type Address,
  type Hex,
} from 'viem';

declare global {
  interface Window {
    ethereum?: {
      request(args: { method: string; params?: unknown[] }): Promise<unknown>;
      on?(event: string, listener: (payload: unknown) => void): void;
      removeListener?(event: string, listener: (payload: unknown) => void): void;
    };
  }
}

export const intentGuardDomain = {
  name: 'IntentGuardPay',
  version: '1',
  chainId: 11_155_111,
  salt: '0xa5b291e76ff920d95da8a68299c3a29b4fdc08db8ba8e16e960e298ccfcabcc4',
} as const;

export const paymentIntentTypes = {
  PaymentIntent: [
    { name: 'intentId', type: 'bytes32' },
    { name: 'payer', type: 'address' },
    { name: 'recipient', type: 'address' },
    { name: 'chainId', type: 'uint256' },
    { name: 'asset', type: 'string' },
    { name: 'amountWei', type: 'uint256' },
    { name: 'maxAmountWei', type: 'uint256' },
    { name: 'purpose', type: 'string' },
    { name: 'expiry', type: 'uint256' },
    { name: 'nonce', type: 'bytes32' },
    { name: 'resourceHash', type: 'bytes32' },
  ],
} as const;

export interface Eip712PaymentIntent {
  intentId: Hex;
  payer: Address;
  recipient: Address;
  chainId: bigint;
  asset: string;
  amountWei: bigint;
  maxAmountWei: bigint;
  purpose: string;
  expiry: bigint;
  nonce: Hex;
  resourceHash: Hex;
}

export interface SignedPaymentIntent {
  domain: typeof intentGuardDomain;
  intent: Eip712PaymentIntent;
  signature: Hex;
}

function randomBytes32(): Hex {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return `0x${Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('')}`;
}

export function createDemoPaymentIntent(payer: Address): Eip712PaymentIntent {
  const resourceHash = keccak256(stringToHex('intentguard-pay/demo-calldata/sepolia/v1'));
  return {
    intentId: randomBytes32(),
    payer,
    recipient: '0x3333333333333333333333333333333333333333',
    chainId: 11_155_111n,
    asset: 'SEP',
    amountWei: 8_000_000_000_000_000n,
    maxAmountWei: 10_000_000_000_000_000n,
    purpose: 'Purchase a verified research dataset for the AI agent',
    expiry: BigInt(Math.floor(Date.now() / 1000) + 15 * 60),
    nonce: randomBytes32(),
    resourceHash,
  };
}

export function hashPaymentIntent(intent: Eip712PaymentIntent): Hex {
  return hashTypedData({
    domain: intentGuardDomain,
    types: paymentIntentTypes,
    primaryType: 'PaymentIntent',
    message: intent,
  });
}

export async function recoverPaymentIntentSigner(
  intent: Eip712PaymentIntent,
  signature: Hex,
): Promise<Address> {
  return recoverTypedDataAddress({
    domain: intentGuardDomain,
    types: paymentIntentTypes,
    primaryType: 'PaymentIntent',
    message: intent,
    signature,
  });
}

export async function requestPaymentIntentSignature(
  account: Address,
  intent: Eip712PaymentIntent,
): Promise<Hex> {
  if (!window.ethereum) {
    throw new Error('No EIP-1193 wallet provider is available.');
  }

  return window.ethereum.request({
    method: 'eth_signTypedData_v4',
    params: [
      account,
      JSON.stringify({
        domain: intentGuardDomain,
        types: {
          EIP712Domain: [
            { name: 'name', type: 'string' },
            { name: 'version', type: 'string' },
            { name: 'chainId', type: 'uint256' },
            { name: 'salt', type: 'bytes32' },
          ],
          ...paymentIntentTypes,
        },
        primaryType: 'PaymentIntent',
        message: {
          ...intent,
          chainId: `0x${intent.chainId.toString(16)}`,
          amountWei: `0x${intent.amountWei.toString(16)}`,
          maxAmountWei: `0x${intent.maxAmountWei.toString(16)}`,
          expiry: `0x${intent.expiry.toString(16)}`,
        },
      }),
    ],
  }) as Promise<Hex>;
}
