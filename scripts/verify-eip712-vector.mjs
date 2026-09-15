#!/usr/bin/env node

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { hashTypedData, recoverTypedDataAddress } from 'viem';

const vectorPath = resolve('fixtures/eip712-golden-vector.json');
const vector = JSON.parse(readFileSync(vectorPath, 'utf8'));
const intent = {
  ...vector.intent,
  chainId: BigInt(vector.intent.chainId),
  amountWei: BigInt(vector.intent.amountWei),
  maxAmountWei: BigInt(vector.intent.maxAmountWei),
  expiry: BigInt(vector.intent.expiry),
};
const types = {
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
};

const digest = hashTypedData({
  domain: vector.domain,
  types,
  primaryType: 'PaymentIntent',
  message: intent,
});
const recoveredSigner = await recoverTypedDataAddress({
  domain: vector.domain,
  types,
  primaryType: 'PaymentIntent',
  message: intent,
  signature: vector.signature,
});

if (digest.toLowerCase() !== vector.digest.toLowerCase()) {
  throw new Error(`Digest mismatch: ${digest} != ${vector.digest}`);
}
if (recoveredSigner.toLowerCase() !== vector.recoveredSigner.toLowerCase()) {
  throw new Error(
    `Signer mismatch: ${recoveredSigner} != ${vector.recoveredSigner}`,
  );
}

console.log(`EIP-712 golden vector verified: ${digest} -> ${recoveredSigner}`);
