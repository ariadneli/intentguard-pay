# Security Policy

IntentGuard Pay is a research prototype. It is not production wallet software and must not be used to protect or move real funds.

## Secrets and keys

- Do not commit private keys, seed phrases, API keys, RPC provider tokens, wallet files, or `.env` files.
- Use `.env.example` as a template for public configuration only.
- The live Sepolia verifier is read-only and should not require wallet credentials.

## Scope

This repository demonstrates deterministic intent validation, replay-aware enforcement, and receipt reconstruction for research and education. It has not been audited for production use.

## Reporting

For public forks, please use GitHub issues or the security reporting workflow configured by the repository owner. Do not include secrets or sensitive wallet material in reports.
