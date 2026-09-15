"""EIP-712 models and encoding helpers for signed payment intents.

The module verifies signatures only. It never stores private keys or broadcasts
transactions. The fixed domain is intentionally scoped to the Sepolia research
prototype.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from eth_account import Account
from eth_account.messages import SignableMessage, encode_typed_data
from eth_utils import is_address, keccak
from pydantic import BaseModel, ConfigDict, Field, field_validator


DOMAIN_SALT = "0x" + keccak(text="intentguard-pay/sepolia/v1").hex()


def _validate_bytes32(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value.startswith("0x"):
        raise ValueError(f"{field_name} must be a 0x-prefixed bytes32 value")
    try:
        raw = bytes.fromhex(value[2:])
    except ValueError as exc:
        raise ValueError(f"{field_name} must contain hexadecimal bytes") from exc
    if len(raw) != 32:
        raise ValueError(f"{field_name} must be exactly 32 bytes")
    return "0x" + raw.hex()


class EIP712Domain(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    name: str
    version: str
    chain_id: int = Field(alias="chainId")
    salt: str

    @field_validator("salt")
    @classmethod
    def validate_salt(cls, value: str) -> str:
        return _validate_bytes32(value, "salt")


EXPECTED_DOMAIN = EIP712Domain(
    name="IntentGuardPay",
    version="1",
    chain_id=11155111,
    salt=DOMAIN_SALT,
)


PAYMENT_INTENT_TYPES = {
    "PaymentIntent": [
        {"name": "intentId", "type": "bytes32"},
        {"name": "payer", "type": "address"},
        {"name": "recipient", "type": "address"},
        {"name": "chainId", "type": "uint256"},
        {"name": "asset", "type": "string"},
        {"name": "amountWei", "type": "uint256"},
        {"name": "maxAmountWei", "type": "uint256"},
        {"name": "purpose", "type": "string"},
        {"name": "expiry", "type": "uint256"},
        {"name": "nonce", "type": "bytes32"},
        {"name": "resourceHash", "type": "bytes32"},
    ]
}


class EIP712PaymentIntent(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    intent_id: str = Field(alias="intentId")
    payer: str
    recipient: str
    chain_id: int = Field(alias="chainId", gt=0)
    asset: str = Field(min_length=1, max_length=32)
    amount_wei: int = Field(alias="amountWei", gt=0)
    max_amount_wei: int = Field(alias="maxAmountWei", gt=0)
    purpose: str = Field(min_length=1, max_length=512)
    expiry: int = Field(gt=0)
    nonce: str
    resource_hash: str = Field(alias="resourceHash")

    @field_validator("intent_id", "nonce", "resource_hash")
    @classmethod
    def validate_bytes32_fields(cls, value: str, info) -> str:
        return _validate_bytes32(value, info.field_name)

    @field_validator("payer", "recipient")
    @classmethod
    def validate_addresses(cls, value: str, info) -> str:
        if not is_address(value):
            raise ValueError(f"{info.field_name} must be a valid Ethereum address")
        return value.lower()


class SignedPaymentIntent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    domain: EIP712Domain
    intent: EIP712PaymentIntent
    signature: str

    @field_validator("signature")
    @classmethod
    def validate_signature_shape(cls, value: str) -> str:
        if not isinstance(value, str) or not value.startswith("0x"):
            raise ValueError("signature must be 0x-prefixed")
        try:
            raw = bytes.fromhex(value[2:])
        except ValueError as exc:
            raise ValueError("signature must contain hexadecimal bytes") from exc
        if len(raw) != 65:
            raise ValueError("signature must be exactly 65 bytes")
        return "0x" + raw.hex()


class SignedProposedExecution(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    recipient: str
    chain_id: int = Field(alias="chainId", gt=0)
    asset: str = Field(min_length=1, max_length=32)
    amount_wei: int = Field(alias="amountWei", gt=0)
    calldata_hash: str = Field(alias="calldataHash")

    @field_validator("recipient")
    @classmethod
    def validate_recipient(cls, value: str) -> str:
        if not is_address(value):
            raise ValueError("recipient must be a valid Ethereum address")
        return value.lower()

    @field_validator("calldata_hash")
    @classmethod
    def validate_calldata_hash(cls, value: str) -> str:
        return _validate_bytes32(value, "calldataHash")


def domain_dict(domain: EIP712Domain = EXPECTED_DOMAIN) -> Dict[str, Any]:
    return domain.model_dump(by_alias=True)


def message_dict(intent: EIP712PaymentIntent) -> Dict[str, Any]:
    return intent.model_dump(by_alias=True)


def build_signable_message(
    intent: EIP712PaymentIntent,
    domain: EIP712Domain = EXPECTED_DOMAIN,
) -> SignableMessage:
    return encode_typed_data(
        domain_data=domain_dict(domain),
        message_types=PAYMENT_INTENT_TYPES,
        message_data=message_dict(intent),
    )


def typed_data_digest(
    intent: EIP712PaymentIntent,
    domain: EIP712Domain = EXPECTED_DOMAIN,
) -> str:
    signable = build_signable_message(intent, domain)
    digest = keccak(b"\x19" + signable.version + signable.header + signable.body)
    return "0x" + digest.hex()


def recover_signer(
    intent: EIP712PaymentIntent,
    signature: str,
    domain: EIP712Domain = EXPECTED_DOMAIN,
) -> Optional[str]:
    try:
        recovered = Account.recover_message(
            build_signable_message(intent, domain), signature=signature
        )
    except (ValueError, TypeError):
        return None
    return recovered.lower()


def domain_matches_expected(domain: EIP712Domain) -> bool:
    return domain.model_dump(by_alias=True) == EXPECTED_DOMAIN.model_dump(by_alias=True)
