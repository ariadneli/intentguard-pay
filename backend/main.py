import os

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from intent_engine import IntentEngine, benchmark, run_demo
from eip712 import SignedPaymentIntent, SignedProposedExecution
from nonce_store import InMemoryNonceStore, SQLiteNonceStore

NONCE_STORE_KIND = os.getenv("INTENTGUARD_NONCE_STORE", "memory").strip().lower()
if NONCE_STORE_KIND == "sqlite":
    nonce_path = os.getenv("INTENTGUARD_NONCE_SQLITE_PATH", "intentguard_nonces.sqlite3")
    NONCE_STORE = SQLiteNonceStore(nonce_path)
else:
    NONCE_STORE = InMemoryNonceStore()

ENGINE = IntentEngine(nonce_store=NONCE_STORE)

app = FastAPI(
    title="IntentGuard Pay API",
    description="Public research prototype for deterministic agentic payment validation.",
    version="1.0.0",
)

ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.getenv(
        "INTENTGUARD_ALLOWED_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173",
    ).split(",")
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


class DemoRunRequest(BaseModel):
    scenario_id: str


class SignedValidationRequest(BaseModel):
    signed_intent: SignedPaymentIntent
    proposed_execution: SignedProposedExecution
    consume_nonce: bool = True


class DemoResetResponse(BaseModel):
    status: str


@app.get("/api")
async def index_handler():
    return {
        "name": "IntentGuard Pay API",
        "version": "1.0.0",
        "mode": "public research build",
    }


@app.get("/api/v1/ping")
async def ping_handler():
    return {"status": "ok"}


@app.get("/api/v1/demo/scenarios")
async def get_scenarios():
    return {
        "scenarios": [
            {
                "id": "normal",
                "title": "Authorized purchase",
                "description": "A bounded Sepolia payment matches the authorized intent envelope.",
                "tone": "emerald",
            },
            {
                "id": "tampered",
                "title": "Prompt injection",
                "description": "Recipient substitution and amount escalation are blocked.",
                "tone": "rose",
            },
            {
                "id": "replay",
                "title": "Replay attempt",
                "description": "A consume-once nonce guard prevents the same signed intent from paying twice.",
                "tone": "amber",
            },
        ]
    }


@app.post("/api/v1/demo/run")
async def execute_demo(payload: DemoRunRequest):
    if payload.scenario_id not in {"normal", "tampered", "replay"}:
        raise HTTPException(status_code=400, detail="unknown scenario")
    # In this simplified public version, we don't reset automatically unless asked.
    return run_demo(ENGINE, payload.scenario_id)


@app.post("/api/v1/signed-intents/validate")
async def validate_signed_intent(payload: SignedValidationRequest):
    return ENGINE.validate_signed(
        payload.signed_intent,
        payload.proposed_execution,
        consume_nonce=payload.consume_nonce,
    )


@app.post("/api/v1/demo/reset", response_model=DemoResetResponse)
async def reset_demo():
    ENGINE.reset()
    return DemoResetResponse(status="reset")


@app.get("/api/v1/evaluation")
async def get_evaluation():
    return benchmark()


@app.get("/api/v1/about")
async def get_about():
    return {
        "title": "IntentGuard Pay",
        "research_question": (
            "Can deterministic intent validation prevent unauthorized agentic payments "
            "without blocking legitimate autonomy?"
        ),
        "what_is_scored": "Mechanism-level control baselines computed from PAACT-Core v1.",
        "what_is_not_scored": "External product performance, real-world attack prevalence, or live-chain deployment claims.",
        "integrated_components": [
            "EIP-712 signed payment-intent envelope",
            "Typed-data digest reconstruction and signer recovery",
            "Deterministic policy validation",
            "Intent–execution scope and exact-amount binding",
            "Payer-scoped consume-once replay state",
            "PAACT-Core v1 mutation corpus and evidence hashing",
        ],
        "project_contribution": (
            "Payment-specific threat model, cross-layer intent–execution binding, "
            "mechanism-level baseline matrix, PAACT-Core corpus, durable replay tests, and receipt evidence."
        ),
    }


if __name__ == "__main__":
    # Default to localhost for safer local development; override via HOST if needed.
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host=host, port=port, reload=False)
