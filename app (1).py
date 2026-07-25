"""
Q9 — Safe AI Mailroom Agent
Single-route FastAPI service: POST /q9/mailroom handles both
operation="propose" and operation="commit".

Run locally:  uvicorn app:app --reload --port 8000
Health check: GET /health
"""
import json
import logging
import os
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from canon import input_digest, dossier_content_hash, proposal_digest, sha256_hex, canonical_bytes
from crypto_verify import load_public_key, verify_receipt_signature
from classifier import classify
import storage

PROFILE = "ga5-mailroom-action-gate/v2"
ALLOWED_ACTIONS = {
    "create_draft", "update_internal_record", "send_approved_notice",
    "request_confirmation", "quarantine_item", "no_action",
}

app = FastAPI()
storage.init_db()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mailroom")

# Set MAILROOM_LOG_DIR to capture raw request bodies for debugging
# (your own guide's tip: "log what the grader actually sends you").
LOG_DIR = os.environ.get("MAILROOM_LOG_DIR", "request_logs")
os.makedirs(LOG_DIR, exist_ok=True)


def _log_body(tag: str, body: dict):
    try:
        path = os.path.join(LOG_DIR, f"{tag}_{body.get('evaluationId', 'unknown')}.json")
        with open(path, "w") as f:
            json.dump(body, f, indent=2)
    except Exception as e:
        logger.warning(f"could not log body: {e}")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/q9/mailroom")
async def mailroom(request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "malformed_json"})

    if not isinstance(body, dict) or "operation" not in body:
        return JSONResponse(status_code=422, content={"error": "missing_operation"})

    op = body["operation"]
    if op == "propose":
        return _handle_propose(body)
    elif op == "commit":
        return _handle_commit(body)
    else:
        return JSONResponse(status_code=400, content={"error": "unknown_operation"})


def _handle_propose(body: dict):
    _log_body("propose", body)

    evaluation_id = body.get("evaluationId")
    dossiers = body.get("dossiers")
    receipt_verifier = body.get("receiptVerifier")

    if not evaluation_id or not isinstance(dossiers, list) or not receipt_verifier:
        return JSONResponse(status_code=422, content={"error": "malformed_propose_request"})

    # duplicate dossierId check
    seen_ids = set()
    for d in dossiers:
        did = d.get("dossierId")
        if not did or did in seen_ids:
            return JSONResponse(status_code=400, content={"error": "duplicate_or_missing_dossierId"})
        seen_ids.add(did)

    digest = input_digest(dossiers)

    existing = storage.get_evaluation(evaluation_id)
    if existing:
        if existing["input_digest"] == digest:
            # exact replay — return the stored response unchanged
            return JSONResponse(status_code=200, content=existing["response_json"])
        else:
            return JSONResponse(status_code=409, content={"error": "evaluation_content_conflict"})

    proposals = []
    for dossier in dossiers:
        dossier_id = dossier["dossierId"]
        content_hash = dossier_content_hash(dossier)
        cached = storage.get_cached_decision(dossier_id, content_hash)

        if cached:
            decision = cached["decision"]
            call_id = cached["call_id"]
        else:
            try:
                decision = classify(dossier)
            except Exception as e:
                logger.error(f"classify failed for {dossier_id}: {e}")
                # Safe fallback: never guess an unsafe action — quarantine for manual review
                decision = type("D", (), {
                    "action": "quarantine_item",
                    "target": {"kind": "security_queue", "id": "mailroom"},
                    "payload": {"artifactId": dossier_id, "reasonCode": "INDIRECT_PROMPT_INJECTION"},
                    "evidence": [],
                })()
            call_id = f"call-{content_hash[:40]}"
            decision_dict = {
                "action": decision.action,
                "target": decision.target,
                "payload": decision.payload,
                "evidence": decision.evidence,
            }
            storage.save_decision(dossier_id, content_hash, decision_dict, call_id)
            decision = decision_dict

        proposal = {
            "dossierId": dossier_id,
            "callId": call_id,
            "action": decision["action"] if isinstance(decision, dict) else decision.action,
            "target": decision["target"] if isinstance(decision, dict) else decision.target,
            "payload": decision["payload"] if isinstance(decision, dict) else decision.payload,
            "evidence": decision["evidence"] if isinstance(decision, dict) else decision.evidence,
        }
        proposals.append(proposal)
        storage.save_proposal(evaluation_id, call_id, dossier_id, proposal)

    response = {
        "profile": PROFILE,
        "evaluationId": evaluation_id,
        "status": "awaiting_receipts",
        "inputDigest": digest,
        "proposals": proposals,
    }
    storage.save_evaluation(evaluation_id, digest, receipt_verifier["publicKeyJwk"], response)
    return JSONResponse(status_code=200, content=response)


def _handle_commit(body: dict):
    _log_body("commit", body)

    evaluation_id = body.get("evaluationId")
    receipts = body.get("receipts")
    req_input_digest = body.get("inputDigest")

    if not evaluation_id or not isinstance(receipts, list):
        return JSONResponse(status_code=422, content={"error": "malformed_commit_request"})

    evaluation = storage.get_evaluation(evaluation_id)
    if not evaluation:
        return JSONResponse(status_code=404, content={"error": "unknown_evaluation"})

    if req_input_digest and req_input_digest != evaluation["input_digest"]:
        return JSONResponse(status_code=409, content={"error": "input_digest_mismatch"})

    # full-commit replay check
    receipts_hash = sha256_hex(canonical_bytes(receipts))
    cached_response = storage.get_commit_response(evaluation_id, receipts_hash)
    if cached_response:
        return JSONResponse(status_code=200, content=cached_response)

    try:
        pubkey = load_public_key(evaluation["pubkey_jwk"])
    except Exception as e:
        logger.error(f"bad pubkey for {evaluation_id}: {e}")
        pubkey = None

    outcomes = []
    for receipt in receipts:
        call_id = receipt.get("callId")
        dossier_id = receipt.get("dossierId")

        existing_outcome = storage.get_commit_outcome(evaluation_id, call_id) if call_id else None
        if existing_outcome:
            outcomes.append(existing_outcome)
            continue

        persisted = storage.get_proposal(evaluation_id, call_id) if call_id else None
        status = "rejected"

        if persisted and pubkey:
            expected_digest = proposal_digest(
                persisted["dossierId"], persisted["callId"], persisted["action"],
                persisted["target"], persisted["payload"], persisted["evidence"],
            )
            digest_ok = receipt.get("proposalDigest") == expected_digest
            action_ok = receipt.get("action") == persisted["action"]
            dossier_ok = receipt.get("dossierId") == persisted["dossierId"]
            sig_ok = verify_receipt_signature(pubkey, receipt)

            if digest_ok and action_ok and dossier_ok and sig_ok and receipt.get("accepted") is True:
                status = "executed"
            # else stays "rejected" — covers bad signature, digest mismatch,
            # action/dossier mismatch, or accepted == False

        outcome = {
            "dossierId": dossier_id,
            "callId": call_id,
            "action": receipt.get("action"),
            "proposalDigest": receipt.get("proposalDigest"),
            "receiptId": receipt.get("receiptId"),
            "status": status,
        }
        storage.save_commit_outcome(evaluation_id, call_id, receipt, outcome)
        outcomes.append(outcome)

    response = {
        "profile": PROFILE,
        "evaluationId": evaluation_id,
        "status": "completed",
        "inputDigest": evaluation["input_digest"],
        "outcomes": outcomes,
    }
    storage.save_commit_response(evaluation_id, receipts_hash, response)
    return JSONResponse(status_code=200, content=response)
