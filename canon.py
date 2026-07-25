"""Canonical JSON + digest helpers shared by the whole app."""
import json
import hashlib


def canonical_bytes(obj) -> bytes:
    """Recursively key-sorted, compact JSON -> UTF-8 bytes.
    json.dumps(sort_keys=True) already sorts dict keys at every nesting level;
    arrays keep their given order (as required by the spec)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def input_digest(dossiers: list) -> str:
    return sha256_hex(canonical_bytes(dossiers))


def dossier_content_hash(dossier: dict) -> str:
    """Per-dossier fingerprint used for the decision cache."""
    return sha256_hex(canonical_bytes(dossier))


def proposal_digest(dossier_id: str, call_id: str, action: str, target, payload: dict, evidence: list) -> str:
    """EXACT fields per spec: dossierId, callId, action, target (null if absent),
    payload, evidence (sorted). Extra response fields are NOT part of this."""
    view = {
        "dossierId": dossier_id,
        "callId": call_id,
        "action": action,
        "target": target,  # None serializes to JSON null
        "payload": payload,
        "evidence": sorted(evidence),
    }
    return sha256_hex(canonical_bytes(view))
