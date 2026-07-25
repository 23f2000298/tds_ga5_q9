"""
Ed25519 receipt-signature verification.

ASSUMPTION FLAGGED FOR YOU TO CONFIRM:
The spec gives the receipt's fields (dossierId, callId, action, accepted,
proposalDigest, receiptId, receiptSignature) but does not spell out, in the
text you pasted, exactly which bytes receiptSignature signs. The strong
convention used everywhere else in this spec is "canonical (recursively
key-sorted, compact) JSON" — so this code signs/verifies over the canonical
JSON of the receipt's OWN fields minus receiptSignature itself:

    {dossierId, callId, action, accepted, proposalDigest, receiptId}

If your first real Check shows every receipt failing signature verification,
that's the signal this assumption is wrong — capture one real receipt via
the logging middleware (see app.py) and paste it here so I can fix the exact
signed payload.
"""
import base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

from canon import canonical_bytes


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def load_public_key(jwk: dict) -> Ed25519PublicKey:
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise ValueError(f"unsupported key type: {jwk.get('kty')}/{jwk.get('crv')}")
    raw = _b64url_decode(jwk["x"])
    return Ed25519PublicKey.from_public_bytes(raw)


def receipt_signing_payload(receipt: dict) -> bytes:
    view = {
        "dossierId": receipt["dossierId"],
        "callId": receipt["callId"],
        "action": receipt["action"],
        "accepted": receipt["accepted"],
        "proposalDigest": receipt["proposalDigest"],
        "receiptId": receipt["receiptId"],
    }
    return canonical_bytes(view)


def verify_receipt_signature(pubkey: Ed25519PublicKey, receipt: dict) -> bool:
    sig_field = receipt.get("receiptSignature", "")
    try:
        # try standard base64 first, then urlsafe, since spec just says "base64"
        try:
            sig = base64.b64decode(sig_field, validate=True)
        except Exception:
            sig = _b64url_decode(sig_field)
        pubkey.verify(sig, receipt_signing_payload(receipt))
        return True
    except (InvalidSignature, ValueError, Exception):
        return False
