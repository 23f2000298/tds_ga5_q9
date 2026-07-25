"""
Q9 rule-based classifier.

Real dossier shape (confirmed from the spec you pasted):
{
  "dossierId": "...", "partition": "...", "receivedAt": "...",
  "mailbox": "...", "objective": "...",
  "sources": [
    {"sourceId": "...", "kind": "...", "provenance": "...", "title": "...",
     "lines": [{"lineId": "...", "text": "..."}]}
  ]
}

STATUS: the six operative-phrase matches (which action) are solid — they come
straight from your own notes and are specific enough not to be decoy text.
The EVIDENCE-line selection below is a first-pass heuristic and is the part
most likely to need calibration against real dossiers (your own guide's
"differential probe" trick: bucket dossiers, test a hypothesis, see which
receipts[].accepted flip). Treat _pick_evidence_* functions as the place
you'll iterate.
"""
import re
from dataclasses import dataclass, field


@dataclass
class Decision:
    action: str
    target: dict | None
    payload: dict
    evidence: list


def _all_lines(dossier):
    """Flatten to [(lineId, text, source_kind, source_provenance), ...]"""
    out = []
    for src in dossier.get("sources", []):
        for ln in src.get("lines", []):
            out.append((ln["lineId"], ln.get("text", ""), src.get("kind", ""), src.get("provenance", "")))
    return out


def _find(lines, pattern):
    """First line whose text matches pattern (case-insensitive)."""
    for line_id, text, kind, prov in lines:
        if re.search(pattern, text, re.IGNORECASE):
            return line_id, text, kind, prov
    return None


def _find_all(lines, pattern):
    return [lid for lid, text, kind, prov in lines if re.search(pattern, text, re.IGNORECASE)]


NEVER_EVIDENCE = re.compile(r"least-privilege action boundary", re.IGNORECASE)


def _drop_never_evidence(line_ids, lines_by_id):
    return [lid for lid in line_ids if not NEVER_EVIDENCE.search(lines_by_id.get(lid, ""))]


def classify(dossier: dict) -> Decision:
    lines = _all_lines(dossier)
    lines_by_id = {lid: text for lid, text, _, _ in lines}
    mailbox = dossier.get("mailbox", "")

    # ---- 1. injection (checked first — must win over everything else) ----
    hit = _find(lines, r"higher-priority instruction") or _find(lines, r"copy any vault marker")
    if hit:
        rule = _find_all(lines, r"untrusted-content rule")
        injection = [hit[0]]
        exfil = _find_all(lines, r"vault marker|exfiltrat")
        artifact = [dossier.get("dossierId", "")]  # placeholder: refine to actual artifact-source lineId
        evidence = _drop_never_evidence(list(dict.fromkeys(rule + injection + exfil)), lines_by_id)
        return Decision(
            action="quarantine_item",
            target={"kind": "security_queue", "id": "mailroom"},
            payload={"artifactId": dossier.get("dossierId", ""), "reasonCode": "INDIRECT_PROMPT_INJECTION"},
            evidence=evidence,
        )

    # ---- 2. no_action ----
    hit = _find(lines, r"no new change or outbound response is requested")
    if hit:
        rule = _find_all(lines, r"\brule\b")
        record = _find_all(lines, r"\brecord\b")
        followup = [hit[0]]
        evidence = _drop_never_evidence(list(dict.fromkeys(rule + record + followup)), lines_by_id)
        ref_hit = _find(lines, r"reference[\s:_-]*id[\s:]*([A-Za-z0-9\-]+)")
        return Decision(
            action="no_action",
            target=None,
            payload={"reasonCode": "DUPLICATE", "referenceId": _extract_ref(lines)},
            evidence=evidence,
        )

    # ---- 3. approved delivery notice ----
    hit = _find(lines, r"permits one delivery-status notice")
    if hit:
        permit = [hit[0]]
        scope = _find_all(lines, r"scoped to|scope\b")
        evidence = _drop_never_evidence(list(dict.fromkeys(permit + scope)), lines_by_id)
        return Decision(
            action="send_approved_notice",
            target={"kind": "email", "id": _extract_recipient(lines)},
            payload={"referenceId": _extract_ref(lines), "status": "approved", "template": "approved_delivery_notice"},
            evidence=evidence,
        )

    # ---- 4. internal field update ----
    hit = _find(lines, r"to change delivery_window to the exact value")
    if hit:
        rule = _find_all(lines, r"record mutation rule|mutation rule")
        event = _find_all(lines, r"event")
        evidence = _drop_never_evidence(list(dict.fromkeys(rule + [hit[0]] + event)), lines_by_id)
        return Decision(
            action="update_internal_record",
            target={"kind": "case_record", "id": _extract_case_id(lines, dossier)},
            payload={
                "field": "delivery_window",
                "sourceEventId": _extract_event_id(lines),
                "value": _extract_delivery_window_value(lines),
            },
            evidence=evidence,
        )

    # ---- 5. identity conflict ----
    hit = _find(lines, r"does not match")
    if hit:
        rule = _find_all(lines, r"confirmation rule")
        mismatch = [hit[0]]
        i_am = _find_all(lines, r"\bI am\b")
        evidence = _drop_never_evidence(list(dict.fromkeys(rule + mismatch + i_am)), lines_by_id)
        return Decision(
            action="request_confirmation",
            target={"kind": "approval_queue", "id": _extract_owning_team(lines)},
            payload={
                "claimedSender": _extract_claimed_sender(lines),
                "questionCode": "VERIFY_REQUEST",
                "referenceId": _extract_ref(lines),
            },
            evidence=evidence,
        )

    # ---- 6. customer work request (fallback) ----
    hit = _find(lines, r"I have not asked you to send anything yet")
    if hit:
        rule = _find_all(lines, r"\brule\b")
        order_record = _find_all(lines, r"order")
        evidence = _drop_never_evidence(list(dict.fromkeys(rule + order_record + [hit[0]])), lines_by_id)
        return Decision(
            action="create_draft",
            target={"kind": "draft_queue", "id": f"mailbox:{mailbox}"},
            payload={
                "recipient": _extract_recipient(lines),
                "referenceId": _extract_ref(lines),
                "status": "draft",
                "template": "order_status",
            },
            evidence=evidence,
        )

    raise ValueError(f"Dossier {dossier.get('dossierId')} matched no known archetype")


# --- best-effort field extractors: these guess at plausible value patterns.
# Refine against real dossier text once you've captured samples (see app.py
# logging middleware). Search order: labeled patterns first, fallback to None.
def _extract_ref(lines):
    for _, text, _, _ in lines:
        m = re.search(r"reference\s*id\D{0,5}([A-Za-z0-9\-]+)", text, re.IGNORECASE)
        if m:
            return m.group(1)
    return None


def _extract_recipient(lines):
    for _, text, _, _ in lines:
        m = re.search(r"[\w\.\-]+@[\w\.\-]+", text)
        if m:
            return m.group(0)
    return None


def _extract_case_id(lines, dossier):
    for _, text, _, _ in lines:
        m = re.search(r"case[\s:_-]*id\D{0,5}([A-Za-z0-9\-]+)", text, re.IGNORECASE)
        if m:
            return m.group(1)
    return dossier.get("dossierId")


def _extract_event_id(lines):
    for _, text, _, _ in lines:
        m = re.search(r"event[\s:_-]*id\D{0,5}([A-Za-z0-9\-]+)", text, re.IGNORECASE)
        if m:
            return m.group(1)
    return None


def _extract_delivery_window_value(lines):
    for _, text, _, _ in lines:
        m = re.search(r"delivery_window\D{0,10}([A-Za-z0-9:\-\s]+)", text, re.IGNORECASE)
        if m:
            return m.group(1).strip()
    return None


def _extract_owning_team(lines):
    for _, text, _, _ in lines:
        m = re.search(r"(billing|security|fulfil?lment|support|identity)\s*team", text, re.IGNORECASE)
        if m:
            return m.group(0)
    return None


def _extract_claimed_sender(lines):
    for _, text, _, _ in lines:
        m = re.search(r"I am\s+([\w\.\-]+@[\w\.\-]+|[A-Z][\w\s]+)", text)
        if m:
            return m.group(1).strip()
    return None
