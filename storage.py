"""SQLite persistence — durable across requests, per the 'do not rely on
process memory for durable state' rule. One file, four tables."""
import json
import sqlite3
import threading

DB_PATH = "mailroom.db"
_lock = threading.Lock()


def _conn():
    c = sqlite3.connect(DB_PATH)
    c.execute("PRAGMA journal_mode=WAL")
    return c


def init_db():
    with _lock, _conn() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS evaluations (
            evaluation_id TEXT PRIMARY KEY,
            input_digest TEXT NOT NULL,
            pubkey_jwk TEXT NOT NULL,
            response_json TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS dossier_cache (
            dossier_id TEXT NOT NULL,
            content_hash TEXT NOT NULL,
            decision_json TEXT NOT NULL,
            call_id TEXT NOT NULL,
            PRIMARY KEY (dossier_id, content_hash)
        );
        CREATE TABLE IF NOT EXISTS proposals (
            evaluation_id TEXT NOT NULL,
            call_id TEXT NOT NULL,
            dossier_id TEXT NOT NULL,
            proposal_json TEXT NOT NULL,
            PRIMARY KEY (evaluation_id, call_id)
        );
        CREATE TABLE IF NOT EXISTS commit_log (
            evaluation_id TEXT NOT NULL,
            call_id TEXT NOT NULL,
            receipt_json TEXT NOT NULL,
            outcome_json TEXT NOT NULL,
            PRIMARY KEY (evaluation_id, call_id)
        );
        CREATE TABLE IF NOT EXISTS commit_responses (
            evaluation_id TEXT NOT NULL,
            receipts_hash TEXT NOT NULL,
            response_json TEXT NOT NULL,
            PRIMARY KEY (evaluation_id, receipts_hash)
        );
        """)


# ---- evaluations ----
def get_evaluation(evaluation_id: str):
    with _lock, _conn() as c:
        row = c.execute(
            "SELECT input_digest, pubkey_jwk, response_json FROM evaluations WHERE evaluation_id=?",
            (evaluation_id,),
        ).fetchone()
    if not row:
        return None
    return {"input_digest": row[0], "pubkey_jwk": json.loads(row[1]), "response_json": json.loads(row[2])}


def save_evaluation(evaluation_id: str, input_digest: str, pubkey_jwk: dict, response: dict):
    with _lock, _conn() as c:
        c.execute(
            "INSERT INTO evaluations (evaluation_id, input_digest, pubkey_jwk, response_json) VALUES (?,?,?,?)",
            (evaluation_id, input_digest, json.dumps(pubkey_jwk), json.dumps(response)),
        )


# ---- dossier decision cache ----
def get_cached_decision(dossier_id: str, content_hash: str):
    with _lock, _conn() as c:
        row = c.execute(
            "SELECT decision_json, call_id FROM dossier_cache WHERE dossier_id=? AND content_hash=?",
            (dossier_id, content_hash),
        ).fetchone()
    if not row:
        return None
    return {"decision": json.loads(row[0]), "call_id": row[1]}


def save_decision(dossier_id: str, content_hash: str, decision: dict, call_id: str):
    with _lock, _conn() as c:
        c.execute(
            "INSERT OR IGNORE INTO dossier_cache (dossier_id, content_hash, decision_json, call_id) VALUES (?,?,?,?)",
            (dossier_id, content_hash, json.dumps(decision), call_id),
        )


# ---- proposals (for commit-time lookup) ----
def save_proposal(evaluation_id: str, call_id: str, dossier_id: str, proposal: dict):
    with _lock, _conn() as c:
        c.execute(
            "INSERT OR IGNORE INTO proposals (evaluation_id, call_id, dossier_id, proposal_json) VALUES (?,?,?,?)",
            (evaluation_id, call_id, dossier_id, json.dumps(proposal)),
        )


def get_proposal(evaluation_id: str, call_id: str):
    with _lock, _conn() as c:
        row = c.execute(
            "SELECT proposal_json FROM proposals WHERE evaluation_id=? AND call_id=?",
            (evaluation_id, call_id),
        ).fetchone()
    return json.loads(row[0]) if row else None


# ---- commit idempotency ----
def get_commit_outcome(evaluation_id: str, call_id: str):
    with _lock, _conn() as c:
        row = c.execute(
            "SELECT outcome_json FROM commit_log WHERE evaluation_id=? AND call_id=?",
            (evaluation_id, call_id),
        ).fetchone()
    return json.loads(row[0]) if row else None


def save_commit_outcome(evaluation_id: str, call_id: str, receipt: dict, outcome: dict):
    with _lock, _conn() as c:
        c.execute(
            "INSERT OR IGNORE INTO commit_log (evaluation_id, call_id, receipt_json, outcome_json) VALUES (?,?,?,?)",
            (evaluation_id, call_id, json.dumps(receipt), json.dumps(outcome)),
        )


def get_commit_response(evaluation_id: str, receipts_hash: str):
    with _lock, _conn() as c:
        row = c.execute(
            "SELECT response_json FROM commit_responses WHERE evaluation_id=? AND receipts_hash=?",
            (evaluation_id, receipts_hash),
        ).fetchone()
    return json.loads(row[0]) if row else None


def save_commit_response(evaluation_id: str, receipts_hash: str, response: dict):
    with _lock, _conn() as c:
        c.execute(
            "INSERT OR IGNORE INTO commit_responses (evaluation_id, receipts_hash, response_json) VALUES (?,?,?)",
            (evaluation_id, receipts_hash, json.dumps(response)),
        )
