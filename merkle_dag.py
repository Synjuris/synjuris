"""
merkle_dag.py — SynJuris v2 Merkle DAG Audit Ledger
"""
import hashlib
import json
from datetime import datetime

MERKLE_VERSION = b"\x01"
GENESIS_HASH   = "0" * 64

def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def compute_node_hash(parent_hash, exhibit_id, exhibit_content, event_date, category, source, confirmed, case_id, timestamp):
    payload = json.dumps({
        "case_id": case_id, "parent": parent_hash, "exhibit_id": exhibit_id,
        "content_hash": _sha256(exhibit_content.encode("utf-8")),
        "category": category or "", "ts": timestamp
    }, sort_keys=True).encode("utf-8")
    return _sha256(MERKLE_VERSION + payload)

def init_merkle_schema(conn):
    conn.execute("CREATE TABLE IF NOT EXISTS merkle_nodes (id INTEGER PRIMARY KEY, case_id INTEGER, exhibit_id INTEGER, parent_hash TEXT, node_hash TEXT UNIQUE)")
    conn.commit()

def add_exhibit_to_dag(conn, case_id, exhibit):
    tip = conn.execute("SELECT node_hash FROM merkle_nodes WHERE case_id=? ORDER BY id DESC LIMIT 1", (case_id,)).fetchone()
    parent = tip[0] if tip else GENESIS_HASH
    ts = datetime.utcnow().isoformat()
    h = compute_node_hash(parent, exhibit['id'], exhibit.get('content',''), exhibit.get('event_date'), exhibit.get('category'), exhibit.get('source'), 1, case_id, ts)
    conn.execute("INSERT OR IGNORE INTO merkle_nodes (case_id, exhibit_id, parent_hash, node_hash) VALUES (?,?,?,?)", (case_id, exhibit['id'], parent, h))
    conn.commit()
    return h
