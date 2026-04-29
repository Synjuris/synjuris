"""
merkle_dag.py — SynJuris v2 Merkle DAG Audit Ledger
=====================================================
Handles cryptographic integrity for the evidence chain.
"""

import hashlib
import json
from datetime import datetime
from typing import Optional

# ── Node construction ─────────────────────────────────────────────────────────

MERKLE_VERSION = b"\x01"   # version byte prefixed to every hash input
GENESIS_HASH   = "0" * 64  # sentinel parent hash for the first node

def _canonical_bytes(data: dict) -> bytes:
    """Deterministic JSON serialization."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")

def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def compute_node_hash(
    parent_hash: str,
    exhibit_id: int,
    exhibit_content: str,
    event_date: Optional[str],
    category: Optional[str],
    source: Optional[str],
    confirmed: int,
    case_id: int,
    timestamp: str,
) -> str:
    """Deterministic hash for a single Merkle DAG node."""
    payload = _canonical_bytes({
        "v":         1,
        "case_id":   case_id,
        "parent":    parent_hash,
        "exhibit_id": exhibit_id,
        "content_hash": _sha256(exhibit_content.encode("utf-8")),
        "event_date": event_date or "",
        "category":  category or "",
        "source":    source or "",
        "confirmed": confirmed,
        "ts":        timestamp,
    })
    return _sha256(MERKLE_VERSION + payload)

def compute_root_hash(node_hashes: list[str]) -> str:
    """Compute the binary Merkle root over a list of hashes."""
    if not node_hashes:
        return GENESIS_HASH
    if len(node_hashes) == 1:
        return node_hashes[0]

    level = node_hashes[:]
    while len(level) > 1:
        next_level = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else level[i]
            combined = _sha256((left + right).encode("ascii"))
            next_level.append(combined)
        level = next_level
    return level[0]

# ── Database schema ───────────────────────────────────────────────────────────

MERKLE_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS merkle_nodes (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id      INTEGER NOT NULL,
    exhibit_id   INTEGER NOT NULL,
    parent_hash  TEXT    NOT NULL,
    node_hash    TEXT    NOT NULL UNIQUE,
    exhibit_snapshot_json TEXT,
    created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE,
    FOREIGN KEY (exhibit_id) REFERENCES evidence(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS merkle_roots (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id    INTEGER NOT NULL UNIQUE,
    root_hash  TEXT    NOT NULL,
    node_count INTEGER NOT NULL DEFAULT 0,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
);
"""

def init_merkle_schema(conn) -> None:
    """Initialize the cryptographic tables in the database."""
    for stmt in MERKLE_SCHEMA_SQL.strip().split(";"):
        if stmt.strip():
            conn.execute(stmt)
    conn.commit()

# ── Node insertion ────────────────────────────────────────────────────────────

def add_exhibit_to_dag(conn, case_id: int, exhibit: dict) -> str:
    """Adds a confirmed exhibit to the tamper-evident chain."""
    existing = conn.execute(
        "SELECT node_hash FROM merkle_nodes WHERE exhibit_id=?",
        (exhibit["id"],)
    ).fetchone()
    if existing:
        return existing[0]

    tip_row = conn.execute(
        "SELECT node_hash FROM merkle_nodes WHERE case_id=? ORDER BY id DESC LIMIT 1",
        (case_id,)
    ).fetchone()
    parent_hash = tip_row[0] if tip_row else GENESIS_HASH

    ts = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    node_hash = compute_node_hash(
        parent_hash    = parent_hash,
        exhibit_id     = exhibit["id"],
        exhibit_content= exhibit.get("content") or "",
        event_date     = exhibit.get("event_date"),
        category       = exhibit.get("category"),
        source         = exhibit.get("source"),
        confirmed      = exhibit.get("confirmed", 1),
        case_id        = case_id,
        timestamp      = ts,
    )

    snapshot = json.dumps({
        "exhibit_id":   exhibit["id"],
        "content_hash": _sha256((exhibit.get("content") or "").encode("utf-8")),
        "event_date":   exhibit.get("event_date") or "",
        "category":     exhibit.get("category") or "",
        "source":       exhibit.get("source") or "",
        "confirmed":    exhibit.get("confirmed", 1),
    }, separators=(",", ":"))

    conn.execute(
        "INSERT INTO merkle_nodes (case_id, exhibit_id, parent_hash, node_hash, exhibit_snapshot_json) "
        "VALUES (?,?,?,?,?)",
        (case_id, exhibit["id"], parent_hash, node_hash, snapshot)
    )

    _update_root(conn, case_id)
    conn.commit()
    return node_hash

def _update_root(conn, case_id: int) -> str:
    """Recomputes the root hash for the entire case."""
    rows = conn.execute(
        "SELECT node_hash FROM merkle_nodes WHERE case_id=? ORDER BY id ASC",
        (case_id,)
    ).fetchall()
    hashes = [r[0] for r in rows]
    root = compute_root_hash(hashes)
    conn.execute(
        "INSERT INTO merkle_roots (case_id, root_hash, node_count, updated_at) VALUES (?,?,?,CURRENT_TIMESTAMP) "
        "ON CONFLICT(case_id) DO UPDATE SET root_hash=excluded.root_hash, "
        "node_count=excluded.node_count, updated_at=excluded.updated_at",
        (case_id, root, len(hashes))
    )
    return root

def generate_proof_statement(conn, case_id: int, exhibit_ids: list[int]) -> str:
    """Generates a human-readable integrity statement for court."""
    root_row = conn.execute(
        "SELECT root_hash, node_count, updated_at FROM merkle_roots WHERE case_id=?",
        (case_id,)
    ).fetchone()

    if not root_row:
        return "No Merkle DAG established for this case."

    lines = [
        "SYNJURIS CRYPTOGRAPHIC INTEGRITY STATEMENT",
        "=" * 50,
        f"Case DAG Root Hash : {root_row[0]}",
        f"Total Nodes        : {root_row[1]}",
        f"Root Computed At   : {root_row[2]}",
        "",
        "The following exhibits are cryptographically included in the above DAG:",
    ]
    
    for eid in exhibit_ids:
        node = conn.execute("SELECT node_hash FROM merkle_nodes WHERE exhibit_id=?", (eid,)).fetchone()
        if node:
            lines.append(f"  Exhibit {eid}: {node[0][:32]}…")

    return "\n".join(lines)
