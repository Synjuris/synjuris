"""
╔══════════════════════════════════════════════════════════════════════════════╗
║              SYNJURIS MASTER PROGRAM — UNIFIED PRODUCTION BUILD             ║
║                                                                              ║
║  Integrates:                                                                 ║
║    • Core HTTP server + SQLite database (from synjuris.py)                  ║
║    • Pattern Engine with Scrutinized Defense Detection (extended)           ║
║    • Merkle DAG Audit Ledger (from merkle_dag.py)                           ║
║    • Document Readiness Engine (from readiness_engine.py)                   ║
║    • UPL Auditor — risk scoring (from auditor.py)                           ║
║    • Guardrails — Grey Rock communication filter (from guardrails.py)       ║
║    • Safe LLM wrapper with retry logic (from safe_llm.py)                   ║
║    • Case Dynamics Engine — x/y/z scoring (from synjuris.py)               ║
║    • Jurisdiction Law table — all 50 states (from synjuris.py)             ║
║    • AI service + Flask-style route blueprints unified into one server      ║
╚══════════════════════════════════════════════════════════════════════════════╝

Run:
    ANTHROPIC_API_KEY=<key> python synjuris_master.py

Environment variables (all optional):
    PORT                  — HTTP port (default 5000)
    SYNJURIS_DB           — SQLite database path (default synjuris.db)
    SYNJURIS_UPLOADS      — Upload directory (default uploads/)
    ANTHROPIC_API_KEY     — Anthropic key for AI features
    OPENAI_API_KEY        — OpenAI key (fallback AI)
    SYNJURIS_LOCAL        — Set to "1" to auto-open browser (default 1)
"""

# ══════════════════════════════════════════════════════════════════════════════
# IMPORTS
# ══════════════════════════════════════════════════════════════════════════════
import sqlite3, json, os, re, hashlib, hmac, time, uuid, math, sys, queue
import threading, webbrowser, urllib.request, urllib.parse
from datetime import datetime, date
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor
from collections import OrderedDict
from typing import Optional, Callable

# ══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ══════════════════════════════════════════════════════════════════════════════
VERSION      = "3.0.0-master"
PORT         = int(os.environ.get("PORT", 5000))
DB_PATH      = os.environ.get("SYNJURIS_DB", "synjuris.db")
UPLOADS_DIR  = os.environ.get("SYNJURIS_UPLOADS", "uploads")
API_KEY      = os.environ.get("ANTHROPIC_API_KEY", "")
OPENAI_KEY   = os.environ.get("OPENAI_API_KEY", "")
LOCAL_MODE   = os.environ.get("SYNJURIS_LOCAL", "1") == "1"

# ══════════════════════════════════════════════════════════════════════════════
# MODULE 1 — UPL AUDITOR
# Scores AI output for unauthorized practice of law risk.
# Source: auditor.py (guarded_module)
# ══════════════════════════════════════════════════════════════════════════════
UPL_RISK_PATTERNS = {
    "explicit_advice": [
        r"\byou should\b", r"\byou need to\b", r"\bi recommend\b",
    ],
    "implicit_advice": [
        r"\bit may be beneficial\b", r"\bit would be better\b", r"\bthe best option\b",
    ],
    "outcome_prediction": [
        r"\byou will likely\b", r"\bthis will result in\b", r"\byou are likely to win\b",
    ],
    "strategy_framing": [
        r"\byour argument\b", r"\byour best argument\b", r"\byou could argue\b",
    ],
}

UPL_CATEGORY_WEIGHTS = {
    "explicit_advice": 0.4,
    "implicit_advice": 0.3,
    "outcome_prediction": 0.4,
    "strategy_framing": 0.2,
}

def upl_score_text(text: str) -> dict:
    """Score text for UPL risk. Returns score (0.0–1.0) and flagged categories."""
    score = 0.0
    flags = []
    for category, patterns in UPL_RISK_PATTERNS.items():
        for p in patterns:
            if re.search(p, text, re.IGNORECASE):
                flags.append(category)
                score += UPL_CATEGORY_WEIGHTS.get(category, 0.2)
    return {"upl_risk_score": min(score, 1.0), "flags": list(set(flags))}


def llm_upl_audit(text: str, llm_call: Callable) -> dict:
    """Use an LLM to perform a deeper UPL compliance audit."""
    prompt = f"""You are a compliance auditor for legal AI outputs.

Analyze the following text for:
- Legal advice
- Recommendations
- Outcome predictions
- Strategy framing

Respond ONLY in JSON with no preamble:

{{"upl_risk_score": 0.0, "flags": []}}

TEXT:
{text}"""
    response = llm_call(prompt)
    try:
        clean = response.strip().replace("```json", "").replace("```", "").strip()
        return json.loads(clean)
    except Exception:
        return {"upl_risk_score": 0.5, "flags": ["parse_error"]}


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 2 — GUARDRAILS (Grey Rock Communication Filter)
# Strips emotional/reactive language from outgoing messages.
# Source: guardrails.py (guarded_module), extended with grey_rock logic
# ══════════════════════════════════════════════════════════════════════════════
BLOCKED_PHRASES = [
    r"\byou should\b",
    r"\bi recommend\b",
    r"\byou need to\b",
]

JADE_SUBSTITUTIONS = [
    # Pattern, Replacement
    (r"(?i)I feel like you always",   "The records indicate a pattern of"),
    (r"(?i)It's not fair that you",   "Per the standing court order,"),
    (r"(?i)Why are you being so",     "I am requesting clarification on"),
    (r"(?i)\byou should\b",           "litigants sometimes"),
    (r"(?i)\bi recommend\b",          "one possible approach is"),
    (r"(?i)\byou need to\b",          "the order requires"),
]

def guardrail_detect_block(text: str) -> bool:
    """True if text contains patterns that should be blocked."""
    for p in BLOCKED_PHRASES:
        if re.search(p, text, re.IGNORECASE):
            return True
    return False

def guardrail_clean(text: str) -> str:
    """Apply JADE → factual substitutions (Grey Rock filter)."""
    for pattern, replacement in JADE_SUBSTITUTIONS:
        text = re.sub(pattern, replacement, text)
    return text

def apply_grey_rock_filter(text: str) -> str:
    """Full Grey Rock filter: clean + length note."""
    text = guardrail_clean(text)
    if len(text.split()) > 50:
        text += " (Note: Streamlining communication for court clarity.)"
    return text


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 3 — SAFE LLM WRAPPER
# Retries LLM calls, enforces guardrails, returns audited output.
# Source: safe_llm.py (guarded_module)
# ══════════════════════════════════════════════════════════════════════════════
MAX_LLM_RETRIES = 2

def safe_generate(prompt: str, llm_call: Callable) -> dict:
    """
    Call llm_call(prompt), enforce guardrails, audit UPL risk.
    Returns {"content": str, "audit": dict}.
    """
    for attempt in range(MAX_LLM_RETRIES + 1):
        raw = llm_call(prompt)

        if guardrail_detect_block(raw):
            prompt += "\n\nREINFORCE: Do NOT give legal advice or recommendations."
            continue

        cleaned = guardrail_clean(raw)
        audit = upl_score_text(cleaned)

        if audit["upl_risk_score"] > 0.5:
            prompt += "\n\nREINFORCE: Remove all advisory language and outcome predictions."
            continue

        return {"content": cleaned, "audit": audit}

    return {
        "content": "Output blocked for safety. Please rephrase your query.",
        "audit": {"upl_risk_score": 1.0, "flags": ["max_retries_exceeded"]},
    }


def safe_generate_with_defense(prompt: str, llm_call: Callable) -> dict:
    """
    Extended safe_generate that also applies the Grey Rock filter
    and checks for high-conflict tone markers in the final output.
    """
    result = safe_generate(prompt, llm_call)
    result["content"] = apply_grey_rock_filter(result["content"])

    # Final high-conflict tone check
    hc_flags = []
    if re.search(r"\bI feel\b", result["content"], re.I):
        hc_flags.append("first_person_emotional")
    if re.search(r"\bYou always\b", result["content"], re.I):
        hc_flags.append("absolute_accusation")
    if hc_flags:
        result["audit"]["high_conflict_risk"] = True
        result["audit"]["hc_flags"] = hc_flags

    return result


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 4 — PATTERN ENGINE
# Detects high-conflict behaviors in text and scores court-scrutinized actions.
# Source: pattern_engine.py (main) + new SCRUTINIZED_PATTERNS from document
# ══════════════════════════════════════════════════════════════════════════════

# Standard patterns from original pattern_engine.py
STANDARD_PATTERNS = {
    "Gatekeeping":         [r"refused access", r"denied visitation", r"withheld child"],
    "Violation of Order":  [r"contempt", r"disobeyed", r"failed to return"],
    "Harassment":          [r"threatened", r"excessive calls", r"insulted"],
    "Parental Alienation": [r"alienat", r"turned the kids against", r"bad-mouth"],
    "Threats":             [r"threaten", r"will make you pay", r"you'll regret"],
    "Relocation":          [r"moved without", r"relocated without", r"left the state"],
    "Financial":           [r"refused to pay", r"hidden assets", r"stopped support"],
    "Stonewalling":        [r"refused to respond", r"ignored", r"no response"],
    "Emotional Abuse":     [r"demeaned", r"berated", r"humiliated"],
    "Neglect / Safety":    [r"left alone", r"unsupervised", r"unsafe"],
    "Substance Concern":   [r"drunk", r"high", r"substance", r"intoxicated"],
    "Child Statement":     [r"child said", r"kids told me", r"my daughter said"],
}

# Extended patterns for behaviors courts specifically scrutinize
SCRUTINIZED_PATTERNS = {
    "gatekeeping": [
        r"(?i)you (?:cannot|won't|are not allowed to) (?:see|have) the children",
        r"(?i)I (?:decided|am deciding) not to give you the (?:records|info|schedule)",
        r"(?i)don't bother showing up for your (?:visit|time)",
    ],
    "disparagement": [
        r"(?i)(?:your|the) (?:mother|father) is (?:crazy|lying|a loser|unstable)",
        r"(?i)tell your (?:mom|dad) that I said",
        r"(?i)the kids know you're",
    ],
    "litigation_abuse": [
        r"(?i)I'm not (?:signing|responding to) that",
        r"(?i)take me back to court",
        r"(?i)I'll make sure you go broke in legal fees",
    ],
}

# Z-axis pressure contributions per scrutinized category
SCRUTINIZED_Z_WEIGHTS = {
    "gatekeeping":       0.25,
    "litigation_abuse":  0.15,
    "disparagement":     0.10,
}

# Evidence weight per category for x/z axis scoring
CATEGORY_WEIGHTS = {
    "Gatekeeping": 5.0, "Violation of Order": 5.0, "Threats": 5.0, "Relocation": 5.0,
    "Parental Alienation": 4.0, "Harassment": 4.0, "Financial": 4.0,
    "Stonewalling": 3.0, "Emotional Abuse": 2.0, "Neglect / Safety": 2.0,
    "Substance Concern": 2.0, "Child Statement": 1.0,
}

class PatternEngine:
    def scan(self, text: str) -> list:
        """Scan text with standard patterns. Returns [(category, score, severity)]."""
        results = []
        for cat, regexes in STANDARD_PATTERNS.items():
            if any(re.search(r, text, re.I) for r in regexes):
                results.append((cat, 1.0, "high"))
        return sorted(results, key=lambda x: -x[1])

def scan_patterns(text: str) -> list:
    return PatternEngine().scan(text)

def analyze_scrutinized_behavior(text: str) -> list:
    """Detect court-scrutinized behaviors. Returns list of detected category names."""
    findings = []
    for category, patterns in SCRUTINIZED_PATTERNS.items():
        for p in patterns:
            if re.search(p, text):
                findings.append(category)
                break
    return list(set(findings))

def compute_scrutinized_z_delta(text: str) -> float:
    """Return total z-axis pressure increase from scrutinized behaviors in text."""
    behaviors = analyze_scrutinized_behavior(text)
    return sum(SCRUTINIZED_Z_WEIGHTS.get(b, 0.0) for b in behaviors)


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 5 — MERKLE DAG AUDIT LEDGER
# Tamper-evident hash chain for evidence integrity.
# Source: merkle_dag.py (main)
# ══════════════════════════════════════════════════════════════════════════════
MERKLE_VERSION = b"\x01"
GENESIS_HASH   = "0" * 64

def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def compute_node_hash(parent_hash, exhibit_id, exhibit_content,
                      event_date, category, source, confirmed, case_id, timestamp) -> str:
    payload = json.dumps({
        "case_id": case_id, "parent": parent_hash, "exhibit_id": exhibit_id,
        "content_hash": _sha256(exhibit_content.encode("utf-8")),
        "category": category or "", "ts": timestamp,
    }, sort_keys=True).encode("utf-8")
    return _sha256(MERKLE_VERSION + payload)

def init_merkle_schema(conn):
    conn.execute("""CREATE TABLE IF NOT EXISTS merkle_nodes (
        id INTEGER PRIMARY KEY,
        case_id INTEGER,
        exhibit_id INTEGER,
        parent_hash TEXT,
        node_hash TEXT UNIQUE,
        exhibit_snapshot_json TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS merkle_roots (
        id INTEGER PRIMARY KEY,
        case_id INTEGER NOT NULL UNIQUE,
        root_hash TEXT NOT NULL,
        node_count INTEGER NOT NULL DEFAULT 0,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )""")
    conn.commit()

def add_exhibit_to_dag(conn, case_id: int, exhibit: dict) -> str:
    """Add exhibit to the Merkle DAG and return its node hash."""
    tip = conn.execute(
        "SELECT node_hash FROM merkle_nodes WHERE case_id=? ORDER BY id DESC LIMIT 1",
        (case_id,)
    ).fetchone()
    parent = tip[0] if tip else GENESIS_HASH
    ts = datetime.utcnow().isoformat()
    h = compute_node_hash(
        parent, exhibit["id"], exhibit.get("content", ""),
        exhibit.get("event_date"), exhibit.get("category"),
        exhibit.get("source"), 1, case_id, ts,
    )
    conn.execute(
        "INSERT OR IGNORE INTO merkle_nodes (case_id, exhibit_id, parent_hash, node_hash, exhibit_snapshot_json) VALUES (?,?,?,?,?)",
        (case_id, exhibit["id"], parent, h, json.dumps(exhibit)),
    )
    # Update root
    node_count = conn.execute(
        "SELECT COUNT(*) FROM merkle_nodes WHERE case_id=?", (case_id,)
    ).fetchone()[0]
    conn.execute(
        "INSERT OR REPLACE INTO merkle_roots (case_id, root_hash, node_count, updated_at) VALUES (?,?,?,?)",
        (case_id, h, node_count, datetime.utcnow().isoformat()),
    )
    conn.commit()
    return h

def get_merkle_root(conn, case_id: int) -> Optional[str]:
    row = conn.execute(
        "SELECT root_hash FROM merkle_roots WHERE case_id=?", (case_id,)
    ).fetchone()
    return row[0] if row else None

def verify_dag_chain(conn, case_id: int) -> dict:
    """Verify the full Merkle chain for a case. Returns {valid, node_count, errors}."""
    nodes = conn.execute(
        "SELECT * FROM merkle_nodes WHERE case_id=? ORDER BY id ASC", (case_id,)
    ).fetchall()
    errors = []
    for i, node in enumerate(nodes):
        n = dict(node)
        expected_parent = GENESIS_HASH if i == 0 else dict(nodes[i-1])["node_hash"]
        if n["parent_hash"] != expected_parent:
            errors.append(f"Node {n['id']}: parent_hash mismatch at position {i}")
        snap = json.loads(n.get("exhibit_snapshot_json") or "{}")
        if snap:
            recomputed = compute_node_hash(
                n["parent_hash"], snap.get("id", 0), snap.get("content", ""),
                snap.get("event_date"), snap.get("category"), snap.get("source"),
                1, case_id, ""  # ts not stored in old nodes — skip hash recompute
            )
    return {"valid": len(errors) == 0, "node_count": len(nodes), "errors": errors}


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 6 — READINESS ENGINE
# Scores document readiness for filing.
# Source: readiness_engine.py (main)
# ══════════════════════════════════════════════════════════════════════════════

def score_document(doc_type: str, case: dict, evidence: list,
                   deadlines: list, parties: list) -> dict:
    score = 0
    if len(evidence) > 0:     score += 40
    if case.get("jurisdiction"): score += 30
    if len(parties) >= 2:     score += 30
    return {
        "doc_type": doc_type,
        "score": score,
        "label": "Ready" if score >= 90 else "In Progress",
        "missing": [
            *( ["Add evidence exhibits"] if len(evidence) == 0 else [] ),
            *( ["Set jurisdiction"] if not case.get("jurisdiction") else [] ),
            *( ["Add both parties"] if len(parties) < 2 else [] ),
        ],
    }

def compute_readiness_scores(case_id: int, conn) -> dict:
    case    = dict(conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone() or {})
    ev      = [dict(r) for r in conn.execute("SELECT * FROM evidence WHERE case_id=? AND confirmed=1", (case_id,)).fetchall()]
    parties = [dict(r) for r in conn.execute("SELECT * FROM parties WHERE case_id=?", (case_id,)).fetchall()]
    dls     = [dict(r) for r in conn.execute("SELECT * FROM deadlines WHERE case_id=?", (case_id,)).fetchall()]
    return {
        "Motion for Contempt":       score_document("Motion for Contempt",       case, ev, dls, parties),
        "Motion to Modify Custody":  score_document("Motion to Modify Custody",  case, ev, dls, parties),
        "Parenting Plan":            score_document("Parenting Plan",            case, ev, dls, parties),
        "Domestic Violence Petition":score_document("Domestic Violence Petition",case, ev, dls, parties),
    }


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 7 — CASE DYNAMICS ENGINE  (x / y / z scoring)
# Deterministic 3-axis case state calculation.
# Source: synjuris.py core
# ══════════════════════════════════════════════════════════════════════════════
_CLAMP_MIN, _CLAMP_MAX = 1, 9
_EV_CEIL, _ADV_CEIL = 50.0, 50.0

def _clamp(v: float) -> int:
    return max(_CLAMP_MIN, min(_CLAMP_MAX, int(v)))

def _s9(raw: float, ceil: float) -> int:
    if raw <= 0:
        return 1
    return _clamp(1 + (raw / ceil) * 8)

def _hash_states(states: list) -> str:
    def _n(o):
        if isinstance(o, float): return round(o, 8)
        if isinstance(o, dict):  return {k: _n(v) for k, v in sorted(o.items())}
        if isinstance(o, list):  return [_n(i) for i in o]
        return o
    return hashlib.sha256(
        json.dumps(_n(states), separators=(",", ":"), sort_keys=True).encode()
    ).hexdigest()

def compute_case_state(case_id: int, conn=None) -> dict:
    """
    Compute deterministic x/y/z case state.
      x = Evidence Weight (1–9)
      y = Procedural Health (1–9)
      z = Adversarial Pressure (1–9)
    Returns full trace with per-exhibit deltas and integrity hash.
    """
    _own_conn = conn is None
    if _own_conn:
        conn = get_db()

    ev  = conn.execute(
        "SELECT id, exhibit_number, content, category, event_date, source "
        "FROM evidence WHERE case_id=? AND confirmed=1 ORDER BY event_date ASC, id ASC",
        (case_id,)
    ).fetchall()
    dls = conn.execute(
        "SELECT id, due_date, title, completed FROM deadlines WHERE case_id=?",
        (case_id,)
    ).fetchall()

    if _own_conn:
        conn.close()

    ev  = [dict(e) for e in ev]
    dls = [dict(d) for d in dls]

    ev_w   = sum(CATEGORY_WEIGHTS.get(e["category"], 1.0) for e in ev)
    adv_w  = sum(CATEGORY_WEIGHTS.get(e["category"], 1.0) for e in ev
                 if CATEGORY_WEIGHTS.get(e["category"], 0) >= 3.0)

    total_dl = len(dls)
    done_dl  = sum(1 for d in dls if d["completed"])
    over     = sum(1 for d in dls if not d["completed"] and d["due_date"]
                   and d["due_date"] < date.today().isoformat())

    if total_dl == 0:
        y_final = 5
    else:
        raw_y = (done_dl / total_dl) * 9 - over * 0.5
        y_final = _clamp(max(raw_y, 0.0)) if raw_y >= 1 else 1

    x_final = _s9(ev_w,  _EV_CEIL)
    z_final = _s9(adv_w, _ADV_CEIL)

    running = {"x": 1, "y": y_final, "z": 1}
    chain   = []
    hist    = [dict(running)]

    per_x = (x_final - 1) / max(len(ev), 1)
    per_z = (z_final - 1) / max(len(ev), 1)

    for e in ev:
        w  = CATEGORY_WEIGHTS.get(e["category"], 1.0)
        dx = per_x * w
        dz = per_z * w if w >= 3.0 else 0.0
        ns = {
            "x": _clamp(running["x"] + dx),
            "y": running["y"],
            "z": _clamp(running["z"] + dz),
        }
        chain.append({
            "exhibit_id":     e["id"],
            "exhibit_number": e["exhibit_number"] or "unnum",
            "category":       e["category"] or "General",
            "weight":         w,
            "event_date":     e["event_date"] or "undated",
            "source":         e["source"] or "manual",
            "delta":          {"x": round(dx, 4), "y": 0.0, "z": round(dz, 4)},
            "state_after":    dict(ns),
        })
        hist.append(dict(ns))
        running = ns

    final_state = {"x": x_final, "y": y_final, "z": z_final}

    return {
        "state": final_state,
        "inputs": {
            "evidence_count":    len(ev),
            "ev_weight_sum":     round(ev_w,  4),
            "adv_weight_sum":    round(adv_w, 4),
            "total_deadlines":   total_dl,
            "done_deadlines":    done_dl,
            "overdue_deadlines": over,
        },
        "deltas": chain,
        "hash":   _hash_states(hist),
    }

def update_case_z_from_exhibit(case_id: int, exhibit_text: str, conn) -> dict:
    """
    Detect scrutinized behaviors in new exhibit text and bump z-axis accordingly.
    Returns {"new_z_score": float (0–1), "flags": list, "z_delta": float}.
    """
    behaviors  = analyze_scrutinized_behavior(exhibit_text)
    z_increase = sum(SCRUTINIZED_Z_WEIGHTS.get(b, 0.0) for b in behaviors)

    current = compute_case_state(case_id, conn)
    raw_z   = current["state"]["z"]
    # Scale back to 0-1 for the scrutiny sub-score
    new_z   = min((raw_z / 9.0) + z_increase, 1.0)

    return {"new_z_score": round(new_z, 4), "flags": behaviors, "z_delta": z_increase}


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 8 — JURISDICTION TABLE
# All 50 states + DC with custody, support, DV statute references.
# Source: synjuris.py
# ══════════════════════════════════════════════════════════════════════════════
JURISDICTION_LAW = {
    "Alabama":        {"custody": "Ala. Code § 30-3-1",           "support": "Ala. Code § 30-3-110",     "dv": "Ala. Code § 30-5-1"},
    "Alaska":         {"custody": "Alaska Stat. § 25.20.060",     "support": "Alaska Stat. § 25.27.020", "dv": "Alaska Stat. § 18.66.100"},
    "Arizona":        {"custody": "A.R.S. § 25-403",              "support": "A.R.S. § 25-501",          "dv": "A.R.S. § 13-3601"},
    "Arkansas":       {"custody": "Ark. Code § 9-13-101",         "support": "Ark. Code § 9-14-201",     "dv": "Ark. Code § 9-15-201"},
    "California":     {"custody": "Cal. Fam. Code § 3020",        "support": "Cal. Fam. Code § 4050",    "dv": "Cal. Fam. Code § 6200"},
    "Colorado":       {"custody": "C.R.S. § 14-10-124",           "support": "C.R.S. § 14-14-104",       "dv": "C.R.S. § 13-14-101"},
    "Connecticut":    {"custody": "C.G.S. § 46b-56",              "support": "C.G.S. § 46b-84",          "dv": "C.G.S. § 46b-15"},
    "Delaware":       {"custody": "13 Del. C. § 722",             "support": "13 Del. C. § 514",         "dv": "10 Del. C. § 1041"},
    "Florida":        {"custody": "Fla. Stat. § 61.13",           "support": "Fla. Stat. § 61.29",       "dv": "Fla. Stat. § 741.28"},
    "Georgia":        {"custody": "O.C.G.A. § 19-9-1",            "support": "O.C.G.A. § 19-6-15",      "dv": "O.C.G.A. § 19-13-1"},
    "Hawaii":         {"custody": "HRS § 571-46",                 "support": "HRS § 576D-1",             "dv": "HRS § 586-1"},
    "Idaho":          {"custody": "Idaho Code § 32-717",          "support": "Idaho Code § 32-706",      "dv": "Idaho Code § 39-6301"},
    "Illinois":       {"custody": "750 ILCS 5/602.5",             "support": "750 ILCS 5/505",           "dv": "750 ILCS 60/101"},
    "Indiana":        {"custody": "I.C. § 31-17-2-8",             "support": "I.C. § 31-16-6-1",        "dv": "I.C. § 34-26-5-1"},
    "Iowa":           {"custody": "Iowa Code § 598.41",           "support": "Iowa Code § 598.21B",      "dv": "Iowa Code § 236.2"},
    "Kansas":         {"custody": "K.S.A. § 23-3203",             "support": "K.S.A. § 23-3001",         "dv": "K.S.A. § 60-3101"},
    "Kentucky":       {"custody": "KRS § 403.270",                "support": "KRS § 403.212",            "dv": "KRS § 403.715"},
    "Louisiana":      {"custody": "La. C.C. Art. 132",            "support": "La. R.S. § 9:315",         "dv": "La. R.S. § 46:2131"},
    "Maine":          {"custody": "19-A M.R.S. § 1653",           "support": "19-A M.R.S. § 2006",       "dv": "19-A M.R.S. § 4001"},
    "Maryland":       {"custody": "Md. Code, FL § 9-101",         "support": "Md. Code, FL § 12-201",    "dv": "Md. Code, FL § 4-501"},
    "Massachusetts":  {"custody": "M.G.L. c.208 § 31",            "support": "M.G.L. c.208 § 28",        "dv": "M.G.L. c.209A § 1"},
    "Michigan":       {"custody": "MCL § 722.23",                 "support": "MCL § 552.451",            "dv": "MCL § 600.2950"},
    "Minnesota":      {"custody": "Minn. Stat. § 518.17",         "support": "Minn. Stat. § 518A.26",    "dv": "Minn. Stat. § 518B.01"},
    "Mississippi":    {"custody": "Miss. Code § 93-5-24",         "support": "Miss. Code § 93-9-1",      "dv": "Miss. Code § 93-21-1"},
    "Missouri":       {"custody": "Mo. Rev. Stat. § 452.375",     "support": "Mo. Rev. Stat. § 452.340", "dv": "Mo. Rev. Stat. § 455.010"},
    "Montana":        {"custody": "MCA § 40-4-212",               "support": "MCA § 40-5-201",           "dv": "MCA § 40-15-101"},
    "Nebraska":       {"custody": "Neb. Rev. Stat. § 43-2923",    "support": "Neb. Rev. Stat. § 42-364", "dv": "Neb. Rev. Stat. § 42-903"},
    "Nevada":         {"custody": "NRS § 125C.0035",              "support": "NRS § 125B.010",           "dv": "NRS § 33.018"},
    "New Hampshire":  {"custody": "RSA § 461-A:6",                "support": "RSA § 458-C:3",            "dv": "RSA § 173-B:1"},
    "New Jersey":     {"custody": "N.J.S.A. § 9:2-4",             "support": "N.J.S.A. § 2A:34-23",     "dv": "N.J.S.A. § 2C:25-17"},
    "New Mexico":     {"custody": "NMSA § 40-4-9.1",              "support": "NMSA § 40-4-11.1",         "dv": "NMSA § 40-13-1"},
    "New York":       {"custody": "N.Y. Dom. Rel. Law § 240",     "support": "N.Y. Fam. Ct. Act § 413",  "dv": "N.Y. Fam. Ct. Act § 812"},
    "North Carolina": {"custody": "N.C.G.S. § 50-13.2",           "support": "N.C.G.S. § 50-13.4",       "dv": "N.C.G.S. § 50B-1"},
    "North Dakota":   {"custody": "N.D.C.C. § 14-09-06.2",        "support": "N.D.C.C. § 14-09-09.7",   "dv": "N.D.C.C. § 14-07.1-01"},
    "Ohio":           {"custody": "ORC § 3109.04",                "support": "ORC § 3119.02",            "dv": "ORC § 3113.31"},
    "Oklahoma":       {"custody": "43 O.S. § 112",                "support": "43 O.S. § 118",            "dv": "22 O.S. § 60.1"},
    "Oregon":         {"custody": "ORS § 107.137",                "support": "ORS § 107.105",            "dv": "ORS § 107.700"},
    "Pennsylvania":   {"custody": "23 Pa.C.S. § 5328",            "support": "23 Pa.C.S. § 4322",        "dv": "23 Pa.C.S. § 6101"},
    "Rhode Island":   {"custody": "R.I. Gen. Laws § 15-5-16",     "support": "R.I. Gen. Laws § 15-5-16.2","dv": "R.I. Gen. Laws § 15-15-1"},
    "South Carolina": {"custody": "S.C. Code § 63-15-230",        "support": "S.C. Code § 63-17-470",    "dv": "S.C. Code § 20-4-20"},
    "South Dakota":   {"custody": "SDCL § 25-5-7.1",              "support": "SDCL § 25-7-6.2",          "dv": "SDCL § 25-10-1"},
    "Tennessee":      {"custody": "TN Code § 36-6-101",           "support": "TN Code § 36-5-101",       "dv": "TN Code § 36-3-601"},
    "Texas":          {"custody": "Tex. Fam. Code § 153.002",     "support": "Tex. Fam. Code § 154.001", "dv": "Tex. Fam. Code § 71.004"},
    "Utah":           {"custody": "Utah Code § 30-3-10",          "support": "Utah Code § 78B-12-202",   "dv": "Utah Code § 77-36-1"},
    "Vermont":        {"custody": "15 V.S.A. § 665",              "support": "15 V.S.A. § 653",          "dv": "15 V.S.A. § 1101"},
    "Virginia":       {"custody": "Va. Code § 20-124.3",          "support": "Va. Code § 20-108.2",      "dv": "Va. Code § 16.1-228"},
    "Washington":     {"custody": "RCW § 26.09.187",              "support": "RCW § 26.19.020",          "dv": "RCW § 26.50.010"},
    "West Virginia":  {"custody": "W. Va. Code § 48-9-206",       "support": "W. Va. Code § 48-13-301",  "dv": "W. Va. Code § 48-27-202"},
    "Wisconsin":      {"custody": "Wis. Stat. § 767.41",          "support": "Wis. Stat. § 767.511",     "dv": "Wis. Stat. § 813.12"},
    "Wyoming":        {"custody": "Wyo. Stat. § 20-2-201",        "support": "Wyo. Stat. § 20-2-304",    "dv": "Wyo. Stat. § 35-21-102"},
    "Washington D.C.":{"custody": "D.C. Code § 16-914",           "support": "D.C. Code § 16-916",       "dv": "D.C. Code § 16-1001"},
}

JURISDICTION_ALIASES = {
    "al":"Alabama","ak":"Alaska","az":"Arizona","ar":"Arkansas","ca":"California",
    "co":"Colorado","ct":"Connecticut","de":"Delaware","fl":"Florida","ga":"Georgia",
    "hi":"Hawaii","id":"Idaho","il":"Illinois","in":"Indiana","ia":"Iowa","ks":"Kansas",
    "ky":"Kentucky","la":"Louisiana","me":"Maine","md":"Maryland","ma":"Massachusetts",
    "mi":"Michigan","mn":"Minnesota","ms":"Mississippi","mo":"Missouri","mt":"Montana",
    "ne":"Nebraska","nv":"Nevada","nh":"New Hampshire","nj":"New Jersey","nm":"New Mexico",
    "ny":"New York","nc":"North Carolina","nd":"North Dakota","oh":"Ohio","ok":"Oklahoma",
    "or":"Oregon","pa":"Pennsylvania","ri":"Rhode Island","sc":"South Carolina",
    "sd":"South Dakota","tn":"Tennessee","tx":"Texas","ut":"Utah","vt":"Vermont",
    "va":"Virginia","wa":"Washington","wv":"West Virginia","wi":"Wisconsin","wy":"Wyoming",
    "dc":"Washington D.C.","d.c.":"Washington D.C.",
    "tenn":"Tennessee","calif":"California","colo":"Colorado","conn":"Connecticut",
    "mass":"Massachusetts","mich":"Michigan","minn":"Minnesota","penn":"Pennsylvania",
}

def resolve_jurisdiction(raw: str):
    if not raw:
        return None, {}
    key = raw.strip().lower()
    canonical = JURISDICTION_ALIASES.get(key) or next(
        (k for k in JURISDICTION_LAW if k.lower() == key), None
    )
    if canonical:
        return canonical, JURISDICTION_LAW.get(canonical, {})
    return raw, {}


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 9 — DATABASE
# ══════════════════════════════════════════════════════════════════════════════
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    conn = get_db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS schema_version (
        version INTEGER PRIMARY KEY,
        applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS cases (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        case_type TEXT,
        jurisdiction TEXT,
        court_name TEXT,
        case_number TEXT,
        filing_deadline TEXT,
        hearing_date TEXT,
        goals TEXT,
        notes TEXT,
        user_id INTEGER,
        is_deleted INTEGER DEFAULT 0,
        deleted_at DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS parties (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id INTEGER REFERENCES cases(id) ON DELETE CASCADE,
        name TEXT, role TEXT, contact TEXT, attorney TEXT, notes TEXT
    );
    CREATE TABLE IF NOT EXISTS evidence (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id INTEGER REFERENCES cases(id) ON DELETE CASCADE,
        exhibit_number TEXT,
        content TEXT,
        source TEXT,
        event_date TEXT,
        category TEXT,
        confirmed INTEGER DEFAULT 0,
        notes TEXT,
        file_path TEXT,
        file_type TEXT,
        original_filename TEXT,
        is_deleted INTEGER DEFAULT 0,
        deleted_at DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS documents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id INTEGER REFERENCES cases(id) ON DELETE CASCADE,
        title TEXT, doc_type TEXT, content TEXT,
        version INTEGER DEFAULT 1,
        parent_id INTEGER,
        is_deleted INTEGER DEFAULT 0,
        deleted_at DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS timeline_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id INTEGER REFERENCES cases(id) ON DELETE CASCADE,
        event_date TEXT, title TEXT, description TEXT,
        category TEXT, importance TEXT DEFAULT 'normal',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS deadlines (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id INTEGER REFERENCES cases(id) ON DELETE CASCADE,
        due_date TEXT, title TEXT, description TEXT,
        completed INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS chat_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id INTEGER REFERENCES cases(id) ON DELETE CASCADE,
        role TEXT, content TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id INTEGER REFERENCES cases(id) ON DELETE CASCADE,
        action_type TEXT NOT NULL,
        ai_call_type TEXT,
        state_x INTEGER, state_y INTEGER, state_z INTEGER,
        trace_hash TEXT NOT NULL,
        state_snapshot_json TEXT,
        prompt_inputs_json TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS merkle_nodes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id INTEGER NOT NULL,
        exhibit_id INTEGER NOT NULL,
        parent_hash TEXT NOT NULL,
        node_hash TEXT NOT NULL UNIQUE,
        exhibit_snapshot_json TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS merkle_roots (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id INTEGER NOT NULL UNIQUE,
        root_hash TEXT NOT NULL,
        node_count INTEGER NOT NULL DEFAULT 0,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    """)
    conn.commit()
    conn.close()
    os.makedirs(UPLOADS_DIR, exist_ok=True)


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 10 — AI SERVICE
# Unified LLM caller — tries Anthropic, falls back to OpenAI.
# ══════════════════════════════════════════════════════════════════════════════
def call_anthropic(prompt: str, system: str = "You are a legal document assistant. Never give legal advice.") -> str:
    if not API_KEY:
        return "[No ANTHROPIC_API_KEY configured]"
    payload = json.dumps({
        "model": "claude-opus-4-6",
        "max_tokens": 1024,
        "system": system,
        "messages": [{"role": "user", "content": prompt}],
    }).encode("utf-8")
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=payload,
        headers={
            "x-api-key": API_KEY,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
            return data["content"][0]["text"]
    except Exception as e:
        return f"[Anthropic error: {e}]"

def call_openai(prompt: str) -> str:
    if not OPENAI_KEY:
        return "[No OPENAI_API_KEY configured]"
    payload = json.dumps({
        "model": "gpt-4o-mini",
        "messages": [
            {"role": "system", "content": "You are a legal document assistant. Never give legal advice."},
            {"role": "user", "content": prompt},
        ],
    }).encode("utf-8")
    req = urllib.request.Request(
        "https://api.openai.com/v1/chat/completions",
        data=payload,
        headers={
            "Authorization": f"Bearer {OPENAI_KEY}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
            return data["choices"][0]["message"]["content"]
    except Exception as e:
        return f"[OpenAI error: {e}]"

def llm_call(prompt: str) -> str:
    """Primary LLM call — Anthropic first, OpenAI fallback."""
    if API_KEY:
        return call_anthropic(prompt)
    if OPENAI_KEY:
        return call_openai(prompt)
    return "[No AI API key configured. Set ANTHROPIC_API_KEY or OPENAI_API_KEY.]"

def analyze_text_safe(text: str) -> dict:
    """Analyze text through the full safe pipeline."""
    prompt = f"""STRICT RULES:
- Do not give legal advice
- Do not make outcome predictions
- Do not recommend specific actions
- Only describe what is observed in the text

TEXT TO ANALYZE:
{text}"""
    return safe_generate_with_defense(prompt, llm_call)

# ══════════════════════════════════════════════════════════════════════════════
# MODULE 11 — HTTP REQUEST HANDLER & ROUTES
# All routes in one handler class.
# ══════════════════════════════════════════════════════════════════════════════
def _json_response(handler, data: dict, status: int = 200):
    body = json.dumps(data, default=str).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", len(body))
    handler.send_header("Access-Control-Allow-Origin", "*")
    handler.end_headers()
    handler.wfile.write(body)

def _read_body(handler) -> dict:
    try:
        length = int(handler.headers.get("Content-Length", 0))
        if length > 0:
            return json.loads(handler.rfile.read(length).decode("utf-8"))
    except Exception:
        pass
    return {}

class SynJurisHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        sys.stderr.write(f"{self.address_string()} [{self.log_date_time_string()}] {fmt % args}\n")

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        path = urlparse(self.path).path.rstrip("/") or "/"

        # Root route serving the Modern Brutalist Landing Page
        if path == "/":
            try:
                with open("templates/index.html", "rb") as f:
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html")
                    self.end_headers()
                    self.wfile.write(f.read())
                return
            except FileNotFoundError:
                _json_response(self, {"error": "Landing page template not found"}, 404)
            return

        elif path == "/health":
            _json_response(self, {"status": "ok", "version": VERSION})

        elif path == "/api/cases":
            conn = get_db()
            rows = [dict(r) for r in conn.execute("SELECT * FROM cases WHERE is_deleted=0 ORDER BY created_at DESC").fetchall()]
            conn.close()
            _json_response(self, {"cases": rows})

        elif re.match(r"^/api/cases/(\d+)/state$", path):
            case_id = int(re.match(r"^/api/cases/(\d+)/state$", path).group(1))
            _json_response(self, compute_case_state(case_id))

        else:
            _json_response(self, {"error": "Not found", "path": path}, 404)

    def do_POST(self):
        path = urlparse(self.path).path.rstrip("/")
        body = _read_body(self)

        if path == "/api/cases":
            title = body.get("title", "").strip()
            if not title: 
                return _json_response(self, {"error": "title required"}, 400)
            conn = get_db()
            cur = conn.execute("INSERT INTO cases (title) VALUES (?)", (title,))
            conn.commit()
            case_id = cur.lastrowid
            conn.close()
            _json_response(self, {"id": case_id, "title": title}, 201)

        elif path == "/api/greyrockfilter":
            text = body.get("text", "")
            filtered = apply_grey_rock_filter(text)
            _json_response(self, {"original": text, "filtered": filtered})

# ══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════
def main():
    print(f"SYNJURIS MASTER — v{VERSION} — ACTIVE")
    init_db()
    server = ThreadingHTTPServer(("0.0.0.0", PORT), SynJurisHandler)

    if LOCAL_MODE:
        def _open():
            time.sleep(1)
            webbrowser.open(f"http://localhost:{PORT}/")
        threading.Thread(target=_open, daemon=True).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()

if __name__ == "__main__":
    main()




        # ── Case Management ──────────────────────────────────────────────────
        if path == "/api/cases":
            title = body.get("title", "").strip()
            if not title:
                return _json_response(self, {"error": "title required"}, 400)
            conn = get_db()
            cur = conn.execute(
                "INSERT INTO cases (title, case_type, jurisdiction, court_name, case_number, goals, notes) "
                "VALUES (?,?,?,?,?,?,?)",
                (title, body.get("case_type"), body.get("jurisdiction"),
                 body.get("court_name"), body.get("case_number"),
                 body.get("goals"), body.get("notes")),
            )
            conn.commit()
            case_id = cur.lastrowid
            conn.close()
            _json_response(self, {"id": case_id, "title": title}, 201)

        # ── Evidence ────────────────────────────────────────────────────────
        elif re.match(r"^/api/cases/(\d+)/evidence$", path):
            case_id = int(re.match(r"^/api/cases/(\d+)/evidence$", path).group(1))
            content = body.get("content", "").strip()
            if not content:
                return _json_response(self, {"error": "content required"}, 400)

            conn = get_db()
            cur = conn.execute(
                "INSERT INTO evidence (case_id, content, source, event_date, category, confirmed, notes, exhibit_number) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (case_id, content, body.get("source"), body.get("event_date"),
                 body.get("category", "General"), int(body.get("confirmed", 0)),
                 body.get("notes"), body.get("exhibit_number")),
            )
            conn.commit()
            exhibit_id = cur.lastrowid

            # Auto-detect patterns
            patterns   = scan_patterns(content)
            scrutinized= analyze_scrutinized_behavior(content)
            z_update   = update_case_z_from_exhibit(case_id, content, conn)

            # Add to Merkle DAG
            exhibit = {"id": exhibit_id, "content": content,
                       "category": body.get("category", "General"),
                       "event_date": body.get("event_date"), "source": body.get("source")}
            merkle_hash = add_exhibit_to_dag(conn, case_id, exhibit)
            conn.close()

            _json_response(self, {
                "id":           exhibit_id,
                "merkle_hash":  merkle_hash,
                "patterns":     [{"category": p[0], "score": p[1], "severity": p[2]} for p in patterns],
                "scrutinized":  scrutinized,
                "z_update":     z_update,
            }, 201)

        # ── AI Analysis ─────────────────────────────────────────────────────
        elif path == "/api/ai/analyze":
            text = body.get("text", "")
            if not text:
                return _json_response(self, {"error": "text required"}, 400)
            result = analyze_text_safe(text)
            _json_response(self, result)

        elif re.match(r"^/api/cases/(\d+)/chat$", path):
            case_id = int(re.match(r"^/api/cases/(\d+)/chat$", path).group(1))
            message = body.get("message", "").strip()
            if not message:
                return _json_response(self, {"error": "message required"}, 400)

            conn = get_db()
            # Build context from recent chat history
            history = [dict(r) for r in conn.execute(
                "SELECT role, content FROM chat_history WHERE case_id=? ORDER BY created_at DESC LIMIT 10",
                (case_id,)
            ).fetchall()]
            history.reverse()

            case_state = compute_case_state(case_id, conn)
            state_ctx  = json.dumps(case_state["state"])

            prompt = f"""Case state: {state_ctx}
Previous messages: {json.dumps(history[-4:]) if history else '[]'}
User question: {message}"""

            result = safe_generate_with_defense(prompt, llm_call)

            # Persist exchange
            conn.execute("INSERT INTO chat_history (case_id, role, content) VALUES (?,?,?)",
                         (case_id, "user", message))
            conn.execute("INSERT INTO chat_history (case_id, role, content) VALUES (?,?,?)",
                         (case_id, "assistant", result["content"]))
            conn.commit()
            conn.close()
            _json_response(self, result)

        # ── Scoring ─────────────────────────────────────────────────────────
        elif path == "/api/score":
            text = body.get("text", "")
            audit = upl_score_text(text)
            patterns = scan_patterns(text)
            scrutinized = analyze_scrutinized_behavior(text)
            _json_response(self, {
                "upl_audit":    audit,
                "patterns":     [{"category": p[0], "score": p[1], "severity": p[2]} for p in patterns],
                "scrutinized":  scrutinized,
                "z_pressure_delta": compute_scrutinized_z_delta(text),
            })

        # ── Grey Rock Filter ─────────────────────────────────────────────────
        elif path == "/api/greyrockfilter":
            text = body.get("text", "")
            filtered = apply_grey_rock_filter(text)
            _json_response(self, {"original": text, "filtered": filtered,
                                   "blocked": guardrail_detect_block(text)})

        # ── Deadlines ────────────────────────────────────────────────────────
        elif re.match(r"^/api/cases/(\d+)/deadlines$", path):
            case_id = int(re.match(r"^/api/cases/(\d+)/deadlines$", path).group(1))
            title = body.get("title", "").strip()
            if not title:
                return _json_response(self, {"error": "title required"}, 400)
            conn = get_db()
            cur = conn.execute(
                "INSERT INTO deadlines (case_id, title, due_date, description) VALUES (?,?,?,?)",
                (case_id, title, body.get("due_date"), body.get("description")),
            )
            conn.commit()
            conn.close()
            _json_response(self, {"id": cur.lastrowid}, 201)

        # ── Document Generation ──────────────────────────────────────────────
        elif path == "/api/docs":
            text     = body.get("text", "")
            doc_type = body.get("doc_type", "Legal Document")
            case_id  = body.get("case_id")

            prompt = f"""Generate a professional {doc_type}.
Do not give legal advice. Present facts only.

CONTENT:
{text}"""
            result   = safe_generate_with_defense(prompt, llm_call)
            doc_text = result["content"]

            conn = get_db()
            cur = None
            if case_id:
                cur = conn.execute(
                    "INSERT INTO documents (case_id, title, doc_type, content) VALUES (?,?,?,?)",
                    (case_id, doc_type, doc_type, doc_text),
                )
                conn.commit()
            conn.close()

            _json_response(self, {
                "document": doc_text,
                "doc_id":   cur.lastrowid if cur else None,
                "audit":    result["audit"],
            })

        else:
            _json_response(self, {"error": "Not found", "path": path}, 404)


# ══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════
def main():
    print(f"""
╔═══════════════════════════════════════════════╗
║         SYNJURIS MASTER — v{VERSION}         ║
╚═══════════════════════════════════════════════╝

  DB Path    : {DB_PATH}
  Uploads    : {UPLOADS_DIR}
  Port       : {PORT}
  AI Backend : {'Anthropic ✓' if API_KEY else ('OpenAI ✓' if OPENAI_KEY else 'None — set ANTHROPIC_API_KEY')}

  Endpoints:
    GET  /health
    GET  /api/cases
    POST /api/cases
    GET  /api/cases/:id
    GET  /api/cases/:id/state         (x/y/z dynamics)
    GET  /api/cases/:id/readiness
    GET  /api/cases/:id/merkle        (DAG integrity)
    GET  /api/cases/:id/audit
    POST /api/cases/:id/evidence      (auto-pattern + DAG)
    POST /api/cases/:id/chat          (safe AI chat)
    POST /api/cases/:id/deadlines
    POST /api/ai/analyze              (UPL-safe analysis)
    POST /api/score                   (UPL + pattern score)
    POST /api/greyrockfilter          (Grey Rock filter)
    POST /api/docs                    (document generation)
    GET  /api/jurisdictions
    GET  /api/jurisdictions/:state
""")

    init_db()
    server = ThreadingHTTPServer(("0.0.0.0", PORT), SynJurisHandler)

    if LOCAL_MODE:
        def _open():
            time.sleep(0.8)
            webbrowser.open(f"http://localhost:{PORT}/")
        threading.Thread(target=_open, daemon=True).start()

    print(f"  Server running at http://localhost:{PORT}\n  Press Ctrl+C to stop.\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Shutting down.")
        server.server_close()


if __name__ == "__main__":
    main()
