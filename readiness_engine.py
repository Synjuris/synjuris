"""
readiness_engine.py — SynJuris v2 Predictive Document Readiness Scoring
=========================================================================
Deterministic scoring for document types based on current evidence state.
Powers UI reordering and speculative pre-generation.
"""

from datetime import date, datetime
from typing import Optional


# ── Requirement Helpers ──────────────────────────────────────────────────────

def _has_category(evidence: list, *categories) -> bool:
    """Check if confirmed evidence contains specific categories."""
    cats = {e.get("category", "") for e in evidence if e.get("confirmed")}
    return any(c in cats for c in categories)

def _confirmed_count(evidence: list) -> int:
    """Return count of confirmed evidence items."""
    return sum(1 for e in evidence if e.get("confirmed"))

def _has_court_order(case: dict) -> bool:
    """Check for case number or court name."""
    return bool(case.get("case_number") or case.get("court_name"))

def _has_hearing(case: dict) -> bool:
    """Check if hearing date is set."""
    return bool(case.get("hearing_date"))

def _days_to_hearing(case: dict) -> Optional[int]:
    """Calculate days remaining until the hearing."""
    hd = case.get("hearing_date")
    if not hd:
        return None
    try:
        h = datetime.strptime(hd, "%Y-%m-%d").date()
        return (h - date.today()).days
    except Exception:
        return None

def _has_parties(parties: list) -> bool:
    """Ensure at least two parties are identified."""
    return len(parties) >= 2


# ── Scoring Ruleset ──────────────────────────────────────────────────────────

DOCUMENT_REQUIREMENTS = {
    "Motion for Contempt": [
        {"label": "Existing court order documented", "check": lambda c, ev, dl, p: _has_court_order(c), "weight": 25, "tip": "Enter case number or court name."},
        {"label": "Violation of Order evidence confirmed", "check": lambda c, ev, dl, p: _has_category(ev, "Violation of Order"), "weight": 30, "tip": "Add a 'Violation of Order' exhibit."},
        {"label": "Gatekeeping or violations documented", "check": lambda c, ev, dl, p: _has_category(ev, "Gatekeeping", "Threats", "Harassment"), "weight": 20, "tip": "Document specific incidents."},
        {"label": "At least 3 confirmed exhibits", "check": lambda c, ev, dl, p: _confirmed_count(ev) >= 3, "weight": 15, "tip": "Add more specific evidence items."},
        {"label": "Parties identified", "check": lambda c, ev, dl, p: _has_parties(p), "weight": 10, "tip": "Add both parties in Overview."},
    ],
    "Emergency Motion for Custody": [
        {"label": "Imminent harm or safety evidence", "check": lambda c, ev, dl, p: _has_category(ev, "Neglect / Safety", "Substance Concern", "Threats"), "weight": 35, "tip": "Document specific safety concerns."},
        {"label": "Relocation or interference documented", "check": lambda c, ev, dl, p: _has_category(ev, "Relocation", "Gatekeeping"), "weight": 25, "tip": "Add evidence of relocation/interference."},
        {"label": "At least 2 confirmed exhibits", "check": lambda c, ev, dl, p: _confirmed_count(ev) >= 2, "weight": 20, "tip": "Confirm your evidence items."},
        {"label": "Jurisdiction set", "check": lambda c, ev, dl, p: bool(c.get("jurisdiction")), "weight": 10, "tip": "Set your state for statutes."},
        {"label": "Parties identified", "check": lambda c, ev, dl, p: _has_parties(p), "weight": 10, "tip": "Add both parties."},
    ],
    "Hearing Prep Guide": [
        {"label": "Hearing date set", "check": lambda c, ev, dl, p: _has_hearing(c), "weight": 20, "tip": "Set your hearing date."},
        {"label": "At least 5 confirmed exhibits", "check": lambda c, ev, dl, p: _confirmed_count(ev) >= 5, "weight": 30, "tip": "Add more confirmed evidence."},
        {"label": "Case goals stated", "check": lambda c, ev, dl, p: bool(c.get("goals")), "weight": 20, "tip": "State your desired outcome."},
        {"label": "Jurisdiction set", "check": lambda c, ev, dl, p: bool(c.get("jurisdiction")), "weight": 15, "tip": "Set your state."},
        {"label": "Parties identified", "check": lambda c, ev, dl, p: _has_parties(p), "weight": 15, "tip": "Add parties correctly."},
    ],
}

DEFAULT_REQUIREMENTS = [
    {"label": "At least 1 confirmed exhibit", "check": lambda c, ev, dl, p: _confirmed_count(ev) >= 1, "weight": 40, "tip": "Confirm one evidence item."},
    {"label": "Parties identified", "check": lambda c, ev, dl, p: bool(p), "weight": 30, "tip": "Add parties in Overview."},
    {"label": "Jurisdiction set", "check": lambda c, ev, dl, p: bool(c.get("jurisdiction")), "weight": 30, "tip": "Set your state."},
]

SPECULATIVE_DOC_TYPES = {"Hearing Prep Guide", "Motion for Contempt", "Declaration"}


# ── Scoring Engine ────────────────────────────────────────────────────────────

def score_document(doc_type: str, case: dict, evidence: list, deadlines: list, parties: list) -> dict:
    """Compute readiness score for a document."""
    requirements = DOCUMENT_REQUIREMENTS.get(doc_type, DEFAULT_REQUIREMENTS)
    met, unmet = [], []
    total_weight = sum(r["weight"] for r in requirements)
    earned_weight = 0

    for req in requirements:
        try:
            passed = req["check"](case, evidence, deadlines, parties)
        except Exception:
            passed = False

        entry = {"label": req["label"], "weight": req["weight"], "met": passed, "tip": req.get("tip", "")}
        if passed:
            earned_weight += req["weight"]
            met.append(entry)
        else:
            unmet.append(entry)

    score = int((earned_weight / max(total_weight, 1)) * 100)
    dth = _days_to_hearing(case)
    time_sensitive = dth is not None and 0 <= dth <= 14

    return {
        "doc_type": doc_type,
        "score": score,
        "label": "Ready" if score >= 90 else "Nearly ready" if score >= 70 else "Partially ready" if score >= 50 else "Not ready",
        "met": met,
        "unmet": unmet,
        "top_tip": unmet[0]["tip"] if unmet else None,
        "time_sensitive": time_sensitive,
        "speculative": doc_type in SPECULATIVE_DOC_TYPES and score >= 90
    }

def compute_readiness_scores(case_id: int, conn) -> dict:
    """Compute scores for all document types."""
    case = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
    if not case: return {}
    c = dict(case)

    ev_rows = conn.execute("SELECT id, category, confirmed, content, event_date, source FROM evidence WHERE case_id=? AND (is_deleted IS NULL OR is_deleted=0)", (case_id,)).fetchall()
    evidence = [dict(r) for r in ev_rows]

    p_rows = conn.execute("SELECT name, role FROM parties WHERE case_id=?", (case_id,)).fetchall()
    parties = [dict(r) for r in p_rows]

    # Deadlines would be fetched here similarly
    deadlines = [] 

    all_doc_types = list(DOCUMENT_REQUIREMENTS.keys()) + ["Exhibit List", "Declaration", "Parenting Plan"]
    return {dt: score_document(dt, c, evidence, deadlines, parties) for dt in all_doc_types}
