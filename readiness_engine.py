"""
readiness_engine.py — SynJuris v2 Predictive Document Readiness Scoring
=========================================================================
Deterministic (no AI) readiness scores for each document type.
Computed from the current evidence state, deadlines, and case metadata.

Score: 0–100
  90+: Ready — generate (and speculatively pre-generate)
  70–89: Nearly ready — show what's missing
  50–69: Partially ready — significant gaps
  <50: Not ready — tell user what to add

Also powers:
  - UI document grid reordering (most-ready first)
  - Speculative pre-generation triggers (score >= 90 + speculative=True)
  - Evidence gap surfacing ("Add X to increase your Motion for Contempt readiness from 67% to 85%")
"""

from datetime import date, datetime
from typing import Optional


# ── Requirement definitions ────────────────────────────────────────────────────

# Each document type has a list of requirements.
# Each requirement: {label, check_fn(case, evidence, deadlines, parties) → bool, weight, tip}
# Weight: how much this requirement contributes to the score (weights sum to 100)

def _has_category(evidence: list, *categories) -> bool:
    cats = {e.get("category", "") for e in evidence if e.get("confirmed")}
    return any(c in cats for c in categories)

def _confirmed_count(evidence: list) -> int:
    return sum(1 for e in evidence if e.get("confirmed"))

def _has_court_order(case: dict) -> bool:
    return bool(case.get("case_number") or case.get("court_name"))

def _has_hearing(case: dict) -> bool:
    return bool(case.get("hearing_date"))

def _days_to_hearing(case: dict) -> Optional[int]:
    hd = case.get("hearing_date")
    if not hd:
        return None
    try:
        h = datetime.strptime(hd, "%Y-%m-%d").date()
        return (h - date.today()).days
    except Exception:
        return None

def _has_parties(parties: list) -> bool:
    return len(parties) >= 2

def _overdue_deadlines(deadlines: list) -> int:
    today = date.today().isoformat()
    return sum(1 for d in deadlines if not d.get("completed") and (d.get("due_date") or "") < today)


DOCUMENT_REQUIREMENTS = {

    "Motion for Contempt": [
        {"label": "Existing court order documented",
         "check": lambda c, ev, dl, p: _has_court_order(c),
         "weight": 25,
         "tip":    "Enter the case number or court name to establish an existing order."},
        {"label": "Violation of Order evidence confirmed",
         "check": lambda c, ev, dl, p: _has_category(ev, "Violation of Order"),
         "weight": 30,
         "tip":    "Add and confirm at least one 'Violation of Order' evidence item."},
        {"label": "Gatekeeping or other violations documented",
         "check": lambda c, ev, dl, p: _has_category(ev, "Gatekeeping", "Threats", "Harassment"),
         "weight": 20,
         "tip":    "Document specific incidents where the order was violated."},
        {"label": "At least 3 confirmed exhibits",
         "check": lambda c, ev, dl, p: _confirmed_count(ev) >= 3,
         "weight": 15,
         "tip":    "Courts expect specific documented instances. Add more confirmed exhibits."},
        {"label": "Parties identified",
         "check": lambda c, ev, dl, p: _has_parties(p),
         "weight": 10,
         "tip":    "Add both parties (you and the other parent) in the Overview tab."},
    ],

    "Emergency Motion for Custody": [
        {"label": "Imminent harm or safety evidence",
         "check": lambda c, ev, dl, p: _has_category(ev, "Neglect / Safety", "Substance Concern", "Threats"),
         "weight": 35,
         "tip":    "Document specific safety concerns — courts require showing imminent harm."},
        {"label": "Relocation or interference documented",
         "check": lambda c, ev, dl, p: _has_category(ev, "Relocation", "Gatekeeping"),
         "weight": 25,
         "tip":    "Add evidence of sudden interference with custody or unauthorized relocation."},
        {"label": "At least 2 confirmed exhibits",
         "check": lambda c, ev, dl, p: _confirmed_count(ev) >= 2,
         "weight": 20,
         "tip":    "Confirm your evidence items — unconfirmed items don't count."},
        {"label": "Jurisdiction set",
         "check": lambda c, ev, dl, p: bool(c.get("jurisdiction")),
         "weight": 10,
         "tip":    "Set your state in the Edit Case dialog for jurisdiction-specific statutes."},
        {"label": "Parties identified",
         "check": lambda c, ev, dl, p: _has_parties(p),
         "weight": 10,
         "tip":    "Add both parties in the Overview tab."},
    ],

    "Motion to Modify Custody": [
        {"label": "Substantial change documented",
         "check": lambda c, ev, dl, p: _confirmed_count(ev) >= 5,
         "weight": 25,
         "tip":    "Courts require showing a 'substantial change in circumstances'. Add more evidence."},
        {"label": "Pattern of behavior documented",
         "check": lambda c, ev, dl, p: _has_category(ev, "Gatekeeping", "Parental Alienation",
                                                       "Violation of Order"),
         "weight": 30,
         "tip":    "Document repeated incidents showing a pattern, not just isolated events."},
        {"label": "Case number or existing order",
         "check": lambda c, ev, dl, p: _has_court_order(c),
         "weight": 20,
         "tip":    "Enter the existing case number — modification requires a prior order."},
        {"label": "Goals stated",
         "check": lambda c, ev, dl, p: bool(c.get("goals")),
         "weight": 15,
         "tip":    "State your custody goals in the Edit Case dialog."},
        {"label": "Parties identified",
         "check": lambda c, ev, dl, p: _has_parties(p),
         "weight": 10,
         "tip":    "Add both parties in the Overview tab."},
    ],

    "Hearing Prep Guide": [
        {"label": "Hearing date set",
         "check": lambda c, ev, dl, p: _has_hearing(c),
         "weight": 20,
         "tip":    "Set your hearing date in the Edit Case dialog."},
        {"label": "At least 5 confirmed exhibits",
         "check": lambda c, ev, dl, p: _confirmed_count(ev) >= 5,
         "weight": 30,
         "tip":    "Add more confirmed evidence — the guide is stronger with more specifics."},
        {"label": "Case goals stated",
         "check": lambda c, ev, dl, p: bool(c.get("goals")),
         "weight": 20,
         "tip":    "State your goals in Edit Case — what outcome are you seeking?"},
        {"label": "Jurisdiction set",
         "check": lambda c, ev, dl, p: bool(c.get("jurisdiction")),
         "weight": 15,
         "tip":    "Set your state for jurisdiction-specific courtroom guidance."},
        {"label": "Parties identified",
         "check": lambda c, ev, dl, p: _has_parties(p),
         "weight": 15,
         "tip":    "Add parties so the guide can reference them correctly."},
    ],

    "Declaration": [
        {"label": "At least 3 confirmed exhibits",
         "check": lambda c, ev, dl, p: _confirmed_count(ev) >= 3,
         "weight": 35,
         "tip":    "A declaration narrates your evidence — add and confirm key incidents."},
        {"label": "Case goals stated",
         "check": lambda c, ev, dl, p: bool(c.get("goals")),
         "weight": 25,
         "tip":    "State what you are asking the court to do in Edit Case."},
        {"label": "Parties identified",
         "check": lambda c, ev, dl, p: _has_parties(p),
         "weight": 20,
         "tip":    "The declaration identifies both parties — add them in Overview."},
        {"label": "Jurisdiction set",
         "check": lambda c, ev, dl, p: bool(c.get("jurisdiction")),
         "weight": 20,
         "tip":    "Set your state for proper sworn statement language."},
    ],

    "Demand Letter": [
        {"label": "At least 1 confirmed exhibit",
         "check": lambda c, ev, dl, p: _confirmed_count(ev) >= 1,
         "weight": 30,
         "tip":    "Add at least one confirmed evidence item to reference in the letter."},
        {"label": "Other party identified",
         "check": lambda c, ev, dl, p: bool(p),
         "weight": 35,
         "tip":    "Add the other party in the Overview tab — the letter is addressed to them."},
        {"label": "Case goals stated",
         "check": lambda c, ev, dl, p: bool(c.get("goals")),
         "weight": 35,
         "tip":    "State what you are demanding in the Edit Case goals field."},
    ],

    "Parenting Plan": [
        {"label": "Both parties identified",
         "check": lambda c, ev, dl, p: _has_parties(p),
         "weight": 30,
         "tip":    "Add both parents as parties in the Overview tab."},
        {"label": "Case goals stated (custody preferences)",
         "check": lambda c, ev, dl, p: bool(c.get("goals")),
         "weight": 35,
         "tip":    "Describe your preferred custody schedule in the goals field."},
        {"label": "Jurisdiction set",
         "check": lambda c, ev, dl, p: bool(c.get("jurisdiction")),
         "weight": 35,
         "tip":    "Parenting plans must comply with your state's specific requirements."},
    ],

    "Response / Answer": [
        {"label": "Case number (petition to respond to)",
         "check": lambda c, ev, dl, p: bool(c.get("case_number")),
         "weight": 30,
         "tip":    "Enter the case number from the petition you received."},
        {"label": "At least 1 confirmed exhibit",
         "check": lambda c, ev, dl, p: _confirmed_count(ev) >= 1,
         "weight": 25,
         "tip":    "Add evidence that supports your response position."},
        {"label": "Both parties identified",
         "check": lambda c, ev, dl, p: _has_parties(p),
         "weight": 25,
         "tip":    "Add both parties — the response caption requires both names."},
        {"label": "Goals stated (what you're asking for)",
         "check": lambda c, ev, dl, p: bool(c.get("goals")),
         "weight": 20,
         "tip":    "State your position in the Edit Case goals field."},
    ],

    "Protective Order Request": [
        {"label": "Threat or harassment evidence",
         "check": lambda c, ev, dl, p: _has_category(ev, "Threats", "Harassment"),
         "weight": 40,
         "tip":    "Add confirmed evidence of specific threats or harassment incidents."},
        {"label": "Domestic violence or safety evidence",
         "check": lambda c, ev, dl, p: _has_category(ev, "Neglect / Safety", "Emotional Abuse"),
         "weight": 25,
         "tip":    "Document specific incidents showing a pattern of threatening behavior."},
        {"label": "Other party identified",
         "check": lambda c, ev, dl, p: bool(p),
         "weight": 20,
         "tip":    "Add the respondent (person you need protection from) in Overview."},
        {"label": "Jurisdiction set",
         "check": lambda c, ev, dl, p: bool(c.get("jurisdiction")),
         "weight": 15,
         "tip":    "Set your state — protective order procedures vary significantly by state."},
    ],

    "Motion for Continuance": [
        {"label": "Hearing date set",
         "check": lambda c, ev, dl, p: _has_hearing(c),
         "weight": 40,
         "tip":    "Set the hearing date you need to postpone in Edit Case."},
        {"label": "Case number",
         "check": lambda c, ev, dl, p: bool(c.get("case_number")),
         "weight": 35,
         "tip":    "Enter the case number to reference in the motion."},
        {"label": "Parties identified",
         "check": lambda c, ev, dl, p: bool(p),
         "weight": 25,
         "tip":    "Add the parties in Overview."},
    ],
}

# Default requirements for document types not explicitly listed
DEFAULT_REQUIREMENTS = [
    {"label": "At least 1 confirmed exhibit",
     "check": lambda c, ev, dl, p: _confirmed_count(ev) >= 1,
     "weight": 40,
     "tip":    "Add and confirm at least one evidence item."},
    {"label": "Parties identified",
     "check": lambda c, ev, dl, p: bool(p),
     "weight": 30,
     "tip":    "Add parties in the Overview tab."},
    {"label": "Jurisdiction set",
     "check": lambda c, ev, dl, p: bool(c.get("jurisdiction")),
     "weight": 30,
     "tip":    "Set your state in Edit Case."},
]

# Documents that should be speculatively pre-generated when score >= 90
SPECULATIVE_DOC_TYPES = {
    "Hearing Prep Guide",
    "Motion for Contempt",
    "Declaration",
}


# ── Scoring function ───────────────────────────────────────────────────────────

def score_document(doc_type: str, case: dict, evidence: list,
                   deadlines: list, parties: list) -> dict:
    """
    Compute readiness score for a single document type.
    Returns dict with score, label, met/unmet requirements, and tips.
    """
    requirements = DOCUMENT_REQUIREMENTS.get(doc_type, DEFAULT_REQUIREMENTS)

    met   = []
    unmet = []
    total_weight = sum(r["weight"] for r in requirements)
    earned_weight = 0

    for req in requirements:
        try:
            passed = req["check"](case, evidence, deadlines, parties)
        except Exception:
            passed = False

        entry = {
            "label":  req["label"],
            "weight": req["weight"],
            "met":    passed,
            "tip":    req.get("tip", ""),
        }

        if passed:
            earned_weight += req["weight"]
            met.append(entry)
        else:
            unmet.append(entry)

    score = int((earned_weight / max(total_weight, 1)) * 100)

    # Urgency boost: hearing within 14 days bumps score display for time-sensitive docs
    dth = _days_to_hearing(case)
    time_sensitive = dth is not None and 0 <= dth <= 14

    if score >= 90:
        label = "Ready"
    elif score >= 70:
        label = "Nearly ready"
    elif score >= 50:
        label = "Partially ready"
    else:
        label = "Not ready"

    # Top tip: the highest-weight unmet requirement
    top_tip = unmet[0]["tip"] if unmet else None

    return {
        "doc_type":       doc_type,
        "score":          score,
        "label":          label,
        "met_count":      len(met),
        "total_count":    len(requirements),
        "met":            met,
        "unmet":          unmet,
        "top_tip":        top_tip,
        "time_sensitive": time_sensitive,
        "speculative":    doc_type in SPECULATIVE_DOC_TYPES and score >= 90,
    }


def compute_readiness_scores(case_id: int, conn) -> dict[str, dict]:
    """
    Compute readiness scores for all known document types.
    Returns dict of {doc_type: score_data}.
    """
    case = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
    if not case:
        return {}

    c       = dict(case)
    ev_rows = conn.execute(
        "SELECT id, category, confirmed, content, event_date, source "
        "FROM evidence WHERE case_id=? AND (is_deleted IS NULL OR is_deleted=0)",
        (case_id,)
    ).fetchall()
    evidence = [dict(r) if hasattr(r, "keys") else
                {"id": r[0], "category": r[2], "confirmed": r[3],
                 "content": r[4], "event_date": r[5], "source": r[6]}  # note: index order
                for r in ev_rows]

    # Re-index: SQLite rows don't always match dict keys
    evidence_fixed = []
    for r in ev_rows:
        if hasattr(r, "keys"):
            evidence_fixed.append(dict(r))
        else:
            evidence_fixed.append({
                "id": r[0], "category": r[2], "confirmed": r[1],
                "content": r[3], "event_date": r[4], "source": r[5]
            })
    # Use the key-based version if available
    evidence = [dict(r) for r in ev_rows] if ev_rows and hasattr(ev_rows[0], "keys") else evidence_fixed

    dl_rows = conn.execute(
        "SELECT due_date, completed FROM deadlines WHERE case_id=?",
        (case_id,)
    ).fetchall()
    deadlines = [dict(r) if hasattr(r, "keys") else
                 {"due_date": r[0], "completed": r[1]} for r in dl_rows]

    p_rows = conn.execute(
        "SELECT name, role FROM parties WHERE case_id=?",
        (case_id,)
    ).fetchall()
    parties = [dict(r) if hasattr(r, "keys") else
               {"name": r[0], "role": r[1]} for r in p_rows]

    all_doc_types = list(DOCUMENT_REQUIREMENTS.keys()) + [
        "Exhibit List", "Small Claims Statement", "Notice of Hearing",
        "Settlement Proposal", "Child Support Worksheet"
    ]

    scores = {}
    for dt in all_doc_types:
        scores[dt] = score_document(dt, c, evidence, deadlines, parties)

    return scores


def get_readiness_summary(case_id: int, conn) -> list[dict]:
    """
    Return document types sorted by readiness (most ready first).
    This is what drives the Documents tab UI reordering.
    """
    scores = compute_readiness_scores(case_id, conn)

    # Sort: time-sensitive first, then by score descending
    items = list(scores.values())
    items.sort(key=lambda x: (
        -(1 if x["time_sensitive"] else 0),
        -x["score"]
    ))

    return items


def readiness_delta(doc_type: str, current_score: int,
                    if_added_category: str, case: dict,
                    evidence: list, deadlines: list, parties: list) -> int:
    """
    Simulate: if the user adds an exhibit of a given category, how much does
    the readiness score increase?

    Used for evidence gap messaging: "Adding a Violation of Order exhibit would
    increase your Motion for Contempt readiness from 67% → 85%."
    """
    # Simulate adding one confirmed exhibit of the given category
    simulated_evidence = evidence + [{
        "id": -1,
        "category":  if_added_category,
        "confirmed": 1,
        "content":   "simulated",
        "event_date": "",
        "source":    "simulated",
    }]
    new_score = score_document(doc_type, case, simulated_evidence, deadlines, parties)
    return new_score["score"] - current_score
