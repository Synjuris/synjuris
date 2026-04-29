"""
readiness_engine.py — SynJuris v2 Document Readiness Scoring
"""
def score_document(doc_type, case, evidence, deadlines, parties):
    score = 0
    if len(evidence) > 0: score += 40
    if case.get('jurisdiction'): score += 30
    if len(parties) >= 2: score += 30
    return {"doc_type": doc_type, "score": score, "label": "Ready" if score >= 90 else "In Progress"}

def compute_readiness_scores(case_id, conn):
    case = dict(conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone() or {})
    ev = [dict(r) for r in conn.execute("SELECT * FROM evidence WHERE case_id=?", (case_id,)).fetchall()]
    parties = [dict(r) for r in conn.execute("SELECT * FROM parties WHERE case_id=?", (case_id,)).fetchall()]
    return {"Motion for Contempt": score_document("Motion for Contempt", case, ev, [], parties)}
