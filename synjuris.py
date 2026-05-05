"""
SynJuris Local Release v1.0.1-local
PATCH: FIX 1 - Grey Rock substitutions no longer assert legal facts.
       FIX 2 - llm_upl_audit() now wired into safe_generate() pipeline.

Run: ANTHROPIC_API_KEY=<key> python synjuris.py
"""
import sqlite3, json, os, re, hashlib, hmac, time, sys
import xml.etree.ElementTree as ET
import html as html_lib
import threading, webbrowser, urllib.request, urllib.parse, secrets, io
from datetime import datetime, date
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
from typing import Optional, Callable

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.units import inch
    from reportlab.lib.colors import HexColor
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether
    from reportlab.lib.styles import ParagraphStyle
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False

VERSION     = "1.0.1-local"
PORT        = int(os.environ.get("PORT", 5000))
DB_PATH     = os.environ.get("SYNJURIS_DB", "synjuris.db")
UPLOADS_DIR = os.environ.get("SYNJURIS_UPLOADS", "uploads")
API_KEY     = os.environ.get("ANTHROPIC_API_KEY", "")
OPENAI_KEY  = os.environ.get("OPENAI_API_KEY", "")
LOCAL_MODE  = os.environ.get("SYNJURIS_LOCAL", "1") == "1"
_MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR  = os.path.join(_MODULE_DIR, "static")
MIME_TYPES  = {".html":"text/html; charset=utf-8",".css":"text/css",".js":"application/javascript",
               ".ico":"image/x-icon",".png":"image/png",".svg":"image/svg+xml",".woff2":"font/woff2"}

DISCLAIMER_VERSION = 1
DISCLAIMER_TEXT = (
    "SynJuris is an organizational and document drafting tool. "
    "It is not a law firm and does not provide legal advice.\n\n"
    "By continuing, you acknowledge:\n"
    "1. Nothing in SynJuris constitutes legal advice or creates an attorney-client relationship.\n"
    "2. All AI-generated content is a draft starting point only. Review with a licensed attorney before filing.\n"
    "3. Pattern detection flags are research indicators only - not legal findings or conclusions.\n"
    "4. SynJuris makes no representations about case outcomes."
)
DISCLAIMER_HASH = hashlib.sha256(DISCLAIMER_TEXT.encode()).hexdigest()[:16]
_CSP_POLICY = (
    "default-src 'self'; script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "font-src https://fonts.gstatic.com; img-src 'self' data:; "
    "connect-src 'self' https://api.anthropic.com https://api.openai.com https://www.courtlistener.com; "
    "frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
)

# ── UPL AUDITOR ───────────────────────────────────────────────────────────────
UPL_RISK_PATTERNS = {
    "explicit_advice":    [r"\byou should\b", r"\byou need to\b", r"\bi recommend\b"],
    "implicit_advice":    [r"\bit may be beneficial\b", r"\bit would be better\b", r"\bthe best option\b"],
    "outcome_prediction": [r"\byou will likely\b", r"\bthis will result in\b", r"\byou are likely to win\b"],
    "strategy_framing":   [r"\byour argument\b", r"\byour best argument\b", r"\byou could argue\b"],
}
UPL_CATEGORY_WEIGHTS = {"explicit_advice":0.4,"implicit_advice":0.3,"outcome_prediction":0.4,"strategy_framing":0.2}

def upl_score_text(text):
    score, flags = 0.0, []
    for cat, patterns in UPL_RISK_PATTERNS.items():
        for p in patterns:
            if re.search(p, text, re.IGNORECASE):
                flags.append(cat); score += UPL_CATEGORY_WEIGHTS.get(cat, 0.2)
    return {"upl_risk_score": min(score, 1.0), "flags": list(set(flags))}

def llm_upl_audit(text, llm_call):
    """FIX 2: LLM-based UPL audit - now called in safe_generate()."""
    prompt = f"""You are a compliance auditor for legal AI outputs.
Analyze for: legal advice, recommendations, outcome predictions, strategy framing.
Respond ONLY in JSON with no preamble: {{"upl_risk_score": 0.0, "flags": []}}
TEXT: {text}"""
    try:
        clean = llm_call(prompt).strip().replace("```json","").replace("```","").strip()
        return json.loads(clean)
    except Exception:
        return {"upl_risk_score": 0.5, "flags": ["parse_error"]}

# ── GUARDRAILS — GREY ROCK FILTER ─────────────────────────────────────────────
# FIX 1: Removed substitutions that asserted legal facts:
#   OLD: "I feel like you always" -> "The records indicate a pattern of"  [REMOVED - UPL risk]
#   OLD: "It's not fair that you" -> "Per the standing court order,"      [REMOVED - UPL risk]
# Replaced with neutral documentation language.
BLOCKED_PHRASES = [r"\byou should\b", r"\bi recommend\b", r"\byou need to\b"]

JADE_SUBSTITUTIONS = [
    (r"(?i)I feel like you always",   "I would like to document that"),
    (r"(?i)It's not fair that you",   "I am noting for the record that"),
    (r"(?i)Why are you being so",      "I am requesting clarification on"),
    (r"(?i)\byou should\b",           "one possible approach is"),
    (r"(?i)\bi recommend\b",          "one possible approach is"),
    (r"(?i)\byou need to\b",          "per our current arrangement,"),
]

GREY_ROCK_WARNING = (
    "The Grey Rock filter has rephrased your message to reduce emotional language. "
    "The rephrased version is not a legal statement and does not assert any legal facts. "
    "Review before sending."
)

def guardrail_detect_block(text):
    return any(re.search(p, text, re.IGNORECASE) for p in BLOCKED_PHRASES)

def guardrail_clean(text):
    for pattern, replacement in JADE_SUBSTITUTIONS:
        text = re.sub(pattern, replacement, text)
    return text

def apply_grey_rock_filter(text):
    text = guardrail_clean(text)
    if len(text.split()) > 50:
        text += " (Note: Streamlining communication for court clarity.)"
    return text

# ── SAFE LLM WRAPPER ──────────────────────────────────────────────────────────
# FIX 2: llm_upl_audit() now called in pipeline when API_KEY present.
MAX_LLM_RETRIES = 2

def safe_generate(prompt, llm_call):
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
        if API_KEY:
            llm_audit = llm_upl_audit(cleaned, llm_call)
            if llm_audit.get("upl_risk_score", 0) > 0.5:
                prompt += "\n\nREINFORCE: Remove all advisory language and outcome predictions."
                audit["llm_flags"] = llm_audit.get("flags", [])
                continue
            audit["llm_upl_score"] = llm_audit.get("upl_risk_score")
            audit["llm_flags"]     = llm_audit.get("flags", [])
        return {"content": cleaned, "audit": audit}
    return {"content": "Output blocked for safety. Please rephrase your query.",
            "audit": {"upl_risk_score": 1.0, "flags": ["max_retries_exceeded"]}}

def safe_generate_with_defense(prompt, llm_call):
    result = safe_generate(prompt, llm_call)
    result["content"] = apply_grey_rock_filter(result["content"])
    hc = []
    if re.search(r"\bI feel\b", result["content"], re.I): hc.append("first_person_emotional")
    if re.search(r"\bYou always\b", result["content"], re.I): hc.append("absolute_accusation")
    if hc: result["audit"]["high_conflict_risk"] = True; result["audit"]["hc_flags"] = hc
    return result

# ── PATTERN ENGINE ────────────────────────────────────────────────────────────
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
SCRUTINIZED_PATTERNS = {
    "gatekeeping":      [r"(?i)you (?:cannot|won't|are not allowed to) (?:see|have) the children",
                         r"(?i)I (?:decided|am deciding) not to give you the (?:records|info|schedule)",
                         r"(?i)don't bother showing up for your (?:visit|time)"],
    "disparagement":    [r"(?i)(?:your|the) (?:mother|father) is (?:crazy|lying|a loser|unstable)",
                         r"(?i)tell your (?:mom|dad) that I said",r"(?i)the kids know you're"],
    "litigation_abuse": [r"(?i)I'm not (?:signing|responding to) that",
                         r"(?i)take me back to court",r"(?i)I'll make sure you go broke in legal fees"],
}
SCRUTINIZED_Z_WEIGHTS = {"gatekeeping":0.25,"litigation_abuse":0.15,"disparagement":0.10}
CATEGORY_WEIGHTS = {
    "Gatekeeping":5.0,"Violation of Order":5.0,"Threats":5.0,"Relocation":5.0,
    "Parental Alienation":4.0,"Harassment":4.0,"Financial":4.0,
    "Stonewalling":3.0,"Emotional Abuse":2.0,"Neglect / Safety":2.0,
    "Substance Concern":2.0,"Child Statement":1.0,
}

def scan_patterns(text):
    results = []
    for cat, regexes in STANDARD_PATTERNS.items():
        if any(re.search(r, text, re.I) for r in regexes):
            results.append((cat, 1.0, "high"))
    return sorted(results, key=lambda x: -x[1])

def analyze_scrutinized_behavior(text):
    findings = []
    for cat, patterns in SCRUTINIZED_PATTERNS.items():
        for p in patterns:
            if re.search(p, text): findings.append(cat); break
    return list(set(findings))

def compute_scrutinized_z_delta(text):
    return sum(SCRUTINIZED_Z_WEIGHTS.get(b,0.0) for b in analyze_scrutinized_behavior(text))

# ── MERKLE DAG ────────────────────────────────────────────────────────────────
MERKLE_VERSION = b"\x01"
GENESIS_HASH   = "0" * 64

def _sha256(data): return hashlib.sha256(data).hexdigest()

def compute_node_hash(parent_hash, exhibit_id, exhibit_content, event_date, category, source, confirmed, case_id, timestamp):
    payload = json.dumps({"case_id":case_id,"parent":parent_hash,"exhibit_id":exhibit_id,
                          "content_hash":_sha256(exhibit_content.encode("utf-8")),
                          "category":category or "","ts":timestamp}, sort_keys=True).encode("utf-8")
    return _sha256(MERKLE_VERSION + payload)

def add_exhibit_to_dag(conn, case_id, exhibit):
    tip = conn.execute("SELECT node_hash FROM merkle_nodes WHERE case_id=? ORDER BY id DESC LIMIT 1",(case_id,)).fetchone()
    parent = tip[0] if tip else GENESIS_HASH
    ts = datetime.utcnow().isoformat()
    h  = compute_node_hash(parent,exhibit["id"],exhibit.get("content",""),
                           exhibit.get("event_date"),exhibit.get("category"),
                           exhibit.get("source"),1,case_id,ts)
    conn.execute("INSERT OR IGNORE INTO merkle_nodes (case_id,exhibit_id,parent_hash,node_hash,exhibit_snapshot_json) VALUES (?,?,?,?,?)",
                 (case_id,exhibit["id"],parent,h,json.dumps(exhibit)))
    nc = conn.execute("SELECT COUNT(*) FROM merkle_nodes WHERE case_id=?",(case_id,)).fetchone()[0]
    conn.execute("INSERT OR REPLACE INTO merkle_roots (case_id,root_hash,node_count,updated_at) VALUES (?,?,?,?)",
                 (case_id,h,nc,datetime.utcnow().isoformat()))
    conn.commit(); return h

def get_merkle_root(conn, case_id):
    row = conn.execute("SELECT root_hash FROM merkle_roots WHERE case_id=?",(case_id,)).fetchone()
    return row[0] if row else None

def verify_dag_chain(conn, case_id):
    nodes = conn.execute("SELECT * FROM merkle_nodes WHERE case_id=? ORDER BY id ASC",(case_id,)).fetchall()
    errors = []
    for i, node in enumerate(nodes):
        n = dict(node)
        ep = GENESIS_HASH if i==0 else dict(nodes[i-1])["node_hash"]
        if n["parent_hash"] != ep: errors.append(f"Node {n['id']}: parent_hash mismatch at position {i}")
    return {"valid":len(errors)==0,"node_count":len(nodes),"errors":errors}

# ── READINESS ENGINE ──────────────────────────────────────────────────────────
def score_document(doc_type, case, evidence, deadlines, parties):
    s = 0
    if evidence: s += 40
    if case.get("jurisdiction"): s += 30
    if len(parties) >= 2: s += 30
    return {"doc_type":doc_type,"score":s,"label":"Ready" if s>=90 else "In Progress",
            "missing":[*(["Add evidence"] if not evidence else []),*(["Set jurisdiction"] if not case.get("jurisdiction") else []),*(["Add both parties"] if len(parties)<2 else [])]}

def compute_readiness_scores(case_id, conn):
    case    = dict(conn.execute("SELECT * FROM cases WHERE id=?",(case_id,)).fetchone() or {})
    ev      = [dict(r) for r in conn.execute("SELECT * FROM evidence WHERE case_id=? AND confirmed=1",(case_id,)).fetchall()]
    parties = [dict(r) for r in conn.execute("SELECT * FROM parties WHERE case_id=?",(case_id,)).fetchall()]
    dls     = [dict(r) for r in conn.execute("SELECT * FROM deadlines WHERE case_id=?",(case_id,)).fetchall()]
    return {t: score_document(t,case,ev,dls,parties) for t in
            ["Motion for Contempt","Motion to Modify Custody","Parenting Plan","Domestic Violence Petition"]}

# ── CASE DYNAMICS ENGINE ──────────────────────────────────────────────────────
def _clamp(v): return max(1,min(9,int(v)))
def _s9(raw,ceil): return 1 if raw<=0 else _clamp(1+(raw/ceil)*8)
def _hash_states(states):
    def _n(o):
        if isinstance(o,float): return round(o,8)
        if isinstance(o,dict): return {k:_n(v) for k,v in sorted(o.items())}
        if isinstance(o,list): return [_n(i) for i in o]
        return o
    return hashlib.sha256(json.dumps(_n(states),separators=(",",":"),sort_keys=True).encode()).hexdigest()

def compute_case_state(case_id, conn=None):
    own = conn is None
    if own: conn=get_db()
    ev  = [dict(e) for e in conn.execute("SELECT id,exhibit_number,content,category,event_date,source FROM evidence WHERE case_id=? AND confirmed=1 ORDER BY event_date ASC,id ASC",(case_id,)).fetchall()]
    dls = [dict(d) for d in conn.execute("SELECT id,due_date,title,completed FROM deadlines WHERE case_id=?",(case_id,)).fetchall()]
    if own: conn.close()
    ev_w  = sum(CATEGORY_WEIGHTS.get(e["category"],1.0) for e in ev)
    adv_w = sum(CATEGORY_WEIGHTS.get(e["category"],1.0) for e in ev if CATEGORY_WEIGHTS.get(e["category"],0)>=3.0)
    total_dl=len(dls); done_dl=sum(1 for d in dls if d["completed"])
    over=sum(1 for d in dls if not d["completed"] and d["due_date"] and d["due_date"]<date.today().isoformat())
    if total_dl==0: y_final=5
    else:
        raw_y=(done_dl/total_dl)*9-over*0.5; y_final=_clamp(max(raw_y,0.0)) if raw_y>=1 else 1
    x_final,z_final=_s9(ev_w,50.0),_s9(adv_w,50.0)
    running={"x":1,"y":y_final,"z":1}; chain,hist=[],[dict(running)]
    per_x=(x_final-1)/max(len(ev),1); per_z=(z_final-1)/max(len(ev),1)
    for e in ev:
        w=CATEGORY_WEIGHTS.get(e["category"],1.0); dx=per_x*w; dz=per_z*w if w>=3.0 else 0.0
        ns={"x":_clamp(running["x"]+dx),"y":running["y"],"z":_clamp(running["z"]+dz)}
        chain.append({"exhibit_id":e["id"],"exhibit_number":e["exhibit_number"] or "unnum",
                      "category":e["category"] or "General","weight":w,
                      "event_date":e["event_date"] or "undated","source":e["source"] or "manual",
                      "delta":{"x":round(dx,4),"y":0.0,"z":round(dz,4)},"state_after":dict(ns)})
        hist.append(dict(ns)); running=ns
    return {"state":{"x":x_final,"y":y_final,"z":z_final},
            "inputs":{"evidence_count":len(ev),"ev_weight_sum":round(ev_w,4),"adv_weight_sum":round(adv_w,4),
                      "total_deadlines":total_dl,"done_deadlines":done_dl,"overdue_deadlines":over},
            "deltas":chain,"hash":_hash_states(hist)}

def update_case_z_from_exhibit(case_id, exhibit_text, conn):
    behaviors=analyze_scrutinized_behavior(exhibit_text)
    z_increase=sum(SCRUTINIZED_Z_WEIGHTS.get(b,0.0) for b in behaviors)
    current=compute_case_state(case_id,conn)
    new_z=min((current["state"]["z"]/9.0)+z_increase,1.0)
    return {"new_z_score":round(new_z,4),"flags":behaviors,"z_delta":z_increase}

# ── JURISDICTION TABLE ────────────────────────────────────────────────────────
JURISDICTION_LAW = {
    "Alabama":{"custody":"Ala. Code § 30-3-1","support":"Ala. Code § 30-3-110","dv":"Ala. Code § 30-5-1"},
    "Alaska":{"custody":"Alaska Stat. § 25.20.060","support":"Alaska Stat. § 25.27.020","dv":"Alaska Stat. § 18.66.100"},
    "Arizona":{"custody":"A.R.S. § 25-403","support":"A.R.S. § 25-501","dv":"A.R.S. § 13-3601"},
    "Arkansas":{"custody":"Ark. Code § 9-13-101","support":"Ark. Code § 9-14-201","dv":"Ark. Code § 9-15-201"},
    "California":{"custody":"Cal. Fam. Code § 3020","support":"Cal. Fam. Code § 4050","dv":"Cal. Fam. Code § 6200"},
    "Colorado":{"custody":"C.R.S. § 14-10-124","support":"C.R.S. § 14-14-104","dv":"C.R.S. § 13-14-101"},
    "Connecticut":{"custody":"C.G.S. § 46b-56","support":"C.G.S. § 46b-84","dv":"C.G.S. § 46b-15"},
    "Delaware":{"custody":"13 Del. C. § 722","support":"13 Del. C. § 514","dv":"10 Del. C. § 1041"},
    "Florida":{"custody":"Fla. Stat. § 61.13","support":"Fla. Stat. § 61.29","dv":"Fla. Stat. § 741.28"},
    "Georgia":{"custody":"O.C.G.A. § 19-9-1","support":"O.C.G.A. § 19-6-15","dv":"O.C.G.A. § 19-13-1"},
    "Hawaii":{"custody":"HRS § 571-46","support":"HRS § 576D-1","dv":"HRS § 586-1"},
    "Idaho":{"custody":"Idaho Code § 32-717","support":"Idaho Code § 32-706","dv":"Idaho Code § 39-6301"},
    "Illinois":{"custody":"750 ILCS 5/602.5","support":"750 ILCS 5/505","dv":"750 ILCS 60/101"},
    "Indiana":{"custody":"I.C. § 31-17-2-8","support":"I.C. § 31-16-6-1","dv":"I.C. § 34-26-5-1"},
    "Iowa":{"custody":"Iowa Code § 598.41","support":"Iowa Code § 598.21B","dv":"Iowa Code § 236.2"},
    "Kansas":{"custody":"K.S.A. § 23-3203","support":"K.S.A. § 23-3001","dv":"K.S.A. § 60-3101"},
    "Kentucky":{"custody":"KRS § 403.270","support":"KRS § 403.212","dv":"KRS § 403.715"},
    "Louisiana":{"custody":"La. C.C. Art. 132","support":"La. R.S. § 9:315","dv":"La. R.S. § 46:2131"},
    "Maine":{"custody":"19-A M.R.S. § 1653","support":"19-A M.R.S. § 2006","dv":"19-A M.R.S. § 4001"},
    "Maryland":{"custody":"Md. Code, FL § 9-101","support":"Md. Code, FL § 12-201","dv":"Md. Code, FL § 4-501"},
    "Massachusetts":{"custody":"M.G.L. c.208 § 31","support":"M.G.L. c.208 § 28","dv":"M.G.L. c.209A § 1"},
    "Michigan":{"custody":"MCL § 722.23","support":"MCL § 552.451","dv":"MCL § 600.2950"},
    "Minnesota":{"custody":"Minn. Stat. § 518.17","support":"Minn. Stat. § 518A.26","dv":"Minn. Stat. § 518B.01"},
    "Mississippi":{"custody":"Miss. Code § 93-5-24","support":"Miss. Code § 93-9-1","dv":"Miss. Code § 93-21-1"},
    "Missouri":{"custody":"Mo. Rev. Stat. § 452.375","support":"Mo. Rev. Stat. § 452.340","dv":"Mo. Rev. Stat. § 455.010"},
    "Montana":{"custody":"MCA § 40-4-212","support":"MCA § 40-5-201","dv":"MCA § 40-15-101"},
    "Nebraska":{"custody":"Neb. Rev. Stat. § 43-2923","support":"Neb. Rev. Stat. § 42-364","dv":"Neb. Rev. Stat. § 42-903"},
    "Nevada":{"custody":"NRS § 125C.0035","support":"NRS § 125B.010","dv":"NRS § 33.018"},
    "New Hampshire":{"custody":"RSA § 461-A:6","support":"RSA § 458-C:3","dv":"RSA § 173-B:1"},
    "New Jersey":{"custody":"N.J.S.A. § 9:2-4","support":"N.J.S.A. § 2A:34-23","dv":"N.J.S.A. § 2C:25-17"},
    "New Mexico":{"custody":"NMSA § 40-4-9.1","support":"NMSA § 40-4-11.1","dv":"NMSA § 40-13-1"},
    "New York":{"custody":"N.Y. Dom. Rel. Law § 240","support":"N.Y. Fam. Ct. Act § 413","dv":"N.Y. Fam. Ct. Act § 812"},
    "North Carolina":{"custody":"N.C.G.S. § 50-13.2","support":"N.C.G.S. § 50-13.4","dv":"N.C.G.S. § 50B-1"},
    "North Dakota":{"custody":"N.D.C.C. § 14-09-06.2","support":"N.D.C.C. § 14-09-09.7","dv":"N.D.C.C. § 14-07.1-01"},
    "Ohio":{"custody":"ORC § 3109.04","support":"ORC § 3119.02","dv":"ORC § 3113.31"},
    "Oklahoma":{"custody":"43 O.S. § 112","support":"43 O.S. § 118","dv":"22 O.S. § 60.1"},
    "Oregon":{"custody":"ORS § 107.137","support":"ORS § 107.105","dv":"ORS § 107.700"},
    "Pennsylvania":{"custody":"23 Pa.C.S. § 5328","support":"23 Pa.C.S. § 4322","dv":"23 Pa.C.S. § 6101"},
    "Rhode Island":{"custody":"R.I. Gen. Laws § 15-5-16","support":"R.I. Gen. Laws § 15-5-16.2","dv":"R.I. Gen. Laws § 15-15-1"},
    "South Carolina":{"custody":"S.C. Code § 63-15-230","support":"S.C. Code § 63-17-470","dv":"S.C. Code § 20-4-20"},
    "South Dakota":{"custody":"SDCL § 25-5-7.1","support":"SDCL § 25-7-6.2","dv":"SDCL § 25-10-1"},
    "Tennessee":{"custody":"TN Code § 36-6-101","support":"TN Code § 36-5-101","dv":"TN Code § 36-3-601"},
    "Texas":{"custody":"Tex. Fam. Code § 153.002","support":"Tex. Fam. Code § 154.001","dv":"Tex. Fam. Code § 71.004"},
    "Utah":{"custody":"Utah Code § 30-3-10","support":"Utah Code § 78B-12-202","dv":"Utah Code § 77-36-1"},
    "Vermont":{"custody":"15 V.S.A. § 665","support":"15 V.S.A. § 653","dv":"15 V.S.A. § 1101"},
    "Virginia":{"custody":"Va. Code § 20-124.3","support":"Va. Code § 20-108.2","dv":"Va. Code § 16.1-228"},
    "Washington":{"custody":"RCW § 26.09.187","support":"RCW § 26.19.020","dv":"RCW § 26.50.010"},
    "West Virginia":{"custody":"W. Va. Code § 48-9-206","support":"W. Va. Code § 48-13-301","dv":"W. Va. Code § 48-27-202"},
    "Wisconsin":{"custody":"Wis. Stat. § 767.41","support":"Wis. Stat. § 767.511","dv":"Wis. Stat. § 813.12"},
    "Wyoming":{"custody":"Wyo. Stat. § 20-2-201","support":"Wyo. Stat. § 20-2-304","dv":"Wyo. Stat. § 35-21-102"},
    "Washington D.C.":{"custody":"D.C. Code § 16-914","support":"D.C. Code § 16-916","dv":"D.C. Code § 16-1001"},
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

def resolve_jurisdiction(raw):
    if not raw: return None, {}
    key = raw.strip().lower()
    canonical = JURISDICTION_ALIASES.get(key) or next((k for k in JURISDICTION_LAW if k.lower()==key),None)
    if canonical: return canonical, JURISDICTION_LAW.get(canonical,{})
    return raw, {}

# ── DATABASE ──────────────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    conn = get_db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY, applied_at DATETIME DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, last_login_at DATETIME);
    CREATE TABLE IF NOT EXISTS cases (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, case_type TEXT, jurisdiction TEXT, court_name TEXT, case_number TEXT, filing_deadline TEXT, hearing_date TEXT, goals TEXT, notes TEXT, narrative TEXT, narrative_date TEXT, narrative_source TEXT, user_id INTEGER, is_deleted INTEGER DEFAULT 0, deleted_at DATETIME, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS parties (id INTEGER PRIMARY KEY AUTOINCREMENT, case_id INTEGER REFERENCES cases(id) ON DELETE CASCADE, name TEXT, role TEXT, contact TEXT, attorney TEXT, notes TEXT);
    CREATE TABLE IF NOT EXISTS evidence (id INTEGER PRIMARY KEY AUTOINCREMENT, case_id INTEGER REFERENCES cases(id) ON DELETE CASCADE, exhibit_number TEXT, content TEXT, source TEXT, event_date TEXT, category TEXT, confirmed INTEGER DEFAULT 0, notes TEXT, file_path TEXT, file_type TEXT, original_filename TEXT, is_deleted INTEGER DEFAULT 0, deleted_at DATETIME, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS sms_imports (id INTEGER PRIMARY KEY AUTOINCREMENT, case_id INTEGER REFERENCES cases(id) ON DELETE CASCADE, filename TEXT, raw_count INTEGER DEFAULT 0, imported_count INTEGER DEFAULT 0, source_format TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS sms_messages (id INTEGER PRIMARY KEY AUTOINCREMENT, import_id INTEGER REFERENCES sms_imports(id) ON DELETE CASCADE, case_id INTEGER REFERENCES cases(id) ON DELETE CASCADE, message_ts TEXT, readable_date TEXT, direction TEXT, contact_name TEXT, address TEXT, body TEXT, flags_json TEXT, metadata_json TEXT, created_as_evidence INTEGER DEFAULT 0, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
    CREATE INDEX IF NOT EXISTS idx_sms_case ON sms_messages(case_id, message_ts);
    CREATE TABLE IF NOT EXISTS documents (id INTEGER PRIMARY KEY AUTOINCREMENT, case_id INTEGER REFERENCES cases(id) ON DELETE CASCADE, title TEXT, doc_type TEXT, content TEXT, version INTEGER DEFAULT 1, parent_id INTEGER, is_deleted INTEGER DEFAULT 0, deleted_at DATETIME, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS timeline_events (id INTEGER PRIMARY KEY AUTOINCREMENT, case_id INTEGER REFERENCES cases(id) ON DELETE CASCADE, event_date TEXT, title TEXT, description TEXT, category TEXT, importance TEXT DEFAULT 'normal', created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS deadlines (id INTEGER PRIMARY KEY AUTOINCREMENT, case_id INTEGER REFERENCES cases(id) ON DELETE CASCADE, due_date TEXT, title TEXT, description TEXT, completed INTEGER DEFAULT 0, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS chat_history (id INTEGER PRIMARY KEY AUTOINCREMENT, case_id INTEGER REFERENCES cases(id) ON DELETE CASCADE, role TEXT, content TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, case_id INTEGER REFERENCES cases(id) ON DELETE CASCADE, action_type TEXT NOT NULL, ai_call_type TEXT, state_x INTEGER, state_y INTEGER, state_z INTEGER, trace_hash TEXT NOT NULL, state_snapshot_json TEXT, prompt_inputs_json TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS merkle_nodes (id INTEGER PRIMARY KEY AUTOINCREMENT, case_id INTEGER NOT NULL, exhibit_id INTEGER NOT NULL, parent_hash TEXT NOT NULL, node_hash TEXT NOT NULL UNIQUE, exhibit_snapshot_json TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS merkle_roots (id INTEGER PRIMARY KEY AUTOINCREMENT, case_id INTEGER NOT NULL UNIQUE, root_hash TEXT NOT NULL, node_count INTEGER NOT NULL DEFAULT 0, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS disclaimer_acks (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, version INTEGER NOT NULL, disclaimer_hash TEXT NOT NULL, acked_at DATETIME DEFAULT CURRENT_TIMESTAMP, ip_hint TEXT);
    CREATE INDEX IF NOT EXISTS idx_disclaimer_user ON disclaimer_acks(user_id, version);
    CREATE TABLE IF NOT EXISTS portal_tokens (id INTEGER PRIMARY KEY AUTOINCREMENT, case_id INTEGER NOT NULL UNIQUE, token TEXT NOT NULL UNIQUE, created_by INTEGER, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, last_viewed DATETIME, view_count INTEGER DEFAULT 0, revoked INTEGER DEFAULT 0);
    CREATE INDEX IF NOT EXISTS idx_portal_token ON portal_tokens(token);
    """)
    conn.commit(); conn.close()
    os.makedirs(UPLOADS_DIR, exist_ok=True)

# ── AI SERVICE ────────────────────────────────────────────────────────────────
def call_anthropic(prompt, system="You are a legal document assistant. Never give legal advice."):
    if not API_KEY: return "[No ANTHROPIC_API_KEY configured]"
    payload = json.dumps({"model":"claude-opus-4-6","max_tokens":1024,"system":system,
                          "messages":[{"role":"user","content":prompt}]}).encode("utf-8")
    req = urllib.request.Request("https://api.anthropic.com/v1/messages",data=payload,
                                 headers={"x-api-key":API_KEY,"anthropic-version":"2023-06-01","content-type":"application/json"})
    try:
        with urllib.request.urlopen(req,timeout=30) as r: return json.loads(r.read())["content"][0]["text"]
    except Exception as e: return f"[Anthropic error: {e}]"

def call_openai(prompt):
    if not OPENAI_KEY: return "[No OPENAI_API_KEY configured]"
    payload = json.dumps({"model":"gpt-4o-mini","messages":[
        {"role":"system","content":"You are a legal document assistant. Never give legal advice."},
        {"role":"user","content":prompt}]}).encode("utf-8")
    req = urllib.request.Request("https://api.openai.com/v1/chat/completions",data=payload,
                                 headers={"Authorization":f"Bearer {OPENAI_KEY}","Content-Type":"application/json"})
    try:
        with urllib.request.urlopen(req,timeout=30) as r: return json.loads(r.read())["choices"][0]["message"]["content"]
    except Exception as e: return f"[OpenAI error: {e}]"

def llm_call(prompt):
    if API_KEY: return call_anthropic(prompt)
    if OPENAI_KEY: return call_openai(prompt)
    return "[No AI API key configured. Set ANTHROPIC_API_KEY or OPENAI_API_KEY.]"

def analyze_text_safe(text):
    return safe_generate_with_defense(
        f"STRICT RULES:\n- Do not give legal advice\n- Do not make outcome predictions\n"
        f"- Do not recommend specific actions\n- Only describe what is observed\n\nTEXT:\n{text}", llm_call)

# ── AUTH HELPERS ──────────────────────────────────────────────────────────────
def _hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256",password.encode("utf-8"),salt.encode("utf-8"),200_000)
    return f"pbkdf2_sha256$200000${salt}${dk.hex()}"

def _verify_password(password, stored):
    try:
        alg,rounds,salt,expected = stored.split("$",3)
        if alg!="pbkdf2_sha256": return False
        dk = hashlib.pbkdf2_hmac("sha256",password.encode("utf-8"),salt.encode("utf-8"),int(rounds))
        return hmac.compare_digest(dk.hex(),expected)
    except Exception: return False

def _handle_confirm_exhibit(case_id, ev_id):
    conn = get_db()
    ev_row = conn.execute("SELECT * FROM evidence WHERE id=? AND case_id=? AND (is_deleted IS NULL OR is_deleted=0)",(ev_id,case_id)).fetchone()
    if not ev_row: conn.close(); return {"error":"evidence not found","status":404}
    ev = dict(ev_row)
    existing = conn.execute("SELECT node_hash FROM merkle_nodes WHERE case_id=? AND exhibit_id=? ORDER BY id DESC LIMIT 1",(case_id,ev_id)).fetchone()
    ex_num = ev.get("exhibit_number")
    if not ex_num:
        n = (conn.execute("SELECT COUNT(*) FROM evidence WHERE case_id=? AND confirmed=1 AND id<>?",(case_id,ev_id)).fetchone()[0] or 0)+1
        ex_num = f"Exhibit {n}"
    conn.execute("UPDATE evidence SET confirmed=1,exhibit_number=? WHERE id=? AND case_id=?",(ex_num,ev_id,case_id))
    conn.commit()
    ev_row = conn.execute("SELECT * FROM evidence WHERE id=? AND case_id=?",(ev_id,case_id)).fetchone()
    merkle_hash = existing[0] if existing else add_exhibit_to_dag(conn,case_id,dict(ev_row))
    conn.commit(); conn.close()
    return {"exhibit_number":ex_num,"merkle_hash":merkle_hash,"ok":True}

# ── NARRATIVE ENGINE ──────────────────────────────────────────────────────────
_DATE_RE = re.compile(r"\b(?:\d{1,2}/\d{1,2}/\d{2,4}|\d{4}-\d{2}-\d{2}|(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec)[a-z]*\.?\s+\d{1,2}(?:,\s*\d{4})?)\b",re.IGNORECASE)
_EV_KW = {"text":"Text message","message":"Text message","email":"Email","call":"Call log","voicemail":"Voicemail","screenshot":"Screenshot","photo":"Photo","video":"Video","recording":"Recording","order":"Court order/document","receipt":"Receipt/record","school":"School record","police":"Police/report record"}

def derive_from_narrative(text):
    sentences = [p.strip(" \t\r\n-\u2022") for p in re.split(r"(?<=[.!?])\s+|\n+",text.strip()) if p.strip(" \t\r\n-\u2022")]
    events,leads,questions=[],[],[]
    for idx,s in enumerate(sentences,start=1):
        m=_DATE_RE.search(s); dh=m.group(0) if m else None
        events.append({"id":idx,"date":dh,"title":f"Narrative event {idx}","description":s,"snippet":s,"status":"draft_requires_review"})
        lower=s.lower()
        for key,label in _EV_KW.items():
            if key in lower and label not in [l["type"] for l in leads]: leads.append({"id":len(leads)+1,"type":label,"snippet":s,"status":"lead_requires_review"})
        if not dh: questions.append({"id":len(questions)+1,"question":"What date belongs with this event?","snippet":s[:120]})
    return {"source_type":"case_narrative","source_status":"user_entered_unverified_not_evidence",
            "events":events,"evidence_leads":leads,"statement_draft":"I state the following based on my personal knowledge:\n\n"+text.strip(),
            "questions":questions,"notice":"Draft structures from narrative. Not evidence or legal advice unless separately reviewed and saved."}

# ── SMS ENGINE ────────────────────────────────────────────────────────────────
_SMS_KW = {
    "child_contact":["call me","call him","before bed","goodnight","gn","see him","talk to him","contact"],
    "exchange_or_schedule":["pick","pickup","drop","bring him","home","school","appointment","practice","what time","asap","tomorrow","tonight"],
    "medical_or_safety":["doctor","surgery","hospital","hurt","cut","stitches","medicine","unsafe","alone"],
    "records_or_school":["school","report card","teacher","homework","clinic","records"],
    "possible_denial_language":["don't come","cannot","can't","not allowed","won't let","not seeing","don't bother"],
    "follow_up_language":["did you get","hello","please lmk","lmk asap","call me please","?"],
}
_SMS_DIR = {"1":"received","2":"sent"}

def _sfe(v):
    if v is None: return ""
    return html_lib.unescape(str(v)).replace("\r\n","\n").replace("\r","\n").strip()

def _epoch_iso(v):
    try:
        ms=int(v or "0")
        if ms<=0: return ""
        return datetime.fromtimestamp(ms/1000.0).strftime("%Y-%m-%d %H:%M:%S")
    except: return ""

def _epoch_date(v):
    try:
        ms=int(v or "0")
        if ms<=0: return ""
        return datetime.fromtimestamp(ms/1000.0).strftime("%Y-%m-%d")
    except: return ""

def _sms_flags(body,prev=None,cur=None):
    lower=(body or "").lower(); flags=[]
    for group,words in _SMS_KW.items():
        hits=[w for w in words if w in lower]
        if hits: flags.append({"type":group,"label":group.replace("_"," ").title(),"basis":hits[:5],"notice":"Neutral keyword flag. Not a legal conclusion."})
    if prev and cur and prev==cur and "?" in lower:
        flags.append({"type":"consecutive_follow_up","label":"Consecutive Follow-Up","basis":["same speaker/question"],"notice":"Structural observation only."})
    return flags

def parse_android_sms_backup_xml(xml_text):
    raw=(xml_text or "").strip()
    if not raw: return {"messages":[],"errors":["empty XML"],"raw_count":0}
    try: root=ET.fromstring(raw.encode("utf-8"))
    except Exception as e: return {"messages":[],"errors":[f"XML error: {e}"],"raw_count":0}
    if root.tag!="smses": return {"messages":[],"errors":["Expected <smses> root"],"raw_count":0}
    rc=int(root.attrib.get("count") or 0) if str(root.attrib.get("count") or "").isdigit() else len(root.findall("sms"))
    messages=[]; prev=None
    for idx,node in enumerate(root.findall("sms"),start=1):
        body=_sfe(node.attrib.get("body")); direction=_SMS_DIR.get(node.attrib.get("type"),"unknown")
        mts=_epoch_iso(node.attrib.get("date"))
        item={"index":idx,"message_ts":mts,"event_date":_epoch_date(node.attrib.get("date")),
              "readable_date":node.attrib.get("readable_date") or mts,"direction":direction,
              "contact_name":node.attrib.get("contact_name") or "","address":node.attrib.get("address") or "",
              "body":body,"flags":_sms_flags(body,prev,direction),
              "metadata":{"protocol":node.attrib.get("protocol"),"read":node.attrib.get("read")},
              "review_status":"candidate_requires_user_review"}
        if body: messages.append(item)
        prev=direction
    messages.sort(key=lambda m:(m.get("message_ts") or "",m.get("index") or 0))
    return {"messages":messages,"errors":[],"raw_count":rc}

def parse_pasted_sms_thread(text):
    raw=(text or "").strip()
    if not raw: return {"messages":[],"errors":["empty input"],"raw_count":0}
    messages=[]; prev=None
    for idx,ln in enumerate([x.strip() for x in raw.splitlines() if x.strip()],start=1):
        speaker,msg="SMS",ln
        if ":" in ln:
            left,right=ln.split(":",1)
            if 0<len(left.strip())<=60 and right.strip(): speaker,msg=left.strip(),right.strip()
        direction="sent" if speaker.lower() in ("me","will","you") else "received" if speaker!="SMS" else "unknown"
        messages.append({"index":idx,"message_ts":"","event_date":"","readable_date":"","direction":direction,
                         "contact_name":speaker,"address":"","body":msg,"flags":_sms_flags(msg,prev,direction),
                         "metadata":{"source":"manual paste"},"review_status":"candidate_requires_user_review"})
        prev=direction
    return {"messages":messages,"errors":[],"raw_count":len(messages)}

def summarize_sms_import(messages):
    flagged=[m for m in messages if m.get("flags")]; by_type={}
    for m in flagged:
        for f in m.get("flags",[]): by_type[f["type"]]=by_type.get(f["type"],0)+1
    return {"message_count":len(messages),"flagged_count":len(flagged),"flag_counts":by_type,
            "first_message":messages[0].get("readable_date","") if messages else "",
            "last_message":messages[-1].get("readable_date","") if messages else "",
            "notice":"Flags are structural/keyword signals only. Not legal conclusions."}

def store_sms_import(case_id, filename, source_format, parsed):
    messages=parsed.get("messages") or []; conn=get_db()
    cur=conn.execute("INSERT INTO sms_imports (case_id,filename,raw_count,imported_count,source_format) VALUES (?,?,?,?,?)",
                     (case_id,filename or "SMS import",parsed.get("raw_count") or len(messages),len(messages),source_format))
    import_id=cur.lastrowid
    for m in messages:
        conn.execute("INSERT INTO sms_messages (import_id,case_id,message_ts,readable_date,direction,contact_name,address,body,flags_json,metadata_json) VALUES (?,?,?,?,?,?,?,?,?,?)",
                     (import_id,case_id,m.get("message_ts"),m.get("readable_date"),m.get("direction"),
                      m.get("contact_name"),m.get("address"),m.get("body"),
                      json.dumps(m.get("flags") or []),json.dumps(m.get("metadata") or {})))
    conn.commit(); conn.close()
    return {"import_id":import_id,"messages":messages,"summary":summarize_sms_import(messages)}

# ── STATIC / PORTAL HELPERS ───────────────────────────────────────────────────
def _read_static(fn):
    p=os.path.join(STATIC_DIR,os.path.basename(fn))
    if os.path.isfile(p):
        with open(p,"r",encoding="utf-8") as f: return f.read()
    return f"<html><body style='background:#0a1520;color:#a0b0c0;padding:40px'>Missing: {fn}</body></html>"

def _serve_static_file(handler,fn):
    safe=os.path.basename(fn); fp=os.path.join(STATIC_DIR,safe)
    if not os.path.isfile(fp): return False
    ext=os.path.splitext(safe)[1].lower(); mime=MIME_TYPES.get(ext,"application/octet-stream")
    with open(fp,"rb") as f: data=f.read()
    handler.send_response(200); handler.send_header("Content-Type",mime)
    handler.send_header("Content-Length",str(len(data))); handler.send_header("Cache-Control","no-cache")
    handler.end_headers(); handler.wfile.write(data); return True

def _send_html(handler,html):
    data=html.encode("utf-8"); handler.send_response(200)
    handler.send_header("Content-Type","text/html; charset=utf-8")
    handler.send_header("Content-Length",str(len(data))); handler.end_headers(); handler.wfile.write(data)

def _needs_disclaimer(uid):
    conn=get_db(); row=conn.execute("SELECT id FROM disclaimer_acks WHERE version=? AND disclaimer_hash=? LIMIT 1",(DISCLAIMER_VERSION,DISCLAIMER_HASH)).fetchone(); conn.close(); return row is None

def _record_disclaimer_ack(ip_hint=None):
    conn=get_db(); conn.execute("INSERT INTO disclaimer_acks (user_id,version,disclaimer_hash,ip_hint) VALUES (?,?,?,?)",(1,DISCLAIMER_VERSION,DISCLAIMER_HASH,ip_hint)); conn.commit(); conn.close()

def _get_disclaimer_modal():
    return (f'''<div id="sj-disclaimer-overlay" style="position:fixed;inset:0;background:rgba(10,21,32,0.93);display:flex;align-items:center;justify-content:center;z-index:9999;font-family:sans-serif">'''
            f'''<div style="background:#111d2b;border:1px solid rgba(201,168,76,0.35);border-radius:12px;padding:36px 40px;max-width:520px;width:90%">'''
            f'''<div style="font-size:22px;color:#e8dfc8;margin-bottom:16px">Before you continue</div>'''
            f'''<div style="background:#0a1520;border:1px solid rgba(255,255,255,0.07);border-radius:8px;padding:16px;margin-bottom:18px;max-height:200px;overflow-y:auto;font-size:12px;color:#a0b0c0;white-space:pre-wrap">{DISCLAIMER_TEXT}</div>'''
            f'''<label style="display:flex;align-items:flex-start;gap:10px;cursor:pointer;margin-bottom:18px">'''
            f'''<input type="checkbox" id="sj-disc-check" onchange="document.getElementById('sj-disc-btn').style.opacity=this.checked?'1':'0.4'" style="accent-color:#c9a84c">'''
            f'''<span style="font-size:12.5px;color:#a0b0c0">I understand SynJuris is not a law firm and does not provide legal advice.</span></label>'''
            f'''<div style="display:flex;gap:10px">'''
            f'''<button onclick="window.location.href='/?bye=1'" style="flex:1;background:transparent;border:1px solid rgba(255,255,255,0.07);border-radius:8px;padding:11px;font-size:13px;color:#506070;cursor:pointer">Exit</button>'''
            f'''<button id="sj-disc-btn" onclick="sjAcceptDisclaimer()" style="flex:2;background:#c9a84c;border:none;border-radius:8px;padding:11px;font-size:13px;font-weight:600;color:#0a1520;cursor:pointer;opacity:0.4">I Understand - Continue</button>'''
            f'''</div><div style="margin-top:12px;font-size:10px;color:#506070;text-align:center">v{DISCLAIMER_VERSION} - {DISCLAIMER_HASH} - Acknowledgment logged with timestamp</div>'''
            f'''</div></div>'''
            f'''<script>async function sjAcceptDisclaimer(){{if(!document.getElementById('sj-disc-check').checked)return;await fetch('/api/disclaimer/ack',{{method:'POST'}}).catch(()=>{{}});const el=document.getElementById('sj-disclaimer-overlay');el.style.opacity='0';setTimeout(()=>el.remove(),300);}}</script>''')

def _generate_portal_token(case_id):
    conn=get_db(); row=conn.execute("SELECT token FROM portal_tokens WHERE case_id=? AND revoked=0",(case_id,)).fetchone()
    if row: conn.close(); return row[0]
    token=secrets.token_urlsafe(24)
    conn.execute("INSERT INTO portal_tokens (case_id,token,created_by) VALUES (?,?,?)",(case_id,token,1))
    conn.commit(); conn.close(); return token

def _render_portal(case_id,token):
    conn=get_db(); pt=conn.execute("SELECT case_id,revoked FROM portal_tokens WHERE token=?",(token,)).fetchone()
    if not pt or pt[1]: conn.close(); return "<html><body style='background:#0a1520;color:#506070;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh'><div style='text-align:center'><div style='font-size:32px;margin-bottom:12px'>404</div><div>This portal link is invalid or has been revoked.</div></div></body></html>"
    conn.execute("UPDATE portal_tokens SET last_viewed=CURRENT_TIMESTAMP,view_count=view_count+1 WHERE token=?",(token,)); conn.commit()
    case=dict(conn.execute("SELECT * FROM cases WHERE id=?",(case_id,)).fetchone() or {})
    exhibits=[dict(r) for r in conn.execute("SELECT exhibit_number,event_date,category,substr(content,1,120) as summary FROM evidence WHERE case_id=? AND confirmed=1 AND (is_deleted IS NULL OR is_deleted=0) ORDER BY event_date ASC",(case_id,)).fetchall()]
    conn.close()
    def esc(s): return str(s or "").replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
    ex_rows="".join(f"<tr><td style='color:#c9a84c;padding:8px 12px;border-bottom:1px solid rgba(255,255,255,0.06);font-size:11px'>{esc(e['exhibit_number'])}</td><td style='color:#506070;padding:8px 12px;border-bottom:1px solid rgba(255,255,255,0.06);font-size:11px'>{esc(e['event_date'])}</td><td style='color:#a0b0c0;padding:8px 12px;border-bottom:1px solid rgba(255,255,255,0.06);font-size:12px'>{esc(e['summary'])}</td><td style='color:#506070;padding:8px 12px;border-bottom:1px solid rgba(255,255,255,0.06);font-size:11px'>{esc(e['category'])} (research indicator)</td></tr>" for e in exhibits) or "<tr><td colspan='4' style='padding:12px;color:#506070;font-size:12px'>No confirmed exhibits.</td></tr>"
    return f'''<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>SynJuris Case Summary</title><style>*{{box-sizing:border-box;margin:0;padding:0}}body{{background:#0a1520;color:#e8dfc8;font-family:sans-serif;min-height:100vh}}</style></head><body><div style="background:#0d1825;border-bottom:1px solid rgba(255,255,255,0.07);padding:14px 32px"><strong style="color:#c9a84c">SynJuris</strong> <span style="color:#506070;font-size:11px">Read-only case summary</span></div><div style="background:rgba(212,146,74,0.08);border-bottom:1px solid rgba(212,146,74,0.18);padding:10px 32px;font-size:11.5px;color:#d4924a"><strong>Not legal advice.</strong> Pattern flags are research indicators only. Consult a licensed attorney.</div><div style="max-width:860px;margin:0 auto;padding:40px 24px"><h1 style="font-size:28px;font-weight:300;margin-bottom:24px">{esc(case.get("title",""))}</h1><table style="width:100%;border-collapse:collapse;background:#111d2b;border:1px solid rgba(255,255,255,0.07);border-radius:8px;overflow:hidden;margin-bottom:28px"><thead><tr><th style="text-align:left;font-size:9.5px;text-transform:uppercase;color:#506070;padding:8px 12px;border-bottom:1px solid rgba(255,255,255,0.07)">Exhibit</th><th style="text-align:left;font-size:9.5px;text-transform:uppercase;color:#506070;padding:8px 12px;border-bottom:1px solid rgba(255,255,255,0.07)">Date</th><th style="text-align:left;font-size:9.5px;text-transform:uppercase;color:#506070;padding:8px 12px;border-bottom:1px solid rgba(255,255,255,0.07)">Summary</th><th style="text-align:left;font-size:9.5px;text-transform:uppercase;color:#506070;padding:8px 12px;border-bottom:1px solid rgba(255,255,255,0.07)">Research flag</th></tr></thead><tbody>{ex_rows}</tbody></table></div><footer style="border-top:1px solid rgba(255,255,255,0.07);padding:20px 32px;font-size:11px;color:#506070;text-align:center"><strong style="color:#d4924a">Not legal advice.</strong> SynJuris is an organizational tool. Generated {datetime.now().strftime("%Y-%m-%d %H:%M UTC")}.</footer></body></html>'''

# ── HTTP HANDLER ──────────────────────────────────────────────────────────────
def _json_response(handler,data,status=200):
    body=json.dumps(data,default=str).encode("utf-8")
    handler.send_response(status); handler.send_header("Content-Type","application/json")
    handler.send_header("Content-Length",len(body)); handler.send_header("Access-Control-Allow-Origin","*")
    handler.end_headers(); handler.wfile.write(body)

def _read_body(handler):
    try:
        n=int(handler.headers.get("Content-Length",0))
        if n>0: return json.loads(handler.rfile.read(n).decode("utf-8"))
    except Exception: pass
    return {}

class SynJurisHandler(BaseHTTPRequestHandler):
    protocol_version="HTTP/1.1"
    def log_message(self,fmt,*args): sys.stderr.write(f"{self.address_string()} {fmt%args}\n")
    def end_headers(self):
        self.send_header("Content-Security-Policy",_CSP_POLICY)
        self.send_header("X-Frame-Options","DENY"); self.send_header("X-Content-Type-Options","nosniff")
        self.send_header("Referrer-Policy","no-referrer"); super().end_headers()
    def do_OPTIONS(self):
        self.send_response(200); self.send_header("Access-Control-Allow-Origin","*")
        self.send_header("Access-Control-Allow-Methods","GET, POST, PUT, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers","Content-Type, Authorization")
        self.send_header("Content-Length","0"); self.end_headers()

    def do_GET(self):
        path=urlparse(self.path).path.rstrip("/") or "/"
        if path.startswith("/static/"):
            if not _serve_static_file(self,path[8:]): _json_response(self,{"error":"not found"},404)
            return
        if path.startswith("/portal/"):
            token=path[len("/portal/"):]; conn=get_db()
            pt=conn.execute("SELECT case_id,revoked FROM portal_tokens WHERE token=?",(token,)).fetchone(); conn.close()
            _send_html(self,_render_portal(pt[0] if pt and not pt[1] else 0,token)); return
        if path in ("/",""):
            query=parse_qs(urlparse(self.path).query)
            if "case" not in query:
                conn=get_db(); count=conn.execute("SELECT COUNT(*) FROM cases WHERE is_deleted=0").fetchone()[0]; conn.close()
                if count==0: self.send_response(302); self.send_header("Location","/onboarding"); self.send_header("Content-Length","0"); self.end_headers(); return
            html=_read_static("dashboard.html")
            if _needs_disclaimer(1): html=html.replace("</body>",_get_disclaimer_modal()+"</body>")
            _send_html(self,html); return
        if path=="/login":      _send_html(self,_read_static("login.html")); return
        if path=="/onboarding": _send_html(self,_read_static("onboarding.html")); return
        if path=="/guided":     _send_html(self,_read_static("guided.html")); return
        if path=="/health":     _json_response(self,{"status":"ok","version":VERSION}); return
        if path=="/api/version":_json_response(self,{"version":VERSION,"db":DB_PATH}); return
        if path=="/api/cases":
            conn=get_db(); rows=[dict(r) for r in conn.execute("SELECT * FROM cases WHERE is_deleted=0 ORDER BY created_at DESC").fetchall()]; conn.close()
            _json_response(self,{"cases":rows}); return
        m=re.match(r"^/api/cases/(\d+)$",path)
        if m:
            cid=int(m.group(1)); conn=get_db()
            row=conn.execute("SELECT * FROM cases WHERE id=? AND is_deleted=0",(cid,)).fetchone()
            if not row: conn.close(); _json_response(self,{"error":"not found"},404); return
            case=dict(row)
            case["parties"]=[dict(r) for r in conn.execute("SELECT * FROM parties WHERE case_id=?",(cid,)).fetchall()]
            case["evidence"]=[dict(r) for r in conn.execute("SELECT * FROM evidence WHERE case_id=? AND is_deleted=0 ORDER BY event_date",(cid,)).fetchall()]
            case["deadlines"]=[dict(r) for r in conn.execute("SELECT * FROM deadlines WHERE case_id=? ORDER BY due_date",(cid,)).fetchall()]
            conn.close(); _json_response(self,case); return
        m=re.match(r"^/api/cases/(\d+)/derive$",path)
        if m:
            cid=int(m.group(1)); conn=get_db()
            row=conn.execute("SELECT narrative,notes FROM cases WHERE id=? AND is_deleted=0",(cid,)).fetchone(); conn.close()
            if not row: _json_response(self,{"error":"case not found"},404); return
            narrative=(row["narrative"] if "narrative" in row.keys() else None) or row["notes"] or ""
            if not narrative.strip(): _json_response(self,{"error":"No narrative found","events":[],"evidence_leads":[],"statement_draft":"","questions":[]},200); return
            _json_response(self,derive_from_narrative(narrative)); return
        m=re.match(r"^/api/cases/(\d+)/sms/imports$",path)
        if m:
            cid=int(m.group(1)); conn=get_db()
            rows=[dict(r) for r in conn.execute("SELECT * FROM sms_imports WHERE case_id=? ORDER BY created_at DESC",(cid,)).fetchall()]; conn.close()
            _json_response(self,{"imports":rows}); return
        m=re.match(r"^/api/cases/(\d+)/sms/imports/(\d+)/messages$",path)
        if m:
            cid,iid=int(m.group(1)),int(m.group(2)); conn=get_db(); rows=[]
            for r in conn.execute("SELECT * FROM sms_messages WHERE case_id=? AND import_id=? ORDER BY message_ts,id",(cid,iid)).fetchall():
                d=dict(r)
                try: d["flags"]=json.loads(d.pop("flags_json") or "[]")
                except: d["flags"]=[]
                try: d["metadata"]=json.loads(d.pop("metadata_json") or "{}")
                except: d["metadata"]={}
                rows.append(d)
            conn.close(); _json_response(self,{"messages":rows,"summary":summarize_sms_import(rows)}); return
        m=re.match(r"^/api/cases/(\d+)/state$",path)
        if m: _json_response(self,compute_case_state(int(m.group(1)))); return
        m=re.match(r"^/api/cases/(\d+)/readiness$",path)
        if m:
            cid=int(m.group(1)); conn=get_db(); result=compute_readiness_scores(cid,conn); conn.close()
            _json_response(self,result); return
        m=re.match(r"^/api/cases/(\d+)/merkle$",path)
        if m:
            cid=int(m.group(1)); conn=get_db()
            _json_response(self,{"root_hash":get_merkle_root(conn,cid),"verification":verify_dag_chain(conn,cid)}); conn.close(); return
        m=re.match(r"^/api/cases/(\d+)/audit$",path)
        if m:
            cid=int(m.group(1)); conn=get_db()
            rows=[dict(r) for r in conn.execute("SELECT id,action_type,ai_call_type,state_x,state_y,state_z,trace_hash,created_at FROM audit_log WHERE case_id=? ORDER BY created_at DESC LIMIT 50",(cid,)).fetchall()]; conn.close()
            _json_response(self,{"audit_log":rows}); return
        if path=="/api/jurisdictions": _json_response(self,{"jurisdictions":sorted(JURISDICTION_LAW.keys())}); return
        m=re.match(r"^/api/jurisdictions/(.+)$",path)
        if m:
            raw=m.group(1); canonical,laws=resolve_jurisdiction(urllib.parse.unquote(raw))
            _json_response(self,{"jurisdiction":canonical,"statutes":laws} if laws else {"error":f"Not found: {raw}"},200 if laws else 404); return
        if path=="/api/disclaimer/ack": _record_disclaimer_ack(ip_hint=self.client_address[0]); _json_response(self,{"ok":True}); return
        m=re.match(r"^/api/cases/(\d+)/portal-token$",path)
        if m:
            cid=int(m.group(1)); token=_generate_portal_token(cid); host=self.headers.get("Host",f"localhost:{PORT}")
            _json_response(self,{"token":token,"url":f"http://{host}/portal/{token}"}); return
        m=re.match(r"^/api/cases/(\d+)/portal-token/revoke$",path)
        if m:
            cid=int(m.group(1)); conn=get_db(); conn.execute("UPDATE portal_tokens SET revoked=1 WHERE case_id=?",(cid,)); conn.commit(); conn.close()
            _json_response(self,{"ok":True}); return
        m=re.match(r"^/api/cases/(\d+)/dag-proof$",path)
        if m:
            _json_response(self,{"error":"reportlab required. Run: pip install reportlab"},501); return
        m=re.match(r"^/api/cases/(\d+)/evidence/(\d+)/confirm$",path)
        if m:
            cid,eid=int(m.group(1)),int(m.group(2)); result=_handle_confirm_exhibit(cid,eid)
            status=result.pop("status",200); _json_response(self,result,status); return
        _json_response(self,{"error":"Not found","path":path},404)

    def do_PUT(self):
        path=urlparse(self.path).path.rstrip("/"); body=_read_body(self)
        m=re.match(r"^/api/cases/(\d+)/evidence/(\d+)$",path)
        if m:
            cid,eid=int(m.group(1)),int(m.group(2)); conn=get_db()
            row=conn.execute("SELECT * FROM evidence WHERE id=? AND case_id=? AND is_deleted=0",(eid,cid)).fetchone()
            if not row: conn.close(); _json_response(self,{"error":"not found"},404); return
            if int(row["confirmed"] or 0)==1 and "content" in body and (body.get("content") or "")!=(row["content"] or ""):
                conn.close(); _json_response(self,{"error":"confirmed evidence cannot be edited"},409); return
            conn.execute("UPDATE evidence SET content=?,source=?,event_date=?,category=?,notes=?,exhibit_number=? WHERE id=? AND case_id=?",
                         (body.get("content",row["content"]),body.get("source",row["source"]),body.get("event_date",row["event_date"]),
                          body.get("category",row["category"]),body.get("notes",row["notes"]),body.get("exhibit_number",row["exhibit_number"]),eid,cid))
            conn.commit(); conn.close(); _json_response(self,{"ok":True,"id":eid}); return
        _json_response(self,{"error":"Not found"},404)

    def do_DELETE(self):
        path=urlparse(self.path).path.rstrip("/")
        m=re.match(r"^/api/cases/(\d+)/evidence/(\d+)$",path)
        if m:
            cid,eid=int(m.group(1)),int(m.group(2)); conn=get_db()
            conn.execute("UPDATE evidence SET is_deleted=1,deleted_at=CURRENT_TIMESTAMP WHERE id=? AND case_id=?",(eid,cid))
            conn.commit(); conn.close(); _json_response(self,{"ok":True,"id":eid}); return
        m=re.match(r"^/api/cases/(\d+)/timeline/(\d+)$",path)
        if m:
            cid,tid=int(m.group(1)),int(m.group(2)); conn=get_db()
            conn.execute("DELETE FROM timeline_events WHERE id=? AND case_id=?",(tid,cid))
            conn.commit(); conn.close(); _json_response(self,{"ok":True,"id":tid}); return
        m=re.match(r"^/api/cases/(\d+)/documents/(\d+)$",path)
        if m:
            cid,did=int(m.group(1)),int(m.group(2)); conn=get_db()
            conn.execute("UPDATE documents SET is_deleted=1,deleted_at=CURRENT_TIMESTAMP WHERE id=? AND case_id=?",(did,cid))
            conn.commit(); conn.close(); _json_response(self,{"ok":True,"id":did}); return
        _json_response(self,{"error":"Not found"},404)

    def do_POST(self):
        path=urlparse(self.path).path.rstrip("/"); body=_read_body(self)
        if path=="/api/signup":
            email=(body.get("email") or "").strip().lower(); pw=body.get("password") or ""
            if not email or not pw: return _json_response(self,{"error":"email and password required"},400)
            if len(pw)<8: return _json_response(self,{"error":"password must be at least 8 characters"},400)
            conn=get_db()
            try:
                cur=conn.execute("INSERT INTO users (email,password_hash) VALUES (?,?)",(email,_hash_password(pw))); conn.commit()
                _json_response(self,{"ok":True,"user_id":cur.lastrowid},201)
            except sqlite3.IntegrityError: _json_response(self,{"error":"account already exists"},409)
            finally: conn.close()
            return
        if path=="/api/login":
            email=(body.get("email") or "").strip().lower(); pw=body.get("password") or ""
            conn=get_db(); row=conn.execute("SELECT id,password_hash FROM users WHERE email=?",(email,)).fetchone()
            if not row or not _verify_password(pw,row["password_hash"]): conn.close(); return _json_response(self,{"error":"invalid email or password"},401)
            conn.execute("UPDATE users SET last_login_at=CURRENT_TIMESTAMP WHERE id=?",(row["id"],)); conn.commit(); conn.close()
            _json_response(self,{"ok":True,"user_id":row["id"]}); return
        if path=="/api/cases":
            title=body.get("title","").strip()
            if not title: return _json_response(self,{"error":"title required"},400)
            conn=get_db()
            cur=conn.execute("INSERT INTO cases (title,case_type,jurisdiction,court_name,case_number,goals,notes,narrative,narrative_date,narrative_source) VALUES (?,?,?,?,?,?,?,?,?,?)",
                             (title,body.get("case_type"),body.get("jurisdiction"),body.get("court_name"),body.get("case_number"),body.get("goals"),body.get("notes"),body.get("narrative"),body.get("narrative_date"),body.get("narrative_source")))
            conn.commit(); cid=cur.lastrowid; conn.close(); _json_response(self,{"id":cid,"title":title},201); return
        m=re.match(r"^/api/cases/(\d+)/parties$",path)
        if m:
            cid=int(m.group(1)); name=(body.get("name") or "").strip()
            if not name: return _json_response(self,{"error":"name required"},400)
            conn=get_db()
            cur=conn.execute("INSERT INTO parties (case_id,name,role,contact,attorney,notes) VALUES (?,?,?,?,?,?)",(cid,name,body.get("role"),body.get("contact"),body.get("attorney"),body.get("notes")))
            conn.commit(); conn.close(); _json_response(self,{"id":cur.lastrowid,"case_id":cid,"name":name},201); return
        m=re.match(r"^/api/cases/(\d+)/evidence$",path)
        if m:
            cid=int(m.group(1)); content=body.get("content","").strip()
            if not content: return _json_response(self,{"error":"content required"},400)
            conn=get_db()
            cur=conn.execute("INSERT INTO evidence (case_id,content,source,event_date,category,confirmed,notes,exhibit_number) VALUES (?,?,?,?,?,?,?,?)",
                             (cid,content,body.get("source"),body.get("event_date"),body.get("category","General"),int(body.get("confirmed",0)),body.get("notes"),body.get("exhibit_number")))
            conn.commit(); eid=cur.lastrowid
            patterns=scan_patterns(content); scrutinized=analyze_scrutinized_behavior(content); z_update=update_case_z_from_exhibit(cid,content,conn)
            merkle_hash=None
            if int(body.get("confirmed",0)): result=_handle_confirm_exhibit(cid,eid); merkle_hash=result.get("merkle_hash")
            conn.close()
            _json_response(self,{"id":eid,"merkle_hash":merkle_hash,"patterns":[{"category":p[0],"score":p[1],"severity":p[2]} for p in patterns],"scrutinized":scrutinized,"z_update":z_update},201); return
        m=re.match(r"^/api/cases/(\d+)/evidence/(\d+)/confirm$",path)
        if m:
            cid,eid=int(m.group(1)),int(m.group(2)); result=_handle_confirm_exhibit(cid,eid)
            status=result.pop("status",200); _json_response(self,result,status); return
        m=re.match(r"^/api/cases/(\d+)/timeline/bulk-create$",path)
        if m:
            cid=int(m.group(1)); events=body.get("events") or []; conn=get_db(); count=0
            for ev in events:
                desc=(ev.get("description") or ev.get("snippet") or "").strip()
                if not desc: continue
                conn.execute("INSERT INTO timeline_events (case_id,event_date,title,description,category,importance) VALUES (?,?,?,?,?,?)",(cid,ev.get("date") or None,ev.get("title") or "Narrative event",desc,"Narrative","normal")); count+=1
            conn.commit(); conn.close(); _json_response(self,{"ok":True,"count":count},201); return
        m=re.match(r"^/api/cases/(\d+)/evidence/from-leads$",path)
        if m:
            cid=int(m.group(1)); leads=body.get("leads") or []; conn=get_db(); created=[]
            for lead in leads:
                snippet=(lead.get("snippet") or "").strip()
                if not snippet: continue
                cur=conn.execute("INSERT INTO evidence (case_id,content,source,event_date,category,confirmed,notes,exhibit_number) VALUES (?,?,?,?,?,?,?,?)",(cid,snippet,lead.get("type") or "Narrative lead",None,"General",0,"From narrative lead; review required.",None)); created.append(cur.lastrowid)
            conn.commit(); conn.close(); _json_response(self,{"ok":True,"count":len(created),"ids":created},201); return
        m=re.match(r"^/api/cases/(\d+)/documents/statement-draft$",path)
        if m:
            cid=int(m.group(1)); content=(body.get("content") or "").strip()
            if not content: return _json_response(self,{"error":"content required"},400)
            conn=get_db(); cur=conn.execute("INSERT INTO documents (case_id,title,doc_type,content,version) VALUES (?,?,?,?,?)",(cid,"Statement Draft","statement_draft",content,1)); conn.commit(); conn.close()
            _json_response(self,{"ok":True,"id":cur.lastrowid},201); return
        m=re.match(r"^/api/cases/(\d+)/sms/import$",path)
        if m:
            cid=int(m.group(1)); fn=(body.get("filename") or "SMS import").strip(); sf=(body.get("format") or "").strip().lower()
            xml_text=body.get("xml") or ""; pasted=body.get("text") or ""
            if xml_text.strip() or fn.lower().endswith(".xml") or sf=="android_xml":
                parsed=parse_android_sms_backup_xml(xml_text); sf="android_sms_backup_xml"
            else: parsed=parse_pasted_sms_thread(pasted); sf="manual_paste"
            if parsed.get("errors"): return _json_response(self,{"ok":False,"errors":parsed.get("errors"),"messages":[]},400)
            stored=store_sms_import(cid,fn,sf,parsed)
            _json_response(self,{"ok":True,"import_id":stored["import_id"],"summary":stored["summary"],"preview":stored["messages"][:150]},201); return
        m=re.match(r"^/api/cases/(\d+)/sms/messages/to-evidence$",path)
        if m:
            cid=int(m.group(1)); ids=body.get("message_ids") or []
            if not isinstance(ids,list) or not ids: return _json_response(self,{"error":"message_ids required"},400)
            safe_ids=[int(x) for x in ids if str(x).isdigit()]
            if not safe_ids: return _json_response(self,{"error":"no valid ids"},400)
            ph=",".join("?" for _ in safe_ids); conn=get_db()
            rows=[dict(r) for r in conn.execute(f"SELECT * FROM sms_messages WHERE case_id=? AND id IN ({ph})",[cid]+safe_ids).fetchall()]
            created=[]
            for r in rows:
                label=f"SMS {r.get('direction') or ''} {r.get('readable_date') or ''}".strip()
                cnt=f"{label}\n{r.get('contact_name') or 'Unknown'}: {r.get('body') or ''}".strip()
                cur=conn.execute("INSERT INTO evidence (case_id,content,source,event_date,category,confirmed,notes,exhibit_number) VALUES (?,?,?,?,?,?,?,?)",(cid,cnt,"SMS import",(r.get("message_ts") or "")[:10] or None,"Communication",0,"From reviewed SMS import. Unconfirmed.",None)); created.append(cur.lastrowid)
                conn.execute("UPDATE sms_messages SET created_as_evidence=1 WHERE id=? AND case_id=?",(r["id"],cid))
            conn.commit(); conn.close(); _json_response(self,{"ok":True,"count":len(created),"ids":created},201); return
        m=re.match(r"^/api/cases/(\d+)/evidence/sms-paste$",path)
        if m:
            cid=int(m.group(1)); raw=(body.get("text") or "").strip(); event_date=body.get("event_date") or None
            if not raw: return _json_response(self,{"error":"text required"},400)
            conn=get_db()
            cur=conn.execute("INSERT INTO evidence (case_id,content,source,event_date,category,confirmed,notes,exhibit_number) VALUES (?,?,?,?,?,?,?,?)",(cid,raw,"SMS paste",event_date,"Communication",0,"Raw pasted SMS. Review before confirming.",None))
            conn.commit(); conn.close(); _json_response(self,{"ok":True,"count":1,"ids":[cur.lastrowid]},201); return
        if path=="/api/ai/analyze":
            text=body.get("text","")
            if not text: return _json_response(self,{"error":"text required"},400)
            _json_response(self,analyze_text_safe(text)); return
        m=re.match(r"^/api/cases/(\d+)/chat$",path)
        if m:
            cid=int(m.group(1)); message=body.get("message","").strip()
            if not message: return _json_response(self,{"error":"message required"},400)
            conn=get_db()
            history=[dict(r) for r in conn.execute("SELECT role,content FROM chat_history WHERE case_id=? ORDER BY created_at DESC LIMIT 10",(cid,)).fetchall()]
            history.reverse(); state_ctx=json.dumps(compute_case_state(cid,conn)["state"])
            prompt=f"Case state: {state_ctx}\nRecent: {json.dumps(history[-4:])}\nQuestion: {message}"
            result=safe_generate_with_defense(prompt,llm_call)
            conn.execute("INSERT INTO chat_history (case_id,role,content) VALUES (?,?,?)",(cid,"user",message))
            conn.execute("INSERT INTO chat_history (case_id,role,content) VALUES (?,?,?)",(cid,"assistant",result["content"]))
            conn.commit(); conn.close(); _json_response(self,result); return
        if path=="/api/score":
            text=body.get("text","")
            _json_response(self,{"upl_audit":upl_score_text(text),"patterns":[{"category":p[0],"score":p[1],"severity":p[2]} for p in scan_patterns(text)],"scrutinized":analyze_scrutinized_behavior(text),"z_pressure_delta":compute_scrutinized_z_delta(text)}); return
        if path=="/api/greyrockfilter":
            text=body.get("text",""); filtered=apply_grey_rock_filter(text)
            _json_response(self,{"original":text,"filtered":filtered,"blocked":guardrail_detect_block(text),"warning":GREY_ROCK_WARNING}); return
        if path=="/api/reset":
            if body.get("confirm")!="RESET": return _json_response(self,{"error":"confirm must equal RESET"},400)
            conn=get_db()
            conn.executescript("DELETE FROM chat_history;DELETE FROM documents;DELETE FROM timeline_events;DELETE FROM deadlines;DELETE FROM merkle_nodes;DELETE FROM merkle_roots;DELETE FROM portal_tokens;DELETE FROM disclaimer_acks;DELETE FROM evidence;DELETE FROM parties;DELETE FROM cases;")
            conn.commit(); conn.close(); _json_response(self,{"ok":True,"message":"Workspace cleared."}); return
        m=re.match(r"^/api/cases/(\d+)/deadlines$",path)
        if m:
            cid=int(m.group(1)); title=body.get("title","").strip()
            if not title: return _json_response(self,{"error":"title required"},400)
            conn=get_db(); cur=conn.execute("INSERT INTO deadlines (case_id,title,due_date,description) VALUES (?,?,?,?)",(cid,title,body.get("due_date"),body.get("description"))); conn.commit(); conn.close()
            _json_response(self,{"id":cur.lastrowid},201); return
        if path=="/api/docs":
            text=body.get("text",""); dt=body.get("doc_type","Legal Document"); cid=body.get("case_id")
            result=safe_generate_with_defense(f"Generate a professional {dt}.\nDo not give legal advice.\n\nCONTENT:\n{text}",llm_call)
            conn=get_db(); cur=None
            if cid: cur=conn.execute("INSERT INTO documents (case_id,title,doc_type,content) VALUES (?,?,?,?)",(cid,dt,dt,result["content"])); conn.commit()
            conn.close(); _json_response(self,{"document":result["content"],"doc_id":cur.lastrowid if cur else None,"audit":result["audit"]}); return
        if path=="/api/disclaimer/ack": _record_disclaimer_ack(ip_hint=self.client_address[0]); _json_response(self,{"ok":True,"version":DISCLAIMER_VERSION}); return
        _json_response(self,{"error":"Not found","path":path},404)

# ── ENTRY POINT ───────────────────────────────────────────────────────────────
def main():
    print(f"SynJuris v{VERSION} | Port {PORT} | DB: {DB_PATH}")
    print(f"AI: {'Anthropic' if API_KEY else ('OpenAI' if OPENAI_KEY else 'None - set ANTHROPIC_API_KEY')}")
    print("FIX 1: Grey Rock - neutral substitutions only")
    print("FIX 2: LLM UPL audit active in pipeline\n")
    init_db()
    server=ThreadingHTTPServer(("0.0.0.0",PORT),SynJurisHandler)
    if LOCAL_MODE:
        def _open(): time.sleep(0.8); webbrowser.open(f"http://localhost:{PORT}/health")
        threading.Thread(target=_open,daemon=True).start()
    print(f"Running at http://localhost:{PORT}  |  Ctrl+C to stop\n")
    try: server.serve_forever()
    except KeyboardInterrupt: print("\nShutting down."); server.server_close()

if __name__=="__main__": main()
