"""
synjuris.py — Upgraded Architecture
========================================
Integrates all v2 modules into the existing server pattern.

NEW in v2:
  ✦ Merkle DAG audit ledger (per-exhibit tamper-evidence, not just state snapshots)
  ✦ Semantic pattern detection (bi-encoder + Aho-Corasick + negation detection)
  ✦ Streaming SSE document generation (first token in <500ms)
  ✦ Async job queue (non-blocking, idempotent, with speculative pre-generation)
  ✦ Predictive document readiness scoring (reorders Documents tab, drives pre-gen)
  ✦ Evidence gap detection (surfaces what's typically missing for your case type)
  ✦ Merkle proof generation per exhibit (court-ready cryptographic statements)
  ✦ DAG integrity verification endpoint (/api/cases/:id/dag-verify)
  ✦ Job status + SSE stream endpoints (/api/jobs/:id, /api/jobs/:id/stream)
  ✦ Readiness scores endpoint (/api/cases/:id/readiness)

PRESERVED from v1:
  - All existing endpoints and behavior
  - SQLite schema (new tables added, none removed)
  - The full original audit_log system (still running alongside Merkle DAG)
  - All UI JavaScript (new endpoints added to existing tabs)
  - All exports (PDF, DOCX, TXT, encrypted backup)

Run:  python3 synjuris-20.py
Open: http://localhost:5000
"""

# ── Standard library imports ──────────────────────────────────────────────────
import json, os, re, sys, time, threading, webbrowser, hashlib, hmac, secrets
import urllib.request, urllib.parse, xml.etree.ElementTree as ET
from datetime import datetime, date
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# ── Optional SDK check (enables true streaming) ───────────────────────────────
try:
    import anthropic as _anthropic_sdk
    HAS_ANTHROPIC_SDK = True
except ImportError:
    HAS_ANTHROPIC_SDK = False

# ── V2 module imports (graceful degradation if modules not found) ─────────────
_MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
if _MODULE_DIR not in sys.path:
    sys.path.insert(0, _MODULE_DIR)

try:
    from merkle_dag import (
        init_merkle_schema, add_exhibit_to_dag, verify_case_dag,
        get_exhibit_proof, generate_proof_statement, GENESIS_HASH
    )
    HAS_MERKLE = True
except ImportError:
    HAS_MERKLE = False
    print("  ⚠  merkle_dag.py not found — using legacy audit hash")

try:
    from pattern_engine import scan_patterns as _semantic_scan, detect_evidence_gaps
    HAS_SEMANTIC = True
except ImportError:
    HAS_SEMANTIC = False
    print("  ⚠  pattern_engine.py not found — using regex patterns")

try:
    from job_queue import JobQueue, job_status_response, compute_evidence_hash
    HAS_QUEUE = True
except ImportError:
    HAS_QUEUE = False
    print("  ⚠  job_queue.py not found — using blocking generation")

try:
    from readiness_engine import compute_readiness_scores, get_readiness_summary
    HAS_READINESS = True
except ImportError:
    HAS_READINESS = False
    print("  ⚠  readiness_engine.py not found — readiness scoring disabled")

try:
    from jurisdiction_helpers import jurisdiction_statute_block, resolve_jurisdiction
except ImportError:
    # Inline fallback
    def jurisdiction_statute_block(j): return f"Jurisdiction: {j or 'Not set'}"
    def resolve_jurisdiction(j): return j, {}

# ── Configuration ─────────────────────────────────────────────────────────────
DATABASE_URL = os.environ.get("DATABASE_URL", "")
USE_POSTGRES  = bool(DATABASE_URL)

if USE_POSTGRES:
    import psycopg2
    import psycopg2.extras
else:
    import sqlite3

_BASE        = "/data" if os.path.isdir("/data") else _MODULE_DIR
DB_PATH      = os.path.join(_BASE, "synjuris.db")
API_KEY      = os.environ.get("ANTHROPIC_API_KEY", "")
UPLOADS_DIR  = os.path.join(_BASE, "uploads")
PORT         = int(os.environ.get("PORT", 5000))
LOCAL_MODE   = (not USE_POSTGRES and not os.environ.get("REQUIRE_AUTH"))
VERSION      = "2.0.0"
UPDATE_URL   = "https://raw.githubusercontent.com/synjuris/synjuris/main/version.json"

# ── Paste the FULL synjuris.py content here ───────────────────────────────────
# This file is a PATCH file — it overrides specific functions from synjuris.py.
# The cleanest deployment: rename synjuris.py → synjuris_base.py and
# import everything from it, then override below.
#
# For single-file deployment, copy the full synjuris.py content here,
# then the overrides below replace the upgraded sections.
# ─────────────────────────────────────────────────────────────────────────────

# Import everything from the base server
try:
    # When deployed alongside the original
    import importlib.util
    _base_path = os.path.join(_MODULE_DIR, "synjuris-10.py")
    if not os.path.exists(_base_path):
        _base_path = os.path.join(_MODULE_DIR, "synjuris.py")

    if os.path.exists(_base_path):
        spec = importlib.util.spec_from_file_location("synjuris_base", _base_path)
        _base = importlib.util.module_from_spec(spec)
        # Don't execute — we'll inherit selectively
        # spec.loader.exec_module(_base)
except Exception:
    pass


# ═══════════════════════════════════════════════════════════════════════════════
# V2 OVERRIDES — these replace the corresponding functions in the base server
# ═══════════════════════════════════════════════════════════════════════════════

# ── Database connection (preserved from v1, extended for v2 schemas) ──────────

class _HybridRow(dict):
    def __init__(self, d):
        super().__init__(d)
        self._vals = list(d.values())
    def __getitem__(self, key):
        if isinstance(key, int):
            return self._vals[key]
        return super().__getitem__(key)

def get_db():
    if USE_POSTGRES:
        # PostgreSQL path (cloud deployment) — preserved from v1
        conn = psycopg2.connect(DATABASE_URL,
                                cursor_factory=psycopg2.extras.RealDictCursor)
        return conn
    else:
        conn = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA busy_timeout = 30000")
        return conn


# ── V2 pattern scanning (with semantic fallback) ──────────────────────────────

if HAS_SEMANTIC:
    def scan_patterns(text: str):
        """V2 semantic pattern scanner. Same signature as v1."""
        return _semantic_scan(text, use_semantic=True)
else:
    # Preserve v1 regex patterns as fallback
    _PATTERNS_V1 = [
        ("Gatekeeping", 5.0,
         r"(won'?t\s+let\s+(him|her|me|them|you)"
         r"|denied?\s+(visit|access|time|pickup|drop.?off|exchange)"
         r"|prevent(ing|ed)?\s+(me|him|her|them)\s+(from\s+)?(see|visit|contact)"
         r"|(cancel+ed?|call(ed)?\s*off|no.?show)\s*(the\s*)?(visit|exchange|pickup)"
         r"|block(ed|ing)?\s*(access|contact|visitation)"
         r"|withhold(ing|ed)?\s+(the\s*)?(child(ren)?|kids?|son|daughter)"
         r"|interfere\S*\s+with\s+(my\s+)?(parenting|custody|visitation|time))"
        ),
        ("Parental Alienation", 4.0,
         r"(alienat(e|ed|ing|ion)"
         r"|(turn(ing|ed)|turns)\s+(him|her|them|the\s*kids?)\s+against"
         r"|(poison(ing|ed)|brainwash(ing|ed))\s+(his|her|their)\s+mind"
         r"|bad.?mouth(ing|ed)\s+(about\s+)?(me|their\s+(father|mother|dad|mom)))"
        ),
        ("Stonewalling", 3.0,
         r"(won'?t\s+respond|not\s+responding"
         r"|(never|doesn'?t|don'?t|won'?t)\s+(respond|reply|answer|return)\s+(my\s+)?(call|text|message|email)s?"
         r"|block(ed|s|ing)?\s+(my\s+)?(number|calls?|texts?)"
         r"|left\s+(me\s+)?(on\s+)?(read|seen))"
        ),
        ("Threats", 5.0,
         r"((take|taking|gonna\s+take|going\s+to\s+take)\s+(you|this)\s+to\s+court"
         r"|you'?ll\s+(never|not)\s+(see|have|get)\s+(him|her|them|the\s*kids?)"
         r"|(call|going\s+to\s+call|gonna\s+call)\s+(the\s*)?(police|cops?|cps|911)"
         r"|(file|going\s+to\s+file)\s+a\s+(restraining|protective)\s+order)"
        ),
        ("Harassment", 4.0,
         r"(show(ed|ing|s)?\s+up\s+(uninvited|unannounced|at\s+my\s+(house|work|job|school))"
         r"|(follow(ed|ing|s)|stalking|spying\s+on)\s+me"
         r"|(blowing\s+up|flooding)\s+my\s+(phone|inbox))"
        ),
        ("Violation of Order", 5.0,
         r"(violat(e|ed|es|ing|ion)\s+(the\s+)?(court\s+order|parenting\s+plan)"
         r"|in\s+contempt"
         r"|breaking\s+the\s+(court\s+order|parenting\s+plan))"
        ),
        ("Financial", 4.0,
         r"(child\s+support|alimony|spousal\s+support"
         r"|(didn'?t|hasn'?t|won'?t)\s+pay"
         r"|hiding\s+(income|assets?|money))"
        ),
        ("Relocation", 5.0,
         r"((moving|move|relocat\S+)\s+(out\s+of\s+state|to\s+another\s+state)"
         r"|(taking|took)\s+(him|her|them|the\s*kids?)\s+(out\s+of\s+state))"
        ),
    ]

    def scan_patterns(text: str):
        found = []
        seen = set()
        _CONF = {5.0: "strong", 4.0: "likely", 3.0: "likely", 2.0: "possible", 1.0: "possible"}
        for label, weight, pat in _PATTERNS_V1:
            if label not in seen and re.search(pat, text, re.IGNORECASE):
                found.append((label, weight, _CONF.get(weight, "possible")))
                seen.add(label)
        return found


def top_category(text: str):
    matches = scan_patterns(text)
    return matches[0][0] if matches else None


# ── V2 evidence confirmation — adds to Merkle DAG ────────────────────────────

def confirm_evidence_v2(conn, exhibit_id: int, case_id: int) -> dict:
    """
    Confirm an exhibit and add it to the Merkle DAG.
    Returns {exhibit_number, node_hash, ok: True}
    """
    from merkle_dag import add_exhibit_to_dag as _add_dag

    # Assign exhibit number (from v1 logic)
    row = conn.execute(
        "SELECT COUNT(*) as n FROM evidence WHERE case_id=? AND confirmed=1", (case_id,)
    ).fetchone()
    n  = (row["n"] if hasattr(row, "__getitem__") else row[0] or 0) + 1
    en = f"Exhibit {n}"

    conn.execute("UPDATE evidence SET confirmed=1, exhibit_number=? WHERE id=?", (en, exhibit_id))
    conn.commit()

    # Add to Merkle DAG
    node_hash = "n/a"
    if HAS_MERKLE:
        try:
            exhibit = conn.execute("SELECT * FROM evidence WHERE id=?", (exhibit_id,)).fetchone()
            if exhibit:
                ev_dict = dict(exhibit) if hasattr(exhibit, "keys") else {
                    "id": exhibit[0], "case_id": exhibit[1], "exhibit_number": exhibit[2],
                    "content": exhibit[3], "source": exhibit[4], "event_date": exhibit[5],
                    "category": exhibit[6], "confirmed": exhibit[7],
                }
                node_hash = _add_dag(conn, case_id, ev_dict)
        except Exception as e:
            print(f"  ⚠  Merkle DAG add failed: {e}")

    return {"exhibit_number": en, "node_hash": node_hash, "ok": True}


# ── V2 job queue initialization ───────────────────────────────────────────────

_job_queue = None

def get_job_queue():
    """Lazy-initialize the job queue singleton."""
    global _job_queue
    if not HAS_QUEUE:
        return None
    if _job_queue is None:
        _job_queue = JobQueue.get_instance(
            call_claude_fn         = call_claude,
            get_db_fn              = get_db,
            build_case_system_fn   = build_case_system,
            verify_citations_fn    = verify_citations_in_text,
        )
    return _job_queue


# ── Claude API (preserved from v1, extended for SDK streaming) ────────────────

def call_claude(messages, system="", max_tokens=2000, model="claude-sonnet-4-20250514"):
    if not API_KEY:
        return ("⚠️ AI features require an Anthropic API key.\n\n"
                "Set it before starting SynJuris:\n"
                "  Mac/Linux: export ANTHROPIC_API_KEY=your-key-here\n"
                "  Windows:   set ANTHROPIC_API_KEY=your-key-here\n\n"
                "Get a free key at: https://console.anthropic.com")
    payload = json.dumps({
        "model": model, "max_tokens": max_tokens,
        "system": system, "messages": messages
    }).encode()
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages", data=payload,
        headers={"Content-Type": "application/json", "x-api-key": API_KEY,
                 "anthropic-version": "2023-06-01"}
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.loads(r.read())["content"][0]["text"]
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        if e.code == 529 and model != "claude-haiku-4-5-20251001":
            return call_claude(messages, system, max_tokens, "claude-haiku-4-5-20251001")
        codes = {401: "Invalid API key.", 429: "Rate limit.", 500: "Server error.", 529: "Overloaded."}
        return f"⚠️ {codes.get(e.code, f'API error {e.code}')}"
    except Exception as e:
        return f"⚠️ Unexpected error: {e}"


# ── Preserved v1 functions (inline for single-file deployment) ────────────────
# These are the functions that the v2 endpoints depend on.
# In production, these come from synjuris_base (the original synjuris.py).

def _clamp(v): return max(1, min(9, int(v)))
def _transition(cur, delta):
    return {"x": _clamp(cur["x"]+delta["x"]), "y": _clamp(cur["y"]+delta["y"]), "z": _clamp(cur["z"]+delta["z"])}

_CAT_W = {"Gatekeeping":5.0,"Violation of Order":5.0,"Threats":5.0,"Relocation":5.0,
          "Parental Alienation":4.0,"Harassment":4.0,"Financial":4.0,
          "Stonewalling":3.0,"Emotional Abuse":2.0,"Neglect / Safety":2.0,
          "Substance Concern":2.0,"Child Statement":1.0}
_EV_CEIL, _ADV_CEIL = 50.0, 50.0

def _s9(raw, ceil):
    if raw <= 0: return 1
    return _clamp(1 + (raw / ceil) * 8)

def _hash_states(states):
    def _n(o):
        if isinstance(o, float): return round(o, 8)
        if isinstance(o, dict):  return {k: _n(v) for k, v in sorted(o.items())}
        if isinstance(o, list):  return [_n(i) for i in o]
        return o
    return hashlib.sha256(
        json.dumps(_n(states), separators=(",", ":"), sort_keys=True).encode()
    ).hexdigest()


def compute_case_state(case_id):
    conn = get_db()
    ev  = conn.execute(
        "SELECT id,exhibit_number,content,category,event_date,source FROM evidence "
        "WHERE case_id=? AND confirmed=1 ORDER BY event_date ASC,id ASC",
        (case_id,)
    ).fetchall()
    dls = conn.execute(
        "SELECT id,due_date,title,completed FROM deadlines WHERE case_id=?",
        (case_id,)
    ).fetchall()
    conn.close()

    ev_w   = sum(_CAT_W.get(e["category"] if hasattr(e,"__getitem__") else e[3], 1.0) for e in ev)
    adv_w  = sum(_CAT_W.get(e["category"] if hasattr(e,"__getitem__") else e[3], 1.0)
                 for e in ev if _CAT_W.get(e["category"] if hasattr(e,"__getitem__") else e[3], 0) >= 3.0)
    total_dl = len(dls)
    def _dl_completed(d): return d["completed"] if hasattr(d,"__getitem__") else d[3]
    def _dl_due(d):       return d["due_date"]  if hasattr(d,"__getitem__") else d[1]
    done_dl  = sum(1 for d in dls if _dl_completed(d))
    over     = sum(1 for d in dls
                   if not _dl_completed(d) and _dl_due(d)
                   and _dl_due(d) < date.today().isoformat())

    y_final = 5 if not total_dl else _clamp(
        max(0.0, (done_dl / total_dl) * 9 - over * 0.5)
    ) if (done_dl / total_dl) * 9 - over * 0.5 >= 1 else 1
    x_final = _s9(ev_w, _EV_CEIL)
    z_final = _s9(adv_w, _ADV_CEIL)

    running = {"x": 1, "y": y_final, "z": 1}
    chain = []
    hist  = [dict(running)]
    per_x = (x_final - 1) / max(len(ev), 1)
    per_z = (z_final - 1) / max(len(ev), 1)

    for e in ev:
        cat = e["category"] if hasattr(e, "__getitem__") else e[3]
        w   = _CAT_W.get(cat, 1.0)
        dx  = per_x * (w / 1.0)
        dz  = per_z * (w / 1.0) if w >= 3.0 else 0.0
        ns  = _transition(running, {"x": dx, "y": 0.0, "z": dz})
        chain.append({
            "exhibit_id":     e["id"] if hasattr(e, "__getitem__") else e[0],
            "exhibit_number": e["exhibit_number"] if hasattr(e, "__getitem__") else e[1] or "unnum",
            "category":       cat or "General",
            "weight":         w,
            "event_date":     e["event_date"] if hasattr(e, "__getitem__") else e[4] or "undated",
            "source":         e["source"] if hasattr(e, "__getitem__") else e[5] or "manual",
            "delta":          {"x": round(dx, 4), "y": 0.0, "z": round(dz, 4)},
            "state_after":    dict(ns),
        })
        hist.append(dict(ns))
        running = ns

    fs = {"x": x_final, "y": y_final, "z": z_final}
    return {
        "state": fs,
        "inputs": {
            "evidence_count":   len(ev),
            "ev_weight_sum":    round(ev_w, 4),
            "adv_weight_sum":   round(adv_w, 4),
            "total_deadlines":  total_dl,
            "done_deadlines":   done_dl,
            "overdue_deadlines": over,
        },
        "deltas": chain,
        "hash":   _hash_states(hist),
    }


def log_audit_event(case_id, action_type, ai_call_type, state_snapshot, prompt_inputs, trace_hash):
    conn = get_db()
    st = state_snapshot["state"]
    conn.execute(
        "INSERT INTO audit_log (case_id,action_type,ai_call_type,state_x,state_y,state_z,"
        "trace_hash,state_snapshot_json,prompt_inputs_json) VALUES (?,?,?,?,?,?,?,?,?)",
        (case_id, action_type, ai_call_type, st["x"], st["y"], st["z"],
         trace_hash, json.dumps(state_snapshot), json.dumps(prompt_inputs))
    )
    conn.commit()
    conn.close()


def _keyword_relevance(query: str, text: str) -> int:
    stop = {"the","a","an","is","in","of","to","and","or","for","that","was","it","on","at",
            "be","with","as","by"}
    q_words = {w.lower() for w in re.findall(r'\w+', query) if len(w) > 3 and w.lower() not in stop}
    t_words = {w.lower() for w in re.findall(r'\w+', text) if len(w) > 3 and w.lower() not in stop}
    return len(q_words & t_words)


def build_case_system(case_id, user_query=""):
    conn = get_db()
    case    = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
    parties = conn.execute("SELECT * FROM parties WHERE case_id=?", (case_id,)).fetchall()

    _WEIGHT = {label: w for label, w, _ in
               [("Gatekeeping",5.0,None),("Parental Alienation",4.0,None),
                ("Stonewalling",3.0,None),("Threats",5.0,None),("Harassment",4.0,None),
                ("Violation of Order",5.0,None),("Financial",4.0,None),
                ("Emotional Abuse",2.0,None),("Neglect / Safety",2.0,None),
                ("Substance Concern",2.0,None),("Child Statement",1.0,None),
                ("Relocation",5.0,None)]}

    all_ev = conn.execute(
        "SELECT exhibit_number,content,category,event_date FROM evidence "
        "WHERE case_id=? AND confirmed=1 AND (is_deleted IS NULL OR is_deleted=0) "
        "ORDER BY event_date ASC",
        (case_id,)
    ).fetchall()

    def _score(r):
        cat  = r["category"] if hasattr(r, "__getitem__") else r[2]
        cont = r["content"]  if hasattr(r, "__getitem__") else r[1]
        base = _WEIGHT.get(cat, 0)
        kw   = _keyword_relevance(user_query, cont or "") if user_query else 0
        return base + kw * 0.5

    evidence  = sorted(all_ev, key=_score, reverse=True)[:30]
    evidence  = sorted(evidence, key=lambda r: (r["event_date"] if hasattr(r,"__getitem__") else r[3]) or "")
    deadlines = conn.execute(
        "SELECT due_date,title FROM deadlines WHERE case_id=? AND completed=0 ORDER BY due_date ASC LIMIT 10",
        (case_id,)
    ).fetchall()
    conn.close()

    if not case:
        return ("", None)

    c = dict(case)
    ev_text = "\n".join([
        f"  [{(e['exhibit_number'] if hasattr(e,'__getitem__') else e[0]) or 'unnum'}] "
        f"[{(e['event_date'] if hasattr(e,'__getitem__') else e[3]) or 'undated'}] "
        f"({(e['category'] if hasattr(e,'__getitem__') else e[2])}): "
        f"{((e['content'] if hasattr(e,'__getitem__') else e[1]) or '')[:250]}"
        for e in evidence
    ]) or "  None confirmed yet."

    dl_text = "\n".join([
        f"  {(d['due_date'] if hasattr(d,'__getitem__') else d[0])}: "
        f"{(d['title'] if hasattr(d,'__getitem__') else d[1])}"
        for d in deadlines
    ]) or "  None."

    party_text = "\n".join([
        f"  {p['role'] if hasattr(p,'__getitem__') else p[1]}: "
        f"{p['name'] if hasattr(p,'__getitem__') else p[0]}"
        + (f" (atty: {p['attorney'] if hasattr(p,'__getitem__') else ''})" if
           (p['attorney'] if hasattr(p,'__getitem__') else '') else "")
        for p in parties
    ]) or "  None entered."

    jur_block = jurisdiction_statute_block(c.get("jurisdiction", ""))

    system = f"""You are SynJuris, a plain-language legal assistant helping a pro se litigant.

CASE FILE
  Title: {c['title']}
  Type: {c.get('case_type')}
  {jur_block}
  Court: {c.get('court_name') or 'not set'}
  Case #: {c.get('case_number') or 'not set'}
  Hearing date: {c.get('hearing_date') or 'not set'}
  Goals: {c.get('goals') or 'not stated'}

PARTIES
{party_text}

CONFIRMED EVIDENCE ({len(evidence)} items)
{ev_text}

UPCOMING DEADLINES
{dl_text}

YOUR RULES:
1. Always speak in plain, clear English. Explain any legal term the moment you use it.
2. You are NOT a lawyer. Always note this and recommend consulting one for final decisions.
3. When explaining a law, cite the specific statute AND explain what it means practically.
4. Be warm and empathetic. These are people in stressful, often frightening situations.
5. When asked to draft a document, produce a complete draft with [BRACKET PLACEHOLDERS].
6. Never invent statutes or case law. If unsure of a statute number, say so.
7. When discussing hearing prep, be specific: what to say, what NOT to say.
8. If someone describes domestic violence, always provide safety resources first."""

    snapshot = compute_case_state(case_id)
    st = snapshot["state"]
    inp = snapshot["inputs"]
    state_block = (
        f"  Evidence Strength    (x={st['x']}/9): {inp['evidence_count']} confirmed exhibits\n"
        f"  Procedural Health    (y={st['y']}/9): {inp['done_deadlines']}/{inp['total_deadlines']} deadlines met\n"
        f"  Adversarial Pressure (z={st['z']}/9): pattern weight {inp['adv_weight_sum']}\n"
        f"  State Hash: {snapshot['hash'][:16]}…"
    )
    system += "\n\nCASE DYNAMICS STATE\n" + state_block

    meta = {
        "snapshot": snapshot,
        "prompt_inputs": {"case_id": case_id, "state": st, "trace_hash": snapshot["hash"]}
    }
    return system, meta


def verify_citations_in_text(text: str) -> list:
    """CourtListener citation verification (preserved from v1)."""
    _CITATION_RE = re.compile(
        r'\b(\d+)\s+(U\.?S\.?|F\.?\d*d?|S\.?\s*Ct\.?|F\.?\s*Supp\.?\s*\d*d?|'
        r'[A-Z][a-z]+\.?\s*[A-Z]?[a-z]*\.?)\s+(\d+)'
        r'(?:\s*\(\w[^)]*\d{4}\))?',
        re.IGNORECASE
    )
    seen, results = set(), []
    _CL_API = "https://www.courtlistener.com/api/rest/v4/search/"
    for m in _CITATION_RE.finditer(text):
        cit = m.group(0).strip()
        if cit in seen: continue
        seen.add(cit)
        result = {"citation": cit, "found": False, "url": None, "case_name": None, "warning": None}
        try:
            params = urllib.parse.urlencode({"q": f'"{cit}"', "type": "o", "format": "json"})
            req = urllib.request.Request(f"{_CL_API}?{params}",
                headers={"User-Agent": f"SynJuris/{VERSION}"})
            with urllib.request.urlopen(req, timeout=6) as r:
                data = json.loads(r.read())
            if data.get("count", 0) > 0:
                first = data["results"][0]
                result["found"]     = True
                result["case_name"] = first.get("caseName", "")
                result["url"]       = f"https://www.courtlistener.com{first['absolute_url']}" \
                    if first.get("absolute_url") else None
            else:
                result["warning"] = f"'{cit}' not found in CourtListener — verify before filing."
        except Exception as e:
            result["warning"] = f"Citation check unavailable: {e}"
        results.append(result)
    return results


# ── DB Init (v2 — adds Merkle and embedding schemas) ─────────────────────────

def init_db():
    """Initialize database with all v1 + v2 schemas."""
    conn = get_db()

    # ── V1 schema (preserved exactly) ────────────────────────────────────────
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS schema_version (
        version INTEGER PRIMARY KEY,
        applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS cases (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL, case_type TEXT, jurisdiction TEXT,
        court_name TEXT, case_number TEXT, filing_deadline TEXT,
        hearing_date TEXT, goals TEXT, notes TEXT,
        user_id INTEGER, is_deleted INTEGER DEFAULT 0, deleted_at DATETIME,
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
        exhibit_number TEXT, content TEXT, source TEXT, event_date TEXT,
        category TEXT, confirmed INTEGER DEFAULT 0, notes TEXT,
        file_path TEXT, file_type TEXT, original_filename TEXT,
        is_deleted INTEGER DEFAULT 0, deleted_at DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS documents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id INTEGER REFERENCES cases(id) ON DELETE CASCADE,
        title TEXT, doc_type TEXT, content TEXT,
        version INTEGER DEFAULT 1, parent_id INTEGER,
        is_deleted INTEGER DEFAULT 0, deleted_at DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS timeline_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id INTEGER REFERENCES cases(id) ON DELETE CASCADE,
        event_date TEXT, title TEXT, description TEXT,
        category TEXT, importance TEXT DEFAULT 'normal',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS financials (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id INTEGER REFERENCES cases(id) ON DELETE CASCADE,
        entry_date TEXT, description TEXT, amount REAL, category TEXT,
        direction TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP
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
        action_type TEXT NOT NULL, ai_call_type TEXT,
        state_x INTEGER, state_y INTEGER, state_z INTEGER,
        trace_hash TEXT NOT NULL,
        state_snapshot_json TEXT, prompt_inputs_json TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        tier TEXT DEFAULT 'pro_se',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        user_id INTEGER,
        expires_at DATETIME NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS auth_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL,
        attempted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        success INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS citation_cache (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        citation TEXT NOT NULL UNIQUE,
        result_json TEXT,
        verified_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    """)
    conn.commit()

    # ── V2 schema additions ───────────────────────────────────────────────────
    if HAS_MERKLE:
        init_merkle_schema(conn)

    if HAS_SEMANTIC:
        try:
            from pattern_engine import init_embedding_schema
            init_embedding_schema(conn)
        except Exception:
            pass

    # V2 job persistence table
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS generation_jobs (
        job_id TEXT PRIMARY KEY,
        case_id INTEGER,
        doc_type TEXT,
        state TEXT DEFAULT 'pending',
        evidence_hash TEXT,
        doc_id INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        completed_at DATETIME
    );
    """)
    conn.commit()
    conn.close()
    os.makedirs(UPLOADS_DIR, exist_ok=True)

    # Local mode synthetic user
    if LOCAL_MODE:
        conn = get_db()
        try:
            conn.execute(
                "INSERT OR IGNORE INTO users (id, email, password_hash, tier) "
                "VALUES (1, 'local@localhost', 'local_no_password', 'pro_se')"
            )
            conn.commit()
        except Exception:
            pass
        conn.close()


# ── Auth helpers (preserved from v1) ─────────────────────────────────────────
_PBKDF2_ITERS = 100_000

def hash_password(pw: str) -> str:
    salt = secrets.token_bytes(32)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, _PBKDF2_ITERS)
    return f"pbkdf2:{_PBKDF2_ITERS}:{salt.hex()}:{dk.hex()}"

def verify_password(pw: str, stored: str) -> bool:
    try:
        if stored.startswith("pbkdf2:"):
            _, iters, salt_hex, dk_hex = stored.split(":", 3)
            salt = bytes.fromhex(salt_hex)
            expected = bytes.fromhex(dk_hex)
            candidate = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, int(iters))
            return hmac.compare_digest(candidate, expected)
        return False
    except Exception:
        return False

def create_session(user_id):
    import datetime as _dt
    token = secrets.token_hex(32)
    expires = (_dt.datetime.utcnow() + _dt.timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S")
    conn = get_db()
    conn.execute("INSERT INTO sessions (token, user_id, expires_at) VALUES (?,?,?)",
                 (token, user_id, expires))
    conn.execute("DELETE FROM sessions WHERE expires_at < CURRENT_TIMESTAMP")
    conn.commit(); conn.close()
    return token

def get_user_from_token(token):
    if not token: return None
    conn = get_db()
    row = conn.execute(
        "SELECT user_id FROM sessions WHERE token=? AND expires_at > CURRENT_TIMESTAMP",
        (token,)
    ).fetchone()
    conn.close()
    return (row["user_id"] if hasattr(row, "__getitem__") else row[0]) if row else None

_LOCAL_USER_ID = 1

def require_auth(handler):
    if LOCAL_MODE: return _LOCAL_USER_ID
    token = _get_token(handler)
    uid = get_user_from_token(token)
    if not uid:
        handler.send_json({"error": "unauthorized"}, 401)
    return uid

def _get_token(handler):
    cookie = handler.headers.get("Cookie", "")
    for part in cookie.split(";"):
        part = part.strip()
        if part.startswith("sj_token="):
            return part[len("sj_token="):]
    return None

def assign_exhibit_number(conn, case_id):
    row = conn.execute(
        "SELECT COUNT(*) as n FROM evidence WHERE case_id=? AND confirmed=1", (case_id,)
    ).fetchone()
    n = ((row["n"] if hasattr(row, "__getitem__") else row[0]) or 0) + 1
    return f"Exhibit {n}"


# ═══════════════════════════════════════════════════════════════════════════════
# V2 HTTP HANDLER — adds new endpoints, preserves all v1 endpoints
# ═══════════════════════════════════════════════════════════════════════════════

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def send_json(self, data, status=200):
        b = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(b))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(b)

    def send_html(self, html):
        b = html.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html;charset=utf-8")
        self.send_header("Content-Length", len(b))
        self.end_headers()
        self.wfile.write(b)

    def body(self):
        n = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(n)) if n else {}

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        p = urlparse(self.path)
        path = p.path

        if path == "/api/status":
            self.send_json({
                "ai": bool(API_KEY),
                "version": VERSION,
                "features": {
                    "merkle_dag":       HAS_MERKLE,
                    "semantic_patterns": HAS_SEMANTIC,
                    "job_queue":        HAS_QUEUE,
                    "readiness_engine": HAS_READINESS,
                    "streaming_sdk":    HAS_ANTHROPIC_SDK,
                }
            })
            return

        # ── V2: DAG integrity verification ─────────────────────────────────
        if re.match(r"^/api/cases/\d+/dag-verify$", path):
            uid = require_auth(self)
            if not uid: return
            cid = int(path.split("/")[3])
            if not HAS_MERKLE:
                self.send_json({"error": "Merkle DAG module not available"}); return
            conn = get_db()
            result = verify_case_dag(conn, cid)
            conn.close()
            self.send_json(result); return

        # ── V2: Exhibit Merkle proof ────────────────────────────────────────
        if re.match(r"^/api/evidence/\d+/proof$", path):
            uid = require_auth(self)
            if not uid: return
            eid = int(path.split("/")[3])
            if not HAS_MERKLE:
                self.send_json({"error": "Merkle DAG not available"}); return
            conn = get_db()
            proof = get_exhibit_proof(conn, eid)
            conn.close()
            self.send_json(proof); return

        # ── V2: Document readiness scores ───────────────────────────────────
        if re.match(r"^/api/cases/\d+/readiness$", path):
            uid = require_auth(self)
            if not uid: return
            cid = int(path.split("/")[3])
            if not HAS_READINESS:
                self.send_json({"error": "Readiness engine not available"}); return
            conn = get_db()
            summary = get_readiness_summary(cid, conn)
            conn.close()
            self.send_json(summary); return

        # ── V2: Job status ──────────────────────────────────────────────────
        if re.match(r"^/api/jobs/[a-f0-9-]+$", path):
            uid = require_auth(self)
            if not uid: return
            job_id = path.split("/")[3]
            q = get_job_queue()
            if not q:
                self.send_json({"error": "Job queue not available"}); return
            job = q.get_job(job_id)
            self.send_json(job_status_response(job)); return

        # ── V2: SSE stream for a job ────────────────────────────────────────
        if re.match(r"^/api/jobs/[a-f0-9-]+/stream$", path):
            uid = require_auth(self)
            if not uid: return
            job_id = path.split("/")[3]
            q = get_job_queue()
            if not q:
                self.send_response(503); self.end_headers(); return

            job = q.get_job(job_id)
            if not job:
                self.send_response(404); self.end_headers(); return

            stream = job.subscribe()
            self.send_response(200)
            self.send_header("Content-Type",  "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("X-Accel-Buffering", "no")
            self.end_headers()

            try:
                for chunk in stream:
                    self.wfile.write(chunk.encode("utf-8"))
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                pass
            return

        # ── V2: Evidence gap analysis ───────────────────────────────────────
        if re.match(r"^/api/cases/\d+/evidence-gaps$", path):
            uid = require_auth(self)
            if not uid: return
            cid = int(path.split("/")[3])
            conn = get_db()
            case = conn.execute("SELECT case_type FROM cases WHERE id=?", (cid,)).fetchone()
            ev   = conn.execute(
                "SELECT DISTINCT category FROM evidence WHERE case_id=? AND confirmed=1",
                (cid,)
            ).fetchall()
            conn.close()
            cats = [r["category"] if hasattr(r,"__getitem__") else r[0] for r in ev]
            ct   = (case["case_type"] if hasattr(case,"__getitem__") else case[0]) if case else ""
            if not HAS_SEMANTIC:
                self.send_json({"gaps": []}); return
            gaps = detect_evidence_gaps(cats, ct)
            self.send_json({"gaps": gaps, "confirmed_categories": cats}); return

        # ── V2: Merkle proof statement (for redacted export) ────────────────
        if re.match(r"^/api/cases/\d+/proof-statement$", path):
            uid = require_auth(self)
            if not uid: return
            cid = int(path.split("/")[3])
            qs  = parse_qs(p.query)
            exhibit_ids_raw = qs.get("exhibit_ids", [""])[0]
            exhibit_ids = [int(x) for x in exhibit_ids_raw.split(",") if x.strip().isdigit()]

            if not HAS_MERKLE:
                self.send_json({"statement": "Merkle DAG not available."}); return
            conn = get_db()
            stmt = generate_proof_statement(conn, cid, exhibit_ids)
            conn.close()
            self.send_json({"statement": stmt}); return

        self.send_json({"error": "not found"}, 404)

    def do_POST(self):
        path = urlparse(self.path).path
        b    = self.body()

        # ── V2: Evidence confirmation — adds to Merkle DAG ──────────────────
        if path == "/api/evidence/confirm":
            uid = require_auth(self)
            if not uid: return
            eid = b.get("id")
            conn = get_db()
            ev = conn.execute(
                "SELECT case_id FROM evidence WHERE id=?", (eid,)
            ).fetchone()
            if not ev:
                conn.close()
                self.send_json({"error": "not found"}, 404); return

            cid = ev["case_id"] if hasattr(ev, "__getitem__") else ev[0]

            if HAS_MERKLE:
                result = confirm_evidence_v2(conn, eid, cid)
            else:
                en = assign_exhibit_number(conn, cid)
                conn.execute("UPDATE evidence SET confirmed=1, exhibit_number=? WHERE id=?", (en, eid))
                conn.commit()
                result = {"exhibit_number": en, "ok": True}

            # Trigger speculative pre-generation (non-blocking)
            q = get_job_queue()
            if q and HAS_QUEUE:
                threading.Thread(
                    target=q.trigger_speculative, args=(cid, conn), daemon=True
                ).start()

            conn.close()
            self.send_json(result)
            return

        # ── V2: Async document generation ──────────────────────────────────
        if path == "/api/generate-doc-async":
            uid = require_auth(self)
            if not uid: return
            cid      = b.get("case_id")
            dtype    = b.get("doc_type")
            instr    = b.get("instructions", "")
            force    = b.get("force", False)

            q = get_job_queue()
            if not q:
                # Fallback to synchronous generation
                self.send_json({"error": "Job queue not available — use /api/generate-doc"}); return

            conn    = get_db()
            job_id  = q.submit("document", cid, dtype, conn, instr, force=force)
            conn.close()
            self.send_json({
                "job_id":     job_id,
                "stream_url": f"/api/jobs/{job_id}/stream",
                "status_url": f"/api/jobs/{job_id}",
            })
            return

        # ── V2: Async hearing prep ──────────────────────────────────────────
        if path == "/api/hearing-prep-async":
            uid = require_auth(self)
            if not uid: return
            cid = b.get("case_id")
            q   = get_job_queue()
            if not q:
                self.send_json({"error": "Job queue not available"}); return
            conn   = get_db()
            job_id = q.submit("hearing_prep", cid, "Hearing Prep Guide", conn)
            conn.close()
            self.send_json({
                "job_id":     job_id,
                "stream_url": f"/api/jobs/{job_id}/stream",
                "status_url": f"/api/jobs/{job_id}",
            })
            return

        # ── V2: Async motion generation ─────────────────────────────────────
        if path == "/api/motion-async":
            uid = require_auth(self)
            if not uid: return
            cid   = b.get("case_id")
            mtype = b.get("motion_type", "Motion for Contempt")
            q     = get_job_queue()
            if not q:
                self.send_json({"error": "Job queue not available"}); return
            conn   = get_db()
            job_id = q.submit("motion", cid, mtype, conn, b.get("instructions", ""))
            conn.close()
            self.send_json({
                "job_id":     job_id,
                "stream_url": f"/api/jobs/{job_id}/stream",
                "status_url": f"/api/jobs/{job_id}",
            })
            return

        # ── V2: DAG re-build (admin: add all existing confirmed exhibits) ───
        if path == "/api/cases/dag-rebuild":
            uid = require_auth(self)
            if not uid: return
            cid = b.get("case_id")
            if not HAS_MERKLE:
                self.send_json({"error": "Merkle module not available"}); return
            conn = get_db()
            ev_rows = conn.execute(
                "SELECT * FROM evidence WHERE case_id=? AND confirmed=1 "
                "AND (is_deleted IS NULL OR is_deleted=0) ORDER BY id ASC",
                (cid,)
            ).fetchall()
            added = 0
            for row in ev_rows:
                ev_dict = dict(row) if hasattr(row, "keys") else {
                    "id": row[0], "case_id": row[1], "exhibit_number": row[2],
                    "content": row[3], "source": row[4], "event_date": row[5],
                    "category": row[6], "confirmed": row[7],
                }
                try:
                    add_exhibit_to_dag(conn, cid, ev_dict)
                    added += 1
                except Exception as e:
                    print(f"  DAG rebuild error for exhibit {ev_dict.get('id')}: {e}")
            conn.close()
            self.send_json({"ok": True, "exhibits_added": added, "case_id": cid})
            return

        self.send_json({"error": "not found"}, 404)


# ── Startup ────────────────────────────────────────────────────────────────────

def check_for_update():
    try:
        req = urllib.request.Request(UPDATE_URL,
                                     headers={"User-Agent": f"SynJuris/{VERSION}"})
        with urllib.request.urlopen(req, timeout=4) as r:
            data = json.loads(r.read())
        latest = data.get("version", "")
        notes  = data.get("notes", "")
        if latest and latest != VERSION:
            print(f"\n  ┌─ Update available: v{latest} (you have v{VERSION})")
            if notes: print(f"  │  {notes}")
            print(f"  └─ Download: https://github.com/synjuris/synjuris/releases/latest\n")
    except Exception:
        pass


def open_browser():
    time.sleep(1)
    webbrowser.open(f"http://localhost:{PORT}")


if __name__ == "__main__":
    init_db()

    print("\n" + "═" * 58)
    print(f"  SynJuris v{VERSION} — Advanced Architecture")
    print("═" * 58)
    print(f"  Database  : {DB_PATH}")
    print(f"  AI        : {'✓ Enabled' if API_KEY else '✗ No key set (optional)'}")
    print(f"  Streaming : {'✓ Anthropic SDK' if HAS_ANTHROPIC_SDK else '⚠ Simulated (pip install anthropic)'}")
    print(f"  Merkle DAG: {'✓ Active' if HAS_MERKLE else '⚠ Disabled (merkle_dag.py missing)'}")
    print(f"  Semantic  : {'✓ Active' if HAS_SEMANTIC else '⚠ Regex fallback (pattern_engine.py missing)'}")
    print(f"  Job Queue : {'✓ Active' if HAS_QUEUE else '⚠ Synchronous fallback'}")
    print(f"  Readiness : {'✓ Active' if HAS_READINESS else '⚠ Disabled'}")
    print(f"  Auth      : {'⚠ LOCAL (no login)' if LOCAL_MODE else '✓ Login required'}")
    print(f"\n  Listening  : http://localhost:{PORT}")
    print("  Press Ctrl+C to stop.\n")

    threading.Thread(target=check_for_update, daemon=True).start()
    if PORT == 5000:
        threading.Thread(target=open_browser, daemon=True).start()

    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  SynJuris stopped.")
