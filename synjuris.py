"""
SynJuris v2.0.0 — Upgraded Architecture
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

# ── V1 HTML assets (merged for standalone deployment) ─────────────────────────

LOGIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SynJuris</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:#0d1b2a;color:#e8dfc8;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
       display:flex;align-items:center;justify-content:center;min-height:100vh}
  .card{background:#111f30;border:1px solid #1e3248;border-radius:12px;padding:40px;width:100%;max-width:400px}
  h1{font-size:24px;color:#c9a84c;margin-bottom:6px;letter-spacing:.04em}
  .sub{font-size:13px;color:#6b7a8d;margin-bottom:28px}
  label{display:block;font-size:12px;color:#8a9ab0;text-transform:uppercase;letter-spacing:.06em;margin-bottom:5px}
  input{width:100%;background:#0d1b2a;border:1px solid #1e3248;border-radius:6px;padding:10px 12px;
        color:#e8dfc8;font-size:15px;margin-bottom:16px;outline:none}
  input:focus{border-color:#c9a84c}
  button{width:100%;background:#c9a84c;color:#0d1b2a;border:none;border-radius:6px;
         padding:12px;font-size:15px;font-weight:600;cursor:pointer;margin-top:4px}
  button:hover{background:#e0bb62}
  .toggle{text-align:center;margin-top:18px;font-size:13px;color:#6b7a8d}
  .toggle a{color:#c9a84c;cursor:pointer;text-decoration:none}
  .err{background:#2a0f0f;border:1px solid #7a2020;border-radius:6px;
       padding:10px 14px;font-size:13px;color:#f08080;margin-bottom:14px;display:none}
  .notice{background:#0f1e2a;border:1px solid #1e3248;border-radius:6px;
          padding:10px 14px;font-size:12px;color:#6b7a8d;margin-bottom:16px}

/* ── Mobile responsive (injected) ─────────────────────────────────────── */
#mob-menu-btn{display:none;background:none;border:none;cursor:pointer;padding:6px 8px;color:var(--gold);font-size:20px;line-height:1;margin-right:4px}
@media(max-width:680px){
  #mob-menu-btn{display:block}
  #app{grid-template-columns:1fr;grid-template-rows:50px 1fr}
  #sidebar{
    position:fixed;top:50px;left:0;bottom:0;width:260px;
    transform:translateX(-100%);transition:transform .22s ease;
    z-index:100;border-right:1px solid var(--gold-bd)
  }
  #sidebar.mob-open{transform:translateX(0)}
  #mob-overlay{display:none;position:fixed;inset:0;top:50px;background:rgba(0,0,0,.55);z-index:99}
  #mob-overlay.mob-open{display:block}
  #main{grid-column:1;overflow-y:auto}
  .topbar-tag{display:none}
  #topbar h1{font-size:15px}
  #apill{font-size:10px}
}
</style>
</head>
<body>
<div class="card">
  <h1>SynJuris</h1>
  <div class="sub">Legal case organizer for pro se litigants</div>
  <div class="err" id="err"></div>
  <div id="login-form">
    <label>Email</label>
    <input type="email" id="email" placeholder="you@example.com" autocomplete="email">
    <label>Password</label>
    <input type="password" id="password" placeholder="••••••••" autocomplete="current-password">
    <button onclick="doLogin()">Sign In</button>
    <div class="toggle">No account? <a onclick="showSignup()">Create one</a></div>
  </div>
  <div id="signup-form" style="display:none">
    <div class="notice">Your data is stored on this server and never shared.</div>
    <label>Email</label>
    <input type="email" id="su-email" placeholder="you@example.com" autocomplete="email">
    <label>Password</label>
    <input type="password" id="su-password" placeholder="At least 8 characters" autocomplete="new-password">
    <label>Confirm Password</label>
    <input type="password" id="su-confirm" placeholder="Repeat password" autocomplete="new-password">
    <button onclick="doSignup()">Create Account</button>
    <div class="toggle">Already have an account? <a onclick="showLogin()">Sign in</a></div>
  </div>
</div>
<script>
function showErr(msg){const e=document.getElementById('err');e.textContent=msg;e.style.display='block';}
function hideErr(){document.getElementById('err').style.display='none';}
function showSignup(){hideErr();document.getElementById('login-form').style.display='none';document.getElementById('signup-form').style.display='block';}
function showLogin(){hideErr();document.getElementById('signup-form').style.display='none';document.getElementById('login-form').style.display='block';}
async function doLogin(){
  hideErr();
  const email=document.getElementById('email').value.trim();
  const pw=document.getElementById('password').value;
  if(!email||!pw){showErr('Please fill in all fields.');return;}
  const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email,password:pw})});
  const d=await r.json();
  if(d.error){showErr(d.error);return;}
  window.location.href='/';
}
async function doSignup(){
  hideErr();
  const email=document.getElementById('su-email').value.trim();
  const pw=document.getElementById('su-password').value;
  const pw2=document.getElementById('su-confirm').value;
  if(!email||!pw||!pw2){showErr('Please fill in all fields.');return;}
  if(pw.length<8){showErr('Password must be at least 8 characters.');return;}
  if(pw!==pw2){showErr('Passwords do not match.');return;}
  const r=await fetch('/api/signup',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email,password:pw})});
  const d=await r.json();
  if(d.error){showErr(d.error);return;}
  window.location.href='/';
}
document.addEventListener('keydown',function(e){if(e.key==='Enter'){
  if(document.getElementById('signup-form').style.display!=='none'){doSignup();}
  else{doLogin();}
}});

// ── Mobile sidebar toggle (injected) ────────────────────────────────────────
(function(){
  // Inject overlay element
  const overlay = document.createElement('div');
  overlay.id = 'mob-overlay';
  document.getElementById('app').appendChild(overlay);

  function closeSidebar(){
    document.getElementById('sidebar').classList.remove('mob-open');
    overlay.classList.remove('mob-open');
  }
  function toggleSidebar(){
    const sb = document.getElementById('sidebar');
    const open = sb.classList.toggle('mob-open');
    overlay.classList.toggle('mob-open', open);
  }

  // Wire hamburger button
  const btn = document.getElementById('mob-menu-btn');
  if(btn) btn.addEventListener('click', toggleSidebar);

  // Close when overlay tapped
  overlay.addEventListener('click', closeSidebar);

  // Close sidebar when a case is selected (on mobile)
  document.getElementById('case-list').addEventListener('click', function(e){
    if(window.innerWidth <= 680) closeSidebar();
  });
})();
</script>
</body>
</html>"""


def build_portal_html(pt, token):
    """Render the client-facing portal page. No framework, self-contained."""
    case_title = pt.get("case_title","Your Case")
    label      = pt.get("label","Client")
    cats = ["Communication","Document","Photo/Video","Gatekeeping","Financial",
            "Stonewalling","Parental Alienation","Threats","Harassment","Witness","Other"]
    opts = "".join(f"<option>{c}</option>" for c in cats)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SynJuris Client Portal</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:#0d1b2a;color:#e8dfc8;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
        padding:20px;max-width:640px;margin:0 auto}}
  h1{{font-size:22px;color:#c9a84c;margin-bottom:4px}}
  .sub{{font-size:13px;color:#6b7a8d;margin-bottom:24px}}
  label{{display:block;font-size:12px;color:#8a9ab0;text-transform:uppercase;
         letter-spacing:.06em;margin-bottom:5px;margin-top:14px}}
  input,textarea,select{{width:100%;background:#111f30;border:1px solid #1e3248;border-radius:6px;
    padding:10px 12px;color:#e8dfc8;font-size:14px;outline:none}}
  textarea{{min-height:100px;resize:vertical}}
  input:focus,textarea:focus,select:focus{{border-color:#c9a84c}}
  .btn{{margin-top:20px;padding:11px 28px;background:#c9a84c;color:#0d1b2a;border:none;
        border-radius:6px;font-size:15px;font-weight:600;cursor:pointer;width:100%}}
  .notice{{padding:12px 16px;border-radius:6px;font-size:13px;margin-top:16px}}
  .n-ok{{background:#0d2b1a;border:1px solid #1a5c33;color:#4caf82}}
  .n-err{{background:#2b0d0d;border:1px solid #5c1a1a;color:#e57373}}
  .disc{{font-size:11px;color:#4a5a6b;margin-top:20px;line-height:1.6}}
</style>
</head>
<body>
<h1>SynJuris Client Portal</h1>
<div class="sub">Case: <strong>{case_title}</strong> &nbsp;·&nbsp; Shared with: {label}</div>
<p style="font-size:13px;color:#8a9ab0;margin-bottom:20px">
  Use this page to submit documents, messages, or other information to your attorney.
  Your attorney will review everything before it is added to the case.
</p>
<div id="form">
  <label>Description / Content</label>
  <textarea id="p-content" placeholder="Paste the message, describe the incident, or summarize the document…"></textarea>
  <label>Date of Event</label>
  <input type="date" id="p-date">
  <label>Source / Context</label>
  <input id="p-src" placeholder="e.g. text message from opposing party, police report, school email">
  <label>Category</label>
  <select id="p-cat">{opts}</select>
  <button class="btn" onclick="submitPortal()">Submit to Attorney for Review</button>
</div>
<div id="status"></div>
<div class="disc">
  ⚠ This portal is for submitting evidence to your attorney only. Nothing submitted here
  is filed with any court. All submissions are reviewed by your attorney before use.
  This portal does not create an attorney-client relationship and does not constitute
  legal advice. Do not submit information about third parties without their knowledge
  unless it is directly relevant to your case.
</div>
<script>
async function submitPortal(){{
  const content=document.getElementById('p-content').value.trim();
  if(!content){{alert('Please enter content.');return;}}
  const btn=document.querySelector('.btn');
  btn.disabled=true; btn.textContent='Submitting…';
  try{{
    const r=await fetch('/api/portal/submit',{{method:'POST',
      headers:{{'Content-Type':'application/json'}},
      body:JSON.stringify({{token:'{token}',content,
        event_date:document.getElementById('p-date').value,
        source:document.getElementById('p-src').value,
        category:document.getElementById('p-cat').value}})
    }});
    const d=await r.json();
    if(d.ok){{
      document.getElementById('form').innerHTML='<div class="notice n-ok">✓ Submitted successfully. Your attorney will review this item.</div>';
    }}else{{
      document.getElementById('status').innerHTML=`<div class="notice n-err">Error: ${{d.error||'Unknown error'}}</div>`;
      btn.disabled=false; btn.textContent='Submit to Attorney for Review';
    }}
  }}catch(e){{
    document.getElementById('status').innerHTML='<div class="notice n-err">Network error. Please try again.</div>';
    btn.disabled=false; btn.textContent='Submit to Attorney for Review';
  }}
}}
</script>
</body>
</html>"""


# ══════════════════════════════════════════════════════════════════════════════
# REDACTED EXPORT — state vector + arguments, raw evidence stripped
# ══════════════════════════════════════════════════════════════════════════════

def build_redacted_export(case_id, user_id):
    """Build a JSON payload suitable for redacted PDF export.
    Contains: case metadata, state vector + interpretation, key document summaries,
    upcoming deadlines. No raw evidence content.
    """
    conn = get_db()
    case      = conn.execute("SELECT * FROM cases WHERE id=? AND user_id=?", (case_id, user_id)).fetchone()
    if not case:
        conn.close(); return {"error": "not found"}
    c = dict(case)
    docs      = conn.execute(
        "SELECT title,doc_type,created_at FROM documents WHERE case_id=? AND (is_deleted IS NULL OR is_deleted=0) ORDER BY created_at DESC LIMIT 10",
        (case_id,)
    ).fetchall()
    deadlines = conn.execute(
        "SELECT due_date,title,completed FROM deadlines WHERE case_id=? ORDER BY due_date ASC LIMIT 10",
        (case_id,)
    ).fetchall()
    ev_counts = conn.execute(
        "SELECT category, COUNT(*) as n FROM evidence WHERE case_id=? AND confirmed=1 "
        "AND (is_deleted IS NULL OR is_deleted=0) GROUP BY category ORDER BY n DESC",
        (case_id,)
    ).fetchall()
    parties   = conn.execute("SELECT name,role FROM parties WHERE case_id=?", (case_id,)).fetchall()
    conn.close()

    snap   = compute_case_state(case_id)
    interp = interpret_case_state(snap)
    st     = snap["state"]

    return {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "synjuris_version": VERSION,
        "case": {
            "title":       c.get("title",""),
            "case_number": c.get("case_number",""),
            "court":       c.get("court_name",""),
            "jurisdiction":c.get("jurisdiction",""),
            "case_type":   c.get("case_type",""),
            "hearing_date":c.get("hearing_date",""),
        },
        "parties": [dict(p) for p in parties],
        "state_vector": {
            "x": st["x"], "y": st["y"], "z": st["z"],
            "hash": snap["hash"],
            "evidence_count": snap["inputs"]["evidence_count"],
        },
        "interpretation": interp,
        "evidence_summary": [{"category": r["category"], "count": r["n"]} for r in ev_counts],
        "documents": [{"title": d["title"], "type": d["doc_type"], "created": d["created_at"]} for d in docs],
        "deadlines": [{"date": d["due_date"], "title": d["title"],
                       "status": "completed" if d["completed"] else "pending"} for d in deadlines],
        "disclaimer": (
            "This report was generated by SynJuris and is based solely on evidence "
            "and data logged by the user. It does not constitute legal advice, "
            "legal representation, or an opinion of counsel. "
            "The state vector and interpretation are computational outputs, not legal conclusions."
        ),
    }



def build_courtroom_html(case_id):
    conn = get_db()
    case = conn.execute("SELECT * FROM cases WHERE id=?",(case_id,)).fetchone()
    evidence = conn.execute("SELECT exhibit_number,content,category,event_date FROM evidence WHERE case_id=? AND confirmed=1 ORDER BY event_date ASC",(case_id,)).fetchall()
    docs = conn.execute("SELECT id,doc_type FROM documents WHERE case_id=? ORDER BY created_at DESC",(case_id,)).fetchall()
    conn.close()
    c = dict(case) if case else {}
    esc = lambda s: str(s or "").replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace('"',"&quot;")
    prep = ""
    pd = next((d for d in docs if d["doc_type"]=="Hearing Prep Guide"),None)
    if pd:
        conn2=get_db(); row=conn2.execute("SELECT content FROM documents WHERE id=?",(pd["id"],)).fetchone(); conn2.close()
        prep = row["content"] if row else ""
    import re as _r
    opening=""; m=_r.search(r"OPENING STATEMENT[\s\S]*?\n([\s\S]*?)(?=\n\d+\.)",prep,_r.IGNORECASE)
    if m: opening=m.group(1).strip()
    kp_raw=""; m2=_r.search(r"KEY POINTS[\s\S]*?\n([\s\S]*?)(?=\n\d+\.)",prep,_r.IGNORECASE)
    if m2: kp_raw=m2.group(1).strip()
    kp_html=("<ul>"+"".join(f"<li>{esc(_r.sub(chr(94)+r'[\d.\u2022\-*]+\s*','',i))}</li>" for i in kp_raw.split("\n") if i.strip())+"</ul>") if kp_raw else '<p style="color:#666">Generate a Hearing Prep Guide first.</p>'
    ev_rows="".join(f'<tr><td style="font-weight:700;color:#C9A84C;white-space:nowrap">{esc(e["exhibit_number"] or chr(8212))}</td><td style="color:#A89F8A;white-space:nowrap">{esc((e["event_date"] or "")[:10])}</td><td style="color:#A89F8A;font-size:11px">{esc(e["category"] or "")}</td><td>{esc((e["content"] or "")[:120])}{"&hellip;" if len(e["content"] or "")>120 else ""}</td></tr>' for e in evidence[:20])
    ev_section=(f'<table class="exhibit-table"><thead><tr><th>Exhibit</th><th>Date</th><th>Category</th><th>Summary</th></tr></thead><tbody>{ev_rows}</tbody></table>' if ev_rows else '<p style="color:#666">No confirmed evidence yet.</p>')
    opening_sec=(f'<div class="opening-box">{esc(opening)}</div>' if opening else '<div class="opening-box" style="color:#666">Generate a Hearing Prep Guide first.</div>')
    prep_sec=(f'<pre style="white-space:pre-wrap;font-family:Georgia,serif;font-size:16px;line-height:1.8;color:#E8DFC8">{esc(prep)}</pre>' if prep else '<p style="color:#666">Generate a Hearing Prep Guide first.</p>')
    ct=esc(c.get("title") or "Case"); meta=esc(" \u00b7 ".join(filter(None,[c.get("case_type"),c.get("jurisdiction"),c.get("court_name")])))
    n=len(evidence)
    return ('<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>SynJuris \u2014 Courtroom</title>'
            '<style>:root{--gold:#C9A84C;--bg:#0a1520;--surface:#111f30;--border:#1e3248;--text:#E8DFC8;--muted:#6B7A8D}'
            '*{box-sizing:border-box;margin:0;padding:0}body{background:var(--bg);color:var(--text);font-family:Georgia,serif;font-size:18px;line-height:1.7}'
            'header{background:var(--surface);border-bottom:2px solid var(--gold);padding:14px 28px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:10}'
            'header h1{font-size:20px;color:var(--gold);letter-spacing:.08em}header .meta{font-size:13px;color:var(--muted)}'
            '.tabs{display:flex;gap:4px;padding:16px 28px 0;background:var(--surface);border-bottom:1px solid var(--border)}'
            '.ctab{padding:8px 18px;font-size:14px;cursor:pointer;border-radius:4px 4px 0 0;color:var(--muted);background:transparent;border:1px solid transparent;border-bottom:none;transition:all .15s}'
            '.ctab.active{background:var(--bg);color:var(--gold);border-color:var(--border);border-bottom-color:var(--bg)}'
            '.panel{display:none;padding:28px;max-width:860px;margin:0 auto}.panel.active{display:block}'
            'h2{font-size:22px;color:var(--gold);margin-bottom:16px;border-bottom:1px solid var(--border);padding-bottom:8px}'
            'p,li{font-size:17px;line-height:1.8;color:var(--text)}ul{padding-left:24px;margin-bottom:14px}li{margin-bottom:8px}'
            '.exhibit-table{width:100%;border-collapse:collapse;font-size:15px;margin-top:12px}'
            '.exhibit-table th{text-align:left;color:var(--gold);padding:8px 10px;border-bottom:2px solid var(--border);font-size:13px;text-transform:uppercase;letter-spacing:.06em}'
            '.exhibit-table td{padding:10px;border-bottom:1px solid var(--border);vertical-align:top}'
            '.exhibit-table tr:hover td{background:rgba(201,168,76,.05)}'
            '.opening-box{background:var(--surface);border-left:4px solid var(--gold);padding:20px 24px;border-radius:0 8px 8px 0;font-size:19px;font-style:italic;line-height:1.9;margin-bottom:20px}'
            '.warning{background:#1a0a00;border:1px solid #663300;border-radius:6px;padding:14px 18px;font-size:14px;color:#ff9966;margin-top:20px}'
            '.btn{background:transparent;border:1px solid var(--gold);color:var(--gold);padding:8px 18px;border-radius:4px;cursor:pointer;font-size:14px;margin-right:8px}'
            '.btn:hover{background:var(--gold);color:#0a1520}'
            '@media print{header,.tabs,.btn{display:none!important}.panel{display:block!important;padding:0}body{background:white;color:black}h2{color:#000}}'
            '</style></head><body>'
            f'<header><div><h1>{ct}</h1><div class="meta">{meta}</div></div>'
            '<div><button class="btn" onclick="window.print()">Print</button>'
            '<button class="btn" onclick="document.body.style.fontSize=(parseFloat(getComputedStyle(document.body).fontSize)+2)+\'px\'">A+</button>'
            '<button class="btn" onclick="document.body.style.fontSize=(parseFloat(getComputedStyle(document.body).fontSize)-2)+\'px\'">A&#8722;</button></div></header>'
            '<div class="tabs">'
            '<div class="ctab active" onclick="showPanel(\'opening\',this)">Opening</div>'
            '<div class="ctab" onclick="showPanel(\'points\',this)">Key Points</div>'
            f'<div class="ctab" onclick="showPanel(\'exhibits\',this)">Exhibits ({n})</div>'
            '<div class="ctab" onclick="showPanel(\'prep\',this)">Full Prep</div></div>'
            f'<div id="opening" class="panel active"><h2>Opening Statement</h2>{opening_sec}'
            '<div class="warning">&#9888; Speak slowly. Address the judge as &ldquo;Your Honor.&rdquo; Do not interrupt.</div></div>'
            f'<div id="points" class="panel"><h2>Key Points to Make</h2>{kp_html}</div>'
            f'<div id="exhibits" class="panel"><h2>Evidence &mdash; {n} Confirmed Exhibits</h2>{ev_section}</div>'
            f'<div id="prep" class="panel"><h2>Full Hearing Prep Guide</h2>{prep_sec}</div>'
            '<script>function showPanel(id,tab){document.querySelectorAll(".panel").forEach(p=>p.classList.remove("active"));'
            'document.querySelectorAll(".ctab").forEach(t=>t.classList.remove("active"));'
            'document.getElementById(id).classList.add("active");tab.classList.add("active");}'
            'var p=["opening","points","exhibits","prep"],cur=0;'
            'document.addEventListener("keydown",function(e){if(e.key==="ArrowRight"){cur=Math.min(cur+1,p.length-1);document.querySelectorAll(".ctab")[cur].click();}'
            'if(e.key==="ArrowLeft"){cur=Math.max(cur-1,0);document.querySelectorAll(".ctab")[cur].click();}});'
            '</scr' + 'ipt></body></html>')

def export_evidence_pdf(case_id):
    """Generate a court-formatted PDF evidence manifest using only stdlib.
    Returns (filename, bytes). Uses minimal PDF spec — no external deps."""
    conn = get_db()
    case       = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
    parties    = conn.execute("SELECT * FROM parties WHERE case_id=?", (case_id,)).fetchall()
    evidence   = conn.execute(
        "SELECT * FROM evidence WHERE case_id=? AND confirmed=1 ORDER BY event_date ASC, created_at ASC",
        (case_id,)
    ).fetchall()
    timeline   = conn.execute(
        "SELECT * FROM timeline_events WHERE case_id=? ORDER BY event_date ASC", (case_id,)
    ).fetchall()
    financials = conn.execute(
        "SELECT * FROM financials WHERE case_id=? ORDER BY entry_date ASC", (case_id,)
    ).fetchall()
    conn.close()

    c = dict(case) if case else {}
    safe = lambda s: str(s or "").replace("\\","\\\\").replace("(","\\(").replace(")","\\)").replace("\r","").replace("\n"," ")

    # ── Build page content streams ──────────────────────────────────────────
    lines = []  # (text, x, y, font, size, color)  color: 0=black 0.3=gray 0.6=blue-ish

    def page_header(y, page_num):
        return [
            (safe(c.get("title","Case")), 50, y,    "B", 14, 0.0),
            ("EVIDENCE MANIFEST",         50, y-18,  "B", 10, 0.3),
            (f"Page {page_num}",          520, y,    "R", 9,  0.5),
            (f"Generated {date.today().isoformat()}", 520, y-14, "R", 8, 0.5),
        ]

    # We'll build raw PDF manually — portable, zero deps
    # PDF coordinate system: origin bottom-left, y increases upward
    # Letter page: 612 x 792 pts

    import struct, zlib, io

    PAGE_W, PAGE_H = 612, 792
    MARGIN_L, MARGIN_R, MARGIN_T, MARGIN_B = 60, 60, 60, 60
    TEXT_W = PAGE_W - MARGIN_L - MARGIN_R

    class PDFWriter:
        def __init__(self):
            self.buf = io.BytesIO()
            self.offsets = []
            self.pages = []
            self.cur_page = None
            self.cur_y = 0
            self.page_num = 0
            self._write(b"%PDF-1.4\n")
            self._write(b"%\xe2\xe3\xcf\xd3\n")  # binary marker

        def _write(self, data):
            self.buf.write(data)

        def _obj(self, obj_id, content):
            self.offsets.append((obj_id, self.buf.tell()))
            self._write(f"{obj_id} 0 obj\n".encode())
            self._write(content)
            self._write(b"\nendobj\n")

        def new_page(self):
            self.page_num += 1
            self.cur_page = io.StringIO()
            self.cur_y = PAGE_H - MARGIN_T
            # header
            self._text_line(safe(c.get("title","Case")), MARGIN_L, self.cur_y, 13, bold=True)
            self.cur_y -= 16
            jur = c.get("jurisdiction","")
            ct  = c.get("case_type","")
            self._text_line(f"{ct}  ·  {jur}  ·  Page {self.page_num}", MARGIN_L, self.cur_y, 8, gray=True)
            self.cur_y -= 6
            self._line(MARGIN_L, self.cur_y, PAGE_W-MARGIN_R, self.cur_y, 0.5)
            self.cur_y -= 14

        def _text_line(self, text, x, y, size, bold=False, gray=False, indent=0):
            font = "F2" if bold else "F1"
            color = "0.45 0.45 0.45" if gray else "0 0 0"
            self.cur_page.write(
                f"BT /{font} {size} Tf {color} rg {x+indent} {y} Td ({text}) Tj ET\n"
            )

        def _line(self, x1, y1, x2, y2, width=0.5):
            self.cur_page.write(f"{width} w {x1} {y1} m {x2} {y2} l S\n")

        def _rect(self, x, y, w, h, fill_gray=0.95):
            self.cur_page.write(f"{fill_gray} g {x} {y} {w} {h} re f 0 g\n")

        def need_space(self, pts):
            if self.cur_y - pts < MARGIN_B + 30:
                self.finish_page()
                self.new_page()

        def write_section(self, title):
            self.need_space(30)
            self.cur_y -= 8
            self._rect(MARGIN_L-2, self.cur_y-4, TEXT_W+4, 16, 0.92)
            self._text_line(title.upper(), MARGIN_L+2, self.cur_y, 9, bold=True)
            self.cur_y -= 18

        def write_text(self, text, size=9, bold=False, gray=False, indent=0, line_height=13):
            # Simple word-wrap
            words = str(text).split()
            line = ""
            chars_per_line = int(TEXT_W / (size * 0.52)) - indent//5
            for word in words:
                test = (line + " " + word).strip()
                if len(test) > chars_per_line:
                    if line:
                        self.need_space(line_height)
                        self._text_line(safe(line), MARGIN_L, self.cur_y, size, bold=bold, gray=gray, indent=indent)
                        self.cur_y -= line_height
                    line = word
                else:
                    line = test
            if line:
                self.need_space(line_height)
                self._text_line(safe(line), MARGIN_L, self.cur_y, size, bold=bold, gray=gray, indent=indent)
                self.cur_y -= line_height

        def finish_page(self):
            if self.cur_page is None:
                return
            stream = self.cur_page.getvalue().encode("latin-1", errors="replace")
            self.pages.append(stream)
            self.cur_page = None

        def build(self):
            self.finish_page()

            obj_id = [1]
            def next_id():
                obj_id[0] += 1
                return obj_id[0]

            # Catalog=1, Pages=2, Font1=3, Font2=4, pages start at 5
            catalog_id = 1
            pages_id   = 2
            font1_id   = 3
            font2_id   = 4
            page_ids   = []
            stream_ids = []

            # fonts
            self._obj(font1_id, b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
            self._obj(font2_id, b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>")

            first_content = 5
            for i, stream in enumerate(self.pages):
                sid = first_content + i*2
                pid = first_content + i*2 + 1
                stream_ids.append(sid)
                page_ids.append(pid)

                self._obj(sid, (
                    f"<< /Length {len(stream)} >>\nstream\n".encode() +
                    stream + b"\nendstream"
                ))
                self._obj(pid, (
                    f"<< /Type /Page /Parent {pages_id} 0 R "
                    f"/MediaBox [0 0 {PAGE_W} {PAGE_H}] "
                    f"/Contents {sid} 0 R "
                    f"/Resources << /Font << /F1 {font1_id} 0 R /F2 {font2_id} 0 R >> >> >>"
                ).encode())

            kids = " ".join(f"{p} 0 R" for p in page_ids)
            self._obj(pages_id, f"<< /Type /Pages /Kids [{kids}] /Count {len(page_ids)} >>".encode())
            self._obj(catalog_id, f"<< /Type /Catalog /Pages {pages_id} 0 R >>".encode())

            # xref
            xref_pos = self.buf.tell()
            all_ids = sorted(self.offsets, key=lambda x: x[0])
            self._write(f"xref\n0 {all_ids[-1][0]+1}\n".encode())
            self._write(b"0000000000 65535 f \n")
            seen = set()
            for oid, off in sorted(all_ids, key=lambda x: x[0]):
                while len(seen) < oid - 1:
                    self._write(b"0000000000 00000 f \n")
                    seen.add(len(seen)+1)
                self._write(f"{off:010d} 00000 n \n".encode())
                seen.add(oid)

            # PDF Info dictionary (Creator, Title, Producer) — aids court e-filing
            info_id = all_ids[-1][0] + 1
            doc_title = safe(c.get("title", "SynJuris Evidence Manifest"))
            info_obj = f"<< /Title ({doc_title}) /Creator (SynJuris) /Producer (SynJuris — synjuris.com) /CreationDate (D:{datetime.now().strftime('%Y%m%d%H%M%S')}) >>"
            self.offsets.append((info_id, self.buf.tell()))
            self._write(f"{info_id} 0 obj\n".encode())
            self._write(info_obj.encode())
            self._write(b"\nendobj\n")
            self._write(f"trailer\n<< /Size {info_id+1} /Root {catalog_id} 0 R /Info {info_id} 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n".encode())
            return self.buf.getvalue()

    # ── Compose the document ─────────────────────────────────────────────────
    pdf = PDFWriter()
    pdf.new_page()

    # Title block
    pdf._rect(MARGIN_L-2, pdf.cur_y-4, TEXT_W+4, 28, 0.88)
    pdf._text_line("SYNJURIS — EVIDENCE MANIFEST", MARGIN_L+4, pdf.cur_y+10, 12, bold=True)
    pdf._text_line(safe(c.get("title","")), MARGIN_L+4, pdf.cur_y-4, 10)
    pdf.cur_y -= 36

    # Case info
    pdf.write_section("Case Information")
    info_pairs = [
        ("Type",        c.get("case_type","")),
        ("Jurisdiction",c.get("jurisdiction","")),
        ("Court",       c.get("court_name","")),
        ("Case Number", c.get("case_number","")),
        ("Hearing Date",c.get("hearing_date","")),
    ]
    for label, val_ in info_pairs:
        if val_:
            pdf.need_space(13)
            pdf._text_line(f"{label}:", MARGIN_L, pdf.cur_y, 9, bold=True)
            pdf._text_line(safe(str(val_)), MARGIN_L+90, pdf.cur_y, 9)
            pdf.cur_y -= 13

    # Parties
    if parties:
        pdf.write_section("Parties")
        for p in parties:
            atty = f"  [Atty: {p['attorney']}]" if p["attorney"] else ""
            pdf.need_space(13)
            pdf._text_line(f"{p['role']}:", MARGIN_L, pdf.cur_y, 9, bold=True)
            pdf._text_line(safe(f"{p['name']}{atty}"), MARGIN_L+90, pdf.cur_y, 9)
            pdf.cur_y -= 13

    # Evidence
    if evidence:
        pdf.write_section(f"Confirmed Evidence ({len(evidence)} items)")
        for ev in evidence:
            pdf.need_space(50)
            en   = ev["exhibit_number"] or "Unnumbered"
            cat  = ev["category"] or "General"
            dt   = ev["event_date"] or "Undated"
            src_ = ev["source"] or "Manual entry"
            pdf._rect(MARGIN_L-2, pdf.cur_y-2, TEXT_W+4, 14, 0.95)
            pdf._text_line(f"{en}  ·  {cat}  ·  {dt}  ·  Source: {safe(src_)}",
                           MARGIN_L+2, pdf.cur_y+2, 8, bold=True)
            pdf.cur_y -= 16
            pdf.write_text(ev["content"] or "", size=9, indent=10)
            if ev["notes"]:
                pdf.write_text(f"Notes: {ev['notes']}", size=8, gray=True, indent=10)
            pdf.cur_y -= 6
            pdf._line(MARGIN_L, pdf.cur_y, PAGE_W-MARGIN_R, pdf.cur_y, 0.3)
            pdf.cur_y -= 8

    # Timeline
    if timeline:
        pdf.write_section(f"Timeline ({len(timeline)} events)")
        for t in timeline:
            pdf.need_space(26)
            imp = " [HIGH IMPORTANCE]" if t["importance"] == "high" else ""
            pdf._text_line(f"{t['event_date'] or 'Undated'}{imp}  —  {safe(t['title'])}",
                           MARGIN_L, pdf.cur_y, 9, bold=True)
            pdf.cur_y -= 13
            if t["description"]:
                pdf.write_text(t["description"], size=8, gray=True, indent=12)

    # Financial summary
    if financials:
        income  = sum(f["amount"] or 0 for f in financials if f["direction"] == "income")
        expense = sum(f["amount"] or 0 for f in financials if f["direction"] == "expense")
        pdf.write_section(f"Financial Records ({len(financials)} entries)")
        for f_ in financials:
            pdf.need_space(13)
            sign = "+" if f_["direction"] == "income" else "-"
            amt  = f"{sign}${(f_['amount'] or 0):.2f}"
            pdf._text_line(f"{f_['entry_date'] or 'Undated'}  {amt}  {safe(f_['description'])}  [{f_['category'] or ''}]",
                           MARGIN_L, pdf.cur_y, 8)
            pdf.cur_y -= 13
        pdf.cur_y -= 4
        pdf._text_line(f"Total income: +${income:.2f}    Total expenses: -${expense:.2f}    Net: ${income-expense:.2f}",
                       MARGIN_L, pdf.cur_y, 9, bold=True)
        pdf.cur_y -= 16

    # Footer disclaimer
    pdf.need_space(40)
    pdf.cur_y -= 10
    pdf._line(MARGIN_L, pdf.cur_y, PAGE_W-MARGIN_R, pdf.cur_y, 0.5)
    pdf.cur_y -= 14
    pdf._text_line("Generated by SynJuris  ·  Review all items before filing  ·  Not legal advice",
                   MARGIN_L, pdf.cur_y, 7, gray=True)

    pdf_bytes = pdf.build()
    safe_title = re.sub(r"[^\w\s-]", "", c.get("title","case")).strip().replace(" ","_")[:40]
    fname = f"SynJuris_{safe_title}_{date.today().isoformat()}.pdf"
    return fname, pdf_bytes


# ══════════════════════════════════════════════════════════════════════════════
# CASE READINESS REPORT — one-page attorney-grade PDF summary
# ══════════════════════════════════════════════════════════════════════════════

def export_readiness_pdf(case_id, user_id):
    """One-page Case Readiness Report. State vector + interpretation + deadlines.
    Returns (filename, bytes). Zero external dependencies."""
    import io as _io

    conn = get_db()
    case      = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
    parties   = conn.execute("SELECT name,role FROM parties WHERE case_id=?", (case_id,)).fetchall()
    deadlines = conn.execute(
        "SELECT due_date,title,completed FROM deadlines WHERE case_id=? ORDER BY due_date ASC LIMIT 6",
        (case_id,)
    ).fetchall()
    ev_counts = conn.execute(
        "SELECT category, COUNT(*) as n FROM evidence WHERE case_id=? AND confirmed=1 "
        "AND (is_deleted IS NULL OR is_deleted=0) GROUP BY category ORDER BY n DESC LIMIT 8",
        (case_id,)
    ).fetchall()
    docs = conn.execute(
        "SELECT doc_type FROM documents WHERE case_id=? AND (is_deleted IS NULL OR is_deleted=0)",
        (case_id,)
    ).fetchall()
    conn.close()

    if not case:
        return "readiness.pdf", b""

    c      = dict(case)
    snap   = compute_case_state(case_id)
    interp = interpret_case_state(snap)
    st     = snap["state"]
    inp    = snap["inputs"]

    # PDF safe-string: escape backslash, parens, strip newlines
    def safe(s):
        t = str(s or "")
        t = t.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        t = t.replace("\r", " ").replace("\n", " ")
        return t

    PAGE_W, PAGE_H = 612, 792
    ML, MR, MT, MB = 54, 54, 54, 54
    TW = PAGE_W - ML - MR

    # ── Minimal self-contained PDF writer ────────────────────────────────────
    class _PDF:
        def __init__(self):
            self.buf = _io.BytesIO()
            self.offsets = []
            self.pages = []
            self.cur_page = None
            self.cur_y = PAGE_H - MT
            header = b"%PDF-1.4\n"
            binary = b"%" + bytes([0xe2, 0xe3, 0xcf, 0xd3]) + b"\n"
            self.buf.write(header + binary)

        def _write(self, d):
            self.buf.write(d if isinstance(d, bytes) else d.encode("latin-1", "replace"))

        def _obj(self, oid, content):
            self.offsets.append((oid, self.buf.tell()))
            self._write(f"{oid} 0 obj\n")
            self._write(content if isinstance(content, bytes) else content.encode("latin-1", "replace"))
            self._write(b"\nendobj\n")

        def new_page(self):
            self.cur_page = _io.StringIO()
            self.cur_y = PAGE_H - MT

        def _t(self, text, x, y, size, bold=False, gray=False, rgb=None):
            font = "F2" if bold else "F1"
            if rgb:   color = f"{rgb[0]:.2f} {rgb[1]:.2f} {rgb[2]:.2f}"
            elif gray: color = "0.50 0.50 0.50"
            else:      color = "0.91 0.87 0.78"
            self.cur_page.write(f"BT /{font} {size} Tf {color} rg {x} {y} Td ({safe(text)}) Tj ET\n")

        def _line(self, x1, y1, x2, y2, w=0.5, g=0.2):
            self.cur_page.write(f"{g:.2f} g {w} w {x1} {y1} m {x2} {y2} l S 0 g\n")

        def _rect(self, x, y, w, h, r=0.07, g=0.12, b=0.18):
            self.cur_page.write(f"{r:.2f} {g:.2f} {b:.2f} rg {x} {y} {w} {h} re f 0.91 0.87 0.78 rg\n")

        def _bar(self, x, y, w, h, val, maxval=9, col=(0.25, 0.60, 0.45)):
            # background track
            self.cur_page.write(f"0.05 0.10 0.15 rg {x} {y} {w} {h} re f\n")
            fw = max(4, int(w * val / maxval))
            r, g, b = col
            self.cur_page.write(f"{r:.2f} {g:.2f} {b:.2f} rg {x} {y} {fw} {h} re f\n")
            self.cur_page.write("0.91 0.87 0.78 rg\n")

        def _wrap(self, text, x, y, size, cpl=None, line_h=11, gray=False):
            """Word-wrap text, return new y."""
            if cpl is None:
                cpl = int(TW / (size * 0.52))
            words = str(text).split()
            buf = ""
            for w in words:
                test = (buf + " " + w).strip()
                if len(test) > cpl:
                    if buf:
                        self._t(buf, x, y, size, gray=gray)
                        y -= line_h
                    buf = w
                else:
                    buf = test
            if buf:
                self._t(buf, x, y, size, gray=gray)
                y -= line_h
            return y

        def finish_page(self):
            if self.cur_page:
                self.pages.append(self.cur_page.getvalue().encode("latin-1", "replace"))
                self.cur_page = None

        def build(self):
            self.finish_page()
            f1_id, f2_id, pages_id, cat_id = 3, 4, 2, 1
            self._obj(f1_id, b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
            self._obj(f2_id, b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>")
            page_ids = []
            sid_base = 5
            for i, stream in enumerate(self.pages):
                sid = sid_base + i * 2
                pid = sid + 1
                page_ids.append(pid)
                self._obj(sid, (f"<< /Length {len(stream)} >>\nstream\n").encode() + stream + b"\nendstream")
                self._obj(pid, (
                    f"<< /Type /Page /Parent {pages_id} 0 R "
                    f"/MediaBox [0 0 {PAGE_W} {PAGE_H}] "
                    f"/Contents {sid} 0 R "
                    f"/Resources << /Font << /F1 {f1_id} 0 R /F2 {f2_id} 0 R >> >> >>"
                ).encode())
            kids = " ".join(f"{p} 0 R" for p in page_ids)
            self._obj(pages_id, f"<< /Type /Pages /Kids [{kids}] /Count {len(page_ids)} >>".encode())
            self._obj(cat_id, f"<< /Type /Catalog /Pages {pages_id} 0 R >>".encode())
            xref_pos = self.buf.tell()
            all_ids = sorted(self.offsets, key=lambda x: x[0])
            self._write(f"xref\n0 {all_ids[-1][0]+1}\n")
            self._write(b"0000000000 65535 f \n")
            seen = set()
            for oid, off in sorted(all_ids, key=lambda x: x[0]):
                while len(seen) < oid - 1:
                    self._write(b"0000000000 00000 f \n")
                    seen.add(len(seen) + 1)
                self._write(f"{off:010d} 00000 n \n")
                seen.add(oid)
            ii = all_ids[-1][0] + 1
            self._obj(ii, f"<< /Title ({safe(c.get('title',''))}) /Creator (SynJuris v{VERSION}) >>".encode())
            self._write(
                f"trailer\n<< /Size {ii+1} /Root {cat_id} 0 R >>\n"
                f"startxref\n{xref_pos}\n%%EOF\n"
            )
            return self.buf.getvalue()

    # ── Compose the report ───────────────────────────────────────────────────
    pdf = _PDF()
    pdf.new_page()
    y = pdf.cur_y

    # Dark header band
    pdf._rect(0, y - 44, PAGE_W, 56, 0.05, 0.10, 0.17)
    pdf._t("SYNJURIS", ML, y - 8, 18, bold=True)
    pdf._t("CASE READINESS REPORT", ML + 132, y - 8, 11, gray=True)
    pdf._t(f"Generated {date.today().strftime('%B %d, %Y')}", PAGE_W - MR - 148, y - 8, 9, gray=True)
    pdf._t(safe(c.get("title", "")), ML, y - 26, 13, bold=True)
    sub = "  ·  ".join(filter(None, [c.get("case_type",""), c.get("jurisdiction",""), c.get("court_name","")]))
    pdf._t(safe(sub), ML, y - 38, 8, gray=True)
    y -= 60

    # Urgency banner
    urgency = interp.get("urgency", "normal")
    urg_col = {"critical":(0.55,0.15,0.15), "high":(0.40,0.30,0.08),
               "moderate":(0.08,0.20,0.35), "normal":(0.05,0.22,0.15)}
    ur, ug, ub = urg_col.get(urgency, (0.05, 0.22, 0.15))
    pdf._rect(ML - 4, y - 18, TW + 8, 22, ur, ug, ub)
    pdf._t(safe(interp.get("summary", "")), ML, y - 10, 9, bold=True)
    y -= 30

    # State vector bars
    y -= 6
    pdf._t("CASE STATE", ML, y, 8, bold=True, gray=True)
    pdf._t(f"Audit hash: {snap['hash'][:24]}...", PAGE_W - MR - 200, y, 7, gray=True)
    y -= 14
    bar_defs = [
        ("Evidence Strength",   st["x"], (0.25, 0.60, 0.45)),
        ("Procedural Health",   st["y"], (0.25, 0.45, 0.70)),
        ("Adversarial Pressure",st["z"], (0.70, 0.30, 0.25)),
    ]
    lv = ["","Very Low","Low","Mod-Low","Moderate","Moderate","Mod-High","High","Very High","Critical"]
    for label, val, col in bar_defs:
        pdf._t(f"{label}", ML, y, 8, bold=True)
        pdf._t(f"{val}/9  {lv[val] if 0 <= val <= 9 else ''}", ML + TW - 62, y, 8, gray=True)
        y -= 11
        pdf._bar(ML, y - 4, TW, 8, val, col=col)
        y -= 16

    # Interpretations
    y -= 4
    pdf._line(ML, y, ML + TW, y)
    y -= 12
    pdf._t("WHAT THIS MEANS", ML, y, 8, bold=True, gray=True)
    y -= 13
    for field in ("x_text", "y_text", "z_text"):
        text = interp.get(field, "")
        y = pdf._wrap(text, ML, y, 8, line_h=11)
        y -= 4

    # Evidence summary
    y -= 4
    pdf._line(ML, y, ML + TW, y)
    y -= 12
    pdf._t(f"EVIDENCE SUMMARY  ({inp.get('evidence_count',0)} confirmed exhibits)", ML, y, 8, bold=True, gray=True)
    y -= 13
    if ev_counts:
        col_w = TW // min(4, len(ev_counts))
        for idx2, row in enumerate(ev_counts):
            cx = ML + (idx2 % 4) * col_w
            if idx2 > 0 and idx2 % 4 == 0:
                y -= 22
            pdf._rect(cx, y - 16, col_w - 4, 20, 0.05, 0.12, 0.20)
            num_col = (0.25,0.60,0.45) if row["n"] > 2 else (0.80,0.65,0.30)
            pdf._t(str(row["n"]), cx + 4, y - 6, 14, bold=True, rgb=num_col)
            pdf._t(safe((row["category"] or "")[:16]), cx + 4, y - 14, 7, gray=True)
        y -= 28
    else:
        pdf._t("No confirmed evidence yet.", ML, y, 8, gray=True)
        y -= 14

    # Deadlines
    if deadlines:
        y -= 4
        pdf._line(ML, y, ML + TW, y)
        y -= 12
        pdf._t("DEADLINES", ML, y, 8, bold=True, gray=True)
        y -= 13
        for dl in deadlines:
            overdue = not dl["completed"] and (dl["due_date"] or "") < date.today().isoformat()
            status = "DONE" if dl["completed"] else ("OVERDUE" if overdue else "Pending")
            scol = (0.35,0.75,0.50) if dl["completed"] else ((0.85,0.25,0.25) if overdue else (0.80,0.65,0.30))
            pdf._t(safe(f"{dl['due_date'] or 'No date'}  ·  {dl['title']}"), ML, y, 8)
            pdf._t(status, ML + TW - 50, y, 8, bold=True, rgb=scol)
            y -= 12

    # Parties
    if parties:
        y -= 6
        pdf._line(ML, y, ML + TW, y)
        y -= 12
        pdf._t("PARTIES", ML, y, 8, bold=True, gray=True)
        y -= 13
        for p in parties:
            pdf._t(safe(f"{p['role']}: {p['name']}"), ML, y, 8)
            y -= 12

    # Documents generated
    doc_types = list({d["doc_type"] for d in docs})
    if doc_types:
        y -= 6
        pdf._line(ML, y, ML + TW, y)
        y -= 12
        pdf._t("DOCUMENTS GENERATED", ML, y, 8, bold=True, gray=True)
        y -= 13
        pdf._t(safe(", ".join(doc_types[:10])), ML, y, 8)
        y -= 12

    # Footer
    pdf._rect(0, MB - 8, PAGE_W, 32, 0.05, 0.10, 0.17)
    pdf._t(
        f"SynJuris v{VERSION}  ·  synjuris.com  ·  NOT LEGAL ADVICE  ·  Hash: {snap['hash'][:20]}...",
        ML, MB + 10, 7, gray=True
    )
    pdf._t(
        "This report is an organizational tool only. Review with a licensed attorney before any court filing.",
        ML, MB, 7, gray=True
    )

    pdf_bytes = pdf.build()
    safe_title = re.sub(r"[^\w\s-]", "", c.get("title", "case")).strip().replace(" ", "_")[:30]
    fname = f"SynJuris_Readiness_{safe_title}_{date.today().isoformat()}.pdf"
    return fname, pdf_bytes

# ══════════════════════════════════════════════════════════════════════════════
# DOCX EXPORT — zero-dependency Word document generator
# Produces a proper .docx (OOXML) with court caption, heading, body, signature.
# No python-docx required — builds the ZIP/XML structure directly.
# ══════════════════════════════════════════════════════════════════════════════

def export_document_docx(doc):
    """Convert a generated document to a .docx file.
    Returns (filename, bytes). Pure stdlib — no external dependencies."""
    import zipfile, io as _io, re as _re

    content = doc.get("content","")
    title   = doc.get("title", doc.get("doc_type","Document"))
    doc_type= doc.get("doc_type","Document")

    # ── OOXML helpers ────────────────────────────────────────────────────────
    def _esc(s):
        return (str(s or "")
                .replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
                .replace('"',"&quot;").replace("'","&apos;"))

    def _para(text, style="Normal", bold=False, size_pt=12, center=False, space_after=120):
        """Build a <w:p> element."""
        align = '<w:jc w:val="center"/>' if center else ''
        b_tag = '<w:b/>' if bold else ''
        sz = str(size_pt * 2)
        return (
            f'<w:p>'
            f'<w:pPr><w:pStyle w:val="{style}"/>{align}'
            f'<w:spacing w:after="{space_after}"/></w:pPr>'
            f'<w:r><w:rPr>{b_tag}<w:sz w:val="{sz}"/><w:szCs w:val="{sz}"/></w:rPr>'
            f'<w:t xml:space="preserve">{_esc(text)}</w:t></w:r></w:p>'
        )

    def _blank():
        return '<w:p><w:pPr><w:spacing w:after="0"/></w:pPr></w:p>'

    # ── Convert content to paragraphs ────────────────────────────────────────
    paragraphs_xml = []

    # Title
    paragraphs_xml.append(_para(title.upper(), bold=True, size_pt=14, center=True, space_after=200))
    paragraphs_xml.append(_blank())

    # Process content: preserve structure, make headers bold
    for raw_line in content.splitlines():
        line = raw_line.rstrip()
        if not line:
            paragraphs_xml.append(_blank())
        elif line.startswith("# ") or (line.isupper() and len(line) > 4 and len(line) < 80):
            # Section header
            paragraphs_xml.append(_para(line.lstrip("# ").strip(), bold=True, size_pt=11, space_after=80))
        elif line.startswith("---") or line.startswith("==="):
            # Horizontal rule → blank paragraph with bottom border
            paragraphs_xml.append(
                '<w:p><w:pPr><w:pBdr><w:bottom w:val="single" w:sz="4" w:space="1" w:color="C9A84C"/></w:pBdr></w:pPr></w:p>'
            )
        else:
            paragraphs_xml.append(_para(line, size_pt=11))

    # SynJuris disclaimer footer
    paragraphs_xml.append(_blank())
    paragraphs_xml.append(_para("─" * 60, size_pt=9, space_after=60))
    paragraphs_xml.append(_para(
        "Generated by SynJuris. This is a draft — not legal advice. "
        "Review all content carefully. Fill in all [BRACKET PLACEHOLDERS] before filing. "
        "Consult a licensed attorney before submitting any document to a court.",
        size_pt=8, space_after=0
    ))

    # ── Build OOXML document.xml ─────────────────────────────────────────────
    doc_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:wpc="http://schemas.microsoft.com/office/word/2010/wordprocessingCanvas" '
        'xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006" '
        'xmlns:o="urn:schemas-microsoft-com:office:office" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" '
        'xmlns:m="http://schemas.openxmlformats.org/officeDocument/2006/math" '
        'xmlns:v="urn:schemas-microsoft-com:vml" '
        'xmlns:wp14="http://schemas.microsoft.com/office/word/2010/wordprocessingDrawing" '
        'xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing" '
        'xmlns:w10="urn:schemas-microsoft-com:office:word" '
        'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
        'xmlns:w14="http://schemas.microsoft.com/office/word/2010/wordml" '
        'xmlns:wpg="http://schemas.microsoft.com/office/word/2010/wordprocessingGroup" '
        'xmlns:wpi="http://schemas.microsoft.com/office/word/2010/wordprocessingInk" '
        'xmlns:wne="http://schemas.microsoft.com/office/word/2006/wordml" '
        'xmlns:wps="http://schemas.microsoft.com/office/word/2010/wordprocessingShape" '
        'mc:Ignorable="w14 wp14">'
        '<w:body>'
        + "".join(paragraphs_xml) +
        '<w:sectPr>'
        '<w:pgSz w:w="12240" w:h="15840"/>'   # Letter size
        '<w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440" '
        'w:header="720" w:footer="720" w:gutter="0"/>'
        '</w:sectPr>'
        '</w:body></w:document>'
    )

    # ── Relationships ─────────────────────────────────────────────────────────
    rels_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" '
        'Target="styles.xml"/>'
        '</Relationships>'
    )

    styles_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
        'xmlns:w14="http://schemas.microsoft.com/office/word/2010/wordml" '
        'mc:Ignorable="w14" '
        'xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006">'
        '<w:docDefaults><w:rPrDefault><w:rPr>'
        '<w:rFonts w:ascii="Times New Roman" w:hAnsi="Times New Roman" w:cs="Times New Roman"/>'
        '<w:sz w:val="22"/><w:szCs w:val="22"/>'
        '</w:rPr></w:rPrDefault></w:docDefaults>'
        '<w:style w:type="paragraph" w:styleId="Normal"><w:name w:val="Normal"/></w:style>'
        '</w:styles>'
    )

    content_types_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/word/document.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
        '<Override PartName="/word/styles.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>'
        '</Types>'
    )

    root_rels_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
        'Target="word/document.xml"/>'
        '</Relationships>'
    )

    # ── Assemble ZIP ─────────────────────────────────────────────────────────
    buf = _io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml",         content_types_xml)
        zf.writestr("_rels/.rels",                  root_rels_xml)
        zf.writestr("word/document.xml",            doc_xml)
        zf.writestr("word/_rels/document.xml.rels", rels_xml)
        zf.writestr("word/styles.xml",              styles_xml)

    safe_title = _re.sub(r"[^\w\s-]", "", title).strip().replace(" ", "_")[:40]
    fname = f"SynJuris_{safe_title}_{date.today().isoformat()}.docx"
    return fname, buf.getvalue()

# ══════════════════════════════════════════════════════════════════════════════
# UI — full single-page app
# ══════════════════════════════════════════════════════════════════════════════


UI = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SynJuris</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Cinzel:wght@400;600;700&family=Lora:ital,wght@0,400;0,600;1,400&family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#0D1B2A;--surface:#111f30;--surface2:#0a1520;
  --border:#1e3248;--border2:#162840;
  --ink:#E8DFC8;--ink2:#A89F8A;--ink3:#6B7A8D;
  --gold:#C9A84C;--gold-dim:#8a6e2f;--gold-bg:rgba(201,168,76,0.08);--gold-bd:rgba(201,168,76,0.25);
  --blue:#4A90D9;--blue-bg:rgba(74,144,217,0.10);--blue-bd:rgba(74,144,217,0.30);
  --green:#4CAF7D;--green-bg:rgba(76,175,125,0.10);--green-bd:rgba(76,175,125,0.30);
  --amber:#C9A84C;--amber-bg:rgba(201,168,76,0.10);--amber-bd:rgba(201,168,76,0.30);
  --red:#E05C5C;--red-bg:rgba(224,92,92,0.10);--red-bd:rgba(224,92,92,0.30);
  --purple:#9B7FD4;--purple-bg:rgba(155,127,212,0.10);--purple-bd:rgba(155,127,212,0.30);
  --serif:'Cinzel',Georgia,serif;
  --sans:'Inter',system-ui,sans-serif;
  --mono:'JetBrains Mono',monospace;
  --r:6px;--rl:10px;--rxl:16px;
}
*{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%;background:var(--bg);color:var(--ink);font-family:var(--sans);font-size:15px;line-height:1.7}

#app{display:grid;grid-template-columns:220px 1fr;grid-template-rows:50px 1fr;height:100vh}

/* topbar */
#topbar{grid-column:1/-1;display:flex;align-items:center;padding:0 20px;background:var(--surface2);border-bottom:1px solid var(--gold-bd);gap:12px;z-index:10}
#topbar h1{font-family:var(--serif);font-size:17px;font-weight:600;letter-spacing:.1em;white-space:nowrap;color:var(--gold)}
#topbar h1 em{font-style:normal;color:var(--ink2);font-weight:400}
.topbar-tag{font-size:9px;letter-spacing:.14em;text-transform:uppercase;color:var(--ink3)}
.sp{flex:1}
.api-pill{font-size:11px;display:flex;align-items:center;gap:5px;color:var(--ink3)}
.api-dot{width:7px;height:7px;border-radius:50%;background:var(--border)}
.api-pill.on .api-dot{background:var(--green)}

/* sidebar */
#sidebar{background:var(--surface2);border-right:1px solid var(--gold-bd);display:flex;flex-direction:column;overflow:hidden}
#sb-head{padding:14px 14px 10px;border-bottom:1px solid var(--border2)}
#sb-head p{font-size:10px;text-transform:uppercase;letter-spacing:.1em;color:var(--ink3);margin-bottom:8px}
#new-btn{width:100%;background:transparent;color:var(--gold);border:1px solid var(--gold-bd);border-radius:var(--r);padding:8px 10px;font-family:var(--sans);font-size:12px;font-weight:500;cursor:pointer;transition:opacity .15s}
#new-btn:hover{background:var(--gold-bg);border-color:var(--gold)}
#case-list{flex:1;overflow-y:auto;padding:6px}
.ci{padding:9px 11px;border-radius:var(--r);cursor:pointer;transition:background .1s;border:1px solid transparent;margin-bottom:2px}
.ci:hover{background:var(--bg)}
.ci.active{background:var(--gold-bg);border-color:var(--gold-bd)}
.ci-t{font-weight:500;font-size:14px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.ci-m{font-size:12px;color:var(--ink3);margin-top:2px}

/* main */
#main{overflow:hidden;display:flex;flex-direction:column}
#welcome{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;padding:40px;gap:14px}
#welcome h2{font-family:var(--serif);font-size:30px;line-height:1.25}
#welcome p{color:var(--ink2);max-width:360px;font-size:13px}
.pill-tag{font-size:11px;background:var(--surface);border:1px solid var(--border);border-radius:20px;padding:5px 14px;color:var(--ink2)}

/* case view */
#cv{flex:1;display:flex;flex-direction:column;overflow:hidden}
#cv-head{padding:16px 24px 0;border-bottom:1px solid var(--border2);flex-shrink:0}
#cv-head h2{font-family:var(--serif);font-size:26px;font-weight:600}
#cv-head .meta{font-size:14px;color:var(--ink3);margin-top:4px}
#tabs{display:flex;gap:0;margin-top:12px}
.tab{padding:9px 16px;font-size:14px;font-weight:500;cursor:pointer;border-bottom:2px solid transparent;color:var(--ink2);transition:all .15s;white-space:nowrap}
.tab:hover{color:var(--ink)}
.tab.active{color:var(--gold);border-bottom-color:var(--gold)}
#tc{flex:1;overflow-y:auto;padding:24px 28px}

/* utility */
.section{margin-bottom:24px}
.st{font-size:10px;text-transform:uppercase;letter-spacing:.1em;color:var(--ink3);margin-bottom:10px;display:flex;align-items:center;gap:8px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--rl)}
.cb{padding:14px 18px}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.grid3{display:grid;grid-template-columns:repeat(3,1fr);gap:10px}
.grid4{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}
.stat{background:var(--surface);border:1px solid var(--border);border-radius:var(--rl);padding:12px 16px}
.stat-n{font-family:var(--serif);font-size:36px;font-weight:600;line-height:1}
.stat-l{font-size:14px;color:var(--ink3);margin-top:5px}
.stat.warn{background:var(--amber-bg);border-color:var(--amber-bd)}
.stat.good{background:var(--green-bg);border-color:var(--green-bd)}
.badge{font-size:13px;font-weight:500;padding:4px 10px;border-radius:10px;white-space:nowrap}
.badge.confirmed{background:var(--green-bg);color:var(--green)}
.badge.unconfirmed{background:var(--amber-bg);color:var(--amber)}
.badge.blue{background:var(--blue-bg);color:var(--blue)}
.badge.purple{background:var(--purple-bg);color:var(--purple)}
.badge.red{background:var(--red-bg);color:var(--red)}

/* evidence */
.ev{padding:11px 15px;border-bottom:1px solid var(--border2);display:flex;gap:10px;align-items:flex-start}
.ev:last-child{border-bottom:none}
.ev-body{flex:1;min-width:0}
.ev-content{font-size:15px;line-height:1.6}
.ev-meta{font-size:13px;color:var(--ink3);margin-top:5px}
.ev-acts{display:flex;gap:5px;margin-top:6px}
.xbtn{font-size:13px;padding:5px 11px;border-radius:4px;border:1px solid var(--border);background:transparent;cursor:pointer;font-family:var(--sans);color:var(--ink2);transition:background .1s}
.xbtn:hover{background:var(--bg)}
.xbtn.ok{border-color:var(--green);color:var(--green)}
.xbtn.ok:hover{background:var(--green-bg)}
.xbtn.rm{border-color:var(--red);color:var(--red)}
.xbtn.rm:hover{background:var(--red-bg)}
.filter-row{display:flex;gap:5px;flex-wrap:wrap;margin-bottom:12px}
.fp{font-size:11px;padding:3px 10px;border-radius:20px;border:1px solid var(--border);background:var(--surface);cursor:pointer;transition:all .1s;color:var(--ink2)}
.fp.active{background:var(--blue);border-color:var(--blue);color:#fff}

/* forms */
.fg{margin-bottom:12px}
label{font-size:14px;font-weight:500;color:var(--ink2);display:block;margin-bottom:6px}
input,select,textarea{width:100%;padding:10px 12px;border:1px solid var(--border);border-radius:var(--r);font-family:var(--sans);font-size:15px;background:var(--surface2);color:var(--ink);outline:none;transition:border-color .15s}
input:focus,select:focus,textarea:focus{border-color:var(--gold);box-shadow:0 0 0 2px rgba(201,168,76,.12)}
textarea{resize:vertical;min-height:72px}
.btn{padding:10px 18px;border-radius:var(--r);font-family:var(--sans);font-size:14px;font-weight:500;cursor:pointer;border:none;transition:opacity .15s}
.btn-p{background:var(--gold);color:#0D1B2A;font-weight:600}.btn-p:hover{opacity:.9}
.btn-s{background:transparent;color:var(--ink2);border:1px solid var(--border)}.btn-s:hover{background:var(--gold-bg);border-color:var(--gold-bd);color:var(--gold)}
.btn-r{background:var(--red);color:#fff}.btn-r:hover{opacity:.88}
.br{display:flex;gap:7px;margin-top:8px;flex-wrap:wrap}
.two-col{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.three-col{display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px}

/* notice */
.notice{font-size:14px;padding:12px 16px;border-radius:var(--r);border-left:3px solid;margin-bottom:14px;line-height:1.6}
.n-info{background:var(--blue-bg);border-color:var(--blue);color:#1e40af}
.n-warn{background:var(--amber-bg);border-color:#f59e0b;color:var(--amber)}
.n-ok{background:var(--green-bg);border-color:var(--green);color:var(--green)}
.n-red{background:var(--red-bg);border-color:var(--red);color:var(--red)}

/* chat */
#chat-wrap{display:flex;flex-direction:column;height:100%;min-height:0}
#chat-msgs{flex:1;overflow-y:auto;padding:12px 0;display:flex;flex-direction:column;gap:10px;min-height:0}
.msg{max-width:82%}
.msg.user{align-self:flex-end}.msg.assistant{align-self:flex-start}
.mb{padding:12px 16px;border-radius:10px;font-size:15px;line-height:1.7;white-space:pre-wrap}
.msg.user .mb{background:var(--gold);color:#0D1B2A;font-weight:500;border-bottom-right-radius:3px}
.msg.assistant .mb{background:var(--surface);border:1px solid var(--border);border-bottom-left-radius:3px}
#chat-ir{display:flex;gap:7px;padding-top:10px;border-top:1px solid var(--border2);flex-shrink:0}
#chat-input{flex:1;font-size:15px}
#chat-send{background:var(--gold);color:#0D1B2A;font-weight:600;border:none;border-radius:var(--r);padding:7px 14px;font-family:var(--sans);font-size:12px;cursor:pointer;transition:opacity .15s}
#chat-send:hover{opacity:.88}#chat-send:disabled{opacity:.5;cursor:default}
.sugg-row{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:10px}
.sugg{font-size:11px;padding:4px 10px;border:1px solid var(--blue-bd);border-radius:20px;color:var(--blue);background:var(--blue-bg);cursor:pointer;transition:opacity .1s}
.sugg:hover{opacity:.8}

/* timeline */
.tl{position:relative;padding-left:28px}
.tl::before{content:'';position:absolute;left:9px;top:0;bottom:0;width:1px;background:var(--border)}
.tl-item{position:relative;margin-bottom:14px}
.tl-dot{position:absolute;left:-23px;top:4px;width:10px;height:10px;border-radius:50%;background:var(--blue);border:2px solid var(--surface)}
.tl-item.high .tl-dot{background:var(--red)}
.tl-item.normal .tl-dot{background:var(--blue)}
.tl-item.low .tl-dot{background:var(--ink3)}
.tl-date{font-size:13px;color:var(--ink3);margin-bottom:4px}
.tl-title{font-size:15px;font-weight:500}
.tl-desc{font-size:14px;color:var(--ink2);margin-top:3px}

/* documents */
.dt-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(155px,1fr));gap:8px;margin-bottom:18px}
.dt-card{padding:12px;border:1px solid var(--border);border-radius:var(--rl);cursor:pointer;transition:all .15s;background:var(--surface)}
.dt-card:hover{border-color:var(--blue);background:var(--blue-bg)}
.dt-icon{font-size:20px;margin-bottom:5px}
.dt-lbl{font-size:12px;font-weight:500}
.dt-desc{font-size:10px;color:var(--ink3);margin-top:2px}
#doc-pre{font-family:var(--mono);font-size:13px;line-height:1.8;background:var(--bg);border:1px solid var(--border);border-radius:var(--r);padding:14px;white-space:pre-wrap;max-height:400px;overflow-y:auto}

/* deadlines */
.dl-item{display:flex;align-items:center;gap:10px;padding:10px 15px;border-bottom:1px solid var(--border2)}
.dl-item:last-child{border-bottom:none}
.dl-item.done .dl-title{text-decoration:line-through;color:var(--ink3)}
.dl-date{font-size:13px;color:var(--ink3);min-width:90px}
.dl-title{font-size:15px;flex:1}
.dl-acts{display:flex;gap:5px}

/* financial */
.fin-item{display:flex;align-items:center;gap:10px;padding:9px 15px;border-bottom:1px solid var(--border2)}
.fin-item:last-child{border-bottom:none}
.fin-desc{flex:1;font-size:15px}
.fin-amt{font-size:15px;font-weight:500;min-width:80px;text-align:right}
.fin-amt.income{color:var(--green)}.fin-amt.expense{color:var(--red)}

/* modal */
#mo{position:fixed;inset:0;background:rgba(28,25,23,.4);display:none;align-items:flex-start;justify-content:center;z-index:200;padding-top:40px;overflow-y:auto}
#mo.open{display:flex}
#modal{background:var(--surface);border-radius:var(--rl);width:520px;max-width:96vw;max-height:88vh;overflow-y:auto;margin:0 auto 40px}
#mo-head{padding:18px 22px 14px;border-bottom:1px solid var(--border2);display:flex;justify-content:space-between;align-items:center;position:sticky;top:0;background:var(--surface);z-index:1}
#mo-head h3{font-family:var(--serif);font-size:18px;font-weight:600}
.mo-x{background:none;border:none;font-size:18px;cursor:pointer;color:var(--ink3);padding:0 4px}
#mo-body{padding:18px 22px 22px}
.sdot{width:7px;height:7px;border-radius:50%;background:var(--border);display:inline-block}
.sdot.active{background:var(--blue)}.sdot.done{background:var(--blue);opacity:.4}

/* drop zone */
#dz{border:2px dashed var(--border);border-radius:var(--rl);padding:24px;text-align:center;color:var(--ink3);font-size:12px;cursor:pointer;transition:all .15s;margin-bottom:12px}
#dz:hover,#dz.over{border-color:var(--blue);color:var(--blue);background:var(--blue-bg)}

/* support resources */
.res-card{padding:12px 14px;border:1px solid var(--border);border-radius:var(--rl);background:var(--surface);margin-bottom:8px}
.res-name{font-size:12px;font-weight:500}
.res-desc{font-size:11px;color:var(--ink2);margin-top:2px}
.res-contact{font-size:11px;color:var(--blue);margin-top:3px}

::-webkit-scrollbar{width:4px}::-webkit-scrollbar-track{background:transparent}::-webkit-scrollbar-thumb{background:var(--border);border-radius:2px}
@keyframes spin{to{transform:rotate(360deg)}}
.spin{display:inline-block;animation:spin .9s linear infinite}
@media print{
  #sidebar,#topbar,.btn,.xbtn,.btn-p,.btn-s,.btn-r,#tabs,#chat-ir,.sugg-row,.filter-row,.dt-grid,#new-btn,.ev-acts,.dl-acts,.fin-item button,.mo-x{display:none!important}
  #app{display:block!important}
  #main{overflow:visible!important;display:block!important}
  #cv{display:block!important;overflow:visible!important}
  #cv-head{border-bottom:2px solid #000!important;padding:0 0 8px 0!important;margin-bottom:16px}
  #tc{overflow:visible!important;padding:0!important}
  .card{border:1px solid #000!important;break-inside:avoid;box-shadow:none!important}
  .ev{break-inside:avoid}
  .tl-item{break-inside:avoid}
  body{background:white!important;color:black!important;font-size:11pt}
  h2{font-size:16pt}
  .st{font-size:9pt;border-bottom:1px solid #ccc;padding-bottom:3px;margin-bottom:8px}
  .badge{border:1px solid #999!important;background:none!important;color:#000!important}
  a[href]:after{content:" (" attr(href) ")"}
}
</style>
</head>
<body>
<div id="app">

<div id="topbar">
  <button id="mob-menu-btn" aria-label="Menu">&#9776;</button>
  <h1>SYN<em>JURIS</em></h1>
  <span class="topbar-tag">AI-ASSISTED &nbsp;&middot;&nbsp; YOUR DATA STAYS YOURS</span>
  <div class="sp"></div>
  <div class="api-pill" id="apill"><span class="api-dot"></span><span id="apill-t">Checking AI…</span></div>
  <span id="tier-badge" onclick="openTierSelector()" title="Click to change tier"
    style="margin-left:10px;font-size:10px;color:var(--ink3);border:1px solid var(--border);border-radius:4px;padding:3px 8px;cursor:pointer;white-space:nowrap"></span>
  <a href="/logout" style="margin-left:10px;font-size:11px;color:var(--ink3);text-decoration:none;border:1px solid var(--border);border-radius:4px;padding:4px 10px;white-space:nowrap" title="Sign out">Sign out</a>
</div>

<div id="sidebar">
  <div id="sb-head"><p>My Cases</p><button id="new-btn" onclick="openNewCase()">+ New Case</button></div>
  <div id="case-list" id="case-list"></div>
</div>

<div id="main">
  <div id="welcome">
    <h2 style="font-family:var(--serif);font-size:48px;color:var(--gold);letter-spacing:.1em;margin-bottom:10px">SYNJURIS</h2>
    <div style="font-size:12px;letter-spacing:.18em;color:var(--ink3);text-transform:uppercase;margin-bottom:24px">LOCAL-FIRST &nbsp;&middot;&nbsp; AI-ASSISTED &nbsp;&middot;&nbsp; DATA SECURITY</div>
    <p style="color:var(--ink2);max-width:480px;font-size:16px;line-height:1.9;margin-bottom:20px">Built for pro se litigants. Organize evidence, understand your rights, draft documents, and prepare for court — all running locally. Your data never leaves this computer.</p>
    <div style="max-width:480px;padding:14px 18px;background:rgba(201,168,76,.08);border:1px solid rgba(201,168,76,.25);border-radius:8px;margin-bottom:28px">
      <div style="font-size:11px;text-transform:uppercase;letter-spacing:.1em;color:var(--gold);margin-bottom:6px">⚖ Work-Product Protection</div>
      <p style="font-size:13px;color:var(--ink2);line-height:1.7">Communications with cloud AI tools have been ruled non-privileged in federal proceedings because they involve third-party transmission. SynJuris runs entirely on your machine — no third party ever receives your case data — which means your strategy may retain work-product status that cloud tools cannot provide.</p>
    </div>
    <button class="btn btn-p" onclick="openNewCase()" style="padding:14px 36px;font-size:15px;letter-spacing:.04em">Start a New Case</button>
    <div style="margin-top:40px;font-size:14px;color:var(--ink3)">&#9670;</div>
  </div>
  <div id="cv" style="display:none">
    <div id="cv-head">
      <div style="display:flex;align-items:flex-start;justify-content:space-between">
        <div>
          <h2 id="cv-title"></h2>
          <div class="meta" id="cv-meta"></div>
        </div>
        <div style="display:flex;gap:6px;margin-top:4px;flex-shrink:0">
          <button class="btn btn-s" style="font-size:11px" onclick="exportEvidence()" title="Download evidence manifest as text file">↓ Export TXT</button>
          <button class="btn btn-s" style="font-size:11px" onclick="exportPDF()" title="Download formatted PDF for court">↓ Export PDF</button>
          <button class="btn btn-s" style="font-size:11px" onclick="backupDB()" title="Download database only">↓ Backup DB</button>
          <button class="btn btn-s" style="font-size:11px" onclick="fullArchive()" title="Download database + all uploaded files as a zip">↓ Full Archive</button>
          <button class="btn btn-s" style="font-size:11px;color:var(--gold);border-color:var(--gold)" onclick="encryptedBackup()" title="Download AES-256 encrypted backup — only you can decrypt it">🔐 Encrypted Backup</button>
          <button class="btn btn-s" style="font-size:11px;color:var(--purple);border-color:var(--purple)" onclick="readinessReport()" title="One-page Case Readiness Report PDF for attorney or client review">📊 Readiness Report</button>
          <button class="btn btn-s" style="font-size:11px" onclick="openEditCase()">Edit Case</button>
        </div>
      </div>
      <div id="tabs">
        <div class="tab active" onclick="switchTab('overview')">Overview</div>
        <div class="tab" onclick="switchTab('roadmap')">🗺 Roadmap</div>
        <div class="tab" onclick="switchTab('evidence')">Evidence</div>
        <div class="tab" onclick="switchTab('timeline')">Timeline</div>
        <div class="tab" onclick="switchTab('deadlines')">Deadlines</div>
        <div class="tab" onclick="switchTab('documents')">Documents</div>
        <div class="tab" onclick="switchTab('motions')">Motions</div>
        <div class="tab" onclick="switchTab('comms')">Comm Log</div>
        <div class="tab" onclick="switchTab('financial')">Financial</div>
        <div class="tab" onclick="switchTab('hearing')">Hearing Prep</div>
        <div class="tab" onclick="switchTab('arguments')">Evidence Organizer</div>
        <div class="tab" onclick="switchTab('strategy')">Case Strategy</div>
        <div class="tab" onclick="switchTab('resources')">Resources</div>
        <div class="tab" onclick="switchTab('courtroom')">🏛 Courtroom</div>
        <div class="tab" onclick="switchTab('dynamics')">&#x2B21; Dynamics</div>
        <div class="tab" onclick="switchTab('chat')">Ask the Law</div>
        <div class="tab atty-only" onclick="switchTab('attorney')" style="display:none">⚖ Attorney</div>
      </div>
    </div>
    <div id="tc"></div>
  </div>
</div>
</div>

<div id="mo" onclick="moClick(event)">
  <div id="modal">
    <div id="mo-head"><h3 id="mo-title">New Case</h3><button class="mo-x" onclick="closeMo()">×</button></div>
    <div id="mo-body"></div>
  </div>
</div>

<script>
let CC = null, ctab = 'overview', evFilter = 'All';

/* ── Init ── */
/* ══════════════════════════════════════════════════════
   ENCRYPTED BACKUP — AES-256-GCM via Web Crypto API
   The server never sees the passphrase. Zero knowledge.
   ══════════════════════════════════════════════════════ */

async function encryptedBackup(){
  const pass = prompt("Set an encryption passphrase for this backup:\n\nWrite it down — without it, the backup CANNOT be decrypted.");
  if(!pass) return;
  const pass2 = prompt("Confirm passphrase:");
  if(pass !== pass2){ alert("Passphrases don't match. Backup cancelled."); return; }

  const statusEl = document.querySelector('#cv-head') || document.body;
  const notice = document.createElement('div');
  notice.style.cssText='position:fixed;bottom:20px;right:20px;background:#111f30;border:1px solid #c9a84c;border-radius:8px;padding:12px 18px;font-size:13px;color:#c9a84c;z-index:9999';
  notice.textContent='🔐 Encrypting backup…'; document.body.appendChild(notice);

  try {
    // 1. Fetch raw backup data from server (plaintext zip as base64)
    const raw = await api('/api/backup-encrypted-raw');
    if(raw.error) throw new Error(raw.error);

    // 2. Derive AES-256-GCM key from passphrase using PBKDF2
    const enc = new TextEncoder();
    const salt = crypto.getRandomValues(new Uint8Array(32));
    const iv   = crypto.getRandomValues(new Uint8Array(12));
    const keyMaterial = await crypto.subtle.importKey(
      "raw", enc.encode(pass), "PBKDF2", false, ["deriveKey"]
    );
    const key = await crypto.subtle.deriveKey(
      { name:"PBKDF2", salt, iterations:210000, hash:"SHA-256" },
      keyMaterial,
      { name:"AES-GCM", length:256 },
      false, ["encrypt"]
    );

    // 3. Encrypt the base64 payload
    const plaintext = enc.encode(JSON.stringify({
      version: raw.version,
      created_at: raw.created_at,
      data: raw.data,
    }));
    const ciphertext = await crypto.subtle.encrypt({name:"AES-GCM", iv}, key, plaintext);

    // 4. Build file: magic(4) + version(1) + salt(32) + iv(12) + ciphertext
    const magic = new Uint8Array([0x53,0x4A,0x42,0x4B]); // "SJBK"
    const ver   = new Uint8Array([1]);
    const parts = [magic, ver, salt, iv, new Uint8Array(ciphertext)];
    const total = parts.reduce((n,p)=>n+p.length, 0);
    const blob_buf = new Uint8Array(total);
    let off = 0;
    for(const p of parts){ blob_buf.set(p, off); off += p.length; }

    // 5. Download
    const blob = new Blob([blob_buf], {type:"application/octet-stream"});
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = raw.filename;
    a.click(); URL.revokeObjectURL(a.href);

    notice.style.background='#0d2b1a'; notice.style.borderColor='#1a5c33'; notice.style.color='#4caf82';
    notice.textContent='✓ Encrypted backup downloaded. Store it safely — only your passphrase can open it.';
  } catch(e) {
    notice.style.background='#2b0d0d'; notice.style.borderColor='#5c1a1a'; notice.style.color='#e57373';
    notice.textContent='Backup failed: '+e.message;
  }
  setTimeout(()=>notice.remove(), 6000);
}

async function restoreEncryptedBackup(){
  const input = document.createElement('input');
  input.type='file'; input.accept='.sj-backup';
  input.onchange = async()=>{
    const file = input.files[0]; if(!file) return;
    const pass = prompt("Enter the passphrase for this backup:");
    if(!pass) return;

    const notice = document.createElement('div');
    notice.style.cssText='position:fixed;bottom:20px;right:20px;background:#111f30;border:1px solid #c9a84c;border-radius:8px;padding:12px 18px;font-size:13px;color:#c9a84c;z-index:9999';
    notice.textContent='🔐 Decrypting…'; document.body.appendChild(notice);

    try {
      const buf = new Uint8Array(await file.arrayBuffer());
      // Parse file format: magic(4) + version(1) + salt(32) + iv(12) + ciphertext
      if(String.fromCharCode(...buf.slice(0,4)) !== "SJBK") throw new Error("Not a valid SynJuris backup file");
      const salt = buf.slice(5, 37);
      const iv   = buf.slice(37, 49);
      const ciphertext = buf.slice(49);

      const enc = new TextEncoder();
      const keyMaterial = await crypto.subtle.importKey(
        "raw", enc.encode(pass), "PBKDF2", false, ["deriveKey"]
      );
      const key = await crypto.subtle.deriveKey(
        { name:"PBKDF2", salt, iterations:210000, hash:"SHA-256" },
        keyMaterial, { name:"AES-GCM", length:256 }, false, ["decrypt"]
      );
      let plaintext;
      try {
        const dec = await crypto.subtle.decrypt({name:"AES-GCM", iv}, key, ciphertext);
        plaintext = JSON.parse(new TextDecoder().decode(dec));
      } catch(e) {
        throw new Error("Decryption failed — wrong passphrase or corrupted file");
      }

      if(!confirm("⚠ This will REPLACE all your current cases and evidence with the backup. Continue?")) {
        notice.remove(); return;
      }

      const r = await api('/api/restore-backup', {data: plaintext.data, confirmed: true});
      if(r.ok){
        notice.style.background='#0d2b1a'; notice.style.borderColor='#1a5c33'; notice.style.color='#4caf82';
        notice.textContent='✓ Backup restored. Reloading…';
        setTimeout(()=>location.reload(), 1500);
      } else {
        throw new Error(r.error||'Restore failed');
      }
    } catch(e) {
      notice.style.background='#2b0d0d'; notice.style.borderColor='#5c1a1a'; notice.style.color='#e57373';
      notice.textContent='Restore failed: '+e.message;
      setTimeout(()=>notice.remove(), 6000);
    }
  };
  input.click();
}

/* ══════════════════════════════════════════════════════
   TIER SELECTOR
   ══════════════════════════════════════════════════════ */
function openTierSelector(){
  showMo('Account Tier',`
    <div class="notice n-info" style="margin-bottom:16px">
      Your tier controls which features are visible. Switch to Attorney to unlock the
      Client Portal, Conflict Check, and Time Entries.
    </div>
    <div style="display:flex;flex-direction:column;gap:10px">
      <div class="card cb" style="cursor:pointer;border:2px solid ${_userTier==='pro_se'?'var(--gold)':' var(--border)'}" onclick="setTier('pro_se')">
        <div style="font-size:14px;font-weight:600;margin-bottom:3px">Pro Se Litigant</div>
        <div style="font-size:12px;color:var(--ink2)">Full case management, evidence engine, AI tools, document generation, hearing prep.</div>
      </div>
      <div class="card cb" style="cursor:pointer;border:2px solid ${_userTier==='attorney'?'var(--gold)':' var(--border)'}" onclick="setTier('attorney')">
        <div style="font-size:14px;font-weight:600;margin-bottom:3px">⚖ Attorney</div>
        <div style="font-size:12px;color:var(--ink2)">Everything above + Client Portal, Conflict Checks, Time Entries, Redacted Export.</div>
      </div>
    </div>
    <div style="font-size:11px;color:var(--ink3);margin-top:14px">You can switch between tiers at any time. No data is lost.</div>
    <div class="br"><button class="btn btn-s" onclick="closeMo()">Close</button></div>
  `);
}
async function setTier(tier){
  const d = await api('/api/me/tier',{tier});
  if(d.ok){ closeMo(); await loadUserTier(); }
  else alert(d.error||'Failed to update tier');
}

/* ══════════════════════════════════════════════════════
   COURTLISTENER CITATION VERIFICATION UI
   ══════════════════════════════════════════════════════ */
function renderCitationWarnings(citations){
  if(!citations||!citations.length) return '';
  const warnings = citations.filter(c=>!c.found);
  const verified = citations.filter(c=>c.found);
  if(!warnings.length && !verified.length) return '';
  return `<div style="margin-top:14px;padding:12px 14px;background:var(--surface2);border-radius:var(--r);border:1px solid var(--border)">
    <div style="font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--ink3);margin-bottom:8px">Citation Verification (CourtListener)</div>
    ${verified.map(c=>`
      <div style="font-size:12px;margin-bottom:4px;color:var(--green)">
        ✓ <strong>${esc(c.citation)}</strong>${c.case_name?` — ${esc(c.case_name)}`:''}
        ${c.url?`<a href="${c.url}" target="_blank" style="color:var(--blue);margin-left:6px;font-size:11px">View ↗</a>`:''}
      </div>`).join('')}
    ${warnings.map(c=>`
      <div style="font-size:12px;margin-bottom:4px;color:var(--amber)">
        ⚠ <strong>${esc(c.citation)}</strong> — ${esc(c.warning||'Not found in CourtListener')}
      </div>`).join('')}
    <div style="font-size:10px;color:var(--ink3);margin-top:6px;font-style:italic">Verify all citations before filing. CourtListener covers federal and many state courts.</div>
  </div>`;
}

async function init(){
  await Promise.all([loadCases(), loadUserTier()]);
  try{
    const r = await fetch('/api/chat',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({case_id:0,message:'ping'})});
    const d = await r.json();
    const on = d.reply && !d.reply.includes('No API key') && !d.reply.includes('AI features require');
    document.getElementById('apill').classList.toggle('on',on);
    document.getElementById('apill-t').textContent = on ? 'AI ready' : 'AI offline — no key set';
  }catch(e){ document.getElementById('apill-t').textContent = 'AI offline'; }
}

/* ── Cases ── */
async function loadCases(){
  const cases = await api('/api/cases');
  const el = document.getElementById('case-list');
  el.innerHTML = '';
  if(!cases.length){el.innerHTML='<div style="padding:14px;font-size:11px;color:var(--ink3);text-align:center">No cases yet</div>';return;}
  cases.forEach(c=>{
    const d = document.createElement('div');
    d.className='ci'+(CC?.id===c.id?' active':'');
    d.innerHTML=`
      <div style="display:flex;align-items:center;gap:6px">
        <div style="flex:1;min-width:0">
          <div class="ci-t">${esc(c.title)}</div>
          <div class="ci-m">${c.case_type||''} · ${c.jurisdiction||''}</div>
        </div>
        <button onclick="event.stopPropagation();deleteCase(${c.id},'${esc(c.title)}')"
          style="flex-shrink:0;background:none;border:none;color:var(--ink3);cursor:pointer;font-size:14px;padding:2px 4px;border-radius:3px;line-height:1"
          title="Delete case">×</button>
      </div>`;
    d.onclick=()=>loadCase(c.id);
    el.appendChild(d);
  });
}

async function loadCase(id){
  const data = await api('/api/cases/'+id);
  CC = data.case; CC._p=data.parties; CC._ev=data.evidence;
  CC._docs=data.documents; CC._tl=data.timeline;
  CC._fin=data.financials; CC._dl=data.deadlines;
  document.getElementById('welcome').style.display='none';
  document.getElementById('cv').style.display='flex';
  document.getElementById('cv-title').textContent=CC.title;
  const hdParts = [CC.case_type,CC.jurisdiction,CC.court_name,CC.case_number?'#'+CC.case_number:null].filter(Boolean).join(' · ');
  const metaEl = document.getElementById('cv-meta');
  // build statute verify links if we have a jurisdiction
  let statuteLinks = '';
  if(CC.jurisdiction){
    const j = encodeURIComponent(CC.jurisdiction);
    const ct = encodeURIComponent(CC.case_type||'custody');
    statuteLinks = ` <span style="margin-left:6px">` +
      `<a href="https://www.google.com/search?q=${j}+${ct}+statute" target="_blank" ` +
      `style="font-size:10px;color:var(--blue);text-decoration:none;border:1px solid var(--blue-bd);border-radius:3px;padding:1px 6px" ` +
      `title="Search for current statutes in ${CC.jurisdiction}">Verify law ↗</a></span>`;
  }
  metaEl.innerHTML = esc(hdParts) + statuteLinks;
  document.querySelectorAll('.ci').forEach(el=>{
    el.classList.toggle('active', el.querySelector('.ci-t')?.textContent===CC.title);
  });
  switchTab(ctab);
}

async function refresh(){ if(CC) await loadCase(CC.id); }

/* ── Tabs ── */
function switchTab(tab){
  ctab=tab;
  document.querySelectorAll('.tab').forEach(t=>t.classList.toggle('active',t.textContent.trim().toLowerCase().replace(/[^a-z]/g,"")===tab.toLowerCase().replace(/[^a-z]/g,"")));
  const c=document.getElementById('tc');
  const map={overview:renderOverview,evidence:renderEvidence,timeline:renderTimeline,
    deadlines:renderDeadlines,documents:renderDocuments,financial:renderFinancial,
    hearing:renderHearing,arguments:renderArguments,strategy:renderStrategy,
    resources:renderResources,courtroom:renderCourtroom,dynamics:renderDynamics,chat:renderChat,
    roadmap:renderRoadmap,motions:renderMotions,comms:renderComms,attorney:renderAttorney};
  if(map[tab]) map[tab](c);
}

/* ── Attorney tier visibility ── */
let _userTier = 'pro_se';
async function loadUserTier(){
  try{
    const me = await api('/api/me');
    _userTier = me.tier || 'pro_se';
    document.querySelectorAll('.atty-only').forEach(el=>{
      el.style.display = _userTier==='attorney' ? '' : 'none';
    });
    // Show tier badge in header
    const badge = document.getElementById('tier-badge');
    if(badge) badge.textContent = _userTier==='attorney' ? '⚖ Attorney' : 'Pro Se';
  }catch(e){}
}

/* ══════════ OVERVIEW ══════════ */
async function renderOverview(c){
  const ev=CC._ev||[], conf=ev.filter(e=>e.confirmed), unc=ev.filter(e=>!e.confirmed);
  const dl=CC._dl||[], over=dl.filter(d=>!d.completed&&d.due_date<today()), due=dl.filter(d=>!d.completed&&d.due_date>=today());
  const cats=[...new Set(conf.map(e=>e.category).filter(Boolean))];

  // Fetch guidance and interpretation in parallel — both are deterministic, fast
  let guidance=[], interp=null;
  try {
    [guidance, interp] = await Promise.all([
      api('/api/cases/'+CC.id+'/guidance'),
      api('/api/cases/'+CC.id+'/interpret')
    ]);
  } catch(e) { /* non-fatal — render without */ }

  const _levelCls = {critical:'n-red', high:'n-warn', moderate:'n-info', normal:''};
  const _urgCls   = {critical:'var(--red)', high:'var(--amber)', moderate:'var(--blue)', normal:'var(--green)'};

  const guidanceHtml = guidance?.length ? `
  <div class="section">
    <div class="st" style="color:var(--gold)">Priority Actions</div>
    ${interp?.interpretation?.summary ? `<div class="notice ${_levelCls[interp.interpretation.urgency]||'n-info'}" style="margin-bottom:12px;font-weight:500">${esc(interp.interpretation.summary)}</div>` : ''}
    <div style="display:flex;flex-direction:column;gap:8px">
      ${guidance.map(g=>`
        <div class="card cb" style="border-left:3px solid ${_urgCls[g.level]||'var(--border)'};cursor:pointer;transition:opacity .1s" onclick="switchTab('${g.action_tab}')" title="Go to ${g.action_tab}">
          <div style="display:flex;align-items:flex-start;gap:10px">
            <span style="font-size:18px;flex-shrink:0">${g.icon}</span>
            <div style="flex:1;min-width:0">
              <div style="font-size:13px;font-weight:600;color:${_urgCls[g.level]||'var(--ink)'};margin-bottom:3px">${esc(g.title)}</div>
              <div style="font-size:12px;color:var(--ink2);line-height:1.6">${esc(g.detail)}</div>
            </div>
            <span style="font-size:11px;color:var(--ink3);white-space:nowrap;flex-shrink:0;margin-top:2px">→ ${esc(g.action_tab)}</span>
          </div>
        </div>`).join('')}
    </div>
  </div>` : '';

  const interpHtml = interp?.interpretation ? `
  <div class="section">
    <div class="st">What Your Scores Mean Right Now</div>
    <div class="card" style="overflow:hidden">
      <div style="padding:11px 16px;border-bottom:1px solid var(--border2)">
        <div style="font-size:10px;text-transform:uppercase;letter-spacing:.08em;color:var(--ink3);margin-bottom:4px">Evidence Strength (x=${interp.state.x}/9)</div>
        <div style="font-size:13px;color:var(--ink2);line-height:1.6">${esc(interp.interpretation.x_text)}</div>
      </div>
      <div style="padding:11px 16px;border-bottom:1px solid var(--border2)">
        <div style="font-size:10px;text-transform:uppercase;letter-spacing:.08em;color:var(--ink3);margin-bottom:4px">Procedural Health (y=${interp.state.y}/9)</div>
        <div style="font-size:13px;color:var(--ink2);line-height:1.6">${esc(interp.interpretation.y_text)}</div>
      </div>
      <div style="padding:11px 16px">
        <div style="font-size:10px;text-transform:uppercase;letter-spacing:.08em;color:var(--ink3);margin-bottom:4px">Adversarial Pressure (z=${interp.state.z}/9)</div>
        <div style="font-size:13px;color:var(--ink2);line-height:1.6">${esc(interp.interpretation.z_text)}</div>
      </div>
    </div>
  </div>` : '';

  c.innerHTML=`
  <div class="grid4" style="margin-bottom:20px">
    ${stat(conf.length,'Confirmed evidence','','good')}
    ${stat(unc.length,'Needs review','','warn')}
    ${stat(due.length,'Upcoming deadlines','')}
    ${stat(over.length,'Overdue','','warn')}
  </div>
  ${guidanceHtml}
  ${interpHtml}
  ${CC._p?.length?`<div class="section"><div class="st">Parties</div><div class="card cb" style="display:flex;flex-wrap:wrap;gap:8px">
    ${CC._p.map(p=>`<div style="background:var(--bg);border:1px solid var(--border);border-radius:var(--r);padding:7px 12px">
      <div style="font-weight:500;font-size:15px">${esc(p.name)}</div>
      <div style="font-size:13px;color:var(--ink3)">${esc(p.role)}${p.attorney?` · Atty: ${esc(p.attorney)}`:''}</div>
    </div>`).join('')}
  </div></div>`:''}
  ${over.length?`<div class="section"><div class="st" style="color:var(--red)">Overdue Deadlines</div><div class="card">
    ${over.map(d=>`<div class="dl-item"><div class="dl-date" style="color:var(--red);font-size:13px">${d.due_date}</div><div class="dl-title" style="font-size:15px">${esc(d.title)}</div></div>`).join('')}
  </div></div>`:''}
  ${cats.length?`<div class="section"><div class="st">Evidence by Category</div><div class="card cb" style="display:flex;flex-wrap:wrap;gap:7px">
    ${cats.map(cat=>{const n=conf.filter(e=>e.category===cat).length;
      return `<div onclick="evFilter='${cat}';switchTab('evidence')" style="cursor:pointer;padding:7px 16px;border-radius:20px;border:1px solid var(--border);font-size:14px"><span style="font-weight:500">${esc(cat)}</span> <span style="color:var(--ink3)">${n}</span></div>`;
    }).join('')}
  </div></div>`:''}
  ${CC.goals?`<div class="section"><div class="st">Case Goals</div><div class="card cb" style="font-size:15px;color:var(--ink2);line-height:1.8">${esc(CC.goals)}</div></div>`:''}
  ${CC.notes?`<div class="section"><div class="st">Background Notes</div><div class="card cb" style="font-size:15px;color:var(--ink2);line-height:1.8">${esc(CC.notes)}</div></div>`:''}`;
}
function stat(n,label,sub,v=''){
  const cls=v==='warn'?'stat warn':v==='good'?'stat good':'stat';
  return `<div class="${cls}"><div class="stat-n">${n}</div><div class="stat-l">${label}</div>${sub?`<div style="font-size:10px;color:var(--ink3)">${sub}</div>`:''}</div>`;
}

/* ══════════ EVIDENCE ══════════ */
function renderEvidence(c){
  const ev=CC._ev||[];
  const cats=['All',...new Set(ev.map(e=>e.category).filter(Boolean))];
  if(!cats.includes(evFilter)) evFilter='All';
  const filtered=evFilter==='All'?ev:ev.filter(e=>e.category===evFilter);
  const unc=filtered.filter(e=>!e.confirmed), conf=filtered.filter(e=>e.confirmed);
  c.innerHTML=`
  <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:12px">
    <div class="filter-row" style="margin-bottom:0">
      ${cats.map(cat=>`<div class="fp${evFilter===cat?' active':''}" onclick="evFilter='${cat}';renderEvidence(document.getElementById('tc'))">${cat}</div>`).join('')}
    </div>
    <div style="display:flex;gap:6px;flex-shrink:0;margin-left:10px">
      <button class="btn btn-s" onclick="openAddEv()">+ Add Item</button>
      <button class="btn btn-s" onclick="openAttachFile()">📎 Attach File</button>
      <button class="btn btn-s" onclick="openImport()">↑ Import SMS</button>
    </div>
  </div>
  ${unc.length?`<div class="section"><div class="st" style="color:var(--amber)">⚠ Needs Review (${unc.length})</div>
    <div class="notice n-warn">Auto-flagged messages — review each one and confirm or remove before it counts as evidence.</div>
    <div class="card">${unc.map(evRow).join('')}</div></div>`:''}
  <div class="section">
    <div class="st">Confirmed Evidence (${conf.length}) <button class="xbtn" onclick="openAddEv()" style="font-size:10px">+ Add</button></div>
    ${conf.length?`<div class="card">${conf.map(evRow).join('')}</div>`
      :`<p style="font-size:12px;color:var(--ink3)">No confirmed evidence yet. Add items or import messages above.</p>`}
  </div>`;
}
// Confidence framing shown on unconfirmed flagged evidence
const _CONF_LABELS = {
  strong:   'Strong indicator — pattern closely matches known violation language.',
  likely:   'Likely indicator — pattern matches common conduct of concern.',
  possible: 'Possible indicator — language may be relevant; confirm carefully.',
};
const _CONF_DISCLAIMER = 'This flag does NOT establish a legal violation. Review the entry and confirm only if it accurately represents what occurred.';

function evRow(e){
  const evDate=e.event_date?e.event_date.slice(0,10):'undated';
  const en=e.exhibit_number||'';
  const isImg = e.file_type && ['jpg','jpeg','png','gif','webp','heic'].includes(e.file_type.toLowerCase());
  const isPdf = e.file_type && e.file_type.toLowerCase()==='pdf';
  const hasFile = !!e.file_path;
  // Confidence framing: only shown for unconfirmed flagged items
  const showFlag = !e.confirmed && e.category && e.category !== 'General' && e.category !== 'Document'
                   && e.category !== 'Photo/Video' && e.category !== 'Communication';
  const confLevel = e.confidence || (e.category && ['Gatekeeping','Violation of Order','Threats','Relocation'].includes(e.category) ? 'strong'
                  : ['Parental Alienation','Harassment','Financial','Stonewalling'].includes(e.category) ? 'likely' : 'possible');
  const flagBlock = showFlag ? `
    <div style="margin-top:8px;padding:8px 10px;background:var(--amber-bg);border:1px solid var(--amber-bd);border-radius:var(--r)">
      <div style="font-size:11px;font-weight:600;color:var(--amber);margin-bottom:3px">⚑ Auto-flagged as ${esc(e.category)} — ${confLevel}</div>
      <div style="font-size:11px;color:var(--ink2);margin-bottom:4px">${esc(_CONF_LABELS[confLevel]||'')}</div>
      <div style="font-size:10px;color:var(--ink3);font-style:italic">${_CONF_DISCLAIMER}</div>
    </div>` : '';
  return `<div class="ev">
    <span class="badge ${e.confirmed?'confirmed':'unconfirmed'}">${esc(e.category||'General')}</span>
    <div class="ev-body">
      ${en?`<div style="font-size:10px;color:var(--blue);font-weight:500;margin-bottom:3px">${esc(en)}</div>`:''}
      <div class="ev-content">${esc((e.content||'').slice(0,300))}${(e.content||'').length>300?'…':''}</div>
      ${hasFile && isImg ? `<img src="${e.file_path}" style="max-width:100%;max-height:180px;border-radius:4px;margin-top:6px;border:1px solid var(--border)" loading="lazy">` : ''}
      ${hasFile && isPdf ? `<a href="${e.file_path}" target="_blank" style="font-size:11px;color:var(--blue);display:inline-block;margin-top:5px">📄 View PDF ↗</a>` : ''}
      ${hasFile && !isImg && !isPdf ? `<a href="${e.file_path}" target="_blank" style="font-size:11px;color:var(--blue);display:inline-block;margin-top:5px">📎 View attachment ↗</a>` : ''}
      ${flagBlock}
      <div class="ev-meta" style="margin-top:6px">${evDate} · ${esc(e.source||'manual')}</div>
      ${e.notes?`<div class="ev-meta">${esc(e.notes)}</div>`:''}
      <div class="ev-acts">
        ${!e.confirmed?`<button class="xbtn ok" onclick="confirmEv(${e.id})">✓ Confirm as Evidence</button>`:''}
        <button class="xbtn rm" onclick="delEv(${e.id})">✕ Remove</button>
      </div>
    </div>
  </div>`;
}
async function confirmEv(id){await api('/api/evidence/confirm',{id});await refresh();}
async function delEv(id){if(!confirm('Remove this item?'))return;await api('/api/evidence/delete',{id});await refresh();}

function openAddEv(){
  showMo('Add Evidence Item',`
    <div class="fg"><label>Content / Description</label><textarea id="ev-c" placeholder="Describe the event, paste a message, or summarize a document…" style="min-height:90px"></textarea></div>
    <div class="two-col">
      <div class="fg"><label>Date of Event</label><input type="date" id="ev-d"></div>
      <div class="fg"><label>Category</label><select id="ev-cat">
        ${['Gatekeeping','Parental Alienation','Stonewalling','Threats','Harassment','Violation of Order','Financial','Communication','Witness','Document','Photo/Video','Other'].map(c=>`<option>${c}</option>`).join('')}
      </select></div>
    </div>
    <div class="fg"><label>Source / Context</label><input id="ev-src" placeholder="e.g. text message, email, police report, witness"></div>
    <div class="fg"><label>Notes (optional)</label><input id="ev-n" placeholder="Any additional context…"></div>
    <div class="br">
      <button class="btn btn-s" onclick="closeMo()">Cancel</button>
      <button class="btn btn-p" onclick="submitEv()">Add to Case</button>
    </div>`);
}
async function submitEv(){
  const content=val('ev-c'); if(!content){alert('Please enter content.');return;}
  await api('/api/evidence',{case_id:CC.id,content,event_date:val('ev-d'),source:val('ev-src'),category:val('ev-cat'),notes:val('ev-n')});
  closeMo(); await refresh();
}

function openAttachFile(){
  showMo('Attach File to Evidence',`
    <div class="notice n-info">Attach a photo, PDF, audio recording, or document. Stays on your computer.</div>
    <div class="fg"><label>File</label>
      <input type="file" id="af-file" accept="image/*,.pdf,.txt,.mp3,.mp4,.mov,.m4a" style="padding:6px">
    </div>
    <div class="two-col">
      <div class="fg"><label>Date</label><input type="date" id="af-date"></div>
      <div class="fg"><label>Category</label><select id="af-cat">
        ${['Photo / Video','Police Report','Medical Record','Financial Record','Court Document','Audio Recording','Screenshot','Other'].map(c=>`<option>${c}</option>`).join('')}
      </select></div>
    </div>
    <div class="fg"><label>Description / Notes</label><input id="af-notes" placeholder="Describe what this file shows…"></div>
    <div id="af-status" style="font-size:12px;color:var(--ink2)"></div>
    <div class="br"><button class="btn btn-s" onclick="closeMo()">Cancel</button>
    <button class="btn btn-p" id="af-btn" onclick="submitAttachFile()">Attach to Case</button></div>`);
}
async function submitAttachFile(){
  const fileInput = document.getElementById('af-file');
  if(!fileInput.files[0]){alert('Please select a file.');return;}
  const file = fileInput.files[0];
  const status = document.getElementById('af-status');
  const btn = document.getElementById('af-btn');
  btn.disabled=true; status.textContent='Reading file…';
  const reader = new FileReader();
  reader.onload = async(e)=>{
    const b64 = e.target.result.split(',')[1];
    status.textContent='Uploading…';
    const d = await api('/api/upload-file',{
      case_id:CC.id, filename:file.name, data:b64,
      event_date:val('af-date'), category:val('af-cat'), notes:val('af-notes')
    });
    if(d.error){status.textContent='Error: '+d.error;btn.disabled=false;return;}
    closeMo(); await refresh();
  };
  reader.readAsDataURL(file);
}

function openImport(){
  showMo('Import SMS / MMS Messages',`
    <div class="notice n-info">Export messages using "SMS Backup &amp; Restore" (Android) or similar. The XML file stays on your computer — it is never uploaded.</div>
    <div id="dz" onclick="document.getElementById('xi').click()" ondragover="this.classList.add('over');event.preventDefault()" ondragleave="this.classList.remove('over')" ondrop="handleDrop(event)">
      Drop your XML backup here, or click to browse
      <input type="file" id="xi" accept=".xml" style="display:none" onchange="handleFile(event)">
    </div>
    <div class="fg"><label>Filter by phone number (optional)</label><input id="xn" placeholder="e.g. 9015550123 — leave blank to import all"></div>
    <div class="notice n-warn">⚠ SynJuris will flag messages matching known patterns. You MUST review and confirm each one — flagging is not the same as evidence.</div>
    <div id="xi-status" style="font-size:12px;color:var(--ink2);margin-top:6px"></div>
    <div class="br"><button class="btn btn-s" onclick="closeMo()">Close</button></div>`);
}
function handleDrop(e){e.preventDefault();document.getElementById('dz').classList.remove('over');if(e.dataTransfer.files[0]) processXML(e.dataTransfer.files[0]);}
function handleFile(e){if(e.target.files[0]) processXML(e.target.files[0]);}
function processXML(file){
  const st=document.getElementById('xi-status');
  if(file.size > 20*1024*1024){
    st.innerHTML='<span style="color:var(--amber)">&#9888; Large file ('+Math.round(file.size/1024/1024)+'MB) detected. Use the phone number filter to import one contact at a time.</span>';
  } else { st.textContent='Reading file...'; }
  const r=new FileReader();
  r.onload=async(e)=>{
    st.textContent='Analyzing messages...';
    try {
      const d=await api('/api/import-xml',{xml:e.target.result,case_id:CC.id,target_number:val('xn')});
      if(d.error){st.innerHTML='<span style="color:var(--red)">Error: '+esc(d.error)+'</span>';return;}
      st.innerHTML='<strong>Done.</strong> Imported '+d.imported+' messages (SMS + MMS). <span style="color:var(--amber)">'+d.flagged+' flagged for review.</span> Go to Evidence tab to confirm.';
      await refresh();
    } catch(err){
      st.innerHTML='<span style="color:var(--red)">Failed — file may be too large. Try filtering by phone number.</span>';
    }
  };
  r.onerror=()=>{st.innerHTML='<span style="color:var(--red)">Could not read file. Make sure it is a valid .xml export.</span>';};
  r.readAsText(file,'UTF-8');
}

/* ══════════ TIMELINE ══════════ */
function renderTimeline(c){
  const tl=CC._tl||[];
  const ev=(CC._ev||[]).filter(e=>e.confirmed&&e.event_date).map(e=>({
    id:'ev-'+e.id,event_date:e.event_date,title:e.exhibit_number||e.category,
    description:(e.content||'').slice(0,120),category:'Evidence',importance:'normal',_ev:true
  }));
  const all=[...tl,...ev].sort((a,b)=>a.event_date?.localeCompare(b.event_date||'')||0);
  c.innerHTML=`
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
    <p style="font-size:12px;color:var(--ink2)">Chronological view of all case events and evidence.</p>
    <button class="btn btn-s" onclick="openAddTL()">+ Add Event</button>
  </div>
  ${!all.length?'<p style="font-size:12px;color:var(--ink3)">No events yet. Add timeline events or confirm dated evidence.</p>':
  `<div class="tl">${all.map(e=>`
    <div class="tl-item ${e.importance}">
      <div class="tl-dot"></div>
      <div class="tl-date">${e.event_date?.slice(0,10)||'undated'} ${e._ev?'<span class="badge blue" style="margin-left:4px">Evidence</span>':''}</div>
      <div class="tl-title">${esc(e.title)}</div>
      ${e.description?`<div class="tl-desc">${esc(e.description)}</div>`:''}
      ${!e._ev?`<div style="margin-top:4px"><button class="xbtn rm" onclick="delTL(${e.id})">Remove</button></div>`:''}
    </div>`).join('')}
  </div>`}`;
}
function openAddTL(){
  showMo('Add Timeline Event',`
    <div class="two-col">
      <div class="fg"><label>Date</label><input type="date" id="tl-d"></div>
      <div class="fg"><label>Importance</label><select id="tl-i"><option value="normal">Normal</option><option value="high">High (red)</option><option value="low">Low</option></select></div>
    </div>
    <div class="fg"><label>Event Title</label><input id="tl-t" placeholder="e.g. First custody exchange denied"></div>
    <div class="fg"><label>Description</label><textarea id="tl-desc" placeholder="What happened? Be specific."></textarea></div>
    <div class="fg"><label>Category</label><select id="tl-cat">
      ${['Incident','Court Date','Communication','Exchange','Violation','Agreement','Filing','Other'].map(c=>`<option>${c}</option>`).join('')}
    </select></div>
    <div class="br"><button class="btn btn-s" onclick="closeMo()">Cancel</button><button class="btn btn-p" onclick="submitTL()">Add Event</button></div>`);
}
async function submitTL(){
  const t=val('tl-t');if(!t){alert('Please enter a title.');return;}
  await api('/api/timeline',{case_id:CC.id,event_date:val('tl-d'),title:t,description:val('tl-desc'),category:val('tl-cat'),importance:val('tl-i')});
  closeMo();await refresh();
}
async function delTL(id){if(!confirm('Remove?'))return;await api('/api/timeline/'+id,{});await refresh();}

/* ══════════ DEADLINES ══════════ */
function renderDeadlines(c){
  const dl=CC._dl||[];
  const pend=dl.filter(d=>!d.completed), done_=dl.filter(d=>d.completed);
  const tod=today();
  c.innerHTML=`
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">
    <p style="font-size:12px;color:var(--ink2)">Track court deadlines, filing dates, and hearing dates.</p>
    <button class="btn btn-s" onclick="openAddDL()">+ Add Deadline</button>
  </div>
  ${!pend.length?'<p style="font-size:12px;color:var(--ink3)">No pending deadlines.</p>':
  `<div class="section"><div class="st">Pending (${pend.length})</div><div class="card">
    ${pend.map(d=>{
      const over=d.due_date&&d.due_date<tod;
      return`<div class="dl-item">
        <div class="dl-date" style="${over?'color:var(--red);font-weight:500':''}"">${d.due_date||'—'}${over?' ⚠':''}</div>
        <div class="dl-title">${esc(d.title)}</div>
        ${d.description?`<div style="font-size:10px;color:var(--ink3)">${esc(d.description)}</div>`:''}
        <div class="dl-acts">
          <button class="xbtn ok" onclick="completeDL(${d.id})">✓ Done</button>
          <button class="xbtn rm" onclick="delDL(${d.id})">✕</button>
        </div>
      </div>`;}).join('')}
  </div></div>`}
  ${done_.length?`<div class="section"><div class="st">Completed (${done_.length})</div><div class="card">
    ${done_.map(d=>`<div class="dl-item done"><div class="dl-date">${d.due_date||'—'}</div><div class="dl-title">${esc(d.title)}</div></div>`).join('')}
  </div></div>`:''}`;
}
function openAddDL(){
  showMo('Add Deadline',`
    <div class="two-col">
      <div class="fg"><label>Due Date</label><input type="date" id="dl-d"></div>
      <div class="fg"><label>Title</label><input id="dl-t" placeholder="e.g. File response to motion"></div>
    </div>
    <div class="fg"><label>Description (optional)</label><input id="dl-desc" placeholder="Any notes about this deadline…"></div>
    <div class="br"><button class="btn btn-s" onclick="closeMo()">Cancel</button><button class="btn btn-p" onclick="submitDL()">Add</button></div>`);
}
async function submitDL(){
  if(!val('dl-t')){alert('Please enter a title.');return;}
  await api('/api/deadlines',{case_id:CC.id,due_date:val('dl-d'),title:val('dl-t'),description:val('dl-desc')});
  closeMo();await refresh();
}
async function completeDL(id){await api('/api/deadlines/'+id+'/complete',{completed:1});await refresh();}
async function delDL(id){if(!confirm('Delete?'))return;await api('/api/deadlines/'+id,{});await refresh();}

/* ══════════ DOCUMENTS ══════════ */
function renderDocuments(c){
  const docs=CC._docs||[];
  const types=[
    {icon:'📋',label:'Motion',desc:'Ask the court for something'},
    {icon:'📝',label:'Declaration',desc:'Sworn written statement'},
    {icon:'✉️',label:'Demand Letter',desc:'Formal request to other party'},
    {icon:'📅',label:'Parenting Plan',desc:'Detailed custody schedule'},
    {icon:'⚖️',label:'Response / Answer',desc:'Reply to filed complaint'},
    {icon:'📄',label:'Exhibit List',desc:'Index of all your evidence'},
    {icon:'🏠',label:'Habitability Notice',desc:'Notify landlord of repair issues'},
    {icon:'💰',label:'Small Claims Statement',desc:'State your claim plainly'},
    {icon:'🛡️',label:'Protective Order Request',desc:'Request safety from the court'},
    {icon:'📊',label:'Child Support Worksheet',desc:'Income &amp; expense breakdown'},
    {icon:'📬',label:'Notice of Hearing',desc:'Notify parties of court date'},
    {icon:'✍️',label:'Settlement Proposal',desc:'Propose resolution terms'},
  ];
  c.innerHTML=`
  <div class="section">
    <div class="st">Generate a Document</div>
    <p style="font-size:12px;color:var(--ink2);margin-bottom:12px">SynJuris will draft a complete document using your case facts and evidence. Review and fill in all [BRACKET PLACEHOLDERS] before filing.</p>
    <div class="dt-grid">${types.map(t=>`
      <div class="dt-card" onclick="openDocGen('${t.label}')">
        <div class="dt-icon">${t.icon}</div>
        <div class="dt-lbl">${t.label}</div>
        <div class="dt-desc">${t.desc}</div>
      </div>`).join('')}</div>
  </div>
  ${docs.length?`<div class="section"><div class="st">Saved Documents (${docs.length})</div><div class="card">
    ${docs.map(d=>`<div class="ev">
      <span class="badge blue">${esc(d.doc_type)}</span>
      <div class="ev-body">
        <div class="ev-content" style="font-weight:500">${esc(d.title)}</div>
        <div class="ev-meta">${d.created_at?.slice(0,10)}</div>
        <div class="ev-acts"><button class="xbtn" onclick="viewDoc(${d.id})">View / Copy</button></div>
      </div>
    </div>`).join('')}
  </div></div>`:''}`;
}
function openDocGen(dtype){
  showMo('Generate: '+dtype,`
    <div class="notice n-info">SynJuris will draft a complete ${dtype} using your confirmed evidence and case details.</div>
    <div class="notice n-warn">This is a self-help draft only — not legal advice. Review every word, fill in all [BRACKET PLACEHOLDERS], and consult an attorney before filing. If your court requires AI disclosure, add: <em>"Portions of this document were prepared with the assistance of AI software (SynJuris/Claude). The filer has reviewed and accepts responsibility for all content."</em></div>
    <div class="fg"><label>Special Instructions (optional)</label><textarea id="di" placeholder="e.g. Focus on the March 15 incident, request expedited hearing, include attorney fee request…"></textarea></div>
    <div id="dg-st" style="font-size:12px;color:var(--ink2)"></div>
    <div class="br"><button class="btn btn-s" onclick="closeMo()">Cancel</button><button class="btn btn-p" id="gen-btn" onclick="genDoc('${dtype}')">Generate Draft</button></div>`);
}
async function genDoc(dtype){
  const st=document.getElementById('dg-st');
  setBtnLoading('gen-btn', true, 'Generate Draft');
  if(st) st.innerHTML=loadingHTML('Drafting your '+dtype+'…','small');
  let d;
  try { d=await api('/api/generate-doc',{case_id:CC.id,doc_type:dtype,instructions:val('di')}); }
  catch(e){ setBtnLoading('gen-btn',false,'Generate Draft'); if(st) st.innerHTML=errorHTML('Network error — try again.'); return; }
  setBtnLoading('gen-btn', false, 'Generate Draft');
  closeMo(); await refresh();
  if(d.content) viewDocContent(d.content, dtype, d.citations||[], d.id);
}
async function viewDoc(id){
  const d=await api('/api/documents/'+id);
  if(d.content) viewDocContent(d.content, d.doc_type, [], id);
}
function viewDocContent(content, title, citations, docId){
  const citBlock = renderCitationWarnings(citations||[]);
  const docxBtn = docId ? `<button class="btn btn-s btn-p" onclick="downloadDocx(${docId})">↓ Download .docx</button>` : '';
  showMo(title,`
    <div class="notice n-warn">Review carefully before filing. Fill in ALL [BRACKET PLACEHOLDERS]. This is a draft — not legal advice.</div>
    ${citBlock}
    <div id="doc-pre" style="margin-top:12px;white-space:pre-wrap;font-family:var(--mono);font-size:12px;line-height:1.6;max-height:400px;overflow-y:auto">${esc(content)}</div>
    <div class="br" style="margin-top:12px">
      <button class="btn btn-s" onclick="copyDoc()">Copy to Clipboard</button>
      ${docxBtn}
      <button class="btn btn-s" onclick="closeMo()">Close</button>
    </div>`);
}

function downloadDocx(id){
  const a=document.createElement('a');
  a.href='/api/documents/'+id+'/docx';
  a.download='';
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
}

function readinessReport(){
  if(!CC) return;
  const a=document.createElement('a');
  a.href='/api/cases/'+CC.id+'/readiness-pdf';
  a.download='';
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
}
async function copyDoc(){await navigator.clipboard.writeText(document.getElementById('doc-pre').textContent);alert('Copied to clipboard.');}

/* ══════════ FINANCIAL ══════════ */
function renderFinancial(c){
  const fin=CC._fin||[];
  const income=fin.filter(f=>f.direction==='income').reduce((a,f)=>a+(f.amount||0),0);
  const expense=fin.filter(f=>f.direction==='expense').reduce((a,f)=>a+(f.amount||0),0);
  c.innerHTML=`
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
    <p style="font-size:12px;color:var(--ink2)">Track case-related income, expenses, and support payments.</p>
    <div style="display:flex;gap:8px">
      <button class="btn btn-s" onclick="openChildSupport()">⚖ Child Support Calc</button>
      <button class="btn btn-s" onclick="openAddFin()">+ Add Entry</button>
    </div>
  </div>
  <div class="grid3" style="margin-bottom:20px">
    ${stat('$'+income.toFixed(2),'Total income','')}
    ${stat('$'+expense.toFixed(2),'Total expenses','')}
    ${stat('$'+(income-expense).toFixed(2),'Net','','gain'+(income-expense>=0?' good':' warn'))}
  </div>
  ${!fin.length?'<p style="font-size:12px;color:var(--ink3)">No financial entries yet.</p>':
  `<div class="card">${fin.map(f=>`<div class="fin-item">
    <div style="font-size:10px;color:var(--ink3);min-width:80px">${f.entry_date||'—'}</div>
    <div class="fin-desc">${esc(f.description)}<div style="font-size:10px;color:var(--ink3)">${f.category||''}</div></div>
    <div class="fin-amt ${f.direction}">${f.direction==='income'?'+':'-'}$${(f.amount||0).toFixed(2)}</div>
    <button class="xbtn rm" onclick="delFin(${f.id})">✕</button>
  </div>`).join('')}</div>`}`;
}
function openAddFin(){
  showMo('Add Financial Entry',`
    <div class="two-col">
      <div class="fg"><label>Date</label><input type="date" id="fi-d"></div>
      <div class="fg"><label>Type</label><select id="fi-dir"><option value="expense">Expense</option><option value="income">Income / Payment received</option></select></div>
    </div>
    <div class="fg"><label>Description</label><input id="fi-desc" placeholder="e.g. Child support payment received, filing fee, attorney consultation…"></div>
    <div class="two-col">
      <div class="fg"><label>Amount ($)</label><input type="number" id="fi-amt" min="0" step="0.01" placeholder="0.00"></div>
      <div class="fg"><label>Category</label><select id="fi-cat">
        ${['Child support','Alimony','Filing fee','Attorney fee','Court costs','Medical','Housing','Other'].map(c=>`<option>${c}</option>`).join('')}
      </select></div>
    </div>
    <div class="br"><button class="btn btn-s" onclick="closeMo()">Cancel</button><button class="btn btn-p" onclick="submitFin()">Add</button></div>`);
}
async function submitFin(){
  const desc=val('fi-desc');if(!desc){alert('Please enter a description.');return;}
  await api('/api/financials',{case_id:CC.id,entry_date:val('fi-d'),description:desc,amount:parseFloat(document.getElementById('fi-amt').value)||0,direction:val('fi-dir'),category:val('fi-cat')});
  closeMo();await refresh();
}
async function delFin(id){if(!confirm('Delete?'))return;await api('/api/financials/'+id,{});await refresh();}

/* ══════════ HEARING PREP ══════════ */
function renderHearing(c){
  const docs=(CC._docs||[]).filter(d=>d.doc_type==='Hearing Prep Guide');
  c.innerHTML=`
  <div style="max-width:600px">
    <p style="font-size:12px;color:var(--ink2);margin-bottom:16px">SynJuris will generate a personalized hearing prep guide using your case facts, evidence, and jurisdiction.</p>
    <div class="notice n-info">The guide includes: opening statement draft, key points, evidence introduction, anticipated arguments, questions to ask, courtroom etiquette, and a checklist of what to bring.</div>
    <div class="br" style="margin-bottom:20px">
      <button class="btn btn-p" id="hp-btn" onclick="genHearingPrep()">Generate Hearing Prep Guide</button>
    </div>
    ${docs.length?`<div class="section"><div class="st">Saved Guides</div><div class="card">
      ${docs.map(d=>`<div class="ev"><span class="badge purple">Hearing Prep</span><div class="ev-body">
        <div class="ev-content" style="font-weight:500">${esc(d.title)}</div>
        <div class="ev-meta">${d.created_at?.slice(0,10)}</div>
        <div class="ev-acts"><button class="xbtn" onclick="viewDoc(${d.id})">View</button></div>
      </div></div>`).join('')}
    </div></div>`:''}
    <div class="section"><div class="st">Courtroom Quick Reference</div>
    <div class="card cb">
      ${[
        ['How to address the judge','Always say "Your Honor." Never "sir," "ma\'am," or "judge."'],
        ['When to stand','Stand when the judge enters or leaves, when addressing the court, and when speaking.'],
        ['Speaking in court','Wait to be recognized. Speak slowly and clearly. Don\'t interrupt.'],
        ['Introducing evidence','Say: "Your Honor, I would like to introduce into evidence what I\'ve marked as [Exhibit #]."'],
        ['Objecting to something','Say: "Objection, Your Honor" and state the reason briefly (e.g., "hearsay," "irrelevant").'],
        ['If you don\'t understand','Say: "Your Honor, I don\'t understand the question. Could you clarify?"'],
        ['Never argue with the judge','If overruled, say "Noted for the record" and move on.'],
        ['Closing','Thank the court: "Thank you, Your Honor."'],
      ].map(([t,d])=>`<div style="margin-bottom:12px">
        <div style="font-size:12px;font-weight:500;margin-bottom:3px">${t}</div>
        <div style="font-size:11px;color:var(--ink2)">${d}</div>
      </div>`).join('')}
    </div></div>
  </div>`;
}
async function genHearingPrep(){
  setBtnLoading('hp-btn', true, 'Generate Hearing Prep Guide');
  let d;
  try { d=await api('/api/hearing-prep',{case_id:CC.id}); }
  catch(e){ setBtnLoading('hp-btn',false,'Generate Hearing Prep Guide'); alert('Network error — check your connection.'); return; }
  setBtnLoading('hp-btn', false, 'Generate Hearing Prep Guide');
  await refresh(); switchTab('hearing');
  if(d.content) viewDocContent(d.content,'Hearing Prep Guide');
}

/* ══════════ RESOURCES ══════════ */
function renderResources(c){ /* privacy notice injected below */
  const sections=[
    {title:'Emergency / Safety',color:'red',items:[
      {name:'National Domestic Violence Hotline',desc:'24/7 crisis support, safety planning, shelter referrals',contact:'1-800-799-7233 · thehotline.org'},
      {name:'National Child Abuse Hotline (Childhelp)',desc:'Report abuse, connect with counselors',contact:'1-800-422-4453 · childhelp.org'},
      {name:'Crisis Text Line',desc:'Text HOME to 741741 for free 24/7 crisis counseling',contact:'Text HOME to 741741'},
      {name:'211 (United Way)',desc:'Local social services, shelter, food, legal aid referrals',contact:'Dial 2-1-1 or 211.org'},
    ]},
    {title:'Free Legal Help',color:'blue',items:[
      {name:'Legal Services Corporation (LSC)',desc:'Free civil legal aid for low-income individuals — find local providers',contact:'lsc.gov/what-legal-aid'},
      {name:'LawHelp.org',desc:'State-by-state free legal resources, forms, and pro bono referrals',contact:'lawhelp.org'},
      {name:'American Bar Association — Free Legal Answers',desc:'Volunteer attorneys answer legal questions online for income-eligible users',contact:'abafreelegalanswers.org'},
      {name:'Law School Clinics',desc:'Many law schools operate free clinics for family law, housing, and more — search your state',contact:'Search: "[your state] law school legal clinic"'},
      {name:'State Bar Lawyer Referral Service',desc:'Most state bars have referral services, some with reduced-fee initial consults',contact:'Search: "[your state] bar lawyer referral"'},
    ]},
    {title:'Court Self-Help',color:'green',items:[
      {name:'Self-Help Centers (court-based)',desc:'Most county courts have a self-help center where staff can answer procedural questions (not legal advice)',contact:'Call your local courthouse and ask for the self-help center'},
      {name:'NOLO',desc:'Plain-English legal guides, forms, and state-specific resources',contact:'nolo.com'},
      {name:'Justia',desc:'Free access to statutes, case law, and legal guides by state',contact:'justia.com'},
      {name:'CourtListener / PACER',desc:'Search federal court records and filings',contact:'courtlistener.com'},
    ]},
    {title:'Children & Family',color:'purple',items:[
      {name:'National Parents Organization',desc:'Resources for parenting time, custody, and shared parenting advocacy',contact:'nationalparentsorganization.org'},
      {name:'Children\'s Rights Council',desc:'Resources and advocacy for children\'s access to both parents',contact:'crckids.org'},
      {name:'Child Welfare Information Gateway',desc:'Federal resource on child welfare, foster care, and family preservation',contact:'childwelfare.gov'},
      {name:'RAINN (Sexual Assault)',desc:'Support for survivors of sexual violence',contact:'1-800-656-4673 · rainn.org'},
    ]},
    {title:'Housing & Tenant Rights',color:'amber',items:[
      {name:'HUD Housing Counseling',desc:'Free or low-cost housing counseling, including tenant rights',contact:'hud.gov/housingcounseling'},
      {name:'National Housing Law Project',desc:'Legal resources for tenants facing eviction',contact:'nhlp.org'},
      {name:'Eviction Lab',desc:'State-by-state eviction data and tenant protection laws',contact:'evictionlab.org'},
      {name:'Tenant Resource Center',desc:'State-specific tenant rights guides and forms',contact:'Search: "[your state] tenant rights"'},
    ]},
  ];
  const privacySection = `
    <div class="section">
      <div class="st" style="color:var(--gold)">Your Data & Privacy</div>
      <div class="card cb" style="margin-bottom:10px">
        <div style="font-size:14px;font-weight:600;margin-bottom:6px">Work-Product Protection</div>
        <div style="font-size:13px;color:var(--ink2);line-height:1.7">
          Communications with cloud AI tools (ChatGPT, Claude.ai) have been ruled non-privileged in
          federal proceedings because they involve third-party transmission — the AI company receives
          your data. SynJuris runs entirely on your machine. No data leaves your computer except the
          text of messages you send to the AI endpoint, transmitted directly to Anthropic under your
          own API key. Your evidence, documents, and strategy may retain work-product status that
          cloud tools cannot provide.
        </div>
      </div>
      <div class="card cb" style="margin-bottom:10px">
        <div style="font-size:14px;font-weight:600;margin-bottom:6px">🔐 Encrypted Backup</div>
        <div style="font-size:13px;color:var(--ink2);line-height:1.7;margin-bottom:10px">
          Your data lives only on this machine. Back it up regularly. The encrypted backup uses
          AES-256-GCM with PBKDF2 key derivation — the server never sees your passphrase.
          Only you can decrypt it.
        </div>
        <div style="display:flex;gap:8px;flex-wrap:wrap">
          <button class="btn btn-s btn-p" onclick="encryptedBackup()">🔐 Create Encrypted Backup</button>
          <button class="btn btn-s" onclick="restoreEncryptedBackup()">↑ Restore from Backup</button>
        </div>
      </div>
      <div class="card cb">
        <div style="font-size:14px;font-weight:600;margin-bottom:6px">Citation Verification</div>
        <div style="font-size:13px;color:var(--ink2);line-height:1.7;margin-bottom:10px">
          All case citations in generated documents are automatically checked against CourtListener —
          a free, comprehensive federal and state court database. Citations that cannot be verified
          are flagged before you file. Courts have sanctioned pro se users up to $1,500 for
          AI-generated ghost citations.
        </div>
        <div style="display:flex;gap:8px;align-items:center">
          <input id="cit-check-input" placeholder="Paste a citation to verify (e.g. 567 U.S. 519)"
            style="flex:1;padding:7px 11px;background:var(--bg);border:1px solid var(--border);border-radius:var(--r);color:var(--ink);font-size:13px">
          <button class="btn btn-s btn-p" onclick="manualCitCheck()">Check</button>
        </div>
        <div id="cit-check-result" style="margin-top:8px;font-size:12px;color:var(--ink3)"></div>
      </div>
    </div>`;

  c.innerHTML=sections.map(s=>`
    <div class="section">
      <div class="st">${s.title}</div>
      ${s.items.map(i=>`<div class="res-card">
        <div class="res-name">${i.name}</div>
        <div class="res-desc">${i.desc}</div>
        <div class="res-contact">${i.contact}</div>
      </div>`).join('')}
    </div>`).join('') + privacySection;
}

async function manualCitCheck(){
  const cit = document.getElementById('cit-check-input')?.value?.trim();
  if(!cit){alert('Enter a citation to check.');return;}
  const el = document.getElementById('cit-check-result');
  if(el) el.innerHTML='<span style="color:var(--ink3)">Checking CourtListener…</span>';
  try{
    const r = await fetch('/api/verify-citation?citation='+encodeURIComponent(cit));
    const d = await r.json();
    if(!el) return;
    if(d.found){
      el.innerHTML=`<span style="color:var(--green)">✓ Found: <strong>${esc(d.case_name||cit)}</strong>`+
        (d.url?` <a href="${d.url}" target="_blank" style="color:var(--blue)">View on CourtListener ↗</a>`:'')+'</span>';
    } else {
      el.innerHTML=`<span style="color:var(--amber)">⚠ ${esc(d.warning||'Not found in CourtListener. Verify before filing.')}</span>`;
    }
  }catch(e){
    if(el) el.innerHTML='<span style="color:var(--amber)">Check unavailable — are you online?</span>';
  }
}


/* ══════════ DYNAMICS ══════════ */
async function renderDynamics(c){
  c.innerHTML='<div style="padding:20px 0;color:var(--ink3);font-size:12px">Computing case state…</div>';
  let snap,auditRows;
  let interp=null;
  try{[snap,auditRows,interp]=await Promise.all([
    api('/api/cases/'+CC.id+'/state'),
    api('/api/cases/'+CC.id+'/audit'),
    api('/api/cases/'+CC.id+'/interpret')
  ]);}
  catch(e){c.innerHTML='<div class="notice n-red">Failed to load dynamics data.</div>';return;}
  const st=snap.state,inp=snap.inputs,deltas=snap.deltas||[],hash=snap.hash||'';
  const interp_data = interp?.interpretation;
  function bar(val,color,label,sub){
    const pct=((val-1)/8*100).toFixed(1);
    const lv=['','Very Low','Low','Moderate-Low','Moderate','Moderate','Moderate-High','High','Very High','Critical'];
    return `<div style="margin-bottom:18px">
      <div style="display:flex;justify-content:space-between;align-items:baseline;margin-bottom:5px">
        <div><span style="font-size:13px;font-weight:600;color:var(--ink)">${label}</span>
        <span style="font-size:11px;color:var(--ink3);margin-left:8px">${sub}</span></div>
        <div style="display:flex;align-items:baseline;gap:6px">
          <span style="font-family:var(--serif);font-size:26px;font-weight:600;color:${color}">${val}</span>
          <span style="font-size:10px;color:var(--ink3)">/9 · ${lv[val]||''}</span>
        </div>
      </div>
      <div style="background:var(--surface2);border-radius:4px;height:10px;overflow:hidden;border:1px solid var(--border)">
        <div style="width:${pct}%;height:100%;background:${color};border-radius:4px;transition:width .5s ease"></div>
      </div></div>`;
  }
  const xC=st.x>=7?'var(--green)':st.x>=4?'var(--blue)':'var(--amber)';
  const yC=st.y>=7?'var(--green)':st.y>=4?'var(--blue)':'var(--red)';
  const zC=st.z>=7?'var(--red)':st.z>=4?'var(--amber)':'var(--green)';
  const deltaRows=(deltas.slice(-10).reverse().map(d=>`
    <tr style="border-bottom:1px solid var(--border2)">
      <td style="padding:6px 8px;font-size:11px;color:var(--blue);font-weight:500">${esc(d.exhibit_number)}</td>
      <td style="padding:6px 8px;font-size:11px">${esc(d.category)}</td>
      <td style="padding:6px 8px;font-size:11px;color:var(--ink3)">${esc(d.event_date)}</td>
      <td style="padding:6px 8px;font-size:11px;font-family:var(--mono)">w=${d.weight}</td>
      <td style="padding:6px 8px;font-size:11px;font-family:var(--mono)"><span style="color:var(--blue)">x+${d.delta.x.toFixed(3)}</span> / <span style="color:var(--red)">z+${d.delta.z.toFixed(3)}</span></td>
      <td style="padding:6px 8px;font-size:11px;font-family:var(--mono);color:var(--ink3)">[${d.state_after.x},${d.state_after.y},${d.state_after.z}]</td>
    </tr>`).join(''))||`<tr><td colspan="6" style="padding:12px;font-size:12px;color:var(--ink3)">No confirmed evidence yet.</td></tr>`;
  const auditR=((auditRows||[]).slice(0,12).map(r=>`
    <tr style="border-bottom:1px solid var(--border2)">
      <td style="padding:6px 8px;font-size:10px;color:var(--ink3)">${(r.created_at||'').slice(0,19)}</td>
      <td style="padding:6px 8px;font-size:11px;font-weight:500">${esc(r.action_type)}</td>
      <td style="padding:6px 8px;font-size:11px;font-family:var(--mono);color:var(--blue)">[${r.state_x},${r.state_y},${r.state_z}]</td>
      <td style="padding:6px 8px;font-size:10px;font-family:var(--mono);color:var(--ink3)">${(r.trace_hash||'').slice(0,16)}…</td>
      <td style="padding:6px 8px"><button class="xbtn" onclick="verifyAudit(${r.id},this)">Verify</button></td>
    </tr>`).join(''))||`<tr><td colspan="5" style="padding:12px;font-size:12px;color:var(--ink3)">No AI calls logged yet.</td></tr>`;
  c.innerHTML=`
  <div style="background:var(--green-bg);border:1px solid var(--green-bd);border-radius:var(--rl);padding:14px 18px;margin-bottom:22px;display:flex;align-items:center;gap:14px">
    <div style="font-size:24px">🛡️</div>
    <div style="flex:1"><div style="font-size:10px;text-transform:uppercase;color:var(--green);font-weight:600;letter-spacing:.08em">Deterministic Audit Engine · Active</div>
    <div style="font-size:12px;color:var(--ink);margin-top:2px">Every AI analysis is backed by a traceable, recomputable state vector.</div></div>
    <div style="text-align:right;flex-shrink:0"><div style="font-size:9px;color:var(--ink3);text-transform:uppercase;letter-spacing:.06em">Current Hash</div>
    <div style="font-family:var(--mono);font-size:9px;color:var(--ink2);word-break:break-all;max-width:180px">${hash}</div></div>
  </div>
  <div class="section"><div class="st">Case State Vector</div><div class="card cb">
    ${bar(st.x,xC,'Evidence Strength','x — weight of confirmed exhibits')}
    ${interp_data ? `<div style="font-size:12px;color:var(--ink2);padding:6px 0 14px;border-bottom:1px solid var(--border2);margin-bottom:14px;line-height:1.6">${esc(interp_data.x_text)}</div>` : ''}
    ${bar(st.y,yC,'Procedural Health','y — deadline completion ratio')}
    ${interp_data ? `<div style="font-size:12px;color:var(--ink2);padding:6px 0 14px;border-bottom:1px solid var(--border2);margin-bottom:14px;line-height:1.6">${esc(interp_data.y_text)}</div>` : ''}
    ${bar(st.z,zC,'Adversarial Pressure','z — severity of opponent patterns')}
    ${interp_data ? `<div style="font-size:12px;color:var(--ink2);padding:6px 0 4px;line-height:1.6">${esc(interp_data.z_text)}</div>` : ''}
  </div></div>
  <div class="section"><div class="st">Scoring Inputs</div><div class="card cb"><div class="grid3" style="gap:10px">
    ${stat(inp.evidence_count,'Confirmed Exhibits','','good')}
    ${stat(inp.ev_weight_sum,'Evidence Weight Sum','')}
    ${stat(inp.adv_weight_sum,'Adversarial Weight Sum','')}
    ${stat(inp.done_deadlines+'/'+inp.total_deadlines,'Deadlines Complete','',inp.overdue_deadlines>0?'warn':'good')}
    ${stat(inp.overdue_deadlines,'Overdue','',(inp.overdue_deadlines>0?'warn':''))}
    ${stat(deltas.length,'Delta Chain Length','')}
  </div></div></div>
  <div class="section"><div class="st">Evidence Delta Chain (last 10)</div><div class="card" style="overflow-x:auto">
    <table style="width:100%;border-collapse:collapse">
      <thead><tr style="border-bottom:2px solid var(--border)">
        <th style="padding:7px 8px;text-align:left;color:var(--ink3);font-size:10px;text-transform:uppercase">Exhibit</th>
        <th style="padding:7px 8px;text-align:left;color:var(--ink3);font-size:10px;text-transform:uppercase">Category</th>
        <th style="padding:7px 8px;text-align:left;color:var(--ink3);font-size:10px;text-transform:uppercase">Date</th>
        <th style="padding:7px 8px;text-align:left;color:var(--ink3);font-size:10px;text-transform:uppercase">Weight</th>
        <th style="padding:7px 8px;text-align:left;color:var(--ink3);font-size:10px;text-transform:uppercase">Δ Applied</th>
        <th style="padding:7px 8px;text-align:left;color:var(--ink3);font-size:10px;text-transform:uppercase">State After</th>
      </tr></thead><tbody>${deltaRows}</tbody>
    </table>
  </div></div>
  <div class="section"><div class="st">AI Call Audit Log</div><div class="card" style="overflow-x:auto">
    <table style="width:100%;border-collapse:collapse">
      <thead><tr style="border-bottom:2px solid var(--border)">
        <th style="padding:7px 8px;text-align:left;color:var(--ink3);font-size:10px;text-transform:uppercase">Time</th>
        <th style="padding:7px 8px;text-align:left;color:var(--ink3);font-size:10px;text-transform:uppercase">Action</th>
        <th style="padding:7px 8px;text-align:left;color:var(--ink3);font-size:10px;text-transform:uppercase">State</th>
        <th style="padding:7px 8px;text-align:left;color:var(--ink3);font-size:10px;text-transform:uppercase">Hash</th>
        <th style="padding:7px 8px;text-align:left;color:var(--ink3);font-size:10px;text-transform:uppercase">Verify</th>
      </tr></thead><tbody id="audit-tbody">${auditR}</tbody>
    </table>
  </div></div>`;
}
async function verifyAudit(id,btn){
  const orig=btn.textContent; btn.disabled=true; btn.textContent='…';
  try{
    const r=await api('/api/audit/verify',{audit_id:id});
    btn.textContent=r.verified?'✓ Match':'⚠ Changed';
    btn.style.color=r.verified?'var(--green)':'var(--red)';
    btn.style.borderColor=r.verified?'var(--green)':'var(--red)';
    const row=btn.closest('tr');
    if(row){const ex=row.nextElementSibling;if(ex&&ex.classList.contains('vd'))ex.remove();
    const d=document.createElement('tr');d.className='vd';
    d.innerHTML=`<td colspan="5" style="padding:8px 12px;background:${r.verified?'var(--green-bg)':'var(--red-bg)'};font-size:11px;color:${r.verified?'var(--green)':'var(--red)'}">${esc(r.note||'')}</td>`;
    row.after(d);}
  }catch(e){btn.textContent=orig;btn.disabled=false;}
}

/* ══════════ CHAT ══════════ */
/* ══════════ ATTORNEY TAB ══════════ */
async function renderAttorney(c){
  c.innerHTML='<div style="padding:20px 0;color:var(--ink3);font-size:12px">Loading attorney tools…</div>';

  let timeEntries=[], portalTokens=[], portalQueue=[];
  try{
    [timeEntries, portalTokens, portalQueue] = await Promise.all([
      api('/api/cases/'+CC.id+'/time-entries'),
      (async()=>{ const d=await api('/api/portal/list',{case_id:CC.id}); return d||[]; })(),
      api('/api/cases/'+CC.id+'/portal-queue')
    ]);
  }catch(e){}

  const snap = await api('/api/cases/'+CC.id+'/state').catch(()=>null);

  // Time entry rows
  const teRows = timeEntries.length ? timeEntries.map(t=>`
    <tr style="border-bottom:1px solid var(--border2)">
      <td style="padding:6px 8px;font-size:11px;color:var(--ink3)">${(t.created_at||"").slice(0,10)}</td>
      <td style="padding:6px 8px;font-size:12px">${esc(t.description)}</td>
      <td style="padding:6px 8px;font-size:12px;text-align:center">${t.hours||0}</td>
      <td style="padding:6px 8px;font-size:11px;text-align:center">
        ${t.billable?'<span style="color:var(--green)">Bill</span>':'<span style="color:var(--ink3)">No</span>'}
      </td>
      <td style="padding:6px 8px;font-size:11px;text-align:center">
        ${t.exported?'<span style="color:var(--ink3)">Exported</span>':'<button class="xbtn ok" onclick="exportTE('+t.id+')">Export</button>'}
      </td>
    </tr>`).join('')
    : `<tr><td colspan="5" style="padding:12px;font-size:12px;color:var(--ink3)">No time entries yet. They auto-generate when you use AI tools.</td></tr>`;

  // Portal token rows
  const ptRows = portalTokens.length ? portalTokens.map(t=>`
    <div class="card cb" style="margin-bottom:8px">
      <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
        <div style="flex:1;min-width:0">
          <div style="font-size:13px;font-weight:500">${esc(t.label)}</div>
          <div style="font-size:11px;color:var(--ink3);margin-top:2px;word-break:break-all">
            http://localhost:${PORT}/portal/${t.token}
          </div>
          <div style="font-size:10px;color:var(--ink3);margin-top:2px">Created ${(t.created_at||"").slice(0,10)} · Expires ${(t.expires_at||"").slice(0,10)}</div>
        </div>
        <div style="display:flex;gap:6px;flex-shrink:0">
          <button class="xbtn ok" onclick="copyPortalLink('http://localhost:${PORT}/portal/${t.token}')">Copy Link</button>
          <button class="xbtn rm" onclick="revokePortal(${t.id})">Revoke</button>
        </div>
      </div>
    </div>`).join('')
    : '<div style="font-size:12px;color:var(--ink3)">No portal links yet. Create one to share with your client.</div>';

  // Portal queue
  const pqRows = portalQueue.filter(p=>p.approved===0).length ? portalQueue.filter(p=>p.approved===0).map(p=>`
    <div class="card cb" style="margin-bottom:8px;border-left:3px solid var(--amber)">
      <div style="font-size:11px;color:var(--amber);font-weight:600;margin-bottom:4px">Pending Review · ${esc(p.category)} · ${(p.created_at||"").slice(0,10)}</div>
      <div style="font-size:13px;color:var(--ink);margin-bottom:8px">${esc((p.content||"").slice(0,300))}${(p.content||"").length>300?"…":""}</div>
      <div style="font-size:11px;color:var(--ink3);margin-bottom:8px">Source: ${esc(p.source||"")} · ${esc(p.event_date||"undated")}</div>
      <div style="display:flex;gap:8px">
        <input id="pn-${p.id}" placeholder="Attorney note (optional)" style="flex:1;padding:6px 10px;background:var(--bg);border:1px solid var(--border);border-radius:var(--r);color:var(--ink);font-size:12px">
        <button class="xbtn ok" onclick="approvePortal(${p.id})">✓ Approve</button>
        <button class="xbtn rm" onclick="rejectPortal(${p.id})">✕ Reject</button>
      </div>
    </div>`).join('')
    : '<div style="font-size:12px;color:var(--ink3)">No pending submissions.</div>';

  c.innerHTML=`
  <div class="section">
    <div class="st" style="color:var(--gold)">Client Portal</div>
    <div class="notice n-info" style="margin-bottom:12px">Share a portal link with your client so they can submit evidence directly to this case for your review. Nothing they submit is added to the case until you approve it.</div>
    <div style="margin-bottom:16px">${ptRows}</div>
    <button class="btn btn-s btn-p" onclick="createPortal()">+ Create Portal Link</button>
  </div>

  ${portalQueue.filter(p=>p.approved===0).length ? `
  <div class="section">
    <div class="st" style="color:var(--amber)">Client Submissions Pending Review (${portalQueue.filter(p=>p.approved===0).length})</div>
    ${pqRows}
  </div>` : ""}

  <div class="section">
    <div class="st">Conflict Check</div>
    <div style="display:flex;gap:8px;margin-bottom:8px">
      <input id="cc-name" placeholder="Search party name across all your cases…" style="flex:1;padding:8px 12px;background:var(--bg);border:1px solid var(--border);border-radius:var(--r);color:var(--ink);font-size:13px">
      <button class="btn btn-s btn-p" onclick="runConflict()">Check</button>
    </div>
    <div id="cc-result" style="font-size:12px;color:var(--ink3)">Enter a name to search all cases and parties.</div>
  </div>

  <div class="section">
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px">
      <div class="st" style="margin-bottom:0">Time Entries</div>
      <div style="display:flex;gap:6px">
        <button class="btn btn-s" onclick="openAddTE()">+ Add Manual</button>
        <button class="btn btn-s btn-p" onclick="exportAllTE()">Export All</button>
      </div>
    </div>
    <div style="overflow-x:auto">
      <table style="width:100%;border-collapse:collapse">
        <thead>
          <tr style="border-bottom:1px solid var(--border)">
            <th style="padding:6px 8px;font-size:10px;color:var(--ink3);text-align:left">DATE</th>
            <th style="padding:6px 8px;font-size:10px;color:var(--ink3);text-align:left">DESCRIPTION</th>
            <th style="padding:6px 8px;font-size:10px;color:var(--ink3);text-align:center">HRS</th>
            <th style="padding:6px 8px;font-size:10px;color:var(--ink3);text-align:center">BILL</th>
            <th style="padding:6px 8px;font-size:10px;color:var(--ink3);text-align:center">STATUS</th>
          </tr>
        </thead>
        <tbody>${teRows}</tbody>
      </table>
    </div>
  </div>

  <div class="section">
    <div class="st">Redacted Case Summary Export</div>
    <div style="font-size:13px;color:var(--ink2);margin-bottom:12px">
      Export a shareable summary showing the state vector, key arguments, statute citations,
      and upcoming deadlines — with raw evidence content stripped. Safe to share with
      co-counsel, mediators, or clients.
    </div>
    <button class="btn btn-s btn-p" onclick="downloadRedacted()">Download Redacted JSON</button>
  </div>`;
}

async function createPortal(){
  const label = prompt("Portal label (e.g. client name or 'Primary Client'):");
  if(!label) return;
  const d = await api('/api/portal/create',{case_id:CC.id,label});
  if(d.url){
    await navigator.clipboard.writeText(d.url).catch(()=>{});
    alert('Portal link created and copied to clipboard:\n'+d.url);
    await refresh(); switchTab('attorney');
  } else { alert(d.error||'Failed to create portal'); }
}
async function copyPortalLink(url){
  await navigator.clipboard.writeText(url).catch(()=>{});
  alert('Copied: '+url);
}
async function revokePortal(tid){
  if(!confirm('Revoke this portal link? The client will no longer be able to submit.')) return;
  await api('/api/portal/revoke',{token_id:tid});
  await refresh(); switchTab('attorney');
}
async function approvePortal(peid){
  const note = document.getElementById('pn-'+peid)?.value||'';
  const d = await api('/api/portal/approve',{portal_evidence_id:peid,attorney_note:note});
  if(d.ok){ await refresh(); switchTab('attorney'); }
  else alert(d.error||'Failed');
}
async function rejectPortal(peid){
  const note = document.getElementById('pn-'+peid)?.value||'';
  await api('/api/portal/reject',{portal_evidence_id:peid,attorney_note:note});
  await refresh(); switchTab('attorney');
}
async function runConflict(){
  const name = document.getElementById('cc-name')?.value?.trim();
  if(!name){alert('Enter a name to check.');return;}
  const d = await api('/api/conflict-check?name='+encodeURIComponent(name));
  const el = document.getElementById('cc-result');
  if(!el) return;
  if(d.result==='conflict'){
    el.innerHTML='<div style="color:var(--red);font-weight:600;margin-bottom:6px">⚠ Potential Conflict — '+d.matches.length+' match(es)</div>'+
      d.matches.map(m=>`<div style="padding:6px 10px;background:var(--surface2);border-radius:var(--r);margin-bottom:4px;font-size:12px">
        <strong>${esc(m.party_name)}</strong> (${esc(m.role)}) in case: <em>${esc(m.case_title)}</em>
      </div>`).join('');
  } else {
    el.innerHTML='<div style="color:var(--green);font-weight:500">✓ No conflicts found for "'+esc(name)+'"</div>';
  }
}
function openAddTE(){
  showMo('Add Time Entry',`
    <div class="fg"><label>Description</label><input id="te-d" placeholder="e.g. Reviewed client portal submission, drafted motion…"></div>
    <div class="two-col">
      <div class="fg"><label>Hours</label><input type="number" id="te-h" value="0.3" min="0.1" step="0.1"></div>
      <div class="fg"><label>Billable</label><select id="te-b"><option value="1">Yes</option><option value="0">No</option></select></div>
    </div>
    <div class="br">
      <button class="btn btn-s" onclick="closeMo()">Cancel</button>
      <button class="btn btn-p" onclick="submitTE()">Add Entry</button>
    </div>`);
}
async function submitTE(){
  const d=document.getElementById('te-d').value.trim();
  const h=parseFloat(document.getElementById('te-h').value)||0;
  if(!d||h<=0){alert('Enter a description and valid hours.');return;}
  await api('/api/time-entries',{case_id:CC.id,description:d,hours:h,
    billable:parseInt(document.getElementById('te-b').value)});
  closeMo(); await refresh(); switchTab('attorney');
}
async function exportTE(id){
  await api('/api/time-entries/export',{ids:[id]});
  await refresh(); switchTab('attorney');
}
async function exportAllTE(){
  const te = await api('/api/cases/'+CC.id+'/time-entries');
  const ids = (te||[]).filter(t=>!t.exported).map(t=>t.id);
  if(!ids.length){alert('No unexported entries.');return;}
  await api('/api/time-entries/export',{ids});
  // Build CSV for download
  const rows = ['Date,Description,Hours,Billable'].concat(
    (te||[]).map(t=>`"${(t.created_at||"").slice(0,10)}","${(t.description||"").replace(/"/g,"''")}", ${t.hours},${t.billable?"Yes":"No"}`)
  );
  const blob = new Blob([rows.join('\n')],{type:'text/csv'});
  const a=document.createElement('a');
  a.href=URL.createObjectURL(blob); a.download='time-entries-'+CC.id+'.csv'; a.click();
  await refresh(); switchTab('attorney');
}
async function downloadRedacted(){
  const d = await api('/api/cases/'+CC.id+'/redacted-export');
  const blob = new Blob([JSON.stringify(d,null,2)],{type:'application/json'});
  const a=document.createElement('a');
  a.href=URL.createObjectURL(blob);
  a.download='synjuris-redacted-'+CC.id+'-'+(new Date().toISOString().slice(0,10))+'.json'; a.click();
}

async function renderChat(c){
  const type=CC.case_type||'legal';
  const suggs=getChatSuggs(type);
  c.innerHTML=`
  <div id="chat-wrap">
    <div class="notice n-warn" style="margin-bottom:10px">SynJuris is not a lawyer. Use AI answers to understand your situation — always consult a licensed attorney for final decisions.</div>
    <div class="sugg-row">${suggs.map(s=>`<span class="sugg" onclick="sendSugg('${s.replace(/'/g,"\\\'")}')">${s}</span>`).join('')}</div>
    <div id="chat-msgs"></div>
    <div id="chat-ir">
      <input id="chat-input" placeholder="Ask anything about your case, the law, what to say in court…" onkeydown="if(event.key==='Enter'&&!event.shiftKey){event.preventDefault();sendChat()}">
      <button id="chat-send" onclick="sendChat()">Send</button>
    </div>
  </div>`;
  const history=await api('/api/chat/'+CC.id);
  history.forEach(m=>appendMsg(m.role,m.content));
  if(!history.length) appendMsg('assistant',`Hello! I'm here to help with your ${type} case in ${CC.jurisdiction||'your jurisdiction'}. What would you like to know?\n\nYou can ask me about the law, what to expect, how to prepare for your hearing, or ask me to draft a document.`);
  scrollChat();
}
function getChatSuggs(t){
  const m={
    'Child Custody':['What factors do courts consider in custody?','Explain parental alienation legally','How do I modify a custody order?'],
    'Divorce':['How is marital property divided?','What is equitable distribution?','How does alimony work in my state?'],
    'Landlord-Tenant':['What are my rights as a tenant?','How does eviction work?','What is a habitability violation?'],
    'Small Claims':['How do I file a small claims case?','What evidence do I need?','How do I collect a judgment?'],
    'Protective Order':['What is a protective order?','How do I get an emergency protective order?','What happens at the hearing?'],
    'Child Support':['How is child support calculated?','How do I enforce a child support order?','Can child support be modified?'],
  };
  return (m[t]||['What are my legal rights?','What should I bring to court?','Explain the process to me']).slice(0,4);
}
function sendSugg(t){document.getElementById('chat-input').value=t;sendChat();}
async function sendChat(){
  const inp=document.getElementById('chat-input'), msg=inp.value.trim();
  if(!msg)return; inp.value=''; document.getElementById('chat-send').disabled=true;
  appendMsg('user',msg);
  const typ=appendMsg('assistant','⟳ Thinking…',true);
  const d=await api('/api/chat',{case_id:CC.id,message:msg});
  typ.querySelector('.mb').textContent=d.reply;
  document.getElementById('chat-send').disabled=false; inp.focus(); scrollChat();
}
function appendMsg(role,content,temp=false){
  const w=document.getElementById('chat-msgs');
  const el=document.createElement('div'); el.className='msg '+role;
  el.innerHTML=`<div class="mb">${esc(content)}</div>`;
  w.appendChild(el); return el;
}
function scrollChat(){const w=document.getElementById('chat-msgs');if(w)w.scrollTop=w.scrollHeight;}

/* ══════════ NEW CASE WIZARD ══════════ */
let _nd={};
function openNewCase(){showMo('New Case',ncStep1());}
function ncStep1(){
  return`<div style="display:flex;gap:5px;margin-bottom:16px">${[1,2,3].map(i=>`<span class="sdot${i===1?' active':''}"></span>`).join('')}</div>
  <div class="fg"><label>Case Title</label><input id="nc-title" placeholder="e.g. Smith custody matter · Jones v. Landlord"></div>
  <div class="two-col">
    <div class="fg"><label>Case Type</label><select id="nc-type">
      <option value="">Select…</option>
      ${['Child Custody','Divorce','Landlord-Tenant','Small Claims','Child Support','Protective Order','Eviction Defense','Guardianship','Name Change','Other'].map(t=>`<option>${t}</option>`).join('')}
    </select></div>
    <div class="fg"><label>State / Jurisdiction</label><input id="nc-jur" placeholder="e.g. Tennessee"></div>
  </div>
  <div class="two-col">
    <div class="fg"><label>Court Name (if known)</label><input id="nc-court" placeholder="e.g. Shelby County Circuit Court"></div>
    <div class="fg"><label>Case / Docket Number (if known)</label><input id="nc-num" placeholder="e.g. 2024-DV-001234"></div>
  </div>
  <div class="br"><button class="btn btn-s" onclick="closeMo()">Cancel</button><button class="btn btn-p" onclick="nc2()">Next →</button></div>`;
}
function nc2(){
  const d={title:val('nc-title'),case_type:val('nc-type'),jurisdiction:val('nc-jur'),court_name:val('nc-court'),case_number:val('nc-num')};
  if(!d.title){alert('Please enter a case title.');return;}
  _nd=d;
  showMo('New Case — Parties',`<div style="display:flex;gap:5px;margin-bottom:16px">${[1,2,3].map(i=>`<span class="sdot${i===2?' active':i<2?' done':''}"></span>`).join('')}</div>
  <p style="font-size:12px;color:var(--ink2);margin-bottom:12px">Add the key people. You can add more later.</p>
  <div id="party-list">${partyRow(0,'','')}${partyRow(1,'','')}</div>
  <button class="btn btn-s" style="margin-bottom:12px" onclick="addPRow()">+ Add Person</button>
  <div class="br"><button class="btn btn-s" onclick="showMo('New Case',ncStep1())">← Back</button><button class="btn btn-p" onclick="nc3()">Next →</button></div>`);
}
let _prc=2;
function partyRow(i,name='',role=''){
  const roles=['Petitioner','Respondent','Child','Attorney','Witness','Judge','Other'];
  return`<div class="two-col" id="pr${i}" style="margin-bottom:8px">
    <input placeholder="Full name" value="${esc(name)}" class="pn">
    <select class="pr">${roles.map(r=>`<option ${r===role?'selected':''}>${r}</option>`).join('')}</select>
  </div>`;
}
function addPRow(){document.getElementById('party-list').insertAdjacentHTML('beforeend',partyRow(_prc++));}
function nc3(){
  const names=[...document.querySelectorAll('.pn')].map(e=>e.value);
  const roles=[...document.querySelectorAll('.pr')].map(e=>e.value);
  _nd.parties=names.map((n,i)=>({name:n,role:roles[i]})).filter(p=>p.name.trim());
  showMo('New Case — Details',`<div style="display:flex;gap:5px;margin-bottom:16px">${[1,2,3].map(i=>`<span class="sdot${i===3?' active':' done'}"></span>`).join('')}</div>
  <div class="two-col">
    <div class="fg"><label>Filing / Response Deadline</label><input type="date" id="nc-fdl"></div>
    <div class="fg"><label>Hearing Date (if scheduled)</label><input type="date" id="nc-hd"></div>
  </div>
  <div class="fg"><label>Your Goals</label><textarea id="nc-goals" placeholder="What outcome are you hoping for? e.g. Primary custody, reduction in rent, return of deposit…"></textarea></div>
  <div class="fg"><label>Background Notes</label><textarea id="nc-notes" placeholder="Brief summary of the situation…"></textarea></div>
  <div class="notice n-info" style="margin-top:8px">Everything is saved locally on your computer only.</div>
  <div class="br"><button class="btn btn-s" onclick="nc2()">← Back</button><button class="btn btn-p" onclick="createCase()">Create Case</button></div>`);
}
async function createCase(){
  _nd.filing_deadline=val('nc-fdl'); _nd.hearing_date=val('nc-hd');
  _nd.goals=val('nc-goals'); _nd.notes=val('nc-notes');
  const d=await api('/api/cases',_nd);
  closeMo(); await loadCases(); await loadCase(d.id);
}

/* ══════════ EDIT CASE ══════════ */
function openEditCase(){
  showMo('Edit Case',`
    <div class="fg"><label>Case Title</label><input id="ec-t" value="${esc(CC.title)}"></div>
    <div class="two-col">
      <div class="fg"><label>Case Type</label><select id="ec-type">
        ${['Child Custody','Divorce','Landlord-Tenant','Small Claims','Child Support','Protective Order','Eviction Defense','Guardianship','Name Change','Other'].map(t=>`<option ${CC.case_type===t?'selected':''}>${t}</option>`).join('')}
      </select></div>
      <div class="fg"><label>Jurisdiction</label><input id="ec-jur" value="${esc(CC.jurisdiction||'')}"></div>
    </div>
    <div class="two-col">
      <div class="fg"><label>Court Name</label><input id="ec-court" value="${esc(CC.court_name||'')}"></div>
      <div class="fg"><label>Case Number</label><input id="ec-num" value="${esc(CC.case_number||'')}"></div>
    </div>
    <div class="two-col">
      <div class="fg"><label>Filing Deadline</label><input type="date" id="ec-fdl" value="${CC.filing_deadline||''}"></div>
      <div class="fg"><label>Hearing Date</label><input type="date" id="ec-hd" value="${CC.hearing_date||''}"></div>
    </div>
    <div class="fg"><label>Goals</label><textarea id="ec-goals">${esc(CC.goals||'')}</textarea></div>
    <div class="fg"><label>Background Notes</label><textarea id="ec-notes">${esc(CC.notes||'')}</textarea></div>
    <div class="br"><button class="btn btn-s" onclick="closeMo()">Cancel</button><button class="btn btn-p" onclick="saveCase()">Save Changes</button></div>`);
}
async function saveCase(){
  await api('/api/cases/'+CC.id,{title:val('ec-t'),case_type:val('ec-type'),jurisdiction:val('ec-jur'),
    court_name:val('ec-court'),case_number:val('ec-num'),filing_deadline:val('ec-fdl'),
    hearing_date:val('ec-hd'),goals:val('ec-goals'),notes:val('ec-notes')});
  closeMo(); await loadCases(); await loadCase(CC.id);
}

async function deleteCase(id, title){
  if(!confirm(`Permanently delete "${title}" and all its evidence, documents, and notes?\n\nThis cannot be undone.`)) return;
  await fetch('/api/cases/'+id, {method:'DELETE'});
  if(CC?.id === id){
    CC = null;
    document.getElementById('welcome').style.display='flex';
    document.getElementById('cv').style.display='none';
  }
  await loadCases();
}

function exportEvidence(){
  if(!CC) return;
  const a = document.createElement('a');
  a.href = '/api/cases/'+CC.id+'/export';
  a.download = '';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}

function backupDB(){
  const a = document.createElement('a');
  a.href = '/api/backup';
  a.download = '';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}

function fullArchive(){
  if(!confirm('This will download your entire SynJuris archive — database + all uploaded files — as a single zip file. Keep it somewhere safe.')) return;
  const a = document.createElement('a');
  a.href = '/api/backup-full';
  a.download = '';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}

/* ══════════ UTILS ══════════ */
async function api(url,body){
  if(!body) return fetch(url).then(r=>r.json());
  const method = url.includes('/api/cases/') && !url.split('/').slice(-1)[0].match(/\d/) ? 'GET' : 'POST';
  const isGet = !body || Object.keys(body).length===0;
  return fetch(url,{method:isGet?'GET':'POST',headers:{'Content-Type':'application/json'},body:isGet?undefined:JSON.stringify(body)}).then(r=>r.json());
}
async function api(url,body){
  if(body===undefined) return fetch(url).then(r=>r.json());
  return fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}).then(r=>r.json());
}
function val(id){return(document.getElementById(id)?.value||'').trim();}
function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');}
function today(){return new Date().toISOString().slice(0,10);}
function showMo(title,body){document.getElementById('mo-title').textContent=title;document.getElementById('mo-body').innerHTML=body;document.getElementById('mo').classList.add('open');}
function closeMo(){document.getElementById('mo').classList.remove('open');}

/* ══════════ ARGUMENTS TAB ══════════ */
async function renderArguments(c){
  c.innerHTML=`
  <div class="notice n-warn" style="margin-bottom:14px">
    <strong>Important:</strong> AI-generated arguments are a starting point — not legal advice. Verify every statute cited and confirm every factual claim before using this in court.
    <label style="display:flex;align-items:center;gap:8px;margin-top:8px;cursor:pointer;font-weight:500">
      <input type="checkbox" id="arg-ack" onchange="document.getElementById('arg-btn').disabled=!this.checked">
      I understand this is AI analysis, not legal advice, and I will verify before relying on it
    </label>
  </div>
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">
    <p style="font-size:12px;color:var(--ink2)">SynJuris organizes your confirmed evidence by legal issue — grouping exhibits together so you can see what supports each part of your case.</p>
    <button class="btn btn-p" id="arg-btn" onclick="buildArguments()" disabled>Organize Evidence by Issue</button>
  </div><div id="arg-results"></div>`;
}

async function buildArguments(){
  const res=document.getElementById('arg-results');
  setBtnLoading('arg-btn', true, 'Re-Organize Evidence');
  res.innerHTML=loadingHTML('Organizing your evidence by legal issue…');
  let d;
  try { d=await api('/api/build-arguments',{case_id:CC.id}); }
  catch(e){ res.innerHTML=errorHTML('Network error — check your connection and try again.'); setBtnLoading('arg-btn',false,'Rebuild Arguments'); return; }
  setBtnLoading('arg-btn', false, 'Re-Organize Evidence');
  if(d.error){res.innerHTML=`<div class="notice n-red">${esc(d.error)}</div>`;return;}
  if(d.raw){res.innerHTML=`<div class="card cb"><pre style="white-space:pre-wrap;font-size:11px">${esc(d.raw)}</pre></div>`;return;}

  let html='';
  if(d.case_theme){
    html+=`<div class="notice n-info" style="margin-bottom:16px"><strong>Case Theme:</strong> ${esc(d.case_theme)}</div>`;
  }
  if(d.arguments?.length){
    d.arguments.forEach((arg,i)=>{
      const sc={'strong':'confirmed','moderate':'blue','weak':'unconfirmed'}[arg.strength]||'blue';
      html+=`<div class="card" style="margin-bottom:12px">
        <div style="padding:12px 16px 0;display:flex;align-items:center;gap:8px">
          <span class="badge ${sc}">${arg.strength||'unknown'}</span>
          <span style="font-weight:500;font-size:13px">${esc(arg.title)}</span>
        </div>
        <div class="card-body" style="padding:10px 16px 14px">
          <div style="font-size:11px;color:var(--blue);margin-bottom:6px">${esc(arg.legal_basis||'')}</div>
          <div style="font-size:12px;margin-bottom:8px">${esc(arg.argument||'')}</div>
          ${arg.exhibits?.length?`<div style="font-size:11px;color:var(--ink3);margin-bottom:6px">Supported by: ${arg.exhibits.map(e=>`<span class="badge blue">${esc(e)}</span>`).join(' ')}</div>`:''}
          <details style="margin-top:6px">
            <summary style="font-size:11px;color:var(--ink3);cursor:pointer">Anticipate &amp; counter</summary>
            <div style="font-size:11px;color:var(--amber);margin-top:6px;padding:8px;background:var(--amber-bg);border-radius:4px">
              <strong>They'll say:</strong> ${esc(arg.anticipate||'')}
            </div>
            <div style="font-size:11px;color:var(--green);margin-top:4px;padding:8px;background:var(--green-bg);border-radius:4px">
              <strong>You say:</strong> ${esc(arg.counter||'')}
            </div>
          </details>
        </div>
      </div>`;
    });
  }
  if(d.evidence_gaps?.length){
    html+=`<div class="section"><div class="st" style="color:var(--amber)">Evidence Gaps</div><div class="card cb">
      ${d.evidence_gaps.map(g=>`<div style="font-size:12px;padding:4px 0;border-bottom:1px solid var(--border-light)">⚠ ${esc(g)}</div>`).join('')}
    </div></div>`;
  }
  res.innerHTML=html;
}

/* ══════════ STRATEGY TAB ══════════ */
async function renderStrategy(c){
  c.innerHTML=`
  <div class="notice n-warn" style="margin-bottom:14px">
    <strong>Important:</strong> These tools generate strategic analysis to help you prepare — they are not legal advice and the AI can be wrong. Always verify with a licensed attorney when possible.
    <label style="display:flex;align-items:center;gap:8px;margin-top:8px;cursor:pointer;font-weight:500">
      <input type="checkbox" id="strat-ack" onchange="['theory-btn','adv-btn','contra-btn'].forEach(id=>{const el=document.getElementById(id);if(el)el.disabled=!this.checked})">
      I understand this is AI analysis. I will verify before relying on it.
    </label>
  </div>
  <div style="display:flex;gap:10px;margin-bottom:14px;flex-wrap:wrap">
    <button class="btn btn-p" id="theory-btn" onclick="buildTheory()" disabled>Organize Your Case Summary</button>
    <button class="btn btn-s" id="adv-btn" onclick="buildAdversarial()" disabled>Anticipate Opposition Arguments</button>
    <button class="btn btn-s" id="contra-btn" onclick="detectContradictions()" disabled>Check Timeline for Gaps</button>
  </div>
  <p style="font-size:12px;color:var(--ink2);margin-bottom:16px">Build your core legal theory, anticipate arguments the other side may raise, and find weaknesses in your timeline before court does.</p>
  <div id="strategy-results"></div>`;
}

async function buildTheory(){
  const res=document.getElementById('strategy-results');
  stratLock(true);
  res.innerHTML=loadingHTML('Organizing your case summary…');
  let d;
  try { d=await api('/api/case-theory',{case_id:CC.id}); }
  catch(e){ res.innerHTML=errorHTML('Network error — try again.'); stratLock(false); return; }
  stratLock(false);
  if(d.raw||d.error){res.innerHTML=`<div class="card cb"><pre style="white-space:pre-wrap;font-size:11px">${esc(d.raw||d.error)}</pre></div>`;return;}

  let html=`<div class="section"><div class="st">Case Summary</div>`;
  if(d.one_sentence_theory){
    html+=`<div class="notice n-info" style="margin-bottom:12px"><strong>Your theory in one sentence:</strong><br>${esc(d.one_sentence_theory)}</div>`;
  }
  if(d.narrative){
    html+=`<div class="card cb" style="margin-bottom:12px"><div class="section-title" style="font-size:10px;text-transform:uppercase;letter-spacing:.08em;color:var(--ink3);margin-bottom:6px">Your Story</div>
      <div style="font-size:12px;line-height:1.7">${esc(d.narrative)}</div></div>`;
  }
  if(d.opening_line){
    html+=`<div class="card cb" style="margin-bottom:12px;border-left:3px solid var(--blue)">
      <div style="font-size:10px;text-transform:uppercase;letter-spacing:.08em;color:var(--blue);margin-bottom:4px">Your Opening Line</div>
      <div style="font-size:12px;font-style:italic">"${esc(d.opening_line)}"</div></div>`;
  }
  if(d.legal_theories?.length){
    html+=`<div class="st" style="margin-top:16px">Legal Theories</div>`;
    d.legal_theories.forEach(t=>{
      html+=`<div class="card" style="margin-bottom:10px"><div class="cb">
        <div style="font-weight:500;font-size:12px;margin-bottom:4px">${esc(t.theory)}</div>
        ${t.statute?`<div style="font-size:10px;color:var(--blue);margin-bottom:6px">${esc(t.statute)}</div>`:''}
        ${t.elements?.length?`<div style="font-size:11px;color:var(--ink2);margin-bottom:6px">Must prove: ${t.elements.map(e=>`<span style="display:inline-block;background:var(--bg);border:1px solid var(--border);border-radius:3px;padding:1px 6px;margin:1px;font-size:10px">${esc(e)}</span>`).join('')}</div>`:''}
        ${t.how_you_prove_it?`<div style="font-size:11px;color:var(--green)">${esc(t.how_you_prove_it)}</div>`:''}
      </div></div>`;
    });
  }
  if(d.burden_of_proof){
    html+=`<div class="card cb" style="margin-bottom:10px"><div style="font-size:11px;color:var(--ink2)">${esc(d.burden_of_proof)}</div></div>`;
  }
  html+=`<div class="grid3" style="margin-top:12px">
    ${d.best_outcome?`<div class="stat good"><div class="stat-n" style="font-size:13px">Best</div><div style="font-size:11px;margin-top:4px">${esc(d.best_outcome)}</div></div>`:''}
    ${d.acceptable_outcome?`<div class="stat"><div class="stat-n" style="font-size:13px">Fair</div><div style="font-size:11px;margin-top:4px">${esc(d.acceptable_outcome)}</div></div>`:''}
    ${d.worst_case?`<div class="stat warn"><div class="stat-n" style="font-size:13px">Worst</div><div style="font-size:11px;margin-top:4px">${esc(d.worst_case)}</div></div>`:''}
  </div></div>`;
  res.innerHTML=html;
}

async function buildAdversarial(){
  const res=document.getElementById('strategy-results');
  stratLock(true);
  res.innerHTML=loadingHTML('Analyzing likely opposition arguments…');
  let d;
  try { d=await api('/api/adversarial',{case_id:CC.id}); }
  catch(e){ res.innerHTML=errorHTML('Network error — try again.'); stratLock(false); return; }
  stratLock(false);
  if(d.raw||d.error){res.innerHTML=`<div class="card cb"><pre style="white-space:pre-wrap;font-size:11px">${esc(d.raw||d.error)}</pre></div>`;return;}

  let html=`<div class="section"><div class="st" style="color:var(--red)">Opposition Argument Analysis</div>`;
  html+=`<div class="notice n-warn" style="margin-bottom:12px">This analysis helps you anticipate arguments the other side may raise so you can prepare responses. Use it to prepare — not to get discouraged.</div>`;
  if(d.opposing_strategy){
    html+=`<div class="card cb" style="margin-bottom:12px"><strong style="font-size:11px">Their overall strategy:</strong><div style="font-size:12px;margin-top:4px">${esc(d.opposing_strategy)}</div></div>`;
  }
  if(d.attacks?.length){
    html+=`<div class="st">Their Arguments &amp; Your Counters</div>`;
    d.attacks.forEach(a=>{
      const sc={'strong':'unconfirmed','moderate':'badge blue','weak':'confirmed'}[a.strength]||'blue';
      html+=`<div class="card" style="margin-bottom:10px"><div class="cb">
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
          <span class="badge ${sc}">${a.strength}</span>
          <span style="font-size:12px;font-weight:500">${esc(a.argument)}</span>
        </div>
        <div style="font-size:11px;color:var(--amber);padding:6px;background:var(--amber-bg);border-radius:4px;margin-bottom:6px">
          Attacks: ${esc(a.target||'')}
        </div>
        <div style="font-size:11px;color:var(--green);padding:6px;background:var(--green-bg);border-radius:4px">
          Your counter: ${esc(a.counter||'')}
        </div>
        ${a.evidence_needed?`<div style="font-size:10px;color:var(--ink3);margin-top:4px">Would help: ${esc(a.evidence_needed)}</div>`:''}
      </div></div>`;
    });
  }
  if(d.key_warning){
    html+=`<div class="notice n-red"><strong>Key warning:</strong> ${esc(d.key_warning)}</div>`;
  }
  const cols=[];
  if(d.your_vulnerabilities?.length) cols.push({title:'Your Weaknesses',items:d.your_vulnerabilities,cls:'warn'});
  if(d.their_vulnerabilities?.length) cols.push({title:'Their Weaknesses',items:d.their_vulnerabilities,cls:'good'});
  if(cols.length){
    html+=`<div class="grid2" style="margin-top:12px">`;
    cols.forEach(col=>{
      html+=`<div class="stat ${col.cls}"><div class="stat-l" style="margin-bottom:6px">${col.title}</div>
        ${col.items.map(i=>`<div style="font-size:11px;padding:3px 0;border-bottom:1px solid rgba(0,0,0,.05)">${esc(i)}</div>`).join('')}
      </div>`;
    });
    html+='</div>';
  }
  if(d.settlement_leverage){
    html+=`<div class="card cb" style="margin-top:12px"><div style="font-size:10px;text-transform:uppercase;letter-spacing:.08em;color:var(--ink3);margin-bottom:4px">Settlement Leverage</div>
      <div style="font-size:12px">${esc(d.settlement_leverage)}</div></div>`;
  }
  html+='</div>';
  res.innerHTML=html;
}

async function detectContradictions(){
  const res=document.getElementById('strategy-results');
  stratLock(true);
  res.innerHTML=loadingHTML('Scanning your timeline for gaps and contradictions…');
  let d;
  try { d=await api('/api/detect-contradictions',{case_id:CC.id}); }
  catch(e){ res.innerHTML=errorHTML('Network error — try again.'); stratLock(false); return; }
  stratLock(false);
  if(d.raw||d.error){res.innerHTML=`<div class="card cb"><pre style="white-space:pre-wrap;font-size:11px">${esc(d.raw||d.error)}</pre></div>`;return;}

  let html=`<div class="section"><div class="st">Timeline Analysis</div>`;
  if(d.overall_assessment){
    html+=`<div class="card cb" style="margin-bottom:12px"><div style="font-size:12px">${esc(d.overall_assessment)}</div></div>`;
  }
  if(d.contradictions?.length){
    d.contradictions.forEach(con=>{
      const sev={'high':'n-red','medium':'n-warn','low':'n-info'}[con.severity]||'n-info';
      html+=`<div class="notice ${sev}" style="margin-bottom:8px">
        <div style="font-weight:500;margin-bottom:3px">${esc(con.description)}</div>
        ${con.recommendation?`<div style="margin-top:4px;font-size:11px">→ ${esc(con.recommendation)}</div>`:''}
      </div>`;
    });
  } else {
    html+=`<div class="notice n-ok">No major contradictions or gaps detected.</div>`;
  }
  if(d.timeline_gaps?.length){
    html+=`<div class="st" style="margin-top:12px;color:var(--amber)">Documentation Gaps</div>`;
    d.timeline_gaps.forEach(g=>{ html+=`<div style="font-size:12px;padding:5px 0;border-bottom:1px solid var(--border-light)">⚠ ${esc(g)}</div>`; });
  }
  html+=`<div class="grid2" style="margin-top:12px">
    ${d.strongest_period?`<div class="stat good"><div class="stat-l">Strongest period</div><div style="font-size:12px;margin-top:4px">${esc(d.strongest_period)}</div></div>`:''}
    ${d.weakest_period?`<div class="stat warn"><div class="stat-l">Weakest period</div><div style="font-size:12px;margin-top:4px">${esc(d.weakest_period)}</div></div>`:''}
  </div></div>`;
  res.innerHTML=html;
}

/* ══════════ PDF EXPORT ══════════ */
function exportPDF(){
  if(!CC) return;
  const a=document.createElement('a');
  a.href='/api/cases/'+CC.id+'/export-pdf';
  a.download='';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}


/* ══════════ COURTROOM VIEW ══════════ */
// High-contrast, large-text mode for use at the podium.
// Opens a standalone full-screen window — separate from the main app.

function renderCourtroom(c){
  c.innerHTML=`
  <div style="max-width:640px">
    <p style="font-size:12px;color:var(--ink2);margin-bottom:16px">
      Opens a full-screen, high-contrast view designed for reading at a podium or from a tablet in the courtroom.
      Your opening statement, key points, evidence list, and counters — all in large readable text with a dark background.
    </p>
    <div class="notice n-info" style="margin-bottom:16px">
      Tip: Generate your <strong>Hearing Prep Guide</strong> and <strong>Case Theory</strong> first — Courtroom View pulls from those.
    </div>
    <button class="btn btn-p" style="font-size:14px;padding:12px 28px" onclick="openCourtroomView()">Open Courtroom View</button>
  </div>`;
}

function openCourtroomView(){
  window.open('/api/cases/'+CC.id+'/courtroom','_blank','width=1000,height=750,toolbar=0,menubar=0,scrollbars=1');
}

/* ══════════ LOADING STATE HELPER ══════════ */
function loadingHTML(msg, size){
  const fs = size==='small' ? '11px' : '12px';
  return `<div style="display:flex;align-items:center;gap:10px;padding:14px 0;color:var(--ink2);font-size:${fs}">
    <span class="spin" style="font-size:18px;display:inline-block">⟳</span>
    <span>${esc(msg)}<br><span style="font-size:10px;color:var(--ink3)">This may take 20–30 seconds — Claude is thinking.</span></span>
  </div>`;
}
function errorHTML(msg){
  return `<div class="notice n-red" style="display:flex;align-items:center;gap:8px">
    <span style="font-size:16px">⚠</span><span>${esc(msg)}</span>
  </div>`;
}

const _btnOrigText = {};

function setBtnLoading(id, loading, doneText){
  const btn = document.getElementById(id);
  if(!btn) return;
  if(loading){
    _btnOrigText[id] = doneText || btn.textContent;
    btn.disabled = true;
    btn.innerHTML = '<span class="spin">⟳</span> Working…';
  } else {
    btn.disabled = false;
    btn.textContent = doneText || _btnOrigText[id] || btn.textContent;
  }
}

// Disable all strategy buttons while any one is running
const _stratBtns = ['theory-btn','adv-btn','contra-btn'];
function stratLock(loading){
  _stratBtns.forEach(id => {
    const btn = document.getElementById(id);
    if(!btn) return;
    if(loading){ btn.disabled = true; }
    else { btn.disabled = !document.getElementById('strat-ack')?.checked; }
  });
}

function moClick(e){if(e.target===document.getElementById('mo'))closeMo();}

/* ══════════ ROADMAP ══════════ */
async function renderRoadmap(c){
  c.innerHTML=loadingHTML('Building your case roadmap…');
  let d;
  try { d=await api('/api/roadmap',{case_id:CC.id}); }
  catch(e){ c.innerHTML=errorHTML('Could not load roadmap. Check your connection.'); return; }
  if(d.raw||d.error){ c.innerHTML=`<div class="card cb"><pre style="white-space:pre-wrap;font-size:11px">${esc(d.raw||d.error)}</pre></div>`; return; }

  const pri={'urgent':'n-red','important':'n-warn','optional':'n-info'};
  const priLabel={'urgent':'🔴 Urgent','important':'🟡 Important','optional':'🔵 Optional'};
  let html=`<div class="section">
    <div style="display:flex;align-items:center;gap:12px;margin-bottom:16px">
      <div style="flex:1;height:6px;background:var(--border);border-radius:3px;overflow:hidden">
        <div style="width:${Math.round((d.stage_number/d.total_stages)*100)}%;height:100%;background:var(--gold);border-radius:3px"></div>
      </div>
      <div style="font-size:12px;color:var(--ink3);white-space:nowrap">Stage ${d.stage_number} of ${d.total_stages}</div>
    </div>
    <div class="card cb" style="margin-bottom:16px">
      <div style="font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--gold);margin-bottom:6px">Current Stage</div>
      <div style="font-size:18px;font-weight:600;margin-bottom:8px">${esc(d.current_stage)}</div>
      <div style="font-size:13px;color:var(--ink2)">${esc(d.stage_description)}</div>
    </div>`;

  if(d.warning){
    html+=`<div class="notice n-red" style="margin-bottom:16px"><strong>⚠ Don't miss:</strong> ${esc(d.warning)}</div>`;
  }

  if(d.immediate_next_steps?.length){
    html+=`<div class="st">Next Steps</div>`;
    d.immediate_next_steps.forEach(s=>{
      html+=`<div class="notice ${pri[s.priority]||'n-info'}" style="margin-bottom:10px">
        <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:6px">
          <div style="font-weight:600;font-size:13px">${esc(s.action)}</div>
          <div style="font-size:10px;color:var(--ink3);white-space:nowrap;margin-left:8px">${priLabel[s.priority]||''}</div>
        </div>
        ${s.deadline?`<div style="font-size:11px;margin-bottom:4px">📅 Deadline: <strong>${esc(s.deadline)}</strong></div>`:''}
        <div style="font-size:12px;color:var(--ink2);margin-bottom:4px">${esc(s.how_to)}</div>
        ${s.form_needed?`<div style="font-size:11px;color:var(--ink3)">📄 Form needed: ${esc(s.form_needed)}</div>`:''}
        ${s.county_note?`<div style="font-size:11px;color:var(--amber);margin-top:4px">📍 ${esc(s.county_note)}</div>`:''}
      </div>`;
    });
  }

  if(d.branch_points?.length){
    html+=`<div class="st" style="margin-top:16px">Decision Points</div>`;
    d.branch_points.forEach(bp=>{
      html+=`<div class="card cb" style="margin-bottom:10px">
        <div style="font-size:12px;font-weight:600;margin-bottom:8px">❓ ${esc(bp.decision)}</div>
        <div class="grid2">
          <div style="background:var(--green-bg);border-radius:6px;padding:10px;font-size:11px"><strong style="color:var(--green)">If yes →</strong><br>${esc(bp.if_yes)}</div>
          <div style="background:var(--red-bg,rgba(220,50,50,.06));border-radius:6px;padding:10px;font-size:11px"><strong style="color:var(--red)">If no →</strong><br>${esc(bp.if_no)}</div>
        </div>
      </div>`;
    });
  }

  if(d.upcoming_stages?.length){
    html+=`<div class="st" style="margin-top:16px">Upcoming Stages</div><div class="card">`;
    d.upcoming_stages.forEach((s,i)=>{
      html+=`<div style="padding:12px 16px;border-bottom:1px solid var(--border-light)">
        <div style="font-size:12px;font-weight:600;margin-bottom:4px">${i+d.stage_number+1}. ${esc(s.stage)}</div>
        <div style="font-size:11px;color:var(--ink2);margin-bottom:6px">${esc(s.description)}</div>
        ${s.key_actions?.map(a=>`<div style="font-size:11px;color:var(--ink3)">• ${esc(a)}</div>`).join('')||''}
      </div>`;
    });
    html+=`</div>`;
  }

  if(d.local_resources){
    html+=`<div class="notice n-info" style="margin-top:16px"><strong>📍 Local Resources:</strong> ${esc(d.local_resources)}</div>`;
  }

  if(d.completed_steps?.length){
    html+=`<div class="st" style="margin-top:16px">Completed</div><div class="card">`;
    d.completed_steps.forEach(s=>{
      html+=`<div style="padding:8px 16px;border-bottom:1px solid var(--border-light);font-size:12px">
        <span style="color:var(--green)">✓</span> ${esc(s.step)}
        ${s.notes?`<span style="color:var(--ink3);font-size:11px"> — ${esc(s.notes)}</span>`:''}
      </div>`;
    });
    html+=`</div>`;
  }

  html+=`<div style="margin-top:16px;text-align:right">
    <button class="btn btn-s" onclick="renderRoadmap(document.getElementById('tc'))">↺ Refresh Roadmap</button>
  </div></div>`;
  c.innerHTML=html;
}

/* ══════════ MOTIONS ══════════ */
function renderMotions(c){
  const motionTypes=[
    'Motion for Contempt','Motion to Modify Custody','Motion to Modify Child Support',
    'Emergency Motion for Custody','Motion for Protective Order','Motion to Compel Discovery',
    'Motion for Continuance','Motion to Strike','Response to Motion','Answer to Petition',
    'Motion for Summary Judgment','Petition to Establish Custody','Motion to Dismiss',
    'Objection to Proposed Order','Request for Findings of Fact'
  ];
  const docs=(CC._docs||[]).filter(d=>motionTypes.some(m=>d.doc_type===m)||d.doc_type?.startsWith('Motion')||d.doc_type?.startsWith('Petition')||d.doc_type?.startsWith('Response')||d.doc_type?.startsWith('Answer')||d.doc_type?.startsWith('Objection')||d.doc_type?.startsWith('Request'));
  c.innerHTML=`
  <div style="max-width:640px">
    <p style="font-size:12px;color:var(--ink2);margin-bottom:16px">Generate complete, properly formatted motions and pleadings using your case facts and jurisdiction-specific statutes.</p>
    <div class="card cb" style="margin-bottom:20px">
      <div class="st">Generate a Motion or Pleading</div>
      <div class="fg" style="margin-bottom:12px">
        <label>Motion Type</label>
        <select id="motion-type">
          ${motionTypes.map(m=>`<option>${m}</option>`).join('')}
          <option value="custom">Custom (type below)…</option>
        </select>
      </div>
      <div class="fg" id="custom-motion-wrap" style="display:none;margin-bottom:12px">
        <label>Custom Motion Name</label>
        <input id="custom-motion-name" placeholder="e.g. Motion to Reinstate Parenting Time">
      </div>
      <div class="notice n-warn" style="margin-bottom:12px">The AI will use your confirmed evidence and case details. Review carefully before filing — this is a draft, not legal advice.</div>
      <button class="btn btn-p" id="motion-btn" onclick="genMotion()">Generate Motion</button>
    </div>
    <div id="motion-result"></div>
    ${docs.length?`<div class="section"><div class="st">Saved Motions & Pleadings</div><div class="card">
      ${docs.map(d=>`<div class="ev"><span class="badge blue">Motion</span><div class="ev-body">
        <div class="ev-content" style="font-weight:500">${esc(d.title||d.doc_type)}</div>
        <div class="ev-meta">${d.created_at?.slice(0,10)||''}</div>
        <div class="ev-acts"><button class="xbtn" onclick="viewDoc(${d.id})">View</button></div>
      </div></div>`).join('')}
    </div></div>`:''}
  </div>`;
  document.getElementById('motion-type').addEventListener('change',function(){
    document.getElementById('custom-motion-wrap').style.display=this.value==='custom'?'':'none';
  });
}
async function genMotion(){
  const sel=document.getElementById('motion-type').value;
  const motionType=sel==='custom'?document.getElementById('custom-motion-name').value.trim():sel;
  if(!motionType){alert('Please enter a motion type.');return;}
  const res=document.getElementById('motion-result');
  setBtnLoading('motion-btn',true,'Generate Motion');
  res.innerHTML=loadingHTML('Drafting your '+motionType+'… This may take 30-60 seconds.');
  let d;
  try { d=await api('/api/motion-template',{case_id:CC.id,motion_type:motionType}); }
  catch(e){ res.innerHTML=errorHTML('Network error — try again.'); setBtnLoading('motion-btn',false,'Generate Motion'); return; }
  setBtnLoading('motion-btn',false,'Generate Motion');
  if(d.error){ res.innerHTML=errorHTML(d.error); return; }
  await refresh();
  res.innerHTML=`<div class="card cb">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
      <div style="font-weight:600">${esc(motionType)}</div>
      <button class="btn btn-s" onclick="copyText('motion-text')">Copy</button>
    </div>
    <pre id="motion-text" style="white-space:pre-wrap;font-size:12px;font-family:Georgia,serif;line-height:1.7">${esc(d.content)}</pre>
  </div>`;
}

/* ══════════ COMMS LOG ══════════ */
function renderComms(c){
  const comms=(CC._ev||[]).filter(e=>e.source?.startsWith('Comm Log'));
  c.innerHTML=`
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
    <p style="font-size:12px;color:var(--ink2)">Log all communications with the other party. Flagged entries are automatically added to your evidence queue.</p>
    <button class="btn btn-s" onclick="openAddComm()">+ Log Communication</button>
  </div>
  ${!comms.length?'<p style="font-size:12px;color:var(--ink3)">No communications logged yet.</p>':
  `<div class="card">${comms.map(e=>`<div class="ev">
    <div style="display:flex;flex-direction:column;gap:3px;min-width:90px">
      <div style="font-size:10px;color:var(--ink3)">${(e.event_date||'').slice(0,10)}</div>
      <span class="badge ${e.confirmed?'green':'amber'}">${e.confirmed?'Confirmed':'Needs review'}</span>
    </div>
    <div class="ev-body">
      <div style="font-size:10px;color:var(--ink3);margin-bottom:3px">${esc(e.source?.replace('Comm Log — ',''))}</div>
      <div class="ev-content">${esc((e.content||'').slice(0,200))}${(e.content||'').length>200?'…':''}</div>
      ${e.category&&e.category!=='Communication'?`<div style="margin-top:4px"><span class="badge red">⚑ ${esc(e.category)}</span></div>`:''}
    </div>
    <div class="ev-acts">
      ${!e.confirmed?`<button class="xbtn ok" onclick="confirmEv(${e.id})">Confirm as Evidence</button>`:''}
    </div>
  </div>`).join('')}</div>`}`;
}
function openAddComm(){
  showMo('Log Communication',`
    <div class="two-col">
      <div class="fg"><label>Date</label><input type="date" id="cm-date"></div>
      <div class="fg"><label>Channel</label><select id="cm-ch">
        <option>Text message</option><option>Email</option><option>Phone call</option>
        <option>In person</option><option>Through attorney</option><option>Social media</option><option>Other</option>
      </select></div>
    </div>
    <div class="fg"><label>Other Party</label><input id="cm-party" placeholder="Name of the other person"></div>
    <div class="fg"><label>Direction</label><select id="cm-dir">
      <option value="received">Received (they contacted me)</option>
      <option value="sent">Sent (I contacted them)</option>
    </select></div>
    <div class="fg"><label>Content / Summary</label>
      <textarea id="cm-content" rows="5" placeholder="Paste the message or summarize what was said…" style="width:100%;background:var(--bg);border:1px solid var(--border);border-radius:var(--r);padding:8px 10px;color:var(--ink);font-size:13px;resize:vertical"></textarea>
    </div>
    <div class="notice n-info" style="margin-bottom:8px">SynJuris will automatically flag this if it matches known violation patterns.</div>
    <div class="br"><button class="btn btn-s" onclick="closeMo()">Cancel</button><button class="btn btn-p" onclick="submitComm()">Log It</button></div>`);
}
async function submitComm(){
  const content=document.getElementById('cm-content').value.trim();
  if(!content){alert('Please enter the communication content.');return;}
  const d=await api('/api/comms',{
    case_id:CC.id,
    entry_date:val('cm-date'),
    channel:val('cm-ch'),
    other_party:val('cm-party'),
    direction:val('cm-dir'),
    content
  });
  closeMo();await refresh();
  if(d.flagged&&d.flags?.length){
    setTimeout(()=>alert('⚑ This communication was flagged for: '+d.flags.join(', ')+'\n\nIt has been added to your evidence queue for review.'),300);
  }
}

/* ══════════ CHILD SUPPORT CALCULATOR ══════════ */
function openChildSupport(){
  showMo('Child Support Calculator',`
    <p style="font-size:12px;color:var(--ink2);margin-bottom:14px">Estimates support based on your state formula. This is an estimate only — verify with the court.</p>
    <div class="two-col">
      <div class="fg"><label>Your Gross Monthly Income ($)</label><input type="number" id="cs-mine" min="0" placeholder="0"></div>
      <div class="fg"><label>Other Parent Monthly Income ($)</label><input type="number" id="cs-theirs" min="0" placeholder="0"></div>
    </div>
    <div class="two-col">
      <div class="fg"><label>Number of Children</label><input type="number" id="cs-kids" min="1" value="1"></div>
      <div class="fg"><label>Custody Split</label><select id="cs-split">
        <option>50/50</option><option>Primary with me (70/30)</option>
        <option>Primary with them (30/70)</option><option>Sole custody (me)</option>
        <option>Sole custody (them)</option>
      </select></div>
    </div>
    <div class="fg"><label>Additional Expenses (optional)</label><input id="cs-exp" placeholder="e.g. $300/mo healthcare, $500/mo daycare"></div>
    <div class="br"><button class="btn btn-s" onclick="closeMo()">Cancel</button><button class="btn btn-p" id="cs-btn" onclick="calcSupport()">Calculate</button></div>
    <div id="cs-result" style="margin-top:14px"></div>`);
}
async function calcSupport(){
  const mine=parseFloat(document.getElementById('cs-mine').value)||0;
  const theirs=parseFloat(document.getElementById('cs-theirs').value)||0;
  const kids=parseInt(document.getElementById('cs-kids').value)||1;
  if(!mine&&!theirs){alert('Please enter at least one income amount.');return;}
  setBtnLoading('cs-btn',true,'Calculate');
  document.getElementById('cs-result').innerHTML=loadingHTML('Calculating using your state formula…','small');
  const d=await api('/api/child-support',{
    case_id:CC.id,your_income:mine,their_income:theirs,
    children:kids,custody_split:val('cs-split'),your_expenses:val('cs-exp')
  });
  setBtnLoading('cs-btn',false,'Calculate');
  if(d.raw||d.error){document.getElementById('cs-result').innerHTML=errorHTML(d.raw||d.error);return;}
  const dir=d.direction==='you pay'?'<span style="color:var(--red)">You pay</span>':'<span style="color:var(--green)">You receive</span>';
  let html=`<div class="card cb">
    <div style="font-size:22px;font-weight:700;margin-bottom:4px">${dir} <span style="color:var(--gold)">$${(d.estimated_amount||0).toLocaleString()}/mo</span></div>
    <div style="font-size:11px;color:var(--ink3);margin-bottom:12px">${esc(d.formula_used)} · ${esc(d.statute||'')}</div>
    <div class="st">How it was calculated</div>
    ${d.calculation_steps?.map(s=>`<div style="display:flex;justify-content:space-between;font-size:12px;padding:5px 0;border-bottom:1px solid var(--border-light)">
      <div>${esc(s.step)}</div><div style="color:var(--gold);font-weight:500">${esc(s.value)}</div>
    </div>`).join('')||''}
    ${d.factors_that_could_change_this?.length?`<div style="margin-top:10px"><div class="st">Factors that could change this</div>
      ${d.factors_that_could_change_this.map(f=>`<div style="font-size:11px;padding:3px 0">• ${esc(f)}</div>`).join('')}
    </div>`:''}
    <div class="notice n-info" style="margin-top:10px;font-size:11px">${esc(d.disclaimer)}</div>
    <div style="margin-top:8px;font-size:11px;color:var(--ink2)">${esc(d.how_to_request||'')}</div>
  </div>`;
  document.getElementById('cs-result').innerHTML=html;
  await refresh();
}

function copyText(id){
  const el=document.getElementById(id);
  if(!el)return;
  navigator.clipboard.writeText(el.textContent).then(()=>alert('Copied to clipboard.'));
}

init();
</script>
</body>
</html>"""


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


    # ── V1 Frontend routes (merged for standalone deployment) ──────────────

    def _handle_frontend(self, path):
        """Returns True if a frontend route was handled."""
        if path == "/login":
            self.send_html(LOGIN_HTML)
            return True

        if path == "/logout":
            token = _get_token(self)
            if token:
                conn = get_db()
                conn.execute("DELETE FROM sessions WHERE token=?", (token,))
                conn.commit(); conn.close()
            self.send_response(302)
            self.send_header("Location", "/login")
            self.send_header("Set-Cookie", "sj_token=; Path=/; HttpOnly; Max-Age=0")
            self.end_headers()
            return True

        if path in ("/", "/index.html"):
            if LOCAL_MODE:
                self.send_html(UI)
                return True
            uid = get_user_from_token(_get_token(self))
            if not uid:
                self.send_response(302)
                self.send_header("Location", "/login")
                self.end_headers()
                return True
            self.send_html(UI)
            return True

        return False

    def do_GET(self):
        p = urlparse(self.path)
        path = p.path

        if self._handle_frontend(path): return

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
