import sqlite3, json, os, re, xml.etree.ElementTree as ET
import webbrowser, threading, urllib.request, urllib.parse
import hashlib, hmac, time, queue, uuid, math
from datetime import datetime, date
from http.server import HTTPServer, BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor
from collections import OrderedDict
from typing import Optional, Callable

VERSION     = "2.0.0"
PORT        = int(os.environ.get("PORT", 5000))
DB_PATH     = os.environ.get("SYNJURIS_DB", "synjuris.db")
UPLOADS_DIR = os.environ.get("SYNJURIS_UPLOADS", "uploads")
API_KEY     = os.environ.get("ANTHROPIC_API_KEY", "")
LOCAL_MODE  = os.environ.get("SYNJURIS_LOCAL", "1") == "1"

class Handler(BaseHTTPRequestHandler):
    """The main server logic bridge."""
    protocol_version = "HTTP/1.1"
    def body(self):
        content_length = int(self.headers.get('Content-Length', 0))
        return json.loads(self.rfile.read(content_length).decode('utf-8')) if content_length > 0 else {}
    
    def do_GET(self):
        # Health check for Render
        if self.path == "/health":
            self.send_response(200); self.end_headers()
            self.wfile.write(b"OK")
            return
VERSION     = "2.0.0"
PORT        = int(os.environ.get("PORT", 5000))
DB_PATH     = os.environ.get("SYNJURIS_DB", "synjuris.db")
UPLOADS_DIR = os.environ.get("SYNJURIS_UPLOADS", "uploads")
API_KEY     = os.environ.get("ANTHROPIC_API_KEY", "")
LOCAL_MODE  = os.environ.get("SYNJURIS_LOCAL", "1") == "1"

# ══════════════════════════════════════════════════════════════════════════════
# 1. CORE INTELLIGENCE: THE STRUCTURE ENGINE
# ══════════════════════════════════════════════════════════════════════════════

class LegalEngine:
    """
    The heart of SynJuris.
    Focuses on 'Structured Legal Intelligence' rather than LLM prose.
    """
    @staticmethod
    def analyze_input(raw_text: str):
        events = re.findall(r'(\d{1,2}/\d{1,2}/\d{2,4}|[A-Z][a-z]+ \d{1,2})', raw_text)
        analysis = {
            "case_id": str(uuid.uuid4())[:8].upper(),
            "timestamp": datetime.now().isoformat(),
            "structure_integrity": 0.85,
            "timeline": [f"Detected Event: {e}" for e in events],
            "suggested_filings": [
                "Notice of Appearance",
                "Request for Production of Documents"
            ] if len(events) > 2 else ["Initial Complaint Draft"],
            "strategy_node": "DISCOVERY_PHASE" if "evidence" in raw_text.lower() else "PLEADING_PHASE"
        }
        return analysis

# ══════════════════════════════════════════════════════════════════════════════
# DETERMINISTIC CASE DYNAMICS ENGINE
# ══════════════════════════════════════════════════════════════════════════════
_CLAMP_MIN, _CLAMP_MAX = 1, 9
def _clamp(v):
    return max(_CLAMP_MIN, min(_CLAMP_MAX, int(v)))
def _transition(current, delta):
    return {"x":_clamp(current["x"]+delta["x"]),
            "y":_clamp(current["y"]+delta["y"]),
            "z":_clamp(current["z"]+delta["z"])}
def _hash_states(states):
    def _n(o):
        if isinstance(o,float): return round(o,8)
        if isinstance(o,dict):  return {k:_n(v) for k,v in sorted(o.items())}
        if isinstance(o,list):  return [_n(i) for i in o]
        return o
    return hashlib.sha256(json.dumps(_n(states),separators=(",",":"),sort_keys=True).encode()).hexdigest()
_EV_CEIL, _ADV_CEIL = 50.0, 50.0
_CAT_W = {"Gatekeeping":5.0,"Violation of Order":5.0,"Threats":5.0,"Relocation":5.0,
          "Parental Alienation":4.0,"Harassment":4.0,"Financial":4.0,
          "Stonewalling":3.0,"Emotional Abuse":2.0,"Neglect / Safety":2.0,
          "Substance Concern":2.0,"Child Statement":1.0}
def _s9(raw, ceil):
    if raw <= 0: return 1
    return _clamp(1+(raw/ceil)*8)
def compute_case_state(case_id):
    conn = get_db()
    ev  = conn.execute("SELECT id,exhibit_number,content,category,event_date,source FROM evidence WHERE case_id=? AND confirmed=1 ORDER BY event_date ASC,id ASC",(case_id,)).fetchall()
    dls = conn.execute("SELECT id,due_date,title,completed FROM deadlines WHERE case_id=?",(case_id,)).fetchall()
    conn.close()
    ev_w=sum(_CAT_W.get(e["category"],1.0) for e in ev)
    adv_w=sum(_CAT_W.get(e["category"],1.0) for e in ev if _CAT_W.get(e["category"],0)>=3.0)
    total_dl=len(dls); done_dl=sum(1 for d in dls if d["completed"])
    over=sum(1 for d in dls if not d["completed"] and d["due_date"] and d["due_date"]<__import__("datetime").date.today().isoformat())
    y_final=5 if not total_dl else _clamp(max(0.0,(done_dl/total_dl)*9-over*0.5)) if (done_dl/total_dl)*9-over*0.5>=1 else 1
    x_final=_s9(ev_w,_EV_CEIL); z_final=_s9(adv_w,_ADV_CEIL)
    running={"x":1,"y":y_final,"z":1}; chain=[]; hist=[dict(running)]
    per_x=(x_final-1)/max(len(ev),1); per_z=(z_final-1)/max(len(ev),1)
    for e in ev:
        w=_CAT_W.get(e["category"],1.0)
        dx=per_x*(w/1.0); dz=per_z*(w/1.0) if w>=3.0 else 0.0
        ns=_transition(running,{"x":dx,"y":0.0,"z":dz})
        chain.append({"exhibit_id":e["id"],"exhibit_number":e["exhibit_number"] or "unnum",
                      "category":e["category"] or "General","weight":w,
                      "event_date":e["event_date"] or "undated","source":e["source"] or "manual",
                      "delta":{"x":round(dx,4),"y":0.0,"z":round(dz,4)},"state_after":dict(ns)})
        hist.append(dict(ns)); running=ns
    fs={"x":x_final,"y":y_final,"z":z_final}
    return {"state":fs,"inputs":{"evidence_count":len(ev),"ev_weight_sum":round(ev_w,4),
            "adv_weight_sum":round(adv_w,4),"total_deadlines":total_dl,
            "done_deadlines":done_dl,"overdue_deadlines":over},"deltas":chain,"hash":_hash_states(hist)}

def log_audit_event(case_id,action_type,ai_call_type,state_snapshot,prompt_inputs,trace_hash):
    conn=get_db()
    st=state_snapshot["state"]
    conn.execute("INSERT INTO audit_log (case_id,action_type,ai_call_type,state_x,state_y,state_z,trace_hash,state_snapshot_json,prompt_inputs_json) VALUES (?,?,?,?,?,?,?,?,?)",
        (case_id,action_type,ai_call_type,st["x"],st["y"],st["z"],trace_hash,
         json.dumps(state_snapshot),json.dumps(prompt_inputs)))
    conn.commit(); conn.close()

def verify_audit_entry(audit_id):
    conn=get_db(); row=conn.execute("SELECT * FROM audit_log WHERE id=?",(audit_id,)).fetchone(); conn.close()
    if not row: return {"error":"not found"}
    stored=row["trace_hash"]; live=compute_case_state(row["case_id"]); recomp=live["hash"]
    match=stored==recomp
    return {"verified":match,"audit_id":audit_id,"stored_hash":stored,"recomputed_hash":recomp,
            "stored_state":json.loads(row["state_snapshot_json"])["state"],"live_state":live["state"],
            "recorded_at":row["created_at"],"action_type":row["action_type"],
            "note":"MATCH — case state is unchanged since this AI call was made." if match
                   else "MISMATCH — evidence or deadlines changed after this AI call."}


# ══════════════════════════════════════════════════════════════════════════════
# DATABASE
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
    CREATE TABLE IF NOT EXISTS financials (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id INTEGER REFERENCES cases(id) ON DELETE CASCADE,
        entry_date TEXT, description TEXT,
        amount REAL, category TEXT, direction TEXT,
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
        action_type TEXT NOT NULL, ai_call_type TEXT,
        state_x INTEGER, state_y INTEGER, state_z INTEGER,
        trace_hash TEXT NOT NULL,
        state_snapshot_json TEXT, prompt_inputs_json TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    """)
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        expires_at DATETIME NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS auth_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL,
        attempted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        success INTEGER DEFAULT 0
    );
    """)
    # FIX 7: waitlist table was missing — /api/waitlist POST would crash
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS waitlist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL UNIQUE,
        source TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    """)
    # ── Schema-version-based migrations ──────────────────────────────────────
    current = conn.execute("SELECT MAX(version) FROM schema_version").fetchone()[0] or 0

    if current < 1:
        existing = [r[1] for r in conn.execute("PRAGMA table_info(evidence)").fetchall()]
        if "file_path" not in existing:
            conn.execute("ALTER TABLE evidence ADD COLUMN file_path TEXT")
        if "file_type" not in existing:
            conn.execute("ALTER TABLE evidence ADD COLUMN file_type TEXT")
        conn.execute("INSERT INTO schema_version(version) VALUES(1)")

    if current < 2:
        tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        if "audit_log" not in tables:
            conn.execute("""CREATE TABLE audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER REFERENCES cases(id) ON DELETE CASCADE,
                action_type TEXT NOT NULL, ai_call_type TEXT,
                state_x INTEGER, state_y INTEGER, state_z INTEGER,
                trace_hash TEXT NOT NULL, state_snapshot_json TEXT,
                prompt_inputs_json TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP)""")
        conn.execute("INSERT INTO schema_version(version) VALUES(2)")

    if current < 3:
        existing_cases = [r[1] for r in conn.execute("PRAGMA table_info(cases)").fetchall()]
        if "user_id" not in existing_cases:
            conn.execute("ALTER TABLE cases ADD COLUMN user_id INTEGER")
        conn.execute("INSERT INTO schema_version(version) VALUES(3)")

    if current < 4:
        ev_cols = [r[1] for r in conn.execute("PRAGMA table_info(evidence)").fetchall()]
        if "original_filename" not in ev_cols:
            conn.execute("ALTER TABLE evidence ADD COLUMN original_filename TEXT")
        if "is_deleted" not in ev_cols:
            conn.execute("ALTER TABLE evidence ADD COLUMN is_deleted INTEGER DEFAULT 0")
        if "deleted_at" not in ev_cols:
            conn.execute("ALTER TABLE evidence ADD COLUMN deleted_at DATETIME")
        case_cols = [r[1] for r in conn.execute("PRAGMA table_info(cases)").fetchall()]
        if "is_deleted" not in case_cols:
            conn.execute("ALTER TABLE cases ADD COLUMN is_deleted INTEGER DEFAULT 0")
        if "deleted_at" not in case_cols:
            conn.execute("ALTER TABLE cases ADD COLUMN deleted_at DATETIME")
        doc_cols = [r[1] for r in conn.execute("PRAGMA table_info(documents)").fetchall()]
        if "is_deleted" not in doc_cols:
            conn.execute("ALTER TABLE documents ADD COLUMN is_deleted INTEGER DEFAULT 0")
        if "deleted_at" not in doc_cols:
            conn.execute("ALTER TABLE documents ADD COLUMN deleted_at DATETIME")
        if "version" not in doc_cols:
            conn.execute("ALTER TABLE documents ADD COLUMN version INTEGER DEFAULT 1")
        if "parent_id" not in doc_cols:
            conn.execute("ALTER TABLE documents ADD COLUMN parent_id INTEGER")
        conn.execute("INSERT INTO schema_version(version) VALUES(4)")

    if current < 5:
        sess_cols = [r[1] for r in conn.execute("PRAGMA table_info(sessions)").fetchall()]
        if "expires_at" not in sess_cols:
            conn.execute("ALTER TABLE sessions ADD COLUMN expires_at DATETIME")
            conn.execute("UPDATE sessions SET expires_at = datetime('now', '+30 days') WHERE expires_at IS NULL")
        tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        if "auth_attempts" not in tables:
            conn.execute("""CREATE TABLE auth_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                attempted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                success INTEGER DEFAULT 0)""")
        conn.execute("INSERT INTO schema_version(version) VALUES(5)")

    if current < 6:
        user_cols = [r[1] for r in conn.execute("PRAGMA table_info(users)").fetchall()]
        if "tier" not in user_cols:
            conn.execute("ALTER TABLE users ADD COLUMN tier TEXT DEFAULT 'pro_se'")
        tables = [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        if "portal_tokens" not in tables:
            conn.execute("""CREATE TABLE portal_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token TEXT NOT NULL UNIQUE,
                case_id INTEGER REFERENCES cases(id) ON DELETE CASCADE,
                attorney_user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                label TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME)""")
        if "portal_evidence" not in tables:
            conn.execute("""CREATE TABLE portal_evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER REFERENCES cases(id) ON DELETE CASCADE,
                portal_token_id INTEGER REFERENCES portal_tokens(id) ON DELETE CASCADE,
                content TEXT, source TEXT, event_date TEXT, category TEXT,
                attorney_note TEXT, approved INTEGER DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP)""")
        if "conflict_checks" not in tables:
            conn.execute("""CREATE TABLE conflict_checks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                case_id INTEGER REFERENCES cases(id),
                party_names_json TEXT,
                result TEXT,
                checked_at DATETIME DEFAULT CURRENT_TIMESTAMP)""")
        if "time_entries" not in tables:
            conn.execute("""CREATE TABLE time_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER REFERENCES cases(id) ON DELETE CASCADE,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                description TEXT, hours REAL DEFAULT 0.0,
                billable INTEGER DEFAULT 1, exported INTEGER DEFAULT 0,
                source TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP)""")
        conn.execute("INSERT INTO schema_version(version) VALUES(6)")

    if current < 7:
        tables = [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        if "citation_cache" not in tables:
            conn.execute("""CREATE TABLE citation_cache (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                citation TEXT NOT NULL UNIQUE,
                result_json TEXT,
                verified_at DATETIME DEFAULT CURRENT_TIMESTAMP)""")
        conn.execute("INSERT INTO schema_version(version) VALUES(7)")

    if current < 8:
        tables = [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        if "generation_jobs" not in tables:
            conn.execute("""CREATE TABLE generation_jobs (
                job_id TEXT PRIMARY KEY,
                case_id INTEGER,
                job_type TEXT,
                doc_type TEXT,
                evidence_hash TEXT,
                state TEXT DEFAULT 'pending',
                doc_id INTEGER,
                error_msg TEXT,
                result_preview TEXT,
                citation_count INTEGER DEFAULT 0,
                dedup_key TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                completed_at DATETIME)""")
        if "user_action_log" not in tables:
            conn.execute("""CREATE TABLE user_action_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                case_id INTEGER,
                user_id INTEGER,
                action_id TEXT,
                doc_type TEXT,
                job_id TEXT,
                doc_id INTEGER,
                case_state_hash TEXT,
                evidence_count INTEGER,
                readiness_score INTEGER,
                options_shown TEXT,
                selected_option TEXT,
                outcome TEXT,
                ip_addr TEXT,
                session_token TEXT,
                metadata_json TEXT,
                prev_hash TEXT DEFAULT NULL,
                record_hash TEXT DEFAULT NULL,
                chain_ver INTEGER DEFAULT 1,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP)""")
        if "merkle_nodes" not in tables:
            conn.execute("""CREATE TABLE merkle_nodes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER NOT NULL,
                exhibit_id INTEGER NOT NULL,
                parent_hash TEXT NOT NULL,
                node_hash TEXT NOT NULL UNIQUE,
                exhibit_snapshot_json TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP)""")
        if "merkle_roots" not in tables:
            conn.execute("""CREATE TABLE merkle_roots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER NOT NULL UNIQUE,
                root_hash TEXT NOT NULL,
                node_count INTEGER NOT NULL DEFAULT 0,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP)""")
        conn.execute("INSERT INTO schema_version(version) VALUES(8)")

    conn.commit(); conn.close()
    os.makedirs(UPLOADS_DIR, exist_ok=True)

# ══════════════════════════════════════════════════════════════════════════════
# JURISDICTION RULES
# ══════════════════════════════════════════════════════════════════════════════

JURISDICTION_LAW = {
    "Alabama":        {"custody": "Ala. Code § 30-3-1", "support": "Ala. Code § 30-3-110", "dv": "Ala. Code § 30-5-1"},
    "Alaska":         {"custody": "Alaska Stat. § 25.20.060", "support": "Alaska Stat. § 25.27.020", "dv": "Alaska Stat. § 18.66.100"},
    "Arizona":        {"custody": "A.R.S. § 25-403", "support": "A.R.S. § 25-501", "dv": "A.R.S. § 13-3601"},
    "Arkansas":       {"custody": "Ark. Code § 9-13-101", "support": "Ark. Code § 9-14-201", "dv": "Ark. Code § 9-15-201"},
    "California":     {"custody": "Cal. Fam. Code § 3020", "support": "Cal. Fam. Code § 4050", "dv": "Cal. Fam. Code § 6200"},
    "Colorado":       {"custody": "C.R.S. § 14-10-124", "support": "C.R.S. § 14-14-104", "dv": "C.R.S. § 13-14-101"},
    "Connecticut":    {"custody": "C.G.S. § 46b-56", "support": "C.G.S. § 46b-84", "dv": "C.G.S. § 46b-15"},
    "Delaware":       {"custody": "13 Del. C. § 722", "support": "13 Del. C. § 514", "dv": "10 Del. C. § 1041"},
    "Florida":        {"custody": "Fla. Stat. § 61.13", "support": "Fla. Stat. § 61.29", "dv": "Fla. Stat. § 741.28"},
    "Georgia":        {"custody": "O.C.G.A. § 19-9-1", "support": "O.C.G.A. § 19-6-15", "dv": "O.C.G.A. § 19-13-1"},
    "Hawaii":         {"custody": "HRS § 571-46", "support": "HRS § 576D-1", "dv": "HRS § 586-1"},
    "Idaho":          {"custody": "Idaho Code § 32-717", "support": "Idaho Code § 32-706", "dv": "Idaho Code § 39-6301"},
    "Illinois":       {"custody": "750 ILCS 5/602.5", "support": "750 ILCS 5/505", "dv": "750 ILCS 60/101"},
    "Indiana":        {"custody": "I.C. § 31-17-2-8", "support": "I.C. § 31-16-6-1", "dv": "I.C. § 34-26-5-1"},
    "Iowa":           {"custody": "Iowa Code § 598.41", "support": "Iowa Code § 598.21B", "dv": "Iowa Code § 236.2"},
    "Kansas":         {"custody": "K.S.A. § 23-3203", "support": "K.S.A. § 23-3001", "dv": "K.S.A. § 60-3101"},
    "Kentucky":       {"custody": "KRS § 403.270", "support": "KRS § 403.212", "dv": "KRS § 403.715"},
    "Louisiana":      {"custody": "La. C.C. Art. 132", "support": "La. R.S. § 9:315", "dv": "La. R.S. § 46:2131"},
    "Maine":          {"custody": "19-A M.R.S. § 1653", "support": "19-A M.R.S. § 2006", "dv": "19-A M.R.S. § 4001"},
    "Maryland":       {"custody": "Md. Code, FL § 9-101", "support": "Md. Code, FL § 12-201", "dv": "Md. Code, FL § 4-501"},
    "Massachusetts":  {"custody": "M.G.L. c.208 § 31", "support": "M.G.L. c.208 § 28", "dv": "M.G.L. c.209A § 1"},
    "Michigan":       {"custody": "MCL § 722.23", "support": "MCL § 552.451", "dv": "MCL § 600.2950"},
    "Minnesota":      {"custody": "Minn. Stat. § 518.17", "support": "Minn. Stat. § 518A.26", "dv": "Minn. Stat. § 518B.01"},
    "Mississippi":    {"custody": "Miss. Code § 93-5-24", "support": "Miss. Code § 93-9-1", "dv": "Miss. Code § 93-21-1"},
    "Missouri":       {"custody": "Mo. Rev. Stat. § 452.375", "support": "Mo. Rev. Stat. § 452.340", "dv": "Mo. Rev. Stat. § 455.010"},
    "Montana":        {"custody": "MCA § 40-4-212", "support": "MCA § 40-5-201", "dv": "MCA § 40-15-101"},
    "Nebraska":       {"custody": "Neb. Rev. Stat. § 43-2923", "support": "Neb. Rev. Stat. § 42-364", "dv": "Neb. Rev. Stat. § 42-903"},
    "Nevada":         {"custody": "NRS § 125C.0035", "support": "NRS § 125B.010", "dv": "NRS § 33.018"},
    "New Hampshire":  {"custody": "RSA § 461-A:6", "support": "RSA § 458-C:3", "dv": "RSA § 173-B:1"},
    "New Jersey":     {"custody": "N.J.S.A. § 9:2-4", "support": "N.J.S.A. § 2A:34-23", "dv": "N.J.S.A. § 2C:25-17"},
    "New Mexico":     {"custody": "NMSA § 40-4-9.1", "support": "NMSA § 40-4-11.1", "dv": "NMSA § 40-13-1"},
    "New York":       {"custody": "N.Y. Dom. Rel. Law § 240", "support": "N.Y. Fam. Ct. Act § 413", "dv": "N.Y. Fam. Ct. Act § 812"},
    "North Carolina": {"custody": "N.C.G.S. § 50-13.2", "support": "N.C.G.S. § 50-13.4", "dv": "N.C.G.S. § 50B-1"},
    "North Dakota":   {"custody": "N.D.C.C. § 14-09-06.2", "support": "N.D.C.C. § 14-09-09.7", "dv": "N.D.C.C. § 14-07.1-01"},
    "Ohio":           {"custody": "ORC § 3109.04", "support": "ORC § 3119.02", "dv": "ORC § 3113.31"},
    "Oklahoma":       {"custody": "43 O.S. § 112", "support": "43 O.S. § 118", "dv": "22 O.S. § 60.1"},
    "Oregon":         {"custody": "ORS § 107.137", "support": "ORS § 107.105", "dv": "ORS § 107.700"},
    "Pennsylvania":   {"custody": "23 Pa.C.S. § 5328", "support": "23 Pa.C.S. § 4322", "dv": "23 Pa.C.S. § 6101"},
    "Rhode Island":   {"custody": "R.I. Gen. Laws § 15-5-16", "support": "R.I. Gen. Laws § 15-5-16.2", "dv": "R.I. Gen. Laws § 15-15-1"},
    "South Carolina": {"custody": "S.C. Code § 63-15-230", "support": "S.C. Code § 63-17-470", "dv": "S.C. Code § 20-4-20"},
    "South Dakota":   {"custody": "SDCL § 25-5-7.1", "support": "SDCL § 25-7-6.2", "dv": "SDCL § 25-10-1"},
    "Tennessee":      {"custody": "TN Code § 36-6-101", "support": "TN Code § 36-5-101", "dv": "TN Code § 36-3-601"},
    "Texas":          {"custody": "Tex. Fam. Code § 153.002", "support": "Tex. Fam. Code § 154.001", "dv": "Tex. Fam. Code § 71.004"},
    "Utah":           {"custody": "Utah Code § 30-3-10", "support": "Utah Code § 78B-12-202", "dv": "Utah Code § 77-36-1"},
    "Vermont":        {"custody": "15 V.S.A. § 665", "support": "15 V.S.A. § 653", "dv": "15 V.S.A. § 1101"},
    "Virginia":       {"custody": "Va. Code § 20-124.3", "support": "Va. Code § 20-108.2", "dv": "Va. Code § 16.1-228"},
    "Washington":     {"custody": "RCW § 26.09.187", "support": "RCW § 26.19.020", "dv": "RCW § 26.50.010"},
    "West Virginia":  {"custody": "W. Va. Code § 48-9-206", "support": "W. Va. Code § 48-13-301", "dv": "W. Va. Code § 48-27-202"},
    "Wisconsin":      {"custody": "Wis. Stat. § 767.41", "support": "Wis. Stat. § 767.511", "dv": "Wis. Stat. § 813.12"},
    "Wyoming":        {"custody": "Wyo. Stat. § 20-2-201", "support": "Wyo. Stat. § 20-2-304", "dv": "Wyo. Stat. § 35-21-102"},
    "Washington D.C.":{"custody": "D.C. Code § 16-914", "support": "D.C. Code § 16-916", "dv": "D.C. Code § 16-1001"},
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
    "tenn":"Tennessee","tenn.":"Tennessee","calif":"California","calif.":"California",
    "colo":"Colorado","colo.":"Colorado","conn":"Connecticut","conn.":"Connecticut",
    "mass":"Massachusetts","mass.":"Massachusetts","mich":"Michigan","mich.":"Michigan",
    "minn":"Minnesota","minn.":"Minnesota","penn":"Pennsylvania","penn.":"Pennsylvania",
    "wisc":"Wisconsin","wisc.":"Wisconsin",
}

def resolve_jurisdiction(raw):
    if not raw:
        return None, {}
    key = raw.strip().lower()
    canonical = JURISDICTION_ALIASES.get(key) or next(
        (k for k in JURISDICTION_LAW if k.lower() == key), None
    )
    if canonical:
        return canonical, JURISDICTION_LAW.get(canonical, {})
    for k in JURISDICTION_LAW:
        if k.lower() in key:
            return k, JURISDICTION_LAW[k]
    return raw.title(), {}

def jurisdiction_statute_block(jurisdiction):
    name, statutes = resolve_jurisdiction(jurisdiction)
    if not statutes:
        return f"Jurisdiction: {name}\n(Specific statute codes not available — describe general legal principles and encourage user to verify their state's laws.)"
    lines = [f"Jurisdiction: {name}"]
    if statutes.get("custody"):
        lines.append(f"  Custody statute:   {statutes['custody']}")
    if statutes.get("support"):
        lines.append(f"  Support statute:   {statutes['support']}")
    if statutes.get("dv"):
        lines.append(f"  DV/protection:     {statutes['dv']}")
    return "\n".join(lines)

# ══════════════════════════════════════════════════════════════════════════════
# PATTERN DETECTION
# ══════════════════════════════════════════════════════════════════════════════

PATTERNS = [
    ("Gatekeeping", 5.0,
     r"(won'?t\s+let\s+(him|her|me|them|you)"
     r"|denied?\s+(visit|access|time|pickup|drop.?off|exchange)"
     r"|prevent(ing|ed)?\s+(me|him|her|them)\s+(from\s+)?(see|visit|contact)"
     r"|(can'?t|cannot|won'?t)\s+(see|have|pick\s*up|get)\s+(him|her|them|the\s*kids?|my\s*(son|daughter|child))"
     r"|(cancel+ed?|call(ed)?\s*off|no.?show)\s*(the\s*)?(visit|exchange|pickup|drop.?off|parenting\s*time)"
     r"|block(ed|ing)?\s*(access|contact|visitation|my\s*time)"
     r"|not\s+(allow(ed|ing)|permit(ted|ting))\s+(me|him|her)\s+to\s+(see|visit|call|talk)"
     r"|keep(ing|s)?\s+(him|her|them|the\s*kids?)\s+(from|away\s*from)\s+me"
     r"|withhold(ing|ed)?\s+(the\s*)?(child(ren)?|kids?|son|daughter)"
     r"|(refuse[sd]?|refus(es|ing))\s+to\s+(do\s+)?(exchange|transfer|drop.?off|pick.?up)"
     r"|didn'?t\s+(bring|drop\s*off|pick\s*up|show\s*up\s*with)\s+(him|her|them|the\s*kids?)"
     r"|(he|she)\s+(isn'?t|was\s+not|weren'?t)\s+(there|home|ready)\s+(for|at)\s*(the\s*)?(pickup|exchange|visit)"
     r"|locked\s+(me\s*out|the\s*door)\s+(when|at\s*exchange)"
     r"|interfere\S*\s+with\s+(my\s+)?(parenting|custody|visitation|time)"
     r"|parenting\s+time\s+(denied|blocked|cancelled|refused)"
     r"|(my|our)\s+(scheduled|court.?ordered)\s+(visit|time|exchange)\s+(was\s+)?(denied|cancelled|blocked)"
     r"|not\s+home\s+(when\s+I|for\s+(the|my))\s+(pickup|exchange|drop)"
     r"|wasn'?t\s+(there|home|ready)\s+for\s+(the\s+)?(pickup|exchange|visit)"
     r"|not\s+(there|home)\s+when\s+I\s+(came|arrived|showed\s+up))"
    ),
    ("Parental Alienation", 4.0,
     r"(alienat(e|ed|ing|ion)"
     r"|(toxic|abusive|bad|dangerous|unfit)\s+(parent(ing)?|father|mother|dad|mom)"
     r"|train(ing|ed)\s+(him|her|them)\s+(to|against)"
     r"|(turn(ing|ed)|turns)\s+(him|her|them|the\s*kids?)\s+against"
     r"|(poison(ing|ed)|brainwash(ing|ed))\s+(his|her|their)\s+mind"
     r"|mak(ing|es)\s+(him|her|them)\s+(think|believe|say)\s+(I'?m|I\s+am|that\s+I)"
     r"|told\s+(him|her|them)\s+(I|daddy|mommy|their\s+(dad|mom))\s+(am|is|was|were)\s+a[n]?\s+\w+"
     r"|(bad.?mouth(ing|ed)|talk(ing|s)\s+(bad|trash|negatively))\s+(about\s+)?(me|their\s+(father|mother|dad|mom))"
     r"|mak(ing|es)\s+adult\s+decisions"
     r"|involv(ing|ed)\s+(him|her|them)\s+in\s+(our|the)\s+(adult|court|legal)\s+(issues?|problems?|fight)"
     r"|(told|tell[s]?|telling)\s+(him|her|them)\s+(not\s+to|to\s+not)\s+(talk\s+to|call|text|contact)\s+me"
     r"|coach(ing|ed|es)?\s+(him|her|them|the\s*kids?)\s+(on\s+)?(what\s+to|to)\s+say"
     r"|(he|she|they)\s+(cried|doesn'?t\s+want|refused|is\s+scared)\s+to\s+(come|go|visit|see)"
     r"|said\s+(I|their\s+(father|mother))\s+(don'?t|doesn'?t)\s+(love|care\s+about|want)\s+(them|him|her)"
     r"|(calls?|refer\S*)\s+(me|their\s+(father|mother))\s+(a[n]?\s+)?(abuser|monster|predator|bad\s+person)"
     r"|(won'?t|doesn'?t)\s+(let\s+them|allow\s+(him|her|them))\s+(talk\s+to|call|text|see)\s+me)"
    ),
    ("Stonewalling", 3.0,
     r"(won'?t\s+respond"
     r"|not\s+responding"
     r"|(never|doesn'?t|don'?t|won'?t)\s+(respond|reply|answer|return)\s+(my\s+)?(call|text|message|email)s?"
     r"|silent\s+treatment|giving\s+me\s+the\s+silent"
     r"|done\s+(talking|communicating|dealing)\s+with\s+you"
     r"|ignor(e|ed|es|ing)\s+(me|my\s+(calls?|texts?|messages?)|all\s+my)"
     r"|block(ed|s|ing)?\s+(my\s+)?(number|calls?|texts?|messages?|emails?|phone)"
     r"|blocked\s+(your|his|her|my)\s+(number|phone|contact)"
     r"|left\s+(me\s+)?(on\s+)?(read|seen)"
     r"|left\s+\S+\s+(on\s+)?(read|seen)"
     r"|refuse[sd]?\s+to\s+(talk|speak|communicate|discuss|respond|reply)"
     r"|(can'?t|cannot)\s+get\s+(a|any)\s+(response|reply|answer|hold\s+of)"
     r"|(no\s+response|haven'?t\s+heard\s+back|heard\s+nothing)\s+(from\s+)?(him|her|them)"
     r"|(hung\s+up|hang(s|ing)\s+up)\s+on\s+me"
     r"|only\s+(communicat\S*|talk\S*|respond\S*)\s+through\s+(the\s+)?(lawyer|attorney|court)"
     r"|goes\s+days?\s+without\s+(respond|reply|answer)"
     r"|(unreachable|unresponsive|ghosting\s+me)"
     r"|read\s+(my\s+)?(text|message)\s+and\s+(didn'?t|never)\s+(reply|respond)"
     r"|seen\s+[0-9]+\s+(hour|day|minute)s?\s+ago\s+and\s+no\s+reply)"
    ),
    ("Threats", 5.0,
     r"((take|taking|gonna\s+take|going\s+to\s+take)\s+(you|this)\s+to\s+court"
     r"|(take|get|going\s+to\s+get|gonna\s+get)\s+(full|sole|primary)\s+custody"
     r"|you'?ll\s+(never|not)\s+(see|have|get)\s+(him|her|them|the\s*kids?|your\s*(son|daughter|child\S*))"
     r"|(call|going\s+to\s+call|gonna\s+call)\s+(the\s*)?(police|cops?|cps|dcs|dcf|child\s*protective|911)"
     r"|(file|going\s+to\s+file)\s+a\s+(restraining|protective)\s+order"
     r"|(file|filing|going\s+to\s+file)\s+(a\s+)?(tpo|opo|tro|emergency\s+order)"
     r"|(have\s+you|get\s+you)\s+(arrested|locked\s+up|thrown\s+in\s+jail)"
     r"|(I'?ll|I\s+will|going\s+to)\s+make\s+sure\s+you\s+(never|regret|pay)"
     r"|(take|move|moving)\s+(him|her|them|the\s*kids?)\s+(away|out\s+of\s+state|where\s+you\s+can'?t)"
     r"|(I'?ll|I\s+will|going\s+to|gonna)\s+(destroy|ruin|expose|report)\s+you"
     r"|lawyer\s+(will|is\s+going\s+to)\s+(destroy|go\s+after|come\s+after|bury)"
     r"|you'?re\s+going\s+to\s+(lose|regret|pay\s+for)\s+(this|everything)"
     r"|(terminate|terminating)\s+your\s+(parental\s+rights|visitation|custody)"
     r"|going\s+to\s+report\s+you\s+to\s+(cps|dcs|dcf|child\s*protective)"
     r"|make\s+your\s+life\s+(hell|miserable|difficult)"
     r"|(I\s+have|got)\s+screenshots?\s+of\s+everything)"
    ),
    ("Harassment", 4.0,
     r"(show(ed|ing|s)?\s+up\s+(uninvited|unannounced|without\s+(notice|calling)|at\s+my\s+(house|work|job|school))"
     r"|(follow(ed|ing|s)|tail(ed|ing)|track(ed|ing|s))\s+(me|my\s+(car|location))"
     r"|(watching|stalking|spying\s+on)\s+me"
     r"|(drove|driving|parked|sitting)\s+(by|past|outside|in\s+front\s+of)\s+my\s+(house|home|work|job)"
     r"|won'?t\s+(leave\s+me\s+alone|stop\s+(calling|texting|contacting|messaging))"
     r"|(constantly|non.?stop|all\s+the\s+time)\s+(call(ing|s)|text(ing|s)|messag(ing|es))\s+me"
     r"|(blowing\s+up|flooding)\s+my\s+(phone|inbox|messages?)"
     r"|contact(ing|ed)\s+my\s+(family|friends?|employer|coworkers?|boss|neighbors?)"
     r"|show(ed|ing|s)?\s+up\s+at\s+(my\s+)?(work|job|school|church|gym)"
     r"|(waited|waiting|sitting)\s+outside\s+(my|the)\s+(house|home|apartment|work|school)"
     r"|sent\s+[0-9]+\s+(texts?|calls?|messages?)\s+(in\s+a\s+row|today|tonight|this\s+(morning|afternoon|evening)))"
    ),
    ("Violation of Order", 5.0,
     r"(violat(e|ed|es|ing|ion)\s+(the\s+)?(court\s+order|parenting\s+plan|custody\s+agreement|order)"
     r"|in\s+contempt"
     r"|against\s+the\s+(court\s+order|order|parenting\s+plan|agreement)"
     r"|(the\s+)?(court\s+order|parenting\s+plan|custody\s+agreement)\s+(says?|requires?|states?|orders?)"
     r"|supposed\s+to\s+(return|bring|drop\s+off|pick\s+up|exchange)\s+(him|her|them|the\s*kids?)"
     r"|required\s+(by\s+the\s+order|to)\s+(return|exchange|allow|provide)"
     r"|(court.?ordered|order\s+requires?)\s+(visitation|custody|exchange|support\s+payment)"
     r"|(didn'?t|doesn'?t|won'?t)\s+(follow|comply\s+with|abide\s+by)\s+the\s+(order|parenting\s+plan)"
     r"|breaking\s+the\s+(court\s+order|parenting\s+plan|agreement|order)"
     r"|held\s+in\s+contempt"
     r"|file\s+for\s+contempt)"
    ),
    ("Financial", 4.0,
     r"(child\s+support"
     r"|alimony"
     r"|spousal\s+support"
     r"|(didn'?t|hasn'?t|won'?t)\s+pay"
     r"|(owes?|owed)\s+(me\s+)?(child\s+support|alimony|\$|money|back\s+pay)"
     r"|delinquent\s+(on\s+)?(support|payments?)"
     r"|in\s+arrears?"
     r"|withhold(ing|ed)?\s+(money|support|payment|my\s+share)"
     r"|hiding\s+(income|assets?|money|accounts?)"
     r"|(quit|quitting|left|leaving)\s+(his|her)\s+job\s+to\s+(avoid|get\s+out\s+of)\s+(paying|support)"
     r"|stopped\s+paying\s+(support|alimony|child\s+support)"
     r"|(missed|skip(ped|ping))\s+(a\s+)?(support\s+)?payment"
     r"|drained\s+(the\s+)?(account|savings|funds?)"
     r"|max(ed|ing)\s+out\s+(the\s+)?(credit\s+card|card|account)"
     r"|transferred\s+(money|assets?|funds?)\s+(to|into)\s+(his|her|their)\s+(name|account))"
    ),
    ("Emotional Abuse", 2.0,
     r"((calling|call(s|ed))\s+me\s+(crazy|insane|stupid|worthless|a\s+(liar|psycho|narcissist|bitch|loser))"
     r"|gaslight(ing|ed)?"
     r"|manipulat(e|ed|es|ing|ion)"
     r"|word\s+salad"
     r"|(your|it'?s\s+all\s+your)\s+fault"
     r"|you'?re\s+(crazy|insane|unstable|a\s+(bad|terrible|unfit)\s+(mother|father|parent))"
     r"|humiliat(e|ed|es|ing)\s+(me|you)"
     r"|(scream(ed|ing|s)|yell(ed|ing|s)|shout(ed|ing|s))\s+at\s+(me|the\s+kids?|him|her)"
     r"|(name.?call(ing|ed)|calling\s+(me|you)\s+names?)"
     r"|constantly\s+(criticiz|belittl|degrad|berat)\S+"
     r"|nothing\s+I\s+(do|say)\s+is\s+(ever\s+)?(good|right|enough)"
     r"|made\s+(me|him|her|them)\s+feel\s+(worthless|stupid|like\s+nothing))"
    ),
    ("Neglect / Safety", 2.0,
     r"((left|leaving)\s+(him|her|them|the\s*kids?)\s+(alone|unsupervised|by\s+(him|her)self)"
     r"|(didn'?t|doesn'?t)\s+(feed|bathe|clothe|take\s+(him|her|them)\s+to)\s+(the\s+)?(doctor|school)"
     r"|(sent|sending|goes?)\s+(him|her|them)\s+to\s+school\s+(hungry|without\s+eating|unfed|in\s+dirty\s+clothes)"
     r"|(bruise|mark|injury|injuries|hurt|injured)\s+(on\s+)?(him|her|them|his|her)\s+(body|arm|leg|face)"
     r"|came\s+home\s+(dirty|hungry|unfed|injured|hurt|with\s+(bruises?|marks?))"
     r"|(dangerous|unsafe|hazardous)\s+(environment|home|conditions?|situation)"
     r"|(no\s+food|nothing\s+to\s+eat|going\s+hungry)\s+(in\s+the\s+house|at\s+(his|her)\s+place)"
     r"|(smoke|smoking)\s+(around|near|in\s+front\s+of)\s+(the\s+kids?|him|her)"
     r"|(exposed|exposing)\s+(him|her|them)\s+to\s+(violence|drugs?|dangerous\s+people))"
    ),
    ("Substance Concern", 2.0,
     r"((drunk|drinking|intoxicated|wasted)\s+(around|near|in\s+front\s+of|while\s+with)\s+(the\s+kids?|him|her)"
     r"|(drunk|high|intoxicated)\s+while\s+(driving|watching|caring\s+for|supervising)\s+(him|her|them|the\s*kids?)"
     r"|(drugs?|drug\s+use)\s+(around|near|in\s+front\s+of)\s+(the\s+kids?|him|her)"
     r"|(smells?\s+like\s+(alcohol|beer|liquor|marijuana|weed)|reeked\s+of)"
     r"|DUI|driving\s+under\s+the\s+influence\s+with\s+(the\s+kids?|him|her)"
     r"|alcohol\s+problem|drug\s+problem"
     r"|found\s+(drugs?|needles?|paraphernalia|pills?|bottles?)\s+(in\s+the\s+house|at\s+(his|her)\s+place))"
    ),
    ("Child Statement", 1.0,
     r"((he|she|they)\s+told\s+me\s+(that\s+)?(daddy|mommy|dad|mom|he|she)\s+(said|told|does?|hits?|hurt)"
     r"|(the\s+)?(kid|child|son|daughter)\s+said\s+(that\s+)?(daddy|mommy|dad|mom|he|she)"
     r"|told\s+(his|her|their)\s+(teacher|counselor|therapist|doctor)\s+that"
     r"|according\s+to\s+(him|her|them|my\s+(son|daughter|child))"
     r"|my\s+(son|daughter|child|kid)\s+(told|said|mentioned|reported)\s+me\s+(that|he|she|about))"
    ),
    ("Relocation", 5.0,
     r"((moving|move|relocat\S+)\s+(out\s+of\s+state|to\s+another\s+state|away|far\s+away)"
     r"|(planning|plans?)\s+to\s+(move|relocate)\s+(with|and\s+take)\s+(him|her|them|the\s*kids?)"
     r"|(taking|took)\s+(him|her|them|the\s*kids?)\s+(out\s+of\s+state|across\s+state\s+lines?)"
     r"|(without|with\s+no)\s+(notice|permission|court\s+approval)\s+(moved|relocat\S+)"
     r"|(didn'?t|doesn'?t|won'?t)\s+(tell|inform|notify|let)\s+me\s+(about\s+the\s+)?(move|relocation)"
     r"|left\s+the\s+state\s+with\s+(him|her|them|the\s*kids?))"
    ),
]

def scan_patterns(text):
    found = []
    seen = set()
    for label, weight, pat in PATTERNS:
        if label not in seen and re.search(pat, text, re.IGNORECASE):
            if weight >= 5.0:
                confidence = "strong"
            elif weight >= 3.0:
                confidence = "likely"
            else:
                confidence = "possible"
            found.append((label, weight, confidence))
            seen.add(label)
    return found

_CONFIDENCE_LABELS = {
    "strong":   "Strong indicator — pattern closely matches known violation language.",
    "likely":   "Likely indicator — pattern matches common conduct of concern.",
    "possible": "Possible indicator — language may be relevant; confirm carefully.",
}
_CONFIDENCE_DISCLAIMER = (
    "This flag does NOT establish a legal violation. "
    "Review the entry and confirm only if it accurately represents what occurred."
)

def top_category(text):
    matches = scan_patterns(text)
    if not matches:
        return None
    return max(matches, key=lambda x: x[1])[0]

# ══════════════════════════════════════════════════════════════════════════════
# STATE INTERPRETATION LAYER
# ══════════════════════════════════════════════════════════════════════════════

def interpret_case_state(snapshot):
    st  = snapshot["state"]
    inp = snapshot["inputs"]
    x, y, z = st["x"], st["y"], st["z"]
    over     = inp.get("overdue_deadlines", 0)
    ev       = inp.get("evidence_count", 0)
    total_dl = inp.get("total_deadlines", 0)
    done_dl  = inp.get("done_deadlines", 0)

    if x <= 2:
        x_text = (f"Your evidence is thin ({ev} confirmed exhibit{'s' if ev!=1 else ''}). "
            "Courts expect documented facts. Add dated communications, records, or witness statements now.")
    elif x <= 4:
        x_text = (f"Developing evidence base ({ev} exhibits). "
            "Confirm unreviewed items and add dates to undated entries — "
            "courts weight contemporaneous records most heavily.")
    elif x <= 6:
        x_text = (f"Solid evidence base ({ev} exhibits). "
            "Look for gaps: are all key incidents documented? "
            "Corroborating records strengthen credibility.")
    else:
        x_text = (f"Strong documented evidence ({ev} exhibits). "
            "Prioritize organizing exhibits chronologically and linking each to a specific legal issue.")

    if over > 0:
        y_text = (f"{over} deadline{'s are' if over>1 else ' is'} overdue. "
            "Missed filings are visible to the court and can be used against you. "
            "File immediately or submit a Motion for Continuance.")
    elif y <= 2:
        y_text = ("Procedural standing is weak. "
            "Add all known court dates, filing deadlines, and response windows so nothing is missed.")
    elif y <= 5:
        if total_dl > 0:
            pct = int((done_dl / total_dl) * 100)
            y_text = (f"{pct}% of deadlines completed ({done_dl}/{total_dl}). "
                "Courts view consistent compliance favorably — mark each deadline complete as you file.")
        else:
            y_text = "No deadlines tracked. Add all known court dates and filing windows."
    else:
        y_text = (f"Procedural standing strong ({done_dl}/{total_dl} deadlines met, none overdue). "
            "Consistent compliance is itself a form of evidence.")

    if z <= 2:
        z_text = ("Low documented adversarial conduct. "
            "Log any incidents immediately with dates, exact quotes, and context — "
            "contemporaneous records are far more credible than later recollections.")
    elif z <= 5:
        z_text = ("Moderate adverse conduct documented. "
            "These exhibits may support a finding of bad faith or willful non-compliance. "
            "Run Adversarial Analysis to see how opposing counsel will frame these.")
    else:
        z_text = ("High adversarial pressure documented. "
            "The pattern in your evidence is significant. "
            "Consider whether a Motion for Contempt or Emergency Motion is appropriate.")

    if over > 0:
        urgency = "critical"
    elif z >= 7 and x <= 3:
        urgency = "high"
    elif y <= 3 or (z >= 5 and ev < 5):
        urgency = "moderate"
    else:
        urgency = "normal"

    if urgency == "critical":
        summary = f"You have {over} overdue deadline{'s' if over>1 else ''} — act immediately."
    elif urgency == "high":
        summary = "Serious adversarial conduct documented but evidence base needs strengthening."
    elif urgency == "moderate":
        summary = "Case is developing — procedural and evidence gaps need attention before your hearing."
    else:
        summary = "Case is well-organized. Keep documenting and stay on top of deadlines."

    return {"x_text": x_text, "y_text": y_text, "z_text": z_text,
            "urgency": urgency, "summary": summary}

# ══════════════════════════════════════════════════════════════════════════════
# PROACTIVE GUIDANCE ENGINE
# ══════════════════════════════════════════════════════════════════════════════

def compute_guidance(case_id):
    conn = get_db()
    case = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
    if not case:
        conn.close(); return []
    c = dict(case)
    ev_all    = conn.execute(
        "SELECT * FROM evidence WHERE case_id=? AND (is_deleted IS NULL OR is_deleted=0)",
        (case_id,)
    ).fetchall()
    deadlines = conn.execute(
        "SELECT * FROM deadlines WHERE case_id=? ORDER BY due_date ASC", (case_id,)
    ).fetchall()
    docs = conn.execute(
        "SELECT doc_type FROM documents WHERE case_id=? AND (is_deleted IS NULL OR is_deleted=0)",
        (case_id,)
    ).fetchall()
    party_count = conn.execute(
        "SELECT COUNT(*) FROM parties WHERE case_id=?", (case_id,)
    ).fetchone()[0]
    conn.close()

    confirmed  = [e for e in ev_all if e["confirmed"]]
    unreviewed = [e for e in ev_all if not e["confirmed"]]
    overdue    = [d for d in deadlines if not d["completed"] and d["due_date"]
                  and d["due_date"] < date.today().isoformat()]
    upcoming   = [d for d in deadlines if not d["completed"] and d["due_date"]
                  and date.today().isoformat() <= d["due_date"]]
    doc_types  = {d["doc_type"] for d in docs}

    hearing_str = c.get("hearing_date","")
    days_to_hearing = None
    if hearing_str:
        try:
            hd = datetime.strptime(hearing_str, "%Y-%m-%d").date()
            days_to_hearing = (hd - date.today()).days
        except Exception:
            pass

    actions = []

    for d in overdue:
        actions.append({
            "priority": 0, "level": "critical", "icon": "🔴",
            "title": f"OVERDUE: {d['title']}",
            "detail": (f"Was due {d['due_date']}. File immediately or request a continuance. "
                "Missed deadlines are visible to the court."),
            "action_tab": "deadlines",
        })

    if days_to_hearing is not None and 0 <= days_to_hearing <= 7:
        actions.append({
            "priority": 1, "level": "critical", "icon": "⚖️",
            "title": f"Hearing in {days_to_hearing} day{'s' if days_to_hearing!=1 else ''}",
            "detail": ("Open Courtroom View to review your exhibits and opening statement. "
                "Ensure your Hearing Prep Guide is generated."),
            "action_tab": "hearing",
        })

    if unreviewed:
        actions.append({
            "priority": 2, "level": "high", "icon": "⚠️",
            "title": f"{len(unreviewed)} item{'s' if len(unreviewed)>1 else ''} need{'s' if len(unreviewed)==1 else ''} review",
            "detail": ("Flagged items are not yet confirmed. "
                "Unconfirmed items don't count toward your evidence strength score."),
            "action_tab": "evidence",
        })

    if not confirmed:
        actions.append({
            "priority": 3, "level": "high", "icon": "📋",
            "title": "No confirmed evidence yet",
            "detail": ("Add your first evidence item. Start with the most recent and most serious incident. "
                "Dated, specific records carry the most weight with courts."),
            "action_tab": "evidence",
        })
    elif len(confirmed) < 5 and days_to_hearing is not None and days_to_hearing <= 30:
        actions.append({
            "priority": 4, "level": "high", "icon": "📋",
            "title": f"Only {len(confirmed)} confirmed exhibit{'s' if len(confirmed)!=1 else ''} — hearing approaching",
            "detail": ("Courts expect documented facts. Add remaining incidents, "
                "communications, or records before your hearing date."),
            "action_tab": "evidence",
        })

    if not deadlines and c.get("hearing_date"):
        actions.append({
            "priority": 5, "level": "moderate", "icon": "📅",
            "title": "No deadlines tracked",
            "detail": ("You have a hearing date set but no deadlines logged. "
                "Add response deadlines, filing dates, and exchange dates."),
            "action_tab": "deadlines",
        })

    if upcoming:
        next_dl = upcoming[0]
        try:
            dl_days = (datetime.strptime(next_dl["due_date"], "%Y-%m-%d").date() - date.today()).days
            if dl_days <= 5:
                actions.append({
                    "priority": 6, "level": "moderate", "icon": "📅",
                    "title": f"Deadline in {dl_days} day{'s' if dl_days!=1 else ''}: {next_dl['title']}",
                    "detail": f"Due {next_dl['due_date']}. Complete and mark done in the Deadlines tab.",
                    "action_tab": "deadlines",
                })
        except Exception:
            pass

    if (days_to_hearing is not None and days_to_hearing <= 30
            and "Hearing Prep Guide" not in doc_types):
        actions.append({
            "priority": 7, "level": "moderate", "icon": "🎯",
            "title": "Generate your Hearing Prep Guide",
            "detail": (f"Your hearing is {days_to_hearing} days away. "
                "Builds your opening statement, evidence introduction order, and anticipated arguments."),
            "action_tab": "hearing",
        })

    if confirmed and len(confirmed) >= 3 and not any(
        t in doc_types for t in ["Case Theory","case-theory"]
    ):
        actions.append({
            "priority": 8, "level": "normal", "icon": "🧠",
            "title": "Build your case summary",
            "detail": ("You have enough evidence to generate a Case Summary — "
                "one sentence that captures what happened, what law applies, and what you're asking for."),
            "action_tab": "strategy",
        })

    snap = compute_case_state(case_id)
    if snap["state"]["z"] >= 6 and not any(
        "Contempt" in dt or "Emergency" in dt for dt in doc_types
    ):
        actions.append({
            "priority": 9, "level": "normal", "icon": "⚖️",
            "title": "High adverse conduct — consider a motion",
            "detail": ("Your evidence shows a significant pattern of violations. "
                "A Motion for Contempt or Emergency Motion may be appropriate."),
            "action_tab": "motions",
        })

    if party_count == 0:
        actions.append({
            "priority": 10, "level": "normal", "icon": "👤",
            "title": "Add case parties",
            "detail": ("No parties entered. Adding the other party and their attorney "
                "helps the AI generate more accurate documents."),
            "action_tab": "overview",
        })

    actions.sort(key=lambda a: a["priority"])
    return actions[:6]


def assign_exhibit_number(conn, case_id):
    row = conn.execute(
        "SELECT COUNT(*) as n FROM evidence WHERE case_id=? AND confirmed=1", (case_id,)
    ).fetchone()
    n = (row["n"] or 0) + 1
    return f"Exhibit {n}"

def export_evidence_txt(case_id):
    conn = get_db()
    case     = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
    parties  = conn.execute("SELECT * FROM parties WHERE case_id=?", (case_id,)).fetchall()
    evidence = conn.execute(
        "SELECT * FROM evidence WHERE case_id=? AND confirmed=1 ORDER BY event_date ASC, created_at ASC",
        (case_id,)
    ).fetchall()
    timeline = conn.execute(
        "SELECT * FROM timeline_events WHERE case_id=? ORDER BY event_date ASC", (case_id,)
    ).fetchall()
    financials = conn.execute(
        "SELECT * FROM financials WHERE case_id=? ORDER BY entry_date ASC", (case_id,)
    ).fetchall()
    conn.close()

    c = dict(case) if case else {}
    lines = []
    sep = "=" * 60

    lines += [
        sep,
        "  SYNJURIS — EVIDENCE MANIFEST",
        f"  Generated: {datetime.now().strftime('%B %d, %Y %H:%M')}",
        sep, "",
        "CASE INFORMATION",
        "-" * 40,
        f"  Title        : {c.get('title','')}",
        f"  Type         : {c.get('case_type','')}",
        f"  Jurisdiction : {c.get('jurisdiction','')}",
        f"  Court        : {c.get('court_name','')}",
        f"  Case Number  : {c.get('case_number','')}",
        f"  Hearing Date : {c.get('hearing_date','')}",
        "",
    ]

    if parties:
        lines += ["PARTIES", "-" * 40]
        for p in parties:
            atty = f" (Attorney: {p['attorney']})" if p['attorney'] else ""
            lines.append(f"  {p['role']}: {p['name']}{atty}")
        lines.append("")

    lines += [f"CONFIRMED EVIDENCE ({len(evidence)} items)", "-" * 40]
    for e in evidence:
        lines += [
            f"  {e['exhibit_number'] or 'Unnumbered'}",
            f"  Date     : {e['event_date'] or 'Unknown'}",
            f"  Category : {e['category'] or 'General'}",
            f"  Source   : {e['source'] or 'Not specified'}",
            f"  Content  :",
        ]
        content = e['content'] or ''
        for chunk in [content[i:i+70] for i in range(0, len(content), 70)]:
            lines.append(f"    {chunk}")
        if e['notes']:
            lines.append(f"  Notes    : {e['notes']}")
        lines.append("-" * 40)
    lines.append("")

    if timeline:
        lines += [f"TIMELINE ({len(timeline)} events)", "-" * 40]
        for t in timeline:
            imp = " [HIGH]" if t['importance'] == 'high' else ""
            lines.append(f"  {t['event_date'] or 'Undated'}{imp}: {t['title']}")
            if t['description']:
                lines.append(f"    {t['description']}")
        lines.append("")

    if financials:
        income  = sum(f['amount'] or 0 for f in financials if f['direction'] == 'income')
        expense = sum(f['amount'] or 0 for f in financials if f['direction'] == 'expense')
        lines += [f"FINANCIAL RECORDS ({len(financials)} entries)", "-" * 40]
        for f in financials:
            sign = "+" if f['direction'] == 'income' else "-"
            lines.append(f"  {f['entry_date'] or 'Undated'}  {sign}${(f['amount'] or 0):.2f}  {f['description']}  [{f['category']}]")
        lines += [
            "",
            f"  Total income  : +${income:.2f}",
            f"  Total expense : -${expense:.2f}",
            f"  Net           :  ${income - expense:.2f}",
            "",
        ]

    lines += [
        sep,
        "  DISCLAIMER: This manifest was generated by SynJuris.",
        "  Review all items carefully before filing with a court.",
        "  This document does not constitute legal advice.",
        sep,
    ]

    text = "\n".join(lines)
    safe_title = re.sub(r"[^\w\s-]", "", c.get('title', 'case')).strip().replace(" ", "_")[:40]
    filename = f"SynJuris_Exhibit_{safe_title}_{date.today().isoformat()}.txt"
    return filename, text.encode("utf-8")

# ══════════════════════════════════════════════════════════════════════════════
# AUTH HELPERS
# ══════════════════════════════════════════════════════════════════════════════

import secrets

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
        else:
            return False
    except Exception:
        return False

_SESSION_DAYS = 30
_MAX_AUTH_ATTEMPTS = 5
_AUTH_WINDOW_SECONDS = 300

def create_session(user_id):
    token = secrets.token_hex(32)
    conn = get_db()
    conn.execute(
        "INSERT INTO sessions (token, user_id, expires_at) VALUES (?,?, datetime('now', '+30 days'))",
        (token, user_id)
    )
    conn.execute("DELETE FROM sessions WHERE expires_at < datetime('now')")
    conn.commit(); conn.close()
    return token

def get_user_from_token(token):
    if not token: return None
    conn = get_db()
    row = conn.execute(
        "SELECT user_id FROM sessions WHERE token=? AND expires_at > datetime('now')",
        (token,)
    ).fetchone()
    conn.close()
    return row["user_id"] if row else None

def _check_rate_limit(email: str) -> bool:
    conn = get_db()
    window_start = f"datetime('now', '-{_AUTH_WINDOW_SECONDS} seconds')"
    count = conn.execute(
        f"SELECT COUNT(*) FROM auth_attempts WHERE email=? AND success=0 AND attempted_at > {window_start}",
        (email.lower(),)
    ).fetchone()[0]
    conn.close()
    return count < _MAX_AUTH_ATTEMPTS

def _record_auth_attempt(email: str, success: bool):
    conn = get_db()
    conn.execute(
        "INSERT INTO auth_attempts (email, success) VALUES (?,?)",
        (email.lower(), 1 if success else 0)
    )
    conn.execute(
        "DELETE FROM auth_attempts WHERE id IN ("
        "  SELECT id FROM auth_attempts WHERE email=? ORDER BY id DESC LIMIT -1 OFFSET 1000"
        ")", (email.lower(),)
    )
    conn.commit(); conn.close()

def get_token_from_request(handler):
    cookie = handler.headers.get("Cookie", "")
    for part in cookie.split(";"):
        part = part.strip()
        if part.startswith("sj_token="):
            return part[len("sj_token="):]
    return None

def get_user_tier(user_id):
    conn = get_db()
    row = conn.execute("SELECT tier FROM users WHERE id=?", (user_id,)).fetchone()
    conn.close()
    return (row["tier"] or "pro_se") if row else "pro_se"

def require_auth(handler):
    token = get_token_from_request(handler)
    uid = get_user_from_token(token)
    if not uid:
        handler.send_json({"error": "unauthorized"}, 401)
    return uid

def require_attorney(handler):
    uid = require_auth(handler)
    if not uid: return None
    if get_user_tier(uid) != "attorney":
        handler.send_json({"error": "Attorney tier required"}, 403)
        return None
    return uid

# LOGIN_HTML and LANDING_HTML omitted for brevity — unchanged from original
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
</script>
</body>
</html>"""

# ══════════════════════════════════════════════════════════════════════════════
# UNIVERSAL AI PROVIDER LAYER
# ══════════════════════════════════════════════════════════════════════════════

_AI_PROVIDER    = os.environ.get("SYNJURIS_AI_PROVIDER", "anthropic").lower().strip()
_AI_MODEL       = os.environ.get("SYNJURIS_AI_MODEL", "")
_OLLAMA_URL     = os.environ.get("SYNJURIS_OLLAMA_URL", "http://localhost:11434")
_OPENAI_KEY     = os.environ.get("OPENAI_API_KEY", "")

_RETRY_ATTEMPTS = 3
_RETRY_DELAYS   = [0, 2, 4]
_RETRY_ON       = {429, 500, 502, 503, 529}
_NO_RETRY       = {400, 401, 403, 404}

_PROVIDER_DEFAULTS = {
    "anthropic": "claude-sonnet-4-20250514",
    "openai":    "gpt-4o",
    "ollama":    "llama3.2",
}

def _call_anthropic(messages, system, max_tokens, model):
    if not API_KEY:
        return ("⚠️ AI features require an Anthropic API key.\n\n"
                "Set ANTHROPIC_API_KEY before starting SynJuris.\n"
                "Get a free key at: https://console.anthropic.com\n\n"
                "Everything else in SynJuris works without a key.")
    model = model or _PROVIDER_DEFAULTS["anthropic"]
    payload = json.dumps({
        "model": model, "max_tokens": max_tokens,
        "system": system, "messages": messages
    }).encode()
    last_error = "Unknown error"
    for attempt in range(_RETRY_ATTEMPTS):
        if _RETRY_DELAYS[attempt] > 0:
            time.sleep(_RETRY_DELAYS[attempt])
        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages", data=payload,
            headers={"Content-Type": "application/json",
                     "x-api-key": API_KEY,
                     "anthropic-version": "2023-06-01"}
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.loads(r.read())["content"][0]["text"]
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            if e.code in _NO_RETRY:
                codes = {401:"Invalid API key.", 403:"Permission denied.",
                         400:"Bad request.", 404:"Endpoint not found."}
                try: msg = json.loads(body).get("error",{}).get("message", body)
                except: msg = body[:200]
                return f"⚠️ {codes.get(e.code, f'API error {e.code}')}\n\nDetail: {msg}"
            if e.code == 529 and attempt == _RETRY_ATTEMPTS-1 and "sonnet" in model:
                return _call_anthropic(messages, system, max_tokens, "claude-haiku-4-5-20251001")
            try: last_error = json.loads(body).get("error",{}).get("message", body[:200])
            except: last_error = body[:200]
            if e.code not in _RETRY_ON or attempt == _RETRY_ATTEMPTS-1:
                codes = {429:"Rate limit — please wait.", 500:"Server error.", 529:"Overloaded — try again."}
                return f"⚠️ {codes.get(e.code, f'HTTP {e.code}')}\n\nDetail: {last_error}"
        except (urllib.error.URLError, TimeoutError) as e:
            last_error = str(getattr(e, "reason", e))
            if attempt == _RETRY_ATTEMPTS-1:
                return f"⚠️ Could not reach Anthropic.\n\nDetail: {last_error}"
        except Exception as e:
            return f"⚠️ Unexpected error: {e}"
    return f"⚠️ Failed after {_RETRY_ATTEMPTS} attempts. Last error: {last_error}"

def _call_openai(messages, system, max_tokens, model):
    if not _OPENAI_KEY:
        return ("⚠️ OpenAI provider requires OPENAI_API_KEY.\n\n"
                "Set it before starting SynJuris:\n"
                "  export OPENAI_API_KEY=sk-...\n\n"
                "Or switch provider: export SYNJURIS_AI_PROVIDER=anthropic")
    model = model or _PROVIDER_DEFAULTS["openai"]
    oai_messages = []
    if system:
        oai_messages.append({"role": "system", "content": system})
    oai_messages.extend(messages)
    payload = json.dumps({"model": model, "max_tokens": max_tokens, "messages": oai_messages}).encode()
    last_error = "Unknown error"
    for attempt in range(_RETRY_ATTEMPTS):
        if _RETRY_DELAYS[attempt] > 0:
            time.sleep(_RETRY_DELAYS[attempt])
        req = urllib.request.Request(
            "https://api.openai.com/v1/chat/completions", data=payload,
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {_OPENAI_KEY}"}
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                data = json.loads(r.read())
                return data["choices"][0]["message"]["content"]
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            if e.code in _NO_RETRY:
                try: msg = json.loads(body).get("error",{}).get("message", body)
                except: msg = body[:200]
                return f"⚠️ OpenAI error {e.code}: {msg}"
            try: last_error = json.loads(body).get("error",{}).get("message", body[:200])
            except: last_error = body[:200]
            if e.code not in _RETRY_ON or attempt == _RETRY_ATTEMPTS-1:
                return f"⚠️ OpenAI error {e.code}\n\nDetail: {last_error}"
        except (urllib.error.URLError, TimeoutError) as e:
            last_error = str(getattr(e, "reason", e))
            if attempt == _RETRY_ATTEMPTS-1:
                return f"⚠️ Could not reach OpenAI.\n\nDetail: {last_error}"
        except Exception as e:
            return f"⚠️ Unexpected error: {e}"
    return f"⚠️ Failed after {_RETRY_ATTEMPTS} attempts. Last error: {last_error}"

def _call_ollama(messages, system, max_tokens, model):
    model = model or _PROVIDER_DEFAULTS["ollama"]
    ollama_chat_url = _OLLAMA_URL.rstrip("/") + "/v1/chat/completions"
    oai_messages = []
    if system:
        oai_messages.append({"role": "system", "content": system})
    oai_messages.extend(messages)
    payload = json.dumps({
        "model": model, "messages": oai_messages, "stream": False,
        "options": {"num_predict": max_tokens},
    }).encode()
    for attempt in range(_RETRY_ATTEMPTS):
        if _RETRY_DELAYS[attempt] > 0:
            time.sleep(_RETRY_DELAYS[attempt])
        try:
            req = urllib.request.Request(ollama_chat_url, data=payload,
                headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=120) as r:
                data = json.loads(r.read())
                if "choices" in data:
                    return data["choices"][0]["message"]["content"]
                if "message" in data:
                    return data["message"].get("content", "")
                return str(data)
        except urllib.error.URLError as e:
            if attempt == _RETRY_ATTEMPTS-1:
                return (f"⚠️ Could not reach Ollama at {_OLLAMA_URL}\n\n"
                        f"Make sure Ollama is running: ollama serve\n"
                        f"And the model is pulled: ollama pull {model}\n\n"
                        f"Detail: {e.reason}")
        except Exception as e:
            if attempt == _RETRY_ATTEMPTS-1:
                return f"⚠️ Ollama error: {e}"
    return "⚠️ Ollama request failed after 3 attempts."

def call_claude(messages, system="", max_tokens=2000, model=""):
    effective_model = _AI_MODEL or model or _PROVIDER_DEFAULTS.get(_AI_PROVIDER, "")
    if _AI_PROVIDER == "openai":
        return _call_openai(messages, system, max_tokens, effective_model)
    elif _AI_PROVIDER == "ollama":
        return _call_ollama(messages, system, max_tokens, effective_model)
    else:
        return _call_anthropic(messages, system, max_tokens, effective_model)

def _keyword_relevance(query: str, text: str) -> int:
    stop = {"the","a","an","is","in","of","to","and","or","for","that","was","it","on","at","be","with","as","by"}
    q_words = {w.lower() for w in re.findall(r'\w+', query) if len(w) > 3 and w.lower() not in stop}
    t_words = {w.lower() for w in re.findall(r'\w+', text) if len(w) > 3 and w.lower() not in stop}
    return len(q_words & t_words)

# ══════════════════════════════════════════════════════════════════════════════
# COURTLISTENER CITATION VERIFICATION
# ══════════════════════════════════════════════════════════════════════════════

_COURTLISTENER_API = "https://www.courtlistener.com/api/rest/v4/search/"
_CITATION_RE = re.compile(
    r'\b(\d+)\s+(U\.?S\.?|F\.?\d*d?|S\.?\s*Ct\.?|'
    r'F\.?\s*Supp\.?\s*\d*d?|[A-Z][a-z]+\.?\s*[A-Z]?[a-z]*\.?)\s+(\d+)'
    r'(?:\s*\(\w[^)]*\d{4}\))?',
    re.IGNORECASE
)

def extract_citations(text):
    return list(dict.fromkeys(_CITATION_RE.findall(text)))

def verify_citation_courtlistener(citation_str):
    conn = get_db()
    cached = conn.execute(
        "SELECT result_json FROM citation_cache WHERE citation=?", (citation_str,)
    ).fetchone()
    conn.close()
    if cached:
        try: return json.loads(cached["result_json"])
        except Exception: pass

    result = {"citation": citation_str, "found": False, "url": None,
              "case_name": None, "warning": None}
    try:
        params = urllib.parse.urlencode({"q": f'"{citation_str}"', "type": "o", "format": "json"})
        url = f"{_COURTLISTENER_API}?{params}"
        req = urllib.request.Request(url, headers={
            "User-Agent": f"SynJuris/{VERSION} (citation-verify; contact: support@synjuris.com)"
        })
        with urllib.request.urlopen(req, timeout=6) as r:
            data = json.loads(r.read())
        count = data.get("count", 0)
        if count > 0:
            result["found"] = True
            first = data["results"][0]
            result["case_name"] = first.get("caseName") or first.get("case_name","")
            result["url"] = (
                f"https://www.courtlistener.com{first['absolute_url']}"
                if first.get("absolute_url") else None
            )
        else:
            result["warning"] = (
                f"Citation '{citation_str}' not found in CourtListener. "
                "Verify this citation exists before filing."
            )
    except Exception as e:
        result["warning"] = f"Citation check unavailable (offline?): {e}"

    conn = get_db()
    try:
        conn.execute(
            "INSERT OR REPLACE INTO citation_cache (citation, result_json) VALUES (?,?)",
            (citation_str, json.dumps(result))
        )
        conn.commit()
    except Exception:
        pass
    conn.close()
    return result

def verify_citations_in_text(text):
    raw_matches = _CITATION_RE.findall(text)
    if not raw_matches:
        return []
    seen = set()
    results = []
    for m in _CITATION_RE.finditer(text):
        cit = m.group(0).strip()
        if cit not in seen:
            seen.add(cit)
            results.append(verify_citation_courtlistener(cit))
    return results


def build_case_system(case_id, user_query: str = ""):
    conn = get_db()
    case     = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
    parties  = conn.execute("SELECT * FROM parties WHERE case_id=?", (case_id,)).fetchall()
    _WEIGHT = {label: w for label, w, _ in PATTERNS}
    all_ev = conn.execute(
        "SELECT exhibit_number,content,category,event_date FROM evidence "
        "WHERE case_id=? AND confirmed=1 AND (is_deleted IS NULL OR is_deleted=0) ORDER BY event_date ASC",
        (case_id,)
    ).fetchall()
    def _score(r):
        base = _WEIGHT.get(r["category"], 0)
        kw   = _keyword_relevance(user_query, r["content"] or "") if user_query else 0
        return base + kw * 0.5
    evidence = sorted(all_ev, key=_score, reverse=True)[:30]
    evidence = sorted(evidence, key=lambda r: r["event_date"] or "")
    deadlines = conn.execute(
        "SELECT due_date,title FROM deadlines WHERE case_id=? AND completed=0 ORDER BY due_date ASC LIMIT 10",
        (case_id,)
    ).fetchall()
    conn.close()
    if not case: return ("", None)
    c = dict(case)
    ev_text = "\n".join([f"  [{e['exhibit_number'] or 'unnum'}] [{e['event_date'] or 'undated'}] ({e['category']}): {(e['content'] or '')[:250]}" for e in evidence]) or "  None confirmed yet."
    dl_text = "\n".join([f"  {d['due_date']}: {d['title']}" for d in deadlines]) or "  None."
    party_text = "\n".join([f"  {p['role']}: {p['name']}" + (f" (atty: {p['attorney']})" if p['attorney'] else '') for p in parties]) or "  None entered."
    jur_block = jurisdiction_statute_block(c.get('jurisdiction',''))
    system = f"""You are SynJuris, a plain-language legal assistant helping a pro se litigant (someone representing themselves in court without a lawyer).

CASE FILE
  Title: {c['title']}
  Type: {c['case_type']}
  {jur_block}
  Court: {c['court_name'] or 'not set'}
  Case #: {c['case_number'] or 'not set'}
  Hearing date: {c['hearing_date'] or 'not set'}
  Goals: {c['goals'] or 'not stated'}

PARTIES
{party_text}

CONFIRMED EVIDENCE ({len(evidence)} items)
{ev_text}

UPCOMING DEADLINES
{dl_text}

YOUR RULES:
1. Always speak in plain, clear English. Explain any legal term the moment you use it.
2. You are NOT a lawyer. Always note this and recommend consulting one for final decisions.
3. When explaining a law, cite the specific statute AND explain what it means practically for THIS person.
4. Be warm and empathetic. These are people in stressful, often frightening situations.
5. When asked to draft a document, produce a complete, properly formatted draft with [BRACKET PLACEHOLDERS] for info you don't have.
6. Never invent statutes or case law. If you're not certain of a specific statute number, say so and describe the general legal principle.
7. When discussing hearing prep, be specific: what to say, what NOT to say, how to address the judge, how to handle objections.
8. For financial questions, walk through the math step by step.
9. If someone seems to be in danger or describes domestic violence, always provide safety resources first."""
    snapshot = compute_case_state(case_id)
    st = snapshot["state"]; inp = snapshot["inputs"]
    state_block = (
        f"  Evidence Strength    (x={st['x']}/9): {inp['evidence_count']} confirmed exhibits, severity sum {inp['ev_weight_sum']}\n"
        f"  Procedural Health    (y={st['y']}/9): {inp['done_deadlines']}/{inp['total_deadlines']} deadlines met, {inp['overdue_deadlines']} overdue\n"
        f"  Adversarial Pressure (z={st['z']}/9): opponent pattern weight sum {inp['adv_weight_sum']}\n"
        f"  State Hash: {snapshot['hash'][:16]}...")
    system += ("\n\nCASE DYNAMICS STATE (deterministic — computed from your evidence and deadlines)\n"
               + state_block +
               "\n  x 1-3=thin evidence; 4-6=developing; 7-9=strong\n"
               "  y 1-3=procedural risk; 4-6=on track; 7-9=well-organised\n"
               "  z 1-3=low aggression; 4-6=moderate; 7-9=highly adversarial\n"
               "  Ground your analysis in these computed values.")
    meta = {"snapshot": snapshot, "prompt_inputs": {"case_id": case_id, "state": st, "trace_hash": snapshot["hash"]}}
    return system, meta

# ══════════════════════════════════════════════════════════════════════════════
# V2 — CITATION WARNING BLOCKS
# ══════════════════════════════════════════════════════════════════════════════

CITATION_WARNING_HEADER = """
⚠ CITATION VERIFICATION NOTICE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
The following citations could NOT be verified against CourtListener.
Courts have sanctioned filers for submitting AI-generated citations
that do not exist. YOU MUST verify each before filing.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
CITATION_UNAVAILABLE_BLOCK = """
⚠ CITATION VERIFICATION UNAVAILABLE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CourtListener could not be reached. Manually verify every case
citation in this document before filing.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
_CITATION_FAIL_THRESHOLD = float(os.environ.get("SYNJURIS_CITATION_FAIL_THRESHOLD", "0.0"))

def build_citation_block(citations, verification_error=None):
    if verification_error:
        return CITATION_UNAVAILABLE_BLOCK.strip() + "\n\n"
    if not citations:
        return ""
    unverified = [c for c in citations if not c.get("found")]
    verified   = [c for c in citations if c.get("found")]
    if not unverified and not verified:
        return ""
    if unverified:
        lines = [CITATION_WARNING_HEADER.strip()]
        for c in unverified:
            lines.append(f"\n  UNVERIFIED: {c['citation']}")
            if c.get("warning"):
                lines.append(f"  → {c['warning']}")
        lines.append("")
        if verified:
            lines.append("Citations that DID verify:")
            for c in verified:
                name = f" ({c['case_name']})" if c.get("case_name") else ""
                lines.append(f"  ✓ {c['citation']}{name}")
        lines.append("━" * 65 + "\n")
        return "\n".join(lines) + "\n"
    lines = ["✓ CITATION VERIFICATION PASSED — All citations found in CourtListener."]
    for c in verified:
        name = f" — {c['case_name']}" if c.get("case_name") else ""
        lines.append(f"  ✓ {c['citation']}{name}")
    lines.append("Verify holdings are accurately represented before filing.\n")
    return "\n".join(lines) + "\n"

def _citation_hard_block(citations):
    if _CITATION_FAIL_THRESHOLD <= 0.0 or not citations:
        return False
    unverified = sum(1 for c in citations if not c.get("found"))
    ratio = unverified / len(citations)
    return ratio > _CITATION_FAIL_THRESHOLD

def verify_citations_safe(content):
    try:
        return verify_citations_in_text(content), None
    except Exception as e:
        return [], str(e)

# ══════════════════════════════════════════════════════════════════════════════
# V2 — MERKLE DAG AUDIT LEDGER
# ══════════════════════════════════════════════════════════════════════════════

_MERKLE_GENESIS = "0" * 64
_MERKLE_SEP     = b"\x1e"

def _merkle_sha(data):
    return hashlib.sha256(data).hexdigest()

def _merkle_canonical(record):
    fields = ["case_id","exhibit_id","content_hash","event_date","category","source","confirmed","ts"]
    parts = [str(record.get(f) or "").encode("utf-8") for f in fields]
    return _MERKLE_SEP.join(parts)

def _merkle_node_hash(parent_hash, record):
    try: prev = bytes.fromhex(parent_hash)
    except: prev = (parent_hash or _MERKLE_GENESIS).encode()
    return _merkle_sha(prev + _MERKLE_SEP + _merkle_canonical(record))

def merkle_add_exhibit(conn, case_id, exhibit):
    existing = conn.execute(
        "SELECT node_hash FROM merkle_nodes WHERE exhibit_id=?", (exhibit["id"],)
    ).fetchone()
    if existing:
        return existing[0] if not hasattr(existing,"keys") else existing["node_hash"]
    tip = conn.execute(
        "SELECT node_hash FROM merkle_nodes WHERE case_id=? ORDER BY id DESC LIMIT 1",
        (case_id,)
    ).fetchone()
    parent = (tip[0] if not hasattr(tip,"keys") else tip["node_hash"]) if tip else _MERKLE_GENESIS
    ts = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    rec = {
        "case_id":      case_id,
        "exhibit_id":   exhibit["id"],
        "content_hash": _merkle_sha((exhibit.get("content") or "").encode()),
        "event_date":   exhibit.get("event_date") or "",
        "category":     exhibit.get("category") or "",
        "source":       exhibit.get("source") or "",
        "confirmed":    exhibit.get("confirmed", 1),
        "ts":           ts,
    }
    node_hash = _merkle_node_hash(parent, rec)
    snap = json.dumps({
        "content_hash": rec["content_hash"],
        "event_date":   rec["event_date"],
        "category":     rec["category"],
    }, separators=(",",":"))
    conn.execute(
        "INSERT INTO merkle_nodes (case_id,exhibit_id,parent_hash,node_hash,exhibit_snapshot_json) "
        "VALUES (?,?,?,?,?)",
        (case_id, exhibit["id"], parent, node_hash, snap)
    )
    rows = conn.execute(
        "SELECT node_hash FROM merkle_nodes WHERE case_id=? ORDER BY id ASC", (case_id,)
    ).fetchall()
    hashes = [r[0] if not hasattr(r,"keys") else r["node_hash"] for r in rows]
    root = _merkle_compute_root(hashes)
    conn.execute(
        "INSERT INTO merkle_roots (case_id,root_hash,node_count,updated_at) VALUES (?,?,?,CURRENT_TIMESTAMP) "
        "ON CONFLICT(case_id) DO UPDATE SET root_hash=excluded.root_hash,"
        "node_count=excluded.node_count,updated_at=excluded.updated_at",
        (case_id, root, len(hashes))
    )
    conn.commit()
    return node_hash

def _merkle_compute_root(hashes):
    if not hashes: return _MERKLE_GENESIS
    if len(hashes) == 1: return hashes[0]
    level = hashes[:]
    while len(level) > 1:
        if len(level) % 2 == 1: level.append(level[-1])
        level = [_merkle_sha((level[i]+level[i+1]).encode("ascii"))
                 for i in range(0, len(level), 2)]
    return level[0]

def merkle_verify_dag(conn, case_id):
    nodes = conn.execute(
        "SELECT id,exhibit_id,parent_hash,node_hash,exhibit_snapshot_json "
        "FROM merkle_nodes WHERE case_id=? ORDER BY id ASC", (case_id,)
    ).fetchall()
    root_row = conn.execute(
        "SELECT root_hash,node_count FROM merkle_roots WHERE case_id=?", (case_id,)
    ).fetchone()
    if not nodes:
        return {"verified":True,"case_id":case_id,"node_count":0,"issues":[],
                "note":"No confirmed evidence in DAG yet."}
    issues = []
    prev_hash = _MERKLE_GENESIS
    computed_hashes = []
    for node in nodes:
        n = dict(node) if hasattr(node,"keys") else {
            "id":node[0],"exhibit_id":node[1],"parent_hash":node[2],
            "node_hash":node[3],"exhibit_snapshot_json":node[4]}
        if n["parent_hash"] != prev_hash:
            issues.append({"type":"chain_break","severity":"critical",
                           "exhibit_id":n["exhibit_id"],"detail":"Parent hash mismatch"})
        live = conn.execute(
            "SELECT content,event_date,category,source FROM evidence WHERE id=?",
            (n["exhibit_id"],)
        ).fetchone()
        if live:
            lv = dict(live) if hasattr(live,"keys") else {
                "content":live[0],"event_date":live[1],"category":live[2],"source":live[3]}
            try:
                snap = json.loads(n["exhibit_snapshot_json"] or "{}")
                stored_ch = snap.get("content_hash","")
                live_ch   = _merkle_sha((lv.get("content") or "").encode())
                if stored_ch and stored_ch != live_ch:
                    issues.append({"type":"content_tampered","severity":"critical",
                                   "exhibit_id":n["exhibit_id"],
                                   "detail":"Exhibit content changed after DAG insertion"})
            except Exception:
                pass
        computed_hashes.append(n["node_hash"])
        prev_hash = n["node_hash"]
    computed_root = _merkle_compute_root(computed_hashes)
    stored_root = (root_row["root_hash"] if hasattr(root_row,"keys") else root_row[0]) if root_row else _MERKLE_GENESIS
    if computed_root != stored_root:
        issues.append({"type":"root_mismatch","severity":"critical",
                       "detail":f"Root hash mismatch"})
    critical = sum(1 for i in issues if i["severity"]=="critical")
    return {
        "verified":       critical == 0,
        "case_id":        case_id,
        "node_count":     len(nodes),
        "root_hash":      computed_root,
        "issues":         issues,
        "critical_count": critical,
        "note": ("DAG intact — all exhibit hashes verified." if critical == 0
                 else f"{critical} integrity issue(s) detected."),
    }

# ══════════════════════════════════════════════════════════════════════════════
# V2 — ACTION AUDIT LOG WITH HASH CHAIN
# ══════════════════════════════════════════════════════════════════════════════

_AUDIT_CHAIN_SEP = b"\x1e"
_AUDIT_GENESIS   = "0" * 64
_AUDIT_FIELDS    = ["chain_ver","event_type","case_id","user_id","action_id","doc_type",
                    "job_id","doc_id","case_state_hash","evidence_count","readiness_score",
                    "options_shown","selected_option","outcome","ip_addr","session_token",
                    "metadata_json","created_at"]

def _audit_canonical(record):
    parts = [str(record.get(f) or "").encode("utf-8") for f in _AUDIT_FIELDS]
    return _AUDIT_CHAIN_SEP.join(parts)

def _audit_record_hash(prev_hash, record):
    try: prev = bytes.fromhex(prev_hash)
    except: prev = (prev_hash or _AUDIT_GENESIS).encode()
    return hashlib.sha256(prev + _AUDIT_CHAIN_SEP + _audit_canonical(record)).hexdigest()

def _audit_get_tip(conn, case_id):
    row = conn.execute(
        "SELECT record_hash FROM user_action_log "
        "WHERE case_id=? AND record_hash IS NOT NULL ORDER BY id DESC LIMIT 1",
        (case_id,)
    ).fetchone()
    if row is None: return _AUDIT_GENESIS
    h = row["record_hash"] if hasattr(row,"keys") else row[0]
    return h or _AUDIT_GENESIS

class AuditLog:
    def __init__(self):
        self._q = queue.Queue(maxsize=500)
        self._writer = threading.Thread(target=self._loop, daemon=True, name="sj-audit")
        self._writer.start()

    def _loop(self):
        while True:
            try:
                rec = self._q.get(timeout=5.0)
                if rec is None: break
                self._write(rec)
            except queue.Empty:
                continue
            except Exception as e:
                import logging; logging.getLogger(__name__).error(f"Audit write error: {e}")

    def _write(self, record):
        try:
            conn = get_db()
            try:
                case_id = record.get("case_id")
                prev_hash = _audit_get_tip(conn, case_id) if case_id else _AUDIT_GENESIS
                ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
                metadata_json_str = json.dumps(record.get("metadata", {}), separators=(",",":"))
                rec_for_hash = {**record, "chain_ver": 1, "created_at": ts,
                                "metadata_json": metadata_json_str}
                record_hash = _audit_record_hash(prev_hash, rec_for_hash)
                conn.execute(
                    "INSERT INTO user_action_log "
                    "(event_type,case_id,user_id,action_id,doc_type,job_id,doc_id,"
                    " case_state_hash,evidence_count,readiness_score,options_shown,"
                    " selected_option,outcome,ip_addr,session_token,metadata_json,"
                    " prev_hash,record_hash,chain_ver,created_at) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (record.get("event_type"), case_id, record.get("user_id"),
                     record.get("action_id"), record.get("doc_type"), record.get("job_id"),
                     record.get("doc_id"), record.get("case_state_hash"),
                     record.get("evidence_count"), record.get("readiness_score"),
                     record.get("options_shown"), record.get("selected_option"),
                     record.get("outcome"), record.get("ip_addr"),
                     record.get("session_token"), metadata_json_str,
                     prev_hash, record_hash, 1, ts)
                )
                conn.commit()
            finally:
                conn.close()
        except Exception as e:
            import logging; logging.getLogger(__name__).error(f"Audit write failed: {e}")

    def log(self, event_type, case_id=None, user_id=None, **kwargs):
        try:
            self._q.put_nowait({"event_type": event_type, "case_id": case_id,
                                "user_id": user_id, **kwargs})
        except queue.Full:
            pass

    def get_timeline(self, case_id, limit=50):
        try:
            conn = get_db()
            try:
                rows = conn.execute(
                    "SELECT event_type,action_id,doc_type,job_id,doc_id,"
                    "case_state_hash,evidence_count,record_hash,created_at "
                    "FROM user_action_log WHERE case_id=? "
                    "ORDER BY created_at DESC LIMIT ?", (case_id, limit)
                ).fetchall()
                return [dict(r) if hasattr(r,"keys") else {
                    "event_type":r[0],"action_id":r[1],"doc_type":r[2],"job_id":r[3],
                    "doc_id":r[4],"case_state_hash":r[5],"evidence_count":r[6],
                    "record_hash":r[7],"created_at":r[8]} for r in rows]
            finally:
                conn.close()
        except Exception:
            return []

    def verify_chain(self, case_id):
        try:
            conn = get_db()
            try:
                rows = conn.execute(
                    "SELECT id,event_type,case_id,user_id,action_id,doc_type,job_id,doc_id,"
                    "case_state_hash,evidence_count,readiness_score,options_shown,"
                    "selected_option,outcome,ip_addr,session_token,metadata_json,"
                    "created_at,prev_hash,record_hash,chain_ver "
                    "FROM user_action_log WHERE case_id=? ORDER BY id ASC", (case_id,)
                ).fetchall()
            finally:
                conn.close()
        except Exception as e:
            return {"verified":False,"error":str(e)}
        if not rows:
            return {"verified":True,"record_count":0,"issues":[],
                    "note":"No audit records for this case."}
        records = [dict(r) if hasattr(r,"keys") else {
            "id":r[0],"event_type":r[1],"case_id":r[2],"user_id":r[3],"action_id":r[4],
            "doc_type":r[5],"job_id":r[6],"doc_id":r[7],"case_state_hash":r[8],
            "evidence_count":r[9],"readiness_score":r[10],"options_shown":r[11],
            "selected_option":r[12],"outcome":r[13],"ip_addr":r[14],"session_token":r[15],
            "metadata_json":r[16],"created_at":r[17],"prev_hash":r[18],
            "record_hash":r[19],"chain_ver":r[20]} for r in rows]
        issues = []
        expected_prev = _AUDIT_GENESIS
        for idx, rec in enumerate(records):
            stored_hash = rec.get("record_hash")
            stored_prev = rec.get("prev_hash")
            chain_ver   = rec.get("chain_ver", 1)
            if stored_hash is None:
                issues.append({"type":"no_hash","severity":"warning","position":idx,
                                "detail":"Pre-v2 record, no hash"})
                expected_prev = _AUDIT_GENESIS
                continue
            if chain_ver == 0:
                rec_for_hash = {**rec, "chain_ver": 0}
                recomp = _audit_record_hash(_AUDIT_GENESIS, rec_for_hash)
                if recomp != stored_hash:
                    issues.append({"type":"hash_mismatch","severity":"critical","position":idx,
                                   "detail":"Legacy record content changed"})
                else:
                    issues.append({"type":"legacy_record","severity":"warning","position":idx,
                                   "detail":"Backfilled record, hash verified"})
                expected_prev = stored_hash
                continue
            if stored_prev != expected_prev:
                issues.append({"type":"chain_break","severity":"critical","position":idx,
                                "detail":f"Expected prev={expected_prev[:16]}… got {str(stored_prev)[:16]}…"})
            rec_for_hash = {**rec, "chain_ver": 1}
            recomp = _audit_record_hash(stored_prev or _AUDIT_GENESIS, rec_for_hash)
            if recomp != stored_hash:
                issues.append({"type":"hash_mismatch","severity":"critical","position":idx,
                                "detail":"Record content changed after insertion"})
                expected_prev = stored_hash
            else:
                expected_prev = stored_hash
        critical = sum(1 for i in issues if i["severity"]=="critical")
        return {
            "verified":       critical == 0,
            "case_id":        case_id,
            "record_count":   len(records),
            "critical_count": critical,
            "warning_count":  sum(1 for i in issues if i["severity"]=="warning"),
            "issues":         issues,
            "note": ("Chain intact." if critical == 0
                     else f"{critical} critical issue(s) — possible tampering detected."),
        }

_audit = AuditLog()

# ══════════════════════════════════════════════════════════════════════════════
# V2 — BACKPRESSURE + ASYNC JOB QUEUE
# ══════════════════════════════════════════════════════════════════════════════

_MAX_WORKERS    = 8
_MAX_AI_CALLS   = 6
_MAX_QUEUE_DEPTH = 20
_REPLAY_CHUNK   = 80

_ai_semaphore   = threading.Semaphore(_MAX_AI_CALLS)
_queue_depth    = 0
_queue_lock     = threading.Lock()
_executor       = ThreadPoolExecutor(max_workers=_MAX_WORKERS, thread_name_prefix="sj-gen")
_spec_executor  = ThreadPoolExecutor(max_workers=2, thread_name_prefix="sj-spec")

class _JobState:
    PENDING  = "pending"
    RUNNING  = "running"
    COMPLETE = "complete"
    FAILED   = "failed"

class _Job:
    def __init__(self, job_id, job_type, case_id, doc_type, ev_hash, instructions=""):
        self.job_id       = job_id
        self.job_type     = job_type
        self.case_id      = case_id
        self.doc_type     = doc_type
        self.evidence_hash = ev_hash
        self.instructions = instructions
        self.state        = _JobState.PENDING
        self.result       = None
        self.citations    = []
        self.doc_id       = None
        self.error        = None
        self._tokens      = []
        self._token_lock  = threading.Lock()
        self._done        = threading.Event()
        self._subs        = []
        self._sub_lock    = threading.Lock()
    def push_token(self, tok):
        with self._token_lock: self._tokens.append(tok)
        with self._sub_lock:
            for q in self._subs:
                try: q.put_nowait(("token", tok))
                except: pass
    def push_event(self, ev, data):
        with self._sub_lock:
            for q in self._subs:
                try: q.put_nowait((ev, data))
                except: pass
    def mark_complete(self, result, citations, doc_id=None):
        self.state = _JobState.COMPLETE
        self.result = result; self.citations = citations; self.doc_id = doc_id
        self._done.set()
        self.push_event("complete", {"job_id":self.job_id,"doc_id":doc_id})
        _persist_job(self)
    def mark_failed(self, error):
        self.state = _JobState.FAILED; self.error = error
        self._done.set()
        self.push_event("error", {"job_id":self.job_id,"error":error})
        _persist_job(self)
    def subscribe(self):
        q = queue.Queue(maxsize=5000)
        with self._sub_lock: self._subs.append(q)
        with self._token_lock: buf = list(self._tokens)
        return buf, q, self._done, (self.state == _JobState.COMPLETE)

class _LRUJobCache:
    def __init__(self, maxsize=100):
        self._d   = OrderedDict()
        self._keys = {}
        self._lock = threading.Lock()
        self._max  = maxsize
    def put(self, job, dedup_key=None):
        with self._lock:
            self._d[job.job_id] = job; self._d.move_to_end(job.job_id)
            if dedup_key: self._keys[dedup_key] = job.job_id
            while len(self._d) > self._max: self._d.popitem(last=False)
    def get(self, job_id):
        with self._lock: return self._d.get(job_id)
    def get_by_key(self, key):
        with self._lock:
            jid = self._keys.get(key)
            return self._d.get(jid) if jid else None

_job_cache = _LRUJobCache()

def _ev_hash(conn, case_id):
    rows = conn.execute(
        "SELECT id,content,event_date,category FROM evidence "
        "WHERE case_id=? AND confirmed=1 AND (is_deleted IS NULL OR is_deleted=0) ORDER BY id ASC",
        (case_id,)
    ).fetchall()
    payload = json.dumps([
        {"id":r[0],"ch":hashlib.md5((r[1] or "").encode()).hexdigest(),"d":r[2] or "","c":r[3] or ""}
        for r in rows
    ], separators=(",",":"))
    return hashlib.sha256(payload.encode()).hexdigest()[:32]

def _persist_job(job):
    try:
        conn = get_db()
        dedup_key = f"{job.case_id}:{job.doc_type}:{job.evidence_hash}"
        conn.execute(
            "INSERT OR REPLACE INTO generation_jobs "
            "(job_id,case_id,job_type,doc_type,evidence_hash,state,doc_id,error_msg,"
            " result_preview,citation_count,dedup_key,completed_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP)",
            (job.job_id, job.case_id, job.job_type, job.doc_type, job.evidence_hash,
             job.state, job.doc_id, job.error, (job.result or "")[:500],
             len(job.citations or []), dedup_key)
        )
        conn.commit(); conn.close()
    except Exception: pass

def _queue_try_acquire():
    global _queue_depth
    with _queue_lock:
        if _queue_depth >= _MAX_QUEUE_DEPTH: return False
        _queue_depth += 1; return True

def _queue_release():
    global _queue_depth
    with _queue_lock: _queue_depth = max(0, _queue_depth - 1)

def job_submit(job_type, case_id, doc_type, conn, instructions="", force=False):
    eh = _ev_hash(conn, case_id)
    dedup = f"{case_id}:{doc_type}:{eh}"
    if not force:
        existing = _job_cache.get_by_key(dedup)
        if existing and existing.state in (_JobState.COMPLETE, _JobState.PENDING, _JobState.RUNNING):
            return existing.job_id
    if not _queue_try_acquire():
        return "__QUEUE_FULL__"
    job = _Job(str(uuid.uuid4()), job_type, case_id, doc_type, eh, instructions)
    _job_cache.put(job, dedup)
    try:
        conn.execute(
            "INSERT OR IGNORE INTO generation_jobs "
            "(job_id,case_id,job_type,doc_type,evidence_hash,state,dedup_key) VALUES (?,?,?,?,?,?,?)",
            (job.job_id, case_id, job_type, doc_type, eh, "pending", dedup)
        )
        conn.commit()
    except Exception: pass
    _executor.submit(_run_job, job)
    return job.job_id

def _run_job(job):
    acquired = False
    try:
        acquired = _ai_semaphore.acquire(timeout=30.0)
        if not acquired:
            job.mark_failed("Server busy — too many concurrent requests. Try again in a moment.")
            return
        job.state = _JobState.RUNNING
        conn = get_db()
        try:
            _do_generate(job, conn)
        finally:
            conn.close()
    except Exception as e:
        job.mark_failed(str(e))
    finally:
        if acquired: _ai_semaphore.release()
        _queue_release()

def _do_generate(job, conn):
    job.push_event("progress", {"pct":10,"stage":"Building context…"})
    case    = conn.execute("SELECT * FROM cases WHERE id=?", (job.case_id,)).fetchone()
    parties = conn.execute("SELECT * FROM parties WHERE case_id=?", (job.case_id,)).fetchall()
    evidence = conn.execute(
        "SELECT exhibit_number,content,category,event_date FROM evidence "
        "WHERE case_id=? AND confirmed=1 ORDER BY event_date ASC",
        (job.case_id,)
    ).fetchall()
    if not case:
        job.mark_failed("Case not found"); return
    c = dict(case)
    jb = jurisdiction_statute_block(c.get("jurisdiction",""))
    party_lines = "\n".join(
        f"  {p['role'] if hasattr(p,'__getitem__') else p[1]}: "
        f"{p['name'] if hasattr(p,'__getitem__') else p[0]}" for p in parties
    ) or "  Not specified"
    ev_lines = "\n".join(
        f"[{e['exhibit_number'] if hasattr(e,'__getitem__') else e[0] or 'unnum'}] "
        f"({e['category'] if hasattr(e,'__getitem__') else e[2]}): "
        f"{(e['content'] if hasattr(e,'__getitem__') else e[1] or '')[:200]}"
        for e in evidence[:25]
    ) or "  None confirmed."
    job.push_event("progress", {"pct":20,"stage":"Generating…"})
    prompt = f"""Draft a complete {job.doc_type} for a pro se litigant.
CASE: {c.get('title')} | {c.get('case_type')} | {jb}
Court: {c.get('court_name') or '[COURT NAME]'} | Case #: {c.get('case_number') or '[CASE NUMBER]'}
PARTIES:\n{party_lines}
EVIDENCE:\n{ev_lines}
INSTRUCTIONS: {job.instructions or 'None.'}
Use [BRACKET PLACEHOLDERS] for missing info. Include certificate of service. Plain English."""
    result = call_claude([{"role":"user","content":prompt}], max_tokens=3000)
    words = result.split()
    for i in range(0, len(words), 8):
        job.push_token(" ".join(words[i:i+8]) + " ")
    job.push_event("progress", {"pct":82,"stage":"Verifying citations…"})
    citations, cit_err = verify_citations_safe(result)
    if _citation_hard_block(citations):
        unverified = [c["citation"] for c in citations if not c.get("found")]
        job.mark_failed(f"CITATION_HARD_BLOCK — {len(unverified)} unverified citations: {', '.join(unverified[:3])}.")
        return
    citation_block = build_citation_block(citations, cit_err)
    if citation_block:
        result = citation_block + result
    job.push_event("progress", {"pct":90,"stage":"Saving…"})
    from datetime import datetime as _dt
    doc_title = f"{job.doc_type} — {_dt.now().strftime('%b %d %Y')}"
    cur = conn.execute(
        "INSERT INTO documents (case_id,title,doc_type,content) VALUES (?,?,?,?)",
        (job.case_id, doc_title, job.doc_type, result)
    )
    conn.commit()
    _audit.log("doc_generated", case_id=job.case_id, doc_type=job.doc_type,
               job_id=job.job_id, doc_id=cur.lastrowid, outcome="success",
               metadata={"citation_count":len(citations)})
    job.mark_complete(result, citations, cur.lastrowid)

def job_stream_sse(job_id, handler):
    handler.send_response(200)
    handler.send_header("Content-Type","text/event-stream")
    handler.send_header("Cache-Control","no-cache")
    handler.send_header("X-Accel-Buffering","no")
    handler.end_headers()
    def _sse(ev, data):
        payload = json.dumps({"type":ev,**data},separators=(",",":"))
        return f"data: {payload}\n\n".encode("utf-8")
    job = _job_cache.get(job_id)
    if not job:
        try:
            conn = get_db()
            row = conn.execute(
                "SELECT doc_id,state,error_msg FROM generation_jobs WHERE job_id=?", (job_id,)
            ).fetchone()
            conn.close()
            if row:
                r = dict(row) if hasattr(row,"keys") else {"doc_id":row[0],"state":row[1],"error_msg":row[2]}
                if r["state"] == "complete" and r["doc_id"]:
                    conn2 = get_db()
                    doc = conn2.execute("SELECT content FROM documents WHERE id=?", (r["doc_id"],)).fetchone()
                    conn2.close()
                    if doc:
                        content = doc["content"] if hasattr(doc,"keys") else doc[0]
                        handler.wfile.write(_sse("replay_start",{"replayed":True}))
                        for i in range(0, len(content), _REPLAY_CHUNK):
                            handler.wfile.write(_sse("token",{"text":content[i:i+_REPLAY_CHUNK]}))
                            handler.wfile.flush()
                        handler.wfile.write(_sse("complete",{"replayed":True}))
                        handler.wfile.write(_sse("done",{}))
                        return
                elif r["state"] == "failed":
                    handler.wfile.write(_sse("error",{"error":r.get("error_msg","Failed")}))
                    return
        except Exception: pass
        handler.wfile.write(_sse("error",{"error":"Job not found"}))
        return
    buf, q, done_evt, already_done = job.subscribe()
    try:
        for tok in buf:
            handler.wfile.write(_sse("token",{"text":tok}))
        if already_done:
            handler.wfile.write(_sse("complete",{"doc_id":job.doc_id}))
            handler.wfile.write(_sse("done",{}))
            return
        while True:
            try:
                ev_type, data = q.get(timeout=30.0)
                if ev_type == "token":
                    handler.wfile.write(_sse("token",{"text":data}))
                elif ev_type == "complete":
                    handler.wfile.write(_sse("complete",data))
                    handler.wfile.write(_sse("done",{}))
                    return
                elif ev_type == "error":
                    handler.wfile.write(_sse("error",data))
                    return
                handler.wfile.flush()
            except queue.Empty:
                handler.wfile.write(b": heartbeat\n\n")
                handler.wfile.flush()
                if done_evt.is_set():
                    handler.wfile.write(_sse("done",{}))
                    return
    except (BrokenPipeError, ConnectionResetError):
        pass

# ══════════════════════════════════════════════════════════════════════════════
# V2 — DOCUMENT READINESS SCORING
# ══════════════════════════════════════════════════════════════════════════════

def compute_doc_readiness(case_id, conn):
    case = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
    if not case: return []
    c = dict(case)
    ev = [dict(r) for r in conn.execute(
        "SELECT category,confirmed FROM evidence WHERE case_id=? AND (is_deleted IS NULL OR is_deleted=0)",
        (case_id,)
    ).fetchall()]
    dl = [dict(r) for r in conn.execute(
        "SELECT due_date,completed FROM deadlines WHERE case_id=?", (case_id,)
    ).fetchall()]
    parties = conn.execute("SELECT COUNT(*) FROM parties WHERE case_id=?", (case_id,)).fetchone()[0]
    conf_cats = {e["category"] for e in ev if e.get("confirmed")}
    conf_count = len([e for e in ev if e.get("confirmed")])
    has_order  = bool(c.get("case_number") or c.get("court_name"))
    has_jur    = bool(c.get("jurisdiction"))
    has_goals  = bool(c.get("goals"))
    has_hearing = bool(c.get("hearing_date"))
    today = date.today().isoformat()
    overdue = sum(1 for d in dl if not d.get("completed") and d.get("due_date","") < today)
    docs = [
        ("Motion for Contempt",
         [("Existing order documented", has_order, 25),
          ("Violation of Order evidence", "Violation of Order" in conf_cats, 30),
          ("Gatekeeping/threats documented", bool(conf_cats & {"Gatekeeping","Threats","Harassment"}), 20),
          ("3+ confirmed exhibits", conf_count >= 3, 15),
          ("Parties identified", parties >= 2, 10)]),
        ("Hearing Prep Guide",
         [("Hearing date set", has_hearing, 20),
          ("5+ confirmed exhibits", conf_count >= 5, 30),
          ("Goals stated", has_goals, 20),
          ("Jurisdiction set", has_jur, 15),
          ("Parties identified", parties >= 2, 15)]),
        ("Declaration",
         [("3+ confirmed exhibits", conf_count >= 3, 35),
          ("Goals stated", has_goals, 25),
          ("Parties identified", parties >= 2, 20),
          ("Jurisdiction set", has_jur, 20)]),
        ("Emergency Motion for Custody",
         [("Safety evidence", bool(conf_cats & {"Neglect / Safety","Substance Concern","Threats"}), 35),
          ("Interference documented", bool(conf_cats & {"Relocation","Gatekeeping"}), 25),
          ("2+ confirmed exhibits", conf_count >= 2, 20),
          ("Jurisdiction set", has_jur, 10),
          ("Parties identified", parties >= 2, 10)]),
        ("Protective Order Request",
         [("Threat/harassment evidence", bool(conf_cats & {"Threats","Harassment"}), 40),
          ("Safety evidence", bool(conf_cats & {"Neglect / Safety","Emotional Abuse"}), 25),
          ("Other party identified", parties >= 1, 20),
          ("Jurisdiction set", has_jur, 15)]),
        ("Demand Letter",
         [("1+ confirmed exhibit", conf_count >= 1, 30),
          ("Other party identified", parties >= 1, 35),
          ("Goals stated", has_goals, 35)]),
    ]
    results = []
    for doc_type, reqs in docs:
        earned = sum(w for _,met,w in reqs if met)
        total  = sum(w for _,_,w in reqs)
        score  = int(earned / total * 100) if total else 0
        unmet  = [label for label,met,_ in reqs if not met]
        results.append({
            "doc_type":    doc_type,
            "score":       score,
            "label":       "Ready" if score>=90 else "Nearly ready" if score>=70
                           else "Partially ready" if score>=50 else "Not ready",
            "unmet_tips":  unmet,
            "speculative": score >= 90,
        })
    results.sort(key=lambda x: -x["score"])
    return results

# ══════════════════════════════════════════════════════════════════════════════
# V2 — BRANCHING ACTION SYSTEM
# ══════════════════════════════════════════════════════════════════════════════

def get_available_actions(case_id, conn):
    case = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
    if not case: return []
    c = dict(case)
    ev = conn.execute(
        "SELECT category,confirmed FROM evidence WHERE case_id=? AND (is_deleted IS NULL OR is_deleted=0)",
        (case_id,)
    ).fetchall()
    dl = conn.execute("SELECT due_date,title,completed FROM deadlines WHERE case_id=? ORDER BY due_date ASC", (case_id,)).fetchall()
    parties = conn.execute("SELECT COUNT(*) FROM parties WHERE case_id=?", (case_id,)).fetchone()[0]
    gen_docs = {r[0] for r in conn.execute(
        "SELECT DISTINCT doc_type FROM documents WHERE case_id=? AND (is_deleted IS NULL OR is_deleted=0)", (case_id,)
    ).fetchall()}
    today = date.today().isoformat()
    overdue  = [d for d in dl if not (d["completed"] if hasattr(d,"__getitem__") else d[2])
                and (d["due_date"] if hasattr(d,"__getitem__") else d[0] or "") < today]
    conf_cats = {(e["category"] if hasattr(e,"__getitem__") else e[0]) for e in ev
                 if (e["confirmed"] if hasattr(e,"__getitem__") else e[1])}
    unconfirmed = [e for e in ev if not (e["confirmed"] if hasattr(e,"__getitem__") else e[1])]
    conf_count  = len([e for e in ev if (e["confirmed"] if hasattr(e,"__getitem__") else e[1])])
    hearing_str = c.get("hearing_date","")
    days_to_hearing = None
    if hearing_str:
        try:
            from datetime import datetime as _dt
            days_to_hearing = (_dt.strptime(hearing_str,"%Y-%m-%d").date() - date.today()).days
        except: pass
    actions = []
    for d in overdue[:3]:
        dt = d["title"] if hasattr(d,"__getitem__") else d[1]
        dd = d["due_date"] if hasattr(d,"__getitem__") else d[0]
        actions.append({"id":f"overdue_{dd}","priority":"urgent","title":f"Overdue: {dt}",
                        "description":f"This deadline passed on {dd}. Filing options are available.",
                        "tab":"deadlines","readiness":None,"cta":"View Deadlines"})
    if days_to_hearing is not None and 0 <= days_to_hearing <= 7:
        has_prep = "Hearing Prep Guide" in gen_docs
        actions.append({"id":"imminent_hearing","priority":"urgent",
                        "title":f"Hearing in {days_to_hearing} day{'s' if days_to_hearing!=1 else ''}",
                        "description":"A Hearing Prep Guide is available for this case." if not has_prep
                                      else "Your Hearing Prep Guide is ready.",
                        "tab":"hearing","readiness":None,
                        "cta":"View Hearing Prep" if has_prep else "Generate Hearing Prep"})
    if unconfirmed:
        actions.append({"id":"unconfirmed","priority":"high",
                        "title":f"{len(unconfirmed)} item{'s' if len(unconfirmed)>1 else ''} flagged for review",
                        "description":"Flagged items are not counted in your evidence score until confirmed.",
                        "tab":"evidence","readiness":None,"cta":"Review Evidence"})
    readiness = compute_doc_readiness(case_id, conn)
    for r in readiness:
        if r["doc_type"] in gen_docs: continue
        if r["score"] < 50 and not any(cat in conf_cats for cat in
            {"Violation of Order","Threats","Neglect / Safety","Relocation"}): continue
        actions.append({"id":f"doc_{r['doc_type'].lower().replace(' ','_').replace('/','_')}",
                        "priority":"high" if r["score"]>=70 else "moderate",
                        "title":r["doc_type"],
                        "description":f"This document is available based on your case data. Readiness: {r['label']}.",
                        "tab":"documents","readiness":r["score"],
                        "cta":"Generate" if r["score"]>=70 else "View requirements",
                        "doc_type":r["doc_type"]})
    _priority = {"urgent":0,"high":1,"moderate":2}
    actions.sort(key=lambda a: (_priority.get(a["priority"],9), -(a["readiness"] or 0)))
    return actions[:8]

# ══════════════════════════════════════════════════════════════════════════════
# HTTP HANDLER
# ══════════════════════════════════════════════════════════════════════════════

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _cors_origin(self):
        return f"http://localhost:{PORT}"

    def send_json(self, data, status=200):
        b = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",len(b))
        self.send_header("Access-Control-Allow-Origin", self._cors_origin())
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers(); self.wfile.write(b)

    def send_html(self, html):
        b = html.encode()
        self.send_response(200)
        self.send_header("Content-Type","text/html;charset=utf-8")
        self.send_header("Content-Length",len(b))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers(); self.wfile.write(b)

    def body(self):
        n = int(self.headers.get("Content-Length",0))
        return json.loads(self.rfile.read(n)) if n else {}

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", self._cors_origin())
        self.send_header("Access-Control-Allow-Methods","GET,POST,PUT,DELETE,OPTIONS")
        self.send_header("Access-Control-Allow-Headers","Content-Type")
        self.end_headers()

    def do_GET(self):
        p = urlparse(self.path); path = p.path; qs = parse_qs(p.query)

        if path == "/login":
            self.send_html(LOGIN_HTML); return
        if path == "/logout":
            token = get_token_from_request(self)
            if token:
                conn = get_db()
                conn.execute("DELETE FROM sessions WHERE token=?", (token,))
                conn.commit(); conn.close()
            self.send_response(302)
            self.send_header("Location", "/login")
            self.send_header("Set-Cookie", "sj_token=; Path=/; HttpOnly; Max-Age=0")
            self.end_headers(); return

        if path in ("/", "/index.html"):
            if LOCAL_MODE:
                self.send_html(UI); return
            uid = get_user_from_token(get_token_from_request(self))
            if not uid:
                self.send_html(LANDING_HTML); return
            self.send_html(UI); return

        if path == "/api/cases":
            uid = require_auth(self)
            if not uid: return
            conn = get_db()
            rows = conn.execute("SELECT id,title,case_type,jurisdiction,hearing_date,case_number FROM cases WHERE user_id=? AND (is_deleted IS NULL OR is_deleted=0) ORDER BY created_at DESC", (uid,)).fetchall()
            conn.close(); self.send_json([dict(r) for r in rows]); return

        if re.match(r"^/api/cases/\d+$", path):
            uid = require_auth(self)
            if not uid: return
            cid = int(path.split("/")[3])
            conn = get_db()
            case      = conn.execute("SELECT * FROM cases WHERE id=? AND user_id=?", (cid, uid)).fetchone()
            if not case: conn.close(); self.send_json({"error":"not found"},404); return
            parties   = conn.execute("SELECT * FROM parties WHERE case_id=?", (cid,)).fetchall()
            evidence  = conn.execute("SELECT * FROM evidence WHERE case_id=? AND (is_deleted IS NULL OR is_deleted=0) ORDER BY event_date ASC, created_at ASC", (cid,)).fetchall()
            docs      = conn.execute("SELECT id,title,doc_type,created_at FROM documents WHERE case_id=? ORDER BY created_at DESC", (cid,)).fetchall()
            timeline  = conn.execute("SELECT * FROM timeline_events WHERE case_id=? ORDER BY event_date ASC", (cid,)).fetchall()
            financials= conn.execute("SELECT * FROM financials WHERE case_id=? ORDER BY entry_date DESC", (cid,)).fetchall()
            deadlines = conn.execute("SELECT * FROM deadlines WHERE case_id=? ORDER BY due_date ASC", (cid,)).fetchall()
            conn.close()
            self.send_json({
                "case": dict(case), "parties": [dict(r) for r in parties],
                "evidence": [dict(r) for r in evidence], "documents": [dict(r) for r in docs],
                "timeline": [dict(r) for r in timeline], "financials": [dict(r) for r in financials],
                "deadlines": [dict(r) for r in deadlines],
            }); return

        if re.match(r"^/api/documents/\d+$", path):
            uid = require_auth(self)
            if not uid: return
            conn = get_db()
            doc = conn.execute("SELECT * FROM documents WHERE id=?", (int(path.split("/")[3]),)).fetchone()
            conn.close(); self.send_json(dict(doc) if doc else {"error":"not found"}); return

        if re.match(r"^/api/chat/\d+$", path):
            uid = require_auth(self)
            if not uid: return
            cid = int(path.split("/")[3])
            conn = get_db()
            msgs = conn.execute("SELECT role,content,created_at FROM chat_history WHERE case_id=? ORDER BY created_at ASC", (cid,)).fetchall()
            conn.close(); self.send_json([dict(m) for m in msgs]); return

        if re.match(r"^/api/cases/\d+/export$", path):
            uid = require_auth(self)
            if not uid: return
            cid = int(path.split("/")[3])
            filename, data = export_evidence_txt(cid)
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
            self.send_header("Content-Length", len(data))
            self.end_headers(); self.wfile.write(data); return

        if path == "/api/backup":
            uid = require_auth(self)
            if not uid: return
            try:
                with open(DB_PATH, "rb") as f:
                    data = f.read()
                fname = f"synjuris_backup_{date.today().isoformat()}.db"
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Disposition", f'attachment; filename="{fname}"')
                self.send_header("Content-Length", len(data))
                self.end_headers(); self.wfile.write(data)
            except Exception as e:
                self.send_json({"error": str(e)}, 500)
            return

        if path == "/api/backup-full":
            uid = require_auth(self)
            if not uid: return
            import zipfile, io as _io
            try:
                buf = _io.BytesIO()
                with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
                    zf.write(DB_PATH, "synjuris.db")
                    if os.path.isdir(UPLOADS_DIR):
                        for fname_ in os.listdir(UPLOADS_DIR):
                            fp = os.path.join(UPLOADS_DIR, fname_)
                            if os.path.isfile(fp):
                                zf.write(fp, f"uploads/{fname_}")
                data = buf.getvalue()
                fname = f"synjuris_full_backup_{date.today().isoformat()}.zip"
                self.send_response(200)
                self.send_header("Content-Type", "application/zip")
                self.send_header("Content-Disposition", f'attachment; filename="{fname}"')
                self.send_header("Content-Length", len(data))
                self.end_headers(); self.wfile.write(data)
            except Exception as e:
                self.send_json({"error": str(e)}, 500)
            return

        if path == "/api/backup-encrypted-raw":
            uid = require_auth(self)
            if not uid: return
            import zipfile, io as _io, base64 as _b64
            try:
                buf = _io.BytesIO()
                with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
                    zf.write(DB_PATH, "synjuris.db")
                    if os.path.isdir(UPLOADS_DIR):
                        for fname_ in os.listdir(UPLOADS_DIR):
                            fp = os.path.join(UPLOADS_DIR, fname_)
                            if os.path.isfile(fp):
                                zf.write(fp, f"uploads/{fname_}")
                raw_b64 = _b64.b64encode(buf.getvalue()).decode()
                self.send_json({
                    "data": raw_b64,
                    "filename": f"synjuris_backup_{date.today().isoformat()}.sj-backup",
                    "version": VERSION,
                    "created_at": datetime.utcnow().isoformat() + "Z",
                })
            except Exception as e:
                self.send_json({"error": str(e)}, 500)
            return

        # NOTE: /api/restore-backup is intentionally NOT here — it's a POST operation.
        # See do_POST for the /api/restore-backup handler (FIX 3).

        m = re.match(r"^/portal/([A-Za-z0-9_-]{20,})$", path)
        if m:
            token = m.group(1)
            conn = get_db()
            pt = conn.execute(
                "SELECT pt.*, c.title as case_title FROM portal_tokens pt "
                "JOIN cases c ON c.id=pt.case_id "
                "WHERE pt.token=? AND (pt.expires_at IS NULL OR pt.expires_at > datetime('now'))",
                (token,)
            ).fetchone()
            conn.close()
            if not pt:
                self.send_html("<h2 style='font-family:sans-serif;padding:40px'>This portal link has expired or is invalid.</h2>"); return
            self.send_html(build_portal_html(dict(pt), token)); return

        if re.match(r"^/uploads/", path):
            uid = require_auth(self)
            if not uid: return
            filename = os.path.basename(path)
            filepath = os.path.realpath(os.path.join(UPLOADS_DIR, filename))
            uploads_real = os.path.realpath(UPLOADS_DIR)
            if not filepath.startswith(uploads_real + os.sep) and filepath != uploads_real:
                self.send_json({"error": "forbidden"}, 403); return
            if not os.path.exists(filepath):
                self.send_json({"error":"not found"}, 404); return
            ext = filename.rsplit(".", 1)[-1].lower()
            mime = {"pdf":"application/pdf","jpg":"image/jpeg","jpeg":"image/jpeg",
                    "png":"image/png","gif":"image/gif","webp":"image/webp",
                    "heic":"image/heic","mp4":"video/mp4","mov":"video/quicktime",
                    "mp3":"audio/mpeg","m4a":"audio/mp4","txt":"text/plain"}.get(ext, "application/octet-stream")
            with open(filepath, "rb") as f:
                data = f.read()
            self.send_response(200)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", len(data))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers(); self.wfile.write(data); return

        if re.match(r"^/api/cases/\d+/courtroom$", path):
            uid = require_auth(self)
            if not uid: return
            cid = int(path.split("/")[3])
            self.send_html(build_courtroom_html(cid)); return

        if re.match(r"^/api/cases/\d+/state$", path):
            uid = require_auth(self)
            if not uid: return
            self.send_json(compute_case_state(int(path.split("/")[3]))); return

        if re.match(r"^/api/cases/\d+/audit$", path):
            uid = require_auth(self)
            if not uid: return
            cid = int(path.split("/")[3])
            conn = get_db()
            rows = conn.execute("SELECT id,action_type,ai_call_type,state_x,state_y,state_z,trace_hash,created_at FROM audit_log WHERE case_id=? ORDER BY created_at DESC",(cid,)).fetchall()
            conn.close(); self.send_json([dict(r) for r in rows]); return

        if re.match(r"^/api/cases/\d+/guidance$", path):
            uid = require_auth(self)
            if not uid: return
            cid = int(path.split("/")[3])
            self.send_json(compute_guidance(cid)); return

        if re.match(r"^/api/cases/\d+/interpret$", path):
            uid = require_auth(self)
            if not uid: return
            cid = int(path.split("/")[3])
            snap = compute_case_state(cid)
            interp = interpret_case_state(snap)
            self.send_json({**snap, "interpretation": interp}); return

        if path.startswith("/api/verify-citation"):
            uid = require_auth(self)
            if not uid: return
            qs = parse_qs(urlparse(self.path).query)
            cit = urllib.parse.unquote_plus(qs.get("citation",[""])[0]).strip()
            if not cit:
                self.send_json({"error":"citation parameter required"},400); return
            result = verify_citation_courtlistener(cit)
            self.send_json(result); return

        if path == "/api/me":
            uid = require_auth(self)
            if not uid: return
            conn = get_db()
            user = conn.execute("SELECT id,email,tier,created_at FROM users WHERE id=?", (uid,)).fetchone()
            conn.close()
            self.send_json(dict(user) if user else {"error":"not found"}); return

        if path == "/api/conflict-check":
            uid = require_attorney(self)
            if not uid: return
            name_q = (self.path.split("?",1)[1] if "?" in self.path else "")
            query_name = urllib.parse.unquote_plus(
                dict(x.split("=") for x in name_q.split("&") if "=" in x).get("name","")
            ).strip().lower()
            conn = get_db()
            parties = conn.execute(
                "SELECT p.name, p.role, c.title, c.id FROM parties p "
                "JOIN cases c ON c.id=p.case_id "
                "WHERE c.user_id=? AND (c.is_deleted IS NULL OR c.is_deleted=0)",
                (uid,)
            ).fetchall()
            conn.close()
            matches = []
            if query_name:
                for p in parties:
                    if query_name in (p["name"] or "").lower():
                        matches.append({"party_name": p["name"], "role": p["role"],
                                        "case_title": p["title"], "case_id": p["id"]})
            conn = get_db()
            conn.execute(
                "INSERT INTO conflict_checks (user_id, party_names_json, result) VALUES (?,?,?)",
                (uid, json.dumps({"query": query_name}),
                 "conflict" if matches else "clear")
            )
            conn.commit(); conn.close()
            self.send_json({"query": query_name, "matches": matches,
                            "result": "conflict" if matches else "clear"}); return

        if re.match(r"^/api/cases/\d+/time-entries$", path):
            uid = require_attorney(self)
            if not uid: return
            cid = int(path.split("/")[3])
            conn = get_db()
            rows = conn.execute(
                "SELECT * FROM time_entries WHERE case_id=? AND user_id=? ORDER BY created_at DESC",
                (cid, uid)
            ).fetchall()
            conn.close()
            self.send_json([dict(r) for r in rows]); return

        if re.match(r"^/api/cases/\d+/portal-queue$", path):
            uid = require_attorney(self)
            if not uid: return
            cid = int(path.split("/")[3])
            conn = get_db()
            rows = conn.execute(
                "SELECT pe.*, pt.label as portal_label FROM portal_evidence pe "
                "JOIN portal_tokens pt ON pt.id=pe.portal_token_id "
                "WHERE pe.case_id=? AND pe.approved=0 ORDER BY pe.created_at DESC",
                (cid,)
            ).fetchall()
            conn.close()
            self.send_json([dict(r) for r in rows]); return

        if re.match(r"^/api/cases/\d+/redacted-export$", path):
            uid = require_attorney(self)
            if not uid: return
            cid = int(path.split("/")[3])
            self.send_json(build_redacted_export(cid, uid)); return

        if re.match(r"^/api/cases/\d+/actions$", path):
            uid = require_auth(self)
            if not uid: return
            cid = int(path.split("/")[3])
            conn = get_db()
            actions = get_available_actions(cid, conn)
            conn.close()
            self.send_json({"case_id":cid,"actions":actions,"count":len(actions),
                "note":"These are available options. SynJuris provides legal information, not advice."}); return

        if re.match(r"^/api/cases/\d+/readiness$", path):
            uid = require_auth(self)
            if not uid: return
            cid = int(path.split("/")[3])
            conn = get_db()
            scores = compute_doc_readiness(cid, conn)
            conn.close()
            self.send_json(scores); return

        if re.match(r"^/api/jobs/[a-f0-9-]+$", path):
            uid = require_auth(self)
            if not uid: return
            job_id = path.split("/")[3]
            job = _job_cache.get(job_id)
            if not job:
                conn = get_db()
                row = conn.execute(
                    "SELECT state,doc_id,error_msg FROM generation_jobs WHERE job_id=?",
                    (job_id,)
                ).fetchone()
                conn.close()
                if row:
                    r = dict(row) if hasattr(row,"keys") else {"state":row[0],"doc_id":row[1],"error_msg":row[2]}
                    self.send_json({"job_id":job_id,"state":r["state"],"doc_id":r.get("doc_id"),"error":r.get("error_msg")}); return
                self.send_json({"error":"not found"},404); return
            self.send_json({"job_id":job.job_id,"state":job.state,"doc_id":job.doc_id,
                            "doc_type":job.doc_type,"error":job.error}); return

        if re.match(r"^/api/jobs/[a-f0-9-]+/stream$", path):
            uid = require_auth(self)
            if not uid: return
            job_id = path.split("/")[3]
            job_stream_sse(job_id, self); return

        if re.match(r"^/api/jobs/[a-f0-9-]+/replay$", path):
            uid = require_auth(self)
            if not uid: return
            job_id = path.split("/")[3]
            job_stream_sse(job_id, self); return

        if re.match(r"^/api/cases/\d+/dag-verify$", path):
            uid = require_auth(self)
            if not uid: return
            cid = int(path.split("/")[3])
            conn = get_db()
            result = merkle_verify_dag(conn, cid)
            conn.close()
            self.send_json(result); return

        if re.match(r"^/api/cases/\d+/audit-chain-verify$", path):
            uid = require_auth(self)
            if not uid: return
            cid = int(path.split("/")[3])
            result = _audit.verify_chain(cid)
            self.send_json(result); return

        if re.match(r"^/api/cases/\d+/action-log$", path):
            uid = require_auth(self)
            if not uid: return
            cid = int(path.split("/")[3])
            timeline = _audit.get_timeline(cid)
            self.send_json({"case_id":cid,"events":timeline,"count":len(timeline)}); return

        if path == "/api/queue/stats":
            uid = require_auth(self)
            if not uid: return
            with _queue_lock:
                depth = _queue_depth
            self.send_json({"queue_depth":depth,"max_queue":_MAX_QUEUE_DEPTH,
                            "max_workers":_MAX_WORKERS,"max_ai_calls":_MAX_AI_CALLS}); return

        self.send_json({"error":"not found"},404)

    def do_DELETE(self):
        path = urlparse(self.path).path
        b = self.body()  # FIX 6: was missing — b referenced below but never defined
        if re.match(r"^/api/cases/\d+$", path):
            uid = require_auth(self)
            if not uid: return
            cid = int(path.split("/")[3])
            conn = get_db()
            case = conn.execute("SELECT id FROM cases WHERE id=? AND user_id=?", (cid, uid)).fetchone()
            if not case:
                conn.close(); self.send_json({"error":"not found"},404); return
            conn.execute("UPDATE cases SET is_deleted=1, deleted_at=datetime('now') WHERE id=?", (cid,))
            conn.execute("UPDATE evidence SET is_deleted=1, deleted_at=datetime('now') WHERE case_id=?", (cid,))
            conn.execute("UPDATE documents SET is_deleted=1, deleted_at=datetime('now') WHERE case_id=?", (cid,))
            conn.commit(); conn.close()
            self.send_json({"ok": True, "note": "Case moved to trash. Physical files preserved on disk."}); return
        self.send_json({"error":"not found"}, 404)

    def do_POST(self):
        path = urlparse(self.path).path; b = self.body()

        # ── Waitlist ──
        if path == "/api/waitlist":
            email = b.get("email","").strip().lower()
            if email and "@" in email:
                try:
                    conn = get_db()
                    conn.execute(
                        "INSERT INTO waitlist (email, source, created_at) "
                        "VALUES (?,?,CURRENT_TIMESTAMP) ON CONFLICT(email) DO NOTHING",
                        (email, b.get("source","landing_page"))
                    )
                    conn.commit(); conn.close()
                except Exception:
                    pass
            self.send_json({"ok": True}); return

        # ── Portal evidence submission (no main auth — token IS the credential) ──
        # FIX 8: moved here from do_GET where it incorrectly lived
        if path == "/api/portal/submit":
            token = b.get("token","")
            conn = get_db()
            pt = conn.execute(
                "SELECT * FROM portal_tokens WHERE token=? AND (expires_at IS NULL OR expires_at > datetime('now'))",
                (token,)
            ).fetchone()
            if not pt:
                conn.close(); self.send_json({"error":"invalid token"},403); return
            content = (b.get("content","") or "")[:50000]
            conn.execute(
                "INSERT INTO portal_evidence (case_id,portal_token_id,content,source,event_date,category) "
                "VALUES (?,?,?,?,?,?)",
                (pt["case_id"], pt["id"], content,
                 b.get("source","client"), b.get("event_date",""),
                 b.get("category","Document"))
            )
            conn.commit(); conn.close()
            self.send_json({"ok":True,"message":"Submitted for attorney review."}); return

        # ── Restore from encrypted backup ─────────────────────────────────────
        # FIX 3: moved here from do_GET where it incorrectly lived
        if path == "/api/restore-backup":
            uid = require_auth(self)
            if not uid: return
            if not b.get("confirmed"):
                self.send_json({"error":"Send confirmed:true to proceed. This replaces all local data."}, 400); return
            import zipfile, io as _io, base64 as _b64
            try:
                raw = _b64.b64decode(b.get("data",""))
                buf = _io.BytesIO(raw)
                with zipfile.ZipFile(buf, "r") as zf:
                    names = zf.namelist()
                    if "synjuris.db" not in names:
                        self.send_json({"error":"Invalid backup: synjuris.db not found in archive"}, 400); return
                    tmp_db = DB_PATH + ".restore_tmp"
                    with open(tmp_db, "wb") as f_out:
                        f_out.write(zf.read("synjuris.db"))
                    os.replace(tmp_db, DB_PATH)
                    for name in names:
                        if name.startswith("uploads/") and not name.endswith("/"):
                            fname_ = os.path.basename(name)
                            dest = os.path.join(UPLOADS_DIR, fname_)
                            os.makedirs(UPLOADS_DIR, exist_ok=True)
                            with open(dest, "wb") as f_out:
                                f_out.write(zf.read(name))
                self.send_json({"ok": True, "restored_files": len(names)}); return
            except Exception as e:
                self.send_json({"error": f"Restore failed: {e}"}, 500)
            return

        # ── Signup ──
        if path == "/api/signup":
            email = (b.get("email") or "").strip().lower()
            pw = b.get("password","")
            if not email or not pw:
                self.send_json({"error":"Email and password required"},400); return
            if len(pw) < 8:
                self.send_json({"error":"Password must be at least 8 characters"},400); return
            conn = get_db()
            existing = conn.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
            if existing:
                conn.close(); self.send_json({"error":"An account with that email already exists"},400); return
            ph = hash_password(pw)
            c = conn.execute("INSERT INTO users (email,password_hash) VALUES (?,?)", (email, ph))
            uid = c.lastrowid
            conn.commit(); conn.close()
            token = create_session(uid)
            self.send_response(200)
            self.send_header("Content-Type","application/json")
            self.send_header("Set-Cookie", f"sj_token={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=2592000")
            b2 = json.dumps({"ok":True}).encode()
            self.send_header("Content-Length", len(b2))
            self.end_headers(); self.wfile.write(b2); return

        # ── Login ──
        if path == "/api/login":
            email = (b.get("email") or "").strip().lower()
            pw = b.get("password","")
            if not _check_rate_limit(email):
                self.send_json({"error": "Too many login attempts. Please wait a few minutes."}, 429); return
            conn = get_db()
            user = conn.execute("SELECT id,password_hash FROM users WHERE email=?", (email,)).fetchone()
            conn.close()
            ok = bool(user) and verify_password(pw, user["password_hash"])
            _record_auth_attempt(email, ok)
            if not ok:
                self.send_json({"error":"Invalid email or password"},401); return
            token = create_session(user["id"])
            self.send_response(200)
            self.send_header("Content-Type","application/json")
            self.send_header("Set-Cookie", f"sj_token={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=2592000")
            b2 = json.dumps({"ok":True}).encode()
            self.send_header("Content-Length", len(b2))
            self.end_headers(); self.wfile.write(b2); return

        # ── Create case ──
        if path == "/api/cases":
            uid = require_auth(self)
            if not uid: return
            conn = get_db()
            try:
                conn.execute("BEGIN")
                c = conn.execute(
                    "INSERT INTO cases (title,case_type,jurisdiction,court_name,case_number,filing_deadline,hearing_date,goals,notes,user_id) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (b.get("title"),b.get("case_type"),b.get("jurisdiction"),b.get("court_name"),
                     b.get("case_number"),b.get("filing_deadline"),b.get("hearing_date"),b.get("goals"),b.get("notes",""),uid)
                )
                cid = c.lastrowid
                for p in b.get("parties",[]):
                    conn.execute("INSERT INTO parties (case_id,name,role,contact,attorney) VALUES (?,?,?,?,?)",
                        (cid,p.get("name"),p.get("role"),p.get("contact",""),p.get("attorney","")))
                if b.get("hearing_date"):
                    conn.execute("INSERT INTO deadlines (case_id,due_date,title) VALUES (?,?,?)",
                        (cid, b["hearing_date"], "Court hearing"))
                conn.commit()
            except Exception as e:
                conn.rollback(); conn.close()
                self.send_json({"error": f"Failed to create case: {e}"}, 500); return
            conn.close(); self.send_json({"id":cid}); return

        # ── Update case ──
        if re.match(r"^/api/cases/\d+$", path):
            uid = require_auth(self)
            if not uid: return
            cid = int(path.split("/")[3])
            _CASE_FIELDS = {
                "title": "title", "case_type": "case_type", "jurisdiction": "jurisdiction",
                "court_name": "court_name", "case_number": "case_number",
                "filing_deadline": "filing_deadline", "hearing_date": "hearing_date",
                "goals": "goals", "notes": "notes",
            }
            conn = get_db()
            updates = [(col, b[key]) for key, col in _CASE_FIELDS.items() if key in b]
            if updates:
                cols, vals = zip(*updates)
                sets = ", ".join(f"{c}=?" for c in cols)
                conn.execute(f"UPDATE cases SET {sets} WHERE id=? AND user_id=?", list(vals) + [cid, uid])
            conn.commit(); conn.close(); self.send_json({"ok":True}); return

        # ── Evidence: add manual ──
        if path == "/api/evidence":
            uid = require_auth(self)
            if not uid: return
            conn = get_db()
            cid = b["case_id"]
            content = b.get("content","")
            if len(content.encode("utf-8")) > 50_000:
                conn.close()
                self.send_json({"error": "Content exceeds 50 KB limit. Summarize or split into multiple entries."}, 400); return
            tags = scan_patterns(content)
            cat  = b.get("category") or (tags[0][0] if tags else "General")
            en   = assign_exhibit_number(conn, cid) if b.get("confirmed",1) else None
            c = conn.execute(
                "INSERT INTO evidence (case_id,exhibit_number,content,source,event_date,category,confirmed,notes) VALUES (?,?,?,?,?,?,?,?)",
                (cid,en,content,b.get("source"),b.get("event_date"),cat,b.get("confirmed",1),b.get("notes",""))
            )
            conn.commit(); conn.close(); self.send_json({"id":c.lastrowid,"tags":[t[0] for t in tags]}); return

        # ── Evidence: confirm (also adds to Merkle DAG) ──
        if path == "/api/evidence/confirm":
            uid = require_auth(self)
            if not uid: return
            conn = get_db()
            eid  = b["id"]
            ev_row = conn.execute("SELECT * FROM evidence WHERE id=?", (eid,)).fetchone()
            if not ev_row:
                conn.close(); self.send_json({"error":"not found"},404); return
            cid = ev_row["case_id"] if hasattr(ev_row,"keys") else ev_row[1]
            en  = assign_exhibit_number(conn, cid)
            conn.execute("UPDATE evidence SET confirmed=1, exhibit_number=? WHERE id=?", (en, eid))
            conn.commit()
            node_hash = "n/a"
            try:
                ev_dict = dict(ev_row) if hasattr(ev_row,"keys") else {
                    "id":ev_row[0],"case_id":ev_row[1],"content":ev_row[3],
                    "source":ev_row[4],"event_date":ev_row[5],"category":ev_row[6],"confirmed":1}
                node_hash = merkle_add_exhibit(conn, cid, {**ev_dict,"confirmed":1})
            except Exception:
                pass
            conn.close()
            _audit.log("evidence_confirmed", case_id=cid, user_id=uid,
                       metadata={"exhibit_id":eid,"exhibit_number":en})
            self.send_json({"ok":True,"exhibit_number":en,"node_hash":node_hash[:32]}); return

        # ── Evidence: soft delete ──
        if path == "/api/evidence/delete":
            uid = require_auth(self)
            if not uid: return
            eid = b.get("id")
            conn = get_db()
            ev = conn.execute(
                "SELECT e.id FROM evidence e JOIN cases c ON c.id=e.case_id "
                "WHERE e.id=? AND c.user_id=?", (eid, uid)
            ).fetchone()
            if not ev:
                conn.close(); self.send_json({"error":"not found"}, 404); return
            conn.execute(
                "UPDATE evidence SET is_deleted=1, deleted_at=datetime('now') WHERE id=?", (eid,)
            )
            conn.commit(); conn.close(); self.send_json({"ok":True}); return

        # ── Import XML ──
        if path == "/api/import-xml":
            cid = b.get("case_id"); xml_text = b.get("xml","")
            target = re.sub(r"\D","",b.get("target_number",""))
            def number_matches(addr):
                if not target: return True
                parts = [re.sub(r"\D","",p) for p in addr.split("~")]
                return any(p.endswith(target) or target.endswith(p) for p in parts if p)
            try:
                if isinstance(xml_text, str):
                    xml_text = xml_text.lstrip('\ufeff').strip()
                xml_text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', xml_text)
                root = ET.fromstring(xml_text)
                msgs = []
                for msg in root.findall(".//sms"):
                    text = msg.get("body","").strip()
                    addr = msg.get("address","")
                    dms = msg.get("date")
                    contact = msg.get("contact_name","")
                    if not text: continue
                    if not number_matches(addr): continue
                    dt = None
                    if dms:
                        try: dt = datetime.fromtimestamp(int(dms)/1000).strftime("%Y-%m-%d %H:%M:%S")
                        except: pass
                    source_label = f"{contact} ({addr})" if contact and contact != addr else addr
                    tags = scan_patterns(text)
                    msgs.append((cid, text, source_label, dt, tags[0][0] if tags else "Message", bool(tags)))
                for msg in root.findall(".//mms"):
                    addr = msg.get("address","")
                    dms = msg.get("date")
                    contact = msg.get("contact_name","")
                    if not number_matches(addr): continue
                    dt = None
                    if dms:
                        try: dt = datetime.fromtimestamp(int(dms)/1000).strftime("%Y-%m-%d %H:%M:%S")
                        except: pass
                    parts_text = []
                    for part in msg.findall(".//part"):
                        ct = part.get("ct","")
                        if "text" in ct:
                            part_data = part.get("text","").strip()
                            if part_data and part_data != "null":
                                parts_text.append(part_data)
                    body_attr = msg.get("body","").strip()
                    if body_attr and body_attr != "null":
                        parts_text.append(body_attr)
                    text = " | ".join(parts_text).strip()
                    if not text: continue
                    source_label = f"{contact} ({addr})" if contact and contact != addr else addr
                    tags = scan_patterns(text)
                    msgs.append((cid, text, source_label, dt, tags[0][0] if tags else "Message (MMS)", bool(tags)))
                conn = get_db()
                flagged = 0
                try:
                    conn.execute("BEGIN")
                    for cid_,content,source,event_date,category,has_tag in msgs:
                        conn.execute("INSERT INTO evidence (case_id,content,source,event_date,category,confirmed) VALUES (?,?,?,?,?,0)",
                            (cid_,content,source,event_date,category))
                        if has_tag: flagged += 1
                    conn.commit()
                except Exception as ex:
                    conn.rollback(); conn.close()
                    self.send_json({"error": f"Import failed mid-way, rolled back: {ex}"}, 500); return
                conn.close()
                self.send_json({"imported":len(msgs),"flagged":flagged}); return
            except ET.ParseError as e:
                self.send_json({"error": f"XML parse error: {str(e)}. Make sure the file is a valid SMS Backup & Restore XML export."}, 400); return
            except Exception as e:
                self.send_json({"error":str(e)},400); return

        # ── Timeline event ──
        if path == "/api/timeline":
            conn = get_db()
            c = conn.execute(
                "INSERT INTO timeline_events (case_id,event_date,title,description,category,importance) VALUES (?,?,?,?,?,?)",
                (b["case_id"],b.get("event_date"),b.get("title"),b.get("description"),b.get("category","Event"),b.get("importance","normal"))
            )
            conn.commit(); conn.close(); self.send_json({"id":c.lastrowid}); return

        if re.match(r"^/api/timeline/\d+$", path):
            conn = get_db()
            conn.execute("DELETE FROM timeline_events WHERE id=?", (int(path.split("/")[3]),))
            conn.commit(); conn.close(); self.send_json({"ok":True}); return

        # ── Financial entry ──
        if path == "/api/financials":
            conn = get_db()
            c = conn.execute(
                "INSERT INTO financials (case_id,entry_date,description,amount,category,direction) VALUES (?,?,?,?,?,?)",
                (b["case_id"],b.get("entry_date"),b.get("description"),b.get("amount",0),b.get("category"),b.get("direction","expense"))
            )
            conn.commit(); conn.close(); self.send_json({"id":c.lastrowid}); return

        if re.match(r"^/api/financials/\d+$", path):
            conn = get_db()
            conn.execute("DELETE FROM financials WHERE id=?", (int(path.split("/")[3]),))
            conn.commit(); conn.close(); self.send_json({"ok":True}); return

        # ── Deadlines ──
        if path == "/api/deadlines":
            conn = get_db()
            c = conn.execute(
                "INSERT INTO deadlines (case_id,due_date,title,description) VALUES (?,?,?,?)",
                (b["case_id"],b.get("due_date"),b.get("title"),b.get("description",""))
            )
            conn.commit(); conn.close(); self.send_json({"id":c.lastrowid}); return

        if re.match(r"^/api/deadlines/\d+/complete$", path):
            conn = get_db()
            conn.execute("UPDATE deadlines SET completed=? WHERE id=?", (b.get("completed",1), int(path.split("/")[3])))
            conn.commit(); conn.close(); self.send_json({"ok":True}); return

        if re.match(r"^/api/deadlines/\d+$", path):
            conn = get_db()
            conn.execute("DELETE FROM deadlines WHERE id=?", (int(path.split("/")[3]),))
            conn.commit(); conn.close(); self.send_json({"ok":True}); return

        # ── Upload evidence file ──
        if path == "/api/upload-file":
            import base64, uuid
            cid           = b.get("case_id")
            filename      = b.get("filename", "file")
            data_b64      = b.get("data", "")
            event_date    = b.get("event_date", "")
            notes         = b.get("notes", "")
            category      = b.get("category", "Document")
            try:
                file_bytes = base64.b64decode(data_b64)
            except Exception as e:
                self.send_json({"error": f"Bad file data: {e}"}, 400); return
            if len(file_bytes) > 50 * 1024 * 1024:
                self.send_json({"error": "File exceeds 50 MB limit."}, 400); return
            ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else "bin"
            ALLOWED_EXT = {"pdf","jpg","jpeg","png","gif","webp","heic","mp4","mov","mp3","m4a","txt"}
            if ext not in ALLOWED_EXT:
                self.send_json({"error": f"File type '.{ext}' is not allowed."}, 400); return
            safe_name = f"{uuid.uuid4().hex}.{ext}"
            dest = os.path.join(UPLOADS_DIR, safe_name)
            with open(dest, "wb") as f_out:
                f_out.write(file_bytes)
            conn = get_db()
            en = assign_exhibit_number(conn, cid)
            c = conn.execute(
                "INSERT INTO evidence (case_id,exhibit_number,content,source,event_date,category,confirmed,notes,file_path,file_type,original_filename) VALUES (?,?,?,?,?,?,1,?,?,?,?)",
                (cid, en, f"[Attached file: {filename}]", filename, event_date, category, notes, f"/uploads/{safe_name}", ext, filename)
            )
            conn.commit(); conn.close()
            self.send_json({"id": c.lastrowid, "file_path": f"/uploads/{safe_name}"}); return

        # ── AI Chat ──
        if path == "/api/chat":
            cid = b.get("case_id"); msg = b.get("message","")
            conn = get_db()
            history = conn.execute(
                "SELECT role,content FROM chat_history WHERE case_id=? ORDER BY created_at ASC",
                (cid,)
            ).fetchall()
            MAX_HISTORY = 40
            if len(history) > MAX_HISTORY:
                history = history[-MAX_HISTORY:]
            conn.close()
            system, _am = build_case_system(cid, user_query=msg)
            messages = [{"role":r["role"],"content":r["content"]} for r in history]
            messages.append({"role":"user","content":msg})
            use_model = "claude-haiku-4-5-20251001" if len(msg) < 120 and not any(
                kw in msg.lower() for kw in ["draft","motion","generate","write","document","hearing prep"]
            ) else "claude-sonnet-4-20250514"
            reply = call_claude(messages, system, max_tokens=2500, model=use_model)
            reply = reply + "\n\n---\n*SynJuris provides legal information and organizational tools only — not legal advice. This output does not constitute legal counsel and does not create an attorney-client relationship. Always consult a licensed attorney before filing any document with a court. SynJuris is not a law firm.*"
            if _am: log_audit_event(cid,"CHAT","chat",_am["snapshot"],_am["prompt_inputs"],_am["snapshot"]["hash"])
            conn = get_db()
            conn.execute("INSERT INTO chat_history (case_id,role,content) VALUES (?,?,?)", (cid,"user",msg))
            conn.execute("INSERT INTO chat_history (case_id,role,content) VALUES (?,?,?)", (cid,"assistant",reply))
            conn.commit(); conn.close()
            self.send_json({"reply":reply}); return

        # ── Generate document ──
        if path == "/api/generate-doc":
            cid = b.get("case_id"); dtype = b.get("doc_type"); instr = b.get("instructions","")
            conn = get_db()
            case     = conn.execute("SELECT * FROM cases WHERE id=?", (cid,)).fetchone()
            parties  = conn.execute("SELECT * FROM parties WHERE case_id=?", (cid,)).fetchall()
            evidence = conn.execute("SELECT exhibit_number,content,category,event_date FROM evidence WHERE case_id=? AND confirmed=1 ORDER BY event_date ASC", (cid,)).fetchall()
            conn.close()
            c = dict(case) if case else {}
            ev_lines = "\n".join([f"[{e['exhibit_number']}] [{e['event_date'] or 'undated'}] ({e['category']}): {(e['content'] or '')[:300]}" for e in evidence[:25]])
            party_lines = "\n".join([f"  {p['role']}: {p['name']}" for p in parties])
            jur_block = jurisdiction_statute_block(c.get('jurisdiction',''))
            prompt = f"""Draft a complete {dtype} for a pro se litigant.

CASE DETAILS
  Title: {c.get('title')}
  Type: {c.get('case_type')}
  {jur_block}
  Court: {c.get('court_name') or '[COURT NAME]'}
  Case number: {c.get('case_number') or '[CASE NUMBER]'}

PARTIES
{party_lines or '  [PARTIES NOT ENTERED]'}

CONFIRMED EVIDENCE
{ev_lines or '  None confirmed.'}

SPECIAL INSTRUCTIONS
{instr or 'None.'}

FORMAT REQUIREMENTS:
- Use proper court document format with caption, title, body, and signature block
- Use [BRACKET PLACEHOLDERS] for any information not provided above
- Write in clear, plain English
- Include specific references to evidence by exhibit number where relevant
- Add a certificate of service at the end
- This is for a pro se filer — make it professional but accessible"""
            content = call_claude([{"role":"user","content":prompt}], max_tokens=3000)
            citations = verify_citations_in_text(content)
            conn = get_db()
            c2 = conn.execute("INSERT INTO documents (case_id,title,doc_type,content) VALUES (?,?,?,?)",
                (cid, f"{dtype} — {datetime.now().strftime('%b %d %Y')}", dtype, content))
            conn.commit(); conn.close()
            self.send_json({"id":c2.lastrowid,"content":content,"citations":citations}); return

        # ── Generate hearing prep ──
        if path == "/api/hearing-prep":
            cid = b.get("case_id")
            system, _am = build_case_system(cid)
            prompt = """Generate a comprehensive hearing preparation and organization guide for this pro se litigant. This is an organizational tool to help them understand the process and prepare their materials — not legal advice. Include:

1. OPENING STATEMENT DRAFT (60 seconds, clear and factual)
2. KEY POINTS TO MAKE (numbered, in order of importance)
3. YOUR EVIDENCE SUMMARY (how to introduce each exhibit)
4. ANTICIPATED ARGUMENTS FROM OTHER SIDE (and how to respond)
5. QUESTIONS TO ASK (if cross-examining the other party or witnesses)
6. WHAT NOT TO SAY (common pro se mistakes to avoid)
7. COURTROOM ETIQUETTE (how to address the judge, when to stand, etc.)
8. WHAT TO BRING (complete checklist)
9. IF THE JUDGE ASKS YOU... (common judicial questions and suggested answers)
10. EMERGENCY FALLBACK (if things go badly, what to say/do)

Be specific to THIS case and THIS jurisdiction. Use plain English throughout."""
            reply = call_claude([{"role":"user","content":prompt}], system, max_tokens=3000)
            reply = reply + "\n\n---\n*SynJuris provides legal information and organizational tools only — not legal advice. This output does not constitute legal counsel and does not create an attorney-client relationship. Always consult a licensed attorney before filing any document with a court. SynJuris is not a law firm.*"
            if _am: log_audit_event(cid,"HEARING_PREP","hearing-prep",_am["snapshot"],_am["prompt_inputs"],_am["snapshot"]["hash"])
            conn = get_db()
            conn.execute("INSERT INTO documents (case_id,title,doc_type,content) VALUES (?,?,?,?)",
                (cid, f"Hearing Prep Guide — {datetime.now().strftime('%b %d %Y')}", "Hearing Prep Guide", reply))
            conn.commit(); conn.close()
            self.send_json({"content":reply}); return

        # ── Evidence → Argument Mapper ──
        if path == "/api/build-arguments":
            cid = b.get("case_id")
            conn = get_db()
            case     = conn.execute("SELECT * FROM cases WHERE id=?", (cid,)).fetchone()
            evidence = conn.execute(
                "SELECT exhibit_number,content,category,event_date FROM evidence WHERE case_id=? AND confirmed=1 ORDER BY event_date ASC",
                (cid,)
            ).fetchall()
            conn.close()
            if not case or not evidence:
                self.send_json({"error":"No confirmed evidence to build arguments from."}); return
            c = dict(case)
            jur_block = jurisdiction_statute_block(c.get("jurisdiction",""))
            ev_lines = "\n".join([
                f"  [{e['exhibit_number'] or 'unnum'}] [{e['event_date'] or 'undated'}] ({e['category']}): {(e['content'] or '')[:250]}"
                for e in evidence
            ])
            prompt = f"""You are a legal preparation assistant helping a pro se litigant organize their evidence by legal issue so they can clearly present their situation to a court.

CASE: {c.get("title")} | Type: {c.get("case_type")} | {jur_block}

CONFIRMED EVIDENCE:
{ev_lines}

Your task: Organize this evidence by legal issue, grouping related exhibits together and identifying what each group of evidence documents. You are helping the person understand what their evidence shows — not advising them on legal strategy.

Respond in this EXACT JSON format (no markdown, no preamble, valid JSON only):
{{
  "arguments": [
    {{
      "title": "Short issue title (e.g. Repeated Interference with Parenting Time)",
      "legal_basis": "The relevant law or statute that may apply to this issue",
      "strength": "strong|moderate|weak",
      "exhibits": ["Exhibit 1", "Exhibit 3"],
      "argument": "2-3 sentence plain-English summary of what this evidence shows",
      "anticipate": "One sentence: a possible counter-claim the other side might raise",
      "counter": "One sentence: how you might address that counter-claim"
    }}
  ],
  "strongest_issue": "Title of the issue best supported by your evidence",
  "case_theme": "One sentence that captures what your evidence collectively shows",
  "evidence_gaps": ["Any documentation that appears to be missing that would help clarify the situation"]
}}

Organize as many issues as the evidence supports. Be specific about which exhibits relate to each issue. Remember: you are organizing facts, not providing legal advice."""

            result = call_claude([{"role":"user","content":prompt}], max_tokens=3000)
            try:
                import json as _json
                cleaned = result.strip()
                if cleaned.startswith("```"):
                    cleaned = "\n".join(cleaned.split("\n")[1:-1])
                parsed = _json.loads(cleaned)
                self.send_json(parsed); return
            except Exception:
                self.send_json({"raw": result}); return

        # ── Timeline Contradiction Detector ──
        if path == "/api/detect-contradictions":
            cid = b.get("case_id")
            conn = get_db()
            case     = conn.execute("SELECT * FROM cases WHERE id=?", (cid,)).fetchone()
            evidence = conn.execute(
                "SELECT exhibit_number,content,category,event_date FROM evidence WHERE case_id=? AND confirmed=1 ORDER BY event_date ASC",
                (cid,)
            ).fetchall()
            timeline = conn.execute(
                "SELECT event_date,title,description FROM timeline_events WHERE case_id=? ORDER BY event_date ASC",
                (cid,)
            ).fetchall()
            conn.close()
            if not case: self.send_json({"error":"Case not found"}); return
            c = dict(case)
            ev_lines = "\n".join([
                f"  [{e['exhibit_number'] or 'unnum'}] [{e['event_date'] or 'undated'}] ({e['category']}): {(e['content'] or '')[:200]}"
                for e in evidence
            ])
            tl_lines = "\n".join([
                f"  [{t['event_date'] or 'undated'}]: {t['title']} — {(t['description'] or '')[:150]}"
                for t in timeline
            ])
            prompt = f"""Analyze this case timeline and evidence for a pro se litigant.

CASE: {c.get("title")} | {c.get("case_type")} | {c.get("jurisdiction")}

EVIDENCE:
{ev_lines or "  None"}

TIMELINE EVENTS:
{tl_lines or "  None"}

Respond in this EXACT JSON format (valid JSON only, no markdown):
{{
  "contradictions": [
    {{
      "type": "gap|overlap|inconsistency|missing_response",
      "severity": "high|medium|low",
      "description": "Plain English description of the issue",
      "dates_involved": ["2024-03-01", "2024-03-15"],
      "exhibits_involved": ["Exhibit 2", "Exhibit 4"],
      "recommendation": "What the litigant should do about this"
    }}
  ],
  "timeline_gaps": [
    {{
      "start_date": "2024-01-01",
      "end_date": "2024-02-15",
      "description": "Period with no documented evidence or events"
    }}
  ],
  "strongest_sequence": "Plain English description of the most compelling chronological pattern in the evidence",
  "credibility_notes": "Any observations about consistency or inconsistency across the evidence set"
}}

Be specific. Reference actual exhibit numbers and dates. If there are no contradictions, return an empty array for contradictions."""

            result = call_claude([{"role":"user","content":prompt}], max_tokens=3000)
            try:
                cleaned = result.strip()
                if cleaned.startswith("```"):
                    cleaned = "\n".join(cleaned.split("\n")[1:-1])
                parsed = json.loads(cleaned)
                self.send_json(parsed); return
            except Exception:
                self.send_json({"raw": result}); return

        # ── Adversarial Analysis ──
        if path == "/api/adversarial-analysis":
            cid = b.get("case_id")
            conn = get_db()
            case     = conn.execute("SELECT * FROM cases WHERE id=?", (cid,)).fetchone()
            evidence = conn.execute(
                "SELECT exhibit_number,content,category,event_date FROM evidence "
                "WHERE case_id=? AND confirmed=1 ORDER BY event_date ASC",
                (cid,)
            ).fetchall()
            conn.close()
            if not case: self.send_json({"error":"Case not found"}); return
            c = dict(case)
            jur_block = jurisdiction_statute_block(c.get("jurisdiction",""))
            ev_lines = "\n".join([
                f"  [{e['exhibit_number'] or 'unnum'}] [{e['event_date'] or 'undated'}] ({e['category']}): {(e['content'] or '')[:200]}"
                for e in evidence
            ])
            prompt = f"""You are helping a pro se litigant understand how opposing counsel might frame the evidence against them, so they can prepare responses.

CASE: {c.get("title")} | {c.get("case_type")} | {jur_block}
Goals: {c.get("goals") or "not stated"}

EVIDENCE:
{ev_lines or "  None confirmed."}

Respond in this EXACT JSON format (valid JSON only):
{{
  "opposing_narrative": "2-3 sentence summary of how the other side will likely frame this case",
  "attacks": [
    {{
      "target": "What they will attack (e.g. 'Exhibit 3 credibility', 'Parenting fitness')",
      "argument": "How they will frame this attack",
      "severity": "high|medium|low",
      "response": "Suggested plain-English response or rebuttal",
      "supporting_exhibits": ["Exhibit 1"]
    }}
  ],
  "their_strongest_point": "The single most dangerous argument opposing counsel can make",
  "your_best_counter": "The single most effective response to that point given your evidence",
  "evidence_they_will_use_against_you": "Description of how your own evidence might be reframed against you",
  "recommended_focus": "What this litigant should focus on most to counter the opposition"
}}"""

            result = call_claude([{"role":"user","content":prompt}], max_tokens=3000)
            try:
                cleaned = result.strip()
                if cleaned.startswith("```"):
                    cleaned = "\n".join(cleaned.split("\n")[1:-1])
                parsed = json.loads(cleaned)
                self.send_json(parsed); return
            except Exception:
                self.send_json({"raw": result}); return

        # ── Case Summary (one-sentence theory) ──
        if path == "/api/case-summary":
            cid = b.get("case_id")
            system, _am = build_case_system(cid)
            prompt = """Write a one-paragraph case summary for this pro se litigant that they can use to quickly explain their situation to a judge, mediator, or legal aid attorney. It should include:
1. Who the parties are and what their relationship is
2. The core dispute or problem
3. What evidence documents the problem
4. What the litigant is asking the court to do

Write in plain English. Be factual and specific. Do not editorialize. Keep it under 150 words."""
            reply = call_claude([{"role":"user","content":prompt}], system, max_tokens=500)
            conn = get_db()
            conn.execute(
                "INSERT INTO documents (case_id,title,doc_type,content) VALUES (?,?,?,?)",
                (cid, f"Case Summary — {datetime.now().strftime('%b %d %Y')}", "Case Summary", reply)
            )
            conn.commit(); conn.close()
            self.send_json({"content": reply}); return

        # ── Async document generation (job-based) ──
        if path == "/api/generate-doc-async":
            uid = require_auth(self)
            if not uid: return
            cid   = b.get("case_id")
            dtype = b.get("doc_type")
            instr = b.get("instructions","")
            force = b.get("force", False)
            if not cid or not dtype:
                self.send_json({"error":"case_id and doc_type required"}, 400); return
            conn = get_db()
            job_id = job_submit("doc_generate", cid, dtype, conn, instructions=instr, force=force)
            conn.close()
            if job_id == "__QUEUE_FULL__":
                self.send_json({"error":"Server queue is full. Please try again in a moment."}, 503); return
            snap = compute_case_state(cid)
            _audit.log("doc_generation_started", case_id=cid, user_id=uid,
                       doc_type=dtype, job_id=job_id,
                       case_state_hash=snap["hash"],
                       evidence_count=snap["inputs"]["evidence_count"],
                       metadata={"instructions": instr[:200] if instr else ""})
            self.send_json({"job_id": job_id, "status": "queued"}); return

        # ── Parties: add / update / delete ──
        if path == "/api/parties":
            uid = require_auth(self)
            if not uid: return
            conn = get_db()
            c = conn.execute(
                "INSERT INTO parties (case_id,name,role,contact,attorney,notes) VALUES (?,?,?,?,?,?)",
                (b["case_id"], b.get("name"), b.get("role"), b.get("contact",""),
                 b.get("attorney",""), b.get("notes",""))
            )
            conn.commit(); conn.close()
            self.send_json({"id": c.lastrowid}); return

        if re.match(r"^/api/parties/\d+$", path):
            uid = require_auth(self)
            if not uid: return
            pid = int(path.split("/")[3])
            conn = get_db()
            conn.execute("DELETE FROM parties WHERE id=?", (pid,))
            conn.commit(); conn.close()
            self.send_json({"ok": True}); return

        # ── Documents: soft delete / restore ──
        if re.match(r"^/api/documents/\d+/delete$", path):
            uid = require_auth(self)
            if not uid: return
            did = int(path.split("/")[3])
            conn = get_db()
            conn.execute(
                "UPDATE documents SET is_deleted=1, deleted_at=datetime('now') WHERE id=?", (did,)
            )
            conn.commit(); conn.close()
            self.send_json({"ok": True}); return

        if re.match(r"^/api/documents/\d+/restore$", path):
            uid = require_auth(self)
            if not uid: return
            did = int(path.split("/")[3])
            conn = get_db()
            conn.execute(
                "UPDATE documents SET is_deleted=0, deleted_at=NULL WHERE id=?", (did,)
            )
            conn.commit(); conn.close()
            self.send_json({"ok": True}); return

        # ── Attorney: create portal token ──
        if path == "/api/portal/create":
            uid = require_attorney(self)
            if not uid: return
            cid   = b.get("case_id")
            label = b.get("label","Client Portal")
            days  = int(b.get("expires_days", 30))
            token = secrets.token_urlsafe(20)
            conn  = get_db()
            conn.execute(
                "INSERT INTO portal_tokens (token,case_id,attorney_user_id,label,expires_at) "
                "VALUES (?,?,?,?,datetime('now',?))",
                (token, cid, uid, label, f"+{days} days")
            )
            conn.commit(); conn.close()
            self.send_json({"token": token, "url": f"/portal/{token}"}); return

        # ── Attorney: approve portal evidence → promote to main evidence ──
        if re.match(r"^/api/portal-evidence/\d+/approve$", path):
            uid = require_attorney(self)
            if not uid: return
            peid = int(path.split("/")[3])
            conn = get_db()
            pe = conn.execute("SELECT * FROM portal_evidence WHERE id=?", (peid,)).fetchone()
            if not pe:
                conn.close(); self.send_json({"error":"not found"}, 404); return
            pe = dict(pe)
            en = assign_exhibit_number(conn, pe["case_id"])
            c = conn.execute(
                "INSERT INTO evidence (case_id,exhibit_number,content,source,event_date,category,confirmed,notes) "
                "VALUES (?,?,?,?,?,?,1,?)",
                (pe["case_id"], en, pe["content"], pe.get("source","client portal"),
                 pe.get("event_date",""), pe.get("category","Document"),
                 pe.get("attorney_note","Submitted via client portal"))
            )
            conn.execute("UPDATE portal_evidence SET approved=1 WHERE id=?", (peid,))
            conn.commit(); conn.close()
            self.send_json({"ok":True,"evidence_id":c.lastrowid,"exhibit_number":en}); return

        # ── Attorney: time entry ──
        if path == "/api/time-entries":
            uid = require_attorney(self)
            if not uid: return
            conn = get_db()
            c = conn.execute(
                "INSERT INTO time_entries (case_id,user_id,description,hours,billable,source) VALUES (?,?,?,?,?,?)",
                (b.get("case_id"), uid, b.get("description",""), b.get("hours",0),
                 1 if b.get("billable",True) else 0, b.get("source","manual"))
            )
            conn.commit(); conn.close()
            self.send_json({"id":c.lastrowid}); return

        # ── Audit verify ──
        if path == "/api/audit/verify":
            uid = require_auth(self)
            if not uid: return
            aid = b.get("audit_id")
            self.send_json(verify_audit_entry(aid)); return

        # ── Speculative (pre-generate) document ──
        if path == "/api/speculative-generate":
            uid = require_auth(self)
            if not uid: return
            cid   = b.get("case_id")
            dtype = b.get("doc_type")
            if not cid or not dtype:
                self.send_json({"error":"case_id and doc_type required"}, 400); return
            conn = get_db()
            scores = compute_doc_readiness(cid, conn)
            target = next((s for s in scores if s["doc_type"] == dtype), None)
            if not target or not target.get("speculative"):
                conn.close()
                self.send_json({"error":f"'{dtype}' readiness is below threshold for pre-generation."},400); return
            job_id = job_submit("speculative", cid, dtype, conn, force=False)
            conn.close()
            if job_id == "__QUEUE_FULL__":
                self.send_json({"error":"Queue full — try again shortly."}, 503); return
            _audit.log("speculative_generation_started", case_id=cid, user_id=uid,
                       doc_type=dtype, job_id=job_id,
                       metadata={"readiness_score": target["score"]})
            self.send_json({"job_id":job_id,"status":"queued","doc_type":dtype,
                            "readiness":target["score"]}); return

        # ── User tier update (admin/internal use) ──
        if path == "/api/admin/set-tier":
            uid = require_auth(self)
            if not uid: return
            target_email = b.get("email","").strip().lower()
            new_tier = b.get("tier","pro_se")
            if new_tier not in ("pro_se","attorney"):
                self.send_json({"error":"Invalid tier. Use 'pro_se' or 'attorney'."}, 400); return
            conn = get_db()
            conn.execute("UPDATE users SET tier=? WHERE email=?", (new_tier, target_email))
            conn.commit()
            changed = conn.execute("SELECT changes()").fetchone()[0]
            conn.close()
            if not changed:
                self.send_json({"error":"User not found."}, 404); return
            self.send_json({"ok":True,"email":target_email,"tier":new_tier}); return

        self.send_json({"error":"not found"}, 404)


# ══════════════════════════════════════════════════════════════════════════════
# HELPER HTML BUILDERS
# ══════════════════════════════════════════════════════════════════════════════

def build_portal_html(pt, token):
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SynJuris Client Portal</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:#0d1b2a;color:#e8dfc8;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;padding:32px 16px}}
  .card{{background:#111f30;border:1px solid #1e3248;border-radius:12px;padding:32px;max-width:600px;margin:0 auto}}
  h1{{font-size:22px;color:#c9a84c;margin-bottom:4px}}
  .sub{{font-size:13px;color:#6b7a8d;margin-bottom:24px}}
  label{{display:block;font-size:12px;color:#8a9ab0;text-transform:uppercase;letter-spacing:.06em;margin-bottom:5px;margin-top:14px}}
  input,select,textarea{{width:100%;background:#0d1b2a;border:1px solid #1e3248;border-radius:6px;
    padding:10px 12px;color:#e8dfc8;font-size:14px;outline:none;font-family:inherit}}
  textarea{{min-height:140px;resize:vertical}}
  input:focus,textarea:focus,select:focus{{border-color:#c9a84c}}
  button{{background:#c9a84c;color:#0d1b2a;border:none;border-radius:6px;padding:12px 20px;
    font-size:14px;font-weight:600;cursor:pointer;margin-top:18px;width:100%}}
  button:hover{{background:#e0bb62}}
  .ok{{background:#0f2a1a;border:1px solid #1a5c2a;border-radius:6px;padding:14px;
    color:#5cdb8f;margin-top:16px;display:none}}
  .err{{background:#2a0f0f;border:1px solid #7a2020;border-radius:6px;padding:14px;
    color:#f08080;margin-top:16px;display:none}}
  .notice{{font-size:12px;color:#6b7a8d;margin-top:16px;line-height:1.5}}
</style>
</head>
<body>
<div class="card">
  <h1>SynJuris Client Portal</h1>
  <div class="sub">Case: {pt.get('case_title','')}&nbsp;·&nbsp;{pt.get('label','')}</div>
  <label>Description of what you're submitting</label>
  <textarea id="content" placeholder="Describe the incident, message, or document in detail. Include dates, times, and who was involved."></textarea>
  <label>Date of the event (if applicable)</label>
  <input type="date" id="event_date">
  <label>Category</label>
  <select id="category">
    <option>Document</option>
    <option>Message / Text</option>
    <option>Gatekeeping</option>
    <option>Threats</option>
    <option>Harassment</option>
    <option>Financial</option>
    <option>Violation of Order</option>
    <option>Parental Alienation</option>
    <option>Safety Concern</option>
    <option>Other</option>
  </select>
  <label>Your name or source</label>
  <input type="text" id="source" placeholder="e.g. Jane Smith (client)">
  <button onclick="submit()">Submit to Attorney</button>
  <div class="ok" id="ok">✓ Submitted successfully. Your attorney will review this item.</div>
  <div class="err" id="err"></div>
  <div class="notice">This submission is private and will be reviewed by your attorney before being added to your case file. Do not submit confidential attorney-client communications through this form.</div>
</div>
<script>
async function submit(){{
  const content=document.getElementById('content').value.trim();
  if(!content){{showErr('Please describe what you are submitting.');return;}}
  const r=await fetch('/api/portal/submit',{{
    method:'POST',headers:{{'Content-Type':'application/json'}},
    body:JSON.stringify({{
      token:'{token}',content,
      event_date:document.getElementById('event_date').value,
      category:document.getElementById('category').value,
      source:document.getElementById('source').value
    }})
  }});
  const d=await r.json();
  if(d.error){{showErr(d.error);return;}}
  document.getElementById('ok').style.display='block';
  document.getElementById('content').value='';
}}
function showErr(msg){{const e=document.getElementById('err');e.textContent=msg;e.style.display='block';}}
</script>
</body>
</html>"""


def build_courtroom_html(case_id):
    conn = get_db()
    case     = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
    evidence = conn.execute(
        "SELECT exhibit_number,content,category,event_date,source FROM evidence "
        "WHERE case_id=? AND confirmed=1 ORDER BY event_date ASC",
        (case_id,)
    ).fetchall()
    conn.close()
    if not case:
        return "<h2 style='font-family:sans-serif;padding:40px'>Case not found.</h2>"
    c = dict(case)
    ev_json = json.dumps([dict(e) for e in evidence])
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Courtroom View — {c.get('title','')}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:#0a0f1a;color:#e8dfc8;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif}}
  header{{background:#111f30;border-bottom:1px solid #1e3248;padding:16px 24px;display:flex;
    align-items:center;justify-content:space-between}}
  h1{{font-size:18px;color:#c9a84c}}
  .case-num{{font-size:12px;color:#6b7a8d}}
  .main{{display:grid;grid-template-columns:300px 1fr;height:calc(100vh - 57px)}}
  .sidebar{{background:#0d1421;border-right:1px solid #1e3248;overflow-y:auto;padding:16px}}
  .sidebar h2{{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:#6b7a8d;margin-bottom:12px}}
  .exhibit{{background:#111f30;border:1px solid #1e3248;border-radius:8px;padding:12px;
    margin-bottom:8px;cursor:pointer;transition:border-color .15s}}
  .exhibit:hover,.exhibit.active{{border-color:#c9a84c}}
  .exhibit-num{{font-size:11px;color:#c9a84c;font-weight:600;margin-bottom:4px}}
  .exhibit-cat{{font-size:10px;color:#6b7a8d;text-transform:uppercase;letter-spacing:.05em}}
  .exhibit-preview{{font-size:12px;color:#a0b0c0;margin-top:6px;
    overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
  .viewer{{padding:32px;overflow-y:auto}}
  .empty{{color:#4a5568;font-size:15px;margin-top:80px;text-align:center}}
  .doc-header{{margin-bottom:24px}}
  .doc-header h2{{font-size:20px;color:#c9a84c;margin-bottom:6px}}
  .meta{{display:flex;gap:16px;flex-wrap:wrap}}
  .meta span{{font-size:12px;color:#6b7a8d;background:#0d1421;
    border:1px solid #1e3248;border-radius:4px;padding:4px 8px}}
  .doc-body{{background:#111f30;border:1px solid #1e3248;border-radius:8px;
    padding:24px;font-size:14px;line-height:1.7;white-space:pre-wrap;word-break:break-word}}
  .badge{{display:inline-block;font-size:10px;padding:2px 8px;border-radius:10px;
    font-weight:600;text-transform:uppercase;letter-spacing:.05em}}
  .badge-high{{background:#3d1515;color:#f08080}}
  .badge-med{{background:#2d2010;color:#d4a44c}}
  .badge-low{{background:#0f1e2a;color:#5b8fa8}}
</style>
</head>
<body>
<header>
  <div>
    <h1>⚖ Courtroom View</h1>
    <div class="case-num">{c.get('title','')} · {c.get('court_name','No court set')} · {c.get('case_number','No case #')}</div>
  </div>
  <div style="font-size:12px;color:#6b7a8d">{len(evidence)} exhibits</div>
</header>
<div class="main">
  <div class="sidebar">
    <h2>Exhibits</h2>
    <div id="exhibit-list"></div>
  </div>
  <div class="viewer" id="viewer">
    <div class="empty">← Select an exhibit to view it</div>
  </div>
</div>
<script>
const exhibits = {ev_json};
const catBadge = c => {{
  const high = ['Gatekeeping','Threats','Relocation','Violation of Order'];
  const med  = ['Parental Alienation','Harassment','Financial','Stonewalling'];
  if(high.includes(c)) return `<span class="badge badge-high">${{c}}</span>`;
  if(med.includes(c))  return `<span class="badge badge-med">${{c}}</span>`;
  return `<span class="badge badge-low">${{c}}</span>`;
}};
function renderList(){{
  const el = document.getElementById('exhibit-list');
  el.innerHTML = exhibits.map((e,i)=>`
    <div class="exhibit" id="ex-${{i}}" onclick="showExhibit(${{i}})">
      <div class="exhibit-num">${{e.exhibit_number||'Unnumbered'}}</div>
      <div class="exhibit-cat">${{e.category||'General'}} · ${{e.event_date||'undated'}}</div>
      <div class="exhibit-preview">${{(e.content||'').substring(0,80)}}</div>
    </div>`).join('');
}}
function showExhibit(i){{
  document.querySelectorAll('.exhibit').forEach(el=>el.classList.remove('active'));
  document.getElementById('ex-'+i)?.classList.add('active');
  const e = exhibits[i];
  document.getElementById('viewer').innerHTML = `
    <div class="doc-header">
      <h2>${{e.exhibit_number||'Unnumbered Exhibit'}}</h2>
      <div class="meta">
        ${{catBadge(e.category||'General')}}
        <span>📅 ${{e.event_date||'Date unknown'}}</span>
        ${{e.source?`<span>📎 ${{e.source}}</span>`:''}}
      </div>
    </div>
    <div class="doc-body">${{(e.content||'').replace(/</g,'&lt;').replace(/>/g,'&gt;')}}</div>`;
}}
renderList();
if(exhibits.length>0) showExhibit(0);
</script>
</body>
</html>"""


def build_redacted_export(case_id, user_id):
    conn = get_db()
    case     = conn.execute("SELECT * FROM cases WHERE id=? AND user_id=?", (case_id, user_id)).fetchone()
    evidence = conn.execute(
        "SELECT exhibit_number,content,category,event_date FROM evidence "
        "WHERE case_id=? AND confirmed=1 ORDER BY event_date ASC",
        (case_id,)
    ).fetchall()
    conn.close()
    if not case:
        return {"error":"not found"}
    c = dict(case)
    _NAME_RE  = re.compile(r'\b([A-Z][a-z]+(?:\s[A-Z][a-z]+)+)\b')
    _PHONE_RE = re.compile(r'\b(\(?\d{3}\)?[\s\-]\d{3}[\s\-]\d{4})\b')
    _EMAIL_RE = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')
    def redact(text):
        text = _NAME_RE.sub("[NAME REDACTED]", text or "")
        text = _PHONE_RE.sub("[PHONE REDACTED]", text)
        text = _EMAIL_RE.sub("[EMAIL REDACTED]", text)
        return text
    return {
        "case_title":    c.get("title",""),
        "jurisdiction":  c.get("jurisdiction",""),
        "case_type":     c.get("case_type",""),
        "exported_at":   datetime.utcnow().isoformat() + "Z",
        "exhibit_count": len(evidence),
        "exhibits": [
            {
                "exhibit_number": e["exhibit_number"],
                "category":       e["category"],
                "event_date":     e["event_date"],
                "content":        redact(e["content"]),
            }
            for e in evidence
        ],
        "note": "Names, phone numbers, and email addresses have been automatically redacted. Review before sharing."
    }


# ══════════════════════════════════════════════════════════════════════════════
# LANDING HTML (shown to unauthenticated users in cloud mode)
# ══════════════════════════════════════════════════════════════════════════════

LANDING_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SynJuris — Legal Intelligence for Pro Se Litigants</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:#0d1b2a;color:#e8dfc8;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif}
  nav{background:#111f30;border-bottom:1px solid #1e3248;padding:16px 32px;
    display:flex;align-items:center;justify-content:space-between}
  .logo{font-size:20px;color:#c9a84c;font-weight:700;letter-spacing:.04em}
  .nav-btns{display:flex;gap:12px}
  .btn{padding:8px 18px;border-radius:6px;font-size:14px;font-weight:600;
    cursor:pointer;border:none;text-decoration:none;display:inline-block}
  .btn-outline{background:transparent;border:1px solid #1e3248;color:#e8dfc8}
  .btn-primary{background:#c9a84c;color:#0d1b2a}
  .btn-outline:hover{border-color:#c9a84c}
  .btn-primary:hover{background:#e0bb62}
  .hero{text-align:center;padding:80px 24px 60px}
  .hero h1{font-size:42px;font-weight:700;color:#e8dfc8;margin-bottom:16px;line-height:1.2}
  .hero h1 span{color:#c9a84c}
  .hero p{font-size:18px;color:#8a9ab0;max-width:600px;margin:0 auto 32px;line-height:1.6}
  .hero-btns{display:flex;gap:12px;justify-content:center;flex-wrap:wrap}
  .features{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));
    gap:20px;padding:0 32px 60px;max-width:1100px;margin:0 auto}
  .feat{background:#111f30;border:1px solid #1e3248;border-radius:10px;padding:24px}
  .feat-icon{font-size:28px;margin-bottom:12px}
  .feat h3{font-size:16px;color:#c9a84c;margin-bottom:8px}
  .feat p{font-size:14px;color:#8a9ab0;line-height:1.6}
  .waitlist{background:#111f30;border-top:1px solid #1e3248;padding:48px 24px;text-align:center}
  .waitlist h2{font-size:24px;color:#c9a84c;margin-bottom:8px}
  .waitlist p{font-size:14px;color:#6b7a8d;margin-bottom:20px}
  .waitlist-form{display:flex;gap:10px;justify-content:center;flex-wrap:wrap;max-width:480px;margin:0 auto}
  .waitlist-form input{flex:1;min-width:220px;background:#0d1b2a;border:1px solid #1e3248;
    border-radius:6px;padding:10px 14px;color:#e8dfc8;font-size:14px;outline:none}
  .waitlist-form input:focus{border-color:#c9a84c}
  .disc{font-size:11px;color:#4a5568;margin-top:48px;padding:0 24px;text-align:center;line-height:1.7}
</style>
</head>
<body>
<nav>
  <div class="logo">SynJuris</div>
  <div class="nav-btns">
    <a href="/login" class="btn btn-outline">Sign In</a>
    <a href="/login" class="btn btn-primary">Get Started</a>
  </div>
</nav>
<div class="hero">
  <h1>Legal Intelligence for<br><span>Pro Se Litigants</span></h1>
  <p>Organize your evidence, track deadlines, and prepare for court — without a lawyer. SynJuris turns your documents and records into a structured case strategy.</p>
  <div class="hero-btns">
    <a href="/login" class="btn btn-primary" style="font-size:16px;padding:14px 28px">Start Building Your Case →</a>
  </div>
</div>
<div class="features">
  <div class="feat">
    <div class="feat-icon">📋</div>
    <h3>Evidence Organizer</h3>
    <p>Import text messages, add incident records, and automatically categorize evidence by legal issue — gatekeeping, threats, violations, and more.</p>
  </div>
  <div class="feat">
    <div class="feat-icon">⚖️</div>
    <h3>AI Legal Assistant</h3>
    <p>Ask plain-English questions about your case, your jurisdiction's statutes, and what to expect at your hearing. Grounded in your actual evidence.</p>
  </div>
  <div class="feat">
    <div class="feat-icon">📄</div>
    <h3>Document Generator</h3>
    <p>Generate motions, declarations, demand letters, and hearing prep guides — properly formatted with your evidence already cited.</p>
  </div>
  <div class="feat">
    <div class="feat-icon">📅</div>
    <h3>Deadline Tracker</h3>
    <p>Never miss a filing date. Track all court deadlines with automatic overdue alerts and procedural health scoring.</p>
  </div>
  <div class="feat">
    <div class="feat-icon">🔒</div>
    <h3>Tamper-Evident Audit</h3>
    <p>Every AI action is logged with a cryptographic hash chain. Verify that your evidence record hasn't changed since any AI-assisted action was taken.</p>
  </div>
  <div class="feat">
    <div class="feat-icon">🧠</div>
    <h3>Case Dynamics Engine</h3>
    <p>Your case gets a live three-axis score: evidence strength, procedural health, and documented adversarial pressure — updated as you add records.</p>
  </div>
</div>
<div class="waitlist">
  <h2>Stay Updated</h2>
  <p>Get notified about new features and updates.</p>
  <div class="waitlist-form">
    <input type="email" id="wl-email" placeholder="your@email.com">
    <button class="btn btn-primary" onclick="joinWaitlist()">Notify Me</button>
  </div>
  <div id="wl-msg" style="margin-top:14px;font-size:14px;color:#5cdb8f;display:none">You're on the list!</div>
</div>
<div class="disc">
  SynJuris provides legal information and organizational tools only — not legal advice.<br>
  This platform does not constitute legal counsel and does not create an attorney-client relationship.<br>
  Always consult a licensed attorney before filing any document with a court.
</div>
<script>
async function joinWaitlist(){
  const email=document.getElementById('wl-email').value.trim();
  if(!email||!email.includes('@')) return;
  await fetch('/api/waitlist',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({email,source:'landing_page'})});
  document.getElementById('wl-msg').style.display='block';
  document.getElementById('wl-email').value='';
}
document.getElementById('wl-email').addEventListener('keydown',e=>{
  if(e.key==='Enter') joinWaitlist();
});
</script>
</body>
</html>"""


# ══════════════════════════════════════════════════════════════════════════════
# MAIN UI (the full SPA — placeholder; expand with your actual UI HTML)
# ══════════════════════════════════════════════════════════════════════════════

UI = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SynJuris</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:#0d1b2a;color:#e8dfc8;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
    display:flex;align-items:center;justify-content:center;min-height:100vh}
  .loading{text-align:center;color:#6b7a8d;font-size:15px}
  .logo{font-size:28px;color:#c9a84c;font-weight:700;margin-bottom:12px}
</style>
</head>
<body>
<div class="loading">
  <div class="logo">SynJuris</div>
  <div>Loading your case file…</div>
</div>
<script>
// The full SPA JavaScript loads here.
// In production this is the complete single-page application.
// On first load, redirect to /api/cases to check auth state.
fetch('/api/cases').then(r=>{
  if(r.status===401){ window.location.href='/login'; }
}).catch(()=>{ window.location.href='/login'; });
</script>
</body>
</html>"""


# ══════════════════════════════════════════════════════════════════════════════
# FLASK WSGI BRIDGE (for Render / Gunicorn / production)
# ══════════════════════════════════════════════════════════════════════════════

if Flask:
    flask_app = Flask(__name__)

    @flask_app.before_request
    def _init_once():
        # idempotent — SQLite CREATE IF NOT EXISTS guards handle repeats
        init_db()

    @flask_app.route("/", defaults={"path": ""}, methods=["GET","POST","PUT","DELETE","OPTIONS"])
    @flask_app.route("/<path:path>",            methods=["GET","POST","PUT","DELETE","OPTIONS"])
    def _catch_all(path):
        """
        Bridge: convert Flask request → fake BaseHTTPRequestHandler-compatible
        object → call our Handler → capture response bytes → return Flask response.
        """
        import io
        body_bytes = flask_req.get_data()

        class _FakeHandler:
            headers    = flask_req.headers
            path       = "/" + path + (("?" + flask_req.query_string.decode()) if flask_req.query_string else "")
            command    = flask_req.method
            rfile      = io.BytesIO(body_bytes)
            server     = None
            _resp_code = 200
            _resp_hdrs = {}
            _resp_buf  = io.BytesIO()
            wfile      = _resp_buf

            def send_response(self, code):   self._resp_code = code
            def send_header(self, k, v):     self._resp_hdrs[k] = v
            def end_headers(self):           pass
            def log_message(self, *a):       pass

            def body(self_):
                try:    return json.loads(body_bytes) if body_bytes else {}
                except: return {}

            def send_json(self_, data, status=200):
                b = json.dumps(data).encode()
                self_._resp_code = status
                self_._resp_hdrs["Content-Type"] = "application/json"
                self_._resp_buf.write(b)

            def send_html(self_, html):
                b = html.encode()
                self_._resp_hdrs["Content-Type"] = "text/html;charset=utf-8"
                self_._resp_buf.write(b)

        fh = _FakeHandler()
        method = flask_req.method.upper()
        handler = Handler.__new__(Handler)
        handler.__dict__.update(fh.__dict__)
        handler.send_json  = fh.send_json
        handler.send_html  = fh.send_html
        handler.send_response = fh.send_response
        handler.send_header   = fh.send_header
        handler.end_headers   = fh.end_headers
        handler.log_message   = fh.log_message
        handler.body          = fh.body
        handler.headers       = fh.headers
        handler.path          = fh.path
        handler.wfile         = fh._resp_buf
        handler.rfile         = fh.rfile

        try:
            if   method == "GET":     handler.do_GET()
            elif method == "POST":    handler.do_POST()
            elif method == "DELETE":  handler.do_DELETE()
            elif method == "OPTIONS": handler.do_OPTIONS()
            else:
                fh._resp_code = 405
                fh._resp_buf.write(b'{"error":"method not allowed"}')
                fh._resp_hdrs["Content-Type"] = "application/json"
        except Exception as e:
            fh._resp_code = 500
            fh._resp_buf.write(json.dumps({"error": str(e)}).encode())
            fh._resp_hdrs["Content-Type"] = "application/json"

        resp_body = fh._resp_buf.getvalue()
        flask_resp = make_response(resp_body, fh._resp_code)
        for k, v in fh._resp_hdrs.items():
            flask_resp.headers[k] = v
        flask_resp.headers["Access-Control-Allow-Origin"] = "*"
        flask_resp.headers["X-Content-Type-Options"]      = "nosniff"
        return flask_resp

    # Expose as `app` for gunicorn:  gunicorn "server:app"
    app = flask_app


# ══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

def main():
    init_db()

    # Cloud/Render mode: let gunicorn own the process — don't start our own server
    if not LOCAL_MODE and Flask:
        print(f"SynJuris v{VERSION} — WSGI mode. Start with: gunicorn 'server:app'")
        return

    # Local mode: start the built-in threaded HTTP server
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"\n{'='*55}")
    print(f"  SynJuris v{VERSION} — Local Mode")
    print(f"  http://localhost:{PORT}")
    print(f"  DB: {DB_PATH}  |  Uploads: {UPLOADS_DIR}")
    print(f"  AI provider: {_AI_PROVIDER.upper()}  |  Auth: {'DISABLED' if LOCAL_MODE else 'ENABLED'}")
    print(f"{'='*55}\n")

    if LOCAL_MODE:
        # Auto-open browser after a short delay
        def _open():
            time.sleep(0.8)
            webbrowser.open(f"http://localhost:{PORT}")
        threading.Thread(target=_open, daemon=True).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nSynJuris stopped.")
    finally:
        server.server_close()
        _executor.shutdown(wait=False)
        _spec_executor.shutdown(wait=False)


if __name__ == "__main__":
    main()
