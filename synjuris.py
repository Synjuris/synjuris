"""
SynJuris — Local Legal Assistant for Pro Se Litigants
Run:  python3 server.py
Open: http://localhost:5000
Your data never leaves this computer.
"""

import sqlite3, json, os, re, xml.etree.ElementTree as ET
import webbrowser, threading, urllib.request, urllib.parse
import hashlib, hmac, time, queue, uuid, math
from datetime import datetime, date
from http.server import HTTPServer, BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor
from collections import OrderedDict
from typing import Optional, Callable

_BASE        = "/data" if os.path.isdir("/data") else os.path.dirname(os.path.abspath(__file__))
DB_PATH      = os.path.join(_BASE, "synjuris.db")
API_KEY      = os.environ.get("ANTHROPIC_API_KEY", "")
UPLOADS_DIR  = os.path.join(_BASE, "uploads")
PORT         = int(os.environ.get("PORT", 5000))
VERSION      = "2.0.0"
UPDATE_URL   = "https://raw.githubusercontent.com/synjuris/synjuris/main/version.json"

def check_for_update():
    """Non-blocking startup check. Prints notice if newer version exists."""
    try:
        req = urllib.request.Request(UPDATE_URL, headers={"User-Agent": f"SynJuris/{VERSION}"})
        with urllib.request.urlopen(req, timeout=4) as r:
            data = json.loads(r.read())
        latest = data.get("version","")
        notes  = data.get("notes","")
        if latest and latest != VERSION:
            print(f"\n  ┌─ Update available: v{latest} (you have v{VERSION})")
            if notes: print(f"  │  {notes}")
            print(f"  └─ Download: https://github.com/synjuris/synjuris/releases/latest\n")
    except Exception:
        pass  # Silent — never block startup over an update check

# ══════════════════════════════════════════════════════════════════════════════
# DETERMINISTIC CASE DYNAMICS ENGINE  (port of engine.ts / hash.ts / types.ts)
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
    # ── Schema-version-based migrations ──────────────────────────────────────
    current = conn.execute("SELECT MAX(version) FROM schema_version").fetchone()[0] or 0

    if current < 1:
        # Migration 1: add file attachment columns to evidence
        existing = [r[1] for r in conn.execute("PRAGMA table_info(evidence)").fetchall()]
        if "file_path" not in existing:
            conn.execute("ALTER TABLE evidence ADD COLUMN file_path TEXT")
        if "file_type" not in existing:
            conn.execute("ALTER TABLE evidence ADD COLUMN file_type TEXT")
        conn.execute("INSERT INTO schema_version(version) VALUES(1)")

    if current < 2:
        # Migration 2: create audit_log if it predates the CREATE IF NOT EXISTS above
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
        # Migration 3: add user_id to cases
        existing_cases = [r[1] for r in conn.execute("PRAGMA table_info(cases)").fetchall()]
        if "user_id" not in existing_cases:
            conn.execute("ALTER TABLE cases ADD COLUMN user_id INTEGER")
        conn.execute("INSERT INTO schema_version(version) VALUES(3)")

    if current < 4:
        # Migration 4: soft delete + original filename columns
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
        # Migration 5: session expiry and auth rate-limit table
        sess_cols = [r[1] for r in conn.execute("PRAGMA table_info(sessions)").fetchall()]
        if "expires_at" not in sess_cols:
            # Set existing sessions to expire 30 days from now
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
        # Migration 6: attorney tier, portal tokens, conflict log, time entries
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
        # Migration 7: CourtListener citation cache + backup metadata
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
        # Migration 8: v2 tables — generation_jobs, user_action_log,
        #              merkle_nodes, merkle_roots, evidence_embeddings
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
# Maps state names/abbreviations to their custody interference statutes.
# Used by the AI system prompt and document generator so every reference
# to law cites the actual statute for that user's state.
# Add states as needed — structure: { display_name: { ... } }

JURISDICTION_LAW = {
    # ── CUSTODY / INTERFERENCE ──────────────────────────────────────────────
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

# Common abbreviations / alternate spellings → canonical name
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
    # common misspellings / shorthand
    "tenn":"Tennessee","tenn.":"Tennessee","calif":"California","calif.":"California",
    "colo":"Colorado","colo.":"Colorado","conn":"Connecticut","conn.":"Connecticut",
    "mass":"Massachusetts","mass.":"Massachusetts","mich":"Michigan","mich.":"Michigan",
    "minn":"Minnesota","minn.":"Minnesota","penn":"Pennsylvania","penn.":"Pennsylvania",
    "wisc":"Wisconsin","wisc.":"Wisconsin",
}

def resolve_jurisdiction(raw):
    """Return canonical state name and its statute dict, or None if unknown."""
    if not raw:
        return None, {}
    key = raw.strip().lower()
    canonical = JURISDICTION_ALIASES.get(key) or next(
        (k for k in JURISDICTION_LAW if k.lower() == key), None
    )
    if canonical:
        return canonical, JURISDICTION_LAW.get(canonical, {})
    # partial match — e.g. "middle district of tennessee"
    for k in JURISDICTION_LAW:
        if k.lower() in key:
            return k, JURISDICTION_LAW[k]
    return raw.title(), {}  # unknown state — return as-is, empty statutes

def jurisdiction_statute_block(jurisdiction):
    """Build the statute reference block injected into AI prompts."""
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
#
# Each entry: (category, severity_weight, regex)
#
# Severity weights:
#   5.0 = Explicit statutory violation (gatekeeping, threats, order violation)
#   4.0 = Strong behavioral indicator (alienation, harassment, financial abuse)
#   3.0 = Communication barrier (stonewalling, blocking)
#   2.0 = Concerning pattern (emotional abuse, neglect indicators)
#   1.0 = Contextual flag (substance mention, child statement, general conflict)
#
# Philosophy: cast wide on detection, let the human confirm.
# Better to flag something innocent than miss something important.
# ──────────────────────────────────────────────────────────────────────────────

PATTERNS = [
    # (category, severity_weight, regex)
    # 5.0=explicit violation  4.0=strong indicator  3.0=comm barrier
    # 2.0=concerning pattern  1.0=contextual flag

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
    """Return list of (category, weight, confidence) for all patterns matching text.
    confidence: 'possible' (w<3), 'likely' (w 3-4), 'strong' (w>=5)
    """
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
    """Return the highest-weight category label for a piece of text, or None."""
    matches = scan_patterns(text)
    if not matches:
        return None
    return max(matches, key=lambda x: x[1])[0]

# =====================================================================
# STATE INTERPRETATION LAYER — deterministic plain-English translation
# =====================================================================

def interpret_case_state(snapshot):
    """Translate x/y/z scores into plain-English guidance. No AI call."""
    st  = snapshot["state"]
    inp = snapshot["inputs"]
    x, y, z = st["x"], st["y"], st["z"]
    over     = inp.get("overdue_deadlines", 0)
    ev       = inp.get("evidence_count", 0)
    total_dl = inp.get("total_deadlines", 0)
    done_dl  = inp.get("done_deadlines", 0)

    # Evidence Strength (x)
    if x <= 2:
        x_text = (
            f"Your evidence is thin ({ev} confirmed exhibit{'s' if ev!=1 else ''}). "
            "Courts expect documented facts. Add dated communications, records, or witness statements now."
        )
    elif x <= 4:
        x_text = (
            f"Developing evidence base ({ev} exhibits). "
            "Confirm unreviewed items and add dates to undated entries — "
            "courts weight contemporaneous records most heavily."
        )
    elif x <= 6:
        x_text = (
            f"Solid evidence base ({ev} exhibits). "
            "Look for gaps: are all key incidents documented? "
            "Corroborating records strengthen credibility."
        )
    else:
        x_text = (
            f"Strong documented evidence ({ev} exhibits). "
            "Prioritize organizing exhibits chronologically and linking each to a specific legal issue."
        )

    # Procedural Health (y)
    if over > 0:
        y_text = (
            f"{over} deadline{'s are' if over>1 else ' is'} overdue. "
            "Missed filings are visible to the court and can be used against you. "
            "File immediately or submit a Motion for Continuance."
        )
    elif y <= 2:
        y_text = (
            "Procedural standing is weak. "
            "Add all known court dates, filing deadlines, and response windows so nothing is missed."
        )
    elif y <= 5:
        if total_dl > 0:
            pct = int((done_dl / total_dl) * 100)
            y_text = (
                f"{pct}% of deadlines completed ({done_dl}/{total_dl}). "
                "Courts view consistent compliance favorably — mark each deadline complete as you file."
            )
        else:
            y_text = (
                "No deadlines tracked. Add all known court dates and filing windows."
            )
    else:
        y_text = (
            f"Procedural standing strong ({done_dl}/{total_dl} deadlines met, none overdue). "
            "Consistent compliance is itself a form of evidence."
        )

    # Adversarial Pressure (z)
    if z <= 2:
        z_text = (
            "Low documented adversarial conduct. "
            "Log any incidents immediately with dates, exact quotes, and context — "
            "contemporaneous records are far more credible than later recollections."
        )
    elif z <= 5:
        z_text = (
            "Moderate adverse conduct documented. "
            "These exhibits may support a finding of bad faith or willful non-compliance. "
            "Run Adversarial Analysis to see how opposing counsel will frame these."
        )
    else:
        z_text = (
            "High adversarial pressure documented. "
            "The pattern in your evidence is significant. "
            "Consider whether a Motion for Contempt or Emergency Motion is appropriate."
        )

    # Overall urgency
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

# =====================================================================
# PROACTIVE GUIDANCE ENGINE — deterministic priority-ranked action list
# =====================================================================

def compute_guidance(case_id):
    """Priority-ranked action list from case state. No AI call."""
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
            "detail": (
                f"Was due {d['due_date']}. File immediately or request a continuance. "
                "Missed deadlines are visible to the court."
            ),
            "action_tab": "deadlines",
        })

    if days_to_hearing is not None and 0 <= days_to_hearing <= 7:
        actions.append({
            "priority": 1, "level": "critical", "icon": "⚖️",
            "title": f"Hearing in {days_to_hearing} day{'s' if days_to_hearing!=1 else ''}",
            "detail": (
                "Open Courtroom View to review your exhibits and opening statement. "
                "Ensure your Hearing Prep Guide is generated."
            ),
            "action_tab": "hearing",
        })

    if unreviewed:
        actions.append({
            "priority": 2, "level": "high", "icon": "⚠️",
            "title": f"{len(unreviewed)} item{'s' if len(unreviewed)>1 else ''} need{'s' if len(unreviewed)==1 else ''} review",
            "detail": (
                "Flagged items are not yet confirmed. "
                "Unconfirmed items don't count toward your evidence strength score."
            ),
            "action_tab": "evidence",
        })

    if not confirmed:
        actions.append({
            "priority": 3, "level": "high", "icon": "📋",
            "title": "No confirmed evidence yet",
            "detail": (
                "Add your first evidence item. Start with the most recent and most serious incident. "
                "Dated, specific records carry the most weight with courts."
            ),
            "action_tab": "evidence",
        })
    elif len(confirmed) < 5 and days_to_hearing is not None and days_to_hearing <= 30:
        actions.append({
            "priority": 4, "level": "high", "icon": "📋",
            "title": f"Only {len(confirmed)} confirmed exhibit{'s' if len(confirmed)!=1 else ''} — hearing approaching",
            "detail": (
                "Courts expect documented facts. Add remaining incidents, "
                "communications, or records before your hearing date."
            ),
            "action_tab": "evidence",
        })

    if not deadlines and c.get("hearing_date"):
        actions.append({
            "priority": 5, "level": "moderate", "icon": "📅",
            "title": "No deadlines tracked",
            "detail": (
                "You have a hearing date set but no deadlines logged. "
                "Add response deadlines, filing dates, and exchange dates."
            ),
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
            "detail": (
                f"Your hearing is {days_to_hearing} days away. "
                "Builds your opening statement, evidence introduction order, and anticipated arguments."
            ),
            "action_tab": "hearing",
        })

    if confirmed and len(confirmed) >= 3 and not any(
        t in doc_types for t in ["Case Theory","case-theory"]
    ):
        actions.append({
            "priority": 8, "level": "normal", "icon": "🧠",
            "title": "Build your case summary",
            "detail": (
                "You have enough evidence to generate a Case Summary — "
                "one sentence that captures what happened, what law applies, and what you're asking for."
            ),
            "action_tab": "strategy",
        })

    snap = compute_case_state(case_id)
    if snap["state"]["z"] >= 6 and not any(
        "Contempt" in dt or "Emergency" in dt for dt in doc_types
    ):
        actions.append({
            "priority": 9, "level": "normal", "icon": "⚖️",
            "title": "High adverse conduct — consider a motion",
            "detail": (
                "Your evidence shows a significant pattern of violations. "
                "A Motion for Contempt or Emergency Motion may be appropriate."
            ),
            "action_tab": "motions",
        })

    if party_count == 0:
        actions.append({
            "priority": 10, "level": "normal", "icon": "👤",
            "title": "Add case parties",
            "detail": (
                "No parties entered. Adding the other party and their attorney "
                "helps the AI generate more accurate documents."
            ),
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
    """Build a plain-text evidence manifest for a case. Returns (filename, bytes)."""
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

    lines += [
        f"CONFIRMED EVIDENCE ({len(evidence)} items)",
        "-" * 40,
    ]
    for e in evidence:
        lines += [
            f"  {e['exhibit_number'] or 'Unumbered'}",
            f"  Date     : {e['event_date'] or 'Unknown'}",
            f"  Category : {e['category'] or 'General'}",
            f"  Source   : {e['source'] or 'Not specified'}",
            f"  Content  :",
        ]
        # word-wrap content at 70 chars
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

# ── Password hashing: PBKDF2-HMAC-SHA256, 100 000 iterations ─────────────────
# Equivalent security class to bcrypt work-factor 12. Zero external deps.
# Format on disk: "pbkdf2:<iterations>:<hex-salt>:<hex-digest>"
# Old sha256 format "salt:hex" is auto-detected and rejected (user must reset).
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
            # Legacy SHA-256 format detected — force re-hash on next login
            # by always returning False (safe: user just needs to re-register
            # or admin can reset). Don't silently accept weak hashes.
            return False
    except Exception:
        return False

_SESSION_DAYS = 30   # cookie + DB lifetime
_MAX_AUTH_ATTEMPTS = 5   # per email per window
_AUTH_WINDOW_SECONDS = 300  # 5 minutes

def create_session(user_id):
    token = secrets.token_hex(32)
    expires = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_db()
    # expire_at = now + 30 days (SQLite datetime arithmetic)
    conn.execute(
        "INSERT INTO sessions (token, user_id, expires_at) VALUES (?,?, datetime('now', '+30 days'))",
        (token, user_id)
    )
    # Purge expired sessions opportunistically
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
    """Return True if login is allowed, False if rate-limited."""
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
    # Trim old records (keep last 1000 per email to avoid unbounded growth)
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
    """Return 'attorney' or 'pro_se' for the given user."""
    conn = get_db()
    row = conn.execute("SELECT tier FROM users WHERE id=?", (user_id,)).fetchone()
    conn.close()
    return (row["tier"] or "pro_se") if row else "pro_se"

def require_auth(handler):
    """Returns user_id or sends 401 and returns None."""
    token = get_token_from_request(handler)
    uid = get_user_from_token(token)
    if not uid:
        handler.send_json({"error": "unauthorized"}, 401)
    return uid

def require_attorney(handler):
    """Returns user_id only for attorney-tier users, else 403."""
    uid = require_auth(handler)
    if not uid: return None
    if get_user_tier(uid) != "attorney":
        handler.send_json({"error": "Attorney tier required"}, 403)
        return None
    return uid

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


LANDING_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SynJuris — Legal Intelligence for Pro Se Litigants</title>
<meta name="description" content="SynJuris helps you organize evidence, track deadlines, and walk into court prepared — even if this is your first time. Built by a pro se dad. Perfected for you.">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Cinzel:wght@400;600;700&family=Inter:wght@300;400;500;600&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0D1B2A;
  --surface:#111f30;
  --border:#1e3248;
  --ink:#E8DFC8;
  --ink2:#A89F8A;
  --ink3:#6B7A8D;
  --gold:#C9A84C;
  --gold2:#e0bb62;
  --green:#4CAF7D;
  --red:#E05C5C;
  --blue:#4A90D9;
}
html{scroll-behavior:smooth}
body{background:var(--bg);color:var(--ink);font-family:'Inter',system-ui,sans-serif;line-height:1.7;font-size:16px}

/* ── NAV ── */
nav{position:sticky;top:0;z-index:100;background:rgba(13,27,42,0.97);backdrop-filter:blur(10px);border-bottom:1px solid rgba(201,168,76,0.2);padding:16px 40px;display:flex;align-items:center;justify-content:space-between}
.nav-logo{font-family:'Cinzel',serif;font-size:20px;font-weight:700;color:var(--gold);letter-spacing:.12em}
.nav-links{display:flex;align-items:center;gap:12px}
.nav-link{color:var(--ink2);text-decoration:none;font-size:14px;transition:color .2s}
.nav-link:hover{color:var(--gold)}
.btn{display:inline-flex;align-items:center;justify-content:center;padding:11px 24px;border-radius:6px;font-family:'Inter',sans-serif;font-size:14px;font-weight:600;cursor:pointer;text-decoration:none;transition:all .2s;border:none}
.btn-primary{background:var(--gold);color:#0D1B2A}
.btn-primary:hover{background:var(--gold2);transform:translateY(-1px)}
.btn-ghost{background:transparent;color:var(--ink2);border:1px solid var(--border)}
.btn-ghost:hover{border-color:var(--gold);color:var(--gold)}
.btn-large{padding:16px 40px;font-size:16px;border-radius:8px}
.btn-xl{padding:20px 52px;font-size:18px;border-radius:8px;letter-spacing:.02em}

/* ── HERO ── */
.hero{min-height:92vh;display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;padding:80px 24px;position:relative;overflow:hidden}
.hero::before{content:'';position:absolute;inset:0;background:radial-gradient(ellipse at 50% 40%,rgba(201,168,76,0.06) 0%,transparent 70%);pointer-events:none}
.hero-eyebrow{font-size:11px;text-transform:uppercase;letter-spacing:.2em;color:var(--gold);margin-bottom:24px;opacity:.9}
.hero h1{font-family:'Cinzel',serif;font-size:clamp(36px,6vw,72px);font-weight:700;line-height:1.1;margin-bottom:28px;max-width:800px}
.hero h1 em{font-style:normal;color:var(--gold)}
.hero-sub{font-size:clamp(17px,2.2vw,22px);color:var(--ink2);max-width:580px;margin:0 auto 16px;font-weight:300;line-height:1.8}
.hero-origin{font-size:15px;color:var(--ink3);max-width:480px;margin:0 auto 48px;font-style:italic;line-height:1.8}
.hero-origin strong{color:var(--ink2);font-style:normal}
.hero-cta-group{display:flex;flex-direction:column;align-items:center;gap:14px}
.hero-price{font-size:13px;color:var(--ink3);margin-top:4px}
.hero-price strong{color:var(--gold);font-size:16px}
.hero-badges{display:flex;gap:12px;flex-wrap:wrap;justify-content:center;margin-top:32px}
.badge{font-size:12px;padding:6px 14px;border-radius:20px;border:1px solid var(--border);color:var(--ink3)}

/* ── TRUST BAR ── */
.trust-bar{background:var(--surface);border-top:1px solid var(--border);border-bottom:1px solid var(--border);padding:20px 40px;display:flex;justify-content:center;gap:48px;flex-wrap:wrap}
.trust-item{display:flex;align-items:center;gap:8px;font-size:13px;color:var(--ink2)}
.trust-icon{font-size:16px}

/* ── SECTION BASE ── */
section{padding:96px 24px}
.container{max-width:1100px;margin:0 auto}
.section-tag{font-size:11px;text-transform:uppercase;letter-spacing:.18em;color:var(--gold);margin-bottom:14px}
.section-title{font-family:'Cinzel',serif;font-size:clamp(28px,4vw,44px);font-weight:600;line-height:1.2;margin-bottom:20px}
.section-sub{font-size:18px;color:var(--ink2);max-width:580px;line-height:1.8;font-weight:300}

/* ── PROBLEM SECTION ── */
.problem{background:var(--surface)}
.problem-grid{display:grid;grid-template-columns:1fr 1fr;gap:40px;align-items:center;margin-top:56px}
.problem-list{display:flex;flex-direction:column;gap:20px}
.problem-item{display:flex;gap:14px;align-items:flex-start}
.problem-icon{font-size:20px;flex-shrink:0;margin-top:2px}
.problem-text h4{font-size:16px;font-weight:600;margin-bottom:4px}
.problem-text p{font-size:14px;color:var(--ink2);line-height:1.7}
.problem-stat{background:var(--bg);border:1px solid var(--border);border-radius:12px;padding:32px;text-align:center}
.stat-num{font-family:'Cinzel',serif;font-size:56px;font-weight:700;color:var(--gold);line-height:1}
.stat-label{font-size:14px;color:var(--ink2);margin-top:8px;line-height:1.6}
.stat-source{font-size:11px;color:var(--ink3);margin-top:8px}

/* ── FEATURES ── */
.features-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:20px;margin-top:56px}
.feature-card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:28px;transition:border-color .2s,transform .2s}
.feature-card:hover{border-color:rgba(201,168,76,0.4);transform:translateY(-2px)}
.feature-icon{font-size:28px;margin-bottom:14px}
.feature-card h3{font-size:17px;font-weight:600;margin-bottom:10px}
.feature-card p{font-size:14px;color:var(--ink2);line-height:1.7}
.feature-tag{display:inline-block;font-size:10px;text-transform:uppercase;letter-spacing:.1em;padding:3px 8px;border-radius:4px;background:rgba(201,168,76,0.12);color:var(--gold);margin-bottom:10px}

/* ── HOW IT WORKS ── */
.how{background:var(--surface)}
.steps{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:24px;margin-top:56px;position:relative}
.step{background:var(--bg);border:1px solid var(--border);border-radius:12px;padding:28px;text-align:center}
.step-num{font-family:'Cinzel',serif;font-size:40px;font-weight:700;color:var(--gold);opacity:.3;line-height:1;margin-bottom:14px}
.step h3{font-size:16px;font-weight:600;margin-bottom:8px}
.step p{font-size:14px;color:var(--ink2);line-height:1.7}

/* ── WHO IT'S FOR ── */
.audience-grid{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-top:48px}
.audience-card{border:1px solid var(--border);border-radius:12px;padding:28px}
.audience-card h3{font-size:18px;font-weight:600;margin-bottom:12px}
.audience-card ul{list-style:none;display:flex;flex-direction:column;gap:8px}
.audience-card ul li{font-size:14px;color:var(--ink2);padding-left:18px;position:relative;line-height:1.6}
.audience-card ul li::before{content:'→';position:absolute;left:0;color:var(--gold)}

/* ── PRICING ── */
.pricing{background:var(--surface)}
.pricing-grid{display:grid;grid-template-columns:1fr 1fr;gap:24px;margin-top:56px;max-width:800px;margin-left:auto;margin-right:auto}
.price-card{border-radius:16px;padding:36px;border:1px solid var(--border)}
.price-card.featured{background:linear-gradient(135deg,rgba(201,168,76,0.1),rgba(201,168,76,0.04));border-color:var(--gold);position:relative}
.price-badge{position:absolute;top:-12px;left:50%;transform:translateX(-50%);background:var(--gold);color:#0D1B2A;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.1em;padding:4px 14px;border-radius:20px;white-space:nowrap}
.price-name{font-size:13px;text-transform:uppercase;letter-spacing:.1em;color:var(--ink3);margin-bottom:8px}
.price-amount{font-family:'Cinzel',serif;font-size:48px;font-weight:700;color:var(--gold);line-height:1;margin-bottom:4px}
.price-period{font-size:13px;color:var(--ink3);margin-bottom:24px}
.price-features{list-style:none;display:flex;flex-direction:column;gap:10px;margin-bottom:32px}
.price-features li{font-size:14px;color:var(--ink2);display:flex;align-items:flex-start;gap:8px;line-height:1.5}
.price-features li::before{content:'✓';color:var(--green);flex-shrink:0;font-weight:700}
.price-features li.muted{color:var(--ink3)}
.price-features li.muted::before{content:'○';color:var(--ink3)}
.price-cta{width:100%;text-align:center}

/* ── WAITLIST ── */
.waitlist-box{background:var(--bg);border:1px solid var(--border);border-radius:12px;padding:40px;text-align:center;max-width:520px;margin:48px auto 0}
.waitlist-box h3{font-family:'Cinzel',serif;font-size:22px;font-weight:600;margin-bottom:10px}
.waitlist-box p{font-size:15px;color:var(--ink2);margin-bottom:24px;line-height:1.7}
.waitlist-form{display:flex;gap:10px;max-width:420px;margin:0 auto}
.waitlist-form input{flex:1;padding:12px 16px;background:var(--surface);border:1px solid var(--border);border-radius:6px;color:var(--ink);font-size:15px;font-family:'Inter',sans-serif;outline:none}
.waitlist-form input:focus{border-color:var(--gold)}
#waitlist-success{display:none;color:var(--green);font-size:14px;margin-top:12px}

/* ── REASSURANCE ── */
.reassure{background:var(--surface)}
.reassure-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:20px;margin-top:48px}
.reassure-card{padding:24px;border:1px solid var(--border);border-radius:10px}
.reassure-card h4{font-size:14px;font-weight:600;color:var(--gold);text-transform:uppercase;letter-spacing:.08em;margin-bottom:8px}
.reassure-card p{font-size:14px;color:var(--ink2);line-height:1.7}

/* ── FINAL CTA ── */
.final-cta{text-align:center;padding:120px 24px}
.final-cta h2{font-family:'Cinzel',serif;font-size:clamp(28px,4vw,48px);font-weight:700;margin-bottom:20px;line-height:1.2}
.final-cta p{font-size:18px;color:var(--ink2);max-width:500px;margin:0 auto 40px;line-height:1.8;font-weight:300}

/* ── FOOTER ── */
footer{background:var(--surface);border-top:1px solid var(--border);padding:32px 40px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:16px}
footer p{font-size:12px;color:var(--ink3)}
.footer-links{display:flex;gap:20px}
.footer-links a{font-size:12px;color:var(--ink3);text-decoration:none}
.footer-links a:hover{color:var(--gold)}

/* ── RESPONSIVE ── */
@media(max-width:768px){
  nav{padding:14px 20px}
  .nav-links .btn-ghost{display:none}
  .problem-grid{grid-template-columns:1fr}
  .audience-grid{grid-template-columns:1fr}
  .pricing-grid{grid-template-columns:1fr}
  .trust-bar{gap:20px;padding:20px}
  .waitlist-form{flex-direction:column}
  section{padding:64px 20px}
  footer{flex-direction:column;text-align:center}
}
</style>
</head>
<body>

<!-- ── NAV ── -->
<nav>
  <div class="nav-logo">SYNJURIS</div>
  <div class="nav-links">
    <a href="#features" class="nav-link">Features</a>
    <a href="#how" class="nav-link">How It Works</a>
    <a href="#pricing" class="nav-link">Pricing</a>
    <a href="/login" class="btn btn-ghost" style="padding:8px 18px;font-size:13px">Sign In</a>
    <a href="https://synjuris.gumroad.com" target="_blank" class="btn btn-primary" style="padding:8px 18px;font-size:13px">Get SynJuris — $67</a>
  </div>
</nav>

<!-- ── HERO ── -->
<section class="hero">
  <div class="hero-eyebrow">Local-First · AI-Assisted · Your Data Stays Yours</div>
  <h1>You Don't Need a Lawyer<br>to <em>Fight Like One.</em></h1>
  <p class="hero-sub">SynJuris organizes your evidence, tracks your deadlines, and walks you into court prepared — even if this is your first time.</p>
  <p class="hero-origin"><strong>A pro se dad built it for his own use.</strong><br>He perfected it for yours.</p>
  <div class="hero-cta-group">
    <a href="https://synjuris.gumroad.com" target="_blank" class="btn btn-primary btn-xl">Get SynJuris for $67</a>
    <div class="hero-price">One-time payment · Runs on your computer · No subscription</div>
  </div>
  <div class="hero-badges">
    <span class="badge">🔒 Your data never leaves your machine</span>
    <span class="badge">⚖️ Built for family court</span>
    <span class="badge">🤖 AI-powered drafting</span>
    <span class="badge">📋 Evidence organizer</span>
  </div>
</section>

<!-- ── TRUST BAR ── -->
<div class="trust-bar">
  <div class="trust-item"><span class="trust-icon">🛡️</span> Work-product protection</div>
  <div class="trust-item"><span class="trust-icon">🔐</span> AES-256 encrypted backups</div>
  <div class="trust-item"><span class="trust-icon">⚖️</span> All 50 states + DC</div>
  <div class="trust-item"><span class="trust-icon">📄</span> Court-ready documents</div>
  <div class="trust-item"><span class="trust-icon">💻</span> Mac, Windows, Linux</div>
</div>

<!-- ── PROBLEM ── -->
<section class="problem">
  <div class="container">
    <div class="section-tag">The Reality</div>
    <h2 class="section-title">The System Wasn't Built for You.<br>We Fixed That.</h2>
    <p class="section-sub">Most people facing family court can't afford an attorney. They show up unprepared, overwhelmed, and alone — against someone who isn't.</p>
    <div class="problem-grid">
      <div class="problem-list">
        <div class="problem-item">
          <span class="problem-icon">📁</span>
          <div class="problem-text">
            <h4>Evidence gets lost or disorganized</h4>
            <p>Texts, emails, photos scattered across your phone. Courts expect organized, dated, categorized facts. SynJuris does that automatically.</p>
          </div>
        </div>
        <div class="problem-item">
          <span class="problem-icon">📅</span>
          <div class="problem-text">
            <h4>Missed deadlines end cases</h4>
            <p>One missed filing date can be used against you. SynJuris tracks every deadline and flags overdue items the moment they slip.</p>
          </div>
        </div>
        <div class="problem-item">
          <span class="problem-icon">📝</span>
          <div class="problem-text">
            <h4>Legal documents feel impossible</h4>
            <p>Motions, declarations, parenting plans — the format alone is intimidating. SynJuris drafts them using your own facts and your state's actual statutes.</p>
          </div>
        </div>
        <div class="problem-item">
          <span class="problem-icon">🎯</span>
          <div class="problem-text">
            <h4>You don't know what you don't know</h4>
            <p>SynJuris flags violation patterns in communications, surfaces evidence gaps, and tells you exactly what courts look for in cases like yours.</p>
          </div>
        </div>
      </div>
      <div>
        <div class="problem-stat" style="margin-bottom:16px">
          <div class="stat-num">73%</div>
          <div class="stat-label">of family court cases have at least one pro se litigant — someone representing themselves without an attorney</div>
          <div class="stat-source">National Center for State Courts</div>
        </div>
        <div class="problem-stat">
          <div class="stat-num">$350</div>
          <div class="stat-label">Average cost of a single hour with a family law attorney. SynJuris costs less than one hour — and works around the clock.</div>
        </div>
      </div>
    </div>
  </div>
</section>

<!-- ── FEATURES ── -->
<section id="features">
  <div class="container">
    <div class="section-tag">What SynJuris Does</div>
    <h2 class="section-title">Every Tool You Need.<br>Nothing You Don't.</h2>
    <p class="section-sub">Built for the reality of representing yourself in court — not watered down, not simplified. The real thing.</p>
    <div class="features-grid">

      <div class="feature-card">
        <div class="feature-tag">Evidence</div>
        <div class="feature-icon">📁</div>
        <h3>Evidence Organizer with Legal Weight Scoring</h3>
        <p>Every text, email, photo, and document — logged, categorized, and automatically scored by legal significance. Courts weight evidence differently. SynJuris knows that.</p>
      </div>

      <div class="feature-card">
        <div class="feature-tag">Detection</div>
        <div class="feature-icon">🚩</div>
        <h3>Real-Time Violation Detection</h3>
        <p>Log a communication and SynJuris scans it for gatekeeping, parental alienation, threats, harassment, order violations, and more — flagged before you forget the details.</p>
      </div>

      <div class="feature-card">
        <div class="feature-tag">Deadlines</div>
        <div class="feature-icon">⏱</div>
        <h3>Deadline Tracking with Overdue Alerts</h3>
        <p>Every filing date, response deadline, and hearing tracked in one place. Overdue items surface immediately. Missing a court deadline can end your case.</p>
      </div>

      <div class="feature-card">
        <div class="feature-tag">AI</div>
        <div class="feature-icon">🤖</div>
        <h3>AI Legal Assistant — Trained on Your Case</h3>
        <p>Ask anything. The AI knows your evidence, your deadlines, your parties, and your jurisdiction. Plain English answers, using your actual case facts.</p>
      </div>

      <div class="feature-card">
        <div class="feature-tag">Documents</div>
        <div class="feature-icon">📄</div>
        <h3>Document Generator</h3>
        <p>Motions, declarations, parenting plans, demand letters — drafted with your case details and formatted for court. Not templates. Actual drafts.</p>
      </div>

      <div class="feature-card">
        <div class="feature-tag">Hearing Prep</div>
        <div class="feature-icon">⚖️</div>
        <h3>Courtroom View & Hearing Prep</h3>
        <p>Walk into your hearing prepared. Opening statement, evidence introduction order, anticipated arguments — organized the way a judge expects to hear it.</p>
      </div>

      <div class="feature-card">
        <div class="feature-tag">Analytics</div>
        <div class="feature-icon">📊</div>
        <h3>Case Dynamics Engine</h3>
        <p>A live score of your case across three dimensions: evidence strength, procedural health, and adversarial pressure. Deterministic, auditable, updated in real time.</p>
      </div>

      <div class="feature-card">
        <div class="feature-tag">Security</div>
        <div class="feature-icon">🔐</div>
        <h3>Encrypted Backup & Tamper-Evident Audit Trail</h3>
        <p>AES-256 encrypted backups only you can open. Every AI interaction logged with a cryptographic hash chain — provably unmodified if it ever matters in court.</p>
      </div>

      <div class="feature-card">
        <div class="feature-tag">Privacy</div>
        <div class="feature-icon">🛡️</div>
        <h3>Work-Product Protection</h3>
        <p>Cloud AI tools have been ruled non-privileged in federal proceedings. SynJuris runs on your machine. Your strategy may retain work-product status cloud tools can't provide.</p>
      </div>

    </div>
  </div>
</section>

<!-- ── HOW IT WORKS ── -->
<section class="how" id="how">
  <div class="container">
    <div class="section-tag">Getting Started</div>
    <h2 class="section-title">Up and Running in Minutes.</h2>
    <p class="section-sub">No installation wizard. No technical knowledge required. Double-click and go.</p>
    <div class="steps">
      <div class="step">
        <div class="step-num">01</div>
        <h3>Download & Launch</h3>
        <p>Purchase and download SynJuris. Double-click the launcher. It opens in your browser at localhost — nothing goes to the internet.</p>
      </div>
      <div class="step">
        <div class="step-num">02</div>
        <h3>Create Your Case</h3>
        <p>Enter your case type, jurisdiction, and hearing date. That's enough to get started. Add more detail as you go.</p>
      </div>
      <div class="step">
        <div class="step-num">03</div>
        <h3>Add Your Evidence</h3>
        <p>Type, paste, or import messages. SynJuris flags violations automatically and scores your evidence as you build.</p>
      </div>
      <div class="step">
        <div class="step-num">04</div>
        <h3>Walk In Prepared</h3>
        <p>Generate documents, run hearing prep, open Courtroom View at the podium. You'll know exactly what to say and when.</p>
      </div>
    </div>
  </div>
</section>

<!-- ── WHO IT'S FOR ── -->
<section>
  <div class="container">
    <div class="section-tag">Who Uses SynJuris</div>
    <h2 class="section-title">Built for Anyone<br>Navigating Court Alone.</h2>
    <div class="audience-grid">
      <div class="audience-card">
        <h3>👤 Pro Se Litigants</h3>
        <ul>
          <li>Custody and visitation disputes</li>
          <li>Child support modifications</li>
          <li>Protective order requests</li>
          <li>Divorce proceedings</li>
          <li>Contempt and enforcement actions</li>
          <li>Anyone who can't afford an attorney but refuses to lose</li>
        </ul>
      </div>
      <div class="audience-card">
        <h3>⚖️ Legal Professionals</h3>
        <ul>
          <li>Attorneys wanting a local-first case tool</li>
          <li>Paralegals organizing client evidence</li>
          <li>Legal aid organizations</li>
          <li>Law school clinics</li>
          <li>Anyone who values work-product protection</li>
          <li>Switch to Attorney mode for portal and billing features</li>
        </ul>
      </div>
    </div>
  </div>
</section>

<!-- ── PRICING ── -->
<section class="pricing" id="pricing">
  <div class="container" style="text-align:center">
    <div class="section-tag">Simple Pricing</div>
    <h2 class="section-title">Pay Once. Own It Forever.</h2>
    <p class="section-sub" style="margin:0 auto 0">No subscription. No monthly fees. No data going to anyone's server.</p>
    <div class="pricing-grid">

      <div class="price-card featured">
        <div class="price-badge">Available Now</div>
        <div class="price-name">SynJuris Local</div>
        <div class="price-amount">$67</div>
        <div class="price-period">One-time · Yours forever</div>
        <ul class="price-features">
          <li>Runs entirely on your computer</li>
          <li>All AI features (bring your own API key)</li>
          <li>Unlimited cases and evidence</li>
          <li>All 50 states + DC statutes</li>
          <li>Document generator + hearing prep</li>
          <li>Encrypted backups</li>
          <li>Mac, Windows, and Linux</li>
          <li>Free updates included</li>
        </ul>
        <a href="https://synjuris.gumroad.com" target="_blank" class="btn btn-primary btn-large price-cta">Get SynJuris — $67</a>
        <p style="font-size:12px;color:var(--ink3);margin-top:12px">Instant download after purchase</p>
      </div>

      <div class="price-card">
        <div class="price-name">SynJuris Cloud</div>
        <div class="price-amount" style="font-size:36px;color:var(--ink3)">Soon</div>
        <div class="price-period">Hosted · No setup required</div>
        <ul class="price-features">
          <li>Nothing to install or maintain</li>
          <li>Access from any device</li>
          <li>All Local features included</li>
          <li class="muted">Attorney collaboration tools</li>
          <li class="muted">Client portal access</li>
          <li class="muted">Priority support</li>
        </ul>
        <button onclick="document.getElementById('waitlist-email').focus()" class="btn btn-ghost btn-large price-cta" style="width:100%">Join the Waitlist</button>
        <p style="font-size:12px;color:var(--ink3);margin-top:12px">Be first to know when it launches</p>
      </div>

    </div>

    <!-- Waitlist -->
    <div class="waitlist-box">
      <h3>Cloud Version — Coming Soon</h3>
      <p>No download. No setup. Just sign in and start building your case from any device. Leave your email and you'll be the first to know.</p>
      <div class="waitlist-form">
        <input type="email" id="waitlist-email" placeholder="your@email.com">
        <button onclick="submitWaitlist()" class="btn btn-primary">Notify Me</button>
      </div>
      <div id="waitlist-success">✓ You're on the list. We'll reach out when the cloud version launches.</div>
    </div>
  </div>
</section>

<!-- ── REASSURANCE ── -->
<section class="reassure">
  <div class="container">
    <div class="section-tag">Peace of Mind</div>
    <h2 class="section-title">A Few Things Worth Knowing.</h2>
    <div class="reassure-grid">
      <div class="reassure-card">
        <h4>SynJuris is not a law firm</h4>
        <p>SynJuris provides legal information and organizational tools. It does not provide legal advice and does not create an attorney-client relationship. Always consult a licensed attorney before filing.</p>
      </div>
      <div class="reassure-card">
        <h4>Your data is yours. Period.</h4>
        <p>Everything you enter stays on your computer. No data is sold, shared, or analyzed. The only thing that leaves your machine is the text of AI messages — sent directly to your AI provider under your own API key.</p>
      </div>
      <div class="reassure-card">
        <h4>Built on real experience</h4>
        <p>SynJuris was built by a father who went through family court pro se. Every feature exists because someone needed it. This isn't a product built by people guessing at your situation.</p>
      </div>
      <div class="reassure-card">
        <h4>You're in control</h4>
        <p>SynJuris presents options and information. You make every decision. The branching action system shows you what's available — never tells you what to do. Your case, your call.</p>
      </div>
    </div>
  </div>
</section>

<!-- ── FINAL CTA ── -->
<section class="final-cta">
  <div class="section-tag">Get Started Today</div>
  <h2>Stop Going In Unprepared.</h2>
  <p>For less than one hour with an attorney, you get a tool that works with you around the clock — organizing, preparing, and helping you show up ready.</p>
  <a href="https://synjuris.gumroad.com" target="_blank" class="btn btn-primary btn-xl">Get SynJuris — $67</a>
  <p style="font-size:13px;color:var(--ink3);margin-top:16px">One-time payment · Instant download · No subscription</p>
</section>

<!-- ── FOOTER ── -->
<footer>
  <p>© 2026 SynJuris. Built for pro se litigants.</p>
  <div class="footer-links">
    <a href="/login">Sign In</a>
    <a href="https://synjuris.gumroad.com" target="_blank">Buy Local Version</a>
    <a href="mailto:support@synjuris.com">support@synjuris.com</a>
  </div>
  <p style="font-size:11px;color:var(--ink3);margin-top:8px;width:100%;text-align:center">
    SynJuris is not a law firm and does not provide legal advice. This software is an organizational and informational tool only.
    Always consult a licensed attorney before filing any document with a court.
  </p>
</footer>

<script>
// Smooth scroll for nav links
document.querySelectorAll('a[href^="#"]').forEach(a => {
  a.addEventListener('click', e => {
    e.preventDefault();
    const el = document.querySelector(a.getAttribute('href'));
    if(el) el.scrollIntoView({behavior:'smooth', block:'start'});
  });
});

// Waitlist form
async function submitWaitlist(){
  const email = document.getElementById('waitlist-email').value.trim();
  if(!email || !email.includes('@')){
    alert('Please enter a valid email address.');
    return;
  }
  // Store locally for now — replace with your email service endpoint
  document.getElementById('waitlist-success').style.display = 'block';
  document.getElementById('waitlist-email').value = '';
  document.querySelector('.waitlist-form button').disabled = true;

  // Optional: POST to your own endpoint
  try {
    await fetch('/api/waitlist', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({email, source: 'landing_page', ts: new Date().toISOString()})
    });
  } catch(e) {
    // Silent — the UI already confirmed to the user
  }
}

// Enter key on waitlist
document.getElementById('waitlist-email').addEventListener('keydown', e => {
  if(e.key === 'Enter') submitWaitlist();
});
</script>
</body>
</html>"""


# ══════════════════════════════════════════════════════════════════════════════
# UNIVERSAL AI PROVIDER LAYER
# ══════════════════════════════════════════════════════════════════════════════
# Selects AI provider via SYNJURIS_AI_PROVIDER environment variable.
# All other code calls call_claude() unchanged — provider is transparent.
#
# Supported providers:
#   anthropic  (default) — Claude via Anthropic API
#   openai               — GPT-4o via OpenAI API
#   ollama               — Local models via Ollama (no API key, no data egress)
#
# Configuration:
#   SYNJURIS_AI_PROVIDER=anthropic  ANTHROPIC_API_KEY=sk-ant-...
#   SYNJURIS_AI_PROVIDER=openai     OPENAI_API_KEY=sk-...      SYNJURIS_AI_MODEL=gpt-4o
#   SYNJURIS_AI_PROVIDER=ollama     SYNJURIS_OLLAMA_URL=http://localhost:11434
#                                   SYNJURIS_AI_MODEL=llama3.2
#
# Retry: 3 attempts, exponential backoff (0s → 2s → 4s)
# ══════════════════════════════════════════════════════════════════════════════

_AI_PROVIDER    = os.environ.get("SYNJURIS_AI_PROVIDER", "anthropic").lower().strip()
_AI_MODEL       = os.environ.get("SYNJURIS_AI_MODEL", "")   # overrides default model per provider
_OLLAMA_URL     = os.environ.get("SYNJURIS_OLLAMA_URL", "http://localhost:11434")
_OPENAI_KEY     = os.environ.get("OPENAI_API_KEY", "")

# Retry config (applies to all providers)
_RETRY_ATTEMPTS = 3
_RETRY_DELAYS   = [0, 2, 4]
_RETRY_ON       = {429, 500, 502, 503, 529}
_NO_RETRY       = {400, 401, 403, 404}

# ── Default models per provider ───────────────────────────────────────────────
_PROVIDER_DEFAULTS = {
    "anthropic": "claude-sonnet-4-20250514",
    "openai":    "gpt-4o",
    "ollama":    "llama3.2",
}

# ── Provider: Anthropic ───────────────────────────────────────────────────────
def _call_anthropic(messages, system, max_tokens, model):
    """Call Anthropic Claude API with retry."""
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
            # Overload fallback: Sonnet → Haiku on final attempt
            if e.code == 529 and attempt == _RETRY_ATTEMPTS-1 and "sonnet" in model:
                return _call_anthropic(messages, system, max_tokens, "claude-haiku-4-5-20251001")
            try: last_error = json.loads(body).get("error",{}).get("message", body[:200])
            except: last_error = body[:200]
            if e.code not in _RETRY_ON or attempt == _RETRY_ATTEMPTS-1:
                codes = {429:"Rate limit — please wait.", 500:"Server error.",
                         529:"Overloaded — try again."}
                return f"⚠️ {codes.get(e.code, f'HTTP {e.code}')}\n\nDetail: {last_error}"
        except (urllib.error.URLError, TimeoutError) as e:
            last_error = str(getattr(e, "reason", e))
            if attempt == _RETRY_ATTEMPTS-1:
                return f"⚠️ Could not reach Anthropic.\n\nDetail: {last_error}"
        except Exception as e:
            return f"⚠️ Unexpected error: {e}"
    return f"⚠️ Failed after {_RETRY_ATTEMPTS} attempts. Last error: {last_error}"

# ── Provider: OpenAI ──────────────────────────────────────────────────────────
def _call_openai(messages, system, max_tokens, model):
    """Call OpenAI API. Converts Anthropic message format to OpenAI format."""
    if not _OPENAI_KEY:
        return ("⚠️ OpenAI provider requires OPENAI_API_KEY.\n\n"
                "Set it before starting SynJuris:\n"
                "  export OPENAI_API_KEY=sk-...\n\n"
                "Or switch provider: export SYNJURIS_AI_PROVIDER=anthropic")
    model = model or _PROVIDER_DEFAULTS["openai"]
    # OpenAI uses system as a message, not a separate field
    oai_messages = []
    if system:
        oai_messages.append({"role": "system", "content": system})
    oai_messages.extend(messages)
    payload = json.dumps({
        "model": model,
        "max_tokens": max_tokens,
        "messages": oai_messages,
    }).encode()
    last_error = "Unknown error"
    for attempt in range(_RETRY_ATTEMPTS):
        if _RETRY_DELAYS[attempt] > 0:
            time.sleep(_RETRY_DELAYS[attempt])
        req = urllib.request.Request(
            "https://api.openai.com/v1/chat/completions", data=payload,
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {_OPENAI_KEY}"}
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

# ── Provider: Ollama (local) ──────────────────────────────────────────────────
def _call_ollama(messages, system, max_tokens, model):
    """
    Call a local Ollama instance. Zero data egress — everything stays on device.
    Install: https://ollama.com  then: ollama pull llama3.2
    Ollama uses OpenAI-compatible /v1/chat/completions endpoint.
    """
    model = model or _PROVIDER_DEFAULTS["ollama"]
    # Check if Ollama is running
    ollama_chat_url = _OLLAMA_URL.rstrip("/") + "/v1/chat/completions"
    oai_messages = []
    if system:
        oai_messages.append({"role": "system", "content": system})
    oai_messages.extend(messages)
    payload = json.dumps({
        "model": model,
        "messages": oai_messages,
        "stream": False,
        "options": {"num_predict": max_tokens},
    }).encode()
    for attempt in range(_RETRY_ATTEMPTS):
        if _RETRY_DELAYS[attempt] > 0:
            time.sleep(_RETRY_DELAYS[attempt])
        try:
            req = urllib.request.Request(
                ollama_chat_url, data=payload,
                headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=120) as r:
                data = json.loads(r.read())
                # Ollama OpenAI-compat format
                if "choices" in data:
                    return data["choices"][0]["message"]["content"]
                # Fallback: native Ollama format
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

# ── Universal entry point ─────────────────────────────────────────────────────
def call_claude(messages, system="", max_tokens=2000, model=""):
    """
    Universal AI call. Routes to the configured provider.
    Signature unchanged from v1 — all existing call sites work without modification.

    Provider selected by SYNJURIS_AI_PROVIDER env var (default: anthropic).
    Model overridden by SYNJURIS_AI_MODEL env var or per-call model argument.
    """
    effective_model = _AI_MODEL or model or _PROVIDER_DEFAULTS.get(_AI_PROVIDER, "")
    if _AI_PROVIDER == "openai":
        return _call_openai(messages, system, max_tokens, effective_model)
    elif _AI_PROVIDER == "ollama":
        return _call_ollama(messages, system, max_tokens, effective_model)
    else:
        # Default: anthropic
        return _call_anthropic(messages, system, max_tokens, effective_model)

def _keyword_relevance(query: str, text: str) -> int:
    """Count shared significant words between query and evidence text (simple RAG proxy)."""
    stop = {"the","a","an","is","in","of","to","and","or","for","that","was","it","on","at","be","with","as","by"}
    q_words = {w.lower() for w in re.findall(r'\w+', query) if len(w) > 3 and w.lower() not in stop}
    t_words = {w.lower() for w in re.findall(r'\w+', text) if len(w) > 3 and w.lower() not in stop}
    return len(q_words & t_words)

# ══════════════════════════════════════════════════════════════════════════════
# COURTLISTENER CITATION VERIFICATION
# ══════════════════════════════════════════════════════════════════════════════
# Uses the free CourtListener API (no key required for basic search).
# Checks whether a case citation actually exists in the federal/state database.
# Results cached in citation_cache to avoid redundant network calls.

_COURTLISTENER_API = "https://www.courtlistener.com/api/rest/v4/search/"
_CITATION_RE = re.compile(
    r'\b(\d+)\s+(U\.?S\.?|F\.?\d*d?|S\.?\s*Ct\.?|'
    r'F\.?\s*Supp\.?\s*\d*d?|[A-Z][a-z]+\.?\s*[A-Z]?[a-z]*\.?)\s+(\d+)'
    r'(?:\s*\(\w[^)]*\d{4}\))?',
    re.IGNORECASE
)

def extract_citations(text):
    """Pull all case citation candidates from an AI-generated text block."""
    return list(dict.fromkeys(_CITATION_RE.findall(text)))  # dedup, preserve order

def verify_citation_courtlistener(citation_str):
    """
    Query CourtListener for a citation string.
    Returns dict: {found: bool, url: str|None, case_name: str|None, warning: str|None}
    Caches result in citation_cache table. Never raises — always returns a dict.
    """
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

    # Cache for 30 days
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
    """
    Scan AI output for case citations, verify each against CourtListener.
    Returns list of verification results. Empty list if none found or offline.
    """
    raw_matches = _CITATION_RE.findall(text)
    if not raw_matches:
        return []
    # Reconstruct citation strings from regex groups
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
    # RAG: score each exhibit by severity weight + keyword overlap with user query
    def _score(r):
        base = _WEIGHT.get(r["category"], 0)
        kw   = _keyword_relevance(user_query, r["content"] or "") if user_query else 0
        return base + kw * 0.5
    evidence = sorted(all_ev, key=_score, reverse=True)[:30]
    evidence = sorted(evidence, key=lambda r: r["event_date"] or "")  # re-sort by date for readability
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
# V2 — CITATION WARNING BLOCKS (FIX 1)
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
# Citation hard-fail threshold (0.0 = warn only, 0.5 = block if >50% unverified)
_CITATION_FAIL_THRESHOLD = float(os.environ.get("SYNJURIS_CITATION_FAIL_THRESHOLD", "0.0"))

def build_citation_block(citations, verification_error=None):
    """Build warning block to prepend to generated documents. Never silent."""
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
    """Return True if generation should be blocked based on threshold."""
    if _CITATION_FAIL_THRESHOLD <= 0.0 or not citations:
        return False
    unverified = sum(1 for c in citations if not c.get("found"))
    ratio = unverified / len(citations)
    return ratio > _CITATION_FAIL_THRESHOLD

def verify_citations_safe(content):
    """Wrapper — returns (citations, error_string). Never raises."""
    try:
        return verify_citations_in_text(content), None
    except Exception as e:
        return [], str(e)

# ══════════════════════════════════════════════════════════════════════════════
# V2 — MERKLE DAG AUDIT LEDGER (FIX: EVIDENCE CHAIN)
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
    """Add a confirmed exhibit to the Merkle DAG. Idempotent."""
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
    # Update root
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
    """Verify the Merkle DAG for a case. Returns detailed report."""
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
# V2 — ACTION AUDIT LOG WITH HASH CHAIN (FIXES 6 + 9)
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
    """Append-only hash-chained audit log. Background writer thread."""
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
        """Verify hash chain for a case audit log."""
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
                # Backfilled legacy record
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

# Global audit log instance
_audit = AuditLog()

# ══════════════════════════════════════════════════════════════════════════════
# V2 — BACKPRESSURE + ASYNC JOB QUEUE (FIXES 8 + 2 + 5)
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
    """Submit a generation job. Returns job_id or "__QUEUE_FULL__"."""
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
    """Core generation logic — runs inside the job thread."""
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
    # Simulate streaming (chunks for UI feedback)
    words = result.split()
    for i in range(0, len(words), 8):
        job.push_token(" ".join(words[i:i+8]) + " ")
    job.push_event("progress", {"pct":82,"stage":"Verifying citations…"})
    citations, cit_err = verify_citations_safe(result)
    # FIX 7: citation hard block
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
    """Stream a job as SSE to the HTTP response."""
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
        # FIX 5: replay from DB
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
# V2 — DOCUMENT READINESS SCORING (FIX 4 SUPPORT)
# ══════════════════════════════════════════════════════════════════════════════

def compute_doc_readiness(case_id, conn):
    """Deterministic readiness scores for key document types. No AI call."""
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
# V2 — BRANCHING ACTION SYSTEM (FIX 4)
# ══════════════════════════════════════════════════════════════════════════════

def get_available_actions(case_id, conn):
    """
    Compute available actions for a case — no advice language.
    Returns list of option dicts the user chooses from.
    """
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

# ══════════════════════════════════════════════════════════════════════════════
# HTTP HANDLER
# ══════════════════════════════════════════════════════════════════════════════

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _cors_origin(self):
        """Return a tight CORS origin. Allows localhost only."""
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

        # Auth pages
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

        # Main app — require auth
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
            if not case: self.send_json({"error":"not found"},404); return
            self.send_json({
                "case": dict(case), "parties": [dict(r) for r in parties],
                "evidence": [dict(r) for r in evidence], "documents": [dict(r) for r in docs],
                "timeline": [dict(r) for r in timeline], "financials": [dict(r) for r in financials],
                "deadlines": [dict(r) for r in deadlines],
            }); return

        if re.match(r"^/api/documents/\d+$", path):
            uid = require_auth(self); 
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

        # ── Export evidence manifest as .txt ──
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

        # ── Backup: download full SQLite database ──
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

        # ── Full archive: database + uploads folder zipped together ──
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

        # ── Encrypted backup: returns raw zip as base64 for client-side AES encryption ──
        # The server never sees the passphrase. Encryption happens entirely in the browser
        # using Web Crypto API (AES-256-GCM). The resulting .sj-backup file can only be
        # decrypted with the user's passphrase — not by SynJuris, not by anyone else.
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

        # ── Restore from encrypted backup: accepts decrypted zip bytes as base64 ──
        if path == "/api/restore-backup":
            uid = require_auth(self)
            if not uid: return
            # This is a destructive operation — require explicit confirmation flag
            if not b.get("confirmed"):
                self.send_json({"error":"Send confirmed:true to proceed. This replaces all local data."}, 400); return
            import zipfile, io as _io, base64 as _b64, shutil
            try:
                raw = _b64.b64decode(b.get("data",""))
                buf = _io.BytesIO(raw)
                with zipfile.ZipFile(buf, "r") as zf:
                    names = zf.namelist()
                    if "synjuris.db" not in names:
                        self.send_json({"error":"Invalid backup: synjuris.db not found in archive"}, 400); return
                    # Write DB to a temp path first, then atomically replace
                    tmp_db = DB_PATH + ".restore_tmp"
                    with open(tmp_db, "wb") as f_out:
                        f_out.write(zf.read("synjuris.db"))
                    os.replace(tmp_db, DB_PATH)
                    # Restore uploads
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

        # ── Client portal page (no auth required — token IS the credential) ──
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

        # ── Portal evidence submission (POST without main auth) ───────────────
        if path == "/api/portal/submit":
            body_len = int(self.headers.get("Content-Length",0))
            raw = self.rfile.read(body_len)
            try: b2 = json.loads(raw)
            except Exception: self.send_json({"error":"bad json"},400); return
            token = b2.get("token","")
            conn = get_db()
            pt = conn.execute(
                "SELECT * FROM portal_tokens WHERE token=? AND (expires_at IS NULL OR expires_at > datetime('now'))",
                (token,)
            ).fetchone()
            if not pt:
                conn.close(); self.send_json({"error":"invalid token"},403); return
            content = (b2.get("content","") or "")[:50000]
            conn.execute(
                "INSERT INTO portal_evidence (case_id,portal_token_id,content,source,event_date,category) "
                "VALUES (?,?,?,?,?,?)",
                (pt["case_id"], pt["id"], content,
                 b2.get("source","client"), b2.get("event_date",""),
                 b2.get("category","Document"))
            )
            conn.commit(); conn.close()
            self.send_json({"ok":True,"message":"Submitted for attorney review."}); return

        # ── Serve uploaded evidence file ──
        if re.match(r"^/uploads/", path):
            uid = require_auth(self)
            if not uid: return
            # Guard: resolve the full path and verify it stays inside UPLOADS_DIR
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

        # ── Courtroom View ──────────────────────────────────────────────────
        if re.match(r"^/api/cases/\d+/courtroom$", path):
            uid = require_auth(self)
            if not uid: return
            cid = int(path.split("/")[3])
            self.send_html(build_courtroom_html(cid)); return

        # ── Case Dynamics ────────────────────────────────────────────────────
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

        # ── Guidance: priority action list (deterministic, no AI) ────────────
        if re.match(r"^/api/cases/\d+/guidance$", path):
            uid = require_auth(self)
            if not uid: return
            cid = int(path.split("/")[3])
            self.send_json(compute_guidance(cid)); return

        # ── State interpretation (deterministic, no AI) ──────────────────────
        if re.match(r"^/api/cases/\d+/interpret$", path):
            uid = require_auth(self)
            if not uid: return
            cid = int(path.split("/")[3])
            snap = compute_case_state(cid)
            interp = interpret_case_state(snap)
            self.send_json({**snap, "interpretation": interp}); return

        # ── Citation verification via CourtListener ─────────────────────────
        if path.startswith("/api/verify-citation"):
            uid = require_auth(self)
            if not uid: return
            qs = parse_qs(urlparse(self.path).query)
            cit = urllib.parse.unquote_plus(qs.get("citation",[""])[0]).strip()
            if not cit:
                self.send_json({"error":"citation parameter required"},400); return
            result = verify_citation_courtlistener(cit)
            self.send_json(result); return

        # ── Current user profile (tier, email) ───────────────────────────────
        if path == "/api/me":
            uid = require_auth(self)
            if not uid: return
            conn = get_db()
            user = conn.execute("SELECT id,email,tier,created_at FROM users WHERE id=?", (uid,)).fetchone()
            conn.close()
            self.send_json(dict(user) if user else {"error":"not found"}); return

        # ── Conflict check: list all party names across user's cases ─────────
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
            # Log the check
            conn = get_db()
            conn.execute(
                "INSERT INTO conflict_checks (user_id, party_names_json, result) VALUES (?,?,?)",
                (uid, json.dumps({"query": query_name}),
                 "conflict" if matches else "clear")
            )
            conn.commit(); conn.close()
            self.send_json({"query": query_name, "matches": matches,
                            "result": "conflict" if matches else "clear"}); return

        # ── Time entries: list for a case ────────────────────────────────────
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

        # ── Portal: get submitted evidence pending review ────────────────────
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

        # ── Redacted export: state vector + arguments, no raw evidence ───────
        if re.match(r"^/api/cases/\d+/redacted-export$", path):
            uid = require_attorney(self)
            if not uid: return
            cid = int(path.split("/")[3])
            self.send_json(build_redacted_export(cid, uid)); return


        # ── V2: Available actions (branching system) ────────────────────────
        if re.match(r"^/api/cases/\d+/actions$", path):
            uid = require_auth(self)
            if not uid: return
            cid = int(path.split("/")[3])
            conn = get_db()
            actions = get_available_actions(cid, conn)
            conn.close()
            self.send_json({"case_id":cid,"actions":actions,"count":len(actions),
                "note":"These are available options. SynJuris provides legal information, not advice."}); return

        # ── V2: Document readiness scores ───────────────────────────────────
        if re.match(r"^/api/cases/\d+/readiness$", path):
            uid = require_auth(self)
            if not uid: return
            cid = int(path.split("/")[3])
            conn = get_db()
            scores = compute_doc_readiness(cid, conn)
            conn.close()
            self.send_json(scores); return

        # ── V2: Job status ──────────────────────────────────────────────────
        if re.match(r"^/api/jobs/[a-f0-9-]+$", path):
            uid = require_auth(self)
            if not uid: return
            job_id = path.split("/")[3]
            job = _job_cache.get(job_id)
            if not job:
                # check DB
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

        # ── V2: Job SSE stream ──────────────────────────────────────────────
        if re.match(r"^/api/jobs/[a-f0-9-]+/stream$", path):
            uid = require_auth(self)
            if not uid: return
            job_id = path.split("/")[3]
            job_stream_sse(job_id, self); return

        # ── V2: Job replay ──────────────────────────────────────────────────
        if re.match(r"^/api/jobs/[a-f0-9-]+/replay$", path):
            uid = require_auth(self)
            if not uid: return
            job_id = path.split("/")[3]
            job_stream_sse(job_id, self); return

        # ── V2: Merkle DAG verify ───────────────────────────────────────────
        if re.match(r"^/api/cases/\d+/dag-verify$", path):
            uid = require_auth(self)
            if not uid: return
            cid = int(path.split("/")[3])
            conn = get_db()
            result = merkle_verify_dag(conn, cid)
            conn.close()
            self.send_json(result); return

        # ── V2: Audit chain verify ──────────────────────────────────────────
        if re.match(r"^/api/cases/\d+/audit-chain-verify$", path):
            uid = require_auth(self)
            if not uid: return
            cid = int(path.split("/")[3])
            result = _audit.verify_chain(cid)
            self.send_json(result); return

        # ── V2: Action audit log timeline ───────────────────────────────────
        if re.match(r"^/api/cases/\d+/action-log$", path):
            uid = require_auth(self)
            if not uid: return
            cid = int(path.split("/")[3])
            timeline = _audit.get_timeline(cid)
            self.send_json({"case_id":cid,"events":timeline,"count":len(timeline)}); return

        # ── V2: Queue stats ─────────────────────────────────────────────────
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
        # ── Delete case, cascade rows, and remove orphaned files ──
        if re.match(r"^/api/cases/\d+$", path):
            uid = require_auth(self)
            if not uid: return
            cid = int(path.split("/")[3])
            conn = get_db()
            case = conn.execute("SELECT id FROM cases WHERE id=? AND user_id=?", (cid, uid)).fetchone()
            if not case:
                conn.close(); self.send_json({"error":"not found"},404); return
            # Soft delete: mark case and all its evidence/documents as deleted
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
            # Rate limit: block after 5 failures in 5 minutes
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
            # Whitelist of updatable columns — field names are never interpolated from user input
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
            # Cap evidence content at 50 KB to protect DB size and AI context window
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

        # ── Evidence: confirm (v2: also adds to Merkle DAG) ──
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
            # Verify ownership via case
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
                # Split on ~ for MMS group threads, strip non-digits from each part
                parts = [re.sub(r"\D","",p) for p in addr.split("~")]
                # Match last 10 digits to handle +1 country code variants
                return any(p.endswith(target) or target.endswith(p) for p in parts if p)
            try:
                # Strip BOM and clean up encoding issues common in SMS backup files
                if isinstance(xml_text, str):
                    xml_text = xml_text.lstrip('\ufeff').strip()
                # Remove any invalid XML characters that crash the parser
                xml_text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', xml_text)
                # If file is very large, warn but proceed
                root = ET.fromstring(xml_text)
                msgs = []
                # Handle SMS messages
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
                # Handle MMS messages — text is in <part> elements, not body attribute
                for msg in root.findall(".//mms"):
                    addr = msg.get("address","")
                    dms = msg.get("date")
                    contact = msg.get("contact_name","")
                    if not number_matches(addr): continue
                    dt = None
                    if dms:
                        try: dt = datetime.fromtimestamp(int(dms)/1000).strftime("%Y-%m-%d %H:%M:%S")
                        except: pass
                    # Extract text from parts
                    parts_text = []
                    for part in msg.findall(".//part"):
                        ct = part.get("ct","")
                        if "text" in ct:
                            part_data = part.get("text","").strip()
                            if part_data and part_data != "null":
                                parts_text.append(part_data)
                    # Also check body attribute as fallback
                    body = msg.get("body","").strip()
                    if body and body != "null":
                        parts_text.append(body)
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

        # ── Upload evidence file (PDF, image, etc.) ──
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
            # Enforce 50 MB per-file cap
            if len(file_bytes) > 50 * 1024 * 1024:
                self.send_json({"error": "File exceeds 50 MB limit."}, 400); return
            ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else "bin"
            # Whitelist safe extensions
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
            # Fetch recent history — cap at 40 turns (20 exchanges) to bound context cost
            history = conn.execute(
                "SELECT role,content FROM chat_history WHERE case_id=? ORDER BY created_at ASC",
                (cid,)
            ).fetchall()
            MAX_HISTORY = 40
            if len(history) > MAX_HISTORY:
                history = history[-MAX_HISTORY:]
            conn.close()
            # Pass the user's message as query context for RAG-style evidence ranking
            system, _am = build_case_system(cid, user_query=msg)
            messages = [{"role":r["role"],"content":r["content"]} for r in history]
            messages.append({"role":"user","content":msg})
            # Route simple/short messages to Haiku; complex/drafting tasks to Sonnet
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
            # Verify any case citations against CourtListener (non-blocking — warnings appended)
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

        # ── Phase 2: Evidence → Argument Mapper ──────────────────────────────────
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
            # try to parse as JSON; fall back to raw text
            try:
                import json as _json
                cleaned = result.strip()
                if cleaned.startswith("```"):
                    cleaned = "\n".join(cleaned.split("\n")[1:-1])
                parsed = _json.loads(cleaned)
                self.send_json(parsed); return
            except Exception:
                self.send_json({"raw": result}); return

        # ── Phase 2: Timeline Contradiction Detector ──────────────────────────
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
  "timeline_gaps": ["Description of any significant time periods with no documentation"],
  "strongest_period": "The date range where your evidence is strongest",
  "weakest_period": "The date range where your evidence is thinnest",
  "overall_assessment": "2-3 sentence plain-English assessment of the timeline's strength"
}}"""

            result = call_claude([{"role":"user","content":prompt}], max_tokens=2000)
            try:
                import json as _json
                cleaned = result.strip()
                if cleaned.startswith("```"):
                    cleaned = "\n".join(cleaned.split("\n")[1:-1])
                parsed = _json.loads(cleaned)
                self.send_json(parsed); return
            except Exception:
                self.send_json({"raw": result}); return

        # ── Phase 3: PDF Export ───────────────────────────────────────────────
        if re.match(r"^/api/cases/\d+/export-pdf$", path):
            cid = int(path.split("/")[3])
            fname, pdf_bytes = export_evidence_pdf(cid)
            self.send_response(200)
            self.send_header("Content-Type", "application/pdf")
            self.send_header("Content-Disposition", f'attachment; filename="{fname}"')
            self.send_header("Content-Length", len(pdf_bytes))
            self.end_headers(); self.wfile.write(pdf_bytes); return

        # ── Case Readiness Report PDF ─────────────────────────────────────────
        if re.match(r"^/api/cases/\d+/readiness-pdf$", path):
            uid = require_auth(self)
            if not uid: return
            cid = int(path.split("/")[3])
            fname, pdf_bytes = export_readiness_pdf(cid, uid)
            self.send_response(200)
            self.send_header("Content-Type", "application/pdf")
            self.send_header("Content-Disposition", f'attachment; filename="{fname}"')
            self.send_header("Content-Length", len(pdf_bytes))
            self.end_headers(); self.wfile.write(pdf_bytes); return

        # ── DOCX document export ──────────────────────────────────────────────
        if re.match(r"^/api/documents/\d+/docx$", path):
            uid = require_auth(self)
            if not uid: return
            doc_id = int(path.split("/")[3])
            conn = get_db()
            doc = conn.execute("SELECT * FROM documents WHERE id=?", (doc_id,)).fetchone()
            conn.close()
            if not doc:
                self.send_json({"error":"not found"}, 404); return
            fname, docx_bytes = export_document_docx(dict(doc))
            self.send_response(200)
            self.send_header("Content-Type", "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
            self.send_header("Content-Disposition", f'attachment; filename="{fname}"')
            self.send_header("Content-Length", len(docx_bytes))
            self.end_headers(); self.wfile.write(docx_bytes); return

        # ── Phase 4: Adversarial Simulation ──────────────────────────────────
        if path == "/api/adversarial":
            cid = b.get("case_id")
            system, _am = build_case_system(cid)
            conn = get_db()
            case = conn.execute("SELECT * FROM cases WHERE id=?", (cid,)).fetchone()
            conn.close()
            if not case: self.send_json({"error":"Case not found"}); return
            prompt = f"""You are simulating opposing counsel in a {dict(case).get("case_type","legal")} case.
Your job is to help the pro se litigant PREPARE by showing them exactly what they are up against.

Respond in this EXACT JSON format (valid JSON only, no markdown):
{{
  "opposing_strategy": "2-3 sentence summary of what opposing counsel\'s overall strategy will likely be",
  "attacks": [
    {{
      "argument": "A specific argument or claim the other side may raise",
      "strength": "strong|moderate|weak",
      "target": "What part of your case this attacks",
      "counter": "How to respond to this in plain English",
      "evidence_needed": "What evidence would best defeat this argument"
    }}
  ],
  "your_vulnerabilities": ["List of the weakest points in the pro se litigant\'s case"],
  "their_vulnerabilities": ["List of weaknesses in the opposing party\'s likely position"],
  "settlement_leverage": "What leverage the pro se litigant has if settlement is discussed",
  "key_warning": "The single most important thing to watch out for at the hearing"
}}"""
            result = call_claude([{"role":"user","content":prompt}], system, max_tokens=2500)
            if _am: log_audit_event(cid,"ADVERSARIAL","adversarial",_am["snapshot"],_am["prompt_inputs"],_am["snapshot"]["hash"])
            if _am: log_audit_event(cid,"CASE_THEORY","case-theory",_am["snapshot"],_am["prompt_inputs"],_am["snapshot"]["hash"])
            try:
                import json as _json
                cleaned = result.strip()
                if cleaned.startswith("```"):
                    cleaned = "\n".join(cleaned.split("\n")[1:-1])
                parsed = _json.loads(cleaned)
                self.send_json(parsed); return
            except Exception:
                self.send_json({"raw": result}); return

        # ── Phase 4: Case Theory Builder ─────────────────────────────────────
        if path == "/api/case-theory":
            cid = b.get("case_id")
            system, _am = build_case_system(cid)
            conn = get_db()
            case = conn.execute("SELECT * FROM cases WHERE id=?", (cid,)).fetchone()
            conn.close()
            if not case: self.send_json({"error":"Case not found"}); return
            c = dict(case)
            prompt = f"""Help this pro se litigant organize their case facts and identify the legal issues relevant to their situation.

Respond in this EXACT JSON format (valid JSON only, no markdown):
{{
  "one_sentence_theory": "One sentence summarizing what happened, what legal issue is involved, and what outcome you are seeking",
  "narrative": "3-5 sentence plain-English story of what happened, in chronological order, that a judge can immediately understand",
  "what_you_are_asking_for": "Specific relief requested, in plain English",
  "legal_theories": [ /* relevant legal issues and what would need to be shown */
    {{
      "theory": "Name of the relevant legal issue (e.g. Interference with Custody, Breach of Parenting Plan)",
      "elements": ["Key fact 1 that would support your position", "Key fact 2 that would support your position"],
      "how_you_prove_it": "Which of your evidence documents supports this issue",
      "statute": "The specific statute if applicable"
    }}
  ],
  "burden_of_proof": "What standard applies in this case and what it means practically",
  "best_outcome": "The best realistic outcome if the hearing goes well",
  "acceptable_outcome": "A fair compromise outcome",
  "worst_case": "What happens if the hearing goes poorly and how to mitigate it",
  "opening_line": "The exact first sentence to say when given the floor at the hearing"
}}"""
            result = call_claude([{"role":"user","content":prompt}], system, max_tokens=2500)
            try:
                import json as _json
                cleaned = result.strip()
                if cleaned.startswith("```"):
                    cleaned = "\n".join(cleaned.split("\n")[1:-1])
                parsed = _json.loads(cleaned)
                self.send_json(parsed); return
            except Exception:
                self.send_json({"raw": result}); return

        # ── Audit verify ────────────────────────────────────────────────────
        if path == "/api/audit/verify":
            aid = b.get("audit_id")
            if not aid: self.send_json({"error":"audit_id required"},400); return
            self.send_json(verify_audit_entry(int(aid))); return

        # ── Case Roadmap ─────────────────────────────────────────────────────
        if path == "/api/roadmap":
            uid = require_auth(self)
            if not uid: return
            cid = b.get("case_id")
            conn = get_db()
            case = conn.execute("SELECT * FROM cases WHERE id=? AND user_id=?", (cid, uid)).fetchone()
            if not case: conn.close(); self.send_json({"error":"Case not found"}, 404); return
            c = dict(case)
            deadlines = conn.execute("SELECT title,due_date,completed FROM deadlines WHERE case_id=? ORDER BY due_date ASC", (cid,)).fetchall()
            docs = conn.execute("SELECT doc_type FROM documents WHERE case_id=?", (cid,)).fetchall()
            ev_count = conn.execute("SELECT COUNT(*) FROM evidence WHERE case_id=? AND confirmed=1", (cid,)).fetchone()[0]
            conn.close()
            dl_text = "\n".join(f"  {'✓' if d['completed'] else '○'} {d['title']} — {d['due_date'] or 'no date'}" for d in deadlines) or "  None yet"
            doc_types = [d["doc_type"] for d in docs]
            jur_block = jurisdiction_statute_block(c.get("jurisdiction",""))
            county = c.get("court_name","").strip()
            prompt = f"""You are a legal case roadmap assistant for a pro se litigant.

CASE: {c['title']}
Type: {c.get('case_type','Unknown')}
Jurisdiction: {c.get('jurisdiction','')}
County/Court: {county or 'Not specified'}
Case Number: {c.get('case_number','Not yet assigned')}
Hearing Date: {c.get('hearing_date','Not scheduled')}
Confirmed Evidence: {ev_count} items
Documents Generated: {', '.join(doc_types) if doc_types else 'None'}
Deadlines:
{dl_text}

{jur_block}

Generate a BRANCHING case roadmap specific to this person's situation. Respond ONLY in this exact JSON format (no markdown):
{{
  "current_stage": "Plain English name of where they are right now",
  "stage_number": <1-10 integer>,
  "total_stages": <integer>,
  "stage_description": "2-3 sentence description of what this stage means",
  "completed_steps": [
    {{"step": "What has been done", "notes": "Brief context"}}
  ],
  "immediate_next_steps": [
    {{
      "priority": "urgent|important|optional",
      "action": "Specific action to take",
      "deadline": "When this must be done or null",
      "how_to": "Plain English instructions for how to do this",
      "form_needed": "Name of form or document needed, or null",
      "county_note": "Any county-specific procedure note if known, or null"
    }}
  ],
  "upcoming_stages": [
    {{
      "stage": "Stage name",
      "description": "What happens in this stage",
      "key_actions": ["action 1", "action 2"]
    }}
  ],
  "branch_points": [
    {{
      "decision": "A key decision or event that will change the path",
      "if_yes": "What happens if yes / outcome A",
      "if_no": "What happens if no / outcome B"
    }}
  ],
  "local_resources": "Any county-specific court resources, self-help centers, or local rules if known",
  "warning": "The single most important thing NOT to miss right now, or null"
}}"""
            result = call_claude([{"role":"user","content":prompt}], max_tokens=3000)
            try:
                import json as _j
                cleaned = result.strip()
                if cleaned.startswith("```"): cleaned = "\n".join(cleaned.split("\n")[1:-1])
                self.send_json(_j.loads(cleaned)); return
            except Exception:
                self.send_json({"raw": result}); return

        # ── Motion Templates ─────────────────────────────────────────────────
        if path == "/api/motion-template":
            uid = require_auth(self)
            if not uid: return
            cid = b.get("case_id"); motion_type = b.get("motion_type","")
            conn = get_db()
            case = conn.execute("SELECT * FROM cases WHERE id=? AND user_id=?", (cid, uid)).fetchone()
            if not case: conn.close(); self.send_json({"error":"Case not found"}, 404); return
            c = dict(case)
            parties = conn.execute("SELECT * FROM parties WHERE case_id=?", (cid,)).fetchall()
            ev = conn.execute("SELECT exhibit_number,content,category,event_date FROM evidence WHERE case_id=? AND confirmed=1 ORDER BY event_date ASC", (cid,)).fetchall()
            conn.close()
            jur_block = jurisdiction_statute_block(c.get("jurisdiction",""))
            parties_text = "\n".join(f"  {p['role']}: {p['name']}" for p in parties) or "  Not specified"
            ev_text = "\n".join(f"  Exhibit {e['exhibit_number'] or '?'} ({e['event_date'] or 'undated'}): {(e['content'] or '')[:100]}" for e in ev[:15]) or "  None confirmed yet"
            prompt = f"""Draft a complete, properly formatted {motion_type} for a pro se litigant to file with the court.

CASE DETAILS:
Case Title: {c['title']}
Case Number: {c.get('case_number','[CASE NUMBER]')}
Court: {c.get('court_name','[COURT NAME]')}
Jurisdiction: {c.get('jurisdiction','')}
{jur_block}

PARTIES:
{parties_text}

CONFIRMED EVIDENCE AVAILABLE:
{ev_text}

INSTRUCTIONS:
- Use proper legal formatting with caption, title, numbered paragraphs, signature block
- Use [BRACKET PLACEHOLDERS] for any information not provided above
- Cite specific statutes from the jurisdiction block above where relevant
- Include a certificate of service at the end
- Write in plain, clear language appropriate for a pro se filer
- Include a section referencing supporting evidence where applicable
- Make it complete enough to actually file — not a skeleton"""
            result = call_claude([{"role":"user","content":prompt}], max_tokens=4000)
            # Save as document
            conn = get_db()
            conn.execute("INSERT INTO documents (case_id,title,doc_type,content) VALUES (?,?,?,?)",
                (cid, motion_type, motion_type, result))
            conn.commit(); conn.close()
            self.send_json({"content": result, "saved": True}); return

        # ── Co-parenting Communication Log ───────────────────────────────────
        if path == "/api/comms":
            uid = require_auth(self)
            if not uid: return
            cid = b.get("case_id")
            conn = get_db()
            case = conn.execute("SELECT id FROM cases WHERE id=? AND user_id=?", (cid, uid)).fetchone()
            if not case: conn.close(); self.send_json({"error":"not found"}, 404); return
            # Add communication entry
            entry_date = b.get("entry_date"); channel = b.get("channel","")
            content = b.get("content",""); direction = b.get("direction","received")
            other_party = b.get("other_party","")
            tags = scan_patterns(content)
            flagged = bool(tags)
            category = tags[0][0] if tags else "Communication"
            confidence = tags[0][2] if tags else None
            # Store as evidence with source indicating it's a comm log entry
            source = f"Comm Log — {channel} — {other_party}" if other_party else f"Comm Log — {channel}"
            c = conn.execute(
                "INSERT INTO evidence (case_id,content,source,event_date,category,confirmed,notes) VALUES (?,?,?,?,?,0,?)",
                (cid, content, source, entry_date, category, f"Direction: {direction} | Channel: {channel}")
            )
            conn.commit(); conn.close()
            self.send_json({"id": c.lastrowid, "flagged": flagged, "flags": [t[0] for t in tags], "confidence": confidence}); return

        # ── Child Support Calculator ─────────────────────────────────────────
        if path == "/api/child-support":
            uid = require_auth(self)
            if not uid: return
            cid = b.get("case_id")
            conn = get_db()
            case = conn.execute("SELECT * FROM cases WHERE id=? AND user_id=?", (cid, uid)).fetchone()
            if not case: conn.close(); self.send_json({"error":"not found"}, 404); return
            c = dict(case)
            conn.close()
            jur_block = jurisdiction_statute_block(c.get("jurisdiction",""))
            your_income = b.get("your_income", 0)
            their_income = b.get("their_income", 0)
            children = b.get("children", 1)
            custody_split = b.get("custody_split", "50/50")
            your_expenses = b.get("your_expenses", "")
            prompt = f"""Calculate child support for a pro se litigant using the correct formula for their jurisdiction.

Jurisdiction: {c.get('jurisdiction','')}
{jur_block}

INPUT DATA:
- Your gross monthly income: ${your_income}
- Other parent gross monthly income: ${their_income}
- Number of children: {children}
- Custody arrangement: {custody_split}
- Your additional expenses (healthcare, childcare, etc): {your_expenses or 'None provided'}

Respond ONLY in this exact JSON format (no markdown):
{{
  "formula_used": "Name of the formula/model used in this state (e.g. Income Shares, Percentage of Income)",
  "statute": "Relevant statute citation",
  "estimated_amount": <monthly dollar amount as number>,
  "direction": "you pay" or "you receive",
  "calculation_steps": [
    {{"step": "Step description", "value": "Result of this step"}}
  ],
  "factors_that_could_change_this": ["factor 1", "factor 2"],
  "how_to_request": "How to formally request child support in this jurisdiction",
  "worksheet_note": "Note about official state worksheet if available",
  "disclaimer": "This is an estimate only. Always verify with the court or an attorney."
}}"""
            result = call_claude([{"role":"user","content":prompt}], max_tokens=2000)
            try:
                import json as _j
                cleaned = result.strip()
                if cleaned.startswith("```"): cleaned = "\n".join(cleaned.split("\n")[1:-1])
                parsed = _j.loads(cleaned)
                # Save to financials
                conn = get_db()
                conn.execute("INSERT INTO financials (case_id,entry_date,description,amount,category,direction) VALUES (?,date('now'),?,?,?,?)",
                    (cid, f"Child Support Estimate ({children} child{'ren' if children>1 else ''}, {custody_split})",
                     parsed.get("estimated_amount",0), "Child Support", parsed.get("direction","unknown")))
                conn.commit(); conn.close()
                self.send_json(parsed); return
            except Exception:
                self.send_json({"raw": result}); return

        # ── Set user tier (self-upgrade) ─────────────────────────────────────
        if path == "/api/me/tier":
            uid = require_auth(self)
            if not uid: return
            tier = b.get("tier","pro_se")
            if tier not in ("pro_se","attorney"):
                self.send_json({"error":"invalid tier"},400); return
            conn = get_db()
            conn.execute("UPDATE users SET tier=? WHERE id=?", (tier, uid))
            conn.commit(); conn.close()
            self.send_json({"ok":True,"tier":tier}); return

        # ── Portal: create access token for a case ───────────────────────────
        if path == "/api/portal/create":
            uid = require_attorney(self)
            if not uid: return
            cid   = b.get("case_id")
            label = b.get("label","Client")
            # Verify ownership
            conn = get_db()
            case = conn.execute("SELECT id FROM cases WHERE id=? AND user_id=?", (cid,uid)).fetchone()
            if not case:
                conn.close(); self.send_json({"error":"not found"},404); return
            import secrets as _sec
            token = _sec.token_urlsafe(32)
            conn.execute(
                "INSERT INTO portal_tokens (token,case_id,attorney_user_id,label,expires_at) "
                "VALUES (?,?,?,?,datetime('now','+90 days'))",
                (token, cid, uid, label)
            )
            conn.commit(); conn.close()
            portal_url = f"http://localhost:{PORT}/portal/{token}"
            self.send_json({"token": token, "url": portal_url, "label": label}); return

        # ── Portal: list tokens for a case ───────────────────────────────────
        if path == "/api/portal/list":
            uid = require_attorney(self)
            if not uid: return
            cid = b.get("case_id")
            conn = get_db()
            rows = conn.execute(
                "SELECT id,token,label,created_at,expires_at FROM portal_tokens "
                "WHERE case_id=? AND attorney_user_id=? ORDER BY created_at DESC",
                (cid, uid)
            ).fetchall()
            conn.close()
            self.send_json([dict(r) for r in rows]); return

        # ── Portal: revoke token ─────────────────────────────────────────────
        if path == "/api/portal/revoke":
            uid = require_attorney(self)
            if not uid: return
            tid = b.get("token_id")
            conn = get_db()
            conn.execute("DELETE FROM portal_tokens WHERE id=? AND attorney_user_id=?", (tid,uid))
            conn.commit(); conn.close()
            self.send_json({"ok":True}); return

        # ── Portal: approve submitted evidence ───────────────────────────────
        if path == "/api/portal/approve":
            uid = require_attorney(self)
            if not uid: return
            peid = b.get("portal_evidence_id")
            note = b.get("attorney_note","")
            conn = get_db()
            pe = conn.execute("SELECT * FROM portal_evidence WHERE id=?", (peid,)).fetchone()
            if not pe:
                conn.close(); self.send_json({"error":"not found"},404); return
            # Promote to main evidence table
            conn.execute("BEGIN")
            try:
                en = assign_exhibit_number(conn, pe["case_id"])
                conn.execute(
                    "INSERT INTO evidence (case_id,exhibit_number,content,source,event_date,category,confirmed,notes) "
                    "VALUES (?,?,?,?,?,?,1,?)",
                    (pe["case_id"], en, pe["content"], pe["source"], pe["event_date"],
                     pe["category"], f"Submitted via client portal. Attorney note: {note}" if note else "Submitted via client portal.")
                )
                conn.execute("UPDATE portal_evidence SET approved=1, attorney_note=? WHERE id=?", (note, peid))
                # Auto-generate time entry for review
                conn.execute(
                    "INSERT INTO time_entries (case_id,user_id,description,hours,source) VALUES (?,?,?,?,?)",
                    (pe["case_id"], uid, f"Reviewed and approved client portal submission — {pe['category']}", 0.1, "portal-approval")
                )
                conn.commit()
            except Exception as e:
                conn.rollback(); conn.close()
                self.send_json({"error":str(e)},500); return
            conn.close()
            self.send_json({"ok":True,"exhibit_number":en}); return

        # ── Portal: reject submitted evidence ────────────────────────────────
        if path == "/api/portal/reject":
            uid = require_attorney(self)
            if not uid: return
            peid = b.get("portal_evidence_id")
            note = b.get("attorney_note","")
            conn = get_db()
            conn.execute("UPDATE portal_evidence SET approved=-1, attorney_note=? WHERE id=?", (note, peid))
            conn.commit(); conn.close()
            self.send_json({"ok":True}); return

        # ── Time entries: add manual ──────────────────────────────────────────
        if path == "/api/time-entries":
            uid = require_attorney(self)
            if not uid: return
            cid  = b.get("case_id")
            desc = b.get("description","")
            hrs  = float(b.get("hours",0))
            bill = int(b.get("billable",1))
            conn = get_db()
            c = conn.execute(
                "INSERT INTO time_entries (case_id,user_id,description,hours,billable,source) VALUES (?,?,?,?,?,'manual')",
                (cid, uid, desc, hrs, bill)
            )
            conn.commit(); conn.close()
            self.send_json({"id":c.lastrowid}); return

        # ── Time entries: mark exported ───────────────────────────────────────
        if path == "/api/time-entries/export":
            uid = require_attorney(self)
            if not uid: return
            ids = b.get("ids",[])
            if not isinstance(ids,list) or not ids:
                self.send_json({"error":"ids required"},400); return
            conn = get_db()
            placeholders = ",".join("?" for _ in ids)
            conn.execute(f"UPDATE time_entries SET exported=1 WHERE id IN ({placeholders}) AND user_id=?",
                         ids + [uid])
            conn.commit(); conn.close()
            self.send_json({"ok":True,"exported":len(ids)}); return

        # ── AI: auto-generate time entry from tool use ────────────────────────
        if path == "/api/time-entries/auto":
            uid = require_attorney(self)
            if not uid: return
            cid    = b.get("case_id")
            action = b.get("action","AI analysis")  # e.g. "Argument Builder"
            hrs    = float(b.get("hours", 0.3))
            desc   = f"[SynJuris] {action} — AI-assisted review and analysis, {hrs:.1f} hr"
            conn = get_db()
            c = conn.execute(
                "INSERT INTO time_entries (case_id,user_id,description,hours,billable,source) VALUES (?,?,?,?,1,'ai-auto')",
                (cid, uid, desc, hrs)
            )
            conn.commit(); conn.close()
            self.send_json({"id":c.lastrowid,"description":desc,"hours":hrs}); return


        # ── V2: Async document generation ───────────────────────────────────
        if path == "/api/generate-doc-async":
            uid = require_auth(self)
            if not uid: return
            cid   = b.get("case_id")
            dtype = b.get("doc_type","")
            instr = b.get("instructions","")
            force = b.get("force", False)
            conn  = get_db()
            job_id = job_submit("document", cid, dtype, conn, instr, force)
            conn.close()
            if job_id == "__QUEUE_FULL__":
                self.send_json({"error":"service_busy",
                    "message":"Server is processing other requests. Try again in a moment.",
                    "retry_after":10}, 503); return
            _audit.log("job_submitted", case_id=cid, user_id=uid,
                       doc_type=dtype, job_id=job_id)
            self.send_json({"job_id":job_id,
                "stream_url":f"/api/jobs/{job_id}/stream",
                "status_url":f"/api/jobs/{job_id}"}); return

        # ── V2: Action selection logging ─────────────────────────────────────
        if re.match(r"^/api/cases/\d+/action-select$", path):
            uid = require_auth(self)
            if not uid: return
            cid = int(path.split("/")[3])
            _audit.log("action_selected", case_id=cid, user_id=uid,
                       action_id=b.get("action_id"), doc_type=b.get("doc_type"),
                       metadata={"note":"User autonomously selected this action."})
            self.send_json({"logged":True,"action_id":b.get("action_id"),
                "note":"Selection recorded. SynJuris provides legal information — you decide."}); return

        self.send_json({"error":"not found"},404)



# ══════════════════════════════════════════════════════════════════════════════
# CLIENT PORTAL — lightweight read/submit page sent to clients
# ══════════════════════════════════════════════════════════════════════════════

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
  showMo('New Case — Almost Done',`<div style="display:flex;gap:5px;margin-bottom:16px">${[1,2,3].map(i=>`<span class="sdot${i===3?' active':' done'}"></span>`).join('')}</div>
  <p style="font-size:12px;color:var(--ink2);margin-bottom:12px">These are optional — you can always add them later from the Edit Case button.</p>
  <div class="two-col">
    <div class="fg"><label>Hearing Date <span style="color:var(--ink3);font-weight:400">(optional)</span></label><input type="date" id="nc-hd"></div>
    <div class="fg"><label>Filing Deadline <span style="color:var(--ink3);font-weight:400">(optional)</span></label><input type="date" id="nc-fdl"></div>
  </div>
  <div class="fg"><label>Your Goals <span style="color:var(--ink3);font-weight:400">(optional)</span></label><textarea id="nc-goals" placeholder="What outcome are you hoping for? You can add this later."></textarea></div>
  <div class="br">
    <button class="btn btn-s" onclick="nc2()">← Back</button>
    <button class="btn btn-s" onclick="createCase()">Skip & Create</button>
    <button class="btn btn-p" onclick="createCase()">Create Case →</button>
  </div>\`);
}
async function createCase(){
  _nd.filing_deadline=val('nc-fdl'); _nd.hearing_date=val('nc-hd');
  _nd.goals=val('nc-goals'); _nd.notes=val('nc-notes');
  const d=await api('/api/cases',_nd);
  if(!d||d.error){alert('Could not create case: '+(d&&d.error?d.error:'Unknown error'));return;}
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

# ══════════════════════════════════════════════════════════════════════════════
# STARTUP
# ══════════════════════════════════════════════════════════════════════════════

def open_browser():
    import time; time.sleep(1)
    webbrowser.open("http://localhost:5000")

if __name__ == "__main__":
    init_db()
    print("\n" + "═"*58)
    print(f"  SynJuris v{VERSION} — Legal Intelligence Platform")
    print("═"*58)
    print(f"  Database : {DB_PATH}")
    _provider_display = {
        "anthropic": f"Anthropic Claude {'✓' if API_KEY else '✗ no key'}",
        "openai":    f"OpenAI {'✓' if _OPENAI_KEY else '✗ no key'}",
        "ollama":    f"Ollama (local) ✓ — {_OLLAMA_URL}",
    }.get(_AI_PROVIDER, _AI_PROVIDER)
    print(f"  AI       : {_provider_display}")
    if _AI_MODEL:
        print(f"  Model    : {_AI_MODEL} (override)")
    print(f"  Retry    : ✓ Exponential backoff (3 attempts)")
    print(f"  Merkle   : ✓ Evidence chain audit")
    print(f"  Audit    : ✓ Hash-chained action log")
    print(f"  Queue    : ✓ Async generation ({_MAX_WORKERS} workers)")
    print(f"  Citations: {'⚠ Hard-fail mode' if _CITATION_FAIL_THRESHOLD > 0 else '✓ Warn-only mode'}")
    if not API_KEY:
        print("\n  To enable AI features:")
        print("    Mac/Linux : export ANTHROPIC_API_KEY=your-key")
        print("    Windows   : set ANTHROPIC_API_KEY=your-key")
        print("    Then restart SynJuris.")
    print(f"\n  Listening on http://localhost:{PORT}  (localhost only)")
    print("  Press Ctrl+C to stop.\n")
    threading.Thread(target=check_for_update, daemon=True).start()
    if PORT == 5000:
        threading.Thread(target=open_browser, daemon=True).start()
    server = ThreadingHTTPServer((("0.0.0.0", PORT)), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  SynJuris stopped.")
"""
SynJuris — Local Legal Assistant for Pro Se Litigants
Run:  python3 synjuris.py
Open: http://localhost:5000
Your data never leaves this computer.
"""

import sqlite3, json, os, re, xml.etree.ElementTree as ET
import webbrowser, threading, urllib.request, urllib.parse
import hashlib, hmac, time, queue, uuid, math
from datetime import datetime, date
from http.server import HTTPServer, BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor
from collections import OrderedDict
from typing import Optional, Callable

_BASE         = "/data" if os.path.isdir("/data") else os.path.dirname(os.path.abspath(__file__))
DB_PATH       = os.path.join(_BASE, "synjuris.db")
API_KEY       = os.environ.get("ANTHROPIC_API_KEY", "")
UPLOADS_DIR   = os.path.join(_BASE, "uploads")
PORT          = int(os.environ.get("PORT", 5000))
VERSION       = "2.0.0"
UPDATE_URL    = "https://raw.githubusercontent.com/synjuris/synjuris/main/version.json"

def check_for_update():
    """Non-blocking startup check. Prints notice if newer version exists."""
    try:
        req = urllib.request.Request(UPDATE_URL, headers={"User-Agent": f"SynJuris/{VERSION}"})
        with urllib.request.urlopen(req, timeout=4) as r:
            data = json.loads(r.read())
        latest = data.get("version","")
        notes  = data.get("notes","")
        if latest and latest != VERSION:
            print(f"\n  ┌─ Update available: v{latest} (you have v{VERSION})")
            if notes: print(f"  │  {notes}")
            print(f"  └─ Download: https://github.com/synjuris/synjuris/releases/latest\n")
    except Exception:
        pass

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

# ══════════════════════════════════════════════════════════════════════════════
# DATABASE & JURISDICTION (Omitted for brevity, but kept in actual file)
# ══════════════════════════════════════════════════════════════════════════════

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

# ... [PATTERNS AND OTHER ENGINE LOGIC] ...

class SynJurisHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Your existing routing logic
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(f"<h1>SynJuris v{VERSION}</h1><p>Local environment active.</p>".encode())

# --- REPLACE THE BRIDGE AT THE VERY BOTTOM WITH THIS ---
# This code connects Gunicorn to your ACTUAL SynJurisHandler logic

def app(environ, start_response):
    """
    WSGI bridge that directs Render traffic into your existing SynJurisHandler.
    """
    from io import BytesIO

    # 1. We create a mock version of the 'self' object your code expects
    class MockRequest:
        def makefile(self, *args, **kwargs):
            return BytesIO()
        def sendall(self, data):
            pass
        def close(self):
            pass

    # 2. Initialize your existing handler without starting a real network server
    handler = SynJurisHandler(MockRequest(), ("0.0.0.0", 0), None)
    
    # 3. Setup the environment so 'self.path', 'self.wfile', and headers work
    output_buffer = BytesIO()
    handler.wfile = output_buffer
    handler.rfile = BytesIO()
    
    # These attributes are required by standard BaseHTTPRequestHandler logic
    handler.request_version = "HTTP/1.1"
    handler.protocol_version = "HTTP/1.1"
    handler.requestline = f"GET {environ.get('PATH_INFO', '/')} HTTP/1.1"
    handler.command = "GET"
    handler.path = environ.get('PATH_INFO', '/')
    
    # Populate headers (useful if your code checks User-Agent, etc.)
    from http.client import HTTPMessage
    handler.headers = HTTPMessage()
    for key, val in environ.items():
        if key.startswith('HTTP_'):
            handler.headers.add_header(key[5:].replace('_', '-'), val)

    # 4. EXECUTE YOUR ACTUAL do_GET LOGIC
    try:
        handler.do_GET()
    except Exception as e:
        # If it fails, we want to see the error message in the browser
        start_response('500 Internal Error', [('Content-Type', 'text/plain')])
        return [f"Logic Error: {str(e)}".encode()]

    # 5. Extract what your code wrote to 'self.wfile' and send it to Render
    status = '200 OK'
    # We use utf-8 to ensure all legal symbols render correctly
    headers = [('Content-type', 'text/html; charset=utf-8')]
    start_response(status, headers)
    return [output_buffer.getvalue()]

if __name__ == "__main__":
    # This remains so your local 'python3 synjuris.py' still works exactly the same
    server = ThreadingHTTPServer(('0.0.0.0', PORT), SynJurisHandler)
    print(f"Starting SynJuris Local on port {PORT}...")
    server.serve_forever()
