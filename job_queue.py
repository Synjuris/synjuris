"""
job_queue.py — SynJuris v2 Async Generation Queue + Streaming SSE
==================================================================
Replaces blocking AI API calls with an async task queue that:

1. Accepts generation requests and returns a job_id immediately
2. Executes the generation in a background thread
3. Streams tokens to the UI via Server-Sent Events (SSE)
4. Caches results for speculative pre-generation
5. Is idempotent: same (case_id, doc_type, evidence_hash) → same job_id

Speculative pre-generation rules (triggers automatically):
  - 10+ confirmed exhibits + hearing within 30 days → pre-gen Hearing Prep Guide
  - State z >= 6 + no Motion for Contempt generated → pre-gen that motion
  - Any new confirmed exhibit → re-run readiness scoring silently

Architecture:
  JobQueue (singleton) → ThreadPoolExecutor → Claude API call → SSE stream
  Results stored in memory (LRU cache, max 50 jobs) + SQLite for persistence

Thread safety: all queue operations use threading.Lock().
SSE format follows the W3C EventSource spec.
"""

import json
import time
import uuid
import hashlib
import threading
import queue
import logging
from typing import Optional, Callable, Generator
from concurrent.futures import ThreadPoolExecutor
from collections import OrderedDict
from datetime import datetime, date

logger = logging.getLogger(__name__)

# ── Job states ────────────────────────────────────────────────────────────────

class JobState:
    PENDING    = "pending"
    RUNNING    = "running"
    COMPLETE   = "complete"
    FAILED     = "failed"
    CACHED     = "cached"


# ── Job record ────────────────────────────────────────────────────────────────

class Job:
    def __init__(self, job_id: str, job_type: str, case_id: int,
                 doc_type: str, evidence_hash: str, instructions: str = ""):
        self.job_id        = job_id
        self.job_type      = job_type   # "document", "hearing_prep", "motion", "chat"
        self.case_id       = case_id
        self.doc_type      = doc_type
        self.evidence_hash = evidence_hash
        self.instructions  = instructions
        self.state         = JobState.PENDING
        self.created_at    = datetime.utcnow().isoformat()
        self.started_at:   Optional[str] = None
        self.completed_at: Optional[str] = None
        self.result:       Optional[str] = None
        self.error:        Optional[str] = None
        self.citations:    list = []
        self.doc_id:       Optional[int] = None
        self.progress_pct: int = 0

        # SSE token stream — ring buffer, max 10000 tokens
        self._stream_tokens: list[str] = []
        self._stream_lock   = threading.Lock()
        self._stream_done   = threading.Event()
        self._subscribers:  list[queue.Queue] = []
        self._sub_lock      = threading.Lock()

    def push_token(self, token: str) -> None:
        """Called by the generation thread to push a token to all subscribers."""
        with self._stream_lock:
            self._stream_tokens.append(token)
        with self._sub_lock:
            for q in self._subscribers:
                try:
                    q.put_nowait(("token", token))
                except queue.Full:
                    pass

    def push_event(self, event: str, data: dict) -> None:
        """Push a named SSE event (progress, complete, error)."""
        with self._sub_lock:
            for q in self._subscribers:
                try:
                    q.put_nowait((event, data))
                except queue.Full:
                    pass

    def mark_complete(self, result: str, citations: list, doc_id: Optional[int] = None) -> None:
        self.state        = JobState.COMPLETE
        self.result       = result
        self.citations    = citations
        self.doc_id       = doc_id
        self.completed_at = datetime.utcnow().isoformat()
        self._stream_done.set()
        self.push_event("complete", {
            "job_id": self.job_id,
            "doc_id": doc_id,
            "citation_count": len(citations),
        })

    def mark_failed(self, error: str) -> None:
        self.state        = JobState.FAILED
        self.error        = error
        self.completed_at = datetime.utcnow().isoformat()
        self._stream_done.set()
        self.push_event("error", {"job_id": self.job_id, "error": error})

    def subscribe(self) -> "SSEStream":
        """Subscribe to the token stream. Returns an SSEStream iterator."""
        sub_q: queue.Queue = queue.Queue(maxsize=5000)
        with self._sub_lock:
            self._subscribers.append(sub_q)
        # Replay already-streamed tokens
        with self._stream_lock:
            buffered = list(self._stream_tokens)
        return SSEStream(sub_q, buffered, self._stream_done,
                         already_done=(self.state in (JobState.COMPLETE, JobState.FAILED)))

    def to_dict(self) -> dict:
        return {
            "job_id":       self.job_id,
            "job_type":     self.job_type,
            "doc_type":     self.doc_type,
            "case_id":      self.case_id,
            "state":        self.state,
            "progress_pct": self.progress_pct,
            "created_at":   self.created_at,
            "started_at":   self.started_at,
            "completed_at": self.completed_at,
            "doc_id":       self.doc_id,
            "error":        self.error,
            "token_count":  len(self._stream_tokens),
        }


# ── SSE stream iterator ───────────────────────────────────────────────────────

class SSEStream:
    """
    Iterator that yields SSE-formatted lines.
    Conforms to the W3C EventSource spec.

    Yields strings like:
      data: {"type": "token", "text": "The "}\n\n
      data: {"type": "complete", "doc_id": 42}\n\n
    """

    def __init__(self, q: queue.Queue, buffered: list[str],
                 done_event: threading.Event, already_done: bool = False):
        self._q           = q
        self._buffered    = buffered
        self._done_event  = done_event
        self._already_done = already_done

    def __iter__(self) -> Generator[str, None, None]:
        # Replay buffered tokens first
        for token in self._buffered:
            yield self._format("token", {"text": token})

        if self._already_done:
            yield self._format("done", {})
            return

        # Stream live events
        while True:
            try:
                event_type, data = self._q.get(timeout=30.0)
                if event_type == "token":
                    yield self._format("token", {"text": data})
                elif event_type == "complete":
                    yield self._format("complete", data)
                    yield self._format("done", {})
                    return
                elif event_type == "error":
                    yield self._format("error", data)
                    return
                else:
                    yield self._format(event_type, data if isinstance(data, dict) else {"data": data})
            except queue.Empty:
                # Heartbeat to keep connection alive
                yield ": heartbeat\n\n"
                if self._done_event.is_set():
                    yield self._format("done", {})
                    return

    @staticmethod
    def _format(event: str, data: dict) -> str:
        payload = json.dumps({"type": event, **data}, separators=(",", ":"))
        return f"data: {payload}\n\n"


# ── LRU job cache ─────────────────────────────────────────────────────────────

class LRUJobCache:
    """Thread-safe LRU cache for Job objects, keyed by job_id and dedup_key."""

    def __init__(self, max_size: int = 100):
        self._max  = max_size
        self._by_id:  OrderedDict[str, Job] = OrderedDict()
        self._by_key: dict[str, str] = {}  # dedup_key → job_id
        self._lock = threading.Lock()

    def put(self, job: Job, dedup_key: Optional[str] = None) -> None:
        with self._lock:
            self._by_id[job.job_id] = job
            self._by_id.move_to_end(job.job_id)
            if dedup_key:
                self._by_key[dedup_key] = job.job_id
            if len(self._by_id) > self._max:
                oldest_id, oldest_job = self._by_id.popitem(last=False)
                # Remove dedup key if present
                for k, v in list(self._by_key.items()):
                    if v == oldest_id:
                        del self._by_key[k]

    def get(self, job_id: str) -> Optional[Job]:
        with self._lock:
            return self._by_id.get(job_id)

    def get_by_key(self, dedup_key: str) -> Optional[Job]:
        with self._lock:
            jid = self._by_key.get(dedup_key)
            return self._by_id.get(jid) if jid else None

    def all_jobs(self) -> list[Job]:
        with self._lock:
            return list(self._by_id.values())


# ── Evidence hash (deduplication key) ────────────────────────────────────────

def compute_evidence_hash(conn, case_id: int) -> str:
    """
    Compute a stable hash of the current confirmed evidence set.
    Used as the dedup key: same evidence → same job → cached result.
    """
    rows = conn.execute(
        "SELECT id, content, event_date, category FROM evidence "
        "WHERE case_id=? AND confirmed=1 AND (is_deleted IS NULL OR is_deleted=0) "
        "ORDER BY id ASC",
        (case_id,)
    ).fetchall()
    payload = json.dumps([
        {"id": r[0], "content_hash": hashlib.md5((r[1] or "").encode()).hexdigest(),
         "date": r[2] or "", "cat": r[3] or ""}
        for r in rows
    ], separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()[:32]


# ── Main job queue ────────────────────────────────────────────────────────────

class JobQueue:
    """
    Singleton async job queue for AI generation tasks.

    Usage:
        queue = JobQueue.get_instance(call_claude_fn, get_db_fn)
        job_id = queue.submit("document", case_id, "Motion for Contempt", conn)
        stream = queue.get_stream(job_id)
    """

    _instance: Optional["JobQueue"] = None
    _lock      = threading.Lock()

    @classmethod
    def get_instance(cls, call_claude_fn: Callable, get_db_fn: Callable,
                     build_case_system_fn: Callable,
                     verify_citations_fn: Callable) -> "JobQueue":
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls(call_claude_fn, get_db_fn,
                                    build_case_system_fn, verify_citations_fn)
        return cls._instance

    def __init__(self, call_claude_fn: Callable, get_db_fn: Callable,
                 build_case_system_fn: Callable, verify_citations_fn: Callable):
        self._call_claude  = call_claude_fn
        self._get_db       = get_db_fn
        self._build_system = build_case_system_fn
        self._verify_cits  = verify_citations_fn
        self._cache        = LRUJobCache(max_size=100)
        self._executor     = ThreadPoolExecutor(max_workers=4, thread_name_prefix="synjuris-gen")
        self._speculative_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="synjuris-spec")

    # ── Public API ────────────────────────────────────────────────────────────

    def submit(self, job_type: str, case_id: int, doc_type: str,
               conn, instructions: str = "",
               force: bool = False) -> str:
        """
        Submit a generation job. Returns job_id immediately.
        If an identical job exists and is complete, returns cached job_id.
        """
        ev_hash  = compute_evidence_hash(conn, case_id)
        dedup_key = f"{case_id}:{doc_type}:{ev_hash}"

        if not force:
            existing = self._cache.get_by_key(dedup_key)
            if existing and existing.state == JobState.COMPLETE:
                existing.state = JobState.CACHED
                return existing.job_id
            if existing and existing.state in (JobState.PENDING, JobState.RUNNING):
                return existing.job_id

        job = Job(
            job_id        = str(uuid.uuid4()),
            job_type      = job_type,
            case_id       = case_id,
            doc_type      = doc_type,
            evidence_hash = ev_hash,
            instructions  = instructions,
        )
        self._cache.put(job, dedup_key)
        self._executor.submit(self._run_job, job)
        return job.job_id

    def get_job(self, job_id: str) -> Optional[Job]:
        return self._cache.get(job_id)

    def get_stream(self, job_id: str) -> Optional[SSEStream]:
        job = self._cache.get(job_id)
        if not job:
            return None
        return job.subscribe()

    def trigger_speculative(self, case_id: int, conn) -> list[str]:
        """
        Check if any documents should be speculatively pre-generated.
        Called after each evidence confirmation. Non-blocking.
        Returns list of pre-generated job_ids.
        """
        triggered = []
        try:
            from readiness_engine import compute_readiness_scores
            scores = compute_readiness_scores(case_id, conn)

            for doc_type, score_data in scores.items():
                if score_data.get("score", 0) >= 90 and score_data.get("speculative", False):
                    ev_hash   = compute_evidence_hash(conn, case_id)
                    dedup_key = f"{case_id}:{doc_type}:{ev_hash}"
                    existing  = self._cache.get_by_key(dedup_key)
                    if not existing:
                        job = Job(
                            job_id        = str(uuid.uuid4()),
                            job_type      = "document",
                            case_id       = case_id,
                            doc_type      = doc_type,
                            evidence_hash = ev_hash,
                            instructions  = "(speculative pre-generation)",
                        )
                        self._cache.put(job, dedup_key)
                        self._speculative_executor.submit(self._run_job, job)
                        triggered.append(job.job_id)
                        logger.info(f"Speculative pre-gen: {doc_type} for case {case_id}")
        except Exception as e:
            logger.warning(f"Speculative pre-gen check failed: {e}")
        return triggered

    # ── Job execution ─────────────────────────────────────────────────────────

    def _run_job(self, job: Job) -> None:
        """Execute a generation job. Runs in a thread pool thread."""
        job.state      = JobState.RUNNING
        job.started_at = datetime.utcnow().isoformat()
        job.push_event("progress", {"job_id": job.job_id, "pct": 5, "stage": "Starting…"})

        try:
            conn = self._get_db()
            try:
                if job.job_type == "document":
                    self._run_document_job(job, conn)
                elif job.job_type == "hearing_prep":
                    self._run_hearing_prep_job(job, conn)
                elif job.job_type == "motion":
                    self._run_motion_job(job, conn)
                elif job.job_type == "chat":
                    self._run_chat_job(job, conn)
                else:
                    raise ValueError(f"Unknown job type: {job.job_type}")
            finally:
                conn.close()
        except Exception as e:
            logger.exception(f"Job {job.job_id} failed: {e}")
            job.mark_failed(str(e))

    def _run_document_job(self, job: Job, conn) -> None:
        """Multi-stage document generation pipeline."""
        job.push_event("progress", {"pct": 10, "stage": "Building case context…"})

        # Stage 1: Build context
        case     = conn.execute("SELECT * FROM cases WHERE id=?", (job.case_id,)).fetchone()
        parties  = conn.execute("SELECT * FROM parties WHERE case_id=?", (job.case_id,)).fetchall()
        evidence = conn.execute(
            "SELECT exhibit_number,content,category,event_date FROM evidence "
            "WHERE case_id=? AND confirmed=1 ORDER BY event_date ASC",
            (job.case_id,)
        ).fetchall()

        if not case:
            job.mark_failed("Case not found")
            return

        from jurisdiction_helpers import jurisdiction_statute_block  # imported from main server
        c = dict(case)
        jur_block   = jurisdiction_statute_block(c.get('jurisdiction', ''))
        party_lines = "\n".join(
            f"  {p['role'] if hasattr(p,'__getitem__') else p[1]}: "
            f"{p['name'] if hasattr(p,'__getitem__') else p[0]}"
            for p in parties
        ) or "  Not specified"
        ev_lines = "\n".join(
            f"[{e['exhibit_number'] if hasattr(e,'__getitem__') else e[0] or 'unnum'}] "
            f"[{e['event_date'] if hasattr(e,'__getitem__') else e[3] or 'undated'}] "
            f"({e['category'] if hasattr(e,'__getitem__') else e[2]}): "
            f"{(e['content'] if hasattr(e,'__getitem__') else e[1] or '')[:300]}"
            for e in evidence[:25]
        ) or "  None confirmed."

        job.push_event("progress", {"pct": 20, "stage": "Drafting document…"})

        prompt = f"""Draft a complete {job.doc_type} for a pro se litigant.

CASE DETAILS
  Title: {c.get('title')}
  Type: {c.get('case_type')}
  {jur_block}
  Court: {c.get('court_name') or '[COURT NAME]'}
  Case number: {c.get('case_number') or '[CASE NUMBER]'}

PARTIES
{party_lines}

CONFIRMED EVIDENCE
{ev_lines}

SPECIAL INSTRUCTIONS
{job.instructions or 'None.'}

FORMAT REQUIREMENTS:
- Use proper court document format with caption, title, body, and signature block
- Use [BRACKET PLACEHOLDERS] for any information not provided above
- Write in clear, plain English
- Include specific references to evidence by exhibit number where relevant
- Add a certificate of service at the end
- This is for a pro se filer — make it professional but accessible"""

        # Stage 2: Stream generation
        content = self._stream_generation(job, [{"role": "user", "content": prompt}],
                                           "", max_tokens=3000, start_pct=20, end_pct=80)

        job.push_event("progress", {"pct": 82, "stage": "Verifying citations…"})

        # Stage 3: Citation verification
        citations = []
        try:
            citations = self._verify_cits(content)
        except Exception as e:
            logger.warning(f"Citation verification failed: {e}")

        job.push_event("progress", {"pct": 90, "stage": "Saving document…"})

        # Stage 4: Persist
        from datetime import datetime as _dt
        doc_title = f"{job.doc_type} — {_dt.now().strftime('%b %d %Y')}"
        cur = conn.execute(
            "INSERT INTO documents (case_id,title,doc_type,content) VALUES (?,?,?,?)",
            (job.case_id, doc_title, job.doc_type, content)
        )
        conn.commit()
        doc_id = cur.lastrowid

        job.push_event("progress", {"pct": 100, "stage": "Complete"})
        job.mark_complete(content, citations, doc_id)

    def _run_hearing_prep_job(self, job: Job, conn) -> None:
        job.push_event("progress", {"pct": 10, "stage": "Analyzing case…"})

        system, _am = self._build_system(job.case_id, user_query="hearing preparation")
        prompt = """Generate a comprehensive hearing preparation and organization guide. Include:

1. OPENING STATEMENT DRAFT (60 seconds, clear and factual)
2. KEY POINTS TO MAKE (numbered, in order of importance)
3. YOUR EVIDENCE SUMMARY (how to introduce each exhibit)
4. ANTICIPATED ARGUMENTS FROM OTHER SIDE (and how to respond)
5. QUESTIONS TO ASK (if cross-examining)
6. WHAT NOT TO SAY (common pro se mistakes)
7. COURTROOM ETIQUETTE
8. WHAT TO BRING (complete checklist)
9. IF THE JUDGE ASKS YOU... (common questions and answers)
10. EMERGENCY FALLBACK (if things go badly)

Be specific to THIS case and jurisdiction. Plain English throughout."""

        job.push_event("progress", {"pct": 20, "stage": "Drafting guide…"})
        content = self._stream_generation(job, [{"role": "user", "content": prompt}],
                                           system, max_tokens=3000, start_pct=20, end_pct=90)

        disclaimer = ("\n\n---\n*SynJuris provides legal information and organizational tools only"
                      " — not legal advice. Always consult a licensed attorney before filing.*")
        content += disclaimer

        from datetime import datetime as _dt
        cur = conn.execute(
            "INSERT INTO documents (case_id,title,doc_type,content) VALUES (?,?,?,?)",
            (job.case_id, f"Hearing Prep Guide — {_dt.now().strftime('%b %d %Y')}",
             "Hearing Prep Guide", content)
        )
        conn.commit()
        job.mark_complete(content, [], cur.lastrowid)

    def _run_motion_job(self, job: Job, conn) -> None:
        job.push_event("progress", {"pct": 10, "stage": "Building motion…"})

        case     = conn.execute("SELECT * FROM cases WHERE id=?", (job.case_id,)).fetchone()
        parties  = conn.execute("SELECT * FROM parties WHERE case_id=?", (job.case_id,)).fetchall()
        evidence = conn.execute(
            "SELECT exhibit_number,content,category,event_date FROM evidence "
            "WHERE case_id=? AND confirmed=1 ORDER BY event_date ASC",
            (job.case_id,)
        ).fetchall()

        if not case:
            job.mark_failed("Case not found")
            return

        c = dict(case)
        from jurisdiction_helpers import jurisdiction_statute_block
        jur_block = jurisdiction_statute_block(c.get('jurisdiction', ''))

        ev_text = "\n".join(
            f"  Exhibit {e['exhibit_number'] or '?'} ({e['event_date'] or 'undated'}): "
            f"{(e['content'] or '')[:100]}"
            for e in evidence[:15]
        ) or "  None confirmed yet"

        party_text = "\n".join(
            f"  {p['role'] if hasattr(p,'__getitem__') else p[1]}: "
            f"{p['name'] if hasattr(p,'__getitem__') else p[0]}"
            for p in parties
        ) or "  Not specified"

        prompt = f"""Draft a complete, properly formatted {job.doc_type} for a pro se litigant.

CASE DETAILS:
Case Title: {c.get('title')}
Case Number: {c.get('case_number','[CASE NUMBER]')}
Court: {c.get('court_name','[COURT NAME]')}
{jur_block}

PARTIES:
{party_text}

CONFIRMED EVIDENCE:
{ev_text}

{job.instructions or ''}

Draft a complete, court-ready motion. Use [BRACKET PLACEHOLDERS] for missing info.
Include a certificate of service. Plain English throughout."""

        job.push_event("progress", {"pct": 20, "stage": "Drafting motion…"})
        content = self._stream_generation(job, [{"role": "user", "content": prompt}],
                                           "", max_tokens=4000, start_pct=20, end_pct=90)

        from datetime import datetime as _dt
        cur = conn.execute(
            "INSERT INTO documents (case_id,title,doc_type,content) VALUES (?,?,?,?)",
            (job.case_id, job.doc_type, job.doc_type, content)
        )
        conn.commit()
        job.mark_complete(content, [], cur.lastrowid)

    def _run_chat_job(self, job: Job, conn) -> None:
        """Chat is handled inline (stateful), but routed here for streaming."""
        pass  # Chat streaming handled separately in the HTTP handler

    def _stream_generation(self, job: Job, messages: list, system: str,
                            max_tokens: int = 2000,
                            start_pct: int = 20, end_pct: int = 90) -> str:
        """
        Call the Claude API with streaming enabled (if available) or fall back
        to the blocking call and simulate token streaming.
        Returns the complete generated text.
        """
        # Try streaming API first
        full_text = self._try_streaming_call(job, messages, system, max_tokens,
                                              start_pct, end_pct)
        if full_text is not None:
            return full_text

        # Fallback: blocking call with simulated streaming
        result = self._call_claude(messages, system, max_tokens)

        # Simulate streaming by chunking the result
        words = result.split()
        chunk_size = 5
        pct_range = end_pct - start_pct

        for i in range(0, len(words), chunk_size):
            chunk = " ".join(words[i:i + chunk_size])
            if i + chunk_size < len(words):
                chunk += " "
            job.push_token(chunk)
            pct = start_pct + int((i / max(len(words), 1)) * pct_range)
            if i % 50 == 0:
                job.push_event("progress", {"pct": pct, "stage": "Generating…"})

        return result

    def _try_streaming_call(self, job: Job, messages: list, system: str,
                             max_tokens: int, start_pct: int, end_pct: int) -> Optional[str]:
        """
        Attempt a streaming API call. Returns full text if successful, None if not available.
        Requires the Anthropic SDK (not the urllib implementation in the main server).
        """
        try:
            import anthropic
            import os
            api_key = os.environ.get("ANTHROPIC_API_KEY", "")
            if not api_key:
                return None

            client  = anthropic.Anthropic(api_key=api_key)
            model   = "claude-sonnet-4-5-20251001"
            full_text = ""
            pct_range = end_pct - start_pct
            char_count = 0
            estimated_total = max_tokens * 4  # rough chars estimate

            kwargs = {"model": model, "max_tokens": max_tokens, "messages": messages}
            if system:
                kwargs["system"] = system

            with client.messages.stream(**kwargs) as stream:
                for text_chunk in stream.text_stream:
                    full_text  += text_chunk
                    char_count += len(text_chunk)
                    job.push_token(text_chunk)
                    pct = start_pct + int(min(char_count / estimated_total, 1.0) * pct_range)
                    job.progress_pct = pct

            return full_text

        except ImportError:
            return None  # anthropic SDK not installed, use urllib fallback
        except Exception as e:
            logger.warning(f"Streaming API call failed: {e}")
            return None


# ── HTTP handler helpers ───────────────────────────────────────────────────────

def format_sse_response(stream: SSEStream):
    """
    Generator that formats an SSEStream for HTTP response.
    Use with a chunked transfer encoding response.
    """
    yield from stream


def job_status_response(job: Optional[Job]) -> dict:
    """Convert a Job to a JSON-serializable status dict."""
    if not job:
        return {"error": "Job not found"}
    d = job.to_dict()
    if job.state == JobState.COMPLETE:
        d["result_preview"] = (job.result or "")[:200] + "…" if job.result else ""
        d["doc_id"] = job.doc_id
        d["citations"] = job.citations
    return d
