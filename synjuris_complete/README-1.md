# SynJuris

**Legal case organizer for people who can't afford a lawyer.**

SynJuris helps you build your case file, understand relevant legal patterns, and prepare documents — so you walk into court or a lawyer's office ready.

> **Not legal advice.** SynJuris is an organizational and drafting tool, not a law firm. Nothing here constitutes legal advice. Consult a licensed attorney before filing any document or making legal decisions.

---

## What it does

- **Organize evidence** — log exhibits, confirm them, seal each one into a cryptographic chain
- **Detect patterns** — flags potentially relevant legal research categories as you type
- **Draft documents** — AI-generated drafts based on your actual evidence, labeled as drafts requiring attorney review
- **Track deadlines** — hearing countdowns, overdue alerts, procedural health scoring
- **Share securely** — generate a read-only portal link for an attorney or advisor
- **Export proof** — court-presentable Merkle DAG integrity statement as a PDF

---

## Run

```bash
# Clone
git clone https://github.com/Synjuris/synjuris
cd synjuris

# Install optional dependency (enables proof PDF export)
pip install reportlab

# Run
ANTHROPIC_API_KEY=your-key-here python3 synjuris_master.py
```

Open: **http://localhost:5000**

On Mac you can also double-click `launch_synjuris_mac.command`.
On Windows double-click `launch_synjuris_windows.bat`.

---

## API key

Get a free Anthropic API key at [console.anthropic.com](https://console.anthropic.com).
AI features are disabled without a key — everything else still works.

---

## Files

```
synjuris_master.py        Main server — everything in one file
static/
  login.html              Login screen
  onboarding.html         Case setup wizard
  dashboard.html          Main workspace
requirements.txt          Dependencies
version.json              Version info
launch_synjuris_mac.command
launch_synjuris_windows.bat
```

---

## API endpoints

```
GET  /                    Dashboard UI
GET  /login               Login UI
GET  /onboarding          Case setup wizard
GET  /portal/:token       Read-only case summary (shareable)
GET  /static/*            Static assets

GET  /health
GET  /api/cases
POST /api/cases
GET  /api/cases/:id
GET  /api/cases/:id/state
GET  /api/cases/:id/readiness
GET  /api/cases/:id/merkle
GET  /api/cases/:id/audit
GET  /api/jurisdictions
GET  /api/jurisdictions/:state

POST /api/cases/:id/evidence
POST /api/cases/:id/evidence/:id/confirm
POST /api/cases/:id/deadlines
POST /api/cases/:id/chat
POST /api/cases/:id/portal-token
POST /api/cases/:id/portal-token/revoke
POST /api/cases/:id/dag-proof
POST /api/ai/analyze
POST /api/score
POST /api/greyrockfilter
POST /api/docs
POST /api/disclaimer/ack
```

---

## Legal notice

SynJuris is not a law firm and does not provide legal advice. Pattern detection output is labeled as research indicators only — not legal findings. All AI-generated documents are drafts that require review by a licensed attorney before filing. Disclaimer acceptance is logged with a timestamp.
