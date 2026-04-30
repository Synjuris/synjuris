# SynJuris v2 — Complete Build

## Files

```
synjuris_master.py     Main server — run this
static/
  login.html           Login + brand screen
  onboarding.html      3-step case setup wizard
  dashboard.html       Main case workspace
requirements.txt       Optional dependencies
```

## Run

```bash
# Minimal (no PDF export)
ANTHROPIC_API_KEY=your-key python3 synjuris_master.py

# With proof PDF export
pip install reportlab
ANTHROPIC_API_KEY=your-key python3 synjuris_master.py
```

Open: http://localhost:5000

## New in v2

| Feature | Endpoint |
|---|---|
| Dashboard UI | GET / |
| Login UI | GET /login |
| Onboarding wizard | GET /onboarding |
| Read-only case portal | GET /portal/:token |
| Merkle proof PDF | POST /api/cases/:id/dag-proof |
| Exhibit confirm + seal | POST /api/cases/:id/evidence/:id/confirm |
| Share link | POST /api/cases/:id/portal-token |
| Disclaimer logging | POST /api/disclaimer/ack |
| Security headers (CSP) | All responses |

## UPL Safeguards

Every screen carries an explicit disclaimer. Pattern detection
output is labeled "research indicator — not a legal finding"
throughout. AI responses pass through a UPL auditor and Grey Rock
filter before being returned. Disclaimer acceptance is logged
with a timestamp in the database.

## GitHub structure

```
synjuris/
├── synjuris_master.py
├── static/
│   ├── login.html
│   ├── onboarding.html
│   └── dashboard.html
├── requirements.txt
└── README.md
```

That's it. One repo, one directory.
