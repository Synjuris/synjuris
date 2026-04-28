# SynJuris v2.0.0 — Quick Start Guide

**Local-First Legal Intelligence for Pro Se Litigants and Attorneys**

Your data never leaves your computer.

---

## What's in This Package

```
synjuris-20.py              ← The application (everything in one file)
merkle_dag.py               ← Evidence chain audit engine
pattern_engine.py           ← Semantic violation detection
job_queue.py                ← Async document generation
readiness_engine.py         ← Document readiness scoring
jurisdiction_helpers.py     ← State statute references
launch_synjuris_mac.command ← Mac/Linux launcher (double-click to start)
launch_synjuris_windows.bat ← Windows launcher (double-click to start)
README.md                   ← This file
```

---

## Requirements

- **Python 3.9 or later** (free download at python.org)
- A modern web browser (Chrome, Firefox, Safari, Edge)
- An API key for AI features (see AI Providers below)

---

## Starting SynJuris

### Mac / Linux
1. Double-click `launch_synjuris_mac.command`
2. If macOS blocks it: right-click → Open → Open
3. Follow the prompts (paste your API key if you have one)
4. SynJuris opens in your browser at http://localhost:5000

### Windows
1. Double-click `launch_synjuris_windows.bat`
2. If Windows Defender prompts: More info → Run anyway
3. Follow the prompts (paste your API key if you have one)
4. SynJuris opens in your browser at http://localhost:5000

### Command Line (any platform)
```bash
# Anthropic (default)
export ANTHROPIC_API_KEY=your-key-here   # Mac/Linux
set ANTHROPIC_API_KEY=your-key-here      # Windows

python3 synjuris-20.py
```

Then open http://localhost:5000 in your browser.

---

## AI Providers

SynJuris supports multiple AI providers. Set one environment variable to switch.

### Anthropic (default)
```bash
export ANTHROPIC_API_KEY=sk-ant-...
```
Get a free key at https://console.anthropic.com

### OpenAI
```bash
export SYNJURIS_AI_PROVIDER=openai
export OPENAI_API_KEY=sk-...
export SYNJURIS_AI_MODEL=gpt-4o        # optional, defaults to gpt-4o
```

### Ollama — fully local, no API key, no cost
```bash
# Install Ollama from https://ollama.com, then:
ollama pull llama3.2

export SYNJURIS_AI_PROVIDER=ollama
export SYNJURIS_AI_MODEL=llama3.2
```

Ollama runs entirely on your machine. No data leaves your computer for AI calls — not even message text. This provides the strongest possible work-product protection.

**AI features include:** Document drafting, case analysis, hearing prep, adversarial simulation, argument builder, child support calculator, legal roadmap, and more. Everything except AI generation works without any key.

---

## Your Data

- All case data is stored in `synjuris.db` in the same folder as the app
- Uploaded files are stored in the `uploads/` folder
- **Nothing is sent to any server.** Your data stays on your machine.
- The only data that leaves your computer is the text of messages you send to the AI, transmitted directly to your chosen AI provider under your own API key — SynJuris never sees it.
- If you use Ollama, nothing leaves your machine at all.

**Back up regularly:** Use the `🔐 Encrypted Backup` button in the app to create a password-protected backup you can store anywhere safely. The backup is encrypted with AES-256-GCM on your device — only your passphrase can open it.

---

## What's New in v2.0

### Cryptographic Evidence Chain
Every confirmed exhibit is added to a Merkle DAG — a tamper-evident chain where any modification to any exhibit invalidates all subsequent hashes. Verifiable at any time from the Dynamics tab.

### Hash-Chained Audit Log
Every action in SynJuris — options shown, documents generated, evidence confirmed — is logged with a cryptographic hash chain. Any modification to a historical record breaks the chain detectably. Useful if you ever need to prove what the system showed you and when.

### Streaming Document Generation
Documents now stream token by token as they're written — first output appears in under a second instead of waiting 30-60 seconds for a complete result.

### Async Job Queue
Document generation runs in the background. You can navigate the app, add evidence, or check deadlines while a document is being drafted. If you close the tab and come back, the document is waiting for you.

### Document Readiness Scoring
The Documents tab now shows a readiness score (0–100%) for each document type based on your current evidence, deadlines, and case details. The most-ready documents appear first. Documents that hit 90%+ readiness are pre-generated silently in the background.

### Branching Action System
Instead of implicit recommendations, SynJuris presents available options with readiness scores. You decide what to do — the system provides information, not advice.

### Citation Verification (Hard Mode)
All AI-generated citations are automatically checked against CourtListener. Unverified citations appear as a prominent warning block at the top of the document — never silently ignored. Set `SYNJURIS_CITATION_FAIL_THRESHOLD=0.5` to block generation entirely if more than 50% of citations are unverified.

### Universal AI Provider Support
Switch between Anthropic, OpenAI, and Ollama with a single environment variable. No code changes required.

---

## Work-Product Protection

Communications with cloud AI tools (ChatGPT, Claude.ai) have been ruled non-privileged in some federal proceedings because they involve third-party transmission. SynJuris runs entirely on your machine. Your evidence, strategy, and documents may retain work-product status that cloud tools cannot provide.

Using Ollama eliminates even the AI provider as a third party — the entire system runs locally.

---

## Attorney Features

Click the tier badge in the top bar to switch to **Attorney** mode. This unlocks:
- **Client Portal** — share a secure link with clients to submit evidence for your review
- **Conflict Check** — search party names across all your cases
- **Time Entries** — auto-generated from AI tool usage, exportable as CSV
- **Redacted Export** — shareable case summary with raw evidence stripped
- **Audit Chain Verify** — cryptographic proof that your audit log has not been tampered with

---

## Upgrading from v1.0

Drop the new files into your existing SynJuris folder. Your database (`synjuris.db`) carries over automatically — all your cases, evidence, and documents are preserved. New tables are added on first launch without touching existing data.

Update your launcher scripts to point to `synjuris-20.py` instead of `synjuris-10.py`.

---

## Support

- Questions: support@synjuris.com
- Updates: https://github.com/synjuris/synjuris/releases

---

**SynJuris is not a law firm and does not provide legal advice.**
This software is an organizational and informational tool only.
Always consult a licensed attorney before filing any document with a court.
