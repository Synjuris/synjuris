# SynJuris v1.0.0 — Quick Start Guide

**Local-First Legal Intelligence for Pro Se Litigants and Attorneys**

Your data never leaves your computer.

---

## What's in This Package

```
synjuris-10.py              ← The application (everything in one file)
launch_synjuris_mac.command ← Mac/Linux launcher (double-click to start)
launch_synjuris_windows.bat ← Windows launcher (double-click to start)
README.md                   ← This file
```

---

## Requirements

- **Python 3.9 or later** (free download at python.org)
- A modern web browser (Chrome, Firefox, Safari, Edge)
- An Anthropic API key for AI features (free at console.anthropic.com)

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
# With API key
export ANTHROPIC_API_KEY=your-key-here   # Mac/Linux
set ANTHROPIC_API_KEY=your-key-here      # Windows

python3 synjuris-10.py
```

Then open http://localhost:5000 in your browser.

---

## Getting an API Key (for AI features)

1. Go to https://console.anthropic.com
2. Create a free account
3. Click "API Keys" → "Create Key"
4. Copy the key and paste it when SynJuris asks

**AI features include:** Document drafting, case analysis, hearing prep, adversarial simulation, argument builder, and more. Everything else works without a key.

---

## Your Data

- All case data is stored in `synjuris.db` in the same folder as the app
- Uploaded files are stored in the `uploads/` folder
- **Nothing is sent to any server.** Your data stays on your machine.
- The only data that leaves your computer is the text of messages you send to the AI, transmitted directly to Anthropic under your own API key — SynJuris never sees it.

**Back up regularly:** Use the `🔐 Encrypted Backup` button in the app to create a password-protected backup you can store anywhere safely.

---

## Work-Product Protection

Communications with cloud AI tools (ChatGPT, Claude.ai) have been ruled non-privileged in some federal proceedings because they involve third-party transmission. SynJuris runs entirely on your machine. Your evidence, strategy, and documents may retain work-product status that cloud tools cannot provide.

---

## Attorney Features

Click the tier badge in the top bar to switch to **Attorney** mode. This unlocks:
- **Client Portal** — share a secure link with clients to submit evidence for your review
- **Conflict Check** — search party names across all your cases
- **Time Entries** — auto-generated from AI tool usage, exportable as CSV
- **Redacted Export** — shareable case summary with raw evidence stripped

---

## Support

- Questions: support@synjuris.com
- Updates: https://github.com/synjuris/synjuris/releases

---

**SynJuris is not a law firm and does not provide legal advice.**
This software is an organizational and informational tool only.
Always consult a licensed attorney before filing any document with a court.
