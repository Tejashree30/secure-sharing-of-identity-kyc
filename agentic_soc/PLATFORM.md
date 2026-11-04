# Agentic AI Cyber Defense Platform (full version)

The original prototype (`python app.py`) is unchanged. This adds a login-protected, multi-page console, a
database-backed backend, a tool-using agent with a visible reasoning trace, real firewall hooks (safe dry-run by default)
and live pop-up alerts.

## Run it

```bash
pip install -r requirements.txt
python server.py
# open http://127.0.0.1:5000   login: admin / admin123   (analyst / analyst123, viewer / viewer123)
```
Or double-click `run.bat` (Windows) / run `./run.sh` (Mac/Linux). Change the default passwords under **Settings & health**.

## What you get

| Page | What it shows |
|---|---|
| Overview | Live KPIs, traffic chart, live traffic feed, recent incidents |
| Incidents | Searchable table; click one for the agent's step-by-step reasoning, the owner message, and buttons: Approve/Deny isolation, Acknowledge, Resolve, False positive (+allowlist), Unblock |
| Blocklist | Everything blocked/isolated, expiry timers, manual block, and the exact firewall commands |
| Owner messages | Plain-language messages sent to data owners, delivery status per channel, Resend |
| Owners & assets | Map IP prefixes to owners and criticality (critical assets raise severity) |
| Attack simulator | Launch each attack type (including an unknown zero-day) and watch everything react |
| Analytics | Incidents per minute, by type/severity, top sources, mean response time, false-positive rate |
| Audit log | Every automatic and human action |
| Settings & health | Auto-response, approval for isolation, thresholds, webhook, status of every integration |

Quick alerts: a toast pops up for every detection, containment, owner notification, escalation, firewall error, failed
login and lost connection. Severity 4+ also shows a red banner and a beep (toggle with the speaker button).

## Architecture

```
traffic (simulated | Scapy live capture) -> firewall filter -> ML detector (Isolation Forest + Random Forest)
   -> Agent: threat-intel lookup -> asset owner lookup -> severity reasoning -> policy decision
   -> tools: block IP | isolate host | queue for analyst | notify owner     (all logged with a reasoning trace)
   -> optional AI analyst (Claude tool use) reviews serious incidents afterwards, behind code guardrails
   -> SQLite (incidents, blocklist, notifications, owners, audit, settings, users) -> REST API -> web console + SSE live alerts
```
New code is in `soc/` (backend), `server.py` (API) and `web/` (console). It subclasses the original `engine.Engine`.

## Safety design (say this in your viva)

- **Firewall is dry-run by default.** Commands (`iptables` / `netsh advfirewall`) are only recorded. Real enforcement needs
  `ALLOW_REAL_FIREWALL=1` plus root/administrator rights, then an admin switches dry-run off in Settings.
- Commands run as argument lists (no shell), after strict IP validation. Loopback, reserved and allowlisted addresses are refused.
- Isolation can require **human approval**. Auto-response can be switched off entirely (recommend-only mode).
- Repeated detections escalate, but escalation obeys the same approval and auto-response settings.
- The LLM analyst can only act on addresses in its own incident, never on allowlisted ones, and these limits are enforced in code.
- Login throttling (5 failures, then 5-minute lock), hashed passwords, role-based access (viewer / analyst / admin), audit trail.

## Optional integrations (all off by default; set as environment variables)

| Variable | Effect |
|---|---|
| `ANTHROPIC_API_KEY` | Claude writes owner messages and an AI analyst reviews incidents (tool use) |
| `ABUSEIPDB_KEY`, `VT_API_KEY` | Real threat-intelligence lookups; automatic fallback to the local feed if they fail |
| `SMTP_HOST`, `SMTP_USER`, `SMTP_PASS`, `OWNER_EMAIL` | Real e-mail to owners |
| Webhook URL (Settings page) | Slack / Teams / Discord incoming webhook |
| `MODE=live` | Capture real packets with Scapy (`pip install scapy`, run with `sudo`) |
| `ALLOW_REAL_FIREWALL=1` | Permit real firewall changes |
| `ADMIN_PASSWORD`, `SECRET_KEY`, `HOST`, `PORT` | Deployment settings |

## Real data and models

```bash
python train_real.py --data path/to/CIC-IDS2017/MachineLearningCSV --max-rows 300000 --xgb
```
Trains and evaluates the hybrid detector on CIC-IDS2017, holds out the "Bot" family as the unknown attack, and compares XGBoost
with Random Forest. UNSW-NB15 needs a similar column mapping.

## Tests

```bash
python -m unittest tests.test_soc -v
```
Covers firewall safety, threat-intel parsing and fallback, packet-flow features, severity and plan rules, owner lookup,
the AI-analyst loop and its guardrails, and the database.

## What was and was not verified

Verified here: the API, roles, login throttling, approval flow, escalation rules, live alert stream, exports and all console pages
(in a headless browser, no script errors), plus the unit tests above.

Not verified here, because the sandbox has no keys, no root and no outside network access:
real AbuseIPDB / VirusTotal calls, real e-mail and webhook delivery, real `iptables` / `netsh` execution, live Scapy capture,
and the real Claude API (the analyst loop was tested against a scripted stand-in). `train_real.py` was run on a small synthetic
file shaped like CIC-IDS2017, so it proves the loader works; **real accuracy numbers need the real dataset.**
Features that CIC-IDS2017 lacks (failed logins, unique ports, hour) are set to constants, so a model trained there is a benchmark of
the method, not a drop-in replacement for the live-capture detector.
