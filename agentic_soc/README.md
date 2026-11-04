# Agentic AI Real-Time Cyber Defense

A real-time system that watches network traffic continuously, detects known and unknown (zero-day) threats with machine learning, **stops the malicious activity automatically**, and uses an AI agent to **tell the owner of the affected data in plain language**.

## Quick start (3 commands)

```bash
pip install -r requirements.txt
python app.py
# then open http://127.0.0.1:5000 in your browser
```

It runs continuously until you press Ctrl+C. No configuration needed. Random attacks appear on their own, and you can trigger one with the buttons on the dashboard.

## What happens, in order

```
live traffic ─► FIREWALL (drops blocked sources) ─► ML detector ─► Agent decides ─► Block / Isolate / Alert
                                                    IsolationForest   severity +        │
                                                    + RandomForest    threat intel      ▼
                                                                                 Owner notifier (Claude or template)
                                                                                 dashboard + log + optional email
```

1. **Detect.** A hybrid model: an Isolation Forest (trained on normal traffic only) catches unknown behaviour; a Random Forest names known attacks (port scan, brute force, DDoS, exfiltration).
2. **Decide.** The agent scores severity, raises it if threat intelligence flags the source, and picks an action. Allowlisted IPs are never blocked.
3. **Stop.** Blocked IPs and isolated hosts are dropped at the "firewall" step, so the dashboard shows the malicious packets being stopped. Activity that keeps repeating (5+ detections) is escalated and stopped automatically.
4. **Tell the owner.** The affected asset's IP is mapped to its owner (`config.py`), and the agent writes a short message: what happened, what was done, what they should do. Low-severity events go to an analyst queue instead, to avoid alert fatigue.

## Files

| File | Purpose |
|---|---|
| `app.py` | Starts the engine and the web dashboard |
| `engine.py` | Real-time loop: stream, firewall, detection, incident handling |
| `detector.py` | Hybrid ML detector |
| `agent.py` | Decision logic: severity, block / isolate / escalate, audit log |
| `notifier.py` | Owner lookup, message writing (Claude or template), email delivery |
| `threat_intel.py` | Mock threat-intelligence feed (replace with AbuseIPDB / VirusTotal / OTX) |
| `data_gen.py` | Synthetic traffic generator (training data and live stream) |
| `config.py` | Owners, thresholds, optional email / LLM settings |
| `dashboard.html` | Live web dashboard |
| `main.py` | Offline evaluation (metrics for your report): `python main.py` |

## Optional upgrades (all off by default)

**Claude writes the owner messages** (otherwise a built-in template is used):
```bash
# Windows (cmd):  set ANTHROPIC_API_KEY=your_key
export ANTHROPIC_API_KEY=your_key      # Mac/Linux
python app.py
```

**Real emails to owners** (Gmail example, use an App Password):
```bash
export SMTP_HOST=smtp.gmail.com SMTP_USER=you@gmail.com SMTP_PASS=app_password OWNER_EMAIL=owner@example.com
python app.py
```
Every message is always saved to `output/notifications.log` too.

## Results (offline test, `python main.py`)

- Threat recall 100%, precision 98%, accuracy 99.6% (9 false alarms in 1,839 normal events, about 0.5%)
- Held-out zero-day attack family (never in supervised training) detected 100%
- Live test: all five attack types detected, blocked or isolated, and owners notified

## Honest limitations (say these in your viva)

- **Traffic is simulated.** The stream is generated, so the numbers are optimistic. To use real data, retrain on CIC-IDS2017 / UNSW-NB15 and feed real flow records (for example from Zeek or CICFlowMeter) into `Engine._tick` instead of `make_event`.
- **Blocking is simulated.** The "firewall" drops events inside the program. Real enforcement hooks (iptables, `netsh advfirewall`, cloud security groups, EDR isolation) would go where `agent.py` updates `blocked_ips` / `isolated_hosts`. Keep a human in the loop for isolation in production.
- **Threat intelligence is a mock** and the owner directory is a simple subnet map.
- The dashboard is a single-user development server, not hardened for production.

## Ideas to extend

Real packet capture, SHAP explanations, persistent incident database, analyst approval buttons for isolation, drift monitoring and automatic retraining.
