"""Owner notification agent.

For each serious incident it (1) works out WHO owns the affected data/asset,
(2) writes a plain-language message (Claude if an API key is set, otherwise a
built-in template), and (3) delivers it: dashboard + notifications.log always,
email if SMTP is configured.
"""
import os
import queue
import smtplib
import threading
import time
from email.message import EmailMessage

import config

LOG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "output", "notifications.log")
os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)

HUMAN = {
    "port_scan": "a port scan (someone probing your systems for open doors)",
    "brute_force": "a password-guessing (brute force) attack",
    "ddos": "a flood of traffic (DDoS) trying to knock the service offline",
    "exfiltration": "an unusually large outbound data transfer that may indicate data theft",
    "unknown_anomaly": "unusual behaviour that does not match any known attack pattern",
    "c2_beacon": "suspicious periodic communication with an outside server",
}
ADVICE = {
    "port_scan": "No action is required unless you see other odd activity. Make sure unused services are switched off.",
    "brute_force": "Please check for unfamiliar logins and reset passwords of accounts on this system if you are unsure. Enable multi-factor authentication.",
    "ddos": "Expect possible slowness. No data is affected. Contact IT if the service stays degraded.",
    "exfiltration": "Please review what data left this system and who was using it. Do not reconnect the affected machine until IT has checked it.",
    "unknown_anomaly": "Please confirm whether this activity was expected (for example a new tool or a large backup). If not, report it to IT.",
}


def find_owner(ip: str) -> dict:
    for prefix, owner in config.OWNERS.items():
        if ip.startswith(prefix):
            return owner
    return config.FALLBACK_OWNER


def affected_asset(inc: dict) -> str:
    """The asset whose owner should be told: the internal side of the connection."""
    if inc["dst_ip"].startswith("10.0."):
        return inc["dst_ip"]
    return inc["src_ip"]


def _actions_text(inc):
    done = []
    for a in inc["actions"]:
        if a == "block_ip":
            done.append(f"blocked {inc['src_ip']} so it can no longer reach your network")
        elif a == "isolate_host":
            done.append(f"isolated host {inc['src_ip']} from the network")
        elif a == "queue_for_analyst":
            done.append("queued the event for a security analyst to review")
        elif a == "alert":
            done.append("raised an alert")
    return "; ".join(done)


def template_message(inc, owner):
    kind = inc["threat_type"]
    return (
        f"Hello {owner['name']},\n\n"
        f"Our automated security agent detected {HUMAN.get(kind, kind)} involving {affected_asset(inc)}, "
        f"which belongs to your area (severity {inc['severity']}/5).\n\n"
        f"What we already did: {_actions_text(inc)}.\n\n"
        f"What we recommend: {ADVICE.get(kind, 'Please contact the security team.')}\n\n"
        f"- Agentic AI Security Monitor"
    )


def llm_message(inc, owner):
    """Ask Claude to write the owner message. Returns None on any failure (caller falls back)."""
    if not config.ANTHROPIC_API_KEY:
        return None
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=config.ANTHROPIC_API_KEY, timeout=20)
        facts = (f"Threat: {HUMAN.get(inc['threat_type'], inc['threat_type'])}\n"
                 f"Affected asset: {affected_asset(inc)} (owner: {owner['name']})\n"
                 f"Source IP: {inc['src_ip']} | Destination IP: {inc['dst_ip']}\n"
                 f"Severity: {inc['severity']} out of 5 | Events seen: {inc['count']}\n"
                 f"Threat-intel says source known malicious: {inc['intel_malicious']}\n"
                 f"Automatic actions already taken: {_actions_text(inc)}\n"
                 f"Recommended owner action: {ADVICE.get(inc['threat_type'], '')}")
        r = client.messages.create(
            model=config.LLM_MODEL, max_tokens=350,
            messages=[{"role": "user", "content":
                       "Write a short, calm, plain-language message (max 120 words, no jargon, no markdown) "
                       f"to {owner['name']}, a non-technical data owner, about this security incident. "
                       "Say what happened, what was done automatically, and what they should do. "
                       "Use only the facts below; do not invent details.\n\n" + facts}])
        return r.content[0].text.strip()
    except Exception as e:  # network, quota, missing package...
        print(f"[notifier] LLM unavailable ({type(e).__name__}); using template")
        return None


def send_email(to, subject, body):
    if not (config.SMTP_HOST and config.SMTP_USER and config.SMTP_PASS):
        return "not configured (shown on dashboard + log only)"
    try:
        msg = EmailMessage()
        msg["From"], msg["To"], msg["Subject"] = config.SMTP_USER, to, subject
        msg.set_content(body)
        with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT, timeout=15) as s:
            s.starttls()
            s.login(config.SMTP_USER, config.SMTP_PASS)
            s.send_message(msg)
        return "sent"
    except Exception as e:
        return f"failed: {type(e).__name__}"


class Notifier:
    """Background worker so slow LLM/email calls never stall detection."""

    def __init__(self):
        self.q = queue.Queue()
        self.sent = []          # newest first
        self.lock = threading.Lock()
        threading.Thread(target=self._worker, daemon=True).start()

    def submit(self, inc):
        self.q.put(inc)

    def _worker(self):
        while True:
            inc = self.q.get()
            try:
                owner = find_owner(affected_asset(inc))
                text = llm_message(inc, owner)
                writer = "Claude (LLM)" if text else "template"
                text = text or template_message(inc, owner)
                subject = f"[Security] {inc['threat_type'].replace('_', ' ').title()} on {affected_asset(inc)}"
                status = send_email(owner["email"], subject, text)
                rec = {"time": time.strftime("%H:%M:%S"), "incident_id": inc["id"], "owner": owner["name"],
                       "to": owner["email"], "subject": subject, "message": text,
                       "written_by": writer, "email_status": status}
                with self.lock:
                    self.sent.insert(0, rec)
                    del self.sent[40:]
                with open(LOG_PATH, "a", encoding="utf-8") as f:
                    f.write(f"[{rec['time']}] To: {rec['owner']} <{rec['to']}> | {subject} | email: {status}\n{text}\n{'-'*70}\n")
            except Exception as e:
                print(f"[notifier] error: {e}")

    def snapshot(self):
        with self.lock:
            return list(self.sent)
