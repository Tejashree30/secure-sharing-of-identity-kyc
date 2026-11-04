"""Central settings. Everything optional is controlled by environment variables,
so the project runs with zero configuration out of the box."""
import os

# Data owners, by internal subnet. The agent notifies the owner of the affected asset.
# Replace the emails with real ones (or set OWNER_EMAIL to send everything to one address).
_DEFAULT_EMAIL = os.getenv("OWNER_EMAIL", "owner@example.com")
OWNERS = {
    "10.0.0.": {"name": "Finance Department", "email": _DEFAULT_EMAIL},
    "10.0.1.": {"name": "HR Department", "email": _DEFAULT_EMAIL},
    "10.0.2.": {"name": "Engineering Team", "email": _DEFAULT_EMAIL},
    "10.0.3.": {"name": "Sales Team", "email": _DEFAULT_EMAIL},
    "10.0.4.": {"name": "Operations Team", "email": _DEFAULT_EMAIL},
    "10.0.5.": {"name": "Database Administrators", "email": _DEFAULT_EMAIL},
    "10.0.6.": {"name": "Web Server Team", "email": _DEFAULT_EMAIL},
    "10.0.7.": {"name": "Student Labs", "email": _DEFAULT_EMAIL},
}
FALLBACK_OWNER = {"name": "Security Administrator", "email": _DEFAULT_EMAIL}

# Optional: real email delivery (leave unset to only show notifications on the dashboard + log file)
SMTP_HOST = os.getenv("SMTP_HOST")          # e.g. smtp.gmail.com
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_PASS")          # for Gmail use an App Password

# Optional: let Claude write the owner message (otherwise a built-in template is used)
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
LLM_MODEL = os.getenv("LLM_MODEL", "claude-haiku-5-5")

# Behaviour
TICK_SECONDS = 1.0            # how often the live stream produces a batch of events
AUTO_ATTACKS = True           # random attack campaigns appear on their own
ATTACK_CHANCE_PER_TICK = 0.05
INCIDENT_COOLDOWN = 30        # seconds; repeat detections from the same source+type are merged
ESCALATE_AFTER = 5            # repeated detections from one source before the agent forces a block/isolation
ALLOWLIST = {"10.0.0.2"}      # IPs the agent must never block
NOTIFY_MIN_SEVERITY = 2       # owners are only emailed for severity >= this (reduces alert fatigue)
HOST = os.getenv("HOST", "127.0.0.1")
PORT = int(os.getenv("PORT", "5000"))
