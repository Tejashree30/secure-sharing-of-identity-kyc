"""Owner notifications: message writing (Claude or template) + delivery channels.

Channels: dashboard (always: DB + live toast), email (if SMTP configured), webhook (Slack / Teams /
Discord-style incoming webhook, if a URL is set in Settings).
Runs in a background thread so slow LLM / SMTP / webhook calls never stall detection.
"""
import json
import queue
import threading
import time
import urllib.request

import config
from notifier import affected_asset, llm_message, send_email, template_message


class PlatformNotifier:
    def __init__(self, db, bus, settings, firewall):
        self.db, self.bus, self.settings, self.fw = db, bus, settings, firewall
        self.q = queue.Queue(maxsize=500)
        self.sent_count = 0
        threading.Thread(target=self._worker, daemon=True).start()

    def submit(self, inc, owner, text=None):
        try:
            self.q.put_nowait((inc, owner, text))
        except queue.Full:
            self.bus.toast("warning", "Notification queue full", "An owner message was dropped")

    # ---- delivery ----
    def _webhook(self, subject, text):
        url = (self.settings.get("webhook_url") or "").strip()
        if not url:
            return "not configured"
        if not url.startswith(("https://", "http://")):
            return "failed: invalid URL"
        try:
            body = json.dumps({"text": f"*{subject}*\n{text}", "content": f"**{subject}**\n{text}"}).encode()
            req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=5).read()
            return "sent"
        except Exception as e:
            return f"failed: {e.__class__.__name__}"

    def _deliver(self, inc, owner, text=None, nid=None):
        subject = f"[Security] {inc['threat_type'].replace('_', ' ').title()} on {affected_asset(inc)}"
        writer = "stored message"
        if text is None:
            text = llm_message(inc, owner)
            writer = "Claude (LLM)" if text else "template"
            text = text or template_message(inc, owner)
            if self.fw.dry_run:
                text += "\n\n(Demo mode: firewall changes were simulated, nothing was blocked on a real device.)"
        email = send_email(owner["email"], subject, text)
        channels = {"dashboard": "delivered",
                    "email": "not configured" if email.startswith("not configured") else email,
                    "webhook": self._webhook(subject, text)}
        if nid is None:
            nid = self.db.x(
                "INSERT INTO notifications(ts,incident_id,owner,to_addr,subject,message,written_by,channels) "
                "VALUES(?,?,?,?,?,?,?,?)",
                (time.time(), inc["id"], owner["name"], owner["email"], subject, text, writer, json.dumps(channels)))
        else:
            self.db.x("UPDATE notifications SET channels=?, ts=? WHERE id=?", (json.dumps(channels), time.time(), nid))
        self.sent_count += 1
        failed = [k for k, v in channels.items() if v.startswith("failed")]
        if failed:
            self.bus.toast("warning", "Notification channel failed",
                           f"{', '.join(failed)} could not deliver the message to {owner['name']}", inc["id"])
        self.bus.toast("success", f"Owner notified: {owner['name']}", subject, inc["id"])
        self.bus.publish("refresh", what="notifications")
        return nid

    def _worker(self):
        while True:
            inc, owner, text = self.q.get()
            try:
                self._deliver(inc, owner, text)
            except Exception as e:
                self.bus.toast("danger", "Notification error", f"{e.__class__.__name__}: {e}")

    def resend(self, nid):
        row = self.db.one("SELECT * FROM notifications WHERE id=?", (nid,))
        if not row:
            return None
        inc = {"id": row["incident_id"], "threat_type": (self.db.one(
            "SELECT threat_type FROM incidents WHERE id=?", (row["incident_id"],)) or {}).get("threat_type", "alert"),
            "src_ip": "", "dst_ip": ""}
        owner = {"name": row["owner"], "email": row["to_addr"]}
        email = send_email(row["to_addr"], row["subject"], row["message"])
        channels = {"dashboard": "delivered",
                    "email": "not configured" if email.startswith("not configured") else email,
                    "webhook": self._webhook(row["subject"], row["message"])}
        self.db.x("UPDATE notifications SET channels=?, ts=? WHERE id=?", (json.dumps(channels), time.time(), nid))
        self.bus.toast("info", "Message re-sent", f"{owner['name']}: " + ", ".join(f"{k} {v}" for k, v in channels.items()))
        self.bus.publish("refresh", what="notifications")
        return channels
