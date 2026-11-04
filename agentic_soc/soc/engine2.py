"""SOCEngine: the original real-time Engine plus persistence, tool-using agent, firewall executor,
approval workflow, TTL expiry, optional live capture and optional LLM analyst.

It SUBCLASSES the original `engine.Engine` (which is not modified): the traffic loop, the firewall
drop filter, the ML detector and the counters are all inherited; only incident handling is replaced.
"""
import json
import queue
import threading
import time

import pandas as pd

import config
from engine import Engine

from .capture import LiveSniffer
from .firewall import FirewallError
from .llm_agent import ToolBox, run_agent
from .pnotifier import PlatformNotifier
from .responder import Responder

STATUSES = ("open", "acknowledged", "resolved", "false_positive", "pending_approval")


class SOCEngine(Engine):
    def __init__(self, db, bus, firewall, intel, settings, mode="sim"):
        super().__init__()                      # trains the detector, creates the base state
        self.db, self.bus, self.fw, self.intel = db, bus, firewall, intel
        self.settings, self.mode = settings, mode
        self.agent.allowlist |= set(settings.get("allowlist", []))
        self.fw.protected |= self.agent.allowlist
        self.pnotifier = PlatformNotifier(db, bus, settings, firewall)
        self.responder = Responder(self)
        self.sniffer, self.capture_msg = None, "simulation"
        self.llm_q, self.llm_client = queue.Queue(maxsize=50), None
        self.llm_reviews = 0
        self.restore()

    # ------------------------------------------------------------------ lifecycle
    def start(self):
        if self.mode == "live":
            self.sniffer = LiveSniffer()
            ok, msg = self.sniffer.start()
            self.capture_msg = msg
            if not ok:
                self.sniffer, self.mode = None, "sim"
                self.bus.toast("warning", "Live capture unavailable", f"{msg}. Running in simulation mode.")
        super().start()
        threading.Thread(target=self._sweeper, daemon=True).start()
        threading.Thread(target=self._llm_worker, daemon=True).start()

    def restore(self):
        """Re-load persisted blocks so containment survives a restart."""
        now = time.time()
        for r in self.db.q("SELECT * FROM blocklist"):
            if r["expires"] and r["expires"] <= now:
                self.db.x("DELETE FROM blocklist WHERE ip=?", (r["ip"],))
            else:
                (self.agent.blocked_ips if r["kind"] == "block" else self.agent.isolated_hosts).add(r["ip"])

    # ------------------------------------------------------------------ traffic loop
    def _tick(self):
        if self.mode == "live" and self.sniffer is not None:
            flows = self.sniffer.drain()
            with self.lock:
                self._process(flows)
            return
        super()._tick()

    def _process(self, batch):
        blocked = self.agent.blocked_ips | self.agent.isolated_hosts
        passed, dropped_srcs, dropped = [], set(), 0
        for e in batch:
            if e["src_ip"] in blocked:
                dropped += 1
                if e["src_ip"] not in dropped_srcs:
                    dropped_srcs.add(e["src_ip"])
                    self._feed(e, "dropped", "blocked source", 0.0, "DROPPED by firewall")
            else:
                passed.append(e)
        threats = 0
        if passed:
            df = pd.DataFrame(passed)
            df["timestamp"] = pd.Timestamp.now()
            for _, ev in self.det.predict(df).iterrows():
                threats += self._handle(ev)
        self.c["events"] += len(batch)
        self.c["dropped"] += dropped
        self.timeline.append((len(batch), threats, dropped))

    def _handle(self, ev):                     # called with self.lock held
        live = ev["label"] == "live"
        is_attack = ev["label"] not in ("normal", "live")
        if ev["verdict"] != "threat":
            if not live:
                self.c["fn" if is_attack else "tn"] += 1
            self._feed(ev, "normal" if not is_attack else "missed", "-", ev["anomaly_score"], "allowed")
            return 0
        if not live:
            self.c["tp" if is_attack else "fp"] += 1
        self.c["threats"] += 1
        key, now = (ev["src_ip"], ev["threat_type"]), time.time()
        inc = self.open.get(key)
        if inc and now - inc["last"] < config.INCIDENT_COOLDOWN:
            inc["count"] += 1
            inc["last"] = now
            action = f"merged into incident #{inc['id']}"
            self.db.x("UPDATE incidents SET count=?, updated=? WHERE id=?", (inc["count"], now, inc["id"]))
            if inc["count"] >= int(config.ESCALATE_AFTER) and not inc.get("escalated"):
                act = self.responder.escalate(inc, ev)
                action = f"ESCALATED -> {act}"
            self._feed(ev, "threat", ev["threat_type"], ev["anomaly_score"], action)
            return 1
        inc = self.responder.handle_new(ev)
        self.open[key] = inc
        self.incidents.insert(0, inc)
        del self.incidents[60:]
        self._feed(ev, "threat", ev["threat_type"], ev["anomaly_score"], ", ".join(inc["actions"]))
        return 1

    # ------------------------------------------------------------------ containment
    def contain(self, kind, ip, reason, incident_id=None, by="agent", ttl=None, in_engine=False):
        """Block (external) or isolate (internal) an address. Used by the agent and by humans."""
        base = {"ok": False, "dry_run": self.fw.dry_run, "commands": [], "error": None}
        if ip in self.agent.allowlist:
            return {**base, "error": "address is allowlisted"}
        target = self.agent.blocked_ips if kind == "block" else self.agent.isolated_hosts
        if ip in target:
            return {**base, "ok": True, "note": "already contained"}
        try:
            res = self.fw.block(ip) if kind == "block" else self.fw.isolate(ip)
        except FirewallError as ex:
            res = {**base, "error": str(ex)}
        if not res["ok"]:
            self.bus.toast("danger", "Firewall error", f"Could not {kind} {ip}: {res['error']}")
            self.db.audit(by, f"{kind}_failed", ip, res["error"])
            return res

        def apply():
            target.add(ip)
            self.c["blocked_total"] += 1

        if in_engine:
            apply()
        else:
            with self.lock:
                apply()
        ttl = int(self.settings.get("block_ttl_minutes", 60)) if ttl is None else int(ttl)
        expires = time.time() + ttl * 60 if ttl > 0 else None
        self.db.x("INSERT INTO blocklist(ip,kind,reason,ts,expires,incident_id,by) VALUES(?,?,?,?,?,?,?) "
                  "ON CONFLICT(ip) DO UPDATE SET kind=excluded.kind, reason=excluded.reason, ts=excluded.ts, "
                  "expires=excluded.expires, incident_id=excluded.incident_id, by=excluded.by",
                  (ip, kind, reason, time.time(), expires, incident_id, by))
        self.db.audit(by, kind, ip, reason + (" [dry-run]" if res["dry_run"] else ""))
        self.bus.publish("refresh", what="blocklist")
        return res

    def release(self, ip, by="system"):
        was_iso = ip in self.agent.isolated_hosts
        was_blk = ip in self.agent.blocked_ips
        res = None
        if was_iso or was_blk:
            try:
                res = self.fw.release(ip) if was_iso else self.fw.unblock(ip)
            except FirewallError as ex:
                res = {"ok": False, "error": str(ex)}
            if res and not res["ok"]:
                self.bus.toast("warning", "Firewall error", f"Could not remove rule for {ip}: {res['error']}")
        self.unblock(ip)                                  # base: removes from sets (takes the lock)
        self.db.x("DELETE FROM blocklist WHERE ip=?", (ip,))
        self.db.audit(by, "release", ip, "")
        self.bus.toast("info", "Source released", f"{ip} can reach the network again ({by})")
        self.bus.publish("refresh", what="blocklist")
        return res

    def manual_block(self, ip, kind, reason, actor, ttl=None):
        if kind not in ("block", "isolate"):
            return {"ok": False, "error": "kind must be 'block' or 'isolate'"}
        res = self.contain(kind, ip, reason or "manual action", None, actor, ttl)
        if res["ok"]:
            self.bus.toast("success", f"{'Blocked' if kind == 'block' else 'Isolated'} {ip}",
                           f"by {actor}" + (" (simulated)" if res["dry_run"] else ""))
        return res

    # ------------------------------------------------------------------ analyst workflow
    def _trace_add(self, inc_id, entry, actions=None, status=None):
        row = self.db.one("SELECT trace, actions FROM incidents WHERE id=?", (inc_id,))
        trace = json.loads(row["trace"] or "[]") + [entry]
        acts = json.loads(row["actions"] or "[]") + (actions or [])
        self.db.x("UPDATE incidents SET trace=?, actions=?, updated=? WHERE id=?",
                  (json.dumps(trace), json.dumps(acts), time.time(), inc_id))
        if status:
            self.db.x("UPDATE incidents SET status=?, pending=NULL WHERE id=?", (status, inc_id))

    def approve(self, inc_id, actor):
        row = self.db.one("SELECT * FROM incidents WHERE id=?", (inc_id,))
        if not row or row["status"] != "pending_approval" or not row["pending"]:
            return {"ok": False, "error": "incident is not waiting for approval"}
        p = json.loads(row["pending"])
        res = self.contain(p["kind"], p["ip"], f"approved by {actor} (incident #{inc_id})", inc_id, actor)
        if not res["ok"]:
            return {"ok": False, "error": res["error"]}
        self._trace_add(inc_id, {"t": 0, "kind": "decision", "text": f"{actor} approved isolation of {p['ip']}."},
                        ["isolate_host"], "open")
        self.db.audit(actor, "approve", inc_id, p["ip"])
        self.bus.toast("success", "Isolation approved", f"{p['ip']} isolated by {actor}", inc_id)
        self.bus.publish("refresh", what="incidents")
        return {"ok": True}

    def deny(self, inc_id, actor):
        row = self.db.one("SELECT status FROM incidents WHERE id=?", (inc_id,))
        if not row or row["status"] != "pending_approval":
            return {"ok": False, "error": "incident is not waiting for approval"}
        self._trace_add(inc_id, {"t": 0, "kind": "decision", "text": f"{actor} denied the isolation request."},
                        ["isolation_denied"], "acknowledged")
        self.db.audit(actor, "deny", inc_id, "")
        self.bus.toast("info", "Isolation denied", f"Incident #{inc_id} acknowledged without isolation", inc_id)
        self.bus.publish("refresh", what="incidents")
        return {"ok": True}

    def set_status(self, inc_id, status, actor, allowlist=False):
        if status not in STATUSES or status == "pending_approval":
            return {"ok": False, "error": "invalid status"}
        row = self.db.one("SELECT * FROM incidents WHERE id=?", (inc_id,))
        if not row:
            return {"ok": False, "error": "incident not found"}
        self.db.x("UPDATE incidents SET status=?, pending=NULL, updated=? WHERE id=?", (status, time.time(), inc_id))
        self._trace_add(inc_id, {"t": 0, "kind": "decision", "text": f"{actor} marked the incident {status.replace('_', ' ')}."})
        self.db.audit(actor, f"status:{status}", inc_id, "")
        if status == "false_positive":
            ip = row["src_ip"]
            if ip in self.agent.blocked_ips or ip in self.agent.isolated_hosts:
                self.release(ip, actor)
            if allowlist:
                self.agent.allowlist.add(ip)
                self.fw.protected.add(ip)
                self.settings["allowlist"] = sorted(self.agent.allowlist)
                self.db.set_setting("allowlist", self.settings["allowlist"])
                self.db.audit(actor, "allowlist_add", ip, f"from incident #{inc_id}")
            self.bus.toast("info", "Marked as false positive", f"{ip} released" + (" and allowlisted" if allowlist else ""), inc_id)
        self.bus.publish("refresh", what="incidents")
        return {"ok": True}

    # ------------------------------------------------------------------ background jobs
    def _sweeper(self):
        while self.running:
            try:
                now = time.time()
                for r in self.db.q("SELECT ip FROM blocklist WHERE expires IS NOT NULL AND expires <= ?", (now,)):
                    self.release(r["ip"], "ttl-expiry")
            except Exception as ex:
                self.bus.toast("warning", "Block expiry error", str(ex))
            time.sleep(5)

    def llm_enabled(self):
        return bool(config.ANTHROPIC_API_KEY or self.llm_client) and self.settings.get("llm_agent", True)

    def llm_submit(self, inc_id):
        try:
            self.llm_q.put_nowait(inc_id)
        except queue.Full:
            pass

    def _llm_worker(self):
        while self.running:
            inc_id = self.llm_q.get()
            try:
                row = self.db.one("SELECT * FROM incidents WHERE id=?", (inc_id,))
                if self.llm_client is None:
                    import anthropic
                    self.llm_client = anthropic.Anthropic(api_key=config.ANTHROPIC_API_KEY, timeout=30)
                tb = ToolBox(self, row)
                text = run_agent(self.llm_client, config.LLM_MODEL, row, tb)
                extra = [a for t in tb.trace if t["tool"] in ("block_ip", "isolate_host")
                         and (t["result"] or {}).get("ok") for a in [t["tool"]]]
                for t in tb.trace:
                    self._trace_add(inc_id, t)
                self._trace_add(inc_id, {"t": 0, "kind": "llm", "text": text}, extra)
                self.llm_reviews += 1
                self.bus.toast("info", f"AI analyst reviewed incident #{inc_id}", text[:160], inc_id)
                self.bus.publish("refresh", what="incidents")
            except Exception as ex:
                self.bus.toast("warning", "AI analyst unavailable", f"{ex.__class__.__name__}: {str(ex)[:120]}")
