"""Agent decision layer: observe -> gather context with tools -> reason -> act -> explain.

Every incident gets a reasoning trace (stored in the DB and shown in the UI) listing what the agent
looked at, which tools it called, what it decided, and why. Containment is deterministic and fast;
an optional LLM analyst (llm_agent.py) can review the incident afterwards.
"""
import ipaddress
import json
import time

import config
from agent import SEVERITY

TITLES = {
    "port_scan": "Port scan", "brute_force": "Brute-force login attempts", "ddos": "DDoS flood",
    "exfiltration": "Data exfiltration", "unknown_anomaly": "Unknown anomaly (zero-day suspect)",
}


def is_internal(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


class Responder:
    def __init__(self, engine):
        self.e = engine

    # ---------- context ----------
    def owner_for(self, ip):
        best = None
        for r in self.e.db.q("SELECT * FROM owners"):
            if ip.startswith(r["prefix"]) and (best is None or len(r["prefix"]) > len(best["prefix"])):
                best = r
        return best or {"prefix": "", "name": config.FALLBACK_OWNER["name"],
                        "email": config.FALLBACK_OWNER["email"], "criticality": 1}

    @staticmethod
    def asset_of(src, dst):
        return dst if is_internal(dst) else src

    @staticmethod
    def score(threat, intel, owner):
        sev = SEVERITY.get(threat, 1)
        reasons = [f"base severity {sev} for {threat.replace('_', ' ')}"]
        if intel["known_malicious"]:
            sev += 1
            reasons.append("threat intelligence flags the source as malicious (+1)")
        if threat == "unknown_anomaly" and not intel["known_malicious"]:
            sev = min(sev, 1)
            reasons.append("unconfirmed anomaly with clean reputation: capped at 1")
        if owner["criticality"] >= 3 and sev >= 2:
            sev += 1
            reasons.append(f"{owner['name']} holds critical assets (+1)")
        return min(sev, 5), reasons

    @staticmethod
    def plan(threat, src, sev):
        internal = is_internal(src)
        if sev >= 3 and internal and threat != "unknown_anomaly":
            return ["isolate_host"]
        if threat == "exfiltration" and internal:
            return ["isolate_host"]
        if sev >= 2 and not internal:
            return ["block_ip"]
        return ["queue_for_analyst"]

    # ---------- new incident ----------
    def handle_new(self, ev):
        e, S = self.e, self.e.settings
        t0 = time.time()
        src, dst, threat = ev["src_ip"], ev["dst_ip"], ev["threat_type"]
        conf, score = float(ev["confidence"]), float(ev["anomaly_score"])
        trace = []

        def step(kind, text, **kw):
            trace.append({"t": round((time.time() - t0) * 1000, 1), "kind": kind, "text": text, **kw})

        step("observe", f"{TITLES.get(threat, threat)} from {src} to {dst}. "
                        f"Model confidence {conf:.2f}, anomaly score {score:.2f}.")
        intel = e.intel.lookup(src)
        step("tool", f"Checked reputation of {src}: {intel['detail']}.", tool="lookup_threat_intel",
             args={"ip": src}, result={k: intel[k] for k in ("known_malicious", "reputation", "source")})
        if intel.get("degraded"):
            e.bus.toast("warning", "Threat-intel providers unavailable", "Using the local fallback feed")
        asset = self.asset_of(src, dst)
        owner = self.owner_for(asset)
        step("tool", f"Asset {asset} belongs to {owner['name']} (criticality {owner['criticality']}/3).",
             tool="get_asset_owner", args={"ip": asset},
             result={"owner": owner["name"], "criticality": owner["criticality"]})
        sev, reasons = self.score(threat, intel, owner)
        step("thought", f"Severity {sev}/5: " + "; ".join(reasons) + ".")

        allow = src in e.agent.allowlist
        plan = [] if allow else self.plan(threat, src, sev)

        inc_id = e.db.x(
            "INSERT INTO incidents(ts,src_ip,dst_ip,threat_type,severity,confidence,anomaly_score,count,status,"
            "actions,trace,intel,owner,true_label,notified,updated) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (time.time(), src, dst, threat, sev, conf, score, 1, "open", "[]", "[]", json.dumps(intel),
             owner["name"], ev["label"], 0, time.time()))

        actions, status, pending = ["alert"], "open", None
        ttl = int(S.get("block_ttl_minutes", 60))
        if allow:
            step("decision", f"{src} is on the allowlist, so it is never blocked. Alert only.")
            actions.append("skip_block:allowlisted")
        for act in plan:
            kind = "block" if act == "block_ip" else "isolate"
            if act == "queue_for_analyst":
                step("decision", "Evidence is not strong enough for automatic containment. Queued for an analyst.")
                actions.append("queue_for_analyst")
            elif not S.get("auto_response", True):
                step("decision", f"Auto-response is switched off, so {act} is only recommended.")
                actions.append("recommend:" + act)
            elif act == "isolate_host" and S.get("approval_for_isolation", False):
                step("decision", f"Isolating {src} cuts a machine off the network, so it waits for analyst approval.")
                actions.append("awaiting_approval:isolate_host")
                status, pending = "pending_approval", {"kind": "isolate", "ip": src}
            else:
                step("decision", f"Containing the threat: {act.replace('_', ' ')} {src}.")
                res = e.contain(kind, src, f"{threat} (incident #{inc_id})", inc_id, "agent", ttl, in_engine=True)
                step("tool", ("DRY-RUN " if res["dry_run"] else "") + (
                    "executed: " + "; ".join(res["commands"]) if res["ok"] else f"FAILED: {res['error']}"),
                    tool=act, args={"ip": src},
                    result={"ok": res["ok"], "dry_run": res["dry_run"], "commands": res["commands"]})
                actions.append(act if res["ok"] else "failed:" + act)

        notified = sev >= int(S.get("notify_min_severity", 2))
        now = time.time()
        inc = {"id": inc_id, "time": time.strftime("%H:%M:%S"), "last": now, "count": 1, "src_ip": src,
               "dst_ip": dst, "threat_type": threat, "severity": sev, "actions": actions,
               "explanation": "; ".join(reasons), "intel_malicious": bool(intel["known_malicious"]),
               "true_label": ev["label"], "notified": notified, "escalated": False, "owner": owner["name"]}
        if notified:
            step("tool", f"Wrote a plain-language message for {owner['name']}.", tool="notify_owner",
                 args={"owner": owner["name"]}, result={"queued": True})
            actions.append("notify_owner")
            e.pnotifier.submit(inc, owner)
        try:
            ms = round((time.time() - ev["timestamp"].timestamp()) * 1000, 1)
        except Exception:
            ms = round((time.time() - t0) * 1000, 1)
        step("summary", f"Handled in {ms} ms. Actions: {', '.join(actions)}.")
        e.db.x("UPDATE incidents SET actions=?, trace=?, status=?, pending=?, notified=?, response_ms=?, updated=? "
               "WHERE id=?", (json.dumps(actions), json.dumps(trace), status, json.dumps(pending) if pending else None,
                              int(notified), ms, time.time(), inc_id))

        done = [a for a in actions if a in ("block_ip", "isolate_host")]
        what = ("blocked source" if "block_ip" in done else "isolated host" if "isolate_host" in done
                else "awaiting approval" if pending else "queued for analyst" if "queue_for_analyst" in actions
                else "alert only")
        tail = " (simulated)" if (done and e.fw.dry_run) else ""
        e.bus.toast("danger" if sev >= 4 else "warning" if sev >= 2 else "info",
                    f"{TITLES.get(threat, threat)} detected",
                    f"{src} → {dst} · severity {sev}/5 · {what}{tail}",
                    inc_id, critical=sev >= 4)
        if pending:
            e.bus.toast("warning", "Approval needed", f"Isolate {src}? Open incident #{inc_id} to approve or deny.", inc_id)
        e.bus.publish("refresh", what="incidents")
        if sev >= 2 and e.llm_enabled():
            e.llm_submit(inc_id)
        return inc

    # ---------- repeated detections ----------
    def escalate(self, inc, ev):
        e = self.e
        src = inc["src_ip"]
        kind = "isolate" if is_internal(src) else "block"
        inc["escalated"] = True
        inc["severity"] = max(inc["severity"], 3)
        status = None
        # escalation must respect the same safety settings as the first response
        if not e.settings.get("auto_response", True):
            act = "recommend:" + ("isolate_host" if kind == "isolate" else "block_ip")
        elif kind == "isolate" and e.settings.get("approval_for_isolation", False):
            act, status = "awaiting_approval:isolate_host", "pending_approval"
            e.db.x("UPDATE incidents SET pending=? WHERE id=?", (json.dumps({"kind": "isolate", "ip": src}), inc["id"]))
            e.bus.toast("warning", "Approval needed", f"Isolate {src}? Activity is persistent. Open incident #{inc['id']}.", inc["id"])
        else:
            res = e.contain(kind, src, f"escalated after {inc['count']} repeated detections", inc["id"], "agent",
                            int(e.settings.get("block_ttl_minutes", 60)), in_engine=True)
            act = ("isolate_host" if kind == "isolate" else "block_ip") if res["ok"] else "failed:escalation"
        if act not in inc["actions"]:
            inc["actions"].append(act)
        row = e.db.one("SELECT trace, actions FROM incidents WHERE id=?", (inc["id"],)) or {}
        trace = json.loads(row.get("trace") or "[]")
        trace.append({"t": 0, "kind": "decision",
                      "text": f"Activity continued ({inc['count']} detections), so the agent escalated: {act}."})
        e.db.x("UPDATE incidents SET severity=?, actions=?, trace=?, updated=? WHERE id=?",
               (inc["severity"], json.dumps(inc["actions"]), json.dumps(trace), time.time(), inc["id"]))
        if status:
            e.db.x("UPDATE incidents SET status=? WHERE id=?", (status, inc["id"]))
        e.bus.toast("danger", "Persistent threat escalated",
                    f"{src}: {act.replace('_', ' ').replace(':', ' ')} after {inc['count']} detections", inc["id"])
        if not inc["notified"]:
            inc["notified"] = True
            inc["actions"].append("notify_owner")
            e.db.x("UPDATE incidents SET notified=1, actions=? WHERE id=?", (json.dumps(inc["actions"]), inc["id"]))
            e.pnotifier.submit(inc, self.owner_for(self.asset_of(src, inc["dst_ip"])))
        e.bus.publish("refresh", what="incidents")
        return act
