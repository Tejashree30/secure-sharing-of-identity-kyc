"""Response agent: observe -> reason -> act -> log.

Actions are SIMULATED (written to an audit log / in-memory firewall set).
Hooks for real enforcement (iptables, cloud security groups, EDR isolation)
are marked in `_enforce`.
"""
import json
from dataclasses import dataclass, field

SEVERITY = {
    "ddos": 3, "exfiltration": 4, "brute_force": 2, "port_scan": 1,
    "unknown_anomaly": 2,
}


@dataclass
class ResponseAgent:
    intel: object
    allowlist: set = field(default_factory=set)
    blocked_ips: set = field(default_factory=set)
    isolated_hosts: set = field(default_factory=set)
    audit: list = field(default_factory=list)

    def decide(self, event) -> dict:
        threat = event["threat_type"]
        src, dst = event["src_ip"], event["dst_ip"]
        rep = self.intel.lookup(src)
        sev = SEVERITY.get(threat, 1)
        # Threat intelligence escalates severity
        if rep["known_malicious"]:
            sev += 1
        # Low-confidence anomaly with clean reputation -> analyst review, not auto-action
        if threat == "unknown_anomaly" and not rep["known_malicious"]:
            sev = min(sev, 1)

        actions = ["alert"]
        if src in self.allowlist:
            actions = ["alert", "skip_block:allowlisted"]
        else:
            # never auto-isolate an internal machine on an unconfirmed anomaly alone
            # (persistent anomalies are escalated by `escalate`)
            if sev >= 3 and src.startswith("10.0.") and threat != "unknown_anomaly":
                actions.append("isolate_host")
            elif sev >= 2 and not src.startswith("10.0."):
                actions.append("block_ip")
            elif sev == 1:
                actions.append("queue_for_analyst")
            if threat == "exfiltration" and src.startswith("10.0."):
                actions.append("isolate_host")
        return {"severity": sev, "actions": list(dict.fromkeys(actions)), "intel": rep}

    def escalate(self, src, count):
        """Activity that keeps coming after the first alert is no longer a one-off:
        stop it. External source -> block IP, internal source -> isolate host."""
        if src in self.allowlist or src in self.blocked_ips or src in self.isolated_hosts:
            return None
        action = "isolate_host" if src.startswith("10.0.") else "block_ip"
        (self.isolated_hosts if action == "isolate_host" else self.blocked_ips).add(src)
        self.audit.append({"src_ip": src, "actions": [action], "explanation":
                           f"escalated after {count} repeated detections -> {action}"})
        return action

    def act(self, event):
        d = self.decide(event)
        src = event["src_ip"]
        for a in d["actions"]:
            if a == "block_ip":
                self.blocked_ips.add(src)       # _enforce: iptables -A INPUT -s <ip> -j DROP
            elif a == "isolate_host":
                self.isolated_hosts.add(src)    # _enforce: EDR / NAC quarantine VLAN
        rec = {
            "time": str(event["timestamp"]), "src_ip": src, "dst_ip": event["dst_ip"],
            "threat_type": event["threat_type"], "confidence": round(float(event["confidence"]), 3),
            "severity": d["severity"], "actions": d["actions"],
            "reputation": d["intel"]["reputation"],
            "explanation": (f"{event['threat_type']} detected (conf {event['confidence']:.2f}, "
                            f"anomaly {event['anomaly_score']:.2f}); intel malicious="
                            f"{d['intel']['known_malicious']}; severity {d['severity']} -> {', '.join(d['actions'])}"),
        }
        self.audit.append(rec)
        return rec

    def save_audit(self, path):
        with open(path, "w") as f:
            json.dump(self.audit, f, indent=2)
