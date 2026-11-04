"""Real-time engine.

Loop (every TICK_SECONDS):
  1. a batch of live flow events arrives (normal traffic + attack campaigns)
  2. FIREWALL: traffic from blocked / isolated sources is dropped before analysis
  3. the ML detector classifies the remaining events
  4. the agent decides + acts (alert / block / isolate), merging duplicates into one incident
  5. the notifier tells the owner of the affected data in plain language
"""
import threading
import time
import traceback
from collections import deque

import numpy as np
import pandas as pd

import config
from agent import ResponseAgent
from data_gen import ATTACK_KINDS_ALL, UNKNOWN_ATTACKS, generate, make_event, rand_ip
from detector import HybridDetector
from notifier import Notifier
from threat_intel import ThreatIntel


class Engine:
    def __init__(self):
        self.rng = np.random.default_rng()
        print("[engine] training detector on historical logs ...")
        df = generate()
        self.det = HybridDetector().fit(df[~df["label"].isin(UNKNOWN_ATTACKS)])
        self.agent = ResponseAgent(intel=ThreatIntel(), allowlist=set(config.ALLOWLIST))
        self.notifier = Notifier()
        self.lock = threading.Lock()
        self.feed = deque(maxlen=60)
        self.incidents = []                 # newest first
        self.open = {}                      # (src, type) -> incident (for de-duplication)
        self.campaigns = []
        self.timeline = deque(maxlen=60)    # (events, threats, dropped) per tick
        self.c = dict(events=0, threats=0, dropped=0, tp=0, fp=0, fn=0, tn=0, blocked_total=0, started=time.time())
        self.running = False
        print("[engine] ready")

    def _next_id(self):
        self._id = getattr(self, "_id", 0) + 1
        return self._id

    # ---------- control ----------
    def start(self):
        self.running = True
        threading.Thread(target=self._loop, daemon=True).start()

    def start_attack(self, kind):
        if kind not in ATTACK_KINDS_ALL:
            return False
        internal_src = kind in ("exfiltration", "c2_beacon")
        src = rand_ip(self.rng, internal_src)
        dst = rand_ip(self.rng, not internal_src)
        with self.lock:
            self.campaigns.append({"kind": kind, "src": src, "dst": dst, "remaining": int(self.rng.integers(6, 12))})
        return True

    def unblock(self, ip):
        with self.lock:
            self.agent.blocked_ips.discard(ip)
            self.agent.isolated_hosts.discard(ip)
            for k in [k for k in self.open if k[0] == ip]:
                del self.open[k]
        return True

    # ---------- main loop ----------
    def _loop(self):
        while self.running:
            t0 = time.time()
            try:
                self._tick()
            except Exception:
                traceback.print_exc()
            time.sleep(max(0.05, config.TICK_SECONDS - (time.time() - t0)))

    def _tick(self):
        with self.lock:
            if config.AUTO_ATTACKS and self.rng.random() < config.ATTACK_CHANCE_PER_TICK:
                kind = str(self.rng.choice(ATTACK_KINDS_ALL))
                internal_src = kind in ("exfiltration", "c2_beacon")
                self.campaigns.append({"kind": kind, "src": rand_ip(self.rng, internal_src),
                                       "dst": rand_ip(self.rng, not internal_src),
                                       "remaining": int(self.rng.integers(6, 12))})
            batch = [make_event("normal", self.rng) for _ in range(int(self.rng.integers(3, 7)))]
            for camp in list(self.campaigns):
                batch += [make_event(camp["kind"], self.rng, camp["src"], camp["dst"]) for _ in range(2)]
                camp["remaining"] -= 1
                if camp["remaining"] <= 0:
                    self.campaigns.remove(camp)

            # ---- firewall: drop traffic from blocked / isolated sources ----
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
                res = self.det.predict(df)
                for _, ev in res.iterrows():
                    threats += self._handle(ev)

            self.c["events"] += len(batch)
            self.c["dropped"] += dropped
            self.timeline.append((len(batch), threats, dropped))

    def _feed(self, e, verdict, ttype, score, action):
        self.feed.appendleft({
            "time": time.strftime("%H:%M:%S"), "src": e["src_ip"], "dst": e["dst_ip"],
            "port": int(e["dst_port"]), "bytes": int(e["bytes_out"]), "verdict": verdict,
            "type": ttype, "score": round(float(score), 2), "action": action})

    def _handle(self, ev):
        is_attack = ev["label"] != "normal"
        if ev["verdict"] != "threat":
            self.c["fn" if is_attack else "tn"] += 1
            self._feed(ev, "normal" if not is_attack else "missed", "-", ev["anomaly_score"], "allowed")
            return 0

        self.c["tp" if is_attack else "fp"] += 1
        self.c["threats"] += 1
        key = (ev["src_ip"], ev["threat_type"])
        now = time.time()
        inc = self.open.get(key)
        if inc and now - inc["last"] < config.INCIDENT_COOLDOWN:
            inc["count"] += 1
            inc["last"] = now
            action = "merged into incident #%d" % inc["id"]
            if inc["count"] >= config.ESCALATE_AFTER:
                esc = self.agent.escalate(ev["src_ip"], inc["count"])
                if esc:
                    self.c["blocked_total"] += 1
                    inc["actions"].append(esc)
                    inc["severity"] = max(inc["severity"], 3)
                    action = f"ESCALATED -> {esc}"
                    if not inc["notified"]:            # owner is told once the problem proves persistent
                        inc["notified"] = True
                        self.notifier.submit(inc)
            self._feed(ev, "threat", ev["threat_type"], ev["anomaly_score"], action)
            return 1

        was_blocked = len(self.agent.blocked_ips) + len(self.agent.isolated_hosts)
        rec = self.agent.act(ev)
        if len(self.agent.blocked_ips) + len(self.agent.isolated_hosts) > was_blocked:
            self.c["blocked_total"] += 1
        inc = {
            "id": self._next_id(), "time": time.strftime("%H:%M:%S"), "last": now, "count": 1,
            "src_ip": ev["src_ip"], "dst_ip": ev["dst_ip"], "threat_type": ev["threat_type"],
            "severity": rec["severity"], "actions": rec["actions"], "explanation": rec["explanation"],
            "intel_malicious": bool(rec["reputation"] >= 0.85 or "malicious=True" in rec["explanation"]),
            "true_label": ev["label"], "notified": rec["severity"] >= config.NOTIFY_MIN_SEVERITY,
        }
        self.open[key] = inc
        self.incidents.insert(0, inc)
        del self.incidents[60:]
        if inc["notified"]:
            self.notifier.submit(inc)
        self._feed(ev, "threat", ev["threat_type"], ev["anomaly_score"], ", ".join(rec["actions"]))
        return 1

    # ---------- snapshot for the dashboard ----------
    def state(self):
        with self.lock:
            c = dict(self.c)
            tp, fp, fn = c["tp"], c["fp"], c["fn"]
            precision = tp / (tp + fp) if tp + fp else None
            recall = tp / (tp + fn) if tp + fn else None
            return {
                "uptime": int(time.time() - c["started"]),
                "counters": {k: c[k] for k in ("events", "threats", "dropped", "blocked_total")},
                "quality": {"precision": precision, "recall": recall, "false_alarms": fp, "missed": fn},
                "feed": list(self.feed)[:25],
                "incidents": [{k: v for k, v in i.items() if k != "last"} for i in self.incidents[:15]],
                "blocked": sorted(self.agent.blocked_ips),
                "isolated": sorted(self.agent.isolated_hosts),
                "timeline": list(self.timeline),
                "notifications": self.notifier.snapshot()[:10],
                "active_campaigns": len(self.campaigns),
                "llm": bool(config.ANTHROPIC_API_KEY),
                "email": bool(config.SMTP_HOST and config.SMTP_USER and config.SMTP_PASS),
            }
