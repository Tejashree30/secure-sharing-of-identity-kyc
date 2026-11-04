"""Live packet capture with Scapy -> per-flow features compatible with the ML detector.

FlowAggregator is pure Python and fully testable without root or Scapy.
LiveSniffer needs `pip install scapy` and root/administrator rights (e.g. `sudo python server.py`).

Feature mapping (same columns as data_gen.FEATURES):
  duration, bytes_out, bytes_in, packets, conn_per_min (SYNs per minute), unique_ports,
  dst_port (most used), hour, failed_logins (heuristic: SYNs to auth ports beyond 2 per window).
"""
import collections
import os
import threading
import time

AUTH_PORTS = {21, 22, 23, 3389, 5900}


class FlowAggregator:
    def __init__(self, window=5.0):
        self.window = window
        self.flows = {}
        self.lock = threading.Lock()

    def add_packet(self, src, dst, dport, length, syn=False, ts=None):
        ts = ts if ts is not None else time.time()
        with self.lock:
            f = self.flows.get((src, dst))
            if f is None:
                f = self.flows[(src, dst)] = {"first": ts, "last": ts, "pkts": 0, "bytes": 0,
                                              "ports": collections.Counter(), "syn": 0, "auth_syn": 0}
            f["last"] = ts
            f["pkts"] += 1
            f["bytes"] += int(length)
            f["ports"][int(dport)] += 1
            if syn:
                f["syn"] += 1
                if int(dport) in AUTH_PORTS:
                    f["auth_syn"] += 1

    def flush(self, now=None, force=False):
        now = now if now is not None else time.time()
        out = []
        with self.lock:
            ready = [k for k, f in self.flows.items() if force or now - f["first"] >= self.window]
            for key in ready:
                f = self.flows[key]
                src, dst = key
                rev = self.flows.get((dst, src))
                dur = max(f["last"] - f["first"], 0.001)
                out.append({
                    "src_ip": src, "dst_ip": dst, "label": "live",
                    "duration": dur, "bytes_out": f["bytes"], "bytes_in": rev["bytes"] if rev else 0,
                    "packets": f["pkts"], "failed_logins": max(0, f["auth_syn"] - 2),
                    "conn_per_min": max(f["syn"], 1) * 60.0 / max(self.window, dur),
                    "unique_ports": len(f["ports"]), "dst_port": f["ports"].most_common(1)[0][0],
                    "hour": time.localtime(now).tm_hour})
            for key in ready:
                del self.flows[key]
        return out


class LiveSniffer:
    def __init__(self, iface=None, window=5.0):
        self.agg = FlowAggregator(window)
        self.iface, self.thread, self.error, self.running = iface, None, None, False

    @staticmethod
    def available():
        try:
            import scapy.all  # noqa: F401
        except Exception as e:
            return False, f"scapy not installed ({e.__class__.__name__}); run: pip install scapy"
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            return False, "packet capture needs root privileges (run with sudo)"
        return True, "ok"

    def start(self):
        ok, msg = self.available()
        if not ok:
            self.error = msg
            return False, msg
        self.running = True
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        return True, "capturing"

    def _run(self):
        try:
            from scapy.all import IP, TCP, UDP, sniff

            def cb(p):
                if IP not in p:
                    return
                if TCP in p:
                    dport, syn = p[TCP].dport, bool(p[TCP].flags & 0x02) and not (p[TCP].flags & 0x10)
                elif UDP in p:
                    dport, syn = p[UDP].dport, False
                else:
                    return
                self.agg.add_packet(p[IP].src, p[IP].dst, dport, len(p), syn)

            sniff(prn=cb, store=False, iface=self.iface, stop_filter=lambda _p: not self.running)
        except Exception as e:
            self.error = f"capture stopped: {e}"
            self.running = False

    def drain(self):
        return self.agg.flush()

    def stop(self):
        self.running = False
