"""Threat-intelligence service.

Providers (used when their key is set in the environment):
  ABUSEIPDB_KEY   -> https://api.abuseipdb.com/api/v2/check
  VT_API_KEY      -> https://www.virustotal.com/api/v3/ip_addresses/<ip>
If no provider is configured, or all fail, it falls back to the local mock feed and flags the
result as `degraded` so the UI can warn the operator. Results are cached for `ttl` seconds.
"""
import ipaddress
import json
import os
import threading
import time
import urllib.request

from threat_intel import ThreatIntel as MockFeed


def parse_abuseipdb(js):
    d = js["data"]
    score = int(d.get("abuseConfidenceScore", 0))
    return {"known_malicious": score >= 50, "reputation": round(score / 100, 2), "source": "abuseipdb",
            "detail": f"AbuseIPDB confidence {score}/100, {d.get('totalReports', 0)} reports"}


def parse_virustotal(js):
    st = js["data"]["attributes"]["last_analysis_stats"]
    mal, sus = int(st.get("malicious", 0)), int(st.get("suspicious", 0))
    return {"known_malicious": mal >= 3, "reputation": round(min(1.0, (mal + 0.5 * sus) / 10), 2),
            "source": "virustotal", "detail": f"VirusTotal: {mal} engines malicious, {sus} suspicious"}


class IntelService:
    def __init__(self, ttl=600, timeout=4.0):
        self.ttl, self.timeout = ttl, timeout
        self.cache, self.lock = {}, threading.Lock()
        self.mock = MockFeed()
        self.errors, self.last_error, self.last_error_ts = 0, None, 0.0
        self.lookups = 0

    # --- configuration (read live so keys can be set without restart) ---
    def configured(self):
        out = []
        if os.getenv("ABUSEIPDB_KEY"): out.append("abuseipdb")
        if os.getenv("VT_API_KEY"): out.append("virustotal")
        return out

    def _http_json(self, url, headers):
        req = urllib.request.Request(url, headers={**headers, "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            return json.loads(r.read().decode("utf-8"))

    def _abuse(self, ip):
        js = self._http_json(f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90",
                             {"Key": os.environ["ABUSEIPDB_KEY"]})
        return parse_abuseipdb(js)

    def _vt(self, ip):
        js = self._http_json(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                             {"x-apikey": os.environ["VT_API_KEY"]})
        return parse_virustotal(js)

    @staticmethod
    def _internal(ip):
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False

    def lookup(self, ip):
        self.lookups += 1
        if self._internal(ip):
            return {"ip": ip, "known_malicious": False, "reputation": 0.0, "source": "internal",
                    "detail": "internal address, not checked", "degraded": False}
        with self.lock:
            hit = self.cache.get(ip)
        if hit and time.time() - hit[0] < self.ttl:
            return hit[1]

        results, failed = [], False
        for name, fn in (("abuseipdb", self._abuse), ("virustotal", self._vt)):
            if name not in self.configured():
                continue
            try:
                results.append(fn(ip))
            except Exception as e:   # network, quota, bad key, bad JSON ...
                failed = True
                self.errors += 1
                self.last_error, self.last_error_ts = f"{name}: {e.__class__.__name__}: {e}", time.time()

        if results:
            best = max(results, key=lambda r: r["reputation"])
            res = {"ip": ip, "known_malicious": any(r["known_malicious"] for r in results),
                   "reputation": best["reputation"], "source": "+".join(r["source"] for r in results),
                   "detail": "; ".join(r["detail"] for r in results), "degraded": False}
        else:
            m = self.mock.lookup(ip)
            res = {"ip": ip, "known_malicious": m["known_malicious"], "reputation": m["reputation"],
                   "source": "mock", "degraded": bool(self.configured()) and failed,
                   "detail": "local mock feed" + (" (live providers failed)" if failed else "")}
        with self.lock:
            self.cache[ip] = (time.time(), res)
        return res
