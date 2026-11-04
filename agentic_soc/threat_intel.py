"""Mock threat-intelligence feed.

In production, replace `lookup` with calls to a real feed (AbuseIPDB, VirusTotal,
AlienVault OTX, MISP). Here a local blocklist is simulated deterministically so
the prototype runs offline.
"""
import hashlib


class ThreatIntel:
    def __init__(self, bad_fraction=0.15):
        self.bad_fraction = bad_fraction

    def lookup(self, ip: str) -> dict:
        h = int(hashlib.sha256(ip.encode()).hexdigest(), 16) % 1000 / 1000
        bad = h < self.bad_fraction
        return {"ip": ip, "known_malicious": bad, "reputation": round(1 - h, 2) if bad else round(h * 0.3, 2)}
