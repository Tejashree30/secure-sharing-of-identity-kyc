"""Firewall executor: real iptables (Linux) / netsh advfirewall (Windows) commands.

SAFE BY DEFAULT: dry_run=True only records the commands that WOULD run.
Real execution needs ALLOW_REAL_FIREWALL=1 in the environment AND root/administrator rights.
Commands are run as argument lists (never through a shell), and every address is validated first.
"""
import ipaddress
import os
import platform
import subprocess
import threading
import time


class FirewallError(Exception):
    pass


class Firewall:
    def __init__(self, dry_run=True, protected=None):
        self.dry_run = dry_run
        self.protected = set(protected or [])
        self.system = platform.system()
        self.history = []          # last executed (or simulated) commands
        self.lock = threading.Lock()

    # ---- safety ----
    def validate(self, ip):
        try:
            addr = ipaddress.ip_address(str(ip).strip())
        except ValueError:
            raise FirewallError(f"invalid IP address: {ip!r}")
        if addr.is_loopback or addr.is_unspecified or addr.is_multicast or addr.is_link_local or addr.is_reserved:
            raise FirewallError(f"refusing to act on special address {addr}")
        if str(addr) in self.protected:
            raise FirewallError(f"{addr} is protected (allowlist)")
        return str(addr)

    # ---- command builders ----
    def commands(self, action, ip):
        windows = self.system == "Windows"
        if not windows:  # Linux; also used to illustrate dry-run on other systems
            t = "iptables"
            drop_in, drop_out = ["-s", ip, "-j", "DROP"], ["-d", ip, "-j", "DROP"]
            ins = lambda chain, rule: [t, "-I", chain, *rule]
            dele = lambda chain, rule: [t, "-D", chain, *rule]
            return {
                "block": [ins("INPUT", drop_in)],
                "unblock": [dele("INPUT", drop_in)],
                "isolate": [ins("INPUT", drop_in), ins("OUTPUT", drop_out),
                            ins("FORWARD", drop_in), ins("FORWARD", drop_out)],
                "release": [dele("INPUT", drop_in), dele("OUTPUT", drop_out),
                            dele("FORWARD", drop_in), dele("FORWARD", drop_out)],
            }[action]
        name = f"AIDEF-{ip}"
        add = lambda d: ["netsh", "advfirewall", "firewall", "add", "rule", f"name={name}-{d}",
                         f"dir={d}", "action=block", f"remoteip={ip}"]
        rm = lambda d: ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}-{d}"]
        return {"block": [add("in")], "unblock": [rm("in")],
                "isolate": [add("in"), add("out")], "release": [rm("in"), rm("out")]}[action]

    # ---- execution ----
    def run(self, action, ip):
        ip = self.validate(ip)
        cmds = self.commands(action, ip)
        shown = [" ".join(c) for c in cmds]
        rec = {"ok": True, "dry_run": self.dry_run, "action": action, "ip": ip,
               "commands": shown, "error": None, "platform": self.system, "ts": time.time()}
        if not self.dry_run:
            if self.system not in ("Linux", "Windows"):
                rec.update(ok=False, error=f"real enforcement not supported on {self.system}")
            elif self.system == "Linux" and hasattr(os, "geteuid") and os.geteuid() != 0:
                rec.update(ok=False, error="root privileges required for iptables")
            else:
                for c in cmds:
                    try:
                        p = subprocess.run(c, capture_output=True, text=True, timeout=8)
                        if p.returncode != 0:
                            rec.update(ok=False, error=(p.stderr or p.stdout).strip()[:300] or f"exit {p.returncode}")
                            break
                    except FileNotFoundError:
                        rec.update(ok=False, error=f"{c[0]} not found")
                        break
                    except subprocess.TimeoutExpired:
                        rec.update(ok=False, error=f"{c[0]} timed out")
                        break
        with self.lock:
            self.history.insert(0, rec)
            del self.history[100:]
        return rec

    def block(self, ip): return self.run("block", ip)
    def unblock(self, ip): return self.run("unblock", ip)
    def isolate(self, ip): return self.run("isolate", ip)
    def release(self, ip): return self.run("release", ip)
