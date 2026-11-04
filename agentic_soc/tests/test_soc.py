"""Unit tests for the platform layer. Run from the project folder:  python -m unittest tests.test_soc -v"""
import json
import os
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from soc.capture import FlowAggregator
from soc.db import DB
from soc.firewall import Firewall, FirewallError
from soc.intel import IntelService, parse_abuseipdb, parse_virustotal
from soc.llm_agent import ToolBox, run_agent
from soc.responder import Responder, is_internal


class FirewallTests(unittest.TestCase):
    def test_dry_run_records_commands_and_applies_nothing(self):
        fw = Firewall(dry_run=True)
        r = fw.block("52.20.30.40")
        self.assertTrue(r["ok"] and r["dry_run"])
        self.assertIn("-s 52.20.30.40", r["commands"][0])
        self.assertEqual(len(fw.history), 1)

    def test_isolate_blocks_both_directions(self):
        cmds = Firewall(dry_run=True).isolate("10.0.3.4")["commands"]
        self.assertEqual(len(cmds), 4)
        self.assertTrue(any("OUTPUT" in c for c in cmds) and any("INPUT" in c for c in cmds))

    def test_refuses_dangerous_or_invalid_addresses(self):
        fw = Firewall(dry_run=True, protected={"10.0.0.2"})
        for bad in ["127.0.0.1", "0.0.0.0", "not-an-ip", "224.0.0.1", "10.0.0.2", "1.2.3.4; rm -rf /", ""]:
            with self.assertRaises(FirewallError, msg=bad):
                fw.block(bad)

    def test_real_mode_without_root_fails_safely(self):
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            self.skipTest("running as root; would really call iptables")
        r = Firewall(dry_run=False).block("52.20.30.40")
        self.assertFalse(r["ok"])


class IntelTests(unittest.TestCase):
    def test_parse_abuseipdb(self):
        r = parse_abuseipdb({"data": {"abuseConfidenceScore": 87, "totalReports": 14}})
        self.assertTrue(r["known_malicious"])
        self.assertEqual(r["reputation"], 0.87)
        self.assertFalse(parse_abuseipdb({"data": {"abuseConfidenceScore": 3}})["known_malicious"])

    def test_parse_virustotal(self):
        js = {"data": {"attributes": {"last_analysis_stats": {"malicious": 7, "suspicious": 2, "harmless": 60}}}}
        r = parse_virustotal(js)
        self.assertTrue(r["known_malicious"])
        self.assertFalse(parse_virustotal({"data": {"attributes": {"last_analysis_stats": {"malicious": 1}}}})["known_malicious"])

    def test_internal_addresses_skip_lookup(self):
        self.assertEqual(IntelService().lookup("10.0.1.5")["source"], "internal")

    def test_provider_failure_falls_back_and_is_flagged(self):
        svc = IntelService(timeout=0.2)
        os.environ["ABUSEIPDB_KEY"] = "dummy"
        try:
            svc._abuse = lambda ip: (_ for _ in ()).throw(TimeoutError("boom"))
            r = svc.lookup("52.20.30.50")
        finally:
            del os.environ["ABUSEIPDB_KEY"]
        self.assertEqual(r["source"], "mock")
        self.assertTrue(r["degraded"])
        self.assertEqual(svc.errors, 1)
        self.assertIn("TimeoutError", svc.last_error)

    def test_results_are_cached(self):
        svc = IntelService()
        a = svc.lookup("52.20.30.70")
        self.assertIs(a, svc.lookup("52.20.30.70"))


class CaptureTests(unittest.TestCase):
    def test_port_scan_traffic_becomes_scan_like_features(self):
        agg = FlowAggregator(window=5)
        t = 1000.0
        for i in range(60):
            agg.add_packet("52.20.30.60", "10.0.2.5", 1000 + i, 60, syn=True, ts=t + i * 0.05)
        self.assertEqual(agg.flush(now=t + 1), [])            # window not over yet
        f = agg.flush(now=t + 6)[0]
        self.assertEqual(f["unique_ports"], 60)
        self.assertGreater(f["conn_per_min"], 500)
        self.assertEqual(f["label"], "live")

    def test_auth_port_syns_count_as_failed_logins(self):
        agg = FlowAggregator(window=1)
        for i in range(12):
            agg.add_packet("52.20.30.60", "10.0.2.5", 22, 60, syn=True, ts=10 + i * 0.01)
        f = agg.flush(now=20)[0]
        self.assertEqual(f["failed_logins"], 10)

    def test_reverse_direction_gives_bytes_in(self):
        agg = FlowAggregator(window=1)
        agg.add_packet("10.0.1.5", "8.8.8.8", 443, 500, ts=1)
        agg.add_packet("8.8.8.8", "10.0.1.5", 50000, 1500, ts=1)
        out = {f["src_ip"]: f for f in agg.flush(now=5)}
        self.assertEqual(out["10.0.1.5"]["bytes_in"], 1500)


class FakeEngine:
    """Just enough engine surface for ToolBox / Responder policy tests."""
    def __init__(self, tmp):
        self.db = DB(os.path.join(tmp, "t.db"))
        self.db.x("INSERT INTO owners(prefix,name,email,criticality) VALUES('10.0.1.','Finance','f@x.com',3)")
        self.settings = {"auto_response": True, "approval_for_isolation": False}
        self.agent = SimpleNamespace(allowlist={"10.0.0.2"}, blocked_ips=set(), isolated_hosts=set())
        self.intel = IntelService()
        self.contained = []
        self.responder = Responder(self)

    def contain(self, kind, ip, reason, incident_id=None, by="x", ttl=None, in_engine=False):
        self.contained.append((kind, ip, by))
        return {"ok": True, "dry_run": True, "commands": [], "error": None}


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.e = FakeEngine(self.tmp)

    def test_severity_rules(self):
        intel_bad = {"known_malicious": True}
        intel_ok = {"known_malicious": False}
        crit = {"name": "Finance", "criticality": 3}
        norm = {"name": "Ops", "criticality": 1}
        self.assertEqual(Responder.score("port_scan", intel_ok, norm)[0], 1)
        self.assertEqual(Responder.score("port_scan", intel_bad, norm)[0], 2)          # intel escalates
        self.assertEqual(Responder.score("ddos", intel_ok, crit)[0], 4)                # critical asset escalates
        self.assertEqual(Responder.score("unknown_anomaly", intel_ok, norm)[0], 1)     # clean anomaly capped

    def test_plan_rules(self):
        self.assertEqual(Responder.plan("exfiltration", "10.0.1.9", 4), ["isolate_host"])
        self.assertEqual(Responder.plan("ddos", "8.8.8.8", 3), ["block_ip"])
        self.assertEqual(Responder.plan("port_scan", "8.8.8.8", 1), ["queue_for_analyst"])
        self.assertEqual(Responder.plan("unknown_anomaly", "10.0.1.9", 3), ["queue_for_analyst"])

    def test_owner_lookup_longest_prefix(self):
        self.e.db.x("INSERT INTO owners(prefix,name,email,criticality) VALUES('10.0.1.7','Payroll','p@x.com',3)")
        self.assertEqual(self.e.responder.owner_for("10.0.1.7").get("name"), "Payroll")
        self.assertEqual(self.e.responder.owner_for("10.0.1.8").get("name"), "Finance")
        self.assertEqual(self.e.responder.owner_for("172.16.0.1")["criticality"], 1)

    def test_is_internal(self):
        self.assertTrue(is_internal("10.0.1.5") and is_internal("192.168.1.1"))
        self.assertFalse(is_internal("8.8.8.8") or is_internal("garbage"))


def tool_use(name, args, id_="t1"):
    return SimpleNamespace(type="tool_use", name=name, input=args, id=id_)


def text(t):
    return SimpleNamespace(type="text", text=t)


class ScriptedClient:
    """Stands in for the Anthropic client: replays scripted model turns."""
    def __init__(self, turns):
        self.turns, self.calls = list(turns), 0
        self.messages = SimpleNamespace(create=self._create)

    def _create(self, **kw):
        self.calls += 1
        return self.turns.pop(0)


class LLMAgentTests(unittest.TestCase):
    def setUp(self):
        self.e = FakeEngine(tempfile.mkdtemp())
        self.row = {"id": 1, "src_ip": "52.20.30.40", "dst_ip": "10.0.1.20", "threat_type": "ddos", "severity": 3,
                    "count": 2, "owner": "Finance", "actions": '["alert"]', "intel": "{}"}
        self.tb = ToolBox(self.e, self.row)

    def test_agent_loop_calls_tools_then_summarises(self):
        client = ScriptedClient([
            SimpleNamespace(stop_reason="tool_use", content=[text("checking"), tool_use("block_ip", {"ip": "52.20.30.40", "reason": "flood"})]),
            SimpleNamespace(stop_reason="end_turn", content=[text("The automatic block was correct.")]),
        ])
        out = run_agent(client, "m", self.row, self.tb)
        self.assertEqual(out, "The automatic block was correct.")
        self.assertEqual(self.e.contained, [("block", "52.20.30.40", "llm-agent")])
        self.assertEqual(client.calls, 2)

    def test_guardrails_block_actions_outside_the_incident(self):
        self.assertIn("not part of this incident", self.tb.dispatch("block_ip", {"ip": "8.8.8.8", "reason": "x"})["error"])
        self.assertEqual(self.e.contained, [])

    def test_guardrail_allowlist_and_wrong_tool_for_address_type(self):
        row = dict(self.row, src_ip="10.0.0.2")
        tb = ToolBox(self.e, row)
        self.assertIn("allowlisted", tb.dispatch("isolate_host", {"ip": "10.0.0.2", "reason": "x"})["error"])
        self.assertIn("use isolate_host", self.tb.dispatch("block_ip", {"ip": "10.0.1.20", "reason": "x"})["error"])

    def test_guardrail_respects_auto_response_and_approval(self):
        self.e.settings["auto_response"] = False
        self.assertIn("switched off", self.tb.dispatch("block_ip", {"ip": "52.20.30.40", "reason": "x"})["error"])
        self.e.settings.update(auto_response=True, approval_for_isolation=True)
        self.assertIn("approval", self.tb.dispatch("isolate_host", {"ip": "10.0.1.20", "reason": "x"})["error"])
        self.assertEqual(self.e.contained, [])

    def test_bad_tool_and_bad_args_do_not_crash(self):
        self.assertIn("unknown tool", self.tb.dispatch("format_disk", {})["error"])
        self.assertIn("bad arguments", self.tb.dispatch("block_ip", {"nope": 1})["error"])

    def test_step_limit(self):
        loop = SimpleNamespace(stop_reason="tool_use", content=[tool_use("add_note", {"text": "hi"})])
        client = ScriptedClient([loop] * 10)
        self.assertIn("step limit", run_agent(client, "m", self.row, self.tb, max_turns=3))
        self.assertEqual(client.calls, 3)


class DBTests(unittest.TestCase):
    def test_settings_roundtrip_and_audit(self):
        db = DB(os.path.join(tempfile.mkdtemp(), "d.db"))
        db.set_setting("k", {"a": [1, 2]})
        self.assertEqual(db.get_setting("k"), {"a": [1, 2]})
        db.set_setting("k", 5)
        self.assertEqual(db.get_setting("k"), 5)
        db.audit("me", "act", "target", "detail")
        self.assertEqual(db.q("SELECT actor FROM audit")[0]["actor"], "me")


if __name__ == "__main__":
    unittest.main()
