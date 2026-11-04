"""Optional LLM analyst: a tool-using agent loop (Claude tool use).

It reviews an incident AFTER the deterministic policy has already contained it, and may call tools to
gather more context or take extra, tightly guarded actions. This is the same observe-think-act pattern
that LangChain / AutoGen / CrewAI wrap; it is written directly against the Anthropic SDK to avoid
heavy dependencies, and the ToolBox below can be wrapped as LangChain tools unchanged.

Guardrails enforced in code (not by the prompt): tools may only act on addresses that belong to the
incident, never on allowlisted addresses, only when auto-response is on, and isolation still honours the
approval setting.
"""
import ipaddress
import json
import time

SYSTEM = (
    "You are a cautious SOC analyst agent. A detection has already been handled by an automatic policy. "
    "Review the incident, use tools only when they add evidence, prefer the least destructive action, and "
    "never act on addresses outside the incident. Finish with a 2-3 sentence plain-language assessment "
    "that says whether the automatic response looks right and what the owner should do."
)

TOOLS = [
    {"name": "lookup_threat_intel", "description": "Look up IP reputation in the threat-intelligence feeds.",
     "input_schema": {"type": "object", "properties": {"ip": {"type": "string"}}, "required": ["ip"]}},
    {"name": "get_asset_owner", "description": "Find the owner and criticality of an internal asset by IP.",
     "input_schema": {"type": "object", "properties": {"ip": {"type": "string"}}, "required": ["ip"]}},
    {"name": "block_ip", "description": "Block an external IP address at the firewall.",
     "input_schema": {"type": "object", "properties": {"ip": {"type": "string"}, "reason": {"type": "string"}},
                      "required": ["ip", "reason"]}},
    {"name": "isolate_host", "description": "Isolate an internal host from the network.",
     "input_schema": {"type": "object", "properties": {"ip": {"type": "string"}, "reason": {"type": "string"}},
                      "required": ["ip", "reason"]}},
    {"name": "add_note", "description": "Attach an analyst note to the incident.",
     "input_schema": {"type": "object", "properties": {"text": {"type": "string"}}, "required": ["text"]}},
]


class ToolBox:
    def __init__(self, engine, incident_row):
        self.e, self.inc = engine, incident_row
        self.allowed_ips = {incident_row["src_ip"], incident_row["dst_ip"]}
        self.trace = []

    def _log(self, name, args, result):
        self.trace.append({"t": 0, "kind": "llm_tool", "text": f"LLM analyst called {name}({json.dumps(args)[:120]})",
                           "tool": name, "args": args, "result": result})

    def _check_ip(self, ip):
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return "invalid IP address"
        if ip not in self.allowed_ips:
            return "address is not part of this incident"
        if ip in self.e.agent.allowlist:
            return "address is allowlisted"
        return None

    def dispatch(self, name, args):
        try:
            fn = {"lookup_threat_intel": self.lookup_threat_intel, "get_asset_owner": self.get_asset_owner,
                  "block_ip": self.block_ip, "isolate_host": self.isolate_host, "add_note": self.add_note}.get(name)
            if fn is None:
                return {"error": f"unknown tool {name}"}
            out = fn(**args)
        except TypeError as ex:
            out = {"error": f"bad arguments: {ex}"}
        except Exception as ex:
            out = {"error": f"{ex.__class__.__name__}: {ex}"}
        self._log(name, args, out)
        return out

    def lookup_threat_intel(self, ip):
        err = None if ip in self.allowed_ips else "address is not part of this incident"
        return {"error": err} if err else self.e.intel.lookup(ip)

    def get_asset_owner(self, ip):
        o = self.e.responder.owner_for(ip)
        return {"owner": o["name"], "criticality": o["criticality"]}

    def _contain(self, kind, ip, reason):
        err = self._check_ip(ip)
        if err:
            return {"ok": False, "error": err}
        if not self.e.settings.get("auto_response", True):
            return {"ok": False, "error": "auto-response is switched off"}
        if kind == "isolate" and self.e.settings.get("approval_for_isolation"):
            return {"ok": False, "error": "isolation requires analyst approval; ask a human"}
        res = self.e.contain(kind, ip, f"LLM analyst: {reason[:120]}", self.inc["id"], "llm-agent")
        return {"ok": res["ok"], "error": res["error"], "dry_run": res["dry_run"]}

    def block_ip(self, ip, reason):
        from .responder import is_internal
        if is_internal(ip):
            return {"ok": False, "error": "internal address: use isolate_host"}
        return self._contain("block", ip, reason)

    def isolate_host(self, ip, reason):
        from .responder import is_internal
        if not is_internal(ip):
            return {"ok": False, "error": "external address: use block_ip"}
        return self._contain("isolate", ip, reason)

    def add_note(self, text):
        return {"ok": True, "note": str(text)[:500]}


def run_agent(client, model, incident_row, toolbox, max_turns=6):
    ctx = {k: incident_row[k] for k in ("id", "src_ip", "dst_ip", "threat_type", "severity", "count", "owner")}
    ctx["actions_taken"] = json.loads(incident_row.get("actions") or "[]")
    ctx["intel"] = json.loads(incident_row.get("intel") or "{}")
    messages = [{"role": "user", "content": "Incident to review:\n" + json.dumps(ctx, indent=2)}]
    for _ in range(max_turns):
        resp = client.messages.create(model=model, max_tokens=700, system=SYSTEM, tools=TOOLS, messages=messages)
        texts = [b.text for b in resp.content if getattr(b, "type", "") == "text"]
        if resp.stop_reason != "tool_use":
            return " ".join(texts).strip() or "No assessment returned."
        messages.append({"role": "assistant", "content": resp.content})
        results = []
        for b in resp.content:
            if getattr(b, "type", "") == "tool_use":
                out = toolbox.dispatch(b.name, dict(b.input))
                results.append({"type": "tool_result", "tool_use_id": b.id, "content": json.dumps(out, default=str)[:2000]})
        messages.append({"role": "user", "content": results})
    return "The agent stopped after reaching its step limit."
