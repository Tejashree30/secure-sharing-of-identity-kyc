"""Agentic AI Cyber Defense Platform: REST API + live web console.

    python server.py            ->  http://127.0.0.1:5000   (login: admin / admin123)

The original single-page dashboard (python app.py) still works and is unchanged.

Environment variables (all optional):
  MODE=live                 capture real packets with Scapy (needs root); default is simulation
  ALLOW_REAL_FIREWALL=1     allow switching off dry-run so iptables/netsh rules are really applied
  ANTHROPIC_API_KEY         Claude writes owner messages and an AI analyst reviews incidents
  ABUSEIPDB_KEY, VT_API_KEY real threat-intelligence lookups
  SMTP_HOST/PORT/USER/PASS  real e-mail to owners (see config.py)
  ADMIN_PASSWORD            initial admin password (default admin123, change it after login)
  SECRET_KEY, HOST, PORT
"""
import csv
import io
import json
import os
import secrets
import time
from functools import wraps

from flask import Flask, Response, jsonify, request, send_from_directory, session
from werkzeug.exceptions import HTTPException
from werkzeug.security import check_password_hash, generate_password_hash

import config
from data_gen import ATTACK_KINDS_ALL
from soc.bus import Bus
from soc.db import DB
from soc.engine2 import STATUSES, SOCEngine
from soc.firewall import Firewall
from soc.intel import IntelService
from soc.capture import LiveSniffer

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "output")
os.makedirs(OUT, exist_ok=True)
START = time.time()

DEFAULTS = {
    "auto_response": True, "approval_for_isolation": False, "dry_run": True, "notify_min_severity": 2,
    "escalate_after": 5, "block_ttl_minutes": 60, "auto_attacks": True, "webhook_url": "", "llm_agent": True,
    "allowlist": sorted(config.ALLOWLIST),
}
OWNER_CRITICALITY = {"Finance Department": 3, "Database Administrators": 3, "HR Department": 2}
ROLE_RANK = {"viewer": 1, "analyst": 2, "admin": 3}
REAL_FW_ALLOWED = os.getenv("ALLOW_REAL_FIREWALL") == "1"


# ---------------------------------------------------------------- setup
def build(db_path=None, mode=None, start_engine=True):
    db = DB(db_path or os.path.join(OUT, "platform.db"))
    bus = Bus()
    settings = dict(DEFAULTS)
    for k in DEFAULTS:
        v = db.get_setting(k)
        if v is not None:
            settings[k] = v
    if not REAL_FW_ALLOWED:
        settings["dry_run"] = True

    if not db.one("SELECT 1 AS x FROM users LIMIT 1"):
        for u, pw, role in (("admin", os.getenv("ADMIN_PASSWORD", "admin123"), "admin"),
                            ("analyst", "analyst123", "analyst"), ("viewer", "viewer123", "viewer")):
            db.x("INSERT INTO users(username,pw_hash,role,created) VALUES(?,?,?,?)",
                 (u, generate_password_hash(pw), role, time.time()))
    if not db.one("SELECT 1 AS x FROM owners LIMIT 1"):
        for prefix, o in config.OWNERS.items():
            db.x("INSERT INTO owners(prefix,name,email,criticality) VALUES(?,?,?,?)",
                 (prefix, o["name"], o["email"], OWNER_CRITICALITY.get(o["name"], 1)))
    secret = db.get_setting("secret_key")
    if not secret:
        secret = os.getenv("SECRET_KEY") or secrets.token_hex(32)
        db.set_setting("secret_key", secret)

    fw = Firewall(dry_run=settings["dry_run"])
    intel = IntelService()
    engine = SOCEngine(db, bus, fw, intel, settings, mode or os.getenv("MODE", "sim"))
    apply_settings(engine)
    if start_engine:
        engine.start()
    return db, bus, engine, secret


def apply_settings(engine):
    s = engine.settings
    config.ESCALATE_AFTER = int(s["escalate_after"])
    config.AUTO_ATTACKS = bool(s["auto_attacks"])
    config.NOTIFY_MIN_SEVERITY = int(s["notify_min_severity"])
    engine.fw.dry_run = True if not REAL_FW_ALLOWED else bool(s["dry_run"])


def create_app(db, bus, engine, secret):
    app = Flask(__name__, static_folder=os.path.join(HERE, "web"), static_url_path="/static")
    app.secret_key = secret
    app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")
    failures = {}   # login throttling: key -> [timestamps]

    # ---- helpers ----
    def auth(role=None):
        def deco(fn):
            @wraps(fn)
            def wrapper(*a, **kw):
                u = session.get("user")
                if not u:
                    return jsonify(error="Not signed in"), 401
                if role and ROLE_RANK[u["role"]] < ROLE_RANK[role]:
                    return jsonify(error=f"This action needs the {role} role"), 403
                return fn(*a, **kw)
            return wrapper
        return deco

    def me():
        return session["user"]["username"]

    def jrow(r):
        for k in ("actions", "trace", "intel", "pending", "channels"):
            if k in r and isinstance(r[k], str):
                try:
                    r[k] = json.loads(r[k])
                except ValueError:
                    pass
        return r

    @app.errorhandler(Exception)
    def on_error(e):
        if isinstance(e, HTTPException):
            return jsonify(error=e.description), e.code
        app.logger.exception("unhandled error")
        return jsonify(error=f"Server error: {e.__class__.__name__}"), 500

    # ---- pages ----
    @app.route("/")
    def index():
        return send_from_directory(os.path.join(HERE, "web"), "index.html")

    # ---- auth ----
    @app.post("/api/login")
    def login():
        d = request.get_json(silent=True) or {}
        user, pw = str(d.get("username", "")).strip(), str(d.get("password", ""))
        key = f"{request.remote_addr}|{user.lower()}"
        recent = [t for t in failures.get(key, []) if time.time() - t < 300]
        if len(recent) >= 5:
            wait = int(300 - (time.time() - recent[0]))
            return jsonify(error=f"Too many failed attempts. Try again in {wait}s."), 429
        row = db.one("SELECT * FROM users WHERE username=?", (user,))
        if not row or not check_password_hash(row["pw_hash"], pw):
            failures[key] = recent + [time.time()]
            db.audit(user or "?", "login_failed", request.remote_addr, "")
            bus.toast("warning", "Failed sign-in attempt", f"user '{user}' from {request.remote_addr}")
            return jsonify(error="Wrong username or password"), 401
        failures.pop(key, None)
        session["user"] = {"username": row["username"], "role": row["role"]}
        session.permanent = False
        db.audit(row["username"], "login", request.remote_addr, "")
        return jsonify(user=session["user"], default_password=check_password_hash(row["pw_hash"], "admin123")
                       or check_password_hash(row["pw_hash"], "analyst123") or check_password_hash(row["pw_hash"], "viewer123"))

    @app.post("/api/logout")
    def logout():
        session.clear()
        return jsonify(ok=True)

    @app.get("/api/me")
    def whoami():
        u = session.get("user")
        if not u:
            return jsonify(error="Not signed in"), 401
        row = db.one("SELECT pw_hash FROM users WHERE username=?", (u["username"],))
        default = bool(row) and any(check_password_hash(row["pw_hash"], p) for p in ("admin123", "analyst123", "viewer123"))
        return jsonify(user=u, default_password=default, real_firewall_allowed=REAL_FW_ALLOWED)

    @app.post("/api/password")
    @auth()
    def password():
        d = request.get_json(silent=True) or {}
        row = db.one("SELECT * FROM users WHERE username=?", (me(),))
        if not check_password_hash(row["pw_hash"], str(d.get("old", ""))):
            return jsonify(error="Current password is wrong"), 400
        new = str(d.get("new", ""))
        if len(new) < 8:
            return jsonify(error="New password must be at least 8 characters"), 400
        db.x("UPDATE users SET pw_hash=? WHERE username=?", (generate_password_hash(new), me()))
        db.audit(me(), "password_change", me(), "")
        return jsonify(ok=True)

    # ---- live stream ----
    @app.get("/api/stream")
    @auth()
    def stream():
        q = bus.subscribe()

        def gen():
            try:
                yield "retry: 2000\n\n"
                while True:
                    try:
                        yield f"data: {json.dumps(q.get(timeout=15), default=str)}\n\n"
                    except Exception:
                        yield ": ping\n\n"
            finally:
                bus.unsubscribe(q)
        return Response(gen(), mimetype="text/event-stream",
                        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    # ---- overview ----
    @app.get("/api/overview")
    @auth()
    def overview():
        s = engine.state()
        c = db.one("SELECT SUM(status IN ('open','pending_approval')) AS open_n, "
                   "SUM(status='pending_approval') AS pend, COUNT(*) AS total FROM incidents") or {}
        s.update(db_open=c.get("open_n") or 0, db_pending=c.get("pend") or 0, db_total=c.get("total") or 0,
                 mode=engine.mode, dry_run=engine.fw.dry_run, auto_response=engine.settings["auto_response"])
        s.pop("incidents", None)
        s.pop("notifications", None)
        return jsonify(s)

    # ---- incidents ----
    @app.get("/api/incidents")
    @auth()
    def incidents():
        where, args = [], []
        if request.args.get("status"):
            where.append("status=?"); args.append(request.args["status"])
        if request.args.get("severity"):
            where.append("severity>=?"); args.append(int(request.args["severity"]))
        if request.args.get("q"):
            like = f"%{request.args['q']}%"
            where.append("(src_ip LIKE ? OR dst_ip LIKE ? OR threat_type LIKE ? OR owner LIKE ?)"); args += [like] * 4
        sql = ("SELECT id,ts,src_ip,dst_ip,threat_type,severity,count,status,actions,owner,response_ms,notified "
               "FROM incidents" + (" WHERE " + " AND ".join(where) if where else "") + " ORDER BY id DESC LIMIT ?")
        args.append(min(int(request.args.get("limit", 200)), 1000))
        return jsonify(items=[jrow(r) for r in db.q(sql, args)])

    @app.get("/api/incidents/<int:iid>")
    @auth()
    def incident(iid):
        r = db.one("SELECT * FROM incidents WHERE id=?", (iid,))
        if not r:
            return jsonify(error="Incident not found"), 404
        r = jrow(r)
        r["notifications"] = [jrow(n) for n in db.q("SELECT * FROM notifications WHERE incident_id=? ORDER BY id DESC", (iid,))]
        r["contained"] = r["src_ip"] in engine.agent.blocked_ips or r["src_ip"] in engine.agent.isolated_hosts
        return jsonify(r)

    @app.post("/api/incidents/<int:iid>/status")
    @auth("analyst")
    def incident_status(iid):
        d = request.get_json(silent=True) or {}
        res = engine.set_status(iid, d.get("status"), me(), bool(d.get("allowlist")))
        return jsonify(res), (200 if res["ok"] else 400)

    @app.post("/api/incidents/<int:iid>/approve")
    @auth("analyst")
    def approve(iid):
        res = engine.approve(iid, me())
        return jsonify(res), (200 if res["ok"] else 400)

    @app.post("/api/incidents/<int:iid>/deny")
    @auth("analyst")
    def deny(iid):
        res = engine.deny(iid, me())
        return jsonify(res), (200 if res["ok"] else 400)

    # ---- blocklist ----
    @app.get("/api/blocklist")
    @auth()
    def blocklist():
        return jsonify(items=db.q("SELECT * FROM blocklist ORDER BY ts DESC"), dry_run=engine.fw.dry_run,
                       commands=engine.fw.history[:15])

    @app.post("/api/blocklist")
    @auth("analyst")
    def blocklist_add():
        d = request.get_json(silent=True) or {}
        res = engine.manual_block(str(d.get("ip", "")).strip(), d.get("kind", "block"), str(d.get("reason", ""))[:200],
                                  me(), d.get("ttl_minutes"))
        return jsonify(res), (200 if res["ok"] else 400)

    @app.delete("/api/blocklist/<ip>")
    @auth("analyst")
    def blocklist_del(ip):
        if not db.one("SELECT 1 AS x FROM blocklist WHERE ip=?", (ip,)) and ip not in engine.agent.blocked_ips \
                and ip not in engine.agent.isolated_hosts:
            return jsonify(error="Address is not blocked"), 404
        engine.release(ip, me())
        return jsonify(ok=True)

    # ---- notifications ----
    @app.get("/api/notifications")
    @auth()
    def notifications():
        return jsonify(items=[jrow(r) for r in db.q("SELECT * FROM notifications ORDER BY id DESC LIMIT 100")])

    @app.post("/api/notifications/<int:nid>/resend")
    @auth("analyst")
    def resend(nid):
        ch = engine.pnotifier.resend(nid)
        return (jsonify(channels=ch), 200) if ch else (jsonify(error="Message not found"), 404)

    # ---- owners ----
    @app.get("/api/owners")
    @auth()
    def owners():
        return jsonify(items=db.q("SELECT * FROM owners ORDER BY prefix"))

    @app.put("/api/owners")
    @auth("admin")
    def owners_put():
        d = request.get_json(silent=True) or {}
        prefix, name, email = str(d.get("prefix", "")).strip(), str(d.get("name", "")).strip(), str(d.get("email", "")).strip()
        crit = int(d.get("criticality", 1))
        if not prefix or not name or "@" not in email or crit not in (1, 2, 3):
            return jsonify(error="Need a prefix, a name, a valid e-mail and criticality 1-3"), 400
        db.x("INSERT INTO owners(prefix,name,email,criticality) VALUES(?,?,?,?) ON CONFLICT(prefix) DO UPDATE SET "
             "name=excluded.name, email=excluded.email, criticality=excluded.criticality", (prefix, name, email, crit))
        db.audit(me(), "owner_save", prefix, name)
        return jsonify(ok=True)

    @app.delete("/api/owners/<path:prefix>")
    @auth("admin")
    def owners_del(prefix):
        db.x("DELETE FROM owners WHERE prefix=?", (prefix,))
        db.audit(me(), "owner_delete", prefix, "")
        return jsonify(ok=True)

    # ---- audit ----
    @app.get("/api/audit")
    @auth()
    def audit():
        return jsonify(items=db.q("SELECT * FROM audit ORDER BY id DESC LIMIT 300"))

    # ---- analytics ----
    @app.get("/api/analytics")
    @auth()
    def analytics():
        now = time.time()
        buckets = {int(r["b"]): r["n"] for r in db.q(
            "SELECT CAST(ts/60 AS INTEGER)*60 AS b, COUNT(*) AS n FROM incidents WHERE ts > ? GROUP BY b", (now - 1800,))}
        start = int((now - 1740) // 60) * 60
        timeline = [{"t": start + i * 60, "n": buckets.get(start + i * 60, 0)} for i in range(30)]
        st = {r["status"]: r["n"] for r in db.q("SELECT status, COUNT(*) AS n FROM incidents GROUP BY status")}
        reviewed = st.get("resolved", 0) + st.get("false_positive", 0)
        mean = db.one("SELECT AVG(response_ms) AS m, MAX(response_ms) AS mx FROM incidents WHERE response_ms IS NOT NULL") or {}
        return jsonify(
            by_type=db.q("SELECT threat_type AS k, COUNT(*) AS n FROM incidents GROUP BY threat_type ORDER BY n DESC"),
            by_severity=db.q("SELECT severity AS k, COUNT(*) AS n FROM incidents GROUP BY severity ORDER BY severity"),
            top_sources=db.q("SELECT src_ip, COUNT(*) AS n, MAX(severity) AS sev, MAX(threat_type) AS type "
                             "FROM incidents GROUP BY src_ip ORDER BY n DESC, sev DESC LIMIT 8"),
            timeline=timeline, status=st, mean_response_ms=round(mean.get("m") or 0, 1),
            max_response_ms=round(mean.get("mx") or 0, 1),
            fp_rate=round(st.get("false_positive", 0) / reviewed, 3) if reviewed else None,
            reviewed=reviewed, total=sum(st.values()), llm_reviews=engine.llm_reviews,
            notifications=engine.pnotifier.sent_count)

    # ---- simulator ----
    @app.post("/api/simulate")
    @auth("analyst")
    def simulate():
        d = request.get_json(silent=True) or {}
        kind, n = d.get("kind"), max(1, min(int(d.get("count", 1)), 5))
        kinds = ATTACK_KINDS_ALL if kind == "all" else [kind]
        if any(k not in ATTACK_KINDS_ALL for k in kinds):
            return jsonify(error="Unknown attack type"), 400
        for k in kinds:
            for _ in range(n):
                engine.start_attack(k)
        db.audit(me(), "simulate", kind, f"x{n}")
        bus.toast("info", "Attack simulation started", f"{'all types' if kind == 'all' else kind} x{n}")
        return jsonify(ok=True)

    # ---- settings ----
    @app.get("/api/settings")
    @auth()
    def settings_get():
        return jsonify(settings=engine.settings, real_firewall_allowed=REAL_FW_ALLOWED)

    @app.put("/api/settings")
    @auth("admin")
    def settings_put():
        d = request.get_json(silent=True) or {}
        rules = {"auto_response": bool, "approval_for_isolation": bool, "dry_run": bool, "auto_attacks": bool,
                 "llm_agent": bool, "notify_min_severity": (1, 5), "escalate_after": (2, 50),
                 "block_ttl_minutes": (0, 1440), "webhook_url": str}
        changed = []
        for k, rule in rules.items():
            if k not in d:
                continue
            v = d[k]
            if rule is bool:
                v = bool(v)
                if k == "dry_run" and not v and not REAL_FW_ALLOWED:
                    return jsonify(error="Real firewall changes are locked. Start the server with ALLOW_REAL_FIREWALL=1."), 400
            elif rule is str:
                v = str(v).strip()[:300]
                if v and not v.startswith(("http://", "https://")):
                    return jsonify(error="Webhook URL must start with http:// or https://"), 400
            else:
                try:
                    v = int(v)
                except (TypeError, ValueError):
                    return jsonify(error=f"{k} must be a number"), 400
                if not rule[0] <= v <= rule[1]:
                    return jsonify(error=f"{k} must be between {rule[0]} and {rule[1]}"), 400
            engine.settings[k] = v
            db.set_setting(k, v)
            changed.append(k)
        apply_settings(engine)
        db.audit(me(), "settings", ",".join(changed), "")
        bus.toast("success", "Settings saved", ", ".join(changed) or "nothing changed")
        return jsonify(ok=True, settings=engine.settings)

    # ---- health ----
    @app.get("/api/health")
    @auth()
    def health():
        ok_cap, cap_msg = LiveSniffer.available()
        smtp = bool(config.SMTP_HOST and config.SMTP_USER and config.SMTP_PASS)
        providers = engine.intel.configured()
        up = time.time() - START
        return jsonify(components=[
            {"name": "ML detector", "status": "ok", "detail": "Isolation Forest + Random Forest trained"},
            {"name": "Database", "status": "ok", "detail": f"SQLite, {db.one('SELECT COUNT(*) AS n FROM incidents')['n']} incidents stored"},
            {"name": "Firewall", "status": "ok" if engine.fw.dry_run else "warning",
             "detail": ("Dry-run (commands recorded, nothing applied)" if engine.fw.dry_run else
                        f"REAL enforcement on {engine.fw.system}")},
            {"name": "Threat intelligence", "status": "ok" if providers and not engine.intel.last_error else
             ("warning" if providers else "info"),
             "detail": (", ".join(providers) if providers else "local mock feed (set ABUSEIPDB_KEY or VT_API_KEY)")
             + (f" | last error: {engine.intel.last_error}" if engine.intel.last_error else "")},
            {"name": "AI agent (LLM)", "status": "ok" if config.ANTHROPIC_API_KEY else "info",
             "detail": f"Claude {config.LLM_MODEL}, {engine.llm_reviews} reviews" if config.ANTHROPIC_API_KEY
             else "Not configured (set ANTHROPIC_API_KEY). Rule-based agent is active."},
            {"name": "E-mail", "status": "ok" if smtp else "info", "detail": config.SMTP_HOST if smtp else "Not configured (set SMTP_*)"},
            {"name": "Webhook", "status": "ok" if engine.settings.get("webhook_url") else "info",
             "detail": "Configured" if engine.settings.get("webhook_url") else "Not configured"},
            {"name": "Packet capture", "status": "ok" if engine.mode == "live" else "info",
             "detail": "Live capture running" if engine.mode == "live" else f"Simulation mode. Live: {cap_msg}"},
        ], uptime=int(up), events=engine.c["events"], eps=round(engine.c["events"] / max(up, 1), 1))

    # ---- exports ----
    @app.get("/api/export/incidents.csv")
    @auth()
    def export_csv():
        rows = db.q("SELECT id,ts,src_ip,dst_ip,threat_type,severity,count,status,owner,actions,response_ms FROM incidents ORDER BY id")
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["id", "time", "src_ip", "dst_ip", "threat_type", "severity", "detections", "status", "owner",
                    "actions", "response_ms"])
        for r in rows:
            w.writerow([r["id"], time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["ts"])), r["src_ip"], r["dst_ip"],
                        r["threat_type"], r["severity"], r["count"], r["status"], r["owner"],
                        " | ".join(json.loads(r["actions"] or "[]")), r["response_ms"]])
        return Response(buf.getvalue(), mimetype="text/csv",
                        headers={"Content-Disposition": "attachment; filename=incidents.csv"})

    @app.get("/api/export/report.json")
    @auth()
    def export_json():
        data = {"generated": time.strftime("%Y-%m-%d %H:%M:%S"),
                "incidents": [jrow(r) for r in db.q("SELECT * FROM incidents ORDER BY id")],
                "blocklist": db.q("SELECT * FROM blocklist"), "audit": db.q("SELECT * FROM audit ORDER BY id DESC LIMIT 500")}
        return Response(json.dumps(data, indent=2), mimetype="application/json",
                        headers={"Content-Disposition": "attachment; filename=report.json"})

    return app


def main():
    db, bus, engine, secret = build()
    app = create_app(db, bus, engine, secret)
    host, port = config.HOST, config.PORT
    print(f"\n  Console running at http://{host}:{port}   (login: admin / admin123, Ctrl+C to stop)\n")
    app.run(host=host, port=port, threaded=True, use_reloader=False)


if __name__ == "__main__":
    main()
