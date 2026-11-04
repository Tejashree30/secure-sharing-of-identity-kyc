"""Entry point for the real-time system:  python app.py  ->  http://127.0.0.1:5000"""
import os

from flask import Flask, jsonify, request, send_from_directory

import config
from engine import Engine

HERE = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__)
engine = Engine()


@app.route("/")
def index():
    return send_from_directory(HERE, "dashboard.html")


@app.route("/api/state")
def state():
    return jsonify(engine.state())


@app.route("/api/attack/<kind>", methods=["POST"])
def attack(kind):
    ok = engine.start_attack(kind)
    return jsonify(ok=ok), (200 if ok else 400)


@app.route("/api/unblock", methods=["POST"])
def unblock():
    ip = (request.get_json(silent=True) or {}).get("ip", "")
    return jsonify(ok=engine.unblock(ip))


if __name__ == "__main__":
    engine.start()
    print(f"\n  Dashboard running at http://{config.HOST}:{config.PORT}   (Ctrl+C to stop)\n")
    app.run(host=config.HOST, port=config.PORT, threaded=True, use_reloader=False)
