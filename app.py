from flask import Flask, request, jsonify, render_template, send_from_directory
from flask_socketio import SocketIO, emit
from sniffer import start_sniff, set_emit_callback
from rules_manager import load_rules, add_rule, remove_rule
from logger import log_info, log_warn
import os
from datetime import datetime

# If you want async with eventlet:
# socketio = SocketIO(app, async_mode='eventlet')
app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")  # use eventlet for production

# Backend: serve frontend
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/rules", methods=["GET"])
def api_get_rules():
    return jsonify(load_rules())

@app.route("/api/rules", methods=["POST"])
def api_add_rule():
    data = request.json
    if not data:
        return jsonify({"error": "bad request"}), 400
    r = add_rule(data)
    # optionally apply system rule here for block rules
    return jsonify(r), 201

@app.route("/api/rules/<rule_id>", methods=["DELETE"])
def api_delete_rule(rule_id):
    ok = remove_rule(rule_id)
    if not ok:
        return jsonify({"error": "not found"}), 404
    return jsonify({"status": "deleted"})

@app.route("/api/logs", methods=["GET"])
def api_get_logs():
    try:
        with open("firewall.log", "r") as f:
            content = f.read().splitlines()[-500:]  # last 500 lines
        return jsonify(content)
    except FileNotFoundError:
        return jsonify([])

# Websocket: push live packets
@socketio.on("connect")
def handle_connect():
    print("Client connected")
    emit("connected", {"time": datetime.utcnow().isoformat()})

def emit_packet_to_clients(info):
    socketio.emit("packet", info)

# wire sniffer emit
set_emit_callback(emit_packet_to_clients)

if __name__ == "__main__":
    # start sniffing (none iface = all)
    start_sniff(interface=None, filter_exp=None)
    # run flask + socketio
    # Use eventlet: pip install eventlet then run
    socketio.run(app, host="0.0.0.0", port=5000)
