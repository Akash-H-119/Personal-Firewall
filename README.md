# 🔥 Personal Firewall Web Application (Python + Flask + Scapy)

A lightweight **web-based personal firewall** built in **Python** using **Flask**, **Scapy**, and **Socket.IO**.

This application monitors real-time network traffic, allows dynamic rule management (block/allow IPs, ports, and protocols), and logs suspicious packets for audit.

---

## 🚀 Features

✅ **Packet Sniffing (Scapy)** — Capture incoming/outgoing packets in real-time  
✅ **Rule Engine** — Allow/block based on IP, Port, Protocol  
✅ **Web Dashboard (Flask + Socket.IO)** — Monitor traffic live from browser  
✅ **Logging** — Store all packet activities in `firewall.log`  
✅ **iptables Integration (Linux)** — Apply block rules system-wide  
✅ **Cross-Platform** — Works on Windows (with Npcap) and Linux  

---

## 🧩 Tech Stack

| Component | Purpose |
|------------|----------|
| **Python (Flask)** | Backend REST API + Web UI |
| **Flask-SocketIO** | Real-time packet updates |
| **Scapy** | Packet sniffing |
| **iptables** | Firewall rule enforcement (Linux only) |
| **Bootstrap 5** | Responsive frontend |
| **Socket.IO JS** | Live updates on browser |

---

## 🗂 Project Structure
| File / Folder | Description |
|----------------|--------------|
| **app.py** | Main entry point. Runs Flask app, serves frontend, and connects to sniffer + WebSocket. |
| **sniffer.py** | Uses Scapy to capture incoming/outgoing packets and sends them to the web UI. |
| **rules_manager.py** | Defines and validates rules (allow/block IP, port, protocol). Reads/writes `rules.json`. |
| **iptables_helper.py** | Applies or removes firewall rules using `iptables` (Linux only). Optional on Windows. |
| **logger.py** | Handles logging of blocked and allowed packets to `firewall.log`. |
| **templates/index.html** | Frontend web dashboard (Bootstrap + Jinja2). Displays live packet feed. |
| **static/index.js** | Client-side logic using Socket.IO for real-time packet display and rule management. |
| **rules.json** | Local JSON file storing active firewall rules. Automatically updated from web UI. |
| **firewall.log** | Logs every captured packet with timestamp and action (blocked/allowed). |
| **requirements.txt** | Lists all Python dependencies for easy setup. |
| **README.md** | Full documentation with setup steps, usage guide, and feature overview. |


