import threading
from scapy.all import sniff, IP, TCP, UDP, Raw
from rules_manager import match_block
from logger import log_info, log_warn
from datetime import datetime
import json
import time

# callback function will be set from app.py (socket io emitter)
_emit_packet_callback = None

def set_emit_callback(fn):
    global _emit_packet_callback
    _emit_packet_callback = fn

def _packet_to_info(pkt):
    info = {}
    try:
        if IP in pkt:
            info['src'] = pkt[IP].src
            info['dst'] = pkt[IP].dst
        else:
            return None
        if TCP in pkt:
            info['proto'] = 'TCP'
            info['sport'] = pkt[TCP].sport
            info['dport'] = pkt[TCP].dport
        elif UDP in pkt:
            info['proto'] = 'UDP'
            info['sport'] = pkt[UDP].sport
            info['dport'] = pkt[UDP].dport
        else:
            info['proto'] = pkt.lastlayer().name if pkt.lastlayer() else "OTHER"
            info['sport'] = None
            info['dport'] = None
        info['summary'] = pkt.summary()
        info['time'] = datetime.utcnow().isoformat() + "Z"
        return info
    except Exception:
        return None

def packet_callback(pkt):
    info = _packet_to_info(pkt)
    if not info:
        return
    blocked = match_block(info)
    if blocked:
        log_warn(f"Blocked packet: {info['summary']}")
        info['action'] = 'blocked'
        # optionally call iptables helper to enforce system-level block
    else:
        # if it matches an allow rule or no block, mark allowed/suspicious
        info['action'] = 'allowed'
        log_info(f"Packet seen: {info['summary']}")
    # emit to frontend if set
    if _emit_packet_callback:
        try:
            _emit_packet_callback(info)
        except Exception:
            pass

def start_sniff(interface=None, filter_exp=None):
    """
    Run sniffing in a background thread.
    NOTE: requires root/admin and Npcap on Windows.
    """
    def _target():
        sniff(prn=packet_callback, store=0, iface=interface, filter=filter_exp)
    t = threading.Thread(target=_target, daemon=True)
    t.start()
    return t
