import json
import uuid
from typing import List, Dict

RULES_FILE = "rules.json"

def load_rules() -> List[Dict]:
    try:
        with open(RULES_FILE, "r") as f:
            data = json.load(f)
            return data.get("rules", [])
    except FileNotFoundError:
        return []

def save_rules(rules: List[Dict]):
    with open(RULES_FILE, "w") as f:
        json.dump({"rules": rules}, f, indent=2)

def add_rule(rule: Dict) -> Dict:
    rules = load_rules()
    rule_id = rule.get("id") or str(uuid.uuid4())
    rule["id"] = rule_id
    rules.append(rule)
    save_rules(rules)
    return rule

def remove_rule(rule_id: str) -> bool:
    rules = load_rules()
    new = [r for r in rules if r.get("id") != rule_id]
    if len(new) == len(rules):
        return False
    save_rules(new)
    return True

def match_block(packet_info: Dict) -> bool:
    """
    packet_info: {"src":..., "dst":..., "sport":..., "dport":..., "proto": "TCP"/"UDP"/"ICMP"}
    Returns True if packet should be blocked (by rule).
    """
    rules = load_rules()
    for r in rules:
        if r.get("action", "").lower() != "block":
            continue
        ip_ok = (r.get("ip") == packet_info.get("src")) or (r.get("ip") == packet_info.get("dst"))
        proto_ok = (r.get("protocol", "").upper() == packet_info.get("proto", "").upper()) if r.get("protocol") else True
        port_ok = True
        if r.get("port"):
            # match against source or dest port
            port_ok = (int(r.get("port")) == int(packet_info.get("sport", -1))) or (int(r.get("port")) == int(packet_info.get("dport", -1)))
        if ip_ok and proto_ok and port_ok:
            return True
    return False
