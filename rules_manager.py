import json
import uuid
from typing import List, Dict

# rules_manager.py

# Example rules list
rules = [
    {"ip": "192.168.1.10", "port": 80, "protocol": "TCP"},
    {"ip": "10.0.0.5", "port": 53, "protocol": "UDP"},
    # Add more rules here
]

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

def match_block(packet_info):
    for r in rules:  # your list of firewall rules
        # Safe conversion for rule port
        try:
            rule_port = int(r.get("port"))
        except (TypeError, ValueError):
            rule_port = -1

        # Safe conversion for packet ports
        try:
            sport = int(packet_info.get("sport", -1))
        except (TypeError, ValueError):
            sport = -1

        try:
            dport = int(packet_info.get("dport", -1))
        except (TypeError, ValueError):
            dport = -1

        # Check if ports match
        port_ok = (rule_port == sport) or (rule_port == dport)

        # You can add IP/protocol checks here if needed
        if port_ok:
            return True

    return False


