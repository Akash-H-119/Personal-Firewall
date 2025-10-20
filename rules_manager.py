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

def match_block(packet_info):
    for r in rules:  # assuming 'rules' is your list of dicts
        # Safely get the rule port
        rule_port = r.get("port")
        if rule_port is None:
            rule_port = -1  # default if missing

        # Get packet source/destination ports
        sport = packet_info.get("sport", -1)
        dport = packet_info.get("dport", -1)

        # Check if port matches
        port_ok = (int(rule_port) == int(sport)) or (int(rule_port) == int(dport))

        # You can also add IP/protocol checks here
        if port_ok:
            return True
    return False

