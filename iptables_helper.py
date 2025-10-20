import subprocess
from logger import log_info, log_error

def apply_block_rule_linux(ip, port=None, protocol="tcp"):
    cmd = ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-p", protocol, "-j", "DROP"]
    if port:
        cmd = ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-p", protocol, "--dport", str(port), "-j", "DROP"]
    try:
        subprocess.run(cmd, check=True)
        log_info(f"Applied iptables block rule: {' '.join(cmd)}")
    except subprocess.CalledProcessError as e:
        log_error(f"Failed to apply iptables rule: {e}")

def remove_block_rule_linux(ip, port=None, protocol="tcp"):
    cmd = ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-p", protocol, "-j", "DROP"]
    if port:
        cmd = ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-p", protocol, "--dport", str(port), "-j", "DROP"]
    try:
        subprocess.run(cmd, check=True)
        log_info(f"Removed iptables block rule: {' '.join(cmd)}")
    except subprocess.CalledProcessError as e:
        log_error(f"Failed to remove iptables rule: {e}")
