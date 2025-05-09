import json
import os
import subprocess
from datetime import datetime

WHITELIST_FILE = 'whitelist.json'
UNBOUND_OVERRIDE = '/etc/unbound/unbound.conf.d/guardian-overrides.conf'
LOG_FILE = 'dns_override.log'

def log(msg):
    with open(LOG_FILE, 'a') as logf:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        logf.write(f"[{timestamp}] {msg}\n")

def load_whitelist():
    if not os.path.exists(WHITELIST_FILE):
        return {}
    with open(WHITELIST_FILE, 'r') as f:
        return json.load(f)

def write_unbound_overrides():
    data = load_whitelist()
    lines = ['server:\n']

    for mac, entry in data.items():
        ip = entry.get('ip')
        status = entry.get('status', 'pending')
        if not ip:
            continue

        if status == 'approved':
            lines.append(f'    access-control: {ip}/32 allow\n')
            log(f"Allowing {mac} ({ip})")
        elif status == 'redirected':
            domain = entry.get('redirect', 'redirect.invalid')
            lines.append(f'    local-zone: "{domain}" redirect\n')
            lines.append(f'    local-data: "{domain} A {ip}"\n')
            log(f"Redirecting {mac} to {domain} ({ip})")
        else:
            lines.append(f'    access-control: {ip}/32 refuse\n')
            log(f"Blocking {mac} ({ip})")

    try:
        with open(UNBOUND_OVERRIDE, 'w') as f:
            f.writelines(lines)
        subprocess.run(['sudo', 'systemctl', 'restart', 'unbound'], check=True)
        log("Unbound override updated and service restarted.")
    except Exception as e:
        log(f"ERROR applying Unbound override: {e}")

if __name__ == "__main__":
    write_unbound_overrides()
