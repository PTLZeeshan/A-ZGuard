#!/usr/bin/env python3
import json
import time
import requests
import os
import datetime
from requests.exceptions import RequestException

# Configuration
WHITELIST_FILE = 'whitelist.json'
SETTINGS_FILE = 'settings.json'
SCAN_INTERVAL = 30  # seconds

# Global router session
session = requests.Session()
session.verify = False


def load_settings():
    """Load or initialize router credentials."""
    if not os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE, 'w') as f:
            json.dump({"UDR": "", "USERNAME": "", "PASSWORD": ""}, f, indent=2)
    return json.load(open(SETTINGS_FILE))


def save_whitelist(data):
    """Persist local device database."""
    with open(WHITELIST_FILE, 'w') as f:
        json.dump(data, f, indent=2)


def load_whitelist():
    """Load or initialize local device database."""
    if not os.path.exists(WHITELIST_FILE):
        with open(WHITELIST_FILE, 'w') as f:
            f.write('{}')
    return json.load(open(WHITELIST_FILE))


def login(settings):
    """Authenticate to the UniFi API and store CSRF token."""
    url = f"https://{settings['UDR']}/api/auth/login"
    resp = session.post(
        url,
        json={"username": settings['USERNAME'], "password": settings['PASSWORD']},
        timeout=5
    )
    resp.raise_for_status()
    token = resp.headers.get('X-Csrf-Token')
    if token:
        session.headers.update({'X-Csrf-Token': token})


def get_clients(settings):
    """Fetch the list of all connected clients from UniFi."""
    url = f"https://{settings['UDR']}/proxy/network/api/s/default/stat/sta"
    resp = session.get(url, timeout=5)
    resp.raise_for_status()
    return resp.json().get('data', [])


def block_mac(settings, mac):
    """Block a MAC via the UniFi API."""
    url = f"https://{settings['UDR']}/proxy/network/api/s/default/cmd/stamgr"
    payload = {"cmd": "block-sta", "mac": mac}
    try:
        resp = session.post(url, json=payload, timeout=5)
        resp.raise_for_status()
        print(f"[+] Blocked {mac}")
    except RequestException as e:
        print(f"[!] Error blocking {mac}: {e}")


def main():
    settings = load_settings()

    # 1) Authenticate once
    try:
        login(settings)
        print("[✓] Authenticated to router API")
    except Exception as e:
        print(f"[FATAL] Cannot log in: {e}")
        return

    # 2) Initial snapshot - whitelist all current clients
    db = load_whitelist()
    if not db:
        print("[*] Initial run: whitelisting existing clients...")
        try:
            clients = get_clients(settings)
        except Exception as e:
            print(f"[FATAL] Initial fetch failed: {e}")
            return
        for c in clients:
            mac = c.get('mac')
            ip = c.get('ip', '')
            name = c.get('hostname') or 'Unknown'
            db[mac] = {
                'ip': ip,
                'name': name,
                'status': 'approved',
                'timestamp': datetime.datetime.now().isoformat()
            }
        save_whitelist(db)
        print(f"[*] Whitelisted {len(db)} devices.")

    print(f"[*] Starting scan loop every {SCAN_INTERVAL}s...")

    # 3) Recurring scan
    while True:
        try:
            clients = get_clients(settings)
        except Exception as e:
            print(f"[!] Fetch error: {e}, retrying login...")
            try:
                login(settings)
            except Exception as e2:
                print(f"[!] Re-auth failed: {e2}, sleeping...")
                time.sleep(SCAN_INTERVAL)
                continue
            time.sleep(1)
            try:
                clients = get_clients(settings)
            except Exception as e3:
                print(f"[!] Second fetch failed: {e3}, sleeping...")
                time.sleep(SCAN_INTERVAL)
                continue

        db = load_whitelist()
        updated = False

        # 4) Detect new devices
        for c in clients:
            mac = c.get('mac')
            if mac not in db:
                ip = c.get('ip', '')
                name = c.get('hostname') or 'Unknown'
                print(f"[+] New device {mac} ({name}@{ip}) - auto-blocking")
                block_mac(settings, mac)
                db[mac] = {
                    'ip': ip,
                    'name': name,
                    'status': 'blocked',
                    'timestamp': datetime.datetime.now().isoformat()
                }
                updated = True
            else:
                # update IP/name if changed
                entry = db[mac]
                new_ip = c.get('ip', '')
                new_name = c.get('hostname') or 'Unknown'
                if entry.get('ip') != new_ip or entry.get('name') != new_name:
                    entry['ip'] = new_ip
                    entry['name'] = new_name
                    entry['timestamp'] = datetime.datetime.now().isoformat()
                    updated = True

        # 5) Persist any changes
        if updated:
            save_whitelist(db)
            print(f"[*] Database updated with new devices at {datetime.datetime.now().isoformat()}")

        time.sleep(SCAN_INTERVAL)


if __name__ == '__main__':
    main()
