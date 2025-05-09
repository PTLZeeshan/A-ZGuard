#!/usr/bin/env python3
import json
import requests
import os

WHITELIST_FILE = 'whitelist.json'
SETTINGS_FILE = 'settings.json'

def load_settings():
    with open(SETTINGS_FILE) as f:
        return json.load(f)

settings = load_settings()
UDR = settings["UDR"]
USERNAME = settings["USERNAME"]
PASSWORD = settings["PASSWORD"]

session = requests.Session()
session.verify = False

def login():
    url = f"https://{UDR}/api/auth/login"
    resp = session.post(url, json={"username": USERNAME, "password": PASSWORD})
    resp.raise_for_status()
    session.headers.update({"X-Csrf-Token": resp.headers["X-Csrf-Token"]})
    print("[✓] Firewall authenticated with UDR")

def block_mac(mac):
    print(f"[→] Blocking {mac}")
    url = f"https://{UDR}/proxy/network/api/s/default/cmd/stamgr"
    session.post(url, json={"cmd": "block-sta", "mac": mac})

def unblock_mac(mac):
    print(f"[→] Unblocking {mac}")
    url = f"https://{UDR}/proxy/network/api/s/default/cmd/stamgr"
    session.post(url, json={"cmd": "unblock-sta", "mac": mac})

def load_whitelist():
    with open(WHITELIST_FILE, 'r') as f:
        return json.load(f)

if __name__ == "__main__":
    login()
    devices = load_whitelist()
    for mac, entry in devices.items():
        status = entry.get("status")
        if status == "approved":
            unblock_mac(mac)
        else:
            block_mac(mac)
    print(f"[✓] Firewall sync complete: {len(devices)} devices processed.")
