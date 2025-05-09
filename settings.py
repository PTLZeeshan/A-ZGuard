import json, os

CONFIG_FILE = '/root/A-ZGuard/router_config.json'

def load_settings():
    if not os.path.exists(CONFIG_FILE):
        return {"UDR": "192.168.1.1", "USERNAME": "admin", "PASSWORD": "your_password"}
    with open(CONFIG_FILE, 'r') as f:
        return json.load(f)

def save_settings(data):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(data, f, indent=2)
