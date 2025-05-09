#!/usr/bin/env python3
from flask import Flask, render_template, request, redirect, url_for, jsonify
import json, os, subprocess, psutil, socket, datetime, requests

app = Flask(__name__)

WHITELIST_FILE = 'whitelist.json'
BACKUP_DIR     = 'backups'
SETTINGS_FILE  = 'settings.json'
LOG_FILE       = 'firewall.log'

def load_settings():
    """Load or initialize router credentials."""
    if not os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE, 'w') as f:
            json.dump({"UDR":"","USERNAME":"","PASSWORD":""}, f, indent=2)
    return json.load(open(SETTINGS_FILE))

def load_whitelist():
    """Load or initialize the whitelist database."""
    if not os.path.exists(WHITELIST_FILE):
        with open(WHITELIST_FILE, 'w') as f:
            f.write('{}')
    return json.load(open(WHITELIST_FILE))

def save_whitelist(data):
    """Persist whitelist to disk."""
    with open(WHITELIST_FILE, 'w') as f:
        json.dump(data, f, indent=2)

def get_system_stats():
    """Gather basic CPU, memory, and uptime stats."""
    mem = psutil.virtual_memory()
    cpu = psutil.cpu_percent(interval=1)
    uptime = subprocess.check_output('uptime -p', shell=True).decode().strip()
    return {
        'memory': f"{mem.used//(1024*1024)}MB / {mem.total//(1024*1024)}MB",
        'cpu':    f"{cpu}%",
        'uptime': uptime
    }

def get_unbound_uptime():
    """Retrieve when Unbound was last started."""
    try:
        out = subprocess.check_output(
            'systemctl show unbound --property=ActiveEnterTimestamp', shell=True
        ).decode()
        return out.split('=')[1].strip()
    except:
        return "Unavailable"

def check_router_connection():
    """Quick test: can we log into the UniFi API?"""
    settings = load_settings()
    try:
        s = requests.Session()
        s.verify = False
        resp = s.post(
            f"https://{settings['UDR']}/api/auth/login",
            json={"username": settings['USERNAME'], "password": settings['PASSWORD']},
            timeout=5
        )
        resp.raise_for_status()
        return True
    except:
        return False

@app.route('/')
def index():
    """Main dashboard."""
    connected = check_router_connection()
    return render_template(
        "dashboard.html",
        data=load_whitelist(),
        stats=get_system_stats(),
        unbound_uptime=get_unbound_uptime(),
        router_connected=connected
    )

@app.route('/set/<mac>/<status>')
def set_status(mac, status):
    """Change a device's status and sync firewall immediately."""
    data = load_whitelist()
    if mac in data:
        data[mac]['status'] = status
        save_whitelist(data)
        subprocess.run(['python3', 'firewall.py'], check=False)
    return redirect(url_for('index'))

@app.route('/redirect/<mac>', methods=['POST','DELETE'])
def handle_redirect(mac):
    """Set or clear a redirect rule for a device."""
    data = load_whitelist()
    if mac in data:
        if request.method == 'POST':
            payload = request.get_json()
            data[mac].update({
                'status': 'redirected',
                'redirect': payload.get('redirect','')
            })
        else:
            data[mac].pop('redirect', None)
            data[mac]['status'] = 'approved'
        save_whitelist(data)
        subprocess.run(['python3', 'firewall.py'], check=False)
    return ('', 204)

@app.route('/refresh-name/<mac>')
def refresh_name(mac):
    """Re-resolve a device's hostname via DNS reverse lookup."""
    data = load_whitelist()
    ip = data.get(mac, {}).get('ip')
    try:
        data[mac]['name'] = socket.gethostbyaddr(ip)[0]
    except:
        data[mac]['name'] = "Unknown"
    save_whitelist(data)
    return redirect(url_for('index'))

@app.route('/manual-scan')
def manual_scan():
    """Use the UniFi API to fetch all clients and auto-approve new ones."""
    settings = load_settings()
    s = requests.Session()
    s.verify = False

    # 1) Log in
    try:
        resp = s.post(
            f"https://{settings['UDR']}/api/auth/login",
            json={"username": settings['USERNAME'], "password": settings['PASSWORD']},
            timeout=5
        )
        resp.raise_for_status()
        token = resp.headers.get("X-Csrf-Token")
        if token:
            s.headers.update({"X-Csrf-Token": token})
    except Exception as e:
        return jsonify({"message": f"❌ Router login failed: {e}"}), 500

    # 2) Fetch client list
    try:
        resp = s.get(
            f"https://{settings['UDR']}/proxy/network/api/s/default/stat/sta",
            timeout=5
        )
        resp.raise_for_status()
        clients = resp.json().get("data", [])
    except Exception as e:
        return jsonify({"message": f"❌ Failed to fetch clients: {e}"}), 500

    # 3) Add any truly new MACs as approved
    data = load_whitelist()
    added = 0
    for c in clients:
        mac      = c.get("mac")
        ip       = c.get("ip","")
        hostname = c.get("hostname") or c.get("name","Unknown")
        if mac and mac not in data:
            data[mac] = {
                "ip":      ip,
                "status":  "approved",
                "name":    hostname
            }
            added += 1

    save_whitelist(data)
    subprocess.run(['python3', 'firewall.py'], check=False)
    return jsonify({"message": f"Scan complete. {added} new device(s) added as approved."})

@app.route('/clear-all', methods=['POST'])
def clear_all():
    """Backup & wipe the whitelist, then re-sync firewall."""
    os.makedirs(BACKUP_DIR, exist_ok=True)
    bak = f"{BACKUP_DIR}/whitelist_{datetime.datetime.now():%Y%m%d_%H%M%S}.json"
    subprocess.run(['cp', WHITELIST_FILE, bak])
    open(WHITELIST_FILE,'w').write('{}')
    subprocess.run(['python3','firewall.py'], check=False)
    return ('', 204)

@app.route('/export/json')
def export_json():
    """Download the whitelist as JSON."""
    return app.response_class(open(WHITELIST_FILE).read(), mimetype='application/json')

@app.route('/export/csv')
def export_csv():
    """Download the whitelist as CSV."""
    import csv
    from io import StringIO
    data = load_whitelist()
    buf = StringIO()
    w   = csv.writer(buf)
    w.writerow(['MAC','IP','Status','Name','Redirect'])
    for mac,e in data.items():
        w.writerow([mac, e.get('ip'), e.get('status'), e.get('name',''), e.get('redirect','')])
    return app.response_class(buf.getvalue(), mimetype='text/csv')

@app.route('/api/stats')
def api_stats():
    """AJAX endpoint for system & Unbound stats."""
    return jsonify({
        "stats":         get_system_stats(),
        "unbound_uptime": get_unbound_uptime()
    })

@app.route('/forwarders', methods=['GET','POST'])
def forwarders():
    """View/edit DNS forwarders and restart Unbound."""
    cfg_file = "/etc/unbound/unbound.conf.d/forward.conf"
    message = None; success = True
    if request.method == 'POST':
        content = request.form.get('forwarders','')
        try:
            with open(cfg_file,'w') as f: f.write(content)
            subprocess.run(['unbound-checkconf', cfg_file], check=True)
            subprocess.run(['sudo','systemctl','restart','unbound'], check=True)
            message = "Forwarders applied."
        except:
            message = "Error: invalid Unbound config."
            success = False
    data = ""
    try:
        data = open(cfg_file).read()
    except:
        pass
    return render_template("forwarders.html", forwarders=data, message=message, success=success)

@app.route('/tuning', methods=['GET','POST'])
def tuning():
    """View/edit Unbound tuning presets or raw config."""
    cfg_file = "/etc/unbound/unbound.conf.d/guardian-tuning.conf"
    message = None; success = True
    presets = {
        "low":      ["msg-cache-size:16m","rrset-cache-size:32m","num-threads:1","cache-min-ttl:60"],
        "balanced": ["msg-cache-size:64m","rrset-cache-size:128m","num-threads:2","cache-min-ttl:120"],
        "high":     ["msg-cache-size:128m","rrset-cache-size:256m","num-threads:4","cache-min-ttl:300"]
    }
    if request.method == 'POST':
        if 'preset' in request.form:
            lvl    = request.form['preset']
            cfg_txt = "server:\n  " + "\n  ".join(presets.get(lvl,[]))
        else:
            user_cfg = request.form.get('config','')
            cfg_txt = user_cfg if user_cfg.strip().startswith("server:") else "server:\n"+user_cfg
        try:
            with open(cfg_file,'w') as f: f.write(cfg_txt)
            subprocess.run(['unbound-checkconf', cfg_file], check=True)
            subprocess.run(['sudo','systemctl','restart','unbound'], check=True)
            message = "Tuning applied."
        except:
            message = "Error applying tuning."
            success = False
    current = ""
    try:
        current = open(cfg_file).read()
    except:
        pass
    return render_template("tuning.html", config=current, message=message, success=success)

@app.route('/settings', methods=['GET','POST'])
def settings():
    """View/update router connection settings."""
    s = load_settings()
    if request.method == 'POST':
        s['UDR']      = request.form['UDR']
        s['USERNAME'] = request.form['USERNAME']
        s['PASSWORD'] = request.form['PASSWORD']
        json.dump(s, open(SETTINGS_FILE,'w'), indent=2)
        return redirect(url_for('settings'))
    return render_template("settings.html", settings=s)

@app.route('/firewall-logs')
def firewall_logs():
    """View the action log for firewall."""
    logs = []
    if os.path.exists(LOG_FILE):
        logs = open(LOG_FILE).read().splitlines()
    return render_template("firewall_logs.html", logs=logs[::-1])

@app.route('/sync-dns', methods=['POST'])
def sync_dns():
    """Manually trigger firewall sync."""
    subprocess.run(['python3','firewall.py'], check=False)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
