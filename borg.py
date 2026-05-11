import eventlet
eventlet.monkey_patch()

import asyncio, threading, hashlib, os, sqlite3, requests, socket, random
from datetime import datetime
from flask import Flask, render_template, jsonify, request, session, redirect
from flask_socketio import SocketIO

DB = "data/monitor.db"
FAIL_THRESHOLD = 3
MIN_OUTAGE_DURATION = 7
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

# Zabbix Credentials
ZABBIX_URL = "https://zabix_url/api_jsonrpc.php"
ZABBIX_USER = "admin"
ZABBIX_PASS = "admin"

app = Flask(__name__)
app.secret_key = "iamtheborg"
socketio = SocketIO(app, async_mode='eventlet', cors_allowed_origins="*")

loop = asyncio.new_event_loop()
tasks = {}

# --- GOLDEN RULE: SINGLETON PROTECTION ---
MONITOR_STARTED = False

def get_db():
    os.makedirs("data", exist_ok=True)
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row
    return c

def init_db():
    conn = get_db(); c = conn.cursor()
    
    # 1. Create the incidents and users tables as usual
    c.execute("CREATE TABLE IF NOT EXISTS incidents(id INTEGER PRIMARY KEY, target TEXT, monitor_detail TEXT, down_time TEXT, up_time TEXT, duration TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS users(username TEXT PRIMARY KEY, password TEXT, role TEXT)")
    
    # 2. DATA PRESERVATION MIGRATION for 'targets'
    # We check if the current table already has the correct unique constraint
    c.execute("PRAGMA table_info(targets)")
    columns = [col[1] for col in c.fetchall()]
    
    if not columns:
        # Table doesn't exist, create it fresh with the correct constraint
        c.execute("""CREATE TABLE targets(
            id INTEGER PRIMARY KEY, name TEXT, description TEXT,
            monitor_type TEXT, monitor_port TEXT, status TEXT DEFAULT 'Online',
            last_down TEXT, last_check TEXT, fail_count INTEGER DEFAULT 0,
            maintenance INTEGER DEFAULT 0, check_interval INTEGER DEFAULT 10, timeout INTEGER DEFAULT 2,
            zabbix_item_key TEXT,
            UNIQUE(name, monitor_type, monitor_port, zabbix_item_key)
        )""")
    else:
        # Table exists. Check if we need to migrate the UNIQUE constraint
        # SQLite doesn't let us modify constraints, so we rebuild
        c.execute("PRAGMA index_list(targets)")
        indexes = c.fetchall()
        # If the unique index doesn't account for zabbix_item_key, migrate
        needs_migration = True
        for idx in indexes:
            c.execute(f"PRAGMA index_info('{idx[1]}')")
            idx_cols = [row[2] for row in c.fetchall()]
            if "zabbix_item_key" in idx_cols:
                needs_migration = False; break
        
        if needs_migration:
            print("📦 [BORG] Migrating database to support multiple Zabbix items...")
            c.execute("ALTER TABLE targets RENAME TO targets_old")
            c.execute("""CREATE TABLE targets(
                id INTEGER PRIMARY KEY, name TEXT, description TEXT,
                monitor_type TEXT, monitor_port TEXT, status TEXT DEFAULT 'Online',
                last_down TEXT, last_check TEXT, fail_count INTEGER DEFAULT 0,
                maintenance INTEGER DEFAULT 0, check_interval INTEGER DEFAULT 10, timeout INTEGER DEFAULT 2,
                zabbix_item_key TEXT,
                UNIQUE(name, monitor_type, monitor_port, zabbix_item_key)
            )""")
            # Copy data from old to new
            c.execute("""INSERT INTO targets (id, name, description, monitor_type, monitor_port, status, last_down, last_check, fail_count, maintenance, check_interval, timeout, zabbix_item_key)
                         SELECT id, name, description, monitor_type, monitor_port, status, last_down, last_check, fail_count, maintenance, check_interval, timeout, zabbix_item_key FROM targets_old""")
            c.execute("DROP TABLE targets_old")
            print("✅ [BORG] Migration complete. Data preserved.")

    def ensure(u, p, r):
        if not c.execute("SELECT 1 FROM users WHERE username=?", (u,)).fetchone():
            c.execute("INSERT INTO users VALUES(?,?,?)", (u, hashlib.sha256(p.encode()).hexdigest(), r))
    ensure("admin", "admin123", "admin"); ensure("viewer", "viewer123", "viewer")
    conn.commit(); conn.close()

init_db()

# --- ZABBIX DISCOVERY HELPERS ---

def get_zabbix_token():
    try:
        auth_p = {"jsonrpc": "2.0", "method": "user.login", "params": {"user": ZABBIX_USER, "password": ZABBIX_PASS}, "id": 1}
        r = requests.post(ZABBIX_URL, json=auth_p, timeout=5).json()
        return r.get('result')
    except: return None

@app.route("/zabbix_hosts")
def list_zabbix_hosts():
    if session.get("role") != "admin": return jsonify([])
    token = get_zabbix_token()
    if not token: return jsonify([])
    try:
        payload = {"jsonrpc": "2.0", "method": "host.get", "params": {"output": ["hostid", "name"], "filter": {"status": 0}, "sortfield": "name"}, "auth": token, "id": 1}
        resp = requests.post(ZABBIX_URL, json=payload, timeout=5).json()
        return jsonify(resp.get('result', []))
    except: return jsonify([])

@app.route("/zabbix_items/<hostid>")
def list_zabbix_items(hostid):
    if session.get("role") != "admin": return jsonify([])
    token = get_zabbix_token()
    if not token: return jsonify([])
    try:
        payload = {"jsonrpc": "2.0", "method": "item.get", "params": {"hostids": hostid, "output": ["name", "key_"], "filter": {"status": 0}, "sortfield": "name"}, "auth": token, "id": 1}
        resp = requests.post(ZABBIX_URL, json=payload, timeout=5).json()
        return jsonify(resp.get('result', []))
    except: return jsonify([])

# --- MONITORING LOGIC ---

def send_telegram(host, desc, check, time, duration=None, event_type=None):
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID: return
    header = "✅ RECOVERED" if duration else "🚨 ALERT: DOWN"
    if event_type: msg = f"⚙️ CONFIG: {event_type}\nHost: {host}\nDesc: {desc}\nTime: {time}"
    else:
        msg = f"{header}\nHost: {host}\nDesc: {desc}\nCheck: {check}\nTime: {time}"
        if duration: msg += f"\nDuration: {duration}"
    try: requests.post(f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
                      json={"chat_id": TELEGRAM_CHAT_ID, "text": msg}, timeout=5)
    except: pass

async def check_icmp(host, timeout):
    try:
        p = await asyncio.create_subprocess_exec("ping", "-c", "3", "-i", "0.2", "-W", str(timeout), host, 
                                                 stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
        await p.wait(); return p.returncode == 0
    except: return False

async def check_tcp(host, port, timeout):
    try:
        def _connect():
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(float(timeout))
            res = s.connect_ex((host, int(port))); s.close(); return res == 0
        return await loop.run_in_executor(None, _connect)
    except: return False

async def check_zabbix_status(hostid, item_key):
    def _fetch():
        token = get_zabbix_token()
        if not token: return False
        try:
            item_p = {"jsonrpc":"2.0","method":"item.get","params":{"hostids":hostid,"search":{"key_":item_key},"output":["lastvalue"]},"auth":token,"id":1}
            res = requests.post(ZABBIX_URL, json=item_p, timeout=5).json()
            items = res.get('result', [])
            return str(items[0].get('lastvalue')) == "1" if items else False
        except: return False
    return await loop.run_in_executor(None, _fetch)

async def monitor_target(tid):
    await asyncio.sleep(random.uniform(0.5, 1.5))
    while True:
        try:
            conn = get_db(); c = conn.cursor()
            t = c.execute("SELECT * FROM targets WHERE id=?", (tid,)).fetchone()
            if not t: conn.close(); return
            if t["maintenance"]: conn.close(); await asyncio.sleep(t["check_interval"]); continue

            m_type = t['monitor_type'].upper()
            if m_type == "ZABBIX": ok = await check_zabbix_status(t["name"], t["zabbix_item_key"]); m_info = f"ZBX:{t['zabbix_item_key']}"
            elif m_type == "TCP": ok = await check_tcp(t["name"], t["monitor_port"], t["timeout"]); m_info = f"TCP:{t['monitor_port']}"
            else: ok = await check_icmp(t["name"], t["timeout"]); m_info = "ICMP"

            now = datetime.now(); ts = now.strftime("%Y-%m-%d %H:%M:%S")

            if ok:
                if t["status"] == "Offline":
                    down_dt = datetime.strptime(t["last_down"], "%Y-%m-%d %H:%M:%S")
                    dur_str = str(now - down_dt).split(".")[0]
                    c.execute("UPDATE targets SET status='Online', fail_count=0, last_down=NULL, last_check=? WHERE id=? AND status='Offline'", (ts, tid))
                    if c.rowcount > 0:
                        conn.commit()
                        if (now - down_dt).total_seconds() >= MIN_OUTAGE_DURATION:
                            c.execute("UPDATE incidents SET up_time=?, duration=? WHERE target=? AND up_time IS NULL", (ts, dur_str, t["name"]))
                            conn.commit()
                        send_telegram(t['name'], t['description'], m_info, ts, dur_str)
                else:
                    c.execute("UPDATE targets SET last_check=?, fail_count=0 WHERE id=?", (ts, tid))
            else:
                new_fail = t["fail_count"] + 1
                if new_fail >= FAIL_THRESHOLD and t["status"] == "Online":
                    c.execute("UPDATE targets SET status='Offline', last_down=?, fail_count=?, last_check=? WHERE id=? AND status='Online'", (ts, new_fail, ts, tid))
                    if c.rowcount > 0:
                        c.execute("INSERT INTO incidents(target, monitor_detail, down_time) VALUES(?,?,?)", (t["name"], m_info, ts))
                        conn.commit()
                        send_telegram(t['name'], t['description'], m_info, ts)
                else:
                    c.execute("UPDATE targets SET fail_count=?, last_check=? WHERE id=?", (new_fail, ts, tid))
            conn.commit(); conn.close()
            socketio.emit('status_update')
        except: pass
        await asyncio.sleep(t["check_interval"] if 't' in locals() and t else 10)

def start_task(tid): tasks[tid] = loop.create_task(monitor_target(tid))
def run_loop():
    asyncio.set_event_loop(loop)
    conn = get_db()
    for r in conn.execute("SELECT id FROM targets"): start_task(r["id"])
    conn.close(); loop.run_forever()

# --- ROUTES ---

@app.route("/")
def index():
    if "user" not in session: return redirect("/login")
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u, p = request.form["username"], hashlib.sha256(request.form["password"].encode()).hexdigest()
        r = get_db().execute("SELECT role FROM users WHERE username=? AND password=?", (u, p)).fetchone()
        if r: session["user"] = u; session["role"] = r["role"]; return redirect("/")
    return render_template("login.html")

@app.route("/logout")
def logout(): session.clear(); return redirect("/login")

@app.route("/status")
def status(): return jsonify([dict(r) for r in get_db().execute("SELECT * FROM targets")])

@app.route("/incidents")
def incidents(): return jsonify([dict(r) for r in get_db().execute("SELECT * FROM incidents ORDER BY id DESC LIMIT 15")])

@app.route("/add", methods=["POST"])
def add():
    if session.get("role") != "admin": return jsonify({"ok":0}), 403
    p = request.form
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    z_key = p.get("zabbix_item_key", "")
    m_type = p.get("monitor_type", "ICMP")
    
    conn = get_db(); c = conn.cursor()
    try:
        c.execute("""INSERT INTO targets(name,description,monitor_type,monitor_port,check_interval,timeout,status,last_check,zabbix_item_key) 
                     VALUES(?,?,?,?,?,?,?,?,?)""",
                  (p["name"], p["description"], m_type, p.get("monitor_port", ""), 
                   p["check_interval"], p["timeout"], "Online", ts, z_key))
        tid = c.lastrowid
        conn.commit()
        loop.call_soon_threadsafe(start_task, tid)
        m_info = f"{m_type}:{z_key if m_type == 'ZABBIX' else p.get('monitor_port')}"
        send_telegram(p["name"], p["description"], m_info, ts, event_type="ADDED NEW HOST")
        socketio.emit('status_update')
        return jsonify({"ok": 1})
    except Exception as e:
        print(f"❌ [BORG] Add failed: {e}")
        return jsonify({"ok": 0, "error": str(e)}), 500
    finally:
        conn.close()

@app.route("/remove/<int:id>", methods=["POST"])
def remove(id):
    if session.get("role") != "admin": return "Err", 403
    conn = get_db(); t = conn.execute("SELECT name, description FROM targets WHERE id=?", (id,)).fetchone()
    conn.execute("DELETE FROM targets WHERE id=?", (id,)); conn.commit(); conn.close()
    if id in tasks: tasks[id].cancel(); del tasks[id]
    send_telegram(t['name'], t['description'], None, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), event_type="REMOVED HOST")
    socketio.emit('status_update'); return jsonify({"ok": 1})

@app.route("/toggle_maintenance/<int:id>", methods=["POST"])
def maint(id):
    if session.get("role") != "admin": return "Err", 403
    conn = get_db(); t = conn.execute("SELECT name, description, maintenance FROM targets WHERE id=?", (id,)).fetchone()
    new_m = 1 - t['maintenance']
    conn.execute("UPDATE targets SET maintenance=? WHERE id=?", (new_m, id)); conn.commit(); conn.close()
    send_telegram(t['name'], t['description'], None, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), event_type="MAINTENANCE STATUS CHANGED")
    socketio.emit('status_update'); return jsonify({"ok": 1})

@app.route("/update_target/<int:id>", methods=["POST"])
def update_target(id):
    if session.get("role") != "admin": return "Err", 403
    p = request.form
    conn = get_db(); t = conn.execute("SELECT name FROM targets WHERE id=?", (id,)).fetchone()
    conn.execute("UPDATE targets SET description=?, check_interval=?, timeout=? WHERE id=?", (p["description"], p["check_interval"], p["timeout"], id))
    conn.commit(); conn.close()
    if id in tasks: tasks[id].cancel(); loop.call_soon_threadsafe(start_task, id)
    socketio.emit('status_update'); return jsonify({"ok": 1})

@app.route("/clear_incidents", methods=["POST"])
def clear_incidents():
    if session.get("role") != "admin": return "Err", 403
    conn = get_db(); conn.execute("DELETE FROM incidents"); conn.commit(); conn.close()
    socketio.emit('status_update'); return jsonify({"ok": 1})

if __name__ == "__main__":
    if not MONITOR_STARTED:
        if os.environ.get("WERKZEUG_RUN_MAIN") == "true" or not app.debug:
            threading.Thread(target=run_loop, daemon=True).start()
            MONITOR_STARTED = True
    socketio.run(app, host="0.0.0.0", port=5555, debug=True)
