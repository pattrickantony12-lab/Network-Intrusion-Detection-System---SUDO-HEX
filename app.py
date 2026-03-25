import os
from datetime import datetime
from flask import (Flask, render_template, request, redirect,
                   url_for, flash, session, send_file, after_this_request)
from flask_socketio import SocketIO
from models import db, User, DetectionLog
from sim_network import NetworkSimulator
from pdf_report import generate_merged_report
from dotenv import load_dotenv

load_dotenv()  # Load variables from .env file

app = Flask(__name__)
app.config['SECRET_KEY'] = 'nids_super_secret_cyber_key_2026'

# ── DATABASE SETUP ────────────────────────────────────────────────────────────
# nids.db  → stores detection logs (wiped each session for forensic freshness)
# users.db → stores registered users PERMANENTLY (never wiped on restart)
#            Developer: open  instance/users.db  in DB Browser for SQLite
#            to inspect all usernames + hashed passwords at any time.
# ─────────────────────────────────────────────────────────────────────────────
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///nids.db'
app.config['SQLALCHEMY_BINDS'] = {
    'users': 'sqlite:///users.db'   # permanent user credentials database
}
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

sim = NetworkSimulator()
is_running = False
LOG_FILE = 'sudo_hex_log.txt'

# Track total statistics for PDF reports
global_attack_stats = {
    'Normal': 0,
    'DDoS Attack (TCP-SYN Flood)': 0,
    'Web Attack (XSS Injection)': 0,
    'Brute Force (RDP/SSH)': 0,
    'Backdoor (C2 Trojan Call)': 0,
    'Exploit (Remote Code Execution)': 0}
global_protocol_stats = {
    'TCP': 0, 'UDP': 0, 'HTTP': 0, 'HTTPS': 0, 'ICMP': 0
}
# The malicious history will now be pulled from the database directly

ADMIN_EMAIL = 'admin@cybersecurity.local'
# For simulation we just print to console/log





def get_log_file():
    """Returns the log file path. Creates the file only when first called during analysis."""
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'w') as f:
            f.write("SUDO HEX LOG - ANALYSIS SESSION STARTED\n")
            f.write(f"Session Start: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 50 + "\n")
    return LOG_FILE


def append_to_log(packet):
    with open(get_log_file(), 'a') as f:
        log_entry = (
            f"[{packet['timestamp']}] PROTOCOL: {packet['protocol']} | "
            f"OSI: {packet.get('osi_layer', 'N/A')} | "
            f"LAYER: {packet['network_layer']} | "
            f"SRC: {packet['source_ip']} -> DST: {packet['destination_ip']} | "
            f"ATTACK: {packet['attack_type']} | "
            f"MALICIOUS: {packet['is_malicious']}\n"
        )
        f.write(log_entry)


def bg_network_monitor():
    global is_running
    is_running = True
    while is_running:
        socketio.sleep(4)  # Analysis Cycle (4 seconds)
        packet = sim.generate_packet()

        # Track statistics in memory for the session (synced with DB on start)
        if packet['attack_type'] in global_attack_stats:
            global_attack_stats[packet['attack_type']] += 1
        if packet['protocol'] in global_protocol_stats:
            global_protocol_stats[packet['protocol']] += 1

        # FORENSIC LOG: Write every packet (including malicious) to the text log file
        # NOTE: get_log_file() creates the file here, during analysis — NOT at startup
        append_to_log(packet)

        # BROADCAST: Emit ALL packets to the live dashboard for real-time visibility
        socketio.emit('new_packet', packet)

        # FORENSIC LOGGING: Only save genuine high-priority attacks to the database
        if packet['is_malicious']:
            print(f"[ALERT] TRACE DETECTED: {packet['attack_type']}")
            log = DetectionLog(
                timestamp=datetime.strptime(packet['timestamp'], '%Y-%m-%d %H:%M:%S'),
                protocol=packet['protocol'],
                network_layer=packet['network_layer'],
                osi_layer=packet.get('osi_layer', 'N/A'),
                source_ip=packet['source_ip'],
                destination_ip=packet['destination_ip'],
                attack_type=packet['attack_type'],
                is_malicious=packet['is_malicious'],
                confidence=packet.get('confidence', 0.0),
                severity=packet.get('severity', 'Unknown')
            )
            with app.app_context():
                db.session.add(log)
                db.session.commit()



# App Startup configuration is handled below in main


@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/manifest.json')
def manifest():
    return send_file('static/manifest.json')


@app.route('/sw.js')
def service_worker():
    return send_file('static/sw.js', mimetype='application/javascript')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username
            return redirect(url_for('dashboard'))

        flash('Invalid username or password.', 'error')

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'error')
        else:
            new_user = User(username=username)  # pyright: ignore[reportCallIssue]
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            # Credentials are permanently saved to instance/users.db
            # Developer: open that file in DB Browser for SQLite to inspect.
            print(f"[NIDS] New user registered: '{username}' -> saved to users.db")
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html',
                           username=session.get('username'))


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    return redirect(url_for('login'))


@app.route('/download-log')
def download_log():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    file_path = get_log_file()
    return send_file(
        file_path,
        as_attachment=True,
        download_name='nids_log.txt')


@app.route('/clear-db')
def clear_db():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    try:
        # Wipe all records from the Database
        DetectionLog.query.delete()
        db.session.commit()
        
        # Reset in-memory statistics
        global global_attack_stats, global_protocol_stats
        for k in global_attack_stats:
            global_attack_stats[k] = 0
        for k in global_protocol_stats:
            global_protocol_stats[k] = 0
        
        flash("SUDO HEX Database cleared successfully. Forensic log is now clean.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error clearing database: {str(e)}", "danger")
        
    return redirect(url_for('dashboard'))


@app.route('/download-report')
def download_report():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Pull all forensic malicious logs from the session
    malicious_logs = DetectionLog.query.filter_by(is_malicious=True).all()
    
    if not malicious_logs:
        flash("No qualifying high-priority attacks (excluding Port Scans) detected yet.", "info")
        return redirect(url_for('dashboard'))

    # Format data and calculate specific malicious protocol stats for the report
    malicious_history_data = []
    malicious_protocol_stats = {'TCP': 0, 'UDP': 0, 'HTTP': 0, 'HTTPS': 0, 'ICMP': 0}
    
    # Calculate attack stats for the report exclusively for the qualifying attacks
    report_attack_stats = {}
    
    for log in malicious_logs:
        malicious_history_data.append({
            'timestamp':      log.timestamp,
            'protocol':       log.protocol,
            'network_layer':  log.network_layer,
            'osi_layer':      log.osi_layer or 'N/A',
            'source_ip':      log.source_ip,
            'destination_ip': log.destination_ip,
            'attack_type':    log.attack_type,
            'is_malicious':   log.is_malicious,
            'confidence':     log.confidence,
            'severity':       log.severity
        })
        if log.protocol in malicious_protocol_stats:
            malicious_protocol_stats[log.protocol] += 1
            
        # Build specific counts for the PDF charts
        report_attack_stats[log.attack_type] = report_attack_stats.get(log.attack_type, 0) + 1

    # Generate the merged PDF report focusing only on the qualifying malicious data
    pdf_path = generate_merged_report(
        malicious_history_data, report_attack_stats, malicious_protocol_stats)

    # Send the file and clean up
    response = send_file(pdf_path, as_attachment=True,
                         download_name=f"SUDO_HEX_Full_Report_{datetime.now().strftime('%Y%m%d')}.pdf")

    # Use a helper or after_this_request to delete but the user
    # wants it "as option not to save straightly in reports folder"
    # so we'll delete it after sending.
    @after_this_request
    def remove_file(response):
        try:
            if os.path.exists(pdf_path):
                os.remove(pdf_path)
        except Exception as e:
            app.logger.error(f"Error deleting temp report: {e}")
        return response

    return response


# ─────────────────────────────────────────────────────────────────
# DEVELOPER CREDENTIALS  (visible ONLY in source code / terminal)
# Plain-text values are NEVER sent to the browser or stored in DB.
# The database stores ONLY the bcrypt hash shown below at runtime.
# ─────────────────────────────────────────────────────────────────
DEV_USERNAME = 'admin'          # <-- change to your preferred username
DEV_PASSWORD = 'admin123'       # <-- change to your preferred password
# ─────────────────────────────────────────────────────────────────


if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # creates both nids.db and users.db if they don't exist

        # Forensic Reset: Clear ONLY detection logs on startup for a fresh session.
        # Users are NEVER wiped — registrations persist across restarts.
        DetectionLog.query.delete()
        db.session.commit()

        # ── DEFAULT ADMIN (created ONCE, only if no users exist yet) ──────────
        # DEV_USERNAME / DEV_PASSWORD below are visible to you in source code.
        # Regular users only ever interact with the hashed version via browser.
        # To inspect all accounts: open  instance/users.db  in DB Browser for SQLite
        # ─────────────────────────────────────────────────────────────────────
        if not User.query.first():  # skip if users already registered
            default_user = User(username=DEV_USERNAME)  # pyright: ignore[reportCallIssue]
            default_user.set_password(DEV_PASSWORD)
            db.session.add(default_user)
            db.session.commit()
            print(f"[NIDS] Default admin created -> username: '{DEV_USERNAME}' password: '{DEV_PASSWORD}'")
        else:
            total = User.query.count()
            print(f"[NIDS] Persistent user DB loaded -- {total} account(s) found in users.db")
        print("[NIDS] Developer: open  instance/users.db  to inspect all credentials.")

        # Reset memory statistics for a fresh session
        for k in global_attack_stats:
            global_attack_stats[k] = 0
        for k in global_protocol_stats:
            global_protocol_stats[k] = 0

    # Start background packet monitoring
    socketio.start_background_task(bg_network_monitor)
    socketio.run(app, debug=False, port=5555, allow_unsafe_werkzeug=True)
