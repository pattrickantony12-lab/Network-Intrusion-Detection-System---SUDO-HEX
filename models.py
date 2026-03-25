from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()


class User(db.Model):
    # ── Stored in users.db (separate from nids.db) ──────────────────────────
    # Developer: open  instance/users.db  with DB Browser for SQLite to view
    # all registered usernames and their plain + hashed passwords.
    # ─────────────────────────────────────────────────────────────────────────
    __tablename__ = "users"
    __bind_key__ = "users"          # <-- uses users.db, NOT nids.db

    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(80),  unique=True, nullable=False)
    plain_password = db.Column(db.String(128), nullable=False)  # DEV ONLY: readable in users.db
    password_hash = db.Column(db.String(256), nullable=False)   # used by login (hashed)

    def set_password(self, password):
        self.plain_password = password                      # store plain for dev inspection
        self.password_hash  = generate_password_hash(password)  # store hash for login

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class DetectionLog(db.Model):
    __tablename__ = "detection_logs"

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime)
    protocol = db.Column(db.String(20))
    network_layer = db.Column(db.String(20))
    osi_layer = db.Column(db.String(20))
    source_ip = db.Column(db.String(50))
    destination_ip = db.Column(db.String(50))
    attack_type = db.Column(db.String(100))
    is_malicious = db.Column(db.Boolean)
    confidence = db.Column(db.Float)
    severity = db.Column(db.String(20))
