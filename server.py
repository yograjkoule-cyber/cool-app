"""
Secure chat server.

Security design
  * Passwords never reach the server. The app turns the password into two
    separate secrets (PBKDF2): one to log in, one to lock your private key.
    The server stores only a hash of the login secret.
  * Messages are end-to-end encrypted on your PC (ECDH P-256 + AES-256-GCM).
    The server only stores and forwards ciphertext - it cannot read messages.
  * Login tokens are signed and expire after 7 days.
  * Rate limits on login / register / sending, strict input checks,
    secret key generated randomly on first run.

Run:   pip install flask flask-sock requests websocket-client cryptography
       python server.py        (then start client.py in another terminal)
"""
import json
import os
import re
import secrets
import sqlite3
import threading
import time

from flask import Flask, jsonify, request
from flask_sock import Sock
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from werkzeug.security import check_password_hash, generate_password_hash

BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE, "chat.db")
KEY_FILE = os.path.join(BASE, "secret.key")
TOKEN_MAX_AGE = 7 * 24 * 3600

USERNAME_RE = re.compile(r"^[a-z0-9_]{3,20}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
B64_RE = re.compile(r"^[A-Za-z0-9+/=]+$")


def load_secret():
    if not os.path.exists(KEY_FILE):
        with open(KEY_FILE, "w") as f:
            f.write(secrets.token_hex(32))
    with open(KEY_FILE) as f:
        return f.read().strip()


app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024
app.config["SOCK_SERVER_OPTIONS"] = {"ping_interval": 25}
sock = Sock(app)
signer = URLSafeTimedSerializer(load_secret(), salt="auth-token")
DUMMY_HASH = generate_password_hash("dummy")  # keeps login timing equal for unknown users


# ---------------------------------------------------------------- database
def db():
    conn = sqlite3.connect(DB, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with db() as c:
        c.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                auth_hash TEXT NOT NULL,
                public_key TEXT NOT NULL,
                wrapped_key TEXT NOT NULL,
                created REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender TEXT NOT NULL, receiver TEXT NOT NULL,
                iv TEXT NOT NULL, ct TEXT NOT NULL, ts REAL NOT NULL);
            CREATE INDEX IF NOT EXISTS idx_msg_pair ON messages(sender, receiver);
            """
        )


def user_exists(name):
    with db() as c:
        return c.execute("SELECT 1 FROM users WHERE username=?", (name,)).fetchone() is not None


# ---------------------------------------------------------------- helpers
_hits, _hits_lock = {}, threading.Lock()


def too_many(key, limit, window):
    """True if `key` did more than `limit` actions in the last `window` seconds."""
    now = time.time()
    with _hits_lock:
        recent = [t for t in _hits.get(key, []) if now - t < window]
        blocked = len(recent) >= limit
        if not blocked:
            recent.append(now)
        _hits[key] = recent
        return blocked


def make_token(username):
    return signer.dumps(username)


def read_token(token):
    try:
        return signer.loads(token, max_age=TOKEN_MAX_AGE)
    except (BadSignature, SignatureExpired):
        return None


def current_user():
    header = request.headers.get("Authorization", "")
    if header.startswith("Bearer "):
        name = read_token(header[7:])
        if name and user_exists(name):
            return name
    return None


def body():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def error(msg, code=400):
    return jsonify(error=msg), code


def valid_public_key(s):
    try:
        j = json.loads(s)
        return (
            len(s) < 500 and j.get("kty") == "EC" and j.get("crv") == "P-256"
            and isinstance(j.get("x"), str) and isinstance(j.get("y"), str)
        )
    except Exception:
        return False


def valid_wrapped_key(s):
    try:
        j = json.loads(s)
        return len(s) < 4000 and isinstance(j.get("iv"), str) and isinstance(j.get("ct"), str)
    except Exception:
        return False


# ---------------------------------------------------------------- API
@app.post("/api/register")
def register():
    if too_many("reg:" + str(request.remote_addr), 20, 3600):
        return error("Too many attempts. Try again later.", 429)
    d = body()
    username = str(d.get("username", "")).lower()
    auth, pub, wrapped = d.get("auth", ""), d.get("public_key", ""), d.get("wrapped_key", "")
    if not USERNAME_RE.match(username):
        return error("Username must be 3-20 characters: a-z, 0-9, _")
    if not (isinstance(auth, str) and HEX64_RE.match(auth)):
        return error("Invalid request")
    if not (isinstance(pub, str) and valid_public_key(pub)):
        return error("Invalid public key")
    if not (isinstance(wrapped, str) and valid_wrapped_key(wrapped)):
        return error("Invalid key data")
    try:
        with db() as c:
            c.execute(
                "INSERT INTO users(username, auth_hash, public_key, wrapped_key, created) VALUES (?,?,?,?,?)",
                (username, generate_password_hash(auth), pub, wrapped, time.time()),
            )
    except sqlite3.IntegrityError:
        return error("That username is taken", 409)
    return jsonify(token=make_token(username))


@app.post("/api/login")
def login():
    d = body()
    username = str(d.get("username", "")).lower()
    auth = d.get("auth", "")
    if too_many(f"login:{request.remote_addr}:{username}", 10, 60):
        return error("Too many attempts. Wait a minute.", 429)
    if not (isinstance(auth, str) and HEX64_RE.match(auth)):
        return error("Invalid request")
    with db() as c:
        row = c.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    ok = check_password_hash(row["auth_hash"] if row else DUMMY_HASH, auth)
    if not (row and ok):
        return error("Wrong username or password", 401)
    return jsonify(token=make_token(username), public_key=row["public_key"], wrapped_key=row["wrapped_key"])


@app.get("/api/users")
def users():
    if not current_user():
        return error("Not logged in", 401)
    with db() as c:
        rows = c.execute("SELECT username, public_key FROM users ORDER BY username").fetchall()
    with clients_lock:
        online = list(clients.keys())
    return jsonify(users=[dict(r) for r in rows], online=online)


@app.get("/api/history/<peer>")
def history(peer):
    me = current_user()
    if not me:
        return error("Not logged in", 401)
    if not USERNAME_RE.match(peer):
        return error("Invalid user")
    with db() as c:
        rows = c.execute(
            """SELECT sender, receiver, iv, ct, ts FROM messages
               WHERE (sender=? AND receiver=?) OR (sender=? AND receiver=?)
               ORDER BY id DESC LIMIT 500""",
            (me, peer, peer, me),
        ).fetchall()
    return jsonify(messages=[dict(r) for r in reversed(rows)])


# ---------------------------------------------------------------- WebSocket
clients, clients_lock = {}, threading.Lock()  # username -> set of sockets
send_lock = threading.Lock()


def push(username, payload):
    with clients_lock:
        targets = list(clients.get(username, ()))
    text = json.dumps(payload)
    for w in targets:
        try:
            with send_lock:
                w.send(text)
        except Exception:
            pass


def push_presence():
    with clients_lock:
        names = list(clients.keys())
    for n in names:
        push(n, {"type": "presence", "online": names})


def handle_message(user, raw):
    try:
        m = json.loads(raw)
    except ValueError:
        return
    if not isinstance(m, dict):
        return
    to = m.get("to")
    if not (isinstance(to, str) and USERNAME_RE.match(to) and user_exists(to)):
        return
    if m.get("type") == "typing":
        push(to, {"type": "typing", "from": user})
        return
    if m.get("type") != "msg":
        return
    iv, ct = m.get("iv"), m.get("ct")
    if not (isinstance(iv, str) and isinstance(ct, str) and B64_RE.match(iv) and B64_RE.match(ct)):
        return
    if len(iv) > 32 or len(ct) > 12000:
        return
    if too_many("send:" + user, 30, 10):
        return
    ts = time.time()
    with db() as c:
        c.execute(
            "INSERT INTO messages(sender, receiver, iv, ct, ts) VALUES (?,?,?,?,?)",
            (user, to, iv, ct, ts),
        )
    out = {"type": "msg", "sender": user, "receiver": to, "iv": iv, "ct": ct, "ts": ts}
    push(to, out)
    if to != user:
        push(user, out)


@sock.route("/ws")
def ws_route(ws):
    try:
        first = json.loads(ws.receive(timeout=10) or "{}")
        user = read_token(first.get("token", "")) if first.get("type") == "auth" else None
    except Exception:
        user = None
    if not (user and user_exists(user)):
        ws.close()
        return
    with clients_lock:
        clients.setdefault(user, set()).add(ws)
    push_presence()
    try:
        while True:
            raw = ws.receive()
            if raw is None or len(raw) > 20000:
                continue
            handle_message(user, raw)
    except Exception:
        pass
    finally:
        with clients_lock:
            clients.get(user, set()).discard(ws)
            if not clients.get(user):
                clients.pop(user, None)
        push_presence()


if __name__ == "__main__":
    init_db()
    cert, key = os.path.join(BASE, "cert.pem"), os.path.join(BASE, "key.pem")
    https = os.path.exists(cert) and os.path.exists(key)
    host = os.environ.get("CHAT_HOST", "127.0.0.1")
    print(f"Server running at {'https' if https else 'http'}://localhost:5000")
    app.run(host=host, port=5000, threaded=True, ssl_context=(cert, key) if https else None)
