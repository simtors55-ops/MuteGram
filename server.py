# -*- coding: utf-8 -*-
"""MuteGram online API starter. Python 3.11+."""
import os
import re
import sqlite3
import secrets
import hashlib
import hmac
from functools import wraps
from pathlib import Path
from flask import Flask, request, jsonify, g

app = Flask(__name__)
DB_PATH = os.environ.get("DATABASE_PATH", str(Path(__file__).with_name("mutegram_server.sqlite3")))
ADMIN_KEY = os.environ.get("MUTEGRAM_ADMIN_KEY", "")
PHONE_RE = re.compile(r"^\+(?:7|888)[0-9]{7,14}$")
PBKDF2_ROUNDS = 310_000

def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db

@app.teardown_appcontext
def close_db(_error=None):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS players (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        phone TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        name TEXT NOT NULL,
        stars INTEGER NOT NULL DEFAULT 500,
        verified INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS sessions (
        token_hash TEXT PRIMARY KEY,
        player_id INTEGER NOT NULL REFERENCES players(id) ON DELETE CASCADE,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS phone_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        player_id INTEGER NOT NULL REFERENCES players(id) ON DELETE CASCADE,
        phone TEXT NOT NULL,
        changed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    """)
    conn.commit()
    conn.close()

def hash_password(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), PBKDF2_ROUNDS).hex()

def make_token(player_id):
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    db().execute("INSERT INTO sessions(token_hash, player_id) VALUES (?, ?)", (token_hash, player_id))
    db().commit()
    return token

def current_player():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token_hash = hashlib.sha256(auth[7:].strip().encode()).hexdigest()
    return db().execute(
        "SELECT p.* FROM players p JOIN sessions s ON s.player_id=p.id WHERE s.token_hash=?",
        (token_hash,)
    ).fetchone()

def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        player = current_player()
        if player is None:
            return jsonify(error="Требуется вход в аккаунт"), 401
        g.player = player
        return fn(*args, **kwargs)
    return wrapped

def player_json(p):
    return {"id": p["id"], "phone": p["phone"], "name": p["name"],
            "stars": p["stars"], "verified": bool(p["verified"])}

@app.get("/")
def index():
    return jsonify(service="MuteGram API", status="ok", version=1)

@app.get("/health")
def health():
    return jsonify(status="ok")

@app.post("/api/register")
def register():
    data = request.get_json(silent=True) or {}
    phone = str(data.get("phone", "")).replace(" ", "").replace("-", "")
    password = str(data.get("password", ""))
    name = str(data.get("name", "")).strip()[:24]
    if not PHONE_RE.fullmatch(phone):
        return jsonify(error="Номер должен начинаться с +7 или +888 и содержать цифры"), 400
    if len(password) < 8:
        return jsonify(error="Пароль должен содержать минимум 8 символов"), 400
    if not name:
        return jsonify(error="Укажи имя игрока"), 400
    salt = secrets.token_bytes(16).hex()
    pwd_hash = hash_password(password, salt)
    try:
        cur = db().execute(
            "INSERT INTO players(phone,password_hash,salt,name) VALUES(?,?,?,?)",
            (phone, pwd_hash, salt, name)
        )
        player_id = cur.lastrowid
        db().execute("INSERT INTO phone_history(player_id,phone) VALUES(?,?)", (player_id, phone))
        db().commit()
    except sqlite3.IntegrityError:
        return jsonify(error="Этот игровой номер уже занят"), 409
    token = make_token(player_id)
    player = db().execute("SELECT * FROM players WHERE id=?", (player_id,)).fetchone()
    return jsonify(token=token, player=player_json(player)), 201

@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}
    phone = str(data.get("phone", "")).replace(" ", "").replace("-", "")
    password = str(data.get("password", ""))
    player = db().execute("SELECT * FROM players WHERE phone=?", (phone,)).fetchone()
    if player is None or not hmac.compare_digest(hash_password(password, player["salt"]), player["password_hash"]):
        return jsonify(error="Неверный номер или пароль"), 401
    return jsonify(token=make_token(player["id"]), player=player_json(player))

@app.get("/api/me")
@login_required
def me():
    return jsonify(player=player_json(g.player))

@app.post("/api/logout")
@login_required
def logout():
    token = request.headers.get("Authorization", "")[7:].strip()
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    db().execute("DELETE FROM sessions WHERE token_hash=?", (token_hash,))
    db().commit()
    return jsonify(status="ok")

@app.post("/api/change-phone")
@login_required
def change_phone():
    data = request.get_json(silent=True) or {}
    new_phone = str(data.get("phone", "")).replace(" ", "").replace("-", "")
    if not new_phone.startswith("+888") or not PHONE_RE.fullmatch(new_phone):
        return jsonify(error="В магазине можно установить только виртуальный номер +888"), 400
    try:
        db().execute("UPDATE players SET phone=? WHERE id=?", (new_phone, g.player["id"]))
        db().execute("INSERT INTO phone_history(player_id,phone) VALUES(?,?)", (g.player["id"], new_phone))
        db().commit()
    except sqlite3.IntegrityError:
        return jsonify(error="Этот игровой номер уже занят"), 409
    player = db().execute("SELECT * FROM players WHERE id=?", (g.player["id"],)).fetchone()
    return jsonify(player=player_json(player), message="Основной игровой номер изменён")

@app.get("/api/phone-history")
@login_required
def phone_history():
    rows = db().execute("SELECT phone,changed_at FROM phone_history WHERE player_id=? ORDER BY id DESC",
                        (g.player["id"],)).fetchall()
    return jsonify(history=[dict(r) for r in rows])

@app.post("/api/admin/player")
def admin_player():
    if not ADMIN_KEY or not hmac.compare_digest(request.headers.get("X-Admin-Key", ""), ADMIN_KEY):
        return jsonify(error="Нет доступа администратора"), 403
    data = request.get_json(silent=True) or {}
    phone = str(data.get("phone", "")).replace(" ", "").replace("-", "")
    player = db().execute("SELECT * FROM players WHERE phone=?", (phone,)).fetchone()
    if player is None:
        return jsonify(error="Игрок не найден"), 404
    return jsonify(player=player_json(player))

@app.post("/api/admin/stars")
def admin_stars():
    if not ADMIN_KEY or not hmac.compare_digest(request.headers.get("X-Admin-Key", ""), ADMIN_KEY):
        return jsonify(error="Нет доступа администратора"), 403
    data = request.get_json(silent=True) or {}
    phone = str(data.get("phone", "")).replace(" ", "").replace("-", "")
    try:
        amount = int(data.get("amount", 0))
    except (TypeError, ValueError):
        return jsonify(error="Количество должно быть целым числом"), 400
    if amount == 0 or abs(amount) > 1_000_000:
        return jsonify(error="Недопустимое количество"), 400
    cur = db().execute("UPDATE players SET stars=stars+? WHERE phone=?", (amount, phone))
    db().commit()
    if cur.rowcount == 0:
        return jsonify(error="Игрок не найден"), 404
    player = db().execute("SELECT * FROM players WHERE phone=?", (phone,)).fetchone()
    return jsonify(player=player_json(player))

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "10000")))
