# -*- coding: utf-8 -*-
"""MuteGram online API v2. Render start command: gunicorn server:app"""
import os, re, secrets, hashlib, hmac
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, request, jsonify, g
from sqlalchemy import (
    create_engine, String, Integer, Boolean, DateTime, ForeignKey, Text,
    select, UniqueConstraint
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker
from sqlalchemy.exc import IntegrityError

app = Flask(__name__)

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///mutegram.sqlite3")
# Render/Postgres URLs sometimes use postgres://; SQLAlchemy expects postgresql://.
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = "postgresql://" + DATABASE_URL[len("postgres://"):]
engine_options = {"pool_pre_ping": True}
if DATABASE_URL.startswith("sqlite:"):
    engine_options["connect_args"] = {"check_same_thread": False}
engine = create_engine(DATABASE_URL, **engine_options)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)

ADMIN_KEY = os.environ.get("MUTEGRAM_ADMIN_KEY", "")
PHONE_RE = re.compile(r"^\+(?:7|888)[0-9]{7,14}$")
PBKDF2_ROUNDS = 310_000


class Base(DeclarativeBase):
    pass


class Player(Base):
    __tablename__ = "players"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    phone: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(128))
    salt: Mapped[str] = mapped_column(String(64))
    name: Mapped[str] = mapped_column(String(24), default="Новый пользователь")
    username: Mapped[str] = mapped_column(String(32), default="star_user")
    stars: Mapped[int] = mapped_column(Integer, default=500)
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    opened: Mapped[int] = mapped_column(Integer, default=0)
    sold: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    inventory = relationship("Gift", cascade="all, delete-orphan", back_populates="player")
    nfts = relationship("NFT", cascade="all, delete-orphan", back_populates="player")
    numbers = relationship("OwnedNumber", cascade="all, delete-orphan", back_populates="player")
    history = relationship("PhoneHistory", cascade="all, delete-orphan", back_populates="player")


class SessionToken(Base):
    __tablename__ = "sessions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    player_id: Mapped[int] = mapped_column(ForeignKey("players.id", ondelete="CASCADE"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))


class Gift(Base):
    __tablename__ = "gifts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    player_id: Mapped[int] = mapped_column(ForeignKey("players.id", ondelete="CASCADE"), index=True)
    gift_key: Mapped[str] = mapped_column(String(48))
    name: Mapped[str] = mapped_column(String(64))
    emoji: Mapped[str] = mapped_column(String(16), default="🎁")
    value: Mapped[int] = mapped_column(Integer, default=0)
    rarity: Mapped[str] = mapped_column(String(32), default="Обычный")
    player = relationship("Player", back_populates="inventory")


class NFT(Base):
    __tablename__ = "nft_usernames"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    player_id: Mapped[int] = mapped_column(ForeignKey("players.id", ondelete="CASCADE"), index=True)
    username: Mapped[str] = mapped_column(String(40))
    player = relationship("Player", back_populates="nfts")
    __table_args__ = (UniqueConstraint("player_id", "username", name="uq_player_nft"),)


class OwnedNumber(Base):
    __tablename__ = "owned_numbers"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    player_id: Mapped[int] = mapped_column(ForeignKey("players.id", ondelete="CASCADE"), index=True)
    phone: Mapped[str] = mapped_column(String(32))
    player = relationship("Player", back_populates="numbers")
    __table_args__ = (UniqueConstraint("player_id", "phone", name="uq_player_number"),)


class PhoneHistory(Base):
    __tablename__ = "phone_history"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    player_id: Mapped[int] = mapped_column(ForeignKey("players.id", ondelete="CASCADE"), index=True)
    phone: Mapped[str] = mapped_column(String(32))
    changed_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    player = relationship("Player", back_populates="history")


Base.metadata.create_all(engine)


@app.before_request
def open_db():
    g.db = SessionLocal()


@app.teardown_request
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        if exc:
            db.rollback()
        db.close()


def db():
    return g.db


def fail(message, status=400):
    return jsonify({"error": message}), status


def clean_phone(value):
    return re.sub(r"[\s()-]", "", str(value or ""))


def password_hash(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), PBKDF2_ROUNDS).hex()


def new_token(player):
    token = secrets.token_urlsafe(36)
    db().add(SessionToken(token_hash=hashlib.sha256(token.encode()).hexdigest(), player_id=player.id))
    db().commit()
    return token


def auth_player():
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return None
    raw = header[7:].strip()
    if not raw:
        return None
    token_hash = hashlib.sha256(raw.encode()).hexdigest()
    session = db().scalar(select(SessionToken).where(SessionToken.token_hash == token_hash))
    return db().get(Player, session.player_id) if session else None


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        player = auth_player()
        if not player:
            return fail("Требуется вход в аккаунт", 401)
        g.player = player
        return fn(*args, **kwargs)
    return wrapper


def player_json(p):
    return {
        "id": p.id, "phone": p.phone, "name": p.name, "username": p.username,
        "stars": p.stars, "verified": bool(p.verified),
        "opened": p.opened, "sold": p.sold,
        "inventory": [
            {"id": x.id, "key": x.gift_key, "name": x.name, "emoji": x.emoji,
             "value": x.value, "rarity": x.rarity} for x in p.inventory
        ],
        "nft_usernames": [x.username for x in p.nfts],
        "nft_username": p.nfts[0].username if p.nfts else None,
        "owned_numbers": [x.phone for x in p.numbers],
    }


@app.get("/")
def index():
    return jsonify({"service": "MuteGram API", "version": 2, "status": "online"})


@app.get("/health")
def health():
    try:
        db().execute(select(Player.id).limit(1))
        return jsonify({"status": "ok", "database": "connected", "version": 2})
    except Exception:
        return fail("Database is unavailable", 503)


@app.post("/api/register")
def register():
    body = request.get_json(silent=True) or {}
    phone = clean_phone(body.get("phone"))
    password = str(body.get("password") or "")
    name = str(body.get("name") or "Новый пользователь").strip()
    if not PHONE_RE.fullmatch(phone):
        return fail("Неверный номер. Используйте +7 или +888 и цифры.")
    if len(password) < 8:
        return fail("Пароль должен содержать минимум 8 символов.")
    if not name or len(name) > 24:
        return fail("Имя должно содержать от 1 до 24 символов.")
    if db().scalar(select(Player.id).where(Player.phone == phone)):
        return fail("Этот номер уже зарегистрирован.", 409)
    salt = secrets.token_hex(16)
    player = Player(phone=phone, password_hash=password_hash(password, salt),
                    salt=salt, name=name, username="star_user")
    db().add(player)
    try:
        db().flush()
        db().add(PhoneHistory(player_id=player.id, phone=phone))
        db().commit()
    except IntegrityError:
        db().rollback()
        return fail("Этот номер уже зарегистрирован.", 409)
    return jsonify({"token": new_token(player), "player": player_json(player)}), 201


@app.post("/api/login")
def login():
    body = request.get_json(silent=True) or {}
    phone = clean_phone(body.get("phone"))
    password = str(body.get("password") or "")
    player = db().scalar(select(Player).where(Player.phone == phone))
    if not player or not hmac.compare_digest(player.password_hash, password_hash(password, player.salt)):
        return fail("Неверный номер или пароль.", 401)
    return jsonify({"token": new_token(player), "player": player_json(player)})


@app.get("/api/me")
@login_required
def me():
    return jsonify({"player": player_json(g.player)})


@app.post("/api/logout")
@login_required
def logout():
    raw = request.headers.get("Authorization", "")[7:].strip()
    token_hash = hashlib.sha256(raw.encode()).hexdigest()
    session = db().scalar(select(SessionToken).where(SessionToken.token_hash == token_hash))
    if session:
        db().delete(session)
        db().commit()
    return jsonify({"status": "ok"})


@app.patch("/api/profile")
@login_required
def update_profile():
    body = request.get_json(silent=True) or {}
    p = g.player
    if "name" in body:
        name = str(body["name"]).strip()
        if not name or len(name) > 24:
            return fail("Имя должно содержать от 1 до 24 символов.")
        p.name = name
    if "username" in body:
        username = str(body["username"]).strip().lstrip("@")
        if not re.fullmatch(r"[A-Za-z0-9_]{3,32}", username):
            return fail("Юзернейм: 3–32 символа, латиница, цифры и _.")
        p.username = username
    db().commit()
    return jsonify({"player": player_json(p)})


@app.get("/api/phone-history")
@login_required
def phone_history():
    rows = db().scalars(select(PhoneHistory).where(
        PhoneHistory.player_id == g.player.id).order_by(PhoneHistory.id.desc())).all()
    return jsonify({"history": [{"phone": x.phone, "changed_at": x.changed_at.isoformat()} for x in rows]})


def admin_ok():
    return bool(ADMIN_KEY) and hmac.compare_digest(request.headers.get("X-Admin-Key", ""), ADMIN_KEY)


def admin_player():
    if not admin_ok():
        return None, fail("Нет доступа администратора.", 403)
    body = request.get_json(silent=True) or {}
    phone = clean_phone(body.get("phone"))
    p = db().scalar(select(Player).where(Player.phone == phone))
    if not p:
        return None, fail("Игрок не найден.", 404)
    return p, None


@app.post("/api/admin/player")
def admin_get_player():
    p, error = admin_player()
    if error:
        return error
    return jsonify({"player": player_json(p)})


@app.post("/api/admin/stars")
def admin_stars():
    p, error = admin_player()
    if error:
        return error
    amount = (request.get_json(silent=True) or {}).get("amount")
    if not isinstance(amount, int) or isinstance(amount, bool) or abs(amount) > 1_000_000:
        return fail("Количество звёзд должно быть целым числом до 1 000 000.")
    if p.stars + amount < 0:
        return fail("Нельзя списать больше звёзд, чем есть у игрока.")
    p.stars += amount
    db().commit()
    return jsonify({"player": player_json(p)})


@app.post("/api/admin/verify")
def admin_verify():
    p, error = admin_player()
    if error:
        return error
    value = (request.get_json(silent=True) or {}).get("verified")
    if not isinstance(value, bool):
        return fail("Поле verified должно быть true или false.")
    p.verified = value
    db().commit()
    return jsonify({"player": player_json(p)})


@app.post("/api/admin/gift")
def admin_gift():
    p, error = admin_player()
    if error:
        return error
    body = request.get_json(silent=True) or {}
    name = str(body.get("name") or "Подарок").strip()[:64]
    emoji = str(body.get("emoji") or "🎁")[:16]
    key = str(body.get("key") or "admin_gift")[:48]
    rarity = str(body.get("rarity") or "Особый")[:32]
    value = body.get("value", 0)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0 or value > 10_000_000:
        return fail("Некорректная стоимость подарка.")
    db().add(Gift(player_id=p.id, gift_key=key, name=name, emoji=emoji, value=value, rarity=rarity))
    db().commit()
    return jsonify({"player": player_json(p)})


@app.post("/api/admin/nft")
def admin_nft():
    p, error = admin_player()
    if error:
        return error
    username = str((request.get_json(silent=True) or {}).get("username") or "").strip().lstrip("@")
    if not re.fullmatch(r"[A-Za-z0-9_]{3,40}", username):
        return fail("Некорректный NFT-юзернейм.")
    if any(x.username.lower() == username.lower() for x in p.nfts):
        return fail("У игрока уже есть этот NFT-юзернейм.")
    db().add(NFT(player_id=p.id, username=username))
    db().commit()
    return jsonify({"player": player_json(p)})


@app.post("/api/admin/number")
def admin_number():
    p, error = admin_player()
    if error:
        return error
    phone = clean_phone((request.get_json(silent=True) or {}).get("phone"))
    if not PHONE_RE.fullmatch(phone):
        return fail("Некорректный номер.")
    if not any(x.phone == phone for x in p.numbers):
        db().add(OwnedNumber(player_id=p.id, phone=phone))
    db().commit()
    return jsonify({"player": player_json(p)})


@app.post("/api/change-phone")
@login_required
def change_phone():
    body = request.get_json(silent=True) or {}
    phone = clean_phone(body.get("phone"))
    if not phone.startswith("+888") or not PHONE_RE.fullmatch(phone):
        return fail("Новый игровой номер должен начинаться с +888.")
    p = g.player
    if phone == p.phone:
        return fail("Этот номер уже используется.")
    if db().scalar(select(Player.id).where(Player.phone == phone)):
        return fail("Номер уже занят другим игроком.", 409)
    old_phone = p.phone
    p.phone = phone
    if not any(x.phone == phone for x in p.numbers):
        db().add(OwnedNumber(player_id=p.id, phone=phone))
    db().add(PhoneHistory(player_id=p.id, phone=phone))
    db().commit()
    return jsonify({"player": player_json(p), "message": "Номер изменён", "old_phone": old_phone})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8000")))
