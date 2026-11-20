# MuteGram FINAL API — FastAPI + SQLite
import os, json, sqlite3, secrets, hashlib, hmac, re
from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel

DB = os.environ.get("MUTEGRAM_DB", "mutegram.db")
ADMIN_PHONE = os.environ.get("MUTEGRAM_ADMIN_PHONE", "")
ADMIN_KEY = os.environ.get("MUTEGRAM_ADMIN_KEY", "")
app = FastAPI(title="MuteGram FINAL API", version="1.0")

def db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    return con

def init():
    with db() as con:
        con.execute("""CREATE TABLE IF NOT EXISTS users(
            phone TEXT PRIMARY KEY, password_hash TEXT NOT NULL,
            salt TEXT NOT NULL, profile_json TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0)""")
        con.execute("""CREATE TABLE IF NOT EXISTS sessions(
            token TEXT PRIMARY KEY, phone TEXT NOT NULL)""")
init()

def normalize_phone(phone):
    p = re.sub(r"[^\d+]", "", phone.strip())
    if not p.startswith("+") or len(re.sub(r"\D", "", p)) < 8:
        raise HTTPException(400, "Введите полный номер телефона с кодом страны")
    return p

def hash_password(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 240000).hex()

def default_profile(phone, name="Новый пользователь"):
    return {
        "stars": 500, "phone": phone, "name": name[:24],
        "username": "user_" + secrets.token_hex(3),
        "nft_username": None, "nft_usernames": [], "owned_numbers": [],
        "verified": False, "inventory": [], "opened": 0, "sold": 0
    }

def session_user(authorization):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Сначала войдите в аккаунт")
    token = authorization[7:]
    with db() as con:
        row = con.execute("""SELECT users.* FROM sessions
            JOIN users ON users.phone=sessions.phone WHERE sessions.token=?""",
            (token,)).fetchone()
    if not row:
        raise HTTPException(401, "Сессия недействительна")
    return row

class Register(BaseModel):
    phone: str
    password: str
    name: str = "Новый пользователь"

class Login(BaseModel):
    phone: str
    password: str

class ProfileUpdate(BaseModel):
    profile: dict

class AdminGrant(BaseModel):
    phone: str
    kind: str
    value: str = ""

@app.get("/")
def root():
    return {"service":"MuteGram FINAL API","status":"online"}


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

    try:
        salt = secrets.token_hex(16)
        player = Player(
            phone=phone,
            password_hash=password_hash(password, salt),
            salt=salt,
            name=name,
            username="star_user"
        )

        db().add(player)
        db().flush()

        db().add(PhoneHistory(player_id=player.id, phone=phone))
        db().commit()

        token = new_token(player)

        return jsonify({
            "token": token,
            "player": player_json(player)
        }), 201

    except IntegrityError:
        db().rollback()
        return fail("Этот номер уже зарегистрирован.", 409)

    except Exception:
        db().rollback()
        app.logger.exception("MUTEGRAM REGISTER ERROR")
        return fail("Внутренняя ошибка регистрации. Проверьте логи Render.", 500)


@app.post("/login")
def login(body: Login):
    phone = normalize_phone(body.phone)
    with db() as con:
        row = con.execute("SELECT * FROM users WHERE phone=?", (phone,)).fetchone()
        if not row or not hmac.compare_digest(hash_password(body.password,row["salt"]),row["password_hash"]):
            raise HTTPException(401, "Неверный номер или пароль")
        token = secrets.token_urlsafe(32)
        con.execute("INSERT INTO sessions(token,phone) VALUES(?,?)",(token,phone))
        profile = json.loads(row["profile_json"])
    return {"token":token,"profile":profile}

@app.put("/profile")
def update_profile(body: ProfileUpdate, authorization: str = Header(default="")):
    user = session_user(authorization)
    profile = body.profile
    # Phone is managed by the purchase endpoint; ignore client attempts to change it.
    profile["phone"] = user["phone"]
    with db() as con:
        con.execute("UPDATE users SET profile_json=? WHERE phone=?",
                    (json.dumps(profile,ensure_ascii=False),user["phone"]))
    return {"ok":True}

@app.get("/profile")
def get_profile(authorization: str = Header(default="")):
    user = session_user(authorization)
    return {"profile":json.loads(user["profile_json"])}

@app.post("/logout")
def logout(authorization: str = Header(default="")):
    if authorization.startswith("Bearer "):
        with db() as con:
            con.execute("DELETE FROM sessions WHERE token=?",(authorization[7:],))
    return {"ok":True}

@app.post("/purchase-number")
def purchase_number(body: dict, authorization: str = Header(default="")):
    user = session_user(authorization)
    new_phone = normalize_phone(str(body.get("number","")))
    if not new_phone.startswith("+888"):
        raise HTTPException(400,"В магазине доступны только номера +888")
    with db() as con:
        if con.execute("SELECT 1 FROM users WHERE phone=?",(new_phone,)).fetchone():
            raise HTTPException(409,"Этот номер уже занят")
        profile = json.loads(user["profile_json"])
        price = int(body.get("price",0))
        if price <= 0 or profile.get("stars",0) < price:
            raise HTTPException(400,"Недостаточно звёзд или неверная цена")
        old_phone = user["phone"]
        profile["stars"] -= price
        profile.setdefault("owned_numbers",[]).append(old_phone)
        profile["phone"] = new_phone
        con.execute("UPDATE users SET phone=?,profile_json=? WHERE phone=?",
                    (new_phone,json.dumps(profile,ensure_ascii=False),old_phone))
        con.execute("UPDATE sessions SET phone=? WHERE phone=?",(new_phone,old_phone))
    return {"ok":True,"profile":profile}

@app.post("/admin/grant")
def admin_grant(body: AdminGrant, authorization: str = Header(default="")):
    user = session_user(authorization)
    if not user["is_admin"] or not ADMIN_KEY:
        raise HTTPException(403,"Нет прав администратора")
    target = normalize_phone(body.phone)
    with db() as con:
        row = con.execute("SELECT profile_json FROM users WHERE phone=?",(target,)).fetchone()
        if not row:
            raise HTTPException(404,"Игрок с таким номером не найден")
        profile = json.loads(row["profile_json"])
        if body.kind == "stars":
            amount = int(body.value)
            if amount < 1 or amount > 100000000: raise HTTPException(400,"Некорректное количество")
            profile["stars"] = profile.get("stars",0) + amount
        elif body.kind == "verify":
            profile["verified"] = body.value.lower() == "true"
        elif body.kind == "username":
            tag = body.value.strip().lstrip("@")
            if not tag: raise HTTPException(400,"Пустой NFT-юзернейм")
            tags = profile.setdefault("nft_usernames",[])
            if tag not in tags: tags.append(tag)
            profile["nft_username"] = tags[0] if tags else None
        else:
            raise HTTPException(400,"Неизвестный тип награды")
        con.execute("UPDATE users SET profile_json=? WHERE phone=?",
                    (json.dumps(profile,ensure_ascii=False),target))
    return {"ok":True,"profile":profile}
