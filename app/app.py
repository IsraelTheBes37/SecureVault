import os
import io
import base64
import secrets
import string
from functools import wraps
from datetime import timedelta
from urllib.parse import quote, urlparse

import pyotp
import qrcode
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.fernet import Fernet
from flask import (
    Flask, request, redirect, url_for, session,
    render_template_string, flash
)
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]
app.config["SQLALCHEMY_DATABASE_URI"] = (
    f"postgresql+psycopg://{quote(os.environ['POSTGRES_USER'], safe='')}:"
    f"{quote(os.environ['POSTGRES_PASSWORD'], safe='')}@db:5432/"
    f"{quote(os.environ['POSTGRES_DB'], safe='')}"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.getenv("COOKIE_SECURE", "false").lower() == "true"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)
app.config["SESSION_REFRESH_EACH_REQUEST"] = False
app.config["WTF_CSRF_TIME_LIMIT"] = 3600
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024

csrf = CSRFProtect(app)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["300 per day", "100 per hour"],
    storage_uri="memory://",
)

db = SQLAlchemy(app)
hasher = PasswordHasher()
cipher = Fernet(os.environ["FERNET_KEY"].encode())


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(254), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    totp_secret = db.Column(db.String(64), nullable=False)


class Credential(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    title = db.Column(db.String(120), nullable=False)
    username = db.Column(db.String(254), nullable=False, default="")
    password_encrypted = db.Column(db.Text, nullable=False)
    website = db.Column(db.String(500), default="")
    note_encrypted = db.Column(db.Text, default="")


def encrypt(value):
    return cipher.encrypt(value.encode()).decode()


def decrypt(value):
    return cipher.decrypt(value.encode()).decode()


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper


BASE = """
<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SecureVault</title>
<style>
*{box-sizing:border-box}body{margin:0;background:#0b1120;color:#e5e7eb;
font:16px Arial,sans-serif}header{padding:20px 7%;background:#111b2e;
display:flex;justify-content:space-between;align-items:center}
a{color:#7dd3fc;text-decoration:none}main{max-width:1000px;margin:35px auto;padding:0 20px}
.card{background:#151f33;border:1px solid #293750;border-radius:14px;
padding:24px;margin:16px 0}input,textarea,button{font:inherit;padding:12px;
border-radius:7px;border:1px solid #40516c;width:100%;margin:7px 0}
input,textarea{background:#0b1120;color:white}button{background:#38bdf8;
color:#082032;border:0;font-weight:bold;cursor:pointer}
small,.muted{color:#aab8cc}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:15px}
.row{display:flex;gap:12px;align-items:center}.row form{flex:1}
.danger{background:#f87171}.secret{overflow-wrap:anywhere}
</style>
</head>
<body>
<header><strong>🔐 SecureVault</strong>
<nav><a href="/">Inicio</a> · <a href="/vault">Mis credenciales</a> ·
<a href="/profile">Perfil</a> · <form method="post" action="/logout" style="display:inline">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><button type="submit" style="width:auto;padding:0;background:none;color:#7dd3fc">Salir</button></form></nav></header>
<main>
{% for message in get_flashed_messages() %}
<div class="card">{{message}}</div>{% endfor %}
CONTENT
</main></body></html>
"""


def page(content, **context):
    return render_template_string(BASE.replace("CONTENT", content), **context)


@app.route("/")
def home():
    if "user_id" not in session:
        return redirect(url_for("login"))
    if not session.get("mfa_ok"):
        return redirect(url_for("verify_2fa"))

    count = Credential.query.filter_by(user_id=session["user_id"]).count()
    return page("""
    <h1>Dashboard</h1>
    <p class="muted">Tu espacio personal de seguridad.</p>
    <div class="grid">
      <div class="card"><h3>Credenciales</h3><h1>{{count}}</h1></div>
      <div class="card"><h3>Autenticación</h3><p>2FA habilitado</p></div>
      <div class="card"><h3>Protección</h3><p>Contraseñas de acceso con Argon2</p></div>
    </div>
    <div class="card"><h2>Acceso rápido</h2>
    <a href="/vault">Consultar mis credenciales →</a></div>
    """, count=count)


@app.route("/register", methods=["GET", "POST"])
@limiter.limit("5 per hour", methods=["POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if len(email) > 254 or not email or "@" not in email:
            flash("Introduce un correo válido.")
            return redirect(url_for("register"))
        if len(password) < 12:
            flash("La contraseña debe tener al menos 12 caracteres.")
            return redirect(url_for("register"))
        if User.query.filter_by(email=email).first():
            flash("Ese correo ya está registrado.")
            return redirect(url_for("register"))

        secret = pyotp.random_base32()
        user = User(email=email, password_hash=hasher.hash(password),
                    totp_secret=secret)
        db.session.add(user)
        db.session.commit()

        session.clear()
        session.permanent = True
        session["pending_user_id"] = user.id
        uri = pyotp.TOTP(secret).provisioning_uri(
            name=email, issuer_name="SecureVault"
        )
        qr = qrcode.make(uri)
        output = io.BytesIO()
        qr.save(output, format="PNG")
        image = base64.b64encode(output.getvalue()).decode()
        return page("""
        <div class="card"><h1>Configura el segundo factor</h1>
        <p>Escanea el QR con una aplicación autenticadora compatible con TOTP.</p>
        <img alt="QR de configuración 2FA"
        style="background:white;padding:10px;max-width:240px;width:100%"
        src="data:image/png;base64,{{image}}">
        <p>Introduce el código de seis cifras para activar tu cuenta.</p>
        <form method="post" action="/setup-2fa">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <input name="code" inputmode="numeric" pattern="[0-9]{6}"
        maxlength="6" placeholder="Código de seis cifras" required>
        <button>Activar 2FA</button></form></div>
        """, image=image)

    return page("""
    <div class="card"><h1>Crear cuenta</h1>
    <form method="post">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
    <label>Correo electrónico</label><input type="email" name="email" required>
    <label>Contraseña (mínimo 12 caracteres)</label>
    <input type="password" name="password" minlength="12" required>
    <button>Registrarme</button></form>
    <p>¿Ya tienes cuenta? <a href="/login">Iniciar sesión</a></p></div>
    """)


@app.route("/setup-2fa", methods=["POST"])
@limiter.limit("5 per minute")
def setup_2fa():
    user_id = session.get("pending_user_id")
    user = db.session.get(User, user_id) if user_id else None
    code = request.form.get("code", "").strip()

    if not user or not pyotp.TOTP(user.totp_secret).verify(code, valid_window=1):
        flash("Código incorrecto. Vuelve a intentarlo.")
        return redirect(url_for("register"))

    session.clear()
    session.permanent = True
    session["user_id"] = user.id
    session["mfa_ok"] = True
    return redirect(url_for("home"))


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter_by(email=email).first()

        try:
            valid = user is not None and hasher.verify(user.password_hash, password)
        except (VerifyMismatchError, Exception):
            valid = False

        if not valid:
            flash("Correo o contraseña incorrectos.")
            return redirect(url_for("login"))

        session.clear()
        session.permanent = True
        session["pending_user_id"] = user.id
        return redirect(url_for("verify_2fa"))

    return page("""
    <div class="card"><h1>Iniciar sesión</h1>
    <form method="post">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
    <label>Correo electrónico</label><input type="email" name="email" required>
    <label>Contraseña</label><input type="password" name="password" required>
    <button>Continuar</button></form>
    <p>¿No tienes cuenta? <a href="/register">Registrarme</a></p></div>
    """)


@app.route("/verify-2fa", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def verify_2fa():
    user_id = session.get("pending_user_id")
    user = db.session.get(User, user_id) if user_id else None
    if not user:
        return redirect(url_for("login"))

    if request.method == "POST":
        code = request.form.get("code", "").strip()
        if pyotp.TOTP(user.totp_secret).verify(code, valid_window=1):
            session.clear()
            session.permanent = True
            session["user_id"] = user.id
            session["mfa_ok"] = True
            return redirect(url_for("home"))
        flash("Código 2FA incorrecto.")

    return page("""
    <div class="card"><h1>Verificación 2FA</h1>
    <p>Abre tu aplicación autenticadora e introduce el código actual.</p>
    <form method="post">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><input name="code" inputmode="numeric"
    pattern="[0-9]{6}" maxlength="6" placeholder="000000" required>
    <button>Verificar</button></form></div>
    """)


@app.route("/vault", methods=["GET", "POST"])
@login_required
def vault():
    if not session.get("mfa_ok"):
        return redirect(url_for("verify_2fa"))

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        website = request.form.get("website", "").strip()
        note = request.form.get("note", "")
        parsed_website = urlparse(website) if website else None

        if not title or len(title) > 120 or len(username) > 254:
            flash("Revisa el título y el usuario.")
        elif len(password) > 4096 or len(note) > 10000 or len(website) > 500:
            flash("Uno de los campos supera el tamaño permitido.")
        elif parsed_website and (parsed_website.scheme not in ("http", "https") or not parsed_website.netloc):
            flash("La web debe comenzar por http:// o https:// y tener un dominio válido.")
        elif not password:
            flash("La contraseña no puede estar vacía.")
        else:
            item = Credential(
                user_id=session["user_id"], title=title, username=username,
                password_encrypted=encrypt(password), website=website,
                note_encrypted=encrypt(note)
            )
            db.session.add(item)
            db.session.commit()
            flash("Credencial guardada cifrada.")
            return redirect(url_for("vault"))

    items = Credential.query.filter_by(user_id=session["user_id"]).order_by(
        Credential.title
    ).all()
    visible = []
    for item in items:
        visible.append({
            "id": item.id, "title": item.title, "username": item.username,
            "password": decrypt(item.password_encrypted),
            "website": item.website, "note": decrypt(item.note_encrypted)
        })

    return page("""
    <h1>Mis credenciales</h1>
    <div class="card"><h2>Nueva credencial</h2>
    <form method="post">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
    <label>Título</label><input name="title" maxlength="120" required>
    <label>Usuario o correo</label><input name="username" maxlength="254">
    <label>Contraseña</label><input id="pw" name="password" required>
    <button type="button" onclick="makePassword()">Generar contraseña segura</button>
    <label>Sitio web</label><input type="url" name="website" maxlength="500">
    <label>Nota</label><textarea name="note" maxlength="10000"></textarea>
    <button>Guardar credencial</button></form></div>
    {% for item in items %}
    <div class="card"><h3>{{item.title}}</h3>
    <p>Usuario: {{item.username}}</p>
    {% if item.website %}<p><a href="{{item.website}}" target="_blank"
    rel="noopener noreferrer">{{item.website}}</a></p>{% endif %}
    <details><summary>Mostrar contraseña y nota</summary>
    <p class="secret">Contraseña: {{item.password}}</p>
    <p class="secret">Nota: {{item.note}}</p></details>
    <form method="post" action="/delete/{{item.id}}"
    onsubmit="return confirm('¿Eliminar esta credencial?')">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
    <button class="danger">Eliminar</button></form></div>
    {% else %}<p>Aún no tienes credenciales guardadas.</p>{% endfor %}
    <script>
    function makePassword(){
      const chars="ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%&*_-";
      const values=new Uint32Array(24);
      crypto.getRandomValues(values);
      document.getElementById("pw").value=
        Array.from(values,v=>chars[v%chars.length]).join("");
    }
    </script>
    """, items=visible)


@app.route("/delete/<int:item_id>", methods=["POST"])
@login_required
def delete_credential(item_id):
    item = db.session.get(Credential, item_id)
    if item and item.user_id == session["user_id"]:
        db.session.delete(item)
        db.session.commit()
        flash("Credencial eliminada.")
    return redirect(url_for("vault"))


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    user = db.session.get(User, session["user_id"])
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        current = request.form.get("current_password", "")
        new = request.form.get("new_password", "")

        try:
            valid = hasher.verify(user.password_hash, current)
        except Exception:
            valid = False

        if not valid:
            flash("La contraseña actual no es correcta.")
        elif not email or len(email) > 254 or "@" not in email:
            flash("Correo no válido.")
        elif User.query.filter(User.email == email, User.id != user.id).first():
            flash("Ese correo ya está en uso.")
        elif new and len(new) < 12:
            flash("La nueva contraseña debe tener al menos 12 caracteres.")
        else:
            user.email = email
            if new:
                user.password_hash = hasher.hash(new)
            db.session.commit()
            flash("Perfil actualizado.")
            return redirect(url_for("profile"))

    return page("""
    <div class="card"><h1>Mi perfil</h1>
    <form method="post">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
    <label>Correo electrónico</label>
    <input type="email" name="email" value="{{user.email}}" required>
    <label>Contraseña actual (obligatoria para guardar)</label>
    <input type="password" name="current_password" required>
    <label>Nueva contraseña (dejar vacía para no cambiarla)</label>
    <input type="password" name="new_password" minlength="12">
    <button>Guardar cambios</button></form>
    <p>2FA: activado. Esta versión no permite desactivarlo desde el perfil.</p>
    </div>
    """, user=user)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.get("/health")
def health():
    try:
        db.session.execute(db.text("SELECT 1"))
        return {"status": "ok"}, 200
    except Exception:
        return {"status": "database unavailable"}, 503


with app.app_context():
    db.create_all()