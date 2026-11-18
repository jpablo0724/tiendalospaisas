"""Academia Tienda Los Paisas - Login (Flask + SQLite)."""
import os
import re
import secrets
import sqlite3
from functools import wraps
from pathlib import Path

from flask import (Flask, abort, flash, g, redirect, render_template, request,
                   session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).parent
DB_PATH = BASE_DIR / "academia.db"

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# ---------- Base de datos ----------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    with sqlite3.connect(DB_PATH) as db:
        db.execute(
            """CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nombre TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                rol TEXT NOT NULL DEFAULT 'estudiante',
                creado_en TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )"""
        )


# ---------- CSRF simple ----------
def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(16)
    return session["_csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def check_csrf():
    if request.method == "POST":
        token = session.get("_csrf")
        if not token or not secrets.compare_digest(token, request.form.get("_csrf", "")):
            abort(400, "Token CSRF inválido")


# ---------- Auth ----------
@app.before_request
def load_user():
    uid = session.get("user_id")
    g.user = None
    if uid is not None:
        g.user = get_db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def safe_next(target):
    """Solo permite redirecciones internas."""
    if target and target.startswith("/") and not target.startswith("//"):
        return target
    return url_for("dashboard")


@app.route("/")
def index():
    return redirect(url_for("dashboard" if g.user else "login"))


@app.route("/registro", methods=["GET", "POST"])
def registro():
    if g.user:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        nombre = request.form.get("nombre", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirmar = request.form.get("confirmar", "")

        error = None
        if not nombre:
            error = "El nombre es obligatorio."
        elif not EMAIL_RE.match(email):
            error = "Correo electrónico inválido."
        elif len(password) < 8:
            error = "La contraseña debe tener al menos 8 caracteres."
        elif password != confirmar:
            error = "Las contraseñas no coinciden."

        if error is None:
            try:
                db = get_db()
                db.execute(
                    "INSERT INTO users (nombre, email, password_hash) VALUES (?, ?, ?)",
                    (nombre, email, generate_password_hash(password)),
                )
                db.commit()
            except sqlite3.IntegrityError:
                error = "Ya existe una cuenta con ese correo."
            else:
                flash("Cuenta creada. Ya puedes iniciar sesión.", "ok")
                return redirect(url_for("login"))
        flash(error, "error")
    return render_template("registro.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = get_db().execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        if user is None or not check_password_hash(user["password_hash"], password):
            flash("Correo o contraseña incorrectos.", "error")
        else:
            session.clear()
            session["user_id"] = user["id"]
            return redirect(safe_next(request.args.get("next")))
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    # Datos de ejemplo hasta que exista la carga real de imágenes.
    colores = ["#ffd500", "#1f4fd8", "#e3171e", "#d9651b"]
    categorias = ["Productos", "Promociones", "Redes sociales", "Logos"]
    imagenes = [
        {"titulo": f"Imagen {i + 1:02d}", "categoria": categorias[i % 4],
         "color": colores[i % 4], "formato": "PNG" if i % 2 else "JPG"}
        for i in range(12)
    ]
    return render_template("dashboard.html", imagenes=imagenes, categorias=categorias)


init_db()

if __name__ == "__main__":
    app.run(debug=True)
