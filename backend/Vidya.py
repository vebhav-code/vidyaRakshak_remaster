import os
from contextlib import contextmanager
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
import psycopg2
from dotenv import load_dotenv

# Load environment variables from backend/.env if present
load_dotenv(os.path.join(os.path.dirname(__file__), '.env'))

app = Flask(
    __name__,
    template_folder="../frontend/templates",
    static_folder="../frontend/static",
    static_url_path='/'
)
app.secret_key = os.environ.get("SECRET_KEY", "vidya_rakshak_default_secret_key_change_in_production")


@app.route('/static/<path:filename>')
def serve_static_prefixed(filename):
    return send_from_directory(app.static_folder, filename)


DATABASE_URL = os.environ.get("DATABASE_URL")
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# Treat placeholder as unconfigured
IS_PLACEHOLDER_DB = not DATABASE_URL or DATABASE_URL.strip() in ("", "REPLACE_WITH_RENDER_POSTGRES_URL")

_db_initialized = False


@contextmanager
def get_db():
    if IS_PLACEHOLDER_DB:
        raise RuntimeError("DATABASE_URL environment variable is not configured. Set a valid Postgres URL in .env or environment.")
    conn = psycopg2.connect(DATABASE_URL)
    try:
        yield conn
    finally:
        conn.close()


def init_db():
    if IS_PLACEHOLDER_DB:
        return
    try:
        with get_db() as conn:
            with conn.cursor() as cursor:
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS details (
                    id SERIAL PRIMARY KEY,
                    first_name VARCHAR(50) NOT NULL,
                    last_name VARCHAR(50) NOT NULL,
                    email VARCHAR(100) UNIQUE NOT NULL,
                    password VARCHAR(255) NOT NULL,
                    score INT NOT NULL DEFAULT 125,
                    activity INT NOT NULL DEFAULT 1
                );
                """)
            conn.commit()
    except Exception as e:
        app.logger.error(f"Database initialization failed: {e}")


# Run table initialization at module startup if DATABASE_URL is available
init_db()


@app.before_request
def ensure_db_initialized():
    global _db_initialized
    if not _db_initialized and not IS_PLACEHOLDER_DB:
        init_db()
        _db_initialized = True


@app.route("/")
def home():
    return render_template("front.html")


@app.route("/signup", methods=["POST"])
def signup():
    first_name = request.form.get("first_name", "").strip()
    last_name = request.form.get("last_name", "").strip()
    email = request.form.get("email", "").strip()
    password = request.form.get("password", "")
    confirm = request.form.get("confirm_password", "")

    if not first_name or not last_name or not email or not password:
        flash("All fields are required!", "error")
        return redirect(url_for("home"))

    if password != confirm:
        flash("Passwords do not match!", "error")
        return redirect(url_for("home"))

    hashed_password = generate_password_hash(password)

    try:
        with get_db() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO details (first_name, last_name, email, password, score, activity) VALUES (%s, %s, %s, %s, 125, 1)",
                    (first_name, last_name, email, hashed_password)
                )
            conn.commit()
        flash("Signup successful! Please log in.", "success")
    except psycopg2.IntegrityError:
        flash("An account with that email already exists. Please log in.", "error")
    except Exception as e:
        app.logger.error(f"Signup error: {e}")
        flash("An error occurred during signup. Please try again.", "error")

    return redirect(url_for("home"))


@app.route("/login", methods=["POST"])
def login():
    email = request.form.get("email", "").strip()
    password = request.form.get("password", "")

    if not email or not password:
        flash("Please enter both email and password.", "error")
        return redirect(url_for("home"))

    try:
        with get_db() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT first_name, last_name, email, password, score, activity FROM details WHERE email = %s",
                    (email,)
                )
                user = cursor.fetchone()

        if user and check_password_hash(user[3], password):
            session["first_name"] = user[0]
            session["last_name"] = user[1]
            session["email"] = user[2]
            flash("Login successful!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid email or password.", "error")
            return redirect(url_for("home"))
    except Exception as e:
        app.logger.error(f"Login error: {e}")
        flash("Database error during login. Please try again later.", "error")
        return redirect(url_for("home"))


@app.route("/dashboard")
def dashboard():
    if "email" not in session:
        flash("Please log in to access the dashboard.", "error")
        return redirect(url_for("home"))

    try:
        with get_db() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT first_name, last_name FROM details WHERE email = %s",
                    (session["email"],)
                )
                user = cursor.fetchone()

        if user:
            return render_template(
                "dashboard.html",
                first_name=user[0],
                last_name=user[1]
            )
        else:
            session.clear()
            flash("User not found. Please log in again.", "error")
            return redirect(url_for("home"))
    except Exception as e:
        app.logger.error(f"Dashboard error: {e}")
        return render_template(
            "dashboard.html",
            first_name=session.get("first_name", "User"),
            last_name=session.get("last_name", "")
        )


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("home"))


if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)