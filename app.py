import os
import sqlite3
import secrets
from datetime import date, datetime, timedelta
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, abort
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# =========================
# Sicherheits-Konfiguration
# =========================

app.secret_key = os.environ.get("SECRET_KEY", "local_dev_secret_change_me")

is_production = os.environ.get("APP_ENV") == "production"

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = is_production
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=12)

# Login-Schutz
MAX_LOGIN_FAILURES = 5
USERNAME_LOCKOUT_MINUTES = 15

# IP-Schutz
MAX_IP_FAILURES = 20
IP_LOCKOUT_MINUTES = 15

# Datenbankpfad
DB_PATH = os.environ.get("DATABASE_PATH", "database.db")


# =========================
# Hilfsfunktionen
# =========================

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def login_required(view_func):
    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        if "user_id" not in session:
            flash("Bitte logge dich zuerst ein.", "error")
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)
    return wrapped_view


def get_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


def validate_csrf():
    session_token = session.get("csrf_token")
    form_token = request.form.get("csrf_token")
    header_token = request.headers.get("X-CSRFToken")

    provided_token = form_token or header_token

    if not session_token or not provided_token or session_token != provided_token:
        abort(400, description="Ungültiger CSRF-Token.")


def get_client_ip():
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.remote_addr or "unknown"


@app.before_request
def csrf_protect():
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        validate_csrf()


@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"

    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "font-src 'self' https://cdn.jsdelivr.net; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'self'; "
        "form-action 'self'"
    )
    response.headers["Content-Security-Policy"] = csp

    if is_production:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

    return response


# =========================
# Login-Throttling: Benutzername
# =========================

def get_login_attempt(conn, username):
    return conn.execute(
        "SELECT * FROM login_attempts WHERE username = ?",
        (username,)
    ).fetchone()


def clear_login_attempts(conn, username):
    conn.execute(
        "DELETE FROM login_attempts WHERE username = ?",
        (username,)
    )
    conn.commit()


def register_failed_login(conn, username):
    now = datetime.utcnow()
    attempt = get_login_attempt(conn, username)

    if attempt is None:
        fail_count = 1
        locked_until = None

        if fail_count >= MAX_LOGIN_FAILURES:
            locked_until = (now + timedelta(minutes=USERNAME_LOCKOUT_MINUTES)).isoformat()

        conn.execute("""
            INSERT INTO login_attempts (username, fail_count, locked_until, last_failed_at)
            VALUES (?, ?, ?, ?)
        """, (username, fail_count, locked_until, now.isoformat()))
        conn.commit()
        return fail_count, locked_until

    fail_count = attempt["fail_count"] + 1
    locked_until = attempt["locked_until"]

    if fail_count >= MAX_LOGIN_FAILURES:
        locked_until = (now + timedelta(minutes=USERNAME_LOCKOUT_MINUTES)).isoformat()

    conn.execute("""
        UPDATE login_attempts
        SET fail_count = ?, locked_until = ?, last_failed_at = ?
        WHERE username = ?
    """, (fail_count, locked_until, now.isoformat(), username))
    conn.commit()

    return fail_count, locked_until


def is_login_locked(conn, username):
    attempt = get_login_attempt(conn, username)

    if attempt is None or not attempt["locked_until"]:
        return False, None

    locked_until = datetime.fromisoformat(attempt["locked_until"])
    now = datetime.utcnow()

    if now >= locked_until:
        clear_login_attempts(conn, username)
        return False, None

    return True, locked_until


# =========================
# Login-Throttling: IP
# =========================

def get_ip_attempt(conn, ip_address):
    return conn.execute(
        "SELECT * FROM ip_login_attempts WHERE ip_address = ?",
        (ip_address,)
    ).fetchone()


def clear_ip_attempts(conn, ip_address):
    conn.execute(
        "DELETE FROM ip_login_attempts WHERE ip_address = ?",
        (ip_address,)
    )
    conn.commit()


def register_failed_ip_login(conn, ip_address):
    now = datetime.utcnow()
    attempt = get_ip_attempt(conn, ip_address)

    if attempt is None:
        fail_count = 1
        locked_until = None

        if fail_count >= MAX_IP_FAILURES:
            locked_until = (now + timedelta(minutes=IP_LOCKOUT_MINUTES)).isoformat()

        conn.execute("""
            INSERT INTO ip_login_attempts (ip_address, fail_count, locked_until, last_failed_at)
            VALUES (?, ?, ?, ?)
        """, (ip_address, fail_count, locked_until, now.isoformat()))
        conn.commit()
        return fail_count, locked_until

    fail_count = attempt["fail_count"] + 1
    locked_until = attempt["locked_until"]

    if fail_count >= MAX_IP_FAILURES:
        locked_until = (now + timedelta(minutes=IP_LOCKOUT_MINUTES)).isoformat()

    conn.execute("""
        UPDATE ip_login_attempts
        SET fail_count = ?, locked_until = ?, last_failed_at = ?
        WHERE ip_address = ?
    """, (fail_count, locked_until, now.isoformat(), ip_address))
    conn.commit()

    return fail_count, locked_until


def is_ip_locked(conn, ip_address):
    attempt = get_ip_attempt(conn, ip_address)

    if attempt is None or not attempt["locked_until"]:
        return False, None

    locked_until = datetime.fromisoformat(attempt["locked_until"])
    now = datetime.utcnow()

    if now >= locked_until:
        clear_ip_attempts(conn, ip_address)
        return False, None

    return True, locked_until


# =========================
# Globales Template-Context
# =========================

@app.context_processor
def inject_globals():
    context = {
        "logged_in": "user_id" in session,
        "current_username": session.get("username"),
        "csrf_token": get_csrf_token(),
        "notification_payload": {
            "today_count": 0,
            "overdue_count": 0,
            "today_titles": [],
            "overdue_titles": [],
            "today_date": date.today().isoformat()
        }
    }

    if "user_id" not in session:
        return context

    user_id = session["user_id"]
    today = date.today().isoformat()
    conn = get_db_connection()

    due_today_tasks = conn.execute("""
        SELECT title
        FROM tasks
        WHERE user_id = ? AND due_date = ? AND status != ?
        ORDER BY id DESC
    """, (user_id, today, "fertig")).fetchall()

    overdue_tasks = conn.execute("""
        SELECT title
        FROM tasks
        WHERE user_id = ? AND due_date < ? AND status != ?
        ORDER BY due_date ASC, id DESC
    """, (user_id, today, "fertig")).fetchall()

    conn.close()

    context["notification_payload"] = {
        "today_count": len(due_today_tasks),
        "overdue_count": len(overdue_tasks),
        "today_titles": [row["title"] for row in due_today_tasks[:5]],
        "overdue_titles": [row["title"] for row in overdue_tasks[:5]],
        "today_date": today
    }

    return context


# =========================
# Auth
# =========================

@app.route("/register", methods=["GET", "POST"])
def register():
    if "user_id" in session:
        return redirect(url_for("home"))

    conn = get_db_connection()

    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"].strip()

        if not username:
            flash("Benutzername darf nicht leer sein.", "error")
            conn.close()
            return redirect(url_for("register"))

        if not password:
            flash("Passwort darf nicht leer sein.", "error")
            conn.close()
            return redirect(url_for("register"))

        existing_user = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        if existing_user is not None:
            flash("Dieser Benutzername existiert bereits.", "error")
            conn.close()
            return redirect(url_for("register"))

        password_hash = generate_password_hash(password)

        conn.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, password_hash)
        )
        conn.commit()
        conn.close()

        flash("Registrierung erfolgreich. Du kannst dich jetzt einloggen.", "success")
        return redirect(url_for("login"))

    conn.close()
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("home"))

    conn = get_db_connection()

    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"].strip()
        client_ip = get_client_ip()

        if not username or not password:
            flash("Benutzername und Passwort sind erforderlich.", "error")
            conn.close()
            return redirect(url_for("login"))

        ip_locked, ip_locked_until = is_ip_locked(conn, client_ip)
        if ip_locked:
            remaining = ip_locked_until - datetime.utcnow()
            minutes_left = max(1, int(remaining.total_seconds() // 60) + 1)
            conn.close()
            flash(f"Zu viele Login-Versuche von deiner IP. Bitte warte ca. {minutes_left} Minute(n).", "error")
            return redirect(url_for("login"))

        locked, locked_until = is_login_locked(conn, username)
        if locked:
            remaining = locked_until - datetime.utcnow()
            minutes_left = max(1, int(remaining.total_seconds() // 60) + 1)
            conn.close()
            flash(f"Zu viele Fehlversuche für diesen Benutzer. Bitte warte ca. {minutes_left} Minute(n).", "error")
            return redirect(url_for("login"))

        user = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        if user is None:
            user_fail_count, user_locked_until = register_failed_login(conn, username)
            ip_fail_count, ip_locked_until = register_failed_ip_login(conn, client_ip)
            conn.close()

            if ip_locked_until:
                flash("Zu viele Versuche von deiner IP. Login wurde vorübergehend gesperrt.", "error")
            elif user_locked_until:
                flash("Zu viele Fehlversuche. Der Benutzerlogin wurde vorübergehend gesperrt.", "error")
            else:
                user_remaining = max(0, MAX_LOGIN_FAILURES - user_fail_count)
                ip_remaining = max(0, MAX_IP_FAILURES - ip_fail_count)
                flash(
                    f"Benutzer nicht gefunden. Verbleibende Versuche Benutzer: {user_remaining}, IP: {ip_remaining}",
                    "error"
                )
            return redirect(url_for("login"))

        if not check_password_hash(user["password_hash"], password):
            user_fail_count, user_locked_until = register_failed_login(conn, username)
            ip_fail_count, ip_locked_until = register_failed_ip_login(conn, client_ip)
            conn.close()

            if ip_locked_until:
                flash("Zu viele Versuche von deiner IP. Login wurde für 15 Minuten gesperrt.", "error")
            elif user_locked_until:
                flash("Zu viele Fehlversuche. Dieser Benutzer wurde für 15 Minuten gesperrt.", "error")
            else:
                user_remaining = max(0, MAX_LOGIN_FAILURES - user_fail_count)
                ip_remaining = max(0, MAX_IP_FAILURES - ip_fail_count)
                flash(
                    f"Falsches Passwort. Verbleibende Versuche Benutzer: {user_remaining}, IP: {ip_remaining}",
                    "error"
                )
            return redirect(url_for("login"))

        clear_login_attempts(conn, username)
        clear_ip_attempts(conn, client_ip)

        session.clear()
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["csrf_token"] = secrets.token_urlsafe(32)
        session.permanent = True

        conn.close()

        flash("Login erfolgreich.", "success")
        return redirect(url_for("home"))

    conn.close()
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Du wurdest ausgeloggt.", "success")
    return redirect(url_for("login"))


# =========================
# Dashboard
# =========================

@app.route("/")
@login_required
def home():
    conn = get_db_connection()
    user_id = session["user_id"]

    subjects = conn.execute(
        "SELECT * FROM subjects WHERE user_id = ? ORDER BY name ASC",
        (user_id,)
    ).fetchall()

    tasks = conn.execute("""
        SELECT tasks.*, subjects.name AS subject_name
        FROM tasks
        LEFT JOIN subjects ON tasks.subject_id = subjects.id
        WHERE tasks.user_id = ?
        ORDER BY tasks.due_date ASC, tasks.id DESC
    """, (user_id,)).fetchall()

    open_count = conn.execute(
        "SELECT COUNT(*) FROM tasks WHERE status = ? AND user_id = ?",
        ("offen", user_id)
    ).fetchone()[0]

    in_progress_count = conn.execute(
        "SELECT COUNT(*) FROM tasks WHERE status = ? AND user_id = ?",
        ("in Bearbeitung", user_id)
    ).fetchone()[0]

    done_count = conn.execute(
        "SELECT COUNT(*) FROM tasks WHERE status = ? AND user_id = ?",
        ("fertig", user_id)
    ).fetchone()[0]

    today = date.today().isoformat()

    today_count = conn.execute(
        "SELECT COUNT(*) FROM tasks WHERE due_date = ? AND user_id = ?",
        (today, user_id)
    ).fetchone()[0]

    overdue_count = conn.execute(
        "SELECT COUNT(*) FROM tasks WHERE due_date < ? AND status != ? AND user_id = ?",
        (today, "fertig", user_id)
    ).fetchone()[0]

    due_today_tasks = conn.execute("""
        SELECT tasks.*, subjects.name AS subject_name
        FROM tasks
        LEFT JOIN subjects ON tasks.subject_id = subjects.id
        WHERE tasks.due_date = ? AND tasks.user_id = ?
        ORDER BY tasks.priority DESC, tasks.id DESC
    """, (today, user_id)).fetchall()

    overdue_tasks = conn.execute("""
        SELECT tasks.*, subjects.name AS subject_name
        FROM tasks
        LEFT JOIN subjects ON tasks.subject_id = subjects.id
        WHERE tasks.due_date < ? AND tasks.status != ? AND tasks.user_id = ?
        ORDER BY tasks.due_date ASC, tasks.id DESC
    """, (today, "fertig", user_id)).fetchall()

    conn.close()

    return render_template(
        "index.html",
        subjects=subjects,
        tasks=tasks,
        open_count=open_count,
        in_progress_count=in_progress_count,
        done_count=done_count,
        today_count=today_count,
        overdue_count=overdue_count,
        due_today_tasks=due_today_tasks,
        overdue_tasks=overdue_tasks,
        today=today
    )


# =========================
# Kalender
# =========================

@app.route("/calendar")
@login_required
def calendar():
    conn = get_db_connection()
    user_id = session["user_id"]

    tasks = conn.execute("""
        SELECT tasks.*, subjects.name AS subject_name
        FROM tasks
        LEFT JOIN subjects ON tasks.subject_id = subjects.id
        WHERE tasks.user_id = ? AND tasks.due_date IS NOT NULL AND tasks.due_date != ''
        ORDER BY tasks.due_date ASC
    """, (user_id,)).fetchall()

    subjects = conn.execute(
        "SELECT * FROM subjects WHERE user_id = ? ORDER BY name ASC",
        (user_id,)
    ).fetchall()

    conn.close()

    calendar_events = []

    for task in tasks:
        if task["priority"] == "hoch":
            event_color = "#d93025"
        elif task["priority"] == "mittel":
            event_color = "#f39c12"
        else:
            event_color = "#2e7d32"

        subject_name = task["subject_name"] if task["subject_name"] else "Kein Fach"
        description = task["description"] if task["description"] else "Keine Beschreibung"

        calendar_events.append({
            "id": str(task["id"]),
            "title": f'{task["title"]} ({subject_name})',
            "start": task["due_date"],
            "color": event_color,
            "extendedProps": {
                "status": task["status"],
                "priority": task["priority"],
                "description": description,
                "subject_name": subject_name
            }
        })

    return render_template("calendar.html", events=calendar_events, subjects=subjects)


@app.route("/update_task_date", methods=["POST"])
@login_required
def update_task_date():
    data = request.get_json()

    if not data:
        return jsonify({"success": False, "message": "Keine Daten erhalten."}), 400

    task_id = data.get("task_id")
    new_date = data.get("new_date")
    user_id = session["user_id"]

    if not task_id or not new_date:
        return jsonify({"success": False, "message": "Fehlende Daten."}), 400

    conn = get_db_connection()

    task = conn.execute(
        "SELECT * FROM tasks WHERE id = ? AND user_id = ?",
        (task_id, user_id)
    ).fetchone()

    if task is None:
        conn.close()
        return jsonify({"success": False, "message": "Aufgabe nicht gefunden."}), 404

    conn.execute(
        "UPDATE tasks SET due_date = ? WHERE id = ? AND user_id = ?",
        (new_date, task_id, user_id)
    )
    conn.commit()
    conn.close()

    return jsonify({"success": True, "message": "Datum aktualisiert."})


@app.route("/create_task_from_calendar", methods=["POST"])
@login_required
def create_task_from_calendar():
    data = request.get_json()

    if not data:
        return jsonify({"success": False, "message": "Keine Daten erhalten."}), 400

    title = str(data.get("title", "")).strip()
    description = str(data.get("description", "")).strip()
    due_date = str(data.get("due_date", "")).strip()
    priority = str(data.get("priority", "mittel")).strip()
    status = str(data.get("status", "offen")).strip()
    subject_id = str(data.get("subject_id", "")).strip()
    user_id = session["user_id"]

    if not title:
        return jsonify({"success": False, "message": "Titel fehlt."}), 400

    if not due_date:
        return jsonify({"success": False, "message": "Datum fehlt."}), 400

    if not subject_id:
        return jsonify({"success": False, "message": "Bitte wähle ein Fach aus."}), 400

    conn = get_db_connection()

    valid_subject = conn.execute(
        "SELECT * FROM subjects WHERE id = ? AND user_id = ?",
        (subject_id, user_id)
    ).fetchone()

    if valid_subject is None:
        conn.close()
        return jsonify({"success": False, "message": "Ungültiges Fach."}), 400

    conn.execute("""
        INSERT INTO tasks (title, description, due_date, priority, status, subject_id, user_id)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (title, description, due_date, priority, status, subject_id, user_id))
    conn.commit()
    conn.close()

    return jsonify({"success": True, "message": "Aufgabe erstellt."})


# =========================
# Fächer
# =========================

@app.route("/subjects", methods=["GET", "POST"])
@login_required
def subjects():
    conn = get_db_connection()
    user_id = session["user_id"]

    if request.method == "POST":
        name = request.form["name"].strip()
        color = request.form["color"].strip()

        if not name:
            flash("Fachname darf nicht leer sein.", "error")
            conn.close()
            return redirect(url_for("subjects"))

        conn.execute(
            "INSERT INTO subjects (name, color, user_id) VALUES (?, ?, ?)",
            (name, color, user_id)
        )
        conn.commit()
        conn.close()

        flash("Fach erfolgreich erstellt.", "success")
        return redirect(url_for("subjects"))

    all_subjects = conn.execute(
        "SELECT * FROM subjects WHERE user_id = ? ORDER BY name ASC",
        (user_id,)
    ).fetchall()

    conn.close()
    return render_template("subjects.html", subjects=all_subjects)


# =========================
# Aufgaben
# =========================

@app.route("/tasks", methods=["GET", "POST"])
@login_required
def tasks():
    conn = get_db_connection()
    user_id = session["user_id"]

    if request.method == "POST":
        title = request.form["title"].strip()
        description = request.form["description"].strip()
        due_date = request.form["due_date"].strip()
        priority = request.form["priority"].strip()
        status = request.form["status"].strip()
        subject_id = request.form["subject_id"].strip()

        if not title:
            flash("Der Titel darf nicht leer sein.", "error")
            conn.close()
            return redirect(url_for("tasks"))

        if not subject_id:
            flash("Bitte wähle ein Fach aus.", "error")
            conn.close()
            return redirect(url_for("tasks"))

        valid_subject = conn.execute(
            "SELECT * FROM subjects WHERE id = ? AND user_id = ?",
            (subject_id, user_id)
        ).fetchone()

        if valid_subject is None:
            flash("Ungültiges Fach.", "error")
            conn.close()
            return redirect(url_for("tasks"))

        conn.execute("""
            INSERT INTO tasks (title, description, due_date, priority, status, subject_id, user_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (title, description, due_date, priority, status, subject_id, user_id))
        conn.commit()
        conn.close()

        flash("Aufgabe erfolgreich gespeichert.", "success")
        return redirect(url_for("tasks"))

    selected_subject_id = request.args.get("subject_id", "").strip()
    selected_status = request.args.get("status", "").strip()
    selected_priority = request.args.get("priority", "").strip()
    selected_sort = request.args.get("sort", "due_date_asc").strip()

    all_subjects = conn.execute(
        "SELECT * FROM subjects WHERE user_id = ? ORDER BY name ASC",
        (user_id,)
    ).fetchall()

    query = """
        SELECT tasks.*, subjects.name AS subject_name
        FROM tasks
        LEFT JOIN subjects ON tasks.subject_id = subjects.id
        WHERE tasks.user_id = ?
    """
    params = [user_id]

    if selected_subject_id:
        query += " AND tasks.subject_id = ?"
        params.append(selected_subject_id)

    if selected_status:
        query += " AND tasks.status = ?"
        params.append(selected_status)

    if selected_priority:
        query += " AND tasks.priority = ?"
        params.append(selected_priority)

    if selected_sort == "due_date_desc":
        query += " ORDER BY tasks.due_date DESC, tasks.id DESC"
    elif selected_sort == "title_asc":
        query += " ORDER BY tasks.title ASC"
    else:
        query += " ORDER BY tasks.due_date ASC, tasks.id DESC"

    all_tasks = conn.execute(query, params).fetchall()

    conn.close()

    return render_template(
        "tasks.html",
        tasks=all_tasks,
        subjects=all_subjects,
        selected_subject_id=selected_subject_id,
        selected_status=selected_status,
        selected_priority=selected_priority,
        selected_sort=selected_sort
    )


@app.route("/delete_task/<int:task_id>", methods=["POST"])
@login_required
def delete_task(task_id):
    conn = get_db_connection()
    user_id = session["user_id"]

    conn.execute(
        "DELETE FROM tasks WHERE id = ? AND user_id = ?",
        (task_id, user_id)
    )
    conn.commit()
    conn.close()

    flash("Aufgabe gelöscht.", "success")
    return redirect(url_for("tasks"))


@app.route("/edit_task/<int:task_id>", methods=["GET", "POST"])
@login_required
def edit_task(task_id):
    conn = get_db_connection()
    user_id = session["user_id"]

    if request.method == "POST":
        title = request.form["title"].strip()
        description = request.form["description"].strip()
        due_date = request.form["due_date"].strip()
        priority = request.form["priority"].strip()
        status = request.form["status"].strip()
        subject_id = request.form["subject_id"].strip()

        if not title:
            flash("Der Titel darf nicht leer sein.", "error")
            conn.close()
            return redirect(url_for("edit_task", task_id=task_id))

        if not subject_id:
            flash("Bitte wähle ein Fach aus.", "error")
            conn.close()
            return redirect(url_for("edit_task", task_id=task_id))

        valid_subject = conn.execute(
            "SELECT * FROM subjects WHERE id = ? AND user_id = ?",
            (subject_id, user_id)
        ).fetchone()

        if valid_subject is None:
            flash("Ungültiges Fach.", "error")
            conn.close()
            return redirect(url_for("edit_task", task_id=task_id))

        conn.execute("""
            UPDATE tasks
            SET title = ?, description = ?, due_date = ?, priority = ?, status = ?, subject_id = ?
            WHERE id = ? AND user_id = ?
        """, (title, description, due_date, priority, status, subject_id, task_id, user_id))

        conn.commit()
        conn.close()

        flash("Aufgabe aktualisiert.", "success")
        return redirect(url_for("tasks"))

    task = conn.execute(
        "SELECT * FROM tasks WHERE id = ? AND user_id = ?",
        (task_id, user_id)
    ).fetchone()

    if task is None:
        conn.close()
        flash("Aufgabe nicht gefunden.", "error")
        return redirect(url_for("tasks"))

    subjects = conn.execute(
        "SELECT * FROM subjects WHERE user_id = ? ORDER BY name ASC",
        (user_id,)
    ).fetchall()

    conn.close()

    return render_template("edit_task.html", task=task, subjects=subjects)


if __name__ == "__main__":
    app.run(debug=not is_production)