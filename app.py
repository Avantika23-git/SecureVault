from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    send_file,
    jsonify
)

from flask_sqlalchemy import SQLAlchemy
from cryptography.fernet import Fernet

import os
import json

# Import phishing module
from backend.cybersecurity.phishing_det.email_analyzer import analyze_email

# ---------------------------------------------------
# Flask App Configuration
# ---------------------------------------------------

app = Flask(__name__)

app.config["SECRET_KEY"] = "mysecretkey"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# ---------------------------------------------------
# Project Paths
# ---------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")

REPORT_FOLDER = os.path.join(BASE_DIR, "reports")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORT_FOLDER, exist_ok=True)

# ---------------------------------------------------
# Encryption Key
# ---------------------------------------------------

KEY_PATH = os.path.join(BASE_DIR, "secret.key")

with open(KEY_PATH, "rb") as key_file:
    key = key_file.read()

fernet = Fernet(key)
# ---------------------------------------------------
# Database Models
# ---------------------------------------------------

class User(db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    username = db.Column(
        db.String(100),
        unique=True,
        nullable=False
    )

    password = db.Column(
        db.String(100),
        nullable=False
    )


class ActivityLog(db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    username = db.Column(
        db.String(100),
        nullable=False
    )

    filename = db.Column(
        db.String(200),
        nullable=False
    )

    action = db.Column(
        db.String(50),
        nullable=False
    )

    timestamp = db.Column(
        db.DateTime,
        default=db.func.current_timestamp()
    )


# ---------------------------------------------------
# Create Database
# ---------------------------------------------------

with app.app_context():
    db.create_all()

# ---------------------------------------------------
# Register
# ---------------------------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        existing_user = User.query.filter_by(
            username=username
        ).first()

        if existing_user:
            return "Username already exists!"

        new_user = User(
            username=username,
            password=password
        )

        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for("login"))

    return render_template("register.html")

# ---------------------------------------------------
# Login
# ---------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        user = User.query.filter_by(
            username=username,
            password=password
        ).first()

        if user:

            session["username"] = username

            return redirect(url_for("home"))

        return "Invalid Username or Password"

    return render_template("login.html")

# ---------------------------------------------------
# Logout
# ---------------------------------------------------

@app.route("/logout")
def logout():

    session.pop("username", None)

    return redirect(url_for("login"))

# ---------------------------------------------------
# Dashboard
# ---------------------------------------------------

@app.route("/")
def home():

    if "username" not in session:
        return redirect(url_for("login"))

    user_folder = os.path.join(
        UPLOAD_FOLDER,
        session["username"]
    )

    os.makedirs(user_folder, exist_ok=True)

    total_files = len([
        f for f in os.listdir(user_folder)
        if f.endswith(".encrypted")
    ])

    total_logs = ActivityLog.query.filter_by(
        username=session["username"]
    ).count()

    stats = {

        "total_files": total_files,

        "high_risk": 3,

        "caution": 7,

        "clean": 41,

        "urls_scanned": 58,

        "activity_count": total_logs
    }

    return render_template(
    "dashboard.html",
    username=session["username"],
    stats=stats,
    active_page="dashboard"
)

# ---------------------------------------------------
# Upload File
# ---------------------------------------------------

@app.route("/upload", methods=["POST"])
def upload_file():

    if "username" not in session:
        return redirect(url_for("login"))

    if "file" not in request.files:
        return "No file selected."

    file = request.files["file"]

    if file.filename == "":
        return "Please choose a file."

    user_folder = os.path.join(
        UPLOAD_FOLDER,
        session["username"]
    )

    os.makedirs(user_folder, exist_ok=True)

    file_data = file.read()

    encrypted_data = fernet.encrypt(file_data)

    encrypted_filename = file.filename + ".encrypted"

    filepath = os.path.join(
        user_folder,
        encrypted_filename
    )

    with open(filepath, "wb") as f:
        f.write(encrypted_data)

    log = ActivityLog(
        username=session["username"],
        filename=encrypted_filename,
        action="Upload"
    )

    db.session.add(log)
    db.session.commit()

    return redirect(url_for("files"))

# ---------------------------------------------------
# View Uploaded Files
# ---------------------------------------------------

@app.route("/files")
def files():

    if "username" not in session:
        return redirect(url_for("login"))

    user_folder = os.path.join(
        UPLOAD_FOLDER,
        session["username"]
    )

    os.makedirs(user_folder, exist_ok=True)

    files = [
        f for f in os.listdir(user_folder)
        if f.endswith(".encrypted")
    ]

    return render_template(
        "files.html",
        files=files
    )

# ---------------------------------------------------
# Download File
# ---------------------------------------------------

@app.route("/download/<filename>")
def download_file(filename):

    if "username" not in session:
        return redirect(url_for("login"))

    user_folder = os.path.join(
        UPLOAD_FOLDER,
        session["username"]
    )

    filepath = os.path.join(
        user_folder,
        filename
    )

    if not os.path.exists(filepath):
        return "File not found."

    with open(filepath, "rb") as f:
        encrypted_data = f.read()

    decrypted_data = fernet.decrypt(encrypted_data)

    original_name = filename.replace(
        ".encrypted",
        ""
    )

    temp_path = os.path.join(
        user_folder,
        "temp_" + original_name
    )

    with open(temp_path, "wb") as f:
        f.write(decrypted_data)

    log = ActivityLog(
        username=session["username"],
        filename=filename,
        action="Download"
    )

    db.session.add(log)
    db.session.commit()

    return send_file(
        temp_path,
        as_attachment=True,
        download_name=original_name
    )


# ---------------------------------------------------
# Delete File
# ---------------------------------------------------

@app.route("/delete/<filename>")
def delete_file(filename):

    if "username" not in session:
        return redirect(url_for("login"))

    user_folder = os.path.join(
        UPLOAD_FOLDER,
        session["username"]
    )

    filepath = os.path.join(
        user_folder,
        filename
    )

    if os.path.exists(filepath):
        os.remove(filepath)

    log = ActivityLog(
        username=session["username"],
        filename=filename,
        action="Delete"
    )

    db.session.add(log)
    db.session.commit()

    return redirect(url_for("files"))



# ---------------------------------------------------
# Activity Logs
# ---------------------------------------------------

@app.route("/logs")
def logs():

    if "username" not in session:
        return redirect(url_for("login"))

    logs = ActivityLog.query.filter_by(
        username=session["username"]
    ).all()

    return render_template(
        "logs.html",
        logs=logs
    )

# ---------------------------------------------------
# Threat Detection Dashboard
# ---------------------------------------------------

@app.route("/phishguard")
def phishguard():

    if "username" not in session:
        return redirect(url_for("login"))

    return render_template(
        "phishguard.html"
    )

# ---------------------------------------------------
# URL Scanner
# ---------------------------------------------------

@app.route("/urlscanner")
def urlscanner():

    if "username" not in session:
        return redirect(url_for("login"))

    return render_template(
        "urlscanner.html"
    )

# ---------------------------------------------------
# Reports
# ---------------------------------------------------

@app.route("/reports")
def reports():

    if "username" not in session:
        return redirect(url_for("login"))

    filepath = os.path.join(
        REPORT_FOLDER,
        "report_history.json"
    )

    if os.path.exists(filepath):

        with open(filepath, "r") as f:

            try:
                report_list = json.load(f)

            except json.JSONDecodeError:
                report_list = []

    else:

        report_list = []

    return render_template(
        "reports.html",
        reports=report_list
    )

# ---------------------------------------------------
# Settings
# ---------------------------------------------------

@app.route("/settings")
def settings():

    if "username" not in session:
        return redirect(url_for("login"))

    return render_template(
        "settings.html"
    )

# ---------------------------------------------------
# Audit Log
# ---------------------------------------------------

@app.route("/auditlog")
def auditlog():

    if "username" not in session:
        return redirect(url_for("login"))

    logs = ActivityLog.query.filter_by(
        username=session["username"]
    ).all()

    return render_template(
        "auditlog.html",
        logs=logs
    )

# ---------------------------------------------------
# Analyze Email
# ---------------------------------------------------

@app.route("/analyze", methods=["POST"])
def analyze():

    data = request.get_json()

    if not data:

        return jsonify({
            "error": "No data received"
        })

    email = data.get("email")

    if not email:

        return jsonify({
            "error": "Email text missing"
        })

    report = analyze_email(email)

    return jsonify(report)

@app.route("/vault")
def vault():

    if "username" not in session:
        return redirect(url_for("login"))

    user_folder = os.path.join(
        UPLOAD_FOLDER,
        session["username"]
    )

    os.makedirs(user_folder, exist_ok=True)

    stats = {

        "total_files": len([
            f for f in os.listdir(user_folder)
            if f.endswith(".encrypted")
        ]),

        "activity_count":
        ActivityLog.query.filter_by(
            username=session["username"]
        ).count(),

        "high_risk": 3

    }

    return render_template(
        "index.html",
        username=session["username"],
        stats=stats,
        active_page="vault"
    )




# ---------------------------------------------------
# Run Application
# ---------------------------------------------------

if __name__ == "__main__":
    app.run(debug=True)