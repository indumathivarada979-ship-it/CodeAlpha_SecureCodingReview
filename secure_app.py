"""Same app after remediation (secure version)."""
import os
import secrets
import sqlite3
import subprocess
import ipaddress
import json
from pathlib import Path

import yaml
from flask import Flask, abort, request, render_template_string, send_from_directory
from markupsafe import escape
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
# Secrets come from the environment, never from source code
app.secret_key = os.environ.get("APP_SECRET_KEY") or secrets.token_hex(32)
DB = os.environ.get("APP_DB", "users.db")
UPLOAD_DIR = Path("uploads").resolve()


def get_db():
    return sqlite3.connect(DB)


def init_db():
    with get_db() as db:
        db.execute(
            "CREATE TABLE IF NOT EXISTS users("
            "id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)"
        )


@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    if not (3 <= len(username) <= 32) or len(password) < 10:
        abort(400, "Invalid username or password too short (min 10 chars)")
    hashed = generate_password_hash(password)          # salted scrypt/pbkdf2
    with get_db() as db:
        db.execute("INSERT INTO users(username, password) VALUES(?, ?)", (username, hashed))
    return "Registered"


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    with get_db() as db:
        row = db.execute("SELECT password FROM users WHERE username = ?", (username,)).fetchone()
    if row and check_password_hash(row[0], password):
        return render_template_string("Welcome {{ u }}", u=username)   # auto-escaped
    return "Invalid login", 401                                         # generic message


@app.route("/hello")
def hello():
    name = request.args.get("name", "")
    return render_template_string("<h1>Hello {{ name }}</h1>", name=name)  # data, not template


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    try:
        ipaddress.ip_address(host)                       # allow-list: valid IP only
    except ValueError:
        abort(400, "Invalid IP address")
    out = subprocess.run(["ping", "-c", "1", host], capture_output=True, text=True, timeout=5)
    return escape(out.stdout)                            # no shell, args as list


@app.route("/download")
def download():
    filename = request.args.get("file", "")
    target = (UPLOAD_DIR / filename).resolve()
    if UPLOAD_DIR not in target.parents or not target.is_file():
        abort(404)                                       # blocks ../ traversal
    return send_from_directory(UPLOAD_DIR, target.name)


@app.route("/load", methods=["POST"])
def load():
    data = json.loads(request.data)                      # JSON instead of pickle
    return str(data)


@app.route("/config", methods=["POST"])
def config():
    cfg = yaml.safe_load(request.data)                   # safe_load only
    return str(cfg)


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=False)