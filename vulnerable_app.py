"""Simple Flask notes/login app - INTENTIONALLY VULNERABLE (audit target)."""
import hashlib
import os
import pickle
import sqlite3
import subprocess

import yaml
from flask import Flask, request, render_template_string, send_file

app = Flask(__name__)
app.secret_key = "supersecret123"          # hard-coded secret
DB = "users.db"
ADMIN_PASSWORD = "admin@123"               # hard-coded credential


def get_db():
    return sqlite3.connect(DB)


def init_db():
    db = get_db()
    db.execute("CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
    db.commit()


@app.route("/register", methods=["POST"])
def register():
    username = request.form["username"]
    password = request.form["password"]
    hashed = hashlib.md5(password.encode()).hexdigest()      # weak hash, no salt
    db = get_db()
    db.execute("INSERT INTO users(username, password) VALUES('%s', '%s')" % (username, hashed))
    db.commit()
    return "Registered"


@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = hashlib.md5(request.form["password"].encode()).hexdigest()
    db = get_db()
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"  # SQL injection
    user = db.execute(query).fetchone()
    return "Welcome " + username if user else "Invalid login"


@app.route("/hello")
def hello():
    name = request.args.get("name", "")
    return render_template_string("<h1>Hello " + name + "</h1>")   # SSTI / reflected XSS


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    return subprocess.check_output("ping -c 1 " + host, shell=True)  # command injection


@app.route("/download")
def download():
    filename = request.args.get("file")
    return send_file(os.path.join("uploads", filename))   # path traversal


@app.route("/load", methods=["POST"])
def load():
    data = pickle.loads(request.data)           # insecure deserialization
    return str(data)


@app.route("/config", methods=["POST"])
def config():
    cfg = yaml.load(request.data, Loader=yaml.Loader)   # unsafe YAML load
    return str(cfg)


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)      # debug mode exposed on all interfaces