from flask import Flask, request, redirect, render_template, url_for
import csv, uuid
from datetime import datetime
import os

app = Flask(__name__)

LINK_FILE = "links.csv"
CLICK_FILE = "clicks.csv"

# Utility to read CSV safely
def read_csv(filename):
    try:
        with open(filename, "r") as f:
            return list(csv.reader(f))
    except FileNotFoundError:
        return []

# Utility to append to CSV
def write_csv(filename, row):
    with open(filename, "a", newline="") as f:
        csv.writer(f).writerow(row)

# Load or create static token for user
def get_or_create_token(user):
    rows = read_csv(LINK_FILE)
    for r in rows:
        if r[0] == user:
            return r[1], r[2]  # return token, link
    token = str(uuid.uuid4())
    link = f"https://track.example.org/hit?uid={token}"
    write_csv(LINK_FILE, [user, token, link])
    return token, link

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/generate', methods=["GET", "POST"])
def generate():
    if request.method == "POST":
        user = request.form.get("user")
        if not user:
            return render_template("generate.html", error="Please enter a user name.")
        token, link = get_or_create_token(user)
        return render_template("generate.html", user=user, token=token, link=link)
    return render_template("generate.html")

@app.route('/hit')
def hit():
    token = request.args.get("uid")
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    if ',' in ip:
        ip = ip.split(',')[0].strip()
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    user = token
    rows = read_csv(LINK_FILE)
    for r in rows:
        if len(r) >= 2 and r[1] == token:
            user = r[0]
            break
    write_csv(CLICK_FILE, [user, ts, ip])
    return redirect("https://intranet.example.com/thank-you")

@app.route('/dashboard')
def dashboard():
    rows = read_csv(CLICK_FILE)
    return render_template("dashboard.html", records=rows)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
