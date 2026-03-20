from flask import Flask, request, redirect, render_template, send_file, session, url_for, make_response, jsonify
import csv, uuid, json, random
from datetime import datetime, timezone
import os, io, time
from functools import wraps
from contextlib import contextmanager
from werkzeug.utils import secure_filename
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import psycopg2
import psycopg2.extras

app = Flask(__name__)
app.secret_key = 'Cybefix@123'  # Change in production

# ── SMTP config ───────────────────────────────────────────────────────────────
SMTP_SERVER = 'smtp.hostinger.com'
SMTP_PORT   = 587
SMTP_USER   = 'rl'
SMTP_PASS   = 'R'

# ── Tracking config ───────────────────────────────────────────────────────────
TRACKING_BASE_URL = 'https://track.example.org'          # base URL of this server
REDIRECT_URL      = 'https://intranet.example.com/thank-you'  # landing page after click

# ── Database config ───────────────────────────────────────────────────────────
DATABASE_URL = os.environ.get(
    'DATABASE_URL',
    'postgresql://localhost/rabbithole'
)

# Legacy CSV paths — only used during one-time migration
_USER_FILE     = "users.csv"
_CLICK_FILE    = "clicks.csv"
_OPEN_FILE     = "opens.csv"
_EMAIL_LOG     = "emails_sent.csv"
_TEMPLATES_FILE = "email_templates.json"


# ── DB helpers ────────────────────────────────────────────────────────────────

@contextmanager
def get_db():
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    username   TEXT PRIMARY KEY,
                    first_name TEXT NOT NULL,
                    last_name  TEXT NOT NULL,
                    email      TEXT NOT NULL,
                    grp        TEXT NOT NULL DEFAULT '',
                    token      TEXT NOT NULL UNIQUE,
                    link       TEXT NOT NULL,
                    track_open TEXT NOT NULL DEFAULT 'no'
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS clicks (
                    id        SERIAL PRIMARY KEY,
                    token     TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    ip        TEXT NOT NULL
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS opens (
                    id        SERIAL PRIMARY KEY,
                    token     TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    ip        TEXT NOT NULL
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS email_log (
                    id        SERIAL PRIMARY KEY,
                    username  TEXT NOT NULL,
                    email     TEXT NOT NULL,
                    timestamp TEXT NOT NULL
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS templates (
                    name    TEXT PRIMARY KEY,
                    content TEXT NOT NULL
                )
            """)
    _migrate_csv_to_db()


def _migrate_csv_to_db():
    """One-time migration from legacy CSV files. Renames each file after import."""

    # users.csv
    if os.path.exists(_USER_FILE):
        try:
            with open(_USER_FILE, 'r') as f:
                reader = csv.DictReader(f)
                rows = list(reader)
            with get_db() as conn:
                with conn.cursor() as cur:
                    for row in rows:
                        cur.execute("""
                            INSERT INTO users
                                (username, first_name, last_name, email, grp, token, link, track_open)
                            VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                            ON CONFLICT (username) DO NOTHING
                        """, (
                            row.get('username', '').strip(),
                            row.get('first_name', '').strip(),
                            row.get('last_name', '').strip(),
                            row.get('email', '').strip(),
                            row.get('group', '').strip(),
                            row.get('token', '').strip(),
                            row.get('link', '').strip(),
                            row.get('track_open', 'no').strip(),
                        ))
            os.rename(_USER_FILE, _USER_FILE + '.migrated')
            print(f"✅ Migrated {_USER_FILE}")
        except Exception as e:
            print(f"⚠️  Could not migrate {_USER_FILE}: {e}")

    # clicks.csv
    if os.path.exists(_CLICK_FILE):
        try:
            with open(_CLICK_FILE, 'r') as f:
                reader = csv.reader(f)
                rows = [r for r in reader if len(r) >= 3 and r[0] != 'token']
            with get_db() as conn:
                with conn.cursor() as cur:
                    cur.executemany(
                        "INSERT INTO clicks (token, timestamp, ip) VALUES (%s,%s,%s)",
                        [(r[0], r[1], r[2]) for r in rows]
                    )
            os.rename(_CLICK_FILE, _CLICK_FILE + '.migrated')
            print(f"✅ Migrated {_CLICK_FILE}")
        except Exception as e:
            print(f"⚠️  Could not migrate {_CLICK_FILE}: {e}")

    # opens.csv
    if os.path.exists(_OPEN_FILE):
        try:
            with open(_OPEN_FILE, 'r') as f:
                reader = csv.reader(f)
                rows = [r for r in reader if len(r) >= 3]
            with get_db() as conn:
                with conn.cursor() as cur:
                    cur.executemany(
                        "INSERT INTO opens (token, timestamp, ip) VALUES (%s,%s,%s)",
                        [(r[0], r[1], r[2]) for r in rows]
                    )
            os.rename(_OPEN_FILE, _OPEN_FILE + '.migrated')
            print(f"✅ Migrated {_OPEN_FILE}")
        except Exception as e:
            print(f"⚠️  Could not migrate {_OPEN_FILE}: {e}")

    # emails_sent.csv
    if os.path.exists(_EMAIL_LOG):
        try:
            with open(_EMAIL_LOG, 'r') as f:
                reader = csv.DictReader(f)
                rows = list(reader)
            with get_db() as conn:
                with conn.cursor() as cur:
                    for row in rows:
                        cur.execute(
                            "INSERT INTO email_log (username, email, timestamp) VALUES (%s,%s,%s)",
                            (row.get('username', ''), row.get('email', ''), row.get('timestamp', ''))
                        )
            os.rename(_EMAIL_LOG, _EMAIL_LOG + '.migrated')
            print(f"✅ Migrated {_EMAIL_LOG}")
        except Exception as e:
            print(f"⚠️  Could not migrate {_EMAIL_LOG}: {e}")

    # email_templates.json
    if os.path.exists(_TEMPLATES_FILE):
        try:
            with open(_TEMPLATES_FILE, 'r') as f:
                data = json.load(f)
            with get_db() as conn:
                with conn.cursor() as cur:
                    for name, content in data.items():
                        cur.execute("""
                            INSERT INTO templates (name, content) VALUES (%s,%s)
                            ON CONFLICT (name) DO NOTHING
                        """, (name, content))
            os.rename(_TEMPLATES_FILE, _TEMPLATES_FILE + '.migrated')
            print(f"✅ Migrated {_TEMPLATES_FILE}")
        except Exception as e:
            print(f"⚠️  Could not migrate {_TEMPLATES_FILE}: {e}")


# ── Auth decorator ────────────────────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


# ── Utility functions ─────────────────────────────────────────────────────────

def load_users():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT username, first_name, last_name, email,
                       grp AS "group", token, link, track_open
                FROM users
            """)
            return [dict(r) for r in cur.fetchall()]


def save_user(user):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO users (username, first_name, last_name, email, grp, token, link, track_open)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (username) DO NOTHING
            """, (
                user['username'], user['first_name'], user['last_name'],
                user['email'], user['group'], user['token'],
                user['link'], user.get('track_open', 'no')
            ))


def get_user_by_username(username):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT username, first_name, last_name, email,
                       grp AS "group", token, link, track_open
                FROM users WHERE username = %s
            """, (username,))
            row = cur.fetchone()
            return dict(row) if row else None


def generate_link(user):
    existing = get_user_by_username(user['username'])
    if existing:
        return existing['token'], existing['link']
    token = str(uuid.uuid4())
    link = f"{TRACKING_BASE_URL}/hit?uid={token}"
    save_user({**user, 'token': token, 'link': link})
    return token, link


def load_templates():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT name, content FROM templates")
            return {r['name']: r['content'] for r in cur.fetchall()}


def log_email_sent(username, email, timestamp):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO email_log (username, email, timestamp) VALUES (%s,%s,%s)",
                (username, email, timestamp)
            )


# ── Auth routes ───────────────────────────────────────────────────────────────

def _new_captcha():
    a, b = random.randint(1, 9), random.randint(1, 9)
    session['captcha_answer'] = a + b
    return f"{a} + {b}"


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Validate CAPTCHA first
        try:
            given = int(request.form.get('captcha_answer', ''))
        except ValueError:
            given = None

        if given != session.get('captcha_answer'):
            return render_template('login.html', error="Incorrect security check.",
                                   captcha_question=_new_captcha())

        if request.form.get('username') == 'admin' and request.form.get('password') == 'admin123':
            session['logged_in'] = True
            session.pop('captcha_answer', None)
            return redirect(url_for('dashboard'))

        return render_template('login.html', error="Invalid credentials.",
                               captcha_question=_new_captcha())

    return render_template('login.html', captcha_question=_new_captcha())


@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))


# ── Index ─────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')


# ── Generate ──────────────────────────────────────────────────────────────────

@app.route('/generate', methods=['GET', 'POST'])
@login_required
def generate():
    if request.method == 'POST':
        username   = request.form['username'].strip()
        first      = request.form['first_name'].strip()
        last       = request.form['last_name'].strip()
        email      = request.form['email'].strip()
        group      = request.form['group'].strip()
        track_open = 'yes' if request.form.get('track_open') else 'no'

        user = {
            'username': username, 'first_name': first, 'last_name': last,
            'email': email, 'group': group, 'track_open': track_open
        }

        existing = get_user_by_username(username)
        if existing and existing['first_name'] == first and existing['email'] == email:
            token     = existing['token']
            link      = existing['link']
            pixel_url = f"{TRACKING_BASE_URL}/img/{token}.png" if existing.get('track_open') == 'yes' else None
            return render_template('generate.html', user=existing, token=token, link=link,
                                   pixel_url=pixel_url,
                                   message="✅ User already exists. Showing existing tracking link.")

        token = str(uuid.uuid4())
        link  = f"{TRACKING_BASE_URL}/hit?uid={token}"
        save_user({**user, 'token': token, 'link': link})

        pixel_url = f"{TRACKING_BASE_URL}/img/{token}.png" if track_open == 'yes' else None
        return render_template('generate.html', user=user, token=token, link=link,
                               pixel_url=pixel_url, message="✅ New tracking link generated.")

    return render_template('generate.html')


# ── Users ─────────────────────────────────────────────────────────────────────

@app.route('/users')
@login_required
def users():
    return render_template('users.html', users=load_users())


@app.route('/users.csv')
@login_required
def serve_users_csv():
    all_users = load_users()
    output = io.StringIO()
    writer = csv.DictWriter(output,
        fieldnames=['username', 'first_name', 'last_name', 'email', 'group', 'token', 'link', 'track_open'])
    writer.writeheader()
    writer.writerows(all_users)
    response = make_response(output.getvalue())
    response.headers["Content-Disposition"] = "attachment; filename=users.csv"
    response.headers["Content-type"] = "text/csv"
    return response


# ── Tracking endpoints ────────────────────────────────────────────────────────

@app.route('/hit')
def hit():
    token = request.args.get("uid")
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    if ',' in ip:
        ip = ip.split(',')[0].strip()
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("INSERT INTO clicks (token, timestamp, ip) VALUES (%s,%s,%s)", (token, ts, ip))
    return redirect(REDIRECT_URL)


@app.route('/img/<uid>.png')
def img(uid):
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    if ',' in ip:
        ip = ip.split(',')[0].strip()
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("INSERT INTO opens (token, timestamp, ip) VALUES (%s,%s,%s)", (uid, ts, ip))
    return send_file("static/pixel.png", mimetype='image/png')


# ── Dashboard ─────────────────────────────────────────────────────────────────

@app.route('/dashboard')
@login_required
def dashboard():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT username, first_name, last_name, email,
                       grp AS "group", token, link, track_open
                FROM users
            """)
            all_users = [dict(r) for r in cur.fetchall()]

            cur.execute("SELECT token, timestamp, ip FROM clicks ORDER BY timestamp")
            click_rows = cur.fetchall()

            cur.execute("SELECT COUNT(DISTINCT token) AS cnt FROM opens")
            opens_count = cur.fetchone()['cnt']

            cur.execute("SELECT COUNT(DISTINCT token) AS cnt FROM clicks")
            clicks_count = cur.fetchone()['cnt']

            cur.execute("SELECT COUNT(DISTINCT LOWER(email)) AS cnt FROM email_log")
            sent_count = cur.fetchone()['cnt']

    user_map = {u['token']: u for u in all_users}
    enriched_clicks = []
    for r in click_rows:
        u = user_map.get(r['token'], {})
        enriched_clicks.append([
            u.get('first_name', ''), u.get('last_name', ''),
            u.get('email', ''), r['token'], r['timestamp'], r['ip']
        ])

    stats = {
        'total_users':   len(all_users),
        'emails_sent':   sent_count,
        'emails_opened': opens_count,
        'links_clicked': clicks_count,
    }
    email_pending = len(all_users) - sent_count

    return render_template('dashboard.html', clicks=enriched_clicks, stats=stats,
                           email_sent=sent_count, email_pending=email_pending)


# ── API endpoints ─────────────────────────────────────────────────────────────

@app.route('/api/clicks')
@login_required
def api_clicks():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT c.token, c.timestamp, c.ip,
                       u.first_name, u.last_name, u.email, u.grp AS "group"
                FROM (
                    SELECT DISTINCT ON (token) token, timestamp, ip
                    FROM clicks
                    ORDER BY token, timestamp DESC
                ) c
                LEFT JOIN users u ON u.token = c.token
            """)
            rows = [dict(r) for r in cur.fetchall()]
    return jsonify({'clicks': rows})


@app.route('/api/repeats')
@login_required
def api_repeats():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT c.token,
                       COUNT(*) AS clicks,
                       MIN(c.timestamp) AS first_click,
                       MAX(c.timestamp) AS last_click,
                       STRING_AGG(DISTINCT c.ip, ', ') AS ip_list,
                       u.first_name, u.last_name, u.email, u.grp AS "group"
                FROM clicks c
                LEFT JOIN users u ON u.token = c.token
                GROUP BY c.token, u.first_name, u.last_name, u.email, u.grp
                HAVING COUNT(*) > 1
            """)
            rows = [dict(r) for r in cur.fetchall()]
    return jsonify({'repeats': rows})


# ── Report ────────────────────────────────────────────────────────────────────

@app.route('/report')
@login_required
def report():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT username, first_name, last_name, email,
                       grp AS "group", token
                FROM users
            """)
            all_users = [dict(r) for r in cur.fetchall()]

            cur.execute("SELECT DISTINCT LOWER(email) AS email FROM email_log")
            sent_emails = {r['email'] for r in cur.fetchall()}

            cur.execute("""
                SELECT token,
                       COUNT(*) AS total_clicks,
                       STRING_AGG(DISTINCT ip, ', ') AS ips
                FROM clicks
                GROUP BY token
            """)
            click_agg = {r['token']: dict(r) for r in cur.fetchall()}

    enriched = []
    for u in all_users:
        token = u.get('token', '')
        agg   = click_agg.get(token, {})
        enriched.append({
            'username':     u.get('username', ''),
            'first_name':   u.get('first_name', ''),
            'last_name':    u.get('last_name', ''),
            'email':        u.get('email', ''),
            'token':        token,
            'email_sent':   '✅' if u.get('email', '').lower() in sent_emails else '❌',
            'link_clicked': '✅' if token in click_agg else '❌',
            'total_clicks': agg.get('total_clicks', 0),
            'ips':          agg.get('ips', ''),
        })

    return render_template("report.html", users=enriched)


# ── Import ────────────────────────────────────────────────────────────────────

@app.route('/import', methods=['GET', 'POST'])
@login_required
def import_users():
    message = ""
    if request.method == 'POST':
        file           = request.files.get('file')
        group_override = request.form.get('group_override', '').strip()

        if file and file.filename.endswith('.csv'):
            filepath = os.path.join('uploads', secure_filename(file.filename))
            os.makedirs('uploads', exist_ok=True)
            file.save(filepath)

            count = 0
            with open(filepath, 'r') as f:
                for row in csv.DictReader(f):
                    user = {
                        'username':   row['username'].strip(),
                        'first_name': row['first_name'].strip(),
                        'last_name':  row['last_name'].strip(),
                        'email':      row['email'].strip(),
                        'group':      group_override or row.get('group', '').strip(),
                        'track_open': 'no',
                    }
                    generate_link(user)
                    count += 1

            message = f"✅ {count} users imported successfully."
        else:
            message = "Please upload a valid CSV file."

    return render_template('import.html', message=message)


# ── Reset analytics ───────────────────────────────────────────────────────────

@app.route('/reset-analytics', methods=['POST'])
@login_required
def reset_analytics():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM clicks")
            cur.execute("DELETE FROM opens")
            cur.execute("DELETE FROM email_log")
    return jsonify({'status': 'success', 'message': 'Analytics reset'})


# ── Email template management ─────────────────────────────────────────────────

@app.route('/save-template', methods=['POST'])
@login_required
def save_template():
    name    = request.form.get('template_name', '').strip()
    content = request.form.get('template_content', '')
    if not name:
        return jsonify({'status': 'error', 'message': 'Template name required'}), 400
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO templates (name, content) VALUES (%s,%s)
                ON CONFLICT (name) DO UPDATE SET content = EXCLUDED.content
            """, (name, content))
    return jsonify({'status': 'success'})


@app.route('/delete-template', methods=['POST'])
@login_required
def delete_template():
    name = request.form.get('template_name', '').strip()
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM templates WHERE name = %s", (name,))
    return jsonify({'status': 'success'})


@app.route('/email-template', methods=['GET', 'POST'])
@login_required
def email_template():
    all_users = load_users()

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT LOWER(email) AS email, COUNT(*) AS cnt
                FROM email_log GROUP BY LOWER(email)
            """)
            email_sent_map = {r['email']: r['cnt'] for r in cur.fetchall()}

    for u in all_users:
        u['sent_count'] = email_sent_map.get(u['email'].strip().lower(), 0)

    groups         = sorted(set(u['group'] for u in all_users if u.get('group')))
    selected_group = request.form.get('group') if request.method == 'POST' else None
    selected_usernames = request.form.getlist('usernames')
    template_text  = request.form.get('template', '')
    generated      = []

    users = [u for u in all_users if u['group'] == selected_group] if selected_group else []

    if request.method == 'POST' and request.form.get('action') == 'generate':
        for u in users:
            if u['username'] in selected_usernames:
                link_url  = f"{TRACKING_BASE_URL}/hit?uid={u['token']}"
                pixel_url = f"{TRACKING_BASE_URL}/img/{u['token']}.png"
                pixel_tag = f'<img src="{pixel_url}" width="1" height="1" style="display:none;" alt="">'
                track_open = u.get('track_open') == 'yes'
                body = template_text \
                    .replace("{{first_name}}", u['first_name']) \
                    .replace("{{last_name}}",  u['last_name']) \
                    .replace("{{email}}",      u['email']) \
                    .replace("{{token}}",      u['token']) \
                    .replace("{{link}}",       f'<a href="{link_url}">Click here</a>') \
                    .replace("{{pixel}}",      pixel_tag if track_open else '')
                if track_open and pixel_url not in body:
                    body += pixel_tag
                generated.append({'email': u['email'], 'body': body})

    saved_templates = load_templates()
    return render_template("email_template.html", groups=groups, users=users,
                           selected_group=selected_group, template_text=template_text,
                           generated=generated, saved_templates=saved_templates)


# ── Send emails ───────────────────────────────────────────────────────────────

@app.route('/send-emails', methods=['POST'])
@login_required
def send_emails():
    selected_usernames = request.form.getlist('usernames')
    template           = request.form.get('template')
    delay              = int(request.form.get('delay', 5))

    if not selected_usernames:
        return render_template("email_sent_summary.html", sent=[], count=0,
                               message="❌ No users selected.")

    all_users     = load_users()
    users_to_send = [u for u in all_users if u['username'] in selected_usernames]
    sent          = []

    for user in users_to_send:
        to_email   = user['email']
        link_url   = user['link']
        track_open = user.get('track_open') == 'yes'
        pixel_url  = f"{TRACKING_BASE_URL}/img/{user['token']}.png"
        pixel_tag  = f'<img src="{pixel_url}" width="1" height="1" style="display:none;" alt="">'

        body = template \
            .replace("{{first_name}}", user['first_name']) \
            .replace("{{last_name}}",  user['last_name']) \
            .replace("{{email}}",      user['email']) \
            .replace("{{token}}",      user['token']) \
            .replace("{{link}}",       f'<a href="{link_url}">CHECK AND VERIFY SALARY SLIP</a>') \
            .replace("{{pixel}}",      pixel_tag if track_open else '')

        if track_open and pixel_url not in body:
            body += pixel_tag

        msg            = MIMEMultipart("alternative")
        msg["Subject"] = "[Update] New Salary Format - Update Details"
        msg["From"]    = SMTP_USER
        msg["To"]      = to_email
        msg.attach(MIMEText(body, "html"))

        try:
            with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
                server.ehlo()
                server.starttls()
                server.ehlo()
                server.login(SMTP_USER, SMTP_PASS)
                server.send_message(msg)

            timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            log_email_sent(user['username'], to_email, timestamp)
            sent.append(to_email)
            print(f"✅ Sent to {to_email}")
            time.sleep(delay)
        except Exception as e:
            print(f"❌ Failed to send to {to_email}: {e}")

    return render_template("email_sent_summary.html", sent=sent, count=len(sent),
                           message="✅ Emails sent.")


# ── Sent status ───────────────────────────────────────────────────────────────

@app.route('/sent-status')
@login_required
def sent_status():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT username, email, timestamp
                FROM email_log ORDER BY timestamp DESC
            """)
            records = [list(r.values()) for r in cur.fetchall()]
    return render_template("sent_status.html", records=records)


# ── Export ────────────────────────────────────────────────────────────────────

@app.route('/export/csv')
@login_required
def export_csv():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT u.first_name, u.last_name, u.email,
                       c.token, c.timestamp, c.ip
                FROM clicks c
                LEFT JOIN users u ON u.token = c.token
                ORDER BY c.timestamp
            """)
            rows = cur.fetchall()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['First Name', 'Last Name', 'Email', 'Token', 'Click Time', 'IP Address'])
    for r in rows:
        writer.writerow([r['first_name'], r['last_name'], r['email'],
                         r['token'], r['timestamp'], r['ip']])

    response = make_response(output.getvalue())
    response.headers["Content-Disposition"] = "attachment; filename=click_report.csv"
    response.headers["Content-type"] = "text/csv"
    return response


# ── Bootstrap ─────────────────────────────────────────────────────────────────

init_db()

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5001)
