from flask import Flask, request, redirect, render_template, send_file, session, url_for, make_response, jsonify, abort
from werkzeug.security import generate_password_hash, check_password_hash
import csv, uuid, json, random, threading, secrets
from datetime import datetime, timezone
from urllib.parse import quote
from html import escape as html_escape
import os, io, time
from functools import wraps
from contextlib import contextmanager
from werkzeug.utils import secure_filename
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import psycopg2
import psycopg2.extras

import scanner_detect

app = Flask(__name__)
# Secrets/config come from the environment; the fallbacks keep local dev working
# but SHOULD be overridden in any real deployment.
app.secret_key = os.environ.get('RABBITHOLE_SECRET_KEY', 'dev-insecure-change-me')

# ── Admin credentials ───────────────────────────────────────────────────────────
# Bootstrap admin: used ONLY to seed the first account when the accounts table is
# empty. Login authenticates against the hashed `accounts` table, not these values.
# If no password is provided, a strong random one is generated and printed at first run.
ADMIN_USER = os.environ.get('RABBITHOLE_ADMIN_USER', 'admin')
ADMIN_PASS = os.environ.get('RABBITHOLE_ADMIN_PASS')  # None => generate at bootstrap

# ── SMTP config (legacy fallback; real config lives in the smtp_configs table) ──
SMTP_SERVER = os.environ.get('SMTP_SERVER', '')
SMTP_PORT   = int(os.environ.get('SMTP_PORT', '587') or 587)
SMTP_USER   = os.environ.get('SMTP_USER', '')
SMTP_PASS   = os.environ.get('SMTP_PASS', '')

# ── Tracking config ───────────────────────────────────────────────────────────
TRACKING_BASE_URL = os.environ.get('TRACKING_BASE_URL', 'http://127.0.0.1:5001').rstrip('/')
REDIRECT_URL      = os.environ.get('REDIRECT_URL', 'https://example.com/')

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

def _utcnow():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _show_scanner_hits():
    """Opt-in query flag (?show_scanner=1) to include flagged scanner/bot
    hits in telemetry views, instead of filtering them out by default."""
    return request.args.get("show_scanner") in ("1", "true", "yes")


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
            cur.execute("""
                CREATE TABLE IF NOT EXISTS smtp_configs (
                    id              SERIAL PRIMARY KEY,
                    name            TEXT NOT NULL UNIQUE,
                    server          TEXT NOT NULL,
                    port            INTEGER NOT NULL DEFAULT 587,
                    username        TEXT NOT NULL DEFAULT '',
                    password        TEXT NOT NULL DEFAULT '',
                    security        TEXT NOT NULL DEFAULT 'starttls',
                    from_email      TEXT NOT NULL DEFAULT '',
                    from_name       TEXT NOT NULL DEFAULT '',
                    default_subject TEXT NOT NULL DEFAULT '',
                    is_active       BOOLEAN NOT NULL DEFAULT FALSE
                )
            """)
            # Campaign/template attribution — added idempotently so databases
            # migrated before this feature pick up the column too.
            cur.execute("ALTER TABLE clicks    ADD COLUMN IF NOT EXISTS campaign TEXT NOT NULL DEFAULT ''")
            cur.execute("ALTER TABLE opens     ADD COLUMN IF NOT EXISTS campaign TEXT NOT NULL DEFAULT ''")
            cur.execute("ALTER TABLE email_log ADD COLUMN IF NOT EXISTS campaign TEXT NOT NULL DEFAULT ''")
            # Security-scanner detection (Microsoft Safe Links, Zscaler, Proofpoint, ...)
            # — these pre-fetch tracking links/pixels before a human ever sees the email,
            # so they're flagged here and excluded from "real" telemetry by default.
            for _tbl in ("clicks", "opens"):
                cur.execute(f"ALTER TABLE {_tbl} ADD COLUMN IF NOT EXISTS is_scanner BOOLEAN NOT NULL DEFAULT FALSE")
                cur.execute(f"ALTER TABLE {_tbl} ADD COLUMN IF NOT EXISTS scanner_vendor TEXT NOT NULL DEFAULT ''")
                cur.execute(f"ALTER TABLE {_tbl} ADD COLUMN IF NOT EXISTS scanner_reason TEXT NOT NULL DEFAULT ''")
            cur.execute("""
                CREATE TABLE IF NOT EXISTS campaigns (
                    id             SERIAL PRIMARY KEY,
                    name           TEXT NOT NULL,
                    smtp_config_id INTEGER,
                    smtp_name      TEXT NOT NULL DEFAULT '',
                    subject        TEXT NOT NULL DEFAULT '',
                    delay          INTEGER NOT NULL DEFAULT 3,
                    total          INTEGER NOT NULL DEFAULT 0,
                    sent           INTEGER NOT NULL DEFAULT 0,
                    failed         INTEGER NOT NULL DEFAULT 0,
                    status         TEXT NOT NULL DEFAULT 'running',
                    stop_requested BOOLEAN NOT NULL DEFAULT FALSE,
                    last_error     TEXT NOT NULL DEFAULT '',
                    created_at     TEXT NOT NULL DEFAULT '',
                    finished_at    TEXT NOT NULL DEFAULT ''
                )
            """)
            cur.execute("ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS landing_page_id INTEGER")
            cur.execute("ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS landing_name TEXT NOT NULL DEFAULT ''")
            # What was actually sent/targeted — stored at launch time so a campaign's
            # detail page can show it after the fact, even once templates/users change.
            cur.execute("ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS template TEXT NOT NULL DEFAULT ''")
            cur.execute("ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS link_text TEXT NOT NULL DEFAULT ''")
            cur.execute("ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS recipient_filter TEXT NOT NULL DEFAULT ''")
            # Pause is cooperative like stop_requested, but resumable — kept as its
            # own flag so the worker loop can tell which one tripped it.
            cur.execute("ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS pause_requested BOOLEAN NOT NULL DEFAULT FALSE")
            # Per-recipient send state for a campaign — a snapshot taken at launch time
            # so pause/resume/restart-after-crash can pick up exactly where they left
            # off instead of re-deriving (and potentially re-sending to) the group.
            cur.execute("""
                CREATE TABLE IF NOT EXISTS campaign_recipients (
                    id          SERIAL PRIMARY KEY,
                    campaign_id INTEGER NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
                    username    TEXT NOT NULL DEFAULT '',
                    first_name  TEXT NOT NULL DEFAULT '',
                    last_name   TEXT NOT NULL DEFAULT '',
                    email       TEXT NOT NULL DEFAULT '',
                    token       TEXT NOT NULL DEFAULT '',
                    track_open  TEXT NOT NULL DEFAULT 'no',
                    status      TEXT NOT NULL DEFAULT 'pending',
                    sent_at     TEXT NOT NULL DEFAULT '',
                    error       TEXT NOT NULL DEFAULT ''
                )
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_campaign_recipients_cid ON campaign_recipients(campaign_id, status)")
            cur.execute("""
                CREATE TABLE IF NOT EXISTS landing_pages (
                    id         SERIAL PRIMARY KEY,
                    name       TEXT NOT NULL UNIQUE,
                    html       TEXT NOT NULL DEFAULT '',
                    thankyou   TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL DEFAULT ''
                )
            """)
            # Extra capture fields — added idempotently so landing pages created
            # before this feature default to "off" and keep their old name/email-only form.
            cur.execute("ALTER TABLE landing_pages ADD COLUMN IF NOT EXISTS capture_phone   BOOLEAN NOT NULL DEFAULT FALSE")
            cur.execute("ALTER TABLE landing_pages ADD COLUMN IF NOT EXISTS capture_id      BOOLEAN NOT NULL DEFAULT FALSE")
            cur.execute("ALTER TABLE landing_pages ADD COLUMN IF NOT EXISTS id_label        TEXT NOT NULL DEFAULT 'Employee / Student ID'")
            cur.execute("ALTER TABLE landing_pages ADD COLUMN IF NOT EXISTS capture_comment BOOLEAN NOT NULL DEFAULT FALSE")
            cur.execute("ALTER TABLE landing_pages ADD COLUMN IF NOT EXISTS comment_label   TEXT NOT NULL DEFAULT 'Comment'")
            cur.execute("""
                CREATE TABLE IF NOT EXISTS accounts (
                    id            SERIAL PRIMARY KEY,
                    username      TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    role          TEXT NOT NULL DEFAULT 'viewer',
                    active        BOOLEAN NOT NULL DEFAULT TRUE,
                    created_at    TEXT NOT NULL DEFAULT '',
                    last_login    TEXT NOT NULL DEFAULT ''
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS submissions (
                    id         SERIAL PRIMARY KEY,
                    token      TEXT NOT NULL DEFAULT '',
                    campaign   TEXT NOT NULL DEFAULT '',
                    landing_id INTEGER,
                    name       TEXT NOT NULL DEFAULT '',
                    email      TEXT NOT NULL DEFAULT '',
                    ip         TEXT NOT NULL DEFAULT '',
                    timestamp  TEXT NOT NULL DEFAULT ''
                )
            """)
            cur.execute("ALTER TABLE submissions ADD COLUMN IF NOT EXISTS phone    TEXT NOT NULL DEFAULT ''")
            cur.execute("ALTER TABLE submissions ADD COLUMN IF NOT EXISTS id_value TEXT NOT NULL DEFAULT ''")
            cur.execute("ALTER TABLE submissions ADD COLUMN IF NOT EXISTS comment  TEXT NOT NULL DEFAULT ''")
            cur.execute("ALTER TABLE submissions ADD COLUMN IF NOT EXISTS is_scanner BOOLEAN NOT NULL DEFAULT FALSE")
            cur.execute("ALTER TABLE submissions ADD COLUMN IF NOT EXISTS scanner_vendor TEXT NOT NULL DEFAULT ''")
            cur.execute("ALTER TABLE submissions ADD COLUMN IF NOT EXISTS scanner_reason TEXT NOT NULL DEFAULT ''")
            # Any campaigns left 'running' from a previous process are stale —
            # a worker thread does not survive a restart, so mark them interrupted.
            cur.execute("""
                UPDATE campaigns SET status = 'interrupted', finished_at = %s
                 WHERE status IN ('running', 'stopping', 'pausing')
            """, (_utcnow(),))
            # The dashboard joins users to clicks/opens/submissions by token on
            # every load (and now on every poll) — these tables grow unbounded,
            # so without an index that join degrades to a full scan per request.
            cur.execute("CREATE INDEX IF NOT EXISTS idx_clicks_token ON clicks(token)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_opens_token ON opens(token)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_submissions_token ON submissions(token)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_users_grp ON users(grp)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_email_log_email_lower ON email_log(LOWER(email))")
    _seed_smtp_config()
    _seed_admin_account()
    _migrate_csv_to_db()


def _seed_admin_account():
    """Ensure the bootstrap admin exists and has a password the operator knows.

    If RABBITHOLE_ADMIN_PASS is set, the admin is pinned to that fixed password.
    Otherwise a fresh random password is generated on EVERY launch, reset on the
    admin row, and printed — so you always have current credentials. Note this
    invalidates the previous launch's password each time the app starts."""
    generated = ADMIN_PASS is None
    password  = ADMIN_PASS or secrets.token_urlsafe(12)
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO accounts (username, password_hash, role, active, created_at)
                VALUES (%s,%s,'admin',TRUE,%s)
                ON CONFLICT (username)
                DO UPDATE SET password_hash = EXCLUDED.password_hash
            """, (ADMIN_USER, generate_password_hash(password), _utcnow()))
    if generated:
        print("\n" + "=" * 64)
        print("  RabbitHole: admin password for this launch")
        print(f"    username: {ADMIN_USER}")
        print(f"    password: {password}")
        print("  A new random password is generated on every launch.")
        print("  (Set RABBITHOLE_ADMIN_PASS to pin a fixed one instead.)")
        print("=" * 64 + "\n", flush=True)
    else:
        print(f"✅ Admin account '{ADMIN_USER}' set from RABBITHOLE_ADMIN_PASS", flush=True)


def _seed_smtp_config():
    """If no SMTP configs exist yet, seed one from the legacy module constants
    so the app keeps working after upgrade. Harmless if constants are blank."""
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS cnt FROM smtp_configs")
            if cur.fetchone()['cnt'] == 0 and SMTP_SERVER:
                cur.execute("""
                    INSERT INTO smtp_configs
                        (name, server, port, username, password, security,
                         from_email, from_name, default_subject, is_active)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,TRUE)
                    ON CONFLICT (name) DO NOTHING
                """, (
                    'Default', SMTP_SERVER, SMTP_PORT, SMTP_USER, SMTP_PASS,
                    'starttls', SMTP_USER, 'RabbitHole', 'Phishing Awareness',
                ))


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


# ── Auth / roles ──────────────────────────────────────────────────────────────

ROLE_RANK = {'viewer': 1, 'operator': 2, 'admin': 3}


def _is_authenticated():
    # 'role' is set at login; a session with 'logged_in' but no 'role' is a stale
    # pre-upgrade session and must re-authenticate.
    return 'logged_in' in session and 'role' in session


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not _is_authenticated():
            session.clear()
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def role_required(min_role):
    """Gate a route on a minimum role (admin > operator > viewer)."""
    needed = ROLE_RANK[min_role]

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not _is_authenticated():
                session.clear()
                return redirect(url_for('login'))
            if ROLE_RANK.get(session.get('role'), 0) < needed:
                if request.path.startswith('/api/'):
                    return jsonify({'status': 'error', 'message': 'Forbidden'}), 403
                return render_template('403.html'), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator


@app.context_processor
def inject_current_user():
    return {'current_user': {'username': session.get('user', ''),
                             'role': session.get('role', '')}}


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


def build_tracking_url(user_token, campaign, lp_id):
    """Single place that assembles a /hit click URL, so every email-body link
    goes through the same query-string logic (including &lp=<id>)."""
    base = TRACKING_BASE_URL
    params = f"uid={user_token}&c={quote(campaign or '')}"
    if lp_id:
        params += f"&lp={lp_id}"
    return f"{base}/hit?{params}"


def tracking_urls(token, campaign='', landing_id=None):
    """Build click and pixel URLs for a token, tagged with an optional campaign
    label so simultaneous templates can be told apart in the logs. When a landing
    page is set, the click URL carries &lp=<id> so /hit serves that page."""
    link_url  = build_tracking_url(token, campaign, landing_id)
    psuffix   = f"?c={quote(campaign)}" if campaign else ""
    pixel_url = f"{TRACKING_BASE_URL}/img/{token}.png{psuffix}"
    return link_url, pixel_url


def load_templates():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT name, content FROM templates")
            return {r['name']: r['content'] for r in cur.fetchall()}


def log_email_sent(username, email, timestamp, campaign=''):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO email_log (username, email, timestamp, campaign) VALUES (%s,%s,%s,%s)",
                (username, email, timestamp, campaign)
            )


# ── SMTP config helpers ─────────────────────────────────────────────────────────

def load_smtp_configs():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM smtp_configs ORDER BY name")
            return [dict(r) for r in cur.fetchall()]


def get_smtp_config(config_id=None):
    """Return the SMTP config to send with: an explicit id if given and valid,
    otherwise the active one, otherwise None."""
    with get_db() as conn:
        with conn.cursor() as cur:
            if config_id:
                cur.execute("SELECT * FROM smtp_configs WHERE id = %s", (config_id,))
                row = cur.fetchone()
                if row:
                    return dict(row)
            cur.execute("SELECT * FROM smtp_configs WHERE is_active = TRUE LIMIT 1")
            row = cur.fetchone()
            return dict(row) if row else None


def smtp_connection(cfg):
    """Open an SMTP connection honouring the config's security mode.
    Caller is responsible for closing (use as a context manager)."""
    security = (cfg.get('security') or 'starttls').lower()
    server, port = cfg['server'], int(cfg['port'])

    if security == 'ssl':
        conn = smtplib.SMTP_SSL(server, port, timeout=30)
        conn.ehlo()
    else:
        conn = smtplib.SMTP(server, port, timeout=30)
        conn.ehlo()
        if security == 'starttls':
            conn.starttls()
            conn.ehlo()

    if cfg.get('username'):
        conn.login(cfg['username'], cfg.get('password', ''))
    return conn


def smtp_from_header(cfg):
    name  = cfg.get('from_name') or ''
    email = cfg.get('from_email') or cfg.get('username') or ''
    return f'{name} <{email}>' if name else email


# ── Landing page helpers ────────────────────────────────────────────────────────

DEFAULT_LANDING_HTML = """<!doctype html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Account Verification</title></head>
<body style="font-family:Arial,sans-serif;background:#f3f4f6;margin:0;padding:40px;">
  <div style="max-width:420px;margin:40px auto;background:#fff;border-radius:8px;
              padding:32px;box-shadow:0 1px 4px rgba(0,0,0,.1);">
    <h2 style="margin-top:0;">Please confirm your details</h2>
    <p>Hello {{first_name}}, verify your information to continue.</p>
    {{form}}
  </div>
</body>
</html>"""


def load_landing_pages():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM landing_pages ORDER BY name")
            return [dict(r) for r in cur.fetchall()]


def get_landing_page(lp_id):
    if not lp_id:
        return None
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM landing_pages WHERE id = %s", (lp_id,))
            row = cur.fetchone()
            return dict(row) if row else None


def _field_html(kind, lp):
    """One capture <input>/<textarea> block, inline-styled. Returns '' for an
    optional field that hasn't been turned on for this landing page."""
    lp = lp or {}
    if kind == 'name':
        return """
  <div style="margin-bottom:12px;">
    <label style="display:block;margin-bottom:4px;">Full name</label>
    <input type="text" name="name" required
           style="width:100%;padding:10px;box-sizing:border-box;border:1px solid #ccc;border-radius:4px;">
  </div>"""
    if kind == 'email':
        return """
  <div style="margin-bottom:16px;">
    <label style="display:block;margin-bottom:4px;">Email</label>
    <input type="email" name="email" required
           style="width:100%;padding:10px;box-sizing:border-box;border:1px solid #ccc;border-radius:4px;">
  </div>"""
    if kind == 'phone':
        if not lp.get('capture_phone'):
            return ''
        return """
  <div style="margin-bottom:16px;">
    <label style="display:block;margin-bottom:4px;">Phone number</label>
    <input type="tel" name="phone"
           style="width:100%;padding:10px;box-sizing:border-box;border:1px solid #ccc;border-radius:4px;">
  </div>"""
    if kind == 'id':
        if not lp.get('capture_id'):
            return ''
        id_label = html_escape(lp.get('id_label') or 'ID')
        return f"""
  <div style="margin-bottom:16px;">
    <label style="display:block;margin-bottom:4px;">{id_label}</label>
    <input type="text" name="id_value"
           style="width:100%;padding:10px;box-sizing:border-box;border:1px solid #ccc;border-radius:4px;">
  </div>"""
    if kind == 'comment':
        if not lp.get('capture_comment'):
            return ''
        comment_label = html_escape(lp.get('comment_label') or 'Comment')
        return f"""
  <div style="margin-bottom:16px;">
    <label style="display:block;margin-bottom:4px;">{comment_label}</label>
    <textarea name="comment" rows="3"
           style="width:100%;padding:10px;box-sizing:border-box;border:1px solid #ccc;border-radius:4px;"></textarea>
  </div>"""
    return ''


def _form_open_html(token, campaign, lp):
    """<form> tag plus the hidden tracking inputs. Pair with {{form_end}}."""
    lp = lp or {}
    return f"""<form method="POST" action="/submit" style="margin-top:16px;">
  <input type="hidden" name="token" value="{html_escape(token or '')}">
  <input type="hidden" name="campaign" value="{html_escape(campaign or '')}">
  <input type="hidden" name="lp" value="{html_escape(str(lp.get('id') or ''))}">"""


def _submit_button_html():
    return """
  <button type="submit"
          style="width:100%;padding:11px;background:#2563eb;color:#fff;border:none;
                 border-radius:4px;font-size:15px;cursor:pointer;">Continue</button>"""


def _landing_form_html(token, campaign, lp):
    """All-in-one convenience form: name/email plus whichever optional fields
    the landing page has turned on. Equivalent to combining {{form_start}},
    the individual {{..._field}} tags, {{submit_button}} and {{form_end}}."""
    lp = lp or {}
    body = (_field_html('name', lp) + _field_html('email', lp)
            + _field_html('phone', lp) + _field_html('id', lp) + _field_html('comment', lp))
    return _form_open_html(token, campaign, lp) + body + _submit_button_html() + "\n</form>"


def render_landing(lp, user, token, campaign):
    """Produce the final standalone landing HTML. Uses plain string replacement
    (never Jinja) on admin-authored HTML, with user values HTML-escaped."""
    u = user or {}
    html_out = lp.get('html') or DEFAULT_LANDING_HTML
    html_out = (html_out
                .replace("{{first_name}}", html_escape(u.get('first_name', '')))
                .replace("{{last_name}}",  html_escape(u.get('last_name', '')))
                .replace("{{email}}",      html_escape(u.get('email', '')))
                .replace("{{form_start}}",    _form_open_html(token, campaign, lp))
                .replace("{{form_end}}",      "</form>")
                .replace("{{submit_button}}", _submit_button_html())
                .replace("{{name_field}}",    _field_html('name', lp))
                .replace("{{email_field}}",   _field_html('email', lp))
                .replace("{{phone_field}}",   _field_html('phone', lp))
                .replace("{{id_field}}",      _field_html('id', lp))
                .replace("{{comment_field}}", _field_html('comment', lp))
                .replace("{{form}}",       _landing_form_html(token, campaign, lp)))
    return html_out


def get_user_by_token(token):
    if not token:
        return None
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT username, first_name, last_name, email, grp AS "group", token
                FROM users WHERE token = %s
            """, (token,))
            row = cur.fetchone()
            return dict(row) if row else None


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

        username = request.form.get('username', '')
        password = request.form.get('password', '')
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM accounts WHERE username = %s AND active = TRUE",
                            (username,))
                acct = cur.fetchone()

        if acct and check_password_hash(acct['password_hash'], password):
            session.clear()
            session['logged_in'] = True
            session['user']      = acct['username']
            session['role']      = acct['role']
            with get_db() as conn:
                with conn.cursor() as cur:
                    cur.execute("UPDATE accounts SET last_login = %s WHERE id = %s",
                                (_utcnow(), acct['id']))
            return redirect(url_for('dashboard'))

        return render_template('login.html', error="Invalid credentials.",
                               captcha_question=_new_captcha())

    return render_template('login.html', captcha_question=_new_captcha())


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


# ── Index ─────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')


# ── Generate ──────────────────────────────────────────────────────────────────

@app.route('/generate', methods=['GET', 'POST'])
@role_required('operator')
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
    all_users = load_users()
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT DISTINCT LOWER(email) AS email FROM email_log")
            sent_emails = {r['email'] for r in cur.fetchall()}
    for u in all_users:
        u['emailed'] = u['email'].strip().lower() in sent_emails
    groups = sorted({u['group'] for u in all_users if u.get('group')})
    return render_template('users.html', users=all_users, groups=groups)


@app.route('/users/edit', methods=['POST'])
@role_required('operator')
def edit_user():
    f = request.form
    orig_username = f.get('orig_username', '').strip()
    username      = f.get('username', '').strip()
    first_name    = f.get('first_name', '').strip()
    last_name     = f.get('last_name', '').strip()
    email         = f.get('email', '').strip()
    group         = f.get('group', '').strip()
    track_open    = 'yes' if f.get('track_open') else 'no'

    if not orig_username or not username or not email:
        return jsonify({'status': 'error', 'message': 'Username and email are required'}), 400

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM users WHERE username = %s", (orig_username,))
            if not cur.fetchone():
                return jsonify({'status': 'error', 'message': 'User not found'}), 404
            if username != orig_username:
                cur.execute("SELECT 1 FROM users WHERE username = %s", (username,))
                if cur.fetchone():
                    return jsonify({'status': 'error', 'message': 'That username is already taken'}), 400
            cur.execute("""
                UPDATE users SET username=%s, first_name=%s, last_name=%s, email=%s, grp=%s, track_open=%s
                 WHERE username=%s
            """, (username, first_name, last_name, email, group, track_open, orig_username))
    return redirect(url_for('users'))


@app.route('/users/delete', methods=['POST'])
@role_required('operator')
def delete_user():
    username = request.form.get('username', '').strip()
    if username:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM users WHERE username = %s", (username,))
    return redirect(url_for('users'))


@app.route('/users/bulk-delete', methods=['POST'])
@role_required('operator')
def bulk_delete_users():
    usernames = [u.strip() for u in request.form.getlist('usernames') if u.strip()]
    group     = request.form.get('group', '').strip()
    with get_db() as conn:
        with conn.cursor() as cur:
            if group:
                cur.execute("DELETE FROM users WHERE grp = %s", (group,))
            elif usernames:
                cur.execute("DELETE FROM users WHERE username = ANY(%s)", (usernames,))
    return redirect(url_for('users'))


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
    token    = request.args.get("uid")
    campaign = request.args.get("c", "")
    lp_id    = request.args.get("lp")
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    if ',' in ip:
        ip = ip.split(',')[0].strip()
    ts = _utcnow()
    scan = scanner_detect.classify(ip, request.headers.get("User-Agent", ""))
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO clicks (token, timestamp, ip, campaign, is_scanner, scanner_vendor, scanner_reason)
                VALUES (%s,%s,%s,%s,%s,%s,%s)
            """, (token, ts, ip, campaign, scan["is_scanner"], scan["vendor"] or "", scan["reason"]))

    # If this link carries a landing page, serve it (with a capture form);
    # otherwise fall back to the configured external redirect.
    lp = get_landing_page(lp_id) if lp_id else None
    if lp:
        user = get_user_by_token(token)
        resp = make_response(render_landing(lp, user, token, campaign))
        resp.headers["Content-Type"] = "text/html; charset=utf-8"
        return resp
    return redirect(REDIRECT_URL)


@app.route('/img/<uid>.png')
def img(uid):
    campaign = request.args.get("c", "")
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    if ',' in ip:
        ip = ip.split(',')[0].strip()
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    scan = scanner_detect.classify(ip, request.headers.get("User-Agent", ""))
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO opens (token, timestamp, ip, campaign, is_scanner, scanner_vendor, scanner_reason)
                VALUES (%s,%s,%s,%s,%s,%s,%s)
            """, (uid, ts, ip, campaign, scan["is_scanner"], scan["vendor"] or "", scan["reason"]))
    return send_file(os.path.join(app.root_path, "static", "pixel.png"), mimetype='image/png')


@app.route('/submit', methods=['POST'])
def submit():
    """Public: records a data-entry submission from a landing page, then shows a
    plain thank-you page. Confirms the target went past the click."""
    token    = request.form.get("token", "")
    campaign = request.form.get("campaign", "")
    lp_id    = request.form.get("lp", "") or None
    name     = request.form.get("name", "").strip()
    email    = request.form.get("email", "").strip()
    phone    = request.form.get("phone", "").strip()
    id_value = request.form.get("id_value", "").strip()
    comment  = request.form.get("comment", "").strip()
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    if ',' in ip:
        ip = ip.split(',')[0].strip()
    scan = scanner_detect.classify(ip, request.headers.get("User-Agent", ""))

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO submissions (token, campaign, landing_id, name, email, phone, id_value, comment, ip, timestamp,
                                          is_scanner, scanner_vendor, scanner_reason)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """, (token, campaign, lp_id, name, email, phone, id_value, comment, ip, _utcnow(),
                  scan["is_scanner"], scan["vendor"] or "", scan["reason"]))

    lp = get_landing_page(lp_id) if lp_id else None
    message = (lp.get('thankyou') if lp and lp.get('thankyou')
               else "Thank you. Your information has been received.")
    page = f"""<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Thank you</title></head>
<body style="font-family:Arial,sans-serif;background:#f3f4f6;margin:0;padding:40px;">
  <div style="max-width:420px;margin:60px auto;background:#fff;border-radius:8px;
              padding:32px;box-shadow:0 1px 4px rgba(0,0,0,.1);text-align:center;">
    {message}
  </div>
</body></html>"""
    resp = make_response(page)
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp


# ── Dashboard ─────────────────────────────────────────────────────────────────

def _compute_dashboard_stats(show_scanner):
    """Shared by the initial page render and the polled /api/stats endpoint —
    kept to COUNT(*) queries only; the full user/click rows for the activity
    table are fetched separately (and lazily) via /api/clicks + /api/group-stats."""
    scanner_filter = "" if show_scanner else "WHERE is_scanner = FALSE"
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS cnt FROM users")
            total_users = cur.fetchone()['cnt']

            cur.execute(f"SELECT COUNT(DISTINCT token) AS cnt FROM opens {scanner_filter}")
            opens_count = cur.fetchone()['cnt']

            cur.execute(f"SELECT COUNT(DISTINCT token) AS cnt FROM clicks {scanner_filter}")
            clicks_count = cur.fetchone()['cnt']

            cur.execute("SELECT COUNT(DISTINCT LOWER(email)) AS cnt FROM email_log")
            sent_count = cur.fetchone()['cnt']

            cur.execute(f"SELECT COUNT(DISTINCT token) AS cnt FROM submissions {scanner_filter}")
            submissions_count = cur.fetchone()['cnt']

            # Raw row count, shown alongside the distinct-victim count above since
            # one victim can submit more than once and the two numbers legitimately differ.
            cur.execute(f"SELECT COUNT(*) AS cnt FROM submissions {scanner_filter}")
            submissions_total = cur.fetchone()['cnt']

            cur.execute("""
                SELECT
                    (SELECT COUNT(*) FROM clicks      WHERE is_scanner) +
                    (SELECT COUNT(*) FROM opens        WHERE is_scanner) +
                    (SELECT COUNT(*) FROM submissions  WHERE is_scanner) AS cnt
            """)
            scanner_filtered = cur.fetchone()['cnt']

            cur.execute("SELECT COUNT(*) AS cnt FROM clicks WHERE is_scanner")
            bot_clicks_count = cur.fetchone()['cnt']

    stats = {
        'total_users':   total_users,
        'emails_sent':   sent_count,
        'emails_opened': opens_count,
        'links_clicked': clicks_count,
        'submissions':   submissions_count,
        'submissions_total': submissions_total,
        'bot_clicks':    bot_clicks_count,
        'email_pending': max(0, total_users - sent_count),
    }
    return stats, scanner_filtered


@app.route('/dashboard')
@login_required
def dashboard():
    show_scanner = _show_scanner_hits()
    stats, scanner_filtered = _compute_dashboard_stats(show_scanner)
    return render_template('dashboard.html', stats=stats,
                           email_pending=stats['email_pending'],
                           show_scanner=show_scanner, scanner_filtered=scanner_filtered)


@app.route('/api/stats')
@login_required
def api_stats():
    stats, scanner_filtered = _compute_dashboard_stats(_show_scanner_hits())
    return jsonify({'stats': stats, 'scanner_filtered': scanner_filtered})


@app.route('/api/group-stats')
@login_required
def api_group_stats():
    """Per-group totals (for the group dropdown and the clicks-by-group
    chart) — the actual click EVENTS for the dashboard's table come from
    /api/clicks, which already returns one row per user who really clicked."""
    scanner_filter = "" if _show_scanner_hits() else "WHERE is_scanner = FALSE"
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(f"""
                SELECT u.grp AS "group",
                       COUNT(*) AS total,
                       COUNT(c.token) AS clicked
                FROM users u
                LEFT JOIN (SELECT DISTINCT token FROM clicks {scanner_filter}) c
                       ON c.token = u.token
                GROUP BY u.grp
            """)
            group_stats = [dict(r) for r in cur.fetchall()]

    groups = sorted({r['group'] for r in group_stats})
    return jsonify({'groups': groups, 'group_stats': group_stats})


# ── API endpoints ─────────────────────────────────────────────────────────────

@app.route('/api/clicks')
@login_required
def api_clicks():
    scanner_filter = "" if _show_scanner_hits() else "WHERE is_scanner = FALSE"
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(f"""
                SELECT c.token, c.timestamp, c.ip, c.is_scanner, c.scanner_vendor,
                       u.first_name, u.last_name, u.email, u.grp AS "group"
                FROM (
                    SELECT DISTINCT ON (token) token, timestamp, ip, is_scanner, scanner_vendor
                    FROM clicks
                    {scanner_filter}
                    ORDER BY token, timestamp DESC
                ) c
                LEFT JOIN users u ON u.token = c.token
            """)
            rows = [dict(r) for r in cur.fetchall()]
    return jsonify({'clicks': rows})


@app.route('/api/bot-clicks')
@login_required
def api_bot_clicks():
    """Every click flagged as an automated scanner hit, independent of the
    show_scanner toggle — this is the dedicated bot-review view."""
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT c.token, c.timestamp, c.ip, c.campaign, c.scanner_vendor, c.scanner_reason,
                       u.first_name, u.last_name, u.email, u.grp AS "group"
                FROM clicks c
                LEFT JOIN users u ON u.token = c.token
                WHERE c.is_scanner = TRUE
                ORDER BY c.timestamp DESC
            """)
            rows = [dict(r) for r in cur.fetchall()]

            cur.execute("""
                SELECT scanner_vendor, COUNT(*) AS cnt
                FROM clicks WHERE is_scanner = TRUE
                GROUP BY scanner_vendor ORDER BY cnt DESC
            """)
            by_vendor = [dict(r) for r in cur.fetchall()]
    return jsonify({'bot_clicks': rows, 'by_vendor': by_vendor})


@app.route('/api/repeats')
@login_required
def api_repeats():
    scanner_filter = "" if _show_scanner_hits() else "WHERE is_scanner = FALSE"
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(f"""
                SELECT c.token,
                       COUNT(*) AS clicks,
                       MIN(c.timestamp) AS first_click,
                       MAX(c.timestamp) AS last_click,
                       STRING_AGG(DISTINCT c.ip, ', ') AS ip_list,
                       u.first_name, u.last_name, u.email, u.grp AS "group"
                FROM clicks c
                LEFT JOIN users u ON u.token = c.token
                {scanner_filter}
                GROUP BY c.token, u.first_name, u.last_name, u.email, u.grp
                HAVING COUNT(*) > 1
            """)
            rows = [dict(r) for r in cur.fetchall()]
    return jsonify({'repeats': rows})


@app.route('/api/campaigns')
@login_required
def api_campaigns():
    """Per-campaign (per-template) breakdown so several templates running at
    once can be compared side by side."""
    scanner_filter = "" if _show_scanner_hits() else "WHERE is_scanner = FALSE"
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT campaign, COUNT(DISTINCT LOWER(email)) AS cnt
                FROM email_log GROUP BY campaign
            """)
            sent = {r['campaign']: r['cnt'] for r in cur.fetchall()}

            cur.execute(f"""
                SELECT campaign, COUNT(DISTINCT token) AS cnt
                FROM opens {scanner_filter} GROUP BY campaign
            """)
            opened = {r['campaign']: r['cnt'] for r in cur.fetchall()}

            cur.execute(f"""
                SELECT campaign,
                       COUNT(DISTINCT token) AS unique_clicks,
                       COUNT(*) AS total_clicks
                FROM clicks {scanner_filter} GROUP BY campaign
            """)
            clicked = {r['campaign']: dict(r) for r in cur.fetchall()}

    names = set(sent) | set(opened) | set(clicked)
    rows = []
    for name in names:
        c = clicked.get(name, {})
        s = sent.get(name, 0)
        uc = c.get('unique_clicks', 0)
        rows.append({
            'campaign':      name or '(untagged)',
            'sent':          s,
            'opened':        opened.get(name, 0),
            'unique_clicks': uc,
            'total_clicks':  c.get('total_clicks', 0),
            'click_rate':    round(uc * 100.0 / s, 1) if s else 0.0,
        })
    rows.sort(key=lambda r: (r['sent'], r['unique_clicks']), reverse=True)
    return jsonify({'campaigns': rows})


@app.route('/api/repeat-offenders')
@login_required
def api_repeat_offenders():
    """Users worth prioritising for awareness training: either they clicked the
    SAME link/campaign more than once, or they clicked the lure across more than
    one distinct campaign."""
    scanner_clause = "" if _show_scanner_hits() else "AND c.is_scanner = FALSE"
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(f"""
                SELECT token, first_name, last_name, email, "group",
                       COUNT(DISTINCT campaign)          AS campaigns_failed,
                       SUM(cnt)                           AS total_clicks,
                       MAX(cnt)                            AS max_same_link_clicks,
                       STRING_AGG(DISTINCT campaign, ', ') AS campaigns,
                       MIN(first_click)                    AS first_click,
                       MAX(last_click)                     AS last_click,
                       STRING_AGG(DISTINCT ips, ', ')      AS ips
                FROM (
                    SELECT c.token, c.campaign,
                           COUNT(*)                       AS cnt,
                           MIN(c.timestamp)                AS first_click,
                           MAX(c.timestamp)                AS last_click,
                           STRING_AGG(DISTINCT c.ip, ', ')  AS ips,
                           u.first_name, u.last_name, u.email, u.grp AS "group"
                    FROM clicks c
                    LEFT JOIN users u ON u.token = c.token
                    WHERE c.campaign <> '' {scanner_clause}
                    GROUP BY c.token, c.campaign, u.first_name, u.last_name, u.email, u.grp
                ) per_campaign
                GROUP BY token, first_name, last_name, email, "group"
                HAVING COUNT(DISTINCT campaign) > 1 OR MAX(cnt) > 1
                ORDER BY max_same_link_clicks DESC, campaigns_failed DESC, total_clicks DESC
            """)
            rows = [dict(r) for r in cur.fetchall()]
    return jsonify({'offenders': rows})


# ── Report ────────────────────────────────────────────────────────────────────

@app.route('/telemetry')
@login_required
def telemetry():
    return render_template("telemetry.html")


@app.route('/submissions')
@login_required
def submissions():
    show_scanner = _show_scanner_hits()
    scanner_clause = "" if show_scanner else "WHERE s.is_scanner = FALSE"
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(f"""
                SELECT s.id, s.name AS sub_name, s.email AS sub_email,
                       s.phone, s.id_value, s.comment, s.campaign, s.ip,
                       s.timestamp::text AS timestamp, s.token,
                       s.is_scanner, s.scanner_vendor,
                       u.username, u.first_name, u.last_name,
                       u.email AS victim_email, u.grp AS "group",
                       lp.name AS landing_name
                FROM submissions s
                LEFT JOIN users u          ON u.token  = s.token
                LEFT JOIN landing_pages lp ON lp.id    = s.landing_id
                {scanner_clause}
                ORDER BY s.timestamp DESC
            """)
            rows = [dict(r) for r in cur.fetchall()]

    # Group by victim (token); anonymous subs keyed by submission id
    victims = {}
    for r in rows:
        key = r.get('token') or f"__anon_{r['id']}"
        ve = (r.get('victim_email') or '').strip().lower()
        se = (r.get('sub_email') or '').strip().lower()
        email_match = bool(ve and se and ve == se)

        if key not in victims:
            victims[key] = {
                'token': r.get('token'),
                'username': r.get('username') or '—',
                'victim_name': (f"{r.get('first_name') or ''} {r.get('last_name') or ''}".strip() or None),
                'victim_email': r.get('victim_email'),
                'group': r.get('group'),
                'timestamps': [],
                'ips': [],
                'campaigns': [],
                'has_match': False,
                'has_scanner': False,
                'submissions': [],
            }

        v = victims[key]
        ts  = str(r.get('timestamp') or '')
        ip  = str(r.get('ip') or '')
        cam = str(r.get('campaign') or '')

        if ts  and ts  not in v['timestamps']: v['timestamps'].append(ts)
        if ip  and ip  not in v['ips']:        v['ips'].append(ip)
        if cam and cam not in v['campaigns']:  v['campaigns'].append(cam)
        if email_match:
            v['has_match'] = True

        v['submissions'].append({
            'sub_name':    r.get('sub_name'),
            'sub_email':   r.get('sub_email'),
            'phone':       r.get('phone'),
            'id_value':    r.get('id_value'),
            'comment':     r.get('comment'),
            'campaign':    r.get('campaign'),
            'landing_name': r.get('landing_name'),
            'ip':          r.get('ip'),
            'timestamp':   ts,
            'email_match': email_match,
            'is_scanner':  r.get('is_scanner', False),
            'scanner_vendor': r.get('scanner_vendor', ''),
        })
        if r.get('is_scanner'):
            v['has_scanner'] = True

    victim_list = list(victims.values())
    return render_template("submissions.html", victims=victim_list, show_scanner=show_scanner)


# ── Account management (admin) ──────────────────────────────────────────────────

def load_accounts():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, username, role, active, created_at, last_login
                FROM accounts ORDER BY username
            """)
            return [dict(r) for r in cur.fetchall()]


def _active_admin_count(cur):
    cur.execute("SELECT COUNT(*) AS cnt FROM accounts WHERE role = 'admin' AND active = TRUE")
    return cur.fetchone()['cnt']


@app.route('/accounts')
@role_required('admin')
def accounts():
    return render_template('accounts.html', accounts=load_accounts())


@app.route('/accounts/save', methods=['POST'])
@role_required('admin')
def save_account():
    f = request.form
    username = f.get('username', '').strip()
    role     = f.get('role', 'viewer')
    active   = f.get('active') == 'on' or f.get('active') == 'true'
    password = f.get('password', '')
    acct_id  = f.get('id', '').strip()

    if not username:
        return jsonify({'status': 'error', 'message': 'Username required'}), 400
    if role not in ROLE_RANK:
        return jsonify({'status': 'error', 'message': 'Invalid role'}), 400

    with get_db() as conn:
        with conn.cursor() as cur:
            if acct_id:
                # Guard: don't let the last active admin be demoted/disabled.
                cur.execute("SELECT username, role, active FROM accounts WHERE id = %s", (acct_id,))
                existing = cur.fetchone()
                if not existing:
                    return jsonify({'status': 'error', 'message': 'Account not found'}), 404
                losing_admin = (existing['role'] == 'admin' and existing['active']
                                and (role != 'admin' or not active))
                if losing_admin and _active_admin_count(cur) <= 1:
                    return jsonify({'status': 'error',
                                    'message': 'Cannot demote or disable the last active admin.'}), 400
                if password:
                    cur.execute("""
                        UPDATE accounts SET username=%s, role=%s, active=%s, password_hash=%s
                         WHERE id=%s
                    """, (username, role, active, generate_password_hash(password), acct_id))
                else:
                    cur.execute("UPDATE accounts SET username=%s, role=%s, active=%s WHERE id=%s",
                                (username, role, active, acct_id))
            else:
                if not password:
                    return jsonify({'status': 'error', 'message': 'Password required for new account'}), 400
                cur.execute("""
                    INSERT INTO accounts (username, password_hash, role, active, created_at)
                    VALUES (%s,%s,%s,%s,%s)
                    ON CONFLICT (username) DO NOTHING
                """, (username, generate_password_hash(password), role, active, _utcnow()))
    return redirect(url_for('accounts'))


@app.route('/accounts/delete', methods=['POST'])
@role_required('admin')
def delete_account():
    acct_id = request.form.get('id', '').strip()
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT username, role, active FROM accounts WHERE id = %s", (acct_id,))
            acct = cur.fetchone()
            if not acct:
                return redirect(url_for('accounts'))
            if acct['username'] == session.get('user'):
                return render_template('403.html', message="You cannot delete your own account."), 400
            if acct['role'] == 'admin' and acct['active'] and _active_admin_count(cur) <= 1:
                return render_template('403.html', message="Cannot delete the last active admin."), 400
            cur.execute("DELETE FROM accounts WHERE id = %s", (acct_id,))
    return redirect(url_for('accounts'))


@app.route('/account/password', methods=['POST'])
@login_required
def change_password():
    """Any logged-in user changes their own password."""
    current = request.form.get('current', '')
    new     = request.form.get('new', '')
    if not new:
        return jsonify({'status': 'error', 'message': 'New password required'}), 400
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, password_hash FROM accounts WHERE username = %s",
                        (session.get('user'),))
            acct = cur.fetchone()
            if not acct or not check_password_hash(acct['password_hash'], current):
                return jsonify({'status': 'error', 'message': 'Current password is incorrect'}), 400
            cur.execute("UPDATE accounts SET password_hash = %s WHERE id = %s",
                        (generate_password_hash(new), acct['id']))
    return jsonify({'status': 'success', 'message': 'Password changed'})


def _build_report():
    """Per-user simulation status plus a client-presentable summary and
    per-group breakdown. Shared by the /report page and its CSV export so
    the two never drift apart."""
    scanner_filter = "" if _show_scanner_hits() else "WHERE is_scanner = FALSE"
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
                SELECT username, STRING_AGG(DISTINCT campaign, ', ' ORDER BY campaign) AS campaigns
                FROM email_log WHERE campaign <> '' GROUP BY username
            """)
            campaigns_by_user = {r['username']: r['campaigns'] for r in cur.fetchall()}

            cur.execute(f"""
                SELECT token, COUNT(*) AS total_opens
                FROM opens {scanner_filter} GROUP BY token
            """)
            open_agg = {r['token']: r['total_opens'] for r in cur.fetchall()}

            cur.execute(f"""
                SELECT token, COUNT(*) AS total_clicks, STRING_AGG(DISTINCT ip, ', ') AS ips,
                       MAX(timestamp) AS last_click
                FROM clicks {scanner_filter}
                GROUP BY token
            """)
            click_agg = {r['token']: dict(r) for r in cur.fetchall()}

            cur.execute(f"""
                SELECT token, COUNT(*) AS total_submissions, MAX(timestamp) AS last_submit
                FROM submissions {scanner_filter} GROUP BY token
            """)
            sub_agg = {r['token']: dict(r) for r in cur.fetchall()}

    enriched = []
    for u in all_users:
        token = u.get('token', '')
        email = (u.get('email') or '').lower()
        cl    = click_agg.get(token, {})
        sb    = sub_agg.get(token, {})
        last_activity = max(filter(None, [cl.get('last_click', ''), sb.get('last_submit', '')]), default='')
        enriched.append({
            'username':          u.get('username', ''),
            'first_name':        u.get('first_name', ''),
            'last_name':         u.get('last_name', ''),
            'email':             u.get('email', ''),
            'group':             u.get('group', ''),
            'token':             token,
            'email_sent':        email in sent_emails,
            'opened':            token in open_agg,
            'total_opens':       open_agg.get(token, 0),
            'link_clicked':      token in click_agg,
            'total_clicks':      cl.get('total_clicks', 0),
            'ips':               cl.get('ips', '') or '',
            'submitted':         token in sub_agg,
            'total_submissions': sb.get('total_submissions', 0),
            'campaigns':         campaigns_by_user.get(u.get('username', ''), ''),
            'last_activity':     last_activity,
        })

    total = len(enriched)
    def pct(n):
        return round(100 * n / total, 1) if total else 0
    summary = {
        'total':     total,
        'sent':      sum(1 for u in enriched if u['email_sent']),
        'opened':    sum(1 for u in enriched if u['opened']),
        'clicked':   sum(1 for u in enriched if u['link_clicked']),
        'submitted': sum(1 for u in enriched if u['submitted']),
    }
    for k in ('sent', 'opened', 'clicked', 'submitted'):
        summary[f'pct_{k}'] = pct(summary[k])

    groups = {}
    for u in enriched:
        g = u['group'] or '(no group)'
        gs = groups.setdefault(g, {'group': g, 'total': 0, 'sent': 0, 'opened': 0, 'clicked': 0, 'submitted': 0})
        gs['total']     += 1
        gs['sent']      += 1 if u['email_sent']   else 0
        gs['opened']    += 1 if u['opened']       else 0
        gs['clicked']   += 1 if u['link_clicked'] else 0
        gs['submitted'] += 1 if u['submitted']    else 0
    group_breakdown = sorted(groups.values(), key=lambda g: g['group'])

    return enriched, summary, group_breakdown


@app.route('/report')
@login_required
def report():
    enriched, summary, group_breakdown = _build_report()
    return render_template("report.html", users=enriched, summary=summary, group_breakdown=group_breakdown)


# ── Import ────────────────────────────────────────────────────────────────────

@app.route('/import', methods=['GET', 'POST'])
@role_required('operator')
def import_users():
    message = ""
    if request.method == 'POST':
        file           = request.files.get('file')
        group_override = request.form.get('group_override', '').strip()
        track_open     = 'yes' if request.form.get('track_open') else 'no'

        if file and file.filename and file.filename.lower().endswith('.csv'):
            filepath = os.path.join('uploads', secure_filename(file.filename))
            os.makedirs('uploads', exist_ok=True)
            file.save(filepath)

            count, skipped = 0, 0
            with open(filepath, 'r', newline='') as f:
                reader = csv.DictReader(f)
                headers = {(h or '').strip().lower() for h in (reader.fieldnames or [])}
                required = {'username', 'first_name', 'last_name', 'email'}
                missing = required - headers
                if missing:
                    message = ("❌ CSV is missing required column(s): "
                               + ", ".join(sorted(missing))
                               + ". Expected headers: username, first_name, last_name, email, group.")
                else:
                    for row in reader:
                        username = (row.get('username') or '').strip()
                        email    = (row.get('email') or '').strip()
                        if not username or not email:
                            skipped += 1
                            continue
                        user = {
                            'username':   username,
                            'first_name': (row.get('first_name') or '').strip(),
                            'last_name':  (row.get('last_name') or '').strip(),
                            'email':      email,
                            'group':      group_override or (row.get('group') or '').strip(),
                            'track_open': track_open,
                        }
                        generate_link(user)
                        count += 1
                    message = f"✅ {count} users imported successfully."
                    if skipped:
                        message += f" ({skipped} row(s) skipped — missing username/email.)"
        else:
            message = "Please upload a valid CSV file."

    return render_template('import.html', message=message)


# ── Reset analytics ───────────────────────────────────────────────────────────

@app.route('/reset-analytics', methods=['POST'])
@role_required('operator')
def reset_analytics():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM clicks")
            cur.execute("DELETE FROM opens")
            cur.execute("DELETE FROM email_log")
            cur.execute("DELETE FROM submissions")
    return jsonify({'status': 'success', 'message': 'Analytics reset'})


# ── Email template management ─────────────────────────────────────────────────

@app.route('/save-template', methods=['POST'])
@role_required('operator')
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
@role_required('operator')
def delete_template():
    name = request.form.get('template_name', '').strip()
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM templates WHERE name = %s", (name,))
    return jsonify({'status': 'success'})


# ── SMTP config management ──────────────────────────────────────────────────────

@app.route('/smtp-configs')
@role_required('operator')
def smtp_configs():
    return render_template('smtp_configs.html', configs=load_smtp_configs())


@app.route('/smtp-configs/save', methods=['POST'])
@role_required('operator')
def save_smtp_config():
    f = request.form
    name = f.get('name', '').strip()
    if not name:
        return jsonify({'status': 'error', 'message': 'Name is required'}), 400

    try:
        port = int(f.get('port') or 587)
    except ValueError:
        return jsonify({'status': 'error', 'message': 'Port must be a number'}), 400

    config_id  = f.get('id', '').strip()
    security   = (f.get('security') or 'starttls').lower()
    if security not in ('starttls', 'ssl', 'none'):
        security = 'starttls'

    values = (
        name, f.get('server', '').strip(), port,
        f.get('username', '').strip(), f.get('password', ''),
        security, f.get('from_email', '').strip(),
        f.get('from_name', '').strip(), f.get('default_subject', '').strip(),
    )

    with get_db() as conn:
        with conn.cursor() as cur:
            if config_id:
                cur.execute("""
                    UPDATE smtp_configs
                       SET name=%s, server=%s, port=%s, username=%s, password=%s,
                           security=%s, from_email=%s, from_name=%s, default_subject=%s
                     WHERE id=%s
                """, values + (config_id,))
            else:
                cur.execute("""
                    INSERT INTO smtp_configs
                        (name, server, port, username, password, security,
                         from_email, from_name, default_subject)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """, values)
                # First config becomes active automatically.
                cur.execute("""
                    UPDATE smtp_configs SET is_active = TRUE
                     WHERE NOT EXISTS (SELECT 1 FROM smtp_configs WHERE is_active = TRUE)
                       AND name = %s
                """, (name,))
    return redirect(url_for('smtp_configs'))


@app.route('/smtp-configs/delete', methods=['POST'])
@role_required('operator')
def delete_smtp_config():
    config_id = request.form.get('id', '').strip()
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT is_active FROM smtp_configs WHERE id = %s", (config_id,))
            row = cur.fetchone()
            cur.execute("DELETE FROM smtp_configs WHERE id = %s", (config_id,))
            # If we removed the active one, promote any remaining config.
            if row and row['is_active']:
                cur.execute("""
                    UPDATE smtp_configs SET is_active = TRUE
                     WHERE id = (SELECT id FROM smtp_configs ORDER BY name LIMIT 1)
                """)
    return redirect(url_for('smtp_configs'))


@app.route('/smtp-configs/activate', methods=['POST'])
@role_required('operator')
def activate_smtp_config():
    config_id = request.form.get('id', '').strip()
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE smtp_configs SET is_active = FALSE")
            cur.execute("UPDATE smtp_configs SET is_active = TRUE WHERE id = %s", (config_id,))
    return redirect(url_for('smtp_configs'))


@app.route('/smtp-configs/test', methods=['POST'])
@role_required('operator')
def test_smtp_config():
    config_id = request.form.get('id', '').strip()
    to_email  = request.form.get('to', '').strip()
    cfg = get_smtp_config(config_id)
    if not cfg:
        return jsonify({'status': 'error', 'message': 'Config not found'}), 404
    if not to_email:
        return jsonify({'status': 'error', 'message': 'Recipient required'}), 400

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"RabbitHole SMTP test — {cfg['name']}"
    msg["From"]    = smtp_from_header(cfg)
    msg["To"]      = to_email
    msg.attach(MIMEText(
        f"<p>This is a test message from RabbitHole using SMTP config "
        f"<b>{cfg['name']}</b> ({cfg['server']}:{cfg['port']}, {cfg['security']}).</p>",
        "html"))
    try:
        with smtp_connection(cfg) as server:
            server.send_message(msg)
        return jsonify({'status': 'success', 'message': f'Test sent to {to_email}'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


# ── Landing page management ─────────────────────────────────────────────────────

@app.route('/landing-pages')
@role_required('operator')
def landing_pages():
    return render_template('landing_pages.html', pages=load_landing_pages(),
                           default_html=DEFAULT_LANDING_HTML)


@app.route('/landing-pages/save', methods=['POST'])
@role_required('operator')
def save_landing_page():
    f = request.form
    name = f.get('name', '').strip()
    if not name:
        return jsonify({'status': 'error', 'message': 'Name is required'}), 400
    lp_id           = f.get('id', '').strip()
    capture_phone   = f.get('capture_phone') == 'on'
    capture_id      = f.get('capture_id') == 'on'
    id_label        = f.get('id_label', '').strip() or 'Employee / Student ID'
    capture_comment = f.get('capture_comment') == 'on'
    comment_label   = f.get('comment_label', '').strip() or 'Comment'
    values = (name, f.get('html', ''), f.get('thankyou', ''),
              capture_phone, capture_id, id_label, capture_comment, comment_label)
    with get_db() as conn:
        with conn.cursor() as cur:
            if lp_id:
                cur.execute("""
                    UPDATE landing_pages
                       SET name=%s, html=%s, thankyou=%s,
                           capture_phone=%s, capture_id=%s, id_label=%s,
                           capture_comment=%s, comment_label=%s
                     WHERE id=%s
                """, values + (lp_id,))
            else:
                cur.execute("""
                    INSERT INTO landing_pages (name, html, thankyou,
                        capture_phone, capture_id, id_label, capture_comment, comment_label, created_at)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """, values + (_utcnow(),))
    return redirect(url_for('landing_pages'))


@app.route('/landing-pages/delete', methods=['POST'])
@role_required('operator')
def delete_landing_page():
    lp_id = request.form.get('id', '').strip()
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM landing_pages WHERE id = %s", (lp_id,))
    return redirect(url_for('landing_pages'))


@app.route('/landing-pages/<int:lp_id>/preview')
@role_required('operator')
def preview_landing_page(lp_id):
    lp = get_landing_page(lp_id)
    if not lp:
        return redirect(url_for('landing_pages'))
    sample = {'first_name': 'Sample', 'last_name': 'User', 'email': 'sample.user@example.com'}
    resp = make_response(render_landing(lp, sample, 'PREVIEW-TOKEN', 'preview'))
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp


# ── Email template & send ─────────────────────────────────────────────────────

@app.route('/email-template', methods=['GET', 'POST'])
@role_required('operator')
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
    select_all_group   = request.form.get('select_all_group') == '1'
    template_text  = request.form.get('template', '')
    generated      = []
    preview_note   = ''

    users = [u for u in all_users if u['group'] == selected_group] if selected_group else []

    campaign   = request.form.get('campaign', '').strip()
    link_text  = request.form.get('link_text', '').strip() or 'Click here'
    landing_id = request.form.get('landing_page_id', '').strip() or None

    if request.method == 'POST' and request.form.get('action') == 'generate':
        # "Select all" skips per-row checkboxes (see /send-emails), so preview
        # the whole group too — capped, since rendering thousands of previews
        # would be pointless to scroll through and slow to generate.
        PREVIEW_CAP = 25
        if select_all_group:
            preview_targets = users[:PREVIEW_CAP]
            if len(users) > PREVIEW_CAP:
                preview_note = f"Showing {PREVIEW_CAP} of {len(users)} selected — Launch Campaign will send to all of them."
        else:
            wanted = set(selected_usernames)
            preview_targets = [u for u in users if u['username'] in wanted]

        for u in preview_targets:
            link_url, pixel_url = tracking_urls(u['token'], campaign, landing_id)
            pixel_tag = f'<img src="{pixel_url}" width="1" height="1" style="display:none;" alt="">'
            track_open = u.get('track_open') == 'yes'
            body = template_text \
                .replace("{{first_name}}", u['first_name']) \
                .replace("{{last_name}}",  u['last_name']) \
                .replace("{{email}}",      u['email']) \
                .replace("{{token}}",      u['token']) \
                .replace("{{link}}",       f'<a href="{link_url}">{link_text}</a>') \
                .replace("{{pixel}}",      pixel_tag if track_open else '')
            if track_open and pixel_url not in body:
                body += pixel_tag
            generated.append({'email': u['email'], 'body': body})

    saved_templates = load_templates()
    smtp_list       = load_smtp_configs()
    landing_list    = load_landing_pages()
    return render_template("email_template.html", groups=groups, users=users,
                           selected_group=selected_group, template_text=template_text,
                           generated=generated, preview_note=preview_note,
                           saved_templates=saved_templates,
                           smtp_configs=smtp_list, landing_pages=landing_list)


# ── Campaigns (background senders) ──────────────────────────────────────────────

def _campaign_update(cid, **fields):
    """Persist progress/state for a campaign row."""
    if not fields:
        return
    cols = ', '.join(f"{k} = %s" for k in fields)
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(f"UPDATE campaigns SET {cols} WHERE id = %s",
                        (*fields.values(), cid))


def _campaign_flags(cid):
    """(stop_requested, pause_requested) for the worker loop's cooperative checks."""
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT stop_requested, pause_requested FROM campaigns WHERE id = %s", (cid,))
            row = cur.fetchone()
            return (bool(row and row['stop_requested']), bool(row and row['pause_requested']))


def _mark_recipient(rid, status, error=''):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE campaign_recipients SET status = %s, sent_at = %s, error = %s WHERE id = %s
            """, (status, _utcnow() if status == 'sent' else '', error, rid))


def _run_campaign(cid, template, subject, link_text, cfg, delay, label, landing_id=None):
    """Background worker: sends one campaign's still-pending recipients, updating
    progress in the DB and honouring a cooperative stop/pause request. Recipients are
    read from campaign_recipients — a snapshot taken at launch — rather than an
    in-memory list, so pausing and resuming (even across a process restart) just means
    calling this again for the same campaign id; it naturally picks up where it left off."""
    from_hdr = smtp_from_header(cfg)
    try:
        server = smtp_connection(cfg)
    except Exception as e:
        _campaign_update(cid, status='failed', last_error=f"SMTP connect: {e}",
                         finished_at=_utcnow())
        print(f"❌ Campaign {cid} failed to connect: {e}")
        return

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT sent, failed FROM campaigns WHERE id = %s", (cid,))
            counts = cur.fetchone()
            sent, failed = counts['sent'], counts['failed']

            cur.execute("""
                SELECT id, username, first_name, last_name, email, token, track_open
                FROM campaign_recipients WHERE campaign_id = %s AND status = 'pending'
                ORDER BY id
            """, (cid,))
            pending = [dict(r) for r in cur.fetchall()]

    stopped = paused = False
    try:
        for rec in pending:
            stop_req, pause_req = _campaign_flags(cid)
            if stop_req:
                stopped = True
                break
            if pause_req:
                paused = True
                break

            to_email   = rec['email']
            track_open = rec.get('track_open') == 'yes'
            link_url, pixel_url = tracking_urls(rec['token'], label, landing_id)
            pixel_tag  = f'<img src="{pixel_url}" width="1" height="1" style="display:none;" alt="">'

            body = template \
                .replace("{{first_name}}", rec['first_name']) \
                .replace("{{last_name}}",  rec['last_name']) \
                .replace("{{email}}",      rec['email']) \
                .replace("{{token}}",      rec['token']) \
                .replace("{{link}}",       f'<a href="{link_url}">{link_text}</a>') \
                .replace("{{pixel}}",      pixel_tag if track_open else '')
            if track_open and pixel_url not in body:
                body += pixel_tag

            msg            = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"]    = from_hdr
            msg["To"]      = to_email
            msg.attach(MIMEText(body, "html"))

            try:
                server.send_message(msg)
                log_email_sent(rec['username'], to_email, _utcnow(), label)
                sent += 1
                _mark_recipient(rec['id'], 'sent')
                _campaign_update(cid, sent=sent)
                print(f"✅ [{label}] sent to {to_email}")
            except Exception as e:
                failed += 1
                _mark_recipient(rec['id'], 'failed', error=str(e))
                _campaign_update(cid, failed=failed, last_error=str(e))
                print(f"❌ [{label}] failed to {to_email}: {e}")

            time.sleep(delay)
    finally:
        try:
            server.quit()
        except Exception:
            pass

    final = 'paused' if paused else ('stopped' if stopped else 'completed')
    fields = dict(status=final, sent=sent, failed=failed)
    if final != 'paused':
        fields['finished_at'] = _utcnow()
    _campaign_update(cid, **fields)
    print(f"🏁 Campaign {cid} ({label}) {final}: {sent} sent, {failed} failed")


@app.route('/send-emails', methods=['POST'])
@role_required('operator')
def send_emails():
    """Launch a campaign as a background job and return immediately, so multiple
    campaigns can run concurrently. Progress is tracked on the /campaigns page."""
    selected_usernames = request.form.getlist('usernames')
    select_all_group   = request.form.get('select_all_group') == '1'
    group              = request.form.get('group', '').strip()
    status_filter      = request.form.get('status_filter', '').strip()
    template           = request.form.get('template')
    delay              = max(0, int(request.form.get('delay', 5) or 0))
    config_id          = request.form.get('smtp_config_id', '').strip() or None
    subject_override   = request.form.get('subject', '').strip()
    link_text          = request.form.get('link_text', '').strip() or 'Click here'
    label              = request.form.get('campaign', '').strip()
    landing_id         = request.form.get('landing_page_id', '').strip() or None

    if not select_all_group and not selected_usernames:
        return render_template("email_sent_summary.html", sent=[], count=0,
                               message="❌ No users selected.")

    cfg = get_smtp_config(config_id)
    if not cfg:
        return render_template("email_sent_summary.html", sent=[], count=0,
                               message="❌ No SMTP config available. Add one under SMTP.")

    all_users = load_users()

    # "Select all" bypasses the per-row checkbox list entirely — the browser
    # only ever submits checkboxes still attached to the DOM, which with a
    # paginated recipient table caps out at one page's worth (e.g. 100) no
    # matter how many rows are actually checked. Re-deriving the recipient
    # set straight from the group/status filter scales to any list size.
    if select_all_group:
        users_to_send = [u for u in all_users if not group or u['group'] == group]
        if status_filter in ('sent', 'pending'):
            with get_db() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT DISTINCT LOWER(email) AS email FROM email_log")
                    sent_emails = {r['email'] for r in cur.fetchall()}
            if status_filter == 'sent':
                users_to_send = [u for u in users_to_send if u['email'].strip().lower() in sent_emails]
            else:
                users_to_send = [u for u in users_to_send if u['email'].strip().lower() not in sent_emails]
    else:
        wanted        = set(selected_usernames)
        users_to_send = [u for u in all_users if u['username'] in wanted]

    if not users_to_send:
        return render_template("email_sent_summary.html", sent=[], count=0,
                               message="❌ No matching users.")

    subject = subject_override or cfg.get('default_subject') or 'RabbitHole'
    if not label:
        label = f"{cfg['name']}-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"

    lp = get_landing_page(landing_id) if landing_id else None
    landing_name = lp['name'] if lp else ''

    if select_all_group:
        status_desc = {'sent': 'already sent', 'pending': 'not yet sent'}.get(status_filter, 'any status')
        recipient_filter = f"Group: {group or 'all groups'} · {status_desc} · {len(users_to_send)} recipients"
    else:
        recipient_filter = f"{len(users_to_send)} manually selected user(s)"

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO campaigns
                    (name, smtp_config_id, smtp_name, subject, delay, total, status,
                     created_at, landing_page_id, landing_name, template, link_text, recipient_filter)
                VALUES (%s,%s,%s,%s,%s,%s,'running',%s,%s,%s,%s,%s,%s)
                RETURNING id
            """, (label, cfg['id'], cfg['name'], subject, delay,
                  len(users_to_send), _utcnow(), landing_id, landing_name,
                  template, link_text, recipient_filter))
            cid = cur.fetchone()['id']

            cur.executemany("""
                INSERT INTO campaign_recipients
                    (campaign_id, username, first_name, last_name, email, token, track_open, status)
                VALUES (%s,%s,%s,%s,%s,%s,%s,'pending')
            """, [(cid, u['username'], u['first_name'], u['last_name'], u['email'],
                   u['token'], u.get('track_open', 'no')) for u in users_to_send])

    thread = threading.Thread(
        target=_run_campaign,
        args=(cid, template, subject, link_text, cfg, delay, label, landing_id),
        daemon=True,
    )
    thread.start()

    return redirect(url_for('campaigns'))


_PENDING_RECIPIENTS_JOIN = """
    LEFT JOIN (
        SELECT campaign_id, COUNT(*) AS pending_count FROM campaign_recipients
        WHERE status = 'pending' GROUP BY campaign_id
    ) pr ON pr.campaign_id = c.id
"""


def _with_resume_flag(row):
    row = dict(row)
    pending = row.pop('pending_count', 0) or 0
    row['needs_resume_setup'] = row['status'] in ('paused', 'interrupted', 'stopped') and pending == 0
    return row


@app.route('/campaigns')
@login_required
def campaigns():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(f"""
                SELECT c.*, COALESCE(pr.pending_count, 0) AS pending_count
                FROM campaigns c
                {_PENDING_RECIPIENTS_JOIN}
                ORDER BY (c.status = 'running') DESC, c.id DESC
            """)
            rows = [_with_resume_flag(r) for r in cur.fetchall()]
    return render_template("campaigns.html", campaigns=rows)


@app.route('/campaigns/<int:cid>')
@login_required
def campaign_detail(cid):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM campaigns WHERE id = %s", (cid,))
            row = cur.fetchone()
    if not row:
        return redirect(url_for('campaigns'))
    return render_template("campaign_detail.html", campaign=dict(row))


@app.route('/api/campaign/<int:cid>')
@login_required
def api_campaign_detail(cid):
    """Per-recipient breakdown for one campaign: sent / opened / clicked,
    joined on the campaign's tracking label."""
    scanner_clause = "" if _show_scanner_hits() else "AND is_scanner = FALSE"
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(f"""
                SELECT c.*, COALESCE(pr.pending_count, 0) AS pending_count
                FROM campaigns c
                {_PENDING_RECIPIENTS_JOIN}
                WHERE c.id = %s
            """, (cid,))
            row = cur.fetchone()
            if not row:
                return jsonify({'error': 'not found'}), 404
            camp  = _with_resume_flag(row)
            label = camp['name']

            cur.execute("""
                SELECT username, email, MIN(timestamp) AS sent_time
                FROM email_log WHERE campaign = %s
                GROUP BY username, email
            """, (label,))
            sent_rows = [dict(r) for r in cur.fetchall()]

            cur.execute("""
                SELECT username, token, first_name, last_name, grp AS "group"
                FROM users
            """)
            by_username = {r['username']: dict(r) for r in cur.fetchall()}

            cur.execute(f"""
                SELECT token, COUNT(*) AS opens, MIN(timestamp) AS first_open
                FROM opens WHERE campaign = %s {scanner_clause} GROUP BY token
            """, (label,))
            opens_by_token = {r['token']: dict(r) for r in cur.fetchall()}

            cur.execute(f"""
                SELECT token, COUNT(*) AS clicks, MAX(timestamp) AS last_click,
                       STRING_AGG(DISTINCT ip, ', ') AS ips
                FROM clicks WHERE campaign = %s {scanner_clause} GROUP BY token
            """, (label,))
            clicks_by_token = {r['token']: dict(r) for r in cur.fetchall()}

            cur.execute(f"""
                SELECT token, COUNT(*) AS subs, MAX(timestamp) AS last_submit
                FROM submissions WHERE campaign = %s {scanner_clause} GROUP BY token
            """, (label,))
            subs_by_token = {r['token']: dict(r) for r in cur.fetchall()}

    recipients = []
    for s in sent_rows:
        u     = by_username.get(s['username'], {})
        token = u.get('token', '')
        op    = opens_by_token.get(token, {})
        cl    = clicks_by_token.get(token, {})
        sb    = subs_by_token.get(token, {})
        recipients.append({
            'username':    s['username'],
            'name':        f"{u.get('first_name', '')} {u.get('last_name', '')}".strip(),
            'email':       s['email'],
            'group':       u.get('group', ''),
            'sent_time':   s['sent_time'],
            'opened':      bool(op),
            'first_open':  op.get('first_open', ''),
            'clicks':      cl.get('clicks', 0),
            'last_click':  cl.get('last_click', ''),
            'ips':         cl.get('ips', '') or '',
            'submitted':   bool(sb),
            'submit_count': sb.get('subs', 0),
            'submit_time': sb.get('last_submit', ''),
        })

    recipients.sort(key=lambda r: (r['submitted'], r['clicks'] > 0, r['opened'], r['clicks']),
                    reverse=True)
    summary = {
        'recipients': len(recipients),
        'opened':     sum(1 for r in recipients if r['opened']),
        'clicked':    sum(1 for r in recipients if r['clicks'] > 0),
        'submissions_total': sum(r['submit_count'] for r in recipients),
        'submitted':  sum(1 for r in recipients if r['submitted']),
    }
    return jsonify({'campaign': camp, 'recipients': recipients, 'summary': summary})


@app.route('/api/campaign-status')
@login_required
def api_campaign_status():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(f"""
                SELECT c.id, c.name, c.smtp_name, c.subject, c.delay, c.total, c.sent, c.failed,
                       c.status, c.stop_requested, c.pause_requested, c.last_error,
                       c.created_at, c.finished_at, COALESCE(pr.pending_count, 0) AS pending_count
                FROM campaigns c
                {_PENDING_RECIPIENTS_JOIN}
                ORDER BY (c.status = 'running') DESC, c.id DESC
            """)
            rows = [_with_resume_flag(r) for r in cur.fetchall()]
    return jsonify({'campaigns': rows})


@app.route('/campaigns/pause', methods=['POST'])
@role_required('operator')
def pause_campaign():
    cid = request.form.get('id', '').strip()
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE campaigns SET pause_requested = TRUE, status = 'pausing'
                 WHERE id = %s AND status = 'running'
            """, (cid,))
    return jsonify({'status': 'success'})


@app.route('/campaigns/resume', methods=['POST'])
@role_required('operator')
def resume_campaign():
    cid = request.form.get('id', '').strip()
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM campaigns WHERE id = %s", (cid,))
            row = cur.fetchone()
    if not row or row['status'] not in ('paused', 'interrupted', 'stopped'):
        return jsonify({'status': 'error', 'message': 'Campaign is not resumable.'}), 400
    camp = dict(row)

    if not camp.get('template'):
        return jsonify({'status': 'error', 'message':
            'This campaign predates message-content tracking, so its original email '
            'body is unknown — resume is not available. Launch a new campaign instead; '
            'selecting recipients by "not yet sent" status will skip anyone this one '
            'already emailed.'}), 400

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT COUNT(*) AS cnt FROM campaign_recipients
                WHERE campaign_id = %s AND status = 'pending'
            """, (cid,))
            pending_count = cur.fetchone()['cnt']

    if pending_count == 0:
        # Best-effort fallback for a campaign that predates per-recipient tracking
        # (or one whose original list is fully processed): re-derive candidates from
        # a group chosen now, excluding anyone already emailed under this label.
        group = request.form.get('group', '').strip()
        if not group and request.form.get('confirm_all') != '1':
            return jsonify({'status': 'needs_setup', 'message':
                "This campaign's original recipient list can't be recovered — "
                'choose a group (or confirm "all users") to resume into.'}), 409

        all_users = load_users()
        candidates = [u for u in all_users if not group or u['group'] == group]
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT DISTINCT LOWER(email) AS email FROM email_log WHERE campaign = %s",
                            (camp['name'],))
                already_sent = {r['email'] for r in cur.fetchall()}
        candidates = [u for u in candidates if u['email'].strip().lower() not in already_sent]

        if not candidates:
            return jsonify({'status': 'error',
                             'message': 'No matching, not-yet-emailed users found to resume into.'}), 400

        with get_db() as conn:
            with conn.cursor() as cur:
                cur.executemany("""
                    INSERT INTO campaign_recipients
                        (campaign_id, username, first_name, last_name, email, token, track_open, status)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,'pending')
                """, [(cid, u['username'], u['first_name'], u['last_name'], u['email'],
                       u['token'], u.get('track_open', 'no')) for u in candidates])
                cur.execute("""
                    UPDATE campaigns SET total = total + %s,
                        recipient_filter = recipient_filter || %s
                    WHERE id = %s
                """, (len(candidates),
                      f" · resumed into: {group or 'all groups'} ({len(candidates)})", cid))

    cfg = get_smtp_config(camp['smtp_config_id'])
    if not cfg:
        return jsonify({'status': 'error',
                         'message': 'Original SMTP config no longer exists — add one under SMTP, then retry.'}), 400

    _campaign_update(cid, status='running', stop_requested=False, pause_requested=False, last_error='')
    thread = threading.Thread(
        target=_run_campaign,
        args=(cid, camp['template'], camp['subject'], camp['link_text'] or 'Click here',
              cfg, camp['delay'], camp['name'], camp['landing_page_id']),
        daemon=True,
    )
    thread.start()
    return jsonify({'status': 'success'})


@app.route('/campaigns/stop', methods=['POST'])
@role_required('operator')
def stop_campaign():
    cid = request.form.get('id', '').strip()
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE campaigns SET stop_requested = TRUE, status = 'stopping'
                 WHERE id = %s AND status IN ('running', 'pausing')
            """, (cid,))
            # No live worker for these — stop can flip them straight to terminal.
            cur.execute("""
                UPDATE campaigns SET status = 'stopped', stop_requested = TRUE, finished_at = %s
                 WHERE id = %s AND status IN ('paused', 'interrupted')
            """, (_utcnow(), cid))
    return jsonify({'status': 'success'})


@app.route('/campaigns/delete', methods=['POST'])
@role_required('operator')
def delete_campaign():
    cid = request.form.get('id', '').strip()
    with get_db() as conn:
        with conn.cursor() as cur:
            # Don't delete a live job out from under its worker.
            cur.execute("DELETE FROM campaigns WHERE id = %s AND status NOT IN ('running', 'pausing')", (cid,))
    return redirect(url_for('campaigns'))


@app.route('/campaigns/bulk-delete', methods=['POST'])
@role_required('operator')
def bulk_delete_campaigns():
    """Delete several campaign records at once. Running campaigns are always
    skipped (same guard as the single-delete route) so a bulk click can never
    pull a live send out from under its worker thread."""
    payload = request.get_json(silent=True) or {}
    raw_ids = payload.get('ids') or request.form.getlist('ids')
    ids = [int(i) for i in (str(x).strip() for x in raw_ids) if i.isdigit()]
    if not ids:
        return jsonify({'status': 'error', 'message': 'No campaign ids given'}), 400

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                DELETE FROM campaigns WHERE id = ANY(%s) AND status NOT IN ('running', 'pausing')
                RETURNING id
            """, (ids,))
            deleted_ids = [r['id'] for r in cur.fetchall()]

    skipped = len(ids) - len(deleted_ids)
    return jsonify({'status': 'success', 'deleted': deleted_ids, 'skipped': skipped})


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


@app.route('/export/submissions.csv')
@login_required
def export_submissions_csv():
    """One row per submission (not grouped by victim) so every entry a user
    submitted is exported, not just their latest."""
    scanner_clause = "" if _show_scanner_hits() else "WHERE s.is_scanner = FALSE"
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(f"""
                SELECT u.username, u.first_name, u.last_name, u.email AS victim_email,
                       u.grp AS "group",
                       s.name AS sub_name, s.email AS sub_email, s.phone, s.id_value,
                       s.comment, s.campaign, lp.name AS landing_name, s.ip,
                       s.timestamp::text AS timestamp, s.is_scanner, s.scanner_vendor
                FROM submissions s
                LEFT JOIN users u          ON u.token = s.token
                LEFT JOIN landing_pages lp ON lp.id   = s.landing_id
                {scanner_clause}
                ORDER BY s.timestamp
            """)
            rows = cur.fetchall()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Username', 'First Name', 'Last Name', 'Victim Email', 'Group',
                      'Submitted Name', 'Submitted Email', 'Phone', 'ID Value', 'Comment',
                      'Campaign', 'Landing Page', 'IP Address', 'Timestamp',
                      'Scanner Hit', 'Scanner Vendor'])
    for r in rows:
        writer.writerow([r['username'], r['first_name'], r['last_name'], r['victim_email'],
                          r['group'], r['sub_name'], r['sub_email'], r['phone'], r['id_value'],
                          r['comment'], r['campaign'], r['landing_name'], r['ip'], r['timestamp'],
                          'yes' if r['is_scanner'] else 'no', r['scanner_vendor']])

    response = make_response(output.getvalue())
    response.headers["Content-Disposition"] = "attachment; filename=submissions_report.csv"
    response.headers["Content-type"] = "text/csv"
    return response


@app.route('/export/report.csv')
@login_required
def export_report_csv():
    """Mirrors the enriched /report table exactly (same _build_report()), so
    what's exported always matches what's on screen."""
    enriched, _summary, _group_breakdown = _build_report()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Username', 'First Name', 'Last Name', 'Email', 'Group',
                      'Email Sent', 'Opened', 'Total Opens', 'Clicked', 'Total Clicks',
                      'IP Addresses', 'Submitted', 'Total Submissions', 'Campaigns',
                      'Last Activity'])
    for u in enriched:
        writer.writerow([u['username'], u['first_name'], u['last_name'], u['email'], u['group'],
                          'yes' if u['email_sent'] else 'no',
                          'yes' if u['opened'] else 'no', u['total_opens'],
                          'yes' if u['link_clicked'] else 'no', u['total_clicks'], u['ips'],
                          'yes' if u['submitted'] else 'no', u['total_submissions'],
                          u['campaigns'], u['last_activity']])

    response = make_response(output.getvalue())
    response.headers["Content-Disposition"] = "attachment; filename=report.csv"
    response.headers["Content-type"] = "text/csv"
    return response


# ── Bootstrap ─────────────────────────────────────────────────────────────────

init_db()

if __name__ == '__main__':
    # threaded=True so the UI (campaign status polling, etc.) stays responsive
    # while background sender threads are running.
    app.run(host='0.0.0.0', port=5001, threaded=True)
