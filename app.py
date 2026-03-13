from flask import Flask, request, redirect, render_template, send_file, session, url_for, make_response, jsonify
import csv, uuid, json
from datetime import datetime, timezone
import os, io, time
from functools import wraps
from werkzeug.utils import secure_filename
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

app = Flask(__name__)
app.secret_key = 'Cybefix@123'  # Change this to a random secret key in production

USER_FILE = "users.csv"
CLICK_FILE = "clicks.csv"
OPEN_FILE = "opens.csv"
EMAIL_LOG = "emails_sent.csv"
TEMPLATES_FILE = "email_templates.json"

SMTP_SERVER = 'smtp.hostinger.com'
SMTP_PORT = 587
SMTP_USER = 'rl'
SMTP_PASS = 'R'


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


# Ensure user file exists with full schema
if not os.path.exists(USER_FILE):
    with open(USER_FILE, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['username', 'first_name', 'last_name', 'email', 'group', 'token', 'link', 'track_open'])


# --- Utility functions ---

def load_users():
    with open(USER_FILE, 'r') as f:
        reader = csv.DictReader(f)
        users = []
        for row in reader:
            cleaned_row = {k: v.strip() for k, v in row.items()}
            cleaned_row.setdefault('track_open', 'no')
            users.append(cleaned_row)
        return users


def save_user(data):
    with open(USER_FILE, 'a', newline='') as f:
        csv.writer(f).writerow(data)


def get_user_by_username(username):
    for u in load_users():
        if u['username'] == username:
            return u
    return None


def generate_link(user):
    existing = get_user_by_username(user['username'])
    if existing:
        return existing['token'], existing['link']
    token = str(uuid.uuid4())
    link = f"https://track.example.org/hit?uid={token}"
    row = [
        user['username'], user['first_name'], user['last_name'],
        user['email'], user['group'], token, link,
        user.get('track_open', 'no')
    ]
    save_user(row)
    return token, link


def load_templates():
    if os.path.exists(TEMPLATES_FILE):
        with open(TEMPLATES_FILE, 'r') as f:
            return json.load(f)
    return {}


def save_templates(templates):
    with open(TEMPLATES_FILE, 'w') as f:
        json.dump(templates, f, indent=2)


# --- Auth ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = request.form.get('username')
        pwd = request.form.get('password')
        if user == 'admin' and pwd == 'admin123':
            session['logged_in'] = True
            return redirect(url_for('dashboard'))
        return render_template('login.html', error="Invalid credentials.")
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))


# --- Index ---

@app.route('/')
def index():
    return "<h3>RabbitHole is live. Use /generate, /users, /dashboard, /report</h3>"


# --- Generate ---

@app.route('/generate', methods=['GET', 'POST'])
@login_required
def generate():
    if request.method == 'POST':
        username = request.form['username'].strip()
        first = request.form['first_name'].strip()
        last = request.form['last_name'].strip()
        email = request.form['email'].strip()
        group = request.form['group'].strip()
        track_open = 'yes' if request.form.get('track_open') else 'no'

        user = {
            'username': username,
            'first_name': first,
            'last_name': last,
            'email': email,
            'group': group,
            'track_open': track_open
        }

        # Check if user already exists
        for existing in load_users():
            if (existing['username'] == username and
                    existing['first_name'] == first and
                    existing['last_name'] == last and
                    existing['email'] == email):
                token = existing['token']
                link = existing['link']
                pixel_url = f"https://track.example.org/img/{token}.png" if existing.get('track_open') == 'yes' else None
                return render_template('generate.html', user=existing, token=token, link=link,
                                       pixel_url=pixel_url,
                                       message="✅ User already exists. Showing existing tracking link.")

        token = str(uuid.uuid4())
        link = f"https://track.example.org/hit?uid={token}"
        row = [username, first, last, email, group, token, link, track_open]
        save_user(row)

        pixel_url = f"https://track.example.org/img/{token}.png" if track_open == 'yes' else None
        return render_template('generate.html', user=user, token=token, link=link,
                               pixel_url=pixel_url,
                               message="✅ New tracking link generated.")

    return render_template('generate.html')


# --- Users ---

@app.route('/users')
@login_required
def users():
    return render_template('users.html', users=load_users())


@app.route('/users.csv')
@login_required
def serve_users_csv():
    return send_file(USER_FILE, mimetype='text/csv')


# --- Tracking endpoints ---

@app.route('/hit')
def hit():
    token = request.args.get("uid")
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    if ',' in ip:
        ip = ip.split(',')[0].strip()
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    with open(CLICK_FILE, 'a', newline='') as f:
        csv.writer(f).writerow([token, ts, ip])
    return redirect("https://intranet.example.com/thank-you")


@app.route('/img/<uid>.png')
def img(uid):
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    if ',' in ip:
        ip = ip.split(',')[0].strip()
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    with open(OPEN_FILE, 'a', newline='') as f:
        csv.writer(f).writerow([uid, ts, ip])
    return send_file("static/pixel.png", mimetype='image/png')


# --- Dashboard ---

@app.route('/dashboard')
@login_required
def dashboard():
    users = load_users()
    user_map = {u['token']: u for u in users}

    try:
        with open(CLICK_FILE, 'r') as f:
            click_data = list(csv.reader(f))
    except FileNotFoundError:
        click_data = []

    enriched_clicks = []
    for row in click_data:
        if len(row) < 3:
            continue
        token, ts, ip = row
        user = user_map.get(token, {})
        enriched_clicks.append([
            user.get('first_name', ''), user.get('last_name', ''),
            user.get('email', ''), token, ts, ip
        ])

    try:
        with open(EMAIL_LOG, 'r') as f:
            email_log = list(csv.reader(f))
    except FileNotFoundError:
        email_log = []

    sent_emails = set(row[1] for row in email_log if len(row) >= 2)
    sent_count = sum(1 for u in users if u['email'] in sent_emails)
    pending_count = len(users) - sent_count

    try:
        with open(OPEN_FILE, 'r') as f:
            open_data = list(csv.reader(f))
    except Exception:
        open_data = []

    stats = {
        'total_users': len(users),
        'emails_sent': len(email_log),
        'emails_opened': len(set(row[0] for row in open_data if row)),
        'links_clicked': len(set(row[0] for row in click_data if row))
    }

    return render_template('dashboard.html', clicks=enriched_clicks, stats=stats,
                           email_sent=sent_count, email_pending=pending_count)


# --- API endpoints ---

@app.route('/api/clicks')
@login_required
def api_clicks():
    users = load_users()
    user_map = {u['token']: u for u in users}

    try:
        with open(CLICK_FILE, 'r') as f:
            click_data = list(csv.reader(f))
    except Exception:
        click_data = []

    latest_clicks = {}
    for row in click_data:
        if len(row) < 3:
            continue
        token, ts, ip = row
        if token not in latest_clicks or ts > latest_clicks[token]['timestamp']:
            latest_clicks[token] = {'timestamp': ts, 'ip': ip}

    enriched = []
    for token, data in latest_clicks.items():
        user = user_map.get(token, {})
        enriched.append({
            'first_name': user.get('first_name', ''),
            'last_name': user.get('last_name', ''),
            'email': user.get('email', ''),
            'group': user.get('group', ''),
            'token': token,
            'timestamp': data['timestamp'],
            'ip': data['ip']
        })

    return {'clicks': enriched}


@app.route('/api/repeats')
@login_required
def api_repeats():
    users = load_users()
    user_map = {u['token']: u for u in users}

    try:
        with open(CLICK_FILE, 'r') as f:
            click_data = list(csv.reader(f))
    except Exception:
        click_data = []

    token_clicks = {}
    for row in click_data:
        if len(row) < 3:
            continue
        token, ts, ip = row
        token_clicks.setdefault(token, []).append((ts, ip))

    enriched = []
    for token, records in token_clicks.items():
        if len(records) <= 1:
            continue
        timestamps = [r[0] for r in records]
        ips = [r[1] for r in records]
        user = user_map.get(token, {})
        enriched.append({
            'first_name': user.get('first_name', ''),
            'last_name': user.get('last_name', ''),
            'email': user.get('email', ''),
            'group': user.get('group', ''),
            'token': token,
            'clicks': len(records),
            'first_click': timestamps[0],
            'last_click': timestamps[-1],
            'ip_list': list(set(ips))
        })

    return {'repeats': enriched}


# --- Report ---

@app.route('/report')
@login_required
def report():
    users = load_users()

    try:
        with open(CLICK_FILE, 'r') as f:
            click_data = list(csv.reader(f))
    except Exception:
        click_data = []

    try:
        with open(EMAIL_LOG, 'r') as f:
            email_data = list(csv.reader(f))
    except Exception:
        email_data = []

    email_sent_emails = set(row[1].strip().lower() for row in email_data if len(row) >= 2)
    token_click_map = {}
    token_ip_map = {}

    for row in click_data:
        if len(row) >= 3:
            token, timestamp, ip = row
            token_click_map.setdefault(token, []).append((timestamp, ip))
            token_ip_map.setdefault(token, set()).add(ip)

    enriched = []
    for u in users:
        token = u.get('token', '')
        email = u.get('email', '').strip().lower()
        enriched.append({
            'username': u.get('username', ''),
            'first_name': u.get('first_name', ''),
            'last_name': u.get('last_name', ''),
            'email': email,
            'token': token,
            'email_sent': '✅' if email in email_sent_emails else '❌',
            'link_clicked': '✅' if token in token_click_map else '❌',
            'total_clicks': len(token_click_map.get(token, [])),
            'ips': ', '.join(token_ip_map.get(token, []))
        })

    return render_template("report.html", users=enriched, clicks=click_data)


# --- Import ---

@app.route('/import', methods=['GET', 'POST'])
@login_required
def import_users():
    message = ""
    if request.method == 'POST':
        file = request.files.get('file')
        group_override = request.form.get('group_override', '').strip()

        if file and file.filename.endswith('.csv'):
            filepath = os.path.join('uploads', secure_filename(file.filename))
            os.makedirs('uploads', exist_ok=True)
            file.save(filepath)

            count = 0
            with open(filepath, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    group = group_override or row.get('group', '').strip()
                    user = {
                        'username': row['username'].strip(),
                        'first_name': row['first_name'].strip(),
                        'last_name': row['last_name'].strip(),
                        'email': row['email'].strip(),
                        'group': group,
                        'track_open': 'no'
                    }
                    generate_link(user)
                    count += 1

            message = f"✅ {count} users imported successfully."
        else:
            message = "Please upload a valid CSV file."

    return render_template('import.html', message=message)


# --- Reset analytics ---

@app.route('/reset-analytics', methods=['POST'])
@login_required
def reset_analytics():
    open(CLICK_FILE, 'w').close()
    open(OPEN_FILE, 'w').close()
    open(EMAIL_LOG, 'w').close()
    return {'status': 'success', 'message': 'Analytics reset'}


# --- Email template management ---

@app.route('/save-template', methods=['POST'])
@login_required
def save_template():
    name = request.form.get('template_name', '').strip()
    content = request.form.get('template_content', '')
    if not name:
        return jsonify({'status': 'error', 'message': 'Template name required'}), 400
    templates = load_templates()
    templates[name] = content
    save_templates(templates)
    return jsonify({'status': 'success'})


@app.route('/delete-template', methods=['POST'])
@login_required
def delete_template():
    name = request.form.get('template_name', '').strip()
    templates = load_templates()
    templates.pop(name, None)
    save_templates(templates)
    return jsonify({'status': 'success'})


@app.route('/email-template', methods=['GET', 'POST'])
@login_required
def email_template():
    all_users = load_users()

    email_sent_map = {}
    if os.path.exists(EMAIL_LOG):
        with open(EMAIL_LOG, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                email = row['email'].strip().lower()
                email_sent_map[email] = email_sent_map.get(email, 0) + 1

    for u in all_users:
        u['sent_count'] = email_sent_map.get(u['email'].strip().lower(), 0)

    groups = sorted(set(u['group'] for u in all_users if u.get('group')))
    selected_group = request.form.get('group') if request.method == 'POST' else None
    selected_usernames = request.form.getlist('usernames')
    template_text = request.form.get('template', '')
    generated = []

    users = [u for u in all_users if u['group'] == selected_group] if selected_group else []

    if request.method == 'POST' and request.form.get('action') == 'generate':
        for u in users:
            if u['username'] in selected_usernames:
                link_url = f"https://track.example.org/hit?uid={u['token']}"
                pixel_url = f"https://track.example.org/img/{u['token']}.png"
                pixel_tag = f'<img src="{pixel_url}" width="1" height="1" style="display:none;" alt="">'
                track_open = u.get('track_open') == 'yes'
                body = template_text.replace("{{first_name}}", u['first_name']) \
                                    .replace("{{last_name}}", u['last_name']) \
                                    .replace("{{email}}", u['email']) \
                                    .replace("{{token}}", u['token']) \
                                    .replace("{{link}}", f'<a href="{link_url}">Click here</a>') \
                                    .replace("{{pixel}}", pixel_tag if track_open else '')
                if track_open and pixel_url not in body:
                    body += pixel_tag
                generated.append({'email': u['email'], 'body': body})

    saved_templates = load_templates()
    return render_template("email_template.html", groups=groups, users=users,
                           selected_group=selected_group, template_text=template_text,
                           generated=generated, saved_templates=saved_templates)


# --- Send emails ---

@app.route('/send-emails', methods=['POST'])
@login_required
def send_emails():
    selected_usernames = request.form.getlist('usernames')
    template = request.form.get('template')
    delay = int(request.form.get('delay', 5))

    if not selected_usernames:
        return render_template("email_sent_summary.html", sent=[], count=0, message="❌ No users selected.")

    all_users = load_users()
    users_to_send = [u for u in all_users if u['username'] in selected_usernames]
    sent = []

    if not os.path.exists(EMAIL_LOG):
        with open(EMAIL_LOG, 'w', newline='') as f:
            csv.writer(f).writerow(['username', 'email', 'timestamp'])

    def log_email_sent(username, email, timestamp):
        with open(EMAIL_LOG, 'a', newline='') as f:
            csv.writer(f).writerow([username, email, timestamp])

    for user in users_to_send:
        to_email = user['email']
        link_url = user['link']
        track_open = user.get('track_open') == 'yes'
        pixel_url = f"https://track.example.org/img/{user['token']}.png"
        pixel_tag = f'<img src="{pixel_url}" width="1" height="1" style="display:none;" alt="">'

        body = template.replace("{{first_name}}", user['first_name']) \
                       .replace("{{last_name}}", user['last_name']) \
                       .replace("{{email}}", user['email']) \
                       .replace("{{token}}", user['token']) \
                       .replace("{{link}}", f'<a href="{link_url}">CHECK AND VERIFY SALARY SLIP</a>') \
                       .replace("{{pixel}}", pixel_tag if track_open else '')

        # Auto-inject pixel only if user opted in and placeholder wasn't used
        if track_open and pixel_url not in body:
            body += pixel_tag

        msg = MIMEMultipart("alternative")
        msg["Subject"] = "[Update] New Salary Format - Update Details"
        msg["From"] = SMTP_USER
        msg["To"] = to_email
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

    return render_template("email_sent_summary.html", sent=sent, count=len(sent), message="✅ Emails sent.")


# --- Sent status ---

@app.route('/sent-status')
@login_required
def sent_status():
    try:
        with open(EMAIL_LOG, 'r') as f:
            records = list(csv.reader(f))
    except FileNotFoundError:
        records = []
    return render_template("sent_status.html", records=records)


# --- Export ---

@app.route('/export/csv')
@login_required
def export_csv():
    users = load_users()
    try:
        with open(CLICK_FILE, 'r') as f:
            clicks = list(csv.reader(f))
    except Exception:
        clicks = []

    user_map = {u['token']: u for u in users}
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['First Name', 'Last Name', 'Email', 'Token', 'Click Time', 'IP Address'])

    for row in clicks:
        if len(row) < 3:
            continue
        token, ts, ip = row
        user = user_map.get(token, {})
        writer.writerow([
            user.get('first_name', ''), user.get('last_name', ''),
            user.get('email', ''), token, ts, ip
        ])

    response = make_response(output.getvalue())
    response.headers["Content-Disposition"] = "attachment; filename=click_report.csv"
    response.headers["Content-type"] = "text/csv"
    return response


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5001)
