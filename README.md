# Rabbit Hole — Phishing-Simulation Tracker & Emailer

**Rabbit Hole** is an **open-source phishing simulation and awareness platform** built for **beginners** in cybersecurity.  
It helps users learn how phishing works, how attackers track user interactions, and how organizations can build awareness.  

⚠️ **Disclaimer**: Rabbit Hole is designed for **educational and research purposes only**.  
Please use it responsibly, only in **legal environments** (labs, awareness training, or with proper permissions).

## Features

- Import or create users and generate unique tracking links  
- Compose and **send emails in bulk** with a custom per-message delay  
- Track **opens** (via pixel) and **link clicks** (via redirect)  
- View a live **dashboard** (charts + tables), including **repeated clicks** and **repeated emails**  
- Export a client-friendly CSV report  
- Configure **SMTP** (STARTTLS/SSL/None) from a secure admin UI

---

## Quick Start

```bash
# 1) (recommended) create a virtualenv
python3 -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate

# 2) install dependencies
pip install Flask

# 3) run the server (dev)
python3 app.py
# -> http://127.0.0.1:5000
```

**Default login:** `admin / admin123` → change this in `app.py` ASAP.

---

## Project Structure

```
app.py                         # Flask application
templates/
  dashboard.html               # Dashboard + charts
  email_template.html          # Build & send emails
  email_sent_summary.html      # Send summary page
  generate.html                # Manual single-user token/link generator
  import.html                  # Bulk import UI
  login.html                   # Login
  report.html                  # Raw data view
  sent_status.html             # Sent-log viewer
  smtp_settings.html           # SMTP configuration UI
static/
  pixel.png                    # Tracking pixel (1x1 png)
uploads/                       # CSV files you upload (created at runtime)
users.csv                      # Master user list (created at runtime)
clicks.csv                     # Link click logs (created at runtime)
opens.csv                      # Open/pixel logs (created at runtime)
emails_sent.csv                # Outbound email log (created at runtime)
smtp_settings.json             # Saved SMTP credentials/settings (created at runtime)
```

---

## Data Files

All data is plain CSV/JSON for easy auditing.

- **users.csv**  
  `username,first_name,last_name,email,group,token,link`

- **clicks.csv**  
  Each row on tracked click: `[token, timestamp_utc, ip]`

- **opens.csv**  
  Each row on tracking-pixel load: `[token, timestamp_utc, ip]`

- **emails_sent.csv**  
  Each successful send: `[username, email, timestamp_utc]`

- **smtp_settings.json** (saved via `/smtp-settings`)
  ```json
  {
    "server": "smtp.example.com",
    "port": 587,
    "username": "user@example.com",
    "password": "•••",
    "security": "starttls",        // "starttls" | "ssl" | "none"
    "from_email": "user@example.com",
    "from_name": "Rabbit Hole",
    "default_subject": "Phishing Awareness"
  }
  ```

> **Reset Analytics** clears **clicks.csv**, **opens.csv**, and **emails_sent.csv**.  
> It does **not** remove `users.csv` or `smtp_settings.json`.

---

## Core Features

### 1) Users & Unique Links
- **Generate** (`/generate`) — Creates a user with a stable `token` and `link`:  
  `https://<your-host>/hit?uid=<token>`
- **Bulk Import** (`/import`) — Upload CSV with headers exactly:  
  `username,first_name,last_name,email,group`  
  Missing tokens/links are created automatically.

### 2) Email Template & Sending
- **Email Template** (`/email-template`)  
  - Select **Group**, see users in a searchable/sortable table with **Select All**  
  - Filter users **Sent/Pending** (driven by `emails_sent.csv`)  
  - Compose HTML using placeholders:
    - `{{first_name}}`, `{{last_name}}`, `{{email}}`, `{{token}}`, `{{link}}`
  - Set **delay** (seconds) between messages
  - **Generate** (preview) or **Send** (via SMTP)

- **SMTP Settings** (`/smtp-settings`)  
  - Modes: **STARTTLS** (587), **SSL/TLS** (465), or **None**  
  - Set From name/email, default subject, and **send test**  
  - Saved to `smtp_settings.json`, used by `/send-emails`

### 3) Tracking
- **Clicks**: `/hit?uid=<token>` → logs to `clicks.csv`, then redirects to your landing page
- **Opens**: `/img/<uid>.png` → logs to `opens.csv` and serves `static/pixel.png`

### 4) Dashboard & Analytics
- **Dashboard** (`/dashboard`) shows:
  - **Stats cards**: Total Users, Emails Sent, Emails Opened, Links Clicked
  - **Filters**: by Group and Click Status (Clicked/Not Clicked)
  - **Charts**:
    - Clicks vs Not Clicks (pie)
    - Clicks by Group (bar)
    - Emails **Sent vs Pending** (pie; pending = users without any row in `emails_sent.csv`)
  - **Tables**:
    - Latest Clicks (user-enriched)
    - **Repeated Clicks** (users with >1 click)
    - **Repeated Emails** (users emailed >1 time)

### 5) Reporting
- **Export CSV** (`/export/csv`) — Client-friendly export including:
  ```
  Username | First_name | Last_name | Email | Token
  | Email sent status | Link_clicked status
  | Total times Users Clicked | IP addresses
  ```
  Sorted by repeated clicks desc, then single clicks, etc.
- **Raw view** (`/report`) — Quick internal inspection.

---

## Routes (Overview)

- **Auth:** `GET/POST /login`, `GET /logout`
- **Users:** `GET/POST /generate`, `GET/POST /import`, `GET /users`, `GET /users.csv`
- **Dash/Reports:** `GET /dashboard`, `GET /report`, `POST /reset-analytics`
- **Email:** `GET/POST /email-template`, `POST /send-emails`, `GET /sent-status`, `GET/POST /smtp-settings`
- **Tracking:** `GET /hit?uid=<token>`, `GET /img/<uid>.png`
- **APIs for dashboard:**  
  `GET /api/clicks` (latest click per token)  
  `GET /api/repeats` (clicks > 1)  
  `GET /api/repeat-emails` (emails > 1) *(include this if you added the route)*

---

## Email Templating

Supported placeholders inside **Email Template (HTML)**:

- `{{first_name}}`
- `{{last_name}}`
- `{{email}}`
- `{{token}}`
- `{{link}}`

**Example**
```html
<p>Hello {{first_name}},</p>
<p>Please review your information here: {{link}}</p>
```

---

## SMTP Behavior

- The app reads `smtp_settings.json`. If missing, it may fall back to defaults in `app.py`.
- Security modes:
  - **STARTTLS** (recommended, port 587)
  - **SSL/TLS** (port 465)
  - **None** (for local/lab SMTP servers)
- **Delay** between messages helps avoid throttling and reduces server spikes.

---

## Security Notes

- Change `app.secret_key`, default admin credentials, and keep secrets out of source (env vars recommended).
- Keep `/smtp-settings` and `/email-template` behind login (already enforced).
- For public deployments, use a production WSGI server + reverse proxy (TLS).
- Consider IP allow-lists/VPN/SSO for internal simulations.
- Ensure proper file permissions & retention on CSV/JSON logs.

---

## Deployment (Production)

- **Gunicorn**
  ```bash
  pip install gunicorn
  gunicorn -w 4 -b 0.0.0.0:5000 app:app
  ```
- Put **nginx** in front for TLS + static caching.
- Use persistent storage for `*.csv`, `smtp_settings.json`, `uploads/`.

---

## Troubleshooting

- **Import KeyError on `/email-template`**  
  Ensure CSV headers are exactly: `username,first_name,last_name,email,group`.

- **Emails not sending**  
  - Check `/smtp-settings` (server, port, security, credentials).
  - Use **Send Test**.
  - Confirm your provider allows SMTP & credentials are valid.
  - Inspect server logs for exceptions.

- **Charts don’t update**  
  - Refresh after sending/resetting analytics.
  - Verify the existence/permissions of `emails_sent.csv`, `clicks.csv`, `opens.csv`.

- **Report ordering/merge duplicates**  
  The export route builds a client-friendly CSV, sorted by repeated clicks, merging duplicates without deleting raw rows.

---

## License

Choose a license appropriate for your organization (e.g., MIT) or keep proprietary.

---

## Contributing

Contributions are welcome!
- Fork this repo
- Create a new branch (feature-xyz)
- Commit and push your changes
- Open a Pull Request 🚀

---

## Credits

Built for internal phishing simulations and awareness campaigns.  
**“Rabbit Hole”** name courtesy of you 🐇🕳️.

---
## Author

Rabbit Hole was developed and open-sourced by:

Cybefox (Yuvraj Todankar)
📧 cyberoninsider@gmail.com
