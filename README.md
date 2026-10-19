# Rabbit Hole — Phishing-Simulation Tracker & Emailer

**Rabbit Hole** is an **open-source phishing simulation and awareness platform** built for **beginners** in cybersecurity.  
It helps users learn how phishing works, how attackers track user interactions, and how organizations can build awareness.  

⚠️ **Disclaimer**: Rabbit Hole is designed for **educational and research purposes only**.  
Please use it responsibly, only in **legal environments** (labs, awareness training, or with proper permissions).

## Features

- **Multi-user, role-based access** — admin / operator / viewer accounts (see [User Roles & Accounts](#user-roles--accounts))
- Import or create targets and generate unique, per-target tracking links
- **Multiple SMTP profiles** (STARTTLS/SSL/None) managed in the UI, selectable per send
- Compose HTML emails and **launch campaigns as background jobs** — several run concurrently, with a custom per-message delay
- **Campaign tagging** so multiple templates/campaigns can run at once and be compared
- Track **opens** (pixel), **link clicks** (redirect), and **data-entry submissions** (landing pages)
- **Landing pages** that capture name & email to confirm a target went past the click
- Live **dashboard** (charts + tables) with per-campaign breakdown, repeated clicks, and repeated emails
- **Campaign monitor** with live progress + a per-campaign detail view
- **Telemetry**: repeat offenders (clicked across multiple campaigns) and a captured-submissions log
- Export a client-friendly CSV report
- PostgreSQL-backed; secrets and deployment settings via environment variables

---

## Quick Start

```bash
# 1) (recommended) create a virtualenv
python3 -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate

# 2) install dependencies
pip install -r requirements.txt   # Flask + psycopg2 (PostgreSQL)

# 3) point at a PostgreSQL database (tables are created automatically on first run)
export DATABASE_URL='postgresql://user:pass@localhost/rabbithole'

# 4) run the server (dev)
python3 app.py
# -> http://127.0.0.1:5001
```

**First login:** on first run an **admin** account is bootstrapped. Its username is
`RABBITHOLE_ADMIN_USER` (default `admin`); its password is `RABBITHOLE_ADMIN_PASS` if
set, otherwise a **strong random password is generated and printed to the console once**.
Log in, change the password, then create the rest of your accounts under **Accounts**.
See [Environment Variables](#environment-variables) and
[User Roles & Accounts](#user-roles--accounts).

> **Note:** data now lives in **PostgreSQL**, not CSV files. Legacy `*.csv` /
> `email_templates.json` found at startup are imported once and renamed `*.migrated`.

---

## Environment Variables

All secrets and deployment-specific settings come from the environment. The
fallbacks keep local dev working but **must** be overridden in any real deployment.

| Variable | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | `postgresql://localhost/rabbithole` | PostgreSQL connection string. |
| `RABBITHOLE_SECRET_KEY` | `dev-insecure-change-me` | Flask session signing key. Set a long random value. |
| `RABBITHOLE_ADMIN_USER` | `admin` | Username for the bootstrap admin account (first run only). |
| `RABBITHOLE_ADMIN_PASS` | _random, printed once_ | Password for the bootstrap admin account (first run only). If unset, a strong random password is generated and printed to the console. |
| `TRACKING_BASE_URL` | `http://127.0.0.1:5001` | Public base URL embedded in tracking links/pixels. Set to your reachable host. |
| `REDIRECT_URL` | `https://example.com/` | Where `/hit` redirects when a click carries no landing page. |
| `SMTP_SERVER` / `SMTP_PORT` / `SMTP_USER` / `SMTP_PASS` | empty / `587` | Optional legacy SMTP fallback. Normally you configure SMTP in the UI instead (stored in the `smtp_configs` table). |

> The bootstrap admin is created **only when no accounts exist yet**. Once accounts
> exist, changing `RABBITHOLE_ADMIN_*` has no effect — manage users from the UI.

---

## User Roles & Accounts

Access is controlled by **named operator accounts** (stored hashed in the
`accounts` table), each with one role. Roles are hierarchical — **admin ⊃ operator
⊃ viewer** — and enforced server-side on every route.

| Role | Can do |
|---|---|
| **viewer** | Read-only: dashboard, report, telemetry, submissions, sent log, target list & exports, campaign views, and read `/api/*`. |
| **operator** | Everything a viewer can, **plus** all campaign/content actions: generate, import, compose & send email, templates, SMTP configs, landing pages, reset analytics, stop/delete campaigns. |
| **admin** | Everything an operator can, **plus** account management (`/accounts`). |

**Managing accounts** (admin only): go to **Accounts** in the nav to create,
edit, disable, or delete accounts and assign roles. Any logged-in user can change
their own password there. Account creation is admin-only — there is no public
self-registration. Guards prevent deleting your own account or demoting/disabling/
deleting the **last active admin**. Disabled accounts cannot log in.

Nav links for actions a role cannot perform are hidden, and the login screen is
protected by a simple arithmetic CAPTCHA.

---

## Project Structure

```
app.py                         # Flask application (all routes + DB access)
requirements.txt               # Flask + psycopg2
templates/
  base.html                    # Shared layout + role-gated nav
  index.html                   # Landing / home
  login.html                   # Login (with CAPTCHA)
  403.html                     # Access-denied page
  dashboard.html               # Dashboard: stats, charts, campaign breakdown
  generate.html                # Single-target token/link generator
  import.html                  # Bulk CSV import
  users.html                   # Target list
  report.html / sent_status.html   # Raw report / sent-email log
  email_template.html          # Compose + launch campaign
  smtp_configs.html            # Manage SMTP profiles
  landing_pages.html           # Manage landing pages
  campaigns.html               # Live campaign monitor
  campaign_detail.html         # Per-campaign recipient breakdown
  telemetry.html               # Repeat offenders
  submissions.html             # Captured data-entry submissions
  accounts.html                # Operator account management (admin)
static/
  pixel.png                    # Tracking pixel (1x1 png)
  style.css                    # UI styles
uploads/                       # Uploaded import CSVs (created at runtime)
```

Data is stored in **PostgreSQL** (connection via `DATABASE_URL`). Tables are created
automatically on first run.

---

## Data Model (PostgreSQL)

| Table | Holds |
|---|---|
| `accounts` | Operator logins: `username`, `password_hash`, `role`, `active`, `last_login`. |
| `users` | **Targets** of simulations: `username, first_name, last_name, email, grp, token, link, track_open`. |
| `clicks` | One row per tracked click: `token, timestamp, ip, campaign`. |
| `opens` | One row per pixel load: `token, timestamp, ip, campaign`. |
| `email_log` | One row per successful send: `username, email, timestamp, campaign`. |
| `submissions` | Landing-page data entries: `token, campaign, landing_id, name, email, ip, timestamp`. |
| `templates` | Saved email templates: `name, content`. |
| `smtp_configs` | SMTP profiles: server/port/credentials/security/from/subject + `is_active`. |
| `landing_pages` | Landing pages: `name, html, thankyou`. |
| `campaigns` | Background send jobs: name, SMTP, subject, delay, totals, status, landing page, timestamps. |

The `campaign` column on `clicks`/`opens`/`email_log` is the campaign label, which ties
tracking back to a specific campaign.

> **Reset Analytics** (operator+) clears `clicks`, `opens`, `email_log`, and
> `submissions`. It does **not** touch `users`, `smtp_configs`, `landing_pages`,
> `templates`, `campaigns`, or `accounts`.

> **Legacy migration:** if `users.csv`, `clicks.csv`, `opens.csv`, `emails_sent.csv`, or
> `email_templates.json` are present at startup, they are imported once into the DB and
> renamed `*.migrated`.

---

## Core Features

### 1) Targets & Unique Links
- **Generate** (`/generate`) — creates a target with a stable `token` and tracking `link`
  (`<TRACKING_BASE_URL>/hit?uid=<token>`), optionally enabling open tracking (pixel).
- **Bulk Import** (`/import`) — upload a CSV with headers
  `username,first_name,last_name,email,group`. Required columns are validated; rows
  missing `username`/`email` are skipped and reported. Tokens/links are created
  automatically.

### 2) SMTP Profiles
- **SMTP** (`/smtp-configs`) — manage **multiple** sending profiles. Each has
  server/port, credentials, security (**STARTTLS** 587 / **SSL/TLS** 465 / **None**),
  From name/email, and a default subject. Mark one **active**, **test-send** any profile,
  and pick which profile to use per campaign.

### 3) Landing Pages (data-entry capture)
- **Landing** (`/landing-pages`) — author custom HTML pages with a `{{form}}`
  placeholder (plus `{{first_name}}`, `{{last_name}}`, `{{email}}`). When a campaign is
  launched with a landing page, clicking the link serves that page with a name/email
  form; submitting records a **submission** and shows a thank-you page. Links without a
  landing page simply redirect to `REDIRECT_URL`. Preview any page before use.

### 4) Email & Campaigns
- **Email** (`/email-template`) — select a **group**, see targets in a searchable table
  with **Select All** and a **Sent/Pending** filter (driven by `email_log`). Compose HTML
  using the placeholders below. Choose the **SMTP profile**, an optional **landing page**,
  a **campaign label**, subject, link text, and per-message **delay**. **Preview** renders
  the email; **Launch Campaign** starts a background send job and returns immediately.
- **Campaigns** (`/campaigns`) — live monitor of all send jobs (several can run at once),
  with progress bars and **Stop**/**Delete**. Click a campaign for a **detail view**
  (`/campaigns/<id>`) listing each recipient's sent / opened / clicked / **submitted**
  status.

### 5) Tracking
- **Clicks**: `/hit?uid=<token>&c=<campaign>&lp=<landing_id>` → logs to `clicks`, then
  either serves the landing page (if `lp` is set) or redirects to `REDIRECT_URL`.
- **Opens**: `/img/<uid>.png?c=<campaign>` → logs to `opens` and serves the pixel.
- **Submissions**: `POST /submit` → records landing-page data entry.

### 6) Dashboard & Analytics
- **Dashboard** (`/dashboard`): stat cards (Total Users, Sent, Opened, Clicked, Pending);
  Group/Click-Status filters; charts (Clicks vs Not Clicks, Clicks by Group); and tables
  for Click Events, **Repeated Clicks**, and a **Campaign Breakdown** (sent/opened/clicks/
  click-rate per campaign).
- **Telemetry** (`/telemetry`): **repeat offenders** — targets who clicked in more than
  one campaign — with a link to all **captured submissions** (`/submissions`).

### 7) Reporting
- **Export CSV** (`/export/csv`) — click report (name, email, token, click time, IP).
- **Raw view** (`/report`) and **Sent Log** (`/sent-status`) for quick inspection.

### 8) Accounts
- **Accounts** (`/accounts`, admin only) — manage operator logins and roles. See
  [User Roles & Accounts](#user-roles--accounts).

---

## Routes (Overview)

Access levels: **public**, **viewer+** (any logged-in user), **operator+**, **admin**.
See [User Roles & Accounts](#user-roles--accounts).

- **Public:** `GET/POST /login`, `GET /logout`, `GET /`, `GET /hit`, `GET /img/<uid>.png`, `POST /submit`
- **Viewer+ (read):** `GET /dashboard`, `/report`, `/telemetry`, `/submissions`, `/sent-status`, `/users`, `/users.csv`, `/export/csv`, `/campaigns`, `/campaigns/<id>`, and `GET /api/clicks | /api/repeats | /api/campaigns | /api/repeat-offenders | /api/campaign-status | /api/campaign/<id>`
- **Operator+ (write):** `GET/POST /generate`, `GET/POST /import`, `GET/POST /email-template`, `POST /send-emails`, `POST /save-template`, `POST /delete-template`, `POST /reset-analytics`, `POST /campaigns/stop`, `POST /campaigns/delete`, `/smtp-configs` (+ `/save` `/delete` `/activate` `/test`), `/landing-pages` (+ `/save` `/delete`, `/landing-pages/<id>/preview`)
- **Admin:** `GET /accounts`, `POST /accounts/save`, `POST /accounts/delete`, `POST /account/password` (self-service, any logged-in user)

---

## Email Templating

Supported placeholders inside the **Email Template (HTML)**:

- `{{first_name}}` · `{{last_name}}` · `{{email}}` · `{{token}}`
- `{{link}}` — rendered as an anchor to the tracking URL (text set by "Link Text")
- `{{pixel}}` — the open-tracking pixel (also auto-appended when open tracking is on)

**Example**
```html
<p>Hello {{first_name}},</p>
<p>Please review your information here: {{link}}</p>
{{pixel}}
```

Landing-page HTML supports `{{first_name}}`, `{{last_name}}`, `{{email}}`, and `{{form}}`.

---

## SMTP Behavior

- SMTP profiles live in the `smtp_configs` table and are managed at `/smtp-configs`.
  A campaign uses the profile selected at launch, or the **active** profile by default.
- Security modes: **STARTTLS** (587), **SSL/TLS** (465), **None** (local/lab servers).
- The `SMTP_*` environment variables are only an optional legacy fallback used to seed a
  first profile if none exist.
- **Delay** between messages helps avoid provider throttling. Running many campaigns at
  once means many simultaneous connections — tune delay/concurrency to your provider.

---

## Security Notes

- Set `RABBITHOLE_SECRET_KEY` to a long random value and change the bootstrap admin password after first login. Secrets come from the environment — keep them out of source. See [Environment Variables](#environment-variables).
- Account passwords are stored **hashed** (werkzeug) in the `accounts` table; access is role-gated (see [User Roles & Accounts](#user-roles--accounts)).
- All management/campaign routes are behind login + role checks; only `/`, `/login`, `/logout`, `/hit`, `/img`, and `/submit` are public.
- For public deployments, use a production WSGI server + reverse proxy (TLS).
- Consider IP allow-lists/VPN/SSO for internal simulations.
- `X-Forwarded-For` is trusted for logging — only expose the app behind a proxy you control.

---

## Deployment (Production)

- Provide a reachable `DATABASE_URL` and set the [environment variables](#environment-variables)
  (`RABBITHOLE_SECRET_KEY`, admin creds, `TRACKING_BASE_URL`, `REDIRECT_URL`).
- **Gunicorn**
  ```bash
  pip install gunicorn
  gunicorn -w 1 --threads 8 -b 0.0.0.0:5001 app:app
  ```
  > Campaigns run as **in-process background threads**. Status and Stop work across
  > workers (they go through the DB), but a worker restart drops its in-flight campaigns
  > (they're marked `interrupted` on next boot). Prefer a single worker with threads, or
  > move to a task queue (RQ/Celery) for heavy, durable sending.
- Put **nginx** in front for TLS + static caching. The app trusts `X-Forwarded-For`, so
  only expose it behind a proxy you control.
- Persist `uploads/` and your PostgreSQL data.

---

## Troubleshooting

- **Import rejected / rows skipped**  
  The CSV must include headers `username,first_name,last_name,email` (plus optional
  `group`). Rows missing `username` or `email` are skipped and counted in the result.

- **Emails not sending**  
  - Check the SMTP profile at `/smtp-configs` (server, port, security, credentials) and
    use **Test**.
  - Confirm the provider allows SMTP and the credentials are valid.
  - Watch a campaign at `/campaigns` — failures increment the **Failed** count and the
    campaign's `last_error`.

- **Clicks open a landing page instead of redirecting (or vice-versa)**  
  Landing pages are per-campaign: a link only serves one if the campaign was launched with
  a landing page selected (`&lp=` in the URL). Otherwise `/hit` redirects to `REDIRECT_URL`.

- **A campaign shows `interrupted`**  
  Its worker thread didn't survive a process restart. Relaunch it (see the Gunicorn note
  above).

- **Charts/counts don't update**  
  The dashboard and campaign views poll the API; refresh after sending or resetting
  analytics.

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

---

## Disclaimer

Rabbit Hole is created for:
- Cybersecurity students
- Awareness trainers
- Researchers

🚫 Do not use on real users, networks, or organizations without explicit permission.
The author is not responsible for misuse.

---

## License

This project is licensed under the **MIT License** — free to use, modify, and distribute.
