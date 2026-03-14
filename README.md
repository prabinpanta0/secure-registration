# Secure Registration Prototype (Julia)

This is a small **prototype security system** for user registration and login, built in **Julia**.

![Julia](https://img.shields.io/badge/Julia-1.11%2B-9558B2)
![SQLite](https://img.shields.io/badge/SQLite-CLI-003B57)

## Features (assignment minimum + secure design)

- Web UI for **username** and **password** registration/login
- **Password strength** analysis with actionable feedback (length, character variety, entropy estimate, and common weakness checks)
- **CAPTCHA** using a timed **math challenge**
- **Anti-bot PoW** (proof-of-work) using a SHA-256 puzzle (defense-in-depth, slows scripted signups)
- Secure password storage using **Argon2id** via the system `argon2` tool (with fallback to PBKDF2-HMAC-SHA256 if missing)
- Honeywords / honey-hashing style defense (stores multiple plausible password hashes; triggers breach lock on honeyword use)
- **MFA (TOTP)** support (RFC6238-style 6-digit codes)
- **Parameterized SQL** example: security audit log written to SQLite using bound parameters (via `sqlite3` CLI)
- Security policies illustrated:
  - Minimum password length + minimum strength score
  - Password **history** (prevents reuse of the last N passwords)
  - Password **expiry** (forces change after N days, enforced on web login)
  - Login **lockout** after repeated failures
  - Basic **rate limiting** (token bucket) for registration/login attempts
  - CSRF protection, server-side sessions (opaque `sid` cookie), security headers, honeypot field, basic UA blocking
  - ML-inspired bot risk scoring (tiny neural net over interaction telemetry; prototype)
  - Step-up verification on login (CAPTCHA + PoW)

User data is stored locally in `data/users.db` (SQLite user database).
Audit events are written to `data/audit.db`.

## System dependencies

- Required: `sqlite3` (user DB + audit DB are written via the SQLite CLI)
- Optional (recommended): `argon2` (Argon2id password hashing; otherwise PBKDF2-HMAC-SHA256 is used)
- Optional: `qrencode` (renders QR codes for TOTP setup; without it the page shows the secret and `otpauth://` URL)

## Pages

- `/` home
- `/register` registration (password coach + CAPTCHA + PoW)
- `/login` login (CAPTCHA + PoW + adaptive risk controls)
- `/mfa/setup` enable/reset TOTP
- `/mfa/verify` verify TOTP during login
- `/password/change` password change (policy enforced)
- Note: when already signed in, visiting `/login` or `/register` redirects to `/account`.

## Run

1. Ensure Julia is installed.
2. Use a local Julia package depot (keeps packages out of global user depot):
   - `export JULIA_DEPOT_PATH="$PWD/.julia"`
3. Install the packages
   - `julia --project=. -e 'using Pkg; Pkg.resolve(); Pkg.instantiate()'`
4. Quick dev run (installs deps locally and runs the server):
   - `julia --project=. devserver.jl`
5. Open:
   - `http://127.0.0.1:8080`

Least-privilege note: do not run as root; the app only needs to write to `data/` and uses restrictive permissions (`umask 077`, `data/` as `0700`).
Dev note: `devserver.jl` reads `.env` and will create/update it with missing values (including `APP_SERVER_SECRET`, `APP_PEPPER`, and `APP_PW_TAG_KEY`) so local secrets stay stable across restarts.

## Configuration (env)

- `APP_HOST` / `APP_PORT`: bind address/port (defaults `127.0.0.1:8080`)
- `APP_SERVER_SECRET`: required; used for signing short-lived tokens
- `APP_PEPPER`: recommended; server-side pepper mixed into password hashing
- `APP_COOKIE_SECURE`: set to `1` only behind HTTPS (adds cookie `Secure` and enables HSTS)
- `APP_REQUIRE_MFA`: `1` by default
- `APP_POW_BITS` / `APP_POW_LOGIN_BITS`: PoW difficulty (registration/login)
- `APP_MFA_SETUP_TOKEN_TTL_SECONDS` / `APP_MFA_VERIFY_TOKEN_TTL_SECONDS`: signed token TTLs for MFA flows
- `APP_LOG_REQUESTS` / `APP_AUDIT_STDOUT`: request logging and audit stdout logging (enabled by `devserver.jl`)

## MFA (TOTP)

MFA is required by default (`APP_REQUIRE_MFA=1`).

- After **register**, the app renders the TOTP setup page (and on success redirects to `/account`).
- After **login**:
  - if MFA is already enabled for the user, you are redirected to `/mfa/verify` and then to `/account` on success
  - if MFA is required but not yet enabled, the app renders the setup page to complete enrollment

Dev UX note: `/mfa/verify` includes a short-lived signed token in the query/form so verification can still proceed if the browser drops the session cookie during redirects.

## Common password list

`src/Security.jl` loads `src/passwords/most-common-passwords.txt` (≈100k entries) and penalizes those passwords heavily.

## Requirements (Python-style)

See `requirements-julia.txt` (for familiarity only). Julia installs from `Project.toml`.

## Files

- `devserver.jl` – dev runner (instantiate + seed + run server)
- `src/DevTools.jl` – seeding utilities
- `src/Security.jl` – hashing, password strength, captcha, PoW, TOTP
- `src/Storage.jl` – SQLite user DB (schema + users + honeywords + password history + rate limits)
- `server.jl` – web entry point
- `src/WebServer.jl` – HTTP.jl web server routes and web security controls
- `src/SecureRegApp.jl` – package entrypoint

## Preview

### Register

![alt text](/images/register.png)

### Login

![alt text](/images/login.png)