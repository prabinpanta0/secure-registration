# Secure Registration Prototype (Julia)

This is a small **prototype security system** for user registration and login, built in **Julia**.

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
  - CSRF protection, signed session cookies, security headers, honeypot field, basic UA blocking
  - ML-inspired bot risk scoring (tiny neural net over interaction telemetry; prototype)
  - Step-up verification on login (CAPTCHA + PoW)

User data is stored locally in `data/users.db` (SQLite user database).
Audit events are written to `data/audit.db`.

## Pages

- `/` home
- `/register` registration (password coach + CAPTCHA + PoW)
- `/login` login (CAPTCHA + PoW + adaptive risk controls)
- `/mfa/setup` enable/reset TOTP
- `/mfa/verify` verify TOTP during login
- `/password/change` password change (policy enforced)

## Run

1. Ensure Julia is installed.
2. Use a local Julia package depot (keeps packages out of global user depot):
   - `export JULIA_DEPOT_PATH="$PWD/.julia"`
3. Quick dev run (installs deps locally, seeds demo user, runs server):
   - `julia --project=. devserver.jl`
4. Open:
   - `http://127.0.0.1:8080`

Least-privilege note: do not run as root; the app only needs to write to `data/` and uses restrictive permissions (`umask 077`, `data/` as `0700`).
Dev note: `devserver.jl` creates `data/dev_secrets.toml` to keep the server secret + pepper stable across restarts.

## MFA (TOTP)

MFA is required by default: after **register**, you are sent to `/mfa/setup`. After **login**, you are sent to `/mfa/verify`.

## Common password list

`src/Security.jl` loads `src/passwords/most-common-passwords.txt` (≈100k entries) and penalizes those passwords heavily.

## Requirements (Python-style)

See `requirements-julia.txt` (for familiarity only). Julia installs from `Project.toml`.

## Files

- `devserver.jl` – dev runner (instantiate + seed + run server)
- `src/DevTools.jl` – seeding utilities
- `src/Security.jl` – hashing, password strength, captcha, PoW, TOTP
- `src/Storage.jl` – TOML persistence and password history policy
- `server.jl` – web entry point
- `src/WebServer.jl` – HTTP.jl web server routes and web security controls
- `src/SecureRegApp.jl` – package entrypoint
