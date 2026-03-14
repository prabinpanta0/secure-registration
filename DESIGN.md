# Prototype Design Notes (Secure System Design)

## Threat model (prototype scope)

The prototype defends against common threats in account registration systems:

- Weak passwords (easy guessing / brute force / credential stuffing)
- Bot registrations (automated signups)
- Password database compromise (offline cracking risk)
- Online guessing attempts (repeated login tries)

## Password criteria used (strength scoring)

The password checker combines several widely used criteria:

- **Length**: longer passwords are exponentially harder to guess.
- **Character set diversity**: mixing lower/upper/digits/symbols increases search space.
- **Estimated entropy**: approximates `length × log2(pool_size)` to explain why longer/more diverse is stronger.

This is the same as the commonly cited formula:

`E = log2(R^L) = L * log2(R)` (where `R` is the character pool size and `L` is the length).
- **Heuristics / penalties**:
  - common password list (prevents obvious choices)
  - username included in password
  - simple sequences (e.g., `abcd`, `1234`)
  - long repeated runs (e.g., `aaaa`)

This produces a score (0–100) with feedback for improvement.

## Password storage (do not “encrypt” passwords)

Passwords are not stored in plaintext. The prototype stores:

- a **unique random salt** per password
- a **slow password hash**:
  - preferred: **Argon2id** computed by the system `argon2` CLI (parameters + salt are stored so verification is recomputation + constant-time compare)
  - fallback: **PBKDF2-HMAC-SHA256** with a high iteration count (stored with salt + iterations)
- an optional **pepper** from `APP_PEPPER` (a server secret not stored in the database)

This reduces the impact of a database leak by making offline cracking harder.

### Argon2id choice in this prototype

If the system `argon2` command is available, the prototype uses **Argon2id** with stored parameters and salt.
If not available, it falls back to **PBKDF2-HMAC-SHA256** (still salted and slow, but not as strong as Argon2id for GPU resistance).

## Policies and procedures demonstrated

- **Minimum strength**: user must reach a minimum score and length.
- **Password history (no reuse)**: remembers the last N password hashes and rejects reuse.
- **Password expiry**: forces change after N days (illustrates “frequency of change” policy).
- **Lockout**: after repeated failed login attempts, account is temporarily locked.
- **Rate limiting**: a token-bucket limiter is applied to registration and login attempts.
- **MFA (TOTP)**: optional second factor (6-digit time-based codes).

## Parameterized queries (SQL injection prevention)

The prototype writes a security **audit log** to SQLite using **bound parameters** (not string concatenation).
This illustrates the principle of parameterized queries to reduce SQL injection risk.

## CAPTCHA choice (bot defense)

The prototype implements a timed **math CAPTCHA**:

- Generated randomly (addition/subtraction/multiplication)
- Validated by the program logic
- Includes a time limit to make scripted automation harder

### Proof-of-Work (PoW) defense

In addition to the human CAPTCHA, the prototype also includes a small **PoW** puzzle (SHA-256 leading-zero difficulty) during registration.
This is a defense-in-depth control designed to make large-scale scripted registration more expensive.

## Notes on “web-only” controls

Some controls (especially **passkeys/WebAuthn**) require substantial browser + server cryptography and are typically implemented with dedicated libraries.
This prototype focuses on implementable controls (password hashing, TOTP, CAPTCHA+PoW, rate limiting, CSRF, headers, and auditing) and documents passkeys as a recommended next step.

## Web prototype controls implemented

The web version includes:

- **Security headers**: CSP, clickjacking protection, no-sniff, referrer policy, cache-control.
- **CSRF protection** for all POST forms (per-session token).
- **Server-side sessions** keyed by an opaque `sid` cookie (in-memory session store; cookie uses `HttpOnly` + `SameSite` and adds `Secure` only when configured).
- **Honeypot field** (hidden input) to catch naive bots.
- **Basic user-agent filtering** to block common scripted clients.
- **ML-inspired risk scoring**: a tiny neural-net style classifier over minimal interaction telemetry to trigger step-up/blocks (prototype).
- **Honeywords (honey-hashing style)**: multiple plausible password hashes are stored; if a honeyword is ever used online, the system treats it as a breach signal and locks the account.

### MFA enrollment/verification tokens (dev UX)

The prototype also uses short-lived **HMAC-signed tokens** during MFA flows to reduce “cookie got lost during redirect” friction in local testing:

- MFA setup token: embedded in the setup form and accepted as a fallback if the session cookie is missing (`APP_MFA_SETUP_TOKEN_TTL_SECONDS`, default 900s).
- MFA verify token: carried through `/mfa/verify?tok=...` and POSTed back as a hidden field (`APP_MFA_VERIFY_TOKEN_TTL_SECONDS`, default 300s).

Tokens are signed with `APP_SERVER_SECRET` and are intentionally short-lived.

## What is not realistically implementable in this prototype

- **Passkeys / WebAuthn + attestation**: requires full WebAuthn ceremony handling (CBOR parsing, origin binding, attestation verification, challenge storage) and browser APIs. Recommended as an extension if you add a dedicated WebAuthn library.
- **OS/TPM “device health” attestation from a browser**: not reliably available to a normal web app without enterprise MDM/agent support.
- **PQC session key exchange**: typically handled by TLS stack (and, in modern deployments, done as hybrid PQ + classical). This prototype recommends TLS 1.3 and tracking hybrid PQC support at the reverse-proxy layer.

## Deployment hardening (SSH)

If deployed to a server, an example hardening baseline:

- Use **key-based SSH** only (disable password auth), disable root login, and restrict users/groups.
- Use modern ciphers/MACs, disable legacy algorithms, and enable automatic security updates.
- Add SSH rate limits (e.g., `fail2ban`) and restrict access by firewall/VPN where possible.

## Least Privilege (implementation notes)

Applied in this prototype:

- **Run unprivileged**: the server is designed to run as a normal user account (not root). Bind to high ports (default `8080`) and put HTTPS in front with a reverse proxy if needed.
- **Minimal write access**: the app only writes to the local `data/` directory (SQLite user DB + SQLite audit log).
- **Restrictive file permissions**:
  - `umask 077` is set at server start so new files default to private.
  - `data/` is created with `0700` permissions; DB files are set to `0600`.
- **No persistent sessions**: sessions are in-memory only (restart clears sessions), reducing long-lived session theft risk.

## Logging hygiene (prototype)

If request logging is enabled, the prototype logs the request path without query strings (helps avoid leaking signed MFA tokens via logs during local testing).
