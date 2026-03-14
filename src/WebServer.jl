module SecureRegWeb

const _PARENT = parentmodule(@__MODULE__)

if isdefined(_PARENT, :Security)
    using ..Security
else
    include("Security.jl")
    using .Security
end

if isdefined(_PARENT, :Storage)
    using ..Storage
else
    include("Storage.jl")
    using .Storage
end

if isdefined(_PARENT, :Audit)
    using ..Audit
else
    include("Audit.jl")
    using .Audit
end

if isdefined(_PARENT, :MLDefense)
    using ..MLDefense
else
    include("MLDefense.jl")
    using .MLDefense
end

import HTTP
using Random
using Dates
using Base64
using SHA

const DB_PATH = joinpath(@__DIR__, "..", "data", "users.db")

const HOST = get(ENV, "APP_HOST", "127.0.0.1")
const PORT = parse(Int, get(ENV, "APP_PORT", "8080"))
const SESSION_TTL_SECONDS = 60 * 60
const SESSION_ABSOLUTE_TTL_SECONDS = parse(Int, get(ENV, "APP_SESSION_ABS_TTL_SECONDS", string(8 * 60 * 60)))
const SESSION_GC_INTERVAL_SECONDS = parse(Int, get(ENV, "APP_SESSION_GC_INTERVAL_SECONDS", "30"))
const MAX_SESSIONS = parse(Int, get(ENV, "APP_MAX_SESSIONS", "20000"))
const APP_ENV = lowercase(get(ENV, "APP_ENV", "dev"))
const COOKIE_SECURE = begin
    v = get(ENV, "APP_COOKIE_SECURE", "")
    if isempty(v)
        APP_ENV in ("prod", "production")
    else
        v in ("1", "true", "TRUE", "yes", "YES")
    end
end
const REQUIRE_MFA = get(ENV, "APP_REQUIRE_MFA", "1") in ("1", "true", "TRUE", "yes", "YES")

const POW_DIFFICULTY_BITS = parse(Int, get(ENV, "APP_POW_BITS", "18"))
const POW_LOGIN_BITS = parse(Int, get(ENV, "APP_POW_LOGIN_BITS", "16"))

const RATE_CAPACITY_LOGIN = 10.0
const RATE_REFILL_LOGIN = 0.4
const RATE_CAPACITY_REGISTER = 5.0
const RATE_REFILL_REGISTER = 0.08

const USERNAME_RE = r"^[A-Za-z0-9_]{3,16}$"
const PASSWORD_EXPIRE_DAYS = 90
const RESERVED_USERNAMES = Set(["admin", "administrator", "root", "support", "security", "mod", "moderator", "__canary__", "canary", "deathnote"])

const MAX_FORM_BYTES = parse(Int, get(ENV, "APP_MAX_FORM_BYTES", "16384"))
const MAX_PASSWORD_BYTES = parse(Int, get(ENV, "APP_MAX_PASSWORD_BYTES", "256"))
const MFA_SETUP_TOKEN_TTL_SECONDS = parse(Int, get(ENV, "APP_MFA_SETUP_TOKEN_TTL_SECONDS", "900"))
const MFA_VERIFY_TOKEN_TTL_SECONDS = parse(Int, get(ENV, "APP_MFA_VERIFY_TOKEN_TTL_SECONDS", "300"))

const _IP_GUARD = Dict{String, Dict{String, Any}}()  # ip => {count, first_ts, banned_until}

function _ip_is_banned(ip::String)::Bool
    entry = get(_IP_GUARD, ip, nothing)
    entry === nothing && return false
    until = Float64(get(entry, "banned_until", 0.0))
    return time() < until
end

function _ip_fail!(ip::String; ban_seconds::Int=300, window_seconds::Int=300, threshold::Int=10)
    nowt = time()
    entry = get!(_IP_GUARD, ip, Dict{String, Any}("count" => 0, "first_ts" => nowt, "banned_until" => 0.0))
    first_ts = Float64(get(entry, "first_ts", nowt))
    if nowt - first_ts > window_seconds
        entry["count"] = 0
        entry["first_ts"] = nowt
    end
    entry["count"] = Int(get(entry, "count", 0)) + 1
    if Int(entry["count"]) >= threshold
        entry["banned_until"] = nowt + ban_seconds
        entry["count"] = 0
        entry["first_ts"] = nowt
    end
    _IP_GUARD[ip] = entry
end

function _ip_success!(ip::String)
    if haskey(_IP_GUARD, ip)
        delete!(_IP_GUARD, ip)
    end
end

function _pepper()
    return get(ENV, "APP_PEPPER", "")
end

function _server_secret()
    s = get(ENV, "APP_SERVER_SECRET", "")
    if isempty(s)
        error("APP_SERVER_SECRET must be set (used for session signing).")
    end
    return s
end

function _b64rand(n::Int)::String
    rd = RandomDevice()
    s = base64encode(rand(rd, UInt8, n))
    # cookie/url safe
    s = replace(s, "+" => "-")
    s = replace(s, "/" => "_")
    s = replace(s, "=" => "")
    return s
end

function _html_escape(s::AbstractString)::String
    t = replace(String(s), "&" => "&amp;")
    t = replace(t, "<" => "&lt;")
    t = replace(t, ">" => "&gt;")
    t = replace(t, "\"" => "&quot;")
    t = replace(t, "'" => "&#39;")
    return t
end

function _url_decode(s::AbstractString)::String
    x = String(s)
    x = replace(x, "+" => " ")
    buf = IOBuffer()
    i = 1
    while i <= lastindex(x)
        c = x[i]
        if c == '%' && i + 2 <= lastindex(x)
            hex = x[i+1:i+2]
            v = try
                parse(Int, hex; base=16)
            catch
                nothing
            end
            if v === nothing
                write(buf, c)
            else
                write(buf, UInt8(v))
                i += 2
            end
        else
            write(buf, c)
        end
        i += 1
    end
    return String(take!(buf))
end

function _read_body_bytes(body)::Vector{UInt8}
    if body isa Vector{UInt8}
        return body
    elseif body isa AbstractString
        return collect(codeunits(String(body)))
    else
        io = IOBuffer()
        write(io, body)
        return take!(io)
    end
end

struct FormTooLargeError <: Exception
    max_bytes::Int
    got_bytes::Int
end

function Base.showerror(io::IO, e::FormTooLargeError)
    print(io, "form too large (got ", e.got_bytes, " bytes, max ", e.max_bytes, ")")
end

function _parse_form(body; max_bytes::Int=MAX_FORM_BYTES)::Dict{String,String}
    bytes = _read_body_bytes(body)
    length(bytes) <= max_bytes || throw(FormTooLargeError(max_bytes, length(bytes)))
    s = try
        String(bytes)
    catch
        throw(ArgumentError("invalid form encoding"))
    end
    out = Dict{String,String}()
    isempty(s) && return out
    for part in split(s, "&")
        isempty(part) && continue
        kv = split(part, "=", limit=2)
        k = _url_decode(kv[1])
        v = length(kv) == 2 ? _url_decode(kv[2]) : ""
        out[k] = v
    end
    return out
end

function _target_path(target::AbstractString)::String
    s = String(target)
    parts = split(s, "?", limit=2)
    return parts[1]
end

function _parse_query(target::AbstractString)::Dict{String,String}
    s = String(target)
    parts = split(s, "?", limit=2)
    length(parts) == 2 || return Dict{String,String}()
    q = parts[2]
    out = Dict{String,String}()
    isempty(q) && return out
    for part in split(q, "&")
        isempty(part) && continue
        kv = split(part, "=", limit=2)
        k = _url_decode(kv[1])
        v = length(kv) == 2 ? _url_decode(kv[2]) : ""
        out[k] = v
    end
    return out
end

function _cookie_get(req::HTTP.Request, name::AbstractString)::Union{Nothing,String}
    hdr = HTTP.header(req, "Cookie", "")
    isempty(hdr) && return nothing
    for p in split(hdr, ";")
        kv = split(strip(p), "=", limit=2)
        length(kv) == 2 || continue
        if kv[1] == name
            v = kv[2]
            if startswith(v, "\"") && endswith(v, "\"") && lastindex(v) >= 2
                v = v[2:end-1]
            end
            return v
        end
    end
    return nothing
end

"""
Session cookies use a random opaque session id stored server-side in memory.

This is already resistant to tampering (unknown ids map to no session); signing is optional and can be
added later, but keeping it simple avoids browser cookie edge cases during testing.
"""

function _cookie_set(name::AbstractString, value::AbstractString; path::AbstractString="/", http_only::Bool=true, same_site::AbstractString=(COOKIE_SECURE ? "Strict" : "Lax"), max_age::Int=SESSION_TTL_SECONDS)
    parts = String[]
    push!(parts, string(name, "=", value))
    push!(parts, "Path=" * path)
    push!(parts, "Max-Age=" * string(max_age))
    push!(parts, "SameSite=" * same_site)
    http_only && push!(parts, "HttpOnly")
    COOKIE_SECURE && push!(parts, "Secure")
    return join(parts, "; ")
end

const _SESSIONS = Dict{String, Dict{String,Any}}()
const _SESSIONS_LAST_GC = Ref{Float64}(0.0)

function _now_utc_s()::String
    return Dates.format(Dates.now(Dates.UTC), dateformat"yyyy-mm-ddTHH:MM:SSZ")
end

function _session_new()::Tuple{String,Dict{String,Any}}
    _sessions_gc!()
    sid = _b64rand(24)
    nowt = time()
    sess = Dict{String,Any}(
        "expires_at" => nowt + SESSION_TTL_SECONDS,
        "created_at" => nowt,
    )
    _SESSIONS[sid] = sess
    return sid, sess
end

function _sessions_gc!(; force::Bool=false)
    nowt = time()
    if !force
        (nowt - _SESSIONS_LAST_GC[]) < SESSION_GC_INTERVAL_SECONDS && return
    end
    _SESSIONS_LAST_GC[] = nowt

    # Remove expired sessions (idle + absolute lifetime).
    for sid in collect(keys(_SESSIONS))
        sess = _SESSIONS[sid]
        exp = Float64(get(sess, "expires_at", 0.0))
        created = Float64(get(sess, "created_at", 0.0))
        if nowt > exp || (created > 0.0 && (nowt - created) > SESSION_ABSOLUTE_TTL_SECONDS)
            delete!(_SESSIONS, sid)
        end
    end

    # Hard cap to limit memory DoS (after cleaning).
    while length(_SESSIONS) > MAX_SESSIONS
        delete!(_SESSIONS, first(keys(_SESSIONS)))
    end

    return nothing
end

function _session_get(req::HTTP.Request)::Tuple{String,Dict{String,Any},Bool}
    _sessions_gc!()
    sid = _cookie_get(req, "sid")
    if sid !== nothing && haskey(_SESSIONS, sid)
        sess = _SESSIONS[sid]
        exp = Float64(get(sess, "expires_at", 0.0))
        created = Float64(get(sess, "created_at", 0.0))
        nowt = time()
        if nowt <= exp && (created <= 0.0 || (nowt - created) <= SESSION_ABSOLUTE_TTL_SECONDS)
            sess["expires_at"] = nowt + SESSION_TTL_SECONDS
            return sid, sess, false
        else
            delete!(_SESSIONS, sid)
        end
    end
    return _session_new()..., true
end

function _session_regenerate!(sid::String, sess::Dict{String,Any}; keep::Vector{String}=String[])::Tuple{String,Dict{String,Any}}
    new_sid, new_sess = _session_new()
    for k in keep
        haskey(sess, k) || continue
        new_sess[k] = sess[k]
    end
    delete!(_SESSIONS, sid)
    return new_sid, new_sess
end

function _csrf_token!(sess::Dict{String,Any})::String
    tok = get(sess, "csrf", "")
    if !(tok isa String) || isempty(tok)
        tok = _b64rand(18)
        sess["csrf"] = tok
    end
    return tok
end

function _ip(req::HTTP.Request)::String
    # Prototype: prefer direct peer if available; do not trust X-Forwarded-For by default.
    try
        peer = get(req.context, :peer, nothing)
        peer === nothing && return "ip:unknown"
        return string("ip:", peer)
    catch
        return "ip:unknown"
    end
end

function _b64url_bytes(bytes::Vector{UInt8})::String
    s = base64encode(bytes)
    s = replace(s, "+" => "-")
    s = replace(s, "/" => "_")
    s = replace(s, "=" => "")
    return s
end

function _b64url_decode_bytes(s::AbstractString)::Vector{UInt8}
    t = replace(String(s), "-" => "+")
    t = replace(t, "_" => "/")
    rem4 = mod(length(t), 4)
    if rem4 != 0
        t *= repeat("=", 4 - rem4)
    end
    return base64decode(t)
end

function _consttime_eq(a::Vector{UInt8}, b::Vector{UInt8})::Bool
    length(a) == length(b) || return false
    acc::UInt8 = 0x00
    @inbounds for i in eachindex(a)
        acc |= a[i] ⊻ b[i]
    end
    return acc == 0x00
end

function _sign_b64url(payload_bytes::Vector{UInt8})::String
    mac = SHA.hmac_sha256(collect(codeunits(_server_secret())), payload_bytes)
    return _b64url_bytes(mac)
end

function _mfa_setup_token(username::AbstractString, secret::AbstractString; issued_at_s::Int=Int(floor(time())))
    # Signed token so MFA setup can succeed even if cookies are blocked/lost (dev UX),
    # without storing secrets server-side beyond the rendered page.
    #
    # Format: base64url(payload) "." base64url(hmac_sha256(server_secret, payload))
    #
    # payload: "u=<username>&s=<secret>&iat=<unix>&n=<nonce>"
    nonce = _b64rand(12)
    payload = "u=" * String(username) * "&s=" * String(secret) * "&iat=" * string(issued_at_s) * "&n=" * nonce
    payload_bytes = Vector{UInt8}(codeunits(payload))
    sig = _sign_b64url(payload_bytes)
    return _b64url_bytes(payload_bytes) * "." * sig
end

function _mfa_setup_token_parse(tok::AbstractString)
    parts = split(String(tok), ".", limit=2)
    length(parts) == 2 || return nothing
    payload_bytes = try
        _b64url_decode_bytes(parts[1])
    catch
        return nothing
    end
    sig = String(parts[2])
    expected = _sign_b64url(payload_bytes)
    _consttime_eq(Vector{UInt8}(codeunits(sig)), Vector{UInt8}(codeunits(expected))) || return nothing
    payload = String(payload_bytes)
    kv = Dict{String,String}()
    for p in split(payload, "&")
        isempty(p) && continue
        kvr = split(p, "=", limit=2)
        length(kvr) == 2 || continue
        kv[kvr[1]] = kvr[2]
    end
    haskey(kv, "u") && haskey(kv, "s") && haskey(kv, "iat") || return nothing
    iat = try
        parse(Int, kv["iat"])
    catch
        return nothing
    end
    (Int(floor(time())) - iat) <= MFA_SETUP_TOKEN_TTL_SECONDS || return nothing
    return (kv["u"], kv["s"], iat)
end

function _mfa_verify_token(username::AbstractString; issued_at_s::Int=Int(floor(time())))
    # Signed token so /mfa/verify can recover if session cookies are lost between redirects (dev UX).
    #
    # Format: base64url(payload) "." base64url(hmac_sha256(server_secret, payload))
    #
    # payload: "u=<username>&iat=<unix>&n=<nonce>"
    nonce = _b64rand(12)
    payload = "u=" * String(username) * "&iat=" * string(issued_at_s) * "&n=" * nonce
    payload_bytes = Vector{UInt8}(codeunits(payload))
    sig = _sign_b64url(payload_bytes)
    return _b64url_bytes(payload_bytes) * "." * sig
end

function _mfa_verify_token_parse(tok::AbstractString)
    parts = split(String(tok), ".", limit=2)
    length(parts) == 2 || return nothing
    payload_bytes = try
        _b64url_decode_bytes(parts[1])
    catch
        return nothing
    end
    sig = String(parts[2])
    expected = _sign_b64url(payload_bytes)
    _consttime_eq(Vector{UInt8}(codeunits(sig)), Vector{UInt8}(codeunits(expected))) || return nothing
    payload = String(payload_bytes)
    kv = Dict{String,String}()
    for p in split(payload, "&")
        isempty(p) && continue
        kvr = split(p, "=", limit=2)
        length(kvr) == 2 || continue
        kv[kvr[1]] = kvr[2]
    end
    haskey(kv, "u") && haskey(kv, "iat") || return nothing
    iat = try
        parse(Int, kv["iat"])
    catch
        return nothing
    end
    (Int(floor(time())) - iat) <= MFA_VERIFY_TOKEN_TTL_SECONDS || return nothing
    return (kv["u"], iat)
end

function _flash_set!(sess::Dict{String,Any}, kind::AbstractString, msg::AbstractString)
    sess["flash_kind"] = String(kind)
    sess["flash_msg"] = String(msg)
    return nothing
end

function _flash_take_html!(sess::Dict{String,Any})::String
    kind = get(sess, "flash_kind", "")
    msg = get(sess, "flash_msg", "")
    if !(kind isa String) || !(msg isa String) || isempty(kind) || isempty(msg)
        return ""
    end
    delete!(sess, "flash_kind")
    delete!(sess, "flash_msg")
    cls = kind == "ok" ? "ok" : (kind == "error" ? "error" : "muted")
    return "<div class='card' style='margin-bottom:12px;'><p class='$cls' style='margin:0;'>" * _html_escape(msg) * "</p></div>"
end

function _ip_token(req::HTTP.Request)::String
    # Privacy-preserving token: HMAC(server_secret, ip_string) then base64url.
    # Keeps reputation tracking without storing raw IP in MLDefense state.
    ip = _ip(req)
    mac = SHA.hmac_sha256(collect(codeunits(_server_secret())), collect(codeunits(ip)))
    return _b64url_bytes(mac)
end

function _ua(req::HTTP.Request)::String
    return HTTP.header(req, "User-Agent", "")
end

function _is_suspicious_ua(ua::AbstractString)::Bool
    u = lowercase(String(ua))
    isempty(u) && return true
    for tok in ("curl", "wget", "python-requests", "httpclient", "powershell", "libwww", "java/")
        occursin(tok, u) && return true
    end
    return false
end

function _security_headers(nonce::Union{Nothing,String}=nothing)::Vector{Pair{String,String}}
    csp =
        nonce === nothing ?
        "default-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'" :
        "default-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'; script-src 'nonce-$(nonce)'; style-src 'nonce-$(nonce)'; img-src 'self' data:; connect-src 'self'"

    headers = Pair{String,String}[
        "X-Frame-Options" => "DENY",
        "X-Content-Type-Options" => "nosniff",
        "Referrer-Policy" => "no-referrer",
        "Permissions-Policy" => "geolocation=(), microphone=(), camera=()",
        "Content-Security-Policy" => csp,
        "Cache-Control" => "no-store",
    ]
    COOKIE_SECURE && push!(headers, "Strict-Transport-Security" => "max-age=15552000; includeSubDomains")
    return headers
end

function _nav_html(sess::Union{Nothing,Dict{String,Any}}=nothing)::String
    u = nothing
    if sess !== nothing
        v = get(sess, "user", nothing)
        if v isa String && !isempty(v)
            u = v
        end
    end
    if u === nothing
        return """
          <a class="pill" href="/">Home</a>
          <a class="pill" href="/register">Register</a>
          <a class="pill" href="/login">Login</a>
        """
    end
    return """
          <a class="pill" href="/">Home</a>
          <a class="pill" href="/account">Account</a>
        """
end

function _html_page(title::AbstractString, body_html::AbstractString; sess::Union{Nothing,Dict{String,Any}}=nothing)
    tip = COOKIE_SECURE ? "" : """<p class="muted" style="margin:14px 6px 0 6px;">Tip: set <code>APP_COOKIE_SECURE=1</code> <i>only when you run behind HTTPS</i> so cookies get the <code>Secure</code> flag and HSTS is enabled.</p>"""
    nav = _nav_html(sess)
    return """
    <!doctype html>
    <html lang="en">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>$(_html_escape(title))</title>
      <style>
        :root{
          --bg:#f7f8ff;
          --paper:#ffffff;
          --ink:#12131a;
          --muted:#4b5563;
          --brand:#c5132a;
          --danger:#b00020;
          --ok:#0a6;
          --shadow:0 12px 30px rgba(17,24,39,0.10);
          --radius:16px;
        }
        *{box-sizing:border-box;}
        body{
          margin:0;
          font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
          color:var(--ink);
          background:
            radial-gradient(1100px 520px at 18% -10%, rgba(197,19,42,0.14), transparent 58%),
            radial-gradient(900px 520px at 95% 2%, rgba(17,24,39,0.10), transparent 55%),
            repeating-linear-gradient(0deg, rgba(17,24,39,0.055), rgba(17,24,39,0.055) 1px, transparent 1px, transparent 28px),
            #fbfaf7;
        }
        a{color:var(--brand); text-decoration:none;}
        a:hover{text-decoration:underline;}
        .shell{max-width:900px; margin:38px auto; padding:0 16px;}
        .top{display:flex; align-items:center; justify-content:space-between; gap:14px; margin-bottom:16px;}
        .logo{
          display:flex; align-items:center; gap:10px;
          background:rgba(255,255,255,0.70);
          border:1px solid rgba(17,24,39,0.10);
          padding:10px 12px; border-radius:999px;
          box-shadow:0 6px 18px rgba(17,24,39,0.06);
          backdrop-filter: blur(8px);
        }
        .dot{width:12px; height:12px; border-radius:50%; background:linear-gradient(135deg,var(--brand),#111827);}
        .nav{display:flex; gap:12px; flex-wrap:wrap; justify-content:flex-end;}
        .pill{
          display:inline-flex; align-items:center;
          padding:8px 12px; border-radius:999px;
          border:1px solid rgba(17,24,39,0.12);
          background:rgba(255,255,255,0.65);
          backdrop-filter: blur(8px);
        }
        .main{
          background:var(--paper);
          border:1px solid rgba(17,24,39,0.10);
          border-radius:var(--radius);
          padding:18px 18px;
          box-shadow:var(--shadow);
        }
        h1{margin:0 0 6px 0; font-size:28px; letter-spacing:-0.02em;}
        p{line-height:1.55;}
        label{display:block; font-weight:600; margin-top:8px;}
        input:not([type=checkbox]):not([type=radio]){
          padding:12px 12px;
          width:100%;
          border-radius:12px;
          border:1px solid rgba(17,24,39,0.14);
          margin:6px 0;
          outline:none;
          background:#fff;
        }
        input:not([type=checkbox]):not([type=radio]):focus{
          border-color:rgba(109,94,252,0.55);
          box-shadow:0 0 0 4px rgba(109,94,252,0.18);
        }
        .checkline{display:flex; align-items:center; gap:10px; margin-top:8px;}
        input[type=checkbox]{width:18px; height:18px;}
        button{
          padding:12px 14px;
          border:none;
          border-radius:14px;
          font-weight:700;
          color:white;
          background:linear-gradient(135deg, var(--brand), #111827);
          cursor:pointer;
          box-shadow:0 10px 20px rgba(17,24,39,0.16);
        }
        button:disabled{opacity:0.55; cursor:not-allowed;}
        .btn-secondary{
          background:linear-gradient(135deg, #111827, #334155);
          box-shadow:0 10px 20px rgba(17,24,39,0.14);
        }
        .row{display:grid; grid-template-columns:1fr 1fr; gap:12px;}
        .muted{color:var(--muted);}
        .error{color:var(--danger);}
        .ok{color:var(--ok);}
        .card{
          border:1px solid rgba(17,24,39,0.10);
          border-radius:14px;
          padding:14px;
          margin:14px 0;
          background:linear-gradient(180deg, rgba(109,94,252,0.06), rgba(255,255,255,0.0));
        }
        .hp{position:absolute; left:-9999px; width:1px; height:1px; overflow:hidden;}
        code{background:rgba(17,24,39,0.06); padding:2px 6px; border-radius:8px;}
        .meter{height:10px; background:rgba(17,24,39,0.08); border-radius:999px; overflow:hidden; margin-top:8px;}
        .bar{height:100%; width:0%; background:linear-gradient(90deg, #ff7a7a, #ffd36e, #22c55e); border-radius:999px; transition:width 180ms ease;}
        .kgrid{display:grid; grid-template-columns:1fr; gap:8px; margin-top:8px;}
        .chip{display:inline-flex; padding:6px 10px; border-radius:999px; border:1px dashed rgba(17,24,39,0.18); background:rgba(255,255,255,0.55);}
        .qrbox{margin-top:12px; background:white; padding:12px; border-radius:12px; display:inline-block;}
      </style>
    </head>
    <body>
    <div class="shell">
      <div class="top">
        <div class="logo"><div class="dot"></div><div><b>SecureReg</b> <span class="muted">prototype</span></div></div>
        <div class="nav">
          $nav
        </div>
      </div>
      <div class="main">
        $body_html
      </div>
      $tip
    </div>
    </body>
    </html>
    """
end

function _respond(req::HTTP.Request, status::Int, body::AbstractString; headers::Vector{Pair{String,String}}=Pair{String,String}[])
    nonce = _b64rand(18)
    # Our pages use inline <style> and <script>. Apply nonce-based CSP and inject nonces.
    body2 = String(body)
    body2 = replace(body2, "<style>" => "<style nonce=\"$nonce\">")
    body2 = replace(body2, "<script>" => "<script nonce=\"$nonce\">")
    hs = Pair{String,String}[
        "Content-Type" => "text/html; charset=utf-8",
    ]
    append!(hs, _security_headers(nonce))
    append!(hs, headers)
    return HTTP.Response(status, hs, body2)
end

function _redirect(location::AbstractString; headers::Vector{Pair{String,String}}=Pair{String,String}[])
    hs = Pair{String,String}["Location" => String(location)]
    append!(hs, headers)
    return HTTP.Response(303, hs, "")
end

function _require_csrf(form::Dict{String,String}, sess::Dict{String,Any})::Bool
    return get(form, "csrf", "") == String(get(sess, "csrf", ""))
end

function _auth_user(sess::Dict{String,Any})::Union{Nothing,String}
    u = get(sess, "user", nothing)
    return u isa String && !isempty(u) ? u : nothing
end

function _password_feedback_html(pw::AbstractString, username::AbstractString)
    if ncodeunits(pw) > MAX_PASSWORD_BYTES
        rep = Security.PasswordReport(0, "Too long", 0.0, ["Password exceeds the maximum length ($(MAX_PASSWORD_BYTES) bytes)."])
        tips = join(["<li>" * _html_escape(t) * "</li>" for t in rep.feedback], "")
        return rep, "<div class='card'><div><b>Password strength:</b> $(_html_escape(rep.label))</div><ul>$tips</ul></div>"
    end
    rep = Security.password_strength(String(pw), String(username))
    tips = join(["<li>" * _html_escape(t) * "</li>" for t in rep.feedback], "")
    return rep, "<div class='card'><div><b>Password strength:</b> $(_html_escape(rep.label)) (score $(rep.score)/100)</div><ul>$tips</ul></div>"
end

function _register_get(req::HTTP.Request)
    sid, sess, isnew = _session_get(req)
    if _auth_user(sess) !== nothing
        return _redirect("/account"; headers=["Set-Cookie" => _cookie_set("sid", sid)])
    end
    csrf = _csrf_token!(sess)
    sess["reg_issued_at_ms"] = time() * 1000.0

    q, ans = Security.generate_math_captcha()
    sess["captcha_q"] = q
    sess["captcha_a"] = ans

    pow = Security.pow_generate(; difficulty_bits=POW_DIFFICULTY_BITS)
    sess["pow_challenge"] = pow["challenge"]
    sess["pow_bits"] = pow["difficulty_bits"]

    body = """
    <h1>Register</h1>
    <p class="muted">Light, fast registration with serious security checks (password policy + CAPTCHA + PoW).</p>
    <form method="POST" action="/register">
      <input type="hidden" name="csrf" value="$(_html_escape(csrf))">
      <input type="hidden" name="telemetry" id="telemetry">
      <div class="hp" hidden aria-hidden="true">
        <label>Website <input name="website" autocomplete="off"></label>
      </div>
      <div class="hp" hidden aria-hidden="true">
        <label>Company <input id="hp_company" name="company" autocomplete="off"></label>
      </div>
      <label>Username</label>
      <input id="username" name="username" autocomplete="username" required>
      <div class="row">
        <div>
          <label>Password</label>
          <input id="password" name="password" type="password" autocomplete="new-password" required>
        </div>
        <div>
          <label>Confirm</label>
          <input id="password2" name="password2" type="password" autocomplete="new-password" required>
        </div>
      </div>
      <div class="card">
        <div style="display:flex; align-items:center; justify-content:space-between; gap:12px;">
          <div><b>Password coach</b> <span id="pw_label" class="chip">Type a password</span></div>
          <div class="muted">Policy: 12+ chars and score ≥ 60</div>
        </div>
        <div class="meter"><div id="pw_bar" class="bar"></div></div>
        <div id="pw_tips" class="kgrid muted"></div>
        <div class="checkline">
          <input id="show_pw" type="checkbox">
          <label for="show_pw" class="muted" style="margin:0; font-weight:600;">Show password</label>
        </div>
        <div class="muted" style="margin-top:8px;">Final verification happens on the server (including the 100k common-password list).</div>
      </div>
      <div class="card">
        <div><b>CAPTCHA:</b> $(_html_escape(q))</div>
        <input name="captcha" inputmode="numeric" required>
      </div>
      <div class="card">
        <div><b>PoW challenge</b> (computed in-browser):</div>
        <div class="muted">Find a nonce so SHA-256(challenge:nonce) has at least <code>$(pow["difficulty_bits"])</code> leading zero bits.</div>
        <div>Challenge: <code>$(_html_escape(String(pow["challenge"])))</code></div>
        <input type="hidden" name="pow_nonce" id="pow_nonce">
        <div id="pow_status" class="muted">Solving…</div>
      </div>
      <button id="submit_btn" type="submit" disabled>Create account</button>
    </form>
    <p><a href="/login">Login</a></p>
    <script>
    // Password coach (client-side preview; server remains authoritative).
    const unEl = document.getElementById("username");
    const pwEl = document.getElementById("password");
    const pw2El = document.getElementById("password2");
    const barEl = document.getElementById("pw_bar");
    const labelEl = document.getElementById("pw_label");
    const tipsEl = document.getElementById("pw_tips");
    const showEl = document.getElementById("show_pw");
    const telEl = document.getElementById("telemetry");
    const hpEl = document.getElementById("hp_company");

    // Interaction telemetry (privacy-minimal, for bot defense): counts only, no raw typing.
    let keys = 0, pastes = 0, mouse = 0, focus = 0;
    let lastKeyT = null;
    const deltas = [];
    let focusMs = 0;
    let focused = document.hasFocus();
    let lastFocusT = performance.now();
    window.addEventListener("mousemove", ()=>{ mouse = Math.min(3, mouse + 1); }, {passive:true});
    window.addEventListener("focus", ()=>{
      focus++;
      if(!focused){
        focused = true;
        lastFocusT = performance.now();
      }
    });
    window.addEventListener("blur", ()=>{
      focus++;
      if(focused){
        focused = false;
        focusMs += (performance.now() - lastFocusT);
      }
    });
    [unEl, pwEl, pw2El].forEach(el=>{
      el.addEventListener("keydown", ()=>{
        keys++;
        const t = performance.now();
        if(lastKeyT !== null){
          const dt = t - lastKeyT;
          if(dt > 0 && dt < 2000 && deltas.length < 64) deltas.push(dt);
        }
        lastKeyT = t;
      });
      el.addEventListener("paste", ()=>{ pastes++; });
    });
    function setTelemetry(){
      if(focused){
        focusMs += (performance.now() - lastFocusT);
        lastFocusT = performance.now();
      }
      let mean = 0, varsum = 0;
      if(deltas.length){
        for(const d of deltas) mean += d;
        mean /= deltas.length;
        for(const d of deltas) varsum += (d - mean) * (d - mean);
        varsum /= deltas.length;
      }
      const std = deltas.length ? Math.sqrt(varsum) : 0;
      const honeypot = (hpEl && hpEl.value && hpEl.value.trim().length) ? 1 : 0;
      telEl.value =
        "keys:" + keys +
        ";pastes:" + pastes +
        ";mouse:" + mouse +
        ";focus:" + focus +
        ";kd_mean_ms:" + mean.toFixed(3) +
        ";kd_std_ms:" + std.toFixed(3) +
        ";focus_ms:" + focusMs.toFixed(3) +
        ";honeypot:" + honeypot;
    }
    document.querySelector("form").addEventListener("submit", setTelemetry);

    function hasLower(s){ return /[a-z]/.test(s); }
    function hasUpper(s){ return /[A-Z]/.test(s); }
    function hasDigit(s){ return /[0-9]/.test(s); }
    function hasSymbol(s){ return /[^A-Za-z0-9_]/.test(s); }
    function looksSequential(s){
      const t = s.toLowerCase();
      const seqs = ["0123456789","abcdefghijklmnopqrstuvwxyz"];
      for(const seq of seqs){
        for(let i=0;i<=seq.length-4;i++){
          const part = seq.slice(i,i+4);
          const rev = part.split("").reverse().join("");
          if(t.includes(part) || t.includes(rev)) return true;
        }
      }
      return false;
    }
    function repeatedRuns(s){ return /(.)\\1\\1\\1/.test(s); }
    function entropyBits(pw){
      let pool = 0;
      if(hasLower(pw)) pool += 26;
      if(hasUpper(pw)) pool += 26;
      if(hasDigit(pw)) pool += 10;
      if(hasSymbol(pw)) pool += 33;
      pool = Math.max(pool, 1);
      return pw.length * Math.log2(pool);
    }
    function scorePassword(pw, username){
      let score = 0;
      const len = pw.length;
      score += len < 8 ? 0 : len < 12 ? 10 : len < 16 ? 25 : len < 20 ? 35 : 40;
      let classes = 0;
      classes += hasLower(pw) ? 1 : 0;
      classes += hasUpper(pw) ? 1 : 0;
      classes += hasDigit(pw) ? 1 : 0;
      classes += hasSymbol(pw) ? 1 : 0;
      score += Math.min(20, classes * 5 + (classes >= 3 ? 2 : 0));
      score += Math.min(20, Math.floor(entropyBits(pw) / 4));
      const un = (username || "").toLowerCase();
      const lp = pw.toLowerCase();
      if(un.length >= 3 && lp.includes(un)) score -= 15;
      if(looksSequential(pw)) score -= 10;
      if(repeatedRuns(pw)) score -= 10;
      score = Math.max(0, Math.min(100, score));
      const label = score < 30 ? "Weak" : score < 60 ? "Moderate" : score < 80 ? "Strong" : "Very strong";
      return {score, label};
    }
    function renderCoach(){
      const un = unEl.value || "";
      const pw = pwEl.value || "";
      const res = scorePassword(pw, un);
      barEl.style.width = res.score + "%";
      labelEl.textContent = pw.length ? (res.label + " (" + res.score + "/100)") : "Type a password";
      const tips = [];
      if(pw.length < 12) tips.push("Use at least 12 characters (16+ is better).");
      if(!hasLower(pw)) tips.push("Add lowercase letters.");
      if(!hasUpper(pw)) tips.push("Add uppercase letters.");
      if(!hasDigit(pw)) tips.push("Add digits.");
      if(!hasSymbol(pw)) tips.push("Add symbols (!@#?).");
      if(un.length >= 3 && pw.toLowerCase().includes(un.toLowerCase())) tips.push("Avoid including your username.");
      if(looksSequential(pw)) tips.push("Avoid sequences like abcd / 1234.");
      if(repeatedRuns(pw)) tips.push("Avoid repeated runs like aaaa.");
      if(pw2El.value && pw2El.value !== pw) tips.push("Confirm password does not match.");
      const commonTop = new Set([
        "password","123456","123456789","qwerty","111111","123123","abc123","password1","admin","letmein",
        "welcome","iloveyou","monkey","dragon","football","baseball","shadow","master","sunshine","princess"
      ]);
      if(commonTop.has(pw.toLowerCase())) tips.push("Common password (easy to guess) — choose something unique.");
      if(tips.length === 0 && pw.length) tips.push("Looks good. Unique passwords are best.");
      tipsEl.innerHTML = tips.map(t => "<div class='chip'>" + t.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;") + "</div>").join("");
    }
    unEl.addEventListener("input", renderCoach);
    pwEl.addEventListener("input", renderCoach);
    pw2El.addEventListener("input", renderCoach);
    showEl.addEventListener("change", ()=>{
      const t = showEl.checked ? "text" : "password";
      pwEl.type = t;
      pw2El.type = t;
    });
    renderCoach();

    // PoW solver (client-side). Difficulty is set low for a prototype.
    const challenge = "$(_html_escape(String(pow["challenge"])))";
    const targetBits = $(pow["difficulty_bits"]);
    const statusEl = document.getElementById("pow_status");
    const nonceEl = document.getElementById("pow_nonce");
    const submitBtn = document.getElementById("submit_btn");

    function leadingZeroBits(bytes){
      let n=0;
      for(const b of bytes){
        if(b===0){ n+=8; continue; }
        for(let i=7;i>=0;i--){
          if(((b>>i)&1)===0) n++;
          else return n;
        }
      }
      return n;
    }

    async function sha256Bytes(msg){
      const enc = new TextEncoder();
      const buf = await crypto.subtle.digest("SHA-256", enc.encode(msg));
      return new Uint8Array(buf);
    }

    (async ()=>{
      let nonce = 0;
      const t0 = performance.now();
      while(true){
        const digest = await sha256Bytes(challenge + ":" + nonce);
        if(leadingZeroBits(digest) >= targetBits){
          nonceEl.value = String(nonce);
          const dt = (performance.now() - t0)/1000.0;
          statusEl.textContent = "Solved in " + dt.toFixed(3) + "s (nonce=" + nonce + ")";
          submitBtn.disabled = false;
          return;
        }
        nonce++;
        if(nonce % 200 === 0) statusEl.textContent = "Solving… tried " + nonce;
      }
    })();
    </script>
    """
    headers = Pair{String,String}[]
    if isnew
        push!(headers, "Set-Cookie" => _cookie_set("sid", sid))
    end
    return _respond(req, 200, _html_page("Register", body; sess=sess); headers=headers)
end

function _register_post(req::HTTP.Request)
    sid, sess, isnew = _session_get(req)
    db = Storage.load_db(DB_PATH)
    ip = _ip(req)

    if _auth_user(sess) !== nothing
        return _redirect("/account"; headers=["Set-Cookie" => _cookie_set("sid", sid)])
    end

    if _ip_is_banned(ip)
        Audit.log_event("ip_temp_ban"; detail=ip)
        return _respond(req, 429, _html_page("Slow down", "<h1>Too many attempts</h1><p class='error'>Try again in a few minutes.</p>"; sess=sess))
    end

    if _is_suspicious_ua(_ua(req))
        Audit.log_event("register_blocked_ua"; detail=_ua(req))
        return _respond(req, 403, _html_page("Blocked", "<h1>Blocked</h1><p class='error'>Suspicious client.</p>"; sess=sess))
    end

    if !Storage.allow_action!(db, "register:" * _ip(req); capacity=RATE_CAPACITY_REGISTER, refill_per_sec=RATE_REFILL_REGISTER)
        Storage.save_db(db)
        Audit.log_event("register_rate_limited")
        _ip_fail!(ip)
        return _respond(req, 429, _html_page("Slow down", "<h1>Too many attempts</h1><p class='error'>Please wait and try again.</p>"; sess=sess))
    end

    form = try
        _parse_form(req.body)
    catch e
        headers = Pair{String,String}[]
        isnew && push!(headers, "Set-Cookie" => _cookie_set("sid", sid))
        if e isa FormTooLargeError
            Audit.log_event("register_form_too_large"; detail=sprint(showerror, e))
            _ip_fail!(ip)
            return _respond(req, 413, _html_page("Too large", "<h1>Request too large</h1><p class='error'>Form too large.</p><p><a href='/register'>Back</a></p>"; sess=sess); headers=headers)
        else
            Audit.log_event("register_form_invalid"; detail=sprint(showerror, e))
            _ip_fail!(ip)
            return _respond(req, 400, _html_page("Bad Request", "<h1>Bad Request</h1><p class='error'>Invalid form.</p><p><a href='/register'>Back</a></p>"; sess=sess); headers=headers)
        end
    end
    if !_require_csrf(form, sess)
        Audit.log_event("register_csrf_failed")
        return _respond(req, 400, _html_page("Bad Request", "<h1>Bad Request</h1><p class='error'>CSRF validation failed.</p>"; sess=sess))
    end

    if !isempty(get(form, "website", ""))
        Audit.log_event("register_honeypot_tripped")
        return _respond(req, 400, _html_page("Bad Request", "<h1>Bad Request</h1><p class='error'>Invalid form.</p>"; sess=sess))
    end
    if !isempty(get(form, "company", ""))
        Audit.log_event("register_honeypot_tripped")
        return _respond(req, 400, _html_page("Bad Request", "<h1>Bad Request</h1><p class='error'>Invalid form.</p>"; sess=sess))
    end

    username = strip(get(form, "username", ""))
    password = get(form, "password", "")
    password2 = get(form, "password2", "")
    captcha = strip(get(form, "captcha", ""))
    pow_nonce_s = strip(get(form, "pow_nonce", ""))
    telemetry = MLDefense.parse_telemetry(get(form, "telemetry", ""))

    issued = Float64(get(sess, "reg_issued_at_ms", time() * 1000.0))
    form_age_ms = max(0.0, (time() * 1000.0) - issued)
    risk = MLDefense.risk_assess(
        ua_suspicious=_is_suspicious_ua(_ua(req)),
        form_age_ms=form_age_ms,
        telemetry=telemetry,
        ip_token=_ip_token(req),
        endpoint="register",
    )

    errors = String[]
    if !occursin(USERNAME_RE, username)
        push!(errors, "Invalid username (3–16 chars, letters/digits/_).")
    elseif lowercase(username) in RESERVED_USERNAMES
        push!(errors, "That username is reserved.")
    elseif Storage.user_exists(db, username)
        push!(errors, "Username is already taken.")
    end
    if password != password2
        push!(errors, "Passwords do not match.")
    end
    if occursin(r"[\r\n\0]", password)
        push!(errors, "Password contains invalid control characters.")
    end
    if ncodeunits(password) > MAX_PASSWORD_BYTES
        push!(errors, "Password is too long (max $(MAX_PASSWORD_BYTES) bytes).")
    end

    expected_a = get(sess, "captcha_a", nothing)
    got_a = try parse(Int, captcha) catch; nothing end
    if !(expected_a isa Int) || got_a === nothing || got_a != expected_a
        push!(errors, "CAPTCHA failed.")
    end

    chal = get(sess, "pow_challenge", "")
    bits = Int(get(sess, "pow_bits", POW_DIFFICULTY_BITS))
    nonce = try parse(UInt64, pow_nonce_s) catch; nothing end
    if !(chal isa String) || isempty(chal) || nonce === nothing || !Security.pow_verify(chal, nonce, bits)
        push!(errors, "PoW verification failed.")
    end

    rep, rep_html = _password_feedback_html(password, username)
    if rep.score < 60 || length(password) < 12
        push!(errors, "Password policy not met (use 12+ chars and a stronger score).")
    end
    if lowercase(password) in Security.common_passwords()
        push!(errors, "Password is too common. Choose a different password.")
    end

    if !isempty(errors)
        Storage.save_db(db)
        Audit.log_event("register_failed"; username=username, detail="risk=$(round(risk.score; digits=3)) label=$(risk.label) | " * join(errors, " | "))
        _ip_fail!(ip)
        err_html = "<ul class='error'>" * join(["<li>" * _html_escape(e) * "</li>" for e in errors], "") * "</ul>"
        body = "<h1>Register</h1>" * err_html * rep_html * "<p><a href='/register'>Try again</a></p>"
        headers = Pair{String,String}[]
        if isnew
            push!(headers, "Set-Cookie" => _cookie_set("sid", sid))
        end
        return _respond(req, 400, _html_page("Register failed", body; sess=sess); headers=headers)
    end

    if risk.score >= 0.92
        Storage.save_db(db)
        Audit.log_event("register_blocked_risk"; username=username, detail="risk=$(round(risk.score; digits=3)) reasons=" * join(risk.reasons, ","))
        _ip_fail!(ip)
        body = "<h1>Extra verification required</h1><p class='error'>This request looked automated. Please retry more slowly from a normal browser.</p><p><a href='/register'>Back</a></p>"
        return _respond(req, 403, _html_page("Verification", body; sess=sess); headers=["Set-Cookie" => _cookie_set("sid", sid)])
    end

    honeywords, honey_index = Security.generate_honeywords(password, username; count=7)
    honey_hashes = [Security.hash_password(w; pepper=_pepper()) for w in honeywords]
    now_utc = _now_utc_s()
    tag_key = get(ENV, "APP_PW_TAG_KEY", _server_secret())
    tag = Security.password_tag(password; key=tag_key)
    Storage.create_user!(db, username; created_at=now_utc, password_record=honey_hashes, password_changed_at=now_utc, history_size=5, honey_index=honey_index, pw_tag=tag)
    Storage.save_db(db)
    Audit.log_event("register_success"; username=username)
    _ip_success!(ip)
    sid, sess = _session_regenerate!(sid, sess)
    sess["user"] = username
    headers = Pair{String,String}["Set-Cookie" => _cookie_set("sid", sid)]
    if REQUIRE_MFA
        body = _mfa_setup_body_html!(sess, username) * "<p class='muted' style='margin-top:12px;'>After enabling MFA, you’ll land on the dashboard.</p>"
        return _respond(req, 200, _html_page("TOTP Setup", body; sess=sess); headers=headers)
    else
        return _redirect("/account"; headers=headers)
    end
end

function _login_get(req::HTTP.Request)
    sid, sess, isnew = _session_get(req)
    if _auth_user(sess) !== nothing
        return _redirect("/account"; headers=["Set-Cookie" => _cookie_set("sid", sid)])
    end
    csrf = _csrf_token!(sess)
    sess["login_issued_at_ms"] = time() * 1000.0

    q, ans = Security.generate_math_captcha()
    sess["login_captcha_q"] = q
    sess["login_captcha_a"] = ans

    pow = Security.pow_generate(; difficulty_bits=POW_LOGIN_BITS)
    sess["login_pow_challenge"] = pow["challenge"]
    sess["login_pow_bits"] = pow["difficulty_bits"]

    body = """
    <h1>Login</h1>
    <form method="POST" action="/login">
      <input type="hidden" name="csrf" value="$(_html_escape(csrf))">
      <input type="hidden" name="telemetry" id="telemetry">
      <input type="hidden" name="pow_nonce" id="pow_nonce">
      <div class="hp" hidden aria-hidden="true">
        <label>Company <input id="hp_company" name="company" autocomplete="off"></label>
      </div>
      <label>Username</label>
      <input id="username" name="username" autocomplete="username" required>
      <label>Password</label>
      <input id="password" name="password" type="password" autocomplete="current-password" required>
      <div class="card">
        <div><b>CAPTCHA:</b> $(_html_escape(q))</div>
        <input name="captcha" inputmode="numeric" required>
      </div>
      <div class="card">
        <div><b>PoW challenge</b> (computed in-browser):</div>
        <div class="muted">Find a nonce so SHA-256(challenge:nonce) has at least <code>$(pow["difficulty_bits"])</code> leading zero bits.</div>
        <div>Challenge: <code>$(_html_escape(String(pow["challenge"])))</code></div>
        <div id="pow_status" class="muted">Solving…</div>
      </div>
      <button id="submit_btn" type="submit" disabled>Login</button>
    </form>
    <p><a href="/register">Register</a></p>
    <script>
      const telEl = document.getElementById("telemetry");
      const unEl = document.getElementById("username");
      const pwEl = document.getElementById("password");
      const hpEl = document.getElementById("hp_company");
      const nonceEl = document.getElementById("pow_nonce");
      const statusEl = document.getElementById("pow_status");
      const submitBtn = document.getElementById("submit_btn");
      let keys = 0, pastes = 0, mouse = 0, focus = 0;
      let lastKeyT = null;
      const deltas = [];
      let focusMs = 0;
      let focused = document.hasFocus();
      let lastFocusT = performance.now();
      window.addEventListener("mousemove", ()=>{ mouse = Math.min(3, mouse + 1); }, {passive:true});
      window.addEventListener("focus", ()=>{
        focus++;
        if(!focused){
          focused = true;
          lastFocusT = performance.now();
        }
      });
      window.addEventListener("blur", ()=>{
        focus++;
        if(focused){
          focused = false;
          focusMs += (performance.now() - lastFocusT);
        }
      });
      [unEl, pwEl].forEach(el=>{
        el.addEventListener("keydown", ()=>{
          keys++;
          const t = performance.now();
          if(lastKeyT !== null){
            const dt = t - lastKeyT;
            if(dt > 0 && dt < 2000 && deltas.length < 64) deltas.push(dt);
          }
          lastKeyT = t;
        });
        el.addEventListener("paste", ()=>{ pastes++; });
      });
      function setTelemetry(){
        if(focused){
          focusMs += (performance.now() - lastFocusT);
          lastFocusT = performance.now();
        }
        let mean = 0, varsum = 0;
        if(deltas.length){
          for(const d of deltas) mean += d;
          mean /= deltas.length;
          for(const d of deltas) varsum += (d - mean) * (d - mean);
          varsum /= deltas.length;
        }
        const std = deltas.length ? Math.sqrt(varsum) : 0;
        const honeypot = (hpEl && hpEl.value && hpEl.value.trim().length) ? 1 : 0;
        telEl.value =
          "keys:" + keys +
          ";pastes:" + pastes +
          ";mouse:" + mouse +
          ";focus:" + focus +
          ";kd_mean_ms:" + mean.toFixed(3) +
          ";kd_std_ms:" + std.toFixed(3) +
          ";focus_ms:" + focusMs.toFixed(3) +
          ";honeypot:" + honeypot;
      }
      document.querySelector("form").addEventListener("submit", setTelemetry);

      // PoW solver (client-side).
      const challenge = "$(_html_escape(String(pow["challenge"])))";
      const targetBits = $(pow["difficulty_bits"]);
      function leadingZeroBits(bytes){
        let n=0;
        for(const b of bytes){
          if(b===0){ n+=8; continue; }
          for(let i=7;i>=0;i--){
            if(((b>>i)&1)===0) n++;
            else return n;
          }
        }
        return n;
      }
      async function sha256Bytes(msg){
        const enc = new TextEncoder();
        const buf = await crypto.subtle.digest("SHA-256", enc.encode(msg));
        return new Uint8Array(buf);
      }
      (async ()=>{
        let nonce = 0;
        const t0 = performance.now();
        while(true){
          const digest = await sha256Bytes(challenge + ":" + nonce);
          if(leadingZeroBits(digest) >= targetBits){
            nonceEl.value = String(nonce);
            const dt = (performance.now() - t0)/1000.0;
            statusEl.textContent = "Solved in " + dt.toFixed(3) + "s (nonce=" + nonce + ")";
            submitBtn.disabled = false;
            return;
          }
          nonce++;
          if(nonce % 250 === 0) statusEl.textContent = "Solving… tried " + nonce;
        }
      })();
    </script>
    """
    headers = Pair{String,String}[]
    if isnew
        push!(headers, "Set-Cookie" => _cookie_set("sid", sid))
    end
    return _respond(req, 200, _html_page("Login", body; sess=sess); headers=headers)
end

function _login_post(req::HTTP.Request)
    sid, sess, isnew = _session_get(req)
    db = Storage.load_db(DB_PATH)
    ip = _ip(req)

    if _ip_is_banned(ip)
        Audit.log_event("ip_temp_ban"; detail=ip)
        return _respond(req, 429, _html_page("Slow down", "<h1>Too many attempts</h1><p class='error'>Try again in a few minutes.</p>"))
    end

    form = try
        _parse_form(req.body)
    catch e
        headers = Pair{String,String}[]
        isnew && push!(headers, "Set-Cookie" => _cookie_set("sid", sid))
        if e isa FormTooLargeError
            Storage.save_db(db)
            Audit.log_event("login_form_too_large"; detail=sprint(showerror, e))
            _ip_fail!(ip)
            return _respond(req, 413, _html_page("Too large", "<h1>Request too large</h1><p class='error'>Form too large.</p><p><a href='/login'>Back</a></p>"); headers=headers)
        else
            Storage.save_db(db)
            Audit.log_event("login_form_invalid"; detail=sprint(showerror, e))
            _ip_fail!(ip)
            return _respond(req, 400, _html_page("Bad Request", "<h1>Bad Request</h1><p class='error'>Invalid form.</p><p><a href='/login'>Back</a></p>"); headers=headers)
        end
    end
    if !_require_csrf(form, sess)
        return _respond(req, 400, _html_page("Bad Request", "<h1>Bad Request</h1><p class='error'>CSRF validation failed.</p>"))
    end
    if !isempty(get(form, "company", ""))
        Storage.save_db(db)
        Audit.log_event("login_honeypot_tripped"; username=strip(get(form, "username", "")))
        _ip_fail!(ip)
        return _respond(req, 400, _html_page("Bad Request", "<h1>Bad Request</h1><p class='error'>Invalid form.</p>"))
    end

    username = strip(get(form, "username", ""))
    password = get(form, "password", "")
    telemetry = MLDefense.parse_telemetry(get(form, "telemetry", ""))
    captcha = strip(get(form, "captcha", ""))
    pow_nonce_s = strip(get(form, "pow_nonce", ""))

    if ncodeunits(password) > MAX_PASSWORD_BYTES
        Storage.save_db(db)
        Audit.log_event("login_rejected_pw_too_long"; username=username)
        _ip_fail!(ip)
        return _respond(req, 400, _html_page("Bad Request", "<h1>Bad Request</h1><p class='error'>Invalid credentials.</p><p><a href='/login'>Try again</a></p>"); headers=["Set-Cookie" => _cookie_set("sid", sid)])
    end

    issued = Float64(get(sess, "login_issued_at_ms", time() * 1000.0))
    form_age_ms = max(0.0, (time() * 1000.0) - issued)
    risk = MLDefense.risk_assess(
        ua_suspicious=_is_suspicious_ua(_ua(req)),
        form_age_ms=form_age_ms,
        telemetry=telemetry,
        ip_token=_ip_token(req),
        endpoint="login",
    )

    # Step-up checks (CAPTCHA + PoW) to slow bots even before password verification.
    expected_a = get(sess, "login_captcha_a", nothing)
    got_a = try parse(Int, captcha) catch; nothing end
    if !(expected_a isa Int) || got_a === nothing || got_a != expected_a
        Storage.save_db(db)
        Audit.log_event("login_captcha_failed"; username=username, detail="risk=$(round(risk.score; digits=3))")
        _ip_fail!(ip)
        sleep(0.8)
        return _respond(req, 401, _html_page("Login failed", "<h1>Login failed</h1><p class='error'>Invalid credentials.</p><p><a href='/login'>Try again</a></p>"))
    end

    chal = get(sess, "login_pow_challenge", "")
    bits = Int(get(sess, "login_pow_bits", POW_LOGIN_BITS))
    nonce = try parse(UInt64, pow_nonce_s) catch; nothing end
    if !(chal isa String) || isempty(chal) || nonce === nothing || !Security.pow_verify(chal, nonce, bits)
        Storage.save_db(db)
        Audit.log_event("login_pow_failed"; username=username, detail="risk=$(round(risk.score; digits=3))")
        _ip_fail!(ip)
        sleep(0.8)
        return _respond(req, 401, _html_page("Login failed", "<h1>Login failed</h1><p class='error'>Invalid credentials.</p><p><a href='/login'>Try again</a></p>"))
    end

    if !Storage.allow_action!(db, "login:" * username; capacity=RATE_CAPACITY_LOGIN, refill_per_sec=RATE_REFILL_LOGIN)
        Storage.save_db(db)
        Audit.log_event("login_rate_limited"; username=username)
        _ip_fail!(ip)
        return _respond(req, 429, _html_page("Slow down", "<h1>Too many attempts</h1><p class='error'>Please wait and try again.</p>"))
    end

    if risk.score >= 0.97
        Storage.save_db(db)
        Audit.log_event("login_blocked_risk"; username=username, detail="risk=$(round(risk.score; digits=3)) reasons=" * join(risk.reasons, ","))
        _ip_fail!(ip)
        sleep(1.5)
        return _respond(req, 403, _html_page("Verification", "<h1>Extra verification required</h1><p class='error'>This login attempt looked automated.</p><p><a href='/login'>Back</a></p>"))
    end

    if lowercase(username) in RESERVED_USERNAMES
        Storage.save_db(db)
        Audit.log_event("login_canary_or_reserved"; username=username, detail="risk=$(round(risk.score; digits=3))")
        _ip_fail!(ip)
        sleep(1.0)
        return _respond(req, 401, _html_page("Login failed", "<h1>Login failed</h1><p class='error'>Invalid credentials.</p><p><a href='/login'>Try again</a></p>"))
    end

    user = Storage.get_user(db, username)
    if user === nothing
        Storage.save_db(db)
        Audit.log_event("login_failed"; username=username, detail="risk=$(round(risk.score; digits=3))")
        _ip_fail!(ip)
        return _respond(req, 401, _html_page("Login failed", "<h1>Login failed</h1><p class='error'>Invalid credentials.</p><p><a href='/login'>Try again</a></p>"))
    end

    remaining = _lockout_remaining_minutes(user)
    if remaining > 0
        Storage.save_db(db)
        Audit.log_event("login_locked_out"; username=username, detail="remaining_minutes=$(remaining)")
        _ip_fail!(ip)
        return _respond(req, 403, _html_page("Locked", "<h1>Locked</h1><p class='error'>Try again later.</p>"))
    end

    st = Storage.verify_login_status(db, username, password, _pepper())
    if st == :honey
        Storage.record_failed_login!(db, username; max_failed=1, lockout_minutes=60)
        Storage.save_db(db)
        Audit.log_event("breach_honeyword_triggered"; username=username, detail="risk=$(round(risk.score; digits=3))")
        _ip_fail!(ip)
        return _respond(req, 403, _html_page("Locked", "<h1>Account locked</h1><p class='error'>Security incident detected. Account locked.</p>"))
    end

    if st != :ok
        Storage.record_failed_login!(db, username; max_failed=5, lockout_minutes=10)
        Storage.save_db(db)
        Audit.log_event("login_failed"; username=username, detail="risk=$(round(risk.score; digits=3))")
        _ip_fail!(ip)
        sleep(min(1.0, risk.score))
        return _respond(req, 401, _html_page("Login failed", "<h1>Login failed</h1><p class='error'>Invalid credentials.</p><p><a href='/login'>Try again</a></p>"))
    end

    _ip_success!(ip)

    if REQUIRE_MFA && !Storage.mfa_totp_enabled(db, username)
        sid, sess = _session_regenerate!(sid, sess)
        sess["user"] = username
        Storage.save_db(db)
        Audit.log_event("login_requires_mfa_setup"; username=username)
        headers = Pair{String,String}["Set-Cookie" => _cookie_set("sid", sid)]
        body = _mfa_setup_body_html!(sess, username) * "<p class='muted' style='margin-top:12px;'>After enabling MFA, you’ll land on the dashboard.</p>"
        return _respond(req, 200, _html_page("TOTP Setup", body; sess=sess); headers=headers)
    end

    if Storage.mfa_totp_enabled(db, username)
        sid, sess = _session_regenerate!(sid, sess)
        sess["pending_user"] = username
        Storage.save_db(db)
        headers = Pair{String,String}["Set-Cookie" => _cookie_set("sid", sid)]
        tok = _mfa_verify_token(username)
        return _redirect("/mfa/verify?tok=" * tok; headers=headers)
    end

    sid, sess = _session_regenerate!(sid, sess)
    sess["user"] = username
    Storage.reset_failed_logins!(db, username)

    if Storage.password_expired(db, username; expire_days=PASSWORD_EXPIRE_DAYS)
        Storage.save_db(db)
        Audit.log_event("login_success"; username=username, detail="password_expired=1")
        headers = Pair{String,String}[]
        push!(headers, "Set-Cookie" => _cookie_set("sid", sid))
        return _redirect("/password/change"; headers=headers)
    end

    Storage.save_db(db)
    Audit.log_event("login_success"; username=username)
    headers = Pair{String,String}[]
    push!(headers, "Set-Cookie" => _cookie_set("sid", sid))
    return _redirect("/account"; headers=headers)
end

function _mfa_verify_get(req::HTTP.Request)
    sid, sess, isnew = _session_get(req)
    pending = get(sess, "pending_user", "")
    tok = get(_parse_query(req.target), "tok", "")
    if (!(pending isa String) || isempty(pending)) && (tok isa String) && !isempty(tok)
        parsed = _mfa_verify_token_parse(tok)
        if parsed !== nothing
            pending, _ = parsed
            sess["pending_user"] = pending
        end
    end
    if !(pending isa String) || isempty(pending)
        return _redirect("/login"; headers=["Set-Cookie" => _cookie_set("sid", sid)])
    end
    csrf = _csrf_token!(sess)
    body = """
    <h1>MFA Verification</h1>
    <p class="muted">Enter the 6-digit code from your authenticator app.</p>
    <form method="POST" action="/mfa/verify">
      <input type="hidden" name="csrf" value="$(_html_escape(csrf))">
      <input type="hidden" name="tok" value="$(_html_escape(String(tok)))">
      <input name="code" inputmode="numeric" required>
      <button type="submit">Verify</button>
    </form>
    """
    headers = Pair{String,String}[]
    push!(headers, "Set-Cookie" => _cookie_set("sid", sid))
    return _respond(req, 200, _html_page("MFA", body; sess=sess); headers=headers)
end

function _mfa_verify_post(req::HTTP.Request)
    sid, sess, isnew = _session_get(req)
    db = Storage.load_db(DB_PATH)
    form = try
        _parse_form(req.body)
    catch e
        headers = Pair{String,String}[]
        isnew && push!(headers, "Set-Cookie" => _cookie_set("sid", sid))
        if e isa FormTooLargeError
            Storage.save_db(db)
            Audit.log_event("mfa_verify_form_too_large"; detail=sprint(showerror, e))
            return _respond(req, 413, _html_page("Too large", "<h1>Request too large</h1><p class='error'>Form too large.</p><p><a href='/mfa/verify'>Back</a></p>"; sess=sess); headers=headers)
        else
            Storage.save_db(db)
            Audit.log_event("mfa_verify_form_invalid"; detail=sprint(showerror, e))
            return _respond(req, 400, _html_page("Bad Request", "<h1>Bad Request</h1><p class='error'>Invalid form.</p><p><a href='/mfa/verify'>Back</a></p>"; sess=sess); headers=headers)
        end
    end
    pending = get(sess, "pending_user", "")
    token_user = nothing
    tok = strip(get(form, "tok", ""))
    if !isempty(tok)
        parsed = _mfa_verify_token_parse(tok)
        if parsed !== nothing
            token_user, _ = parsed
        end
    end
    if pending isa String && !isempty(pending) && token_user !== nothing && pending != token_user
        Storage.save_db(db)
        Audit.log_event("mfa_verify_token_mismatch"; username=String(pending))
        return _respond(req, 400, _html_page("Bad Request", "<h1>Bad Request</h1><p class='error'>Invalid token.</p>"; sess=sess))
    end
    if !(pending isa String) || isempty(pending)
        if token_user !== nothing
            pending = token_user
            sess["pending_user"] = pending
        else
            return _redirect("/login"; headers=["Set-Cookie" => _cookie_set("sid", sid)])
        end
    end
    if !_require_csrf(form, sess) && token_user === nothing
        return _respond(req, 400, _html_page("Bad Request", "<h1>Bad Request</h1><p class='error'>CSRF validation failed.</p>"; sess=sess))
    end
    secret = Storage.get_totp_secret(db, pending)
    code = strip(get(form, "code", ""))
    if secret === nothing || !Security.totp_verify(secret, code)
        Storage.save_db(db)
        Audit.log_event("login_totp_failed"; username=pending)
        return _respond(req, 401, _html_page("MFA failed", "<h1>MFA failed</h1><p class='error'>Invalid code.</p><p><a href='/mfa/verify'>Try again</a></p>"; sess=sess))
    end
    sid, sess = _session_regenerate!(sid, sess)
    sess["user"] = pending
    _flash_set!(sess, "ok", "MFA verified. You’re signed in.")
    Storage.reset_failed_logins!(db, pending)
    Storage.save_db(db)
    Audit.log_event("login_success"; username=pending, detail="mfa=totp")
    return _redirect("/account"; headers=["Set-Cookie" => _cookie_set("sid", sid)])
end

function _account_get(req::HTTP.Request)
    sid, sess, isnew = _session_get(req)
    u = _auth_user(sess)
    if u === nothing
        return _redirect("/login"; headers=["Set-Cookie" => _cookie_set("sid", sid)])
    end
    db = Storage.load_db(DB_PATH)
    mfa = Storage.mfa_totp_enabled(db, u) ? "enabled" : "disabled"
    csrf = _csrf_token!(sess)
    flash = _flash_take_html!(sess)
    if REQUIRE_MFA && !Storage.mfa_totp_enabled(db, u)
        body = """
        $(flash)
        <h1>Account</h1>
        <div class="card">
          <div><b>User:</b> $(_html_escape(u))</div>
          <div><b>TOTP MFA:</b> disabled</div>
          <p class="error" style="margin-top:10px;">MFA setup is required before continuing.</p>
          <p><a href="/mfa/setup">Enable TOTP now</a></p>
        </div>
        """
        return _respond(req, 200, _html_page("Account", body; sess=sess); headers=["Set-Cookie" => _cookie_set("sid", sid)])
    end
    body = """
    $(flash)
    <h1>Welcome, $(_html_escape(u))</h1>
    <p class="muted">You’re signed in. (MFA: $mfa)</p>
    <form method="POST" action="/logout">
      <input type="hidden" name="csrf" value="$(_html_escape(csrf))">
      <button type="submit">Logout</button>
    </form>
    """
    return _respond(req, 200, _html_page("Account", body; sess=sess); headers=["Set-Cookie" => _cookie_set("sid", sid)])
end

function _pw_change_get(req::HTTP.Request)
    sid, sess, isnew = _session_get(req)
    u = _auth_user(sess)
    if u === nothing
        return _redirect("/login"; headers=["Set-Cookie" => _cookie_set("sid", sid)])
    end
    csrf = _csrf_token!(sess)
    body = """
    <h1>Change password</h1>
    <form method="POST" action="/password/change">
      <input type="hidden" name="csrf" value="$(_html_escape(csrf))">
      <label>Current password</label>
      <input name="current" type="password" autocomplete="current-password" required>
      <div class="row">
        <div>
          <label>New password</label>
          <input id="newpw" name="newpw" type="password" autocomplete="new-password" required>
        </div>
        <div>
          <label>Confirm</label>
          <input id="newpw2" name="newpw2" type="password" autocomplete="new-password" required>
        </div>
      </div>
      <div class="card">
        <div style="display:flex; align-items:center; justify-content:space-between; gap:12px;">
          <div><b>Password coach</b> <span id="pw_label" class="chip">Type a password</span></div>
          <div class="muted">Policy: 12+ chars and score ≥ 60</div>
        </div>
        <div class="meter"><div id="pw_bar" class="bar"></div></div>
        <div id="pw_tips" class="kgrid muted"></div>
        <div class="checkline">
          <input id="show_pw" type="checkbox">
          <label for="show_pw" class="muted" style="margin:0; font-weight:600;">Show password</label>
        </div>
      </div>
      <button type="submit">Update</button>
    </form>
    <p><a href="/account">Back</a></p>
    <script>
    const pwEl = document.getElementById("newpw");
    const pw2El = document.getElementById("newpw2");
    const barEl = document.getElementById("pw_bar");
    const labelEl = document.getElementById("pw_label");
    const tipsEl = document.getElementById("pw_tips");
    const showEl = document.getElementById("show_pw");

    function hasLower(s){ return /[a-z]/.test(s); }
    function hasUpper(s){ return /[A-Z]/.test(s); }
    function hasDigit(s){ return /[0-9]/.test(s); }
    function hasSymbol(s){ return /[^A-Za-z0-9_]/.test(s); }
    function looksSequential(s){
      const t = s.toLowerCase();
      const seqs = ["0123456789","abcdefghijklmnopqrstuvwxyz"];
      for(const seq of seqs){
        for(let i=0;i<=seq.length-4;i++){
          const part = seq.slice(i,i+4);
          const rev = part.split("").reverse().join("");
          if(t.includes(part) || t.includes(rev)) return true;
        }
      }
      return false;
    }
    function repeatedRuns(s){ return /(.)\\1\\1\\1/.test(s); }
    function entropyBits(pw){
      let pool = 0;
      if(hasLower(pw)) pool += 26;
      if(hasUpper(pw)) pool += 26;
      if(hasDigit(pw)) pool += 10;
      if(hasSymbol(pw)) pool += 33;
      pool = Math.max(pool, 1);
      return pw.length * Math.log2(pool);
    }
    function scorePassword(pw){
      let score = 0;
      const len = pw.length;
      score += len < 8 ? 0 : len < 12 ? 10 : len < 16 ? 25 : len < 20 ? 35 : 40;
      let classes = 0;
      classes += hasLower(pw) ? 1 : 0;
      classes += hasUpper(pw) ? 1 : 0;
      classes += hasDigit(pw) ? 1 : 0;
      classes += hasSymbol(pw) ? 1 : 0;
      score += Math.min(20, classes * 5 + (classes >= 3 ? 2 : 0));
      score += Math.min(20, Math.floor(entropyBits(pw) / 4));
      if(looksSequential(pw)) score -= 10;
      if(repeatedRuns(pw)) score -= 10;
      score = Math.max(0, Math.min(100, score));
      const label = score < 30 ? "Weak" : score < 60 ? "Moderate" : score < 80 ? "Strong" : "Very strong";
      return {score, label};
    }
    function renderCoach(){
      const pw = pwEl.value || "";
      const res = scorePassword(pw);
      barEl.style.width = res.score + "%";
      labelEl.textContent = pw.length ? (res.label + " (" + res.score + "/100)") : "Type a password";
      const tips = [];
      if(pw.length < 12) tips.push("Use at least 12 characters (16+ is better).");
      if(!hasLower(pw)) tips.push("Add lowercase letters.");
      if(!hasUpper(pw)) tips.push("Add uppercase letters.");
      if(!hasDigit(pw)) tips.push("Add digits.");
      if(!hasSymbol(pw)) tips.push("Add symbols (!@#?).");
      if(looksSequential(pw)) tips.push("Avoid sequences like abcd / 1234.");
      if(repeatedRuns(pw)) tips.push("Avoid repeated runs like aaaa.");
      if(pw2El.value && pw2El.value !== pw) tips.push("Confirm password does not match.");
      if(tips.length === 0 && pw.length) tips.push("Looks good. Unique passwords are best.");
      tipsEl.innerHTML = tips.map(t => "<div class='chip'>" + t.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;") + "</div>").join("");
    }
    pwEl.addEventListener("input", renderCoach);
    pw2El.addEventListener("input", renderCoach);
    showEl.addEventListener("change", ()=>{
      const t = showEl.checked ? "text" : "password";
      pwEl.type = t;
      pw2El.type = t;
    });
    renderCoach();
    </script>
    """
    return _respond(req, 200, _html_page("Change password", body; sess=sess); headers=["Set-Cookie" => _cookie_set("sid", sid)])
end

function _pw_change_post(req::HTTP.Request)
    sid, sess, isnew = _session_get(req)
    u = _auth_user(sess)
    if u === nothing
        return _redirect("/login"; headers=["Set-Cookie" => _cookie_set("sid", sid)])
    end
    db = Storage.load_db(DB_PATH)
    form = try
        _parse_form(req.body)
    catch e
        headers = Pair{String,String}[]
        isnew && push!(headers, "Set-Cookie" => _cookie_set("sid", sid))
        if e isa FormTooLargeError
            Storage.save_db(db)
            Audit.log_event("pw_change_form_too_large"; username=u, detail=sprint(showerror, e))
            return _respond(req, 413, _html_page("Too large", "<h1>Request too large</h1><p class='error'>Form too large.</p><p><a href='/password/change'>Back</a></p>"; sess=sess); headers=headers)
        else
            Storage.save_db(db)
            Audit.log_event("pw_change_form_invalid"; username=u, detail=sprint(showerror, e))
            return _respond(req, 400, _html_page("Bad Request", "<h1>Bad Request</h1><p class='error'>Invalid form.</p><p><a href='/password/change'>Back</a></p>"; sess=sess); headers=headers)
        end
    end
    if !_require_csrf(form, sess)
        return _respond(req, 400, _html_page("Bad Request", "<h1>Bad Request</h1><p class='error'>CSRF validation failed.</p>"; sess=sess))
    end

    current = get(form, "current", "")
    newpw = get(form, "newpw", "")
    newpw2 = get(form, "newpw2", "")
    errors = String[]

    current_too_long = ncodeunits(current) > MAX_PASSWORD_BYTES
    new_too_long = ncodeunits(newpw) > MAX_PASSWORD_BYTES || ncodeunits(newpw2) > MAX_PASSWORD_BYTES
    if current_too_long || new_too_long
        push!(errors, "Password input is too long (max $(MAX_PASSWORD_BYTES) bytes).")
    end

    if !current_too_long
        st = Storage.verify_login_status(db, u, current, _pepper())
        if st == :honey
            Storage.record_failed_login!(db, u; max_failed=1, lockout_minutes=60)
            Storage.save_db(db)
            Audit.log_event("breach_honeyword_triggered"; username=u, detail="action=pw_change")
            return _respond(req, 403, _html_page("Locked", "<h1>Account locked</h1><p class='error'>Security incident detected. Account locked.</p>"; sess=sess); headers=["Set-Cookie" => _cookie_set("sid", sid)])
        end
        if st != :ok
            push!(errors, "Current password is incorrect.")
        end
    end
    if newpw != newpw2
        push!(errors, "New passwords do not match.")
    end
    if occursin(r"[\r\n\0]", newpw)
        push!(errors, "New password contains invalid control characters.")
    end

    rep, rep_html = _password_feedback_html(newpw, u)
    if rep.score < 60 || length(newpw) < 12
        push!(errors, "Password policy not met (use 12+ chars and a stronger score).")
    end
    tag_key = get(ENV, "APP_PW_TAG_KEY", _server_secret())
    tag = Security.password_tag(newpw; key=tag_key)
    if Storage.password_reuse_detected(db, u, tag; history_size=5)
        push!(errors, "You cannot reuse a previous password.")
    end
    if lowercase(newpw) in Security.common_passwords()
        push!(errors, "Password is too common. Choose a different password.")
    end

    if !isempty(errors)
        Storage.save_db(db)
        Audit.log_event("password_change_failed"; username=u, detail=join(errors, " | "))
        err_html = "<ul class='error'>" * join(["<li>" * _html_escape(e) * "</li>" for e in errors], "") * "</ul>"
        body = "<h1>Change password</h1>" * err_html * rep_html * "<p><a href='/password/change'>Try again</a></p>"
        return _respond(req, 400, _html_page("Change password", body; sess=sess); headers=["Set-Cookie" => _cookie_set("sid", sid)])
    end

    Storage.update_password!(db, u, newpw, _pepper(); history_size=5, pw_tag=tag)
    Storage.save_db(db)
    Audit.log_event("password_changed"; username=u)
    sid, sess = _session_regenerate!(sid, sess; keep=["user"])
    return _respond(req, 200, _html_page("Password updated", "<h1>Password updated</h1><p class='ok'>Password changed successfully.</p><p><a href='/account'>Back to account</a></p>"; sess=sess); headers=["Set-Cookie" => _cookie_set("sid", sid)])
end

function _mfa_setup_get(req::HTTP.Request)
    sid, sess, isnew = _session_get(req)
    u = _auth_user(sess)
    if u === nothing
        return _redirect("/login"; headers=["Set-Cookie" => _cookie_set("sid", sid)])
    end
    return _respond(req, 200, _html_page("TOTP Setup", _mfa_setup_body_html!(sess, u); sess=sess); headers=["Set-Cookie" => _cookie_set("sid", sid)])
end

function _mfa_setup_body_html!(sess::Dict{String,Any}, u::AbstractString)::String
    csrf = _csrf_token!(sess)
    secret = get(sess, "totp_setup_secret", "")
    if !(secret isa String) || isempty(secret)
        secret = Security.totp_secret()
        sess["totp_setup_secret"] = secret
    end
    setup_tok = _mfa_setup_token(String(u), secret)
    url = "otpauth://totp/SecureRegWeb:" * String(u) * "?secret=" * secret * "&issuer=SecureRegWeb&digits=6&period=30"

    qr_svg = ""
    try
        qr_svg = read(`qrencode -t SVG -o - $url`, String)
    catch
        qr_svg = ""
    end
    return """
    <h1>Enable TOTP</h1>
    <p class="muted">MFA is required to continue.</p>
    <div class="card">
      <div><b>Secret (Base32):</b> <code>$(_html_escape(secret))</code></div>
      <div class="muted">Scan the QR in your authenticator app (or copy the secret).</div>
      <div><b>otpauth URL:</b> <code>$(_html_escape(url))</code></div>
      $(isempty(qr_svg) ? "" : "<div class='qrbox'>" * qr_svg * "</div>")
    </div>
    <form method="POST" action="/mfa/setup">
      <input type="hidden" name="csrf" value="$(_html_escape(csrf))">
      <input type="hidden" name="setup_token" value="$(_html_escape(setup_tok))">
      <label>Enter current 6-digit code to confirm</label>
      <input name="code" inputmode="numeric" required>
      <button type="submit">Enable</button>
    </form>
    """
end

function _mfa_setup_post(req::HTTP.Request)
    sid, sess, isnew = _session_get(req)
    u = _auth_user(sess)
    db = Storage.load_db(DB_PATH)
    form = try
        _parse_form(req.body)
    catch e
        uname = u === nothing ? "" : u
        headers = Pair{String,String}[]
        isnew && push!(headers, "Set-Cookie" => _cookie_set("sid", sid))
        if e isa FormTooLargeError
            Storage.save_db(db)
            Audit.log_event("mfa_setup_form_too_large"; username=uname, detail=sprint(showerror, e))
            return _respond(req, 413, _html_page("Too large", "<h1>Request too large</h1><p class='error'>Form too large.</p><p><a href='/mfa/setup'>Back</a></p>"; sess=sess); headers=headers)
        else
            Storage.save_db(db)
            Audit.log_event("mfa_setup_form_invalid"; username=uname, detail=sprint(showerror, e))
            return _respond(req, 400, _html_page("Bad Request", "<h1>Bad Request</h1><p class='error'>Invalid form.</p><p><a href='/mfa/setup'>Back</a></p>"; sess=sess); headers=headers)
        end
    end

    # If session cookies are missing/blocked, allow a short-lived signed setup token as fallback.
    token_user = nothing
    token_secret = nothing
    tok = strip(get(form, "setup_token", ""))
    if u === nothing && !isempty(tok)
        parsed = _mfa_setup_token_parse(tok)
        if parsed !== nothing
            token_user, token_secret, _ = parsed
            u = token_user
            sess["user"] = u
            Audit.log_event("mfa_setup_token_used"; username=u)
        end
    end
    if u === nothing
        cookie_present = !isempty(HTTP.header(req, "Cookie", ""))
        Audit.log_event("mfa_setup_no_session"; detail="cookie_present=$(cookie_present)")
        Storage.save_db(db)
        return _redirect("/login"; headers=["Set-Cookie" => _cookie_set("sid", sid)])
    end

    if !_require_csrf(form, sess) && token_user === nothing
        Audit.log_event("mfa_setup_csrf_failed"; username=u)
        return _respond(req, 400, _html_page("Bad Request", "<h1>Bad Request</h1><p class='error'>CSRF validation failed.</p>"; sess=sess))
    end

    secret = token_secret === nothing ? get(sess, "totp_setup_secret", "") : token_secret
    code = strip(get(form, "code", ""))
    if !(secret isa String) || isempty(secret) || !Security.totp_verify(secret, code)
        Storage.save_db(db)
        Audit.log_event("totp_enable_confirm_failed"; username=u)
        return _respond(req, 401, _html_page("TOTP", "<h1>TOTP setup failed</h1><p class='error'>Invalid code.</p><p><a href='/mfa/setup'>Try again</a></p>"; sess=sess))
    end
    Storage.set_totp_secret!(db, u, secret)
    Storage.save_db(db)
    Audit.log_event("totp_enabled"; username=u)
    sid, sess = _session_regenerate!(sid, sess; keep=["user"])
    _flash_set!(sess, "ok", "MFA is now enabled.")
    return _redirect("/account"; headers=["Set-Cookie" => _cookie_set("sid", sid)])
end

function _logout_post(req::HTTP.Request)
    sid, sess, isnew = _session_get(req)
    form = try
        _parse_form(req.body)
    catch e
        headers = Pair{String,String}[]
        isnew && push!(headers, "Set-Cookie" => _cookie_set("sid", sid))
        if e isa FormTooLargeError
            Audit.log_event("logout_form_too_large"; detail=sprint(showerror, e))
            return _respond(req, 413, _html_page("Too large", "<h1>Request too large</h1><p class='error'>Form too large.</p><p><a href='/'>Back</a></p>"); headers=headers)
        else
            Audit.log_event("logout_form_invalid"; detail=sprint(showerror, e))
            return _respond(req, 400, _html_page("Bad Request", "<h1>Bad Request</h1><p class='error'>Invalid form.</p><p><a href='/'>Back</a></p>"); headers=headers)
        end
    end
    if !_require_csrf(form, sess)
        return _respond(req, 400, _html_page("Bad Request", "<h1>Bad Request</h1><p class='error'>CSRF validation failed.</p>"))
    end
    delete!(_SESSIONS, sid)
    return _redirect("/"; headers=["Set-Cookie" => _cookie_set("sid", "deleted"; max_age=0)])
end

function _home(req::HTTP.Request)
    sid, sess, isnew = _session_get(req)
    u = _auth_user(sess)
    links = u === nothing ? "<a href='/register'>Register</a> • <a href='/login'>Login</a>" : "<a href='/account'>Account</a>"
    body = "<h1>SecureRegWeb</h1><p class='muted'>Security-focused registration prototype.</p><p>$links</p>"
    headers = Pair{String,String}[]
    if isnew
        push!(headers, "Set-Cookie" => _cookie_set("sid", sid))
    end
    return _respond(req, 200, _html_page("Home", body; sess=sess); headers=headers)
end

function _lockout_remaining_minutes(user)::Int
    locked_until = get(user, "locked_until", "")
    if !(locked_until isa AbstractString) || isempty(locked_until)
        return 0
    end
    t = try
        Dates.DateTime(String(locked_until), dateformat"yyyy-mm-ddTHH:MM:SSZ")
    catch
        return 0
    end
    nowt = Dates.now(Dates.UTC)
    if nowt >= t
        return 0
    end
    return Int(ceil(Dates.value(t - nowt) / (60 * 1000)))
end

function _dispatch(req::HTTP.Request)
    target = _target_path(req.target)
    if req.method == "GET" && target == "/"
        return _home(req)
    elseif req.method == "GET" && target == "/register"
        return _register_get(req)
    elseif req.method == "POST" && target == "/register"
        return _register_post(req)
    elseif req.method == "GET" && target == "/login"
        return _login_get(req)
    elseif req.method == "POST" && target == "/login"
        return _login_post(req)
    elseif req.method == "GET" && target == "/account"
        return _account_get(req)
    elseif req.method == "GET" && target == "/mfa/verify"
        return _mfa_verify_get(req)
    elseif req.method == "POST" && target == "/mfa/verify"
        return _mfa_verify_post(req)
    elseif req.method == "GET" && target == "/mfa/setup"
        return _mfa_setup_get(req)
    elseif req.method == "POST" && target == "/mfa/setup"
        return _mfa_setup_post(req)
    elseif req.method == "GET" && target == "/password/change"
        return _pw_change_get(req)
    elseif req.method == "POST" && target == "/password/change"
        return _pw_change_post(req)
    elseif req.method == "POST" && target == "/logout"
        return _logout_post(req)
    else
        return HTTP.Response(404, _security_headers(), "Not found")
    end
end

function main()
    Base.exit_on_sigint(false)
    server = start()
    try
        wait(server)
    catch e
        if e isa InterruptException
            println("\nShutting down (Ctrl+C).")
            try
                close(server)
            catch
            end
        else
            rethrow()
        end
    end
end

function start(; host::AbstractString=HOST, port::Integer=PORT)
    _server_secret() # ensure set
    try
        Libc.umask(0o077)
    catch
    end
    Storage.ensure_db_dir(DB_PATH)
    println("Starting web server on http://$(host):$(port)")
    println("Set env: APP_SERVER_SECRET and (recommended) APP_PEPPER")
    log_requests = get(ENV, "APP_LOG_REQUESTS", "0") in ("1", "true", "TRUE", "yes", "YES")
    handler = function (req::HTTP.Request)
        resp = _dispatch(req)
        if log_requests
            try
                println(string(Dates.format(Dates.now(Dates.UTC), dateformat"HH:mm:SS"), " ", req.method, " ", _target_path(req.target), " -> ", resp.status))
            catch
            end
        end
        return resp
    end
    return HTTP.serve!(handler, host, port; verbose=false)
end

end # module
