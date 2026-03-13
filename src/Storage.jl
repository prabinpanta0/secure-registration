module Storage

using Dates
using TOML
using Base64
using ..Security

struct DB
    path::String
end

const DEFAULT_DB_PATH = joinpath(@__DIR__, "..", "data", "users.db")
const _RATE = Dict{String, Dict{String, Any}}()
const _RATE_LOCK = ReentrantLock()

function _db_path(path::AbstractString)::String
    return String(path)
end

function ensure_db_dir(path::AbstractString)
    dir = dirname(String(path))
    isdir(dir) || mkpath(dir)
    try
        chmod(dir, 0o700)
    catch
    end
end

function _sqlite_quote(s::AbstractString)::String
    return "'" * replace(String(s), "'" => "''") * "'"
end

function _run_sql(db::DB, script::AbstractString; capture::Bool=false)
    cmd = `sqlite3 -batch $(db.path)`
    script2 = "PRAGMA foreign_keys = ON;\n" * String(script)
    if capture
        out = IOBuffer()
        err = IOBuffer()
        try
            run(pipeline(cmd; stdin=IOBuffer(script2), stdout=out, stderr=err))
        catch e
            msg = String(take!(err))
            throw(ErrorException("sqlite3 failed: $(isempty(msg) ? sprint(showerror, e) : msg)"))
        end
        return String(take!(out))
    else
        err = IOBuffer()
        try
            run(pipeline(cmd; stdin=IOBuffer(script2), stdout=devnull, stderr=err))
        catch e
            msg = String(take!(err))
            throw(ErrorException("sqlite3 failed: $(isempty(msg) ? sprint(showerror, e) : msg)"))
        end
        return nothing
    end
end

function _ensure_schema(db::DB)
    ensure_db_dir(db.path)
    schema = """
    PRAGMA foreign_keys = ON;
    PRAGMA journal_mode=WAL;
    PRAGMA synchronous=NORMAL;
    CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        created_at TEXT NOT NULL,
        password_changed_at TEXT NOT NULL,
        pw_tag TEXT NOT NULL,
        mfa_totp_enabled INTEGER NOT NULL DEFAULT 0,
        mfa_totp_secret_b32 TEXT NOT NULL DEFAULT '',
        failed_logins INTEGER NOT NULL DEFAULT 0,
        locked_until TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX IF NOT EXISTS idx_users_pw_tag ON users(pw_tag);

    CREATE TABLE IF NOT EXISTS pw_honey (
        username TEXT NOT NULL,
        pos INTEGER NOT NULL,
        record_b64 TEXT NOT NULL,
        PRIMARY KEY(username, pos),
        FOREIGN KEY(username) REFERENCES users(username) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS honey_real (
        username TEXT PRIMARY KEY,
        real_pos INTEGER NOT NULL,
        FOREIGN KEY(username) REFERENCES users(username) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS pw_tag_history (
        username TEXT NOT NULL,
        seq INTEGER NOT NULL,
        pw_tag TEXT NOT NULL,
        changed_at TEXT NOT NULL,
        PRIMARY KEY(username, seq),
        FOREIGN KEY(username) REFERENCES users(username) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_pw_tag_history_tag ON pw_tag_history(pw_tag);
    """
    _run_sql(db, schema)
    try
        chmod(db.path, 0o600)
    catch
    end
    return nothing
end

function load_db(path::AbstractString=DEFAULT_DB_PATH)::DB
    db = DB(_db_path(path))
    _ensure_schema(db)
    return db
end

function save_db(::AbstractString, ::DB)
    return nothing
end

function save_db(::DB)
    return nothing
end

function user_exists(db::DB, username::AbstractString)::Bool
    script = """
    .parameter init
    .parameter set :u $(_sqlite_quote(username))
    SELECT CASE WHEN EXISTS(SELECT 1 FROM users WHERE username=:u) THEN 1 ELSE 0 END;
    """
    out = strip(_run_sql(db, script; capture=true))
    return out == "1"
end

function get_user(db::DB, username::AbstractString)
    script = """
    .parameter init
    .parameter set :u $(_sqlite_quote(username))
    .mode list
    .separator '|'
    SELECT created_at, password_changed_at, mfa_totp_enabled, mfa_totp_secret_b32, failed_logins, locked_until, pw_tag
    FROM users WHERE username=:u;
    """
    out = strip(_run_sql(db, script; capture=true))
    isempty(out) && return nothing
    parts = split(out, '|')
    length(parts) == 7 || return nothing
    return Dict(
        "created_at" => parts[1],
        "password_changed_at" => parts[2],
        "mfa_totp_enabled" => (parts[3] == "1"),
        "mfa_totp_secret_b32" => parts[4],
        "failed_logins" => parse(Int, parts[5]),
        "locked_until" => parts[6],
        "pw_tag" => parts[7],
    )
end

function _toml_string(d::AbstractDict)
    io = IOBuffer()
    TOML.print(io, d)
    return String(take!(io))
end

function _toml_parse(s::AbstractString)
    return TOML.parse(String(s))
end

function _b64_record(rec::AbstractDict)::String
    s = _toml_string(rec)
    return base64encode(Vector{UInt8}(codeunits(s)))
end

function _parse_b64_record(s::AbstractString)
    raw = base64decode(String(s))
    return _toml_parse(String(raw))
end

function create_user!(
    db::DB,
    username::AbstractString;
    created_at::AbstractString,
    password_record,
    password_changed_at::AbstractString,
    history_size::Int=5,
    honey_index::Union{Nothing,Int}=nothing,
    pw_tag::AbstractString,
)
    uname = String(username)
    user_exists(db, uname) && throw(ArgumentError("user exists"))

    script = IOBuffer()
    write(script, "BEGIN;\n")
    write(script, ".parameter init\n")
    write(script, ".parameter set :u ", _sqlite_quote(uname), "\n")
    write(script, ".parameter set :c ", _sqlite_quote(created_at), "\n")
    write(script, ".parameter set :pca ", _sqlite_quote(password_changed_at), "\n")
    write(script, ".parameter set :tag ", _sqlite_quote(pw_tag), "\n")
    write(script, "INSERT INTO users(username, created_at, password_changed_at, pw_tag) VALUES(:u, :c, :pca, :tag);\n")
    write(script, "INSERT INTO pw_tag_history(username, seq, pw_tag, changed_at) VALUES(:u, 0, :tag, :pca);\n")

    if password_record isa Vector
        honey_index === nothing && throw(ArgumentError("honey_index required for honey record"))
        write(script, ".parameter set :real ", string(honey_index), "\n")
        write(script, "INSERT INTO honey_real(username, real_pos) VALUES(:u, :real);\n")
        for (pos, rec) in enumerate(password_record)
            rec_b64 = _b64_record(rec)
            write(script, ".parameter set :pos ", string(pos), "\n")
            write(script, ".parameter set :rb ", _sqlite_quote(rec_b64), "\n")
            write(script, "INSERT INTO pw_honey(username, pos, record_b64) VALUES(:u, :pos, :rb);\n")
        end
    elseif password_record isa AbstractDict
        # legacy support: store as single honey list with real_pos=1
        rec_b64 = _b64_record(password_record)
        write(script, "INSERT INTO honey_real(username, real_pos) VALUES(:u, 1);\n")
        write(script, ".parameter set :pos 1\n")
        write(script, ".parameter set :rb ", _sqlite_quote(rec_b64), "\n")
        write(script, "INSERT INTO pw_honey(username, pos, record_b64) VALUES(:u, :pos, :rb);\n")
    else
        throw(ArgumentError("password_record must be Dict or Vector"))
    end

    write(script, "COMMIT;\n")
    _run_sql(db, String(take!(script)))
    _trim_pw_history!(db, uname, history_size)
    return nothing
end

function _trim_pw_history!(db::DB, username::AbstractString, history_size::Int)
    history_size < 1 && return
    script = """
    .parameter init
    .parameter set :u $(_sqlite_quote(username))
    .parameter set :n $(history_size - 1)
    DELETE FROM pw_tag_history
    WHERE username=:u AND seq > :n;
    """
    _run_sql(db, script)
    return nothing
end

function verify_login_status(db::DB, username::AbstractString, password::AbstractString, pepper::AbstractString)::Symbol
    user = get_user(db, username)
    user === nothing && return :bad
    uname = String(username)

    script = """
    .parameter init
    .parameter set :u $(_sqlite_quote(uname))
    .mode list
    .separator '|'
    SELECT pos, record_b64 FROM pw_honey WHERE username=:u ORDER BY pos ASC;
    """
    out = strip(_run_sql(db, script; capture=true))
    isempty(out) && return :bad

    rows = split(out, '\n')
    match_pos = 0
    for row in rows
        isempty(row) && continue
        parts = split(row, '|', limit=2)
        length(parts) == 2 || continue
        pos = parse(Int, parts[1])
        rec = _parse_b64_record(parts[2])
        if Security.verify_password(password, rec; pepper=pepper)
            match_pos = pos
            break
        end
    end
    match_pos == 0 && return :bad

    real_out = strip(_run_sql(db, """
    .parameter init
    .parameter set :u $(_sqlite_quote(uname))
    SELECT real_pos FROM honey_real WHERE username=:u;
    """; capture=true))
    isempty(real_out) && return :bad
    real_pos = parse(Int, real_out)
    return match_pos == real_pos ? :ok : :honey
end

function verify_login(db::DB, username::AbstractString, password::AbstractString, pepper::AbstractString)::Bool
    return verify_login_status(db, username, password, pepper) == :ok
end

function record_failed_login!(db::DB, username::AbstractString; max_failed::Int=5, lockout_minutes::Int=10)
    uname = String(username)
    user_exists(db, uname) || return
    t = Dates.now(Dates.UTC) + Dates.Minute(lockout_minutes)
    locked_until = Dates.format(t, dateformat"yyyy-mm-ddTHH:MM:SSZ")
    _run_sql(db, """
    .parameter init
    .parameter set :u $(_sqlite_quote(uname))
    .parameter set :max $(max_failed)
    .parameter set :lu $(_sqlite_quote(locked_until))
    UPDATE users
    SET failed_logins = CASE WHEN failed_logins + 1 >= :max THEN 0 ELSE failed_logins + 1 END,
        locked_until  = CASE WHEN failed_logins + 1 >= :max THEN :lu ELSE locked_until END
    WHERE username=:u;
    """)
end

function reset_failed_logins!(db::DB, username::AbstractString)
    uname = String(username)
    user_exists(db, uname) || return
    _run_sql(db, """
    .parameter init
    .parameter set :u $(_sqlite_quote(uname))
    UPDATE users SET failed_logins=0, locked_until='' WHERE username=:u;
    """)
end

function password_expired(db::DB, username::AbstractString; expire_days::Int=90)::Bool
    user = get_user(db, username)
    user === nothing && return false
    changed = String(get(user, "password_changed_at", ""))
    isempty(changed) && return false
    t = try
        Dates.DateTime(changed, dateformat"yyyy-mm-ddTHH:MM:SSZ")
    catch
        return false
    end
    return (Dates.now(Dates.UTC) - t) > Dates.Day(expire_days)
end

function password_reuse_detected(db::DB, username::AbstractString, candidate_pw_tag::AbstractString; history_size::Int=5)::Bool
    uname = String(username)
    user_exists(db, uname) || return false
    script = """
    .parameter init
    .parameter set :u $(_sqlite_quote(uname))
    .parameter set :tag $(_sqlite_quote(candidate_pw_tag))
    .parameter set :n $(history_size)
    SELECT CASE WHEN EXISTS(
        SELECT 1 FROM (
            SELECT pw_tag FROM pw_tag_history
            WHERE username=:u
            ORDER BY seq DESC
            LIMIT :n
        ) WHERE pw_tag=:tag LIMIT 1
    ) THEN 1 ELSE 0 END;
    """
    out = strip(_run_sql(db, script; capture=true))
    return out == "1"
end

function count_password_tag(db::DB, pw_tag::AbstractString)::Int
    script = """
    .parameter init
    .parameter set :tag $(_sqlite_quote(pw_tag))
    SELECT COUNT(*) FROM users WHERE pw_tag=:tag;
    """
    out = strip(_run_sql(db, script; capture=true))
    return isempty(out) ? 0 : parse(Int, out)
end

function update_password!(
    db::DB,
    username::AbstractString,
    new_password::AbstractString,
    pepper::AbstractString;
    history_size::Int=5,
    honey_count::Int=7,
    pw_tag::AbstractString,
)
    uname = String(username)
    user_exists(db, uname) || throw(ArgumentError("unknown user"))
    now_utc = Dates.format(Dates.now(Dates.UTC), dateformat"yyyy-mm-ddTHH:MM:SSZ")

    honeywords, real_index = Security.generate_honeywords(new_password, uname; count=honey_count)
    honey_hashes = [Security.hash_password(w; pepper=pepper) for w in honeywords]

    script = IOBuffer()
    write(script, "BEGIN;\n")
    write(script, ".parameter init\n")
    write(script, ".parameter set :u ", _sqlite_quote(uname), "\n")
    write(script, ".parameter set :pca ", _sqlite_quote(now_utc), "\n")
    write(script, ".parameter set :tag ", _sqlite_quote(pw_tag), "\n")
    write(script, ".parameter set :real ", string(real_index), "\n")
    write(script, "UPDATE users SET password_changed_at=:pca, pw_tag=:tag WHERE username=:u;\n")
    write(script, "UPDATE honey_real SET real_pos=:real WHERE username=:u;\n")
    write(script, "DELETE FROM pw_honey WHERE username=:u;\n")
    for (pos, rec) in enumerate(honey_hashes)
        rec_b64 = _b64_record(rec)
        write(script, ".parameter set :pos ", string(pos), "\n")
        write(script, ".parameter set :rb ", _sqlite_quote(rec_b64), "\n")
        write(script, "INSERT INTO pw_honey(username, pos, record_b64) VALUES(:u, :pos, :rb);\n")
    end

    # Shift history (seq+1), then insert new at seq 0.
    write(script, "UPDATE pw_tag_history SET seq = seq + 1 WHERE username=:u;\n")
    write(script, "INSERT OR REPLACE INTO pw_tag_history(username, seq, pw_tag, changed_at) VALUES(:u, 0, :tag, :pca);\n")
    write(script, "COMMIT;\n")
    _run_sql(db, String(take!(script)))
    _trim_pw_history!(db, uname, history_size)
    return nothing
end

function mfa_totp_enabled(db::DB, username::AbstractString)::Bool
    user = get_user(db, username)
    user === nothing && return false
    return Bool(get(user, "mfa_totp_enabled", false))
end

function get_totp_secret(db::DB, username::AbstractString)::Union{Nothing,String}
    user = get_user(db, username)
    user === nothing && return nothing
    secret = String(get(user, "mfa_totp_secret_b32", ""))
    isempty(secret) && return nothing
    return secret
end

function set_totp_secret!(db::DB, username::AbstractString, secret_b32::AbstractString)
    uname = String(username)
    user_exists(db, uname) || throw(ArgumentError("unknown user"))
    _run_sql(db, """
    .parameter init
    .parameter set :u $(_sqlite_quote(uname))
    .parameter set :s $(_sqlite_quote(secret_b32))
    UPDATE users SET mfa_totp_secret_b32=:s, mfa_totp_enabled=1 WHERE username=:u;
    """)
end

function clear_totp!(db::DB, username::AbstractString)
    uname = String(username)
    user_exists(db, uname) || throw(ArgumentError("unknown user"))
    _run_sql(db, """
    .parameter init
    .parameter set :u $(_sqlite_quote(uname))
    UPDATE users SET mfa_totp_secret_b32='', mfa_totp_enabled=0 WHERE username=:u;
    """)
end

function allow_action!(::DB, key::AbstractString; capacity::Float64=10.0, refill_per_sec::Float64=0.2)::Bool
    lock(_RATE_LOCK) do
        k = String(key)
        entry = get!(_RATE, k, Dict{String, Any}("tokens" => capacity, "updated_at" => Dates.now(Dates.UTC)))
        tokens = Float64(get(entry, "tokens", capacity))
        lastt = get(entry, "updated_at", Dates.now(Dates.UTC))
        nowt = Dates.now(Dates.UTC)
        dt = max(0.0, Dates.value(nowt - lastt) / 1000.0)
        tokens = min(capacity, tokens + dt * refill_per_sec)
        allowed = tokens >= 1.0
        if allowed
            tokens -= 1.0
        end
        entry["tokens"] = tokens
        entry["updated_at"] = nowt
        _RATE[k] = entry
        return allowed
    end
end

end # module
