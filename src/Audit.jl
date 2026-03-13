module Audit

using Dates

const AUDIT_DB_PATH = joinpath(@__DIR__, "..", "data", "audit.db")
const _INIT = Ref(false)
const _HAS_PARAMETER = Ref{Union{Nothing,Bool}}(nothing)

function _sqlite_quote(s::AbstractString)::String
    # SQL string literal quoting: single-quote and escape internal quotes by doubling.
    return "'" * replace(String(s), "'" => "''") * "'"
end

function _ensure_db()
    dir = dirname(AUDIT_DB_PATH)
    isdir(dir) || mkpath(dir)
    try
        chmod(dir, 0o700)
    catch
    end
    if _INIT[]
        return nothing
    end
    cmd = `sqlite3 -batch $(AUDIT_DB_PATH)`
    schema = """
    PRAGMA journal_mode=WAL;
    PRAGMA synchronous=NORMAL;
    CREATE TABLE IF NOT EXISTS audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL,
        username TEXT,
        action TEXT NOT NULL,
        detail TEXT
    );
    """
    err = IOBuffer()
    try
        run(pipeline(cmd; stdin=IOBuffer(schema), stdout=devnull, stderr=err))
    catch e
        msg = String(take!(err))
        throw(ErrorException("Audit DB init failed: $(isempty(msg) ? sprint(showerror, e) : msg)"))
    end
    try
        chmod(AUDIT_DB_PATH, 0o600)
    catch
    end
    _INIT[] = true
    return nothing
end

"""
Append an audit event using a parameterized SQLite insert via the `sqlite3` CLI.

This illustrates injection-resistant database writes without requiring external Julia DB packages.
"""
function log_event(action::AbstractString; username::AbstractString="", detail::AbstractString="")
    _ensure_db()
    ts = Dates.format(Dates.now(Dates.UTC), dateformat"yyyy-mm-ddTHH:MM:SSZ")
    if get(ENV, "APP_AUDIT_STDOUT", "0") in ("1", "true", "TRUE", "yes", "YES")
        u = isempty(username) ? "-" : String(username)
        d = isempty(detail) ? "" : (" | " * String(detail))
        try
            println("[AUDIT] ", ts, " | ", u, " | ", String(action), d)
        catch
        end
    end

    # Detect whether sqlite3 supports ".parameter" (once).
    if _HAS_PARAMETER[] === nothing
        err = IOBuffer()
        ok = true
        try
            run(pipeline(`sqlite3 -batch $(AUDIT_DB_PATH)`; stdin=IOBuffer(".parameter init\nSELECT 1;\n"), stdout=devnull, stderr=err))
        catch
            ok = false
        end
        _HAS_PARAMETER[] = ok
    end

    script = IOBuffer()
    if _HAS_PARAMETER[] === true
        write(script, ".parameter init\n")
        write(script, ".parameter set :ts ", _sqlite_quote(ts), "\n")
        write(script, ".parameter set :u ", _sqlite_quote(username), "\n")
        write(script, ".parameter set :a ", _sqlite_quote(action), "\n")
        write(script, ".parameter set :d ", _sqlite_quote(detail), "\n")
        write(script, "INSERT INTO audit(ts, username, action, detail) VALUES(:ts, :u, :a, :d);\n")
    else
        write(script, "INSERT INTO audit(ts, username, action, detail) VALUES(",
              _sqlite_quote(ts), ",", _sqlite_quote(username), ",", _sqlite_quote(action), ",", _sqlite_quote(detail), ");\n")
    end

    cmd = `sqlite3 -batch $(AUDIT_DB_PATH)`
    errbuf = IOBuffer()
    try
        run(pipeline(cmd; stdin=IOBuffer(String(take!(script))), stdout=devnull, stderr=errbuf))
    catch e
        msg = String(take!(errbuf))
        throw(ErrorException("Audit log_event failed: action=$(action) username=$(username) ts=$(ts) err=$(isempty(msg) ? sprint(showerror, e) : msg)"))
    end
    return nothing
end

end # module
