#!/usr/bin/env julia

# Keep all Julia packages local to this repo (avoid global ~/.julia).
let local_depot = joinpath(@__DIR__, ".julia")
    ENV["JULIA_DEPOT_PATH"] = local_depot
    try
        empty!(Base.DEPOT_PATH)
        push!(Base.DEPOT_PATH, local_depot)
    catch
    end
end

import Pkg
Pkg.activate(@__DIR__)

function ensure_project_ready!()
    try
        Pkg.instantiate(; update_registry=false)
        return
    catch e
        msg = sprint(showerror, e)
        println("\nPkg.instantiate failed: ", msg)
        println("Attempting `Pkg.resolve()` + `Pkg.instantiate()` (may require network on first run)...\n")
        try
            Pkg.resolve()
            Pkg.instantiate()
            return
        catch e2
            msg2 = sprint(showerror, e2)
            println("\nFailed to prepare environment: ", msg2)
            println("\nIf this is a fresh repo/depot, run once:")
            println("  export JULIA_DEPOT_PATH=\"$(@__DIR__)/.julia\" && julia --project=. -e 'using Pkg; Pkg.resolve(); Pkg.instantiate()'")
            rethrow(e2)
        end
    end
end

ensure_project_ready!()

include("src/DevTools.jl")
include("src/WebServer.jl")

using .DevTools
using .SecureRegWeb
using Random
using Base64

function _rand_token_hex(nbytes::Int)::String
    rd = RandomDevice()
    return bytes2hex(rand(rd, UInt8, nbytes))
end

function _dotenv_parse_line(line::AbstractString)
    s = strip(String(line))
    isempty(s) && return nothing
    startswith(s, "#") && return nothing
    i = findfirst(==('='), s)
    i === nothing && return nothing
    k = strip(s[begin:prevind(s, i)])
    v = strip(s[nextind(s, i):end])
    if isempty(k)
        return nothing
    end
    # Trim surrounding quotes.
    if (startswith(v, "\"") && endswith(v, "\"") && lastindex(v) >= 2) || (startswith(v, "'") && endswith(v, "'") && lastindex(v) >= 2)
        v = v[2:end-1]
    end
    return String(k) => String(v)
end

function load_dotenv!(path::AbstractString=joinpath(@__DIR__, ".env"); override::Bool=false)
    isfile(path) || return Dict{String,String}()
    parsed = Dict{String,String}()
    for line in eachline(path)
        kv = _dotenv_parse_line(line)
        kv === nothing && continue
        parsed[first(kv)] = last(kv)
        if override || !haskey(ENV, first(kv))
            ENV[first(kv)] = last(kv)
        end
    end
    return parsed
end

function _dotenv_write(path::AbstractString, dict::Dict{String,String})
    # Stable order for readability.
    keys_sorted = sort(collect(keys(dict)))
    io = IOBuffer()
    for k in keys_sorted
        v = dict[k]
        write(io, k, "=\"", v, "\"\n")
    end
    open(path, "w") do f
        write(f, String(take!(io)))
    end
    try
        chmod(path, 0o600)
    catch
    end
end

function ensure_env_secrets!()
    env_path = joinpath(@__DIR__, ".env")
    parsed = load_dotenv!(env_path; override=false)

    changed = false
    for key in ("APP_SERVER_SECRET", "APP_PEPPER", "APP_PW_TAG_KEY")
        if !haskey(parsed, key) || isempty(parsed[key])
            parsed[key] = _rand_token_hex(32)
            ENV[key] = parsed[key]
            changed = true
        end
    end
    if !haskey(parsed, "APP_ENV") || isempty(parsed["APP_ENV"])
        parsed["APP_ENV"] = "dev"
        ENV["APP_ENV"] = "dev"
        changed = true
    end
    if !haskey(parsed, "APP_COOKIE_SECURE") || isempty(parsed["APP_COOKIE_SECURE"])
        parsed["APP_COOKIE_SECURE"] = "0"
        ENV["APP_COOKIE_SECURE"] = "0"
        changed = true
    end

    if changed
        _dotenv_write(env_path, parsed)
        println("Dev: updated `.env` (added missing secrets/config).")
    end
end

ensure_env_secrets!()

ENV["APP_REQUIRE_MFA"] = get(ENV, "APP_REQUIRE_MFA", "1")
ENV["APP_LOG_REQUESTS"] = get(ENV, "APP_LOG_REQUESTS", "1")
ENV["APP_AUDIT_STDOUT"] = get(ENV, "APP_AUDIT_STDOUT", "1")

# if get(ENV, "APP_SEED", "1") in ("1", "true", "TRUE", "yes", "YES")
#     DevTools.seed_demo_user!()
# end

println("Starting SecureRegWeb for browser testing...")
println("- URL: http://$(get(ENV, "APP_HOST", "127.0.0.1")):$(get(ENV, "APP_PORT", "8080"))")
println("- Logs: stdout + SQLite audit in `data/audit.db`")
println("- Stop: Ctrl+C (or type `q` + Enter)\n")

Base.exit_on_sigint(false)
server = SecureRegWeb.start()

function _shutdown!(server; reason::AbstractString)
    println("\nShutting down ($(reason)).")
    try
        close(server)
    catch
    end
    try
        wait(server)
    catch
    end
    println("Stopped.")
end

try
    while true
        eof(stdin) && break
        line = readline(stdin)
        s = lowercase(strip(line))
        if s in ("q", "quit", "exit")
            _shutdown!(server; reason="q")
            break
        end
    end
catch e
    if e isa InterruptException
        _shutdown!(server; reason="Ctrl+C")
    else
        rethrow()
    end
end
