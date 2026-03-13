#!/usr/bin/env julia
function _dotenv_parse_line(line::AbstractString)
    s = strip(String(line))
    isempty(s) && return nothing
    startswith(s, "#") && return nothing
    i = findfirst(==('='), s)
    i === nothing && return nothing
    k = strip(s[begin:prevind(s, i)])
    v = strip(s[nextind(s, i):end])
    isempty(k) && return nothing
    if (startswith(v, "\"") && endswith(v, "\"") && lastindex(v) >= 2) || (startswith(v, "'") && endswith(v, "'") && lastindex(v) >= 2)
        v = v[2:end-1]
    end
    return String(k) => String(v)
end

function load_dotenv!(path::AbstractString=".env"; override::Bool=false)
    isfile(path) || return
    for line in eachline(path)
        kv = _dotenv_parse_line(line)
        kv === nothing && continue
        (override || !haskey(ENV, first(kv))) && (ENV[first(kv)] = last(kv))
    end
end

load_dotenv!(joinpath(@__DIR__, ".env"); override=false)

include("src/WebServer.jl")

using .SecureRegWeb

SecureRegWeb.main()
