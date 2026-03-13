module DevTools

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
using Dates
using Random
using Base64

function _now_utc_s()::String
    return Dates.format(Dates.now(Dates.UTC), dateformat"yyyy-mm-ddTHH:MM:SSZ")
end

function _rand_token(nbytes::Int)::String
    return base64encode(rand(Random.default_rng(), UInt8, nbytes))
end

function seed_demo_user!(; username::String="demo", password::Union{Nothing,String}=nothing, enable_totp::Bool=true)
    db = Storage.load_db()

    if Storage.user_exists(db, username)
        println("Seed: user '$username' already exists (skipping).")
        return nothing
    end

    pepper = get(ENV, "APP_PEPPER", "")
    tag_key = get(ENV, "APP_PW_TAG_KEY", get(ENV, "APP_SERVER_SECRET", ""))
    pw = password === nothing ? ("Demo-" * _rand_token(12) * "!") : password
    honeywords, honey_index = Security.generate_honeywords(pw, username; count=7)
    honey_hashes = [Security.hash_password(w; pepper=pepper) for w in honeywords]
    now_utc = _now_utc_s()
    tag = Security.password_tag(pw; key=tag_key)

    Storage.create_user!(
        db,
        username;
        created_at=now_utc,
        password_record=honey_hashes,
        password_changed_at=now_utc,
        history_size=5,
        honey_index=honey_index,
        pw_tag=tag,
    )

    secret = ""
    if enable_totp
        secret = Security.totp_secret()
        Storage.set_totp_secret!(db, username, secret)
    end

    Storage.save_db(db)
    Audit.log_event("seed_demo_user"; username=username)

    println("\nSeeded demo user:")
    println("- username: ", username)
    println("- password: ", pw)
    if enable_totp
        println("- TOTP secret (Base32): ", secret)
        println("- otpauth URL: otpauth://totp/SecureRegWeb:$username?secret=$(secret)&issuer=SecureRegWeb&digits=6&period=30")
    else
        println("- TOTP: disabled")
    end
    println()
    return nothing
end

end # module
