using Test

include(joinpath(@__DIR__, "..", "src", "Security.jl"))
include(joinpath(@__DIR__, "..", "src", "Storage.jl"))
include(joinpath(@__DIR__, "..", "src", "MLDefense.jl"))

using .Security
using .Storage
using .MLDefense

@testset "Security primitives" begin
    rep = Security.password_strength("CorrectHorseBatteryStaple!2026", "alice")
    @test rep.score >= 60

    secret = Security.totp_secret()
    code = Security.totp_code(secret)
    @test Security.totp_verify(secret, code)

    pow = Security.pow_generate(difficulty_bits=14)
    c = String(pow["challenge"])
    d = Int(pow["difficulty_bits"])
    nonce = Security.pow_solve(c, d; max_tries=2_000_000)
    @test nonce !== nothing
    @test Security.pow_verify(c, UInt64(nonce), d)
end

@testset "Honeywords" begin
    mktempdir() do dir
        db_path = joinpath(dir, "secure_reg_test_users.db")
        db = Storage.load_db(db_path)
        pepper = "pep"
        tag_key = "tagkey"
        honey, idx = Security.generate_honeywords("TestPass!1234", "alice"; count=7)
        @test honey[idx] == "TestPass!1234"
        @test length(unique(honey)) == length(honey)

        hashes = [Security.hash_password(w; pepper=pepper) for w in honey]
        tag = Security.password_tag("TestPass!1234"; key=tag_key)
        Storage.create_user!(db, "alice"; created_at="t", password_record=hashes, password_changed_at="t", honey_index=idx, pw_tag=tag)

        @test Storage.verify_login_status(db, "alice", "TestPass!1234", pepper) == :ok
        @test Storage.verify_login_status(db, "alice", honey[mod1(idx + 1, length(honey))], pepper) == :honey
    end
end

@testset "ML defense" begin
    tel = MLDefense.parse_telemetry("keys:12;pastes:0;mouse:3;focus:1;kd_mean_ms:120;kd_std_ms:55;focus_ms:1800;honeypot:0")
    r = MLDefense.risk_assess(ua_suspicious=true, form_age_ms=200.0, telemetry=tel, ip_token="tok", endpoint="login")
    @test r.score >= 0.5
    @test !isempty(r.reasons)

    tel_hp = MLDefense.parse_telemetry("honeypot:1")
    r2 = MLDefense.risk_assess(ua_suspicious=false, form_age_ms=4000.0, telemetry=tel_hp, ip_token="tok", endpoint="login")
    @test r2.label == "High"
    @test r2.score >= 0.99

    # Reputation burst should raise risk over time for same source.
    tel_ok = MLDefense.parse_telemetry("keys:20;pastes:0;mouse:3;focus:0;kd_mean_ms:110;kd_std_ms:60;focus_ms:2500;honeypot:0")
    last = nothing
    for _ in 1:10
        last = MLDefense.risk_assess(ua_suspicious=false, form_age_ms=1200.0, telemetry=tel_ok, ip_token="same", endpoint="login")
    end
    @test last !== nothing
    @test (last::MLDefense.RiskResult).label in ("Medium", "High")

    if Threads.nthreads() > 1
        futs = [Threads.@spawn begin
            for _ in 1:200
                MLDefense.risk_assess(ua_suspicious=false, form_age_ms=900.0, telemetry=tel_ok, ip_token="p", endpoint="login")
            end
            true
        end for _ in 1:Threads.nthreads()]
        @test all(fetch.(futs))
    end
end
