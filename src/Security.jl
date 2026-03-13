module Security

using Random
using SHA
using Base64
using Dates

const _COMMON_PASSWORDS_CACHE = Ref{Union{Nothing, Set{String}}}(nothing)

function _load_common_passwords()
    path = joinpath(@__DIR__, "passwords", "most-common-passwords.txt")
    if !isfile(path)
        return Set{String}()
    end
    pwset = Set{String}()
    open(path, "r") do io
        for ln in eachline(io)
            s = strip(ln)
            isempty(s) && continue
            push!(pwset, lowercase(s))
        end
    end
    return pwset
end

function common_passwords()::Set{String}
    cached = _COMMON_PASSWORDS_CACHE[]
    if cached === nothing
        _COMMON_PASSWORDS_CACHE[] = _load_common_passwords()
        cached = _COMMON_PASSWORDS_CACHE[]
    end
    return cached::Set{String}
end

struct PasswordReport
    score::Int
    label::String
    entropy_bits::Float64
    feedback::Vector{String}
end

function _consttime_eq(a::Vector{UInt8}, b::Vector{UInt8})::Bool
    if length(a) != length(b)
        return false
    end
    acc::UInt8 = 0x00
    @inbounds for i in eachindex(a)
        acc |= a[i] ⊻ b[i]
    end
    return acc == 0x00
end

function pbkdf2_hmac_sha256(password::Vector{UInt8}, salt::Vector{UInt8}; iterations::Int=200_000, dklen::Int=32)
    iterations < 1 && throw(ArgumentError("iterations must be >= 1"))
    dklen < 1 && throw(ArgumentError("dklen must be >= 1"))

    hlen = 32
    blocks = Int(ceil(dklen / hlen))
    out = Vector{UInt8}(undef, 0)

    for block_index in 1:blocks
        int4 = UInt8[(block_index >> 24) & 0xff, (block_index >> 16) & 0xff, (block_index >> 8) & 0xff, block_index & 0xff]
        u = SHA.hmac_sha256(password, vcat(salt, int4))
        t = copy(u)
        for _ in 2:iterations
            u = SHA.hmac_sha256(password, u)
            @inbounds for i in eachindex(t)
                t[i] ⊻= u[i]
            end
        end
        append!(out, t)
    end

    return out[1:dklen]
end

function _has_cmd(cmdname::AbstractString)::Bool
    return Sys.which(cmdname) !== nothing
end

function _b64url(s::AbstractString)::String
    t = replace(String(s), "+" => "-")
    t = replace(t, "/" => "_")
    t = replace(t, "=" => "")
    return t
end

function password_tag(password::AbstractString; key::AbstractString)::String
    mac = SHA.hmac_sha256(collect(codeunits(String(key))), collect(codeunits(String(password))))
    return _b64url(base64encode(mac))
end

function _run_capture(cmd::Cmd, stdin_bytes::Vector{UInt8})::Vector{UInt8}
    out = IOBuffer()
    run(pipeline(cmd; stdin=IOBuffer(stdin_bytes), stdout=out, stderr=devnull))
    return take!(out)
end

"""
Argon2id password hashing using the system `argon2` CLI (if available).

Stores parameters so verification can be done by recomputation + constant-time compare.
"""
function argon2id_hash(password::AbstractString; pepper::AbstractString="", t::Int=3, m_log2::Int=16, p::Int=1, hashlen::Int=32, version::Int=13)
    _has_cmd("argon2") || throw(ArgumentError("argon2 CLI not found"))
    rd = RandomDevice()
    salt_bytes = rand(rd, UInt8, 16)
    salt_b64 = base64encode(salt_bytes)  # CLI salt is treated as bytes of the string; store the exact string.
    pw_bytes = collect(codeunits(string(password, pepper, "\n")))
    cmd = `argon2 $salt_b64 -id -t $t -m $m_log2 -p $p -l $hashlen -r -v $version`
    raw = _run_capture(cmd, pw_bytes)
    return Dict(
        "alg" => "argon2id-cli",
        "t" => t,
        "m_log2" => m_log2,
        "p" => p,
        "hashlen" => hashlen,
        "version" => version,
        "salt_b64" => salt_b64,
        "hash_b64" => base64encode(raw),
    )
end

function argon2id_verify(password::AbstractString, record::AbstractDict; pepper::AbstractString="")::Bool
    _has_cmd("argon2") || return false
    get(record, "alg", "") == "argon2id-cli" || return false
    salt_b64 = String(get(record, "salt_b64", ""))
    expected = base64decode(String(get(record, "hash_b64", "")))

    t = Int(get(record, "t", 0))
    m_log2 = Int(get(record, "m_log2", 0))
    p = Int(get(record, "p", 0))
    hashlen = Int(get(record, "hashlen", length(expected)))
    version = Int(get(record, "version", 13))
    (t > 0 && m_log2 > 0 && p > 0 && hashlen > 0) || return false

    pw_bytes = collect(codeunits(string(password, pepper, "\n")))
    cmd = `argon2 $salt_b64 -id -t $t -m $m_log2 -p $p -l $hashlen -r -v $version`
    got = try
        _run_capture(cmd, pw_bytes)
    catch
        return false
    end
    return _consttime_eq(got, expected)
end

function hash_password(password::AbstractString; pepper::AbstractString="", iterations::Int=200_000)
    if _has_cmd("argon2")
        return argon2id_hash(password; pepper=pepper)
    else
        rd = RandomDevice()
        salt = rand(rd, UInt8, 16)
        pw_bytes = collect(codeunits(string(password, pepper)))
        dk = pbkdf2_hmac_sha256(pw_bytes, salt; iterations=iterations, dklen=32)
        return Dict(
            "alg" => "pbkdf2-hmac-sha256",
            "iterations" => iterations,
            "salt_b64" => base64encode(salt),
            "hash_b64" => base64encode(dk),
        )
    end
end

function verify_password(password::AbstractString, record::AbstractDict; pepper::AbstractString="")::Bool
    alg = get(record, "alg", "")
    if alg == "argon2id-cli"
        return argon2id_verify(password, record; pepper=pepper)
    elseif alg == "pbkdf2-hmac-sha256"
        iterations = Int(get(record, "iterations", 0))
        iterations > 0 || return false
        salt = base64decode(String(get(record, "salt_b64", "")))
        expected = base64decode(String(get(record, "hash_b64", "")))

        pw_bytes = collect(codeunits(string(password, pepper)))
        got = pbkdf2_hmac_sha256(pw_bytes, salt; iterations=iterations, dklen=length(expected))
        return _consttime_eq(got, expected)
    else
        return false
    end
end

function _has_lower(s) any(c -> 'a' <= c <= 'z', s) end
function _has_upper(s) any(c -> 'A' <= c <= 'Z', s) end
function _has_digit(s) any(isdigit, s) end
function _has_symbol(s) any(c -> !((isletter(c) || isdigit(c)) || c == '_'), s) end

function _entropy_estimate_bits(password::AbstractString)::Float64
    s = collect(password)
    has_lower = _has_lower(s)
    has_upper = _has_upper(s)
    has_digit = _has_digit(s)
    has_symbol = _has_symbol(s)
    pool = 0
    pool += has_lower ? 26 : 0
    pool += has_upper ? 26 : 0
    pool += has_digit ? 10 : 0
    pool += has_symbol ? 33 : 0
    pool = max(pool, 1)
    return length(s) * log2(pool)
end

function _looks_sequential(password::AbstractString)::Bool
    s = lowercase(password)
    seqs = ["0123456789", "abcdefghijklmnopqrstuvwxyz"]
    for seq in seqs
        for i in 1:(lastindex(seq) - 3)
            part = seq[i:i+3]
            if occursin(part, s) || occursin(reverse(part), s)
                return true
            end
        end
    end
    return false
end

function _has_repeated_runs(password::AbstractString)::Bool
    s = collect(password)
    run = 1
    for i in (firstindex(s) + 1):lastindex(s)
        if s[i] == s[i-1]
            run += 1
            if run >= 4
                return true
            end
        else
            run = 1
        end
    end
    return false
end

function password_strength(password::AbstractString, username::AbstractString="")::PasswordReport
    pw = String(password)
    un = lowercase(String(username))
    s = collect(pw)
    feedback = String[]

    entropy = _entropy_estimate_bits(pw)

    score = 0
    len = length(s)
    score += len < 8 ? 0 : len < 12 ? 10 : len < 16 ? 25 : len < 20 ? 35 : 40

    classes = 0
    has_lower = _has_lower(s); has_lower && (classes += 1)
    has_upper = _has_upper(s); has_upper && (classes += 1)
    has_digit = _has_digit(s); has_digit && (classes += 1)
    has_symbol = _has_symbol(s); has_symbol && (classes += 1)
    score += min(20, classes * 5 + (classes >= 3 ? 2 : 0))

    score += min(20, Int(floor(entropy / 4)))

    lower_pw = lowercase(pw)
    if lower_pw in common_passwords()
        score -= 30
        push!(feedback, "Avoid common passwords found in cracking lists.")
    end
    if !isempty(un) && occursin(un, lower_pw) && length(un) >= 3
        score -= 15
        push!(feedback, "Do not include your username in your password.")
    end
    if _looks_sequential(pw)
        score -= 10
        push!(feedback, "Avoid sequences like 'abcd' or '1234'.")
    end
    if _has_repeated_runs(pw)
        score -= 10
        push!(feedback, "Avoid repeated characters like 'aaaa'.")
    end

    if len < 12
        push!(feedback, "Use at least 12 characters (longer is better).")
    elseif len < 16
        push!(feedback, "16+ characters is noticeably stronger against guessing attacks.")
    end

    if !has_upper
        push!(feedback, "Add uppercase letters.")
    end
    if !has_lower
        push!(feedback, "Add lowercase letters.")
    end
    if !has_digit
        push!(feedback, "Add digits.")
    end
    if !has_symbol
        push!(feedback, "Add symbols (e.g., !@#?).")
    end
    if classes <= 2
        push!(feedback, "Mix character types to increase the search space.")
    end

    score = clamp(score, 0, 100)
    label = score < 30 ? "Weak" : score < 60 ? "Moderate" : score < 80 ? "Strong" : "Very strong"

    if isempty(feedback)
        push!(feedback, "Good choice. Prefer unique passphrases you don't reuse anywhere else.")
    else
        push!(feedback, "Prefer unique passwords and consider a password manager.")
    end

    return PasswordReport(score, label, entropy, feedback)
end

function generate_honeywords(password::AbstractString, username::AbstractString=""; count::Int=7)
    count < 3 && throw(ArgumentError("count must be >= 3"))
    pw = String(password)
    un = String(username)

    candidates = String[]

    # Variants that attackers commonly try when cracking dumps (plausible honeywords).
    base = replace(pw, r"\s+" => "")
    push!(candidates, base)
    push!(candidates, lowercase(base))
    push!(candidates, uppercasefirst(lowercase(base)))
    push!(candidates, base * "!")
    push!(candidates, base * "1")
    push!(candidates, base * "2026")
    push!(candidates, base * "#")
    push!(candidates, replace(base, "a" => "@"))
    push!(candidates, replace(base, "i" => "1"))
    push!(candidates, replace(base, "o" => "0"))
    if !isempty(un)
        push!(candidates, base * "_" * un)
        push!(candidates, un * "_" * base)
    end

    # Deduplicate while preserving order.
    seen = Set{String}()
    uniq = String[]
    for c in candidates
        isempty(c) && continue
        c2 = c[1:min(end, 128)]
        c2 == pw && continue
        if !(c2 in seen)
            push!(uniq, c2)
            push!(seen, c2)
        end
    end

    # Ensure we have enough honeywords; pad with random-looking strings.
    rng = Random.default_rng()
    while length(uniq) < count
        push!(uniq, base64encode(rand(rng, UInt8, 12)))
    end

    # Randomize the position of the real password; ensure it appears exactly once.
    real_index = rand(rng, 1:count)
    honey = Vector{String}(undef, count)
    fill_idx = 1
    for i in 1:count
        if i == real_index
            honey[i] = pw
        else
            honey[i] = uniq[fill_idx]
            fill_idx += 1
        end
    end
    return honey, real_index
end

function generate_math_captcha()
    ops = [:+, :-, :*]
    op = rand(ops)
    if op == :*
        a = rand(2:12)
        b = rand(2:12)
    else
        a = rand(10:99)
        b = rand(1:20)
    end
    ans = op == :+ ? a + b : op == :- ? a - b : a * b
    sym = op == :+ ? "+" : op == :- ? "-" : "×"
    question = "Solve: $a $sym $b = ?"
    return question, ans
end

function run_math_captcha(; seconds_limit::Int=30)::Bool
    question, ans = generate_math_captcha()
    println(question, " (you have $(seconds_limit)s)")
    t0 = time()
    print("Answer: ")
    input = try
        strip(readline())
    catch
        return false
    end
    if time() - t0 > seconds_limit
        println("Time limit exceeded.")
        return false
    end
    got = try
        parse(Int, input)
    catch
        return false
    end
    return got == ans
end

const _B32_ALPH = collect("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
const _B32_MAP = Dict{Char, UInt8}(c => UInt8(i - 1) for (i, c) in enumerate(_B32_ALPH))

function base32encode(data::Vector{UInt8})::String
    out = IOBuffer()
    buffer = UInt32(0)
    bits = 0
    for b in data
        buffer = (buffer << 8) | UInt32(b)
        bits += 8
        while bits >= 5
            idx = Int((buffer >> (bits - 5)) & 0x1f) + 1
            write(out, _B32_ALPH[idx])
            bits -= 5
        end
    end
    if bits > 0
        idx = Int((buffer << (5 - bits)) & 0x1f) + 1
        write(out, _B32_ALPH[idx])
    end
    return String(take!(out))
end

function base32decode(s::AbstractString)::Vector{UInt8}
    clean = replace(uppercase(String(s)), "=" => "")
    buffer = UInt32(0)
    bits = 0
    out = UInt8[]
    for ch in clean
        haskey(_B32_MAP, ch) || throw(ArgumentError("invalid base32 character"))
        buffer = (buffer << 5) | UInt32(_B32_MAP[ch])
        bits += 5
        while bits >= 8
            push!(out, UInt8((buffer >> (bits - 8)) & 0xff))
            bits -= 8
        end
    end
    return out
end

function totp_secret(; nbytes::Int=20)::String
    rd = RandomDevice()
    return base32encode(rand(rd, UInt8, nbytes))
end

function _hotp(secret_b32::AbstractString, counter::UInt64; digits::Int=6)::String
    key = base32decode(secret_b32)
    msg = UInt8[
        (counter >> 56) & 0xff,
        (counter >> 48) & 0xff,
        (counter >> 40) & 0xff,
        (counter >> 32) & 0xff,
        (counter >> 24) & 0xff,
        (counter >> 16) & 0xff,
        (counter >> 8) & 0xff,
        counter & 0xff,
    ]
    mac = SHA.hmac_sha1(key, msg)
    offset = (mac[end] & 0x0f) + 1
    bin =
        ((UInt32(mac[offset]) & 0x7f) << 24) |
        (UInt32(mac[offset + 1]) << 16) |
        (UInt32(mac[offset + 2]) << 8) |
        UInt32(mac[offset + 3])
    mod = UInt32(10)^UInt32(digits)
    code = Int(bin % mod)
    return lpad(string(code), digits, '0')
end

function totp_code(secret_b32::AbstractString; timestamp::Int=Int(floor(time())), step::Int=30, digits::Int=6)::String
    counter = UInt64(fld(timestamp, step))
    return _hotp(secret_b32, counter; digits=digits)
end

function _constant_time_eq(a::AbstractString, b::AbstractString)::Bool
    aa = Vector{UInt8}(codeunits(String(a)))
    bb = Vector{UInt8}(codeunits(String(b)))
    diff = UInt32(length(aa) ⊻ length(bb))
    n = max(length(aa), length(bb))
    @inbounds for i in 1:n
        x = i <= length(aa) ? aa[i] : 0x00
        y = i <= length(bb) ? bb[i] : 0x00
        diff |= UInt32(x ⊻ y)
    end
    return diff == 0x00000000
end

function totp_verify(secret_b32::AbstractString, code::AbstractString; window::Int=1, step::Int=30, digits::Int=6)::Bool
    c = strip(String(code))
    length(c) == digits || return false
    nowt = Int(floor(time()))
    base_counter = fld(nowt, step)
    for delta in -window:window
        expected = _hotp(secret_b32, UInt64(base_counter + delta); digits=digits)
        if _constant_time_eq(expected, c)
            return true
        end
    end
    return false
end

function pow_generate(; difficulty_bits::Int=20)
    rd = RandomDevice()
    challenge = base64encode(rand(rd, UInt8, 16))
    return Dict("challenge" => challenge, "difficulty_bits" => difficulty_bits)
end

function _leading_zero_bits(bytes::Vector{UInt8})::Int
    n = 0
    for b in bytes
        if b == 0x00
            n += 8
            continue
        end
        for i in 7:-1:0
            if ((b >> i) & 0x01) == 0
                n += 1
            else
                return n
            end
        end
    end
    return n
end

function pow_verify(challenge::AbstractString, nonce::UInt64, difficulty_bits::Int)::Bool
    msg = string(challenge, ":", nonce)
    digest = SHA.sha256(collect(codeunits(msg)))
    return _leading_zero_bits(digest) >= difficulty_bits
end

function pow_solve(challenge::AbstractString, difficulty_bits::Int; max_tries::Int=10_000_000)
    for nonce in 0:UInt64(max_tries - 1)
        if pow_verify(challenge, nonce, difficulty_bits)
            return nonce
        end
    end
    return nothing
end

end # module
