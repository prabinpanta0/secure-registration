module MLDefense

export RiskResult, Telemetry, parse_telemetry, risk_assess

using Dates
import Base.Threads

struct RiskResult
    score::Float64
    label::String
    reasons::Vector{String}
end

struct Telemetry
    keys::Float64
    pastes::Float64
    mouse::Float64
    focus_changes::Float64
    kd_mean_ms::Float64
    kd_std_ms::Float64
    focus_ms::Float64
    jitter::Float64
    straight::Float64
    honeypot::Float64
end

Telemetry() = Telemetry(0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

const _MEM_WINDOW_S = 30.0 * 60.0
const _MEM_MAX_EVENTS = 64
const _CLEAN_EVERY = 512

const _SHARDS_INIT_LOCK = ReentrantLock()
const _SHARD_LOCKS = Ref{Vector{ReentrantLock}}()
const _SHARD_MAPS = Ref{Vector{Dict{String,Any}}}()
const _SHARD_CALLS = Ref{Vector{Int}}()

# Optional dependency: DataStructures.jl for CircularBuffer (fallback provided).
const _USE_DS = Ref(false)
try
    @eval using DataStructures
    _USE_DS[] = true
catch
    _USE_DS[] = false
end

mutable struct _LocalCircularBuffer
    data::Vector{Float64}
    head::Int
    len::Int
end

function _LocalCircularBuffer(cap::Int)
    return _LocalCircularBuffer(fill(0.0, cap), 0, 0)
end

function _cb_capacity(cb::_LocalCircularBuffer)::Int
    return length(cb.data)
end

function _cb_push!(cb::_LocalCircularBuffer, x::Float64)
    cap = _cb_capacity(cb)
    cap == 0 && return cb
    cb.head = (cb.head % cap) + 1
    cb.data[cb.head] = x
    cb.len = min(cap, cb.len + 1)
    return cb
end

function _cb_count_recent(cb::_LocalCircularBuffer, cutoff::Float64)::Int
    n = 0
    cap = _cb_capacity(cb)
    cap == 0 && return 0
    # order not needed; scan len elements
    @inbounds for i in 1:cb.len
        idx = cb.head - (i - 1)
        idx <= 0 && (idx += cap)
        cb.data[idx] >= cutoff && (n += 1)
    end
    return n
end

_cb_new(cap::Int) = _USE_DS[] ? DataStructures.CircularBuffer{Float64}(cap) : _LocalCircularBuffer(cap)

function _cb_push!(cb, x::Float64)
    if _USE_DS[]
        push!(cb, x)
        return cb
    else
        return _cb_push!(cb::_LocalCircularBuffer, x)
    end
end

function _cb_count_recent(cb, cutoff::Float64)::Int
    if _USE_DS[]
        n = 0
        @inbounds for t in cb
            t >= cutoff && (n += 1)
        end
        return n
    else
        return _cb_count_recent(cb::_LocalCircularBuffer, cutoff)
    end
end

mutable struct _MemEntry
    buf
    last_seen::Float64
end

function _ensure_shards!()
    if isassigned(_SHARD_LOCKS) && isassigned(_SHARD_MAPS) && isassigned(_SHARD_CALLS)
        return nothing
    end
    lock(_SHARDS_INIT_LOCK) do
        if isassigned(_SHARD_LOCKS) && isassigned(_SHARD_MAPS) && isassigned(_SHARD_CALLS)
            return nothing
        end
        n = max(16, 2 * Threads.nthreads())
        _SHARD_LOCKS[] = [ReentrantLock() for _ in 1:n]
        _SHARD_MAPS[] = [Dict{String,Any}() for _ in 1:n]
        _SHARD_CALLS[] = fill(0, n)
        return nothing
    end
end

function parse_telemetry(s::AbstractString)::Telemetry
    # Format: "k:v;k:v;..." where v is numeric. Missing/invalid entries are ignored.
    str = strip(String(s))
    isempty(str) && return Telemetry()

    keys = 0.0
    pastes = 0.0
    mouse = 0.0
    focus_changes = 0.0
    kd_mean_ms = 0.0
    kd_std_ms = 0.0
    focus_ms = 0.0
    jitter = 0.0
    straight = 0.0
    honeypot = 0.0

    for part in eachsplit(str, ';')
        isempty(part) && continue
        kv = split(part, ':', limit=2)
        length(kv) == 2 || continue
        k = strip(kv[1])
        v = try
            parse(Float64, strip(kv[2]))
        catch
            continue
        end
        if k == "keys"
            keys = v
        elseif k == "pastes"
            pastes = v
        elseif k == "mouse"
            mouse = v
        elseif k == "focus"
            focus_changes = v
        elseif k == "kd_mean_ms"
            kd_mean_ms = v
        elseif k == "kd_std_ms"
            kd_std_ms = v
        elseif k == "focus_ms"
            focus_ms = v
        elseif k == "jitter"
            jitter = v
        elseif k == "straight"
            straight = v
        elseif k == "honeypot"
            honeypot = v
        end
    end

    return Telemetry(keys, pastes, mouse, focus_changes, kd_mean_ms, kd_std_ms, focus_ms, jitter, straight, honeypot)
end

@inline function _sigmoid(z::Float64)::Float64
    if z >= 0
        ez = exp(-z)
        return 1.0 / (1.0 + ez)
    else
        ez = exp(z)
        return ez / (1.0 + ez)
    end
end

@inline _clamp01(x::Float64)::Float64 = x < 0 ? 0.0 : x > 1 ? 1.0 : x

function _mem_key(; ip_token::AbstractString="", endpoint::AbstractString="")::String
    it = isempty(ip_token) ? "ip:unknown" : String(ip_token)
    ep = isempty(endpoint) ? "ep:unknown" : "ep:" * String(endpoint)
    return it * "|" * ep
end

function _mem_reputation_score!(now_s::Float64; ip_token::AbstractString="", endpoint::AbstractString="")::Float64
    isempty(ip_token) && return 0.0
    _ensure_shards!()
    key = _mem_key(; ip_token=ip_token, endpoint=endpoint)
    locks = _SHARD_LOCKS[]
    maps = _SHARD_MAPS[]
    calls = _SHARD_CALLS[]
    shard = mod1(hash(key), length(locks))

    lock(locks[shard]) do
        calls[shard] += 1
        cutoff = now_s - _MEM_WINDOW_S

        entry = get(maps[shard], key, nothing)
        if entry === nothing
            buf = _cb_new(_MEM_MAX_EVENTS)
            entry = _MemEntry(buf, now_s)
            maps[shard][key] = entry
        end

        _cb_push!(entry.buf, now_s)
        entry.last_seen = now_s

        # Occasional cleanup to prevent unbounded growth
        if calls[shard] % _CLEAN_EVERY == 0
            stale_cut = cutoff
            dead = String[]
            for (k, e) in maps[shard]
                (e isa _MemEntry) || continue
                if e.last_seen < stale_cut
                    push!(dead, k)
                end
            end
            for k in dead
                delete!(maps[shard], k)
            end
        end

        n_recent = _cb_count_recent(entry.buf, cutoff)
        return _clamp01((n_recent - 1) / 8.0)
    end
end

"""
ML-inspired risk scoring.

This is intentionally lightweight (no external ML packages) and should be described as a prototype:
- A tiny 1-hidden-layer neural net takes normalized behavioral signals and outputs a risk probability.
- Reasons are returned for explainability (important for secure design, auditing, and grading).
"""
function risk_assess(;
    ua_suspicious::Bool,
    form_age_ms::Float64,
    telemetry::Telemetry,
    ip_token::AbstractString="",
    endpoint::AbstractString="",
    now::DateTime=Dates.now(Dates.UTC),
)
    reasons = String[]

    if telemetry.honeypot > 0
        push!(reasons, "Honeypot field was filled (bot)")
        return RiskResult(1.0, "High", reasons)
    end

    keystrokes = telemetry.keys
    pastes = telemetry.pastes
    mouse = telemetry.mouse
    focus = telemetry.focus_changes
    kd_mean_ms = telemetry.kd_mean_ms
    kd_std_ms = telemetry.kd_std_ms
    focus_ms = telemetry.focus_ms
    jitter = telemetry.jitter
    straight = telemetry.straight

    form_age_s = max(0.0, form_age_ms / 1000.0)
    hour = Dates.hour(now)

    if ua_suspicious
        push!(reasons, "Suspicious User-Agent")
    end
    if form_age_s > 0 && form_age_s < 1.5
        push!(reasons, "Submitted too fast (bot-like)")
    end
    if mouse <= 0
        push!(reasons, "No mouse movement observed")
    end
    if pastes >= 2
        push!(reasons, "Multiple paste events")
    end
    if keystrokes <= 1 && pastes >= 1
        push!(reasons, "Paste-heavy input (credential stuffing pattern)")
    end
    if focus >= 6
        push!(reasons, "Excessive focus changes (automation or tab-switching)")
    end
    if focus_ms > 0 && form_age_ms > 0
        ratio = focus_ms / max(form_age_ms, 1.0)
        if ratio < 0.35 && form_age_ms > 1500
            push!(reasons, "Low focused time ratio (background automation)")
        end
    end
    if hour in (0, 1, 2, 3, 4)
        push!(reasons, "Unusual submission time (late-night anomaly)")
    end
    if straight >= 0.95 && mouse > 0
        push!(reasons, "Mouse path looks too straight (scripted)")
    end
    if jitter <= 0.01 && mouse > 0
        push!(reasons, "Low pointer jitter (non-human smoothness)")
    end
    if kd_mean_ms > 0
        if kd_mean_ms < 25
            push!(reasons, "Keystroke timing too fast (automation)")
        elseif kd_std_ms > 0
            cv = kd_std_ms / max(kd_mean_ms, 1.0)
            if cv < 0.08
                push!(reasons, "Keystroke timing too regular (bot-like rhythm)")
            end
        end
    end

    # Endpoint-aware priors (login stricter too)
    ep = lowercase(String(endpoint))
    prior =
        ep == "register" ? 0.08 :
        ep == "login" ? 0.06 :
        startswith(ep, "mfa") ? 0.04 : 0.02

    # Saturating transforms (avoid huge negative values)
    # - fast submissions => higher risk
    τ = 2.0
    fast01 = exp(-form_age_s / τ)               # 0..1
    fast = 2.0 * fast01 - 1.0                   # -1..1

    # - mouse/keys are "human signals": more => lower risk
    mouse_h01 = 1.0 - exp(-min(mouse, 30.0) / 6.0)
    mouse_r01 = 1.0 - mouse_h01
    keys_h01 = 1.0 - exp(-min(keystrokes, 200.0) / 25.0)
    keys_r01 = 1.0 - keys_h01
    paste_r01 = 1.0 - exp(-min(pastes, 10.0) / 1.5)
    focus_r01 = 1.0 - exp(-min(focus, 20.0) / 4.0)

    # Keystroke rhythm risk (0..1)
    rhythm_r01 = 0.0
    if kd_mean_ms > 0 && kd_std_ms > 0
        cv = kd_std_ms / max(kd_mean_ms, 1.0)
        rhythm_r01 = _clamp01((0.20 - min(cv, 0.20)) / 0.20) # cv small => higher risk
    end

    # Normalize inputs into roughly [-1, 1] for NN
    x = zeros(Float64, 6)
    x[1] = ua_suspicious ? 1.0 : -1.0
    x[2] = clamp(fast, -1.0, 1.0)
    x[3] = 2.0 * mouse_r01 - 1.0
    x[4] = 2.0 * paste_r01 - 1.0
    x[5] = 2.0 * keys_r01 - 1.0
    x[6] = 2.0 * rhythm_r01 - 1.0

    # Tiny neural net: 6 -> 5 -> 1 (hand-tuned weights; prototype)
    W1 = [
         1.10  0.60  0.70  0.20  0.50  0.10;
         0.20  0.80  0.30  0.10  0.60  0.15;
         0.70  0.40  0.90  0.10  0.20  0.10;
         0.15  0.20  0.10  0.85  0.10  0.05;
         0.10  0.15  0.10  0.05  0.20  0.80;
    ]
    b1 = [0.10, 0.05, 0.10, -0.05, 0.00]
    h = similar(b1)
    @inbounds for i in eachindex(b1)
        s = b1[i]
        for j in eachindex(x)
            s += W1[i, j] * x[j]
        end
        h[i] = tanh(s)
    end
    W2 = [1.10, 0.90, 1.05, 0.85, 0.60]
    b2 = 0.10
    z = b2
    @inbounds for i in eachindex(W2)
        z += W2[i] * h[i]
    end
    nn_score = _sigmoid(z)

    # Layer 2: rule score (transparent)
    rule_score = 0.0
    rule_score += ua_suspicious ? 0.30 : 0.0
    rule_score += (form_age_s > 0 && form_age_s < 1.5) ? 0.25 : 0.0
    rule_score += 0.15 * mouse_r01
    rule_score += 0.15 * paste_r01
    rule_score += 0.10 * keys_r01
    rule_score += 0.10 * focus_r01
    rule_score += 0.10 * rhythm_r01
    rule_score += (hour in (0, 1, 2, 3, 4)) ? 0.05 : 0.0
    rule_score = _clamp01(rule_score)

    # Layer 3: memory/reputation (continuous auth prototype)
    now_s = Dates.datetime2unix(now)
    rep_score = _mem_reputation_score!(now_s; ip_token=ip_token, endpoint=ep)
    if rep_score >= 0.40
        push!(reasons, "Repeated attempts from same source (reputation)")
    end

    # Ensemble (defense-in-depth): blend model + rules + reputation
    # Reputation is weighted high to reliably trigger step-up under repeated attempts.
    score = _clamp01(0.40 * nn_score + 0.15 * rule_score + 0.45 * rep_score + prior)

    label = score >= 0.80 ? "High" : score >= 0.55 ? "Medium" : "Low"
    if isempty(reasons) && label == "Low"
        push!(reasons, "Normal-looking interaction")
    elseif isempty(reasons)
        push!(reasons, "No explicit rule matched; elevated risk inferred from model feature combinations")
    end

    return RiskResult(score, label, reasons)
end

end # module
