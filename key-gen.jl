using Random
using Printf

"""
    generate_secure_key_hex(n_bytes::Int)

Generates unbiased cryptographic key material from the OS CSPRNG.
"""
function generate_secure_key_hex(n_bytes::Int)
    rd = RandomDevice()
    bytes = rand(rd, UInt8, n_bytes)
    return bytes2hex(bytes)
end

# --- Execution ---

println("# Generated Security Keys for SecureReg")
println("---------------------------------------")

keys = Dict(
    "APP_SERVER_SECRET" => generate_secure_key_hex(32),
    "APP_PEPPER"        => generate_secure_key_hex(32),
    "APP_PW_TAG_KEY"    => generate_secure_key_hex(32)
)

for (name, val) in keys
    @printf("%s=\"%s\"\n", name, val)
end
