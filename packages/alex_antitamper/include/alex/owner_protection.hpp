#pragma once

#include <array>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace alex::owner
{

enum class ProtectMode
{
    Off,
    Sign,
    SignAndLock,
};

struct PublicKey
{
    std::string owner_id = "alex";
    std::uint32_t owner_hash = 0;
    std::array<std::uint8_t, 32> ed25519_public{};
};

struct PrivateKey
{
    PublicKey public_key;
    std::array<std::uint8_t, 32> ed25519_seed{};
};

struct Capsule
{
    ProtectMode mode = ProtectMode::Off;
    std::uint32_t owner_hash = 0;
    std::uint64_t nonce = 0;
    std::uint64_t payload_digest = 0;
    std::array<std::uint8_t, 64> signature{};
    std::vector<std::uint64_t> values;
};

struct ScanResult
{
    bool present = false;
    bool verified = false;
    bool invalid = false;
    std::string owner_id;
    std::uint32_t owner_hash = 0;
    std::uint64_t nonce = 0;
    std::string reason;
};

constexpr std::uint64_t capsule_magic_a();
constexpr std::uint64_t capsule_magic_b();

std::string protect_mode_name(ProtectMode mode);
ProtectMode parse_protect_mode(std::string_view value);

std::uint32_t owner_hash(std::string_view owner_id);
std::uint64_t payload_digest(std::string_view payload, std::uint32_t owner_hash, std::uint64_t nonce);
std::uint32_t capsule_guard_hash(const std::vector<std::uint64_t>& values);

PrivateKey generate_keypair(std::string owner_id, std::uint64_t seed = 0);
std::string serialize_public_key(const PublicKey& key);
std::string serialize_private_key(const PrivateKey& key);
PublicKey parse_public_key(std::string_view text);
PrivateKey parse_private_key(std::string_view text);
PublicKey read_public_key(const std::filesystem::path& path);
PrivateKey read_private_key(const std::filesystem::path& path);
void write_keypair(const std::filesystem::path& prefix, const PrivateKey& key);

Capsule sign_capsule(std::string_view payload, ProtectMode mode, const PrivateKey& key, std::uint64_t nonce);
std::optional<Capsule> capsule_from_values(const std::vector<std::uint64_t>& values);
bool verify_capsule(const Capsule& capsule, const PublicKey& key);
ScanResult scan_source(std::string_view source, const std::vector<PublicKey>& keys);

} // namespace alex::owner
