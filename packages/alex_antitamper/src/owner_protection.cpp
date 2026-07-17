#include "alex/owner_protection.hpp"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>
#include <cctype>
#include <fstream>
#include <iomanip>
#include <limits>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>

namespace alex::owner
{
namespace
{

constexpr std::uint64_t kMagicA = 814701623ull;
constexpr std::uint64_t kMagicB = 372819541ull;
constexpr std::uint64_t kVersion = 2ull;
constexpr size_t kCapsuleValues = 26;

using PkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using MdContextPtr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;

std::uint64_t fnv1a64(std::string_view text)
{
    std::uint64_t hash = 1469598103934665603ull;
    for (unsigned char byte : text)
    {
        hash ^= byte;
        hash *= 1099511628211ull;
    }
    return hash;
}

std::string trim(std::string_view value)
{
    size_t first = 0;
    while (first < value.size() && std::isspace(static_cast<unsigned char>(value[first])))
        ++first;
    size_t last = value.size();
    while (last > first && std::isspace(static_cast<unsigned char>(value[last - 1])))
        --last;
    return std::string(value.substr(first, last - first));
}

std::unordered_map<std::string, std::string> parseKv(std::string_view text, std::string_view expectedHeader)
{
    std::unordered_map<std::string, std::string> result;
    std::istringstream input{std::string(text)};
    std::string line;
    if (!std::getline(input, line) || trim(line) != expectedHeader)
        throw std::runtime_error("invalid owner key header; vNext requires an Ed25519 v2 key");
    while (std::getline(input, line))
    {
        size_t separator = line.find('=');
        if (separator != std::string::npos)
            result[trim(std::string_view(line).substr(0, separator))] = trim(std::string_view(line).substr(separator + 1));
    }
    return result;
}

std::uint64_t parseU64(const std::unordered_map<std::string, std::string>& fields, const char* name)
{
    auto found = fields.find(name);
    if (found == fields.end())
        throw std::runtime_error(std::string("missing owner key field: ") + name);
    size_t used = 0;
    std::uint64_t value = std::stoull(found->second, &used, 10);
    if (used != found->second.size())
        throw std::runtime_error(std::string("invalid owner key field: ") + name);
    return value;
}

template<size_t Size>
std::string hex(const std::array<std::uint8_t, Size>& bytes)
{
    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (std::uint8_t byte : bytes)
        output << std::setw(2) << static_cast<unsigned>(byte);
    return output.str();
}

template<size_t Size>
std::array<std::uint8_t, Size> parseHex(std::string_view value, const char* field)
{
    if (value.size() != Size * 2)
        throw std::runtime_error(std::string("invalid Ed25519 ") + field + " length");
    std::array<std::uint8_t, Size> bytes{};
    for (size_t i = 0; i < Size; ++i)
    {
        auto digit = [](char character) -> int {
            if (character >= '0' && character <= '9')
                return character - '0';
            if (character >= 'a' && character <= 'f')
                return character - 'a' + 10;
            if (character >= 'A' && character <= 'F')
                return character - 'A' + 10;
            return -1;
        };
        int high = digit(value[i * 2]);
        int low = digit(value[i * 2 + 1]);
        if (high < 0 || low < 0)
            throw std::runtime_error(std::string("invalid Ed25519 ") + field + " encoding");
        bytes[i] = static_cast<std::uint8_t>((high << 4) | low);
    }
    return bytes;
}

std::string readText(const std::filesystem::path& path)
{
    std::ifstream input(path, std::ios::binary);
    if (!input)
        throw std::runtime_error("could not open owner key: " + path.string());
    std::ostringstream contents;
    contents << input.rdbuf();
    return contents.str();
}

void writeText(const std::filesystem::path& path, std::string_view text)
{
    if (!path.parent_path().empty())
        std::filesystem::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::binary);
    if (!output)
        throw std::runtime_error("could not write owner key: " + path.string());
    output.write(text.data(), static_cast<std::streamsize>(text.size()));
}

std::string signatureMessage(const Capsule& capsule)
{
    std::ostringstream message;
    message << "alex-owner-ed25519-v2|" << capsule.owner_hash << "|"
            << static_cast<unsigned>(capsule.mode == ProtectMode::SignAndLock ? 2 : 1) << "|"
            << capsule.nonce << "|" << capsule.payload_digest << "|" << kMagicA << "|" << kMagicB << "|" << kVersion;
    return message.str();
}

PkeyPtr privatePkey(const std::array<std::uint8_t, 32>& seed)
{
    EVP_PKEY* raw = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, seed.data(), seed.size());
    if (!raw)
        throw std::runtime_error("OpenSSL could not create an Ed25519 private key");
    return PkeyPtr(raw, EVP_PKEY_free);
}

PkeyPtr publicPkey(const std::array<std::uint8_t, 32>& bytes)
{
    EVP_PKEY* raw = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, bytes.data(), bytes.size());
    if (!raw)
        throw std::runtime_error("OpenSSL could not create an Ed25519 public key");
    return PkeyPtr(raw, EVP_PKEY_free);
}

std::vector<std::uint64_t> extractNumbers(std::string_view source)
{
    std::vector<std::uint64_t> numbers;
    for (size_t i = 0; i < source.size();)
    {
        if (!std::isdigit(static_cast<unsigned char>(source[i])))
        {
            ++i;
            continue;
        }
        std::uint64_t value = 0;
        while (i < source.size() && std::isdigit(static_cast<unsigned char>(source[i])))
        {
            unsigned digit = static_cast<unsigned>(source[i++] - '0');
            if (value <= (std::numeric_limits<std::uint64_t>::max() - digit) / 10ull)
                value = value * 10ull + digit;
        }
        numbers.push_back(value);
    }
    return numbers;
}

} // namespace

constexpr std::uint64_t capsule_magic_a()
{
    return kMagicA;
}

constexpr std::uint64_t capsule_magic_b()
{
    return kMagicB;
}

std::string protect_mode_name(ProtectMode mode)
{
    switch (mode)
    {
    case ProtectMode::Off:
        return "off";
    case ProtectMode::Sign:
        return "sign";
    case ProtectMode::SignAndLock:
        return "sign-and-lock";
    }
    return "off";
}

ProtectMode parse_protect_mode(std::string_view value)
{
    if (value == "off" || value == "none" || value == "0")
        return ProtectMode::Off;
    if (value == "sign" || value == "signed")
        return ProtectMode::Sign;
    if (value == "sign-and-lock" || value == "lock" || value == "locked" || value == "on")
        return ProtectMode::SignAndLock;
    throw std::runtime_error("--owner-protect expects off, sign, or sign-and-lock");
}

std::uint32_t owner_hash(std::string_view ownerId)
{
    return static_cast<std::uint32_t>(fnv1a64(ownerId) & 0xffffffffu);
}

std::uint64_t payload_digest(std::string_view payload, std::uint32_t ownerHash, std::uint64_t nonce)
{
    std::uint64_t digest = fnv1a64(payload);
    digest ^= static_cast<std::uint64_t>(ownerHash) << 17u;
    digest *= 1099511628211ull;
    digest ^= nonce + 0x9e3779b97f4a7c15ull + (digest << 6u) + (digest >> 2u);
    return digest;
}

std::uint32_t capsule_guard_hash(const std::vector<std::uint64_t>& values)
{
    std::uint32_t hash = 0;
    for (size_t i = 0; i < values.size(); ++i)
        hash = static_cast<std::uint32_t>((static_cast<std::uint64_t>(hash) * 131u + (values[i] % 65536u) + static_cast<std::uint32_t>(i + 1) * 17u) & 0xffffu);
    return hash == 0 ? 1u : hash;
}

PrivateKey generate_keypair(std::string ownerId, std::uint64_t seed)
{
    if (ownerId.empty())
        ownerId = "alex";
    PrivateKey key;
    key.public_key.owner_id = ownerId;
    key.public_key.owner_hash = owner_hash(ownerId);
    if (seed == 0)
    {
        if (RAND_bytes(key.ed25519_seed.data(), static_cast<int>(key.ed25519_seed.size())) != 1)
            throw std::runtime_error("OpenSSL could not generate Ed25519 key material");
    }
    else
    {
        std::string material = ownerId + "|" + std::to_string(seed) + "|alex-owner-ed25519-v2";
        unsigned int size = 0;
        if (EVP_Digest(material.data(), material.size(), key.ed25519_seed.data(), &size, EVP_sha256(), nullptr) != 1 || size != key.ed25519_seed.size())
            throw std::runtime_error("OpenSSL could not derive deterministic Ed25519 key material");
    }
    PkeyPtr pkey = privatePkey(key.ed25519_seed);
    size_t publicSize = key.public_key.ed25519_public.size();
    if (EVP_PKEY_get_raw_public_key(pkey.get(), key.public_key.ed25519_public.data(), &publicSize) != 1 || publicSize != key.public_key.ed25519_public.size())
        throw std::runtime_error("OpenSSL could not derive the Ed25519 public key");
    return key;
}

std::string serialize_public_key(const PublicKey& key)
{
    std::ostringstream output;
    output << "alex-owner-public-v2\nalgorithm=Ed25519\nowner_id=" << key.owner_id << "\nowner_hash=" << key.owner_hash << "\npublic=" << hex(key.ed25519_public) << "\n";
    return output.str();
}

std::string serialize_private_key(const PrivateKey& key)
{
    std::ostringstream output;
    output << "alex-owner-private-v2\nalgorithm=Ed25519\nowner_id=" << key.public_key.owner_id << "\nowner_hash=" << key.public_key.owner_hash
           << "\npublic=" << hex(key.public_key.ed25519_public) << "\nseed=" << hex(key.ed25519_seed) << "\n";
    return output.str();
}

PublicKey parse_public_key(std::string_view text)
{
    auto fields = parseKv(text, "alex-owner-public-v2");
    if (fields["algorithm"] != "Ed25519")
        throw std::runtime_error("unsupported owner signature algorithm");
    PublicKey key;
    key.owner_id = fields.count("owner_id") ? fields["owner_id"] : "alex";
    key.owner_hash = static_cast<std::uint32_t>(parseU64(fields, "owner_hash"));
    key.ed25519_public = parseHex<32>(fields["public"], "public key");
    if (key.owner_hash == 0)
        throw std::runtime_error("invalid owner public key values");
    return key;
}

PrivateKey parse_private_key(std::string_view text)
{
    auto fields = parseKv(text, "alex-owner-private-v2");
    if (fields["algorithm"] != "Ed25519")
        throw std::runtime_error("unsupported owner signature algorithm");
    PrivateKey key;
    key.public_key.owner_id = fields.count("owner_id") ? fields["owner_id"] : "alex";
    key.public_key.owner_hash = static_cast<std::uint32_t>(parseU64(fields, "owner_hash"));
    key.public_key.ed25519_public = parseHex<32>(fields["public"], "public key");
    key.ed25519_seed = parseHex<32>(fields["seed"], "private seed");
    PrivateKey derived = generate_keypair(key.public_key.owner_id, 1);
    PkeyPtr pkey = privatePkey(key.ed25519_seed);
    size_t publicSize = derived.public_key.ed25519_public.size();
    if (EVP_PKEY_get_raw_public_key(pkey.get(), derived.public_key.ed25519_public.data(), &publicSize) != 1 || derived.public_key.ed25519_public != key.public_key.ed25519_public)
        throw std::runtime_error("owner private key does not match its public key");
    return key;
}

PublicKey read_public_key(const std::filesystem::path& path)
{
    return parse_public_key(readText(path));
}

PrivateKey read_private_key(const std::filesystem::path& path)
{
    return parse_private_key(readText(path));
}

void write_keypair(const std::filesystem::path& prefix, const PrivateKey& key)
{
    writeText(prefix.string() + ".private", serialize_private_key(key));
    writeText(prefix.string() + ".public", serialize_public_key(key.public_key));
}

Capsule sign_capsule(std::string_view payload, ProtectMode mode, const PrivateKey& key, std::uint64_t nonce)
{
    if (mode == ProtectMode::Off)
        return {};
    Capsule capsule;
    capsule.mode = mode;
    capsule.owner_hash = key.public_key.owner_hash;
    capsule.nonce = nonce;
    capsule.payload_digest = payload_digest(payload, capsule.owner_hash, nonce);
    std::string message = signatureMessage(capsule);
    PkeyPtr pkey = privatePkey(key.ed25519_seed);
    MdContextPtr context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    size_t signatureSize = capsule.signature.size();
    if (!context || EVP_DigestSignInit(context.get(), nullptr, nullptr, nullptr, pkey.get()) != 1 ||
        EVP_DigestSign(context.get(), capsule.signature.data(), &signatureSize, reinterpret_cast<const unsigned char*>(message.data()), message.size()) != 1 ||
        signatureSize != capsule.signature.size())
        throw std::runtime_error("OpenSSL Ed25519 signing failed");

    capsule.values = {kMagicA, kMagicB, kVersion, mode == ProtectMode::SignAndLock ? 2ull : 1ull, capsule.owner_hash,
        capsule.nonce & 0xffffffffull, capsule.nonce >> 32u, capsule.payload_digest & 0xffffffffull, capsule.payload_digest >> 32u};
    for (size_t offset = 0; offset < capsule.signature.size(); offset += 4)
    {
        std::uint64_t word = static_cast<std::uint64_t>(capsule.signature[offset]) |
            (static_cast<std::uint64_t>(capsule.signature[offset + 1]) << 8u) |
            (static_cast<std::uint64_t>(capsule.signature[offset + 2]) << 16u) |
            (static_cast<std::uint64_t>(capsule.signature[offset + 3]) << 24u);
        capsule.values.push_back(word);
    }
    capsule.values.push_back(capsule_guard_hash(capsule.values));
    return capsule;
}

std::optional<Capsule> capsule_from_values(const std::vector<std::uint64_t>& values)
{
    if (values.size() < kCapsuleValues || values[0] != kMagicA || values[1] != kMagicB || values[2] != kVersion || (values[3] != 1 && values[3] != 2))
        return std::nullopt;
    std::vector<std::uint64_t> withoutChecksum(values.begin(), values.begin() + static_cast<std::ptrdiff_t>(kCapsuleValues - 1));
    if ((values[kCapsuleValues - 1] & 0xffffu) != capsule_guard_hash(withoutChecksum))
        return std::nullopt;
    Capsule capsule;
    capsule.mode = values[3] == 2 ? ProtectMode::SignAndLock : ProtectMode::Sign;
    capsule.owner_hash = static_cast<std::uint32_t>(values[4]);
    capsule.nonce = (values[5] & 0xffffffffull) | ((values[6] & 0xffffffffull) << 32u);
    capsule.payload_digest = (values[7] & 0xffffffffull) | ((values[8] & 0xffffffffull) << 32u);
    for (size_t word = 0; word < 16; ++word)
    {
        std::uint64_t value = values[9 + word];
        for (size_t byte = 0; byte < 4; ++byte)
            capsule.signature[word * 4 + byte] = static_cast<std::uint8_t>((value >> (byte * 8u)) & 0xffu);
    }
    capsule.values.assign(values.begin(), values.begin() + static_cast<std::ptrdiff_t>(kCapsuleValues));
    return capsule;
}

bool verify_capsule(const Capsule& capsule, const PublicKey& key)
{
    if (capsule.owner_hash != key.owner_hash)
        return false;
    std::string message = signatureMessage(capsule);
    PkeyPtr pkey = publicPkey(key.ed25519_public);
    MdContextPtr context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    return context && EVP_DigestVerifyInit(context.get(), nullptr, nullptr, nullptr, pkey.get()) == 1 &&
        EVP_DigestVerify(context.get(), capsule.signature.data(), capsule.signature.size(), reinterpret_cast<const unsigned char*>(message.data()), message.size()) == 1;
}

ScanResult scan_source(std::string_view source, const std::vector<PublicKey>& keys)
{
    ScanResult result;
    std::vector<std::uint64_t> numbers = extractNumbers(source);
    for (size_t i = 0; i + kCapsuleValues <= numbers.size(); ++i)
    {
        if (numbers[i] != kMagicA || numbers[i + 1] != kMagicB)
            continue;
        result.present = true;
        std::vector<std::uint64_t> window(numbers.begin() + static_cast<std::ptrdiff_t>(i), numbers.begin() + static_cast<std::ptrdiff_t>(i + kCapsuleValues));
        std::optional<Capsule> capsule = capsule_from_values(window);
        if (!capsule)
        {
            result.invalid = true;
            result.reason = "owner capsule checksum or shape is invalid";
            continue;
        }
        result.owner_hash = capsule->owner_hash;
        result.nonce = capsule->nonce;
        for (const PublicKey& key : keys)
        {
            if (verify_capsule(*capsule, key))
            {
                result.verified = true;
                result.invalid = false;
                result.owner_id = key.owner_id;
                result.reason = "verified Ed25519 owner capsule";
                return result;
            }
        }
        result.invalid = true;
        result.reason = "owner capsule Ed25519 signature did not match configured public keys";
    }
    return result;
}

} // namespace alex::owner
