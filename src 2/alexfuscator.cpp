#include "Luau/Parser.h"
#include "alex/owner_protection.hpp"
#include "alexfuscator/alex_language.hpp"

#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <numeric>
#include <optional>
#include <random>
#include <set>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#if defined(_WIN32)
#include <io.h>
#else
#include <unistd.h>
#endif

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace
{

enum class Profile
{
    Compatibility,
    Hardened,
    Maximum,
};

enum class RuntimeTarget
{
    Universal,
    Roblox,
    Executor,
};

enum class KeyMode
{
    Standalone,
    Online,
};

enum class ProtectionLevel
{
    Preset,
    Off,
    Standard,
    Aggressive,
    Maximum,
};

enum class EnvironmentBinding
{
    Portable,
    Roblox,
    Executor,
};

enum class FallbackPolicy
{
    Hardened,
    Fail,
};

enum class InputLanguage
{
    Auto,
    Luau,
    Alex,
};

struct Config
{
    fs::path inputPath;
    fs::path outputPath;
    fs::path debugMapPath;
    fs::path dumpIrPath;
    fs::path dumpVmPath;
    fs::path ownerKeygenPath;
    fs::path ownerPrivateKeyPath;
    fs::path reportPath;
    Profile profile = Profile::Maximum;
    RuntimeTarget runtime = RuntimeTarget::Universal;
    KeyMode keyMode = KeyMode::Standalone;
    ProtectionLevel controlFlow = ProtectionLevel::Preset;
    ProtectionLevel constantProtection = ProtectionLevel::Preset;
    ProtectionLevel vmDiversity = ProtectionLevel::Preset;
    ProtectionLevel tamperDensity = ProtectionLevel::Preset;
    EnvironmentBinding environmentBinding = EnvironmentBinding::Portable;
    InputLanguage language = InputLanguage::Auto;
    InputLanguage effectiveLanguage = InputLanguage::Luau;
    uint64_t gameId = 0;
    std::string target = "roblox-luau";
    std::string analysisNotice;
    std::string onlineKeyUrl;
    std::string onlineKeyMaterial;
    std::string ownerId = "alex";
    bool ownerIdExplicit = false;
    std::string seedText = "auto";
    uint64_t seed = 0;
    bool watermark = false;
    bool serve = false;
    bool integrityChecks = true;
    bool integrityExplicit = false;
    bool layersExplicit = false;
    bool oneLine = true;
    bool oneLineExplicit = false;
    bool envLock = false;
    bool unsafeDebugMap = false;
    bool fallbackPolicyExplicit = false;
    bool bytecodeTrampoline = true;
    bool stage2 = true;
    bool stage2EnvKey = true;
    bool stage2FakeProto = true;
    bool stage2LazyHandlers = true;
    alex::owner::ProtectMode ownerProtect = alex::owner::ProtectMode::Off;
    int port = 8787;
    size_t layers = 1;
    FallbackPolicy fallbackPolicy = FallbackPolicy::Hardened;
    int stage2Decoys = 9;
    int stage2ChunkMin = 37;
    int stage2ChunkMax = 353;
    int reportFd = -1;
    bool diagnosticsJson = false;
};

struct CryptoLayer
{
    uint32_t key = 0;
    uint32_t salt = 0;
    uint32_t salt2 = 0;
    uint32_t multiplier = 0;
    uint32_t increment = 0;
    uint32_t variant = 0;
    uint32_t stateMul = 0;
    uint32_t stateMod = 0;
    uint32_t keyMul = 0;
    uint32_t maskMul = 0;
    uint32_t carryMul = 0;
    uint32_t carrySalt = 0;
    uint32_t streamXor = 0;
    uint32_t postMul = 0;
};

struct IntegrityDigest
{
    size_t size = 0;
    uint32_t a = 1;
    uint32_t b = 0;
    uint32_t c = 0;
    uint32_t d = 0;
};

struct PackedPayload
{
    std::string alphabet;
    std::string encoded;
    size_t plainSize = 0;
    IntegrityDigest integrity;
    std::vector<CryptoLayer> layers;
};

struct V6AeadEnvelope
{
    std::array<uint8_t, 32> key{};
    std::array<uint8_t, 32> salt{};
    std::array<uint8_t, 12> nonce{};
    std::array<uint8_t, 16> tag{};
    std::string ciphertext;
};

std::array<uint8_t, 32> hmacSha256(std::span<const uint8_t> key, std::span<const uint8_t> data)
{
    std::array<uint8_t, 32> result{};
    unsigned int length = 0;
    if (!HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), data.data(), data.size(), result.data(), &length) || length != result.size())
        throw std::runtime_error("OpenSSL HMAC-SHA256 failed");
    return result;
}

std::array<uint8_t, 32> hkdfSha256(std::span<const uint8_t> input, std::span<const uint8_t> salt, std::string_view info)
{
    std::array<uint8_t, 32> prk = hmacSha256(salt, input);
    std::vector<uint8_t> expand(info.begin(), info.end());
    expand.push_back(1);
    return hmacSha256(prk, expand);
}

V6AeadEnvelope makeV6AeadEnvelope(std::string_view plaintext, const Config& config, uint32_t guardExpected, std::mt19937_64& rng)
{
    V6AeadEnvelope envelope;
    for (uint8_t& byte : envelope.salt)
        byte = static_cast<uint8_t>(rng() & 0xffu);
    for (uint8_t& byte : envelope.nonce)
        byte = static_cast<uint8_t>(rng() & 0xffu);

    std::string material = "alexfuscator-v6|" + std::to_string(config.seed) + "|" + std::to_string(static_cast<int>(config.profile)) + "|" +
        (config.stage2EnvKey ? std::to_string(static_cast<int>(config.runtime)) + ":" + std::to_string(static_cast<int>(config.environmentBinding)) : "portable") + "|" +
        std::to_string(guardExpected) + "|" + (config.keyMode == KeyMode::Online ? config.onlineKeyMaterial : std::to_string(rng()) + ":" + std::to_string(rng()));
    envelope.key = hkdfSha256(
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(material.data()), material.size()), envelope.salt, "alexfuscator-register-vm-v6-aead");

    EVP_CIPHER_CTX* context = EVP_CIPHER_CTX_new();
    if (!context)
        throw std::runtime_error("OpenSSL could not allocate ChaCha20-Poly1305 context");
    envelope.ciphertext.resize(plaintext.size() + 16);
    int written = 0;
    int finalWritten = 0;
    bool ok = EVP_EncryptInit_ex(context, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) == 1 &&
        EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_AEAD_SET_IVLEN, static_cast<int>(envelope.nonce.size()), nullptr) == 1 &&
        EVP_EncryptInit_ex(context, nullptr, nullptr, envelope.key.data(), envelope.nonce.data()) == 1 &&
        EVP_EncryptUpdate(context, reinterpret_cast<unsigned char*>(envelope.ciphertext.data()), &written,
            reinterpret_cast<const unsigned char*>(plaintext.data()), static_cast<int>(plaintext.size())) == 1 &&
        EVP_EncryptFinal_ex(context, reinterpret_cast<unsigned char*>(envelope.ciphertext.data()) + written, &finalWritten) == 1 &&
        EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_AEAD_GET_TAG, static_cast<int>(envelope.tag.size()), envelope.tag.data()) == 1;
    EVP_CIPHER_CTX_free(context);
    if (!ok)
        throw std::runtime_error("OpenSSL ChaCha20-Poly1305 encryption failed");
    envelope.ciphertext.resize(static_cast<size_t>(written + finalWritten));
    return envelope;
}

struct OwnerBinding
{
    alex::owner::ProtectMode mode = alex::owner::ProtectMode::Off;
    bool active = false;
    bool locked = false;
    alex::owner::Capsule capsule;
    uint32_t guardHash = 0;
};

std::string readFile(const fs::path& path)
{
    if (path == "-")
    {
        std::ostringstream ss;
        ss << std::cin.rdbuf();
        return ss.str();
    }

    std::ifstream in(path, std::ios::binary);
    if (!in)
        throw std::runtime_error("failed to open input: " + path.string());

    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

void writeFile(const fs::path& path, std::string_view data)
{
    if (path == "-")
    {
        std::cout.write(data.data(), static_cast<std::streamsize>(data.size()));
        return;
    }

    if (!path.parent_path().empty())
        fs::create_directories(path.parent_path());

    std::ofstream out(path, std::ios::binary);
    if (!out)
        throw std::runtime_error("failed to open output: " + path.string());
    out.write(data.data(), static_cast<std::streamsize>(data.size()));
}

std::string profileName(Profile profile)
{
    switch (profile)
    {
    case Profile::Compatibility:
        return "compatibility";
    case Profile::Hardened:
        return "hardened";
    case Profile::Maximum:
        return "maximum";
    }
    return "maximum";
}

std::string runtimeTargetName(RuntimeTarget runtime)
{
    switch (runtime)
    {
    case RuntimeTarget::Universal:
        return "universal";
    case RuntimeTarget::Roblox:
        return "roblox";
    case RuntimeTarget::Executor:
        return "executor";
    }
    return "universal";
}

std::string keyModeName(KeyMode mode)
{
    return mode == KeyMode::Online ? "online" : "standalone";
}

std::string protectionLevelName(ProtectionLevel level)
{
    switch (level)
    {
    case ProtectionLevel::Preset:
        return "preset";
    case ProtectionLevel::Off:
        return "off";
    case ProtectionLevel::Standard:
        return "standard";
    case ProtectionLevel::Aggressive:
        return "aggressive";
    case ProtectionLevel::Maximum:
        return "maximum";
    }
    return "preset";
}

int protectionRank(ProtectionLevel level)
{
    switch (level)
    {
    case ProtectionLevel::Off:
        return 0;
    case ProtectionLevel::Standard:
        return 1;
    case ProtectionLevel::Aggressive:
        return 2;
    case ProtectionLevel::Maximum:
        return 3;
    case ProtectionLevel::Preset:
        return 0;
    }
    return 0;
}

std::string environmentBindingName(EnvironmentBinding binding)
{
    switch (binding)
    {
    case EnvironmentBinding::Portable:
        return "portable";
    case EnvironmentBinding::Roblox:
        return "roblox";
    case EnvironmentBinding::Executor:
        return "executor";
    }
    return "portable";
}

std::string inputLanguageName(InputLanguage language)
{
    switch (language)
    {
    case InputLanguage::Auto:
        return "auto";
    case InputLanguage::Luau:
        return "luau";
    case InputLanguage::Alex:
        return "alex";
    }
    return "luau";
}

InputLanguage parseInputLanguage(std::string_view value)
{
    if (value == "auto")
        return InputLanguage::Auto;
    if (value == "luau")
        return InputLanguage::Luau;
    if (value == "alex")
        return InputLanguage::Alex;
    throw std::runtime_error("--language expects auto, luau, or alex");
}

InputLanguage resolveInputLanguage(InputLanguage requested, const fs::path& inputPath)
{
    if (requested != InputLanguage::Auto)
        return requested;
    if (inputPath != "-")
    {
        std::string extension = inputPath.extension().string();
        std::transform(extension.begin(), extension.end(), extension.begin(), [](unsigned char value) { return static_cast<char>(std::tolower(value)); });
        if (extension == ".alex")
            return InputLanguage::Alex;
    }
    return InputLanguage::Luau;
}

Profile parseProfile(std::string_view value)
{
    if (value == "compatibility")
        return Profile::Compatibility;
    if (value == "hardened")
        return Profile::Hardened;
    if (value == "maximum")
        return Profile::Maximum;
    if (value == "fast" || value == "balanced" || value == "max")
        throw std::runtime_error("legacy profile '" + std::string(value) + "' was removed; use compatibility, hardened, or maximum");
    throw std::runtime_error("unknown profile '" + std::string(value) + "'; expected compatibility, hardened, or maximum");
}

RuntimeTarget parseRuntimeTarget(std::string_view value)
{
    if (value == "universal")
        return RuntimeTarget::Universal;
    if (value == "roblox")
        return RuntimeTarget::Roblox;
    if (value == "executor")
        return RuntimeTarget::Executor;
    throw std::runtime_error("--runtime expects universal, roblox, or executor");
}

KeyMode parseKeyMode(std::string_view value)
{
    if (value == "standalone")
        return KeyMode::Standalone;
    if (value == "online")
        return KeyMode::Online;
    throw std::runtime_error("--key-mode expects standalone or online");
}

ProtectionLevel parseProtectionLevel(std::string_view option, std::string_view value)
{
    if (value == "preset")
        return ProtectionLevel::Preset;
    if (value == "off")
        return ProtectionLevel::Off;
    if (value == "standard")
        return ProtectionLevel::Standard;
    if (value == "aggressive")
        return ProtectionLevel::Aggressive;
    if (value == "maximum")
        return ProtectionLevel::Maximum;
    throw std::runtime_error(std::string(option) + " expects preset, off, standard, aggressive, or maximum");
}

EnvironmentBinding parseEnvironmentBinding(std::string_view value)
{
    if (value == "portable")
        return EnvironmentBinding::Portable;
    if (value == "roblox")
        return EnvironmentBinding::Roblox;
    if (value == "executor")
        return EnvironmentBinding::Executor;
    throw std::runtime_error("--environment-binding expects portable, roblox, or executor");
}

uint64_t parseGameId(std::string_view value)
{
    if (value == "off" || value == "none")
        return 0;
    if (value.empty())
        throw std::runtime_error("--game-id expects off or a positive Roblox universe ID");

    constexpr uint64_t maxExactLuaInteger = 9007199254740991ull;
    uint64_t result = 0;
    for (char ch : value)
    {
        if (ch < '0' || ch > '9')
            throw std::runtime_error("--game-id expects off or a positive Roblox universe ID");
        uint64_t digit = static_cast<uint64_t>(ch - '0');
        if (result > (maxExactLuaInteger - digit) / 10u)
            throw std::runtime_error("--game-id exceeds the largest exact Luau integer");
        result = result * 10u + digit;
    }
    if (result == 0)
        throw std::runtime_error("--game-id expects a positive Roblox universe ID");
    return result;
}

uint64_t fnv1a64(std::string_view text)
{
    uint64_t h = 1469598103934665603ull;
    for (unsigned char c : text)
    {
        h ^= c;
        h *= 1099511628211ull;
    }
    return h;
}

uint64_t autoSeed()
{
    uint64_t now = static_cast<uint64_t>(std::chrono::high_resolution_clock::now().time_since_epoch().count());
    std::random_device rd;
    uint64_t a = static_cast<uint64_t>(rd()) << 32;
    uint64_t b = static_cast<uint64_t>(rd());
    return now ^ a ^ b;
}

uint64_t parseSeed(const std::string& text)
{
    if (text.empty() || text == "auto")
        return autoSeed();

    char* end = nullptr;
    uint64_t value = std::strtoull(text.c_str(), &end, 0);
    if (end && *end == '\0')
        return value;

    return fnv1a64(text);
}

std::string defaultOutputFor(const fs::path& inputPath)
{
    std::string stem = inputPath.stem().string();
    if (stem.empty())
        stem = "script";
    return (fs::path("outputs") / "alexfuscator" / (stem + ".obf.luau")).string();
}

void validateLuau(std::string_view source)
{
    Luau::Allocator allocator;
    Luau::AstNameTable names(allocator);
    Luau::ParseResult result = Luau::Parser::parse(source.data(), source.size(), names, allocator);

    if (result.root && result.errors.empty())
        return;

    std::ostringstream ss;
    ss << "input is not valid Luau";
    if (!result.errors.empty())
    {
        const Luau::ParseError& error = result.errors.front();
        ss << " at line " << error.getLocation().begin.line + 1 << ", column " << error.getLocation().begin.column + 1 << ": " << error.getMessage();
    }
    throw std::runtime_error(ss.str());
}

uint8_t bxor8(uint8_t a, uint8_t b)
{
    return static_cast<uint8_t>(a ^ b);
}

std::string makeIdent(std::mt19937_64& rng, std::string_view prefix);

bool validateLuauNoThrow(std::string_view source)
{
    try
    {
        validateLuau(source);
        return true;
    }
    catch (const std::exception&)
    {
        return false;
    }
}

size_t longBracketClose(std::string_view source, size_t open)
{
    if (open >= source.size() || source[open] != '[')
        return std::string_view::npos;

    size_t marker = open + 1;
    while (marker < source.size() && source[marker] == '=')
        ++marker;
    if (marker >= source.size() || source[marker] != '[')
        return std::string_view::npos;

    size_t equals = marker - open - 1;
    size_t pos = marker + 1;
    while (pos < source.size())
    {
        if (source[pos] == ']')
        {
            size_t probe = pos + 1;
            size_t seen = 0;
            while (probe < source.size() && source[probe] == '=' && seen < equals)
            {
                ++probe;
                ++seen;
            }
            if (seen == equals && probe < source.size() && source[probe] == ']')
                return probe + 1;
        }
        ++pos;
    }

    return source.size();
}

size_t consumeQuotedString(std::string_view source, size_t start)
{
    char quote = source[start];
    size_t i = start + 1;
    bool escaped = false;
    while (i < source.size())
    {
        char c = source[i++];
        if (escaped)
        {
            escaped = false;
            continue;
        }
        if (c == '\\')
        {
            escaped = true;
            continue;
        }
        if (c == quote)
            break;
    }
    return i;
}

std::string collapseLuauToOneLine(std::string_view source)
{
    std::string out;
    out.reserve(source.size());

    auto appendSpace = [&]() {
        if (!out.empty() && out.back() != ' ')
            out.push_back(' ');
    };

    size_t i = 0;
    while (i < source.size())
    {
        unsigned char c = static_cast<unsigned char>(source[i]);
        if (std::isspace(c))
        {
            appendSpace();
            ++i;
            continue;
        }
        if (source[i] == '-' && i + 1 < source.size() && source[i + 1] == '-')
        {
            if (i + 2 < source.size() && source[i + 2] == '[')
            {
                size_t close = longBracketClose(source, i + 2);
                if (close != std::string_view::npos)
                {
                    i = close;
                    appendSpace();
                    continue;
                }
            }
            i += 2;
            while (i < source.size() && source[i] != '\n' && source[i] != '\r')
                ++i;
            appendSpace();
            continue;
        }
        if (source[i] == '\'' || source[i] == '"')
        {
            size_t end = consumeQuotedString(source, i);
            out.append(source.substr(i, end - i));
            i = end;
            continue;
        }
        if (source[i] == '[')
        {
            size_t close = longBracketClose(source, i);
            if (close != std::string_view::npos)
            {
                for (char ch : source.substr(i, close - i))
                    out.push_back((ch == '\n' || ch == '\r') ? ' ' : ch);
                i = close;
                continue;
            }
        }

        out.push_back(source[i++]);
    }

    while (!out.empty() && out.front() == ' ')
        out.erase(out.begin());
    while (!out.empty() && out.back() == ' ')
        out.pop_back();
    return out;
}

std::string finalizeGeneratedOutput(const Config& config, std::string output)
{
    if (!config.oneLine)
        return output;

    std::string candidate = collapseLuauToOneLine(output);
    if (candidate.empty() || !validateLuauNoThrow(candidate))
        throw std::runtime_error("failed to produce valid one-line Luau output");
    if (candidate.find('\n') != std::string::npos || candidate.find('\r') != std::string::npos)
        throw std::runtime_error("one-line output still contains a newline");
    return candidate;
}

IntegrityDigest makeIntegrityDigest(std::string_view data)
{
    constexpr uint32_t mod = 65521u;
    IntegrityDigest digest;
    digest.size = data.size();

    for (size_t i = 0; i < data.size(); ++i)
    {
        uint32_t byte = static_cast<unsigned char>(data[i]);
        uint32_t luaIndex = static_cast<uint32_t>((i + 1) % mod);
        uint32_t weight = static_cast<uint32_t>(((i + 1) % 251u) + 1u);
        digest.a = (digest.a + byte) % mod;
        digest.b = (digest.b + digest.a) % mod;
        digest.c = (digest.c + byte * weight + luaIndex) % mod;
        digest.d = (digest.d + digest.c + byte) % mod;
    }

    return digest;
}

json integrityJson(const IntegrityDigest& digest)
{
    return {
        {"algorithm", "adler16x4"},
        {"size", digest.size},
        {"a", digest.a},
        {"b", digest.b},
        {"c", digest.c},
        {"d", digest.d},
    };
}

std::string shuffledBase95Alphabet(std::mt19937_64& rng)
{
    std::string alphabet;
    for (int c = 32; c <= 126; ++c)
        alphabet.push_back(static_cast<char>(c));
    std::shuffle(alphabet.begin(), alphabet.end(), rng);
    return alphabet;
}

std::string encodeBase95Custom(const std::vector<uint8_t>& bytes, const std::string& alphabet)
{
    std::string out;
    out.reserve(((bytes.size() + 3) / 4) * 5);

    for (size_t i = 0; i < bytes.size(); i += 4)
    {
        uint32_t a = bytes[i];
        uint32_t b = i + 1 < bytes.size() ? bytes[i + 1] : 0;
        uint32_t c = i + 2 < bytes.size() ? bytes[i + 2] : 0;
        uint32_t d = i + 3 < bytes.size() ? bytes[i + 3] : 0;
        uint32_t value = (a << 24u) | (b << 16u) | (c << 8u) | d;
        char digits[5];
        for (int j = 4; j >= 0; --j)
        {
            digits[j] = alphabet[value % 95u];
            value /= 95u;
        }
        out.append(digits, 5);
    }

    return out;
}

struct GuardSpec
{
    uint32_t start = 0;
    uint32_t expected = 0;
    std::vector<uint32_t> salts;
};

GuardSpec makeGuardSpec(std::mt19937_64& rng, size_t count)
{
    GuardSpec guard;
    guard.start = static_cast<uint32_t>(rng() & 0xffffu);
    guard.expected = guard.start;
    guard.salts.reserve(count);
    for (size_t i = 0; i < count; ++i)
    {
        uint32_t salt = static_cast<uint32_t>((rng() & 0xffffu) | 1u);
        guard.salts.push_back(salt);
        guard.expected = static_cast<uint32_t>((static_cast<uint64_t>(guard.expected) * 131u + salt + static_cast<uint32_t>(i + 1) * 17u) & 0xffffu);
    }
    return guard;
}

OwnerBinding makeOwnerBinding(const Config& config, std::string_view source, uint32_t guardExpected)
{
    OwnerBinding binding;
    binding.mode = config.ownerProtect;
    binding.active = config.ownerProtect != alex::owner::ProtectMode::Off;
    binding.locked = config.ownerProtect == alex::owner::ProtectMode::SignAndLock;
    if (!binding.active)
        return binding;

    if (config.ownerPrivateKeyPath.empty())
        throw std::runtime_error("--owner-private-key is required when --owner-protect is enabled");

    alex::owner::PrivateKey key = alex::owner::read_private_key(config.ownerPrivateKeyPath);
    if (config.ownerIdExplicit && alex::owner::owner_hash(config.ownerId) != key.public_key.owner_hash)
        throw std::runtime_error("--owner-id does not match --owner-private-key");

    std::string ownerId = config.ownerIdExplicit ? config.ownerId : key.public_key.owner_id;
    uint64_t nonceSeed = fnv1a64(config.seedText + "|" + std::to_string(config.seed) + "|" + std::to_string(guardExpected) + "|" + ownerId);
    std::mt19937_64 rng(config.seed ^ nonceSeed ^ 0x0a17e58f0cabu);
    uint64_t nonce = rng() ^ (nonceSeed << 1u);
    binding.capsule = alex::owner::sign_capsule(source, config.ownerProtect, key, nonce);
    binding.guardHash = alex::owner::capsule_guard_hash(binding.capsule.values);
    return binding;
}

uint32_t effectiveGuardExpected(const GuardSpec& guard, const OwnerBinding& owner)
{
    uint32_t expected = guard.expected;
    if (owner.locked)
        expected = (expected + owner.guardHash) & 0xffffu;
    return expected;
}

std::string intExpr(uint32_t value, uint32_t modulus, std::mt19937_64& rng);

std::string emitOwnerGuardBinding(std::mt19937_64& rng, const std::string& decoyName, const std::string& guardName, const OwnerBinding& binding)
{
    if (!binding.active)
        return {};

    std::string vCapsule = makeIdent(rng, "_");
    std::string vHash = makeIdent(rng, "_");
    uint32_t expectedHash = alex::owner::capsule_guard_hash(binding.capsule.values);

    std::ostringstream out;
    out << "    local " << vCapsule << "={";
    for (size_t i = 0; i < binding.capsule.values.size(); ++i)
    {
        if (i != 0)
            out << ",";
        out << binding.capsule.values[i];
    }
    out << "}\n";
    out << "    do local " << vHash << "=0;for i=1,#" << vCapsule << " do local v=" << vCapsule << "[i];if type(v)~=\"number\" then return " << decoyName
        << "() end;" << vHash << "=(" << vHash << "*131+(v%65536)+i*17)%65536 end;if " << vHash << "~=" << intExpr(expectedHash, 65536u, rng)
        << " then return " << decoyName << "() end";
    if (binding.locked)
        out << ";" << guardName << "=(" << guardName << "+" << vHash << ")%65536";
    out << " end\n";
    return out.str();
}

uint32_t onlineGuardHash(std::string_view material)
{
    IntegrityDigest digest = makeIntegrityDigest(material);
    return static_cast<uint32_t>((digest.size + digest.a + digest.b + digest.c + digest.d) & 0xffffu);
}

uint32_t gameIdGuardHash(uint64_t gameId)
{
    if (gameId == 0)
        return 0;
    IntegrityDigest digest = makeIntegrityDigest("game-id:" + std::to_string(gameId));
    return static_cast<uint32_t>((digest.size + digest.a + digest.b + digest.c + digest.d) & 0xffffu);
}

std::string emitGameIdBinding(const Config& config, std::mt19937_64& rng, const std::string& decoyName, const std::string& guardName)
{
    if (config.gameId == 0)
        return {};

    std::string vDecode = makeIdent(rng, "_");
    std::string vGlobals = makeIdent(rng, "_");
    std::string vGame = makeIdent(rng, "_");
    std::string vExpected = makeIdent(rng, "_");
    std::string vOk = makeIdent(rng, "_");
    std::string vMatches = makeIdent(rng, "_");
    uint32_t mask = static_cast<uint32_t>((rng() % 211u) + 23u);
    auto hidden = [&](std::string_view value) {
        std::ostringstream expression;
        expression << vDecode << "({";
        for (size_t index = 0; index < value.size(); ++index)
        {
            if (index != 0)
                expression << ",";
            uint32_t key = (mask + static_cast<uint32_t>(index + 1) * 19u) % 251u;
            expression << ((static_cast<unsigned char>(value[index]) + key) & 0xffu);
        }
        expression << "})";
        return expression.str();
    };

    std::ostringstream out;
    out << "    do\n";
    out << "        local " << vDecode << "=function(bytes)local out={} for i=1,#bytes do out[i]=string.char((bytes[i]-(" << mask << "+i*19)%251)%256) end return table.concat(out) end\n";
    out << "        local " << vGlobals << "=(getfenv and getfenv(0)) or _G\n";
    out << "        local " << vExpected << "=tonumber(" << hidden(std::to_string(config.gameId)) << ")\n";
    out << "        local " << vOk << "," << vMatches << "=pcall(function() local " << vGame << "=" << vGlobals << "[" << hidden("game") << "]; return " << vGame
        << "~=nil and " << vGame << "[" << hidden("GameId") << "]==" << vExpected << " end)\n";
    out << "        if not " << vOk << " or " << vMatches << "~=true then return " << decoyName << "() end\n";
    out << "        " << guardName << "=(" << guardName << "+" << intExpr(gameIdGuardHash(config.gameId), 65536u, rng) << ")%65536\n";
    out << "    end\n";
    return out.str();
}

std::string emitOnlineKeyBinding(
    const Config& config, std::mt19937_64& rng, const std::string& decoyName, const std::string& guardName, const std::string& materialTarget = {})
{
    if (config.keyMode != KeyMode::Online)
        return {};

    IntegrityDigest expected = makeIntegrityDigest(config.onlineKeyMaterial);
    std::string vDecode = makeIdent(rng, "_");
    std::string vGlobals = makeIdent(rng, "_");
    std::string vSyn = makeIdent(rng, "_");
    std::string vRequest = makeIdent(rng, "_");
    std::string vOk = makeIdent(rng, "_");
    std::string vResponse = makeIdent(rng, "_");
    std::string vBody = makeIdent(rng, "_");
    std::string vHash = makeIdent(rng, "_");
    uint32_t mask = static_cast<uint32_t>((rng() % 211u) + 23u);
    uint32_t stride = static_cast<uint32_t>((rng() % 29u) + 11u);
    auto hidden = [&](std::string_view value) {
        std::ostringstream expression;
        expression << vDecode << "({";
        for (size_t index = 0; index < value.size(); ++index)
        {
            if (index != 0)
                expression << ",";
            uint32_t key = (mask + static_cast<uint32_t>(index + 1) * stride) % 251u;
            expression << ((static_cast<unsigned char>(value[index]) + key) & 0xffu);
        }
        expression << "})";
        return expression.str();
    };
    std::ostringstream out;
    out << "    do\n";
    out << "        local " << vDecode << "=function(bytes)local out={} for i=1,#bytes do out[i]=string.char((bytes[i]-(" << mask << "+i*" << stride << ")%251)%256) end return table.concat(out) end\n";
    out << "        local " << vGlobals << " = (getfenv and getfenv(0)) or _G\n";
    out << "        local " << vSyn << "=" << vGlobals << "[" << hidden("syn") << "]\n";
    out << "        local " << vRequest << "=" << vGlobals << "[" << hidden("request") << "] or " << vGlobals << "[" << hidden("http_request") << "] or (type(" << vSyn << ")==" << hidden("table") << " and " << vSyn << "[" << hidden("request") << "])\n";
    out << "        if type(" << vRequest << ") ~= " << hidden("function") << " then return " << decoyName << "() end\n";
    out << "        local " << vOk << ", " << vResponse << " = pcall(" << vRequest << ", {[" << hidden("Url") << "]=" << hidden(config.onlineKeyUrl) << ",[" << hidden("Method") << "]=" << hidden("GET") << ",[" << hidden("Headers") << "]={[" << hidden("Accept") << "]=" << hidden("text/plain") << "}})\n";
    out << "        if not " << vOk << " then return " << decoyName << "() end\n";
    out << "        local " << vBody << " = type(" << vResponse << ") == " << hidden("table") << " and (" << vResponse << "[" << hidden("Body") << "] or " << vResponse << "[" << hidden("body") << "]) or " << vResponse << "\n";
    out << "        if type(" << vBody << ") ~= " << hidden("string") << " or #" << vBody << " ~= " << expected.size << " then return " << decoyName << "() end\n";
    out << "        local a,b,c,d=1,0,0,0; for i=1,#" << vBody << " do local byte=string.byte(" << vBody << ",i); local weight=(i%251)+1; a=(a+byte)%65521; b=(b+a)%65521; c=(c+byte*weight+(i%65521))%65521; d=(d+c+byte)%65521 end\n";
    out << "        if a~=" << expected.a << " or b~=" << expected.b << " or c~=" << expected.c << " or d~=" << expected.d << " then return " << decoyName << "() end\n";
    if (!materialTarget.empty())
        out << "        " << materialTarget << "=" << vBody << "\n";
    out << "        local " << vHash << "=(#" << vBody << "+a+b+c+d)%65536; " << guardName << "=(" << guardName << "+" << vHash << ")%65536\n";
    out << "    end\n";
    return out.str();
}

uint32_t polymorphicByteParam(std::mt19937_64& rng, uint32_t domain, size_t layerIndex, uint32_t stride, uint32_t minValue, uint32_t span, bool odd)
{
    uint32_t indexMix = static_cast<uint32_t>((layerIndex + 1u) * stride + domain * 29u);
    uint32_t value = minValue + static_cast<uint32_t>((rng() + indexMix + (rng() >> 17u)) % span);
    if (odd)
        value |= 1u;
    return value & 0xffu;
}

CryptoLayer makeCryptoLayer(std::mt19937_64& rng, uint32_t domain, size_t layerIndex)
{
    static constexpr uint32_t stateMods[] = {211u, 223u, 227u, 229u, 233u, 239u, 241u, 251u};
    uint32_t indexMix = static_cast<uint32_t>((layerIndex + 1u) * 0x45d9f3bu + domain * 0x9e37u);
    CryptoLayer layer;
    layer.key = static_cast<uint32_t>(((rng() ^ (uint64_t(indexMix) << 9u)) & 0xffffu) | 1u);
    layer.salt = static_cast<uint32_t>(((rng() + indexMix + domain) & 0xffu) | 1u);
    layer.salt2 = static_cast<uint32_t>(((rng() ^ (indexMix >> 3u)) & 0xffu) | 1u);
    layer.multiplier = static_cast<uint32_t>((((rng() + indexMix) % 58000u) + 3001u) | 1u);
    layer.increment = static_cast<uint32_t>(((rng() ^ indexMix) % 60000u) + 101u);
    layer.variant = static_cast<uint32_t>((rng() + indexMix + domain) % 16u);
    layer.stateMul = polymorphicByteParam(rng, domain, layerIndex, 17u, 7u, 58u, true);
    layer.stateMod = stateMods[(rng() + indexMix + domain) % (sizeof(stateMods) / sizeof(stateMods[0]))];
    layer.keyMul = polymorphicByteParam(rng, domain, layerIndex, 31u, 5u, 74u, true);
    layer.maskMul = polymorphicByteParam(rng, domain, layerIndex, 43u, 3u, 82u, true);
    layer.carryMul = polymorphicByteParam(rng, domain, layerIndex, 59u, 1u, 30u, true);
    layer.carrySalt = static_cast<uint32_t>((rng() + indexMix * 3u + domain) & 0xffu);
    layer.streamXor = static_cast<uint32_t>((rng() ^ (indexMix * 11u) ^ (domain << 5u)) & 0xffu);
    layer.postMul = polymorphicByteParam(rng, domain, layerIndex, 71u, 5u, 90u, true);
    return layer;
}

std::vector<uint8_t> encryptBytesWithLayer(
    const std::vector<uint8_t>& bytes,
    const CryptoLayer& layer)
{
    std::vector<uint8_t> encrypted;
    encrypted.reserve(bytes.size());
    uint32_t state = layer.key;
    uint32_t carry = layer.carrySalt & 0xffu;
    for (size_t i = 0; i < bytes.size(); ++i)
    {
        uint32_t luaIndex = static_cast<uint32_t>(i + 1);
        uint32_t dyn = (carry * layer.carryMul + layer.streamXor + (luaIndex % 17u) * layer.variant) & 0xffu;
        state = static_cast<uint32_t>((static_cast<uint64_t>(state) * layer.multiplier + layer.increment + layer.salt + luaIndex * layer.stateMul + dyn) & 0xffffu);
        uint8_t k = static_cast<uint8_t>(((state >> 8u) + (state % layer.stateMod) + luaIndex * layer.keyMul + layer.salt + carry + layer.streamXor) & 0xffu);
        uint8_t mask = static_cast<uint8_t>((luaIndex * layer.maskMul + layer.salt + ((carry * layer.carryMul) & 0xffu) + layer.salt2 + layer.streamXor) & 0xffu);
        uint8_t post = static_cast<uint8_t>((layer.streamXor + luaIndex * layer.postMul + layer.carrySalt + layer.variant) & 0xffu);
        uint8_t mixed = static_cast<uint8_t>((bytes[i] + mask) & 0xffu);
        uint8_t cipher = static_cast<uint8_t>((bxor8(mixed, k) + post) & 0xffu);
        encrypted.push_back(cipher);
        carry = (cipher + k + luaIndex * layer.carryMul + layer.salt2 + layer.carrySalt) & 0xffu;
    }
    return encrypted;
}

PackedPayload encryptBase95Payload(std::string_view text, std::mt19937_64& rng, size_t layerCount)
{
    PackedPayload payload;
    payload.alphabet = shuffledBase95Alphabet(rng);
    payload.plainSize = text.size();
    payload.integrity = makeIntegrityDigest(text);
    payload.layers.reserve(static_cast<size_t>(layerCount));

    std::vector<uint8_t> bytes(text.begin(), text.end());
    for (size_t i = 0; i < layerCount; ++i)
    {
        CryptoLayer layer = makeCryptoLayer(rng, 0x95u, i);
        payload.layers.push_back(layer);
        bytes = encryptBytesWithLayer(bytes, layer);
    }

    payload.encoded = encodeBase95Custom(bytes, payload.alphabet);
    return payload;
}

std::string makeIdent(std::mt19937_64& rng, std::string_view prefix)
{
    static constexpr char firstChars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_";
    static constexpr char restChars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_";
    std::string out;
    if (prefix == "_" && (rng() % 4u) == 0)
        out.push_back(firstChars[rng() % (sizeof(firstChars) - 1)]);
    else
        out.assign(prefix);
    if (out.empty())
        out.push_back(firstChars[rng() % (sizeof(firstChars) - 1)]);
    int extra = static_cast<int>((rng() % 11u) + 6u);
    for (int i = 0; i < extra; ++i)
        out.push_back(restChars[rng() % (sizeof(restChars) - 1)]);
    return out;
}

std::string intExpr(uint32_t value, uint32_t modulus, std::mt19937_64& rng)
{
    uint32_t mask = static_cast<uint32_t>((rng() % 700000u) + 3000u);
    uint32_t outer = static_cast<uint32_t>((rng() % 90000u) + 409u);
    std::ostringstream out;
    out << "(((" << (value + mask + outer) << " - " << mask << ") - " << outer << ") % " << modulus << ")";
    return out.str();
}

std::string emitAlphabetBuilder(std::string_view target, std::string_view alphabet, std::mt19937_64& rng)
{
    std::string vBytes = makeIdent(rng, "_");
    std::string vOut = makeIdent(rng, "_");
    uint32_t mask = static_cast<uint32_t>((rng() % 211u) + 17u);

    std::ostringstream out;
    out << "    local " << vBytes << " = {";
    for (size_t i = 0; i < alphabet.size(); ++i)
    {
        if (i != 0)
            out << ",";
        uint32_t enc = (static_cast<unsigned char>(alphabet[i]) + ((static_cast<uint32_t>(i + 1) * 13u + mask) % 251u)) & 0xffu;
        out << enc;
    }
    out << "}\n";
    out << "    local " << vOut << " = {}\n";
    out << "    for i = 1, #" << vBytes << " do " << vOut << "[i] = string.char((" << vBytes << "[i] - ((i * 13 + " << mask
        << ") % 251)) % 256) end\n";
    out << "    local " << target << " = table.concat(" << vOut << ")\n";
    return out.str();
}

std::string emitShardedStringBuilder(
    std::string_view target, std::string_view value, std::mt19937_64& rng, size_t minimumChunk, size_t maximumChunk)
{
    struct Chunk
    {
        int index = 0;
        std::string text;
        uint32_t mask = 0;
    };

    std::vector<Chunk> chunks;
    minimumChunk = std::max<size_t>(1, minimumChunk);
    maximumChunk = std::max(minimumChunk, maximumChunk);
    for (size_t i = 0; i < value.size();)
    {
        size_t chunkSize = minimumChunk + static_cast<size_t>(rng() % (maximumChunk - minimumChunk + 1));
        chunkSize = std::min(chunkSize, value.size() - i);
        Chunk chunk;
        chunk.index = static_cast<int>(chunks.size() + 1);
        chunk.text = std::string(value.substr(i, chunkSize));
        chunk.mask = static_cast<uint32_t>((rng() % 213u) + 19u);
        chunks.push_back(std::move(chunk));
        i += chunkSize;
    }
    if (chunks.empty())
        chunks.push_back({1, "", static_cast<uint32_t>((rng() % 213u) + 19u)});

    std::shuffle(chunks.begin(), chunks.end(), rng);
    int maskA = static_cast<int>((rng() % 8000u) + 400u);
    int maskB = static_cast<int>((rng() % 7u) + 3u);
    std::string vBag = makeIdent(rng, "_");
    std::string vParts = makeIdent(rng, "_");
    std::string vRaw = makeIdent(rng, "_");
    std::string vBody = makeIdent(rng, "_");

    std::ostringstream out;
    out << "    local " << vBag << " = {\n";
    for (const Chunk& chunk : chunks)
    {
        out << "        {" << (chunk.index * maskB + maskA) << "," << chunk.mask << ",{";
        for (size_t i = 0; i < chunk.text.size(); ++i)
        {
            if (i != 0)
                out << ",";
            uint32_t luaIndex = static_cast<uint32_t>(i + 1);
            uint32_t key = (luaIndex * 17u + chunk.mask) % 251u;
            uint32_t enc = (static_cast<unsigned char>(chunk.text[i]) + key) & 0xffu;
            out << enc;
        }
        out << "}},\n";
    }
    out << "    }\n";
    out << "    local " << vParts << " = {}\n";
    out << "    for i = 1, #" << vBag << " do\n";
    out << "        local e = " << vBag << "[i]\n";
    out << "        local " << vRaw << ", " << vBody << " = {}, e[3]\n";
    out << "        for j = 1, #" << vBody << " do " << vRaw << "[j] = string.char((" << vBody << "[j] - ((j * 17 + e[2]) % 251)) % 256) end\n";
    out << "        " << vParts << "[(e[1] - " << maskA << ") / " << maskB << "] = table.concat(" << vRaw << ")\n";
    out << "    end\n";
    out << "    local " << target << " = table.concat(" << vParts << ")\n";
    return out.str();
}

std::string emitLayerTable(std::string_view target, const std::vector<CryptoLayer>& layers, uint32_t guardExpected, std::mt19937_64& rng)
{
    std::ostringstream out;
    out << "    local " << target << " = {}\n";
    std::vector<size_t> layerOrder;
    layerOrder.reserve(layers.size());
    for (size_t index = 0; index < layers.size(); ++index)
        layerOrder.push_back(index);
    std::shuffle(layerOrder.begin(), layerOrder.end(), rng);

    for (size_t layerIndex : layerOrder)
    {
        const CryptoLayer& layer = layers[layerIndex];
        const std::array<std::pair<uint32_t, uint32_t>, 14> values{{
            {((layer.key + guardExpected) & 0xffffu), 65536u},
            {((layer.salt + guardExpected) & 0xffu), 256u},
            {((layer.salt2 + guardExpected) & 0xffu), 256u},
            {((layer.multiplier + guardExpected) & 0xffffu), 65536u},
            {((layer.increment + guardExpected) & 0xffffu), 65536u},
            {((layer.variant + guardExpected) & 0xffu), 256u},
            {((layer.stateMul + guardExpected) & 0xffu), 256u},
            {((layer.stateMod + guardExpected) & 0xffu), 256u},
            {((layer.keyMul + guardExpected) & 0xffu), 256u},
            {((layer.maskMul + guardExpected) & 0xffu), 256u},
            {((layer.carryMul + guardExpected) & 0xffu), 256u},
            {((layer.carrySalt + guardExpected) & 0xffu), 256u},
            {((layer.streamXor + guardExpected) & 0xffu), 256u},
            {((layer.postMul + guardExpected) & 0xffu), 256u},
        }};
        std::array<size_t, 14> slotOrder{};
        for (size_t slot = 0; slot < slotOrder.size(); ++slot)
            slotOrder[slot] = slot;
        std::shuffle(slotOrder.begin(), slotOrder.end(), rng);

        out << "    " << target << "[" << layerIndex + 1 << "] = {}\n";
        for (size_t slot : slotOrder)
            out << "    " << target << "[" << layerIndex + 1 << "][" << slot + 1 << "] = " << intExpr(values[slot].first, values[slot].second, rng) << "\n";
    }
    return out.str();
}

std::string emitLayerCapsule(std::string_view target, const std::vector<CryptoLayer>& layers, uint32_t guardExpected, const IntegrityDigest& digest, std::mt19937_64& rng)
{
    struct CapsuleRecord
    {
        uint32_t layer = 0;
        uint32_t slot = 0;
        uint32_t value = 0;
        uint32_t mod = 256;
        uint32_t salt = 0;
        bool fake = false;
    };

    auto layerValues = [&](const CryptoLayer& layer) {
        return std::vector<std::pair<uint32_t, uint32_t>>{
            {((layer.key + guardExpected) & 0xffffu), 65536u},
            {((layer.salt + guardExpected) & 0xffu), 256u},
            {((layer.salt2 + guardExpected) & 0xffu), 256u},
            {((layer.multiplier + guardExpected) & 0xffffu), 65536u},
            {((layer.increment + guardExpected) & 0xffffu), 65536u},
            {((layer.variant + guardExpected) & 0xffu), 256u},
            {((layer.stateMul + guardExpected) & 0xffu), 256u},
            {((layer.stateMod + guardExpected) & 0xffu), 256u},
            {((layer.keyMul + guardExpected) & 0xffu), 256u},
            {((layer.maskMul + guardExpected) & 0xffu), 256u},
            {((layer.carryMul + guardExpected) & 0xffu), 256u},
            {((layer.carrySalt + guardExpected) & 0xffu), 256u},
            {((layer.streamXor + guardExpected) & 0xffu), 256u},
            {((layer.postMul + guardExpected) & 0xffu), 256u},
        };
    };

    std::vector<CapsuleRecord> records;
    for (size_t i = 0; i < layers.size(); ++i)
    {
        std::vector<std::pair<uint32_t, uint32_t>> values = layerValues(layers[i]);
        for (size_t slot = 0; slot < values.size(); ++slot)
        {
            records.push_back({
                static_cast<uint32_t>(i + 1),
                static_cast<uint32_t>(slot + 1),
                values[slot].first,
                values[slot].second,
                static_cast<uint32_t>((rng() % 251u) + 1u),
                false,
            });
        }
    }

    size_t fakeCount = std::max<size_t>(layers.size() * 5u, 17u);
    for (size_t i = 0; i < fakeCount; ++i)
    {
        records.push_back({
            static_cast<uint32_t>(layers.size() + 3u + (rng() % 23u)),
            static_cast<uint32_t>(15u + (rng() % 41u)),
            static_cast<uint32_t>(rng() & 0xffffu),
            (rng() % 2u) ? 65536u : 256u,
            static_cast<uint32_t>((rng() % 251u) + 1u),
            true,
        });
    }
    std::shuffle(records.begin(), records.end(), rng);

    std::string vBag = makeIdent(rng, "_");
    std::string vEntry = makeIdent(rng, "_");
    std::string vLayer = makeIdent(rng, "_");
    std::string vSlot = makeIdent(rng, "_");
    std::string vMod = makeIdent(rng, "_");
    std::string vValue = makeIdent(rng, "_");
    uint32_t layerMul = static_cast<uint32_t>(((rng() % 83u) + 5u) | 1u);
    uint32_t slotMul = static_cast<uint32_t>(((rng() % 71u) + 7u) | 1u);
    uint32_t layerSalt = static_cast<uint32_t>((rng() % 90000u) + 1000u);
    uint32_t slotSalt = static_cast<uint32_t>((rng() % 70000u) + 700u);
    uint32_t valueSalt = static_cast<uint32_t>((digest.a + digest.c + (rng() % 60000u)) % 65536u);

    std::ostringstream out;
    out << "    local " << target << " = {}\n";
    out << "    local " << vBag << " = {\n";
    for (size_t i = 0; i < records.size(); ++i)
    {
        const CapsuleRecord& record = records[i];
        uint32_t row = static_cast<uint32_t>(i + 1);
        uint32_t encodedLayer = record.layer * layerMul + layerSalt + record.salt * 3u + row;
        uint32_t encodedSlot = record.slot * slotMul + slotSalt + record.salt * 5u + row * 2u;
        uint32_t encodedValue = (record.value + valueSalt + record.salt * 7u + record.layer * 11u + record.slot * 13u + row * 17u) % record.mod;
        out << "        {"
            << intExpr(encodedLayer, 2147483647u, rng) << ","
            << intExpr(encodedSlot, 2147483647u, rng) << ","
            << intExpr(encodedValue, record.mod, rng) << ","
            << intExpr(record.salt, 256u, rng) << ","
            << intExpr(record.mod == 65536u ? 1u : 0u, 2u, rng)
            << "},\n";
    }
    out << "    }\n";
    out << "    for i = 1, #" << vBag << " do\n";
    out << "        local " << vEntry << " = " << vBag << "[i]\n";
    out << "        local " << vLayer << " = (" << vEntry << "[1] - " << intExpr(layerSalt, 131072u, rng) << " - " << vEntry << "[4] * 3 - i) / " << layerMul << "\n";
    out << "        local " << vSlot << " = (" << vEntry << "[2] - " << intExpr(slotSalt, 131072u, rng) << " - " << vEntry << "[4] * 5 - i * 2) / " << slotMul << "\n";
    out << "        if " << vLayer << " >= 1 and " << vLayer << " <= " << layers.size() << " and " << vSlot << " >= 1 and " << vSlot << " <= 14 and " << vLayer
        << " == math.floor(" << vLayer << ") and " << vSlot << " == math.floor(" << vSlot << ") then\n";
    out << "            " << target << "[" << vLayer << "] = " << target << "[" << vLayer << "] or {}\n";
    out << "            local " << vMod << " = " << vEntry << "[5] == 1 and 65536 or 256\n";
    out << "            local " << vValue << " = (" << vEntry << "[3] - " << intExpr(valueSalt, 65536u, rng) << " - " << vEntry << "[4] * 7 - " << vLayer << " * 11 - " << vSlot
        << " * 13 - i * 17) % " << vMod << "\n";
    out << "            " << target << "[" << vLayer << "][" << vSlot << "] = " << vValue << "\n";
    out << "        end\n";
    out << "    end\n";
    return out.str();
}

std::string emitByteArrayIntegrityFunction(std::string_view name, const IntegrityDigest& digest)
{
    std::ostringstream out;
    out << "    local " << name << " = function(bytes)\n";
    out << "        if type(bytes) ~= \"table\" or #bytes ~= " << digest.size << " then return false end\n";
    out << "        local a, b, c, d = 1, 0, 0, 0\n";
    out << "        for i = 1, #bytes do\n";
    out << "            local byte = bytes[i]\n";
    out << "            if type(byte) ~= \"number\" or byte < 0 or byte > 255 then return false end\n";
    out << "            local weight = (i % 251) + 1\n";
    out << "            a = (a + byte) % 65521\n";
    out << "            b = (b + a) % 65521\n";
    out << "            c = (c + byte * weight + (i % 65521)) % 65521\n";
    out << "            d = (d + c + byte) % 65521\n";
    out << "        end\n";
    out << "        return a == " << digest.a << " and b == " << digest.b << " and c == " << digest.c << " and d == " << digest.d << "\n";
    out << "    end\n";
    return out.str();
}

std::string emitOpaqueJunk(std::mt19937_64& rng, const std::string& decoyName, int blocks)
{
    std::ostringstream out;
    for (int block = 0; block < blocks; ++block)
    {
        std::string vA = makeIdent(rng, "_");
        std::string vB = makeIdent(rng, "_");
        uint32_t base = static_cast<uint32_t>((rng() % 70000u) + 3000u);
        uint32_t mul = static_cast<uint32_t>((rng() % 89u) + 11u);
        uint32_t add = static_cast<uint32_t>((rng() % 997u) + 29u);
        uint32_t mod = static_cast<uint32_t>((rng() % 113u) + 41u);
        uint32_t realValue = static_cast<uint32_t>((static_cast<uint64_t>(base) * mul + add) % mod);
        uint32_t impossible = (realValue + static_cast<uint32_t>((rng() % (mod - 1u)) + 1u)) % mod;
        out << "    local " << vA << " = " << base << "\n";
        out << "    local " << vB << " = ((" << vA << " * " << mul << " + " << add << ") % " << mod << ")\n";
        out << "    if " << vB << " == " << impossible << " then return " << decoyName << "() end\n";
    }
    return out.str();
}

std::string jsonNumberText(const json& value)
{
    if (value.is_number_integer() || value.is_number_unsigned())
        return std::to_string(value.get<int64_t>());

    std::ostringstream out;
    out << std::setprecision(17) << value.get<double>();
    return out.str();
}

void writeVaruint(std::string& out, uint64_t value)
{
    do
    {
        uint8_t byte = static_cast<uint8_t>(value & 0x7fu);
        value >>= 7u;
        if (value)
            byte |= 0x80u;
        out.push_back(static_cast<char>(byte));
    } while (value);
}

void writeBinaryVmValue(std::string& out, const json& value)
{
    if (value.is_array())
    {
        out.push_back(static_cast<char>(1));
        writeVaruint(out, value.size());
        for (const json& item : value)
            writeBinaryVmValue(out, item);
        return;
    }

    if (value.is_number())
    {
        std::string text = jsonNumberText(value);
        out.push_back(static_cast<char>(2));
        writeVaruint(out, text.size());
        out.append(text);
        return;
    }

    throw std::runtime_error("internal error: unsupported VM bundle value");
}

std::string encodeBinaryVmBundle(const json& value)
{
    std::string out;
    out.reserve(value.dump().size());
    writeBinaryVmValue(out, value);
    return out;
}

enum class V6Op : uint8_t
{
    Nop,
    LoadConstant,
    LoadConstantAlt,
    Move,
    GetLocal,
    GetLocalAlt,
    DeclareLocal,
    SetLocal,
    GetGlobal,
    SetGlobal,
    GetIndex,
    GetIndexK,
    SetIndex,
    SetIndexK,
    NewTable,
    SetList,
    AppendPack,
    Binary,
    BinaryAlt,
    Unary,
    PackNew,
    PackPush,
    PackExtend,
    PackGet,
    PackSet,
    Call,
    CallGlobal0,
    CallMethod0,
    MakeClosure,
    Varargs,
    Return,
    Jump,
    JumpFalse,
    JumpFalseAlt,
    JumpTrue,
    EnterScope,
    LeaveScopes,
    ToString,
    IteratorInit,
    JumpNil,
    ForCheck,
    OpaqueGuard,
    Count,
};

enum class V6Binary : uint8_t
{
    Add,
    Sub,
    Mul,
    Div,
    FloorDiv,
    Mod,
    Pow,
    Concat,
    Ne,
    Eq,
    Lt,
    Le,
    Gt,
    Ge,
    Count,
};

enum class V6Unary : uint8_t
{
    Not,
    Minus,
    Length,
    Count,
};

struct V6Instruction
{
    V6Op op = V6Op::Nop;
    std::vector<uint32_t> args;
};

struct V6BasicBlock
{
    size_t id = 0;
    size_t start = 0;
    size_t end = 0;
    std::vector<size_t> successors;
};

struct V6Prototype
{
    std::vector<uint32_t> params;
    std::vector<uint32_t> children;
    std::vector<uint32_t> captures;
    std::unordered_set<uint32_t> captureSet;
    std::vector<V6Instruction> code;
    std::vector<V6BasicBlock> blocks;
    json constants = json::array();
    std::vector<uint32_t> logicalToPhysicalConstant;
    std::vector<uint32_t> opcodes;
    std::vector<uint32_t> binaryCodes;
    std::vector<uint32_t> unaryCodes;
    uint32_t name = 0;
    uint32_t maxRegister = 0;
    uint32_t virtualRegisterCount = 0;
    uint32_t argMultiplier = 1;
    uint32_t argSalt = 0;
    uint32_t argStep = 0;
    bool vararg = false;
    bool decoy = false;
    size_t opaqueGuardCount = 0;
    size_t substitutionCount = 0;
    size_t superoperatorCount = 0;
};

struct V6Program
{
    std::vector<V6Prototype> prototypes;
    std::vector<std::string> strings;
    std::unordered_map<std::string, uint32_t> stringIds;
    uint32_t rootPrototype = 1;
    size_t localCount = 0;
    size_t instructionCount = 0;
    size_t blockCount = 0;
    size_t decoyPrototypeCount = 0;
    size_t opaqueGuardCount = 0;
    size_t substitutionCount = 0;
    size_t superoperatorCount = 0;
    size_t constantFoldCount = 0;
    size_t branchFoldCount = 0;
    size_t unreachableInstructionCount = 0;
    size_t redundantMoveCount = 0;
    bool registerReuse = false;
};

struct V6CompileFailure : std::runtime_error
{
    std::string code;
    std::string stage;
    std::string astKind;
    int line = 0;
    int column = 0;

    V6CompileFailure(std::string code, std::string stage, std::string astKind, const Luau::Location& location, std::string message)
        : std::runtime_error(std::move(message))
        , code(std::move(code))
        , stage(std::move(stage))
        , astKind(std::move(astKind))
        , line(location.begin.line + 1)
        , column(location.begin.column + 1)
    {
    }
};

struct CliFailure : std::runtime_error
{
    std::string code;
    std::string option;

    CliFailure(std::string code, std::string option, std::string message)
        : std::runtime_error(std::move(message))
        , code(std::move(code))
        , option(std::move(option))
    {
    }
};

size_t v6OpIndex(V6Op op)
{
    return static_cast<size_t>(op);
}

enum class V6OperandRole : uint8_t
{
    None,
    RegisterDef,
    RegisterUse,
    Constant,
    String,
    Local,
    Prototype,
    Target,
    Immediate,
};

enum class V6ResultBehavior : uint8_t
{
    None,
    Single,
    Pack,
};

struct V6OpInfo
{
    const char* name = "invalid";
    std::array<V6OperandRole, 5> operands{};
    uint8_t operandCount = 0;
    V6ResultBehavior result = V6ResultBehavior::None;
    bool terminator = false;
    bool sideEffecting = false;
    bool mayYield = false;
};

V6OpInfo makeV6OpInfo(const char* name, std::initializer_list<V6OperandRole> operands, V6ResultBehavior result = V6ResultBehavior::None,
    bool terminator = false, bool sideEffecting = false, bool mayYield = false)
{
    if (operands.size() > 5)
        throw std::runtime_error("internal error: AlexVM opcode has too many operands");
    V6OpInfo info;
    info.name = name;
    info.operandCount = static_cast<uint8_t>(operands.size());
    info.result = result;
    info.terminator = terminator;
    info.sideEffecting = sideEffecting;
    info.mayYield = mayYield;
    std::copy(operands.begin(), operands.end(), info.operands.begin());
    return info;
}

const std::array<V6OpInfo, static_cast<size_t>(V6Op::Count)>& v6InstructionSet()
{
    using R = V6OperandRole;
    using B = V6ResultBehavior;
    static const std::array<V6OpInfo, static_cast<size_t>(V6Op::Count)> instructions = {
        makeV6OpInfo("nop", {}),
        makeV6OpInfo("load_constant", {R::RegisterDef, R::Constant}, B::Single),
        makeV6OpInfo("load_constant_alt", {R::RegisterDef, R::Constant}, B::Single),
        makeV6OpInfo("move", {R::RegisterDef, R::RegisterUse}, B::Single),
        makeV6OpInfo("get_local", {R::RegisterDef, R::Local}, B::Single),
        makeV6OpInfo("get_local_alt", {R::RegisterDef, R::Local}, B::Single),
        makeV6OpInfo("declare_local", {R::Local, R::RegisterUse}, B::None, false, true),
        makeV6OpInfo("set_local", {R::Local, R::RegisterUse}, B::None, false, true),
        makeV6OpInfo("get_global", {R::RegisterDef, R::String}, B::Single, false, true),
        makeV6OpInfo("set_global", {R::String, R::RegisterUse}, B::None, false, true),
        makeV6OpInfo("get_index", {R::RegisterDef, R::RegisterUse, R::RegisterUse}, B::Single, false, true),
        makeV6OpInfo("get_index_k", {R::RegisterDef, R::RegisterUse, R::String}, B::Single, false, true),
        makeV6OpInfo("set_index", {R::RegisterUse, R::RegisterUse, R::RegisterUse}, B::None, false, true),
        makeV6OpInfo("set_index_k", {R::RegisterUse, R::String, R::RegisterUse}, B::None, false, true),
        makeV6OpInfo("new_table", {R::RegisterDef}, B::Single, false, true),
        makeV6OpInfo("set_list", {R::RegisterUse, R::Immediate, R::RegisterUse}, B::None, false, true),
        makeV6OpInfo("append_pack", {R::RegisterUse, R::RegisterUse, R::Immediate}, B::None, false, true),
        makeV6OpInfo("binary", {R::RegisterDef, R::Immediate, R::RegisterUse, R::RegisterUse}, B::Single, false, true),
        makeV6OpInfo("binary_alt", {R::RegisterDef, R::Immediate, R::RegisterUse, R::RegisterUse}, B::Single, false, true),
        makeV6OpInfo("unary", {R::RegisterDef, R::Immediate, R::RegisterUse}, B::Single, false, true),
        makeV6OpInfo("pack_new", {R::RegisterDef}, B::Pack),
        makeV6OpInfo("pack_push", {R::RegisterUse, R::RegisterUse}, B::None, false, true),
        makeV6OpInfo("pack_extend", {R::RegisterUse, R::RegisterUse}, B::None, false, true),
        makeV6OpInfo("pack_get", {R::RegisterDef, R::RegisterUse, R::Immediate}, B::Single),
        makeV6OpInfo("pack_set", {R::RegisterUse, R::Immediate, R::RegisterUse}, B::None, false, true),
        makeV6OpInfo("call", {R::RegisterDef, R::RegisterUse, R::RegisterUse}, B::Pack, false, true, true),
        makeV6OpInfo("call_global_0", {R::RegisterDef, R::String}, B::Pack, false, true, true),
        makeV6OpInfo("call_method_0", {R::RegisterDef, R::RegisterUse, R::String}, B::Pack, false, true, true),
        makeV6OpInfo("make_closure", {R::RegisterDef, R::Prototype}, B::Single, false, true),
        makeV6OpInfo("varargs", {R::RegisterDef}, B::Pack),
        makeV6OpInfo("return", {R::RegisterUse}, B::None, true, true),
        makeV6OpInfo("jump", {R::Target}, B::None, true),
        makeV6OpInfo("jump_false", {R::RegisterUse, R::Target}, B::None, true),
        makeV6OpInfo("jump_false_alt", {R::RegisterUse, R::Target}, B::None, true),
        makeV6OpInfo("jump_true", {R::RegisterUse, R::Target}, B::None, true),
        makeV6OpInfo("enter_scope", {}, B::None, false, true),
        makeV6OpInfo("leave_scopes", {R::Immediate}, B::None, false, true),
        makeV6OpInfo("to_string", {R::RegisterDef, R::RegisterUse}, B::Single, false, true),
        makeV6OpInfo("iterator_init", {R::RegisterDef, R::RegisterUse}, B::Pack, false, true),
        makeV6OpInfo("jump_nil", {R::RegisterUse, R::Target}, B::None, true),
        makeV6OpInfo("for_check", {R::RegisterDef, R::RegisterUse, R::RegisterUse, R::RegisterUse}, B::Single, false, true),
        makeV6OpInfo("opaque_guard", {R::Immediate, R::Immediate, R::Immediate, R::Immediate, R::Immediate}),
    };
    return instructions;
}

const V6OpInfo& v6OpInfo(V6Op op)
{
    size_t index = v6OpIndex(op);
    if (index >= v6InstructionSet().size())
        throw std::runtime_error("internal error: invalid AlexVM opcode");
    return v6InstructionSet()[index];
}

std::string_view v6OperandRoleName(V6OperandRole role)
{
    switch (role)
    {
    case V6OperandRole::RegisterDef:
        return "register_def";
    case V6OperandRole::RegisterUse:
        return "register_use";
    case V6OperandRole::Constant:
        return "constant";
    case V6OperandRole::String:
        return "string";
    case V6OperandRole::Local:
        return "local_cell";
    case V6OperandRole::Prototype:
        return "prototype";
    case V6OperandRole::Target:
        return "block_target";
    case V6OperandRole::Immediate:
        return "immediate";
    case V6OperandRole::None:
        return "none";
    }
    return "none";
}

std::string_view v6ResultBehaviorName(V6ResultBehavior result)
{
    switch (result)
    {
    case V6ResultBehavior::None:
        return "zero";
    case V6ResultBehavior::Single:
        return "one";
    case V6ResultBehavior::Pack:
        return "variadic";
    }
    return "zero";
}

bool v6IsBinary(V6Op op)
{
    return op == V6Op::Binary || op == V6Op::BinaryAlt;
}

bool v6IsLoadConstant(V6Op op)
{
    return op == V6Op::LoadConstant || op == V6Op::LoadConstantAlt;
}

bool v6IsTerminator(V6Op op)
{
    return v6OpInfo(op).terminator;
}

std::vector<size_t> v6TargetArgs(V6Op op)
{
    std::vector<size_t> result;
    const V6OpInfo& info = v6OpInfo(op);
    for (size_t index = 0; index < info.operandCount; ++index)
        if (info.operands[index] == V6OperandRole::Target)
            result.push_back(index);
    return result;
}

std::vector<size_t> v6RegisterDefs(V6Op op)
{
    std::vector<size_t> result;
    const V6OpInfo& info = v6OpInfo(op);
    for (size_t index = 0; index < info.operandCount; ++index)
        if (info.operands[index] == V6OperandRole::RegisterDef)
            result.push_back(index);
    return result;
}

std::vector<size_t> v6RegisterUses(V6Op op)
{
    std::vector<size_t> result;
    const V6OpInfo& info = v6OpInfo(op);
    for (size_t index = 0; index < info.operandCount; ++index)
        if (info.operands[index] == V6OperandRole::RegisterUse)
            result.push_back(index);
    return result;
}

std::vector<size_t> v6StringArgs(V6Op op)
{
    std::vector<size_t> result;
    const V6OpInfo& info = v6OpInfo(op);
    for (size_t index = 0; index < info.operandCount; ++index)
        if (info.operands[index] == V6OperandRole::String)
            result.push_back(index);
    return result;
}

std::vector<V6BasicBlock> buildV6Blocks(const std::vector<V6Instruction>& code)
{
    if (code.empty())
        throw std::runtime_error("internal error: empty v6 prototype");

    std::set<size_t> leaders = {0};
    for (size_t index = 0; index < code.size(); ++index)
    {
        const V6Instruction& instruction = code[index];
        for (size_t position : v6TargetArgs(instruction.op))
        {
            if (position >= instruction.args.size() || instruction.args[position] >= code.size())
                throw std::runtime_error("internal error: v6 control-flow target is out of range");
            leaders.insert(instruction.args[position]);
        }
        if (v6IsTerminator(instruction.op) && index + 1 < code.size())
            leaders.insert(index + 1);
    }

    std::vector<size_t> starts(leaders.begin(), leaders.end());
    std::vector<V6BasicBlock> blocks;
    std::vector<size_t> blockForInstruction(code.size(), 0);
    for (size_t index = 0; index < starts.size(); ++index)
    {
        size_t start = starts[index];
        size_t end = index + 1 < starts.size() ? starts[index + 1] : code.size();
        V6BasicBlock block{index, start, end, {}};
        for (size_t instruction = start; instruction < end; ++instruction)
            blockForInstruction[instruction] = index;
        blocks.push_back(std::move(block));
    }

    for (V6BasicBlock& block : blocks)
    {
        const V6Instruction& last = code[block.end - 1];
        auto addSuccessor = [&](size_t instruction) {
            size_t successor = blockForInstruction.at(instruction);
            if (std::find(block.successors.begin(), block.successors.end(), successor) == block.successors.end())
                block.successors.push_back(successor);
        };
        if (last.op == V6Op::Jump)
            addSuccessor(last.args[0]);
        else if (last.op == V6Op::JumpFalse || last.op == V6Op::JumpFalseAlt || last.op == V6Op::JumpTrue || last.op == V6Op::JumpNil)
        {
            addSuccessor(last.args[1]);
            if (block.end < code.size())
                addSuccessor(block.end);
        }
        else if (last.op != V6Op::Return && block.end < code.size())
            addSuccessor(block.end);
    }
    return blocks;
}

std::optional<bool> v6ConstantTruthy(const json& constant)
{
    if (!constant.is_array() || constant.empty() || !constant[0].is_number_integer())
        return std::nullopt;
    int tag = constant[0].get<int>();
    if (tag == 0)
        return false;
    if (tag == 1 && constant.size() >= 2)
        return constant[1].get<int>() != 0;
    if (tag == 2 || tag == 3)
        return true;
    return std::nullopt;
}

std::optional<json> foldV6Unary(V6Unary operation, const json& value, const V6Program& program)
{
    if (operation == V6Unary::Not)
    {
        if (std::optional<bool> truthy = v6ConstantTruthy(value))
            return json::array({1, *truthy ? 0 : 1});
        return std::nullopt;
    }
    if (!value.is_array() || value.size() < 2)
        return std::nullopt;
    int tag = value[0].get<int>();
    if (operation == V6Unary::Minus && tag == 2)
        return json::array({2, -value[1].get<double>()});
    if (operation == V6Unary::Length && tag == 3)
    {
        uint32_t stringId = value[1].get<uint32_t>();
        if (stringId != 0 && stringId <= program.strings.size())
            return json::array({2, program.strings[stringId - 1].size()});
    }
    return std::nullopt;
}

std::optional<json> foldV6Binary(V6Binary operation, const json& left, const json& right, const V6Program& program)
{
    if (!left.is_array() || !right.is_array() || left.empty() || right.empty())
        return std::nullopt;
    int leftTag = left[0].get<int>();
    int rightTag = right[0].get<int>();
    auto boolean = [](bool value) { return json::array({1, value ? 1 : 0}); };

    if (operation == V6Binary::Eq || operation == V6Binary::Ne)
    {
        bool equal = false;
        if (leftTag == rightTag)
        {
            if (leftTag == 0)
                equal = true;
            else if (leftTag == 1)
                equal = left[1].get<int>() == right[1].get<int>();
            else if (leftTag == 2)
                equal = left[1].get<double>() == right[1].get<double>();
            else if (leftTag == 3)
                equal = left[1].get<uint32_t>() == right[1].get<uint32_t>();
            else
                return std::nullopt;
        }
        return boolean(operation == V6Binary::Eq ? equal : !equal);
    }

    if (leftTag == 2 && rightTag == 2)
    {
        double lhs = left[1].get<double>();
        double rhs = right[1].get<double>();
        if (operation == V6Binary::Lt)
            return boolean(lhs < rhs);
        if (operation == V6Binary::Le)
            return boolean(lhs <= rhs);
        if (operation == V6Binary::Gt)
            return boolean(lhs > rhs);
        if (operation == V6Binary::Ge)
            return boolean(lhs >= rhs);

        double result = 0.0;
        if (operation == V6Binary::Add)
            result = lhs + rhs;
        else if (operation == V6Binary::Sub)
            result = lhs - rhs;
        else if (operation == V6Binary::Mul)
            result = lhs * rhs;
        else if (operation == V6Binary::Div)
            result = lhs / rhs;
        else if (operation == V6Binary::FloorDiv)
            result = std::floor(lhs / rhs);
        else if (operation == V6Binary::Mod)
            result = lhs - std::floor(lhs / rhs) * rhs;
        else if (operation == V6Binary::Pow)
            result = std::pow(lhs, rhs);
        else
            return std::nullopt;
        if (std::isfinite(result))
            return json::array({2, result});
        return std::nullopt;
    }

    if (leftTag == 3 && rightTag == 3 && left.size() >= 2 && right.size() >= 2)
    {
        uint32_t leftId = left[1].get<uint32_t>();
        uint32_t rightId = right[1].get<uint32_t>();
        if (leftId == 0 || rightId == 0 || leftId > program.strings.size() || rightId > program.strings.size())
            return std::nullopt;
        const std::string& lhs = program.strings[leftId - 1];
        const std::string& rhs = program.strings[rightId - 1];
        if (operation == V6Binary::Lt)
            return boolean(lhs < rhs);
        if (operation == V6Binary::Le)
            return boolean(lhs <= rhs);
        if (operation == V6Binary::Gt)
            return boolean(lhs > rhs);
        if (operation == V6Binary::Ge)
            return boolean(lhs >= rhs);
    }
    return std::nullopt;
}

void pruneV6Prototype(V6Prototype& prototype, V6Program& program)
{
    std::vector<V6BasicBlock> blocks = buildV6Blocks(prototype.code);
    std::vector<bool> reachableBlock(blocks.size(), false);
    std::vector<size_t> worklist{0};
    reachableBlock[0] = true;
    while (!worklist.empty())
    {
        size_t block = worklist.back();
        worklist.pop_back();
        for (size_t successor : blocks[block].successors)
        {
            if (!reachableBlock[successor])
            {
                reachableBlock[successor] = true;
                worklist.push_back(successor);
            }
        }
    }

    std::vector<bool> keep(prototype.code.size(), false);
    for (const V6BasicBlock& block : blocks)
    {
        if (!reachableBlock[block.id])
            continue;
        for (size_t pc = block.start; pc < block.end; ++pc)
            keep[pc] = true;
    }
    size_t redundantMoves = 0;
    for (size_t pc = 0; pc < prototype.code.size(); ++pc)
    {
        const V6Instruction& instruction = prototype.code[pc];
        if (keep[pc] && instruction.op == V6Op::Move && instruction.args[0] == instruction.args[1])
        {
            keep[pc] = false;
            ++redundantMoves;
        }
    }

    size_t keptCount = static_cast<size_t>(std::count(keep.begin(), keep.end(), true));
    program.redundantMoveCount += redundantMoves;
    program.unreachableInstructionCount += prototype.code.size() - keptCount - redundantMoves;
    if (keptCount == prototype.code.size())
        return;

    std::vector<size_t> redirect(prototype.code.size(), keptCount);
    size_t next = keptCount;
    for (size_t pc = prototype.code.size(); pc-- > 0;)
    {
        if (keep[pc])
            --next;
        redirect[pc] = next;
    }
    std::vector<V6Instruction> rewritten;
    rewritten.reserve(keptCount);
    for (size_t pc = 0; pc < prototype.code.size(); ++pc)
    {
        if (!keep[pc])
            continue;
        V6Instruction instruction = prototype.code[pc];
        for (size_t position : v6TargetArgs(instruction.op))
        {
            size_t target = instruction.args[position];
            if (target >= redirect.size() || redirect[target] >= keptCount)
                throw std::runtime_error("semantic cleanup produced an invalid control-flow target");
            instruction.args[position] = static_cast<uint32_t>(redirect[target]);
        }
        rewritten.push_back(std::move(instruction));
    }
    prototype.code = std::move(rewritten);
}

void runV6SemanticPasses(V6Program& program)
{
    for (V6Prototype& prototype : program.prototypes)
    {
        for (size_t pc = 0; pc < prototype.code.size(); ++pc)
        {
            V6Instruction& instruction = prototype.code[pc];
            if (instruction.op == V6Op::Unary && pc >= 1)
            {
                const V6Instruction& source = prototype.code[pc - 1];
                if (v6IsLoadConstant(source.op) && source.args[0] == instruction.args[2])
                {
                    if (std::optional<json> folded = foldV6Unary(static_cast<V6Unary>(instruction.args[1]), prototype.constants[source.args[1] - 1], program))
                    {
                        prototype.constants.push_back(std::move(*folded));
                        instruction = {V6Op::LoadConstant, {instruction.args[0], static_cast<uint32_t>(prototype.constants.size())}};
                        ++program.constantFoldCount;
                    }
                }
            }
            else if (instruction.op == V6Op::Binary && pc >= 2)
            {
                const V6Instruction& left = prototype.code[pc - 2];
                const V6Instruction& right = prototype.code[pc - 1];
                if (v6IsLoadConstant(left.op) && v6IsLoadConstant(right.op) && left.args[0] == instruction.args[2] && right.args[0] == instruction.args[3])
                {
                    if (std::optional<json> folded = foldV6Binary(static_cast<V6Binary>(instruction.args[1]), prototype.constants[left.args[1] - 1],
                            prototype.constants[right.args[1] - 1], program))
                    {
                        prototype.constants.push_back(std::move(*folded));
                        instruction = {V6Op::LoadConstant, {instruction.args[0], static_cast<uint32_t>(prototype.constants.size())}};
                        ++program.constantFoldCount;
                    }
                }
            }
        }

        for (size_t pc = 1; pc < prototype.code.size(); ++pc)
        {
            V6Instruction& branch = prototype.code[pc];
            if (branch.op != V6Op::JumpFalse && branch.op != V6Op::JumpTrue && branch.op != V6Op::JumpNil)
                continue;
            const V6Instruction& source = prototype.code[pc - 1];
            if (!v6IsLoadConstant(source.op) || source.args[0] != branch.args[0])
                continue;
            const json& constant = prototype.constants[source.args[1] - 1];
            bool jump = false;
            if (branch.op == V6Op::JumpNil)
                jump = constant.is_array() && !constant.empty() && constant[0].get<int>() == 0;
            else if (std::optional<bool> truthy = v6ConstantTruthy(constant))
                jump = branch.op == V6Op::JumpFalse ? !*truthy : *truthy;
            else
                continue;
            uint32_t target = branch.args[1];
            branch = jump ? V6Instruction{V6Op::Jump, {target}} : V6Instruction{V6Op::Nop, {}};
            ++program.branchFoldCount;
        }
        pruneV6Prototype(prototype, program);
    }
}

struct V6ValidationFailure : std::runtime_error
{
    std::string stage;
    std::string code;
    std::string kind;
    size_t prototype = 0;
    size_t instruction = 0;

    V6ValidationFailure(std::string stage, std::string code, std::string kind, size_t prototype, size_t instruction, std::string message)
        : std::runtime_error(std::move(message))
        , stage(std::move(stage))
        , code(std::move(code))
        , kind(std::move(kind))
        , prototype(prototype)
        , instruction(instruction)
    {
    }
};

void validateV6Program(V6Program& program, std::string stage, bool validateDefinitions)
{
    auto fail = [&](std::string code, std::string kind, size_t prototype, size_t instruction, std::string message) -> void {
        throw V6ValidationFailure(stage, std::move(code), std::move(kind), prototype, instruction, std::move(message));
    };

    if (program.prototypes.empty() || program.rootPrototype == 0 || program.rootPrototype > program.prototypes.size())
        fail("invalid_root_prototype", "Program", 0, 0, "AlexIR has no valid root prototype");

    for (size_t prototypeIndex = 0; prototypeIndex < program.prototypes.size(); ++prototypeIndex)
    {
        V6Prototype& prototype = program.prototypes[prototypeIndex];
        if (prototype.code.empty())
            fail("empty_prototype", "Prototype", prototypeIndex + 1, 0, "AlexIR prototype has no instructions");

        uint32_t registerLimit = prototype.maxRegister != 0 ? prototype.maxRegister : prototype.virtualRegisterCount;
        for (size_t instructionIndex = 0; instructionIndex < prototype.code.size(); ++instructionIndex)
        {
            const V6Instruction& instruction = prototype.code[instructionIndex];
            const V6OpInfo& info = v6OpInfo(instruction.op);
            if (instruction.args.size() != info.operandCount)
                fail("operand_count_mismatch", info.name, prototypeIndex + 1, instructionIndex,
                    "AlexVM instruction operand count does not match its declarative schema");

            for (size_t operandIndex = 0; operandIndex < instruction.args.size(); ++operandIndex)
            {
                uint32_t value = instruction.args[operandIndex];
                switch (info.operands[operandIndex])
                {
                case V6OperandRole::RegisterDef:
                case V6OperandRole::RegisterUse:
                    if (value == 0 || value > registerLimit)
                        fail("register_out_of_range", info.name, prototypeIndex + 1, instructionIndex, "AlexVM register operand is out of range");
                    break;
                case V6OperandRole::Constant:
                    if (value == 0 || value > prototype.constants.size())
                        fail("constant_out_of_range", info.name, prototypeIndex + 1, instructionIndex, "AlexVM constant operand is out of range");
                    break;
                case V6OperandRole::String:
                    if (value == 0 || value > program.strings.size())
                        fail("string_out_of_range", info.name, prototypeIndex + 1, instructionIndex, "AlexVM string operand is out of range");
                    break;
                case V6OperandRole::Prototype:
                    if (value == 0 || value > program.prototypes.size())
                        fail("prototype_out_of_range", info.name, prototypeIndex + 1, instructionIndex, "AlexVM child prototype operand is out of range");
                    break;
                case V6OperandRole::Target:
                    if (value >= prototype.code.size())
                        fail("control_flow_target_out_of_range", info.name, prototypeIndex + 1, instructionIndex, "AlexVM control-flow target is out of range");
                    break;
                case V6OperandRole::Local:
                    if (value == 0)
                        fail("invalid_local", info.name, prototypeIndex + 1, instructionIndex, "AlexIR local identifiers must be nonzero");
                    break;
                case V6OperandRole::None:
                case V6OperandRole::Immediate:
                    break;
                }
            }

            if (v6IsBinary(instruction.op) && instruction.args[1] >= static_cast<uint32_t>(V6Binary::Count))
                fail("invalid_binary_operator", info.name, prototypeIndex + 1, instructionIndex, "AlexVM binary operator tag is invalid");
            if (instruction.op == V6Op::Unary && instruction.args[1] >= static_cast<uint32_t>(V6Unary::Count))
                fail("invalid_unary_operator", info.name, prototypeIndex + 1, instructionIndex, "AlexVM unary operator tag is invalid");
        }

        for (uint32_t child : prototype.children)
            if (child == 0 || child > program.prototypes.size())
                fail("child_prototype_out_of_range", "Prototype", prototypeIndex + 1, 0, "prototype child reference is out of range");
        for (uint32_t parameter : prototype.params)
            if (parameter == 0)
                fail("invalid_parameter", "Prototype", prototypeIndex + 1, 0, "prototype parameter identifier must be nonzero");
        for (uint32_t capture : prototype.captures)
            if (capture == 0)
                fail("invalid_capture", "Prototype", prototypeIndex + 1, 0, "prototype capture identifier must be nonzero");

        prototype.blocks = buildV6Blocks(prototype.code);
        if (!validateDefinitions)
            continue;

        using RegisterSet = std::unordered_set<uint32_t>;
        std::vector<bool> reachable(prototype.blocks.size(), false);
        std::vector<size_t> worklist{0};
        reachable[0] = true;
        while (!worklist.empty())
        {
            size_t blockId = worklist.back();
            worklist.pop_back();
            for (size_t successor : prototype.blocks[blockId].successors)
            {
                if (!reachable[successor])
                {
                    reachable[successor] = true;
                    worklist.push_back(successor);
                }
            }
        }
        std::vector<std::vector<size_t>> predecessors(prototype.blocks.size());
        RegisterSet universe;
        for (const V6BasicBlock& block : prototype.blocks)
        {
            if (reachable[block.id])
                for (size_t successor : block.successors)
                    if (reachable[successor])
                        predecessors.at(successor).push_back(block.id);
            for (size_t pc = block.start; pc < block.end; ++pc)
                for (size_t position : v6RegisterDefs(prototype.code[pc].op))
                    universe.insert(prototype.code[pc].args[position]);
        }

        std::vector<RegisterSet> in(prototype.blocks.size(), universe);
        std::vector<RegisterSet> out(prototype.blocks.size(), universe);
        in[0].clear();
        bool changed = true;
        while (changed)
        {
            changed = false;
            for (const V6BasicBlock& block : prototype.blocks)
            {
                if (!reachable[block.id])
                    continue;
                RegisterSet nextIn;
                if (block.id != 0 && !predecessors[block.id].empty())
                {
                    nextIn = out[predecessors[block.id].front()];
                    for (size_t index = 1; index < predecessors[block.id].size(); ++index)
                    {
                        RegisterSet intersection;
                        for (uint32_t value : nextIn)
                            if (out[predecessors[block.id][index]].count(value))
                                intersection.insert(value);
                        nextIn = std::move(intersection);
                    }
                }
                RegisterSet nextOut = nextIn;
                for (size_t pc = block.start; pc < block.end; ++pc)
                    for (size_t position : v6RegisterDefs(prototype.code[pc].op))
                        nextOut.insert(prototype.code[pc].args[position]);
                if (nextIn != in[block.id] || nextOut != out[block.id])
                {
                    in[block.id] = std::move(nextIn);
                    out[block.id] = std::move(nextOut);
                    changed = true;
                }
            }
        }

        for (const V6BasicBlock& block : prototype.blocks)
        {
            if (!reachable[block.id])
                continue;
            RegisterSet defined = in[block.id];
            for (size_t pc = block.start; pc < block.end; ++pc)
            {
                const V6Instruction& instruction = prototype.code[pc];
                for (size_t position : v6RegisterUses(instruction.op))
                    if (!defined.count(instruction.args[position]))
                    {
                        std::string incoming;
                        for (size_t predecessor : predecessors[block.id])
                            incoming += (incoming.empty() ? "" : ",") + std::to_string(predecessor) +
                                (out[predecessor].count(instruction.args[position]) ? ":defined" : ":missing");
                        fail("use_before_definition", v6OpInfo(instruction.op).name, prototypeIndex + 1, pc,
                            "AlexIR register r" + std::to_string(instruction.args[position]) + " is not definitely defined on every incoming control-flow path to block " +
                                std::to_string(block.id) + " (" + incoming + ")");
                    }
                for (size_t position : v6RegisterDefs(instruction.op))
                    defined.insert(instruction.args[position]);
            }
        }
    }
}

json v6ProgramToJson(const V6Program& program, std::string_view format)
{
    json prototypes = json::array();
    for (const V6Prototype& prototype : program.prototypes)
    {
        json code = json::array();
        for (const V6Instruction& instruction : prototype.code)
        {
            const V6OpInfo& info = v6OpInfo(instruction.op);
            json roles = json::array();
            for (size_t index = 0; index < info.operandCount; ++index)
                roles.push_back(v6OperandRoleName(info.operands[index]));
            code.push_back({{"op", info.name}, {"args", instruction.args}, {"operand_roles", std::move(roles)},
                {"result_arity", v6ResultBehaviorName(info.result)}, {"side_effecting", info.sideEffecting}, {"may_yield", info.mayYield}});
        }
        json blocks = json::array();
        for (const V6BasicBlock& block : prototype.blocks)
            blocks.push_back({{"id", block.id}, {"start", block.start}, {"end", block.end}, {"successors", block.successors}});
        prototypes.push_back({
            {"params", prototype.params}, {"children", prototype.children}, {"captures", prototype.captures}, {"code", std::move(code)},
            {"blocks", std::move(blocks)}, {"constants", prototype.constants}, {"constant_map", prototype.logicalToPhysicalConstant},
            {"opcodes", prototype.opcodes}, {"binary_codes", prototype.binaryCodes}, {"unary_codes", prototype.unaryCodes}, {"name", prototype.name},
            {"virtual_registers", prototype.virtualRegisterCount}, {"physical_registers", prototype.maxRegister}, {"arg_multiplier", prototype.argMultiplier},
            {"arg_salt", prototype.argSalt}, {"arg_step", prototype.argStep}, {"vararg", prototype.vararg}, {"decoy", prototype.decoy},
        });
    }
    return {
        {"format", format}, {"version", format == "alex-ir" ? 2 : 6}, {"root_prototype", program.rootPrototype}, {"strings", program.strings},
        {"prototypes", std::move(prototypes)},
        {"stats", {{"locals", program.localCount}, {"instructions", program.instructionCount}, {"blocks", program.blockCount},
                      {"decoy_prototypes", program.decoyPrototypeCount}, {"opaque_guards", program.opaqueGuardCount},
                      {"substitutions", program.substitutionCount}, {"superoperators", program.superoperatorCount},
                      {"constant_folds", program.constantFoldCount}, {"branch_folds", program.branchFoldCount},
                      {"unreachable_removed", program.unreachableInstructionCount}, {"redundant_moves_removed", program.redundantMoveCount},
                      {"register_reuse", program.registerReuse}}},
    };
}

V6Op v6OpFromName(std::string_view name)
{
    for (size_t index = 0; index < v6InstructionSet().size(); ++index)
        if (name == v6InstructionSet()[index].name)
            return static_cast<V6Op>(index);
    throw std::runtime_error("unknown opcode in AlexIR/AlexVM text");
}

V6Program v6ProgramFromJson(const json& value, std::string_view expectedFormat)
{
    if (!value.is_object() || value.value("format", "") != expectedFormat || value.value("version", 0) != (expectedFormat == "alex-ir" ? 2 : 6))
        throw std::runtime_error("invalid AlexIR/AlexVM text header");
    V6Program program;
    program.rootPrototype = value.at("root_prototype").get<uint32_t>();
    program.strings = value.at("strings").get<std::vector<std::string>>();
    for (size_t index = 0; index < program.strings.size(); ++index)
        program.stringIds.emplace(program.strings[index], static_cast<uint32_t>(index + 1));
    for (const json& source : value.at("prototypes"))
    {
        V6Prototype prototype;
        prototype.params = source.at("params").get<std::vector<uint32_t>>();
        prototype.children = source.at("children").get<std::vector<uint32_t>>();
        prototype.captures = source.at("captures").get<std::vector<uint32_t>>();
        prototype.captureSet.insert(prototype.captures.begin(), prototype.captures.end());
        for (const json& encoded : source.at("code"))
            prototype.code.push_back({v6OpFromName(encoded.at("op").get<std::string>()), encoded.at("args").get<std::vector<uint32_t>>()});
        for (const json& encoded : source.at("blocks"))
            prototype.blocks.push_back({encoded.at("id").get<size_t>(), encoded.at("start").get<size_t>(), encoded.at("end").get<size_t>(),
                encoded.at("successors").get<std::vector<size_t>>()});
        prototype.constants = source.at("constants");
        prototype.logicalToPhysicalConstant = source.at("constant_map").get<std::vector<uint32_t>>();
        prototype.opcodes = source.at("opcodes").get<std::vector<uint32_t>>();
        prototype.binaryCodes = source.at("binary_codes").get<std::vector<uint32_t>>();
        prototype.unaryCodes = source.at("unary_codes").get<std::vector<uint32_t>>();
        prototype.name = source.at("name").get<uint32_t>();
        prototype.virtualRegisterCount = source.at("virtual_registers").get<uint32_t>();
        prototype.maxRegister = source.at("physical_registers").get<uint32_t>();
        prototype.argMultiplier = source.at("arg_multiplier").get<uint32_t>();
        prototype.argSalt = source.at("arg_salt").get<uint32_t>();
        prototype.argStep = source.at("arg_step").get<uint32_t>();
        prototype.vararg = source.at("vararg").get<bool>();
        prototype.decoy = source.at("decoy").get<bool>();
        program.prototypes.push_back(std::move(prototype));
    }
    const json& stats = value.at("stats");
    program.localCount = stats.at("locals").get<size_t>();
    program.instructionCount = stats.at("instructions").get<size_t>();
    program.blockCount = stats.at("blocks").get<size_t>();
    program.decoyPrototypeCount = stats.at("decoy_prototypes").get<size_t>();
    program.opaqueGuardCount = stats.at("opaque_guards").get<size_t>();
    program.substitutionCount = stats.at("substitutions").get<size_t>();
    program.superoperatorCount = stats.at("superoperators").get<size_t>();
    program.constantFoldCount = stats.at("constant_folds").get<size_t>();
    program.branchFoldCount = stats.at("branch_folds").get<size_t>();
    program.unreachableInstructionCount = stats.at("unreachable_removed").get<size_t>();
    program.redundantMoveCount = stats.at("redundant_moves_removed").get<size_t>();
    program.registerReuse = stats.at("register_reuse").get<bool>();
    return program;
}

std::string v6ProgramText(const V6Program& program, std::string_view format)
{
    json encoded = v6ProgramToJson(program, format);
    std::string text = encoded.dump(2);
    V6Program decoded = v6ProgramFromJson(json::parse(text), format);
    if (v6ProgramToJson(decoded, format) != encoded)
        throw std::runtime_error("AlexIR/AlexVM text failed deterministic round-trip validation");
    return text + "\n";
}

class V6SemanticCompiler
{
public:
    V6SemanticCompiler(std::mt19937_64& rng, const Config& config)
        : rng(rng)
        , config(config)
        , localMultiplier(static_cast<uint32_t>(((rng() % 193u) + 17u) | 1u))
        , localSalt(static_cast<uint32_t>((rng() % 50000u) + 2003u))
    {
    }

    V6Program compile(Luau::AstStatBlock* root, V6Program* semanticSnapshot = nullptr)
    {
        program.prototypes.emplace_back();
        program.prototypes[0].vararg = true;
        contexts.push_back({0, 1, 0, {}});
        compileBlockBody(root);
        emitEmptyReturn();
        program.prototypes[0].virtualRegisterCount = static_cast<uint32_t>(current().nextRegister - 1);
        contexts.pop_back();

        program.localCount = nextLocal - 1;
        runV6SemanticPasses(program);
        validateV6Program(program, "ir_validate", true);
        if (semanticSnapshot)
            *semanticSnapshot = program;
        addDecoyPrototypes();
        finalizeProgram();
        validateV6Program(program, "vm_lower", false);
        return std::move(program);
    }

protected:
    struct LoopContext
    {
        int breakDepth = 0;
        int continueDepth = 0;
        std::vector<size_t> breaks;
        std::vector<size_t> continues;
    };

    struct Context
    {
        size_t prototype = 0;
        uint32_t nextRegister = 1;
        int scopeDepth = 0;
        std::vector<LoopContext> loops;
    };

    enum class TargetKind
    {
        Local,
        Global,
        Index,
        IndexName,
    };

    struct PreparedTarget
    {
        TargetKind kind = TargetKind::Local;
        uint32_t id = 0;
        uint32_t object = 0;
        uint32_t key = 0;
    };

    std::mt19937_64& rng;
    const Config& config;
    V6Program program;
    std::vector<Context> contexts;
    std::unordered_map<const Luau::AstLocal*, uint32_t> localIds;
    std::unordered_map<const Luau::AstLocal*, uint32_t> localOwners;
    uint32_t nextLocal = 1;
    uint32_t localMultiplier = 1;
    uint32_t localSalt = 0;

    Context& current()
    {
        return contexts.back();
    }

    V6Prototype& prototype()
    {
        return program.prototypes[current().prototype];
    }

    uint32_t currentPrototypeId() const
    {
        return static_cast<uint32_t>(contexts.back().prototype + 1);
    }

    [[noreturn]] void unsupported(const Luau::Location& location, std::string astKind, std::string detail) const
    {
        throw V6CompileFailure("unsupported_syntax", "semantic_ir", std::move(astKind), location, "AlexVM 6 does not support " + detail);
    }

    static std::string astString(const Luau::AstArray<char>& value)
    {
        return std::string(value.data, value.size);
    }

    uint32_t allocRegister()
    {
        return current().nextRegister++;
    }

    size_t emit(V6Op op, std::vector<uint32_t> args = {})
    {
        size_t index = prototype().code.size();
        prototype().code.push_back({op, std::move(args)});
        if (op == V6Op::CallGlobal0 || op == V6Op::CallMethod0)
            ++prototype().superoperatorCount;
        return index;
    }

    void patch(size_t instruction, size_t argument, size_t target)
    {
        V6Instruction& value = prototype().code.at(instruction);
        if (argument >= value.args.size())
            throw std::runtime_error("internal error: v6 jump patch argument is missing");
        value.args[argument] = static_cast<uint32_t>(target);
    }

    uint32_t stringId(std::string value)
    {
        auto [it, inserted] = program.stringIds.emplace(value, static_cast<uint32_t>(program.strings.size() + 1));
        if (inserted)
            program.strings.push_back(std::move(value));
        return it->second;
    }

    uint32_t localId(const Luau::AstLocal* local, uint32_t owner)
    {
        auto found = localIds.find(local);
        if (found != localIds.end())
            return found->second;
        uint32_t id = nextLocal++ * localMultiplier + localSalt;
        localIds.emplace(local, id);
        localOwners.emplace(local, owner);
        return id;
    }

    uint32_t localId(const Luau::AstLocal* local)
    {
        return localId(local, currentPrototypeId());
    }

    void noteCapture(const Luau::AstLocal* local, uint32_t id)
    {
        auto owner = localOwners.find(local);
        if (owner == localOwners.end() || owner->second == currentPrototypeId())
            return;
        if (prototype().captureSet.insert(id).second)
            prototype().captures.push_back(id);
    }

    uint32_t addConstant(json value)
    {
        prototype().constants.push_back(std::move(value));
        return static_cast<uint32_t>(prototype().constants.size());
    }

    uint32_t emitConstant(json value)
    {
        uint32_t destination = allocRegister();
        emit(V6Op::LoadConstant, {destination, addConstant(std::move(value))});
        return destination;
    }

    uint32_t emitNil()
    {
        return emitConstant(json::array({0}));
    }

    V6Binary binaryOperator(Luau::AstExprBinary::Op op, const Luau::Location& location) const
    {
        switch (op)
        {
        case Luau::AstExprBinary::Add:
            return V6Binary::Add;
        case Luau::AstExprBinary::Sub:
            return V6Binary::Sub;
        case Luau::AstExprBinary::Mul:
            return V6Binary::Mul;
        case Luau::AstExprBinary::Div:
            return V6Binary::Div;
        case Luau::AstExprBinary::FloorDiv:
            return V6Binary::FloorDiv;
        case Luau::AstExprBinary::Mod:
            return V6Binary::Mod;
        case Luau::AstExprBinary::Pow:
            return V6Binary::Pow;
        case Luau::AstExprBinary::Concat:
            return V6Binary::Concat;
        case Luau::AstExprBinary::CompareNe:
            return V6Binary::Ne;
        case Luau::AstExprBinary::CompareEq:
            return V6Binary::Eq;
        case Luau::AstExprBinary::CompareLt:
            return V6Binary::Lt;
        case Luau::AstExprBinary::CompareLe:
            return V6Binary::Le;
        case Luau::AstExprBinary::CompareGt:
            return V6Binary::Gt;
        case Luau::AstExprBinary::CompareGe:
            return V6Binary::Ge;
        case Luau::AstExprBinary::And:
        case Luau::AstExprBinary::Or:
        case Luau::AstExprBinary::Op__Count:
            break;
        }
        unsupported(location, "AstExprBinary", "this binary operator");
    }

    V6Unary unaryOperator(Luau::AstExprUnary::Op op, const Luau::Location& location) const
    {
        switch (op)
        {
        case Luau::AstExprUnary::Op::Not:
            return V6Unary::Not;
        case Luau::AstExprUnary::Op::Minus:
            return V6Unary::Minus;
        case Luau::AstExprUnary::Op::Len:
            return V6Unary::Length;
        }
        unsupported(location, "AstExprUnary", "this unary operator");
    }

    static Luau::AstExpr* peelTypeWrappers(Luau::AstExpr* expression)
    {
        while (expression)
        {
            if (auto assertion = expression->as<Luau::AstExprTypeAssertion>())
                expression = assertion->expr;
            else if (auto instantiate = expression->as<Luau::AstExprInstantiate>())
                expression = instantiate->expr;
            else
                break;
        }
        return expression;
    }

    uint32_t compileExpressionPack(Luau::AstExpr* expression)
    {
        Luau::AstExpr* peeled = peelTypeWrappers(expression);
        if (auto call = peeled->as<Luau::AstExprCall>())
            return compileCall(call);
        if (peeled->as<Luau::AstExprVarargs>())
        {
            uint32_t destination = allocRegister();
            emit(V6Op::Varargs, {destination});
            return destination;
        }

        uint32_t pack = allocRegister();
        emit(V6Op::PackNew, {pack});
        uint32_t value = compileExpression(expression);
        emit(V6Op::PackPush, {pack, value});
        return pack;
    }

    uint32_t compileExpressionList(const Luau::AstArray<Luau::AstExpr*>& expressions, std::optional<uint32_t> prefix = std::nullopt)
    {
        uint32_t pack = allocRegister();
        emit(V6Op::PackNew, {pack});
        if (prefix)
            emit(V6Op::PackPush, {pack, *prefix});
        for (size_t index = 0; index < expressions.size; ++index)
        {
            if (index + 1 == expressions.size)
            {
                uint32_t tail = compileExpressionPack(expressions.data[index]);
                emit(V6Op::PackExtend, {pack, tail});
            }
            else
            {
                uint32_t value = compileExpression(expressions.data[index]);
                emit(V6Op::PackPush, {pack, value});
            }
        }
        return pack;
    }

    uint32_t compileCall(Luau::AstExprCall* call)
    {
        Luau::AstExpr* function = peelTypeWrappers(call->func);
        if (!call->self && call->args.size == 0)
        {
            if (auto global = function->as<Luau::AstExprGlobal>())
            {
                uint32_t destination = allocRegister();
                emit(V6Op::CallGlobal0, {destination, stringId(global->name.value ? global->name.value : "")});
                return destination;
            }
        }
        if (call->self && call->args.size == 0)
        {
            if (auto index = function->as<Luau::AstExprIndexName>())
            {
                uint32_t self = compileExpression(index->expr);
                uint32_t destination = allocRegister();
                emit(V6Op::CallMethod0, {destination, self, stringId(index->index.value ? index->index.value : "")});
                return destination;
            }
        }

        uint32_t functionRegister = 0;
        uint32_t arguments = 0;
        if (call->self)
        {
            auto index = function->as<Luau::AstExprIndexName>();
            if (!index)
                unsupported(call->location, "AstExprCall", "this method-call target");
            uint32_t self = compileExpression(index->expr);
            functionRegister = allocRegister();
            emit(V6Op::GetIndexK, {functionRegister, self, stringId(index->index.value ? index->index.value : "")});
            arguments = compileExpressionList(call->args, self);
        }
        else
        {
            functionRegister = compileExpression(call->func);
            arguments = compileExpressionList(call->args);
        }

        uint32_t destination = allocRegister();
        emit(V6Op::Call, {destination, functionRegister, arguments});
        return destination;
    }

    uint32_t compileFunction(Luau::AstExprFunction* function)
    {
        size_t parent = current().prototype;
        size_t child = program.prototypes.size();
        program.prototypes.emplace_back();
        program.prototypes[parent].children.push_back(static_cast<uint32_t>(child + 1));
        if (function->debugname.value)
            program.prototypes[child].name = stringId(function->debugname.value);
        program.prototypes[child].vararg = function->vararg;

        contexts.push_back({child, 1, 0, {}});
        if (function->self)
            prototype().params.push_back(localId(function->self, static_cast<uint32_t>(child + 1)));
        for (size_t index = 0; index < function->args.size; ++index)
            prototype().params.push_back(localId(function->args.data[index], static_cast<uint32_t>(child + 1)));
        compileBlockBody(function->body);
        emitEmptyReturn();
        prototype().virtualRegisterCount = current().nextRegister - 1;
        contexts.pop_back();

        uint32_t destination = allocRegister();
        emit(V6Op::MakeClosure, {destination, static_cast<uint32_t>(child + 1)});
        return destination;
    }

    uint32_t compileExpression(Luau::AstExpr* expression)
    {
        if (auto group = expression->as<Luau::AstExprGroup>())
            return compileExpression(group->expr);
        if (auto assertion = expression->as<Luau::AstExprTypeAssertion>())
            return compileExpression(assertion->expr);
        if (auto instantiate = expression->as<Luau::AstExprInstantiate>())
            return compileExpression(instantiate->expr);
        if (expression->as<Luau::AstExprConstantNil>())
            return emitNil();
        if (auto boolean = expression->as<Luau::AstExprConstantBool>())
            return emitConstant(json::array({1, boolean->value ? 1 : 0}));
        if (auto number = expression->as<Luau::AstExprConstantNumber>())
            return emitConstant(json::array({2, number->value}));
        if (auto integer = expression->as<Luau::AstExprConstantInteger>())
            return emitConstant(json::array({2, integer->value}));
        if (auto string = expression->as<Luau::AstExprConstantString>())
            return emitConstant(json::array({3, stringId(astString(string->value))}));
        if (auto local = expression->as<Luau::AstExprLocal>())
        {
            uint32_t id = localId(local->local);
            noteCapture(local->local, id);
            uint32_t destination = allocRegister();
            emit(V6Op::GetLocal, {destination, id});
            return destination;
        }
        if (auto global = expression->as<Luau::AstExprGlobal>())
        {
            uint32_t destination = allocRegister();
            emit(V6Op::GetGlobal, {destination, stringId(global->name.value ? global->name.value : "")});
            return destination;
        }
        if (expression->as<Luau::AstExprVarargs>())
        {
            uint32_t values = compileExpressionPack(expression);
            uint32_t destination = allocRegister();
            emit(V6Op::PackGet, {destination, values, 1});
            return destination;
        }
        if (auto index = expression->as<Luau::AstExprIndexName>())
        {
            uint32_t object = compileExpression(index->expr);
            uint32_t destination = allocRegister();
            emit(V6Op::GetIndexK, {destination, object, stringId(index->index.value ? index->index.value : "")});
            return destination;
        }
        if (auto index = expression->as<Luau::AstExprIndexExpr>())
        {
            uint32_t object = compileExpression(index->expr);
            uint32_t key = compileExpression(index->index);
            uint32_t destination = allocRegister();
            emit(V6Op::GetIndex, {destination, object, key});
            return destination;
        }
        if (auto binary = expression->as<Luau::AstExprBinary>())
        {
            if (binary->op == Luau::AstExprBinary::And || binary->op == Luau::AstExprBinary::Or)
            {
                uint32_t destination = allocRegister();
                uint32_t left = compileExpression(binary->left);
                emit(V6Op::Move, {destination, left});
                V6Op jump = binary->op == Luau::AstExprBinary::And ? V6Op::JumpFalse : V6Op::JumpTrue;
                size_t done = emit(jump, {left, 0});
                uint32_t right = compileExpression(binary->right);
                emit(V6Op::Move, {destination, right});
                patch(done, 1, prototype().code.size());
                return destination;
            }
            uint32_t left = compileExpression(binary->left);
            uint32_t right = compileExpression(binary->right);
            uint32_t destination = allocRegister();
            emit(V6Op::Binary, {destination, static_cast<uint32_t>(binaryOperator(binary->op, binary->location)), left, right});
            return destination;
        }
        if (auto unary = expression->as<Luau::AstExprUnary>())
        {
            uint32_t source = compileExpression(unary->expr);
            uint32_t destination = allocRegister();
            emit(V6Op::Unary, {destination, static_cast<uint32_t>(unaryOperator(unary->op, unary->location)), source});
            return destination;
        }
        if (auto call = expression->as<Luau::AstExprCall>())
        {
            uint32_t values = compileCall(call);
            uint32_t destination = allocRegister();
            emit(V6Op::PackGet, {destination, values, 1});
            return destination;
        }
        if (auto function = expression->as<Luau::AstExprFunction>())
            return compileFunction(function);
        if (auto conditional = expression->as<Luau::AstExprIfElse>())
        {
            uint32_t destination = allocRegister();
            uint32_t condition = compileExpression(conditional->condition);
            size_t otherwise = emit(V6Op::JumpFalse, {condition, 0});
            uint32_t yes = compileExpression(conditional->trueExpr);
            emit(V6Op::Move, {destination, yes});
            size_t done = emit(V6Op::Jump, {0});
            patch(otherwise, 1, prototype().code.size());
            uint32_t no = compileExpression(conditional->falseExpr);
            emit(V6Op::Move, {destination, no});
            patch(done, 0, prototype().code.size());
            return destination;
        }
        if (auto interpolation = expression->as<Luau::AstExprInterpString>())
        {
            uint32_t destination = emitConstant(json::array({3, stringId(astString(interpolation->strings.data[0]))}));
            for (size_t index = 0; index < interpolation->expressions.size; ++index)
            {
                uint32_t value = compileExpression(interpolation->expressions.data[index]);
                uint32_t text = allocRegister();
                emit(V6Op::ToString, {text, value});
                uint32_t joined = allocRegister();
                emit(V6Op::Binary, {joined, static_cast<uint32_t>(V6Binary::Concat), destination, text});
                uint32_t suffix = emitConstant(json::array({3, stringId(astString(interpolation->strings.data[index + 1]))}));
                destination = allocRegister();
                emit(V6Op::Binary, {destination, static_cast<uint32_t>(V6Binary::Concat), joined, suffix});
            }
            return destination;
        }
        if (auto table = expression->as<Luau::AstExprTable>())
        {
            uint32_t destination = allocRegister();
            emit(V6Op::NewTable, {destination});
            uint32_t listIndex = 1;
            for (size_t index = 0; index < table->items.size; ++index)
            {
                const Luau::AstExprTable::Item& item = table->items.data[index];
                if (item.kind == Luau::AstExprTable::Item::Kind::List)
                {
                    if (index + 1 == table->items.size)
                    {
                        uint32_t values = compileExpressionPack(item.value);
                        emit(V6Op::AppendPack, {destination, values, listIndex});
                    }
                    else
                    {
                        uint32_t value = compileExpression(item.value);
                        emit(V6Op::SetList, {destination, listIndex++, value});
                    }
                }
                else if (item.kind == Luau::AstExprTable::Item::Kind::Record)
                {
                    auto key = item.key ? item.key->as<Luau::AstExprConstantString>() : nullptr;
                    if (!key)
                        unsupported(expression->location, "AstExprTable", "this record key");
                    uint32_t value = compileExpression(item.value);
                    emit(V6Op::SetIndexK, {destination, stringId(astString(key->value)), value});
                }
                else
                {
                    uint32_t key = compileExpression(item.key);
                    uint32_t value = compileExpression(item.value);
                    emit(V6Op::SetIndex, {destination, key, value});
                }
            }
            return destination;
        }
        unsupported(expression->location, "AstExpr", "this expression form");
    }

    PreparedTarget prepareTarget(Luau::AstExpr* target)
    {
        if (auto local = target->as<Luau::AstExprLocal>())
        {
            uint32_t id = localId(local->local);
            noteCapture(local->local, id);
            return {TargetKind::Local, id, 0, 0};
        }
        if (auto global = target->as<Luau::AstExprGlobal>())
            return {TargetKind::Global, stringId(global->name.value ? global->name.value : ""), 0, 0};
        if (auto index = target->as<Luau::AstExprIndexName>())
        {
            uint32_t object = compileExpression(index->expr);
            return {TargetKind::IndexName, stringId(index->index.value ? index->index.value : ""), object, 0};
        }
        if (auto index = target->as<Luau::AstExprIndexExpr>())
        {
            uint32_t object = compileExpression(index->expr);
            uint32_t key = compileExpression(index->index);
            return {TargetKind::Index, 0, object, key};
        }
        unsupported(target->location, "AstExpr", "this assignment target");
    }

    uint32_t readTarget(const PreparedTarget& target)
    {
        uint32_t destination = allocRegister();
        switch (target.kind)
        {
        case TargetKind::Local:
            emit(V6Op::GetLocal, {destination, target.id});
            break;
        case TargetKind::Global:
            emit(V6Op::GetGlobal, {destination, target.id});
            break;
        case TargetKind::Index:
            emit(V6Op::GetIndex, {destination, target.object, target.key});
            break;
        case TargetKind::IndexName:
            emit(V6Op::GetIndexK, {destination, target.object, target.id});
            break;
        }
        return destination;
    }

    void writeTarget(const PreparedTarget& target, uint32_t value)
    {
        switch (target.kind)
        {
        case TargetKind::Local:
            emit(V6Op::SetLocal, {target.id, value});
            break;
        case TargetKind::Global:
            emit(V6Op::SetGlobal, {target.id, value});
            break;
        case TargetKind::Index:
            emit(V6Op::SetIndex, {target.object, target.key, value});
            break;
        case TargetKind::IndexName:
            emit(V6Op::SetIndexK, {target.object, target.id, value});
            break;
        }
    }

    void compileBlockBody(Luau::AstStatBlock* block)
    {
        for (size_t index = 0; index < block->body.size; ++index)
            compileStatement(block->body.data[index]);
    }

    void compileScopedBlock(Luau::AstStatBlock* block)
    {
        emit(V6Op::EnterScope);
        ++current().scopeDepth;
        compileBlockBody(block);
        emit(V6Op::LeaveScopes, {1});
        --current().scopeDepth;
    }

    void emitEmptyReturn()
    {
        uint32_t values = allocRegister();
        emit(V6Op::PackNew, {values});
        emit(V6Op::Return, {values});
    }

    void patchLoop(LoopContext& loop, size_t breakTarget, size_t continueTarget)
    {
        for (size_t jump : loop.breaks)
            patch(jump, 0, breakTarget);
        for (size_t jump : loop.continues)
            patch(jump, 0, continueTarget);
    }

    void compileStatement(Luau::AstStat* statement)
    {
        if (auto local = statement->as<Luau::AstStatLocal>())
        {
            uint32_t values = compileExpressionList(local->values);
            for (size_t index = 0; index < local->vars.size; ++index)
            {
                uint32_t value = allocRegister();
                emit(V6Op::PackGet, {value, values, static_cast<uint32_t>(index + 1)});
                emit(V6Op::DeclareLocal, {localId(local->vars.data[index]), value});
            }
            return;
        }
        if (auto localFunction = statement->as<Luau::AstStatLocalFunction>())
        {
            uint32_t id = localId(localFunction->name);
            uint32_t nil = emitNil();
            emit(V6Op::DeclareLocal, {id, nil});
            uint32_t closure = compileFunction(localFunction->func);
            emit(V6Op::SetLocal, {id, closure});
            return;
        }
        if (auto returns = statement->as<Luau::AstStatReturn>())
        {
            uint32_t values = compileExpressionList(returns->list);
            emit(V6Op::Return, {values});
            return;
        }
        if (auto expression = statement->as<Luau::AstStatExpr>())
        {
            Luau::AstExpr* peeled = peelTypeWrappers(expression->expr);
            if (auto call = peeled->as<Luau::AstExprCall>())
                compileCall(call);
            else
                compileExpression(expression->expr);
            return;
        }
        if (auto assignment = statement->as<Luau::AstStatAssign>())
        {
            std::vector<PreparedTarget> targets;
            targets.reserve(assignment->vars.size);
            for (size_t index = 0; index < assignment->vars.size; ++index)
                targets.push_back(prepareTarget(assignment->vars.data[index]));
            uint32_t values = compileExpressionList(assignment->values);
            for (size_t index = 0; index < targets.size(); ++index)
            {
                uint32_t value = allocRegister();
                emit(V6Op::PackGet, {value, values, static_cast<uint32_t>(index + 1)});
                writeTarget(targets[index], value);
            }
            return;
        }
        if (auto compound = statement->as<Luau::AstStatCompoundAssign>())
        {
            PreparedTarget target = prepareTarget(compound->var);
            uint32_t left = readTarget(target);
            uint32_t right = compileExpression(compound->value);
            uint32_t value = allocRegister();
            emit(V6Op::Binary, {value, static_cast<uint32_t>(binaryOperator(compound->op, compound->location)), left, right});
            writeTarget(target, value);
            return;
        }
        if (auto function = statement->as<Luau::AstStatFunction>())
        {
            PreparedTarget target = prepareTarget(function->name);
            uint32_t closure = compileFunction(function->func);
            writeTarget(target, closure);
            return;
        }
        if (auto conditional = statement->as<Luau::AstStatIf>())
        {
            uint32_t condition = compileExpression(conditional->condition);
            size_t otherwise = emit(V6Op::JumpFalse, {condition, 0});
            compileScopedBlock(conditional->thenbody);
            size_t done = emit(V6Op::Jump, {0});
            patch(otherwise, 1, prototype().code.size());
            if (conditional->elsebody)
            {
                if (auto block = conditional->elsebody->as<Luau::AstStatBlock>())
                    compileScopedBlock(block);
                else if (auto elseIf = conditional->elsebody->as<Luau::AstStatIf>())
                    compileStatement(elseIf);
                else
                    unsupported(conditional->elsebody->location, "AstStatIf", "this else body");
            }
            patch(done, 0, prototype().code.size());
            return;
        }
        if (auto block = statement->as<Luau::AstStatBlock>())
        {
            compileScopedBlock(block);
            return;
        }
        if (auto loop = statement->as<Luau::AstStatWhile>())
        {
            size_t start = prototype().code.size();
            uint32_t condition = compileExpression(loop->condition);
            size_t done = emit(V6Op::JumpFalse, {condition, 0});
            current().loops.push_back({current().scopeDepth, current().scopeDepth, {}, {}});
            compileScopedBlock(loop->body);
            size_t continueTarget = prototype().code.size();
            emit(V6Op::Jump, {static_cast<uint32_t>(start)});
            size_t end = prototype().code.size();
            patch(done, 1, end);
            LoopContext context = std::move(current().loops.back());
            current().loops.pop_back();
            patchLoop(context, end, continueTarget);
            return;
        }
        if (auto loop = statement->as<Luau::AstStatRepeat>())
        {
            size_t start = prototype().code.size();
            emit(V6Op::EnterScope);
            ++current().scopeDepth;
            int iterationDepth = current().scopeDepth;
            current().loops.push_back({iterationDepth - 1, iterationDepth, {}, {}});
            compileBlockBody(loop->body);
            size_t continueTarget = prototype().code.size();
            uint32_t condition = compileExpression(loop->condition);
            emit(V6Op::LeaveScopes, {1});
            --current().scopeDepth;
            emit(V6Op::JumpFalse, {condition, static_cast<uint32_t>(start)});
            size_t end = prototype().code.size();
            LoopContext context = std::move(current().loops.back());
            current().loops.pop_back();
            patchLoop(context, end, continueTarget);
            return;
        }
        if (auto loop = statement->as<Luau::AstStatFor>())
        {
            uint32_t from = compileExpression(loop->from);
            uint32_t limit = compileExpression(loop->to);
            uint32_t step = loop->step ? compileExpression(loop->step) : emitConstant(json::array({2, 1}));
            uint32_t currentValue = allocRegister();
            emit(V6Op::Move, {currentValue, from});
            size_t start = prototype().code.size();
            uint32_t condition = allocRegister();
            emit(V6Op::ForCheck, {condition, currentValue, limit, step});
            size_t done = emit(V6Op::JumpFalse, {condition, 0});

            int baseDepth = current().scopeDepth;
            current().loops.push_back({baseDepth, baseDepth, {}, {}});
            emit(V6Op::EnterScope);
            ++current().scopeDepth;
            emit(V6Op::DeclareLocal, {localId(loop->var), currentValue});
            compileBlockBody(loop->body);
            emit(V6Op::LeaveScopes, {1});
            --current().scopeDepth;
            size_t continueTarget = prototype().code.size();
            uint32_t next = allocRegister();
            emit(V6Op::Binary, {next, static_cast<uint32_t>(V6Binary::Add), currentValue, step});
            emit(V6Op::Move, {currentValue, next});
            emit(V6Op::Jump, {static_cast<uint32_t>(start)});
            size_t end = prototype().code.size();
            patch(done, 1, end);
            LoopContext context = std::move(current().loops.back());
            current().loops.pop_back();
            patchLoop(context, end, continueTarget);
            return;
        }
        if (auto loop = statement->as<Luau::AstStatForIn>())
        {
            uint32_t source = compileExpressionList(loop->values);
            uint32_t iteratorState = allocRegister();
            emit(V6Op::IteratorInit, {iteratorState, source});
            uint32_t iterator = allocRegister();
            uint32_t state = allocRegister();
            uint32_t control = allocRegister();
            emit(V6Op::PackGet, {iterator, iteratorState, 1});
            emit(V6Op::PackGet, {state, iteratorState, 2});
            emit(V6Op::PackGet, {control, iteratorState, 3});

            size_t start = prototype().code.size();
            uint32_t arguments = allocRegister();
            emit(V6Op::PackNew, {arguments});
            emit(V6Op::PackPush, {arguments, state});
            emit(V6Op::PackPush, {arguments, control});
            uint32_t values = allocRegister();
            emit(V6Op::Call, {values, iterator, arguments});
            uint32_t first = allocRegister();
            emit(V6Op::PackGet, {first, values, 1});
            size_t done = emit(V6Op::JumpNil, {first, 0});
            emit(V6Op::Move, {control, first});

            int baseDepth = current().scopeDepth;
            current().loops.push_back({baseDepth, baseDepth, {}, {}});
            emit(V6Op::EnterScope);
            ++current().scopeDepth;
            for (size_t index = 0; index < loop->vars.size; ++index)
            {
                uint32_t value = allocRegister();
                emit(V6Op::PackGet, {value, values, static_cast<uint32_t>(index + 1)});
                emit(V6Op::DeclareLocal, {localId(loop->vars.data[index]), value});
            }
            compileBlockBody(loop->body);
            emit(V6Op::LeaveScopes, {1});
            --current().scopeDepth;
            size_t continueTarget = prototype().code.size();
            emit(V6Op::Jump, {static_cast<uint32_t>(start)});
            size_t end = prototype().code.size();
            patch(done, 1, end);
            LoopContext context = std::move(current().loops.back());
            current().loops.pop_back();
            patchLoop(context, end, continueTarget);
            return;
        }
        if (statement->as<Luau::AstStatBreak>() || statement->as<Luau::AstStatContinue>())
        {
            if (current().loops.empty())
                throw V6CompileFailure("invalid_control_flow", "semantic_ir", "AstStatLoopControl", statement->location, "loop control statement is outside a loop");
            LoopContext& loop = current().loops.back();
            bool isBreak = statement->as<Luau::AstStatBreak>() != nullptr;
            int targetDepth = isBreak ? loop.breakDepth : loop.continueDepth;
            int leaveCount = current().scopeDepth - targetDepth;
            if (leaveCount > 0)
                emit(V6Op::LeaveScopes, {static_cast<uint32_t>(leaveCount)});
            size_t jump = emit(V6Op::Jump, {0});
            (isBreak ? loop.breaks : loop.continues).push_back(jump);
            return;
        }
        if (statement->as<Luau::AstStatTypeAlias>() || statement->as<Luau::AstStatTypeFunction>() || statement->as<Luau::AstStatDeclareGlobal>() ||
            statement->as<Luau::AstStatDeclareFunction>() || statement->as<Luau::AstStatDeclareExternType>())
        {
            emit(V6Op::Nop);
            return;
        }
        unsupported(statement->location, "AstStat", "this statement form");
    }

    void addDecoyPrototypes()
    {
        int rank = protectionRank(config.vmDiversity);
        size_t count = rank >= 3 ? static_cast<size_t>(std::max(3, config.stage2Decoys)) : rank >= 2 ? 2u : 0u;
        if (!config.bytecodeTrampoline || !config.stage2FakeProto)
            count = 0;
        for (size_t index = 0; index < count; ++index)
        {
            V6Prototype decoy;
            decoy.decoy = true;
            decoy.constants.push_back(json::array({2, static_cast<uint32_t>((rng() % 900000u) + 1000u)}));
            decoy.code.push_back({V6Op::Nop, {}});
            decoy.code.push_back({V6Op::PackNew, {1}});
            decoy.code.push_back({V6Op::Return, {1}});
            decoy.virtualRegisterCount = 1;
            program.prototypes.push_back(std::move(decoy));
        }
        program.decoyPrototypeCount = count;
    }

    void injectOpaqueGuards(V6Prototype& proto)
    {
        int rank = protectionRank(config.controlFlow);
        size_t frequency = rank >= 3 ? 4u : rank >= 2 ? 8u : 0u;
        if (frequency == 0 || proto.decoy || proto.code.size() < 4)
            return;

        std::vector<V6Instruction> original = std::move(proto.code);
        std::vector<V6Instruction> rewritten;
        std::vector<size_t> targetMap(original.size() + 1, 0);
        rewritten.reserve(original.size() + original.size() / frequency + 1);
        for (size_t index = 0; index < original.size(); ++index)
        {
            targetMap[index] = rewritten.size();
            if (index != 0 && index % frequency == 0)
            {
                uint32_t value = static_cast<uint32_t>((rng() % 90000u) + 1000u);
                uint32_t multiplier = static_cast<uint32_t>((rng() % 83u) + 11u);
                uint32_t add = static_cast<uint32_t>((rng() % 997u) + 17u);
                uint32_t modulus = static_cast<uint32_t>((rng() % 109u) + 43u);
                uint32_t expected = static_cast<uint32_t>((static_cast<uint64_t>(value) * multiplier + add) % modulus);
                rewritten.push_back({V6Op::OpaqueGuard, {value, multiplier, add, modulus, expected}});
                ++proto.opaqueGuardCount;
            }
            rewritten.push_back(std::move(original[index]));
        }
        targetMap[original.size()] = rewritten.size();
        for (V6Instruction& instruction : rewritten)
        {
            for (size_t position : v6TargetArgs(instruction.op))
                instruction.args[position] = static_cast<uint32_t>(targetMap.at(instruction.args[position]));
        }
        proto.code = std::move(rewritten);
    }

    void substituteInstructions(V6Prototype& proto)
    {
        int rank = protectionRank(config.vmDiversity);
        if (rank < 2 || proto.decoy)
            return;
        uint64_t divisor = rank >= 3 ? 2u : 4u;
        for (V6Instruction& instruction : proto.code)
        {
            if (rng() % divisor != 0)
                continue;
            V6Op replacement = instruction.op;
            if (instruction.op == V6Op::LoadConstant)
                replacement = V6Op::LoadConstantAlt;
            else if (instruction.op == V6Op::GetLocal)
                replacement = V6Op::GetLocalAlt;
            else if (instruction.op == V6Op::Binary)
                replacement = V6Op::BinaryAlt;
            else if (instruction.op == V6Op::JumpFalse)
                replacement = V6Op::JumpFalseAlt;
            if (replacement != instruction.op)
            {
                instruction.op = replacement;
                ++proto.substitutionCount;
            }
        }
    }

    void shuffleConstants(V6Prototype& proto)
    {
        size_t count = proto.constants.size();
        proto.logicalToPhysicalConstant.resize(count);
        std::vector<size_t> order(count);
        std::iota(order.begin(), order.end(), 0u);
        if (protectionRank(config.constantProtection) > 0 && count > 1)
            std::shuffle(order.begin(), order.end(), rng);

        json physical = json::array();
        for (size_t physicalIndex = 0; physicalIndex < order.size(); ++physicalIndex)
        {
            size_t logical = order[physicalIndex];
            proto.logicalToPhysicalConstant[logical] = static_cast<uint32_t>(physicalIndex + 1);
            physical.push_back(std::move(proto.constants[logical]));
        }
        proto.constants = std::move(physical);
        for (V6Instruction& instruction : proto.code)
        {
            if (v6IsLoadConstant(instruction.op))
            {
                uint32_t logical = instruction.args.at(1);
                instruction.args[1] = proto.logicalToPhysicalConstant.at(logical - 1);
            }
        }
    }

    void allocateRegisters(V6Prototype& proto)
    {
        const uint32_t count = proto.virtualRegisterCount;
        if (count == 0)
            return;
        proto.blocks = buildV6Blocks(proto.code);

        using RegisterSet = std::unordered_set<uint32_t>;
        std::vector<RegisterSet> use(proto.blocks.size());
        std::vector<RegisterSet> def(proto.blocks.size());
        for (const V6BasicBlock& block : proto.blocks)
        {
            for (size_t index = block.start; index < block.end; ++index)
            {
                const V6Instruction& instruction = proto.code[index];
                for (size_t position : v6RegisterUses(instruction.op))
                {
                    uint32_t reg = instruction.args.at(position);
                    if (!def[block.id].count(reg))
                        use[block.id].insert(reg);
                }
                for (size_t position : v6RegisterDefs(instruction.op))
                    def[block.id].insert(instruction.args.at(position));
            }
        }

        std::vector<RegisterSet> liveIn(proto.blocks.size());
        std::vector<RegisterSet> liveOut(proto.blocks.size());
        bool changed = true;
        while (changed)
        {
            changed = false;
            for (size_t reverse = proto.blocks.size(); reverse-- > 0;)
            {
                const V6BasicBlock& block = proto.blocks[reverse];
                RegisterSet nextOut;
                for (size_t successor : block.successors)
                    nextOut.insert(liveIn[successor].begin(), liveIn[successor].end());
                RegisterSet nextIn = use[block.id];
                for (uint32_t reg : nextOut)
                {
                    if (!def[block.id].count(reg))
                        nextIn.insert(reg);
                }
                if (nextOut != liveOut[block.id] || nextIn != liveIn[block.id])
                {
                    liveOut[block.id] = std::move(nextOut);
                    liveIn[block.id] = std::move(nextIn);
                    changed = true;
                }
            }
        }

        std::vector<RegisterSet> interference(static_cast<size_t>(count + 1));
        for (const V6BasicBlock& block : proto.blocks)
        {
            RegisterSet live = liveOut[block.id];
            for (size_t reverse = block.end; reverse-- > block.start;)
            {
                const V6Instruction& instruction = proto.code[reverse];
                for (size_t position : v6RegisterDefs(instruction.op))
                {
                    uint32_t defined = instruction.args.at(position);
                    for (uint32_t other : live)
                    {
                        if (defined == other)
                            continue;
                        interference[defined].insert(other);
                        interference[other].insert(defined);
                    }
                    live.erase(defined);
                }
                for (size_t position : v6RegisterUses(instruction.op))
                    live.insert(instruction.args.at(position));
            }
        }

        std::vector<uint32_t> order(count);
        std::iota(order.begin(), order.end(), 1u);
        std::vector<uint64_t> tie(count + 1);
        for (uint32_t reg = 1; reg <= count; ++reg)
            tie[reg] = rng();
        std::sort(order.begin(), order.end(), [&](uint32_t left, uint32_t right) {
            if (interference[left].size() != interference[right].size())
                return interference[left].size() > interference[right].size();
            return tie[left] < tie[right];
        });

        std::vector<uint32_t> color(count + 1, 0);
        uint32_t colorCount = 0;
        for (uint32_t reg : order)
        {
            std::vector<bool> unavailable(static_cast<size_t>(colorCount + 2), false);
            for (uint32_t neighbor : interference[reg])
            {
                if (color[neighbor] < unavailable.size())
                    unavailable[color[neighbor]] = true;
            }
            std::vector<uint32_t> available;
            for (uint32_t candidate = 1; candidate <= colorCount; ++candidate)
            {
                if (!unavailable[candidate])
                    available.push_back(candidate);
            }
            if (available.empty())
                color[reg] = ++colorCount;
            else
                color[reg] = available[static_cast<size_t>(rng() % available.size())];
        }

        std::vector<uint32_t> permutation(colorCount);
        std::iota(permutation.begin(), permutation.end(), 1u);
        if (protectionRank(config.vmDiversity) > 0)
            std::shuffle(permutation.begin(), permutation.end(), rng);
        for (uint32_t reg = 1; reg <= count; ++reg)
            color[reg] = permutation[color[reg] - 1];

        for (V6Instruction& instruction : proto.code)
        {
            std::unordered_set<size_t> positions;
            for (size_t position : v6RegisterDefs(instruction.op))
                positions.insert(position);
            for (size_t position : v6RegisterUses(instruction.op))
                positions.insert(position);
            for (size_t position : positions)
                instruction.args[position] = color.at(instruction.args.at(position));
        }
        proto.maxRegister = colorCount;
        program.registerReuse = program.registerReuse || colorCount < count;
        proto.blocks = buildV6Blocks(proto.code);
    }

    void assignCodecs(V6Prototype& proto)
    {
        std::vector<uint32_t> opcodePool;
        for (uint32_t value = 17; value < 241; ++value)
            opcodePool.push_back(value);
        std::shuffle(opcodePool.begin(), opcodePool.end(), rng);
        proto.opcodes.assign(opcodePool.begin(), opcodePool.begin() + static_cast<std::ptrdiff_t>(v6OpIndex(V6Op::Count)));

        std::vector<uint32_t> tagPool;
        for (uint32_t value = 257; value < 997; ++value)
            tagPool.push_back(value);
        std::shuffle(tagPool.begin(), tagPool.end(), rng);
        size_t cursor = 0;
        proto.binaryCodes.resize(static_cast<size_t>(V6Binary::Count));
        for (uint32_t& value : proto.binaryCodes)
            value = tagPool[cursor++];
        proto.unaryCodes.resize(static_cast<size_t>(V6Unary::Count));
        for (uint32_t& value : proto.unaryCodes)
            value = tagPool[cursor++];

        proto.argMultiplier = static_cast<uint32_t>(((rng() % 89u) + 3u) | 1u);
        proto.argSalt = static_cast<uint32_t>((rng() % 90000u) + 1000u);
        proto.argStep = static_cast<uint32_t>((rng() % 251u) + 17u);
    }

    void shuffleStrings()
    {
        size_t count = program.strings.size();
        if (count < 2 || protectionRank(config.vmDiversity) == 0)
            return;
        std::vector<size_t> order(count);
        std::iota(order.begin(), order.end(), 0u);
        std::shuffle(order.begin(), order.end(), rng);
        std::vector<uint32_t> map(count + 1, 0);
        std::vector<std::string> physical(count);
        for (size_t physicalIndex = 0; physicalIndex < count; ++physicalIndex)
        {
            size_t logical = order[physicalIndex];
            physical[physicalIndex] = std::move(program.strings[logical]);
            map[logical + 1] = static_cast<uint32_t>(physicalIndex + 1);
        }
        program.strings = std::move(physical);
        for (V6Prototype& proto : program.prototypes)
        {
            if (proto.name != 0)
                proto.name = map.at(proto.name);
            for (V6Instruction& instruction : proto.code)
            {
                for (size_t position : v6StringArgs(instruction.op))
                    instruction.args[position] = map.at(instruction.args[position]);
            }
            for (json& constant : proto.constants)
            {
                if (constant.is_array() && constant.size() >= 2 && constant[0].get<int>() == 3)
                    constant[1] = map.at(constant[1].get<uint32_t>());
            }
        }
    }

    void finalizeProgram()
    {
        for (V6Prototype& proto : program.prototypes)
        {
            injectOpaqueGuards(proto);
            substituteInstructions(proto);
            shuffleConstants(proto);
        }
        shuffleStrings();

        for (V6Prototype& proto : program.prototypes)
        {
            allocateRegisters(proto);
            assignCodecs(proto);
            program.instructionCount += proto.decoy ? 0 : proto.code.size();
            program.blockCount += proto.decoy ? 0 : proto.blocks.size();
            program.opaqueGuardCount += proto.opaqueGuardCount;
            program.substitutionCount += proto.substitutionCount;
            program.superoperatorCount += proto.superoperatorCount;
        }
        program.localCount = nextLocal - 1;
    }
};

struct AlexCompileFailure : std::runtime_error
{
    alex::lang::Diagnostic diagnostic;

    explicit AlexCompileFailure(alex::lang::Diagnostic diagnostic)
        : std::runtime_error(diagnostic.message)
        , diagnostic(std::move(diagnostic))
    {
    }
};

class AlexSemanticCompiler final : public V6SemanticCompiler
{
public:
    AlexSemanticCompiler(std::mt19937_64& rng, const Config& config)
        : V6SemanticCompiler(rng, config)
    {
    }

    V6Program compile(const alex::lang::Program& source, V6Program* semanticSnapshot = nullptr)
    {
        program.prototypes.emplace_back();
        program.prototypes[0].vararg = true;
        contexts.push_back({0, 1, 0, {}});
        lexicalScopes.emplace_back();
        compileBlockBody(source.root);
        emitEmptyReturn();
        program.prototypes[0].virtualRegisterCount = current().nextRegister - 1;
        lexicalScopes.pop_back();
        contexts.pop_back();

        program.localCount = nextLocal - 1;
        runV6SemanticPasses(program);
        validateV6Program(program, "ir_validate", true);
        if (semanticSnapshot)
            *semanticSnapshot = program;
        addDecoyPrototypes();
        finalizeProgram();
        validateV6Program(program, "vm_lower", false);
        return std::move(program);
    }

private:
    struct Binding
    {
        uint32_t id = 0;
        uint32_t owner = 0;
    };

    std::vector<std::unordered_map<std::string, Binding>> lexicalScopes;

    [[noreturn]] void fail(std::string stage, std::string code, std::string kind, const alex::lang::Span& span, std::string message) const
    {
        throw AlexCompileFailure({std::move(stage), std::move(code), std::move(kind), std::move(message), span});
    }

    Binding declare(const std::string& name, const alex::lang::Span& span)
    {
        auto& scope = lexicalScopes.back();
        if (scope.count(name))
            fail("bind", "duplicate_local", "Local", span, "a local with this name is already declared in the current scope");
        uint32_t id = nextLocal++ * localMultiplier + localSalt;
        Binding binding{id, currentPrototypeId()};
        scope.emplace(name, binding);
        return binding;
    }

    std::optional<Binding> resolve(const std::string& name) const
    {
        for (auto scope = lexicalScopes.rbegin(); scope != lexicalScopes.rend(); ++scope)
        {
            auto found = scope->find(name);
            if (found != scope->end())
                return found->second;
        }
        return std::nullopt;
    }

    void noteCapture(const Binding& binding)
    {
        if (binding.owner == currentPrototypeId())
            return;
        if (prototype().captureSet.insert(binding.id).second)
            prototype().captures.push_back(binding.id);
    }

    V6Binary binaryOperator(std::string_view operation, const alex::lang::Span& span) const
    {
        if (operation == "+")
            return V6Binary::Add;
        if (operation == "-")
            return V6Binary::Sub;
        if (operation == "*")
            return V6Binary::Mul;
        if (operation == "/")
            return V6Binary::Div;
        if (operation == "//")
            return V6Binary::FloorDiv;
        if (operation == "%")
            return V6Binary::Mod;
        if (operation == "^")
            return V6Binary::Pow;
        if (operation == "..")
            return V6Binary::Concat;
        if (operation == "~=")
            return V6Binary::Ne;
        if (operation == "==")
            return V6Binary::Eq;
        if (operation == "<")
            return V6Binary::Lt;
        if (operation == "<=")
            return V6Binary::Le;
        if (operation == ">")
            return V6Binary::Gt;
        if (operation == ">=")
            return V6Binary::Ge;
        fail("ir_validate", "unknown_binary_operator", "Binary", span, "unknown Alex binary operator");
    }

    V6Unary unaryOperator(std::string_view operation, const alex::lang::Span& span) const
    {
        if (operation == "not")
            return V6Unary::Not;
        if (operation == "-")
            return V6Unary::Minus;
        if (operation == "#")
            return V6Unary::Length;
        fail("ir_validate", "unknown_unary_operator", "Unary", span, "unknown Alex unary operator");
    }

    uint32_t compileExpressionPack(const alex::lang::ExprPtr& expression)
    {
        if (expression->kind == alex::lang::Expr::Kind::Call || expression->kind == alex::lang::Expr::Kind::MethodCall)
            return compileCall(expression);
        if (expression->kind == alex::lang::Expr::Kind::Varargs)
        {
            uint32_t destination = allocRegister();
            emit(V6Op::Varargs, {destination});
            return destination;
        }
        uint32_t pack = allocRegister();
        emit(V6Op::PackNew, {pack});
        emit(V6Op::PackPush, {pack, compileExpression(expression)});
        return pack;
    }

    uint32_t compileExpressionList(const std::vector<alex::lang::ExprPtr>& expressions, std::optional<uint32_t> prefix = std::nullopt)
    {
        uint32_t pack = allocRegister();
        emit(V6Op::PackNew, {pack});
        if (prefix)
            emit(V6Op::PackPush, {pack, *prefix});
        for (size_t index = 0; index < expressions.size(); ++index)
        {
            if (index + 1 == expressions.size())
                emit(V6Op::PackExtend, {pack, compileExpressionPack(expressions[index])});
            else
                emit(V6Op::PackPush, {pack, compileExpression(expressions[index])});
        }
        return pack;
    }

    uint32_t compileCall(const alex::lang::ExprPtr& call)
    {
        bool method = call->kind == alex::lang::Expr::Kind::MethodCall;
        const alex::lang::ExprPtr& function = call->values.front();
        size_t firstArgument = 1;

        if (!method && call->values.size() == 1 && function->kind == alex::lang::Expr::Kind::Name && !resolve(function->text))
        {
            uint32_t destination = allocRegister();
            emit(V6Op::CallGlobal0, {destination, stringId(function->text)});
            return destination;
        }
        if (method && call->values.size() == 1)
        {
            uint32_t self = compileExpression(function);
            uint32_t destination = allocRegister();
            emit(V6Op::CallMethod0, {destination, self, stringId(call->text)});
            return destination;
        }

        uint32_t functionRegister = 0;
        uint32_t arguments = 0;
        std::vector<alex::lang::ExprPtr> argumentExpressions(call->values.begin() + static_cast<std::ptrdiff_t>(firstArgument), call->values.end());
        if (method)
        {
            uint32_t self = compileExpression(function);
            functionRegister = allocRegister();
            emit(V6Op::GetIndexK, {functionRegister, self, stringId(call->text)});
            arguments = compileExpressionList(argumentExpressions, self);
        }
        else
        {
            functionRegister = compileExpression(function);
            arguments = compileExpressionList(argumentExpressions);
        }

        uint32_t destination = allocRegister();
        emit(V6Op::Call, {destination, functionRegister, arguments});
        return destination;
    }

    uint32_t compileFunction(const alex::lang::ExprPtr& function)
    {
        size_t parent = current().prototype;
        size_t child = program.prototypes.size();
        program.prototypes.emplace_back();
        program.prototypes[parent].children.push_back(static_cast<uint32_t>(child + 1));
        if (!function->text.empty())
            program.prototypes[child].name = stringId(function->text);
        program.prototypes[child].vararg = function->variadic;

        contexts.push_back({child, 1, 0, {}});
        lexicalScopes.emplace_back();
        for (const std::string& parameter : function->names)
            prototype().params.push_back(declare(parameter, function->span).id);
        compileBlockBody(function->body);
        emitEmptyReturn();
        prototype().virtualRegisterCount = current().nextRegister - 1;
        lexicalScopes.pop_back();
        contexts.pop_back();

        uint32_t destination = allocRegister();
        emit(V6Op::MakeClosure, {destination, static_cast<uint32_t>(child + 1)});
        return destination;
    }

    uint32_t compileValueBlock(const alex::lang::BlockPtr& block)
    {
        if (!block || block->statements.empty())
            fail("ir_validate", "empty_value_block", "IfElse", block ? block->span : alex::lang::Span{}, "an if-expression branch must produce a value");
        emit(V6Op::EnterScope);
        ++current().scopeDepth;
        lexicalScopes.emplace_back();
        for (size_t index = 0; index + 1 < block->statements.size(); ++index)
            compileStatement(block->statements[index]);
        const alex::lang::StatementPtr& tail = block->statements.back();
        if (tail->kind != alex::lang::Statement::Kind::Expression)
            fail("ir_validate", "missing_branch_value", "IfElse", tail->span, "an if-expression branch must end with an expression");
        uint32_t value = compileExpression(tail->values.front());
        lexicalScopes.pop_back();
        emit(V6Op::LeaveScopes, {1});
        --current().scopeDepth;
        return value;
    }

    uint32_t compileExpression(const alex::lang::ExprPtr& expression)
    {
        using Kind = alex::lang::Expr::Kind;
        switch (expression->kind)
        {
        case Kind::Nil:
            return emitNil();
        case Kind::Boolean:
            return emitConstant(json::array({1, expression->boolean ? 1 : 0}));
        case Kind::Number:
            return emitConstant(json::array({2, expression->number}));
        case Kind::String:
            return emitConstant(json::array({3, stringId(expression->text)}));
        case Kind::Name:
        {
            uint32_t destination = allocRegister();
            if (std::optional<Binding> binding = resolve(expression->text))
            {
                noteCapture(*binding);
                emit(V6Op::GetLocal, {destination, binding->id});
            }
            else
                emit(V6Op::GetGlobal, {destination, stringId(expression->text)});
            return destination;
        }
        case Kind::Varargs:
        {
            uint32_t values = compileExpressionPack(expression);
            uint32_t destination = allocRegister();
            emit(V6Op::PackGet, {destination, values, 1});
            return destination;
        }
        case Kind::Group:
            return compileExpression(expression->values.front());
        case Kind::IndexName:
        {
            uint32_t object = compileExpression(expression->values.front());
            uint32_t destination = allocRegister();
            emit(V6Op::GetIndexK, {destination, object, stringId(expression->text)});
            return destination;
        }
        case Kind::Index:
        {
            uint32_t object = compileExpression(expression->values[0]);
            uint32_t key = compileExpression(expression->values[1]);
            uint32_t destination = allocRegister();
            emit(V6Op::GetIndex, {destination, object, key});
            return destination;
        }
        case Kind::Binary:
        {
            if (expression->text == "and" || expression->text == "or")
            {
                uint32_t destination = allocRegister();
                uint32_t left = compileExpression(expression->values[0]);
                emit(V6Op::Move, {destination, left});
                size_t done = emit(expression->text == "and" ? V6Op::JumpFalse : V6Op::JumpTrue, {left, 0});
                emit(V6Op::Move, {destination, compileExpression(expression->values[1])});
                patch(done, 1, prototype().code.size());
                return destination;
            }
            uint32_t left = compileExpression(expression->values[0]);
            uint32_t right = compileExpression(expression->values[1]);
            uint32_t destination = allocRegister();
            emit(V6Op::Binary, {destination, static_cast<uint32_t>(binaryOperator(expression->text, expression->span)), left, right});
            return destination;
        }
        case Kind::Unary:
        {
            uint32_t source = compileExpression(expression->values.front());
            uint32_t destination = allocRegister();
            emit(V6Op::Unary, {destination, static_cast<uint32_t>(unaryOperator(expression->text, expression->span)), source});
            return destination;
        }
        case Kind::Call:
        case Kind::MethodCall:
        {
            uint32_t values = compileCall(expression);
            uint32_t destination = allocRegister();
            emit(V6Op::PackGet, {destination, values, 1});
            return destination;
        }
        case Kind::Function:
            return compileFunction(expression);
        case Kind::IfElse:
        {
            uint32_t destination = allocRegister();
            uint32_t condition = compileExpression(expression->values.front());
            size_t otherwise = emit(V6Op::JumpFalse, {condition, 0});
            emit(V6Op::Move, {destination, compileValueBlock(expression->body)});
            size_t done = emit(V6Op::Jump, {0});
            patch(otherwise, 1, prototype().code.size());
            emit(V6Op::Move, {destination, compileValueBlock(expression->elseBody)});
            patch(done, 0, prototype().code.size());
            return destination;
        }
        case Kind::Interpolation:
        {
            uint32_t destination = emitConstant(json::array({3, stringId("")}));
            for (const alex::lang::ExprPtr& part : expression->values)
            {
                uint32_t value = compileExpression(part);
                uint32_t text = value;
                if (part->kind != Kind::String)
                {
                    text = allocRegister();
                    emit(V6Op::ToString, {text, value});
                }
                uint32_t joined = allocRegister();
                emit(V6Op::Binary, {joined, static_cast<uint32_t>(V6Binary::Concat), destination, text});
                destination = joined;
            }
            return destination;
        }
        case Kind::Table:
        {
            uint32_t destination = allocRegister();
            emit(V6Op::NewTable, {destination});
            uint32_t listIndex = 1;
            for (size_t index = 0; index < expression->tableItems.size(); ++index)
            {
                const alex::lang::TableItem& item = expression->tableItems[index];
                if (item.kind == alex::lang::TableItem::Kind::List)
                {
                    if (index + 1 == expression->tableItems.size())
                        emit(V6Op::AppendPack, {destination, compileExpressionPack(item.value), listIndex});
                    else
                        emit(V6Op::SetList, {destination, listIndex++, compileExpression(item.value)});
                }
                else if (item.kind == alex::lang::TableItem::Kind::Record)
                    emit(V6Op::SetIndexK, {destination, stringId(item.name), compileExpression(item.value)});
                else
                    emit(V6Op::SetIndex, {destination, compileExpression(item.key), compileExpression(item.value)});
            }
            return destination;
        }
        }
        fail("ir_validate", "unsupported_expression", alex::lang::expressionKindName(expression->kind), expression->span, "unsupported Alex expression");
    }

    PreparedTarget prepareTarget(const alex::lang::ExprPtr& target)
    {
        if (target->kind == alex::lang::Expr::Kind::Name)
        {
            if (std::optional<Binding> binding = resolve(target->text))
            {
                noteCapture(*binding);
                return {TargetKind::Local, binding->id, 0, 0};
            }
            return {TargetKind::Global, stringId(target->text), 0, 0};
        }
        if (target->kind == alex::lang::Expr::Kind::IndexName)
            return {TargetKind::IndexName, stringId(target->text), compileExpression(target->values.front()), 0};
        if (target->kind == alex::lang::Expr::Kind::Index)
            return {TargetKind::Index, 0, compileExpression(target->values[0]), compileExpression(target->values[1])};
        fail("ir_validate", "invalid_assignment_target", alex::lang::expressionKindName(target->kind), target->span, "this expression cannot be assigned to");
    }

    void compileBlockBody(const alex::lang::BlockPtr& block)
    {
        for (const alex::lang::StatementPtr& statement : block->statements)
            compileStatement(statement);
    }

    void compileScopedBlock(const alex::lang::BlockPtr& block)
    {
        emit(V6Op::EnterScope);
        ++current().scopeDepth;
        lexicalScopes.emplace_back();
        compileBlockBody(block);
        lexicalScopes.pop_back();
        emit(V6Op::LeaveScopes, {1});
        --current().scopeDepth;
    }

    void compileStatement(const alex::lang::StatementPtr& statement)
    {
        using Kind = alex::lang::Statement::Kind;
        switch (statement->kind)
        {
        case Kind::Let:
        {
            uint32_t values = compileExpressionList(statement->values);
            for (size_t index = 0; index < statement->names.size(); ++index)
            {
                uint32_t value = allocRegister();
                emit(V6Op::PackGet, {value, values, static_cast<uint32_t>(index + 1)});
                emit(V6Op::DeclareLocal, {declare(statement->names[index], statement->span).id, value});
            }
            return;
        }
        case Kind::Function:
        {
            Binding binding = declare(statement->names.front(), statement->span);
            emit(V6Op::DeclareLocal, {binding.id, emitNil()});
            emit(V6Op::SetLocal, {binding.id, compileFunction(statement->values.front())});
            return;
        }
        case Kind::Return:
            emit(V6Op::Return, {compileExpressionList(statement->values)});
            return;
        case Kind::Expression:
            if (statement->values.front()->kind == alex::lang::Expr::Kind::Call || statement->values.front()->kind == alex::lang::Expr::Kind::MethodCall)
                compileCall(statement->values.front());
            else
                compileExpression(statement->values.front());
            return;
        case Kind::Assign:
        {
            std::vector<PreparedTarget> targets;
            for (const alex::lang::ExprPtr& target : statement->targets)
                targets.push_back(prepareTarget(target));
            uint32_t values = compileExpressionList(statement->values);
            for (size_t index = 0; index < targets.size(); ++index)
            {
                uint32_t value = allocRegister();
                emit(V6Op::PackGet, {value, values, static_cast<uint32_t>(index + 1)});
                writeTarget(targets[index], value);
            }
            return;
        }
        case Kind::CompoundAssign:
        {
            PreparedTarget target = prepareTarget(statement->targets.front());
            uint32_t left = readTarget(target);
            uint32_t right = compileExpression(statement->values.front());
            uint32_t value = allocRegister();
            emit(V6Op::Binary, {value, static_cast<uint32_t>(binaryOperator(statement->text, statement->span)), left, right});
            writeTarget(target, value);
            return;
        }
        case Kind::If:
        {
            uint32_t condition = compileExpression(statement->condition);
            size_t otherwise = emit(V6Op::JumpFalse, {condition, 0});
            compileScopedBlock(statement->body);
            size_t done = emit(V6Op::Jump, {0});
            patch(otherwise, 1, prototype().code.size());
            if (statement->elseBody)
                compileScopedBlock(statement->elseBody);
            patch(done, 0, prototype().code.size());
            return;
        }
        case Kind::Scope:
            compileScopedBlock(statement->body);
            return;
        case Kind::While:
        {
            size_t start = prototype().code.size();
            uint32_t condition = compileExpression(statement->condition);
            size_t done = emit(V6Op::JumpFalse, {condition, 0});
            current().loops.push_back({current().scopeDepth, current().scopeDepth, {}, {}});
            compileScopedBlock(statement->body);
            size_t continueTarget = prototype().code.size();
            emit(V6Op::Jump, {static_cast<uint32_t>(start)});
            size_t end = prototype().code.size();
            patch(done, 1, end);
            LoopContext context = std::move(current().loops.back());
            current().loops.pop_back();
            patchLoop(context, end, continueTarget);
            return;
        }
        case Kind::Repeat:
        {
            size_t start = prototype().code.size();
            emit(V6Op::EnterScope);
            ++current().scopeDepth;
            lexicalScopes.emplace_back();
            int iterationDepth = current().scopeDepth;
            current().loops.push_back({iterationDepth - 1, iterationDepth, {}, {}});
            compileBlockBody(statement->body);
            size_t continueTarget = prototype().code.size();
            uint32_t condition = compileExpression(statement->condition);
            lexicalScopes.pop_back();
            emit(V6Op::LeaveScopes, {1});
            --current().scopeDepth;
            emit(V6Op::JumpFalse, {condition, static_cast<uint32_t>(start)});
            size_t end = prototype().code.size();
            LoopContext context = std::move(current().loops.back());
            current().loops.pop_back();
            patchLoop(context, end, continueTarget);
            return;
        }
        case Kind::ForNumeric:
        {
            uint32_t from = compileExpression(statement->values[0]);
            uint32_t limit = compileExpression(statement->values[1]);
            uint32_t step = statement->values.size() > 2 ? compileExpression(statement->values[2]) : emitConstant(json::array({2, 1}));
            uint32_t currentValue = allocRegister();
            emit(V6Op::Move, {currentValue, from});
            size_t start = prototype().code.size();
            uint32_t condition = allocRegister();
            emit(V6Op::ForCheck, {condition, currentValue, limit, step});
            size_t done = emit(V6Op::JumpFalse, {condition, 0});
            int baseDepth = current().scopeDepth;
            current().loops.push_back({baseDepth, baseDepth, {}, {}});
            emit(V6Op::EnterScope);
            ++current().scopeDepth;
            lexicalScopes.emplace_back();
            Binding loop = declare(statement->names.front(), statement->span);
            emit(V6Op::DeclareLocal, {loop.id, currentValue});
            compileBlockBody(statement->body);
            lexicalScopes.pop_back();
            emit(V6Op::LeaveScopes, {1});
            --current().scopeDepth;
            size_t continueTarget = prototype().code.size();
            uint32_t next = allocRegister();
            emit(V6Op::Binary, {next, static_cast<uint32_t>(V6Binary::Add), currentValue, step});
            emit(V6Op::Move, {currentValue, next});
            emit(V6Op::Jump, {static_cast<uint32_t>(start)});
            size_t end = prototype().code.size();
            patch(done, 1, end);
            LoopContext context = std::move(current().loops.back());
            current().loops.pop_back();
            patchLoop(context, end, continueTarget);
            return;
        }
        case Kind::ForIn:
        {
            uint32_t source = compileExpressionList(statement->values);
            uint32_t iteratorState = allocRegister();
            emit(V6Op::IteratorInit, {iteratorState, source});
            uint32_t iterator = allocRegister();
            uint32_t state = allocRegister();
            uint32_t control = allocRegister();
            emit(V6Op::PackGet, {iterator, iteratorState, 1});
            emit(V6Op::PackGet, {state, iteratorState, 2});
            emit(V6Op::PackGet, {control, iteratorState, 3});
            size_t start = prototype().code.size();
            uint32_t arguments = allocRegister();
            emit(V6Op::PackNew, {arguments});
            emit(V6Op::PackPush, {arguments, state});
            emit(V6Op::PackPush, {arguments, control});
            uint32_t values = allocRegister();
            emit(V6Op::Call, {values, iterator, arguments});
            uint32_t first = allocRegister();
            emit(V6Op::PackGet, {first, values, 1});
            size_t done = emit(V6Op::JumpNil, {first, 0});
            emit(V6Op::Move, {control, first});
            int baseDepth = current().scopeDepth;
            current().loops.push_back({baseDepth, baseDepth, {}, {}});
            emit(V6Op::EnterScope);
            ++current().scopeDepth;
            lexicalScopes.emplace_back();
            for (size_t index = 0; index < statement->names.size(); ++index)
            {
                uint32_t value = allocRegister();
                emit(V6Op::PackGet, {value, values, static_cast<uint32_t>(index + 1)});
                emit(V6Op::DeclareLocal, {declare(statement->names[index], statement->span).id, value});
            }
            compileBlockBody(statement->body);
            lexicalScopes.pop_back();
            emit(V6Op::LeaveScopes, {1});
            --current().scopeDepth;
            size_t continueTarget = prototype().code.size();
            emit(V6Op::Jump, {static_cast<uint32_t>(start)});
            size_t end = prototype().code.size();
            patch(done, 1, end);
            LoopContext context = std::move(current().loops.back());
            current().loops.pop_back();
            patchLoop(context, end, continueTarget);
            return;
        }
        case Kind::Break:
        case Kind::Continue:
        {
            if (current().loops.empty())
                fail("bind", "loop_control_outside_loop", alex::lang::statementKindName(statement->kind), statement->span, "loop control is only valid inside a loop");
            LoopContext& loop = current().loops.back();
            bool isBreak = statement->kind == Kind::Break;
            int targetDepth = isBreak ? loop.breakDepth : loop.continueDepth;
            int leaveCount = current().scopeDepth - targetDepth;
            if (leaveCount > 0)
                emit(V6Op::LeaveScopes, {static_cast<uint32_t>(leaveCount)});
            size_t jump = emit(V6Op::Jump, {0});
            (isBreak ? loop.breaks : loop.continues).push_back(jump);
            return;
        }
        }
        fail("ir_validate", "unsupported_statement", alex::lang::statementKindName(statement->kind), statement->span, "unsupported Alex statement");
    }
};

std::string emitEncryptedStringConstant(const std::string& value, std::mt19937_64& rng, const std::string& decodeFn)
{
    uint32_t mask = static_cast<uint32_t>((rng() % 229u) + 19u);
    std::ostringstream out;
    out << decodeFn << "({";
    for (size_t i = 0; i < value.size(); ++i)
    {
        if (i != 0)
            out << ",";
        uint32_t luaIndex = static_cast<uint32_t>(i + 1);
        uint32_t k = (mask + luaIndex * 31u + luaIndex * (luaIndex + 7u)) & 0xffu;
        out << (static_cast<unsigned char>(value[i]) ^ k);
    }
    out << "}," << mask << ")";
    return out.str();
}

std::string emitRobloxEnvGate(std::mt19937_64& rng, const std::string& decoyName, const std::string& guardName, const GuardSpec& guard)
{
    std::string vEnv = makeIdent(rng, "_");
    std::string vCheck = makeIdent(rng, "_");
    std::string vS = makeIdent(rng, "_");
    std::string vStep = makeIdent(rng, "_");
    std::string vGateOk = makeIdent(rng, "_");
    std::string vGateValue = makeIdent(rng, "_");
    size_t guardIndex = 0;
    auto step = [&]() {
        uint32_t salt = guard.salts.at(guardIndex);
        ++guardIndex;
        std::ostringstream expr;
        expr << vStep << "(ok and ";
        return std::make_pair(expr.str(), std::string(", ") + std::to_string(salt) + ", " + std::to_string(guardIndex) + ")");
    };
    uint32_t mask = static_cast<uint32_t>((rng() % 211u) + 23u);
    auto hidden = [&](std::string_view value) {
        std::ostringstream expr;
        expr << vS << "({";
        for (size_t i = 0; i < value.size(); ++i)
        {
            if (i != 0)
                expr << ",";
            uint32_t key = ((static_cast<uint32_t>(i + 1) * 17u + mask) % 251u);
            expr << ((static_cast<unsigned char>(value[i]) + key) & 0xffu);
        }
        expr << "})";
        return expr.str();
    };
    std::ostringstream out;
    out << "    local " << vS << " = function(bytes)\n";
    out << "        local out = {}\n";
    out << "        for i = 1, #bytes do out[i] = string.char((bytes[i] - ((i * 17 + " << mask << ") % 251)) % 256) end\n";
    out << "        return table.concat(out)\n";
    out << "    end\n";
    out << "    local " << vCheck << " = function(fn)\n";
    out << "        local ok, value = pcall(fn)\n";
    out << "        return ok and value == true\n";
    out << "    end\n";
    out << "    local " << guardName << " = " << intExpr(guard.start, 65536u, rng) << "\n";
    out << "    local " << vStep << " = function(flag, salt, index)\n";
    out << "        if flag == true then " << guardName << " = ((" << guardName << " * 131 + salt + index * 17) % 65536); return true end\n";
    out << "        " << guardName << " = ((" << guardName << " + salt + index * 97 + 4099) % 65536)\n";
    out << "        return false\n";
    out << "    end\n";
    out << "    local " << vEnv << " = function()\n";
    out << "        local ok = true\n";
    out << "        local globals = (getfenv and getfenv(0)) or _G\n";
    out << "        local ty = type\n";
    out << "        local tf = globals[" << hidden("typeof") << "]\n";
    out << "        local gm = globals[" << hidden("game") << "]\n";
    out << "        local ws = globals[" << hidden("workspace") << "]\n";
    out << "        local tk = globals[" << hidden("task") << "]\n";
    out << "        local en = globals[" << hidden("Enum") << "]\n";
    out << "        local ins = globals[" << hidden("Instance") << "]\n";
    {
        auto p = step();
        out << "        ok = " << p.first << "ty(tf) == " << hidden("function") << p.second << "\n";
    }
    {
        auto p = step();
        out << "        ok = " << p.first << "ty(globals) == " << hidden("table") << p.second << "\n";
    }
    {
        auto p = step();
        out << "        ok = " << p.first << "globals[" << hidden("python") << "] == nil and globals[" << hidden("__python") << "] == nil and globals[" << hidden("py")
            << "] == nil and globals[" << hidden("sys") << "] == nil and globals[" << hidden("open") << "] == nil" << p.second << "\n";
    }
    {
        auto p = step();
        out << "        ok = " << p.first << "globals[" << hidden("io") << "] == nil and globals[" << hidden("package") << "] == nil" << p.second << "\n";
    }
    out << "        local osl = globals[" << hidden("os") << "]\n";
    {
        auto p = step();
        out << "        ok = " << p.first << "(ty(osl) ~= " << hidden("table") << " or (ty(osl[" << hidden("execute") << "]) == " << hidden("nil")
        << " and ty(osl[" << hidden("getenv") << "]) == " << hidden("nil") << " and ty(osl[" << hidden("remove") << "]) == " << hidden("nil")
        << " and ty(osl[" << hidden("rename") << "]) == " << hidden("nil") << "))" << p.second << "\n";
    }
    {
        auto p = step();
        out << "        ok = " << p.first << "ty(gm) == " << hidden("userdata") << " and tf(gm) == " << hidden("Instance") << p.second << "\n";
    }
    {
        auto p = step();
        out << "        ok = " << p.first << "ty(ws) == " << hidden("userdata") << " and tf(ws) == " << hidden("Instance") << p.second << "\n";
    }
    {
        auto p = step();
        out << "        ok = " << p.first << "ty(tk) == " << hidden("table") << " and ty(tk[" << hidden("spawn") << "]) == " << hidden("function") << p.second << "\n";
    }
    {
        auto p = step();
        out << "        ok = " << p.first << "en ~= nil and ty(ins) == " << hidden("table") << " and ty(ins[" << hidden("new") << "]) == " << hidden("function") << p.second << "\n";
    }
    {
        auto p = step();
        out << "        ok = " << p.first << vCheck << "(function()\n";
    out << "            return gm[" << hidden("ClassName") << "] == " << hidden("DataModel") << " and ws[" << hidden("ClassName") << "] == " << hidden("Workspace")
        << " and ws[" << hidden("IsA") << "](ws, " << hidden("Workspace") << ")\n";
        out << "        end)" << p.second << "\n";
    }
    {
        auto p = step();
        out << "        ok = " << p.first << vCheck << "(function()\n";
    out << "            local get = gm[" << hidden("GetService") << "]\n";
    out << "            local rs1 = get(gm, " << hidden("RunService") << ")\n";
    out << "            local rs2 = get(gm, " << hidden("RunService") << ")\n";
    out << "            return rs1 == rs2 and ty(rs1) == " << hidden("userdata") << " and tf(rs1) == " << hidden("Instance") << " and rs1[" << hidden("IsA")
        << "](rs1, " << hidden("RunService") << ") and rs1[" << hidden("IsClient") << "](rs1) and not rs1[" << hidden("IsServer") << "](rs1)\n";
        out << "        end)" << p.second << "\n";
    }
    {
        auto p = step();
        out << "        ok = " << p.first << vCheck << "(function()\n";
    out << "            local exists = pcall(function() return gm[" << hidden("GetService") << "](gm, " << hidden("__CoreScriptDebugProbe__") << ") end)\n";
    out << "            return exists == false\n";
        out << "        end)" << p.second << "\n";
    }
    {
        auto p = step();
        out << "        ok = " << p.first << vCheck << "(function()\n";
    out << "            local f = ins[" << hidden("new") << "](" << hidden("Folder") << ")\n";
    out << "            local isA = f[" << hidden("IsA") << "]\n";
    out << "            local good = ty(f) == " << hidden("userdata") << " and tf(f) == " << hidden("Instance") << " and f[" << hidden("ClassName") << "] == "
        << hidden("Folder") << " and isA(f, " << hidden("Folder") << ") and isA(f, " << hidden("Instance") << ") and tostring(f[" << hidden("Parent")
        << "]) == " << hidden("nil") << "\n";
    out << "            f[" << hidden("Destroy") << "](f)\n";
    out << "            return good\n";
        out << "        end)" << p.second << "\n";
    }
    {
        auto p = step();
        out << "        ok = " << p.first << vCheck << "(function()\n";
    out << "            local v3 = globals[" << hidden("Vector3") << "]\n";
    out << "            return tf(v3[" << hidden("new") << "](1, 2, 3)) == " << hidden("Vector3") << " and v3[" << hidden("new") << "](1, 2, 3) == v3["
        << hidden("new") << "](1, 2, 3)\n";
        out << "        end)" << p.second << "\n";
    }
    {
        auto p = step();
        out << "        ok = " << p.first << vCheck << "(function()\n";
    out << "            local item = en[" << hidden("KeyCode") << "][" << hidden("A") << "]\n";
    out << "            return tf(item) == " << hidden("EnumItem") << " and tostring(item) == " << hidden("Enum.KeyCode.A") << "\n";
        out << "        end)" << p.second << "\n";
    }
    out << "        return ok and " << guardName << " == " << intExpr(guard.expected, 65536u, rng) << "\n";
    out << "    end\n";
    out << "    local " << vGateOk << ", " << vGateValue << " = pcall(" << vEnv << ")\n";
    out << "    if not " << vGateOk << " or " << vGateValue << " ~= true then return " << decoyName << "() end\n";
    return out.str();
}

std::string emitGuardSetup(const Config& config, std::mt19937_64& rng, const std::string& decoyName, const std::string& guardName, const GuardSpec& guard)
{
    if (config.environmentBinding == EnvironmentBinding::Roblox)
        return emitRobloxEnvGate(rng, decoyName, guardName, guard);

    if (config.environmentBinding == EnvironmentBinding::Executor)
    {
        std::string vDecode = makeIdent(rng, "_");
        std::string vGlobals = makeIdent(rng, "_");
        std::string vDebug = makeIdent(rng, "_");
        std::string vOk = makeIdent(rng, "_");
        uint32_t mask = static_cast<uint32_t>((rng() % 211u) + 23u);
        uint32_t stride = static_cast<uint32_t>((rng() % 29u) + 11u);
        auto hidden = [&](std::string_view value) {
            std::ostringstream expression;
            expression << vDecode << "({";
            for (size_t index = 0; index < value.size(); ++index)
            {
                if (index != 0)
                    expression << ",";
                uint32_t key = (mask + static_cast<uint32_t>(index + 1) * stride) % 251u;
                expression << ((static_cast<unsigned char>(value[index]) + key) & 0xffu);
            }
            expression << "})";
            return expression.str();
        };
        std::ostringstream out;
        out << "    local " << guardName << " = " << intExpr(guard.expected, 65536u, rng) << "\n";
        out << "    local " << vDecode << "=function(bytes)local out={} for i=1,#bytes do out[i]=string.char((bytes[i]-(" << mask << "+i*" << stride << ")%251)%256) end return table.concat(out) end\n";
        out << "    local " << vGlobals << " = (getfenv and getfenv(0)) or _G\n";
        out << "    local " << vDebug << "=" << vGlobals << "[" << hidden("debug") << "]\n";
        out << "    local " << vOk << " = type(" << vGlobals << ") == " << hidden("table") << " and type(" << vDebug << ") == " << hidden("table") << " and (type(" << vGlobals
            << "[" << hidden("getgenv") << "]) == " << hidden("function") << " or type(" << vGlobals << "[" << hidden("identifyexecutor") << "]) == " << hidden("function") << " or type(" << vGlobals << "[" << hidden("getexecutorname") << "]) == " << hidden("function") << ")\n";
        out << "    if not " << vOk << " then return " << decoyName << "() end\n";
        return out.str();
    }

    std::ostringstream out;
    out << "    local " << guardName << " = " << intExpr(guard.expected, 65536u, rng) << "\n";
    return out.str();
}

struct VmEmitResult
{
    std::string source;
    IntegrityDigest bundleIntegrity;
    json debug = json::object();
};

std::string gLastVmCompileError;
json gLastV6Diagnostic = json::object();

struct V6SerializedProgram
{
    json bundle = json::array();
    json debug = json::object();
};

uint64_t encodeV6Operand(const V6Prototype& proto, uint32_t value, size_t ordinal)
{
    return static_cast<uint64_t>(value) * proto.argMultiplier + proto.argSalt + static_cast<uint64_t>(ordinal) * proto.argStep;
}

V6SerializedProgram serializeV6Program(const V6Program& program, const Config& config, std::mt19937_64& rng)
{
    json prototypes = json::array();
    std::ostringstream opcodeShape;
    std::ostringstream blockShape;
    std::ostringstream constantShape;
    std::ostringstream topologyShape;
    size_t emittedRows = 0;
    size_t decoyRows = 0;
    size_t lazyBlockCount = 0;
    size_t encryptedConstantFragmentCount = 0;
    size_t closureCount = 0;
    size_t upvalueCellCount = 0;
    size_t virtualRegisterCount = 0;
    size_t physicalRegisterCount = 0;
    size_t reusedRegisterCount = 0;
    size_t constantCount = 0;
    size_t movedConstantCount = 0;
    size_t reorderedBlockCount = 0;

    for (size_t prototypeIndex = 0; prototypeIndex < program.prototypes.size(); ++prototypeIndex)
    {
        const V6Prototype& proto = program.prototypes[prototypeIndex];
        closureCount += proto.children.size();
        upvalueCellCount += proto.captures.size();
        virtualRegisterCount += proto.virtualRegisterCount;
        physicalRegisterCount += proto.maxRegister;
        reusedRegisterCount += proto.virtualRegisterCount > proto.maxRegister ? proto.virtualRegisterCount - proto.maxRegister : 0;
        constantCount += proto.constants.size();
        std::vector<size_t> blockOrder(proto.blocks.size());
        std::iota(blockOrder.begin(), blockOrder.end(), 0u);
        if (protectionRank(config.controlFlow) > 0 && blockOrder.size() > 1)
            std::shuffle(blockOrder.begin(), blockOrder.end(), rng);
        for (size_t index = 0; index < blockOrder.size(); ++index)
            reorderedBlockCount += blockOrder[index] != index ? 1u : 0u;

        std::vector<size_t> physicalOrder;
        physicalOrder.reserve(proto.code.size());
        for (size_t blockId : blockOrder)
        {
            const V6BasicBlock& block = proto.blocks[blockId];
            blockShape << prototypeIndex + 1 << ':' << blockId << ',';
            for (size_t instruction = block.start; instruction < block.end; ++instruction)
                physicalOrder.push_back(instruction);
        }
        if (physicalOrder.size() != proto.code.size())
            throw std::runtime_error("internal error: v6 physical block layout is incomplete");

        std::vector<size_t> physicalForLogical(proto.code.size(), 0);
        for (size_t physical = 0; physical < physicalOrder.size(); ++physical)
            physicalForLogical[physicalOrder[physical]] = physical;

        json rows = json::array();
        for (size_t physical = 0; physical < physicalOrder.size(); ++physical)
        {
            size_t logical = physicalOrder[physical];
            const V6Instruction& instruction = proto.code[logical];
            std::vector<uint32_t> arguments = instruction.args;
            for (size_t position : v6TargetArgs(instruction.op))
                arguments[position] = static_cast<uint32_t>(physicalForLogical.at(arguments[position]) + 1);
            if (v6IsBinary(instruction.op))
                arguments[1] = proto.binaryCodes.at(arguments[1]);
            else if (instruction.op == V6Op::Unary)
                arguments[1] = proto.unaryCodes.at(arguments[1]);

            json encodedArguments = json::array();
            for (size_t argument = 0; argument < arguments.size(); ++argument)
                encodedArguments.push_back(encodeV6Operand(proto, arguments[argument], argument + 1));
            uint32_t next = logical + 1 < proto.code.size() ? static_cast<uint32_t>(physicalForLogical[logical + 1] + 1) : 0;
            uint32_t opcode = proto.opcodes.at(v6OpIndex(instruction.op));
            rows.push_back(json::array({opcode, encodedArguments, encodeV6Operand(proto, next, 0)}));
            opcodeShape << prototypeIndex + 1 << ':' << opcode << ',';
            ++emittedRows;
        }

        std::unordered_set<uint32_t> usedOpcodes(proto.opcodes.begin(), proto.opcodes.end());
        int diversityRank = protectionRank(config.vmDiversity);
        size_t fakeRows = proto.decoy ? 0u : static_cast<size_t>(diversityRank * 2 + protectionRank(config.tamperDensity));
        for (size_t fake = 0; fake < fakeRows; ++fake)
        {
            uint32_t opcode = 1;
            do
            {
                opcode = static_cast<uint32_t>((rng() % 254u) + 1u);
            } while (usedOpcodes.count(opcode));
            json arguments = json::array();
            size_t count = static_cast<size_t>(rng() % 5u);
            for (size_t argument = 0; argument < count; ++argument)
                arguments.push_back(encodeV6Operand(proto, static_cast<uint32_t>(rng() % 1000u), argument + 1));
            rows.push_back(json::array({opcode, arguments, encodeV6Operand(proto, 0, 0)}));
            ++decoyRows;
        }

        json params = json::array();
        for (uint32_t value : proto.params)
            params.push_back(value);
        json children = json::array();
        for (uint32_t value : proto.children)
            children.push_back(value);
        json captures = json::array();
        for (uint32_t value : proto.captures)
            captures.push_back(value);
        json opcodes = json::array();
        for (uint32_t value : proto.opcodes)
            opcodes.push_back(value);
        json binaryCodes = json::array();
        for (uint32_t value : proto.binaryCodes)
            binaryCodes.push_back(value);
        json unaryCodes = json::array();
        for (uint32_t value : proto.unaryCodes)
            unaryCodes.push_back(value);
        json constantMap = json::array();
        for (uint32_t value : proto.logicalToPhysicalConstant)
        {
            constantMap.push_back(value);
            constantShape << prototypeIndex + 1 << ':' << value << ',';
        }
        for (size_t index = 0; index < proto.logicalToPhysicalConstant.size(); ++index)
            movedConstantCount += proto.logicalToPhysicalConstant[index] != index + 1 ? 1u : 0u;
        uint32_t entry = proto.code.empty() ? 0u : static_cast<uint32_t>(physicalForLogical[0] + 1);
        uint32_t topology = static_cast<uint32_t>((rng() % 65521u) + 1u);
        topologyShape << topology << ':' << blockOrder.size() << ':' << rows.size() << ',';
        bool lazyBlocks = config.profile == Profile::Maximum && config.stage2 && config.stage2LazyHandlers && !proto.decoy &&
            protectionRank(config.constantProtection) == 3 && !proto.blocks.empty();
        json encryptedBlocks = json::array();
        json blockIndex = json::array();
        if (lazyBlocks)
        {
            for (size_t index = 0; index < proto.code.size(); ++index)
                blockIndex.push_back(0);
            size_t cursor = 0;
            for (size_t recordIndex = 0; recordIndex < blockOrder.size(); ++recordIndex)
            {
                const V6BasicBlock& block = proto.blocks[blockOrder[recordIndex]];
                size_t count = block.end - block.start;
                json blockRows = json::array();
                for (size_t row = 0; row < count; ++row)
                {
                    blockRows.push_back(rows[cursor + row]);
                    blockIndex[cursor + row] = recordIndex + 1;
                }
                std::string blockPlaintext = encodeBinaryVmBundle(blockRows);
                V6AeadEnvelope blockEnvelope = makeV6AeadEnvelope(blockPlaintext, config, 0, rng);
                auto bytes = [](auto&& values) {
                    json result = json::array();
                    for (auto value : values)
                        result.push_back(static_cast<uint32_t>(static_cast<uint8_t>(value)));
                    return result;
                };
                encryptedBlocks.push_back(json::array({
                    cursor + 1,
                    count,
                    bytes(blockEnvelope.ciphertext),
                    bytes(blockEnvelope.key),
                    bytes(blockEnvelope.nonce),
                    bytes(blockEnvelope.tag),
                }));
                cursor += count;
                ++lazyBlockCount;
            }
            rows = json::array();
        }
        json emittedConstants = proto.constants;
        json encryptedConstants = json::array();
        bool protectConstantFragment = config.profile == Profile::Maximum && config.stage2 && protectionRank(config.constantProtection) == 3 &&
            !proto.decoy && !proto.constants.empty();
        if (protectConstantFragment)
        {
            std::string constantPlaintext = encodeBinaryVmBundle(proto.constants);
            V6AeadEnvelope constantEnvelope = makeV6AeadEnvelope(constantPlaintext, config, 0, rng);
            auto bytes = [](auto&& values) {
                json result = json::array();
                for (auto value : values)
                    result.push_back(static_cast<uint32_t>(static_cast<uint8_t>(value)));
                return result;
            };
            encryptedConstants = json::array({bytes(constantEnvelope.ciphertext), bytes(constantEnvelope.key), bytes(constantEnvelope.nonce), bytes(constantEnvelope.tag)});
            emittedConstants = json::array();
            ++encryptedConstantFragmentCount;
        }
        prototypes.push_back(json::array({
            params,
            rows,
            proto.vararg ? 1 : 0,
            proto.name,
            emittedConstants,
            children,
            captures,
            opcodes,
            binaryCodes,
            unaryCodes,
            proto.argMultiplier,
            proto.argSalt,
            proto.argStep,
            proto.maxRegister,
            entry,
            constantMap,
            proto.blocks.size(),
            proto.code.size(),
            proto.decoy ? 1 : 0,
            topology,
            encryptedBlocks,
            blockIndex,
            lazyBlocks ? 1 : 0,
            encryptedConstants,
        }));
    }

    auto fingerprint = [](const std::string& text) {
        IntegrityDigest digest = makeIntegrityDigest(text);
        return std::to_string(digest.size) + ":" + std::to_string(digest.a) + ":" + std::to_string(digest.b) + ":" + std::to_string(digest.c) + ":" + std::to_string(digest.d);
    };

    V6SerializedProgram serialized;
    serialized.bundle = json::array({6, program.rootPrototype, prototypes});
    serialized.debug = {
        {"backend", "alexvm6"},
        {"vm_version", 6},
        {"ir_version", 2},
        {"prototype_count", program.prototypes.size() - program.decoyPrototypeCount},
        {"decoy_prototype_count", program.decoyPrototypeCount},
        {"instruction_count", program.instructionCount},
        {"emitted_row_count", emittedRows + decoyRows},
        {"decoy_instruction_count", decoyRows},
        {"basic_block_count", program.blockCount},
        {"local_count", program.localCount},
        {"closure_count", closureCount},
        {"upvalue_cell_count", upvalueCellCount},
        {"virtual_register_count", virtualRegisterCount},
        {"physical_register_count", physicalRegisterCount},
        {"constant_count", constantCount},
        {"register_liveness_reuse", program.registerReuse},
        {"opaque_branch_count", program.opaqueGuardCount},
        {"instruction_substitution_count", program.substitutionCount},
        {"superoperator_instruction_count", program.superoperatorCount},
        {"constant_fold_count", program.constantFoldCount},
        {"branch_fold_count", program.branchFoldCount},
        {"unreachable_instruction_count", program.unreachableInstructionCount},
        {"redundant_move_count", program.redundantMoveCount},
        {"per_prototype_opcode_maps", true},
        {"per_prototype_operand_codecs", true},
        {"per_prototype_register_numbering", true},
        {"constant_placement_randomized", protectionRank(config.constantProtection) > 0},
        {"physical_block_shuffle", protectionRank(config.controlFlow) > 0},
        {"control_flow_flattening", protectionRank(config.controlFlow) > 0},
        {"opaque_branches", program.opaqueGuardCount > 0},
        {"instruction_substitution", program.substitutionCount > 0},
        {"superoperators", program.superoperatorCount > 0},
        {"safe_decoy_prototypes", program.decoyPrototypeCount > 0},
        {"handler_topology_randomized", true},
        {"per_block_lazy_decryption", lazyBlockCount > 0},
        {"lazy_encrypted_block_count", lazyBlockCount},
        {"encrypted_constant_fragments", encryptedConstantFragmentCount > 0},
        {"encrypted_constant_fragment_count", encryptedConstantFragmentCount},
        {"hkdf_sha256", false},
        {"chacha20_poly1305", false},
        {"passes", json::array({
            {{"name", "frontend_lowering"}, {"changes", program.instructionCount}},
            {{"name", "ir_validation"}, {"changes", 0}},
            {{"name", "cfg_construction"}, {"changes", program.blockCount}},
            {{"name", "constant_propagation"}, {"changes", program.constantFoldCount}},
            {{"name", "branch_folding"}, {"changes", program.branchFoldCount}},
            {{"name", "unreachable_pruning"}, {"changes", program.unreachableInstructionCount}},
            {{"name", "redundant_move_cleanup"}, {"changes", program.redundantMoveCount}},
            {{"name", "constant_placement"}, {"changes", movedConstantCount}},
            {{"name", "register_liveness"}, {"changes", reusedRegisterCount}},
            {{"name", "opaque_edges"}, {"changes", program.opaqueGuardCount}},
            {{"name", "instruction_substitution"}, {"changes", program.substitutionCount}},
            {{"name", "block_layout"}, {"changes", reorderedBlockCount}},
            {{"name", "prototype_polymorphism"}, {"changes", program.prototypes.size()}},
            {{"name", "decoy_prototypes"}, {"changes", program.decoyPrototypeCount}},
        })},
    };
    if (config.unsafeDebugMap)
    {
        serialized.debug["opcode_map_fingerprint"] = fingerprint(opcodeShape.str());
        serialized.debug["block_order_fingerprint"] = fingerprint(blockShape.str());
        serialized.debug["constant_layout_fingerprint"] = fingerprint(constantShape.str());
        serialized.debug["handler_topology_fingerprint"] = fingerprint(topologyShape.str());
        serialized.debug["complete_structural_fingerprint"] = fingerprint(opcodeShape.str() + blockShape.str() + constantShape.str() + topologyShape.str());
    }
    return serialized;
}

struct V6RuntimeNames
{
    std::string proto;
    std::string strings;
    std::string registers;
    std::string environment;
    std::string row;
    std::string args;
    std::string opcode;
    std::string pc;
    std::string decodeArg;
    std::string unwrap;
    std::string store;
    std::string getLocal;
    std::string setLocal;
    std::string declareLocal;
    std::string globalTable;
    std::string resolveGlobal;
    std::string pack;
    std::string callPacked;
    std::string makeClosure;
    std::string binary;
    std::string unary;
    std::string truthy;
    std::string varargs;
    std::string iteratorInit;
    std::string loadConstants;
    std::string tostringFn;
};

void emitV6DispatchBranches(std::ostringstream& out, const std::vector<V6Op>& order, const V6RuntimeNames& n)
{
    bool first = true;
    auto condition = [&](V6Op op) {
        out << (first ? "            if " : "            elseif ") << n.opcode << " == " << n.proto << ".o[" << (v6OpIndex(op) + 1) << "] then ";
        first = false;
    };
    auto d = [&](size_t index) {
        return n.decodeArg + "(" + std::to_string(index) + ")";
    };

    for (V6Op op : order)
    {
        condition(op);
        switch (op)
        {
        case V6Op::Nop:
            out << n.pc << " = " << n.pc << "\n";
            break;
        case V6Op::LoadConstant:
        case V6Op::LoadConstantAlt:
            out << n.registers << "[" << d(1) << "] = " << n.unwrap << "(" << n.loadConstants << "(" << n.proto << ")[" << d(2) << "])\n";
            break;
        case V6Op::Move:
            out << n.registers << "[" << d(1) << "] = " << n.registers << "[" << d(2) << "]\n";
            break;
        case V6Op::GetLocal:
        case V6Op::GetLocalAlt:
            out << n.registers << "[" << d(1) << "] = " << n.getLocal << "(" << n.environment << ", " << d(2) << ")\n";
            break;
        case V6Op::DeclareLocal:
            out << n.declareLocal << "(" << n.environment << ", " << d(1) << ", " << n.registers << "[" << d(2) << "])\n";
            break;
        case V6Op::SetLocal:
            out << n.setLocal << "(" << n.environment << ", " << d(1) << ", " << n.registers << "[" << d(2) << "])\n";
            break;
        case V6Op::GetGlobal:
            out << n.registers << "[" << d(1) << "] = " << n.resolveGlobal << "(" << n.environment << ", " << n.strings << "[" << d(2) << "])\n";
            break;
        case V6Op::SetGlobal:
            out << n.globalTable << "(" << n.environment << ")[" << n.strings << "[" << d(1) << "]] = " << n.registers << "[" << d(2) << "]\n";
            break;
        case V6Op::GetIndex:
            out << n.registers << "[" << d(1) << "] = " << n.registers << "[" << d(2) << "][" << n.registers << "[" << d(3) << "]]\n";
            break;
        case V6Op::GetIndexK:
            out << n.registers << "[" << d(1) << "] = " << n.registers << "[" << d(2) << "][" << n.strings << "[" << d(3) << "]]\n";
            break;
        case V6Op::SetIndex:
            out << n.registers << "[" << d(1) << "][" << n.registers << "[" << d(2) << "]] = " << n.registers << "[" << d(3) << "]\n";
            break;
        case V6Op::SetIndexK:
            out << n.registers << "[" << d(1) << "][" << n.strings << "[" << d(2) << "]] = " << n.registers << "[" << d(3) << "]\n";
            break;
        case V6Op::NewTable:
            out << n.registers << "[" << d(1) << "] = {}\n";
            break;
        case V6Op::SetList:
            out << n.registers << "[" << d(1) << "][" << d(2) << "] = " << n.registers << "[" << d(3) << "]\n";
            break;
        case V6Op::AppendPack:
            out << "local t, p, s = " << n.registers << "[" << d(1) << "], " << n.registers << "[" << d(2) << "], " << d(3) << "; for i = 1, p.n do t[s + i - 1] = p[i] end\n";
            break;
        case V6Op::Binary:
        case V6Op::BinaryAlt:
            out << n.registers << "[" << d(1) << "] = " << n.binary << "(" << n.proto << ", " << d(2) << ", " << n.registers << "[" << d(3) << "], " << n.registers << "[" << d(4) << "])\n";
            break;
        case V6Op::Unary:
            out << n.registers << "[" << d(1) << "] = " << n.unary << "(" << n.proto << ", " << d(2) << ", " << n.registers << "[" << d(3) << "])\n";
            break;
        case V6Op::PackNew:
            out << n.registers << "[" << d(1) << "] = {n=0}\n";
            break;
        case V6Op::PackPush:
            out << "local p = " << n.registers << "[" << d(1) << "]; p.n = p.n + 1; p[p.n] = " << n.registers << "[" << d(2) << "]\n";
            break;
        case V6Op::PackExtend:
            out << "local p, q = " << n.registers << "[" << d(1) << "], " << n.registers << "[" << d(2) << "]; for i = 1, q.n do p.n = p.n + 1; p[p.n] = q[i] end\n";
            break;
        case V6Op::PackGet:
            out << n.registers << "[" << d(1) << "] = " << n.registers << "[" << d(2) << "][" << d(3) << "]\n";
            break;
        case V6Op::PackSet:
            out << n.registers << "[" << d(1) << "][" << d(2) << "] = " << n.registers << "[" << d(3) << "]\n";
            break;
        case V6Op::Call:
            out << n.registers << "[" << d(1) << "] = " << n.callPacked << "(" << n.registers << "[" << d(2) << "], " << n.registers << "[" << d(3) << "])\n";
            break;
        case V6Op::CallGlobal0:
            out << n.registers << "[" << d(1) << "] = " << n.pack << "(" << n.resolveGlobal << "(" << n.environment << ", " << n.strings << "[" << d(2) << "])())\n";
            break;
        case V6Op::CallMethod0:
            out << "local s = " << n.registers << "[" << d(2) << "]; " << n.registers << "[" << d(1) << "] = " << n.pack << "(s[" << n.strings << "[" << d(3) << "]](s))\n";
            break;
        case V6Op::MakeClosure:
            out << n.registers << "[" << d(1) << "] = " << n.makeClosure << "(" << d(2) << ", " << n.environment << ")\n";
            break;
        case V6Op::Varargs:
            out << n.registers << "[" << d(1) << "] = " << n.varargs << "(" << n.environment << ")\n";
            break;
        case V6Op::Return:
            out << "return " << n.registers << "[" << d(1) << "]\n";
            break;
        case V6Op::Jump:
            out << n.pc << " = " << d(1) << "\n";
            break;
        case V6Op::JumpFalse:
        case V6Op::JumpFalseAlt:
            out << "if not " << n.truthy << "(" << n.registers << "[" << d(1) << "]) then " << n.pc << " = " << d(2) << " end\n";
            break;
        case V6Op::JumpTrue:
            out << "if " << n.truthy << "(" << n.registers << "[" << d(1) << "]) then " << n.pc << " = " << d(2) << " end\n";
            break;
        case V6Op::EnterScope:
            out << n.environment << " = {v={}, h={}, p=" << n.environment << "}\n";
            break;
        case V6Op::LeaveScopes:
            out << "for _ = 1, " << d(1) << " do " << n.environment << " = " << n.environment << ".p end\n";
            break;
        case V6Op::ToString:
            out << n.registers << "[" << d(1) << "] = " << n.tostringFn << "(" << n.registers << "[" << d(2) << "])\n";
            break;
        case V6Op::IteratorInit:
            out << n.registers << "[" << d(1) << "] = " << n.iteratorInit << "(" << n.registers << "[" << d(2) << "])\n";
            break;
        case V6Op::JumpNil:
            out << "if " << n.registers << "[" << d(1) << "] == nil then " << n.pc << " = " << d(2) << " end\n";
            break;
        case V6Op::ForCheck:
            out << "local c, l, s = " << n.registers << "[" << d(2) << "], " << n.registers << "[" << d(3) << "], " << n.registers << "[" << d(4) << "]; " << n.registers << "[" << d(1) << "] = (s >= 0 and c <= l) or (s < 0 and c >= l)\n";
            break;
        case V6Op::OpaqueGuard:
            out << "if ((" << d(1) << " * " << d(2) << " + " << d(3) << ") % " << d(4) << ") ~= " << d(5) << " then return nil end\n";
            break;
        case V6Op::Count:
            break;
        }
    }
    out << "            else return nil end\n";
}

std::string emitV6AeadRuntime(const V6AeadEnvelope& envelope, const Config& config, std::mt19937_64& rng, uint32_t guardExpected,
    const std::string& guardName, const std::string& bxorName, const std::string& onlineMaterialName, const std::string& keyName,
    const std::string& keyCapsuleName, const std::string& nonceName, const std::string& tagName, const std::string& decryptName)
{
    auto emitCapsule = [&](std::ostringstream& out, std::span<const uint8_t> bytes, bool bindOnline) {
        out << "{";
        for (size_t index = 0; index < bytes.size(); ++index)
        {
            if (index != 0)
                out << ",";
            uint32_t mask = static_cast<uint32_t>((rng() % 239u) + 7u);
            uint8_t onlineByte = 0;
            if (bindOnline && config.keyMode == KeyMode::Online && !config.onlineKeyMaterial.empty())
                onlineByte = static_cast<uint8_t>(config.onlineKeyMaterial[index % config.onlineKeyMaterial.size()]);
            uint32_t mixed = bxor8(bytes[index], onlineByte);
            uint32_t encoded = (mixed + mask + guardExpected % 256u) % 256u;
            out << "{" << encoded << "," << mask << "}";
        }
        out << "}";
    };

    std::ostringstream out;
    out << "    local " << keyCapsuleName << "=";
    emitCapsule(out, envelope.key, true);
    out << "\n";
    out << "    local " << keyName << "={}; for i=1,#" << keyCapsuleName << " do local q=" << keyCapsuleName << "[i]; local ob=0; if " << onlineMaterialName
        << " then ob=string.byte(" << onlineMaterialName << ",((i-1)%#" << onlineMaterialName << ")+1) end; " << keyName << "[i]=" << bxorName << "((q[1]-q[2]-(" << guardName
        << "%256))%256,ob) end\n";
    out << "    local " << nonceName << "Raw=";
    emitCapsule(out, envelope.nonce, false);
    out << "; local " << nonceName << "={}; for i=1,#" << nonceName << "Raw do local q=" << nonceName << "Raw[i]; " << nonceName << "[i]=(q[1]-q[2]-(" << guardName << "%256))%256 end\n";
    out << "    local " << tagName << "Raw=";
    emitCapsule(out, envelope.tag, false);
    out << "; local " << tagName << "={}; for i=1,#" << tagName << "Raw do local q=" << tagName << "Raw[i]; " << tagName << "[i]=(q[1]-q[2]-(" << guardName << "%256))%256 end\n";

    out << "    local " << decryptName << "=function(cipher,key,nonce,tag)\n";
    out << "        local b=bit32; if not b then return nil end; local MOD,B=4294967296,8192; local rot=b.lrotate or function(x,n) return b.bor(b.lshift(x,n),b.rshift(x,32-n)) end\n";
    out << "        local function word(a,i) return (a[i] or 0)+(a[i+1] or 0)*256+(a[i+2] or 0)*65536+(a[i+3] or 0)*16777216 end\n";
    out << "        local function block(counter) local s={1634760805,857760878,2036477234,1797285236}; for i=1,8 do s[4+i]=word(key,(i-1)*4+1) end; s[13]=counter%MOD; s[14]=word(nonce,1); s[15]=word(nonce,5); s[16]=word(nonce,9); local x={}; for i=1,16 do x[i]=s[i] end; local function q(a,c,d,e) x[a]=(x[a]+x[c])%MOD; x[e]=rot(b.bxor(x[e],x[a]),16); x[d]=(x[d]+x[e])%MOD; x[c]=rot(b.bxor(x[c],x[d]),12); x[a]=(x[a]+x[c])%MOD; x[e]=rot(b.bxor(x[e],x[a]),8); x[d]=(x[d]+x[e])%MOD; x[c]=rot(b.bxor(x[c],x[d]),7) end; for _=1,10 do q(1,5,9,13); q(2,6,10,14); q(3,7,11,15); q(4,8,12,16); q(1,6,11,16); q(2,7,12,13); q(3,8,9,14); q(4,5,10,15) end; local r={}; for i=1,16 do local v=(x[i]+s[i])%MOD; local p=(i-1)*4; r[p+1]=v%256; r[p+2]=math.floor(v/256)%256; r[p+3]=math.floor(v/65536)%256; r[p+4]=math.floor(v/16777216)%256 end; return r end\n";
    out << "        local function reduce(t) for i=1,20 do t[i]=t[i] or 0 end; for i=20,11,-1 do if t[i]~=0 then t[i-10]=t[i-10]+t[i]*5; t[i]=0 end end; while true do local carry=0; for i=1,10 do local v=t[i]+carry; carry=math.floor(v/B); t[i]=v-carry*B end; if carry==0 then break end; t[1]=t[1]+carry*5 end; local function ge() for i=10,1,-1 do local p=i==1 and B-5 or B-1; if t[i]>p then return true elseif t[i]<p then return false end end; return true end; while ge() do local borrow=0; for i=1,10 do local p=i==1 and B-5 or B-1; local v=t[i]-p-borrow; if v<0 then v=v+B; borrow=1 else borrow=0 end; t[i]=v end end; return t end\n";
    out << "        local function limbs(bytes,start,count,one) local t={}; for i=1,10 do t[i]=0 end; for j=0,count-1 do local bit=j*8; local i=math.floor(bit/13)+1; t[i]=(t[i] or 0)+(bytes[start+j] or 0)*(2^(bit%13)) end; if one then local bit=count*8; local i=math.floor(bit/13)+1; t[i]=(t[i] or 0)+2^(bit%13) end; return reduce(t) end\n";
    out << "        local function mul(a,r) local t={}; for i=1,20 do t[i]=0 end; for i=1,10 do for j=1,10 do t[i+j-1]=t[i+j-1]+a[i]*r[j] end end; return reduce(t) end\n";
    out << "        local function poly(message,polykey) local rb={}; for i=1,16 do rb[i]=polykey[i] end; rb[4]=b.band(rb[4],15); rb[8]=b.band(rb[8],15); rb[12]=b.band(rb[12],15); rb[16]=b.band(rb[16],15); rb[5]=b.band(rb[5],252); rb[9]=b.band(rb[9],252); rb[13]=b.band(rb[13],252); local r=limbs(rb,1,16,false); local a={}; for i=1,10 do a[i]=0 end; local pos=1; while pos<=#message do local count=math.min(16,#message-pos+1); local m=limbs(message,pos,count,true); local sum={}; for i=1,10 do sum[i]=a[i]+m[i] end; a=mul(reduce(sum),r); pos=pos+count end; local raw={}; for j=0,15 do local bit=j*8; local i=math.floor(bit/13)+1; local shift=bit%13; local v=math.floor((a[i] or 0)/(2^shift)); if shift>5 then v=v+(a[i+1] or 0)*(2^(13-shift)) end; raw[j+1]=v%256 end; local carry=0; for i=1,16 do local v=raw[i]+polykey[16+i]+carry; raw[i]=v%256; carry=math.floor(v/256) end; return raw end\n";
    out << "        local polykey=block(0); local mac={}; for i=1,#cipher do mac[#mac+1]=cipher[i] end; while #mac%16~=0 do mac[#mac+1]=0 end; for _=1,8 do mac[#mac+1]=0 end; local length=#cipher; for _=1,8 do mac[#mac+1]=length%256; length=math.floor(length/256) end; local calculated=poly(mac,polykey); local diff=0; for i=1,16 do diff=b.bor(diff,b.bxor(calculated[i],tag[i])) end; if diff~=0 then return nil end; local plain,counter={},1; for offset=1,#cipher,64 do local stream=block(counter); local count=math.min(64,#cipher-offset+1); for j=1,count do plain[offset+j-1]=b.bxor(cipher[offset+j-1],stream[j]) end; counter=(counter+1)%MOD end; return plain\n";
    out << "    end\n";
    return out.str();
}

std::optional<VmEmitResult> tryEmitRegisterVmV6(std::string_view source, const Config& config)
{
    gLastVmCompileError.clear();
    gLastV6Diagnostic = json::object();

    try
    {
        std::mt19937_64 rng(config.seed ^ 0x5a17f05ca70b5eedull);
        V6Program program;
        V6Program semanticProgram;
        if (config.effectiveLanguage == InputLanguage::Alex)
        {
            alex::lang::ParseResult parsed = alex::lang::parse(source);
            if (!parsed)
                throw AlexCompileFailure(parsed.diagnostics.front());
            std::vector<alex::lang::Diagnostic> bindingDiagnostics = alex::lang::bind(parsed.program);
            if (!bindingDiagnostics.empty())
                throw AlexCompileFailure(bindingDiagnostics.front());
            AlexSemanticCompiler compiler(rng, config);
            program = compiler.compile(parsed.program, &semanticProgram);
        }
        else
        {
            Luau::Allocator allocator;
            Luau::AstNameTable names(allocator);
            Luau::ParseResult parsed = Luau::Parser::parse(source.data(), source.size(), names, allocator);
            if (!parsed.root || !parsed.errors.empty())
            {
                if (!parsed.errors.empty())
                {
                    const Luau::ParseError& error = parsed.errors.front();
                    gLastV6Diagnostic = {
                        {"code", "parse_error"},
                        {"stage", "parse"},
                        {"language", "luau"},
                        {"kind", "LuauSource"},
                        {"message", error.getMessage()},
                        {"location", {{"line", error.getLocation().begin.line + 1}, {"column", error.getLocation().begin.column + 1}}},
                    };
                }
                gLastVmCompileError = "Luau parser rejected the source";
                return std::nullopt;
            }
            V6SemanticCompiler compiler(rng, config);
            program = compiler.compile(parsed.root, &semanticProgram);
        }
        if (!config.dumpIrPath.empty())
            writeFile(config.dumpIrPath, v6ProgramText(semanticProgram, "alex-ir"));
        if (!config.dumpVmPath.empty())
            writeFile(config.dumpVmPath, v6ProgramText(program, "alex-vm"));
        V6SerializedProgram serialized = serializeV6Program(program, config, rng);
        std::string binaryProgram = encodeBinaryVmBundle(serialized.bundle);

        int tamperRank = protectionRank(config.tamperDensity);
        GuardSpec guard = makeGuardSpec(rng, 16);
        OwnerBinding owner = makeOwnerBinding(config, source, guard.expected);
        uint32_t guardExpected = effectiveGuardExpected(guard, owner);
        guardExpected = (guardExpected + gameIdGuardHash(config.gameId)) & 0xffffu;
        if (config.keyMode == KeyMode::Online)
            guardExpected = (guardExpected + onlineGuardHash(config.onlineKeyMaterial)) & 0xffffu;
        V6AeadEnvelope aead = makeV6AeadEnvelope(binaryProgram, config, guardExpected, rng);
        PackedPayload packed = encryptBase95Payload(aead.ciphertext, rng, config.layers);

        std::string vDecoy = makeIdent(rng, "_");
        std::string vGuard = makeIdent(rng, "_");
        std::string vBxor = makeIdent(rng, "_");
        std::string vDecodeString = makeIdent(rng, "_");
        std::string vBundle = makeIdent(rng, "_");
        std::string vIr = makeIdent(rng, "_");
        std::string vPackedAlphabet = makeIdent(rng, "_");
        std::string vPackedPayload = makeIdent(rng, "_");
        std::string vPackedMap = makeIdent(rng, "_");
        std::string vPackedLayers = makeIdent(rng, "_");
        std::string vDecode95 = makeIdent(rng, "_");
        std::string vDecryptIr = makeIdent(rng, "_");
        std::string vIntegrity = makeIdent(rng, "_");
        std::string vParseIr = makeIdent(rng, "_");
        std::string vPrototypes = makeIdent(rng, "_");
        std::string vRoot = makeIdent(rng, "_");
        std::string vNil = makeIdent(rng, "_");
        std::string vMetadata = makeIdent(rng, "_");
        std::string vFrames = makeIdent(rng, "_");
        std::string vGlobals = makeIdent(rng, "_");
        std::string vUnpack = makeIdent(rng, "_");
        std::string vCompat = makeIdent(rng, "_");
        std::string vAliases = makeIdent(rng, "_");
        std::string vCapturedCells = makeIdent(rng, "_");
        std::string vMetadataFor = makeIdent(rng, "_");
        std::string vNativeCompat = makeIdent(rng, "_");
        std::string vDebugProxy = makeIdent(rng, "_");
        std::string vSyntheticHash = makeIdent(rng, "_");
        std::string vOnlineMaterial = makeIdent(rng, "_");
        std::string vAeadDecrypt = makeIdent(rng, "_");
        std::string vAeadKey = makeIdent(rng, "_");
        std::string vAeadKeyCapsule = makeIdent(rng, "_");
        std::string vAeadNonce = makeIdent(rng, "_");
        std::string vAeadTag = makeIdent(rng, "_");
        std::string vLoadRow = makeIdent(rng, "_");
        std::string vLoadConstants = makeIdent(rng, "_");

        V6RuntimeNames n{
            makeIdent(rng, "_"), makeIdent(rng, "_"), makeIdent(rng, "_"), makeIdent(rng, "_"), makeIdent(rng, "_"), makeIdent(rng, "_"),
            makeIdent(rng, "_"), makeIdent(rng, "_"), makeIdent(rng, "_"), makeIdent(rng, "_"), makeIdent(rng, "_"), makeIdent(rng, "_"),
            makeIdent(rng, "_"), makeIdent(rng, "_"), makeIdent(rng, "_"), makeIdent(rng, "_"), makeIdent(rng, "_"), makeIdent(rng, "_"),
            makeIdent(rng, "_"), makeIdent(rng, "_"), makeIdent(rng, "_"), makeIdent(rng, "_"), makeIdent(rng, "_"), makeIdent(rng, "_"),
            makeIdent(rng, "_"), makeIdent(rng, "_"),
        };
        n.loadConstants = vLoadConstants;
        auto hiddenCompat = [&](std::string_view value) {
            return emitEncryptedStringConstant(std::string(value), rng, vDecodeString);
        };

        std::ostringstream out;
        if (config.watermark)
            out << "-- Alexfuscator " << profileName(config.profile) << " | AlexVM 6, no source reconstruction\n";
        out << "return (function(...)\n";
        out << "    local " << vDecoy << " = function() return nil end\n";
        out << emitGuardSetup(config, rng, vDecoy, vGuard, guard);
        out << emitOwnerGuardBinding(rng, vDecoy, vGuard, owner);
        out << emitGameIdBinding(config, rng, vDecoy, vGuard);
        out << "    local " << vOnlineMaterial << " = nil\n";
        out << emitOnlineKeyBinding(config, rng, vDecoy, vGuard, vOnlineMaterial);
        out << emitOpaqueJunk(rng, vDecoy, 1 + protectionRank(config.controlFlow) * 2 + tamperRank);
        out << "    local " << vGlobals << " = (getfenv and getfenv(0)) or _G\n";
        out << "    local " << n.getLocal << ", " << n.setLocal << ", " << n.resolveGlobal << ", " << n.globalTable << ", " << n.makeClosure << ", " << n.binary << ", " << n.unary << ", " << n.varargs << ", " << n.iteratorInit << ", " << n.proto << "\n";
        out << "    local " << vBxor << " = (bit32 and bit32.bxor) or function(a, b) local r, p = 0, 1; for _ = 1, 8 do local aa, bb = a % 2, b % 2; if aa ~= bb then r = r + p end; a = (a - aa) / 2; b = (b - bb) / 2; p = p * 2 end; return r end\n";
        out << "    local " << vDecodeString << " = function(bytes, mask) local r = {}; for i = 1, #bytes do local k = (mask + i * 31 + i * (i + 7)) % 256; r[i] = string.char(" << vBxor << "(bytes[i], k)) end; return table.concat(r) end\n";
        if (!config.analysisNotice.empty())
        {
            std::string notice = makeIdent(rng, "_");
            out << "    local " << notice << " = " << emitEncryptedStringConstant(config.analysisNotice, rng, vDecodeString) << "\n";
        }
        out << "    local " << n.strings << " = {}\n";
        for (size_t index = 0; index < program.strings.size(); ++index)
            out << "    " << n.strings << "[" << index + 1 << "] = " << emitEncryptedStringConstant(program.strings[index], rng, vDecodeString) << "\n";

        out << emitAlphabetBuilder(vPackedAlphabet, packed.alphabet, rng);
        out << emitShardedStringBuilder(
            vPackedPayload, packed.encoded, rng, static_cast<size_t>(config.stage2ChunkMin), static_cast<size_t>(config.stage2ChunkMax));
        if (config.profile == Profile::Compatibility)
            out << emitLayerTable(vPackedLayers, packed.layers, guardExpected, rng);
        else
            out << emitLayerCapsule(vPackedLayers, packed.layers, guardExpected, packed.integrity, rng);
        out << "    local " << vPackedMap << " = {}; for i = 1, #" << vPackedAlphabet << " do " << vPackedMap << "[string.byte(" << vPackedAlphabet << ", i)] = i - 1 end\n";
        out << "    local " << vDecode95 << " = function(s, wanted) local r, n = {}, 0; for i = 1, #s, 5 do local x = 0; for j = 0, 4 do x = x * 95 + (" << vPackedMap << "[string.byte(s, i + j)] or 0) end; if n < wanted then n=n+1; r[n]=math.floor(x/16777216)%256 end; if n < wanted then n=n+1; r[n]=math.floor(x/65536)%256 end; if n < wanted then n=n+1; r[n]=math.floor(x/256)%256 end; if n < wanted then n=n+1; r[n]=x%256 end end; return r end\n";
        out << "    local " << vDecryptIr << " = function(blob, layer) local g16, g8 = " << vGuard << "%65536, " << vGuard << "%256; local r, state = {}, (layer[1]-g16)%65536; local salt,salt2=(layer[2]-g8)%256,(layer[3]-g8)%256; local mult,inc=(layer[4]-g16)%65536,(layer[5]-g16)%65536; local variant=((layer[6] or 0)-g8)%256; local sm,smod,km,mm=(layer[7]-g8)%256,(layer[8]-g8)%256,(layer[9]-g8)%256,(layer[10]-g8)%256; local cm,cs,sx,pm=(layer[11]-g8)%256,(layer[12]-g8)%256,(layer[13]-g8)%256,(layer[14]-g8)%256; if smod<2 then smod=251 end; if cm==0 then cm=1 end; local carry=cs; for i=1,#blob do local dyn=(carry*cm+sx+(i%17)*variant)%256; state=(state*mult+inc+salt+i*sm+dyn)%65536; local k=(math.floor(state/256)+(state%smod)+i*km+salt+carry+sx)%256; local c=blob[i]; local post=(sx+i*pm+cs+variant)%256; local x=" << vBxor << "((c-post)%256,k); x=(x-((i*mm+salt+((carry*cm)%256)+salt2+sx)%256))%256; carry=(c+k+i*cm+salt2+cs)%256; r[i]=x end; return r end\n";
        out << "    local " << vParseIr << " = function(bytes) local pos=1; local parse; local function rb() local b=bytes[pos] or 0; pos=pos+1; return b end; local function rv() local value,shift=0,1; while true do local b=rb(); value=value+(b%128)*shift; if b<128 then return value end; shift=shift*128 end end; local function rn(count) local sign,int,frac,div,es,exp,mode=1,0,0,1,1,0,0; for _=1,count do local c=rb(); if c==45 and mode==0 and int==0 and div==1 then sign=-1 elseif c==46 then mode=1 elseif c==101 or c==69 then mode=2 elseif c==45 and mode==2 and exp==0 then es=-1 elseif c>=48 and c<=57 then local d=c-48; if mode==0 then int=int*10+d elseif mode==1 then div=div*10; frac=frac*10+d else exp=exp*10+d end end end; return sign*(int+frac/div)*(10^(es*exp)) end; local function arr() local n=rv(); local t={}; for i=1,n do t[i]=parse() end; return t end; parse=function() local tag=rb(); if tag==1 then return arr() elseif tag==2 then return rn(rv()) end end; return parse() end\n";
        out << "    local " << vIr << " = " << vDecode95 << "(" << vPackedPayload << ", " << packed.plainSize << "); for i=#" << vPackedLayers << ",1,-1 do " << vIr << "=" << vDecryptIr << "(" << vIr << "," << vPackedLayers << "[i]) end\n";
        if (config.integrityChecks)
        {
            out << emitByteArrayIntegrityFunction(vIntegrity, packed.integrity);
            out << "    if not " << vIntegrity << "(" << vIr << ") then return " << vDecoy << "() end\n";
        }
        out << emitV6AeadRuntime(aead, config, rng, guardExpected, vGuard, vBxor, vOnlineMaterial, vAeadKey, vAeadKeyCapsule, vAeadNonce, vAeadTag, vAeadDecrypt);
        out << "    " << vIr << "=" << vAeadDecrypt << "(" << vIr << "," << vAeadKey << "," << vAeadNonce << "," << vAeadTag << "); if not " << vIr << " then return " << vDecoy << "() end\n";
        out << "    local " << vBundle << " = " << vParseIr << "(" << vIr << "); if " << vBundle << "[1] ~= 6 then return " << vDecoy << "() end\n";
        out << "    local " << vNil << " = {}\n";
        out << "    local function " << n.unwrap << "(v) if v == " << vNil << " then return nil end return v end\n";
        out << "    local function " << n.store << "(v) if v == nil then return " << vNil << " end return v end\n";
        out << "    local function decodeConstants(raw) local c={n=#raw}; for i=1,#raw do local x=raw[i]; if x[1]==0 then c[i]=" << vNil << " elseif x[1]==1 then c[i]=x[2]~=0 elseif x[1]==2 then c[i]=x[2] else c[i]=" << n.strings << "[x[2]] end end; return c end\n";
        out << "    local " << vPrototypes << " = {}; for i=1,#" << vBundle << "[3] do local x=" << vBundle << "[3][i]; " << vPrototypes << "[i]={p=x[1],b=x[2],v=x[3],n=x[4],c=decodeConstants(x[5]),x=x[6],u=x[7],o=x[8],bo=x[9],uo=x[10],am=x[11],as=x[12],ap=x[13],mr=x[14],e=x[15],cm=x[16],bc=x[17],ic=x[18],d=x[19],t=x[20],lb=x[21],li=x[22],lazy=x[23],ce=x[24],id=i} end\n";
        out << "    local " << vRoot << " = " << vPrototypes << "[" << vBundle << "[2]]\n";
        out << "    local " << vLoadRow << "=function(p,pc) local row=p.b[pc]; if row then return row end; if p.lazy==0 then return nil end; local id=p.li[pc]; local record=id and p.lb[id]; if not record then return nil end; local bytes=" << vAeadDecrypt << "(record[3],record[4],record[5],record[6]); if not bytes then return nil end; local decoded=" << vParseIr << "(bytes); if type(decoded)~='table' or #decoded~=record[2] then return nil end; for i=1,record[2] do p.b[record[1]+i-1]=decoded[i] end; p.lb[id]=nil; return p.b[pc] end\n";
        out << "    local " << vLoadConstants << "=function(p) if p.ce and #p.ce>0 then local bytes=" << vAeadDecrypt << "(p.ce[1],p.ce[2],p.ce[3],p.ce[4]); if not bytes then return {} end; local raw=" << vParseIr << "(bytes); if type(raw)~='table' then return {} end; p.c=decodeConstants(raw); p.ce=nil end; return p.c end\n";
        out << "    local " << n.pack << " = function(...) return table.pack and table.pack(...) or {n=select('#',...),...} end\n";
        out << "    local " << vUnpack << " = table.unpack or unpack\n";
        out << "    local " << n.callPacked << " = function(fn,args) return " << n.pack << "(fn(" << vUnpack << "(args,1,args.n or #args))) end\n";
        out << "    local " << n.truthy << " = function(v) return not (v == nil or v == false) end\n";
        out << "    local " << n.tostringFn << " = tostring\n";
        out << "    " << n.getLocal << " = function(env,id) local e=env; while e do if e.h[id] then return " << n.unwrap << "(e.v[id]) end; e=e.p end end\n";
        out << "    " << n.setLocal << " = function(env,id,value) local e=env; while e do if e.h[id] then e.v[id]=" << n.store << "(value); return end; e=e.p end; env.h[id]=true; env.v[id]=" << n.store << "(value) end\n";
        out << "    local " << n.declareLocal << " = function(env,id,value) env.h[id]=true; env.v[id]=" << n.store << "(value) end\n";
        out << "    " << n.globalTable << " = function(env) local e=env; while e do if e.g then return e.g end; e=e.p end; return " << vGlobals << " end\n";
        out << "    " << n.resolveGlobal << " = function(env,name) return " << n.globalTable << "(env)[name] end\n";
        out << "    " << n.varargs << " = function(env) local e=env; while e do if e.a then return e.a end; e=e.p end; return {n=0} end\n";
        out << "    " << n.binary << " = function(p,op,a,b) if op==p.bo[1] then return a+b elseif op==p.bo[2] then return a-b elseif op==p.bo[3] then return a*b elseif op==p.bo[4] then return a/b elseif op==p.bo[5] then return a//b elseif op==p.bo[6] then return a%b elseif op==p.bo[7] then return a^b elseif op==p.bo[8] then return a..b elseif op==p.bo[9] then return a~=b elseif op==p.bo[10] then return a==b elseif op==p.bo[11] then return a<b elseif op==p.bo[12] then return a<=b elseif op==p.bo[13] then return a>b elseif op==p.bo[14] then return a>=b end end\n";
        out << "    " << n.unary << " = function(p,op,a) if op==p.uo[1] then return not " << n.truthy << "(a) elseif op==p.uo[2] then return -a elseif op==p.uo[3] then return #a end end\n";
        out << "    " << n.iteratorInit << " = function(source) local iterator,state,control=source[1],source[2],source[3]; if type(iterator)~='function' then local mt=getmetatable(iterator); if mt and mt.__iter then local r=" << n.callPacked << "(mt.__iter," << n.pack << "(iterator)); iterator,state,control=r[1],r[2],r[3] elseif type(iterator)=='table' then state,iterator,control=iterator,next,nil end end; return {n=3,iterator,state,control} end\n";
        out << "    local " << vMetadata << " = setmetatable({}, {__mode='k'}); local " << vFrames << " = {}\n";
        out << "    local " << vMetadataFor << " = function(target) if type(target)=='number' then local frame=" << vFrames << "[#" << vFrames << "-target+1]; return frame and frame.meta, frame and frame.meta and frame.meta.fn end; return " << vMetadata << "[target],target end\n";
        out << "    local " << vCapturedCells << " = function(meta) local cells={}; if not meta then return cells end; for _,id in ipairs(meta.proto.u) do local e=meta.env; while e and not e.h[id] do e=e.p end; if e then cells[#cells+1]={e=e,id=id} end end; return cells end\n";
        out << "    local " << vCompat << " = {}\n";
        out << "    local " << vNativeCompat << " = function(name,...) local direct=" << vGlobals << "[name]; if type(direct)=='function' and direct~=" << vCompat << "[name] then return direct(...) end; local dbg=" << vGlobals << "[" << hiddenCompat("debug") << "]; local nested=dbg and dbg[name]; if type(nested)=='function' then return nested(...) end end\n";
        out << "    " << vCompat << "[" << hiddenCompat("info") << "]=function(target,options) local meta,fn=" << vMetadataFor << "(target); if not meta then local dbg=" << vGlobals << "[" << hiddenCompat("debug") << "]; local native=dbg and dbg[" << hiddenCompat("info") << "]; if native then return native(target,options) end end; options=options or " << hiddenCompat("flna") << "; local values={n=0}; local function emit(v) values.n=values.n+1; values[values.n]=v end; for i=1,#options do local o=string.sub(options,i,i); if o==" << hiddenCompat("s") << " then emit(" << hiddenCompat("=[Alexfuscator]") << ") elseif o==" << hiddenCompat("l") << " then emit(0) elseif o==" << hiddenCompat("n") << " then emit(meta.proto.n~=0 and " << n.strings << "[meta.proto.n] or '') elseif o==" << hiddenCompat("a") << " then emit(#meta.proto.p); emit(meta.proto.v~=0) elseif o==" << hiddenCompat("f") << " then emit(fn) end end; return " << vUnpack << "(values,1,values.n) end\n";
        out << "    " << vCompat << "[" << hiddenCompat("getinfo") << "]=function(target,options) local meta,fn=" << vMetadataFor << "(target); if not meta then return " << vNativeCompat << "(" << hiddenCompat("getinfo") << ",target,options) end; local cells=" << vCapturedCells << "(meta); return {[" << hiddenCompat("source") << "]=" << hiddenCompat("=[Alexfuscator]") << ",[" << hiddenCompat("short_src") << "]=" << hiddenCompat("[Alexfuscator]") << ",[" << hiddenCompat("what") << "]=" << hiddenCompat("Lua") << ",[" << hiddenCompat("currentline") << "]=-1,[" << hiddenCompat("linedefined") << "]=0,[" << hiddenCompat("lastlinedefined") << "]=0,[" << hiddenCompat("name") << "]=meta.proto.n~=0 and " << n.strings << "[meta.proto.n] or '',[" << hiddenCompat("namewhat") << "]='',[" << hiddenCompat("nups") << "]=#cells,[" << hiddenCompat("numparams") << "]=#meta.proto.p,[" << hiddenCompat("is_vararg") << "]=meta.proto.v~=0,[" << hiddenCompat("func") << "]=fn} end\n";
        out << "    " << vCompat << "[" << hiddenCompat("getconstants") << "]=function(fn) local meta=" << vMetadata << "[fn]; if not meta then return " << vNativeCompat << "(" << hiddenCompat("getconstants") << ",fn) end; local c,r=" << vLoadConstants << "(meta.proto),{}; for i=1,#meta.proto.cm do r[i]=" << n.unwrap << "(c[meta.proto.cm[i]]) end; return r end\n";
        out << "    " << vCompat << "[" << hiddenCompat("getconstant") << "]=function(fn,index) local meta=" << vMetadata << "[fn]; if not meta then return " << vNativeCompat << "(" << hiddenCompat("getconstant") << ",fn,index) end; assert(type(index)=='number' and index>=1 and index<=#meta.proto.cm and index==math.floor(index)," << hiddenCompat("constant index out of range") << "); local c=" << vLoadConstants << "(meta.proto); return " << n.unwrap << "(c[meta.proto.cm[index]]) end\n";
        out << "    " << vCompat << "[" << hiddenCompat("setconstant") << "]=function(fn,index,value) local meta=" << vMetadata << "[fn]; if not meta then return " << vNativeCompat << "(" << hiddenCompat("setconstant") << ",fn,index,value) end; assert(type(index)=='number' and index>=1 and index<=#meta.proto.cm and index==math.floor(index)," << hiddenCompat("constant index out of range") << "); local c=" << vLoadConstants << "(meta.proto); c[meta.proto.cm[index]]=" << n.store << "(value) end\n";
        out << "    " << vCompat << "[" << hiddenCompat("getupvalues") << "]=function(fn) local meta=" << vMetadata << "[fn]; if not meta then return " << vNativeCompat << "(" << hiddenCompat("getupvalues") << ",fn) end; local cells,r=" << vCapturedCells << "(meta),{}; for i=1,#cells do r[i]=" << n.unwrap << "(cells[i].e.v[cells[i].id]) end; return r end\n";
        out << "    " << vCompat << "[" << hiddenCompat("getupvalue") << "]=function(fn,index) local meta=" << vMetadata << "[fn]; if not meta then return " << vNativeCompat << "(" << hiddenCompat("getupvalue") << ",fn,index) end; local cell=" << vCapturedCells << "(meta)[index]; assert(cell," << hiddenCompat("upvalue index out of range") << "); return " << n.unwrap << "(cell.e.v[cell.id]) end\n";
        out << "    " << vCompat << "[" << hiddenCompat("setupvalue") << "]=function(fn,index,value) local meta=" << vMetadata << "[fn]; if not meta then return " << vNativeCompat << "(" << hiddenCompat("setupvalue") << ",fn,index,value) end; local cell=" << vCapturedCells << "(meta)[index]; assert(cell," << hiddenCompat("upvalue index out of range") << "); cell.e.v[cell.id]=" << n.store << "(value) end\n";
        out << "    " << vCompat << "[" << hiddenCompat("getprotos") << "]=function(fn) local meta=" << vMetadata << "[fn]; if not meta then return " << vNativeCompat << "(" << hiddenCompat("getprotos") << ",fn) end; local r={}; for i=1,#meta.proto.x do r[i]=" << n.makeClosure << "(meta.proto.x[i],meta.env,meta.g) end; return r end\n";
        out << "    " << vCompat << "[" << hiddenCompat("getproto") << "]=function(fn,index,active) local meta=" << vMetadata << "[fn]; if not meta then return " << vNativeCompat << "(" << hiddenCompat("getproto") << ",fn,index,active) end; assert(type(index)=='number' and index>=1 and index<=#meta.proto.x and index==math.floor(index)," << hiddenCompat("proto index out of range") << "); local id=meta.proto.x[index]; if active then return meta.active[id] or {} end; return " << n.makeClosure << "(id,meta.env,meta.g) end\n";
        out << "    " << vCompat << "[" << hiddenCompat("getstack") << "]=function(level,index) local frame=" << vFrames << "[#" << vFrames << "-(level or 1)+1]; if not frame then return " << vNativeCompat << "(" << hiddenCompat("getstack") << ",level,index) end; local ids,r={},{}; for id in pairs(frame.h) do ids[#ids+1]=id end; table.sort(ids); for i,id in ipairs(ids) do r[i]=" << n.unwrap << "(frame.v[id]) end; if index then return r[index] end; return r end\n";
        out << "    " << vCompat << "[" << hiddenCompat("setstack") << "]=function(level,index,value) local frame=" << vFrames << "[#" << vFrames << "-(level or 1)+1]; if not frame then return " << vNativeCompat << "(" << hiddenCompat("setstack") << ",level,index,value) end; local ids={}; for id in pairs(frame.h) do ids[#ids+1]=id end; table.sort(ids); assert(ids[index]," << hiddenCompat("stack index out of range") << "); frame.v[ids[index]]=" << n.store << "(value) end\n";
        out << "    " << vCompat << "[" << hiddenCompat("islclosure") << "]=function(fn) if " << vMetadata << "[fn] then return true end; local native=" << vGlobals << "[" << hiddenCompat("islclosure") << "]; return type(native)=='function' and native(fn) or false end\n";
        out << "    " << vCompat << "[" << hiddenCompat("iscclosure") << "]=function(fn) if " << vMetadata << "[fn] then return false end; local native=" << vGlobals << "[" << hiddenCompat("iscclosure") << "]; return type(native)=='function' and native(fn) or false end\n";
        out << "    " << vCompat << "[" << hiddenCompat("isourclosure") << "]=function(fn) return " << vMetadata << "[fn]~=nil end\n";
        out << "    " << vCompat << "[" << hiddenCompat("clonefunction") << "]=function(fn) local meta=" << vMetadata << "[fn]; if not meta then return " << vNativeCompat << "(" << hiddenCompat("clonefunction") << ",fn) end; return " << n.makeClosure << "(meta.proto.id,meta.env,meta.g) end\n";
        out << "    " << vCompat << "[" << hiddenCompat("hookfunction") << "]=function(fn,replacement) local meta=" << vMetadata << "[fn]; if not meta then return " << vNativeCompat << "(" << hiddenCompat("hookfunction") << ",fn,replacement) end; local original=" << n.makeClosure << "(meta.proto.id,meta.env,meta.g); meta.hook=replacement; return original end\n";
        out << "    " << vCompat << "[" << hiddenCompat("restorefunction") << "]=function(fn) local meta=" << vMetadata << "[fn]; if not meta then return " << vNativeCompat << "(" << hiddenCompat("restorefunction") << ",fn) end; meta.hook=nil; return fn end\n";
        out << "    " << vCompat << "[" << hiddenCompat("getfenv") << "]=function(target) local meta=type(target)=='function' and " << vMetadata << "[target] or nil; if meta then return meta.g or " << n.globalTable << "(meta.env) end; local native=" << vGlobals << "[" << hiddenCompat("getfenv") << "]; if native then return native(target) end; return " << vGlobals << " end\n";
        out << "    " << vCompat << "[" << hiddenCompat("setfenv") << "]=function(target,globals) local meta=" << vMetadata << "[target]; if not meta then return " << vNativeCompat << "(" << hiddenCompat("setfenv") << ",target,globals) end; meta.g=globals; return target end\n";
        out << "    " << vCompat << "[" << hiddenCompat("newlclosure") << "]=function(fn) return fn end; " << vCompat << "[" << hiddenCompat("newcclosure") << "]=function(fn) return function(...) return fn(...) end end\n";
        out << "    local " << vSyntheticHash << "=function(fn) local meta=" << vMetadata << "[fn]; if not meta then return " << vNativeCompat << "(" << hiddenCompat("getfunctionhash") << ",fn) end; local value=(meta.proto.id*2654435761+#meta.proto.b*131+#meta.proto.cm*17)%4294967296; return string.format('%08x%08x',value,(value*1103515245+12345)%4294967296) end\n";
        out << "    " << vCompat << "[" << hiddenCompat("getfunctionhash") << "]=" << vSyntheticHash << "; " << vCompat << "[" << hiddenCompat("getfunctionbytecode") << "]=function(fn) local meta=" << vMetadata << "[fn]; if not meta then return " << vNativeCompat << "(" << hiddenCompat("getfunctionbytecode") << ",fn) end; return string.char(27).." << hiddenCompat("ALEXVM6:") << "..tostring(meta.proto.id)..':'.." << vSyntheticHash << "(fn) end\n";
        const std::vector<std::pair<std::string_view, std::string_view>> v6CompatAliases = {
            {"getinfo", "getinfo"}, {"getfuncinfo", "getinfo"}, {"getfunctioninfo", "getinfo"}, {"getconstants", "getconstants"}, {"getconsts", "getconstants"},
            {"getconstant", "getconstant"}, {"getconst", "getconstant"}, {"setconstant", "setconstant"}, {"setconst", "setconstant"}, {"setconsts", "setconstant"},
            {"getupvalues", "getupvalues"}, {"getupvals", "getupvalues"}, {"getupvalue", "getupvalue"}, {"getupval", "getupvalue"}, {"setupvalue", "setupvalue"},
            {"setupval", "setupvalue"}, {"setupvals", "setupvalue"}, {"getprotos", "getprotos"}, {"getproto", "getproto"}, {"getstack", "getstack"},
            {"setstack", "setstack"}, {"setcallstack", "setstack"}, {"islclosure", "islclosure"}, {"iscclosure", "iscclosure"}, {"isourclosure", "isourclosure"},
            {"checkclosure", "isourclosure"}, {"clonefunction", "clonefunction"}, {"hookfunction", "hookfunction"}, {"hookfunc", "hookfunction"},
            {"detourfunction", "hookfunction"}, {"detourfunc", "hookfunction"}, {"detour_function", "hookfunction"}, {"replaceclosure", "hookfunction"},
            {"restorefunction", "restorefunction"}, {"unhookfunction", "restorefunction"}, {"newlclosure", "newlclosure"}, {"newcclosure", "newcclosure"},
            {"getfunctionhash", "getfunctionhash"}, {"getfunctionbytecode", "getfunctionbytecode"}, {"dumpfunctionbytecode", "getfunctionbytecode"},
        };
        out << "    local " << vAliases << "={}\n";
        for (const auto& [alias, target] : v6CompatAliases)
            out << "    " << vAliases << "[" << hiddenCompat(alias) << "]=" << hiddenCompat(target) << "\n";
        out << "    local nativeDebug=" << vGlobals << "[" << hiddenCompat("debug") << "] or {}; local " << vDebugProxy << "=setmetatable({}, {__index=function(_,key) if key==" << hiddenCompat("info") << " then return " << vCompat << "[" << hiddenCompat("info") << "] end; local alias=" << vAliases << "[key]; if alias then return " << vCompat << "[alias] end; return nativeDebug[key] end}); " << vCompat << "[" << hiddenCompat("debug") << "]=" << vDebugProxy << "\n";
        out << "    " << n.resolveGlobal << "=function(env,name) if name==" << hiddenCompat("debug") << " then return " << vDebugProxy << " end; if name==" << hiddenCompat("getfenv") << " then return " << vCompat << "[" << hiddenCompat("getfenv") << "] end; if name==" << hiddenCompat("setfenv") << " then return " << vCompat << "[" << hiddenCompat("setfenv") << "] end; local alias=" << vAliases << "[name]; if alias then return " << vCompat << "[alias] end; return " << n.globalTable << "(env)[name] end\n";

        std::vector<V6Op> dispatchOrder;
        for (size_t index = 0; index < v6OpIndex(V6Op::Count); ++index)
            dispatchOrder.push_back(static_cast<V6Op>(index));
        if (protectionRank(config.vmDiversity) > 0)
            std::shuffle(dispatchOrder.begin(), dispatchOrder.end(), rng);

        out << "    " << n.proto << " = function(" << n.proto << ", " << n.environment << ") local " << n.registers << ", " << n.pc << " = {}, " << n.proto << ".e; while " << n.pc << " ~= 0 do local " << n.row << "=" << vLoadRow << "(" << n.proto << "," << n.pc << "); if not " << n.row << " then return nil end; local " << n.opcode << "," << n.args << "=" << n.row << "[1]," << n.row << "[2]; " << n.pc << "=(" << n.row << "[3]-" << n.proto << ".as)/" << n.proto << ".am; local function " << n.decodeArg << "(i) return (" << n.args << "[i]-" << n.proto << ".as-i*" << n.proto << ".ap)/" << n.proto << ".am end\n";
        emitV6DispatchBranches(out, dispatchOrder, n);
        out << "        end; return {n=0} end\n";
        out << "    " << n.makeClosure << " = function(protoId,env,globals) local p=" << vPrototypes << "[protoId]; local wrapper; wrapper=function(...) local meta=" << vMetadata << "[wrapper]; if meta.hook then return meta.hook(...) end; local values=" << n.pack << "(...); local child={v={},h={},p=meta.env,proto=p,meta=meta,g=meta.g}; for i=1,#p.p do " << n.declareLocal << "(child,p.p[i],values[i]) end; if p.v~=0 then local extra={n=math.max(0,values.n-#p.p)}; for i=1,extra.n do extra[i]=values[#p.p+i] end; child.a=extra end; " << vFrames << "[#" << vFrames << "+1]=child; local result=" << n.proto << "(p,child); " << vFrames << "[#" << vFrames << "]=nil; if result then return " << vUnpack << "(result,1,result.n) end end; local meta={proto=p,env=env,g=globals,fn=wrapper,active={}}; " << vMetadata << "[wrapper]=meta; local owner=env; while owner and not owner.meta do owner=owner.p end; if owner and owner.meta then local active=owner.meta.active; active[protoId]=active[protoId] or {}; active[protoId][#active[protoId]+1]=wrapper end; return wrapper end\n";
        out << "    local rootEnv={v={},h={},p=nil,a=" << n.pack << "(...),proto=" << vRoot << ",g=" << vGlobals << "}; local result=" << n.proto << "(" << vRoot << ",rootEnv); if result then return " << vUnpack << "(result,1,result.n) end\n";
        out << "end)(...)\n";

        json debug = serialized.debug;
        debug["analysis_notice_key_bound"] = false;
        debug["encrypted_vm_container"] = true;
        debug["handler_topology_randomized"] = protectionRank(config.vmDiversity) > 0;
        debug["hkdf_sha256"] = true;
        debug["chacha20_poly1305"] = true;
        debug["authenticated_vm_container"] = true;
        debug["chained_integrity_checks"] = config.integrityChecks && debug.value("per_block_lazy_decryption", false);
        debug["passes"].push_back({{"name", "authenticated_container"}, {"changes", 1}});
        return VmEmitResult{out.str(), packed.integrity, std::move(debug)};
    }
    catch (const V6CompileFailure& failure)
    {
        gLastVmCompileError = failure.what();
        gLastV6Diagnostic = {
            {"code", failure.code},
            {"stage", failure.stage},
            {"ast_kind", failure.astKind},
            {"message", failure.what()},
            {"location", {{"line", failure.line}, {"column", failure.column}}},
        };
        return std::nullopt;
    }
    catch (const AlexCompileFailure& failure)
    {
        const alex::lang::Diagnostic& diagnostic = failure.diagnostic;
        gLastVmCompileError = failure.what();
        gLastV6Diagnostic = {
            {"code", diagnostic.code},
            {"stage", diagnostic.stage},
            {"language", "alex"},
            {"kind", diagnostic.kind},
            {"message", diagnostic.message},
            {"location", {{"line", diagnostic.span.begin.line}, {"column", diagnostic.span.begin.column}}},
        };
        return std::nullopt;
    }
    catch (const V6ValidationFailure& failure)
    {
        gLastVmCompileError = failure.what();
        gLastV6Diagnostic = {
            {"code", failure.code}, {"stage", failure.stage}, {"language", inputLanguageName(config.effectiveLanguage)}, {"kind", failure.kind},
            {"message", failure.what()}, {"prototype", failure.prototype}, {"instruction", failure.instruction},
        };
        return std::nullopt;
    }
    catch (const std::exception& failure)
    {
        gLastVmCompileError = failure.what();
        gLastV6Diagnostic = {{"code", "compiler_internal_error"}, {"stage", "emit"}, {"message", failure.what()}};
        return std::nullopt;
    }
}

void writeVmDebugMap(
    const Config& config, size_t inputBytes, size_t outputBytes, const IntegrityDigest& bundleIntegrity, const json& extra = json::object())
{
    if (config.debugMapPath.empty() && config.reportFd < 0)
        return;

    json data = {
        {"tool", "alexfuscator"},
        {"report_version", 4},
        {"profile", profileName(config.profile)},
        {"mode", "alexvm6"},
        {"backend", "alexvm6"},
        {"vm_version", 6},
        {"ir_version", 2},
        {"language", inputLanguageName(config.effectiveLanguage)},
        {"language_version", config.effectiveLanguage == InputLanguage::Alex ? 1 : 0},
        {"frontend", config.effectiveLanguage == InputLanguage::Alex ? "alex1" : "luau"},
        {"target", config.target},
        {"runtime", runtimeTargetName(config.runtime)},
        {"key_mode", keyModeName(config.keyMode)},
        {"environment_binding", environmentBindingName(config.environmentBinding)},
        {"game_id_lock", config.gameId != 0},
        {"game_id_guard_bound", config.gameId != 0},
        {"control_flow", protectionLevelName(config.controlFlow)},
        {"constant_protection", protectionLevelName(config.constantProtection)},
        {"vm_diversity", protectionLevelName(config.vmDiversity)},
        {"tamper_density", protectionLevelName(config.tamperDensity)},
        {"effective_controls", {
            {"control_flow", protectionLevelName(config.controlFlow)},
            {"constant_protection", protectionLevelName(config.constantProtection)},
            {"vm_diversity", protectionLevelName(config.vmDiversity)},
            {"tamper_density", protectionLevelName(config.tamperDensity)},
            {"environment_binding", environmentBindingName(config.environmentBinding)},
        }},
        {"seed", config.seed},
        {"layers", config.layers},
        {"input_bytes", inputBytes},
        {"output_bytes", outputBytes},
        {"one_line", config.oneLine},
        {"env_lock", config.envLock},
        {"analysis_notice", !config.analysisNotice.empty()},
        {"owner_protect", alex::owner::protect_mode_name(config.ownerProtect)},
        {"owner_locked", config.ownerProtect == alex::owner::ProtectMode::SignAndLock},
        {"fallback_used", false},
        {"bytecode_trampoline", config.bytecodeTrampoline},
        {"lazy_authenticated_blocks", config.stage2 && config.stage2LazyHandlers},
        {"decoy_prototypes_enabled", config.bytecodeTrampoline && config.stage2FakeProto},
        {"container_key_target_bound", config.stage2EnvKey},
        {"transport_chunk_size", {{"min", config.stage2ChunkMin}, {"max", config.stage2ChunkMax}}},
        {"integrity_checks", config.integrityChecks},
        {"superoperators", false},
        {"encoded_virtual_pc", true},
        {"physical_bytecode_shuffle", protectionRank(config.controlFlow) > 0},
        {"debug_map_redacted", !config.unsafeDebugMap},
        {"used_handler_emission", true},
        {"full_handler_deck", true},
        {"decoy_handlers", false},
        {"cloned_decoy_handlers", false},
        {"expression_coded_handler_slots", false},
        {"guard_bound_handler_dispatch", false},
        {"randomized_vm_context_fields", false},
        {"randomized_identifiers", true},
        {"vm_bundle_integrity", integrityJson(bundleIntegrity)},
        {"notes", json::array({"Alex 1 and Luau lower into validated AlexIR 2 and AlexVM 6 instructions", "fixed seeds produce deterministic output", "standalone runtime material remains recoverable through tracing", "output does not reconstruct or load the original source string"})},
    };
    for (auto it = extra.begin(); it != extra.end(); ++it)
        data[it.key()] = it.value();
    data["feature_flags"] = {
        {"register_vm", true},
        {"typed_semantic_ir", true},
        {"validated_control_flow", true},
        {"declarative_instruction_set", true},
        {"round_trip_debug_formats", true},
        {"explicit_result_arity", true},
        {"lexical_upvalue_cells", true},
        {"register_liveness_reuse", data.value("register_liveness_reuse", false)},
        {"per_prototype_opcode_maps", data.value("per_prototype_opcode_maps", false)},
        {"per_prototype_operand_codecs", data.value("per_prototype_operand_codecs", false)},
        {"physical_block_shuffle", data.value("physical_block_shuffle", false)},
        {"control_flow_flattening", data.value("control_flow_flattening", false)},
        {"opaque_branches", data.value("opaque_branches", false)},
        {"instruction_substitution", data.value("instruction_substitution", false)},
        {"superoperators_used", data.value("superoperators", false)},
        {"handler_topology_randomized", data.value("handler_topology_randomized", false)},
        {"safe_decoy_prototypes", data.value("safe_decoy_prototypes", false)},
        {"encrypted_vm_container", data.value("encrypted_vm_container", false)},
        {"encrypted_constant_fragments", data.value("encrypted_constant_fragments", false)},
        {"chained_integrity_checks", data.value("chained_integrity_checks", false)},
        {"per_block_lazy_decryption", data.value("per_block_lazy_decryption", false)},
        {"hkdf_sha256", data.value("hkdf_sha256", false)},
        {"chacha20_poly1305", data.value("chacha20_poly1305", false)},
    };
    if (!config.unsafeDebugMap)
    {
        data.erase("stage2_key_len");
        data.erase("stage2_runtime_fingerprint_expected");
        data.erase("stage2_header_hash");
        data.erase("stage2_mac");
    }
    std::string serialized = data.dump(2);
    if (!config.debugMapPath.empty())
        writeFile(config.debugMapPath, serialized);
    if (config.reportFd >= 0)
    {
        size_t offset = 0;
        while (offset < serialized.size())
        {
#if defined(_WIN32)
            int written = _write(config.reportFd, serialized.data() + offset, static_cast<unsigned>(std::min<size_t>(serialized.size() - offset, 1u << 30u)));
#else
            ssize_t written = ::write(config.reportFd, serialized.data() + offset, serialized.size() - offset);
#endif
            if (written <= 0)
                throw std::runtime_error("failed to write machine-readable report descriptor");
            offset += static_cast<size_t>(written);
        }
    }
}

[[noreturn]] void usage(int exitCode)
{
    std::ostream& os = exitCode == 0 ? std::cout : std::cerr;
    os << "alexfuscator - Alex 1 and Roblox Luau compiler/obfuscator\n\n"
       << "Usage:\n"
       << "  alexfuscator input.luau -o output.luau [--profile maximum] [--seed auto]\n"
       << "  alexfuscator input.alex -o output.luau [--profile maximum]\n"
       << "  alexfuscator --stdin --stdout --profile hardened [options]\n"
       << "  alexfuscator --owner-keygen keys/alex_owner [--owner-id alex]\n"
       << "  alexfuscator --serve [--port 8787]\n\n"
       << "Options:\n"
       << "  -o, --output PATH          Output .luau path\n"
       << "  --language auto|luau|alex Input language, default auto by extension\n"
       << "  --profile compatibility|hardened|maximum  vNext profile, default maximum\n"
       << "  --runtime universal|roblox|executor  Generated runtime target, default universal\n"
       << "  --key-mode standalone|online  Payload key mode, default standalone\n"
       << "  --control-flow LEVEL      preset|off|standard|aggressive|maximum\n"
       << "  --constant-protection LEVEL  Curated constant protection level\n"
       << "  --vm-diversity LEVEL      Curated VM polymorphism level\n"
       << "  --tamper-density LEVEL    Curated integrity/decoy density\n"
       << "  --environment-binding portable|roblox|executor  default portable\n"
       << "  --game-id off|ID          Lock output to one Roblox universe ID, default off\n"
       << "  --format one-line|pretty  Output formatting, default one-line\n"
       << "  --analysis-notice TEXT    Embed an informational notice; never key-bound\n"
       << "  --online-key-url URL      Capability endpoint required by online mode\n"
       << "  --online-key-material KEY Build-time key material required by online mode\n"
       << "  --layers N                Expert outer encryption rounds, no local cap\n"
       << "  --target roblox-luau      Language target; roblox-luau is currently supported\n"
       << "  --seed auto|VALUE          Randomization seed, default auto\n"
       << "  --stdin                    Read source from standard input\n"
       << "  --stdout                   Write only generated Luau to standard output\n"
       << "  --report PATH              Write a safe machine-readable build report\n"
       << "  --report-fd N              Write the report to an inherited descriptor\n"
       << "  --diagnostics-json         Emit structured JSON diagnostics on stderr\n"
       << "  --no-watermark             Omit header comment\n"
       << "  --integrity|--no-integrity  Override emitted payload integrity checks\n"
       << "  --one-line                 Alias for --format one-line\n"
       << "  --pretty                   Keep generated formatting for debugging\n"
       << "  --env-lock|--no-env-lock   Legacy aliases for roblox/portable binding\n"
       << "  --compat-test-mode         Alias for --no-env-lock for local runner tests\n"
       << "  --fallback-policy fail     Compatibility alias; source-loader fallback was removed\n"
       << "  --owner-protect off|sign|sign-and-lock  Emit signed owner capsule, default off\n"
       << "  --owner-keygen PATH        Write PATH.private and PATH.public owner keys\n"
       << "  --owner-private-key PATH   Private key used for --owner-protect sign/sign-and-lock\n"
       << "  --owner-id NAME            Owner id for keygen/signing, default alex\n"
       << "  --unsafe-debug-map         Include sensitive debug fields useful for reversing output\n"
       << "  --dump-ir PATH             Write deterministic AlexIR 2 text; requires --unsafe-debug-map\n"
       << "  --dump-vm PATH             Write deterministic AlexVM 6 text; requires --unsafe-debug-map\n"
       << "  --bytecode-trampoline      Add unreachable entry islands/decoy bytecode, default\n"
       << "  --no-bytecode-trampoline   Disable unreachable entry islands/decoy bytecode\n"
       << "  --stage2                   Enable Maximum lazy block/constant AEAD, default\n"
       << "  --no-stage2                Disable lazy block/constant AEAD for debugging\n"
       << "  --stage2-decoys N          Number of unreachable safe decoy prototypes, default 9\n"
       << "  --stage2-chunk-size A:B    Encrypted transport shard size range, default 37:353\n"
       << "  --stage2-env-key           Mix runtime target/binding into the key schedule, default\n"
       << "  --no-stage2-env-key        Use the portable container key schedule\n"
       << "  --stage2-fake-proto        Include unreachable safe decoy prototypes, default\n"
       << "  --no-stage2-fake-proto     Disable decoy prototypes\n"
       << "  --stage2-lazy-handlers     Enable Maximum per-block lazy decryption, default\n"
       << "  --no-stage2-lazy-handlers  Disable per-block lazy decryption\n"
       << "  --debug-map PATH           Write sensitive transform metadata\n"
       << "  --serve                    Launch localhost UI wrapper\n"
       << "  --port N                   UI port for --serve, default 8787\n";
    std::exit(exitCode);
}

size_t parseLayerCount(const std::string& value)
{
    size_t parsed = 0;
    size_t pos = 0;
    try
    {
        unsigned long long raw = std::stoull(value, &pos, 10);
        if (pos != value.size())
            throw std::runtime_error("bad layer count");
        if (raw == 0)
            return 1;
        if (raw > static_cast<unsigned long long>(std::numeric_limits<size_t>::max()))
            throw std::runtime_error("layer count is too large for this platform");
        parsed = static_cast<size_t>(raw);
    }
    catch (const std::exception&)
    {
        throw std::runtime_error("--layers expects a positive integer");
    }
    return parsed;
}

std::pair<int, int> parseStage2ChunkSize(const std::string& value)
{
    size_t colon = value.find(':');
    if (colon == std::string::npos)
        throw std::runtime_error("--stage2-chunk-size expects MIN:MAX");
    int minSize = std::stoi(value.substr(0, colon));
    int maxSize = std::stoi(value.substr(colon + 1));
    minSize = std::clamp(minSize, 16, 4096);
    maxSize = std::clamp(maxSize, minSize, 8192);
    return {minSize, maxSize};
}

FallbackPolicy parseFallbackPolicy(const std::string& value)
{
    if (value == "fail")
        return FallbackPolicy::Fail;
    throw CliFailure("removed_source_fallback", "--fallback-policy", "source-loader fallback was removed; --fallback-policy only accepts fail");
}

Config parseArgs(int argc, char** argv)
{
    Config config;
    for (int i = 1; i < argc; ++i)
    {
        std::string arg = argv[i];
        auto needValue = [&](std::string_view name) -> std::string {
            if (i + 1 >= argc)
                throw std::runtime_error(std::string(name) + " requires a value");
            return argv[++i];
        };

        if (arg == "-h" || arg == "--help")
            usage(0);
        else if (arg == "--stdin")
            config.inputPath = "-";
        else if (arg == "--stdout")
            config.outputPath = "-";
        else if (arg == "-o" || arg == "--output")
            config.outputPath = needValue(arg);
        else if (arg == "--language")
            config.language = parseInputLanguage(needValue(arg));
        else if (arg == "--profile")
            config.profile = parseProfile(needValue(arg));
        else if (arg == "--runtime")
            config.runtime = parseRuntimeTarget(needValue(arg));
        else if (arg == "--key-mode")
            config.keyMode = parseKeyMode(needValue(arg));
        else if (arg == "--control-flow")
            config.controlFlow = parseProtectionLevel(arg, needValue(arg));
        else if (arg == "--constant-protection")
            config.constantProtection = parseProtectionLevel(arg, needValue(arg));
        else if (arg == "--vm-diversity")
            config.vmDiversity = parseProtectionLevel(arg, needValue(arg));
        else if (arg == "--tamper-density")
            config.tamperDensity = parseProtectionLevel(arg, needValue(arg));
        else if (arg == "--environment-binding")
            config.environmentBinding = parseEnvironmentBinding(needValue(arg));
        else if (arg == "--game-id")
            config.gameId = parseGameId(needValue(arg));
        else if (arg == "--analysis-notice")
            config.analysisNotice = needValue(arg);
        else if (arg == "--online-key-url")
            config.onlineKeyUrl = needValue(arg);
        else if (arg == "--online-key-material")
            config.onlineKeyMaterial = needValue(arg);
        else if (arg == "--report")
            config.reportPath = needValue(arg);
        else if (arg == "--report-fd")
        {
            config.reportFd = std::stoi(needValue(arg));
            if (config.reportFd < 3)
                throw std::runtime_error("--report-fd expects an inherited descriptor number of 3 or greater");
        }
        else if (arg == "--diagnostics-json")
            config.diagnosticsJson = true;
        else if (arg == "--layers")
        {
            config.layers = parseLayerCount(needValue(arg));
            config.layersExplicit = true;
        }
        else if (arg == "--target")
            config.target = needValue(arg);
        else if (arg == "--seed")
            config.seedText = needValue(arg);
        else if (arg == "--no-watermark")
            config.watermark = false;
        else if (arg == "--source-minify" || arg == "--no-source-minify" || arg == "--source-wrap" || arg == "--no-source-wrap")
            throw CliFailure("removed_option", arg, arg + " was removed with the source-loader fallback; AlexVM 6 never embeds source");
        else if (arg == "--integrity")
        {
            config.integrityChecks = true;
            config.integrityExplicit = true;
        }
        else if (arg == "--no-integrity")
        {
            config.integrityChecks = false;
            config.integrityExplicit = true;
        }
        else if (arg == "--one-line")
        {
            config.oneLine = true;
            config.oneLineExplicit = true;
        }
        else if (arg == "--pretty")
        {
            config.oneLine = false;
            config.oneLineExplicit = true;
        }
        else if (arg == "--format")
        {
            std::string value = needValue(arg);
            if (value == "one-line")
                config.oneLine = true;
            else if (value == "pretty")
                config.oneLine = false;
            else
                throw std::runtime_error("--format expects one-line or pretty");
            config.oneLineExplicit = true;
        }
        else if (arg == "--env-lock")
        {
            config.envLock = true;
            config.environmentBinding = EnvironmentBinding::Roblox;
        }
        else if (arg == "--no-env-lock" || arg == "--compat-test-mode")
        {
            config.envLock = false;
            config.environmentBinding = EnvironmentBinding::Portable;
        }
        else if (arg == "--max-vm-v2" || arg == "--max-vm-v3" || arg == "--max-vm-v4" || arg == "--legacy-vm")
            throw CliFailure("removed_option", arg, arg + " was removed; all production profiles use AlexVM 6");
        else if (arg == "--vm-version" || arg == "--vm-selector")
        {
            (void)needValue(arg);
            throw CliFailure("removed_option", arg, arg + " was removed; all production profiles use AlexVM 6");
        }
        else if (arg == "--source-fallback" || arg == "--allow-source-fallback" || arg == "--native-fallback" || arg == "--ast-vm")
            throw CliFailure("removed_source_fallback", arg, arg + " was removed; unsupported input now returns a compiler diagnostic");
        else if (arg == "--fallback-policy")
        {
            config.fallbackPolicy = parseFallbackPolicy(needValue(arg));
            config.fallbackPolicyExplicit = true;
        }
        else if (arg == "--anti-ai" || arg == "--anti-ai-option" || arg == "--anti-ai1" || arg == "--anti-ai-notice" || arg == "--anti-ai2" || arg == "--anti-ai-decoy")
            throw std::runtime_error("anti-ai key binding was removed in vNext; use --analysis-notice TEXT for informational notices");
        else if (arg == "--owner-protect")
            config.ownerProtect = alex::owner::parse_protect_mode(needValue(arg));
        else if (arg == "--owner-keygen")
            config.ownerKeygenPath = needValue(arg);
        else if (arg == "--owner-private-key")
            config.ownerPrivateKeyPath = needValue(arg);
        else if (arg == "--owner-id")
        {
            config.ownerId = needValue(arg);
            config.ownerIdExplicit = true;
        }
        else if (arg == "--unsafe-debug-map")
            config.unsafeDebugMap = true;
        else if (arg == "--dump-ir")
            config.dumpIrPath = needValue(arg);
        else if (arg == "--dump-vm")
            config.dumpVmPath = needValue(arg);
        else if (arg == "--bytecode-trampoline")
            config.bytecodeTrampoline = true;
        else if (arg == "--no-bytecode-trampoline")
            config.bytecodeTrampoline = false;
        else if (arg == "--stage2")
            config.stage2 = true;
        else if (arg == "--no-stage2")
            config.stage2 = false;
        else if (arg == "--stage2-decoys")
            config.stage2Decoys = std::clamp(std::stoi(needValue(arg)), 0, 64);
        else if (arg == "--stage2-chunk-size")
        {
            auto [minSize, maxSize] = parseStage2ChunkSize(needValue(arg));
            config.stage2ChunkMin = minSize;
            config.stage2ChunkMax = maxSize;
        }
        else if (arg == "--stage2-env-key")
            config.stage2EnvKey = true;
        else if (arg == "--no-stage2-env-key")
            config.stage2EnvKey = false;
        else if (arg == "--stage2-fake-proto")
            config.stage2FakeProto = true;
        else if (arg == "--no-stage2-fake-proto")
            config.stage2FakeProto = false;
        else if (arg == "--stage2-lazy-handlers")
            config.stage2LazyHandlers = true;
        else if (arg == "--no-stage2-lazy-handlers")
            config.stage2LazyHandlers = false;
        else if (arg == "--debug-map")
            config.debugMapPath = needValue(arg);
        else if (arg == "--serve")
            config.serve = true;
        else if (arg == "--port")
            config.port = std::stoi(needValue(arg));
        else if (arg == "-" && config.inputPath.empty())
            config.inputPath = "-";
        else if (!arg.empty() && arg[0] == '-')
            throw std::runtime_error("unknown option: " + arg);
        else if (config.inputPath.empty())
            config.inputPath = arg;
        else
            throw std::runtime_error("multiple input files were provided");
    }

    if (config.target != "roblox-luau")
        throw std::runtime_error("only --target roblox-luau is currently supported");

    config.seed = parseSeed(config.seedText);

    auto applyPreset = [](ProtectionLevel& value, ProtectionLevel fallback) {
        if (value == ProtectionLevel::Preset)
            value = fallback;
    };
    switch (config.profile)
    {
    case Profile::Compatibility:
        applyPreset(config.controlFlow, ProtectionLevel::Off);
        applyPreset(config.constantProtection, ProtectionLevel::Standard);
        applyPreset(config.vmDiversity, ProtectionLevel::Standard);
        applyPreset(config.tamperDensity, ProtectionLevel::Standard);
        break;
    case Profile::Hardened:
        applyPreset(config.controlFlow, ProtectionLevel::Standard);
        applyPreset(config.constantProtection, ProtectionLevel::Aggressive);
        applyPreset(config.vmDiversity, ProtectionLevel::Aggressive);
        applyPreset(config.tamperDensity, ProtectionLevel::Aggressive);
        break;
    case Profile::Maximum:
        applyPreset(config.controlFlow, ProtectionLevel::Maximum);
        applyPreset(config.constantProtection, ProtectionLevel::Maximum);
        applyPreset(config.vmDiversity, ProtectionLevel::Maximum);
        applyPreset(config.tamperDensity, ProtectionLevel::Maximum);
        break;
    }

    if (!config.layersExplicit)
    {
        switch (config.constantProtection)
        {
        case ProtectionLevel::Off:
        case ProtectionLevel::Standard:
            config.layers = 1;
            break;
        case ProtectionLevel::Aggressive:
            config.layers = 3;
            break;
        case ProtectionLevel::Maximum:
            config.layers = 7;
            break;
        case ProtectionLevel::Preset:
            break;
        }
    }
    if (!config.integrityExplicit)
        config.integrityChecks = config.tamperDensity != ProtectionLevel::Off;

    config.fallbackPolicy = FallbackPolicy::Fail;
    config.envLock = config.environmentBinding != EnvironmentBinding::Portable;

    if (config.keyMode == KeyMode::Online)
    {
        if (config.runtime != RuntimeTarget::Executor)
            throw std::runtime_error("online key mode requires --runtime executor");
        if (config.onlineKeyUrl.empty() || config.onlineKeyMaterial.empty())
            throw std::runtime_error("online key mode requires --online-key-url and --online-key-material");
    }
    if (config.environmentBinding == EnvironmentBinding::Roblox && config.runtime == RuntimeTarget::Executor)
        throw std::runtime_error("roblox environment binding conflicts with --runtime executor");
    if (config.environmentBinding == EnvironmentBinding::Executor && config.runtime == RuntimeTarget::Roblox)
        throw std::runtime_error("executor environment binding conflicts with --runtime roblox");

    if (!config.reportPath.empty() && config.debugMapPath.empty())
        config.debugMapPath = config.reportPath;

    if (!config.serve && config.ownerKeygenPath.empty())
    {
        if (config.inputPath.empty())
            throw std::runtime_error("missing input file");
        if (config.outputPath.empty())
            config.outputPath = config.inputPath == "-" ? fs::path("-") : fs::path(defaultOutputFor(config.inputPath));
        config.effectiveLanguage = resolveInputLanguage(config.language, config.inputPath);
    }

    if ((!config.dumpIrPath.empty() || !config.dumpVmPath.empty()) && !config.unsafeDebugMap)
        throw std::runtime_error("--dump-ir and --dump-vm require --unsafe-debug-map");

    return config;
}

int launchServer(const char* argv0, const Config& config)
{
    fs::path exe = fs::absolute(argv0);
    fs::path cwd = fs::current_path();
    fs::path script = cwd / "tools" / "alexfuscator_web.py";
    if (!fs::exists(script))
        throw std::runtime_error("could not find tools/alexfuscator_web.py from " + cwd.string());

    std::ostringstream cmd;
    cmd << "python3 " << std::quoted(script.string())
        << " --binary " << std::quoted(exe.string())
        << " --port " << config.port;
    return std::system(cmd.str().c_str());
}

} // namespace

int main(int argc, char** argv)
{
    bool diagnosticsJson = false;
    for (int i = 1; i < argc; ++i)
        diagnosticsJson = diagnosticsJson || std::string_view(argv[i]) == "--diagnostics-json";

    try
    {
        Config config = parseArgs(argc, argv);
        if (!config.ownerKeygenPath.empty())
        {
            alex::owner::PrivateKey key = alex::owner::generate_keypair(config.ownerId, config.seed == 0 ? autoSeed() : config.seed);
            alex::owner::write_keypair(config.ownerKeygenPath, key);
            std::cout << "Alexfuscator wrote owner keys: " << config.ownerKeygenPath.string() << ".private and "
                      << config.ownerKeygenPath.string() << ".public"
                      << " (owner_id=" << key.public_key.owner_id << ", owner_hash=" << key.public_key.owner_hash << ")\n";
            return 0;
        }
        if (config.serve)
            return launchServer(argv[0], config);

        std::string source = readFile(config.inputPath);

        std::optional<VmEmitResult> vmOutput = tryEmitRegisterVmV6(source, config);
        if (!vmOutput)
        {
            std::string detail = gLastVmCompileError.empty() ? "unsupported Luau syntax" : gLastVmCompileError;
            if (diagnosticsJson)
            {
                json error = gLastV6Diagnostic.empty() ? json({{"code", "compile_failed"}, {"stage", "semantic_ir"}, {"message", detail}}) : gLastV6Diagnostic;
                std::cerr << json({{"ok", false}, {"error", std::move(error)}}).dump() << "\n";
                return 1;
            }
            throw std::runtime_error("AlexVM 6 could not lower the script: " + detail);
        }

        std::string output = finalizeGeneratedOutput(config, std::move(vmOutput->source));
        validateLuau(output);
        writeFile(config.outputPath, output);
        writeVmDebugMap(config, source.size(), output.size(), vmOutput->bundleIntegrity, vmOutput->debug);

        std::ostream& log = config.outputPath == "-" ? std::cerr : std::cout;
        log << "Alexfuscator wrote " << config.outputPath << " (" << output.size() << " bytes, profile=" << profileName(config.profile)
                  << ", mode=alexvm6"
                  << ", layers=" << config.layers << ", seed=" << config.seed
                  << ", integrity=" << (config.integrityChecks ? "on" : "off")
                  << ", runtime=" << runtimeTargetName(config.runtime)
                  << ", key_mode=" << keyModeName(config.keyMode)
                  << ", environment_binding=" << environmentBindingName(config.environmentBinding)
                  << ", game_id_lock=" << (config.gameId == 0 ? "off" : "on")
                  << ", owner_protect=" << alex::owner::protect_mode_name(config.ownerProtect)
                  << ", one_line=" << (config.oneLine ? "on" : "off") << ")\n";
        return 0;
    }
    catch (const CliFailure& e)
    {
        if (diagnosticsJson)
            std::cerr << json({{"ok", false}, {"error", {{"code", e.code}, {"stage", "cli"}, {"option", e.option}, {"message", e.what()}}}}).dump() << "\n";
        else
            std::cerr << "alexfuscator: " << e.what() << "\n";
        return 1;
    }
    catch (const std::exception& e)
    {
        if (diagnosticsJson)
            std::cerr << json({{"ok", false}, {"error", {{"code", "compile_failed"}, {"message", e.what()}}}}).dump() << "\n";
        else
            std::cerr << "alexfuscator: " << e.what() << "\n";
        return 1;
    }
}
