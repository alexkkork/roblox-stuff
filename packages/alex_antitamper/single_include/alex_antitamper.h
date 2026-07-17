#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iterator>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#if defined(_WIN32)
#define NOMINMAX
#include <windows.h>
#elif defined(__APPLE__)
#include <mach-o/dyld.h>
#include <unistd.h>
#else
#include <unistd.h>
#endif

namespace alex::antitamper
{

using Sha256 = std::array<std::uint8_t, 32>;

enum class FindingKind
{
    MissingFile,
    FileHashMismatch,
    MemoryHashMismatch,
    ReadError,
    InvalidExpectedHash,
};

struct Finding
{
    FindingKind kind = FindingKind::ReadError;
    std::string name;
    std::string expected;
    std::string actual;
    std::string detail;
};

struct CheckResult
{
    bool ok = true;
    std::vector<Finding> findings;
};

struct FileRule
{
    std::string name;
    std::filesystem::path path;
    std::string expected_sha256_hex;
    bool required = true;
};

struct MemoryRule
{
    std::string name;
    const void* data = nullptr;
    std::size_t size = 0;
    Sha256 expected_sha256{};
};

namespace detail
{

inline constexpr std::array<std::uint32_t, 64> sha256_k = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};

inline std::uint32_t rotr(std::uint32_t value, std::uint32_t bits)
{
    return (value >> bits) | (value << (32u - bits));
}

inline std::uint32_t load_be32(const std::uint8_t* p)
{
    return (static_cast<std::uint32_t>(p[0]) << 24u) |
        (static_cast<std::uint32_t>(p[1]) << 16u) |
        (static_cast<std::uint32_t>(p[2]) << 8u) |
        static_cast<std::uint32_t>(p[3]);
}

inline void store_be32(std::uint8_t* p, std::uint32_t value)
{
    p[0] = static_cast<std::uint8_t>((value >> 24u) & 0xffu);
    p[1] = static_cast<std::uint8_t>((value >> 16u) & 0xffu);
    p[2] = static_cast<std::uint8_t>((value >> 8u) & 0xffu);
    p[3] = static_cast<std::uint8_t>(value & 0xffu);
}

inline int hex_value(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

inline std::string default_name(const std::filesystem::path& path)
{
    std::string text = path.filename().string();
    return text.empty() ? path.string() : text;
}

}

inline Sha256 sha256(std::span<const std::uint8_t> data)
{
    std::array<std::uint32_t, 8> h = {
        0x6a09e667u,
        0xbb67ae85u,
        0x3c6ef372u,
        0xa54ff53au,
        0x510e527fu,
        0x9b05688cu,
        0x1f83d9abu,
        0x5be0cd19u,
    };

    std::vector<std::uint8_t> msg(data.begin(), data.end());
    std::uint64_t bit_length = static_cast<std::uint64_t>(msg.size()) * 8ull;
    msg.push_back(0x80u);
    while ((msg.size() % 64u) != 56u)
        msg.push_back(0u);
    for (int i = 7; i >= 0; --i)
        msg.push_back(static_cast<std::uint8_t>((bit_length >> (i * 8)) & 0xffu));

    for (std::size_t offset = 0; offset < msg.size(); offset += 64)
    {
        std::array<std::uint32_t, 64> w{};
        for (std::size_t i = 0; i < 16; ++i)
            w[i] = detail::load_be32(msg.data() + offset + i * 4);
        for (std::size_t i = 16; i < 64; ++i)
        {
            std::uint32_t s0 = detail::rotr(w[i - 15], 7) ^ detail::rotr(w[i - 15], 18) ^ (w[i - 15] >> 3u);
            std::uint32_t s1 = detail::rotr(w[i - 2], 17) ^ detail::rotr(w[i - 2], 19) ^ (w[i - 2] >> 10u);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        std::uint32_t a = h[0];
        std::uint32_t b = h[1];
        std::uint32_t c = h[2];
        std::uint32_t d = h[3];
        std::uint32_t e = h[4];
        std::uint32_t f = h[5];
        std::uint32_t g = h[6];
        std::uint32_t hh = h[7];

        for (std::size_t i = 0; i < 64; ++i)
        {
            std::uint32_t s1 = detail::rotr(e, 6) ^ detail::rotr(e, 11) ^ detail::rotr(e, 25);
            std::uint32_t ch = (e & f) ^ ((~e) & g);
            std::uint32_t temp1 = hh + s1 + ch + detail::sha256_k[i] + w[i];
            std::uint32_t s0 = detail::rotr(a, 2) ^ detail::rotr(a, 13) ^ detail::rotr(a, 22);
            std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            std::uint32_t temp2 = s0 + maj;
            hh = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        h[0] += a;
        h[1] += b;
        h[2] += c;
        h[3] += d;
        h[4] += e;
        h[5] += f;
        h[6] += g;
        h[7] += hh;
    }

    Sha256 out{};
    for (std::size_t i = 0; i < h.size(); ++i)
        detail::store_be32(out.data() + i * 4, h[i]);
    return out;
}

inline Sha256 sha256(std::string_view data)
{
    return sha256(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(data.data()), data.size()));
}

inline std::string hex(Sha256 hash)
{
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (std::uint8_t byte : hash)
        out << std::setw(2) << static_cast<unsigned>(byte);
    return out.str();
}

inline bool parse_sha256(std::string_view text, Sha256& out)
{
    if (text.size() != 64)
        return false;
    Sha256 value{};
    for (std::size_t i = 0; i < value.size(); ++i)
    {
        int hi = detail::hex_value(text[i * 2]);
        int lo = detail::hex_value(text[i * 2 + 1]);
        if (hi < 0 || lo < 0)
            return false;
        value[i] = static_cast<std::uint8_t>((hi << 4) | lo);
    }
    out = value;
    return true;
}

inline bool constant_time_equal(std::string_view a, std::string_view b)
{
    if (a.size() != b.size())
        return false;
    unsigned diff = 0;
    for (std::size_t i = 0; i < a.size(); ++i)
        diff |= static_cast<unsigned>(static_cast<unsigned char>(a[i]) ^ static_cast<unsigned char>(b[i]));
    return diff == 0;
}

inline std::vector<std::uint8_t> read_file_bytes(const std::filesystem::path& path)
{
    std::ifstream in(path, std::ios::binary);
    if (!in)
        throw std::runtime_error("could not open file: " + path.string());
    return std::vector<std::uint8_t>(
        std::istreambuf_iterator<char>(in),
        std::istreambuf_iterator<char>());
}

inline Sha256 file_sha256(const std::filesystem::path& path)
{
    std::vector<std::uint8_t> bytes = read_file_bytes(path);
    return sha256(std::span<const std::uint8_t>(bytes.data(), bytes.size()));
}

inline std::filesystem::path self_path()
{
#if defined(_WIN32)
    std::vector<char> buffer(260);
    for (;;)
    {
        DWORD size = GetModuleFileNameA(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (size == 0)
            throw std::runtime_error("GetModuleFileNameA failed");
        if (size < buffer.size() - 1)
            return std::filesystem::path(std::string(buffer.data(), size));
        buffer.resize(buffer.size() * 2);
    }
#elif defined(__APPLE__)
    std::uint32_t size = 0;
    _NSGetExecutablePath(nullptr, &size);
    std::vector<char> buffer(size + 1, 0);
    if (_NSGetExecutablePath(buffer.data(), &size) != 0)
        throw std::runtime_error("_NSGetExecutablePath failed");
    return std::filesystem::weakly_canonical(std::filesystem::path(buffer.data()));
#else
    std::vector<char> buffer(4096);
    for (;;)
    {
        ssize_t size = readlink("/proc/self/exe", buffer.data(), buffer.size());
        if (size < 0)
            throw std::runtime_error("readlink /proc/self/exe failed");
        if (static_cast<std::size_t>(size) < buffer.size())
            return std::filesystem::path(std::string(buffer.data(), static_cast<std::size_t>(size)));
        buffer.resize(buffer.size() * 2);
    }
#endif
}

inline std::string finding_kind_name(FindingKind kind)
{
    switch (kind)
    {
    case FindingKind::MissingFile:
        return "missing_file";
    case FindingKind::FileHashMismatch:
        return "file_hash_mismatch";
    case FindingKind::MemoryHashMismatch:
        return "memory_hash_mismatch";
    case FindingKind::ReadError:
        return "read_error";
    case FindingKind::InvalidExpectedHash:
        return "invalid_expected_hash";
    }
    return "unknown";
}

class Guard
{
public:
    using FailureCallback = std::function<void(const CheckResult&)>;

    Guard& add_file(std::filesystem::path path, std::string expected_sha256_hex, std::string name = {})
    {
        FileRule rule;
        rule.path = std::move(path);
        rule.expected_sha256_hex = std::move(expected_sha256_hex);
        rule.name = name.empty() ? detail::default_name(rule.path) : std::move(name);
        files_.push_back(std::move(rule));
        return *this;
    }

    Guard& add_self_file(std::string expected_sha256_hex, std::string name = {})
    {
        std::filesystem::path path = self_path();
        return add_file(path, std::move(expected_sha256_hex), name.empty() ? "self" : std::move(name));
    }

    Guard& add_memory(std::string name, const void* data, std::size_t size, Sha256 expected_sha256)
    {
        MemoryRule rule;
        rule.name = std::move(name);
        rule.data = data;
        rule.size = size;
        rule.expected_sha256 = expected_sha256;
        memory_.push_back(rule);
        return *this;
    }

    Guard& seal_memory(std::string name, const void* data, std::size_t size)
    {
        auto bytes = std::span<const std::uint8_t>(static_cast<const std::uint8_t*>(data), size);
        return add_memory(std::move(name), data, size, sha256(bytes));
    }

    Guard& on_failure(FailureCallback callback)
    {
        failure_ = std::move(callback);
        return *this;
    }

    CheckResult check() const
    {
        CheckResult result;

        for (const FileRule& rule : files_)
        {
            Sha256 expected{};
            if (!parse_sha256(rule.expected_sha256_hex, expected))
            {
                result.ok = false;
                result.findings.push_back({FindingKind::InvalidExpectedHash, rule.name, rule.expected_sha256_hex, {}, rule.path.string()});
                continue;
            }

            std::error_code ec;
            bool exists = std::filesystem::exists(rule.path, ec);
            if (ec || !exists)
            {
                if (rule.required)
                {
                    result.ok = false;
                    result.findings.push_back({FindingKind::MissingFile, rule.name, rule.expected_sha256_hex, {}, rule.path.string()});
                }
                continue;
            }

            try
            {
                std::string expected_hex = hex(expected);
                std::string actual = hex(file_sha256(rule.path));
                if (!constant_time_equal(actual, expected_hex))
                {
                    result.ok = false;
                    result.findings.push_back({FindingKind::FileHashMismatch, rule.name, expected_hex, actual, rule.path.string()});
                }
            }
            catch (const std::exception& e)
            {
                result.ok = false;
                result.findings.push_back({FindingKind::ReadError, rule.name, hex(expected), {}, e.what()});
            }
        }

        for (const MemoryRule& rule : memory_)
        {
            if (!rule.data && rule.size != 0)
            {
                result.ok = false;
                result.findings.push_back({FindingKind::ReadError, rule.name, hex(rule.expected_sha256), {}, "null memory region"});
                continue;
            }

            auto bytes = std::span<const std::uint8_t>(static_cast<const std::uint8_t*>(rule.data), rule.size);
            std::string actual = hex(sha256(bytes));
            std::string expected = hex(rule.expected_sha256);
            if (!constant_time_equal(actual, expected))
            {
                result.ok = false;
                result.findings.push_back({FindingKind::MemoryHashMismatch, rule.name, expected, actual, {}});
            }
        }

        return result;
    }

    bool check_or_fail() const
    {
        CheckResult result = check();
        if (!result.ok && failure_)
            failure_(result);
        return result.ok;
    }

    const std::vector<FileRule>& files() const
    {
        return files_;
    }

    const std::vector<MemoryRule>& memory() const
    {
        return memory_;
    }

private:
    std::vector<FileRule> files_;
    std::vector<MemoryRule> memory_;
    FailureCallback failure_;
};

}
