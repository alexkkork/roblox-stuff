#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

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

Sha256 sha256(std::span<const std::uint8_t> data);
Sha256 sha256(std::string_view data);
std::string hex(Sha256 hash);
bool parse_sha256(std::string_view text, Sha256& out);
bool constant_time_equal(std::string_view a, std::string_view b);
std::vector<std::uint8_t> read_file_bytes(const std::filesystem::path& path);
Sha256 file_sha256(const std::filesystem::path& path);
std::filesystem::path self_path();
std::string finding_kind_name(FindingKind kind);

class Guard
{
public:
    using FailureCallback = std::function<void(const CheckResult&)>;

    Guard& add_file(std::filesystem::path path, std::string expected_sha256_hex, std::string name = {});
    Guard& add_self_file(std::string expected_sha256_hex, std::string name = {});
    Guard& add_memory(std::string name, const void* data, std::size_t size, Sha256 expected_sha256);
    Guard& seal_memory(std::string name, const void* data, std::size_t size);
    Guard& on_failure(FailureCallback callback);

    CheckResult check() const;
    bool check_or_fail() const;
    const std::vector<FileRule>& files() const;
    const std::vector<MemoryRule>& memory() const;

private:
    std::vector<FileRule> files_;
    std::vector<MemoryRule> memory_;
    FailureCallback failure_;
};

} 
