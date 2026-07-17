#pragma once

#include "alex/antitamper.hpp"

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

using Ed25519PublicKey = std::array<std::uint8_t, 32>;
using Ed25519PrivateSeed = std::array<std::uint8_t, 32>;
using Ed25519Signature = std::array<std::uint8_t, 64>;

struct ManifestEntry
{
    std::string name;
    std::filesystem::path relative_path;
    std::uint64_t expected_size = 0;
    Sha256 expected_sha256{};
    bool required = true;
};

struct SignedManifest
{
    std::uint32_t version = 1;
    std::string application_id;
    std::uint64_t build_number = 0;
    std::vector<ManifestEntry> entries;
    Ed25519Signature signature{};
};

enum class ManifestFindingKind
{
    InvalidSignature,
    UnsupportedVersion,
    ApplicationMismatch,
    RollbackDetected,
    TooManyEntries,
    DuplicateEntry,
    InvalidPath,
    PathEscapesRoot,
    SymlinkRejected,
    MissingFile,
    FileTooLarge,
    FileSizeMismatch,
    FileHashMismatch,
    ReadError,
};

struct ManifestFinding
{
    ManifestFindingKind kind = ManifestFindingKind::ReadError;
    std::string name;
    std::string detail;
    std::string expected;
    std::string actual;
};

struct ManifestCheckResult
{
    bool ok = true;
    Sha256 manifest_digest{};
    std::vector<ManifestFinding> findings;
};

struct ManifestPolicy
{
    std::filesystem::path root;
    std::string expected_application_id;
    std::uint64_t minimum_build_number = 0;
    std::size_t maximum_entries = 4096;
    std::uint64_t maximum_file_bytes = 256ull * 1024ull * 1024ull;
    bool allow_symlinks = false;
};

Ed25519PublicKey ed25519_public_key(const Ed25519PrivateSeed& privateSeed);
std::vector<std::uint8_t> canonical_manifest_bytes(const SignedManifest& manifest);
Sha256 manifest_digest(const SignedManifest& manifest);
void sign_manifest(SignedManifest& manifest, const Ed25519PrivateSeed& privateSeed);
bool verify_manifest_signature(const SignedManifest& manifest, const Ed25519PublicKey& publicKey);

ManifestEntry make_manifest_entry(
    const std::filesystem::path& root,
    const std::filesystem::path& relativePath,
    std::string name = {},
    bool required = true);

ManifestCheckResult verify_signed_manifest(
    const SignedManifest& manifest,
    const Ed25519PublicKey& publicKey,
    const ManifestPolicy& policy);

std::string manifest_finding_kind_name(ManifestFindingKind kind);

class ManifestGuard
{
public:
    using FailureCallback = std::function<void(const ManifestCheckResult&)>;

    ManifestGuard(SignedManifest manifest, Ed25519PublicKey publicKey, ManifestPolicy policy);
    ManifestGuard& on_failure(FailureCallback callback);

    ManifestCheckResult check() const;
    bool check_or_fail() const;

private:
    SignedManifest manifest_;
    Ed25519PublicKey public_key_{};
    ManifestPolicy policy_;
    FailureCallback failure_;
};

} // namespace alex::antitamper
