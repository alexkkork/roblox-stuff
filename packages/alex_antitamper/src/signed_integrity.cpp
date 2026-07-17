#include "alex/signed_integrity.hpp"

#include <openssl/evp.h>

#include <algorithm>
#include <limits>
#include <memory>
#include <set>
#include <stdexcept>
#include <system_error>
#include <utility>

namespace alex::antitamper
{
namespace
{

constexpr std::string_view kManifestDomain = "alex-signed-integrity-manifest-v1";
constexpr std::uint32_t kManifestVersion = 1;
constexpr std::size_t kMaximumCanonicalStringBytes = 1024 * 1024;

using PkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using MdContextPtr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;

void appendU32(std::vector<std::uint8_t>& output, std::uint32_t value)
{
    for (unsigned int shift = 0; shift < 32; shift += 8)
        output.push_back(static_cast<std::uint8_t>(value >> shift));
}

void appendU64(std::vector<std::uint8_t>& output, std::uint64_t value)
{
    for (unsigned int shift = 0; shift < 64; shift += 8)
        output.push_back(static_cast<std::uint8_t>(value >> shift));
}

void appendString(std::vector<std::uint8_t>& output, std::string_view value)
{
    if (value.size() > kMaximumCanonicalStringBytes || value.size() > std::numeric_limits<std::uint32_t>::max())
        throw std::runtime_error("integrity manifest string exceeds the canonical encoding limit");
    appendU32(output, static_cast<std::uint32_t>(value.size()));
    output.insert(output.end(), value.begin(), value.end());
}

PkeyPtr privateKey(const Ed25519PrivateSeed& seed)
{
    EVP_PKEY* raw = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, seed.data(), seed.size());
    if (!raw)
        throw std::runtime_error("OpenSSL could not create an Ed25519 private key");
    return PkeyPtr(raw, EVP_PKEY_free);
}

PkeyPtr publicKey(const Ed25519PublicKey& bytes)
{
    EVP_PKEY* raw = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, bytes.data(), bytes.size());
    if (!raw)
        throw std::runtime_error("OpenSSL could not create an Ed25519 public key");
    return PkeyPtr(raw, EVP_PKEY_free);
}

bool safeRelativePath(const std::filesystem::path& path)
{
    if (path.empty() || path.is_absolute() || path.has_root_name() || path.has_root_directory())
        return false;
    for (const std::filesystem::path& component : path)
        if (component.empty() || component == "." || component == "..")
            return false;
    return true;
}

bool pathWithin(const std::filesystem::path& root, const std::filesystem::path& candidate)
{
    auto rootPart = root.begin();
    auto candidatePart = candidate.begin();
    for (; rootPart != root.end(); ++rootPart, ++candidatePart)
        if (candidatePart == candidate.end() || *rootPart != *candidatePart)
            return false;
    return true;
}

void fail(ManifestCheckResult& result, ManifestFinding finding)
{
    result.ok = false;
    result.findings.push_back(std::move(finding));
}

std::string defaultEntryName(const std::filesystem::path& path)
{
    const std::string filename = path.filename().string();
    return filename.empty() ? path.generic_string() : filename;
}

} // namespace

Ed25519PublicKey ed25519_public_key(const Ed25519PrivateSeed& privateSeed)
{
    const PkeyPtr key = privateKey(privateSeed);
    Ed25519PublicKey result{};
    std::size_t size = result.size();
    if (EVP_PKEY_get_raw_public_key(key.get(), result.data(), &size) != 1 || size != result.size())
        throw std::runtime_error("OpenSSL could not derive the Ed25519 public key");
    return result;
}

std::vector<std::uint8_t> canonical_manifest_bytes(const SignedManifest& manifest)
{
    if (manifest.entries.size() > std::numeric_limits<std::uint32_t>::max())
        throw std::runtime_error("integrity manifest has too many entries to encode");

    std::vector<std::uint8_t> output;
    output.reserve(128 + manifest.entries.size() * 128);
    appendString(output, kManifestDomain);
    appendU32(output, manifest.version);
    appendString(output, manifest.application_id);
    appendU64(output, manifest.build_number);
    appendU32(output, static_cast<std::uint32_t>(manifest.entries.size()));
    for (const ManifestEntry& entry : manifest.entries)
    {
        appendString(output, entry.name);
        appendString(output, entry.relative_path.generic_string());
        appendU64(output, entry.expected_size);
        output.push_back(entry.required ? 1u : 0u);
        output.insert(output.end(), entry.expected_sha256.begin(), entry.expected_sha256.end());
    }
    return output;
}

Sha256 manifest_digest(const SignedManifest& manifest)
{
    const std::vector<std::uint8_t> bytes = canonical_manifest_bytes(manifest);
    return sha256(std::span<const std::uint8_t>(bytes.data(), bytes.size()));
}

void sign_manifest(SignedManifest& manifest, const Ed25519PrivateSeed& privateSeed)
{
    const std::vector<std::uint8_t> message = canonical_manifest_bytes(manifest);
    const PkeyPtr key = privateKey(privateSeed);
    const MdContextPtr context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    std::size_t signatureSize = manifest.signature.size();
    if (!context || EVP_DigestSignInit(context.get(), nullptr, nullptr, nullptr, key.get()) != 1 ||
        EVP_DigestSign(context.get(), manifest.signature.data(), &signatureSize, message.data(), message.size()) != 1 ||
        signatureSize != manifest.signature.size())
        throw std::runtime_error("OpenSSL Ed25519 manifest signing failed");
}

bool verify_manifest_signature(const SignedManifest& manifest, const Ed25519PublicKey& publicKeyBytes)
{
    const std::vector<std::uint8_t> message = canonical_manifest_bytes(manifest);
    const PkeyPtr key = publicKey(publicKeyBytes);
    const MdContextPtr context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!context || EVP_DigestVerifyInit(context.get(), nullptr, nullptr, nullptr, key.get()) != 1)
        throw std::runtime_error("OpenSSL Ed25519 manifest verification initialization failed");
    const int status = EVP_DigestVerify(
        context.get(), manifest.signature.data(), manifest.signature.size(), message.data(), message.size());
    if (status < 0)
        throw std::runtime_error("OpenSSL Ed25519 manifest verification failed");
    return status == 1;
}

ManifestEntry make_manifest_entry(
    const std::filesystem::path& root,
    const std::filesystem::path& relativePath,
    std::string name,
    bool required)
{
    if (!safeRelativePath(relativePath))
        throw std::runtime_error("manifest entry path must be a normalized relative path");
    const std::filesystem::path path = root / relativePath;
    std::error_code error;
    const std::uint64_t size = std::filesystem::file_size(path, error);
    if (error)
        throw std::runtime_error("could not read manifest entry size: " + path.string());

    ManifestEntry entry;
    entry.name = name.empty() ? defaultEntryName(relativePath) : std::move(name);
    entry.relative_path = relativePath;
    entry.expected_size = size;
    entry.expected_sha256 = file_sha256(path);
    entry.required = required;
    return entry;
}

ManifestCheckResult verify_signed_manifest(
    const SignedManifest& manifest,
    const Ed25519PublicKey& publicKeyBytes,
    const ManifestPolicy& policy)
{
    ManifestCheckResult result;
    result.manifest_digest = manifest_digest(manifest);

    if (!verify_manifest_signature(manifest, publicKeyBytes))
    {
        fail(result, {ManifestFindingKind::InvalidSignature, "manifest", "Ed25519 signature verification failed", {}, {}});
        return result;
    }
    if (manifest.version != kManifestVersion)
    {
        fail(result, {ManifestFindingKind::UnsupportedVersion, "manifest", "unsupported signed manifest version",
            std::to_string(kManifestVersion), std::to_string(manifest.version)});
        return result;
    }
    if (!policy.expected_application_id.empty() && manifest.application_id != policy.expected_application_id)
    {
        fail(result, {ManifestFindingKind::ApplicationMismatch, "manifest", "application identity does not match the runtime policy",
            policy.expected_application_id, manifest.application_id});
        return result;
    }
    if (manifest.build_number < policy.minimum_build_number)
    {
        fail(result, {ManifestFindingKind::RollbackDetected, "manifest", "signed build is older than the accepted minimum",
            std::to_string(policy.minimum_build_number), std::to_string(manifest.build_number)});
        return result;
    }
    if (manifest.entries.size() > policy.maximum_entries)
    {
        fail(result, {ManifestFindingKind::TooManyEntries, "manifest", "entry count exceeds the runtime policy",
            std::to_string(policy.maximum_entries), std::to_string(manifest.entries.size())});
        return result;
    }

    std::error_code error;
    const std::filesystem::path canonicalRoot = std::filesystem::weakly_canonical(policy.root, error);
    if (error)
    {
        fail(result, {ManifestFindingKind::ReadError, "manifest", "could not resolve integrity root: " + error.message(), {}, {}});
        return result;
    }

    std::set<std::string> names;
    std::set<std::string> paths;
    for (const ManifestEntry& entry : manifest.entries)
    {
        const std::string relative = entry.relative_path.generic_string();
        if (!names.insert(entry.name).second || !paths.insert(relative).second)
        {
            fail(result, {ManifestFindingKind::DuplicateEntry, entry.name, "duplicate manifest name or path", {}, relative});
            continue;
        }
        if (entry.name.empty() || !safeRelativePath(entry.relative_path))
        {
            fail(result, {ManifestFindingKind::InvalidPath, entry.name, "entry path must be normalized and relative", {}, relative});
            continue;
        }

        const std::filesystem::path path = canonicalRoot / entry.relative_path;
        const bool exists = std::filesystem::exists(path, error);
        if (error || !exists)
        {
            if (entry.required)
                fail(result, {ManifestFindingKind::MissingFile, entry.name, error ? error.message() : path.string(), {}, {}});
            error.clear();
            continue;
        }

        const std::filesystem::file_status symlinkStatus = std::filesystem::symlink_status(path, error);
        if (error)
        {
            fail(result, {ManifestFindingKind::ReadError, entry.name, error.message(), {}, {}});
            error.clear();
            continue;
        }
        if (!policy.allow_symlinks && std::filesystem::is_symlink(symlinkStatus))
        {
            fail(result, {ManifestFindingKind::SymlinkRejected, entry.name, path.string(), {}, {}});
            continue;
        }

        const std::filesystem::path canonicalPath = std::filesystem::weakly_canonical(path, error);
        if (error || !pathWithin(canonicalRoot, canonicalPath))
        {
            fail(result, {ManifestFindingKind::PathEscapesRoot, entry.name,
                error ? error.message() : canonicalPath.string(), canonicalRoot.string(), {}});
            error.clear();
            continue;
        }

        const std::uint64_t observedSize = std::filesystem::file_size(canonicalPath, error);
        if (error)
        {
            fail(result, {ManifestFindingKind::ReadError, entry.name, error.message(), {}, {}});
            error.clear();
            continue;
        }
        if (observedSize > policy.maximum_file_bytes)
        {
            fail(result, {ManifestFindingKind::FileTooLarge, entry.name, canonicalPath.string(),
                std::to_string(policy.maximum_file_bytes), std::to_string(observedSize)});
            continue;
        }
        if (observedSize != entry.expected_size)
        {
            fail(result, {ManifestFindingKind::FileSizeMismatch, entry.name, canonicalPath.string(),
                std::to_string(entry.expected_size), std::to_string(observedSize)});
            continue;
        }

        try
        {
            const std::string expected = hex(entry.expected_sha256);
            const std::string actual = hex(file_sha256(canonicalPath));
            if (!constant_time_equal(expected, actual))
                fail(result, {ManifestFindingKind::FileHashMismatch, entry.name, canonicalPath.string(), expected, actual});
        }
        catch (const std::exception& exception)
        {
            fail(result, {ManifestFindingKind::ReadError, entry.name, exception.what(), {}, {}});
        }
    }
    return result;
}

std::string manifest_finding_kind_name(ManifestFindingKind kind)
{
    switch (kind)
    {
    case ManifestFindingKind::InvalidSignature: return "invalid_signature";
    case ManifestFindingKind::UnsupportedVersion: return "unsupported_version";
    case ManifestFindingKind::ApplicationMismatch: return "application_mismatch";
    case ManifestFindingKind::RollbackDetected: return "rollback_detected";
    case ManifestFindingKind::TooManyEntries: return "too_many_entries";
    case ManifestFindingKind::DuplicateEntry: return "duplicate_entry";
    case ManifestFindingKind::InvalidPath: return "invalid_path";
    case ManifestFindingKind::PathEscapesRoot: return "path_escapes_root";
    case ManifestFindingKind::SymlinkRejected: return "symlink_rejected";
    case ManifestFindingKind::MissingFile: return "missing_file";
    case ManifestFindingKind::FileTooLarge: return "file_too_large";
    case ManifestFindingKind::FileSizeMismatch: return "file_size_mismatch";
    case ManifestFindingKind::FileHashMismatch: return "file_hash_mismatch";
    case ManifestFindingKind::ReadError: return "read_error";
    }
    return "unknown";
}

ManifestGuard::ManifestGuard(SignedManifest manifest, Ed25519PublicKey publicKeyBytes, ManifestPolicy policy)
    : manifest_(std::move(manifest))
    , public_key_(publicKeyBytes)
    , policy_(std::move(policy))
{
}

ManifestGuard& ManifestGuard::on_failure(FailureCallback callback)
{
    failure_ = std::move(callback);
    return *this;
}

ManifestCheckResult ManifestGuard::check() const
{
    return verify_signed_manifest(manifest_, public_key_, policy_);
}

bool ManifestGuard::check_or_fail() const
{
    ManifestCheckResult result = check();
    if (!result.ok && failure_)
        failure_(result);
    return result.ok;
}

} // namespace alex::antitamper
