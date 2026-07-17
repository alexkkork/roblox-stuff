#include "alex/signed_integrity.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <string_view>

namespace fs = std::filesystem;
namespace anti = alex::antitamper;

namespace
{

bool require(bool condition, std::string_view message)
{
    if (!condition)
        std::cerr << "signed_integrity_test: " << message << '\n';
    return condition;
}

void write(const fs::path& path, std::string_view value)
{
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output.write(value.data(), static_cast<std::streamsize>(value.size()));
}

bool has(const anti::ManifestCheckResult& result, anti::ManifestFindingKind kind)
{
    for (const anti::ManifestFinding& finding : result.findings)
        if (finding.kind == kind)
            return true;
    return false;
}

} // namespace

int main()
{
    bool ok = true;
    const fs::path root = fs::temp_directory_path() / "alex-signed-integrity-test";
    std::error_code error;
    fs::remove_all(root, error);
    fs::create_directories(root);
    write(root / "vm.bin", "protected-vm-image");
    write(root / "config.bin", "configuration");

    anti::Ed25519PrivateSeed seed{};
    for (size_t index = 0; index < seed.size(); ++index)
        seed[index] = static_cast<std::uint8_t>(index * 7 + 3);
    const anti::Ed25519PublicKey publicKey = anti::ed25519_public_key(seed);

    anti::SignedManifest manifest;
    manifest.application_id = "alex-vm";
    manifest.build_number = 42;
    manifest.entries.push_back(anti::make_manifest_entry(root, "vm.bin", "vm-image"));
    manifest.entries.push_back(anti::make_manifest_entry(root, "config.bin", "config"));
    anti::sign_manifest(manifest, seed);

    anti::ManifestPolicy policy;
    policy.root = root;
    policy.expected_application_id = "alex-vm";
    policy.minimum_build_number = 40;
    anti::ManifestCheckResult result = anti::verify_signed_manifest(manifest, publicKey, policy);
    ok &= require(result.ok && result.findings.empty(), "valid signed manifest failed");
    ok &= require(result.manifest_digest == anti::manifest_digest(manifest), "manifest digest is unstable");

    anti::SignedManifest forged = manifest;
    forged.entries[0].expected_size += 1;
    result = anti::verify_signed_manifest(forged, publicKey, policy);
    ok &= require(!result.ok && has(result, anti::ManifestFindingKind::InvalidSignature),
        "manifest field mutation did not invalidate the signature");

    anti::Ed25519PrivateSeed otherSeed = seed;
    otherSeed[0] ^= 0x55;
    result = anti::verify_signed_manifest(manifest, anti::ed25519_public_key(otherSeed), policy);
    ok &= require(!result.ok && has(result, anti::ManifestFindingKind::InvalidSignature), "wrong public key was accepted");

    anti::ManifestPolicy wrongApplication = policy;
    wrongApplication.expected_application_id = "another-app";
    result = anti::verify_signed_manifest(manifest, publicKey, wrongApplication);
    ok &= require(!result.ok && has(result, anti::ManifestFindingKind::ApplicationMismatch), "application binding was ignored");

    anti::ManifestPolicy rollback = policy;
    rollback.minimum_build_number = 43;
    result = anti::verify_signed_manifest(manifest, publicKey, rollback);
    ok &= require(!result.ok && has(result, anti::ManifestFindingKind::RollbackDetected), "rollback policy was ignored");

    write(root / "vm.bin", "protected-vm-imagf");
    result = anti::verify_signed_manifest(manifest, publicKey, policy);
    ok &= require(!result.ok && has(result, anti::ManifestFindingKind::FileHashMismatch), "same-size payload mutation was not detected");
    write(root / "vm.bin", "short");
    result = anti::verify_signed_manifest(manifest, publicKey, policy);
    ok &= require(!result.ok && has(result, anti::ManifestFindingKind::FileSizeMismatch), "payload size mutation was not detected");
    write(root / "vm.bin", "protected-vm-image");

    fs::remove(root / "config.bin");
    result = anti::verify_signed_manifest(manifest, publicKey, policy);
    ok &= require(!result.ok && has(result, anti::ManifestFindingKind::MissingFile), "required missing file was not detected");

    anti::SignedManifest optional = manifest;
    optional.entries[1].required = false;
    anti::sign_manifest(optional, seed);
    result = anti::verify_signed_manifest(optional, publicKey, policy);
    ok &= require(result.ok, "optional missing file failed verification");

    anti::SignedManifest duplicate = optional;
    duplicate.entries.push_back(duplicate.entries[0]);
    anti::sign_manifest(duplicate, seed);
    result = anti::verify_signed_manifest(duplicate, publicKey, policy);
    ok &= require(!result.ok && has(result, anti::ManifestFindingKind::DuplicateEntry), "duplicate signed entry was accepted");

    anti::SignedManifest traversal = optional;
    traversal.entries[0].relative_path = "../vm.bin";
    anti::sign_manifest(traversal, seed);
    result = anti::verify_signed_manifest(traversal, publicKey, policy);
    ok &= require(!result.ok && has(result, anti::ManifestFindingKind::InvalidPath), "path traversal entry was accepted");

    bool callbackInvoked = false;
    anti::ManifestGuard guard(traversal, publicKey, policy);
    guard.on_failure([&](const anti::ManifestCheckResult&) { callbackInvoked = true; });
    ok &= require(!guard.check_or_fail() && callbackInvoked, "fail-closed callback was not invoked");

    fs::remove_all(root, error);
    if (!ok)
        return 1;
    std::cout << "signed-integrity-unit-ok\n";
    return 0;
}
