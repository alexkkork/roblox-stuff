// Easy, reusable file-integrity guard.
//
// This intentionally provides tamper evidence instead of anti-debugging,
// process inspection, hidden control flow, or deliberate crash/loop traps.
// Copy this file together with ../single_include/alex_antitamper.h, then build:
//
//   c++ -std=c++20 easy_file_guard.cpp -O2 -o easy_file_guard
//
// Generate hashes:
//
//   ./easy_file_guard hash script.luau settings.json
//
// Verify one or more file/hash pairs:
//
//   ./easy_file_guard verify script.luau 0123...cdef settings.json abcd...7890
//
// Generate copy/paste-ready Guard rules:
//
//   ./easy_file_guard emit script.luau settings.json
//
// For an embedded application, copy the emitted add_file lines into the
// startup path and stop before parsing or executing any protected file.

#include "../single_include/alex_antitamper.h"

#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace fs = std::filesystem;

namespace
{

std::string cpp_string(std::string_view value)
{
    std::string output;
    output.reserve(value.size() + 2);
    output.push_back('"');
    for (unsigned char character : value)
    {
        switch (character)
        {
        case '\\': output += "\\\\"; break;
        case '"': output += "\\\""; break;
        case '\n': output += "\\n"; break;
        case '\r': output += "\\r"; break;
        case '\t': output += "\\t"; break;
        default:
            if (character < 0x20 || character == 0x7f)
            {
                static constexpr char digits[] = "0123456789abcdef";
                output += "\\x";
                output.push_back(digits[(character >> 4) & 0xf]);
                output.push_back(digits[character & 0xf]);
            }
            else
            {
                output.push_back(static_cast<char>(character));
            }
            break;
        }
    }
    output.push_back('"');
    return output;
}

void print_usage(const char* program)
{
    std::cerr
        << "Usage:\n"
        << "  " << program << " hash FILE [FILE ...]\n"
        << "  " << program << " verify FILE SHA256 [FILE SHA256 ...]\n"
        << "  " << program << " emit FILE [FILE ...]\n";
}

int hash_files(int argc, char** argv)
{
    if (argc < 3)
        return 2;

    bool failed = false;
    for (int index = 2; index < argc; ++index)
    {
        const fs::path path = argv[index];
        try
        {
            std::cout << alex::antitamper::hex(alex::antitamper::file_sha256(path))
                      << "  " << path.generic_string() << "\n";
        }
        catch (const std::exception& error)
        {
            failed = true;
            std::cerr << "read_error: " << path << ": " << error.what() << "\n";
        }
    }
    return failed ? 1 : 0;
}

int emit_rules(int argc, char** argv)
{
    if (argc < 3)
        return 2;

    bool failed = false;
    std::cout << "alex::antitamper::Guard guard;\n";
    for (int index = 2; index < argc; ++index)
    {
        const fs::path path = argv[index];
        try
        {
            const std::string digest = alex::antitamper::hex(alex::antitamper::file_sha256(path));
            std::cout << "guard.add_file(" << cpp_string(path.generic_string())
                      << ", " << cpp_string(digest) << ");\n";
        }
        catch (const std::exception& error)
        {
            failed = true;
            std::cerr << "read_error: " << path << ": " << error.what() << "\n";
        }
    }
    std::cout
        << "if (!guard.check_or_fail()) {\n"
        << "    // Refuse to parse, load, or execute the protected files.\n"
        << "    return 1;\n"
        << "}\n";
    return failed ? 1 : 0;
}

int verify_files(int argc, char** argv)
{
    if (argc < 4 || ((argc - 2) % 2) != 0)
        return 2;

    alex::antitamper::Guard guard;
    for (int index = 2; index < argc; index += 2)
        guard.add_file(argv[index], argv[index + 1]);

    const alex::antitamper::CheckResult result = guard.check();
    if (result.ok)
    {
        std::cout << "integrity_ok\n";
        return 0;
    }

    for (const alex::antitamper::Finding& finding : result.findings)
    {
        std::cerr << alex::antitamper::finding_kind_name(finding.kind)
                  << ": " << finding.name;
        if (!finding.detail.empty())
            std::cerr << ": " << finding.detail;
        if (!finding.expected.empty())
            std::cerr << "\n  expected: " << finding.expected;
        if (!finding.actual.empty())
            std::cerr << "\n  actual:   " << finding.actual;
        std::cerr << "\n";
    }
    return 1;
}

} // namespace

int main(int argc, char** argv)
{
    if (argc < 2)
    {
        print_usage(argv[0]);
        return 2;
    }

    const std::string_view command = argv[1];
    int result = 2;
    if (command == "hash")
        result = hash_files(argc, argv);
    else if (command == "verify")
        result = verify_files(argc, argv);
    else if (command == "emit")
        result = emit_rules(argc, argv);

    if (result == 2)
        print_usage(argv[0]);
    return result;
}
