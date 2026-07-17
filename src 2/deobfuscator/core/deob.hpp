#pragma once

#include <filesystem>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>

#include <nlohmann/json.hpp>

namespace alex::deobfuscator
{

struct Options
{
    std::filesystem::path input;
    std::filesystem::path output_dir;
    std::string mode = "auto";
    std::optional<std::filesystem::path> trace;
    std::optional<uint64_t> trace_window_start;
    std::optional<uint64_t> trace_window_end;
    std::function<void(const nlohmann::json&)> progress;
};

struct Result
{
    int exit_code = 0;
    nlohmann::json report;
};

Result analyze(const Options& options);

} // namespace alex::deobfuscator
