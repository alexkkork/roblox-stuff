#include "core/deob.hpp"

#include <exception>
#include <iostream>
#include <stdexcept>

namespace fs = std::filesystem;

namespace
{

void printUsage()
{
    std::cerr << "usage: alex_deobfuscator INPUT --output-dir DIR [--mode auto|exact|reconstruct|disassemble] [--trace PATH] [--trace-window START END] [--progress-jsonl] [--report PATH|-]\n";
}

} // namespace

int main(int argc, char** argv)
{
    try
    {
        alex::deobfuscator::Options options;
        std::optional<std::string> reportTarget;

        for (int i = 1; i < argc; ++i)
        {
            std::string arg = argv[i];
            if (arg == "--help" || arg == "-h")
            {
                printUsage();
                return 0;
            }
            if (arg == "--output-dir" && i + 1 < argc)
                options.output_dir = argv[++i];
            else if (arg == "--mode" && i + 1 < argc)
                options.mode = argv[++i];
            else if (arg == "--trace" && i + 1 < argc)
                options.trace = fs::path(argv[++i]);
            else if (arg == "--trace-window" && i + 2 < argc)
            {
                options.trace_window_start = std::stoull(argv[++i]);
                options.trace_window_end = std::stoull(argv[++i]);
                if (*options.trace_window_start == 0 || *options.trace_window_end < *options.trace_window_start)
                    throw std::runtime_error("--trace-window requires START > 0 and END >= START");
            }
            else if (arg == "--progress-jsonl")
                options.progress = [](const nlohmann::json& event) {
                    std::cerr << "@@ALEX_PROGRESS@@" << event.dump() << '\n';
                    std::cerr.flush();
                };
            else if (arg == "--report" && i + 1 < argc)
                reportTarget = argv[++i];
            else if (!arg.empty() && arg[0] != '-' && options.input.empty())
                options.input = arg;
            else
                throw std::runtime_error("unknown or incomplete argument: " + arg);
        }

        if (options.input.empty() || options.output_dir.empty())
        {
            printUsage();
            return 1;
        }

        alex::deobfuscator::Result result = alex::deobfuscator::analyze(options);
        if (reportTarget && *reportTarget == "-")
            std::cout << result.report.dump() << '\n';
        else if (reportTarget)
        {
            fs::copy_file(options.output_dir / "deobfuscation_report.json", *reportTarget, fs::copy_options::overwrite_existing);
        }
        else
        {
            std::cout << "Status: " << result.report.value("status", "blocked") << '\n';
            std::cout << "Report: " << (options.output_dir / "deobfuscation_report.json") << '\n';
        }
        return result.exit_code;
    }
    catch (const std::exception& error)
    {
        std::cerr << "alex_deobfuscator: " << error.what() << '\n';
        return 1;
    }
}
