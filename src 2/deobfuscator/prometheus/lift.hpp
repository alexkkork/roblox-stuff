#pragma once

#include <cstdint>
#include <map>
#include <set>
#include <string>

#include <nlohmann/json.hpp>

namespace alex::deobfuscator::prometheus
{

struct LiftRequest
{
    const std::map<int64_t, nlohmann::json>& blocks;
    const nlohmann::json& prototypes;
    int64_t payload_entry = 0;
    const std::set<int64_t>& payload_blocks;
};

struct LiftResult
{
    bool family_recognized = false;
    bool complete = false;
    std::string source;
    std::string reason;
    nlohmann::json mapping = nlohmann::json::array();
    nlohmann::json decoded_strings = nlohmann::json::array();
    size_t lifted_instructions = 0;
    size_t emitted_statements = 0;
    size_t reconstructed_prototypes = 0;
};

LiftResult lift(const LiftRequest& request);

} // namespace alex::deobfuscator::prometheus
