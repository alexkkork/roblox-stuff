#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace rt
{

struct Obj
{
    uint64_t id = 0;
    uint64_t parent = 0;
    std::string type;
    std::string name;
    bool service = false;
    bool native = false;
    bool dead = false;
};

struct State
{
    bool ready = false;
    bool sealed = false;
    std::string release;
    std::string api;
    std::string schema;

    bool hasGame = false;
    bool gameNative = false;
    bool gameMatch = false;
    uint64_t gameId = 0;
    uint64_t gameParent = 0;
    std::string gameType;
    bool gameDead = false;

    std::optional<int64_t> place;
    std::optional<int64_t> universe;
    std::optional<int64_t> placeVersion;
    std::optional<std::string> job;

    bool hasWorkspace = false;
    bool workspaceNative = false;
    bool workspaceMatch = false;
    bool workspaceAlias = false;
    uint64_t workspaceId = 0;
    uint64_t workspaceParent = 0;
    std::string workspaceType;
    bool workspaceDead = false;

    std::vector<Obj> children;
    std::vector<std::string> errors;
};

struct Rules
{
    std::string release;
    std::string api;
    std::string schema;
    std::optional<int64_t> place;
    std::optional<int64_t> universe;
    std::optional<std::string> job;
    std::vector<std::string> services;
    bool sealed = true;
    bool workspaceAlias = true;
    bool nativeServices = true;
};

struct Hit
{
    std::string code;
    std::string item;
    std::string wanted;
    std::string got;
};

struct Result
{
    bool ok = false;
    std::size_t checks = 0;
    std::vector<Hit> hits;
};

Rules defaults(std::string release, std::string api, std::string schema = "1");
Result check(const State& state, const Rules& rules);
bool enforce(const State& state, const Rules& rules, const std::function<void(const Result&)>& fail = {});

} // namespace rt
