#include "guard.h"

#include <sstream>
#include <utility>

namespace rt
{
namespace
{

std::string yes(bool value)
{
    return value ? "true" : "false";
}

template<typename T>
std::string text(const std::optional<T>& value)
{
    if (!value)
        return "missing";
    std::ostringstream out;
    out << *value;
    return out.str();
}

template<>
std::string text(const std::optional<std::string>& value)
{
    return value ? *value : "missing";
}

class Run
{
public:
    void need(bool pass, std::string code, std::string item, std::string wanted, std::string got)
    {
        ++result.checks;
        if (!pass)
            result.hits.push_back({std::move(code), std::move(item), std::move(wanted), std::move(got)});
    }

    Result done()
    {
        result.ok = result.hits.empty();
        return std::move(result);
    }

private:
    Result result;
};

} // namespace

Rules defaults(std::string release, std::string api, std::string schema)
{
    Rules rules;
    rules.release = std::move(release);
    rules.api = std::move(api);
    rules.schema = std::move(schema);
    rules.services = {
        "Workspace",
        "RunService",
        "Players",
        "HttpService",
        "CollectionService",
        "TweenService",
        "Debris",
        "UserInputService",
        "ContextActionService",
    };
    return rules;
}

Result check(const State& state, const Rules& rules)
{
    Run run;
    run.need(state.ready, "engine_missing", "engine", "ready", "missing");
    if (rules.sealed)
        run.need(state.sealed, "engine_open", "engine", "sealed", "still booting");
    if (!rules.release.empty())
        run.need(state.release == rules.release, "release_changed", "release", rules.release, state.release);
    if (!rules.api.empty())
        run.need(state.api == rules.api, "api_changed", "API hash", rules.api, state.api);
    if (!rules.schema.empty())
        run.need(state.schema == rules.schema, "schema_changed", "API schema", rules.schema, state.schema);
    run.need(state.errors.empty(), "scan_failed", "native scan", "no errors", state.errors.empty() ? "no errors" : state.errors.front());

    run.need(state.hasGame, "game_missing", "game", "DataModel", "missing");
    run.need(state.gameNative, "game_fake", "game", "native userdata", "not native");
    run.need(state.gameMatch, "game_swapped", "game", "registry identity", yes(state.gameMatch));
    run.need(state.gameType == "DataModel", "game_type", "game.ClassName", "DataModel", state.gameType);
    run.need(!state.gameDead, "game_dead", "game", "live", state.gameDead ? "dead" : "live");
    run.need(state.gameId != 0, "game_id", "game registry id", "non-zero", std::to_string(state.gameId));
    run.need(state.gameParent == 0, "game_parent", "game.Parent", "nil", std::to_string(state.gameParent));
    run.need(state.placeVersion && *state.placeVersion >= 1, "place_version", "game.PlaceVersion", ">= 1", text(state.placeVersion));

    if (rules.place)
        run.need(state.place == rules.place, "place_changed", "game.PlaceId", text(rules.place), text(state.place));
    if (rules.universe)
        run.need(state.universe == rules.universe, "universe_changed", "game.GameId", text(rules.universe), text(state.universe));
    if (rules.job)
        run.need(state.job == rules.job, "job_changed", "game.JobId", text(rules.job), text(state.job));

    run.need(state.hasWorkspace, "workspace_missing", "workspace", "Workspace", "missing");
    run.need(state.workspaceNative, "workspace_fake", "workspace", "native userdata", "not native");
    run.need(state.workspaceMatch, "workspace_swapped", "workspace", "registry identity", yes(state.workspaceMatch));
    if (rules.workspaceAlias)
        run.need(state.workspaceAlias, "workspace_alias", "Workspace", "same object as workspace", yes(state.workspaceAlias));
    run.need(state.workspaceType == "Workspace", "workspace_type", "workspace.ClassName", "Workspace", state.workspaceType);
    run.need(!state.workspaceDead, "workspace_dead", "workspace", "live", state.workspaceDead ? "dead" : "live");
    run.need(state.workspaceParent == state.gameId && state.gameId != 0, "workspace_parent", "workspace.Parent", "game",
        std::to_string(state.workspaceParent));

    for (const std::string& wanted : rules.services)
    {
        const Obj* found = nullptr;
        std::size_t count = 0;
        for (const Obj& child : state.children)
        {
            if (child.type != wanted)
                continue;
            found = &child;
            ++count;
        }

        run.need(count == 1, "service_count", wanted, "one DataModel child", std::to_string(count));
        if (count != 1)
            continue;
        run.need(found->parent == state.gameId, "service_parent", wanted + ".Parent", "game", std::to_string(found->parent));
        run.need(found->service, "service_tag", wanted, "Service tag", "not tagged");
        run.need(!found->dead, "service_dead", wanted, "live", found->dead ? "dead" : "live");
        if (rules.nativeServices)
            run.need(found->native, "service_fake", wanted, "native registry object", "not native");
    }

    return run.done();
}

bool enforce(const State& state, const Rules& rules, const std::function<void(const Result&)>& fail)
{
    const Result result = check(state, rules);
    if (!result.ok && fail)
        fail(result);
    return result.ok;
}

} // namespace rt
