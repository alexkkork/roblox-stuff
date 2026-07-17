#include "guard.h"

#include <iostream>

int main()
{
    rt::Rules rules = rt::defaults("729", "put-your-api-sha256-here");
    rules.place = 123456;
    rules.universe = 987654;
    rules.job = "server-job-id";

    rt::State state;
    state.ready = true;
    state.sealed = true;
    state.release = "729";
    state.api = "put-your-api-sha256-here";
    state.schema = "1";
    state.hasGame = true;
    state.gameNative = true;
    state.gameMatch = true;
    state.gameId = 1;
    state.gameType = "DataModel";
    state.place = 123456;
    state.universe = 987654;
    state.placeVersion = 1;
    state.job = "server-job-id";
    state.hasWorkspace = true;
    state.workspaceNative = true;
    state.workspaceMatch = true;
    state.workspaceAlias = true;
    state.workspaceId = 2;
    state.workspaceParent = 1;
    state.workspaceType = "Workspace";

    uint64_t id = 2;
    for (const std::string& type : rules.services)
        state.children.push_back({id++, 1, type, type, true, true, false});

    const bool ok = rt::enforce(state, rules, [](const rt::Result& result) {
        for (const rt::Hit& hit : result.hits)
            std::cerr << hit.code << ": " << hit.item << " wanted " << hit.wanted << ", got " << hit.got << '\n';
    });

    std::cout << (ok ? "runtime check passed\n" : "runtime check failed\n");
    return ok ? 0 : 1;
}
