#include "alex/antitamper.hpp"

#include <iostream>

int main()
{
    static const unsigned char region[] = {1, 2, 3, 4, 5};

    alex::antitamper::Guard guard;
    guard.seal_memory("region", region, sizeof(region));
    guard.on_failure([](const alex::antitamper::CheckResult& result) {
        for (const auto& finding : result.findings)
            std::cerr << alex::antitamper::finding_kind_name(finding.kind) << ":" << finding.name << "\n";
    });

    return guard.check_or_fail() ? 0 : 1;
}
