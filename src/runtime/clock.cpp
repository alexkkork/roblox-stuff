#include "clock.hpp"

#include <cmath>
#include <stdexcept>

namespace rbx::runtime
{

VirtualClock::VirtualClock(int64_t epochMillis, double initialSeconds)
    : epochMillis_(epochMillis)
    , now_(initialSeconds)
{
    if (!std::isfinite(initialSeconds) || initialSeconds < 0.0)
        throw std::invalid_argument("virtual clock initial time must be finite and non-negative");
}

ClockMode VirtualClock::mode() const
{
    return ClockMode::Virtual;
}

double VirtualClock::now() const
{
    return now_;
}

int64_t VirtualClock::unixMillis() const
{
    return epochMillis_ + static_cast<int64_t>(std::floor(now_ * 1000.0));
}

bool VirtualClock::advanceTo(double monotonicSeconds)
{
    if (!std::isfinite(monotonicSeconds) || monotonicSeconds < now_)
        return false;
    now_ = monotonicSeconds;
    return true;
}

bool VirtualClock::advanceBy(double seconds)
{
    return std::isfinite(seconds) && seconds >= 0.0 && advanceTo(now_ + seconds);
}

RealtimeClock::RealtimeClock()
    : steadyStart_(std::chrono::steady_clock::now())
    , wallStart_(std::chrono::system_clock::now())
{
}

ClockMode RealtimeClock::mode() const
{
    return ClockMode::Realtime;
}

double RealtimeClock::now() const
{
    return std::chrono::duration<double>(std::chrono::steady_clock::now() - steadyStart_).count();
}

int64_t RealtimeClock::unixMillis() const
{
    const auto wall = wallStart_ + std::chrono::duration_cast<std::chrono::system_clock::duration>(
                                      std::chrono::duration<double>(now()));
    return std::chrono::duration_cast<std::chrono::milliseconds>(wall.time_since_epoch()).count();
}

bool RealtimeClock::advanceTo(double)
{
    return false;
}

std::shared_ptr<RuntimeClock> makeClock(ClockMode mode, int64_t virtualEpochMillis)
{
    if (mode == ClockMode::Virtual)
        return std::make_shared<VirtualClock>(virtualEpochMillis);
    return std::make_shared<RealtimeClock>();
}

} // namespace rbx::runtime
