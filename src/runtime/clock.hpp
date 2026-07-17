#pragma once

#include <chrono>
#include <cstdint>
#include <memory>

namespace rbx::runtime
{

enum class ClockMode
{
    Virtual,
    Realtime,
};

class RuntimeClock
{
public:
    virtual ~RuntimeClock() = default;
    virtual ClockMode mode() const = 0;
    virtual double now() const = 0;
    virtual int64_t unixMillis() const = 0;
    virtual bool advanceTo(double monotonicSeconds) = 0;
};

class VirtualClock final : public RuntimeClock
{
public:
    explicit VirtualClock(int64_t epochMillis = 0, double initialSeconds = 0.0);

    ClockMode mode() const override;
    double now() const override;
    int64_t unixMillis() const override;
    bool advanceTo(double monotonicSeconds) override;
    bool advanceBy(double seconds);

private:
    int64_t epochMillis_;
    double now_;
};

class RealtimeClock final : public RuntimeClock
{
public:
    RealtimeClock();

    ClockMode mode() const override;
    double now() const override;
    int64_t unixMillis() const override;
    bool advanceTo(double monotonicSeconds) override;

private:
    std::chrono::steady_clock::time_point steadyStart_;
    std::chrono::system_clock::time_point wallStart_;
};

std::shared_ptr<RuntimeClock> makeClock(ClockMode mode, int64_t virtualEpochMillis = 0);

} // namespace rbx::runtime
