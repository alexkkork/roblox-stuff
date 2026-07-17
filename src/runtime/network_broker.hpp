#pragma once

#include "scheduler.hpp"

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace rbx::runtime
{

using NetworkRequestId = uint64_t;

enum class NetworkMode : uint8_t
{
    Offline,
    Allowlist,
    Live,
};

enum class NetworkError : uint8_t
{
    None,
    Offline,
    HostNotAllowed,
    InvalidUrl,
    PrivateAddressBlocked,
    InvalidRequest,
    QueueFull,
    Cancelled,
    Timeout,
    TransportFailure,
    TooManyRedirects,
    HeadersTooLarge,
    BodyTooLarge,
    InvalidRedirect,
};

struct NetworkLimits
{
    std::size_t maxRequestBodyBytes = 4 * 1024 * 1024;
    std::size_t maxResponseBodyBytes = 16 * 1024 * 1024;
    std::size_t maxHeaderBytes = 64 * 1024;
    std::size_t maxHeaders = 128;
    std::size_t maxRedirects = 5;
    std::size_t maxConcurrent = 8;
    std::size_t maxQueued = 64;
    std::chrono::milliseconds maxTimeout{30000};
};

struct NetworkPolicyConfig
{
    NetworkMode mode = NetworkMode::Offline;
    std::set<std::string, std::less<>> allowedHosts;
    bool allowPrivateNetwork = false;
    NetworkLimits limits;
};

struct ParsedUrl
{
    std::string scheme;
    std::string host;
    std::optional<uint16_t> port;
    std::string target;
};

struct NetworkHop
{
    std::string url;
    std::vector<std::string> resolvedAddresses;
};

struct NetworkRequest
{
    std::string method = "GET";
    std::string url;
    std::map<std::string, std::string, std::less<>> headers;
    std::string body;
    std::chrono::milliseconds timeout{30000};
    std::size_t redirectLimit = 5;
};

struct NetworkResponse
{
    int statusCode = 0;
    std::string statusMessage;
    std::map<std::string, std::string, std::less<>> headers;
    std::string body;
    std::vector<NetworkHop> hops;
    double deterministicLatencySeconds = 0.0;
};

struct NetworkResult
{
    NetworkError error = NetworkError::None;
    std::string message;
    std::string requiredHost;
    NetworkResponse response;

    explicit operator bool() const
    {
        return error == NetworkError::None;
    }
};

class NetworkGuard
{
public:
    explicit NetworkGuard(NetworkPolicyConfig config);

    const NetworkPolicyConfig& config() const;
    NetworkResult authorizeRequest(const NetworkRequest& request) const;
    NetworkResult authorizeHop(std::string_view url, const std::vector<std::string>& resolvedAddresses) const;
    NetworkResult validateResponse(const NetworkRequest& request, const NetworkResponse& response) const;

    static std::optional<ParsedUrl> parseUrl(std::string_view url);
    static std::string normalizeHost(std::string_view host);
    static bool isPublicAddress(std::string_view address);

private:
    bool hostAllowed(std::string_view host) const;
    NetworkPolicyConfig config_;
};

struct TransportContext
{
    std::function<NetworkResult(std::string_view, const std::vector<std::string>&)> authorizeEndpoint;
    std::function<bool()> cancelled;
};

class IHttpTransport
{
public:
    virtual ~IHttpTransport() = default;

    // Transports MUST resolve a destination first and invoke authorizeEndpoint
    // before connecting, for the initial URL and every redirect. This is the
    // pre-connect half of DNS-rebinding and redirect protection; the broker also
    // validates the returned hop trace after completion.
    virtual NetworkResult perform(const NetworkRequest& request, const TransportContext& context) = 0;
};

struct NetworkBrokerStats
{
    std::size_t queued = 0;
    std::size_t active = 0;
    std::size_t pending = 0;
    uint64_t submitted = 0;
    uint64_t completed = 0;
    uint64_t rejected = 0;
    uint64_t cancelled = 0;
};

class NetworkBroker
{
public:
    using Completion = std::function<void(NetworkResult)>;

    NetworkBroker(Scheduler& scheduler, NetworkPolicyConfig policy, std::shared_ptr<IHttpTransport> transport);
    ~NetworkBroker();

    NetworkBroker(const NetworkBroker&) = delete;
    NetworkBroker& operator=(const NetworkBroker&) = delete;

    NetworkRequestId submit(NetworkRequest request, Completion completion);
    bool cancel(NetworkRequestId id);
    NetworkBrokerStats stats() const;
    const NetworkGuard& guard() const;

private:
    struct Impl;
    std::shared_ptr<Impl> impl_;
};

struct NetworkFixture
{
    NetworkResult result;
};

class FixtureHttpTransport final : public IHttpTransport
{
public:
    void add(std::string url, NetworkFixture fixture);
    bool remove(std::string_view url);
    void clear();
    NetworkResult perform(const NetworkRequest& request, const TransportContext& context) override;

private:
    std::map<std::string, NetworkFixture, std::less<>> fixtures_;
};

std::string_view toString(NetworkMode mode);
std::string_view toString(NetworkError error);

} // namespace rbx::runtime
