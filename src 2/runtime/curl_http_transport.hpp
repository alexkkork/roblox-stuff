#pragma once

#include "network_broker.hpp"

#include <chrono>
#include <memory>
#include <string>

namespace rbx::runtime
{

struct CurlHttpTransportOptions
{
    NetworkLimits limits;
    std::chrono::milliseconds connectTimeout{10000};
    std::string userAgent = "RobloxLuauRuntime/3.0";
};

// Production libcurl transport. curl_global_init must be called by the process
// before construction. Every request uses a fresh direct connection, manually
// resolved and pinned to addresses authorized by NetworkGuard before connect.
class CurlHttpTransport final : public IHttpTransport
{
public:
    explicit CurlHttpTransport(CurlHttpTransportOptions options = {});
    ~CurlHttpTransport() override;

    CurlHttpTransport(const CurlHttpTransport&) = delete;
    CurlHttpTransport& operator=(const CurlHttpTransport&) = delete;

    NetworkResult perform(const NetworkRequest& request, const TransportContext& context) override;
    const CurlHttpTransportOptions& options() const;

private:
    CurlHttpTransportOptions options_;
};

std::shared_ptr<IHttpTransport> makeCurlHttpTransport(CurlHttpTransportOptions options = {});

} // namespace rbx::runtime
