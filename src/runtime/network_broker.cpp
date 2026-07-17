#include "network_broker.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <condition_variable>
#include <deque>
#include <limits>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <unordered_map>
#include <utility>

namespace rbx::runtime
{
namespace
{

NetworkResult failure(NetworkError error, std::string message, std::string host = {})
{
    NetworkResult result;
    result.error = error;
    result.message = std::move(message);
    result.requiredHost = std::move(host);
    return result;
}

bool validMethod(std::string_view method)
{
    if (method.empty() || method.size() > 16)
        return false;
    return std::all_of(method.begin(), method.end(), [](unsigned char character) {
        return character >= 'A' && character <= 'Z';
    });
}

bool validHeader(std::string_view name, std::string_view value)
{
    if (name.empty() || name.size() > 256 || value.find_first_of("\r\n") != std::string_view::npos)
        return false;
    return std::all_of(name.begin(), name.end(), [](unsigned char character) {
        return std::isalnum(character) || character == '-' || character == '_';
    });
}

std::size_t headerBytes(const std::map<std::string, std::string, std::less<>>& headers)
{
    std::size_t result = 0;
    for (const auto& [name, value] : headers)
    {
        if (name.size() > std::numeric_limits<std::size_t>::max() - result || value.size() > std::numeric_limits<std::size_t>::max() - result - name.size())
            return std::numeric_limits<std::size_t>::max();
        result += name.size() + value.size() + 4;
    }
    return result;
}

std::optional<std::array<unsigned, 4>> parseIpv4(std::string_view address)
{
    std::array<unsigned, 4> parts{};
    std::size_t start = 0;
    for (std::size_t index = 0; index < parts.size(); ++index)
    {
        const std::size_t end = address.find('.', start);
        const std::size_t stop = end == std::string_view::npos ? address.size() : end;
        if (stop == start || (index < 3 && end == std::string_view::npos) || (index == 3 && end != std::string_view::npos))
            return std::nullopt;
        unsigned value = 0;
        const char* first = address.data() + start;
        const char* last = address.data() + stop;
        auto parsed = std::from_chars(first, last, value, 10);
        if (parsed.ec != std::errc{} || parsed.ptr != last || value > 255 || (stop - start > 1 && address[start] == '0'))
            return std::nullopt;
        parts[index] = value;
        start = stop + 1;
    }
    return parts;
}

std::optional<std::array<unsigned char, 16>> parseIpv6(std::string_view address)
{
    if (address.empty() || address.find('%') != std::string_view::npos)
        return std::nullopt;
    if ((address.front() == ':' && !address.starts_with("::")) || (address.back() == ':' && !address.ends_with("::")))
        return std::nullopt;

    const std::size_t compression = address.find("::");
    if (compression != std::string_view::npos && address.find("::", compression + 2) != std::string_view::npos)
        return std::nullopt;

    auto parseWords = [](std::string_view part, std::vector<uint16_t>& words) {
        if (part.empty())
            return true;
        std::size_t start = 0;
        while (start < part.size())
        {
            const std::size_t colon = part.find(':', start);
            const std::size_t stop = colon == std::string_view::npos ? part.size() : colon;
            if (stop == start)
                return false;
            const std::string_view token = part.substr(start, stop - start);
            if (token.find('.') != std::string_view::npos)
            {
                if (colon != std::string_view::npos)
                    return false;
                const std::optional<std::array<unsigned, 4>> ipv4 = parseIpv4(token);
                if (!ipv4)
                    return false;
                words.push_back(static_cast<uint16_t>(((*ipv4)[0] << 8) | (*ipv4)[1]));
                words.push_back(static_cast<uint16_t>(((*ipv4)[2] << 8) | (*ipv4)[3]));
            }
            else
            {
                if (token.size() > 4)
                    return false;
                unsigned value = 0;
                const auto parsed = std::from_chars(token.data(), token.data() + token.size(), value, 16);
                if (parsed.ec != std::errc{} || parsed.ptr != token.data() + token.size() || value > 0xffff)
                    return false;
                words.push_back(static_cast<uint16_t>(value));
            }
            if (words.size() > 8)
                return false;
            if (colon == std::string_view::npos)
                break;
            start = colon + 1;
        }
        return true;
    };

    std::vector<uint16_t> words;
    if (compression == std::string_view::npos)
    {
        if (!parseWords(address, words) || words.size() != 8)
            return std::nullopt;
    }
    else
    {
        std::vector<uint16_t> suffix;
        if (!parseWords(address.substr(0, compression), words) || !parseWords(address.substr(compression + 2), suffix) ||
            words.size() + suffix.size() >= 8)
            return std::nullopt;
        words.resize(8 - suffix.size(), 0);
        words.insert(words.end(), suffix.begin(), suffix.end());
    }

    std::array<unsigned char, 16> bytes{};
    for (std::size_t index = 0; index < words.size(); ++index)
    {
        bytes[index * 2] = static_cast<unsigned char>(words[index] >> 8);
        bytes[index * 2 + 1] = static_cast<unsigned char>(words[index] & 0xff);
    }
    return bytes;
}

bool publicIpv4(const std::array<unsigned, 4>& value)
{
    const unsigned a = value[0];
    const unsigned b = value[1];
    if (a == 0 || a == 10 || a == 127 || a >= 224)
        return false;
    if (a == 100 && b >= 64 && b <= 127)
        return false;
    if (a == 169 && b == 254)
        return false;
    if (a == 172 && b >= 16 && b <= 31)
        return false;
    if (a == 192 && (b == 0 || b == 168))
        return false;
    if (a == 192 && b == 88 && value[2] == 99)
        return false;
    if (a == 198 && (b == 18 || b == 19))
        return false;
    if (a == 198 && b == 51 && value[2] == 100)
        return false;
    if (a == 203 && b == 0 && value[2] == 113)
        return false;
    return true;
}

bool publicEmbeddedIpv4(const std::array<unsigned char, 16>& bytes, std::size_t offset, bool inverted = false)
{
    std::array<unsigned, 4> address{};
    for (std::size_t index = 0; index < address.size(); ++index)
        address[index] = inverted ? static_cast<unsigned>(bytes[offset + index] ^ 0xff) : bytes[offset + index];
    return publicIpv4(address);
}

bool allDigitsOrDots(std::string_view value)
{
    return !value.empty() && std::all_of(value.begin(), value.end(), [](unsigned char character) {
        return std::isdigit(character) || character == '.';
    });
}

std::string lowercase(std::string_view text)
{
    std::string result(text);
    std::transform(result.begin(), result.end(), result.begin(), [](unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
    return result;
}

} // namespace

NetworkGuard::NetworkGuard(NetworkPolicyConfig config)
    : config_(std::move(config))
{
    std::set<std::string, std::less<>> normalized;
    for (const std::string& host : config_.allowedHosts)
    {
        std::string value = host;
        if (value.starts_with("*."))
            value = "*." + normalizeHost(std::string_view(value).substr(2));
        else
            value = normalizeHost(value);
        if (!value.empty())
            normalized.insert(std::move(value));
    }
    config_.allowedHosts = std::move(normalized);
    if (config_.limits.maxConcurrent == 0 || config_.limits.maxQueued == 0)
        throw std::invalid_argument("network concurrency and queue limits must be non-zero");
}

const NetworkPolicyConfig& NetworkGuard::config() const
{
    return config_;
}

NetworkResult NetworkGuard::authorizeRequest(const NetworkRequest& request) const
{
    const std::optional<ParsedUrl> parsed = parseUrl(request.url);
    if (!parsed)
        return failure(NetworkError::InvalidUrl, "network URL must use HTTP or HTTPS and be well-formed");
    if (config_.mode == NetworkMode::Offline)
        return failure(NetworkError::Offline, "network access is disabled", parsed->host);
    if (!hostAllowed(parsed->host))
        return failure(NetworkError::HostNotAllowed, "host is not in the network allowlist", parsed->host);
    if (!validMethod(request.method))
        return failure(NetworkError::InvalidRequest, "HTTP method must contain uppercase ASCII letters only", parsed->host);
    if (request.headers.size() > config_.limits.maxHeaders || headerBytes(request.headers) > config_.limits.maxHeaderBytes)
        return failure(NetworkError::HeadersTooLarge, "request headers exceed configured limits", parsed->host);
    for (const auto& [name, value] : request.headers)
    {
        if (!validHeader(name, value))
            return failure(NetworkError::InvalidRequest, "request contains an invalid header", parsed->host);
    }
    if (request.body.size() > config_.limits.maxRequestBodyBytes)
        return failure(NetworkError::BodyTooLarge, "request body exceeds configured limit", parsed->host);
    if (request.redirectLimit > config_.limits.maxRedirects)
        return failure(NetworkError::TooManyRedirects, "requested redirect limit exceeds policy", parsed->host);
    if (request.timeout.count() <= 0 || request.timeout > config_.limits.maxTimeout)
        return failure(NetworkError::InvalidRequest, "request timeout exceeds policy", parsed->host);

    if (!config_.allowPrivateNetwork && (allDigitsOrDots(parsed->host) || parsed->host.find(':') != std::string::npos) && !isPublicAddress(parsed->host))
        return failure(NetworkError::PrivateAddressBlocked, "private, local, or non-canonical address is blocked", parsed->host);
    return {};
}

NetworkResult NetworkGuard::authorizeHop(std::string_view url, const std::vector<std::string>& resolvedAddresses) const
{
    const std::optional<ParsedUrl> parsed = parseUrl(url);
    if (!parsed)
        return failure(NetworkError::InvalidRedirect, "redirect target is not a valid HTTP(S) URL");
    if (!hostAllowed(parsed->host))
        return failure(NetworkError::HostNotAllowed, "redirect target host is not allowed", parsed->host);
    if (resolvedAddresses.empty())
        return failure(NetworkError::TransportFailure, "transport did not report resolved addresses", parsed->host);
    if (!config_.allowPrivateNetwork)
    {
        for (const std::string& address : resolvedAddresses)
        {
            if (!isPublicAddress(address))
                return failure(NetworkError::PrivateAddressBlocked, "resolved destination is private, local, link-local, or reserved", parsed->host);
        }
    }
    return {};
}

NetworkResult NetworkGuard::validateResponse(const NetworkRequest& request, const NetworkResponse& response) const
{
    if (response.body.size() > config_.limits.maxResponseBodyBytes)
        return failure(NetworkError::BodyTooLarge, "response body exceeds configured limit");
    if (response.headers.size() > config_.limits.maxHeaders || headerBytes(response.headers) > config_.limits.maxHeaderBytes)
        return failure(NetworkError::HeadersTooLarge, "response headers exceed configured limits");
    if (response.hops.empty())
        return failure(NetworkError::TransportFailure, "transport omitted its endpoint validation trace");
    if (response.hops.size() > request.redirectLimit + 1 || response.hops.size() > config_.limits.maxRedirects + 1)
        return failure(NetworkError::TooManyRedirects, "response exceeded redirect limit");
    for (const NetworkHop& hop : response.hops)
    {
        NetworkResult allowed = authorizeHop(hop.url, hop.resolvedAddresses);
        if (!allowed)
            return allowed;
    }
    return {};
}

std::optional<ParsedUrl> NetworkGuard::parseUrl(std::string_view url)
{
    if (url.empty() || url.size() > 8192 || url.find_first_of("\r\n\t") != std::string_view::npos)
        return std::nullopt;
    const std::size_t schemeEnd = url.find("://");
    if (schemeEnd == std::string_view::npos)
        return std::nullopt;
    ParsedUrl result;
    result.scheme = lowercase(url.substr(0, schemeEnd));
    if (result.scheme != "http" && result.scheme != "https")
        return std::nullopt;

    const std::size_t authorityStart = schemeEnd + 3;
    const std::size_t targetStart = url.find_first_of("/?#", authorityStart);
    std::string_view authority = targetStart == std::string_view::npos ? url.substr(authorityStart) : url.substr(authorityStart, targetStart - authorityStart);
    if (authority.empty() || authority.find('@') != std::string_view::npos)
        return std::nullopt;
    result.target = targetStart == std::string_view::npos ? "/" : std::string(url.substr(targetStart));
    if (result.target.starts_with("#"))
        result.target.insert(result.target.begin(), '/');

    std::string_view host;
    std::string_view port;
    if (authority.front() == '[')
    {
        const std::size_t close = authority.find(']');
        if (close == std::string_view::npos)
            return std::nullopt;
        host = authority.substr(1, close - 1);
        if (close + 1 < authority.size())
        {
            if (authority[close + 1] != ':')
                return std::nullopt;
            port = authority.substr(close + 2);
        }
    }
    else
    {
        const std::size_t colon = authority.rfind(':');
        if (colon != std::string_view::npos)
        {
            if (authority.find(':') != colon)
                return std::nullopt;
            host = authority.substr(0, colon);
            port = authority.substr(colon + 1);
        }
        else
            host = authority;
    }
    result.host = normalizeHost(host);
    if (result.host.empty() || result.host.size() > 253)
        return std::nullopt;
    if (!port.empty())
    {
        unsigned value = 0;
        auto parsed = std::from_chars(port.data(), port.data() + port.size(), value);
        if (parsed.ec != std::errc{} || parsed.ptr != port.data() + port.size() || value == 0 || value > 65535)
            return std::nullopt;
        result.port = static_cast<uint16_t>(value);
    }
    return result;
}

std::string NetworkGuard::normalizeHost(std::string_view host)
{
    std::string result = lowercase(host);
    while (!result.empty() && result.back() == '.')
        result.pop_back();
    if (result.empty() || result.find_first_of(" /\\?#\r\n\t") != std::string::npos)
        return {};
    return result;
}

bool NetworkGuard::isPublicAddress(std::string_view address)
{
    std::string value = lowercase(address);
    if (const std::optional<std::array<unsigned, 4>> ipv4 = parseIpv4(value))
        return publicIpv4(*ipv4);
    const std::optional<std::array<unsigned char, 16>> parsed = parseIpv6(value);
    if (!parsed)
        return false;
    const std::array<unsigned char, 16>& bytes = *parsed;

    const bool first96Zero = std::all_of(bytes.begin(), bytes.begin() + 12, [](unsigned char byte) { return byte == 0; });
    const bool mappedIpv4 = std::all_of(bytes.begin(), bytes.begin() + 10, [](unsigned char byte) { return byte == 0; }) &&
        bytes[10] == 0xff && bytes[11] == 0xff;
    if (first96Zero || mappedIpv4)
        return publicEmbeddedIpv4(bytes, 12);

    // Only global-unicast space is eligible for live requests. This blocks
    // ULA, link-local, multicast, site-local, discard-only, and both NAT64
    // prefixes (including 64:ff9b::/96) before any connection is attempted.
    if ((bytes[0] & 0xe0) != 0x20)
        return false;

    // Documentation and benchmarking ranges are non-public destinations.
    if (bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] == 0x0d && bytes[3] == 0xb8)
        return false;
    if (bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] == 0x00 && bytes[3] == 0x02 && bytes[4] == 0 && bytes[5] == 0)
        return false;

    // Transition mechanisms embed IPv4 destinations. Reject them when the
    // embedded address is private/reserved so textual or expanded spellings
    // cannot bypass the same IPv4 policy.
    if (bytes[0] == 0x20 && bytes[1] == 0x02 && !publicEmbeddedIpv4(bytes, 2)) // 6to4
        return false;
    if (bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] == 0 && bytes[3] == 0 &&
        (!publicEmbeddedIpv4(bytes, 4) || !publicEmbeddedIpv4(bytes, 12, true))) // Teredo
        return false;
    if (bytes[8] == 0 && bytes[9] == 0 && bytes[10] == 0x5e && bytes[11] == 0xfe && !publicEmbeddedIpv4(bytes, 12)) // ISATAP
        return false;
    return true;
}

bool NetworkGuard::hostAllowed(std::string_view host) const
{
    if (config_.mode == NetworkMode::Live)
        return true;
    const std::string normalized = normalizeHost(host);
    if (config_.allowedHosts.contains(normalized))
        return true;
    for (const std::string& allowed : config_.allowedHosts)
    {
        if (!allowed.starts_with("*."))
            continue;
        const std::string_view suffix(allowed.data() + 1, allowed.size() - 1);
        if (normalized.size() > suffix.size() && normalized.ends_with(suffix))
            return true;
    }
    return false;
}

struct NetworkBroker::Impl : std::enable_shared_from_this<NetworkBroker::Impl>
{
    struct Control
    {
        NetworkRequestId id = 0;
        NetworkRequest request;
        Completion completion;
        std::atomic<bool> cancelled{false};
        std::atomic<bool> delivered{false};
    };

    Scheduler& scheduler;
    NetworkGuard guard;
    std::shared_ptr<IHttpTransport> transport;
    mutable std::mutex mutex;
    std::condition_variable condition;
    std::deque<std::shared_ptr<Control>> queue;
    std::unordered_map<NetworkRequestId, std::shared_ptr<Control>> pending;
    std::vector<std::thread> workers;
    bool stopping = false;
    std::size_t active = 0;
    NetworkRequestId nextId = 1;
    NetworkBrokerStats counters;

    Impl(Scheduler& schedulerValue, NetworkPolicyConfig policy, std::shared_ptr<IHttpTransport> transportValue)
        : scheduler(schedulerValue)
        , guard(std::move(policy))
        , transport(std::move(transportValue))
    {
        if (!transport)
            throw std::invalid_argument("network broker requires a transport");
    }

    void start()
    {
        const std::size_t count = guard.config().limits.maxConcurrent;
        workers.reserve(count);
        for (std::size_t index = 0; index < count; ++index)
            workers.emplace_back([this] { workerLoop(); });
    }

    void stop()
    {
        {
            std::lock_guard lock(mutex);
            if (stopping)
                return;
            stopping = true;
            for (auto& [_, control] : pending)
                control->cancelled.store(true, std::memory_order_release);
        }
        condition.notify_all();
        for (std::thread& worker : workers)
        {
            if (worker.joinable())
                worker.join();
        }
        workers.clear();
    }

    void deliver(const std::shared_ptr<Control>& control, NetworkResult result, double delay = 0.0)
    {
        if (control->delivered.exchange(true, std::memory_order_acq_rel))
            return;
        std::weak_ptr<Impl> weakSelf = shared_from_this();
        scheduler.postExternal(
            [weakSelf, control, result = std::move(result)]() mutable {
                std::shared_ptr<Impl> self = weakSelf.lock();
                if (!self)
                    return;
                {
                    std::lock_guard lock(self->mutex);
                    self->pending.erase(control->id);
                    self->counters.completed++;
                }
                if (control->completion)
                    control->completion(std::move(result));
            },
            delay,
            "http-completion");
    }

    void workerLoop()
    {
        for (;;)
        {
            std::shared_ptr<Control> control;
            {
                std::unique_lock lock(mutex);
                condition.wait(lock, [this] { return stopping || !queue.empty(); });
                if (stopping && queue.empty())
                    return;
                control = std::move(queue.front());
                queue.pop_front();
                ++active;
            }

            NetworkResult result;
            if (control->cancelled.load(std::memory_order_acquire))
                result = failure(NetworkError::Cancelled, "HTTP request was cancelled");
            else
            {
                TransportContext context;
                context.authorizeEndpoint = [this](std::string_view url, const std::vector<std::string>& addresses) {
                    return guard.authorizeHop(url, addresses);
                };
                context.cancelled = [control] {
                    return control->cancelled.load(std::memory_order_acquire);
                };
                try
                {
                    result = transport->perform(control->request, context);
                }
                catch (const std::exception& exception)
                {
                    result = failure(NetworkError::TransportFailure, exception.what());
                }
                catch (...)
                {
                    result = failure(NetworkError::TransportFailure, "unknown transport exception");
                }
                if (control->cancelled.load(std::memory_order_acquire))
                    result = failure(NetworkError::Cancelled, "HTTP request was cancelled");
                else if (result)
                {
                    NetworkResult validation = guard.validateResponse(control->request, result.response);
                    if (!validation)
                        result = std::move(validation);
                }
            }

            const double delay = result ? result.response.deterministicLatencySeconds : 0.0;
            {
                std::lock_guard lock(mutex);
                --active;
            }
            deliver(control, std::move(result), std::max(0.0, delay));
        }
    }
};

NetworkBroker::NetworkBroker(Scheduler& scheduler, NetworkPolicyConfig policy, std::shared_ptr<IHttpTransport> transport)
    : impl_(std::make_shared<Impl>(scheduler, std::move(policy), std::move(transport)))
{
    impl_->start();
}

NetworkBroker::~NetworkBroker()
{
    if (impl_)
        impl_->stop();
}

NetworkRequestId NetworkBroker::submit(NetworkRequest request, Completion completion)
{
    if (!impl_->scheduler.ownsCurrentThread())
        throw std::logic_error("HTTP requests must be submitted on the scheduler owner thread");
    if (!completion)
        throw std::invalid_argument("HTTP completion callback cannot be empty");

    auto control = std::make_shared<Impl::Control>();
    {
        std::lock_guard lock(impl_->mutex);
        control->id = impl_->nextId++;
        control->request = std::move(request);
        control->completion = std::move(completion);
        impl_->pending.emplace(control->id, control);
        impl_->counters.submitted++;
    }

    NetworkResult authorization = impl_->guard.authorizeRequest(control->request);
    if (!authorization)
    {
        {
            std::lock_guard lock(impl_->mutex);
            impl_->counters.rejected++;
        }
        impl_->deliver(control, std::move(authorization));
        return control->id;
    }

    {
        std::lock_guard lock(impl_->mutex);
        if (impl_->stopping)
        {
            impl_->counters.rejected++;
            impl_->deliver(control, failure(NetworkError::Cancelled, "network broker is shutting down"));
            return control->id;
        }
        if (impl_->queue.size() >= impl_->guard.config().limits.maxQueued)
        {
            impl_->counters.rejected++;
            impl_->deliver(control, failure(NetworkError::QueueFull, "network request queue is full"));
            return control->id;
        }
        impl_->queue.push_back(control);
    }
    impl_->condition.notify_one();
    return control->id;
}

bool NetworkBroker::cancel(NetworkRequestId id)
{
    std::shared_ptr<Impl::Control> control;
    {
        std::lock_guard lock(impl_->mutex);
        auto found = impl_->pending.find(id);
        if (found == impl_->pending.end() || found->second->delivered.load(std::memory_order_acquire))
            return false;
        control = found->second;
        control->cancelled.store(true, std::memory_order_release);
        impl_->counters.cancelled++;
        auto queued = std::find(impl_->queue.begin(), impl_->queue.end(), control);
        if (queued != impl_->queue.end())
            impl_->queue.erase(queued);
    }
    impl_->deliver(control, failure(NetworkError::Cancelled, "HTTP request was cancelled"));
    return true;
}

NetworkBrokerStats NetworkBroker::stats() const
{
    std::lock_guard lock(impl_->mutex);
    NetworkBrokerStats result = impl_->counters;
    result.queued = impl_->queue.size();
    result.active = impl_->active;
    result.pending = impl_->pending.size();
    return result;
}

const NetworkGuard& NetworkBroker::guard() const
{
    return impl_->guard;
}

void FixtureHttpTransport::add(std::string url, NetworkFixture fixture)
{
    fixtures_[std::move(url)] = std::move(fixture);
}

bool FixtureHttpTransport::remove(std::string_view url)
{
    return fixtures_.erase(std::string(url)) != 0;
}

void FixtureHttpTransport::clear()
{
    fixtures_.clear();
}

NetworkResult FixtureHttpTransport::perform(const NetworkRequest& request, const TransportContext& context)
{
    auto found = fixtures_.find(request.url);
    if (found == fixtures_.end())
        return failure(NetworkError::TransportFailure, "no deterministic fixture for URL");
    if (context.cancelled && context.cancelled())
        return failure(NetworkError::Cancelled, "HTTP request was cancelled");

    NetworkResult result = found->second.result;
    if (result && result.response.hops.empty())
        return failure(NetworkError::TransportFailure, "fixture must declare resolved endpoint addresses");
    if (result)
    {
        for (const NetworkHop& hop : result.response.hops)
        {
            NetworkResult authorized = context.authorizeEndpoint(hop.url, hop.resolvedAddresses);
            if (!authorized)
                return authorized;
        }
    }
    return result;
}

std::string_view toString(NetworkMode mode)
{
    switch (mode)
    {
    case NetworkMode::Offline:
        return "offline";
    case NetworkMode::Allowlist:
        return "allowlist";
    case NetworkMode::Live:
        return "live";
    }
    return "unknown";
}

std::string_view toString(NetworkError error)
{
    switch (error)
    {
    case NetworkError::None:
        return "none";
    case NetworkError::Offline:
        return "offline";
    case NetworkError::HostNotAllowed:
        return "host-not-allowed";
    case NetworkError::InvalidUrl:
        return "invalid-url";
    case NetworkError::PrivateAddressBlocked:
        return "private-address-blocked";
    case NetworkError::InvalidRequest:
        return "invalid-request";
    case NetworkError::QueueFull:
        return "queue-full";
    case NetworkError::Cancelled:
        return "cancelled";
    case NetworkError::Timeout:
        return "timeout";
    case NetworkError::TransportFailure:
        return "transport-failure";
    case NetworkError::TooManyRedirects:
        return "too-many-redirects";
    case NetworkError::HeadersTooLarge:
        return "headers-too-large";
    case NetworkError::BodyTooLarge:
        return "body-too-large";
    case NetworkError::InvalidRedirect:
        return "invalid-redirect";
    }
    return "unknown";
}

} // namespace rbx::runtime
