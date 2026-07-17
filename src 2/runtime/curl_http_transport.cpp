#include "curl_http_transport.hpp"

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netdb.h>
#include <sys/socket.h>
#endif

#include <curl/curl.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <chrono>
#include <cstdio>
#include <iterator>
#include <limits>
#include <map>
#include <optional>
#include <new>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace rbx::runtime
{
namespace
{

struct CurlHandle
{
    CURL* value = curl_easy_init();
    ~CurlHandle()
    {
        if (value)
            curl_easy_cleanup(value);
    }
};

struct CurlList
{
    curl_slist* value = nullptr;
    ~CurlList()
    {
        curl_slist_free_all(value);
    }

    void append(const std::string& text)
    {
        curl_slist* next = curl_slist_append(value, text.c_str());
        if (!next)
            throw std::bad_alloc();
        value = next;
    }
};

struct TransferState
{
    const TransportContext* context = nullptr;
    const NetworkLimits* limits = nullptr;
    std::string body;
    std::map<std::string, std::string, std::less<>> headers;
    std::string statusMessage;
    std::size_t headerBytes = 0;
    bool bodyLimitHit = false;
    bool headerLimitHit = false;
};

NetworkResult fail(NetworkError error, std::string message, std::string requiredHost = {})
{
    NetworkResult result;
    result.error = error;
    result.message = std::move(message);
    result.requiredHost = std::move(requiredHost);
    return result;
}

std::string lower(std::string_view text)
{
    std::string result(text);
    std::transform(result.begin(), result.end(), result.begin(), [](unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
    return result;
}

std::string trim(std::string_view text)
{
    while (!text.empty() && std::isspace(static_cast<unsigned char>(text.front())))
        text.remove_prefix(1);
    while (!text.empty() && std::isspace(static_cast<unsigned char>(text.back())))
        text.remove_suffix(1);
    return std::string(text);
}

std::optional<std::string> headerValue(const std::map<std::string, std::string, std::less<>>& headers, std::string_view requested)
{
    const std::string key = lower(requested);
    auto found = std::find_if(headers.begin(), headers.end(), [&](const auto& header) {
        return lower(header.first) == key;
    });
    return found == headers.end() ? std::nullopt : std::optional(found->second);
}

size_t writeBody(char* data, size_t size, size_t count, void* userdata)
{
    TransferState& state = *static_cast<TransferState*>(userdata);
    if (size != 0 && count > std::numeric_limits<std::size_t>::max() / size)
    {
        state.bodyLimitHit = true;
        return 0;
    }
    const std::size_t bytes = size * count;
    if (bytes > state.limits->maxResponseBodyBytes - std::min(state.body.size(), state.limits->maxResponseBodyBytes))
    {
        state.bodyLimitHit = true;
        return 0;
    }
    state.body.append(data, bytes);
    return bytes;
}

size_t writeHeader(char* data, size_t size, size_t count, void* userdata)
{
    TransferState& state = *static_cast<TransferState*>(userdata);
    if (size != 0 && count > std::numeric_limits<std::size_t>::max() / size)
    {
        state.headerLimitHit = true;
        return 0;
    }
    const std::size_t bytes = size * count;
    if (bytes > state.limits->maxHeaderBytes - std::min(state.headerBytes, state.limits->maxHeaderBytes))
    {
        state.headerLimitHit = true;
        return 0;
    }
    state.headerBytes += bytes;
    std::string_view line(data, bytes);
    while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
        line.remove_suffix(1);
    if (line.empty())
        return bytes;

    if (line.starts_with("HTTP/"))
    {
        state.headers.clear();
        const std::size_t firstSpace = line.find(' ');
        const std::size_t secondSpace = firstSpace == std::string_view::npos ? std::string_view::npos : line.find(' ', firstSpace + 1);
        state.statusMessage = secondSpace == std::string_view::npos ? std::string() : trim(line.substr(secondSpace + 1));
        return bytes;
    }

    const std::size_t colon = line.find(':');
    if (colon == std::string_view::npos)
        return bytes;
    // Preserve the server's script-visible header spelling. Internal lookups
    // (for example Location during redirect handling) remain case-insensitive.
    const std::string name = trim(line.substr(0, colon));
    const std::string value = trim(line.substr(colon + 1));
    if (name.empty())
        return bytes;
    auto found = std::find_if(state.headers.begin(), state.headers.end(), [&](const auto& header) {
        return lower(header.first) == lower(name);
    });
    const bool inserted = found == state.headers.end();
    if (inserted)
        state.headers.emplace(name, value);
    else
        found->second += ", " + value;
    if (state.headers.size() > state.limits->maxHeaders)
    {
        state.headerLimitHit = true;
        return 0;
    }
    return bytes;
}

int transferProgress(void* userdata, curl_off_t, curl_off_t, curl_off_t, curl_off_t)
{
    const TransferState& state = *static_cast<const TransferState*>(userdata);
    return state.context && state.context->cancelled && state.context->cancelled() ? 1 : 0;
}

uint16_t effectivePort(const ParsedUrl& url)
{
    return url.port.value_or(url.scheme == "https" ? 443 : 80);
}

std::vector<std::string> resolveAddresses(const ParsedUrl& parsed, std::string& error)
{
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    addrinfo* head = nullptr;
    const std::string service = std::to_string(effectivePort(parsed));
    const int status = getaddrinfo(parsed.host.c_str(), service.c_str(), &hints, &head);
    if (status != 0 || !head)
    {
#if defined(_WIN32)
        error = "DNS resolution failed with status " + std::to_string(status);
#else
        error = std::string("DNS resolution failed: ") + gai_strerror(status);
#endif
        return {};
    }

    std::set<std::string, std::less<>> unique;
    for (addrinfo* cursor = head; cursor; cursor = cursor->ai_next)
    {
        std::array<char, NI_MAXHOST> buffer{};
        if (getnameinfo(cursor->ai_addr, static_cast<socklen_t>(cursor->ai_addrlen), buffer.data(), static_cast<socklen_t>(buffer.size()), nullptr, 0,
                NI_NUMERICHOST) == 0)
            unique.emplace(buffer.data());
    }
    freeaddrinfo(head);
    if (unique.empty())
        error = "DNS resolution returned no numeric addresses";
    return std::vector<std::string>(unique.begin(), unique.end());
}

std::string resolveEntry(const ParsedUrl& parsed, const std::vector<std::string>& addresses)
{
    const std::string host = parsed.host.find(':') == std::string::npos ? parsed.host : "[" + parsed.host + "]";
    std::string result = host + ":" + std::to_string(effectivePort(parsed)) + ":";
    bool first = true;
    for (const std::string& address : addresses)
    {
        if (!first)
            result += ',';
        if (address.find(':') != std::string::npos)
            result += '[' + address + ']';
        else
            result += address;
        first = false;
    }
    return result;
}

std::string origin(const ParsedUrl& parsed)
{
    const std::string host = parsed.host.find(':') == std::string::npos ? parsed.host : "[" + parsed.host + "]";
    return parsed.scheme + "://" + host + ":" + std::to_string(effectivePort(parsed));
}

std::string directoryOf(std::string_view target)
{
    const std::size_t query = target.find_first_of("?#");
    target = target.substr(0, query);
    const std::size_t slash = target.rfind('/');
    return slash == std::string_view::npos ? "/" : std::string(target.substr(0, slash + 1));
}

std::optional<std::string> redirectUrl(std::string_view currentUrl, std::string_view location)
{
    const std::optional<ParsedUrl> current = NetworkGuard::parseUrl(currentUrl);
    if (!current || location.empty() || location.find_first_of("\r\n") != std::string_view::npos)
        return std::nullopt;
    if (location.starts_with("http://") || location.starts_with("https://") || location.starts_with("HTTP://") || location.starts_with("HTTPS://"))
        return std::string(location);
    if (location.starts_with("//"))
        return current->scheme + ":" + std::string(location);
    if (location.front() == '/')
        return origin(*current) + std::string(location);
    return origin(*current) + directoryOf(current->target) + std::string(location);
}

bool redirectStatus(long status)
{
    return status == 301 || status == 302 || status == 303 || status == 307 || status == 308;
}

bool sensitiveHeader(std::string_view name)
{
    const std::string key = lower(name);
    return key == "authorization" || key == "cookie" || key == "proxy-authorization" || key == "x-api-key" || key == "host";
}

void stripCrossOriginHeaders(std::map<std::string, std::string, std::less<>>& headers)
{
    for (auto iterator = headers.begin(); iterator != headers.end();)
        iterator = sensitiveHeader(iterator->first) ? headers.erase(iterator) : std::next(iterator);
}

void removeEntityHeaders(std::map<std::string, std::string, std::less<>>& headers)
{
    for (auto iterator = headers.begin(); iterator != headers.end();)
    {
        const std::string key = lower(iterator->first);
        iterator = key == "content-length" || key == "content-type" || key == "transfer-encoding" ? headers.erase(iterator) : std::next(iterator);
    }
}

NetworkResult performHop(const NetworkRequest& request, std::string_view url, const std::vector<std::string>& addresses, const TransportContext& context,
    const CurlHttpTransportOptions& options, std::chrono::steady_clock::time_point deadline)
{
    const std::optional<ParsedUrl> parsed = NetworkGuard::parseUrl(url);
    if (!parsed)
        return fail(NetworkError::InvalidUrl, "transport received an invalid HTTP(S) URL");
    if (context.cancelled && context.cancelled())
        return fail(NetworkError::Cancelled, "HTTP request was cancelled");

    const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now());
    if (remaining.count() <= 0)
        return fail(NetworkError::Timeout, "HTTP request timed out");

    CurlHandle easy;
    if (!easy.value)
        return fail(NetworkError::TransportFailure, "curl_easy_init failed");
    CurlList requestHeaders;
    CurlList pinnedResolution;
    try
    {
        for (const auto& [name, value] : request.headers)
            requestHeaders.append(name + ": " + value);
        pinnedResolution.append(resolveEntry(*parsed, addresses));
    }
    catch (const std::bad_alloc&)
    {
        return fail(NetworkError::TransportFailure, "unable to allocate libcurl request metadata");
    }

    TransferState transfer{&context, &options.limits};
    curl_easy_setopt(easy.value, CURLOPT_URL, std::string(url).c_str());
    curl_easy_setopt(easy.value, CURLOPT_HTTPHEADER, requestHeaders.value);
    curl_easy_setopt(easy.value, CURLOPT_RESOLVE, pinnedResolution.value);
    curl_easy_setopt(easy.value, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(easy.value, CURLOPT_MAXREDIRS, 0L);
    curl_easy_setopt(easy.value, CURLOPT_PROXY, "");
    curl_easy_setopt(easy.value, CURLOPT_NOPROXY, "*");
    curl_easy_setopt(easy.value, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(easy.value, CURLOPT_FRESH_CONNECT, 1L);
    curl_easy_setopt(easy.value, CURLOPT_FORBID_REUSE, 1L);
    curl_easy_setopt(easy.value, CURLOPT_DNS_CACHE_TIMEOUT, 0L);
    curl_easy_setopt(easy.value, CURLOPT_TIMEOUT_MS, static_cast<long>(remaining.count()));
    curl_easy_setopt(easy.value, CURLOPT_CONNECTTIMEOUT_MS, static_cast<long>(std::min(remaining, options.connectTimeout).count()));
    curl_easy_setopt(easy.value, CURLOPT_WRITEFUNCTION, writeBody);
    curl_easy_setopt(easy.value, CURLOPT_WRITEDATA, &transfer);
    curl_easy_setopt(easy.value, CURLOPT_HEADERFUNCTION, writeHeader);
    curl_easy_setopt(easy.value, CURLOPT_HEADERDATA, &transfer);
    curl_easy_setopt(easy.value, CURLOPT_XFERINFOFUNCTION, transferProgress);
    curl_easy_setopt(easy.value, CURLOPT_XFERINFODATA, &transfer);
    curl_easy_setopt(easy.value, CURLOPT_NOPROGRESS, 0L);
    curl_easy_setopt(easy.value, CURLOPT_ACCEPT_ENCODING, "");
    if (!options.userAgent.empty())
        curl_easy_setopt(easy.value, CURLOPT_USERAGENT, options.userAgent.c_str());
#if LIBCURL_VERSION_NUM >= 0x075500
    curl_easy_setopt(easy.value, CURLOPT_PROTOCOLS_STR, "http,https");
#else
    curl_easy_setopt(easy.value, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
#endif

    if (request.method == "GET")
        curl_easy_setopt(easy.value, CURLOPT_HTTPGET, 1L);
    else if (request.method == "HEAD")
        curl_easy_setopt(easy.value, CURLOPT_NOBODY, 1L);
    else if (request.method == "POST")
        curl_easy_setopt(easy.value, CURLOPT_POST, 1L);
    else
        curl_easy_setopt(easy.value, CURLOPT_CUSTOMREQUEST, request.method.c_str());
    if (!request.body.empty())
    {
        curl_easy_setopt(easy.value, CURLOPT_POSTFIELDS, request.body.data());
        curl_easy_setopt(easy.value, CURLOPT_POSTFIELDSIZE_LARGE, static_cast<curl_off_t>(request.body.size()));
        if (request.method != "POST")
            curl_easy_setopt(easy.value, CURLOPT_CUSTOMREQUEST, request.method.c_str());
    }

    const CURLcode code = curl_easy_perform(easy.value);
    if (transfer.bodyLimitHit)
        return fail(NetworkError::BodyTooLarge, "response body exceeds configured limit");
    if (transfer.headerLimitHit)
        return fail(NetworkError::HeadersTooLarge, "response headers exceed configured limits");
    if (context.cancelled && context.cancelled())
        return fail(NetworkError::Cancelled, "HTTP request was cancelled");
    if (code == CURLE_OPERATION_TIMEDOUT)
        return fail(NetworkError::Timeout, "HTTP request timed out");
    if (code != CURLE_OK)
        return fail(NetworkError::TransportFailure, std::string("libcurl: ") + curl_easy_strerror(code));

    long status = 0;
    curl_easy_getinfo(easy.value, CURLINFO_RESPONSE_CODE, &status);
    NetworkResult result;
    result.response.statusCode = static_cast<int>(status);
    result.response.statusMessage = std::move(transfer.statusMessage);
    result.response.headers = std::move(transfer.headers);
    result.response.body = std::move(transfer.body);
    return result;
}

} // namespace

CurlHttpTransport::CurlHttpTransport(CurlHttpTransportOptions options)
    : options_(std::move(options))
{
    if (options_.limits.maxResponseBodyBytes == 0 || options_.limits.maxHeaderBytes == 0 || options_.limits.maxHeaders == 0)
        throw std::invalid_argument("curl transport limits must be non-zero");
    if (options_.connectTimeout.count() <= 0)
        throw std::invalid_argument("curl connect timeout must be positive");
}

CurlHttpTransport::~CurlHttpTransport() = default;

NetworkResult CurlHttpTransport::perform(const NetworkRequest& original, const TransportContext& context)
{
    if (!context.authorizeEndpoint)
        return fail(NetworkError::TransportFailure, "transport endpoint authorization callback is missing");
    NetworkRequest request = original;
    std::string currentUrl = request.url;
    std::vector<NetworkHop> hops;
    const auto deadline = std::chrono::steady_clock::now() + request.timeout;
    const std::size_t redirectLimit = std::min(request.redirectLimit, options_.limits.maxRedirects);

    for (std::size_t redirectCount = 0;; ++redirectCount)
    {
        const std::optional<ParsedUrl> parsed = NetworkGuard::parseUrl(currentUrl);
        if (!parsed)
            return fail(redirectCount == 0 ? NetworkError::InvalidUrl : NetworkError::InvalidRedirect, "invalid HTTP redirect URL");

        std::string resolutionError;
        std::vector<std::string> addresses = resolveAddresses(*parsed, resolutionError);
        if (addresses.empty())
            return fail(NetworkError::TransportFailure, std::move(resolutionError), parsed->host);
        NetworkResult authorized = context.authorizeEndpoint(currentUrl, addresses);
        if (!authorized)
            return authorized;

        NetworkResult hop = performHop(request, currentUrl, addresses, context, options_, deadline);
        if (!hop)
            return hop;
        hops.push_back(NetworkHop{currentUrl, addresses});
        if (!redirectStatus(hop.response.statusCode))
        {
            hop.response.hops = std::move(hops);
            return hop;
        }

        const std::optional<std::string> location = headerValue(hop.response.headers, "location");
        if (!location)
        {
            hop.response.hops = std::move(hops);
            return hop;
        }
        if (redirectCount >= redirectLimit)
            return fail(NetworkError::TooManyRedirects, "HTTP response exceeded redirect limit");
        const std::optional<std::string> nextUrl = redirectUrl(currentUrl, *location);
        if (!nextUrl)
            return fail(NetworkError::InvalidRedirect, "HTTP response contains an invalid redirect target");
        const std::optional<ParsedUrl> nextParsed = NetworkGuard::parseUrl(*nextUrl);
        if (!nextParsed)
            return fail(NetworkError::InvalidRedirect, "HTTP response redirects outside HTTP(S)");

        if (origin(*parsed) != origin(*nextParsed))
            stripCrossOriginHeaders(request.headers);
        if (hop.response.statusCode == 303 || ((hop.response.statusCode == 301 || hop.response.statusCode == 302) && request.method == "POST"))
        {
            request.method = request.method == "HEAD" ? "HEAD" : "GET";
            request.body.clear();
            removeEntityHeaders(request.headers);
        }
        currentUrl = *nextUrl;
        request.url = currentUrl;
    }
}

const CurlHttpTransportOptions& CurlHttpTransport::options() const
{
    return options_;
}

std::shared_ptr<IHttpTransport> makeCurlHttpTransport(CurlHttpTransportOptions options)
{
    return std::make_shared<CurlHttpTransport>(std::move(options));
}

} // namespace rbx::runtime
