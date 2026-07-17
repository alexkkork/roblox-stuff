#include "lua.h"
#include "lualib.h"
#include "luacode.h"
#include "Luau/CodeGen.h"
#include "Luau/Parser.h"
#include "alex/antitamper.hpp"
#include "alex/owner_protection.hpp"
#include "runtime/release729_datatypes.hpp"
#include "runtime/release_manifest.hpp"
#include "runtime/register_overflow.hpp"
#include "runtime/curl_http_transport.hpp"
#include "runtime/luau_runtime_bridge.hpp"
#include "runtime/roblox_debug.hpp"
#include "runtime/roblox_environment_guard.hpp"
#include "runtime/runtime_context.hpp"
#include "runtime/roblox_utf8.hpp"
#include "runtime_v2.hpp"

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#include <curl/curl.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <functional>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <random>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace
{

#include "generated/RobloxApiDumpSummary.inc"

constexpr std::string_view kBuiltInSiftApiKey = "";

enum class NetworkPolicy
{
    Allowlist,
    Live,
    Offline,
};

enum class LuraphMode
{
    Off,
    Auto,
    Force,
};

enum class OwnerProtectionMode
{
    Respect,
    Ignore,
    Audit,
};

enum class AnalysisHooksMode
{
    Auto,
    On,
    Off,
};

enum class ClockMode
{
    Virtual,
    Realtime,
};

enum class UnsupportedPolicy
{
    ProfileDefault,
    Error,
    TraceNil,
};

enum class RegisterOverflowMode
{
    Error,
    Spill,
};

constexpr size_t kDefaultProbeTraceLimitBytes = 64 * 1024 * 1024;
constexpr size_t kMaxProbeTraceLimitBytes = 1024 * 1024 * 1024;

struct RuntimeConfig
{
    fs::path outputDir = "captures";
    fs::path traceCompatPath;
    fs::path traceEnvironmentPath;
    fs::path probeTracePath;
    fs::path luraphGeneratedInterpreterProbePath;
    size_t probeTraceLimitBytes = kDefaultProbeTraceLimitBytes;
    std::string chunkName;
    std::string profile = "executor-client";
    OwnerProtectionMode ownerProtection = OwnerProtectionMode::Respect;
    AnalysisHooksMode analysisHooks = AnalysisHooksMode::Off;
    rbx::runtime::ExecutionMode executionMode = rbx::runtime::ExecutionMode::Faithful;
    rbx::runtime::ExecutorPreset executorPreset = rbx::runtime::ExecutorPreset::Generic;
    rbx::runtime::FilesystemPolicy filesystemPolicy = rbx::runtime::FilesystemPolicy::ProfileDefault;
    bool minimalEnv = false;
    NetworkPolicy networkPolicy = NetworkPolicy::Offline;
    bool allowPrivateNetwork = false;
    std::set<std::string> allowHosts = {"raw.githubusercontent.com", "localhost", "127.0.0.1", "::1"};
    std::map<std::string, fs::path> fixtures;
    std::vector<alex::owner::PublicKey> ownerPublicKeys;
    std::vector<fs::path> ownerPublicKeyPaths;
    std::string jobId = "test-job-id";
    std::string playerName = "Player";
    int64_t placeId = 0;
    int64_t gameId = 0;
    int64_t userId = 123456;
    double timeoutSeconds = 30.0;
    size_t captureMinBytes = 100;
    int luauOptimizationLevel = 2;
    int luauDebugLevel = 1;
    bool captureStringHooks = false;
    bool traceCalls = false;
    uint64_t traceEnvironmentAfterClockCalls = 0;
    size_t traceEnvironmentMaxEvents = 100000;
    LuraphMode luraphMode = LuraphMode::Auto;
    bool luraphStopAfterExactSource = false;
    bool luraphSaveIntermediates = false;
    uint64_t luraphMaxSteps = 2000000000;
    uint64_t luraphStallSteps = 0;
    double progressIntervalSeconds = 0.0;
    bool siftDecompile = false;
    bool siftDisassemble = false;
    std::string siftApiKey;
    std::string siftApiKeyEnv = "SIFTRBLX_API_KEY";
    std::string siftBaseUrl = "https://siftrblx.com";
    bool autorunLoadstring = false;
    bool stopAfterCapture = false;
    bool tracePcallErrors = false;
    bool normalizePcallErrors = false;
    bool nativeCodegen = true;
    bool passSourceAsArg = false;
    ClockMode clockMode = ClockMode::Virtual;
    UnsupportedPolicy unsupportedPolicy = UnsupportedPolicy::ProfileDefault;
    RegisterOverflowMode registerOverflow = RegisterOverflowMode::Error;
    double frameRate = 60.0;
    double maxVirtualSeconds = 30.0;
    fs::path scenarioPath;
    fs::path reportPath;
    size_t nativeCodegenBlockSize = 64 * 1024 * 1024;
    size_t nativeCodegenMaxTotalSize = 512 * 1024 * 1024;
    size_t memoryLimitBytes = 512 * 1024 * 1024;
    uint64_t deterministicSeed = 0;
    bool deterministicSeedExplicit = false;
    bool studioRunScriptCompatibility = false;
    double virtualEpochSeconds = 1735689600.0; // 2025-01-01T00:00:00Z
    int nextCaptureId = 1;
};

RuntimeConfig gConfig;

struct NativeEnvironmentTraceEvent
{
    uint64_t firstSequence = 0;
    uint64_t lastSequence = 0;
    uint64_t count = 0;
    std::string operation;
    std::string scope;
    std::string keyType;
    std::string key;
    std::string valueType;
    bool hit = false;
};

std::vector<NativeEnvironmentTraceEvent> gNativeEnvironmentTraceEvents;
std::unordered_map<std::string, size_t> gNativeEnvironmentTraceIndex;
uint64_t gNativeEnvironmentTraceAccesses = 0;
uint64_t gNativeEnvironmentClockCalls = 0;
uint64_t gNativeEnvironmentTraceDropped = 0;
bool gNativeEnvironmentTraceActive = false;
bool gNativeEnvironmentTraceWritten = false;
const void* gNativeEnvironmentPointer = nullptr;
const void* gNativeSharedGlobalPointer = nullptr;
json gScenario = json::object();
std::vector<json> gCompatReportEvents;
std::vector<json> gNetworkRequirements;
std::vector<std::string> gCapturedStdout;
std::vector<std::string> gCapturedStderr;
json gMainReportReturns = json::array();
json gMainTypedReturns = json::array();
json gBlockedReason = nullptr;
json gRobloxEnvironmentIntegrity = {
    {"status", "not_checked"},
    {"passed", nullptr},
    {"checks_performed", 0},
    {"findings", json::array()},
};
std::string gSteadyStateReasonOverride;
constexpr size_t kOutputCaptureLimitBytes = 4 * 1024 * 1024;
constexpr size_t kOutputLineLimitBytes = 64 * 1024;
size_t gOutputCapturedBytes = 0;
bool gOutputLimitHit = false;
std::ofstream gProbeTraceStream;
size_t gProbeTraceBytes = 0;
bool gProbeTraceLimitHit = false;
uint64_t gProtectedErrorCount = 0;
uint64_t gClosureClassificationTraceCount = 0;

struct CodegenUsage
{
    uint64_t chunksLoaded = 0;
    uint64_t chunksNativeAttempted = 0;
    uint64_t chunksNativeSucceeded = 0;
    uint64_t chunksNativePartial = 0;
    uint64_t chunksNativeRetried = 0;
    uint64_t bytecodeBytes = 0;
    uint64_t nativeCodeBytes = 0;
    uint64_t nativeDataBytes = 0;
    uint64_t nativeMetadataBytes = 0;
    uint64_t functionsTotal = 0;
    uint64_t functionsCompiled = 0;
    uint64_t functionsBound = 0;
};

CodegenUsage gCodegenUsage;

struct RegisterOverflowUsage
{
    uint64_t retries = 0;
    uint64_t chunksRewritten = 0;
    uint64_t chunksNarrowed = 0;
    uint64_t functionsRewritten = 0;
    uint64_t bindingsSpilled = 0;
    uint64_t declarationsSunk = 0;
    uint64_t bindingsNarrowed = 0;
    uint64_t scopesNarrowed = 0;
    std::vector<std::string> diagnostics;
};

RegisterOverflowUsage gRegisterOverflowUsage;
size_t gCodegenBudgetBytes = 0;
std::chrono::steady_clock::time_point gExecutionDeadline;
std::chrono::steady_clock::time_point gExecutionStart;
std::chrono::steady_clock::time_point gLastProgressPrint;
uint64_t gInterruptCounter = 0;
uint64_t gLastLuraphProgressStep = 0;
uint64_t gSchedulerTaskIdBaseline = 0;
bool gTimeoutTraceCaptured = false;
bool gInstructionBudgetReached = false;
bool gWallTimeoutReached = false;
bool gLuraphStallReached = false;
std::string gHostInterruptMessage;
std::string gInputSha256;
size_t gInputBytes = 0;
std::set<std::string> gLargeStringFingerprints;
std::set<std::string> gSiftBytecodeFingerprints;

struct LuraphRecoveryState
{
    bool active = false;
    bool detected = false;
    bool exactRecovered = false;
    bool stopRequested = false;
    std::string status = "unknown";
    std::string reason = "not started";
    std::string vmStatus = "not_run";
    std::string decompilerStatus = "not_run";
    std::vector<json> observations;
    fs::path exactSourcePath;
    fs::path bridgeSourcePath;
    fs::path generatedInterpreterPath;
    bool generatedInterpreterProbeApplied = false;
    fs::path packedBlobPath;
    fs::path bytecodePath;
    fs::path functionDumpPath;
    fs::path fallbackPath;
    fs::path siftDecompileResponsePath;
    fs::path siftDisassembleResponsePath;
    fs::path disassemblyPath;
    fs::path unpackedStatePath;
};

LuraphRecoveryState gLuraph;

struct VmMemoryBudget
{
    size_t limit = 0;
    size_t current = 0;
    size_t peak = 0;
    bool limitHit = false;
};

VmMemoryBudget gVmMemoryBudget;

void* vmMemoryAllocate(void* userdata, void* pointer, size_t oldSize, size_t newSize)
{
    auto& budget = *static_cast<VmMemoryBudget*>(userdata);
    if (newSize == 0)
    {
        std::free(pointer);
        budget.current -= std::min(budget.current, oldSize);
        return nullptr;
    }

    const size_t growth = newSize > oldSize ? newSize - oldSize : 0;
    if (growth > 0 && budget.limit > 0 && (budget.current > budget.limit || growth > budget.limit - budget.current))
    {
        budget.limitHit = true;
        return nullptr;
    }

    void* result = std::realloc(pointer, newSize);
    if (!result)
        return nullptr;

    if (newSize >= oldSize)
        budget.current += newSize - oldSize;
    else
        budget.current -= std::min(budget.current, oldSize - newSize);
    budget.peak = std::max(budget.peak, budget.current);
    return result;
}

std::string sha256Hex(std::string_view value)
{
    return alex::antitamper::hex(alex::antitamper::sha256(value));
}

uint64_t seedFromSha256(std::string_view hex)
{
    uint64_t result = 0;
    for (size_t i = 0; i < std::min<size_t>(16, hex.size()); ++i)
    {
        char c = hex[i];
        uint64_t nibble = c >= '0' && c <= '9' ? static_cast<uint64_t>(c - '0') : static_cast<uint64_t>(10 + std::tolower(static_cast<unsigned char>(c)) - 'a');
        result = (result << 4) | (nibble & 0xf);
    }
    return result;
}

constexpr int kTagVector2 = 10;
constexpr int kTagVector3 = 11;
constexpr int kTagColor3 = 12;
constexpr int kTagUDim = 13;
constexpr int kTagUDim2 = 14;
constexpr int kTagCFrame = 15;
constexpr int kTagRay = 16;

struct Vector2Value
{
    double x = 0;
    double y = 0;
};

struct Vector3Value
{
    double x = 0;
    double y = 0;
    double z = 0;
};

struct Color3Value
{
    double r = 0;
    double g = 0;
    double b = 0;
};

struct UDimValue
{
    double scale = 0;
    int offset = 0;
};

struct UDim2Value
{
    UDimValue x;
    UDimValue y;
};

struct CFrameValue
{
    double r00 = 1;
    double r01 = 0;
    double r02 = 0;
    double x = 0;
    double r10 = 0;
    double r11 = 1;
    double r12 = 0;
    double y = 0;
    double r20 = 0;
    double r21 = 0;
    double r22 = 1;
    double z = 0;
};

struct RayValue
{
    Vector3Value origin;
    Vector3Value direction;
};

std::string readFile(const fs::path& path)
{
    std::ifstream in(path, std::ios::binary);
    if (!in)
        throw std::runtime_error("unable to read file: " + path.string());

    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

void writeFile(const fs::path& path, std::string_view data)
{
    fs::create_directories(path.parent_path());
    std::ofstream out(path, std::ios::binary);
    if (!out)
        throw std::runtime_error("unable to write file: " + path.string());

    out.write(data.data(), static_cast<std::streamsize>(data.size()));
}

void appendFile(const fs::path& path, std::string_view data)
{
    fs::create_directories(path.parent_path());
    std::ofstream out(path, std::ios::binary | std::ios::app);
    if (!out)
        throw std::runtime_error("unable to write file: " + path.string());

    out.write(data.data(), static_cast<std::streamsize>(data.size()));
}

const char* nativeEnvironmentOperationName(int kind)
{
    switch (kind)
    {
    case LUA_TRACE_GET_GLOBAL:
        return "get_global";
    case LUA_TRACE_SET_GLOBAL:
        return "set_global";
    case LUA_TRACE_GET_IMPORT:
        return "get_import";
    case LUA_TRACE_GET_TABLE:
        return "get_table";
    case LUA_TRACE_SET_TABLE:
        return "set_table";
    case LUA_TRACE_RAW_GET:
        return "raw_get";
    default:
        return "unknown";
    }
}

const char* nativeEnvironmentTypeName(int type)
{
    switch (type)
    {
    case LUA_TNONE:
        return "none";
    case LUA_TNIL:
        return "nil";
    case LUA_TBOOLEAN:
        return "boolean";
    case LUA_TLIGHTUSERDATA:
        return "lightuserdata";
    case LUA_TNUMBER:
        return "number";
    case LUA_TINTEGER:
        return "integer";
    case LUA_TVECTOR:
        return "vector";
    case LUA_TSTRING:
        return "string";
    case LUA_TTABLE:
        return "table";
    case LUA_TFUNCTION:
        return "function";
    case LUA_TUSERDATA:
        return "userdata";
    case LUA_TTHREAD:
        return "thread";
    case LUA_TBUFFER:
        return "buffer";
    case LUA_TCLASS:
        return "class";
    case LUA_TOBJECT:
        return "object";
    default:
        return "internal";
    }
}

std::string nativeEnvironmentKey(const lua_TraceValue& value)
{
    if (value.type == LUA_TSTRING && value.stringValue)
    {
        constexpr size_t kMaximumKeyBytes = 512;
        const size_t retained = std::min(value.stringLength, kMaximumKeyBytes);
        std::string result(value.stringValue, retained);
        if (retained != value.stringLength)
            result += "...[truncated:" + std::to_string(value.stringLength) + "]";
        return result;
    }
    if (value.type == LUA_TNUMBER || value.type == LUA_TINTEGER)
    {
        std::ostringstream stream;
        stream << std::setprecision(17) << value.numberValue;
        return stream.str();
    }
    if (value.type == LUA_TBOOLEAN)
        return value.booleanValue ? "true" : "false";
    if (value.type == LUA_TNIL)
        return "nil";
    return std::string("<") + nativeEnvironmentTypeName(value.type) + ">";
}

void captureNativeEnvironmentAccess(lua_State*, const lua_TraceAccess* access)
{
    try
    {
        if (!access || !gNativeEnvironmentTraceActive)
            return;

        std::string scope = "script_environment";
        if (access->tablePointer == gNativeSharedGlobalPointer)
            scope = "shared_global";
        else if (access->tablePointer != gNativeEnvironmentPointer)
        {
            // The interpreter emits only environment-table accesses. rawget
            // is broader, so discard unrelated payload/protector tables.
            if (access->kind == LUA_TRACE_RAW_GET)
                return;
            scope = "closure_environment";
        }

        const uint64_t sequence = ++gNativeEnvironmentTraceAccesses;

        const std::string operation = nativeEnvironmentOperationName(access->kind);
        const std::string keyType = nativeEnvironmentTypeName(access->key.type);
        const std::string key = nativeEnvironmentKey(access->key);
        const std::string valueType = nativeEnvironmentTypeName(access->value.type);
        const bool hit = access->value.type != LUA_TNONE && access->value.type != LUA_TNIL;
        std::string signature;
        signature.reserve(operation.size() + scope.size() + keyType.size() + key.size() + valueType.size() + 6);
        signature.append(operation).push_back('\0');
        signature.append(scope).push_back('\0');
        signature.append(keyType).push_back('\0');
        signature.append(key).push_back('\0');
        signature.append(valueType).push_back('\0');
        signature.push_back(hit ? '1' : '0');

        if (const auto existing = gNativeEnvironmentTraceIndex.find(signature); existing != gNativeEnvironmentTraceIndex.end())
        {
            NativeEnvironmentTraceEvent& event = gNativeEnvironmentTraceEvents[existing->second];
            event.lastSequence = sequence;
            ++event.count;
            return;
        }

        if (gNativeEnvironmentTraceEvents.size() >= gConfig.traceEnvironmentMaxEvents)
        {
            ++gNativeEnvironmentTraceDropped;
            return;
        }

        NativeEnvironmentTraceEvent event;
        event.firstSequence = sequence;
        event.lastSequence = sequence;
        event.count = 1;
        event.operation = operation;
        event.scope = std::move(scope);
        event.keyType = keyType;
        event.key = key;
        event.valueType = valueType;
        event.hit = hit;
        gNativeEnvironmentTraceIndex.emplace(std::move(signature), gNativeEnvironmentTraceEvents.size());
        gNativeEnvironmentTraceEvents.push_back(std::move(event));
    }
    catch (...)
    {
        ++gNativeEnvironmentTraceDropped;
    }
}

void observeNativeEnvironmentCall(lua_State* L, const char* name)
{
    if (gConfig.traceEnvironmentPath.empty() || !name ||
        (std::strcmp(name, "os.clock") != 0 && std::strcmp(name, "runtime.elapsed") != 0))
        return;

    ++gNativeEnvironmentClockCalls;
    if (!gNativeEnvironmentTraceActive && gNativeEnvironmentClockCalls >= gConfig.traceEnvironmentAfterClockCalls)
    {
        gNativeEnvironmentTraceActive = true;
        lua_callbacks(L)->traceaccess = captureNativeEnvironmentAccess;
    }
}

void initializeNativeEnvironmentTrace(lua_State* L)
{
    gNativeEnvironmentTraceEvents.clear();
    gNativeEnvironmentTraceEvents.reserve(std::min<size_t>(gConfig.traceEnvironmentMaxEvents, 4096));
    gNativeEnvironmentTraceIndex.clear();
    gNativeEnvironmentTraceIndex.reserve(std::min<size_t>(gConfig.traceEnvironmentMaxEvents, 4096));
    gNativeEnvironmentTraceAccesses = 0;
    gNativeEnvironmentClockCalls = 0;
    gNativeEnvironmentTraceDropped = 0;
    gNativeEnvironmentTraceActive = false;
    gNativeEnvironmentTraceWritten = false;
    gNativeEnvironmentPointer = lua_topointer(L, LUA_GLOBALSINDEX);
    lua_getglobal(L, "_G");
    gNativeSharedGlobalPointer = lua_topointer(L, -1);
    lua_pop(L, 1);

    lua_Callbacks* callbacks = lua_callbacks(L);
    callbacks->tracesharedglobal = gNativeSharedGlobalPointer;
    callbacks->tracenativecall = observeNativeEnvironmentCall;
    if (gConfig.traceEnvironmentAfterClockCalls == 0)
    {
        gNativeEnvironmentTraceActive = true;
        callbacks->traceaccess = captureNativeEnvironmentAccess;
    }
}

void writeNativeEnvironmentTrace()
{
    if (gConfig.traceEnvironmentPath.empty() || gNativeEnvironmentTraceWritten)
        return;
    gNativeEnvironmentTraceWritten = true;

    try
    {
        std::ostringstream output;
        output << json({
                           {"kind", "trace_metadata"},
                           {"schema", "rbx-native-environment-trace/v1"},
                           {"active", gNativeEnvironmentTraceActive},
                           {"activation_clock_calls", gConfig.traceEnvironmentAfterClockCalls},
                           {"clock_calls_observed", gNativeEnvironmentClockCalls},
                           {"accesses", gNativeEnvironmentTraceAccesses},
                           {"unique_events", gNativeEnvironmentTraceEvents.size()},
                           {"dropped", gNativeEnvironmentTraceDropped},
                           {"native_codegen_required_off", true},
                       })
                          .dump()
               << "\n";
        for (const NativeEnvironmentTraceEvent& event : gNativeEnvironmentTraceEvents)
        {
            output << json({
                               {"kind", "environment_access"},
                               {"first_sequence", event.firstSequence},
                               {"last_sequence", event.lastSequence},
                               {"count", event.count},
                               {"operation", event.operation},
                               {"scope", event.scope},
                               {"key_type", event.keyType},
                               {"key", event.key},
                               {"value_type", event.valueType},
                               {"hit", event.hit},
                           })
                              .dump()
                   << "\n";
        }
        writeFile(gConfig.traceEnvironmentPath, output.str());
    }
    catch (const std::exception& error)
    {
        std::cerr << "[environment_trace_error] " << error.what() << "\n";
    }
}

std::string nextId()
{
    std::ostringstream ss;
    ss << std::setw(4) << std::setfill('0') << gConfig.nextCaptureId++;
    return ss.str();
}

void appendIndex(const json& entry)
{
    fs::create_directories(gConfig.outputDir);
    std::ofstream out(gConfig.outputDir / "capture_index.jsonl", std::ios::binary | std::ios::app);
    out << entry.dump() << "\n";
}

std::string lowerAscii(std::string text)
{
    std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return text;
}

bool analysisHooksEnabled()
{
    if (gConfig.analysisHooks == AnalysisHooksMode::On)
        return true;
    if (gConfig.analysisHooks == AnalysisHooksMode::Off)
        return false;
    return gConfig.executionMode == rbx::runtime::ExecutionMode::Diagnostic && gConfig.profile != "roblox-client";
}

rbx::runtime::FilesystemPolicy effectiveFilesystemPolicy()
{
    if (gConfig.filesystemPolicy != rbx::runtime::FilesystemPolicy::ProfileDefault)
        return gConfig.filesystemPolicy;
    return gConfig.profile == "executor-client" ? rbx::runtime::FilesystemPolicy::Memory : rbx::runtime::FilesystemPolicy::Disabled;
}

rbx::runtime::NetworkPolicyConfig nativeNetworkPolicy()
{
    rbx::runtime::NetworkPolicyConfig policy;
    policy.mode = gConfig.networkPolicy == NetworkPolicy::Live ? rbx::runtime::NetworkMode::Live
        : gConfig.networkPolicy == NetworkPolicy::Allowlist              ? rbx::runtime::NetworkMode::Allowlist
                                                                         : rbx::runtime::NetworkMode::Offline;
    policy.allowedHosts.insert(gConfig.allowHosts.begin(), gConfig.allowHosts.end());
    policy.allowPrivateNetwork = gConfig.allowPrivateNetwork;
    return policy;
}

std::string parseUrlHost(const std::string& url)
{
    size_t scheme = url.find("://");
    size_t start = scheme == std::string::npos ? 0 : scheme + 3;
    size_t end = url.find_first_of("/?#", start);
    std::string authority = url.substr(start, end == std::string::npos ? std::string::npos : end - start);
    if (size_t credentials = authority.rfind('@'); credentials != std::string::npos)
        authority.erase(0, credentials + 1);

    std::string host;
    if (!authority.empty() && authority.front() == '[')
    {
        size_t bracket = authority.find(']');
        if (bracket == std::string::npos)
            return {};
        host = authority.substr(1, bracket - 1);
        if (bracket + 1 < authority.size() && authority[bracket + 1] != ':')
            return {};
    }
    else
    {
        size_t colon = authority.rfind(':');
        host = colon == std::string::npos ? authority : authority.substr(0, colon);
        if (host.find(':') != std::string::npos)
            return {}; // IPv6 literals must use URL brackets.
    }
    return lowerAscii(host);
}

bool hasHttpScheme(const std::string& url)
{
    size_t separator = url.find("://");
    if (separator == std::string::npos)
        return false;
    std::string scheme = lowerAscii(url.substr(0, separator));
    return scheme == "http" || scheme == "https";
}

bool isPrivateNetworkHost(const std::string& host)
{
    if (host == "localhost" || host == "::1" || host == "0:0:0:0:0:0:0:1")
        return true;
    std::array<unsigned int, 4> octets{};
    char tail = 0;
    if (std::sscanf(host.c_str(), "%u.%u.%u.%u%c", &octets[0], &octets[1], &octets[2], &octets[3], &tail) == 4 &&
        std::all_of(octets.begin(), octets.end(), [](unsigned int value) { return value <= 255; }))
    {
        return octets[0] == 0 || octets[0] == 10 || octets[0] == 127 || octets[0] >= 224 ||
            (octets[0] == 100 && octets[1] >= 64 && octets[1] <= 127) ||
            (octets[0] == 169 && octets[1] == 254) ||
            (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31) ||
            (octets[0] == 192 && octets[1] == 168);
    }
    std::string lower = lowerAscii(host);
    return lower.rfind("fc", 0) == 0 || lower.rfind("fd", 0) == 0 || lower.rfind("fe8", 0) == 0 ||
        lower.rfind("fe9", 0) == 0 || lower.rfind("fea", 0) == 0 || lower.rfind("feb", 0) == 0;
}

bool hostAllowed(const std::string& url)
{
    if (!hasHttpScheme(url) || parseUrlHost(url).empty())
        return false;
    if (gConfig.fixtures.find(url) != gConfig.fixtures.end())
        return true;
    const std::string host = parseUrlHost(url);
    if (isPrivateNetworkHost(host) && !gConfig.allowPrivateNetwork)
        return false;
    if (gConfig.networkPolicy == NetworkPolicy::Live)
        return true;
    if (gConfig.networkPolicy == NetworkPolicy::Offline)
        return false;
    return gConfig.allowHosts.find(host) != gConfig.allowHosts.end();
}

bool privateSocketAddress(const curl_sockaddr* address)
{
    if (!address)
        return true;
    if (address->family == AF_INET)
    {
        const auto* ipv4 = reinterpret_cast<const sockaddr_in*>(&address->addr);
        const uint32_t value = ntohl(ipv4->sin_addr.s_addr);
        const unsigned int a = (value >> 24) & 0xff;
        const unsigned int b = (value >> 16) & 0xff;
        return a == 0 || a == 10 || a == 127 || a >= 224 ||
            (a == 100 && b >= 64 && b <= 127) ||
            (a == 169 && b == 254) ||
            (a == 172 && b >= 16 && b <= 31) ||
            (a == 192 && (b == 0 || b == 168)) ||
            (a == 198 && (b == 18 || b == 19));
    }
    if (address->family == AF_INET6)
    {
        const auto* ipv6 = reinterpret_cast<const sockaddr_in6*>(&address->addr);
        const unsigned char* bytes = reinterpret_cast<const unsigned char*>(&ipv6->sin6_addr);
        bool allZero = true;
        for (int index = 0; index < 16; ++index)
            allZero = allZero && bytes[index] == 0;
        if (allZero || (std::all_of(bytes, bytes + 15, [](unsigned char byte) { return byte == 0; }) && bytes[15] == 1))
            return true;
        if ((bytes[0] & 0xfe) == 0xfc || (bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80) || bytes[0] == 0xff)
            return true;
        const bool mappedIpv4 = std::all_of(bytes, bytes + 10, [](unsigned char byte) { return byte == 0; }) && bytes[10] == 0xff && bytes[11] == 0xff;
        if (mappedIpv4)
        {
            const unsigned int a = bytes[12];
            const unsigned int b = bytes[13];
            return a == 0 || a == 10 || a == 127 || a >= 224 ||
                (a == 100 && b >= 64 && b <= 127) || (a == 169 && b == 254) ||
                (a == 172 && b >= 16 && b <= 31) || (a == 192 && (b == 0 || b == 168));
        }
        return false;
    }
    return true;
}

curl_socket_t guardedOpenSocket(void*, curlsocktype, curl_sockaddr* address)
{
    if (!gConfig.allowPrivateNetwork && privateSocketAddress(address))
        return CURL_SOCKET_BAD;
    return ::socket(address->family, address->socktype, address->protocol);
}

fs::path compatTracePath()
{
    return gConfig.traceCompatPath.empty() ? (gConfig.outputDir / "compat_trace.jsonl") : gConfig.traceCompatPath;
}

void traceCompat(const std::string& kind, const std::string& name, const json& detail = json::object())
{
    json entry = detail;
    entry["kind"] = kind;
    entry["name"] = name;
    if (kind == "network_blocked" && gNetworkRequirements.size() < 64)
    {
        const std::string fallbackPolicy = gConfig.networkPolicy == NetworkPolicy::Offline ? "offline"
            : gConfig.networkPolicy == NetworkPolicy::Live                                  ? "live"
                                                                                             : "allowlist";
        const std::string policy = detail.value("policy", fallbackPolicy);
        json requirement = {
            {"host", detail.value("host", "")},
            {"url", name},
            {"policy", policy},
            {"reason", detail.value("reason", "network_policy")},
        };
        bool duplicate = std::any_of(gNetworkRequirements.begin(), gNetworkRequirements.end(), [&](const json& existing) {
            return existing.value("host", "") == requirement.value("host", "") && existing.value("url", "") == requirement.value("url", "");
        });
        if (!duplicate)
            gNetworkRequirements.push_back(std::move(requirement));
        if (!detail.value("host", "").empty())
        {
            gBlockedReason = {
                {"kind", "network_host"},
                {"name", detail.value("host", "")},
                {"url", name},
                {"policy", policy},
            };
        }
    }
    if (gCompatReportEvents.size() < 4096)
        gCompatReportEvents.push_back(entry);

    fs::path path = compatTracePath();
    fs::create_directories(path.parent_path());
    std::ofstream out(path, std::ios::binary | std::ios::app);
    out << entry.dump() << "\n";
}

std::string bracketedErrorField(std::string_view message, std::string_view field)
{
    const std::string prefix = "[" + std::string(field) + "=";
    const size_t start = message.find(prefix);
    if (start == std::string_view::npos)
        return {};
    const size_t valueStart = start + prefix.size();
    const size_t end = message.find(']', valueStart);
    return end == std::string_view::npos ? std::string() : std::string(message.substr(valueStart, end - valueStart));
}

void recordNativeNetworkRequirement(std::string_view message)
{
    const std::string host = bracketedErrorField(message, "required-host");
    if (host.empty())
        return;
    std::string url = bracketedErrorField(message, "url");
    if (url.empty())
        url = "https://" + host + "/";
    traceCompat("network_blocked", url, {
        {"host", host},
        {"policy", gConfig.networkPolicy == NetworkPolicy::Offline ? "offline" : "allowlist"},
        {"reason", "native_network_policy"},
    });
}

std::string clockModeName(ClockMode mode)
{
    return mode == ClockMode::Realtime ? "realtime" : "virtual";
}

bool strictUnsupported()
{
    if (gConfig.unsupportedPolicy == UnsupportedPolicy::Error)
        return true;
    if (gConfig.unsupportedPolicy == UnsupportedPolicy::TraceNil)
        return false;
    return gConfig.profile == "roblox-client";
}

std::string unsupportedPolicyName()
{
    return strictUnsupported() ? "error" : "trace-nil";
}

std::string registerOverflowModeName(RegisterOverflowMode mode)
{
    return mode == RegisterOverflowMode::Spill ? "spill" : "error";
}

std::string apiDumpSummaryJson()
{
    std::string output;
    for (size_t i = 0; i < kApiDumpSummaryJsonPartCount; ++i)
        output += kApiDumpSummaryJsonParts[i];
    return output;
}

std::string luraphModeName(LuraphMode mode)
{
    switch (mode)
    {
    case LuraphMode::Off:
        return "off";
    case LuraphMode::Force:
        return "force";
    case LuraphMode::Auto:
    default:
        return "auto";
    }
}

std::string ownerProtectionModeName(OwnerProtectionMode mode)
{
    switch (mode)
    {
    case OwnerProtectionMode::Respect:
        return "respect";
    case OwnerProtectionMode::Ignore:
        return "ignore";
    case OwnerProtectionMode::Audit:
        return "audit";
    }
    return "respect";
}

std::string analysisHooksModeName(AnalysisHooksMode mode)
{
    switch (mode)
    {
    case AnalysisHooksMode::Auto:
        return "auto";
    case AnalysisHooksMode::On:
        return "on";
    case AnalysisHooksMode::Off:
        return "off";
    }
    return "auto";
}

std::string siftApiKeySourceName()
{
    if (!gConfig.siftApiKey.empty())
        return "cli";

    const char* value = std::getenv(gConfig.siftApiKeyEnv.c_str());
    if (value && value[0] != '\0')
        return gConfig.siftApiKeyEnv;

    if (!kBuiltInSiftApiKey.empty())
        return "built_in";

    return "none";
}

bool hasPrefix(std::string_view text, std::string_view prefix)
{
    return text.size() >= prefix.size() && text.substr(0, prefix.size()) == prefix;
}

bool containsText(std::string_view haystack, std::string_view needle)
{
    return haystack.find(needle) != std::string_view::npos;
}

double printableRatio(std::string_view data)
{
    if (data.empty())
        return 1.0;

    size_t printable = 0;
    for (unsigned char c : data)
    {
        if ((c >= 32 && c < 127) || c == '\n' || c == '\r' || c == '\t')
            ++printable;
    }
    return static_cast<double>(printable) / static_cast<double>(data.size());
}

std::string bytesToHex(std::string_view data)
{
    static constexpr char hex[] = "0123456789abcdef";
    std::string out;
    out.resize(data.size() * 2);
    for (size_t i = 0; i < data.size(); ++i)
    {
        unsigned char c = static_cast<unsigned char>(data[i]);
        out[i * 2] = hex[c >> 4];
        out[i * 2 + 1] = hex[c & 0x0f];
    }
    return out;
}

bool isValidUtf8(std::string_view data)
{
    size_t i = 0;
    auto continuation = [&](size_t offset) {
        return i + offset < data.size() && (static_cast<unsigned char>(data[i + offset]) & 0xc0) == 0x80;
    };
    while (i < data.size())
    {
        const unsigned char lead = static_cast<unsigned char>(data[i]);
        if (lead <= 0x7f)
        {
            ++i;
            continue;
        }
        if (lead >= 0xc2 && lead <= 0xdf && continuation(1))
        {
            i += 2;
            continue;
        }
        if (lead >= 0xe0 && lead <= 0xef && continuation(1) && continuation(2))
        {
            const unsigned char second = static_cast<unsigned char>(data[i + 1]);
            if ((lead != 0xe0 || second >= 0xa0) && (lead != 0xed || second <= 0x9f))
            {
                i += 3;
                continue;
            }
        }
        if (lead >= 0xf0 && lead <= 0xf4 && continuation(1) && continuation(2) && continuation(3))
        {
            const unsigned char second = static_cast<unsigned char>(data[i + 1]);
            if ((lead != 0xf0 || second >= 0x90) && (lead != 0xf4 || second <= 0x8f))
            {
                i += 4;
                continue;
            }
        }
        return false;
    }
    return true;
}

json luaStringJson(std::string_view value)
{
    if (isValidUtf8(value))
        return std::string(value);
    return {
        {"type", "binary-string"},
        {"encoding", "hex"},
        {"bytes", value.size()},
        {"data", bytesToHex(value)},
    };
}

std::string jsonSafeText(std::string value)
{
    if (isValidUtf8(value))
        return value;
    for (char& character : value)
    {
        if (static_cast<unsigned char>(character) >= 0x80)
            character = '?';
    }
    return value;
}

bool looksLikeLuraphWorkload(std::string_view source)
{
    return containsText(source, "LPH@") || containsText(source, "LPH$") || containsText(source, "Luraph") ||
           containsText(source, "luaauth.com") || containsText(source, "):d()(") || containsText(source, "):q()(");
}

std::string previewText(std::string_view data, size_t maxBytes = 160)
{
    std::string out;
    out.reserve(std::min(maxBytes, data.size()));
    for (size_t i = 0; i < data.size() && i < maxBytes; ++i)
    {
        unsigned char c = static_cast<unsigned char>(data[i]);
        if ((c >= 32 && c < 127) || c == '\n' || c == '\r' || c == '\t')
            out.push_back(static_cast<char>(c));
        else
            out.push_back('.');
    }
    return out;
}

bool looksLikeJsonDocument(std::string_view data)
{
    size_t start = 0;
    while (start < data.size() && std::isspace(static_cast<unsigned char>(data[start])))
        ++start;
    if (start >= data.size() || (data[start] != '{' && data[start] != '['))
        return false;

    std::string_view sample = data.substr(start, std::min<size_t>(data.size() - start, 2048));
    return containsText(sample, "\":") || (data[start] == '[' && containsText(sample, "{"));
}

std::string_view trimWhitespace(std::string_view data)
{
    size_t start = 0;
    while (start < data.size() && std::isspace(static_cast<unsigned char>(data[start])))
        ++start;

    size_t end = data.size();
    while (end > start && std::isspace(static_cast<unsigned char>(data[end - 1])))
        --end;

    return data.substr(start, end - start);
}

bool looksLikeStandaloneStringLiteral(std::string_view data)
{
    data = trimWhitespace(data);
    if (data.size() < 2)
        return false;

    char quote = data.front();
    if (quote == '"' || quote == '\'')
    {
        bool escaped = false;
        for (size_t i = 1; i < data.size(); ++i)
        {
            char c = data[i];
            if (escaped)
            {
                escaped = false;
                continue;
            }
            if (c == '\\')
            {
                escaped = true;
                continue;
            }
            if (c == quote)
                return i + 1 == data.size();
        }
        return false;
    }

    if (data.front() != '[')
        return false;

    size_t marker = 1;
    while (marker < data.size() && data[marker] == '=')
        ++marker;
    if (marker >= data.size() || data[marker] != '[')
        return false;

    size_t equals = marker - 1;
    if (data.size() < equals + 4 || data.back() != ']')
        return false;

    size_t closeStart = data.size() - equals - 2;
    if (data[closeStart] != ']')
        return false;
    for (size_t i = 0; i < equals; ++i)
    {
        if (data[closeStart + 1 + i] != '=')
            return false;
    }

    return true;
}

bool parsesAsNonEmptyLuauChunk(std::string_view data)
{
    Luau::Allocator allocator;
    Luau::AstNameTable names(allocator);
    Luau::ParseResult result = Luau::Parser::parse(data.data(), data.size(), names, allocator);

    return result.root && result.errors.empty() && result.root->body.size > 0;
}

size_t countTextOccurrences(std::string_view data, std::string_view needle)
{
    if (needle.empty())
        return 0;

    size_t count = 0;
    size_t offset = 0;
    while ((offset = data.find(needle, offset)) != std::string_view::npos)
    {
        ++count;
        offset += needle.size();
    }
    return count;
}

bool looksLikeGeneratedLuraphInterpreter(std::string_view data)
{
    // Luraph creates a large parser-valid dispatcher and passes its VM state
    // through the chunk vararg. That generated loader is useful evidence, but
    // it is not the protected program's original source.
    if (data.size() < 16 * 1024)
        return false;

    const std::string_view trimmed = trimWhitespace(data);
    const std::string_view prefix = trimmed.substr(0, std::min<size_t>(256, trimmed.size()));
    if (!prefix.starts_with("local ") || !containsText(prefix, "=...;return({"))
        return false;

    return containsText(data, "coroutine.yield") &&
           countTextOccurrences(data, "while true do") >= 8 &&
           countTextOccurrences(data, "function(") >= 32;
}

std::string classifyCapturedText(std::string_view kind, std::string_view data, std::string& reason)
{
    const std::string_view markerPrefix = data.substr(0, std::min<size_t>(4096, data.size()));
    if (hasPrefix(data, "LPH@") || hasPrefix(data, "LPH$") ||
        (data.size() > 1024 && (containsText(markerPrefix, "LPH@") || containsText(markerPrefix, "LPH$"))))
    {
        reason = "Luraph packed blob marker";
        return "packed_blob";
    }

    double ratio = printableRatio(data);
    if (ratio < 0.85 || data.find('\0') != std::string_view::npos)
    {
        reason = "binary or low-printable payload";
        return "bytecode_blob";
    }

    bool sourceBearingKind =
        containsText(kind, "loadstring") || kind == "httpget" || kind == "main_return_1" ||
        containsText(kind, "string_") || containsText(kind, "table_concat") ||
        containsText(kind, "buffer_tostring") || containsText(kind, "coroutine_");
    sourceBearingKind = sourceBearingKind || containsText(kind, "nested_string") || containsText(kind, "upvalue");

    bool hasPrimaryLuauToken =
        containsText(data, "local ") || containsText(data, "function") || containsText(data, "return") ||
        containsText(data, "game") || containsText(data, "loadstring") || containsText(data, "getgenv") ||
        containsText(data, "if ") || containsText(data, " then") || containsText(data, "end") ||
        containsText(data, "for ") || containsText(data, "while ");
    bool hasAssignmentShape = containsText(data, "=") && (containsText(data, "\n") || data.size() >= 24);

    const std::string_view sourcePrefix = data.substr(0, std::min<size_t>(1024, data.size()));
    if (sourceBearingKind && data.size() >= 8 && !looksLikeJsonDocument(data) && (hasPrimaryLuauToken || hasAssignmentShape) &&
        !containsText(sourcePrefix, "LPH@") && !containsText(sourcePrefix, "LPH$"))
    {
        if (looksLikeStandaloneStringLiteral(data))
        {
            reason = "standalone string literal is not exact Luau source";
            return "intermediate_noise";
        }

        if (!parsesAsNonEmptyLuauChunk(data))
        {
            reason = "Luau parser rejected source candidate";
            return "intermediate_noise";
        }

        const bool closureBridge =
            containsText(data, "return setfenv(function(...) return ") &&
            containsText(data, "setmetatable({") &&
            containsText(data, "__index = getfenv((...))") &&
            containsText(data, "= ...");
        if (closureBridge)
        {
            reason = "generated source bridge delegates to a runtime-supplied closure; it is not standalone payload source";
            return "closure_bridge";
        }

        if (looksLikeGeneratedLuraphInterpreter(data))
        {
            reason = "generated Luraph VM interpreter source is not original payload source";
            return "generated_vm_interpreter";
        }

        reason = "runtime source-bearing path produced Luau-looking text";
        return "exact_source_candidate";
    }

    reason = "text did not look like exact Luau source";
    return "intermediate_noise";
}

void writeLuraphReport()
{
    if (!gLuraph.active)
        return;

    uint64_t stepsSinceProgress = gInterruptCounter >= gLastLuraphProgressStep ? gInterruptCounter - gLastLuraphProgressStep : 0;
    bool hasArtifact =
        !gLuraph.packedBlobPath.empty() || !gLuraph.bytecodePath.empty() || !gLuraph.functionDumpPath.empty() || !gLuraph.bridgeSourcePath.empty() ||
        !gLuraph.generatedInterpreterPath.empty() || !gLuraph.fallbackPath.empty() ||
        !gLuraph.exactSourcePath.empty();

    json payloadEvents = json::array();
    for (size_t index = 0; index < gCapturedStdout.size(); ++index)
    {
        payloadEvents.push_back({
            {"sequence", index + 1},
            {"kind", "stdout"},
            {"value", gCapturedStdout[index]},
        });
    }
    for (size_t index = 0; index < gCapturedStderr.size(); ++index)
    {
        payloadEvents.push_back({
            {"sequence", gCapturedStdout.size() + index + 1},
            {"kind", "stderr"},
            {"value", gCapturedStderr[index]},
        });
    }
    for (size_t index = 0; index < gMainReportReturns.size(); ++index)
    {
        payloadEvents.push_back({
            {"sequence", gCapturedStdout.size() + gCapturedStderr.size() + index + 1},
            {"kind", "main_return"},
            {"value", gMainReportReturns[index]},
        });
    }

    json report = {
        {"luraph_mode", luraphModeName(gConfig.luraphMode)},
        {"detected", gLuraph.detected},
        {"exact_recovery_status", gLuraph.status},
        {"reason", gLuraph.reason},
        {"vm_execution_status", gLuraph.vmStatus},
        {"decompiler_status", gLuraph.decompilerStatus},
        {"sift_decompile_enabled", gConfig.siftDecompile},
        {"sift_disassemble_enabled", gConfig.siftDisassemble},
        {"sift_api_key_source", siftApiKeySourceName()},
        {"sift_base_url", gConfig.siftBaseUrl},
        {"stop_after_exact_source", gConfig.luraphStopAfterExactSource},
        {"save_intermediates", gConfig.luraphSaveIntermediates},
        {"generated_interpreter_probe", {
            {"configured", !gConfig.luraphGeneratedInterpreterProbePath.empty()},
            {"applied", gLuraph.generatedInterpreterProbeApplied},
            {"path", gConfig.luraphGeneratedInterpreterProbePath.empty()
                ? json(nullptr) : json(gConfig.luraphGeneratedInterpreterProbePath.string())},
        }},
        {"max_steps", gConfig.luraphMaxSteps},
        {"stall_steps", gConfig.luraphStallSteps},
        {"progress_interval_seconds", gConfig.progressIntervalSeconds},
        {"current_step", gInterruptCounter},
        {"last_progress_step", gLastLuraphProgressStep},
        {"steps_since_progress", stepsSinceProgress},
        {"stall_detection_active", gConfig.luraphStallSteps > 0 && hasArtifact && !gLuraph.exactRecovered},
        {"observations", gLuraph.observations},
        {"payload_evidence", {
            {"scope", "script_visible_runtime_behavior"},
            {"source_claim", "none"},
            {"reason", "observable behavior can verify a reconstruction but is not original source"},
            {"event_count", payloadEvents.size()},
            {"events", std::move(payloadEvents)},
        }},
    };

    if (!gLuraph.exactSourcePath.empty())
        report["original_luau_exact"] = gLuraph.exactSourcePath.string();
    if (!gLuraph.bridgeSourcePath.empty())
        report["luraph_runtime_closure_bridge"] = gLuraph.bridgeSourcePath.string();
    if (!gLuraph.generatedInterpreterPath.empty())
        report["luraph_generated_interpreter"] = gLuraph.generatedInterpreterPath.string();
    if (!gLuraph.packedBlobPath.empty())
        report["luraph_packed_blob"] = gLuraph.packedBlobPath.string();
    if (!gLuraph.bytecodePath.empty())
        report["luraph_bytecode_or_prototypes"] = gLuraph.bytecodePath.string();
    if (!gLuraph.functionDumpPath.empty())
        report["luraph_function_dump"] = gLuraph.functionDumpPath.string();
    if (!gLuraph.fallbackPath.empty())
        report["luraph_decompiled_fallback"] = gLuraph.fallbackPath.string();
    if (!gLuraph.siftDecompileResponsePath.empty())
        report["sift_decompile_response"] = gLuraph.siftDecompileResponsePath.string();
    if (!gLuraph.siftDisassembleResponsePath.empty())
        report["sift_disassemble_response"] = gLuraph.siftDisassembleResponsePath.string();
    if (!gLuraph.disassemblyPath.empty())
        report["luraph_disassembly"] = gLuraph.disassemblyPath.string();
    if (!gLuraph.unpackedStatePath.empty())
        report["luraph_unpacked_state"] = gLuraph.unpackedStatePath.string();

    writeFile(gConfig.outputDir / "luraph_recovery_report.json", report.dump(2));
}

void writeLuraphFallbackNote();
void runSiftForBytecode(std::string_view data, const std::string& filename);
void appendLuraphFallbackText(const std::string& text);
void observeCapturedText(const std::string& kind, const fs::path& path, std::string_view data, const json& extra);

std::optional<std::string> decodeAscii85AsLuauU32Buffer(std::string_view text)
{
    std::string output;
    output.reserve((text.size() / 5) * 4);

    uint32_t value = 0;
    int digits = 0;
    for (unsigned char c : text)
    {
        if (std::isspace(c))
            continue;

        if (c == 'z' && digits == 0)
        {
            output.append(4, '\0');
            continue;
        }

        if (c < '!' || c > 'u')
            return std::nullopt;

        value = value * 85u + static_cast<uint32_t>(c - '!');
        ++digits;

        if (digits == 5)
        {
            output.push_back(static_cast<char>(value & 0xff));
            output.push_back(static_cast<char>((value >> 8) & 0xff));
            output.push_back(static_cast<char>((value >> 16) & 0xff));
            output.push_back(static_cast<char>((value >> 24) & 0xff));
            value = 0;
            digits = 0;
        }
    }

    if (digits != 0)
        return std::nullopt;

    return output;
}

std::optional<std::string> decodeLphPackedBlob(std::string_view data)
{
    size_t marker = data.find("LPH@");
    if (marker == std::string_view::npos)
        marker = data.find("LPH$");
    if (marker == std::string_view::npos)
        return std::nullopt;

    size_t end = data.size();
    for (size_t equals = 0; equals <= 64; ++equals)
    {
        const std::string open = "[" + std::string(equals, '=') + "[";
        if (marker < open.size() || data.substr(marker - open.size(), open.size()) != open)
            continue;
        const std::string close = "]" + std::string(equals, '=') + "]";
        const size_t closeOffset = data.find(close, marker + 4);
        if (closeOffset == std::string_view::npos)
            return std::nullopt;
        end = closeOffset;
        break;
    }
    return decodeAscii85AsLuauU32Buffer(data.substr(marker + 4, end - marker - 4));
}

std::optional<std::string_view> findLphPackedCarrier(std::string_view source)
{
    size_t marker = source.find("LPH@");
    if (marker == std::string_view::npos)
        marker = source.find("LPH$");
    if (marker == std::string_view::npos)
        return std::nullopt;
    for (size_t equals = 0; equals <= 64; ++equals)
    {
        const std::string open = "[" + std::string(equals, '=') + "[";
        if (marker < open.size() || source.substr(marker - open.size(), open.size()) != open)
            continue;
        const std::string close = "]" + std::string(equals, '=') + "]";
        const size_t closeOffset = source.find(close, marker + 4);
        if (closeOffset == std::string_view::npos)
            return std::nullopt;
        return source.substr(marker, closeOffset - marker);
    }
    return std::nullopt;
}

void markLuraphProgress()
{
    if (gLuraph.active)
        gLastLuraphProgressStep = gInterruptCounter;
}

bool hasLuraphExtractionArtifact()
{
    return !gLuraph.packedBlobPath.empty() || !gLuraph.bytecodePath.empty() || !gLuraph.functionDumpPath.empty() || !gLuraph.bridgeSourcePath.empty() ||
           !gLuraph.generatedInterpreterPath.empty() || !gLuraph.fallbackPath.empty() ||
           !gLuraph.exactSourcePath.empty();
}

std::string luraphArtifactSummary()
{
    std::ostringstream out;
    bool first = true;
    auto add = [&](bool present, const char* name) {
        if (!present)
            return;
        if (!first)
            out << ",";
        out << name;
        first = false;
    };

    add(!gLuraph.packedBlobPath.empty(), "packed");
    add(!gLuraph.bytecodePath.empty(), "bytecode");
    add(!gLuraph.functionDumpPath.empty(), "functions");
    add(!gLuraph.bridgeSourcePath.empty(), "bridge");
    add(!gLuraph.generatedInterpreterPath.empty(), "interpreter");
    add(!gLuraph.fallbackPath.empty(), "fallback");
    add(!gLuraph.exactSourcePath.empty(), "exact");

    return first ? "none" : out.str();
}

uint64_t luraphStepsSinceProgress()
{
    if (gInterruptCounter < gLastLuraphProgressStep)
        return 0;
    return gInterruptCounter - gLastLuraphProgressStep;
}

void initializeLuraphRecovery(std::string_view source, const fs::path& scriptPath)
{
    gLuraph = LuraphRecoveryState{};
    if (gConfig.luraphMode == LuraphMode::Off)
        return;

    gLuraph.detected = looksLikeLuraphWorkload(source);
    gLuraph.active = gConfig.luraphMode == LuraphMode::Force || (gConfig.luraphMode == LuraphMode::Auto && gLuraph.detected);

    if (!gLuraph.active)
        return;

    gLuraph.status = "unknown";
    gLuraph.reason = gLuraph.detected ? "Luraph markers detected in input script" : "Luraph mode forced by CLI";
    gLuraph.vmStatus = "initialized";
    markLuraphProgress();
    gLuraph.observations.push_back({
        {"kind", "input_script"},
        {"path", scriptPath.string()},
        {"bytes", source.size()},
        {"classification", gLuraph.detected ? "luraph_wrapper" : "forced_luraph_analysis"},
        {"reason", gLuraph.reason},
    });
    if (gConfig.luraphSaveIntermediates)
        if (const std::optional<std::string_view> carrier = findLphPackedCarrier(source))
            observeCapturedText("input_packed_literal", scriptPath, *carrier, {{"provenance", "static_long_bracket_literal"}});
    writeLuraphReport();
}

void finalizeLuraphRecovery(const std::string& vmStatus, const std::string& reason)
{
    if (!gLuraph.active)
        return;

    gLuraph.vmStatus = vmStatus;
    if (!gLuraph.exactRecovered)
    {
        if (vmStatus == "completed")
        {
            gLuraph.status = "not_present";
            if (!gLuraph.generatedInterpreterPath.empty())
                gLuraph.reason = "VM generated an interpreter and closure bridge, but did not expose original payload source";
            else if (!gLuraph.bytecodePath.empty())
                gLuraph.reason = "only bytecode/prototype-like data was observed";
            else if (!gLuraph.packedBlobPath.empty())
                gLuraph.reason = "packed Luraph blob was observed, but exact source was not present in captured runtime values";
            else if (!gLuraph.functionDumpPath.empty())
                gLuraph.reason = "VM returned functions/prototypes without exposing exact source text";
            else if (!gLuraph.bridgeSourcePath.empty())
                gLuraph.reason = "VM emitted a source bridge to a live closure, not standalone payload source";
            else if (!gLuraph.generatedInterpreterPath.empty())
                gLuraph.reason = "VM generated its interpreter source at runtime, but did not expose original payload source";
            else
                gLuraph.reason = "script completed without exposing exact source";
        }
        else if (vmStatus == "timed_out" || vmStatus == "stalled" || vmStatus == "error")
        {
            gLuraph.status = "blocked";
            gLuraph.reason = reason.empty() ? "VM did not expose exact source before stopping" : reason;
        }
        else if (!reason.empty())
            gLuraph.reason = reason;

        writeLuraphFallbackNote();
    }

    writeLuraphReport();
}

void writeLuraphUnpackedState(std::string_view data, const std::string& classification, const std::string& reason)
{
    if (!gLuraph.active || !gConfig.luraphSaveIntermediates)
        return;

    json state = {
        {"decode_status", classification == "packed_blob" ? "blocked" : "not_applicable"},
        {"decode_reason",
         classification == "packed_blob" ? "packed LPH blob captured; decoded with Luau buffer.writeu32 little-endian word order; exact source was not present in this captured value" : reason},
        {"bytes", data.size()},
        {"printable_ratio", printableRatio(data)},
        {"prefix", previewText(data, 96)},
    };

    std::map<char, size_t> alphabet;
    for (char c : data)
        alphabet[c]++;
    state["unique_byte_count"] = alphabet.size();

    gLuraph.unpackedStatePath = gConfig.outputDir / "luraph_unpacked_state.json";
    writeFile(gLuraph.unpackedStatePath, state.dump(2));
}

void writeLuraphFallbackNote()
{
    if (!gLuraph.active || gLuraph.exactRecovered || !gLuraph.fallbackPath.empty())
        return;

    std::string note =
        "-- No decompiled fallback was generated by this runtime pass.\n"
        "-- Exact source recovery status: " + gLuraph.status + "\n"
        "-- Reason: " + gLuraph.reason + "\n";
    gLuraph.fallbackPath = gConfig.outputDir / "luraph_decompiled_fallback.lua";
    writeFile(gLuraph.fallbackPath, note);
}

void appendLuraphFallbackText(const std::string& text)
{
    if (!gLuraph.active || gLuraph.exactRecovered)
        return;

    if (gLuraph.fallbackPath.empty())
    {
        gLuraph.fallbackPath = gConfig.outputDir / "luraph_decompiled_fallback.lua";
        writeFile(gLuraph.fallbackPath, "");
    }

    appendFile(gLuraph.fallbackPath, text);
}

void observeCapturedText(const std::string& kind, const fs::path& path, std::string_view data, const json& extra)
{
    if (!gLuraph.active)
        return;

    std::string reason;
    std::string classification = classifyCapturedText(kind, data, reason);

    json observation = extra;
    observation["kind"] = kind;
    observation["path"] = path.string();
    observation["bytes"] = data.size();
    observation["classification"] = classification;
    observation["reason"] = reason;
    observation["preview"] = previewText(data);
    gLuraph.observations.push_back(observation);

    if (classification == "packed_blob")
    {
        markLuraphProgress();
        gLuraph.detected = true;
        if (gConfig.luraphSaveIntermediates && gLuraph.packedBlobPath.empty())
        {
            gLuraph.packedBlobPath = gConfig.outputDir / "luraph_packed_blob.txt";
            writeFile(gLuraph.packedBlobPath, data);
            writeLuraphUnpackedState(data, classification, reason);
            if (std::optional<std::string> decoded = decodeLphPackedBlob(data))
            {
                if (!decoded->empty())
                {
                    gLuraph.bytecodePath = gConfig.outputDir / "luraph_bytecode_or_prototypes.bin";
                    writeFile(gLuraph.bytecodePath, *decoded);
                    gLuraph.observations.push_back({
                        {"kind", "luraph_packed_decode"},
                        {"path", gLuraph.bytecodePath.string()},
                        {"bytes", decoded->size()},
                        {"classification", "bytecode_blob"},
                        {"reason", containsText(data, "LPH$")
                            ? "Ascii85-decoded LPH$ payload using Luau buffer.writeu32 little-endian word order and zero shorthand"
                            : "Ascii85-decoded LPH@ payload using Luau buffer.writeu32 little-endian word order"},
                        {"preview", previewText(*decoded)},
                    });
                    markLuraphProgress();
                    runSiftForBytecode(*decoded, "luraph_lph_decoded_payload.luac");
                }
            }
        }
        if (!gLuraph.exactRecovered)
        {
            gLuraph.status = "unknown";
            gLuraph.reason = "captured packed Luraph blob, but exact source has not appeared";
        }
    }
    else if (classification == "bytecode_blob")
    {
        markLuraphProgress();
        if (gConfig.luraphSaveIntermediates && gLuraph.bytecodePath.empty())
        {
            gLuraph.bytecodePath = gConfig.outputDir / "luraph_bytecode_or_prototypes.bin";
            writeFile(gLuraph.bytecodePath, data);
            writeLuraphUnpackedState(data, classification, reason);
        }
        if (!gLuraph.exactRecovered)
        {
            gLuraph.status = "not_present";
            gLuraph.reason = "captured binary bytecode/prototype-like data, not exact source text";
        }
        runSiftForBytecode(data, "luraph_bytecode_or_prototypes.luac");
    }
    else if (classification == "exact_source_candidate")
    {
        markLuraphProgress();
        if (!gLuraph.exactRecovered)
        {
            gLuraph.exactRecovered = true;
            gLuraph.stopRequested = gConfig.luraphStopAfterExactSource;
            gLuraph.status = "recovered";
            gLuraph.reason = "captured exact source text from a runtime source-bearing path";
            gLuraph.exactSourcePath = gConfig.outputDir / "original_luau_exact.lua";
            writeFile(gLuraph.exactSourcePath, data);
        }
    }
    else if (classification == "closure_bridge")
    {
        markLuraphProgress();
        if (gConfig.luraphSaveIntermediates && gLuraph.bridgeSourcePath.empty())
        {
            gLuraph.bridgeSourcePath = gConfig.outputDir / "luraph_runtime_closure_bridge.lua";
            writeFile(gLuraph.bridgeSourcePath, data);
        }
        if (!gLuraph.exactRecovered)
        {
            gLuraph.status = "not_present";
            gLuraph.reason = "captured a generated source bridge to a runtime closure, not exact source text";
        }
    }
    else if (classification == "generated_vm_interpreter")
    {
        markLuraphProgress();
        if (gConfig.luraphSaveIntermediates && gLuraph.generatedInterpreterPath.empty())
        {
            gLuraph.generatedInterpreterPath = gConfig.outputDir / "luraph_generated_interpreter.lua";
            writeFile(gLuraph.generatedInterpreterPath, data);
        }
        if (!gLuraph.exactRecovered)
        {
            gLuraph.status = "not_present";
            gLuraph.reason = "captured the generated Luraph VM interpreter, not original payload source";
        }
    }

    writeLuraphReport();
}

fs::path captureTextImpl(
    const std::string& kind,
    std::string_view data,
    const std::string& extension,
    const json& extra,
    bool hostObservation)
{
    if (!analysisHooksEnabled() && !hostObservation)
        return {};

    std::string id = nextId();
    fs::path path = gConfig.outputDir / (kind + "_" + id + extension);
    writeFile(path, data);

    json entry = extra;
    entry["kind"] = kind;
    entry["path"] = path.string();
    entry["bytes"] = data.size();
    appendIndex(entry);

    observeCapturedText(kind, path, data, extra);

    std::cout << (hostObservation ? "[observe] " : "[capture] ") << kind << ": " << data.size() << " bytes -> " << path << "\n";
    return path;
}

fs::path captureText(const std::string& kind, std::string_view data, const std::string& extension = ".lua", const json& extra = json::object())
{
    return captureTextImpl(kind, data, extension, extra, false);
}

fs::path captureHostObservation(const std::string& kind, std::string_view data, const std::string& extension = ".lua", const json& extra = json::object())
{
    return captureTextImpl(kind, data, extension, extra, true);
}

fs::path captureTextDedup(const std::string& kind, std::string_view data, const std::string& extension = ".lua", const json& extra = json::object())
{
    std::ostringstream fp;
    fp << kind << ":" << data.size() << ":" << std::hash<std::string_view>{}(data);
    if (!gLargeStringFingerprints.insert(fp.str()).second)
        return {};

    return captureText(kind, data, extension, extra);
}

fs::path captureHostObservationDedup(
    const std::string& kind,
    std::string_view data,
    const std::string& extension = ".lua",
    const json& extra = json::object())
{
    std::ostringstream fp;
    fp << kind << ":" << data.size() << ":" << std::hash<std::string_view>{}(data);
    if (!gLargeStringFingerprints.insert(fp.str()).second)
        return {};

    return captureHostObservation(kind, data, extension, extra);
}

std::string trimTypeName(lua_State* L, int index);
std::string valueSummary(lua_State* L, int index);

void captureProtectedErrorNative(lua_State* L)
{
    // This callback runs before Luau unwinds the protected frame. Keep it
    // observational and bounded: no Lua calls, error conversion, or changes to
    // the stack/error object that could alter pcall/xpcall behavior.
    const uint64_t observation = ++gProtectedErrorCount;
    if (!gConfig.tracePcallErrors || observation > 128)
        return;

    const int top = lua_gettop(L);
    const std::string type = top > 0 ? trimTypeName(L, -1) : "none";
    const std::string summary = top > 0 ? valueSummary(L, -1) : "<missing error object>";
    std::ostringstream diagnostic;
    diagnostic << "error_type=" << type << "\n"
               << "error_value=" << summary << "\n"
               << "stack_depth=" << lua_stackdepth(L) << "\n";
    if (const char* trace = lua_debugtrace(L); trace && *trace)
        diagnostic << trace;
    captureHostObservationDedup(
        "pcall_error",
        diagnostic.str(),
        ".txt",
        {{"error_type", type}, {"observation", observation}, {"stack_depth", lua_stackdepth(L)}});
}

void captureMirror(const fs::path& filename, std::string_view data)
{
    if (!analysisHooksEnabled())
        return;
    if (data.size() >= gConfig.captureMinBytes)
        writeFile(gConfig.outputDir / filename, data);
}

bool shouldCaptureAnalysisString(std::string_view kind, std::string_view data)
{
    if (data.size() >= gConfig.captureMinBytes)
        return true;

    if (!gLuraph.active || data.empty())
        return false;

    std::string reason;
    std::string classification = classifyCapturedText(kind, data, reason);
    return classification == "packed_blob" || classification == "bytecode_blob" || classification == "exact_source_candidate" ||
           classification == "closure_bridge" || classification == "generated_vm_interpreter";
}

std::string stackString(lua_State* L, int index)
{
    size_t len = 0;
    const char* text = lua_tolstring(L, index, &len);
    if (!text)
        return lua_typename(L, lua_type(L, index));
    return std::string(text, len);
}

void reportLuaError(lua_State* L, const std::string& context)
{
    std::string message = stackString(L, -1);
    captureText(context, message, ".txt");
    std::cerr << "[" << context << "] " << message << "\n";
}

std::unique_ptr<char, decltype(&std::free)> compileLuau(std::string_view source, size_t& bytecodeSize)
{
    static const char* robloxMutableGlobals[] = {
        "loadstring",
        "getfenv",
        "game",
        "workspace",
        "Workspace",
        "script",
        "HttpService",
        "type",
        "typeof",
        nullptr,
    };
    static const char* executorMutableGlobals[] = {
        "loadstring",
        "getfenv",
        "game",
        "workspace",
        "Workspace",
        "script",
        "HttpService",
        "type",
        "typeof",
        // Executor-client installs private writable copies of these libraries.
        // Declaring them mutable prevents the compiler from baking in builtin
        // fastcalls/imports that would ignore script-installed hooks.
        "math",
        "string",
        "table",
        "coroutine",
        "bit32",
        "utf8",
        "os",
        "debug",
        "buffer",
        "vector",
        nullptr,
    };

    lua_CompileOptions options{};
    options.optimizationLevel = gConfig.luauOptimizationLevel;
    options.debugLevel = gConfig.luauDebugLevel;
    options.typeInfoLevel = 0;
    options.coverageLevel = 0;
    options.mutableGlobals = gConfig.profile == "executor-client" ? executorMutableGlobals : robloxMutableGlobals;

    std::unique_ptr<char, decltype(&std::free)> bytecode(
        luau_compile(source.data(), source.size(), &options, &bytecodeSize), std::free);
    if (gConfig.registerOverflow != RegisterOverflowMode::Spill || !bytecode || bytecodeSize < 2 || bytecode.get()[0] != 0)
        return bytecode;

    const std::string_view compilerError(bytecode.get() + 1, bytecodeSize - 1);
    if (compilerError.find("Out of local registers") == std::string_view::npos &&
        compilerError.find("Out of upvalue registers") == std::string_view::npos)
        return bytecode;

    ++gRegisterOverflowUsage.retries;
    const bool upvalueOverflow = compilerError.find("Out of upvalue registers") != std::string_view::npos;
    const size_t retainedLocalTarget = upvalueOverflow ? 90 : 140;
    rbx::runtime::RegisterOverflowRewrite narrowed = rbx::runtime::narrowRegisterOverflowScopes(source, retainedLocalTarget);
    for (const std::string& diagnostic : narrowed.diagnostics)
        gRegisterOverflowUsage.diagnostics.push_back(diagnostic);

    std::string_view spillInput = source;
    if (narrowed.applied)
    {
        size_t narrowedBytecodeSize = 0;
        std::unique_ptr<char, decltype(&std::free)> narrowedBytecode(
            luau_compile(narrowed.source.data(), narrowed.source.size(), &options, &narrowedBytecodeSize), std::free);
        if (narrowedBytecode && narrowedBytecodeSize >= 2 && narrowedBytecode.get()[0] != 0)
        {
            ++gRegisterOverflowUsage.chunksRewritten;
            ++gRegisterOverflowUsage.chunksNarrowed;
            gRegisterOverflowUsage.functionsRewritten += narrowed.functionsRewritten;
            gRegisterOverflowUsage.declarationsSunk += narrowed.declarationsSunk;
            gRegisterOverflowUsage.bindingsNarrowed += narrowed.bindingsNarrowed;
            gRegisterOverflowUsage.scopesNarrowed += narrowed.scopesNarrowed;
            bytecodeSize = narrowedBytecodeSize;
            return narrowedBytecode;
        }

        const std::string_view narrowedError = narrowedBytecode && narrowedBytecodeSize >= 2
            ? std::string_view(narrowedBytecode.get() + 1, narrowedBytecodeSize - 1)
            : std::string_view();
        if (narrowedError.find("Out of local registers") == std::string_view::npos &&
            narrowedError.find("Out of upvalue registers") == std::string_view::npos)
        {
            gRegisterOverflowUsage.diagnostics.push_back("lexical lifetime narrowing produced a non-register compiler diagnostic; preserving the original compiler result");
            return bytecode;
        }
        spillInput = narrowed.source;
    }

    rbx::runtime::RegisterOverflowRewrite rewritten = rbx::runtime::spillRegisterOverflow(spillInput, retainedLocalTarget);
    for (const std::string& diagnostic : rewritten.diagnostics)
        gRegisterOverflowUsage.diagnostics.push_back(diagnostic);
    if (!rewritten.applied)
        return bytecode;

    size_t rewrittenBytecodeSize = 0;
    std::unique_ptr<char, decltype(&std::free)> rewrittenBytecode(
        luau_compile(rewritten.source.data(), rewritten.source.size(), &options, &rewrittenBytecodeSize), std::free);
    if (!rewrittenBytecode || rewrittenBytecodeSize < 2 || rewrittenBytecode.get()[0] == 0)
        return bytecode;

    ++gRegisterOverflowUsage.chunksRewritten;
    if (narrowed.applied)
    {
        ++gRegisterOverflowUsage.chunksNarrowed;
        gRegisterOverflowUsage.functionsRewritten += narrowed.functionsRewritten;
        gRegisterOverflowUsage.declarationsSunk += narrowed.declarationsSunk;
        gRegisterOverflowUsage.bindingsNarrowed += narrowed.bindingsNarrowed;
        gRegisterOverflowUsage.scopesNarrowed += narrowed.scopesNarrowed;
    }
    gRegisterOverflowUsage.functionsRewritten += rewritten.functionsRewritten;
    gRegisterOverflowUsage.bindingsSpilled += rewritten.bindingsSpilled;
    bytecodeSize = rewrittenBytecodeSize;
    return rewrittenBytecode;
}

bool loadChunk(lua_State* L, std::string_view source, const std::string& chunkName, bool enableNativeCodegen = true)
{
    size_t bytecodeSize = 0;
    auto bytecode = compileLuau(source, bytecodeSize);
    int status = luau_load(L, chunkName.c_str(), bytecode.get(), bytecodeSize, 0);
    if (status != 0)
        return false;

    ++gCodegenUsage.chunksLoaded;
    gCodegenUsage.bytecodeBytes += bytecodeSize;

    if (enableNativeCodegen && gConfig.nativeCodegen && Luau::CodeGen::isSupported() && Luau::CodeGen::isNativeExecutionEnabled(L))
    {
        ++gCodegenUsage.chunksNativeAttempted;
        Luau::CodeGen::CompilationOptions nativeOptions;
        nativeOptions.flags = Luau::CodeGen::CodeGen_ColdFunctions;

        Luau::CodeGen::CompilationStats stats{};
        Luau::CodeGen::CompilationResult result = Luau::CodeGen::compile(L, -1, nativeOptions, &stats);
        if (result.result == Luau::CodeGen::CodeGenCompilationResult::CodeGenAssemblerFinalizationFailure)
        {
            // Luau 0.729 emits one assembler image per module. Very large
            // obfuscated modules can overflow an AArch64 branch displacement
            // when every cold prototype is included, in which case Luau
            // intentionally abandons the whole image. Retry the same loaded
            // closure with its profitable/hot subset so native execution is
            // retained without changing bytecode semantics.
            traceCompat("native_codegen_retry", chunkName, {
                {"reason", Luau::CodeGen::toString(result.result)},
                {"initial_functions_total", stats.functionsTotal},
                {"strategy", "omit_cold_functions"},
            });
            ++gCodegenUsage.chunksNativeRetried;
            nativeOptions.flags = 0;
            stats = {};
            result = Luau::CodeGen::compile(L, -1, nativeOptions, &stats);
        }
        gCodegenUsage.nativeCodeBytes += stats.nativeCodeSizeBytes;
        gCodegenUsage.nativeDataBytes += stats.nativeDataSizeBytes;
        gCodegenUsage.nativeMetadataBytes += stats.nativeMetadataSizeBytes;
        gCodegenUsage.functionsTotal += stats.functionsTotal;
        gCodegenUsage.functionsCompiled += stats.functionsCompiled;
        gCodegenUsage.functionsBound += stats.functionsBound;
        json detail = {
            {"result", Luau::CodeGen::toString(result.result)},
            {"bytecodeBytes", stats.bytecodeSizeBytes},
            {"nativeCodeBytes", stats.nativeCodeSizeBytes},
            {"nativeDataBytes", stats.nativeDataSizeBytes},
            {"nativeMetadataBytes", stats.nativeMetadataSizeBytes},
            {"functionsTotal", stats.functionsTotal},
            {"functionsCompiled", stats.functionsCompiled},
            {"functionsBound", stats.functionsBound},
            {"retriedWithoutColdFunctions", nativeOptions.flags == 0},
        };
        detail["protoFailures"] = json::array();
        for (const Luau::CodeGen::ProtoCompilationFailure& failure : result.protoFailures)
        {
            detail["protoFailures"].push_back({
                {"result", Luau::CodeGen::toString(failure.result)},
                {"debugname", failure.debugname},
                {"line", failure.line},
            });
        }
        if (result.hasErrors())
        {
            ++gCodegenUsage.chunksNativePartial;
            traceCompat("native_codegen_partial", chunkName, detail);
        }
        else
        {
            ++gCodegenUsage.chunksNativeSucceeded;
            if (stats.functionsTotal > 0)
                traceCompat("native_codegen", chunkName, detail);
        }
    }

    return true;
}

std::string trimTypeName(lua_State* L, int index)
{
    if (rbx::v2::isInstance(L, index))
        return "Instance";
    int type = lua_type(L, index);
    switch (type)
    {
    case LUA_TNIL:
        return "nil";
    case LUA_TBOOLEAN:
        return "boolean";
    case LUA_TNUMBER:
    case LUA_TINTEGER:
        return "number";
    case LUA_TSTRING:
        return "string";
    case LUA_TTABLE:
    {
        index = lua_absindex(L, index);
        lua_rawgetfield(L, index, "__type");
        if (lua_isstring(L, -1))
        {
            std::string result = stackString(L, -1);
            lua_pop(L, 1);
            return result;
        }
        lua_pop(L, 1);

        lua_rawgetfield(L, index, "ClassName");
        bool hasClassName = lua_isstring(L, -1);
        lua_pop(L, 1);
        lua_rawgetfield(L, index, "_children");
        bool hasChildren = lua_istable(L, -1);
        lua_pop(L, 1);
        return hasClassName && hasChildren ? "Instance" : "table";
    }
    case LUA_TFUNCTION:
        return "function";
    case LUA_TTHREAD:
        return "thread";
    case LUA_TBUFFER:
        return "buffer";
    case LUA_TVECTOR:
        return "Vector3";
    case LUA_TUSERDATA:
    {
        if (lua_getmetatable(L, index))
        {
            lua_rawgetfield(L, -1, "__type");
            if (lua_isstring(L, -1))
            {
                std::string result = stackString(L, -1);
                lua_pop(L, 2);
                return result;
            }
            lua_pop(L, 2);
        }
        int tag = lua_userdatatag(L, index);
        if (tag == kTagVector2)
            return "Vector2";
        if (tag == kTagVector3)
            return "Vector3";
        if (tag == kTagColor3)
            return "Color3";
        if (tag == kTagUDim)
            return "UDim";
        if (tag == kTagUDim2)
            return "UDim2";
        if (tag == kTagCFrame)
            return "CFrame";
        if (tag == kTagRay)
            return "Ray";
        return "userdata";
    }
    default:
        return lua_typename(L, type);
    }
}

std::string valueSummary(lua_State* L, int index);

json luaValueToJsonImpl(
    lua_State* L, int index, int depth, std::set<const void*>& visitedTables, size_t& valuesVisited)
{
    constexpr size_t MaxSerializedValues = 100000;
    if (depth > 64)
        return "<max-depth>";
    if (++valuesVisited > MaxSerializedValues)
        return "<value-limit>";

    index = lua_absindex(L, index);
    switch (lua_type(L, index))
    {
    case LUA_TNIL:
        return nullptr;
    case LUA_TBOOLEAN:
        return lua_toboolean(L, index) != 0;
    case LUA_TNUMBER:
    case LUA_TINTEGER:
        return lua_tonumber(L, index);
    case LUA_TSTRING:
    {
        size_t len = 0;
        const char* s = lua_tolstring(L, index, &len);
        return luaStringJson(std::string_view(s ? s : "", len));
    }
    case LUA_TTABLE:
    {
        const void* identity = lua_topointer(L, index);
        if (!visitedTables.insert(identity).second)
            return "<cycle-or-reference>";

        struct Entry
        {
            int intKey = 0;
            std::string stringKey;
            json value;
            bool arrayKey = false;
        };

        std::vector<Entry> entries;
        bool allArrayKeys = true;
        int maxIndex = 0;
        bool truncated = false;

        lua_pushnil(L);
        while (lua_next(L, index) != 0)
        {
            if (entries.size() >= 4096)
            {
                lua_pop(L, 2);
                truncated = true;
                allArrayKeys = false;
                break;
            }
            Entry entry;
            int isNum = 0;
            double numericKey = lua_tonumberx(L, -2, &isNum);
            if (isNum && numericKey >= 1 && std::floor(numericKey) == numericKey && numericKey <= std::numeric_limits<int>::max())
            {
                entry.arrayKey = true;
                entry.intKey = static_cast<int>(numericKey);
                maxIndex = std::max(maxIndex, entry.intKey);
            }
            else
            {
                allArrayKeys = false;
                if (lua_type(L, -2) == LUA_TSTRING)
                {
                    std::string key = stackString(L, -2);
                    entry.stringKey = isValidUtf8(key) ? std::move(key) : "<binary-key:" + bytesToHex(key) + ">";
                }
                else
                    entry.stringKey = valueSummary(L, -2);
            }

            entry.value = luaValueToJsonImpl(L, -1, depth + 1, visitedTables, valuesVisited);
            entries.push_back(std::move(entry));
            lua_pop(L, 1);
        }

        if (allArrayKeys && maxIndex == static_cast<int>(entries.size()))
        {
            json result = json::array();
            for (int i = 0; i < maxIndex; ++i)
                result.push_back(nullptr);
            for (const Entry& entry : entries)
                result[entry.intKey - 1] = entry.value;
            return result;
        }

        json result = json::object();
        for (const Entry& entry : entries)
        {
            if (entry.arrayKey)
                result[std::to_string(entry.intKey)] = entry.value;
            else
                result[entry.stringKey] = entry.value;
        }
        if (truncated)
            result["<truncated>"] = true;
        return result;
    }
    default:
        return valueSummary(L, index);
    }
}

json luaValueToJson(lua_State* L, int index, int depth)
{
    std::set<const void*> visitedTables;
    size_t valuesVisited = 0;
    return luaValueToJsonImpl(L, index, depth, visitedTables, valuesVisited);
}

json typedLuaValueToJson(lua_State* L, int index, size_t returnIndex)
{
    index = lua_absindex(L, index);
    const char* kind = lua_typename(L, lua_type(L, index));
    json result = {{"index", returnIndex}, {"kind", kind ? kind : "unknown"}};
    switch (lua_type(L, index))
    {
    case LUA_TNIL:
        result["value"] = nullptr;
        break;
    case LUA_TBOOLEAN:
        result["value"] = lua_toboolean(L, index) != 0;
        break;
    case LUA_TNUMBER:
    case LUA_TINTEGER:
    {
        double value = lua_tonumber(L, index);
        if (std::isnan(value))
            result["number"] = "nan";
        else if (std::isinf(value))
            result["number"] = value < 0 ? "-infinity" : "infinity";
        else if (value == 0 && std::signbit(value))
            result["number"] = "-0";
        else
            result["value"] = value;
        break;
    }
    case LUA_TSTRING:
    {
        size_t length = 0;
        const char* value = lua_tolstring(L, index, &length);
        result["value"] = luaStringJson(std::string_view(value ? value : "", length));
        result["bytes"] = length;
        break;
    }
    default:
        result["value"] = luaValueToJson(L, index, 0);
        result["summary"] = valueSummary(L, index);
        break;
    }
    return result;
}

void pushJsonValue(lua_State* L, const json& value, int depth = 0)
{
    if (depth > 64 || value.is_null())
    {
        lua_pushnil(L);
        return;
    }

    if (value.is_boolean())
        lua_pushboolean(L, value.get<bool>());
    else if (value.is_number_integer())
        lua_pushnumber(L, static_cast<double>(value.get<int64_t>()));
    else if (value.is_number_unsigned())
        lua_pushnumber(L, static_cast<double>(value.get<uint64_t>()));
    else if (value.is_number_float())
        lua_pushnumber(L, value.get<double>());
    else if (value.is_string())
    {
        const std::string& s = value.get_ref<const std::string&>();
        lua_pushlstring(L, s.data(), s.size());
    }
    else if (value.is_array())
    {
        lua_createtable(L, static_cast<int>(value.size()), 0);
        int tableIndex = lua_gettop(L);
        int i = 1;
        for (const json& child : value)
        {
            pushJsonValue(L, child, depth + 1);
            lua_rawseti(L, tableIndex, i++);
        }
    }
    else if (value.is_object())
    {
        lua_createtable(L, 0, static_cast<int>(value.size()));
        int tableIndex = lua_gettop(L);
        for (auto it = value.begin(); it != value.end(); ++it)
        {
            pushJsonValue(L, it.value(), depth + 1);
            lua_setfield(L, tableIndex, it.key().c_str());
        }
    }
    else
        lua_pushnil(L);
}

std::string valueSummary(lua_State* L, int index)
{
    int type = lua_type(L, index);
    if (type == LUA_TSTRING)
    {
        size_t len = 0;
        const char* text = lua_tolstring(L, index, &len);
        if (!text)
            return "";
        std::string preview(text, std::min<size_t>(len, 80));
        for (char& c : preview)
        {
            unsigned char uc = static_cast<unsigned char>(c);
            if (uc < 32 || uc == 127 || uc >= 128)
                c = '.';
        }
        if (len > preview.size())
            preview += "...(" + std::to_string(len) + " bytes)";
        return preview;
    }
    if (type == LUA_TBOOLEAN)
        return lua_toboolean(L, index) ? "true" : "false";
    if (type == LUA_TNUMBER || type == LUA_TINTEGER)
    {
        std::ostringstream ss;
        ss << lua_tonumber(L, index);
        return ss.str();
    }
    return trimTypeName(L, index);
}

std::string compactLabel(std::string text, size_t limit = 96)
{
    for (char& c : text)
    {
        unsigned char uc = static_cast<unsigned char>(c);
        if (uc < 32 || uc == 127 || uc >= 128)
            c = '.';
    }

    if (text.size() > limit)
        text = text.substr(0, limit) + "...";
    return text;
}

std::string shallowTableSummary(lua_State* L, int index, int maxEntries = 8)
{
    std::ostringstream out;
    index = lua_absindex(L, index);
    out << "table{";

    int shown = 0;
    int total = 0;
    lua_pushnil(L);
    while (lua_next(L, index) != 0)
    {
        ++total;
        if (shown < maxEntries)
        {
            if (shown > 0)
                out << ", ";
            out << compactLabel(valueSummary(L, -2), 32) << "=" << compactLabel(valueSummary(L, -1), 48);
            ++shown;
        }
        lua_pop(L, 1);
    }

    if (total > shown)
        out << ", ...";
    out << "} entries=" << total;
    return out.str();
}

void capturePotentialPayloadString(lua_State* L, int index, const std::string& label)
{
    if (!gLuraph.active)
        return;

    size_t len = 0;
    const char* text = lua_tolstring(L, index, &len);
    if (!text)
        return;

    std::string_view data(text, len);
    if (!shouldCaptureAnalysisString("luraph_nested_string", data))
        return;

    bool binary = data.find('\0') != std::string_view::npos || printableRatio(data) < 0.65;
    captureTextDedup("luraph_nested_string", data, binary ? ".bin" : ".lua", {{"label", label}});
}

fs::path captureFunctionSnapshotString(lua_State* L, int index, const std::string& label)
{
    size_t len = 0;
    const char* text = lua_tolstring(L, index, &len);
    if (!text)
        return {};

    std::string_view data(text, len);
    if (!shouldCaptureAnalysisString("function_snapshot_string", data))
        return {};

    bool binary = data.find('\0') != std::string_view::npos || printableRatio(data) < 0.65;
    return captureTextDedup("function_snapshot_string", data, binary ? ".bin" : ".lua", {{"label", label}});
}

json tablePreviewToJson(lua_State* L, int index, int maxEntries = 96, int depth = 0, int maxDepth = 3, bool captureStrings = false, const std::string& labelPrefix = "")
{
    json entries = json::array();
    index = lua_absindex(L, index);

    int seen = 0;
    lua_pushnil(L);
    while (lua_next(L, index) != 0)
    {
        json entry = {
            {"key_type", trimTypeName(L, -2)},
            {"key", valueSummary(L, -2)},
            {"value_type", trimTypeName(L, -1)},
            {"value", valueSummary(L, -1)},
        };

        if (lua_type(L, -2) == LUA_TNUMBER || lua_type(L, -2) == LUA_TINTEGER)
            entry["numeric_key"] = lua_tonumber(L, -2);
        else if (lua_type(L, -2) == LUA_TSTRING)
        {
            size_t keyLen = 0;
            const char* keyText = lua_tolstring(L, -2, &keyLen);
            entry["key_bytes"] = keyLen;
            if (keyText)
                entry["key_hex"] = bytesToHex(std::string_view(keyText, keyLen));
        }

        if (lua_type(L, -1) == LUA_TSTRING)
        {
            size_t len = 0;
            const char* text = lua_tolstring(L, -1, &len);
            entry["bytes"] = len;
            if (text)
            {
                entry["hex"] = bytesToHex(std::string_view(text, len));
                std::string reason;
                entry["classification"] = classifyCapturedText("table_preview", std::string_view(text, len), reason);
                if (!reason.empty())
                    entry["reason"] = reason;
            }
            if (captureStrings)
            {
                std::string keyLabel = compactLabel(valueSummary(L, -2), 64);
                std::string childLabel = labelPrefix.empty() ? keyLabel : labelPrefix + "." + keyLabel;
                fs::path captured = captureFunctionSnapshotString(L, -1, childLabel);
                if (!captured.empty())
                    entry["capture_path"] = captured.string();
            }
        }
        else if (lua_type(L, -1) == LUA_TTABLE)
        {
            int count = 0;
            lua_pushnil(L);
            while (lua_next(L, -2) != 0)
            {
                ++count;
                lua_pop(L, 1);
                if (count >= 1000)
                {
                    lua_pop(L, 1);
                    break;
                }
            }
            entry["table_entries_seen"] = count;
            if (depth < maxDepth)
            {
                std::string keyLabel = compactLabel(valueSummary(L, -2), 64);
                std::string childPrefix = labelPrefix.empty() ? keyLabel : labelPrefix + "." + keyLabel;
                entry["preview"] = tablePreviewToJson(L, -1, maxEntries, depth + 1, maxDepth, captureStrings, childPrefix);
            }
        }

        entries.push_back(std::move(entry));
        lua_pop(L, 1);

        if (++seen >= maxEntries)
        {
            lua_pop(L, 1);
            break;
        }
    }

    return entries;
}

json functionInfoToJson(lua_State* L, int index, const std::string& label, bool captureSnapshotStrings = false)
{
    index = lua_absindex(L, index);

    json info = {
        {"label", label},
        {"type", trimTypeName(L, index)},
        {"pointer", ""},
        {"source", nullptr},
        {"short_src", nullptr},
        {"linedefined", nullptr},
        {"currentline", nullptr},
        {"name", nullptr},
        {"what", nullptr},
        {"nupvalues", 0},
        {"nparams", 0},
        {"isvararg", false},
        {"upvalues", json::array()},
    };

    {
        std::ostringstream ptr;
        ptr << lua_topointer(L, index);
        info["pointer"] = ptr.str();
    }

    lua_pushvalue(L, index);
    int funcIndex = lua_gettop(L);

    lua_Debug ar{};
    if (lua_getinfo(L, -1, "slnua", &ar))
    {
        if (ar.source)
            info["source"] = ar.source;
        if (ar.short_src)
            info["short_src"] = ar.short_src;
        info["linedefined"] = ar.linedefined;
        info["currentline"] = ar.currentline;
        if (ar.name)
            info["name"] = ar.name;
        if (ar.what)
            info["what"] = ar.what;
        info["nupvalues"] = static_cast<int>(ar.nupvals);
        info["nparams"] = static_cast<int>(ar.nparams);
        info["isvararg"] = ar.isvararg != 0;
    }

    for (int upvalue = 1; upvalue <= 255; ++upvalue)
    {
        const char* name = lua_getupvalue(L, funcIndex, upvalue);
        if (!name)
            break;

        json uv = {
            {"index", upvalue},
            {"name", name},
            {"type", trimTypeName(L, -1)},
            {"summary", valueSummary(L, -1)},
        };

        if (lua_type(L, -1) == LUA_TSTRING)
        {
            size_t len = 0;
            const char* text = lua_tolstring(L, -1, &len);
            uv["bytes"] = len;
            if (text)
                uv["hex"] = bytesToHex(std::string_view(text, len));
            std::string reason;
            uv["classification"] = text ? classifyCapturedText("function_upvalue", std::string_view(text, len), reason) : "unknown";
            if (!reason.empty())
                uv["reason"] = reason;
            capturePotentialPayloadString(L, -1, label + ".upvalue." + std::to_string(upvalue));
            if (captureSnapshotStrings)
            {
                fs::path captured = captureFunctionSnapshotString(L, -1, label + ".upvalue." + std::to_string(upvalue));
                if (!captured.empty())
                    uv["capture_path"] = captured.string();
            }
        }
        else if (lua_type(L, -1) == LUA_TTABLE)
        {
            uv["preview"] = tablePreviewToJson(L, -1, 1024, 0, 16, captureSnapshotStrings, label + ".upvalue." + std::to_string(upvalue));
        }

        info["upvalues"].push_back(uv);
        lua_pop(L, 1);
    }

    lua_pop(L, 1);
    return info;
}

void dumpFunctionsFromValue(
    lua_State* L,
    int index,
    const std::string& label,
    int depth,
    json& functions,
    int& functionCount,
    int& nodeCount,
    std::set<const void*>& visitedTables,
    std::set<const void*>& visitedFunctions)
{
    if (!gLuraph.active || depth > 16 || functionCount >= 1024 || nodeCount >= 50000)
        return;

    ++nodeCount;
    index = lua_absindex(L, index);
    int type = lua_type(L, index);

    if (type == LUA_TFUNCTION)
    {
        const void* functionPtr = lua_topointer(L, index);
        if (!visitedFunctions.insert(functionPtr).second)
            return;

        functions.push_back(functionInfoToJson(L, index, label, gConfig.luraphSaveIntermediates));
        ++functionCount;

        lua_pushvalue(L, index);
        int functionIndex = lua_gettop(L);
        for (int upvalue = 1; upvalue <= 255 && functionCount < 1024 && nodeCount < 50000; ++upvalue)
        {
            const char* name = lua_getupvalue(L, functionIndex, upvalue);
            if (!name)
                break;
            const std::string childLabel = label + ".upvalue." + std::to_string(upvalue) + "." + compactLabel(name, 48);
            dumpFunctionsFromValue(
                L,
                -1,
                childLabel,
                depth + 1,
                functions,
                functionCount,
                nodeCount,
                visitedTables,
                visitedFunctions);
            lua_pop(L, 1);
        }
        lua_pop(L, 1);
        return;
    }

    if (type == LUA_TSTRING)
    {
        capturePotentialPayloadString(L, index, label);
        return;
    }

    if (type != LUA_TTABLE)
        return;

    const void* tablePtr = lua_topointer(L, index);
    if (!visitedTables.insert(tablePtr).second)
        return;

    int entries = 0;
    lua_pushnil(L);
    while (lua_next(L, index) != 0)
    {
        std::string key = compactLabel(valueSummary(L, -2), 64);
        std::string childLabel = label.empty() ? key : label + "." + key;
        dumpFunctionsFromValue(L, -1, childLabel, depth + 1, functions, functionCount, nodeCount, visitedTables, visitedFunctions);
        lua_pop(L, 1);

        if (++entries >= 5000 || functionCount >= 1024 || nodeCount >= 50000)
            break;
    }
}

void captureFunctionDump(lua_State* L, int index, const std::string& label)
{
    if (!gLuraph.active)
        return;

    json functions = json::array();
    int functionCount = 0;
    int nodeCount = 0;
    std::set<const void*> visitedTables;
    std::set<const void*> visitedFunctions;
    dumpFunctionsFromValue(L, index, label, 0, functions, functionCount, nodeCount, visitedTables, visitedFunctions);
    if (functionCount == 0)
        return;

    json dump = {
        {"label", label},
        {"function_count", functionCount},
        {"nodes_scanned", nodeCount},
        {"functions", functions},
    };

    gLuraph.functionDumpPath = gConfig.outputDir / "luraph_function_dump.json";
    json root = {
        {"schema", "rbx-luau-runtime.luraph-function-dump.v1"},
        {"note", "Live Luau closures cannot be serialized back to exact original source through the public VM API. This file records function/prototype metadata and upvalue summaries."},
        {"dumps", json::array()},
    };

    if (fs::exists(gLuraph.functionDumpPath))
    {
        json existing = json::parse(readFile(gLuraph.functionDumpPath), nullptr, false);
        if (!existing.is_discarded() && existing.is_object() && existing.contains("dumps"))
            root = std::move(existing);
    }

    root["dumps"].push_back(dump);
    writeFile(gLuraph.functionDumpPath, root.dump(2));
    markLuraphProgress();

    if (gLuraph.decompilerStatus == "not_run" || gLuraph.decompilerStatus == "missing_api_key" || gLuraph.decompilerStatus == "failed")
    {
        appendLuraphFallbackText(
            "\n-- Function/prototype metadata was captured in luraph_function_dump.json.\n"
            "-- This is proof/intermediate data, not original source.\n");
    }

    writeLuraphReport();
}

void captureReturnValues(lua_State* L, int firstIndex, int count, const std::string& prefix)
{
    for (int i = 0; i < count; ++i)
    {
        int index = firstIndex + i;
        if (lua_type(L, index) == LUA_TSTRING)
        {
            size_t len = 0;
            const char* text = lua_tolstring(L, index, &len);
            if (text)
            {
                std::string kind = prefix + "_" + std::to_string(i + 1);
                std::string_view data(text, len);
                if (shouldCaptureAnalysisString(kind, data))
                {
                    bool binary = data.find('\0') != std::string_view::npos || printableRatio(data) < 0.65;
                    captureText(kind, data, binary ? ".bin" : ".lua");
                }
            }
        }
        else if (lua_type(L, index) == LUA_TTABLE)
        {
            json encoded = luaValueToJson(L, index, 0);
            captureText(prefix + "_" + std::to_string(i + 1), encoded.dump(2), ".json");
            captureFunctionDump(L, index, prefix + "_" + std::to_string(i + 1));
        }
        else if (lua_type(L, index) == LUA_TFUNCTION)
        {
            captureFunctionDump(L, index, prefix + "_" + std::to_string(i + 1));
        }
    }
}

std::string timeoutDebugSnapshot(lua_State* L)
{
    std::ostringstream out;

    if (const char* trace = lua_debugtrace(L))
        out << trace;

    out << "\n\n-- locals --\n";
    for (int level = 0; level < 16; ++level)
    {
        lua_Debug ar{};
        if (!lua_getinfo(L, level, "sln", &ar))
            break;

        out << "#" << level << " " << (ar.short_src ? ar.short_src : "?");
        if (ar.currentline >= 0)
            out << ":" << ar.currentline;
        if (ar.name)
            out << " function " << ar.name;
        out << "\n";

        int shown = 0;
        for (int local = 1; local <= 24; ++local)
        {
            const char* name = lua_getlocal(L, level, local);
            if (!name)
                break;

            out << "  " << name << " = ";
            int type = lua_type(L, -1);
            if (type == LUA_TSTRING)
            {
                size_t len = 0;
                const char* text = lua_tolstring(L, -1, &len);
                std::string preview(text ? text : "", text ? std::min<size_t>(len, 96) : 0);
                out << '"' << preview << '"';
                if (len > preview.size())
                    out << " ... (" << len << " bytes)";
            }
            else if (type == LUA_TTABLE)
                out << shallowTableSummary(L, -1);
            else
                out << valueSummary(L, -1);
            out << "\n";
            lua_pop(L, 1);

            if (++shown >= 24)
                break;
        }
    }

    return out.str();
}

struct HttpResponse
{
    std::string body;
    long statusCode = 0;
    std::map<std::string, std::string> headers;
};

struct CurlWriteState
{
    std::string* output = nullptr;
    size_t limit = 0;
    bool exceeded = false;
};

struct CurlHeaderState
{
    std::map<std::string, std::string>* headers = nullptr;
    size_t bytes = 0;
    size_t limit = 0;
    bool exceeded = false;
};

size_t curlWriteCallback(char* ptr, size_t size, size_t nmemb, void* userdata)
{
    auto* state = static_cast<CurlWriteState*>(userdata);
    size_t bytes = size * nmemb;
    if (!state || !state->output || (state->limit > 0 && bytes > state->limit - std::min(state->limit, state->output->size())))
    {
        if (state) state->exceeded = true;
        return 0;
    }
    state->output->append(ptr, bytes);
    return bytes;
}

size_t curlHeaderCallback(char* ptr, size_t size, size_t nmemb, void* userdata)
{
    size_t bytes = size * nmemb;
    auto* state = static_cast<CurlHeaderState*>(userdata);
    if (!state || !state->headers || (state->limit > 0 && bytes > state->limit - std::min(state->limit, state->bytes)))
    {
        if (state) state->exceeded = true;
        return 0;
    }
    state->bytes += bytes;
    std::string line(ptr, bytes);
    size_t colon = line.find(':');
    if (colon != std::string::npos)
    {
        std::string key = line.substr(0, colon);
        std::string value = line.substr(colon + 1);
        while (!value.empty() && (value.front() == ' ' || value.front() == '\t'))
            value.erase(value.begin());
        while (!value.empty() && (value.back() == '\r' || value.back() == '\n' || value.back() == ' ' || value.back() == '\t'))
            value.pop_back();
        state->headers->emplace(std::move(key), std::move(value));
    }
    return bytes;
}

std::optional<std::string> responseHeader(const std::map<std::string, std::string>& headers, std::string_view name)
{
    std::string wanted = lowerAscii(std::string(name));
    for (const auto& [key, value] : headers)
    {
        if (lowerAscii(key) == wanted)
            return value;
    }
    return std::nullopt;
}

std::string resolveRedirectUrl(const std::string& currentUrl, const std::string& location)
{
    if (hasHttpScheme(location))
        return location;

    size_t schemeEnd = currentUrl.find("://");
    if (schemeEnd == std::string::npos)
        return {};
    std::string scheme = currentUrl.substr(0, schemeEnd);
    size_t authorityStart = schemeEnd + 3;
    size_t pathStart = currentUrl.find('/', authorityStart);
    std::string origin = pathStart == std::string::npos ? currentUrl : currentUrl.substr(0, pathStart);

    if (location.rfind("//", 0) == 0)
        return scheme + ":" + location;
    if (!location.empty() && location.front() == '/')
        return origin + location;

    std::string base = currentUrl;
    size_t suffix = base.find_first_of("?#");
    if (suffix != std::string::npos)
        base.resize(suffix);
    size_t slash = base.find_last_of('/');
    if (slash == std::string::npos || slash < authorityStart)
        return origin + "/" + location;
    return base.substr(0, slash + 1) + location;
}

bool isRedirectStatus(long statusCode)
{
    return statusCode == 301 || statusCode == 302 || statusCode == 303 || statusCode == 307 || statusCode == 308;
}

const std::string& syntheticOpiumwareFingerprint()
{
    static const std::string value = [] {
        std::random_device source;
        std::seed_seq seed{
            source(), source(), source(), source(),
            source(), source(), source(), source(),
        };
        std::mt19937_64 random(seed);
        std::array<unsigned char, 48> bytes{};
        for (size_t offset = 0; offset < bytes.size(); offset += sizeof(uint64_t))
        {
            uint64_t word = random();
            for (size_t byte = 0; byte < sizeof(word); ++byte)
                bytes[offset + byte] = static_cast<unsigned char>((word >> (byte * 8)) & 0xff);
        }

        std::ostringstream output;
        output << std::hex << std::nouppercase << std::setfill('0');
        for (unsigned char byte : bytes)
            output << std::setw(2) << static_cast<unsigned int>(byte);
        return output.str();
    }();
    return value;
}

HttpResponse httpRequestDetailed(
    const std::string& method,
    const std::string& url,
    const std::string& body = "",
    const std::vector<std::string>& headers = {},
    const std::string& cookies = "",
    long timeoutMs = 0)
{
    if (auto fixture = gConfig.fixtures.find(url); fixture != gConfig.fixtures.end())
    {
        HttpResponse response;
        response.body = readFile(fixture->second);
        response.statusCode = 200;
        response.headers["X-Rbx-Runtime-Fixture"] = fixture->second.string();
        return response;
    }

    std::string currentUrl = url;
    std::string currentMethod = method;
    std::string currentBody = body;
    std::string currentCookies = cookies;
    std::string userAgent = "Roblox/WinInet";
    std::vector<std::string> requestHeaders;
    requestHeaders.reserve(headers.size() + 2);
    for (const std::string& header : headers)
    {
        size_t colon = header.find(':');
        std::string key = colon == std::string::npos ? header : header.substr(0, colon);
        while (!key.empty() && (key.back() == ' ' || key.back() == '\t'))
            key.pop_back();
        if (lowerAscii(key) == "user-agent" && colon != std::string::npos)
        {
            userAgent = header.substr(colon + 1);
            while (!userAgent.empty() && (userAgent.front() == ' ' || userAgent.front() == '\t'))
                userAgent.erase(userAgent.begin());
            continue;
        }
        if (lowerAscii(key) == "opiumware-fingerprint" || lowerAscii(key) == "opiumware-user-identifier")
            continue;
        requestHeaders.push_back(header);
    }
    if (gConfig.profile == "executor-client" && gConfig.executorPreset == rbx::runtime::ExecutorPreset::Opiumware)
    {
        const std::string& fingerprint = syntheticOpiumwareFingerprint();
        requestHeaders.push_back("Opiumware-Fingerprint: " + fingerprint);
        requestHeaders.push_back("Opiumware-User-Identifier: " + fingerprint);
    }

    for (int redirectCount = 0; redirectCount <= 5; ++redirectCount)
    {
        if (!hostAllowed(currentUrl))
        {
            std::string host = parseUrlHost(currentUrl);
            traceCompat(
                "network_blocked",
                currentUrl,
                {{"host", host},
                 {"policy", gConfig.networkPolicy == NetworkPolicy::Offline ? "offline" : (gConfig.networkPolicy == NetworkPolicy::Live ? "live" : "allowlist")},
                 {"reason", hasHttpScheme(currentUrl) ? "host_not_allowed" : "unsupported_scheme"}});
            throw std::runtime_error(host.empty() ? "network URL must use HTTP or HTTPS" : "network host is not allowed: " + host);
        }

        CURL* curl = curl_easy_init();
        if (!curl)
            throw std::runtime_error("curl_easy_init failed");

        HttpResponse response;
        CurlWriteState writeState{&response.body, 16 * 1024 * 1024, false};
        CurlHeaderState headerState{&response.headers, 0, 64 * 1024, false};
        char errorBuffer[CURL_ERROR_SIZE] = {};
        struct curl_slist* headerList = nullptr;
        for (const std::string& header : requestHeaders)
            headerList = curl_slist_append(headerList, header.c_str());

        curl_easy_setopt(curl, CURLOPT_URL, currentUrl.c_str());
        curl_easy_setopt(curl, CURLOPT_OPENSOCKETFUNCTION, guardedOpenSocket);
        // Never let ambient proxy variables turn the socket guard into a check
        // of the proxy address while the proxy connects to an unvalidated URL.
        curl_easy_setopt(curl, CURLOPT_PROXY, "");
        curl_easy_setopt(curl, CURLOPT_NOPROXY, "*");
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
#ifdef CURLOPT_PROTOCOLS_STR
        curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "http,https");
#endif
        curl_easy_setopt(curl, CURLOPT_USERAGENT, userAgent.c_str());
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 15L);
        if (timeoutMs > 0)
            curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, timeoutMs);
        else
            curl_easy_setopt(curl, CURLOPT_TIMEOUT, 60L);
        curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errorBuffer);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlWriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &writeState);
        curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, curlHeaderCallback);
        curl_easy_setopt(curl, CURLOPT_HEADERDATA, &headerState);

        if (headerList)
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerList);
        if (!currentCookies.empty())
            curl_easy_setopt(curl, CURLOPT_COOKIE, currentCookies.c_str());

        if (currentMethod == "GET")
        {
            curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
        }
        else if (currentMethod == "HEAD")
        {
            curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
        }
        else if (currentMethod == "POST")
        {
            curl_easy_setopt(curl, CURLOPT_POST, 1L);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, currentBody.data());
            curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(currentBody.size()));
        }
        else
        {
            curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, currentMethod.c_str());
            if (!currentBody.empty())
            {
                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, currentBody.data());
                curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(currentBody.size()));
            }
        }

        CURLcode code = curl_easy_perform(curl);
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response.statusCode);
        if (headerList)
            curl_slist_free_all(headerList);
        curl_easy_cleanup(curl);

        if (writeState.exceeded)
            throw std::runtime_error("HTTP response body exceeded 16 MiB limit");
        if (headerState.exceeded)
            throw std::runtime_error("HTTP response headers exceeded 64 KiB limit");
        if (code != CURLE_OK)
            throw std::runtime_error(errorBuffer[0] ? errorBuffer : curl_easy_strerror(code));

        std::optional<std::string> location = responseHeader(response.headers, "location");
        if (isRedirectStatus(response.statusCode) && location)
        {
            if (redirectCount == 5)
                throw std::runtime_error("too many HTTP redirects for " + url);
            std::string nextUrl = resolveRedirectUrl(currentUrl, *location);
            if (nextUrl.empty())
                throw std::runtime_error("invalid HTTP redirect for " + currentUrl);
            traceCompat("network_redirect", currentUrl, {{"status", response.statusCode}, {"target", nextUrl}});
            if (parseUrlHost(nextUrl) != parseUrlHost(currentUrl))
            {
                requestHeaders.erase(std::remove_if(requestHeaders.begin(), requestHeaders.end(), [](const std::string& header) {
                    size_t colon = header.find(':');
                    std::string key = lowerAscii(header.substr(0, colon));
                    return key == "authorization" || key == "proxy-authorization" || key == "cookie" || key == "x-api-key";
                }), requestHeaders.end());
                currentCookies.clear();
            }
            currentUrl = std::move(nextUrl);
            if (response.statusCode == 303 || ((response.statusCode == 301 || response.statusCode == 302) && currentMethod == "POST"))
            {
                currentMethod = "GET";
                currentBody.clear();
            }
            continue;
        }

        if (response.statusCode >= 400)
            traceCompat("network_response", currentUrl, {{"method", currentMethod}, {"status", response.statusCode}});
        return response;
    }

    throw std::runtime_error("too many HTTP redirects for " + url);
}

std::string httpRequest(const std::string& method, const std::string& url, const std::string& body = "", const std::vector<std::string>& headers = {})
{
    return httpRequestDetailed(method, url, body, headers).body;
}

std::string trimTrailingSlashes(std::string value)
{
    while (!value.empty() && value.back() == '/')
        value.pop_back();
    return value;
}

std::string getSiftApiKey()
{
    if (!gConfig.siftApiKey.empty())
        return gConfig.siftApiKey;

    const char* value = std::getenv(gConfig.siftApiKeyEnv.c_str());
    if (value && value[0] != '\0')
        return std::string(value);

    return std::string(kBuiltInSiftApiKey);
}

HttpResponse siftPostRaw(const std::string& endpoint, std::string_view body, const std::string& filename)
{
    std::string key = getSiftApiKey();
    if (key.empty())
        throw std::runtime_error("Sift API key is not configured; set " + gConfig.siftApiKeyEnv + " or pass --sift-api-key");

    std::string url = trimTrailingSlashes(gConfig.siftBaseUrl) + endpoint;

    CURL* curl = curl_easy_init();
    if (!curl)
        throw std::runtime_error("curl_easy_init failed");

    HttpResponse response;
    CurlWriteState writeState{&response.body, 64 * 1024 * 1024, false};
    CurlHeaderState headerState{&response.headers, 0, 128 * 1024, false};
    char errorBuffer[CURL_ERROR_SIZE] = {};
    struct curl_slist* headerList = nullptr;

    std::string authHeader = "X-API-Key: " + key;
    std::string filenameHeader = "X-Filename: " + filename;
    headerList = curl_slist_append(headerList, authHeader.c_str());
    headerList = curl_slist_append(headerList, "Content-Type: application/octet-stream");
    headerList = curl_slist_append(headerList, filenameHeader.c_str());

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_OPENSOCKETFUNCTION, guardedOpenSocket);
    curl_easy_setopt(curl, CURLOPT_PROXY, "");
    curl_easy_setopt(curl, CURLOPT_NOPROXY, "*");
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "RobloxLuauRuntime/1.0 SiftFallback");
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 20L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 120L);
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errorBuffer);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlWriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &writeState);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, curlHeaderCallback);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &headerState);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerList);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.data());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(body.size()));

    CURLcode code = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response.statusCode);

    curl_slist_free_all(headerList);
    curl_easy_cleanup(curl);

    if (writeState.exceeded || headerState.exceeded)
        throw std::runtime_error("Sift response exceeded the configured size limit");
    if (code != CURLE_OK)
        throw std::runtime_error(errorBuffer[0] ? errorBuffer : curl_easy_strerror(code));

    return response;
}

std::optional<std::string> findFirstStringMember(const json& value, const std::vector<std::string>& keys)
{
    if (value.is_object())
    {
        for (const std::string& key : keys)
        {
            auto it = value.find(key);
            if (it != value.end() && it->is_string() && !it->get_ref<const std::string&>().empty())
                return it->get<std::string>();
        }

        for (auto it = value.begin(); it != value.end(); ++it)
        {
            if (auto nested = findFirstStringMember(it.value(), keys))
                return nested;
        }
    }
    else if (value.is_array())
    {
        for (const json& child : value)
        {
            if (auto nested = findFirstStringMember(child, keys))
                return nested;
        }
    }

    return std::nullopt;
}

void recordDecompilerObservation(const std::string& phase, const std::string& status, const std::string& detail = "")
{
    if (!gLuraph.active)
        return;

    json observation = {
        {"kind", "decompiler"},
        {"phase", phase},
        {"status", status},
    };
    if (!detail.empty())
        observation["detail"] = detail;
    gLuraph.observations.push_back(observation);
    markLuraphProgress();
}

void runSiftForBytecode(std::string_view data, const std::string& filename)
{
    if (!gLuraph.active || (!gConfig.siftDecompile && !gConfig.siftDisassemble) || data.empty())
        return;

    std::ostringstream fp;
    fp << data.size() << ":" << std::hash<std::string_view>{}(data);
    if (!gSiftBytecodeFingerprints.insert(fp.str()).second)
        return;

    std::string key = getSiftApiKey();
    if (key.empty())
    {
        if (gLuraph.decompilerStatus != "missing_api_key")
        {
            gLuraph.decompilerStatus = "missing_api_key";
            recordDecompilerObservation("sift", "missing_api_key", "set the configured environment variable or pass --sift-api-key");
            writeLuraphReport();
        }
        return;
    }

    bool anySuccess = false;
    bool anyFailure = false;

    if (gConfig.siftDecompile)
    {
        try
        {
            HttpResponse response = siftPostRaw("/api/v1/decompile", data, filename);
            gLuraph.siftDecompileResponsePath = gConfig.outputDir / "sift_decompile_response.json";
            writeFile(gLuraph.siftDecompileResponsePath, response.body);
            if (response.statusCode >= 400)
            {
                anyFailure = true;
                recordDecompilerObservation("sift_decompile", "http_error", "HTTP " + std::to_string(response.statusCode) + "; response saved");
            }

            json parsed = json::parse(response.body, nullptr, false);
            if (response.statusCode >= 400)
            {
                // Body was already saved above; Sift often returns useful JSON errors.
            }
            else if (!parsed.is_discarded())
            {
                std::optional<std::string> luau = findFirstStringMember(parsed, {"luau"});
                if (luau && !luau->empty())
                {
                    std::string fallback =
                        "-- Decompiled fallback generated by Sift.\n"
                        "-- This is not exact original source; exact recovery remains separate.\n\n" +
                        *luau;
                    if (!fallback.empty() && fallback.back() != '\n')
                        fallback.push_back('\n');
                    gLuraph.fallbackPath = gConfig.outputDir / "luraph_decompiled_fallback.lua";
                    writeFile(gLuraph.fallbackPath, fallback);
                    anySuccess = true;
                    recordDecompilerObservation("sift_decompile", "ok", "wrote luraph_decompiled_fallback.lua");
                }
                else
                {
                    anyFailure = true;
                    recordDecompilerObservation("sift_decompile", "no_luau_result", "response did not contain results[].luau");
                }
            }
            else
            {
                anyFailure = true;
                recordDecompilerObservation("sift_decompile", "invalid_json", "response was saved but could not be parsed");
            }
        }
        catch (const std::exception& e)
        {
            anyFailure = true;
            recordDecompilerObservation("sift_decompile", "error", e.what());
        }
    }

    if (gConfig.siftDisassemble)
    {
        try
        {
            HttpResponse response = siftPostRaw("/api/v1/disassemble", data, filename);
            gLuraph.siftDisassembleResponsePath = gConfig.outputDir / "sift_disassemble_response.json";
            writeFile(gLuraph.siftDisassembleResponsePath, response.body);
            if (response.statusCode >= 400)
            {
                anyFailure = true;
                recordDecompilerObservation("sift_disassemble", "http_error", "HTTP " + std::to_string(response.statusCode) + "; response saved");
            }

            std::string listing = response.body;
            json parsed = json::parse(response.body, nullptr, false);
            if (!parsed.is_discarded())
            {
                if (std::optional<std::string> extracted = findFirstStringMember(parsed, {"disassembly", "assembly", "listing", "text", "output", "luau"}))
                    listing = *extracted;
                else
                    listing = parsed.dump(2);
            }

            if (!listing.empty() && listing.back() != '\n')
                listing.push_back('\n');

            gLuraph.disassemblyPath = gConfig.outputDir / "luraph_disassembly.txt";
            writeFile(gLuraph.disassemblyPath, listing);
            if (response.statusCode < 400)
            {
                anySuccess = true;
                recordDecompilerObservation("sift_disassemble", "ok", "wrote luraph_disassembly.txt");
            }
        }
        catch (const std::exception& e)
        {
            anyFailure = true;
            recordDecompilerObservation("sift_disassemble", "error", e.what());
        }
    }

    if (anySuccess && anyFailure)
        gLuraph.decompilerStatus = "partial";
    else if (anySuccess)
        gLuraph.decompilerStatus = gConfig.siftDecompile && gConfig.siftDisassemble ? "decompiled_and_disassembled" : (gConfig.siftDecompile ? "decompiled" : "disassembled");
    else
        gLuraph.decompilerStatus = "failed";

    if (gLuraph.status != "recovered" && anySuccess)
    {
        gLuraph.status = "not_present";
        gLuraph.reason = "decompiler fallback was produced, but exact original source was not captured";
    }

    writeLuraphReport();
}

std::string urlEncode(std::string_view input)
{
    std::ostringstream encoded;
    encoded << std::hex << std::uppercase;
    for (unsigned char c : input)
    {
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~')
            encoded << static_cast<char>(c);
        else
            encoded << '%' << std::setw(2) << std::setfill('0') << static_cast<int>(c);
    }
    return encoded.str();
}

int fromHex(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

std::string urlDecode(std::string_view input)
{
    std::string out;
    for (size_t i = 0; i < input.size(); ++i)
    {
        if (input[i] == '%' && i + 2 < input.size())
        {
            int hi = fromHex(input[i + 1]);
            int lo = fromHex(input[i + 2]);
            if (hi >= 0 && lo >= 0)
            {
                out.push_back(static_cast<char>((hi << 4) | lo));
                i += 2;
                continue;
            }
        }
        if (input[i] == '+')
            out.push_back(' ');
        else
            out.push_back(input[i]);
    }
    return out;
}

struct GuidGeneratorState
{
    uint64_t value = 0;
};

constexpr std::string_view kGuidSubsystemKey = "host.guid-generator";

uint32_t nextGuidWord(GuidGeneratorState& state)
{
    // SplitMix64 is defined entirely in fixed-width integer operations, so
    // seeded GUID streams are identical across the supported platforms.
    uint64_t value = (state.value += UINT64_C(0x9e3779b97f4a7c15));
    value = (value ^ (value >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    value = (value ^ (value >> 27)) * UINT64_C(0x94d049bb133111eb);
    value ^= value >> 31;
    return static_cast<uint32_t>(value ^ (value >> 32));
}

std::string generateGuid(GuidGeneratorState& state, bool wrap)
{
    uint32_t a = nextGuidWord(state);
    uint32_t b = nextGuidWord(state);
    uint32_t c = nextGuidWord(state);
    uint32_t d = nextGuidWord(state);

    // RFC 4122 version 4-ish formatting.
    b = (b & 0xffff0fffU) | 0x00004000U;
    c = (c & 0x3fffffffU) | 0x80000000U;

    std::ostringstream ss;
    if (wrap)
        ss << "{";
    ss << std::hex << std::nouppercase << std::setfill('0')
       << std::setw(8) << a << "-"
       << std::setw(4) << ((b >> 16) & 0xffff) << "-"
       << std::setw(4) << (b & 0xffff) << "-"
       << std::setw(4) << ((c >> 16) & 0xffff) << "-"
       << std::setw(4) << (c & 0xffff)
       << std::setw(8) << d;
    if (wrap)
        ss << "}";
    return ss.str();
}

int stringArgIndex(lua_State* L)
{
    if (lua_isstring(L, 1))
        return 1;
    if (lua_isstring(L, 2))
        return 2;
    luaL_error(L, "expected URL string");
}

int l_httpget(lua_State* L)
{
    int urlIndex = stringArgIndex(L);
    std::string url = stackString(L, urlIndex);

    try
    {
        std::string response = httpRequest("GET", url);
        if (response.size() >= gConfig.captureMinBytes)
        {
            captureText("httpget", response, ".lua", {{"url", url}});
            captureMirror("captured_httpget.lua", response);
        }
        lua_pushlstring(L, response.data(), response.size());
        return 1;
    }
    catch (const std::exception& e)
    {
        luaL_error(L, "HttpGet failed: %s", e.what());
    }
}

int l_httppost(lua_State* L)
{
    int urlIndex = stringArgIndex(L);
    int bodyIndex = urlIndex + 1;
    std::string url = stackString(L, urlIndex);
    std::string body = lua_isnoneornil(L, bodyIndex) ? "" : stackString(L, bodyIndex);

    try
    {
        std::string response = httpRequest("POST", url, body, {"Content-Type: application/json"});
        if (response.size() >= gConfig.captureMinBytes)
            captureText("httppost", response, ".txt", {{"url", url}});
        lua_pushlstring(L, response.data(), response.size());
        return 1;
    }
    catch (const std::exception& e)
    {
        luaL_error(L, "HttpPost failed: %s", e.what());
    }
}

std::optional<std::string> getLuaStringField(lua_State* L, int tableIndex, const char* field)
{
    tableIndex = lua_absindex(L, tableIndex);
    lua_getfield(L, tableIndex, field);
    if (lua_isstring(L, -1))
    {
        std::string value = stackString(L, -1);
        lua_pop(L, 1);
        return value;
    }
    lua_pop(L, 1);
    return std::nullopt;
}

std::vector<std::string> getLuaHeaderList(lua_State* L, int tableIndex)
{
    std::vector<std::string> headers;
    tableIndex = lua_absindex(L, tableIndex);
    lua_getfield(L, tableIndex, "Headers");
    if (lua_istable(L, -1))
    {
        int headersIndex = lua_absindex(L, -1);
        lua_pushnil(L);
        while (lua_next(L, headersIndex) != 0)
        {
            if (lua_isstring(L, -2) && lua_isstring(L, -1))
                headers.push_back(stackString(L, -2) + ": " + stackString(L, -1));
            lua_pop(L, 1);
        }
    }
    lua_pop(L, 1);
    return headers;
}

std::string getLuaCookieString(lua_State* L, int tableIndex)
{
    std::vector<std::pair<std::string, std::string>> cookies;
    tableIndex = lua_absindex(L, tableIndex);
    lua_getfield(L, tableIndex, "Cookies");
    if (lua_istable(L, -1))
    {
        int cookiesIndex = lua_absindex(L, -1);
        lua_pushnil(L);
        while (lua_next(L, cookiesIndex) != 0)
        {
            if (lua_isstring(L, -2) && lua_isstring(L, -1))
                cookies.emplace_back(stackString(L, -2), stackString(L, -1));
            lua_pop(L, 1);
        }
    }
    lua_pop(L, 1);

    std::sort(cookies.begin(), cookies.end());
    std::string result;
    for (const auto& [key, value] : cookies)
    {
        if (!result.empty())
            result += "; ";
        result += key + "=" + value;
    }
    return result;
}

long getLuaTimeoutMs(lua_State* L, int tableIndex)
{
    tableIndex = lua_absindex(L, tableIndex);
    lua_getfield(L, tableIndex, "Timeout");
    long timeoutMs = 0;
    if (lua_isnumber(L, -1))
    {
        double seconds = lua_tonumber(L, -1);
        if (seconds > 0)
            timeoutMs = static_cast<long>(std::min(seconds, 60.0) * 1000.0);
    }
    lua_pop(L, 1);
    return timeoutMs;
}

const char* httpStatusMessage(long statusCode)
{
    switch (statusCode)
    {
    case 200: return "OK";
    case 201: return "Created";
    case 202: return "Accepted";
    case 204: return "No Content";
    case 301: return "Moved Permanently";
    case 302: return "Found";
    case 303: return "See Other";
    case 307: return "Temporary Redirect";
    case 308: return "Permanent Redirect";
    case 400: return "Bad Request";
    case 401: return "Unauthorized";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 408: return "Request Timeout";
    case 409: return "Conflict";
    case 429: return "Too Many Requests";
    case 500: return "Internal Server Error";
    case 502: return "Bad Gateway";
    case 503: return "Service Unavailable";
    case 504: return "Gateway Timeout";
    default: return "HTTP Response";
    }
}

void pushHeadersTable(lua_State* L, const std::map<std::string, std::string>& headers)
{
    lua_createtable(L, 0, static_cast<int>(headers.size()));
    int tableIndex = lua_gettop(L);
    for (const auto& [key, value] : headers)
    {
        lua_pushlstring(L, value.data(), value.size());
        lua_setfield(L, tableIndex, key.c_str());
    }
}

int l_http_request(lua_State* L)
{
    std::string url;
    std::string method = "GET";
    std::string body;
    std::vector<std::string> headers;
    std::string cookies;
    long timeoutMs = 0;

    int requestIndex = lua_istable(L, 2) ? 2 : 1;
    if (lua_istable(L, requestIndex))
    {
        url = getLuaStringField(L, requestIndex, "Url").value_or(getLuaStringField(L, requestIndex, "URL").value_or(""));
        method = getLuaStringField(L, requestIndex, "Method").value_or(method);
        body = getLuaStringField(L, requestIndex, "Body").value_or("");
        headers = getLuaHeaderList(L, requestIndex);
        cookies = getLuaCookieString(L, requestIndex);
        timeoutMs = getLuaTimeoutMs(L, requestIndex);
    }
    else
    {
        url = stackString(L, stringArgIndex(L));
    }

    if (url.empty())
        luaL_error(L, "RequestAsync expected Url");

    method = lowerAscii(method);
    std::transform(method.begin(), method.end(), method.begin(), [](unsigned char c) { return static_cast<char>(std::toupper(c)); });

    try
    {
        HttpResponse response = httpRequestDetailed(method, url, body, headers, cookies, timeoutMs);
        if (response.body.size() >= gConfig.captureMinBytes)
        {
            std::string kind = method == "POST" ? "httppost" : "httpget";
            captureText(kind, response.body, method == "GET" ? ".lua" : ".txt", {{"url", url}, {"method", method}, {"status", response.statusCode}});
            if (method == "GET")
                captureMirror("captured_httpget.lua", response.body);
        }

        lua_createtable(L, 0, 5);
        int resultIndex = lua_gettop(L);
        lua_pushboolean(L, response.statusCode >= 200 && response.statusCode < 400);
        lua_setfield(L, resultIndex, "Success");
        lua_pushinteger(L, static_cast<int>(response.statusCode));
        lua_setfield(L, resultIndex, "StatusCode");
        lua_pushstring(L, httpStatusMessage(response.statusCode));
        lua_setfield(L, resultIndex, "StatusMessage");
        lua_pushlstring(L, response.body.data(), response.body.size());
        lua_setfield(L, resultIndex, "Body");
        pushHeadersTable(L, response.headers);
        lua_setfield(L, resultIndex, "Headers");
        lua_createtable(L, 0, 0);
        lua_setfield(L, resultIndex, "Cookies");
        return 1;
    }
    catch (const std::exception& e)
    {
        luaL_error(L, "RequestAsync failed: %s", e.what());
    }
}

int l_trace_compat(lua_State* L)
{
    std::string kind = lua_isstring(L, 1) ? stackString(L, 1) : "unknown";
    std::string name = lua_isstring(L, 2) ? stackString(L, 2) : "";
    json detail = json::object();
    if (!lua_isnoneornil(L, 3))
    {
        const std::string summary = valueSummary(L, 3);
        // Network events are part of the report/site data contract.  Preserve
        // their typed fields at the top level instead of hiding them in the
        // generic human-readable `detail` string.
        if (kind == "network_response")
        {
            try
            {
                detail["status"] = std::stoi(summary);
            }
            catch (const std::exception&)
            {
                detail["detail"] = summary;
            }
        }
        else if (kind == "network_blocked")
            detail["host"] = summary;
        else if (kind == "network_redirect")
            detail["target"] = summary;
        else
            detail["detail"] = summary;
    }
    traceCompat(kind, name, detail);
    return 0;
}

int l_api_dump_json(lua_State* L)
{
    static const std::string dump = apiDumpSummaryJson();
    lua_pushlstring(L, dump.data(), dump.size());
    return 1;
}

int l_scenario_json(lua_State* L)
{
    std::string value = gScenario.dump();
    lua_pushlstring(L, value.data(), value.size());
    return 1;
}

int l_runtime_config(lua_State* L)
{
    lua_createtable(L, 0, 32);
    int tableIndex = lua_gettop(L);
    lua_pushlstring(L, gConfig.profile.data(), gConfig.profile.size());
    lua_setfield(L, tableIndex, "profile");
    std::string_view executionMode = rbx::runtime::name(gConfig.executionMode);
    lua_pushlstring(L, executionMode.data(), executionMode.size());
    lua_setfield(L, tableIndex, "executionMode");
    std::string_view executorPreset = rbx::runtime::name(gConfig.executorPreset);
    lua_pushlstring(L, executorPreset.data(), executorPreset.size());
    lua_setfield(L, tableIndex, "executorPreset");
    std::string_view filesystemPolicy = rbx::runtime::name(effectiveFilesystemPolicy());
    lua_pushlstring(L, filesystemPolicy.data(), filesystemPolicy.size());
    lua_setfield(L, tableIndex, "filesystemPolicy");
    lua_pushnumber(L, static_cast<double>(gConfig.memoryLimitBytes));
    lua_setfield(L, tableIndex, "memoryLimitBytes");
    lua_pushinteger64(L, static_cast<int64_t>(gConfig.deterministicSeed));
    lua_setfield(L, tableIndex, "deterministicSeed");
    lua_pushnumber(L, gConfig.virtualEpochSeconds);
    lua_setfield(L, tableIndex, "virtualEpochSeconds");
    lua_pushboolean(L, gConfig.allowPrivateNetwork);
    lua_setfield(L, tableIndex, "allowPrivateNetwork");
    lua_pushinteger(L, rbx::v2::kRuntimeVersion);
    lua_setfield(L, tableIndex, "runtimeVersion");
    lua_pushlstring(L, rbx::v2::kEngineRelease.data(), rbx::v2::kEngineRelease.size());
    lua_setfield(L, tableIndex, "engineRelease");
    std::string clockName = clockModeName(gConfig.clockMode);
    lua_pushlstring(L, clockName.data(), clockName.size());
    lua_setfield(L, tableIndex, "clock");
    lua_pushnumber(L, gConfig.frameRate);
    lua_setfield(L, tableIndex, "frameRate");
    lua_pushnumber(L, gConfig.maxVirtualSeconds);
    lua_setfield(L, tableIndex, "maxVirtualSeconds");
    std::string unsupportedName = unsupportedPolicyName();
    lua_pushlstring(L, unsupportedName.data(), unsupportedName.size());
    lua_setfield(L, tableIndex, "unsupported");
    std::string hooksName = analysisHooksModeName(gConfig.analysisHooks);
    lua_pushlstring(L, hooksName.data(), hooksName.size());
    lua_setfield(L, tableIndex, "analysisHooksMode");
    lua_pushboolean(L, analysisHooksEnabled());
    lua_setfield(L, tableIndex, "analysisHooks");
    std::string ownerModeName = ownerProtectionModeName(gConfig.ownerProtection);
    lua_pushlstring(L, ownerModeName.data(), ownerModeName.size());
    lua_setfield(L, tableIndex, "ownerProtection");
    lua_pushboolean(L, gConfig.minimalEnv);
    lua_setfield(L, tableIndex, "minimalEnv");
    lua_pushboolean(L, gConfig.studioRunScriptCompatibility);
    lua_setfield(L, tableIndex, "studioRunScriptCompatibility");
    lua_pushlstring(L, gConfig.chunkName.data(), gConfig.chunkName.size());
    lua_setfield(L, tableIndex, "chunkName");
    lua_pushnumber(L, static_cast<double>(gConfig.placeId));
    lua_setfield(L, tableIndex, "placeId");
    lua_pushnumber(L, static_cast<double>(gConfig.gameId));
    lua_setfield(L, tableIndex, "gameId");
    lua_pushnumber(L, static_cast<double>(gConfig.userId));
    lua_setfield(L, tableIndex, "userId");
    lua_pushlstring(L, gConfig.jobId.data(), gConfig.jobId.size());
    lua_setfield(L, tableIndex, "jobId");
    lua_pushlstring(L, gConfig.playerName.data(), gConfig.playerName.size());
    lua_setfield(L, tableIndex, "playerName");
    lua_pushboolean(L, gConfig.stopAfterCapture);
    lua_setfield(L, tableIndex, "stopAfterCapture");
    lua_pushstring(L, gConfig.networkPolicy == NetworkPolicy::Live ? "live" : (gConfig.networkPolicy == NetworkPolicy::Offline ? "offline" : "allowlist"));
    lua_setfield(L, tableIndex, "networkPolicy");
    lua_pushnumber(L, static_cast<double>(gConfig.captureMinBytes));
    lua_setfield(L, tableIndex, "captureMinBytes");
    lua_pushnumber(L, static_cast<double>(gConfig.luauOptimizationLevel));
    lua_setfield(L, tableIndex, "luauOptimizationLevel");
    lua_pushnumber(L, static_cast<double>(gConfig.luauDebugLevel));
    lua_setfield(L, tableIndex, "luauDebugLevel");
    lua_pushboolean(L, gConfig.captureStringHooks);
    lua_setfield(L, tableIndex, "captureStringHooks");
    lua_pushboolean(L, gConfig.traceCalls);
    lua_setfield(L, tableIndex, "traceCalls");
    std::string modeName = luraphModeName(gConfig.luraphMode);
    lua_pushlstring(L, modeName.data(), modeName.size());
    lua_setfield(L, tableIndex, "luraphMode");
    lua_pushboolean(L, gConfig.luraphStopAfterExactSource);
    lua_setfield(L, tableIndex, "luraphStopAfterExactSource");
    lua_pushboolean(L, gConfig.luraphSaveIntermediates);
    lua_setfield(L, tableIndex, "luraphSaveIntermediates");
    lua_pushnumber(L, static_cast<double>(gConfig.luraphMaxSteps));
    lua_setfield(L, tableIndex, "luraphMaxSteps");
    lua_pushnumber(L, gConfig.progressIntervalSeconds);
    lua_setfield(L, tableIndex, "progressIntervalSeconds");
    lua_pushboolean(L, gConfig.tracePcallErrors);
    lua_setfield(L, tableIndex, "tracePcallErrors");
    lua_pushboolean(L, gConfig.normalizePcallErrors);
    lua_setfield(L, tableIndex, "normalizePcallErrors");
    lua_pushboolean(L, gConfig.nativeCodegen && Luau::CodeGen::isSupported());
    lua_setfield(L, tableIndex, "nativeCodegen");
    lua_pushboolean(L, gConfig.passSourceAsArg);
    lua_setfield(L, tableIndex, "passSourceAsArg");
    lua_pushnumber(L, static_cast<double>(gConfig.nativeCodegenBlockSize));
    lua_setfield(L, tableIndex, "nativeCodegenBlockSize");
    lua_pushnumber(L, static_cast<double>(gConfig.nativeCodegenMaxTotalSize));
    lua_setfield(L, tableIndex, "nativeCodegenMaxTotalSize");
    lua_pushboolean(L, gConfig.siftDecompile);
    lua_setfield(L, tableIndex, "siftDecompile");
    lua_pushboolean(L, gConfig.siftDisassemble);
    lua_setfield(L, tableIndex, "siftDisassemble");
    lua_pushlstring(L, gConfig.siftApiKeyEnv.data(), gConfig.siftApiKeyEnv.size());
    lua_setfield(L, tableIndex, "siftApiKeyEnv");
    lua_pushlstring(L, gConfig.siftBaseUrl.data(), gConfig.siftBaseUrl.size());
    lua_setfield(L, tableIndex, "siftBaseUrl");
    return 1;
}

int l_capture_text(lua_State* L)
{
    std::string kind = lua_isstring(L, 1) ? stackString(L, 1) : "runtime_string";
    size_t len = 0;
    const char* text = luaL_checklstring(L, 2, &len);
    std::string extension = luaL_optstring(L, 3, ".txt");

    std::string_view data(text, len);
    if (shouldCaptureAnalysisString(kind, data))
        captureTextDedup(kind, data, extension);

    return 0;
}

int l_debug_snapshot(lua_State* L)
{
    std::string snapshot = timeoutDebugSnapshot(L);
    lua_pushlstring(L, snapshot.data(), snapshot.size());
    return 1;
}

int l_function_snapshot(lua_State* L)
{
    luaL_checktype(L, 1, LUA_TFUNCTION);
    std::string label = luaL_optstring(L, 2, "function");
    bool captureSnapshotStrings = lua_toboolean(L, 3) != 0;
    json info = functionInfoToJson(L, 1, label, captureSnapshotStrings);
    std::string dumped = info.dump(2);
    lua_pushlstring(L, dumped.data(), dumped.size());
    return 1;
}

int l_json_encode(lua_State* L)
{
    int valueIndex = lua_isnoneornil(L, 2) ? 1 : 2;
    json encoded = luaValueToJson(L, valueIndex, 0);
    std::string dumped = encoded.dump();
    lua_pushlstring(L, dumped.data(), dumped.size());
    return 1;
}

int l_json_decode(lua_State* L)
{
    int valueIndex = lua_isstring(L, 1) ? 1 : 2;
    std::string text = stackString(L, valueIndex);
    try
    {
        json parsed = json::parse(text);
        pushJsonValue(L, parsed);
        return 1;
    }
    catch (const std::exception& e)
    {
        luaL_error(L, "JSONDecode failed: %s", e.what());
    }
}

int l_url_encode(lua_State* L)
{
    int valueIndex = lua_isstring(L, 1) ? 1 : 2;
    std::string result = urlEncode(stackString(L, valueIndex));
    lua_pushlstring(L, result.data(), result.size());
    return 1;
}

int l_url_decode(lua_State* L)
{
    int valueIndex = lua_isstring(L, 1) ? 1 : 2;
    std::string result = urlDecode(stackString(L, valueIndex));
    lua_pushlstring(L, result.data(), result.size());
    return 1;
}

int l_generate_guid(lua_State* L)
{
    int boolIndex = lua_isboolean(L, 1) ? 1 : 2;
    bool wrap = !lua_isnoneornil(L, boolIndex) && lua_toboolean(L, boolIndex);
    rbx::runtime::RuntimeContext* context = rbx::runtime::RuntimeContext::from(L);
    if (!context)
        luaL_error(L, "GenerateGUID requires an attached RuntimeContext");
    GuidGeneratorState* state = context->subsystem<GuidGeneratorState>(kGuidSubsystemKey);
    if (!state)
    {
        GuidGeneratorState initial;
        initial.value = context->deterministicSeed() ^ UINT64_C(0x726f626c6f782d37);
        state = &context->emplaceSubsystem<GuidGeneratorState>(std::string(kGuidSubsystemKey), initial);
    }
    std::string guid = generateGuid(*state, wrap);
    lua_pushlstring(L, guid.data(), guid.size());
    return 1;
}

int l_typeof(lua_State* L)
{
    // Match Luau/Roblox's base-library contract: a missing value is an
    // argument error, while an explicit nil is a valid value whose type is
    // "nil".  Protected loaders use this distinction as an integrity probe.
    luaL_checkany(L, 1);
    std::string typeName = trimTypeName(L, 1);
    lua_pushlstring(L, typeName.data(), typeName.size());
    return 1;
}

std::string knownFunctionName(lua_State* L, int index)
{
    index = lua_absindex(L, index);
    static const char* globals[] = {
        "assert", "error", "getfenv", "getmetatable", "identifyexecutor", "iscclosure", "islclosure",
        "loadstring", "next", "pcall", "print", "rawget", "rawset", "select", "setfenv", "setmetatable",
        "tonumber", "tostring", "type", "typeof", "unpack", "xpcall", "require", "time", "tick",
        "elapsedTime", "wait", "spawn", "delay", "defer", "getgenv", "getrenv", "getsenv", "gethui",
        "cloneref", "compareinstances", "checkcaller", nullptr,
    };
    for (const char** name = globals; *name; ++name)
    {
        lua_getglobal(L, *name);
        const bool match = lua_rawequal(L, index, -1) != 0;
        lua_pop(L, 1);
        if (match)
            return *name;
    }

    static const char* namespaces[] = {
        "string", "table", "math", "coroutine", "task", "debug", "bit32", "buffer", "os", "utf8", nullptr,
    };
    for (const char** namespaceName = namespaces; *namespaceName; ++namespaceName)
    {
        lua_getglobal(L, *namespaceName);
        if (!lua_istable(L, -1))
        {
            lua_pop(L, 1);
            continue;
        }
        const int tableIndex = lua_absindex(L, -1);
        lua_pushnil(L);
        while (lua_next(L, tableIndex) != 0)
        {
            const bool match = lua_rawequal(L, index, -1) != 0;
            if (match && lua_isstring(L, -2))
            {
                const std::string member = stackString(L, -2);
                lua_pop(L, 3);
                return std::string(*namespaceName) + "." + member;
            }
            lua_pop(L, 1);
        }
        lua_pop(L, 1);
    }
    return {};
}

void traceClosureClassification(lua_State* L, const char* classifier, bool result)
{
    if (!gConfig.traceCalls)
        return;
    const uint64_t observation = ++gClosureClassificationTraceCount;
    if (observation > 1024)
        return;

    std::string known = knownFunctionName(L, 1);
    lua_Debug ar{};
    lua_pushvalue(L, 1);
    const bool hasInfo = lua_getinfo(L, -1, "sna", &ar) != 0;
    lua_pop(L, 1);

    std::cerr << "[closure_classification] observation=" << observation << " classifier=" << classifier
              << " result=" << (result ? "true" : "false") << " known=" << (known.empty() ? "unknown" : known)
              << " pointer=" << lua_topointer(L, 1);
    if (hasInfo)
    {
        std::cerr << " what=" << (ar.what ? ar.what : "") << " source=" << (ar.short_src ? ar.short_src : "")
                  << " name=" << (ar.name ? ar.name : "") << " nparams=" << static_cast<int>(ar.nparams)
                  << " vararg=" << static_cast<int>(ar.isvararg);
    }
    std::cerr << "\n";
}

int l_iscclosure(lua_State* L)
{
    const bool result = lua_iscfunction(L, 1) != 0;
    traceClosureClassification(L, "iscclosure", result);
    lua_pushboolean(L, result);
    return 1;
}

int l_islclosure(lua_State* L)
{
    const bool result = lua_isLfunction(L, 1) != 0;
    traceClosureClassification(L, "islclosure", result);
    lua_pushboolean(L, result);
    return 1;
}

int l_identifyexecutor(lua_State* L)
{
    rbx::runtime::RuntimeContext* context = rbx::runtime::RuntimeContext::from(L);
    if (!context || !context->executor().enabled())
        luaL_error(L, "identifyexecutor is unavailable outside executor-client");
    const rbx::runtime::ExecutorIdentity& identity = context->executor().surface().identity;
    lua_pushlstring(L, identity.name.data(), identity.name.size());
    lua_pushlstring(L, identity.version.data(), identity.version.size());
    return 2;
}

int l_getexecutorname(lua_State* L)
{
    rbx::runtime::RuntimeContext* context = rbx::runtime::RuntimeContext::from(L);
    if (!context || !context->executor().enabled())
        luaL_error(L, "getexecutorname is unavailable outside executor-client");
    const std::string& name = context->executor().surface().identity.name;
    lua_pushlstring(L, name.data(), name.size());
    return 1;
}

bool formatOutputLine(lua_State* L, std::string& output)
{
    int n = lua_gettop(L);
    output.clear();
    output.reserve(std::min(kOutputLineLimitBytes, kOutputCaptureLimitBytes - std::min(gOutputCapturedBytes, kOutputCaptureLimitBytes)));
    for (int i = 1; i <= n; ++i)
    {
        if (i > 1)
        {
            if (output.size() >= kOutputLineLimitBytes || gOutputCapturedBytes + output.size() >= kOutputCaptureLimitBytes)
            {
                gOutputLimitHit = true;
                return false;
            }
            output.push_back('\t');
        }
        size_t length = 0;
        const char* value = luaL_tolstring(L, i, &length);
        const size_t lineRemaining = kOutputLineLimitBytes - output.size();
        const size_t totalRemaining = kOutputCaptureLimitBytes - std::min(kOutputCaptureLimitBytes, gOutputCapturedBytes + output.size());
        if (length > lineRemaining || length > totalRemaining)
        {
            lua_pop(L, 1);
            gOutputLimitHit = true;
            return false;
        }
        output.append(value, length);
        lua_pop(L, 1);
    }
    if (gOutputCapturedBytes >= kOutputCaptureLimitBytes || output.size() + 1 > kOutputCaptureLimitBytes - gOutputCapturedBytes)
    {
        gOutputLimitHit = true;
        return false;
    }
    gOutputCapturedBytes += output.size() + 1;
    return true;
}

bool isLuraphProbeTrace(lua_State* L)
{
    if (gConfig.probeTracePath.empty() || lua_type(L, 1) != LUA_TSTRING)
        return false;
    size_t length = 0;
    const char* value = lua_tolstring(L, 1, &length);
    return value && std::string_view(value, length).starts_with("@@LPH_");
}

bool formatProbeTraceLine(lua_State* L, std::string& output)
{
    const int count = lua_gettop(L);
    output.clear();
    output.reserve(256);
    for (int index = 1; index <= count; ++index)
    {
        if (index > 1)
            output.push_back('\t');
        size_t length = 0;
        const char* value = luaL_tolstring(L, index, &length);
        if (output.size() > kOutputLineLimitBytes || length > kOutputLineLimitBytes - output.size())
        {
            lua_pop(L, 1);
            gProbeTraceLimitHit = true;
            return false;
        }
        output.append(value, length);
        lua_pop(L, 1);
    }
    if (gProbeTraceBytes >= gConfig.probeTraceLimitBytes || output.size() + 1 > gConfig.probeTraceLimitBytes - gProbeTraceBytes)
    {
        gProbeTraceLimitHit = true;
        return false;
    }
    gProbeTraceBytes += output.size() + 1;
    return true;
}

void appendProbeOutputEvent(std::string_view channel, std::string_view line)
{
    if (!gProbeTraceStream.is_open())
        return;

    const std::string event = "@@LPH_OUTPUT_V1@@\t" + std::string(channel) + "\t" + bytesToHex(line);
    if (gProbeTraceBytes >= gConfig.probeTraceLimitBytes || event.size() + 1 > gConfig.probeTraceLimitBytes - gProbeTraceBytes)
    {
        gProbeTraceLimitHit = true;
        return;
    }
    gProbeTraceBytes += event.size() + 1;
    gProbeTraceStream << event << '\n';
    if (!gProbeTraceStream)
        gProbeTraceLimitHit = true;
}

int l_print(lua_State* L)
{
    std::string line;
    if (isLuraphProbeTrace(L))
    {
        if (!gProbeTraceStream.is_open() || !formatProbeTraceLine(L, line))
        {
            const std::string message = "Luraph probe trace exceeded the " + std::to_string(gConfig.probeTraceLimitBytes) + "-byte capture limit";
            luaL_error(L, "%s", message.c_str());
        }
        gProbeTraceStream << line << '\n';
        if (!gProbeTraceStream)
            luaL_error(L, "could not write Luraph probe trace");
        return 0;
    }
    if (!formatOutputLine(L, line))
        luaL_error(L, "runtime output exceeded the 4 MiB capture limit");
    gCapturedStdout.push_back(jsonSafeText(line));
    appendProbeOutputEvent("stdout", line);
    std::cout << line << "\n";
    return 0;
}

int l_warn(lua_State* L)
{
    std::string line;
    if (!formatOutputLine(L, line))
        luaL_error(L, "runtime output exceeded the 4 MiB capture limit");
    gCapturedStderr.push_back(jsonSafeText(line));
    appendProbeOutputEvent("stderr", line);
    std::cerr << "[warn] " << line << "\n";
    return 0;
}

int l_wait(lua_State* L)
{
    double seconds = luaL_optnumber(L, 1, 0.03);
    if (seconds < 0)
        seconds = 0;
    auto start = std::chrono::steady_clock::now();
    std::this_thread::sleep_for(std::chrono::duration<double>(seconds));
    auto end = std::chrono::steady_clock::now();
    lua_pushnumber(L, std::chrono::duration<double>(end - start).count());
    return 1;
}

int callFunctionNow(lua_State* L, int funcIndex, int firstArg)
{
    int top = lua_gettop(L);
    int nargs = std::max(0, top - firstArg + 1);

    lua_pushvalue(L, funcIndex);
    for (int i = firstArg; i <= top; ++i)
        lua_pushvalue(L, i);

    int status = lua_pcall(L, nargs, 0, 0);
    if (status != LUA_OK)
    {
        std::cerr << "[task] " << stackString(L, -1) << "\n";
        lua_pop(L, 1);
    }
    return 0;
}

int l_spawn(lua_State* L)
{
    luaL_checktype(L, 1, LUA_TFUNCTION);
    return callFunctionNow(L, 1, 2);
}

int l_delay(lua_State* L)
{
    double seconds = luaL_optnumber(L, 1, 0);
    luaL_checktype(L, 2, LUA_TFUNCTION);
    if (seconds > 0)
        std::this_thread::sleep_for(std::chrono::duration<double>(seconds));
    return callFunctionNow(L, 2, 3);
}

int l_defer(lua_State* L)
{
    luaL_checktype(L, 1, LUA_TFUNCTION);
    return callFunctionNow(L, 1, 2);
}

int l_elapsed_time(lua_State* L)
{
    if (lua_callbacks(L)->tracenativecall)
        lua_callbacks(L)->tracenativecall(L, "runtime.elapsed");
    if (rbx::runtime::RuntimeContext* context = rbx::runtime::RuntimeContext::from(L))
    {
        lua_pushnumber(L, context->scheduler().now());
        return 1;
    }
    static const auto start = std::chrono::steady_clock::now();
    auto now = std::chrono::steady_clock::now();
    lua_pushnumber(L, std::chrono::duration<double>(now - start).count());
    return 1;
}

int l_wall_time(lua_State* L)
{
    if (rbx::runtime::RuntimeContext* context = rbx::runtime::RuntimeContext::from(L))
    {
        lua_pushnumber(L, static_cast<double>(context->scheduler().clock()->unixMillis()) / 1000.0);
        return 1;
    }
    auto now = std::chrono::system_clock::now().time_since_epoch();
    lua_pushnumber(L, std::chrono::duration<double>(now).count());
    return 1;
}

std::shared_ptr<rbx::runtime::MemoryFilesystem> checkedExecutorFilesystem(lua_State* L)
{
    rbx::runtime::RuntimeContext* context = rbx::runtime::RuntimeContext::from(L);
    if (!context || !context->executor().enabled())
        luaL_error(L, "executor filesystem is unavailable in this security context");
    std::shared_ptr<rbx::runtime::MemoryFilesystem> filesystem = context->executor().surface().filesystem;
    if (!filesystem)
        luaL_error(L, "executor filesystem is disabled");
    return filesystem;
}

void checkFilesystemResult(lua_State* L, const rbx::runtime::FilesystemResult& result)
{
    if (!result)
        luaL_error(L, "%s: %s", std::string(rbx::runtime::toString(result.error)).c_str(), result.message.c_str());
}

int l_memory_readfile(lua_State* L)
{
    const std::string path = luaL_checkstring(L, 1);
    rbx::runtime::ReadFileResult result = checkedExecutorFilesystem(L)->readFile(path);
    checkFilesystemResult(L, result);
    lua_pushlstring(L, result.contents.data(), result.contents.size());
    return 1;
}

int l_memory_writefile(lua_State* L)
{
    size_t length = 0;
    const std::string path = luaL_checkstring(L, 1);
    const char* contents = luaL_checklstring(L, 2, &length);
    checkFilesystemResult(L, checkedExecutorFilesystem(L)->writeFile(path, std::string(contents, length), true));
    return 0;
}

int l_memory_appendfile(lua_State* L)
{
    size_t length = 0;
    const std::string path = luaL_checkstring(L, 1);
    const char* contents = luaL_checklstring(L, 2, &length);
    checkFilesystemResult(L, checkedExecutorFilesystem(L)->appendFile(path, std::string_view(contents, length), true));
    return 0;
}

int l_memory_makefolder(lua_State* L)
{
    checkFilesystemResult(L, checkedExecutorFilesystem(L)->makeDirectory(luaL_checkstring(L, 1), true));
    return 0;
}

int l_memory_delfile(lua_State* L)
{
    checkFilesystemResult(L, checkedExecutorFilesystem(L)->removeFile(luaL_checkstring(L, 1)));
    return 0;
}

int l_memory_delfolder(lua_State* L)
{
    checkFilesystemResult(L, checkedExecutorFilesystem(L)->removeDirectory(luaL_checkstring(L, 1), true));
    return 0;
}

int l_memory_isfile(lua_State* L)
{
    lua_pushboolean(L, checkedExecutorFilesystem(L)->isFile(luaL_checkstring(L, 1)));
    return 1;
}

int l_memory_isfolder(lua_State* L)
{
    lua_pushboolean(L, checkedExecutorFilesystem(L)->isDirectory(luaL_checkstring(L, 1)));
    return 1;
}

int l_memory_listfiles(lua_State* L)
{
    const std::string path = luaL_optstring(L, 1, "");
    rbx::runtime::ListResult result = checkedExecutorFilesystem(L)->list(path, false);
    checkFilesystemResult(L, result);
    lua_createtable(L, static_cast<int>(result.entries.size()), 0);
    int output = lua_absindex(L, -1);
    int index = 1;
    for (const rbx::runtime::DirectoryEntry& entry : result.entries)
    {
        lua_pushlstring(L, entry.path.data(), entry.path.size());
        lua_rawseti(L, output, index++);
    }
    return 1;
}

int l_memory_loadfile(lua_State* L)
{
    const std::string path = luaL_checkstring(L, 1);
    rbx::runtime::ReadFileResult result = checkedExecutorFilesystem(L)->readFile(path);
    if (!result)
    {
        lua_pushnil(L);
        lua_pushfstring(L, "%s: %s", std::string(rbx::runtime::toString(result.error)).c_str(), result.message.c_str());
        return 2;
    }
    if (!loadChunk(L, result.contents, "=@memory/" + path))
    {
        lua_pushnil(L);
        lua_insert(L, -2);
        return 2;
    }
    return 1;
}

void registerExecutorFilesystem(lua_State* L)
{
    if (gConfig.profile != "executor-client" || effectiveFilesystemPolicy() != rbx::runtime::FilesystemPolicy::Memory)
        return;
    static const luaL_Reg functions[] = {
        {"readfile", l_memory_readfile},
        {"writefile", l_memory_writefile},
        {"appendfile", l_memory_appendfile},
        {"makefolder", l_memory_makefolder},
        {"delfile", l_memory_delfile},
        {"delfolder", l_memory_delfolder},
        {"isfile", l_memory_isfile},
        {"isfolder", l_memory_isfolder},
        {"listfiles", l_memory_listfiles},
        {"loadfile", l_memory_loadfile},
        {nullptr, nullptr},
    };
    lua_pushvalue(L, LUA_GLOBALSINDEX);
    luaL_register(L, nullptr, functions);
    lua_pop(L, 1);
}

void installLegacyTaskAliases(lua_State* L)
{
    lua_getglobal(L, "task");
    if (!lua_istable(L, -1))
    {
        lua_pop(L, 1);
        throw std::runtime_error("native task library was not installed");
    }
    struct Alias
    {
        const char* global;
        const char* member;
    };
    static constexpr Alias aliases[] = {
        {"wait", "wait"},
        {"delay", "delay"},
        {"defer", "defer"},
        {"spawn", "defer"},
    };
    for (const Alias& alias : aliases)
    {
        lua_getfield(L, -1, alias.member);
        lua_setglobal(L, alias.global);
    }
    lua_pop(L, 1);
}

void preloadMemoryFilesystem(rbx::runtime::RuntimeContext& context)
{
    std::shared_ptr<rbx::runtime::MemoryFilesystem> filesystem = context.executor().surface().filesystem;
    if (!filesystem || !gScenario.contains("filesystem"))
        return;

    auto loadEntry = [&](const std::string& path, const json& descriptor) {
        rbx::runtime::FilesystemResult result;
        if (descriptor.is_object() && descriptor.value("directory", false))
            result = filesystem->makeDirectory(path, true);
        else
        {
            std::string contents;
            if (descriptor.is_string())
                contents = descriptor.get<std::string>();
            else if (descriptor.is_object() && descriptor.contains("contents") && descriptor["contents"].is_string())
                contents = descriptor["contents"].get<std::string>();
            else if (descriptor.is_object() && descriptor.contains("content") && descriptor["content"].is_string())
                contents = descriptor["content"].get<std::string>();
            else
                throw std::runtime_error("filesystem fixture must be a string, directory, or content descriptor: " + path);
            result = filesystem->writeFile(path, std::move(contents), true);
        }
        if (!result)
            throw std::runtime_error("filesystem fixture " + path + " failed: " + result.message);
    };

    const json& fixtures = gScenario["filesystem"];
    if (fixtures.is_object())
    {
        for (auto iterator = fixtures.begin(); iterator != fixtures.end(); ++iterator)
            loadEntry(iterator.key(), iterator.value());
    }
    else if (fixtures.is_array())
    {
        for (const json& descriptor : fixtures)
        {
            if (!descriptor.is_object() || !descriptor.contains("path") || !descriptor["path"].is_string())
                throw std::runtime_error("filesystem array fixtures require a string path");
            loadEntry(descriptor["path"].get<std::string>(), descriptor);
        }
    }
    else
        throw std::runtime_error("scenario filesystem must be an object or array");
}

template<typename T>
T* checkTagged(lua_State* L, int index, int tag, const char* typeName)
{
    void* ptr = lua_touserdatatagged(L, index, tag);
    if (!ptr)
        luaL_typeerror(L, index, typeName);
    return static_cast<T*>(ptr);
}

template<>
Vector3Value* checkTagged<Vector3Value>(lua_State* L, int index, int tag, const char* typeName)
{
    if (const float* vector = lua_tovector(L, index))
    {
        thread_local std::array<Vector3Value, 32> values;
        thread_local size_t cursor = 0;
        Vector3Value& value = values[cursor++ % values.size()];
        value = {vector[0], vector[1], vector[2]};
        return &value;
    }

    void* ptr = lua_touserdatatagged(L, index, tag);
    if (!ptr)
        luaL_typeerror(L, index, typeName);
    return static_cast<Vector3Value*>(ptr);
}

template<typename T>
T* pushTagged(lua_State* L, int tag)
{
    void* ptr = lua_newuserdatatagged(L, sizeof(T), tag);
    lua_getuserdatametatable(L, tag);
    lua_setmetatable(L, -2);
    return new (ptr) T();
}

int pushVector2(lua_State* L, double x, double y)
{
    Vector2Value* value = pushTagged<Vector2Value>(L, kTagVector2);
    // Roblox stores Vector2 components as float32 even though Luau numbers are doubles.
    value->x = static_cast<float>(x);
    value->y = static_cast<float>(y);
    return 1;
}

int pushVector3(lua_State* L, double x, double y, double z)
{
    lua_pushvector(L, static_cast<float>(x), static_cast<float>(y), static_cast<float>(z));
    return 1;
}

int pushColor3(lua_State* L, double r, double g, double b)
{
    Color3Value* value = pushTagged<Color3Value>(L, kTagColor3);
    value->r = r;
    value->g = g;
    value->b = b;
    return 1;
}

int pushUDim(lua_State* L, double scale, int offset)
{
    UDimValue* value = pushTagged<UDimValue>(L, kTagUDim);
    value->scale = static_cast<float>(scale);
    value->offset = offset;
    return 1;
}

int pushUDim2(lua_State* L, const UDimValue& x, const UDimValue& y)
{
    UDim2Value* value = pushTagged<UDim2Value>(L, kTagUDim2);
    value->x = x;
    value->y = y;
    value->x.scale = static_cast<float>(x.scale);
    value->y.scale = static_cast<float>(y.scale);
    return 1;
}

int pushCFrame(lua_State* L, const CFrameValue& cf)
{
    CFrameValue* value = pushTagged<CFrameValue>(L, kTagCFrame);
    *value = cf;
    return 1;
}

int pushRay(lua_State* L, const Vector3Value& origin, const Vector3Value& direction)
{
    RayValue* value = pushTagged<RayValue>(L, kTagRay);
    value->origin = origin;
    value->direction = direction;
    return 1;
}

int l_vector2_new(lua_State* L)
{
    return pushVector2(L, luaL_optnumber(L, 1, 0), luaL_optnumber(L, 2, 0));
}

int l_vector2_min(lua_State* L)
{
    const int count = lua_gettop(L);
    Vector2Value* first = checkTagged<Vector2Value>(L, 1, kTagVector2, "Vector2");
    double x = first->x;
    double y = first->y;
    for (int index = 2; index <= count; ++index)
    {
        Vector2Value* value = checkTagged<Vector2Value>(L, index, kTagVector2, "Vector2");
        x = std::min(x, value->x);
        y = std::min(y, value->y);
    }
    return pushVector2(L, x, y);
}

int l_vector2_max(lua_State* L)
{
    const int count = lua_gettop(L);
    Vector2Value* first = checkTagged<Vector2Value>(L, 1, kTagVector2, "Vector2");
    double x = first->x;
    double y = first->y;
    for (int index = 2; index <= count; ++index)
    {
        Vector2Value* value = checkTagged<Vector2Value>(L, index, kTagVector2, "Vector2");
        x = std::max(x, value->x);
        y = std::max(y, value->y);
    }
    return pushVector2(L, x, y);
}

int l_vector2_index(lua_State* L)
{
    Vector2Value* value = checkTagged<Vector2Value>(L, 1, kTagVector2, "Vector2");
    std::string key = stackString(L, 2);
    if (key == "X" || key == "x")
        lua_pushnumber(L, value->x);
    else if (key == "Y" || key == "y")
        lua_pushnumber(L, value->y);
    else if (key == "Magnitude")
        lua_pushnumber(L, std::sqrt(value->x * value->x + value->y * value->y));
    else if (key == "Unit")
    {
        double mag = std::sqrt(value->x * value->x + value->y * value->y);
        pushVector2(L, mag == 0 ? 0 : value->x / mag, mag == 0 ? 0 : value->y / mag);
    }
    else if (key == "Dot")
    {
        lua_pushcfunction(
            L,
            [](lua_State* L2) -> int
            {
                Vector2Value* a = checkTagged<Vector2Value>(L2, 1, kTagVector2, "Vector2");
                Vector2Value* b = checkTagged<Vector2Value>(L2, 2, kTagVector2, "Vector2");
                lua_pushnumber(L2, a->x * b->x + a->y * b->y);
                return 1;
            },
            "Vector2.Dot"
        );
    }
    else if (key == "Cross")
    {
        lua_pushcfunction(
            L,
            [](lua_State* L2) -> int
            {
                Vector2Value* a = checkTagged<Vector2Value>(L2, 1, kTagVector2, "Vector2");
                Vector2Value* b = checkTagged<Vector2Value>(L2, 2, kTagVector2, "Vector2");
                lua_pushnumber(L2, a->x * b->y - a->y * b->x);
                return 1;
            },
            "Vector2.Cross"
        );
    }
    else if (key == "Lerp")
    {
        lua_pushcfunction(
            L,
            [](lua_State* L2) -> int
            {
                Vector2Value* a = checkTagged<Vector2Value>(L2, 1, kTagVector2, "Vector2");
                Vector2Value* b = checkTagged<Vector2Value>(L2, 2, kTagVector2, "Vector2");
                double alpha = luaL_checknumber(L2, 3);
                return pushVector2(L2, a->x + (b->x - a->x) * alpha, a->y + (b->y - a->y) * alpha);
            },
            "Vector2.Lerp"
        );
    }
    else if (key == "FuzzyEq")
    {
        lua_pushcfunction(
            L,
            [](lua_State* L2) -> int
            {
                Vector2Value* a = checkTagged<Vector2Value>(L2, 1, kTagVector2, "Vector2");
                Vector2Value* b = checkTagged<Vector2Value>(L2, 2, kTagVector2, "Vector2");
                double epsilon = luaL_optnumber(L2, 3, 1e-5);
                lua_pushboolean(L2, std::abs(a->x - b->x) <= epsilon && std::abs(a->y - b->y) <= epsilon);
                return 1;
            },
            "Vector2.FuzzyEq"
        );
    }
    else if (key == "Min")
        lua_pushcfunction(L, l_vector2_min, "Vector2.Min");
    else if (key == "Max")
        lua_pushcfunction(L, l_vector2_max, "Vector2.Max");
    else if (key == "Abs")
        lua_pushcfunction(L, [](lua_State* L2) { Vector2Value* v = checkTagged<Vector2Value>(L2, 1, kTagVector2, "Vector2"); return pushVector2(L2, std::abs(v->x), std::abs(v->y)); }, "Vector2.Abs");
    else if (key == "Ceil")
        lua_pushcfunction(L, [](lua_State* L2) { Vector2Value* v = checkTagged<Vector2Value>(L2, 1, kTagVector2, "Vector2"); return pushVector2(L2, std::ceil(v->x), std::ceil(v->y)); }, "Vector2.Ceil");
    else if (key == "Floor")
        lua_pushcfunction(L, [](lua_State* L2) { Vector2Value* v = checkTagged<Vector2Value>(L2, 1, kTagVector2, "Vector2"); return pushVector2(L2, std::floor(v->x), std::floor(v->y)); }, "Vector2.Floor");
    else if (key == "Sign")
        lua_pushcfunction(L, [](lua_State* L2) { Vector2Value* v = checkTagged<Vector2Value>(L2, 1, kTagVector2, "Vector2"); auto sign = [](double n) { return n > 0 ? 1.0 : n < 0 ? -1.0 : 0.0; }; return pushVector2(L2, sign(v->x), sign(v->y)); }, "Vector2.Sign");
    else if (key == "Angle")
    {
        lua_pushcfunction(L, [](lua_State* L2) {
            Vector2Value* a = checkTagged<Vector2Value>(L2, 1, kTagVector2, "Vector2");
            Vector2Value* b = checkTagged<Vector2Value>(L2, 2, kTagVector2, "Vector2");
            const double dot = a->x * b->x + a->y * b->y;
            const double cross = a->x * b->y - a->y * b->x;
            if (lua_toboolean(L2, 3))
                lua_pushnumber(L2, std::atan2(cross, dot));
            else
            {
                const double scale = std::sqrt((a->x * a->x + a->y * a->y) * (b->x * b->x + b->y * b->y));
                lua_pushnumber(L2, std::acos(std::clamp(dot / scale, -1.0, 1.0)));
            }
            return 1;
        }, "Vector2.Angle");
    }
    else
        lua_pushnil(L);
    return 1;
}

int l_vector2_add(lua_State* L)
{
    Vector2Value* a = checkTagged<Vector2Value>(L, 1, kTagVector2, "Vector2");
    Vector2Value* b = checkTagged<Vector2Value>(L, 2, kTagVector2, "Vector2");
    return pushVector2(L, a->x + b->x, a->y + b->y);
}

int l_vector2_sub(lua_State* L)
{
    Vector2Value* a = checkTagged<Vector2Value>(L, 1, kTagVector2, "Vector2");
    Vector2Value* b = checkTagged<Vector2Value>(L, 2, kTagVector2, "Vector2");
    return pushVector2(L, a->x - b->x, a->y - b->y);
}

int l_vector2_mul(lua_State* L)
{
    if (lua_type(L, 1) == LUA_TNUMBER)
    {
        double s = lua_tonumber(L, 1);
        Vector2Value* v = checkTagged<Vector2Value>(L, 2, kTagVector2, "Vector2");
        return pushVector2(L, v->x * s, v->y * s);
    }
    Vector2Value* v = checkTagged<Vector2Value>(L, 1, kTagVector2, "Vector2");
    if (lua_type(L, 2) == LUA_TNUMBER)
    {
        double s = lua_tonumber(L, 2);
        return pushVector2(L, v->x * s, v->y * s);
    }
    Vector2Value* b = checkTagged<Vector2Value>(L, 2, kTagVector2, "Vector2");
    return pushVector2(L, v->x * b->x, v->y * b->y);
}

int l_vector2_div(lua_State* L)
{
    Vector2Value* v = checkTagged<Vector2Value>(L, 1, kTagVector2, "Vector2");
    if (lua_type(L, 2) == LUA_TNUMBER)
    {
        double s = lua_tonumber(L, 2);
        return pushVector2(L, v->x / s, v->y / s);
    }
    Vector2Value* b = checkTagged<Vector2Value>(L, 2, kTagVector2, "Vector2");
    return pushVector2(L, v->x / b->x, v->y / b->y);
}

int l_vector2_unm(lua_State* L)
{
    Vector2Value* v = checkTagged<Vector2Value>(L, 1, kTagVector2, "Vector2");
    return pushVector2(L, -v->x, -v->y);
}

int l_vector2_eq(lua_State* L)
{
    Vector2Value* a = checkTagged<Vector2Value>(L, 1, kTagVector2, "Vector2");
    Vector2Value* b = checkTagged<Vector2Value>(L, 2, kTagVector2, "Vector2");
    lua_pushboolean(L, a->x == b->x && a->y == b->y);
    return 1;
}

int l_vector2_tostring(lua_State* L)
{
    Vector2Value* v = checkTagged<Vector2Value>(L, 1, kTagVector2, "Vector2");
    std::ostringstream ss;
    ss << v->x << ", " << v->y;
    std::string s = ss.str();
    lua_pushlstring(L, s.data(), s.size());
    return 1;
}

int l_vector3_new(lua_State* L)
{
    return pushVector3(L, luaL_optnumber(L, 1, 0), luaL_optnumber(L, 2, 0), luaL_optnumber(L, 3, 0));
}

int l_vector3_from_axis(lua_State* L)
{
    std::string axis;
    if (!rbx::v2::enumItemName(L, 1, "Axis", axis))
        luaL_typeerror(L, 1, "Enum.Axis");
    if (axis == "X") return pushVector3(L, 1, 0, 0);
    if (axis == "Y") return pushVector3(L, 0, 1, 0);
    if (axis == "Z") return pushVector3(L, 0, 0, 1);
    luaL_error(L, "invalid argument #1 to 'FromAxis' (Enum.Axis expected, got %s)", luaL_typename(L, 1));
    return 0;
}

int l_vector3_from_normal_id(lua_State* L)
{
    std::string normal;
    if (!rbx::v2::enumItemName(L, 1, "NormalId", normal))
        luaL_typeerror(L, 1, "Enum.NormalId");
    if (normal == "Right") return pushVector3(L, 1, 0, 0);
    if (normal == "Left") return pushVector3(L, -1, 0, 0);
    if (normal == "Top") return pushVector3(L, 0, 1, 0);
    if (normal == "Bottom") return pushVector3(L, 0, -1, 0);
    if (normal == "Back") return pushVector3(L, 0, 0, 1);
    if (normal == "Front") return pushVector3(L, 0, 0, -1);
    luaL_error(L, "invalid argument #1 to 'FromNormalId' (Enum.NormalId expected, got %s)", luaL_typename(L, 1));
    return 0;
}

int l_vector3_min(lua_State* L)
{
    const int count = lua_gettop(L);
    Vector3Value* first = checkTagged<Vector3Value>(L, 1, kTagVector3, "Vector3");
    double x = first->x, y = first->y, z = first->z;
    for (int index = 2; index <= count; ++index)
    {
        Vector3Value* value = checkTagged<Vector3Value>(L, index, kTagVector3, "Vector3");
        x = std::min(x, value->x); y = std::min(y, value->y); z = std::min(z, value->z);
    }
    return pushVector3(L, x, y, z);
}

int l_vector3_max(lua_State* L)
{
    const int count = lua_gettop(L);
    Vector3Value* first = checkTagged<Vector3Value>(L, 1, kTagVector3, "Vector3");
    double x = first->x, y = first->y, z = first->z;
    for (int index = 2; index <= count; ++index)
    {
        Vector3Value* value = checkTagged<Vector3Value>(L, index, kTagVector3, "Vector3");
        x = std::max(x, value->x); y = std::max(y, value->y); z = std::max(z, value->z);
    }
    return pushVector3(L, x, y, z);
}

int l_vector3_index(lua_State* L)
{
    Vector3Value* value = checkTagged<Vector3Value>(L, 1, kTagVector3, "Vector3");
    std::string key = stackString(L, 2);
    if (key == "X" || key == "x")
        lua_pushnumber(L, value->x);
    else if (key == "Y" || key == "y")
        lua_pushnumber(L, value->y);
    else if (key == "Z" || key == "z")
        lua_pushnumber(L, value->z);
    else if (key == "Magnitude")
        lua_pushnumber(L, std::sqrt(value->x * value->x + value->y * value->y + value->z * value->z));
    else if (key == "Unit")
    {
        double mag = std::sqrt(value->x * value->x + value->y * value->y + value->z * value->z);
        pushVector3(L, mag == 0 ? 0 : value->x / mag, mag == 0 ? 0 : value->y / mag, mag == 0 ? 0 : value->z / mag);
    }
    else if (key == "Dot")
    {
        lua_pushcfunction(
            L,
            [](lua_State* L2) -> int
            {
                Vector3Value* a = checkTagged<Vector3Value>(L2, 1, kTagVector3, "Vector3");
                Vector3Value* b = checkTagged<Vector3Value>(L2, 2, kTagVector3, "Vector3");
                lua_pushnumber(L2, a->x * b->x + a->y * b->y + a->z * b->z);
                return 1;
            },
            "Vector3.Dot"
        );
    }
    else if (key == "Cross")
    {
        lua_pushcfunction(
            L,
            [](lua_State* L2) -> int
            {
                Vector3Value* a = checkTagged<Vector3Value>(L2, 1, kTagVector3, "Vector3");
                Vector3Value* b = checkTagged<Vector3Value>(L2, 2, kTagVector3, "Vector3");
                return pushVector3(L2, a->y * b->z - a->z * b->y, a->z * b->x - a->x * b->z, a->x * b->y - a->y * b->x);
            },
            "Vector3.Cross"
        );
    }
    else if (key == "Lerp")
    {
        lua_pushcfunction(
            L,
            [](lua_State* L2) -> int
            {
                Vector3Value* a = checkTagged<Vector3Value>(L2, 1, kTagVector3, "Vector3");
                Vector3Value* b = checkTagged<Vector3Value>(L2, 2, kTagVector3, "Vector3");
                double alpha = luaL_checknumber(L2, 3);
                return pushVector3(
                    L2,
                    a->x + (b->x - a->x) * alpha,
                    a->y + (b->y - a->y) * alpha,
                    a->z + (b->z - a->z) * alpha
                );
            },
            "Vector3.Lerp"
        );
    }
    else if (key == "FuzzyEq")
    {
        lua_pushcfunction(
            L,
            [](lua_State* L2) -> int
            {
                Vector3Value* a = checkTagged<Vector3Value>(L2, 1, kTagVector3, "Vector3");
                Vector3Value* b = checkTagged<Vector3Value>(L2, 2, kTagVector3, "Vector3");
                double epsilon = luaL_optnumber(L2, 3, 1e-5);
                lua_pushboolean(
                    L2,
                    std::abs(a->x - b->x) <= epsilon && std::abs(a->y - b->y) <= epsilon && std::abs(a->z - b->z) <= epsilon
                );
                return 1;
            },
            "Vector3.FuzzyEq"
        );
    }
    else if (key == "Min")
        lua_pushcfunction(L, l_vector3_min, "Vector3.Min");
    else if (key == "Max")
        lua_pushcfunction(L, l_vector3_max, "Vector3.Max");
    else if (key == "Abs")
        lua_pushcfunction(L, [](lua_State* L2) { Vector3Value* v = checkTagged<Vector3Value>(L2, 1, kTagVector3, "Vector3"); return pushVector3(L2, std::abs(v->x), std::abs(v->y), std::abs(v->z)); }, "Vector3.Abs");
    else if (key == "Ceil")
        lua_pushcfunction(L, [](lua_State* L2) { Vector3Value* v = checkTagged<Vector3Value>(L2, 1, kTagVector3, "Vector3"); return pushVector3(L2, std::ceil(v->x), std::ceil(v->y), std::ceil(v->z)); }, "Vector3.Ceil");
    else if (key == "Floor")
        lua_pushcfunction(L, [](lua_State* L2) { Vector3Value* v = checkTagged<Vector3Value>(L2, 1, kTagVector3, "Vector3"); return pushVector3(L2, std::floor(v->x), std::floor(v->y), std::floor(v->z)); }, "Vector3.Floor");
    else if (key == "Sign")
        lua_pushcfunction(L, [](lua_State* L2) { Vector3Value* v = checkTagged<Vector3Value>(L2, 1, kTagVector3, "Vector3"); auto sign = [](double n) { return n > 0 ? 1.0 : n < 0 ? -1.0 : 0.0; }; return pushVector3(L2, sign(v->x), sign(v->y), sign(v->z)); }, "Vector3.Sign");
    else if (key == "Angle")
    {
        lua_pushcfunction(L, [](lua_State* L2) {
            Vector3Value* a = checkTagged<Vector3Value>(L2, 1, kTagVector3, "Vector3");
            Vector3Value* b = checkTagged<Vector3Value>(L2, 2, kTagVector3, "Vector3");
            const double dot = a->x * b->x + a->y * b->y + a->z * b->z;
            const double scale = std::sqrt((a->x * a->x + a->y * a->y + a->z * a->z) * (b->x * b->x + b->y * b->y + b->z * b->z));
            double angle = std::acos(std::clamp(dot / scale, -1.0, 1.0));
            if (!lua_isnoneornil(L2, 3))
            {
                Vector3Value* axis = checkTagged<Vector3Value>(L2, 3, kTagVector3, "Vector3");
                const double crossX = a->y * b->z - a->z * b->y;
                const double crossY = a->z * b->x - a->x * b->z;
                const double crossZ = a->x * b->y - a->y * b->x;
                if (axis->x * crossX + axis->y * crossY + axis->z * crossZ < 0) angle = -angle;
            }
            lua_pushnumber(L2, angle);
            return 1;
        }, "Vector3.Angle");
    }
    else
        lua_pushnil(L);
    return 1;
}

int l_vector3_add(lua_State* L)
{
    Vector3Value* a = checkTagged<Vector3Value>(L, 1, kTagVector3, "Vector3");
    Vector3Value* b = checkTagged<Vector3Value>(L, 2, kTagVector3, "Vector3");
    return pushVector3(L, a->x + b->x, a->y + b->y, a->z + b->z);
}

int l_vector3_sub(lua_State* L)
{
    Vector3Value* a = checkTagged<Vector3Value>(L, 1, kTagVector3, "Vector3");
    Vector3Value* b = checkTagged<Vector3Value>(L, 2, kTagVector3, "Vector3");
    return pushVector3(L, a->x - b->x, a->y - b->y, a->z - b->z);
}

int l_vector3_mul(lua_State* L)
{
    if (lua_type(L, 1) == LUA_TNUMBER)
    {
        double s = lua_tonumber(L, 1);
        Vector3Value* v = checkTagged<Vector3Value>(L, 2, kTagVector3, "Vector3");
        return pushVector3(L, v->x * s, v->y * s, v->z * s);
    }
    Vector3Value* v = checkTagged<Vector3Value>(L, 1, kTagVector3, "Vector3");
    if (lua_type(L, 2) == LUA_TNUMBER)
    {
        double s = lua_tonumber(L, 2);
        return pushVector3(L, v->x * s, v->y * s, v->z * s);
    }
    Vector3Value* b = checkTagged<Vector3Value>(L, 2, kTagVector3, "Vector3");
    return pushVector3(L, v->x * b->x, v->y * b->y, v->z * b->z);
}

int l_vector3_div(lua_State* L)
{
    Vector3Value* v = checkTagged<Vector3Value>(L, 1, kTagVector3, "Vector3");
    if (lua_type(L, 2) == LUA_TNUMBER)
    {
        double s = lua_tonumber(L, 2);
        return pushVector3(L, v->x / s, v->y / s, v->z / s);
    }
    Vector3Value* b = checkTagged<Vector3Value>(L, 2, kTagVector3, "Vector3");
    return pushVector3(L, v->x / b->x, v->y / b->y, v->z / b->z);
}

int l_vector3_unm(lua_State* L)
{
    Vector3Value* v = checkTagged<Vector3Value>(L, 1, kTagVector3, "Vector3");
    return pushVector3(L, -v->x, -v->y, -v->z);
}

int l_vector3_eq(lua_State* L)
{
    Vector3Value* a = checkTagged<Vector3Value>(L, 1, kTagVector3, "Vector3");
    Vector3Value* b = checkTagged<Vector3Value>(L, 2, kTagVector3, "Vector3");
    lua_pushboolean(L, a->x == b->x && a->y == b->y && a->z == b->z);
    return 1;
}

int l_vector3_tostring(lua_State* L)
{
    Vector3Value* v = checkTagged<Vector3Value>(L, 1, kTagVector3, "Vector3");
    std::ostringstream ss;
    ss << v->x << ", " << v->y << ", " << v->z;
    std::string s = ss.str();
    lua_pushlstring(L, s.data(), s.size());
    return 1;
}

int l_color3_new(lua_State* L)
{
    return pushColor3(L, luaL_optnumber(L, 1, 0), luaL_optnumber(L, 2, 0), luaL_optnumber(L, 3, 0));
}

int l_color3_from_rgb(lua_State* L)
{
    return pushColor3(L, luaL_optnumber(L, 1, 0) / 255.0, luaL_optnumber(L, 2, 0) / 255.0, luaL_optnumber(L, 3, 0) / 255.0);
}

int l_color3_from_hsv(lua_State* L)
{
    double hue = luaL_optnumber(L, 1, 0);
    double saturation = luaL_optnumber(L, 2, 0);
    double value = luaL_optnumber(L, 3, 0);
    hue = hue - std::floor(hue);
    double scaled = hue * 6.0;
    int sector = static_cast<int>(std::floor(scaled));
    double fraction = scaled - sector;
    double p = value * (1.0 - saturation);
    double q = value * (1.0 - saturation * fraction);
    double t = value * (1.0 - saturation * (1.0 - fraction));
    switch (sector % 6)
    {
    case 0:
        return pushColor3(L, value, t, p);
    case 1:
        return pushColor3(L, q, value, p);
    case 2:
        return pushColor3(L, p, value, t);
    case 3:
        return pushColor3(L, p, q, value);
    case 4:
        return pushColor3(L, t, p, value);
    default:
        return pushColor3(L, value, p, q);
    }
}

int l_color3_from_hex(lua_State* L)
{
    std::string value = stackString(L, 1);
    if (!value.empty() && value.front() == '#')
        value.erase(value.begin());
    if (value.size() != 6 || !std::all_of(value.begin(), value.end(), [](unsigned char c) { return std::isxdigit(c) != 0; }))
    {
        luaL_error(L, "invalid hex color");
        return 0;
    }
    unsigned long packed = std::stoul(value, nullptr, 16);
    return pushColor3(L, ((packed >> 16) & 0xff) / 255.0, ((packed >> 8) & 0xff) / 255.0, (packed & 0xff) / 255.0);
}

int l_color3_index(lua_State* L)
{
    Color3Value* c = checkTagged<Color3Value>(L, 1, kTagColor3, "Color3");
    std::string key = stackString(L, 2);
    if (key == "R" || key == "r")
        lua_pushnumber(L, c->r);
    else if (key == "G" || key == "g")
        lua_pushnumber(L, c->g);
    else if (key == "B" || key == "b")
        lua_pushnumber(L, c->b);
    else if (key == "ToHex")
    {
        lua_pushcfunction(
            L,
            [](lua_State* L2) -> int
            {
                Color3Value* c2 = checkTagged<Color3Value>(L2, 1, kTagColor3, "Color3");
                auto clampByte = [](double v) { return std::clamp(static_cast<int>(std::round(v * 255.0)), 0, 255); };
                std::ostringstream ss;
                ss << std::uppercase << std::hex << std::setfill('0') << std::setw(2) << clampByte(c2->r) << std::setw(2)
                   << clampByte(c2->g) << std::setw(2) << clampByte(c2->b);
                std::string s = ss.str();
                lua_pushlstring(L2, s.data(), s.size());
                return 1;
            },
            "Color3.ToHex"
        );
    }
    else if (key == "Lerp")
    {
        lua_pushcfunction(
            L,
            [](lua_State* L2) -> int
            {
                Color3Value* a = checkTagged<Color3Value>(L2, 1, kTagColor3, "Color3");
                Color3Value* b = checkTagged<Color3Value>(L2, 2, kTagColor3, "Color3");
                double alpha = luaL_checknumber(L2, 3);
                return pushColor3(
                    L2,
                    a->r + (b->r - a->r) * alpha,
                    a->g + (b->g - a->g) * alpha,
                    a->b + (b->b - a->b) * alpha
                );
            },
            "Color3.Lerp"
        );
    }
    else if (key == "ToHSV")
    {
        lua_pushcfunction(
            L,
            [](lua_State* L2) -> int
            {
                Color3Value* value = checkTagged<Color3Value>(L2, 1, kTagColor3, "Color3");
                double maximum = std::max({value->r, value->g, value->b});
                double minimum = std::min({value->r, value->g, value->b});
                double delta = maximum - minimum;
                double hue = 0;
                if (delta != 0)
                {
                    if (maximum == value->r)
                        hue = std::fmod((value->g - value->b) / delta, 6.0);
                    else if (maximum == value->g)
                        hue = (value->b - value->r) / delta + 2.0;
                    else
                        hue = (value->r - value->g) / delta + 4.0;
                    hue /= 6.0;
                    if (hue < 0)
                        hue += 1.0;
                }
                lua_pushnumber(L2, hue);
                lua_pushnumber(L2, maximum == 0 ? 0 : delta / maximum);
                lua_pushnumber(L2, maximum);
                return 3;
            },
            "Color3.ToHSV"
        );
    }
    else
        lua_pushnil(L);
    return 1;
}

int l_color3_eq(lua_State* L)
{
    Color3Value* a = checkTagged<Color3Value>(L, 1, kTagColor3, "Color3");
    Color3Value* b = checkTagged<Color3Value>(L, 2, kTagColor3, "Color3");
    lua_pushboolean(L, a->r == b->r && a->g == b->g && a->b == b->b);
    return 1;
}

int l_color3_tostring(lua_State* L)
{
    Color3Value* c = checkTagged<Color3Value>(L, 1, kTagColor3, "Color3");
    std::ostringstream ss;
    ss << c->r << ", " << c->g << ", " << c->b;
    std::string s = ss.str();
    lua_pushlstring(L, s.data(), s.size());
    return 1;
}

int l_color3_to_hsv(lua_State* L)
{
    Color3Value* value = checkTagged<Color3Value>(L, 1, kTagColor3, "Color3");
    double maximum = std::max({value->r, value->g, value->b});
    double minimum = std::min({value->r, value->g, value->b});
    double delta = maximum - minimum;
    double hue = 0;
    if (delta != 0)
    {
        if (maximum == value->r)
            hue = std::fmod((value->g - value->b) / delta, 6.0);
        else if (maximum == value->g)
            hue = (value->b - value->r) / delta + 2.0;
        else
            hue = (value->r - value->g) / delta + 4.0;
        hue /= 6.0;
        if (hue < 0)
            hue += 1.0;
    }
    lua_pushnumber(L, hue);
    lua_pushnumber(L, maximum == 0 ? 0 : delta / maximum);
    lua_pushnumber(L, maximum);
    return 3;
}

int l_udim_new(lua_State* L)
{
    return pushUDim(L, luaL_optnumber(L, 1, 0), luaL_optinteger(L, 2, 0));
}

int l_udim_index(lua_State* L)
{
    UDimValue* u = checkTagged<UDimValue>(L, 1, kTagUDim, "UDim");
    std::string key = stackString(L, 2);
    if (key == "Scale")
        lua_pushnumber(L, u->scale);
    else if (key == "Offset")
        lua_pushinteger(L, u->offset);
    else
        lua_pushnil(L);
    return 1;
}

int l_udim_tostring(lua_State* L)
{
    UDimValue* u = checkTagged<UDimValue>(L, 1, kTagUDim, "UDim");
    std::ostringstream ss;
    ss << u->scale << ", " << u->offset;
    std::string s = ss.str();
    lua_pushlstring(L, s.data(), s.size());
    return 1;
}

int l_udim_add(lua_State* L)
{
    UDimValue* a = checkTagged<UDimValue>(L, 1, kTagUDim, "UDim");
    UDimValue* b = checkTagged<UDimValue>(L, 2, kTagUDim, "UDim");
    return pushUDim(L, a->scale + b->scale, a->offset + b->offset);
}

int l_udim_sub(lua_State* L)
{
    UDimValue* a = checkTagged<UDimValue>(L, 1, kTagUDim, "UDim");
    UDimValue* b = checkTagged<UDimValue>(L, 2, kTagUDim, "UDim");
    return pushUDim(L, a->scale - b->scale, a->offset - b->offset);
}

int l_udim_eq(lua_State* L)
{
    UDimValue* a = checkTagged<UDimValue>(L, 1, kTagUDim, "UDim");
    UDimValue* b = checkTagged<UDimValue>(L, 2, kTagUDim, "UDim");
    lua_pushboolean(L, a->scale == b->scale && a->offset == b->offset);
    return 1;
}

int l_udim2_new(lua_State* L)
{
    UDimValue x{luaL_optnumber(L, 1, 0), luaL_optinteger(L, 2, 0)};
    UDimValue y{luaL_optnumber(L, 3, 0), luaL_optinteger(L, 4, 0)};
    return pushUDim2(L, x, y);
}

int l_udim2_from_scale(lua_State* L)
{
    return pushUDim2(L, UDimValue{luaL_optnumber(L, 1, 0), 0}, UDimValue{luaL_optnumber(L, 2, 0), 0});
}

int l_udim2_from_offset(lua_State* L)
{
    return pushUDim2(L, UDimValue{0, luaL_optinteger(L, 1, 0)}, UDimValue{0, luaL_optinteger(L, 2, 0)});
}

int l_udim2_index(lua_State* L)
{
    UDim2Value* u = checkTagged<UDim2Value>(L, 1, kTagUDim2, "UDim2");
    std::string key = stackString(L, 2);
    if (key == "X")
        pushUDim(L, u->x.scale, u->x.offset);
    else if (key == "Y")
        pushUDim(L, u->y.scale, u->y.offset);
    else
        lua_pushnil(L);
    return 1;
}

int l_udim2_tostring(lua_State* L)
{
    UDim2Value* u = checkTagged<UDim2Value>(L, 1, kTagUDim2, "UDim2");
    std::ostringstream ss;
    ss << "{" << u->x.scale << ", " << u->x.offset << "}, {" << u->y.scale << ", " << u->y.offset << "}";
    std::string s = ss.str();
    lua_pushlstring(L, s.data(), s.size());
    return 1;
}

int l_udim2_add(lua_State* L)
{
    UDim2Value* a = checkTagged<UDim2Value>(L, 1, kTagUDim2, "UDim2");
    UDim2Value* b = checkTagged<UDim2Value>(L, 2, kTagUDim2, "UDim2");
    return pushUDim2(
        L,
        UDimValue{a->x.scale + b->x.scale, a->x.offset + b->x.offset},
        UDimValue{a->y.scale + b->y.scale, a->y.offset + b->y.offset}
    );
}

int l_udim2_sub(lua_State* L)
{
    UDim2Value* a = checkTagged<UDim2Value>(L, 1, kTagUDim2, "UDim2");
    UDim2Value* b = checkTagged<UDim2Value>(L, 2, kTagUDim2, "UDim2");
    return pushUDim2(
        L,
        UDimValue{a->x.scale - b->x.scale, a->x.offset - b->x.offset},
        UDimValue{a->y.scale - b->y.scale, a->y.offset - b->y.offset}
    );
}

int l_udim2_eq(lua_State* L)
{
    UDim2Value* a = checkTagged<UDim2Value>(L, 1, kTagUDim2, "UDim2");
    UDim2Value* b = checkTagged<UDim2Value>(L, 2, kTagUDim2, "UDim2");
    lua_pushboolean(
        L,
        a->x.scale == b->x.scale && a->x.offset == b->x.offset && a->y.scale == b->y.scale && a->y.offset == b->y.offset
    );
    return 1;
}

CFrameValue identityCFrame()
{
    return {};
}

CFrameValue cframeFromEuler(double rx, double ry, double rz)
{
    double cx = std::cos(rx), sx = std::sin(rx);
    double cy = std::cos(ry), sy = std::sin(ry);
    double cz = std::cos(rz), sz = std::sin(rz);

    CFrameValue cf;
    cf.r00 = cy * cz;
    cf.r01 = -cy * sz;
    cf.r02 = sy;
    cf.r10 = sx * sy * cz + cx * sz;
    cf.r11 = -sx * sy * sz + cx * cz;
    cf.r12 = -sx * cy;
    cf.r20 = -cx * sy * cz + sx * sz;
    cf.r21 = cx * sy * sz + sx * cz;
    cf.r22 = cx * cy;
    return cf;
}

CFrameValue cframeFromEulerYXZ(double rx, double ry, double rz)
{
    double cx = std::cos(rx), sx = std::sin(rx);
    double cy = std::cos(ry), sy = std::sin(ry);
    double cz = std::cos(rz), sz = std::sin(rz);

    CFrameValue cf;
    cf.r00 = cy * cz + sy * sx * sz;
    cf.r01 = -cy * sz + sy * sx * cz;
    cf.r02 = sy * cx;
    cf.r10 = cx * sz;
    cf.r11 = cx * cz;
    cf.r12 = -sx;
    cf.r20 = -sy * cz + cy * sx * sz;
    cf.r21 = sy * sz + cy * sx * cz;
    cf.r22 = cy * cx;
    return cf;
}

Vector3Value subtractVector(const Vector3Value& a, const Vector3Value& b)
{
    return {a.x - b.x, a.y - b.y, a.z - b.z};
}

Vector3Value crossVector(const Vector3Value& a, const Vector3Value& b)
{
    return {a.y * b.z - a.z * b.y, a.z * b.x - a.x * b.z, a.x * b.y - a.y * b.x};
}

double dotVector(const Vector3Value& a, const Vector3Value& b)
{
    return a.x * b.x + a.y * b.y + a.z * b.z;
}

Vector3Value unitVector(const Vector3Value& value)
{
    double magnitude = std::sqrt(value.x * value.x + value.y * value.y + value.z * value.z);
    return magnitude <= 1e-12 ? Vector3Value{} : Vector3Value{value.x / magnitude, value.y / magnitude, value.z / magnitude};
}

CFrameValue cframeLookAt(const Vector3Value& position, const Vector3Value& target, const Vector3Value& up = {0, 1, 0})
{
    Vector3Value look = unitVector(subtractVector(target, position));
    if (look.x == 0 && look.y == 0 && look.z == 0)
        look = {0, 0, -1};
    Vector3Value back{-look.x, -look.y, -look.z};
    Vector3Value right = unitVector(crossVector(up, back));
    if (right.x == 0 && right.y == 0 && right.z == 0)
        right = unitVector(crossVector({0, 0, 1}, back));
    Vector3Value actualUp = crossVector(back, right);
    CFrameValue result;
    result.x = position.x;
    result.y = position.y;
    result.z = position.z;
    result.r00 = right.x;
    result.r10 = right.y;
    result.r20 = right.z;
    result.r01 = actualUp.x;
    result.r11 = actualUp.y;
    result.r21 = actualUp.z;
    result.r02 = back.x;
    result.r12 = back.y;
    result.r22 = back.z;
    return result;
}

CFrameValue cframeFromAxisAngle(const Vector3Value& rawAxis, double angle)
{
    Vector3Value axis = unitVector(rawAxis);
    if (axis.x == 0 && axis.y == 0 && axis.z == 0)
        return identityCFrame();

    double cosine = std::cos(angle);
    double sine = std::sin(angle);
    double complement = 1.0 - cosine;
    CFrameValue result;
    result.r00 = cosine + axis.x * axis.x * complement;
    result.r01 = axis.x * axis.y * complement - axis.z * sine;
    result.r02 = axis.x * axis.z * complement + axis.y * sine;
    result.r10 = axis.y * axis.x * complement + axis.z * sine;
    result.r11 = cosine + axis.y * axis.y * complement;
    result.r12 = axis.y * axis.z * complement - axis.x * sine;
    result.r20 = axis.z * axis.x * complement - axis.y * sine;
    result.r21 = axis.z * axis.y * complement + axis.x * sine;
    result.r22 = cosine + axis.z * axis.z * complement;
    return result;
}

int l_cframe_new(lua_State* L)
{
    int n = lua_gettop(L);
    CFrameValue cf = identityCFrame();
    if (n >= 12)
    {
        cf.x = luaL_checknumber(L, 1);
        cf.y = luaL_checknumber(L, 2);
        cf.z = luaL_checknumber(L, 3);
        cf.r00 = luaL_checknumber(L, 4);
        cf.r01 = luaL_checknumber(L, 5);
        cf.r02 = luaL_checknumber(L, 6);
        cf.r10 = luaL_checknumber(L, 7);
        cf.r11 = luaL_checknumber(L, 8);
        cf.r12 = luaL_checknumber(L, 9);
        cf.r20 = luaL_checknumber(L, 10);
        cf.r21 = luaL_checknumber(L, 11);
        cf.r22 = luaL_checknumber(L, 12);
    }
    else if (n == 1 && lua_isvector(L, 1))
    {
        Vector3Value* position = checkTagged<Vector3Value>(L, 1, kTagVector3, "Vector3");
        cf.x = position->x;
        cf.y = position->y;
        cf.z = position->z;
    }
    else if (n == 2 && lua_isvector(L, 1) && lua_isvector(L, 2))
    {
        Vector3Value* position = checkTagged<Vector3Value>(L, 1, kTagVector3, "Vector3");
        Vector3Value* target = checkTagged<Vector3Value>(L, 2, kTagVector3, "Vector3");
        cf = cframeLookAt(*position, *target);
    }
    else if (n >= 3)
    {
        cf.x = luaL_checknumber(L, 1);
        cf.y = luaL_checknumber(L, 2);
        cf.z = luaL_checknumber(L, 3);
    }
    return pushCFrame(L, cf);
}

int l_cframe_look_at(lua_State* L)
{
    Vector3Value* position = checkTagged<Vector3Value>(L, 1, kTagVector3, "Vector3");
    Vector3Value* target = checkTagged<Vector3Value>(L, 2, kTagVector3, "Vector3");
    Vector3Value up{0, 1, 0};
    if (!lua_isnoneornil(L, 3))
        up = *checkTagged<Vector3Value>(L, 3, kTagVector3, "Vector3");
    return pushCFrame(L, cframeLookAt(*position, *target, up));
}

int l_cframe_angles(lua_State* L)
{
    CFrameValue cf = cframeFromEuler(luaL_optnumber(L, 1, 0), luaL_optnumber(L, 2, 0), luaL_optnumber(L, 3, 0));
    return pushCFrame(L, cf);
}

int l_cframe_angles_yxz(lua_State* L)
{
    return pushCFrame(L, cframeFromEulerYXZ(luaL_checknumber(L, 1), luaL_checknumber(L, 2), luaL_checknumber(L, 3)));
}

int l_cframe_from_axis_angle(lua_State* L)
{
    Vector3Value* axis = checkTagged<Vector3Value>(L, 1, kTagVector3, "Vector3");
    return pushCFrame(L, cframeFromAxisAngle(*axis, luaL_checknumber(L, 2)));
}

int l_cframe_from_matrix(lua_State* L)
{
    Vector3Value* position = checkTagged<Vector3Value>(L, 1, kTagVector3, "Vector3");
    Vector3Value* right = checkTagged<Vector3Value>(L, 2, kTagVector3, "Vector3");
    Vector3Value* up = checkTagged<Vector3Value>(L, 3, kTagVector3, "Vector3");
    Vector3Value back = lua_isnoneornil(L, 4)
        ? crossVector(*right, *up)
        : *checkTagged<Vector3Value>(L, 4, kTagVector3, "Vector3");

    CFrameValue result;
    result.x = position->x;
    result.y = position->y;
    result.z = position->z;
    result.r00 = right->x; result.r10 = right->y; result.r20 = right->z;
    result.r01 = up->x; result.r11 = up->y; result.r21 = up->z;
    result.r02 = back.x; result.r12 = back.y; result.r22 = back.z;
    return pushCFrame(L, result);
}

int l_cframe_look_along(lua_State* L)
{
    Vector3Value* position = checkTagged<Vector3Value>(L, 1, kTagVector3, "Vector3");
    Vector3Value* direction = checkTagged<Vector3Value>(L, 2, kTagVector3, "Vector3");
    Vector3Value up{0, 1, 0};
    if (!lua_isnoneornil(L, 3))
        up = *checkTagged<Vector3Value>(L, 3, kTagVector3, "Vector3");
    Vector3Value target{position->x + direction->x, position->y + direction->y, position->z + direction->z};
    return pushCFrame(L, cframeLookAt(*position, target, up));
}

int l_cframe_from_rotation_between_vectors(lua_State* L)
{
    Vector3Value from = unitVector(*checkTagged<Vector3Value>(L, 1, kTagVector3, "Vector3"));
    Vector3Value to = unitVector(*checkTagged<Vector3Value>(L, 2, kTagVector3, "Vector3"));
    Vector3Value axis = crossVector(from, to);
    double axisMagnitude = std::sqrt(dotVector(axis, axis));
    double cosine = std::clamp(dotVector(from, to), -1.0, 1.0);

    if (axisMagnitude <= 1e-12)
    {
        if (cosine >= 0)
            return pushCFrame(L, identityCFrame());
        if (!lua_isnoneornil(L, 3))
            axis = *checkTagged<Vector3Value>(L, 3, kTagVector3, "Vector3");
        else
            axis = std::abs(from.x) < 0.9 ? crossVector(from, {1, 0, 0}) : crossVector(from, {0, 1, 0});
        return pushCFrame(L, cframeFromAxisAngle(axis, 3.14159265358979323846));
    }

    return pushCFrame(L, cframeFromAxisAngle(axis, std::atan2(axisMagnitude, cosine)));
}

CFrameValue multiplyCFrame(const CFrameValue& a, const CFrameValue& b)
{
    CFrameValue r;
    r.r00 = a.r00 * b.r00 + a.r01 * b.r10 + a.r02 * b.r20;
    r.r01 = a.r00 * b.r01 + a.r01 * b.r11 + a.r02 * b.r21;
    r.r02 = a.r00 * b.r02 + a.r01 * b.r12 + a.r02 * b.r22;
    r.r10 = a.r10 * b.r00 + a.r11 * b.r10 + a.r12 * b.r20;
    r.r11 = a.r10 * b.r01 + a.r11 * b.r11 + a.r12 * b.r21;
    r.r12 = a.r10 * b.r02 + a.r11 * b.r12 + a.r12 * b.r22;
    r.r20 = a.r20 * b.r00 + a.r21 * b.r10 + a.r22 * b.r20;
    r.r21 = a.r20 * b.r01 + a.r21 * b.r11 + a.r22 * b.r21;
    r.r22 = a.r20 * b.r02 + a.r21 * b.r12 + a.r22 * b.r22;
    r.x = a.r00 * b.x + a.r01 * b.y + a.r02 * b.z + a.x;
    r.y = a.r10 * b.x + a.r11 * b.y + a.r12 * b.z + a.y;
    r.z = a.r20 * b.x + a.r21 * b.y + a.r22 * b.z + a.z;
    return r;
}

Vector3Value transformPoint(const CFrameValue& cf, const Vector3Value& v)
{
    return {
        cf.r00 * v.x + cf.r01 * v.y + cf.r02 * v.z + cf.x,
        cf.r10 * v.x + cf.r11 * v.y + cf.r12 * v.z + cf.y,
        cf.r20 * v.x + cf.r21 * v.y + cf.r22 * v.z + cf.z,
    };
}

Vector3Value transformVector(const CFrameValue& cf, const Vector3Value& v)
{
    return {
        cf.r00 * v.x + cf.r01 * v.y + cf.r02 * v.z,
        cf.r10 * v.x + cf.r11 * v.y + cf.r12 * v.z,
        cf.r20 * v.x + cf.r21 * v.y + cf.r22 * v.z,
    };
}

CFrameValue inverseCFrame(const CFrameValue& cf)
{
    CFrameValue result;
    result.r00 = cf.r00;
    result.r01 = cf.r10;
    result.r02 = cf.r20;
    result.r10 = cf.r01;
    result.r11 = cf.r11;
    result.r12 = cf.r21;
    result.r20 = cf.r02;
    result.r21 = cf.r12;
    result.r22 = cf.r22;
    result.x = -(result.r00 * cf.x + result.r01 * cf.y + result.r02 * cf.z);
    result.y = -(result.r10 * cf.x + result.r11 * cf.y + result.r12 * cf.z);
    result.z = -(result.r20 * cf.x + result.r21 * cf.y + result.r22 * cf.z);
    return result;
}

struct Quaternion
{
    double w = 1;
    double x = 0;
    double y = 0;
    double z = 0;
};

Quaternion quaternionFromCFrame(const CFrameValue& cf)
{
    Quaternion result;
    double trace = cf.r00 + cf.r11 + cf.r22;
    if (trace > 0)
    {
        double scale = std::sqrt(trace + 1.0) * 2.0;
        result.w = 0.25 * scale;
        result.x = (cf.r21 - cf.r12) / scale;
        result.y = (cf.r02 - cf.r20) / scale;
        result.z = (cf.r10 - cf.r01) / scale;
    }
    else if (cf.r00 > cf.r11 && cf.r00 > cf.r22)
    {
        double scale = std::sqrt(1.0 + cf.r00 - cf.r11 - cf.r22) * 2.0;
        result.w = (cf.r21 - cf.r12) / scale;
        result.x = 0.25 * scale;
        result.y = (cf.r01 + cf.r10) / scale;
        result.z = (cf.r02 + cf.r20) / scale;
    }
    else if (cf.r11 > cf.r22)
    {
        double scale = std::sqrt(1.0 + cf.r11 - cf.r00 - cf.r22) * 2.0;
        result.w = (cf.r02 - cf.r20) / scale;
        result.x = (cf.r01 + cf.r10) / scale;
        result.y = 0.25 * scale;
        result.z = (cf.r12 + cf.r21) / scale;
    }
    else
    {
        double scale = std::sqrt(1.0 + cf.r22 - cf.r00 - cf.r11) * 2.0;
        result.w = (cf.r10 - cf.r01) / scale;
        result.x = (cf.r02 + cf.r20) / scale;
        result.y = (cf.r12 + cf.r21) / scale;
        result.z = 0.25 * scale;
    }
    return result;
}

Quaternion slerpQuaternion(Quaternion a, Quaternion b, double alpha)
{
    double dot = a.w * b.w + a.x * b.x + a.y * b.y + a.z * b.z;
    if (dot < 0)
    {
        b = {-b.w, -b.x, -b.y, -b.z};
        dot = -dot;
    }
    dot = std::clamp(dot, -1.0, 1.0);
    double aWeight = 1.0 - alpha;
    double bWeight = alpha;
    if (dot < 0.9995)
    {
        double angle = std::acos(dot);
        double inverseSin = 1.0 / std::sin(angle);
        aWeight = std::sin((1.0 - alpha) * angle) * inverseSin;
        bWeight = std::sin(alpha * angle) * inverseSin;
    }
    Quaternion result{
        a.w * aWeight + b.w * bWeight,
        a.x * aWeight + b.x * bWeight,
        a.y * aWeight + b.y * bWeight,
        a.z * aWeight + b.z * bWeight,
    };
    double magnitude = std::sqrt(result.w * result.w + result.x * result.x + result.y * result.y + result.z * result.z);
    if (magnitude > 0)
    {
        result.w /= magnitude;
        result.x /= magnitude;
        result.y /= magnitude;
        result.z /= magnitude;
    }
    return result;
}

CFrameValue cframeFromQuaternion(const Quaternion& q, double x, double y, double z)
{
    CFrameValue result;
    double xx = q.x * q.x;
    double yy = q.y * q.y;
    double zz = q.z * q.z;
    double xy = q.x * q.y;
    double xz = q.x * q.z;
    double yz = q.y * q.z;
    double wx = q.w * q.x;
    double wy = q.w * q.y;
    double wz = q.w * q.z;
    result.r00 = 1.0 - 2.0 * (yy + zz);
    result.r01 = 2.0 * (xy - wz);
    result.r02 = 2.0 * (xz + wy);
    result.r10 = 2.0 * (xy + wz);
    result.r11 = 1.0 - 2.0 * (xx + zz);
    result.r12 = 2.0 * (yz - wx);
    result.r20 = 2.0 * (xz - wy);
    result.r21 = 2.0 * (yz + wx);
    result.r22 = 1.0 - 2.0 * (xx + yy);
    result.x = x;
    result.y = y;
    result.z = z;
    return result;
}

int l_cframe_mul(lua_State* L)
{
    CFrameValue* a = checkTagged<CFrameValue>(L, 1, kTagCFrame, "CFrame");
    if (lua_userdatatag(L, 2) == kTagCFrame)
    {
        CFrameValue* b = checkTagged<CFrameValue>(L, 2, kTagCFrame, "CFrame");
        return pushCFrame(L, multiplyCFrame(*a, *b));
    }
    Vector3Value* v = checkTagged<Vector3Value>(L, 2, kTagVector3, "Vector3");
    Vector3Value result = transformPoint(*a, *v);
    return pushVector3(L, result.x, result.y, result.z);
}

int l_cframe_add(lua_State* L)
{
    CFrameValue* frame = checkTagged<CFrameValue>(L, 1, kTagCFrame, "CFrame");
    Vector3Value* offset = checkTagged<Vector3Value>(L, 2, kTagVector3, "Vector3");
    CFrameValue result = *frame;
    result.x += offset->x;
    result.y += offset->y;
    result.z += offset->z;
    return pushCFrame(L, result);
}

int l_cframe_sub(lua_State* L)
{
    CFrameValue* frame = checkTagged<CFrameValue>(L, 1, kTagCFrame, "CFrame");
    Vector3Value* offset = checkTagged<Vector3Value>(L, 2, kTagVector3, "Vector3");
    CFrameValue result = *frame;
    result.x -= offset->x;
    result.y -= offset->y;
    result.z -= offset->z;
    return pushCFrame(L, result);
}

int l_cframe_eq(lua_State* L)
{
    CFrameValue* a = checkTagged<CFrameValue>(L, 1, kTagCFrame, "CFrame");
    CFrameValue* b = checkTagged<CFrameValue>(L, 2, kTagCFrame, "CFrame");
    lua_pushboolean(
        L,
        a->x == b->x && a->y == b->y && a->z == b->z && a->r00 == b->r00 && a->r01 == b->r01 && a->r02 == b->r02 &&
            a->r10 == b->r10 && a->r11 == b->r11 && a->r12 == b->r12 && a->r20 == b->r20 && a->r21 == b->r21 && a->r22 == b->r22
    );
    return 1;
}

int l_cframe_index(lua_State* L)
{
    CFrameValue* cf = checkTagged<CFrameValue>(L, 1, kTagCFrame, "CFrame");
    std::string key = stackString(L, 2);
    if (key == "X" || key == "x")
        lua_pushnumber(L, cf->x);
    else if (key == "Y" || key == "y")
        lua_pushnumber(L, cf->y);
    else if (key == "Z" || key == "z")
        lua_pushnumber(L, cf->z);
    else if (key == "Position" || key == "p")
        pushVector3(L, cf->x, cf->y, cf->z);
    else if (key == "LookVector")
        pushVector3(L, -cf->r02, -cf->r12, -cf->r22);
    else if (key == "RightVector")
        pushVector3(L, cf->r00, cf->r10, cf->r20);
    else if (key == "UpVector")
        pushVector3(L, cf->r01, cf->r11, cf->r21);
    else if (key == "Rotation")
    {
        CFrameValue rotation = *cf;
        rotation.x = rotation.y = rotation.z = 0;
        pushCFrame(L, rotation);
    }
    else if (key == "Inverse")
    {
        lua_pushcfunction(
            L,
            [](lua_State* L2) -> int
            {
                CFrameValue* self = checkTagged<CFrameValue>(L2, 1, kTagCFrame, "CFrame");
                return pushCFrame(L2, inverseCFrame(*self));
            },
            "CFrame.Inverse"
        );
    }
    else if (key == "ToWorldSpace")
    {
        lua_pushcfunction(
            L,
            [](lua_State* L2) -> int
            {
                CFrameValue* self = checkTagged<CFrameValue>(L2, 1, kTagCFrame, "CFrame");
                CFrameValue* other = checkTagged<CFrameValue>(L2, 2, kTagCFrame, "CFrame");
                return pushCFrame(L2, multiplyCFrame(*self, *other));
            },
            "CFrame.ToWorldSpace"
        );
    }
    else if (key == "PointToWorldSpace")
    {
        lua_pushcfunction(
            L,
            [](lua_State* L2) -> int
            {
                CFrameValue* self = checkTagged<CFrameValue>(L2, 1, kTagCFrame, "CFrame");
                Vector3Value* point = checkTagged<Vector3Value>(L2, 2, kTagVector3, "Vector3");
                Vector3Value result = transformPoint(*self, *point);
                return pushVector3(L2, result.x, result.y, result.z);
            },
            "CFrame.PointToWorldSpace"
        );
    }
    else if (key == "ToObjectSpace")
    {
        lua_pushcfunction(
            L,
            [](lua_State* L2) -> int
            {
                CFrameValue* self = checkTagged<CFrameValue>(L2, 1, kTagCFrame, "CFrame");
                CFrameValue* other = checkTagged<CFrameValue>(L2, 2, kTagCFrame, "CFrame");
                return pushCFrame(L2, multiplyCFrame(inverseCFrame(*self), *other));
            },
            "CFrame.ToObjectSpace"
        );
    }
    else if (key == "PointToObjectSpace")
    {
        lua_pushcfunction(
            L,
            [](lua_State* L2) -> int
            {
                CFrameValue* self = checkTagged<CFrameValue>(L2, 1, kTagCFrame, "CFrame");
                Vector3Value* point = checkTagged<Vector3Value>(L2, 2, kTagVector3, "Vector3");
                Vector3Value result = transformPoint(inverseCFrame(*self), *point);
                return pushVector3(L2, result.x, result.y, result.z);
            },
            "CFrame.PointToObjectSpace"
        );
    }
    else if (key == "VectorToWorldSpace" || key == "VectorToObjectSpace")
    {
        bool objectSpace = key == "VectorToObjectSpace";
        lua_pushboolean(L, objectSpace);
        lua_pushcclosure(
            L,
            [](lua_State* L2) -> int
            {
                CFrameValue* self = checkTagged<CFrameValue>(L2, 1, kTagCFrame, "CFrame");
                Vector3Value* vector = checkTagged<Vector3Value>(L2, 2, kTagVector3, "Vector3");
                CFrameValue transform = lua_toboolean(L2, lua_upvalueindex(1)) ? inverseCFrame(*self) : *self;
                Vector3Value result = transformVector(transform, *vector);
                return pushVector3(L2, result.x, result.y, result.z);
            },
            objectSpace ? "CFrame.VectorToObjectSpace" : "CFrame.VectorToWorldSpace",
            1
        );
    }
    else if (key == "Lerp")
    {
        lua_pushcfunction(
            L,
            [](lua_State* L2) -> int
            {
                CFrameValue* a = checkTagged<CFrameValue>(L2, 1, kTagCFrame, "CFrame");
                CFrameValue* b = checkTagged<CFrameValue>(L2, 2, kTagCFrame, "CFrame");
                double alpha = luaL_checknumber(L2, 3);
                Quaternion rotation = slerpQuaternion(quaternionFromCFrame(*a), quaternionFromCFrame(*b), alpha);
                CFrameValue result = cframeFromQuaternion(
                    rotation,
                    a->x + (b->x - a->x) * alpha,
                    a->y + (b->y - a->y) * alpha,
                    a->z + (b->z - a->z) * alpha
                );
                return pushCFrame(L2, result);
            },
            "CFrame.Lerp"
        );
    }
    else if (key == "GetComponents" || key == "components")
    {
        lua_pushcfunction(
            L,
            [](lua_State* L2) -> int
            {
                CFrameValue* self = checkTagged<CFrameValue>(L2, 1, kTagCFrame, "CFrame");
                lua_pushnumber(L2, self->x);
                lua_pushnumber(L2, self->y);
                lua_pushnumber(L2, self->z);
                lua_pushnumber(L2, self->r00);
                lua_pushnumber(L2, self->r01);
                lua_pushnumber(L2, self->r02);
                lua_pushnumber(L2, self->r10);
                lua_pushnumber(L2, self->r11);
                lua_pushnumber(L2, self->r12);
                lua_pushnumber(L2, self->r20);
                lua_pushnumber(L2, self->r21);
                lua_pushnumber(L2, self->r22);
                return 12;
            },
            "CFrame.GetComponents"
        );
    }
    else
        lua_pushnil(L);
    return 1;
}

int l_cframe_tostring(lua_State* L)
{
    CFrameValue* cf = checkTagged<CFrameValue>(L, 1, kTagCFrame, "CFrame");
    std::ostringstream ss;
    ss << cf->x << ", " << cf->y << ", " << cf->z << ", "
       << cf->r00 << ", " << cf->r01 << ", " << cf->r02 << ", "
       << cf->r10 << ", " << cf->r11 << ", " << cf->r12 << ", "
       << cf->r20 << ", " << cf->r21 << ", " << cf->r22;
    std::string s = ss.str();
    lua_pushlstring(L, s.data(), s.size());
    return 1;
}

int l_ray_new(lua_State* L)
{
    Vector3Value* origin = checkTagged<Vector3Value>(L, 1, kTagVector3, "Vector3");
    Vector3Value* direction = checkTagged<Vector3Value>(L, 2, kTagVector3, "Vector3");
    return pushRay(L, *origin, *direction);
}

int l_ray_index(lua_State* L)
{
    RayValue* ray = checkTagged<RayValue>(L, 1, kTagRay, "Ray");
    std::string key = stackString(L, 2);
    if (key == "Origin")
        pushVector3(L, ray->origin.x, ray->origin.y, ray->origin.z);
    else if (key == "Direction")
        pushVector3(L, ray->direction.x, ray->direction.y, ray->direction.z);
    else
        lua_pushnil(L);
    return 1;
}

int l_ray_tostring(lua_State* L)
{
    RayValue* ray = checkTagged<RayValue>(L, 1, kTagRay, "Ray");
    std::ostringstream ss;
    ss << "Origin: " << ray->origin.x << ", " << ray->origin.y << ", " << ray->origin.z
       << "; Direction: " << ray->direction.x << ", " << ray->direction.y << ", " << ray->direction.z;
    std::string s = ss.str();
    lua_pushlstring(L, s.data(), s.size());
    return 1;
}

void registerMetatable(lua_State* L, const char* name, int tag, const luaL_Reg* funcs)
{
    luaL_newmetatable(L, name);
    luaL_register(L, nullptr, funcs);
    lua_pushliteral(L, "The metatable is locked");
    lua_setfield(L, -2, "__metatable");
    lua_pushvalue(L, -1);
    lua_setuserdatametatable(L, tag);
    lua_pop(L, 1);
}

void registerVector3Metatable(lua_State* L, const luaL_Reg* funcs)
{
    lua_pushvector(L, 0.0f, 0.0f, 0.0f);
    if (!lua_getmetatable(L, -1))
        lua_newtable(L);
    lua_remove(L, -2);
    lua_setreadonly(L, -1, false);
    luaL_register(L, nullptr, funcs);
    lua_pushliteral(L, "The metatable is locked");
    lua_setfield(L, -2, "__metatable");
    lua_setreadonly(L, -1, true);
    lua_pop(L, 1);
}

void registerConstructorTable(lua_State* L, const char* globalName, const luaL_Reg* funcs)
{
    lua_newtable(L);
    luaL_register(L, nullptr, funcs);
    lua_setglobal(L, globalName);
}

void registerMathTypes(lua_State* L)
{
    static const luaL_Reg vector2Meta[] = {
        {"__index", l_vector2_index},
        {"__add", l_vector2_add},
        {"__sub", l_vector2_sub},
        {"__mul", l_vector2_mul},
        {"__div", l_vector2_div},
        {"__unm", l_vector2_unm},
        {"__eq", l_vector2_eq},
        {"__tostring", l_vector2_tostring},
        {nullptr, nullptr},
    };
    static const luaL_Reg vector3Meta[] = {
        {"__index", l_vector3_index},
        {"__add", l_vector3_add},
        {"__sub", l_vector3_sub},
        {"__mul", l_vector3_mul},
        {"__div", l_vector3_div},
        {"__unm", l_vector3_unm},
        {"__eq", l_vector3_eq},
        {"__tostring", l_vector3_tostring},
        {nullptr, nullptr},
    };
    static const luaL_Reg color3Meta[] = {
        {"__index", l_color3_index},
        {"__eq", l_color3_eq},
        {"__tostring", l_color3_tostring},
        {nullptr, nullptr},
    };
    static const luaL_Reg udimMeta[] = {
        {"__index", l_udim_index},
        {"__add", l_udim_add},
        {"__sub", l_udim_sub},
        {"__eq", l_udim_eq},
        {"__tostring", l_udim_tostring},
        {nullptr, nullptr},
    };
    static const luaL_Reg udim2Meta[] = {
        {"__index", l_udim2_index},
        {"__add", l_udim2_add},
        {"__sub", l_udim2_sub},
        {"__eq", l_udim2_eq},
        {"__tostring", l_udim2_tostring},
        {nullptr, nullptr},
    };
    static const luaL_Reg cframeMeta[] = {
        {"__index", l_cframe_index},
        {"__mul", l_cframe_mul},
        {"__add", l_cframe_add},
        {"__sub", l_cframe_sub},
        {"__eq", l_cframe_eq},
        {"__tostring", l_cframe_tostring},
        {nullptr, nullptr},
    };
    static const luaL_Reg rayMeta[] = {
        {"__index", l_ray_index},
        {"__tostring", l_ray_tostring},
        {nullptr, nullptr},
    };

    registerMetatable(L, "Vector2", kTagVector2, vector2Meta);
    registerVector3Metatable(L, vector3Meta);
    registerMetatable(L, "Color3", kTagColor3, color3Meta);
    registerMetatable(L, "UDim", kTagUDim, udimMeta);
    registerMetatable(L, "UDim2", kTagUDim2, udim2Meta);
    registerMetatable(L, "CFrame", kTagCFrame, cframeMeta);
    registerMetatable(L, "Ray", kTagRay, rayMeta);

    static const luaL_Reg color3Ctor[] = {
        {"new", l_color3_new},
        {"fromRGB", l_color3_from_rgb},
        {"toHSV", l_color3_to_hsv},
        {"fromHSV", l_color3_from_hsv},
        {"fromHex", l_color3_from_hex},
        {nullptr, nullptr},
    };
    static const luaL_Reg udimCtor[] = {{"new", l_udim_new}, {nullptr, nullptr}};
    static const luaL_Reg udim2Ctor[] = {{"new", l_udim2_new}, {"fromOffset", l_udim2_from_offset}, {"fromScale", l_udim2_from_scale}, {nullptr, nullptr}};
    static const luaL_Reg cframeCtor[] = {
        {"new", l_cframe_new},
        {"Angles", l_cframe_angles},
        {"fromOrientation", l_cframe_angles_yxz},
        {"fromEulerAnglesXYZ", l_cframe_angles},
        {"fromEulerAnglesYXZ", l_cframe_angles_yxz},
        {"fromEulerAngles", l_cframe_angles},
        {"fromAxisAngle", l_cframe_from_axis_angle},
        {"fromMatrix", l_cframe_from_matrix},
        {"lookAt", l_cframe_look_at},
        {"lookAlong", l_cframe_look_along},
        {"fromRotationBetweenVectors", l_cframe_from_rotation_between_vectors},
        {nullptr, nullptr},
    };
    static const luaL_Reg rayCtor[] = {{"new", l_ray_new}, {nullptr, nullptr}};

    // These insertion sequences reproduce the release-729 constructor-table
    // iteration order observed in Studio. Some compatibility workloads use
    // raw `next` as part of their environment fingerprint.
    lua_newtable(L);
    pushVector2(L, 0, 1); lua_setfield(L, -2, "yAxis");
    lua_pushcfunction(L, l_vector2_min, "min"); lua_setfield(L, -2, "min");
    pushVector2(L, 0, 0); lua_setfield(L, -2, "zero");
    lua_pushcfunction(L, l_vector2_max, "max"); lua_setfield(L, -2, "max");
    lua_pushcfunction(L, l_vector2_new, "new"); lua_setfield(L, -2, "new");
    pushVector2(L, 1, 1); lua_setfield(L, -2, "one");
    pushVector2(L, 1, 0); lua_setfield(L, -2, "xAxis");
    lua_setglobal(L, "Vector2");

    lua_newtable(L);
    pushVector3(L, 0, 0, 0); lua_setfield(L, -2, "zero");
    lua_pushcfunction(L, l_vector3_from_axis, "fromAxis"); lua_setfield(L, -2, "fromAxis");
    pushVector3(L, 0, 1, 0); lua_setfield(L, -2, "yAxis");
    pushVector3(L, 1, 1, 1); lua_setfield(L, -2, "one");
    lua_pushcfunction(L, l_vector3_from_normal_id, "FromNormalId"); lua_setfield(L, -2, "FromNormalId");
    lua_pushcfunction(L, l_vector3_min, "min"); lua_setfield(L, -2, "min");
    lua_pushcfunction(L, l_vector3_from_normal_id, "fromNormalId"); lua_setfield(L, -2, "fromNormalId");
    lua_pushcfunction(L, l_vector3_new, "new"); lua_setfield(L, -2, "new");
    pushVector3(L, 1, 0, 0); lua_setfield(L, -2, "xAxis");
    lua_pushcfunction(L, l_vector3_max, "max"); lua_setfield(L, -2, "max");
    lua_pushcfunction(L, l_vector3_from_axis, "FromAxis"); lua_setfield(L, -2, "FromAxis");
    pushVector3(L, 0, 0, 1); lua_setfield(L, -2, "zAxis");
    lua_setglobal(L, "Vector3");

    registerConstructorTable(L, "Color3", color3Ctor);
    registerConstructorTable(L, "UDim", udimCtor);
    registerConstructorTable(L, "UDim2", udim2Ctor);
    registerConstructorTable(L, "CFrame", cframeCtor);
    registerConstructorTable(L, "Ray", rayCtor);

    lua_getglobal(L, "CFrame");
    pushCFrame(L, identityCFrame());
    lua_setfield(L, -2, "identity");
    lua_pop(L, 1);
}

int l_loadstring_runner(lua_State* L)
{
    int nargs = lua_gettop(L);
    int loadId = lua_tointeger(L, lua_upvalueindex(2));

    if (gLuraph.active && gConfig.luraphSaveIntermediates)
    {
        gLuraph.observations.push_back({
            {"kind", "loadstring_bridge_invocation"},
            {"load_id", loadId},
            {"argument_count", nargs},
        });
        lua_pushvalue(L, lua_upvalueindex(1));
        captureFunctionDump(L, -1, "loadstring_chunk_" + std::to_string(loadId));
        lua_pop(L, 1);
        for (int argument = 1; argument <= nargs; ++argument)
        {
            if (lua_type(L, argument) == LUA_TFUNCTION || lua_type(L, argument) == LUA_TTABLE)
                captureFunctionDump(L, argument, "loadstring_argument_" + std::to_string(loadId) + "_" + std::to_string(argument));
        }
    }

    lua_pushvalue(L, lua_upvalueindex(1));
    lua_insert(L, 1);

    int status = lua_pcall(L, nargs, LUA_MULTRET, 0);
    if (status != LUA_OK)
    {
        std::string message = stackString(L, -1);
        std::ostringstream prefix;
        prefix << "loadstring_error_" << std::setw(4) << std::setfill('0') << loadId;
        captureText(prefix.str(), message, ".txt");
        lua_error(L);
    }

    int returns = lua_gettop(L);
    std::ostringstream prefix;
    prefix << "loadstring_return_" << std::setw(4) << std::setfill('0') << loadId;
    captureReturnValues(L, 1, returns, prefix.str());
    return returns;
}

int l_loadstring(lua_State* L)
{
    size_t len = 0;
    const char* source = luaL_checklstring(L, 1, &len);
    // Luau derives the default debug source from the supplied text.  A fixed
    // name changes debug.info/traceback results and is observable to scripts.
    const char* chunkName = luaL_optstring(L, 2, source);
    std::string probeSource;
    std::string_view sourceToCompile(source, len);

    // Saving a copy at this native boundary is passive: the same source,
    // chunk name, environment, closure, and return values continue through
    // the faithful loadstring path below. This lets protected loaders be
    // diagnosed without installing script-visible string/table hooks.
    if (!analysisHooksEnabled() && gLuraph.active && gConfig.luraphSaveIntermediates)
    {
        json metadata = {{"default_chunk_name", chunkName == source}};
        if (chunkName != source)
            metadata["chunk"] = compactLabel(chunkName, 256);
        captureHostObservationDedup("loadstring_input", std::string_view(source, len), ".lua", metadata);
    }

    if (!gConfig.luraphGeneratedInterpreterProbePath.empty() && gLuraph.active &&
        looksLikeGeneratedLuraphInterpreter(std::string_view(source, len)))
    {
        try
        {
            probeSource = readFile(gConfig.luraphGeneratedInterpreterProbePath);
        }
        catch (const std::exception& error)
        {
            luaL_error(L, "could not read Luraph generated-interpreter probe: %s", error.what());
        }
        if (probeSource.empty() || !parsesAsNonEmptyLuauChunk(probeSource))
            luaL_error(L, "Luraph generated-interpreter probe is empty or invalid Luau");

        sourceToCompile = probeSource;
        gLuraph.generatedInterpreterProbeApplied = true;
        gLuraph.observations.push_back({
            {"kind", "generated_interpreter_probe_substitution"},
            {"classification", "analysis_probe"},
            {"reason", "instrumented generated interpreter substituted at its original loadstring boundary"},
            {"path", gConfig.luraphGeneratedInterpreterProbePath.string()},
            {"original_bytes", len},
            {"probe_bytes", probeSource.size()},
            {"original_sha256", sha256Hex(std::string_view(source, len))},
            {"probe_sha256", sha256Hex(probeSource)},
        });
        writeLuraphReport();
    }

    if (!analysisHooksEnabled())
    {
        lua_setsafeenv(L, LUA_ENVIRONINDEX, false);
        if (!loadChunk(L, sourceToCompile, chunkName))
        {
            lua_pushnil(L);
            lua_insert(L, -2);
            return 2;
        }
        if (gLuraph.active && gConfig.luraphSaveIntermediates)
        {
            const int loadId = gConfig.nextCaptureId;
            lua_pushinteger(L, loadId);
            lua_pushcclosure(L, l_loadstring_runner, "observed_loadstring_chunk", 2);
            gLuraph.observations.push_back({
                {"kind", "loadstring_bridge_wrapped"},
                {"load_id", loadId},
                {"bytes", sourceToCompile.size()},
                {"probe_substituted", !probeSource.empty()},
            });
            writeLuraphReport();
        }
        return 1;
    }

    int loadId = gConfig.nextCaptureId;
    captureText("loadstring_input", std::string_view(source, len), ".lua", {{"chunk", chunkName}});
    captureMirror("captured_script.lua", std::string_view(source, len));

    lua_setsafeenv(L, LUA_ENVIRONINDEX, false);

    if (!loadChunk(L, sourceToCompile, chunkName))
    {
        if (analysisHooksEnabled())
            captureText("loadstring_compile_error", stackString(L, -1), ".txt", {{"chunk", chunkName}});
        lua_pushnil(L);
        lua_insert(L, -2);
        return 2;
    }

    lua_pushinteger(L, loadId);
    lua_pushcclosure(L, l_loadstring_runner, "captured_loadstring_chunk", 2);

    if (gConfig.autorunLoadstring)
    {
        int wrapperIndex = lua_gettop(L);
        lua_pushvalue(L, wrapperIndex);
        int status = lua_pcall(L, 0, LUA_MULTRET, 0);
        int top = lua_gettop(L);
        if (status != LUA_OK)
            std::cerr << "[autorun-loadstring] " << stackString(L, -1) << "\n";
        lua_settop(L, wrapperIndex);
        (void)top;
    }

    return 1;
}

int l_module_loadstring(lua_State* L)
{
    size_t len = 0;
    const char* source = luaL_checklstring(L, 1, &len);
    const char* chunkName = luaL_optstring(L, 2, "=ModuleScript");
    lua_setsafeenv(L, LUA_ENVIRONINDEX, false);
    // ModuleScripts use the same interpreter/CodeGen selection as the main
    // script.  Keeping this on the common load path is important: otherwise a
    // native main chunk can silently execute every required module through the
    // interpreter, which both breaks parity accounting and hides module-only
    // CodeGen regressions.
    if (!loadChunk(L, std::string_view(source, len), chunkName))
    {
        lua_pushnil(L);
        lua_insert(L, -2);
        return 2;
    }
    return 1;
}


const char* kScrubAnalysisGlobals = R"LUASCRUB(
local hidden = {
    "__rbx_httpget",
    "__rbx_httppost",
    "__rbx_http_request",
    "__rbx_json_encode",
    "__rbx_json_decode",
    "__rbx_url_encode",
    "__rbx_url_decode",
    "__rbx_generate_guid",
    "__rbx_elapsed_time",
    "__rbx_wall_time",
    "__rbx_trace_compat",
    "__rbx_api_dump_json",
    "__rbx_scenario_json",
    "__rbx_runtime_config",
    "__rbx_module_loadstring",
    "__rbx_native_signal_new",
    "__rbx_native_signal_fire",
    "__rbx_native_signal_disconnect_all",
    "__rbx_native_http_request",
    "__rbx_capture_text",
    "__rbx_debug_snapshot",
    "__rbx_function_snapshot",
    "__rbx_instance_new",
    "__rbx_instance_bind_public_new",
    "__rbx_instance_bind_public_from_existing",
    "__rbx_executor_bind_native",
    "__rbx_instance_children",
    "__rbx_instance_find",
    "__rbx_instance_is_a",
    "__rbx_instance_destroy",
    "__rbx_instance_set_parent",
    "__rbx_instance_property_signal",
    "__rbx_instance_get_attribute",
    "__rbx_instance_get_attributes",
    "__rbx_instance_set_attribute",
    "__rbx_instance_attribute_signal",
    "__rbx_instance_tags",
    "__rbx_instance_clone",
    "__rbx_instance_full_name",
    "__rbx_make_signal",
    "__rbx_instance_methods",
    "__rbx_execute",
    "__rbx_scheduler_report",
}
for _, name in ipairs(hidden) do
    rawset(_G, name, nil)
end
)LUASCRUB";

void registerGlobals(lua_State* L)
{
    static const luaL_Reg globals[] = {
        {"loadstring", l_loadstring},
        {"print", l_print},
        {"typeof", l_typeof},
        {"warn", l_warn},
        {"wait", l_wait},
        {"spawn", l_spawn},
        {"delay", l_delay},
        {"defer", l_defer},
        {"__rbx_httpget", l_httpget},
        {"__rbx_httppost", l_httppost},
        {"__rbx_http_request", l_http_request},
        {"__rbx_json_encode", l_json_encode},
        {"__rbx_json_decode", l_json_decode},
        {"__rbx_url_encode", l_url_encode},
        {"__rbx_url_decode", l_url_decode},
        {"__rbx_generate_guid", l_generate_guid},
        {"__rbx_elapsed_time", l_elapsed_time},
        {"__rbx_wall_time", l_wall_time},
        {"__rbx_trace_compat", l_trace_compat},
        {"__rbx_api_dump_json", l_api_dump_json},
        {"__rbx_scenario_json", l_scenario_json},
        {"__rbx_runtime_config", l_runtime_config},
        {"__rbx_module_loadstring", l_module_loadstring},
        {"__rbx_capture_text", l_capture_text},
        {"__rbx_debug_snapshot", l_debug_snapshot},
        {"__rbx_function_snapshot", l_function_snapshot},
        {nullptr, nullptr},
    };

    lua_pushvalue(L, LUA_GLOBALSINDEX);
    luaL_register(L, nullptr, globals);
    lua_pop(L, 1);
    if (gConfig.profile == "executor-client")
    {
        lua_pushcfunction(L, l_identifyexecutor, "identifyexecutor");
        lua_setglobal(L, "identifyexecutor");
        lua_pushcfunction(L, l_getexecutorname, "getexecutorname");
        lua_setglobal(L, "getexecutorname");
        lua_pushcfunction(L, l_iscclosure, "iscclosure");
        lua_setglobal(L, "iscclosure");
        lua_pushcfunction(L, l_islclosure, "islclosure");
        lua_setglobal(L, "islclosure");
    }
}

void runLoadedChunk(lua_State* L, const std::string& context)
{
    int status = lua_pcall(L, 0, LUA_MULTRET, 0);
    if (status != LUA_OK)
    {
        reportLuaError(L, context);
        throw std::runtime_error(context + " failed");
    }
}

void runSource(lua_State* L, std::string_view source, const std::string& chunkName, const std::string& context)
{
    if (!loadChunk(L, source, chunkName))
    {
        reportLuaError(L, context + "_compile_error");
        throw std::runtime_error(context + " compile failed");
    }
    runLoadedChunk(L, context);
}

void populateScriptEnvironment(lua_State* L, bool studioRunScriptCompatibility = false)
{
    // Studio's CLI RunScript environment owns only these two mutable tables;
    // engine APIs remain visible through the sandbox environment's __index.
    // Keeping APIs inherited is observable through raw iteration and is part
    // of the Luraph v14.x host fingerprint.
    if (studioRunScriptCompatibility)
    {
        if (lua_getmetatable(L, LUA_GLOBALSINDEX))
        {
            lua_setreadonly(L, -1, false);
            lua_pushliteral(L, "The metatable is locked");
            lua_setfield(L, -2, "__metatable");
            lua_setreadonly(L, -1, true);
            lua_pop(L, 1);
        }
        lua_newtable(L);
        lua_setfield(L, LUA_GLOBALSINDEX, "shared");
        lua_newtable(L);
        lua_setfield(L, LUA_GLOBALSINDEX, "_G");
        return;
    }

    static const char* names[] = {
        "game", "workspace", "Workspace", "script", "shared", "Instance", "Enum", "task",
        "Players", "RunService", "HttpService", "CollectionService", "TweenService",
        "UserInputService", "ContextActionService", "Debris", "TweenInfo", "RaycastParams",
        "OverlapParams", "Vector2", "Vector3", "CFrame", "Color3", "UDim", "UDim2", "Ray",
        "Vector2int16", "Vector3int16",
        "Rect", "Region3", "Region3int16", "Axes", "Faces", "Path2DControlPoint", "PathWaypoint",
        "NumberRange", "NumberSequence", "NumberSequenceKeypoint", "ColorSequence", "ColorSequenceKeypoint",
        "PhysicalProperties", "BrickColor", "Random", "DateTime", "Font", "Content",
        "FloatCurveKey", "RotationCurveKey", "ValueCurveKey", "CatalogSearchParams",
        "DockWidgetPluginGuiInfo", "SecurityCapabilities", "SharedTable",
        "require", "wait", "spawn", "delay", "defer", "time", "elapsedTime", "tick", "ypcall",
        nullptr,
    };
    for (const char** name = names; *name; ++name)
    {
        if (std::strcmp(*name, "shared") == 0)
            lua_newtable(L);
        else
            lua_getglobal(L, *name);
        lua_setfield(L, LUA_GLOBALSINDEX, *name);
    }
    // Roblox keeps per-script globals separate from the mutable cross-script _G table.
    lua_newtable(L);
    lua_setfield(L, LUA_GLOBALSINDEX, "_G");
}

void installExecutorMutableNamespaceCopies(lua_State* L)
{
    if (gConfig.profile != "executor-client")
        return;

    // luaL_sandboxthread installs a frozen proxy metatable. Executor probes
    // commonly inspect or patch their own environment proxy, so replace only
    // this script's metatable with a writable copy. Its __index still targets
    // the sealed host environment; changes cannot escape this lua_State.
    if (lua_getmetatable(L, LUA_GLOBALSINDEX))
    {
        const int originalMetatable = lua_absindex(L, -1);
        lua_newtable(L);
        const int privateMetatable = lua_absindex(L, -1);
        lua_pushnil(L);
        while (lua_next(L, originalMetatable) != 0)
        {
            lua_pushvalue(L, -2);
            lua_pushvalue(L, -2);
            lua_rawset(L, privateMetatable);
            lua_pop(L, 1);
        }
        lua_pushvalue(L, privateMetatable);
        lua_setmetatable(L, LUA_GLOBALSINDEX);
        lua_pop(L, 2);
    }

    // luaL_sandboxthread deliberately shares frozen standard-library
    // namespaces. Executors commonly permit per-script hooks, so give this
    // profile shallow private copies. Roblox constructors, Enum, and task stay
    // locked; library writes cannot affect another script or the host runtime.
    static const char* names[] = {
        "math", "string", "table", "coroutine", "bit32", "utf8", "os", "debug", "buffer", "vector",
        "syn", "http", nullptr,
    };

    for (const char** name = names; *name; ++name)
    {
        lua_getglobal(L, *name);
        if (!lua_istable(L, -1))
        {
            lua_pop(L, 1);
            continue;
        }
        const int original = lua_absindex(L, -1);
        // Luau's native clone preserves the array/hash layout while producing
        // a mutable table. Rebuilding through lua_next/rawset rehashes the
        // namespace and makes iteration order differ from Roblox solely
        // because executor-client needs a private writable copy.
        lua_clonetable(L, original);
        lua_setglobal(L, *name);
        lua_pop(L, 1);
    }

    // GETIMPORT may otherwise keep serving entries from Luau's safe-environment
    // cache after a script replaces a member on one of the private copies.
    // A mutable executor namespace and safeenv imports are contradictory: once
    // these copies exist, imports must observe their current contents.
    lua_setsafeenv(L, LUA_GLOBALSINDEX, false);
}

void captureInterruptTrace(lua_State* L, const std::string& kind, const std::string& vmStatus, const std::string& reason, json extra = json::object())
{
    if (gTimeoutTraceCaptured)
        return;

    gTimeoutTraceCaptured = true;
    std::string trace = timeoutDebugSnapshot(L);
    if (!trace.empty())
    {
        extra["interrupts"] = gInterruptCounter;
        if (analysisHooksEnabled())
            captureText(kind, trace, ".txt", extra);
        else if (gLuraph.active && gConfig.luraphSaveIntermediates)
            captureHostObservation(kind, trace, ".txt", extra);
    }

    finalizeLuraphRecovery(vmStatus, reason);
}

void captureTimeoutTrace(lua_State* L)
{
    captureInterruptTrace(L, "timeout_trace", "timed_out", "VM timed out before exact source was observed");
}

void printProgressIfDue(bool force = false)
{
    if (gConfig.progressIntervalSeconds <= 0)
        return;

    auto now = std::chrono::steady_clock::now();
    if (!force && gLastProgressPrint.time_since_epoch().count() != 0)
    {
        double sinceLast = std::chrono::duration<double>(now - gLastProgressPrint).count();
        if (sinceLast < gConfig.progressIntervalSeconds)
            return;
    }

    double elapsed = std::max(0.001, std::chrono::duration<double>(now - gExecutionStart).count());
    double rate = static_cast<double>(gInterruptCounter) / elapsed;

    std::ostringstream line;
    line << "[progress] steps=" << gInterruptCounter
         << " elapsed=" << std::fixed << std::setprecision(1) << elapsed << "s"
         << " rate=" << std::fixed << std::setprecision(0) << rate << "/s";

    if (gConfig.luraphMaxSteps > 0)
    {
        double pct = (static_cast<double>(gInterruptCounter) / static_cast<double>(gConfig.luraphMaxSteps)) * 100.0;
        line << " max=" << gConfig.luraphMaxSteps
             << " pct=" << std::fixed << std::setprecision(2) << pct << "%";
        if (rate > 0 && gInterruptCounter < gConfig.luraphMaxSteps)
        {
            double eta = static_cast<double>(gConfig.luraphMaxSteps - gInterruptCounter) / rate;
            line << " eta=" << std::fixed << std::setprecision(1) << eta << "s";
        }
    }

    if (gLuraph.active)
    {
        line << " luraph_status=" << gLuraph.status
             << " artifacts=" << luraphArtifactSummary();

        if (gConfig.luraphStallSteps <= 0)
            line << " stall=disabled";
        else if (hasLuraphExtractionArtifact() && !gLuraph.exactRecovered)
            line << " stall=" << luraphStepsSinceProgress() << "/" << gConfig.luraphStallSteps;
        else if (gLuraph.exactRecovered)
            line << " stall=done";
        else
            line << " stall=pending";
    }

    std::cerr << line.str() << "\n";
    gLastProgressPrint = now;
}

void interruptForTimeout(lua_State* L, int)
{
    ++gInterruptCounter;

    // Host limits are not Lua exceptions.  A script may catch luaL_error with
    // pcall/xpcall, so use the VM break state and retain an out-of-band reason
    // that is checked before any script return or scheduler state is accepted.
    if (gInstructionBudgetReached || gWallTimeoutReached || gLuraphStallReached || (gLuraph.active && gLuraph.stopRequested))
    {
        lua_break(L);
        return;
    }

    if (gLuraph.active && gConfig.luraphMaxSteps > 0 && gInterruptCounter >= gConfig.luraphMaxSteps)
    {
        printProgressIfDue(true);
        gInstructionBudgetReached = true;
        gHostInterruptMessage = "instruction safepoint budget exhausted after " + std::to_string(gInterruptCounter) + " steps";
        captureInterruptTrace(
            L,
            "instruction_budget_trace",
            "instruction_budget",
            gHostInterruptMessage,
            {{"max_steps", gConfig.luraphMaxSteps}});
        lua_break(L);
        return;
    }

    if ((gInterruptCounter & 0xfff) != 0)
        return;

    printProgressIfDue();

    if (gLuraph.active && gConfig.luraphStallSteps > 0 && hasLuraphExtractionArtifact() && !gLuraph.exactRecovered)
    {
        uint64_t idleSteps = luraphStepsSinceProgress();
        if (idleSteps > gConfig.luraphStallSteps)
        {
            printProgressIfDue(true);
            std::string reason = "Luraph VM stalled after " + std::to_string(idleSteps) + " safepoints without a new capture after extraction began";
            gLuraphStallReached = true;
            gHostInterruptMessage = reason;
            captureInterruptTrace(
                L,
                "stall_trace",
                "stalled",
                reason,
                {{"idle_safepoints", idleSteps}, {"stall_steps", gConfig.luraphStallSteps}, {"last_progress_step", gLastLuraphProgressStep}});
            lua_break(L);
            return;
        }
    }

    if (gExecutionDeadline.time_since_epoch().count() != 0 && std::chrono::steady_clock::now() > gExecutionDeadline)
    {
        gWallTimeoutReached = true;
        std::ostringstream message;
        message << "execution timed out after " << std::fixed << std::setprecision(2) << gConfig.timeoutSeconds << " seconds";
        gHostInterruptMessage = message.str();
        captureTimeoutTrace(L);
        lua_break(L);
    }
}

NetworkPolicy parseNetworkPolicy(const std::string& value)
{
    if (value == "live")
        return NetworkPolicy::Live;
    if (value == "offline")
        return NetworkPolicy::Offline;
    if (value == "allowlist")
        return NetworkPolicy::Allowlist;
    throw std::runtime_error("invalid network policy: " + value);
}

rbx::runtime::ExecutionMode parseExecutionMode(const std::string& value)
{
    if (value == "faithful")
        return rbx::runtime::ExecutionMode::Faithful;
    if (value == "diagnostic")
        return rbx::runtime::ExecutionMode::Diagnostic;
    throw std::runtime_error("invalid execution mode: " + value);
}

rbx::runtime::ExecutorPreset parseExecutorPreset(const std::string& value)
{
    if (value == "generic")
        return rbx::runtime::ExecutorPreset::Generic;
    if (value == "opiumware")
        return rbx::runtime::ExecutorPreset::Opiumware;
    throw std::runtime_error("invalid executor preset: " + value);
}

rbx::runtime::FilesystemPolicy parseFilesystemPolicy(const std::string& value)
{
    if (value == "disabled")
        return rbx::runtime::FilesystemPolicy::Disabled;
    if (value == "memory")
        return rbx::runtime::FilesystemPolicy::Memory;
    throw std::runtime_error("invalid filesystem policy: " + value);
}

size_t parseMemoryLimitBytes(const std::string& value)
{
    constexpr uint64_t kMiB = 1024ull * 1024ull;
    uint64_t mebibytes = std::stoull(value);
    if (mebibytes == 0)
        throw std::runtime_error("--memory-limit-mb must be at least 1");
    if (mebibytes > std::numeric_limits<size_t>::max() / kMiB)
        throw std::runtime_error("--memory-limit-mb is too large for this platform");
    return static_cast<size_t>(mebibytes * kMiB);
}

size_t parseProbeTraceLimitBytes(const std::string& value)
{
    size_t consumed = 0;
    uint64_t bytes = 0;
    try
    {
        bytes = std::stoull(value, &consumed);
    }
    catch (const std::exception&)
    {
        throw std::runtime_error("--probe-trace-limit-bytes must be an integer");
    }

    if (consumed != value.size())
        throw std::runtime_error("--probe-trace-limit-bytes must be an integer");
    if (bytes == 0)
        throw std::runtime_error("--probe-trace-limit-bytes must be at least 1");
    if (bytes > kMaxProbeTraceLimitBytes)
        throw std::runtime_error("--probe-trace-limit-bytes must not exceed " + std::to_string(kMaxProbeTraceLimitBytes));
    return static_cast<size_t>(bytes);
}

LuraphMode parseLuraphMode(const std::string& value)
{
    if (value == "off")
        return LuraphMode::Off;
    if (value == "auto")
        return LuraphMode::Auto;
    if (value == "force")
        return LuraphMode::Force;
    throw std::runtime_error("invalid luraph mode: " + value);
}

OwnerProtectionMode parseOwnerProtectionMode(const std::string& value)
{
    if (value == "respect")
        return OwnerProtectionMode::Respect;
    if (value == "ignore")
        return OwnerProtectionMode::Ignore;
    if (value == "audit")
        return OwnerProtectionMode::Audit;
    throw std::runtime_error("invalid owner protection mode: " + value);
}

AnalysisHooksMode parseAnalysisHooksMode(const std::string& value)
{
    if (value == "auto")
        return AnalysisHooksMode::Auto;
    if (value == "on")
        return AnalysisHooksMode::On;
    if (value == "off")
        return AnalysisHooksMode::Off;
    throw std::runtime_error("invalid analysis hooks mode: " + value);
}

ClockMode parseClockMode(const std::string& value)
{
    if (value == "virtual")
        return ClockMode::Virtual;
    if (value == "realtime")
        return ClockMode::Realtime;
    throw std::runtime_error("invalid clock mode: " + value);
}

UnsupportedPolicy parseUnsupportedPolicy(const std::string& value)
{
    if (value == "error")
        return UnsupportedPolicy::Error;
    if (value == "trace-nil")
        return UnsupportedPolicy::TraceNil;
    throw std::runtime_error("invalid unsupported policy: " + value);
}

RegisterOverflowMode parseRegisterOverflowMode(const std::string& value)
{
    if (value == "error")
        return RegisterOverflowMode::Error;
    if (value == "spill")
        return RegisterOverflowMode::Spill;
    throw std::runtime_error("invalid register overflow mode: " + value);
}

void loadOwnerPublicKeys()
{
    for (const fs::path& path : gConfig.ownerPublicKeyPaths)
        gConfig.ownerPublicKeys.push_back(alex::owner::read_public_key(path));

    if (gConfig.ownerPublicKeys.empty())
    {
        fs::path local = fs::current_path() / "keys" / "alex_owner.public";
        if (fs::exists(local))
            gConfig.ownerPublicKeys.push_back(alex::owner::read_public_key(local));
    }
}

int handleOwnerProtection(std::string_view source)
{
    if (gConfig.ownerProtection == OwnerProtectionMode::Ignore)
        return -1;

    alex::owner::ScanResult scan = alex::owner::scan_source(source, gConfig.ownerPublicKeys);
    if (scan.invalid)
        traceCompat("owner_capsule_invalid", std::to_string(scan.owner_hash), {{"reason", scan.reason}, {"nonce", scan.nonce}});

    if (!scan.verified)
        return -1;

    json report = {
        {"status", gConfig.ownerProtection == OwnerProtectionMode::Respect ? "refused" : "audit"},
        {"reason", "verified owner-protected Alexfuscator capsule"},
        {"owner_id", scan.owner_id},
        {"owner_hash", scan.owner_hash},
        {"nonce", scan.nonce},
        {"mode", ownerProtectionModeName(gConfig.ownerProtection)},
    };

    if (gConfig.ownerProtection == OwnerProtectionMode::Audit)
    {
        traceCompat("owner_capsule_verified", scan.owner_id, report);
        return -1;
    }

    writeFile(gConfig.outputDir / "owner_protected_refused.json", report.dump(2));
    std::cout << "[owner] refused protected script for owner " << scan.owner_id << " before execution\n";
    return 0;
}

void printUsage(const char* argv0)
{
    std::cerr << "Usage: " << argv0 << " [options] script.lua\n"
              << "Options:\n"
              << "  --out DIR\n"
              << "  --capture-min N\n"
              << "  --capture-string-hooks|--no-capture-string-hooks\n"
              << "  --profile roblox-client|executor-client\n"
              << "  --execution-mode faithful|diagnostic (default faithful)\n"
              << "  --executor-preset generic|opiumware (default generic)\n"
              << "  --filesystem disabled|memory (profile default)\n"
              << "  --memory-limit-mb N (default 512)\n"
              << "  --deterministic-seed N (default derived from source SHA-256)\n"
              << "  --clock virtual|realtime (default virtual)\n"
              << "  --frame-rate N (default 60)\n"
              << "  --max-virtual-seconds N (default 30)\n"
              << "  --scenario PATH (versioned JSON world and fixture descriptor)\n"
              << "  --unsupported error|trace-nil\n"
              << "  --register-overflow error|spill (default error; spill rewrites excess lexical bindings)\n"
              << "  --report PATH|- (machine-readable runtime report)\n"
              << "  --analysis-hooks on|off|auto (faithful default off; diagnostic default on)\n"
              << "  --owner-protection respect|ignore|audit\n"
              << "  --owner-public-key PATH (repeatable; also auto-loads keys/alex_owner.public if present)\n"
              << "  --minimal-env\n"
              << "  --network-policy allowlist|live|offline\n"
              << "  --allow-host HOST\n"
              << "  --allow-private-network (local CLI only)\n"
              << "  --fixture URL=PATH\n"
              << "  --trace-compat PATH\n"
              << "  --trace-calls\n"
              << "  --trace-environment PATH (native global/environment access JSONL)\n"
              << "  --probe-trace PATH (internal Luraph probe evidence output)\n"
              << "  --probe-trace-limit-bytes N (1.." << kMaxProbeTraceLimitBytes << "; default " << kDefaultProbeTraceLimitBytes << ")\n"
              << "  --trace-environment-after-clock-calls N (delay activation for timing probes)\n"
              << "  --trace-environment-max-events N (default 100000)\n"
              << "  --luraph-mode off|auto|force\n"
              << "  --luraph-stop-after-exact-source|--no-luraph-stop-after-exact-source\n"
              << "  --luraph-save-intermediates|--no-luraph-save-intermediates\n"
              << "  --luraph-generated-interpreter-probe PATH (analysis-only loadstring substitution)\n"
              << "  --luraph-max-steps N\n"
              << "  --luraph-stall-steps N (0 disables no-new-capture stall detection)\n"
              << "  --progress-interval SECONDS (prints VM safepoint progress; 0 disables)\n"
              << "  --sift-decompile|--decompile\n"
              << "  --sift-disassemble|--disassemble|--disamble\n"
              << "  --sift-api-key KEY (prefer SIFTRBLX_API_KEY env for secrets)\n"
              << "  --sift-api-key-env NAME\n"
              << "  --sift-base-url URL\n"
              << "  --chunk-name NAME\n"
              << "  --luau-opt-level N\n"
              << "  --luau-debug-level N\n"
              << "  --timeout SECONDS (0 disables the watchdog)\n"
              << "  --place-id ID --game-id ID --job-id ID --user-id ID --player-name NAME\n"
              << "  --stop-after-capture\n"
              << "  --trace-pcall-errors\n"
              << "  --normalize-pcall-errors|--no-normalize-pcall-errors\n"
              << "  --native-codegen|--no-native-codegen\n"
              << "  --native-codegen-block-mb N\n"
              << "  --native-codegen-max-mb N\n"
              << "  --pass-source-as-arg\n"
              << "  --autorun-loadstring|--no-autorun-loadstring\n";
}

json schedulerReport(lua_State* L)
{
    if (!L)
        return json::object();
    rbx::runtime::RuntimeContext* context = rbx::runtime::RuntimeContext::from(L);
    if (!context)
        return json::object();

    const rbx::runtime::Scheduler& scheduler = context->scheduler();
    const rbx::runtime::SchedulerStats stats = scheduler.stats();
    json errors = json::array();
    for (const rbx::runtime::TaskSnapshot& task : scheduler.tasks())
    {
        if (task.status == rbx::runtime::TaskStatus::Failed)
            errors.push_back(task.error);
    }
    json events = json::array();
    for (const rbx::runtime::SchedulerEvent& event : scheduler.events())
    {
        events.push_back({
            {"sequence", event.sequence},
            {"time", event.time},
            {"task", event.task},
            {"kind", event.kind},
            {"detail", event.detail},
        });
    }
    const double frameDuration = scheduler.options().frameDurationSeconds;
    return {
        {"clock", scheduler.clock()->mode() == rbx::runtime::ClockMode::Virtual ? "virtual" : "realtime"},
        {"virtual_time", scheduler.now()},
        {"frames", frameDuration > 0.0 ? static_cast<uint64_t>(std::floor(scheduler.now() / frameDuration)) : 0},
        {"timed_out", false},
        {"budget_reached", false},
        {"stop_reason", "running"},
        {"errors", std::move(errors)},
        {"events", std::move(events)},
        {"pending", {
            {"ready", scheduler.queuedCount()},
            {"deferred", 0},
            {"timers", scheduler.timerCount()},
            {"external", stats.externalPending},
            {"waiting", stats.waiting},
            {"suspended", stats.suspended},
        }},
        {"total_resumes", stats.totalResumes},
    };
}

json nativeRuntimeReport(lua_State* L)
{
    rbx::runtime::RuntimeContext* context = L ? rbx::runtime::RuntimeContext::from(L) : nullptr;
    if (!context)
        return json::object();

    const rbx::runtime::SchedulerStats stats = context->scheduler().stats();
    json tasks = json::array();
    for (const rbx::runtime::TaskSnapshot& task : context->scheduler().tasks())
    {
        tasks.push_back({
            {"id", task.id},
            {"name", task.name},
            {"state", rbx::runtime::toString(task.status)},
            {"queue", rbx::runtime::toString(task.lastQueue)},
            {"sequence", task.sequence},
            {"resume_count", task.resumeCount},
            {"wait_key", task.waitKey},
            {"error", task.error.empty() ? json(nullptr) : json(task.error)},
            {"security_identity", rbx::runtime::toString(task.execution.security.identity)},
            {"actor_lane", task.execution.actorLane == 0 ? "synchronized" : "desynchronized"},
            {"script_instance_id", task.execution.scriptInstanceId},
        });
    }

    json modules = json::array();
    for (const rbx::runtime::ModuleSnapshot& module : context->modules().snapshots())
    {
        modules.push_back({
            {"id", module.id},
            {"name", module.debugName},
            {"state", rbx::runtime::toString(module.state)},
            {"loader_task", module.loaderTask},
            {"waiters", module.waiterCount},
            {"has_source", module.hasSource},
            {"has_value", module.hasValue},
            {"error", module.error.empty() ? json(nullptr) : json(module.error)},
        });
    }

    const rbx::runtime::ThreadContext& mainThread = context->mainThread();
    json filesystem = nullptr;
    if (context->executor().surface().filesystem)
    {
        const rbx::runtime::FilesystemStats filesystemStats = context->executor().surface().filesystem->stats();
        filesystem = {
            {"mode", "memory"},
            {"used_bytes", filesystemStats.usedBytes},
            {"files", filesystemStats.fileCount},
            {"directories", filesystemStats.directoryCount},
            {"total_byte_limit", filesystemStats.limits.totalBytes},
            {"file_byte_limit", filesystemStats.limits.maxFileBytes},
            {"entry_limit", filesystemStats.limits.maxEntries},
        };
    }
    json network = nullptr;
    if (rbx::runtime::NetworkBroker* broker = context->network())
    {
        const rbx::runtime::NetworkBrokerStats networkStats = broker->stats();
        network = {
            {"mode", rbx::runtime::toString(broker->guard().config().mode)},
            {"allow_private_network", broker->guard().config().allowPrivateNetwork},
            {"queued", networkStats.queued},
            {"active", networkStats.active},
            {"pending", networkStats.pending},
            {"submitted", networkStats.submitted},
            {"completed", networkStats.completed},
            {"rejected", networkStats.rejected},
            {"cancelled", networkStats.cancelled},
        };
    }
    return {
        {"attached", context->attached()},
        {"thread_contexts", context->threadCount()},
        {"main_thread", {
            {"id", mainThread.id},
            {"script", mainThread.script.debugName},
            {"security_identity", rbx::runtime::toString(mainThread.security.identity)},
            {"actor_lane", rbx::runtime::toString(mainThread.actorLane)},
            {"cancelled", mainThread.cancellation.cancelled()},
        }},
        {"clock", {
            {"mode", context->scheduler().clock()->mode() == rbx::runtime::ClockMode::Virtual ? "virtual" : "realtime"},
            {"monotonic_seconds", context->scheduler().clock()->now()},
            {"unix_millis", context->scheduler().clock()->unixMillis()},
        }},
        {"scheduler", {
            {"queued", stats.queued},
            {"running", stats.running},
            {"waiting", stats.waiting},
            {"suspended", stats.suspended},
            {"completed", stats.completed},
            {"cancelled", stats.cancelled},
            {"failed", stats.failed},
            {"external_pending", stats.externalPending},
            {"total_resumes", stats.totalResumes},
            {"tasks", std::move(tasks)},
        }},
        {"modules", std::move(modules)},
        {"network", std::move(network)},
        {"executor", {
            {"enabled", context->executor().enabled()},
            {"name", context->executor().surface().identity.name},
            {"version", context->executor().surface().identity.version},
            {"filesystem", std::move(filesystem)},
        }},
    };
}

void verifyRobloxEnvironment(lua_State* L)
{
    const rbx::v2::DataModelSnapshot snapshot = rbx::v2::inspectDataModel(L);
    rbx::runtime::RobloxEnvironmentPolicy policy = rbx::runtime::defaultRobloxEnvironmentPolicy();
    policy.expectedPlaceId = gConfig.placeId;
    policy.expectedGameId = gConfig.gameId;
    policy.expectedJobId = gConfig.jobId;
    const rbx::runtime::RobloxEnvironmentResult result = rbx::runtime::evaluateRobloxEnvironment(snapshot, policy);

    json findings = json::array();
    for (const rbx::runtime::RobloxEnvironmentFinding& finding : result.findings)
    {
        findings.push_back({
            {"code", finding.code},
            {"subject", finding.subject},
            {"expected", finding.expected},
            {"observed", finding.observed},
        });
    }

    json services = json::array();
    for (const rbx::v2::DataModelChildSnapshot& child : snapshot.directChildren)
    {
        if (!child.serviceClass)
            continue;
        services.push_back({
            {"class", child.className},
            {"name", child.name},
            {"instance_id", child.instanceId},
            {"parent_id", child.parentId},
            {"native_identity", child.registryObjectValid},
            {"destroyed", child.destroyed},
        });
    }

    gRobloxEnvironmentIntegrity = {
        {"status", rbx::runtime::robloxEnvironmentStatus(result)},
        {"passed", result.passed},
        {"checks_performed", result.checksPerformed},
        {"findings", std::move(findings)},
        {"engine", {
            {"initialized", snapshot.engineInitialized},
            {"sealed", snapshot.engineSealed},
            {"release", snapshot.engineRelease},
            {"api_hash", snapshot.apiHash},
            {"reflection_version", snapshot.reflectionVersion},
        }},
        {"data_model", {
            {"native_identity", snapshot.gameRegistryIdentityValid},
            {"instance_id", snapshot.gameInstanceId},
            {"class", snapshot.gameClassName},
            {"parent_id", snapshot.gameParentId},
            {"place_id", snapshot.placeId ? json(*snapshot.placeId) : json(nullptr)},
            {"game_id", snapshot.gameId ? json(*snapshot.gameId) : json(nullptr)},
            {"place_version", snapshot.placeVersion ? json(*snapshot.placeVersion) : json(nullptr)},
            {"job_id", snapshot.jobId ? json(*snapshot.jobId) : json(nullptr)},
        }},
        {"workspace", {
            {"native_identity", snapshot.workspaceRegistryIdentityValid},
            {"alias_identity", snapshot.workspaceAliasIdentityValid},
            {"instance_id", snapshot.workspaceInstanceId},
            {"parent_id", snapshot.workspaceParentId},
            {"class", snapshot.workspaceClassName},
        }},
        {"services", std::move(services)},
    };

    if (!result.passed)
    {
        const std::string firstCode = result.findings.empty() ? "unknown" : result.findings.front().code;
        throw std::runtime_error("Roblox DataModel integrity check failed [" + firstCode + "]");
    }
}

void writeRuntimeReport(const std::string& status, const std::string& error, lua_State* L = nullptr)
{
    if (gConfig.reportPath.empty())
        return;
    static const std::string apiJson = apiDumpSummaryJson();
    json unsupported = json::array();
    for (const json& entry : gCompatReportEvents)
    {
        std::string kind = entry.value("kind", "");
        if (kind == "stub_method" || kind == "missing_member" || kind == "missing_global" || kind == "missing_fixture")
            unsupported.push_back(entry);
    }
    json scheduler = schedulerReport(L);
    const std::string steadyStateReason = !gSteadyStateReasonOverride.empty() ? gSteadyStateReasonOverride
        : status == "virtual_budget"                                           ? "virtual_time_budget"
                                                                                : "native_scheduler_steady_state";
    if (status == "steady_state")
    {
        scheduler["stop_reason"] = "steady_state_budget";
        scheduler["errors"] = json::array();
        scheduler["steady_state_reason"] = steadyStateReason;
    }
    else if (status == "virtual_budget")
    {
        scheduler["budget_reached"] = true;
        scheduler["stop_reason"] = "virtual_budget";
        scheduler["errors"] = json::array();
        scheduler["steady_state_reason"] = steadyStateReason;
    }
    else if (status == "instruction_budget")
    {
        scheduler["budget_reached"] = true;
        scheduler["stop_reason"] = "instruction_budget";
        scheduler["steady_state_reason"] = nullptr;
    }
    else if (status == "completed" || status == "stopped_after_exact_source")
        scheduler["stop_reason"] = "completed";
    else if (status == "blocked")
        scheduler["stop_reason"] = "blocked";
    std::string effectiveStatus = status;

    std::string terminationReason = "runtime_error";
    if (effectiveStatus == "completed" || effectiveStatus == "stopped_after_exact_source")
        terminationReason = "completed";
    else if (effectiveStatus == "virtual_budget" || effectiveStatus == "steady_state")
        terminationReason = "virtual_budget";
    else if (effectiveStatus == "blocked")
        terminationReason = "blocked";
    else if (effectiveStatus == "instruction_budget")
        terminationReason = "instruction_budget";
    else if (containsText(error, "network host is not allowed") || containsText(error, "[required-host="))
        terminationReason = "network_required";
    else if (containsText(error, "execution timed out") || containsText(error, "max steps exceeded"))
        terminationReason = "wall_timeout";
    else if (containsText(error, "output exceeded"))
        terminationReason = "output_limit";
    else if (gVmMemoryBudget.limitHit || containsText(error, "not enough memory") || containsText(error, "out of memory") ||
        containsText(error, "memory limit"))
        terminationReason = "memory_limit";

    std::string executionState = "failed";
    if (terminationReason == "completed")
        executionState = "completed";
    else if (terminationReason == "virtual_budget")
        executionState = "steady_state";
    else if (terminationReason == "network_required" || terminationReason == "blocked")
        executionState = "blocked";

    json activityEvidence = json::array();
    if (!gCapturedStdout.empty())
        activityEvidence.push_back({{"kind", "stdout"}, {"count", gCapturedStdout.size()}});
    if (!gMainReportReturns.empty())
        activityEvidence.push_back({{"kind", "return"}, {"count", gMainReportReturns.size()}});
    for (const json& event : gCompatReportEvents)
    {
        const std::string kind = event.value("kind", "");
        if (kind == "api_call" || kind == "network_response" || kind == "network_request")
            activityEvidence.push_back({{"kind", kind}, {"name", event.value("name", "")}});
    }
    if (L)
    {
        if (rbx::runtime::RuntimeContext* context = rbx::runtime::RuntimeContext::from(L))
        {
            uint64_t payloadTasks = 0;
            for (const rbx::runtime::TaskSnapshot& task : context->scheduler().tasks())
                if (task.id > gSchedulerTaskIdBaseline && task.name != "main")
                    ++payloadTasks;
            if (payloadTasks != 0)
                activityEvidence.push_back({{"kind", "scheduler_tasks"}, {"count", payloadTasks}});
        }
    }
    const bool payloadActivity = !activityEvidence.empty();
    const bool releaseSubjectMatch = gInputSha256 == rbx::runtime::kSubjectSha256 && gInputBytes == rbx::runtime::kSubjectBytes;
    std::string workloadClassification = gLuraph.detected ? "luraph_wrapper" : "generic_script";
    if (releaseSubjectMatch)
        workloadClassification = "release729_subject";
    std::string workloadPhase = "loaded";
    if (gLuraph.detected && gInterruptCounter > 0)
        workloadPhase = payloadActivity ? "payload_activity" : "executing";
    if (gLuraph.exactRecovered)
        workloadPhase = "source_observed";

    json dependencyRequirements = json::array();
    for (const json& requirement : gNetworkRequirements)
    {
        dependencyRequirements.push_back({
            {"kind", "network_host"},
            {"name", requirement.value("host", "")},
            {"url", requirement.value("url", "")},
            {"reason", requirement.value("reason", "network_policy")},
            {"required", true},
        });
    }
    for (const json& item : unsupported)
    {
        dependencyRequirements.push_back({
            {"kind", "runtime_api"},
            {"name", item.value("name", "")},
            {"reason", item.value("kind", "unsupported")},
            {"required", true},
        });
    }

    json nativeSnapshot = nativeRuntimeReport(L);
    json engineSnapshot = L ? json::parse(rbx::v2::engineStatsJson(L)) : json::object();
    json datatypeCatalog = json::array();
    json datatypeAvailability = json::object();
    for (const rbx::runtime::DatatypeCatalogEntry& datatype : rbx::runtime::release729DatatypeCatalog())
    {
        const std::string availability(rbx::runtime::toString(datatype.availability));
        datatypeCatalog.push_back({
            {"name", datatype.name},
            {"availability", availability},
            {"has_global", datatype.hasGlobal},
            {"constructible", datatype.constructible},
            {"mutable", datatype.mutableValue},
        });
        datatypeAvailability[availability] = datatypeAvailability.value(availability, uint64_t{0}) + 1;
    }
    engineSnapshot["datatypes"] = {
        {"release", rbx::runtime::kEngineRelease},
        {"count", datatypeCatalog.size()},
        {"availability", std::move(datatypeAvailability)},
        {"catalog", std::move(datatypeCatalog)},
    };
    uint64_t observedApiCalls = 0;
    for (const json& event : gCompatReportEvents)
        if (event.value("kind", "") == "api_call")
            ++observedApiCalls;
    const json nativeScheduler = nativeSnapshot.value("scheduler", json::object());
    const json nativeNetwork = nativeSnapshot.value("network", json::object());
    json engineEffects = {
        {"instances_created", engineSnapshot.value("created_instances", uint64_t{0})},
        {"instances_destroyed", engineSnapshot.value("destroyed_instances", uint64_t{0})},
        {"instances_live", engineSnapshot.value("live_instances", uint64_t{0})},
        {"scheduler_resumes", nativeScheduler.value("total_resumes", uint64_t{0})},
        {"network_requests_submitted", nativeNetwork.is_object() ? nativeNetwork.value("submitted", uint64_t{0}) : uint64_t{0}},
        {"network_requests_completed", nativeNetwork.is_object() ? nativeNetwork.value("completed", uint64_t{0}) : uint64_t{0}},
        {"api_calls_observed", observedApiCalls},
        {"compatibility_events", gCompatReportEvents.size()},
        {"stdout_lines", gCapturedStdout.size()},
        {"stderr_lines", gCapturedStderr.size()},
    };

    json report = {
        {"version", rbx::runtime::kReportSchemaVersion},
        {"schema", "rbx-luau-runtime.report.v3"},
        {"engine_release", rbx::runtime::kEngineRelease},
        {"api_hash", rbx::runtime::kFullApiSha256},
        {"api_descriptor_hash", sha256Hex(apiJson)},
        {"release", json::parse(rbx::runtime::releaseManifestJson())},
        {"profile", gConfig.profile},
        {"execution_mode", rbx::runtime::name(gConfig.executionMode)},
        {"execution_state", executionState},
        {"executor_preset", rbx::runtime::name(gConfig.executorPreset)},
        {"filesystem_policy", rbx::runtime::name(effectiveFilesystemPolicy())},
        {"clock", clockModeName(gConfig.clockMode)},
        {"virtual_epoch_seconds", gConfig.virtualEpochSeconds},
        {"frame_rate", gConfig.frameRate},
        {"max_virtual_seconds", gConfig.maxVirtualSeconds},
        {"unsupported_policy", unsupportedPolicyName()},
        {"register_overflow", {
            {"mode", registerOverflowModeName(gConfig.registerOverflow)},
            {"retries", gRegisterOverflowUsage.retries},
            {"chunks_rewritten", gRegisterOverflowUsage.chunksRewritten},
            {"chunks_narrowed", gRegisterOverflowUsage.chunksNarrowed},
            {"functions_rewritten", gRegisterOverflowUsage.functionsRewritten},
            {"bindings_spilled", gRegisterOverflowUsage.bindingsSpilled},
            {"declarations_sunk", gRegisterOverflowUsage.declarationsSunk},
            {"bindings_narrowed", gRegisterOverflowUsage.bindingsNarrowed},
            {"scopes_narrowed", gRegisterOverflowUsage.scopesNarrowed},
            {"diagnostics", gRegisterOverflowUsage.diagnostics},
        }},
        {"status", effectiveStatus},
        {"termination_reason", terminationReason},
        {"steady_state_reason", executionState == "steady_state" ? json(steadyStateReason) : json(nullptr)},
        {"blocked_reason", executionState == "blocked" ? gBlockedReason : json(nullptr)},
        {"error", error.empty() ? json(nullptr) : json(jsonSafeText(error))},
        {"returns", gMainReportReturns},
        {"typed_returns", gMainTypedReturns},
        {"stdout", gCapturedStdout},
        {"stderr", gCapturedStderr},
        {"unsupported", unsupported},
        {"network_requirements", gNetworkRequirements},
        {"dependency_requirements", std::move(dependencyRequirements)},
        {"scheduler", scheduler},
        {"native_runtime", std::move(nativeSnapshot)},
        {"engine", std::move(engineSnapshot)},
        {"engine_effects", std::move(engineEffects)},
        {"environment_trace", {
            {"enabled", !gConfig.traceEnvironmentPath.empty()},
            {"active", gNativeEnvironmentTraceActive},
            {"path", gConfig.traceEnvironmentPath.empty() ? json(nullptr) : json(gConfig.traceEnvironmentPath.string())},
            {"activation_clock_calls", gConfig.traceEnvironmentAfterClockCalls},
            {"clock_calls_observed", gNativeEnvironmentClockCalls},
            {"accesses", gNativeEnvironmentTraceAccesses},
            {"unique_events", gNativeEnvironmentTraceEvents.size()},
            {"dropped", gNativeEnvironmentTraceDropped},
            {"script_visible_proxy", false},
            {"native_codegen", false},
        }},
        {"workload", {
            {"family", gLuraph.detected ? "luraph" : "generic"},
            {"detected", gLuraph.detected},
            {"classification", workloadClassification},
            {"subject_fixture_match", releaseSubjectMatch},
            {"phase", workloadPhase},
            {"payload_activity", payloadActivity},
            {"activity_evidence", std::move(activityEvidence)},
            {"safepoints", gInterruptCounter},
            {"input_sha256", gInputSha256},
            {"input_bytes", gInputBytes},
        }},
        {"limits", {
            {"memory_limit_bytes", gVmMemoryBudget.limit},
            {"memory_current_bytes", gVmMemoryBudget.current},
            {"memory_peak_bytes", gVmMemoryBudget.peak},
            {"memory_limit_hit", gVmMemoryBudget.limitHit},
            {"output_limit_bytes", kOutputCaptureLimitBytes},
            {"output_captured_bytes", gOutputCapturedBytes},
            {"output_limit_hit", gOutputLimitHit},
            {"probe_trace_limit_bytes", gConfig.probeTraceLimitBytes},
            {"probe_trace_bytes", gProbeTraceBytes},
            {"probe_trace_limit_hit", gProbeTraceLimitHit},
            {"codegen_block_bytes", gConfig.nativeCodegenBlockSize},
            {"codegen_max_bytes", gCodegenBudgetBytes},
            {"wall_timeout_seconds", gConfig.timeoutSeconds},
        }},
        {"codegen", {
            {"enabled", gConfig.nativeCodegen},
            {"supported", Luau::CodeGen::isSupported()},
            {"budget_bytes", gCodegenBudgetBytes},
            {"chunks_loaded", gCodegenUsage.chunksLoaded},
            {"chunks_native_attempted", gCodegenUsage.chunksNativeAttempted},
            {"chunks_native_succeeded", gCodegenUsage.chunksNativeSucceeded},
            {"chunks_native_partial", gCodegenUsage.chunksNativePartial},
            {"chunks_native_retried", gCodegenUsage.chunksNativeRetried},
            {"bytecode_bytes", gCodegenUsage.bytecodeBytes},
            {"native_code_bytes", gCodegenUsage.nativeCodeBytes},
            {"native_data_bytes", gCodegenUsage.nativeDataBytes},
            {"native_metadata_bytes", gCodegenUsage.nativeMetadataBytes},
            {"functions_total", gCodegenUsage.functionsTotal},
            {"functions_compiled", gCodegenUsage.functionsCompiled},
            {"functions_bound", gCodegenUsage.functionsBound},
        }},
        {"security", {
            {"identity", gConfig.profile == "roblox-client" ? "LocalScript" : "ExecutorSandbox"},
            {"allow_private_network", gConfig.allowPrivateNetwork},
            {"roblox_environment_guard", gRobloxEnvironmentIntegrity},
        }},
        {"identity", {
            {"place_id", gConfig.placeId},
            {"game_id", gConfig.gameId},
            {"job_id", gConfig.jobId},
            {"user_id", gConfig.userId},
            {"player_name", gConfig.playerName},
        }},
    };
    std::string encoded = report.dump(2, ' ', false, json::error_handler_t::replace);
    if (gConfig.reportPath == "-")
        std::cout << encoded << "\n";
    else
    {
        if (!gConfig.reportPath.parent_path().empty())
            fs::create_directories(gConfig.reportPath.parent_path());
        writeFile(gConfig.reportPath, encoded + "\n");
    }
}

} // namespace

int main(int argc, char** argv)
{
    try
    {
        fs::path scriptPath;
        bool placeIdExplicit = false;
        bool gameIdExplicit = false;
        bool jobIdExplicit = false;
        bool userIdExplicit = false;
        bool playerNameExplicit = false;
        bool clockExplicit = false;
        bool frameRateExplicit = false;
        bool maxVirtualExplicit = false;
        bool analysisHooksExplicit = false;
        bool captureStringHooksExplicit = false;
        bool tracePcallErrorsExplicit = false;
        bool normalizePcallErrorsExplicit = false;
        bool luraphSaveExplicit = false;
        bool luraphStallExplicit = false;
        for (int i = 1; i < argc; ++i)
        {
            std::string arg = argv[i];
            if (arg == "--out" && i + 1 < argc)
                gConfig.outputDir = argv[++i];
            else if (arg == "--capture-min" && i + 1 < argc)
                gConfig.captureMinBytes = static_cast<size_t>(std::stoull(argv[++i]));
            else if (arg == "--capture-string-hooks")
            {
                gConfig.captureStringHooks = true;
                captureStringHooksExplicit = true;
            }
            else if (arg == "--no-capture-string-hooks")
            {
                gConfig.captureStringHooks = false;
                captureStringHooksExplicit = true;
            }
            else if (arg == "--profile" && i + 1 < argc)
            {
                gConfig.profile = argv[++i];
                if (gConfig.profile != "roblox-client" && gConfig.profile != "executor-client")
                    throw std::runtime_error("invalid profile: " + gConfig.profile);
            }
            else if (arg == "--execution-mode" && i + 1 < argc)
                gConfig.executionMode = parseExecutionMode(argv[++i]);
            else if (arg == "--executor-preset" && i + 1 < argc)
                gConfig.executorPreset = parseExecutorPreset(argv[++i]);
            else if (arg == "--filesystem" && i + 1 < argc)
                gConfig.filesystemPolicy = parseFilesystemPolicy(argv[++i]);
            else if (arg == "--memory-limit-mb" && i + 1 < argc)
                gConfig.memoryLimitBytes = parseMemoryLimitBytes(argv[++i]);
            else if (arg == "--deterministic-seed" && i + 1 < argc)
            {
                gConfig.deterministicSeed = std::stoull(argv[++i], nullptr, 0);
                gConfig.deterministicSeedExplicit = true;
            }
            else if (arg == "--clock" && i + 1 < argc)
            {
                gConfig.clockMode = parseClockMode(argv[++i]);
                clockExplicit = true;
            }
            else if (arg == "--frame-rate" && i + 1 < argc)
            {
                gConfig.frameRate = std::stod(argv[++i]);
                frameRateExplicit = true;
            }
            else if (arg == "--max-virtual-seconds" && i + 1 < argc)
            {
                gConfig.maxVirtualSeconds = std::stod(argv[++i]);
                maxVirtualExplicit = true;
            }
            else if (arg == "--scenario" && i + 1 < argc)
                gConfig.scenarioPath = argv[++i];
            else if (arg == "--unsupported" && i + 1 < argc)
                gConfig.unsupportedPolicy = parseUnsupportedPolicy(argv[++i]);
            else if (arg == "--register-overflow" && i + 1 < argc)
                gConfig.registerOverflow = parseRegisterOverflowMode(argv[++i]);
            else if (arg == "--report" && i + 1 < argc)
                gConfig.reportPath = argv[++i];
            else if (arg == "--analysis-hooks" && i + 1 < argc)
            {
                gConfig.analysisHooks = parseAnalysisHooksMode(argv[++i]);
                analysisHooksExplicit = true;
            }
            else if (arg == "--owner-protection" && i + 1 < argc)
                gConfig.ownerProtection = parseOwnerProtectionMode(argv[++i]);
            else if (arg == "--owner-public-key" && i + 1 < argc)
                gConfig.ownerPublicKeyPaths.push_back(argv[++i]);
            else if (arg == "--minimal-env")
                gConfig.minimalEnv = true;
            else if (arg == "--network-policy" && i + 1 < argc)
                gConfig.networkPolicy = parseNetworkPolicy(argv[++i]);
            else if (arg == "--allow-host" && i + 1 < argc)
                gConfig.allowHosts.insert(lowerAscii(argv[++i]));
            else if (arg == "--allow-private-network")
                gConfig.allowPrivateNetwork = true;
            else if (arg == "--fixture" && i + 1 < argc)
            {
                std::string mapping = argv[++i];
                size_t eq = mapping.find('=');
                if (eq == std::string::npos)
                    throw std::runtime_error("--fixture must be URL=PATH");
                gConfig.fixtures[mapping.substr(0, eq)] = mapping.substr(eq + 1);
            }
            else if (arg == "--trace-compat" && i + 1 < argc)
                gConfig.traceCompatPath = argv[++i];
            else if (arg == "--trace-calls")
                gConfig.traceCalls = true;
            else if (arg == "--trace-environment" && i + 1 < argc)
                gConfig.traceEnvironmentPath = argv[++i];
            else if (arg == "--probe-trace" && i + 1 < argc)
                gConfig.probeTracePath = argv[++i];
            else if (arg == "--probe-trace-limit-bytes")
            {
                if (i + 1 >= argc)
                    throw std::runtime_error("--probe-trace-limit-bytes requires a value");
                gConfig.probeTraceLimitBytes = parseProbeTraceLimitBytes(argv[++i]);
            }
            else if (arg == "--trace-environment-after-clock-calls" && i + 1 < argc)
                gConfig.traceEnvironmentAfterClockCalls = std::stoull(argv[++i]);
            else if (arg == "--trace-environment-max-events" && i + 1 < argc)
                gConfig.traceEnvironmentMaxEvents = std::stoull(argv[++i]);
            else if (arg == "--luraph-mode" && i + 1 < argc)
                gConfig.luraphMode = parseLuraphMode(argv[++i]);
            else if (arg == "--luraph-stop-after-exact-source")
            {
                gConfig.luraphStopAfterExactSource = true;
            }
            else if (arg == "--no-luraph-stop-after-exact-source")
            {
                gConfig.luraphStopAfterExactSource = false;
            }
            else if (arg == "--luraph-save-intermediates")
            {
                gConfig.luraphSaveIntermediates = true;
                luraphSaveExplicit = true;
            }
            else if (arg == "--no-luraph-save-intermediates")
            {
                gConfig.luraphSaveIntermediates = false;
                luraphSaveExplicit = true;
            }
            else if (arg == "--luraph-generated-interpreter-probe" && i + 1 < argc)
                gConfig.luraphGeneratedInterpreterProbePath = argv[++i];
            else if (arg == "--luraph-max-steps" && i + 1 < argc)
                gConfig.luraphMaxSteps = std::stoull(argv[++i]);
            else if (arg == "--luraph-stall-steps" && i + 1 < argc)
            {
                gConfig.luraphStallSteps = std::stoull(argv[++i]);
                luraphStallExplicit = true;
            }
            else if (arg == "--progress-interval" && i + 1 < argc)
                gConfig.progressIntervalSeconds = std::stod(argv[++i]);
            else if (arg == "--sift-decompile" || arg == "--decompile")
                gConfig.siftDecompile = true;
            else if (arg == "--sift-disassemble" || arg == "--disassemble" || arg == "--sift-disamble" || arg == "--disamble")
                gConfig.siftDisassemble = true;
            else if (arg == "--sift-api-key" && i + 1 < argc)
                gConfig.siftApiKey = argv[++i];
            else if (arg == "--sift-api-key-env" && i + 1 < argc)
                gConfig.siftApiKeyEnv = argv[++i];
            else if (arg == "--sift-base-url" && i + 1 < argc)
                gConfig.siftBaseUrl = argv[++i];
            else if (arg == "--chunk-name" && i + 1 < argc)
                gConfig.chunkName = argv[++i];
            else if (arg == "--luau-opt-level" && i + 1 < argc)
                gConfig.luauOptimizationLevel = std::stoi(argv[++i]);
            else if (arg == "--luau-debug-level" && i + 1 < argc)
                gConfig.luauDebugLevel = std::stoi(argv[++i]);
            else if (arg == "--timeout" && i + 1 < argc)
                gConfig.timeoutSeconds = std::stod(argv[++i]);
            else if (arg == "--place-id" && i + 1 < argc)
            {
                gConfig.placeId = std::stoll(argv[++i]);
                placeIdExplicit = true;
            }
            else if (arg == "--game-id" && i + 1 < argc)
            {
                gConfig.gameId = std::stoll(argv[++i]);
                gameIdExplicit = true;
            }
            else if (arg == "--job-id" && i + 1 < argc)
            {
                gConfig.jobId = argv[++i];
                jobIdExplicit = true;
            }
            else if (arg == "--user-id" && i + 1 < argc)
            {
                gConfig.userId = std::stoll(argv[++i]);
                userIdExplicit = true;
            }
            else if (arg == "--player-name" && i + 1 < argc)
            {
                gConfig.playerName = argv[++i];
                playerNameExplicit = true;
            }
            else if (arg == "--stop-after-capture")
                gConfig.stopAfterCapture = true;
            else if (arg == "--trace-pcall-errors")
            {
                gConfig.tracePcallErrors = true;
                tracePcallErrorsExplicit = true;
            }
            else if (arg == "--normalize-pcall-errors")
            {
                gConfig.normalizePcallErrors = true;
                normalizePcallErrorsExplicit = true;
            }
            else if (arg == "--no-normalize-pcall-errors")
            {
                gConfig.normalizePcallErrors = false;
                normalizePcallErrorsExplicit = true;
            }
            else if (arg == "--native-codegen")
                gConfig.nativeCodegen = true;
            else if (arg == "--no-native-codegen")
                gConfig.nativeCodegen = false;
            else if (arg == "--native-codegen-block-mb" && i + 1 < argc)
                gConfig.nativeCodegenBlockSize = static_cast<size_t>(std::stoull(argv[++i])) * 1024 * 1024;
            else if (arg == "--native-codegen-max-mb" && i + 1 < argc)
                gConfig.nativeCodegenMaxTotalSize = static_cast<size_t>(std::stoull(argv[++i])) * 1024 * 1024;
            else if (arg == "--pass-source-as-arg")
                gConfig.passSourceAsArg = true;
            else if (arg == "--autorun-loadstring")
                gConfig.autorunLoadstring = true;
            else if (arg == "--no-autorun-loadstring")
                gConfig.autorunLoadstring = false;
            else if (arg == "-h" || arg == "--help")
            {
                printUsage(argv[0]);
                return 0;
            }
            else if (scriptPath.empty())
                scriptPath = arg;
            else
                std::cerr << "[runtime] ignoring extra argument: " << arg << "\n";
        }

        if (scriptPath.empty())
        {
            printUsage(argv[0]);
            return 2;
        }

        if (gConfig.executionMode == rbx::runtime::ExecutionMode::Faithful)
        {
            gConfig.analysisHooks = AnalysisHooksMode::Off;
            gConfig.captureStringHooks = false;
            if (!tracePcallErrorsExplicit) gConfig.tracePcallErrors = false;
            gConfig.normalizePcallErrors = false;
            gConfig.luraphStopAfterExactSource = false;
            if (!luraphSaveExplicit) gConfig.luraphSaveIntermediates = false;
            if (!luraphStallExplicit) gConfig.luraphStallSteps = 0;
        }
        else
        {
            if (!analysisHooksExplicit) gConfig.analysisHooks = AnalysisHooksMode::On;
            if (!captureStringHooksExplicit) gConfig.captureStringHooks = true;
            if (!normalizePcallErrorsExplicit) gConfig.normalizePcallErrors = true;
            if (!luraphSaveExplicit) gConfig.luraphSaveIntermediates = true;
        }

        if (gConfig.frameRate <= 0 || !std::isfinite(gConfig.frameRate))
            throw std::runtime_error("--frame-rate must be a positive finite number");
        if (gConfig.maxVirtualSeconds < 0 || !std::isfinite(gConfig.maxVirtualSeconds))
            throw std::runtime_error("--max-virtual-seconds must be a non-negative finite number");
        if (gConfig.traceEnvironmentMaxEvents == 0)
            throw std::runtime_error("--trace-environment-max-events must be non-zero");
        if (!gConfig.traceEnvironmentPath.empty())
            gConfig.nativeCodegen = false;
        if (gConfig.nativeCodegen && (gConfig.nativeCodegenBlockSize == 0 || gConfig.nativeCodegenMaxTotalSize == 0))
            throw std::runtime_error("native CodeGen block and maximum sizes must be non-zero");

        if (!gConfig.scenarioPath.empty())
        {
            gScenario = json::parse(readFile(gConfig.scenarioPath));
            int scenarioVersion = gScenario.value("version", 0);
            if (!gScenario.is_object() || (scenarioVersion != 1 && scenarioVersion != rbx::runtime::kScenarioSchemaVersion))
                throw std::runtime_error("scenario must be an object with version 1 or 2");
            json identity = gScenario.value("identity", json::object());
            json clock = gScenario.value("clock", json::object());
            if (!placeIdExplicit && identity.contains("place_id")) gConfig.placeId = identity["place_id"].get<int64_t>();
            if (!gameIdExplicit && identity.contains("game_id")) gConfig.gameId = identity["game_id"].get<int64_t>();
            if (!jobIdExplicit && identity.contains("job_id")) gConfig.jobId = identity["job_id"].get<std::string>();
            if (!userIdExplicit && identity.contains("user_id")) gConfig.userId = identity["user_id"].get<int64_t>();
            if (!playerNameExplicit && identity.contains("player_name")) gConfig.playerName = identity["player_name"].get<std::string>();
            if (!clockExplicit && clock.contains("mode")) gConfig.clockMode = parseClockMode(clock["mode"].get<std::string>());
            if (!frameRateExplicit && clock.contains("frame_rate")) gConfig.frameRate = clock["frame_rate"].get<double>();
            if (!maxVirtualExplicit && clock.contains("max_seconds")) gConfig.maxVirtualSeconds = clock["max_seconds"].get<double>();
            if (clock.contains("epoch_unix_millis"))
                gConfig.virtualEpochSeconds = clock["epoch_unix_millis"].get<double>() / 1000.0;
            else if (clock.contains("epoch_unix_seconds"))
                gConfig.virtualEpochSeconds = clock["epoch_unix_seconds"].get<double>();
        }
        else
            gScenario = json{{"version", rbx::runtime::kScenarioSchemaVersion}};

        fs::create_directories(gConfig.outputDir);
        std::string source = readFile(scriptPath);
        gInputBytes = source.size();
        gInputSha256 = sha256Hex(source);
        // Studio's RunScript host exposes a native loadstring even though a
        // normal Roblox client script does not. Luraph v14.x fingerprints
        // that CLI-host boundary and deliberately enters a decoy VM loop when
        // the function is absent. Preserve it only for an explicitly forced
        // or structurally detected Luraph workload in faithful mode.
        const bool luraphNativeLoadstringCompatibility =
            gConfig.profile == "roblox-client" &&
            gConfig.executionMode == rbx::runtime::ExecutionMode::Faithful &&
            gConfig.luraphMode != LuraphMode::Off &&
            (gConfig.luraphMode == LuraphMode::Force || looksLikeLuraphWorkload(source));
        gConfig.studioRunScriptCompatibility = luraphNativeLoadstringCompatibility;
        if (!gConfig.deterministicSeedExplicit)
        {
            if (gConfig.clockMode == ClockMode::Virtual)
                gConfig.deterministicSeed = seedFromSha256(gInputSha256);
            else
            {
                std::random_device source;
                gConfig.deterministicSeed = (static_cast<uint64_t>(source()) << 32) ^ source();
            }
        }
        loadOwnerPublicKeys();
        int ownerDecision = handleOwnerProtection(source);
        if (ownerDecision >= 0)
            return ownerDecision;

        curl_global_init(CURL_GLOBAL_DEFAULT);

        gVmMemoryBudget = {};
        gVmMemoryBudget.limit = gConfig.memoryLimitBytes;
        lua_State* L = lua_newstate(vmMemoryAllocate, &gVmMemoryBudget);
        if (!L)
            throw std::runtime_error(gVmMemoryBudget.limitHit ? "VM memory limit exceeded while creating state" : "lua_newstate failed");

        std::unique_ptr<rbx::runtime::RuntimeContext> runtimeContext;
        std::shared_ptr<rbx::runtime::LuauRuntimeBridge> nativeBridge;
        try
        {
            rbx::runtime::RuntimeContextOptions contextOptions;
            contextOptions.profile = gConfig.profile == "roblox-client" ? rbx::runtime::RuntimeProfile::RobloxClient : rbx::runtime::RuntimeProfile::ExecutorClient;
            contextOptions.executionMode = gConfig.executionMode;
            contextOptions.executorPreset = gConfig.executorPreset;
            contextOptions.filesystem = effectiveFilesystemPolicy();
            contextOptions.clockMode = gConfig.clockMode == ClockMode::Virtual ? rbx::runtime::ClockMode::Virtual : rbx::runtime::ClockMode::Realtime;
            contextOptions.virtualEpochMillis = static_cast<int64_t>(std::llround(gConfig.virtualEpochSeconds * 1000.0));
            contextOptions.deterministicSeed = gConfig.deterministicSeed;
            contextOptions.memoryLimitBytes = gConfig.memoryLimitBytes;
            contextOptions.scheduler.frameDurationSeconds = 1.0 / gConfig.frameRate;
            runtimeContext = std::make_unique<rbx::runtime::RuntimeContext>(L, contextOptions);
            runtimeContext->attach();
            preloadMemoryFilesystem(*runtimeContext);
            rbx::runtime::NetworkPolicyConfig networkPolicy = nativeNetworkPolicy();
            rbx::runtime::CurlHttpTransportOptions transportOptions;
            transportOptions.limits = networkPolicy.limits;
            transportOptions.connectTimeout = std::chrono::seconds(10);
            // Release-729's script-visible HTTP persona uses this exact default
            // in both profiles. Executor presets may add opt-in headers, and an
            // explicit User-Agent request header still overrides it.
            transportOptions.userAgent = "Roblox/WinInet";
            runtimeContext->installNetwork(networkPolicy, rbx::runtime::makeCurlHttpTransport(std::move(transportOptions)));
        }
        catch (...)
        {
            if (runtimeContext)
            {
                if (runtimeContext->attached())
                    runtimeContext->detach();
            }
            lua_close(L);
            runtimeContext.reset();
            throw;
        }
        auto closeRuntime = [&] {
            lua_callbacks(L)->traceaccess = nullptr;
            lua_callbacks(L)->tracenativecall = nullptr;
            lua_callbacks(L)->tracesharedglobal = nullptr;
            writeNativeEnvironmentTrace();
            if (gProbeTraceStream.is_open())
            {
                gProbeTraceStream.flush();
                gProbeTraceStream.close();
            }
            if (nativeBridge)
            {
                nativeBridge->shutdown();
                nativeBridge.reset();
            }
            if (runtimeContext)
            {
                if (runtimeContext->attached())
                    runtimeContext->detach();
            }
            // Lua userdata can own NativeSignal instances whose destructor
            // performs scheduler-side waiter/connection cleanup. Keep the
            // RuntimeContext (and therefore its Scheduler) alive until every
            // userdata finalizer has run during lua_close.
            lua_close(L);
            runtimeContext.reset();
        };
        gInterruptCounter = 0;
        gLastLuraphProgressStep = 0;
        gSchedulerTaskIdBaseline = 0;
        gTimeoutTraceCaptured = false;
        gInstructionBudgetReached = false;
        gWallTimeoutReached = false;
        gLuraphStallReached = false;
        gHostInterruptMessage.clear();
        gExecutionStart = std::chrono::steady_clock::now();
        gLastProgressPrint = {};
        gLargeStringFingerprints.clear();
        gSiftBytecodeFingerprints.clear();
        gCompatReportEvents.clear();
        gNetworkRequirements.clear();
        gCapturedStdout.clear();
        gCapturedStderr.clear();
        gOutputCapturedBytes = 0;
        gOutputLimitHit = false;
        if (gProbeTraceStream.is_open())
            gProbeTraceStream.close();
        gProbeTraceBytes = 0;
        gProbeTraceLimitHit = false;
        if (!gConfig.probeTracePath.empty())
        {
            if (!gConfig.probeTracePath.parent_path().empty())
                fs::create_directories(gConfig.probeTracePath.parent_path());
            gProbeTraceStream.open(gConfig.probeTracePath, std::ios::binary | std::ios::trunc);
            if (!gProbeTraceStream)
                throw std::runtime_error("could not open Luraph probe trace output");
        }
        gProtectedErrorCount = 0;
        gClosureClassificationTraceCount = 0;
        gMainReportReturns = json::array();
        gMainTypedReturns = json::array();
        gBlockedReason = nullptr;
        gSteadyStateReasonOverride.clear();
        gCodegenUsage = {};
        gRegisterOverflowUsage = {};
        gCodegenBudgetBytes = 0;
        if (gConfig.timeoutSeconds > 0 || gConfig.luraphStopAfterExactSource || gConfig.luraphMaxSteps > 0 || gConfig.luraphStallSteps > 0 ||
            gConfig.progressIntervalSeconds > 0)
        {
            lua_callbacks(L)->interrupt = interruptForTimeout;
            if (gConfig.timeoutSeconds > 0)
                gExecutionDeadline = std::chrono::steady_clock::now() + std::chrono::duration_cast<std::chrono::steady_clock::duration>(std::chrono::duration<double>(gConfig.timeoutSeconds));
            else
                gExecutionDeadline = {};
        }
        else
            gExecutionDeadline = {};

        try
        {
            if (gConfig.nativeCodegen)
            {
                if (Luau::CodeGen::isSupported())
                {
                    // Native code pages live outside Luau's allocator, so reserve
                    // at most half of the process budget for CodeGen and leave the
                    // other half available to the VM heap and host-side reports.
                    const size_t memoryShare = std::max<size_t>(4096, gConfig.memoryLimitBytes / 2);
                    size_t maxTotalSize = std::min(gConfig.nativeCodegenMaxTotalSize, memoryShare);
                    size_t blockSize = std::min(std::max<size_t>(4096, gConfig.nativeCodegenBlockSize), maxTotalSize);
                    gCodegenBudgetBytes = maxTotalSize;
                    Luau::CodeGen::create(L, blockSize, maxTotalSize, nullptr, nullptr);
                }
                else
                    traceCompat("native_codegen_unavailable", "platform");
            }

            luaL_openlibs(L);
            rbx::runtime::installRobloxDebug(L);
            rbx::runtime::installRobloxUtf8(L);
            registerMathTypes(L);
            registerGlobals(L);
            registerExecutorFilesystem(L);
            rbx::runtime::LuauRuntimeBridgeOptions bridgeOptions;
            bridgeOptions.installTaskLibrary = true;
            bridgeOptions.httpResponseObserver = [](const rbx::runtime::NetworkRequest& request, const rbx::runtime::NetworkResponse& response) {
                if (response.body.size() < gConfig.captureMinBytes)
                    return;
                const bool get = request.method == "GET";
                captureText(get ? "httpget" : "httppost", response.body, get ? ".lua" : ".txt",
                    {{"url", request.url}, {"method", request.method}, {"status", response.statusCode}});
                if (get)
                    captureMirror("captured_httpget.lua", response.body);
            };
            if (!gConfig.minimalEnv)
            {
                rbx::v2::initialize(L, apiDumpSummaryJson(), {strictUnsupported(), gConfig.profile == "executor-client"});
                nativeBridge = rbx::runtime::LuauRuntimeBridge::create(*runtimeContext, bridgeOptions);
                runSource(L, rbx::v2::shimSource(), "=roblox_runtime_v2_setup", "roblox_runtime_v2_setup");
                rbx::runtime::installRelease729Datatypes(L);
                rbx::v2::seal(L);
            }
            else
                nativeBridge = rbx::runtime::LuauRuntimeBridge::create(*runtimeContext, bridgeOptions);
            installLegacyTaskAliases(L);

            if (!gConfig.minimalEnv)
            {
                // Luau's built-in type already reports native Instances as
                // userdata. Replacing it changes the observable identity of a
                // core primitive and triggers protected-loader integrity
                // guards; Roblox-specific names belong in typeof instead.
                lua_pushcfunction(L, l_typeof, "typeof");
                lua_setglobal(L, "typeof");
                if (gConfig.profile == "roblox-client" && !luraphNativeLoadstringCompatibility)
                {
                    lua_pushnil(L);
                    lua_setglobal(L, "loadstring");
                }
                runSource(L, kScrubAnalysisGlobals, "=roblox_host_scrub", "roblox_host_scrub");
                luaL_sandbox(L);
                luaL_sandboxthread(L);
                installExecutorMutableNamespaceCopies(L);
                populateScriptEnvironment(L, luraphNativeLoadstringCompatibility);
                verifyRobloxEnvironment(L);
            }
            else if (!analysisHooksEnabled())
                runSource(L, kScrubAnalysisGlobals, "=roblox_analysis_scrub", "roblox_analysis_scrub");

            // Setup and sandbox installation execute Luau too.  Workload
            // safepoints and stall progress begin at the main-script boundary,
            // so release-pinned budgets are independent of host bootstrap cost.
            gInterruptCounter = 0;
            gLastLuraphProgressStep = 0;
            for (const rbx::runtime::TaskSnapshot& task : runtimeContext->scheduler().tasks())
                gSchedulerTaskIdBaseline = std::max<uint64_t>(gSchedulerTaskIdBaseline, task.id);
            initializeLuraphRecovery(source, scriptPath);
            if (gLuraph.active && luraphNativeLoadstringCompatibility)
            {
                gLuraph.observations.push_back({
                    {"kind", "runtime_compatibility"},
                    {"feature", "studio_runscript_native_loadstring"},
                    {"scope", "detected_luraph_faithful_only"},
                    {"security", "inherits_runtime_network_filesystem_and_execution_limits"},
                });
                gLuraph.observations.push_back({
                    {"kind", "runtime_compatibility"},
                    {"feature", "studio_runscript_chunk_identity"},
                    {"value", "RunScript"},
                    {"scope", "default_chunk_name_only"},
                });
                gLuraph.observations.push_back({
                    {"kind", "runtime_compatibility"},
                    {"feature", "studio_runscript_environment_topology"},
                    {"own_keys", {"shared", "_G"}},
                    {"api_lookup", "sandbox_metatable"},
                    {"metatable_visibility", "The metatable is locked"},
                });
                writeLuraphReport();
            }
            if (!gConfig.traceEnvironmentPath.empty())
                initializeNativeEnvironmentTrace(L);
            lua_callbacks(L)->debugprotectederror = gConfig.tracePcallErrors ? captureProtectedErrorNative : nullptr;
            std::string mainChunkName;
            if (gConfig.chunkName.empty())
                mainChunkName = luraphNativeLoadstringCompatibility ? "=RunScript" : "=" + scriptPath.string();
            else
                mainChunkName = gConfig.chunkName[0] == '=' ? gConfig.chunkName : "=" + gConfig.chunkName;
            if (!loadChunk(L, source, mainChunkName))
            {
                std::string message = stackString(L, -1);
                reportLuaError(L, "main_compile_error");
                finalizeLuraphRecovery("error", "main script failed to compile");
                writeRuntimeReport("compile_error", message, L);
                if (!gConfig.minimalEnv)
                    rbx::v2::shutdown(L);
                closeRuntime();
                curl_global_cleanup();
                return 1;
            }

            const int closureIndex = lua_absindex(L, -1);
            const int executionBase = closureIndex - 1;
            int firstArgument = 0;
            int argumentCount = 0;
            if (gConfig.passSourceAsArg)
            {
                lua_pushlstring(L, source.data(), source.size());
                firstArgument = lua_absindex(L, -1);
                argumentCount = 1;
            }

            rbx::runtime::LuauMainRunOptions runOptions;
            runOptions.maxResumes = 1000000;
            runOptions.maxVirtualSeconds = gConfig.maxVirtualSeconds;
            runOptions.maxWallSeconds = gConfig.timeoutSeconds;
            runOptions.advanceVirtualTimers = true;
            rbx::runtime::LuauMainResult mainResult =
                nativeBridge->runMain(L, closureIndex, firstArgument, argumentCount, runOptions);
            lua_settop(L, executionBase);

            if (gLuraph.active && gLuraph.exactRecovered && gConfig.luraphStopAfterExactSource)
            {
                nativeBridge->releaseMainResults(mainResult);
                finalizeLuraphRecovery("stopped_after_exact_source", "stopped after exact source recovery");
                writeRuntimeReport("stopped_after_exact_source", "", L);
                if (!gConfig.minimalEnv)
                    rbx::v2::shutdown(L);
                closeRuntime();
                curl_global_cleanup();
                return 0;
            }
            if (gInstructionBudgetReached || gWallTimeoutReached || gLuraphStallReached)
            {
                nativeBridge->releaseMainResults(mainResult);
                const std::string message = !gHostInterruptMessage.empty() ? gHostInterruptMessage : "host execution limit reached";
                if (gInstructionBudgetReached)
                {
                    finalizeLuraphRecovery("instruction_budget", message);
                    writeRuntimeReport("instruction_budget", message, L);
                }
                else
                {
                    finalizeLuraphRecovery(gLuraphStallReached ? "stalled" : "timed_out", message);
                    writeRuntimeReport("runtime_error", message, L);
                }
                if (!gConfig.minimalEnv)
                    rbx::v2::shutdown(L);
                closeRuntime();
                curl_global_cleanup();
                return 1;
            }
            if (mainResult.mainCompleted)
            {
                const int firstReturn = executionBase + 1;
                const int returns = nativeBridge->pushMainResults(L, mainResult);
                nativeBridge->releaseMainResults(mainResult);
                captureReturnValues(L, firstReturn, returns, "main_return");
                for (int i = 0; i < returns; ++i)
                {
                    gMainReportReturns.push_back(luaValueToJson(L, firstReturn + i, 0));
                    gMainTypedReturns.push_back(typedLuaValueToJson(L, firstReturn + i, static_cast<size_t>(i + 1)));
                }
            }
            else
                nativeBridge->releaseMainResults(mainResult);

            if (mainResult.state == rbx::runtime::LuauMainState::Failed)
            {
                std::string message = mainResult.error.empty() ? "main task failed without an error" : mainResult.error;
                if (gConfig.profile == "executor-client" && containsText(message, "attempt to modify a readonly table"))
                {
                    const std::string scenarioFingerprint = gConfig.scenarioPath.empty() ? "none" : sha256Hex(gScenario.dump());
                    std::ostringstream context;
                    context << "[executor_readonly_context] source_sha256=" << sha256Hex(source)
                            << " source_bytes=" << source.size()
                            << " scenario_sha256=" << scenarioFingerprint
                            << " seed=" << gConfig.deterministicSeed
                            << " mode=" << rbx::runtime::name(gConfig.executionMode)
                            << " codegen=" << (gConfig.nativeCodegen ? "on" : "off")
                            << " writable=script-env,getrenv,stdlib,syn,http"
                            << " locked=roblox-api";
                    const std::size_t firstNewline = message.find('\n');
                    if (firstNewline == std::string::npos)
                        message += "\n" + context.str();
                    else
                        message.insert(firstNewline + 1, context.str() + "\n");
                }
                recordNativeNetworkRequirement(message);
                if (gLuraph.active && gLuraph.exactRecovered && gConfig.luraphStopAfterExactSource)
                {
                    finalizeLuraphRecovery("stopped_after_exact_source", "stopped after exact source recovery");
                    writeRuntimeReport("stopped_after_exact_source", "", L);
                    if (!gConfig.minimalEnv)
                        rbx::v2::shutdown(L);
                    closeRuntime();
                    curl_global_cleanup();
                    return 0;
                }
                captureText("main_runtime_error", message, ".txt");
                std::cerr << "[main_runtime_error] " << message << "\n";
                if (containsText(message, "Luraph VM stalled"))
                    finalizeLuraphRecovery("stalled", message);
                else if (containsText(message, "execution timed out") || containsText(message, "max steps exceeded"))
                    finalizeLuraphRecovery("timed_out", "VM stopped before exact source was recovered");
                else
                    finalizeLuraphRecovery("error", "main script errored before exact source was recovered");
                writeRuntimeReport("runtime_error", message, L);
                if (!gConfig.minimalEnv)
                    rbx::v2::shutdown(L);
                closeRuntime();
                curl_global_cleanup();
                return 1;
            }

            if (mainResult.state == rbx::runtime::LuauMainState::Blocked)
            {
                if (const std::optional<rbx::runtime::TaskSnapshot> task = runtimeContext->scheduler().task(mainResult.task))
                {
                    gBlockedReason = {
                        {"kind", task->status == rbx::runtime::TaskStatus::WaitingModule ? "module_dependency"
                                : task->status == rbx::runtime::TaskStatus::WaitingExternal ? "external_completion"
                                : "caller_controlled_yield"},
                        {"task", task->id},
                        {"state", rbx::runtime::toString(task->status)},
                        {"wait_key", task->waitKey.empty() ? json(nullptr) : json(task->waitKey)},
                    };
                }
                finalizeLuraphRecovery("blocked", "main task is waiting for an external or caller-controlled completion");
                writeRuntimeReport("blocked", "", L);
                if (!gConfig.minimalEnv)
                    rbx::v2::shutdown(L);
                closeRuntime();
                curl_global_cleanup();
                return 0;
            }

            if (mainResult.state == rbx::runtime::LuauMainState::SteadyState)
            {
                finalizeLuraphRecovery("steady_state", "native scheduler reached a healthy steady state");
                const std::optional<double> nextTimer = runtimeContext->scheduler().nextTimerDue();
                const bool virtualTimerBudget = gConfig.clockMode == ClockMode::Virtual && nextTimer && !mainResult.mainCompleted &&
                    mainResult.elapsedVirtualSeconds + 1e-9 >= gConfig.maxVirtualSeconds;
                if (virtualTimerBudget)
                {
                    gSteadyStateReasonOverride = "virtual_time_budget";
                    writeRuntimeReport("virtual_budget", "", L);
                }
                else
                {
                    gSteadyStateReasonOverride = "native_scheduler_steady_state";
                    if (const std::optional<rbx::runtime::TaskSnapshot> task = runtimeContext->scheduler().task(mainResult.task))
                    {
                        if (task->status == rbx::runtime::TaskStatus::WaitingSignal)
                            gSteadyStateReasonOverride = "waiting_signal:" + task->waitKey;
                        else if (task->status == rbx::runtime::TaskStatus::WaitingModule)
                            gSteadyStateReasonOverride = "waiting_module:" + task->waitKey;
                        else if (mainResult.resumes >= runOptions.maxResumes)
                            gSteadyStateReasonOverride = "scheduler_resume_budget";
                    }
                    if (mainResult.mainCompleted)
                    {
                        for (const rbx::runtime::TaskSnapshot& task : runtimeContext->scheduler().tasks())
                        {
                            if (task.status == rbx::runtime::TaskStatus::WaitingSignal)
                            {
                                gSteadyStateReasonOverride = "background_waiting_signal:" + task.waitKey;
                                break;
                            }
                            if (task.status == rbx::runtime::TaskStatus::WaitingExternal)
                            {
                                gSteadyStateReasonOverride = "background_waiting_external:" + task.waitKey;
                                break;
                            }
                        }
                    }
                    writeRuntimeReport("steady_state", "", L);
                }
                if (!gConfig.minimalEnv)
                    rbx::v2::shutdown(L);
                closeRuntime();
                curl_global_cleanup();
                return 0;
            }

            finalizeLuraphRecovery("completed", "");
            writeRuntimeReport("completed", "", L);
            if (!gConfig.minimalEnv)
                rbx::v2::shutdown(L);
            closeRuntime();
        }
        catch (...)
        {
            if (!gConfig.minimalEnv)
                rbx::v2::shutdown(L);
            closeRuntime();
            throw;
        }

        curl_global_cleanup();
        return 0;
    }
    catch (const std::exception& e)
    {
        std::cerr << "[runtime] " << e.what() << "\n";
        writeRuntimeReport("error", e.what());
        curl_global_cleanup();
        return 1;
    }
}
