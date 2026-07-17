#include "roblox_utf8.hpp"

#include "lua.h"
#include "lualib.h"

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <limits>
#include <string>
#include <string_view>
#include <vector>

#if defined(RBX_UTF8_USE_COREFOUNDATION)
#include <CoreFoundation/CoreFoundation.h>
#elif defined(RBX_UTF8_USE_ICU)
#include <unicode/ubrk.h>
#include <unicode/unorm2.h>
#include <unicode/ustring.h>
#elif defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winnls.h>
#endif

namespace rbx::runtime
{
namespace
{

struct Codepoint
{
    uint32_t value = 0;
    size_t byteBegin = 0;
    size_t byteEnd = 0;
    int32_t utf16Begin = 0;
    int32_t utf16End = 0;
};

struct ByteRange
{
    size_t begin = 0;
    size_t end = 0; // exclusive
};

bool decodeUtf8(std::string_view input, std::vector<Codepoint>& output, size_t& invalidOffset)
{
    output.clear();
    invalidOffset = 0;
    int32_t utf16Offset = 0;
    for (size_t offset = 0; offset < input.size();)
    {
        const size_t begin = offset;
        const uint8_t first = static_cast<uint8_t>(input[offset++]);
        uint32_t value = 0;
        int continuationCount = 0;
        if (first <= 0x7f)
            value = first;
        else if (first >= 0xc2 && first <= 0xdf)
        {
            value = first & 0x1f;
            continuationCount = 1;
        }
        else if (first >= 0xe0 && first <= 0xef)
        {
            value = first & 0x0f;
            continuationCount = 2;
        }
        else if (first >= 0xf0 && first <= 0xf4)
        {
            value = first & 0x07;
            continuationCount = 3;
        }
        else
        {
            invalidOffset = begin;
            return false;
        }

        if (input.size() - offset < static_cast<size_t>(continuationCount))
        {
            invalidOffset = begin;
            return false;
        }
        for (int index = 0; index < continuationCount; ++index)
        {
            const uint8_t next = static_cast<uint8_t>(input[offset++]);
            if ((next & 0xc0) != 0x80)
            {
                invalidOffset = offset - 1;
                return false;
            }
            value = (value << 6) | (next & 0x3f);
        }

        const bool overlong = (continuationCount == 1 && value < 0x80) || (continuationCount == 2 && value < 0x800) ||
            (continuationCount == 3 && value < 0x10000);
        if (overlong || value > 0x10ffff || (value >= 0xd800 && value <= 0xdfff))
        {
            invalidOffset = begin;
            return false;
        }

        Codepoint point;
        point.value = value;
        point.byteBegin = begin;
        point.byteEnd = offset;
        point.utf16Begin = utf16Offset;
        utf16Offset += value > 0xffff ? 2 : 1;
        point.utf16End = utf16Offset;
        output.push_back(point);
    }
    return true;
}

[[noreturn]] void invalidUtf8(lua_State* L, size_t offset)
{
    luaL_error(L, "invalid UTF-8 code at byte %d", static_cast<int>(offset + 1));
    std::abort();
}

size_t byteOffsetForUtf16(const std::vector<Codepoint>& points, int32_t utf16Offset, size_t byteLength)
{
    if (utf16Offset <= 0)
        return 0;
    const auto point = std::lower_bound(points.begin(), points.end(), utf16Offset,
        [](const Codepoint& candidate, int32_t requested) { return candidate.utf16End < requested; });
    if (point != points.end())
    {
        if (point->utf16End == utf16Offset)
            return point->byteEnd;
        if (point->utf16Begin == utf16Offset)
            return point->byteBegin;
    }
    return byteLength;
}

bool isCombiningFallback(uint32_t value)
{
    return (value >= 0x0300 && value <= 0x036f) || (value >= 0x0483 && value <= 0x0489) ||
        (value >= 0x0591 && value <= 0x05bd) || value == 0x05bf || (value >= 0x05c1 && value <= 0x05c2) ||
        (value >= 0x0610 && value <= 0x061a) || (value >= 0x064b && value <= 0x065f) ||
        (value >= 0x1ab0 && value <= 0x1aff) || (value >= 0x1dc0 && value <= 0x1dff) ||
        (value >= 0x20d0 && value <= 0x20ff) || (value >= 0xfe00 && value <= 0xfe0f) ||
        (value >= 0xfe20 && value <= 0xfe2f) || (value >= 0xe0100 && value <= 0xe01ef) ||
        (value >= 0x1f3fb && value <= 0x1f3ff);
}

bool isRegionalIndicator(uint32_t value)
{
    return value >= 0x1f1e6 && value <= 0x1f1ff;
}

std::vector<ByteRange> fallbackGraphemeRanges(const std::vector<Codepoint>& points)
{
    std::vector<ByteRange> result;
    size_t index = 0;
    while (index < points.size())
    {
        const size_t begin = index;
        size_t regionalCount = isRegionalIndicator(points[index].value) ? 1 : 0;
        ++index;
        while (index < points.size())
        {
            const uint32_t previous = points[index - 1].value;
            const uint32_t current = points[index].value;
            bool join = isCombiningFallback(current) || current == 0x200d || previous == 0x200d ||
                (previous == 0x000d && current == 0x000a);
            if (isRegionalIndicator(current) && regionalCount == 1)
            {
                join = true;
                ++regionalCount;
            }
            if (!join)
                break;
            ++index;
        }
        result.push_back({points[begin].byteBegin, points[index - 1].byteEnd});
    }
    return result;
}

#if defined(RBX_UTF8_USE_COREFOUNDATION)

class CFStringOwner
{
public:
    explicit CFStringOwner(CFStringRef value = nullptr)
        : value_(value)
    {
    }
    ~CFStringOwner()
    {
        if (value_)
            CFRelease(value_);
    }
    CFStringOwner(const CFStringOwner&) = delete;
    CFStringOwner& operator=(const CFStringOwner&) = delete;
    CFStringRef get() const { return value_; }

private:
    CFStringRef value_ = nullptr;
};

CFStringOwner makeCFString(std::string_view input)
{
    return CFStringOwner(CFStringCreateWithBytes(kCFAllocatorDefault, reinterpret_cast<const UInt8*>(input.data()),
        static_cast<CFIndex>(input.size()), kCFStringEncodingUTF8, false));
}

std::vector<ByteRange> platformGraphemeRanges(std::string_view input, const std::vector<Codepoint>& points)
{
    CFStringOwner text = makeCFString(input);
    if (!text.get())
        return fallbackGraphemeRanges(points);
    std::vector<ByteRange> result;
    const CFIndex length = CFStringGetLength(text.get());
    for (CFIndex offset = 0; offset < length;)
    {
        const CFRange range = CFStringGetRangeOfComposedCharactersAtIndex(text.get(), offset);
        result.push_back({byteOffsetForUtf16(points, static_cast<int32_t>(range.location), input.size()),
            byteOffsetForUtf16(points, static_cast<int32_t>(range.location + range.length), input.size())});
        offset = range.location + range.length;
    }
    return result;
}

std::string platformNormalize(std::string_view input, bool compose)
{
    CFStringOwner immutable = makeCFString(input);
    if (!immutable.get())
        return {};
    CFStringOwner normalized(CFStringCreateMutableCopy(kCFAllocatorDefault, 0, immutable.get()));
    if (!normalized.get())
        return {};
    CFStringNormalize(const_cast<CFMutableStringRef>(normalized.get()), compose ? kCFStringNormalizationFormC : kCFStringNormalizationFormD);
    const CFIndex length = CFStringGetLength(normalized.get());
    const CFIndex capacity = CFStringGetMaximumSizeForEncoding(length, kCFStringEncodingUTF8);
    if (capacity < 0)
        return {};
    std::string output(static_cast<size_t>(capacity), '\0');
    CFIndex used = 0;
    const CFIndex converted = CFStringGetBytes(normalized.get(), CFRangeMake(0, length), kCFStringEncodingUTF8, 0, false,
        reinterpret_cast<UInt8*>(output.data()), capacity, &used);
    if (converted != length)
        return {};
    output.resize(static_cast<size_t>(used));
    return output;
}

#elif defined(RBX_UTF8_USE_ICU)

bool toUtf16(std::string_view input, std::vector<UChar>& output)
{
    if (input.size() > static_cast<size_t>(std::numeric_limits<int32_t>::max()))
        return false;
    UErrorCode status = U_ZERO_ERROR;
    int32_t length = 0;
    u_strFromUTF8(nullptr, 0, &length, input.data(), static_cast<int32_t>(input.size()), &status);
    if (status != U_BUFFER_OVERFLOW_ERROR && U_FAILURE(status))
        return false;
    status = U_ZERO_ERROR;
    output.resize(static_cast<size_t>(length));
    u_strFromUTF8(output.data(), length, nullptr, input.data(), static_cast<int32_t>(input.size()), &status);
    return U_SUCCESS(status);
}

std::vector<ByteRange> platformGraphemeRanges(std::string_view input, const std::vector<Codepoint>& points)
{
    std::vector<UChar> utf16;
    if (!toUtf16(input, utf16))
        return fallbackGraphemeRanges(points);
    UErrorCode status = U_ZERO_ERROR;
    UBreakIterator* iterator = ubrk_open(UBRK_CHARACTER, nullptr, utf16.data(), static_cast<int32_t>(utf16.size()), &status);
    if (U_FAILURE(status) || !iterator)
        return fallbackGraphemeRanges(points);
    std::vector<ByteRange> result;
    int32_t begin = ubrk_first(iterator);
    for (int32_t end = ubrk_next(iterator); end != UBRK_DONE; begin = end, end = ubrk_next(iterator))
        result.push_back({byteOffsetForUtf16(points, begin, input.size()), byteOffsetForUtf16(points, end, input.size())});
    ubrk_close(iterator);
    return result;
}

std::string platformNormalize(std::string_view input, bool compose)
{
    std::vector<UChar> utf16;
    if (!toUtf16(input, utf16))
        return {};
    UErrorCode status = U_ZERO_ERROR;
    const UNormalizer2* normalizer = compose ? unorm2_getNFCInstance(&status) : unorm2_getNFDInstance(&status);
    if (U_FAILURE(status))
        return {};
    status = U_ZERO_ERROR;
    int32_t normalizedLength = unorm2_normalize(normalizer, utf16.data(), static_cast<int32_t>(utf16.size()), nullptr, 0, &status);
    if (status != U_BUFFER_OVERFLOW_ERROR && U_FAILURE(status))
        return {};
    status = U_ZERO_ERROR;
    std::vector<UChar> normalized(static_cast<size_t>(normalizedLength));
    unorm2_normalize(normalizer, utf16.data(), static_cast<int32_t>(utf16.size()), normalized.data(), normalizedLength, &status);
    if (U_FAILURE(status))
        return {};
    status = U_ZERO_ERROR;
    int32_t outputLength = 0;
    u_strToUTF8(nullptr, 0, &outputLength, normalized.data(), normalizedLength, &status);
    if (status != U_BUFFER_OVERFLOW_ERROR && U_FAILURE(status))
        return {};
    status = U_ZERO_ERROR;
    std::string output(static_cast<size_t>(outputLength), '\0');
    u_strToUTF8(output.data(), outputLength, nullptr, normalized.data(), normalizedLength, &status);
    return U_SUCCESS(status) ? output : std::string();
}

#elif defined(_WIN32)

std::wstring toWide(std::string_view input)
{
    if (input.empty() || input.size() > static_cast<size_t>(std::numeric_limits<int>::max()))
        return {};
    const int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input.data(), static_cast<int>(input.size()), nullptr, 0);
    if (length <= 0)
        return {};
    std::wstring output(static_cast<size_t>(length), L'\0');
    return MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input.data(), static_cast<int>(input.size()), output.data(), length) == length
        ? output
        : std::wstring();
}

std::vector<ByteRange> platformGraphemeRanges(std::string_view, const std::vector<Codepoint>& points)
{
    return fallbackGraphemeRanges(points);
}

std::string platformNormalize(std::string_view input, bool compose)
{
    if (input.empty())
        return {};
    const std::wstring source = toWide(input);
    if (source.empty())
        return {};
    const NORM_FORM form = compose ? NormalizationC : NormalizationD;
    const int length = NormalizeString(form, source.data(), static_cast<int>(source.size()), nullptr, 0);
    if (length <= 0)
        return {};
    std::wstring normalized(static_cast<size_t>(length), L'\0');
    if (NormalizeString(form, source.data(), static_cast<int>(source.size()), normalized.data(), length) != length)
        return {};
    const int bytes = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, normalized.data(), length, nullptr, 0, nullptr, nullptr);
    if (bytes <= 0)
        return {};
    std::string output(static_cast<size_t>(bytes), '\0');
    return WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, normalized.data(), length, output.data(), bytes, nullptr, nullptr) == bytes
        ? output
        : std::string();
}

#else

std::vector<ByteRange> platformGraphemeRanges(std::string_view, const std::vector<Codepoint>& points)
{
    return fallbackGraphemeRanges(points);
}

std::string platformNormalize(std::string_view input, bool)
{
    if (std::all_of(input.begin(), input.end(), [](char value) { return static_cast<unsigned char>(value) < 0x80; }))
        return std::string(input);
    return {};
}

#endif

int relativePosition(int position, size_t length)
{
    if (position >= 0)
        return position;
    const uint64_t magnitude = static_cast<uint64_t>(-(static_cast<int64_t>(position)));
    if (magnitude > length)
        return 0;
    return static_cast<int>(length) + position + 1;
}

int graphemeIterator(lua_State* L)
{
    const int index = lua_tointeger(L, lua_upvalueindex(2));
    lua_rawgeti(L, lua_upvalueindex(1), index);
    if (lua_isnil(L, -1))
        return 0;
    lua_rawgeti(L, lua_upvalueindex(1), index + 1);
    lua_pushinteger(L, index + 2);
    lua_replace(L, lua_upvalueindex(2));
    return 2;
}

int utf8Graphemes(lua_State* L)
{
    size_t length = 0;
    const char* data = luaL_checklstring(L, 1, &length);
    if (length > static_cast<size_t>(std::numeric_limits<int>::max()))
        luaL_error(L, "string slice too long");
    const int initial = relativePosition(luaL_optinteger(L, 2, 1), length);
    const int final = relativePosition(luaL_optinteger(L, 3, -1), length);
    luaL_argcheck(L, initial >= 1 && initial <= static_cast<int>(length) + 1, 2, "initial position out of string");
    luaL_argcheck(L, final >= 0 && final <= static_cast<int>(length), 3, "final position out of string");

    std::vector<Codepoint> points;
    size_t invalidOffset = 0;
    if (!decodeUtf8(std::string_view(data, length), points, invalidOffset))
    {
        std::vector<Codepoint>().swap(points);
        invalidUtf8(L, invalidOffset);
    }
    const std::vector<ByteRange> ranges = platformGraphemeRanges(std::string_view(data, length), points);

    lua_createtable(L, static_cast<int>(ranges.size() * 2), 0);
    int outputIndex = 1;
    const size_t firstByte = static_cast<size_t>(initial - 1);
    const size_t lastByte = static_cast<size_t>(final);
    for (const ByteRange& range : ranges)
    {
        if (range.begin < firstByte || range.begin >= lastByte)
            continue;
        lua_pushinteger(L, static_cast<int>(range.begin + 1));
        lua_rawseti(L, -2, outputIndex++);
        lua_pushinteger(L, static_cast<int>(range.end));
        lua_rawseti(L, -2, outputIndex++);
    }
    lua_pushinteger(L, 1);
    lua_pushcclosure(L, graphemeIterator, "graphemes iterator", 2);
    return 1;
}

int normalize(lua_State* L, bool compose)
{
    size_t length = 0;
    const char* data = luaL_checklstring(L, 1, &length);
    std::vector<Codepoint> points;
    size_t invalidOffset = 0;
    if (!decodeUtf8(std::string_view(data, length), points, invalidOffset))
    {
        std::vector<Codepoint>().swap(points);
        invalidUtf8(L, invalidOffset);
    }
    std::vector<Codepoint>().swap(points);
    std::string output = platformNormalize(std::string_view(data, length), compose);
    if (output.empty() && length != 0)
        luaL_error(L, "Unicode normalization failed");
    lua_pushlstring(L, output.data(), output.size());
    return 1;
}

int utf8NfcNormalize(lua_State* L) { return normalize(L, true); }
int utf8NfdNormalize(lua_State* L) { return normalize(L, false); }

} // namespace

void installRobloxUtf8(lua_State* L)
{
    lua_getglobal(L, "utf8");
    if (!lua_istable(L, -1))
        luaL_error(L, "utf8 library is unavailable");
    lua_pushcfunction(L, utf8NfdNormalize, "nfdnormalize");
    lua_setfield(L, -2, "nfdnormalize");
    lua_pushcfunction(L, utf8NfcNormalize, "nfcnormalize");
    lua_setfield(L, -2, "nfcnormalize");
    lua_pushcfunction(L, utf8Graphemes, "graphemes");
    lua_setfield(L, -2, "graphemes");
    lua_pop(L, 1);
}

} // namespace rbx::runtime
