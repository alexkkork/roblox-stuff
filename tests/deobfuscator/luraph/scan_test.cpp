#include "luraph/scan.hpp"

#include <array>
#include <cmath>
#include <cstdint>
#include <iostream>
#include <limits>
#include <string>
#include <string_view>
#include <vector>

namespace luraph = alex::deobfuscator::luraph;

namespace
{

bool require(bool condition, std::string_view message)
{
    if (!condition)
        std::cerr << "luraph_adapter_test: " << message << '\n';
    return condition;
}

bool hasDiagnostic(const luraph::EnvelopeAnalysis& analysis, std::string_view code)
{
    for (const luraph::Diagnostic& diagnostic : analysis.diagnostics)
        if (diagnostic.code == code)
            return true;
    return false;
}

bool sameSpan(const luraph::ByteSpan& left, const luraph::ByteSpan& right)
{
    return left.begin == right.begin && left.end == right.end;
}

bool sameInstruction(const luraph::InstructionMetadata& left, const luraph::InstructionMetadata& right)
{
    if (left.index != right.index || !sameSpan(left.span, right.span))
        return false;
    for (size_t word = 0; word < left.words.size(); ++word)
        if (left.words[word].value != right.words[word].value || !sameSpan(left.words[word].span, right.words[word].span))
            return false;
    return true;
}

const luraph::ReaderMetadata* findReader(const luraph::EnvelopeAnalysis& analysis, std::string_view name)
{
    for (const luraph::ReaderMetadata& reader : analysis.readers)
        if (reader.name == name)
            return &reader;
    return nullptr;
}

std::string decodedBytes(const luraph::CarrierExtraction& extraction)
{
    return std::string(extraction.bytes.begin(), extraction.bytes.end());
}

void appendUleb(std::vector<unsigned char>& output, uint64_t value)
{
    do
    {
        unsigned char byte = static_cast<unsigned char>(value & 0x7fu);
        value >>= 7u;
        if (value != 0)
            byte |= 0x80u;
        output.push_back(byte);
    } while (value != 0);
}

void appendLittle(std::vector<unsigned char>& output, uint64_t value, size_t width)
{
    for (size_t index = 0; index < width; ++index)
        output.push_back(static_cast<unsigned char>(value >> (index * 8u)));
}

uint64_t signedFold(int64_t value)
{
    constexpr uint64_t modulus = uint64_t{1} << 53u;
    return value < 0 ? modulus - static_cast<uint64_t>(-value) : static_cast<uint64_t>(value);
}

std::string radix85Carrier(const std::vector<unsigned char>& decoded)
{
    if (decoded.size() % 4 != 0)
        return {};
    std::string carrier = "LPH&";
    for (size_t offset = 0; offset < decoded.size(); offset += 4)
    {
        uint32_t value = 0;
        for (size_t index = 0; index < 4; ++index)
            value |= static_cast<uint32_t>(decoded[offset + index]) << (index * 8u);
        char digits[5]{};
        for (size_t index = 5; index > 0; --index)
        {
            digits[index - 1] = static_cast<char>(value % 85u + 33u);
            value /= 85u;
        }
        carrier.append(digits, sizeof(digits));
    }
    return carrier;
}

std::string radix85DollarCarrier(const std::vector<unsigned char>& decoded)
{
    std::string carrier = radix85Carrier(decoded);
    if (!carrier.empty())
        carrier[3] = '$';
    return carrier;
}

std::string longCarrierLiteral(std::string_view carrier)
{
    return "[========[" + std::string(carrier) + "]========]";
}

struct SyntheticContainer
{
    std::vector<unsigned char> decoded;
    std::vector<unsigned char> trailer;
    std::vector<luraph::InstructionMetadata> instructions;
    std::string carrier;
};

SyntheticContainer syntheticContainer()
{
    SyntheticContainer fixture;
    appendUleb(fixture.decoded, 12618 + 15);
    fixture.decoded.push_back(0);

    const auto appendFixed = [&](unsigned char tag, size_t width) {
        fixture.decoded.push_back(tag);
        for (size_t index = 0; index < width; ++index)
            fixture.decoded.push_back(static_cast<unsigned char>(tag + index));
    };
    const auto appendString = [&](unsigned char tag, std::string_view value) {
        fixture.decoded.push_back(tag);
        appendUleb(fixture.decoded, value.size());
        fixture.decoded.insert(fixture.decoded.end(), value.begin(), value.end());
    };

    appendFixed(0, 2);
    appendFixed(40, 8);
    appendFixed(47, 0);
    appendFixed(68, 4);
    appendFixed(76, 1);
    appendFixed(90, 4);
    appendFixed(91, 1);
    appendFixed(110, 0);
    appendString(117, "abc");
    appendFixed(156, 8);
    appendString(157, "");
    appendFixed(182, 1);
    appendFixed(199, 2);
    appendFixed(233, 4);
    appendFixed(255, 4);

    appendUleb(fixture.decoded, 87799 + 1);
    appendUleb(fixture.decoded, 7);
    appendUleb(fixture.decoded, 7379 + 2);
    const auto appendInstruction = [&](const std::array<int64_t, 4>& words) {
        luraph::InstructionMetadata instruction;
        instruction.index = fixture.instructions.size();
        const size_t instructionBegin = fixture.decoded.size();
        for (size_t word = 0; word < words.size(); ++word)
        {
            const size_t wordBegin = fixture.decoded.size();
            appendUleb(fixture.decoded, signedFold(words[word]));
            instruction.words[word] = luraph::InstructionWordMetadata{
                words[word],
                luraph::ByteSpan{wordBegin, fixture.decoded.size()},
            };
        }
        instruction.span = luraph::ByteSpan{instructionBegin, fixture.decoded.size()};
        fixture.instructions.push_back(instruction);
    };
    appendInstruction({0, 7, -1, -2});
    appendInstruction({1, (int64_t{1} << 52u) - 1, -(int64_t{1} << 52u), -1234567});
    appendUleb(fixture.decoded, 2);
    appendUleb(fixture.decoded, 1 * 4 + 2);
    appendUleb(fixture.decoded, 3 * 4 + 3);
    appendUleb(fixture.decoded, 11);
    appendUleb(fixture.decoded, 20);

    fixture.trailer = {0xde, 0xad, 0xbe};
    while ((fixture.decoded.size() + fixture.trailer.size()) % 4 != 0)
        fixture.trailer.push_back(0xef);
    fixture.decoded.insert(fixture.decoded.end(), fixture.trailer.begin(), fixture.trailer.end());
    fixture.carrier = radix85Carrier(fixture.decoded);
    return fixture;
}

struct ConstantValueContainer
{
    std::vector<unsigned char> decoded;
    std::string carrier;
};

ConstantValueContainer constantValueContainer()
{
    ConstantValueContainer fixture;
    constexpr size_t constantCount = 32;
    appendUleb(fixture.decoded, 12618 + constantCount);
    fixture.decoded.push_back(0x5a);

    const auto appendFixed = [&](unsigned char tag, uint64_t value, size_t width) {
        fixture.decoded.push_back(tag);
        appendLittle(fixture.decoded, value, width);
    };
    const auto appendString = [&](unsigned char tag, const std::vector<unsigned char>& value) {
        fixture.decoded.push_back(tag);
        appendUleb(fixture.decoded, value.size());
        fixture.decoded.insert(fixture.decoded.end(), value.begin(), value.end());
    };

    appendFixed(0, 0x8000u, 2);
    appendFixed(39, 0x7fffu, 2);
    appendFixed(40, 0x7ff0000000000000ull, 8);
    appendFixed(41, 0xfff0000000000000ull, 8);
    appendFixed(42, 0x8000000000000000ull, 8);
    appendFixed(46, 0x7ff8000000001234ull, 8);
    appendFixed(47, 0, 0);
    appendFixed(67, 0, 0);
    appendFixed(68, 0x7f800000u, 4);
    appendFixed(69, 0xff800000u, 4);
    appendFixed(70, 0x80000000u, 4);
    appendFixed(75, 0x7fc01234u, 4);
    appendFixed(76, 0, 1);
    appendFixed(89, 255, 1);
    appendFixed(90, 0x80000000u, 4);
    appendFixed(91, 1, 1);
    appendFixed(109, 254, 1);
    appendFixed(110, 0, 0);
    appendFixed(116, 0, 0);
    appendString(117, {0x00, 0xff, 'A'});
    appendString(155, {});
    appendFixed(156, std::numeric_limits<uint64_t>::max(), 8);
    appendString(157, {'x', 0x00, 'y'});
    appendString(181, {0x80, 0x81, 0x00});
    appendFixed(182, 0, 1);
    appendFixed(198, 255, 1);
    appendFixed(199, 0x1234u, 2);
    appendFixed(232, 0xffffu, 2);
    appendFixed(233, 0x89abcdefu, 4);
    appendFixed(255, 0xffffffffu, 4);
    appendFixed(43, 0x3ff8000000000000ull, 8);
    appendFixed(71, 0xc0200000u, 4);

    appendUleb(fixture.decoded, 87799);
    appendUleb(fixture.decoded, 20);
    while (fixture.decoded.size() % 4 != 0)
        fixture.decoded.push_back(0xa5);
    fixture.carrier = radix85Carrier(fixture.decoded);
    return fixture;
}

std::vector<unsigned char> paddedContainerPrefix(uint64_t rawConstantCount)
{
    std::vector<unsigned char> decoded;
    appendUleb(decoded, rawConstantCount);
    while (decoded.size() % 4 != 0)
        decoded.push_back(0);
    return decoded;
}

std::string wrapperFixture(std::string_view carrierLiteral, std::string_view version = "14.7")
{
    std::string source = "-- This file was protected using Luraph Obfuscator v" + std::string(version) + " [https://lura.ph/]\nreturn({";
    source += "P=function(self)return function(...)return ... end end,";
    source += "readu8=function(s,i)return string.byte(s,i)end,";
    source += "readu32=function(s,i)return bit32.band(string.byte(s,i),255)end,";
    source += "payload=" + std::string(carrierLiteral);
    source += "}):P()(...);";
    return source;
}

std::string luaAuthWrapperFixture(std::string_view carrierLiteral)
{
    std::string body = wrapperFixture(carrierLiteral);
    body.erase(0, body.find('\n') + 1);
    return "la_code=123456789;la_script_id='fixture_id_123'\n"
           "--[[ LuaAuth protected loader. https://luaauth.com ]]\n\n" + body;
}

std::string luaAuthReaderRoleFixture(std::string_view carrierLiteral)
{
    std::string source = "la_code=314159265;la_script_id='reader_role_fixture'\n";
    source += "--[[ LuaAuth protected loader. https://luaauth.com ]]\n\n";
    source += "return({";
    source += "P=function(self)return function(...)return ... end end,";
    source += "readu8=function(s,i)return string.byte(s,i)end,";
    source += "readi8=function(s,i)return string.byte(s,i)end,";
    source += "readu16=function(s,i)return string.byte(s,i)end,";
    source += "readi16=function(s,i)return string.byte(s,i)end,";
    source += "readu32=function(s,i)return string.byte(s,i)end,";
    source += "readi32=function(s,i)return string.byte(s,i)end,";
    source += "readu64=function(s,i)return string.byte(s,i)end,";
    source += "readi64=function(s,i)return string.byte(s,i)end,";
    source += "readf32=function(s,i)return string.byte(s,i)end,";
    source += "readf64=function(s,i)return string.byte(s,i)end,";
    source += "payload=" + std::string(carrierLiteral);
    source += "}):P()(...);";
    return source;
}

std::string fixture(std::string_view version)
{
    std::string source = "-- This file was protected using Luraph Obfuscator v" + std::string(version) + " [https://lura.ph/]\nreturn({";
    source += "P=function(self)return function(...)return ... end end,";
    source += "readu8=function(s,i)return string.byte(s,i)end,";
    source += "readu32=function(s,i)return bit32.band(string.byte(s,i),255)end,";
    for (int index = 0; index < 18; ++index)
        source += "f" + std::to_string(index) + "=function(x)for i=1,2 do x=(x or 0)+i end return x end,";
    source += "payload=[=[LPH@";
    for (int index = 0; index < 1400; ++index)
        source += static_cast<char>('!' + (index % 80));
    source += "]=]}):P()(...);";
    return source;
}

} // namespace

int main()
{
    bool ok = true;

    const std::string supportedSource = fixture("14.7");
    const luraph::EnvelopeAnalysis supported = luraph::analyzeEnvelope(supportedSource);
    ok &= require(supported.complete, "supported fixture should complete its bounded scan");
    ok &= require(supported.bounded, "analysis must report bounded execution");
    ok &= require(supported.family_detected, "v14.7 family was not detected");
    ok &= require(supported.version_supported, "v14.7 should be supported");
    ok &= require(!supported.source_recovery_attempted, "envelope analysis must not claim source recovery");
    ok &= require(supported.wrapper.kind == luraph::WrapperKind::ReturnedTableMethodDispatch, "wrapper dispatch shape was not recovered");
    ok &= require(supported.wrapper.forwards_varargs, "wrapper vararg forwarding was not recovered");
    ok &= require(supported.wrapper.function_member_count >= 16, "dense function table was not counted");
    ok &= require(supported.counts.encoded_blob_candidate_count >= 1, "encoded carrier was not detected");
    ok &= require(supported.confidence.level == luraph::ConfidenceLevel::High, "supported fixture should have high confidence");
    ok &= require(supported.static_decode.eligible, "supported wrapper should be eligible for static literal decoding");
    ok &= require(supported.static_decode.attempted, "static literal decoding was not attempted");
    ok &= require(supported.static_decode.complete, "supported fixture static decoding should complete");
    ok &= require(!supported.static_decode.payload_decode_attempted, "literal extraction must not claim payload decoding was attempted");
    ok &= require(!supported.static_decode.payload_decoded, "literal extraction must not claim a decoded payload");
    ok &= require(supported.static_decode.carrier_candidate_count == 1, "carrier candidate metric is incorrect");
    ok &= require(supported.static_decode.carrier_decoded_count == 1, "carrier decode metric is incorrect");
    ok &= require(supported.static_decode.decoded_carrier_bytes == 1404, "decoded carrier byte metric is incorrect");
    ok &= require(supported.carriers.size() == 1, "decoded carrier record is missing");
    if (!supported.carriers.empty())
    {
        const luraph::CarrierExtraction& carrier = supported.carriers.front();
        ok &= require(carrier.status == luraph::CarrierDecodeStatus::DecodedLiteral, "long-bracket carrier was not decoded as a literal");
        ok &= require(carrier.literal_kind == luraph::CarrierLiteralKind::LongBracketString, "carrier literal kind is incorrect");
        ok &= require(carrier.decoded_byte_count == carrier.bytes.size(), "carrier byte count differs from retained bytes");
        ok &= require(carrier.lph_marker_offset == 0, "decoded LPH marker offset is incorrect");
        ok &= require(decodedBytes(carrier).substr(0, 8) == "LPH@!\"#$", "decoded long-bracket bytes do not match the source literal");
    }
    ok &= require(hasDiagnostic(supported, "CARRIER_LITERAL_DECODED"), "carrier decode diagnostic is missing");
    ok &= require(hasDiagnostic(supported, "VM_SEMANTICS_NOT_ATTEMPTED"), "VM semantics boundary diagnostic is missing");

    const std::string luaAuthSource = luaAuthWrapperFixture(longCarrierLiteral("LPH$!!!!!z!!!!!"));
    const luraph::EnvelopeAnalysis luaAuth = luraph::analyzeEnvelope(luaAuthSource);
    ok &= require(luaAuth.complete && luaAuth.family_detected, "LuaAuth-wrapped LPH$ family was not detected");
    ok &= require(luaAuth.version_supported, "supported LPH$ launcher family was rejected");
    ok &= require(luaAuth.luaauth_launcher.present && luaAuth.luaauth_launcher.exact_assignment_shape,
        "LuaAuth launcher assignments were not recognized");
    ok &= require(luaAuth.luaauth_launcher.metadata_removed_from_body && luaAuth.luaauth_launcher.protected_body_range.has_value(),
        "LuaAuth launcher was not separated from the protected body");
    ok &= require(luaAuth.luaauth_launcher.code_digit_count == 9 && luaAuth.luaauth_launcher.script_id_byte_count == 14,
        "LuaAuth launcher retained incorrect safe metadata lengths");
    ok &= require(luaAuth.counts.source_bytes == luaAuthSource.size(), "LuaAuth source byte count excluded its launcher");
    ok &= require(luaAuth.wrapper.kind == luraph::WrapperKind::ReturnedTableMethodDispatch,
        "LuaAuth protected body wrapper was not analyzed independently");
    ok &= require(luaAuth.static_decode.eligible && luaAuth.static_decode.complete,
        "LPH$ carrier was not eligible for bounded static decoding");
    ok &= require(luaAuth.carriers.size() == 1 && luaAuth.carriers.front().kind == luraph::BlobKind::LphDollar,
        "LPH$ carrier kind was not retained");
    ok &= require(luaAuth.containers.size() == 1 && luaAuth.containers.front().decode_status == luraph::ContainerDecodeStatus::Decoded,
        "LPH$ radix-85 container was not decoded");
    if (!luaAuth.containers.empty())
    {
        const luraph::ContainerAnalysis& decoded = luaAuth.containers.front();
        ok &= require(decoded.parse_status == luraph::ContainerParseStatus::UnsupportedSchema,
            "LPH$ bytes were incorrectly parsed with the LPH& record schema");
        ok &= require(decoded.marker == '$' && decoded.decoded_bytes == 12 && decoded.radix85_group_count == 3 &&
                          decoded.radix85_zero_group_count == 1,
            "LPH$ zero-shorthand metrics are incorrect");
        ok &= require(decoded.decoded_data == std::vector<unsigned char>(12, 0),
            "LPH$ little-endian decoded bytes are incorrect");
    }
    ok &= require(luaAuth.container_metrics.decoded_count == 1 && luaAuth.container_metrics.parsed_count == 0 &&
                      luaAuth.container_metrics.failure_count == 0,
        "LPH$ decode and schema-boundary metrics are incorrect");
    ok &= require(luaAuth.carriers.front().literal_range.begin >= luaAuth.luaauth_launcher.protected_body_range->begin,
        "LPH$ source ranges were not translated back to original-input offsets");
    ok &= require(hasDiagnostic(luaAuth, "LUAAUTH_LAUNCHER_REMOVED"), "LuaAuth launcher-removal diagnostic is missing");
    ok &= require(hasDiagnostic(luaAuth, "LPH_DOLLAR_SCHEMA_UNSUPPORTED"), "LPH$ schema-boundary diagnostic is missing");

    const std::vector<unsigned char> dollarByteOrderFixture = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
    const std::string dollarByteOrderCarrier = radix85DollarCarrier(dollarByteOrderFixture);
    ok &= require(!dollarByteOrderCarrier.empty(), "LPH$ byte-order carrier construction failed");
    const luraph::EnvelopeAnalysis dollarByteOrder = luraph::analyzeEnvelope(
        luaAuthWrapperFixture(longCarrierLiteral(dollarByteOrderCarrier)));
    ok &= require(dollarByteOrder.containers.size() == 1, "LPH$ byte-order container record is missing");
    if (dollarByteOrder.containers.size() == 1)
    {
        const luraph::ContainerAnalysis& decoded = dollarByteOrder.containers.front();
        ok &= require(decoded.decode_status == luraph::ContainerDecodeStatus::Decoded && decoded.marker == '$',
            "LPH$ nonzero radix-85 groups were not decoded");
        ok &= require(decoded.decoded_data == dollarByteOrderFixture,
            "LPH$ radix-85 groups did not preserve their proven little-endian byte order");
        ok &= require(decoded.parse_status == luraph::ContainerParseStatus::UnsupportedSchema,
            "LPH$ byte recovery was incorrectly promoted to record-schema recovery");
        ok &= require(decoded.constants.empty() && decoded.prototypes.empty() && decoded.root_selector_span.size() == 0,
            "LPH$ decoding invented record lanes or a root before the randomized schema was proven");
    }

    const luraph::EnvelopeAnalysis dollarReaders = luraph::analyzeEnvelope(
        luaAuthReaderRoleFixture(longCarrierLiteral(dollarByteOrderCarrier)));
    struct ExpectedReaderRole
    {
        std::string_view name;
        luraph::ReaderValueKind kind;
        size_t bits;
    };
    constexpr std::array<ExpectedReaderRole, 8> expectedReaderRoles = {{
        {"readu8", luraph::ReaderValueKind::UnsignedInteger, 8},
        {"readu16", luraph::ReaderValueKind::UnsignedInteger, 16},
        {"readu32", luraph::ReaderValueKind::UnsignedInteger, 32},
        {"readi8", luraph::ReaderValueKind::SignedInteger, 8},
        {"readi16", luraph::ReaderValueKind::SignedInteger, 16},
        {"readi32", luraph::ReaderValueKind::SignedInteger, 32},
        {"readf32", luraph::ReaderValueKind::FloatingPoint, 32},
        {"readf64", luraph::ReaderValueKind::FloatingPoint, 64},
    }};
    ok &= require(dollarReaders.static_decode.reader_metadata_count == expectedReaderRoles.size(),
        "LPH$ structural reader-role inventory is incomplete");
    for (const ExpectedReaderRole& expected : expectedReaderRoles)
    {
        const luraph::ReaderMetadata* reader = findReader(dollarReaders, expected.name);
        ok &= require(reader != nullptr, "LPH$ structural reader role is missing");
        if (!reader)
            continue;
        ok &= require(reader->value_kind == expected.kind && reader->bit_width == expected.bits &&
                          reader->byte_width == expected.bits / 8,
            "LPH$ reader role has incorrect type or width metadata");
        ok &= require(reader->definition_present && reader->definition_range.has_value() && reader->reference_count >= 1,
            "LPH$ reader role lacks its structural definition evidence");
        ok &= require(reader->byte_order == luraph::ByteOrder::Unknown && reader->inferred_from_identifier &&
                          !reader->implementation_verified,
            "LPH$ reader role was presented as implementation-verified or assigned an unproven byte order");
    }
    ok &= require(findReader(dollarReaders, "readu64") == nullptr && findReader(dollarReaders, "readi64") == nullptr,
        "unsupported reader names were promoted to proven LPH$ roles");

    const luraph::ReaderMetadata* readu8 = findReader(supported, "readu8");
    const luraph::ReaderMetadata* readu32 = findReader(supported, "readu32");
    ok &= require(readu8 != nullptr && readu32 != nullptr, "declared reader metadata is missing");
    if (readu32)
    {
        ok &= require(readu32->definition_present, "readu32 definition was not identified");
        ok &= require(readu32->value_kind == luraph::ReaderValueKind::UnsignedInteger, "readu32 value kind is incorrect");
        ok &= require(readu32->bit_width == 32 && readu32->byte_width == 4, "readu32 width metadata is incorrect");
        ok &= require(readu32->byte_order == luraph::ByteOrder::Unknown, "byte order was inferred without syntactic proof");
        ok &= require(readu32->inferred_from_identifier && !readu32->implementation_verified, "reader name hint was presented as verified behavior");
    }
    ok &= require(supported.static_decode.reader_metadata_count == 2, "reader metadata count is incorrect");
    ok &= require(supported.static_decode.reader_definition_count == 2, "reader definition count is incorrect");
    ok &= require(hasDiagnostic(supported, "READER_METADATA_EXTRACTED"), "reader metadata diagnostic is missing");

    const SyntheticContainer containerFixture = syntheticContainer();
    ok &= require(!containerFixture.carrier.empty(), "synthetic radix-85 carrier construction failed");
    const luraph::EnvelopeAnalysis schemaShapedDollar = luraph::analyzeEnvelope(
        luaAuthWrapperFixture(longCarrierLiteral(radix85DollarCarrier(containerFixture.decoded))));
    ok &= require(schemaShapedDollar.containers.size() == 1, "schema-shaped LPH$ container record is missing");
    if (schemaShapedDollar.containers.size() == 1)
    {
        const luraph::ContainerAnalysis& decoded = schemaShapedDollar.containers.front();
        ok &= require(decoded.decode_status == luraph::ContainerDecodeStatus::Decoded &&
                          decoded.decoded_data == containerFixture.decoded,
            "schema-shaped LPH$ bytes were not retained exactly");
        ok &= require(decoded.parse_status == luraph::ContainerParseStatus::UnsupportedSchema,
            "LPH&-shaped bytes bypassed the LPH$ schema boundary");
        ok &= require(decoded.constant_count == 0 && decoded.constants.empty() && decoded.prototype_count == 0 &&
                          decoded.prototypes.empty() && decoded.instruction_count == 0 && decoded.descriptor_count == 0,
            "LPH$ bytes inherited LPH& constant, prototype, instruction, or descriptor lanes");
        ok &= require(decoded.root_selector == 0 && decoded.root_selector_span.size() == 0,
            "LPH$ bytes inherited an unproven LPH& root selector");
    }
    ok &= require(schemaShapedDollar.container_metrics.parsed_count == 0 &&
                      schemaShapedDollar.container_metrics.constant_count == 0 &&
                      schemaShapedDollar.container_metrics.prototype_count == 0,
        "LPH$ aggregate metrics claim randomized tag or key schedule records were parsed");
    ok &= require(hasDiagnostic(schemaShapedDollar, "LPH_DOLLAR_SCHEMA_UNSUPPORTED"),
        "schema-shaped LPH$ input did not retain its randomized-schema boundary");

    const luraph::EnvelopeAnalysis container = luraph::analyzeEnvelope(wrapperFixture(longCarrierLiteral(containerFixture.carrier)));
    ok &= require(container.static_decode.complete, "valid LPH& container decoding should complete");
    ok &= require(!container.static_decode.payload_decode_attempted && !container.static_decode.payload_decoded,
        "container parsing must not claim protected-program decoding");
    ok &= require(container.container_metrics.candidate_count == 1 && container.container_metrics.attempt_count == 1,
        "LPH& candidate metrics are incorrect");
    ok &= require(container.container_metrics.decoded_count == 1 && container.container_metrics.parsed_count == 1 &&
                      container.container_metrics.failure_count == 0,
        "LPH& decode/parse metrics are incorrect");
    ok &= require(container.container_metrics.decoded_bytes == containerFixture.decoded.size(), "decoded container byte metric is incorrect");
    ok &= require(container.container_metrics.constant_count == 15 && container.container_metrics.prototype_count == 1,
        "container record count metrics are incorrect");
    ok &= require(container.container_metrics.instruction_count == 2 && container.container_metrics.descriptor_count == 2,
        "container instruction/descriptor metrics are incorrect");
    ok &= require(container.container_metrics.trailer_bytes == containerFixture.trailer.size(), "container trailer metric is incorrect");
    ok &= require(container.containers.size() == 1, "container analysis record is missing");
    ok &= require(container.carriers.size() == 1 && container.carriers.front().kind == luraph::BlobKind::LphAmpersand &&
                      container.carriers.front().container_index == 0,
        "LPH& carrier was not linked to its container record");
    if (!container.containers.empty())
    {
        const luraph::ContainerAnalysis& parsed = container.containers.front();
        ok &= require(parsed.decode_status == luraph::ContainerDecodeStatus::Decoded, "valid LPH& radix-85 status is incorrect");
        ok &= require(parsed.parse_status == luraph::ContainerParseStatus::Parsed, "valid LPH& parse status is incorrect");
        ok &= require(parsed.decoded_bytes == containerFixture.decoded.size() && parsed.decoded_sha256.size() == 64,
            "decoded container identity metadata is incorrect");
        ok &= require(parsed.constant_count == 15 && parsed.constants.size() == 15, "constant metadata count is incorrect");
        ok &= require(parsed.constant_pool_mode == 0 && parsed.constant_pool_mode_span.size() == 1 &&
                          parsed.constant_count_span.end == parsed.constant_pool_mode_span.begin &&
                          parsed.constant_pool_mode_span.end == parsed.constants_span.begin,
            "constant pool mode metadata is incorrect");
        ok &= require(parsed.constants_span.end == parsed.prototype_count_span.begin &&
                          parsed.prototype_count_span.end == parsed.prototypes_span.begin &&
                          parsed.prototypes_span.end == parsed.root_selector_span.begin &&
                          parsed.root_selector_span.end == parsed.trailer_span.begin,
            "proven LPH& record lanes and root selector are not contiguous");
        if (parsed.constants.size() == 15)
        {
            const std::array<unsigned char, 15> expectedTags = {0, 40, 47, 68, 76, 90, 91, 110, 117, 156, 157, 182, 199, 233, 255};
            const std::array<luraph::ConstantKind, 15> expectedKinds = {
                luraph::ConstantKind::Integer, luraph::ConstantKind::Float, luraph::ConstantKind::Boolean,
                luraph::ConstantKind::Float, luraph::ConstantKind::Integer, luraph::ConstantKind::Integer,
                luraph::ConstantKind::Integer, luraph::ConstantKind::Boolean, luraph::ConstantKind::String,
                luraph::ConstantKind::Integer, luraph::ConstantKind::String, luraph::ConstantKind::Integer,
                luraph::ConstantKind::Integer, luraph::ConstantKind::Integer, luraph::ConstantKind::Integer,
            };
            const std::array<size_t, 15> expectedWidths = {2, 8, 0, 4, 1, 4, 1, 0, 3, 8, 0, 1, 2, 4, 4};
            for (size_t index = 0; index < parsed.constants.size(); ++index)
            {
                ok &= require(parsed.constants[index].tag == expectedTags[index] && parsed.constants[index].kind == expectedKinds[index] &&
                                  parsed.constants[index].data_bytes == expectedWidths[index],
                    "constant family metadata is incorrect");
            }
            ok &= require(parsed.constants[8].length_span.has_value() && parsed.constants[10].length_span.has_value(),
                "string constant length metadata is missing");
            ok &= require(parsed.constants_span.end == parsed.prototype_count_span.begin,
                "constant pool spans are not contiguous");
        }
        ok &= require(parsed.prototype_count == 1 && parsed.prototypes.size() == 1, "prototype metadata count is incorrect");
        if (!parsed.prototypes.empty())
        {
            const luraph::PrototypeMetadata& prototype = parsed.prototypes.front();
            ok &= require(prototype.meta == 7 && prototype.final_value == 11, "prototype scalar metadata is incorrect");
            ok &= require(prototype.instruction_count == 2 && prototype.instructions.size() == 2 && prototype.instruction_words_span.size() > 0,
                "prototype instruction span is incorrect");
            if (prototype.instructions.size() == containerFixture.instructions.size())
            {
                ok &= require(prototype.instructions.front().words[1].value == 7 && prototype.instructions.back().words[1].value == (int64_t{1} << 52u) - 1,
                    "positive signed-fold words were not retained");
                ok &= require(prototype.instructions.front().words[2].value == -1 &&
                                  prototype.instructions.back().words[2].value == -(int64_t{1} << 52u),
                    "negative signed-fold words were not retained");
                ok &= require(prototype.instruction_words_span.begin == prototype.instructions.front().span.begin &&
                                  prototype.instruction_words_span.end == prototype.instructions.back().span.end,
                    "aggregate instruction span does not bound the retained instructions");
                for (size_t instruction = 0; instruction < prototype.instructions.size(); ++instruction)
                {
                    const luraph::InstructionMetadata& actual = prototype.instructions[instruction];
                    const luraph::InstructionMetadata& expected = containerFixture.instructions[instruction];
                    ok &= require(sameInstruction(actual, expected), "instruction values or byte spans differ from the encoded fixture");
                    ok &= require(actual.span.begin == actual.words.front().span.begin && actual.span.end == actual.words.back().span.end,
                        "instruction span does not bound its four word spans");
                    for (size_t word = 1; word < actual.words.size(); ++word)
                        ok &= require(actual.words[word - 1].span.end == actual.words[word].span.begin,
                            "instruction word spans are not contiguous");
                }
            }
            ok &= require(prototype.descriptor_count == 2 && prototype.descriptors.size() == 2,
                "prototype descriptor metadata is incorrect");
            ok &= require(prototype.meta_span.begin == prototype.span.begin &&
                              prototype.meta_span.end == prototype.instruction_count_span.begin &&
                              prototype.instruction_count_span.end == prototype.instruction_words_span.begin &&
                              prototype.instruction_words_span.end == prototype.descriptor_count_span.begin &&
                              prototype.descriptor_count_span.end == prototype.descriptors_span.begin &&
                              prototype.descriptors_span.end == prototype.final_span.begin &&
                              prototype.final_span.end == prototype.span.end,
                "proven LPH& prototype record lanes are not contiguous");
            if (prototype.descriptors.size() == 2)
            {
                ok &= require(prototype.descriptors[0].kind == 2 && prototype.descriptors[0].referenced_index == 1,
                    "first descriptor split is incorrect");
                ok &= require(prototype.descriptors[1].kind == 3 && prototype.descriptors[1].referenced_index == 3,
                    "second descriptor split is incorrect");
            }
        }
        ok &= require(parsed.root_selector == 20, "root selector metadata is incorrect");
        ok &= require(parsed.trailer_span.size() == containerFixture.trailer.size() && parsed.trailer_bytes == containerFixture.trailer,
            "unread trailer was not preserved exactly");
        ok &= require(parsed.trailer_span.end == containerFixture.decoded.size(), "trailer byte span is incorrect");
    }
    ok &= require(hasDiagnostic(container, "LPH_CONTAINER_DECODED"), "LPH& decode diagnostic is missing");
    ok &= require(hasDiagnostic(container, "LPH_CONTAINER_PARSED"), "LPH& parse diagnostic is missing");

    const ConstantValueContainer valueFixture = constantValueContainer();
    const luraph::EnvelopeAnalysis valueAnalysis =
        luraph::analyzeEnvelope(wrapperFixture(longCarrierLiteral(valueFixture.carrier)));
    ok &= require(valueAnalysis.containers.size() == 1, "constant-value container analysis is missing");
    if (valueAnalysis.containers.size() == 1)
    {
        const luraph::ContainerAnalysis& parsed = valueAnalysis.containers.front();
        ok &= require(parsed.parse_status == luraph::ContainerParseStatus::Parsed && parsed.constant_pool_mode == 0x5a,
            "constant-value container framing is incorrect");
        ok &= require(parsed.constant_count == 32 && parsed.constants.size() == 32,
            "constant-value family fixture count is incorrect");
        if (parsed.constants.size() == 32)
        {
            const auto requireSigned = [&](size_t index, int64_t value) {
                const luraph::ConstantMetadata& constant = parsed.constants[index];
                ok &= require(constant.kind == luraph::ConstantKind::Integer && constant.signed_integer_value == value &&
                                  !constant.unsigned_integer_value.has_value(),
                    "signed integer constant value is incorrect");
            };
            const auto requireUnsigned = [&](size_t index, uint64_t value) {
                const luraph::ConstantMetadata& constant = parsed.constants[index];
                ok &= require(constant.kind == luraph::ConstantKind::Integer && constant.unsigned_integer_value == value &&
                                  !constant.signed_integer_value.has_value(),
                    "unsigned integer constant value is incorrect");
            };
            const auto requireBoolean = [&](size_t index, bool value) {
                const luraph::ConstantMetadata& constant = parsed.constants[index];
                ok &= require(constant.kind == luraph::ConstantKind::Boolean && constant.boolean_value == value && constant.data_bytes == 0,
                    "boolean constant value is incorrect");
            };

            requireSigned(0, -32768);
            requireSigned(1, 32767);
            requireBoolean(6, false);
            requireBoolean(7, false);
            requireSigned(12, 0);
            requireSigned(13, -255);
            requireSigned(14, std::numeric_limits<int32_t>::min());
            requireSigned(15, -1);
            requireSigned(16, -254);
            requireBoolean(17, true);
            requireBoolean(18, true);
            requireUnsigned(21, std::numeric_limits<uint64_t>::max());
            requireUnsigned(24, 0);
            requireUnsigned(25, 255);
            requireUnsigned(26, 0x1234u);
            requireUnsigned(27, 0xffffu);
            requireUnsigned(28, 0x89abcdefu);
            requireUnsigned(29, 0xffffffffu);

            ok &= require(parsed.constants[2].float64_bits == 0x7ff0000000000000ull &&
                              parsed.constants[2].float64_value.has_value() && std::isinf(*parsed.constants[2].float64_value) &&
                              !std::signbit(*parsed.constants[2].float64_value),
                "positive f64 infinity was not retained exactly");
            ok &= require(parsed.constants[3].float64_bits == 0xfff0000000000000ull &&
                              parsed.constants[3].float64_value.has_value() && std::isinf(*parsed.constants[3].float64_value) &&
                              std::signbit(*parsed.constants[3].float64_value),
                "negative f64 infinity was not retained exactly");
            ok &= require(parsed.constants[4].float64_bits == 0x8000000000000000ull &&
                              parsed.constants[4].float64_value.has_value() && *parsed.constants[4].float64_value == 0.0 &&
                              std::signbit(*parsed.constants[4].float64_value),
                "negative f64 zero was not retained exactly");
            ok &= require(parsed.constants[5].float64_bits == 0x7ff8000000001234ull &&
                              parsed.constants[5].float64_value.has_value() && std::isnan(*parsed.constants[5].float64_value),
                "f64 NaN value or payload bits were not retained");

            ok &= require(parsed.constants[8].float32_bits == 0x7f800000u && parsed.constants[8].float32_value.has_value() &&
                              std::isinf(*parsed.constants[8].float32_value) && !std::signbit(*parsed.constants[8].float32_value),
                "positive f32 infinity was not retained exactly");
            ok &= require(parsed.constants[9].float32_bits == 0xff800000u && parsed.constants[9].float32_value.has_value() &&
                              std::isinf(*parsed.constants[9].float32_value) && std::signbit(*parsed.constants[9].float32_value),
                "negative f32 infinity was not retained exactly");
            ok &= require(parsed.constants[10].float32_bits == 0x80000000u && parsed.constants[10].float32_value.has_value() &&
                              *parsed.constants[10].float32_value == 0.0f && std::signbit(*parsed.constants[10].float32_value),
                "negative f32 zero was not retained exactly");
            ok &= require(parsed.constants[11].float32_bits == 0x7fc01234u && parsed.constants[11].float32_value.has_value() &&
                              std::isnan(*parsed.constants[11].float32_value),
                "f32 NaN value or payload bits were not retained");
            ok &= require(parsed.constants[30].float64_bits == 0x3ff8000000000000ull &&
                              parsed.constants[30].float64_value == 1.5,
                "finite f64 value was not decoded");
            ok &= require(parsed.constants[31].float32_bits == 0xc0200000u && parsed.constants[31].float32_value == -2.5f,
                "finite f32 value was not decoded");

            ok &= require(parsed.constants[19].string_bytes == std::vector<unsigned char>({0x00, 0xff, 'A'}) &&
                              parsed.constants[19].data_bytes == 3 && parsed.constants[19].length_span.has_value(),
                "first string family did not retain exact binary bytes");
            ok &= require(parsed.constants[20].string_bytes.empty() && parsed.constants[20].data_bytes == 0 &&
                              parsed.constants[20].length_span.has_value(),
                "empty string constant metadata is incorrect");
            ok &= require(parsed.constants[22].string_bytes == std::vector<unsigned char>({'x', 0x00, 'y'}) &&
                              parsed.constants[23].string_bytes == std::vector<unsigned char>({0x80, 0x81, 0x00}),
                "second string family did not retain exact binary bytes");

            const std::array<unsigned char, 32> expectedTags = {
                0, 39, 40, 41, 42, 46, 47, 67, 68, 69, 70, 75, 76, 89, 90,
                91, 109, 110, 116, 117, 155, 156, 157, 181, 182, 198, 199, 232, 233, 255,
                43, 71,
            };
            for (size_t index = 0; index < expectedTags.size(); ++index)
                ok &= require(parsed.constants[index].tag == expectedTags[index], "constant tag boundary ordering is incorrect");
        }
    }

    const luraph::EnvelopeAnalysis repeatedContainer = luraph::analyzeEnvelope(wrapperFixture(longCarrierLiteral(containerFixture.carrier)));
    ok &= require(repeatedContainer.containers.size() == 1 && repeatedContainer.containers.front().prototypes.size() == 1,
        "repeated container analysis did not retain prototype metadata");
    if (container.containers.size() == 1 && !container.containers.front().prototypes.empty() && repeatedContainer.containers.size() == 1 &&
        !repeatedContainer.containers.front().prototypes.empty())
    {
        const std::vector<luraph::InstructionMetadata>& first = container.containers.front().prototypes.front().instructions;
        const std::vector<luraph::InstructionMetadata>& second = repeatedContainer.containers.front().prototypes.front().instructions;
        ok &= require(first.size() == second.size(), "repeated container analysis changed the instruction count");
        if (first.size() == second.size())
            for (size_t instruction = 0; instruction < first.size(); ++instruction)
                ok &= require(sameInstruction(first[instruction], second[instruction]),
                    "repeated container analysis changed instruction values or spans");
    }

    luraph::AnalysisLimits instructionLimit;
    instructionLimit.max_container_instructions = containerFixture.instructions.size() - 1;
    const luraph::EnvelopeAnalysis instructionLimitedContainer =
        luraph::analyzeEnvelope(wrapperFixture(longCarrierLiteral(containerFixture.carrier)), instructionLimit);
    ok &= require(instructionLimitedContainer.containers.size() == 1 &&
                      instructionLimitedContainer.containers.front().parse_status == luraph::ContainerParseStatus::CountLimitExceeded &&
                      instructionLimitedContainer.containers.front().prototypes.empty(),
        "instruction count limit was not enforced before retaining partial instruction metadata");
    ok &= require(hasDiagnostic(instructionLimitedContainer, "LPH_CONTAINER_COUNT_LIMIT"),
        "instruction count-limit diagnostic is missing");

    const luraph::EnvelopeAnalysis emptyContainer = luraph::analyzeEnvelope(wrapperFixture(longCarrierLiteral("LPH&")));
    ok &= require(emptyContainer.containers.size() == 1, "empty LPH& status record is missing");
    if (!emptyContainer.containers.empty())
    {
        ok &= require(emptyContainer.containers.front().decode_status == luraph::ContainerDecodeStatus::Decoded &&
                          emptyContainer.containers.front().parse_status == luraph::ContainerParseStatus::Truncated,
            "empty LPH& statuses are incorrect");
        ok &= require(emptyContainer.containers.front().decoded_sha256 ==
                          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "decoded-container SHA-256 implementation is incorrect");
    }
    ok &= require(hasDiagnostic(emptyContainer, "LPH_CONTAINER_TRUNCATED"), "truncated-container diagnostic is missing");

    const luraph::EnvelopeAnalysis invalidPrefixContainer = luraph::analyzeEnvelope(wrapperFixture(longCarrierLiteral("xLPH&!!!!!")));
    ok &= require(invalidPrefixContainer.containers.size() == 1 &&
                      invalidPrefixContainer.containers.front().decode_status == luraph::ContainerDecodeStatus::InvalidPrefix,
        "embedded LPH& marker was treated as a leading prefix");
    ok &= require(hasDiagnostic(invalidPrefixContainer, "LPH_AMPERSAND_PREFIX"), "LPH& prefix diagnostic is missing");

    const luraph::EnvelopeAnalysis misalignedContainer = luraph::analyzeEnvelope(wrapperFixture(longCarrierLiteral("LPH&!!!!")));
    ok &= require(misalignedContainer.containers.size() == 1 &&
                      misalignedContainer.containers.front().decode_status == luraph::ContainerDecodeStatus::MisalignedBody,
        "misaligned radix-85 body was accepted");
    ok &= require(hasDiagnostic(misalignedContainer, "LPH_RADIX85_ALIGNMENT"), "radix-85 alignment diagnostic is missing");

    const luraph::EnvelopeAnalysis invalidCharacterContainer = luraph::analyzeEnvelope(wrapperFixture(longCarrierLiteral("LPH&!!!! ")));
    ok &= require(invalidCharacterContainer.containers.size() == 1 &&
                      invalidCharacterContainer.containers.front().decode_status == luraph::ContainerDecodeStatus::InvalidCharacter,
        "invalid radix-85 character was accepted");
    ok &= require(hasDiagnostic(invalidCharacterContainer, "LPH_RADIX85_CHARACTER"), "radix-85 character diagnostic is missing");

    const luraph::EnvelopeAnalysis overflowingContainer = luraph::analyzeEnvelope(wrapperFixture(longCarrierLiteral("LPH&uuuuu")));
    ok &= require(overflowingContainer.containers.size() == 1 &&
                      overflowingContainer.containers.front().decode_status == luraph::ContainerDecodeStatus::Radix85Overflow,
        "overflowing radix-85 group was accepted");
    ok &= require(hasDiagnostic(overflowingContainer, "LPH_RADIX85_OVERFLOW"), "radix-85 overflow diagnostic is missing");

    luraph::AnalysisLimits containerOutputLimit;
    containerOutputLimit.max_decoded_container_bytes = 3;
    const luraph::EnvelopeAnalysis outputLimitedContainer =
        luraph::analyzeEnvelope(wrapperFixture(longCarrierLiteral(containerFixture.carrier)), containerOutputLimit);
    ok &= require(outputLimitedContainer.containers.size() == 1 &&
                      outputLimitedContainer.containers.front().decode_status == luraph::ContainerDecodeStatus::OutputLimitExceeded &&
                      outputLimitedContainer.container_metrics.decoded_bytes == 0,
        "container output limit retained partial bytes");
    ok &= require(hasDiagnostic(outputLimitedContainer, "LPH_CONTAINER_OUTPUT_LIMIT"), "container output-limit diagnostic is missing");

    const std::vector<unsigned char> noncanonicalBytes = {0x80, 0x00, 0x00, 0x00};
    const luraph::EnvelopeAnalysis noncanonicalContainer =
        luraph::analyzeEnvelope(wrapperFixture(longCarrierLiteral(radix85Carrier(noncanonicalBytes))));
    ok &= require(noncanonicalContainer.containers.size() == 1 &&
                      noncanonicalContainer.containers.front().parse_status == luraph::ContainerParseStatus::NonCanonicalUleb,
        "noncanonical ULEB was accepted");
    ok &= require(hasDiagnostic(noncanonicalContainer, "LPH_ULEB_NONCANONICAL"), "noncanonical ULEB diagnostic is missing");

    std::vector<unsigned char> overflowingUlebBytes(12, 0);
    for (size_t index = 0; index < 10; ++index)
        overflowingUlebBytes[index] = 0x80;
    const luraph::EnvelopeAnalysis overflowingUlebContainer =
        luraph::analyzeEnvelope(wrapperFixture(longCarrierLiteral(radix85Carrier(overflowingUlebBytes))));
    ok &= require(overflowingUlebContainer.containers.size() == 1 &&
                      overflowingUlebContainer.containers.front().parse_status == luraph::ContainerParseStatus::UlebOverflow,
        "overflowing ULEB was accepted");
    ok &= require(hasDiagnostic(overflowingUlebContainer, "LPH_ULEB_OVERFLOW"), "ULEB overflow diagnostic is missing");

    const luraph::EnvelopeAnalysis underflowContainer =
        luraph::analyzeEnvelope(wrapperFixture(longCarrierLiteral(radix85Carrier(std::vector<unsigned char>{0, 0, 0, 0}))));
    ok &= require(underflowContainer.containers.size() == 1 &&
                      underflowContainer.containers.front().parse_status == luraph::ContainerParseStatus::CountUnderflow,
        "biased count underflow was accepted");
    ok &= require(hasDiagnostic(underflowContainer, "LPH_COUNT_UNDERFLOW"), "biased count-underflow diagnostic is missing");

    luraph::AnalysisLimits constantLimit;
    constantLimit.max_container_constants = 1;
    const luraph::EnvelopeAnalysis constantLimitedContainer = luraph::analyzeEnvelope(
        wrapperFixture(longCarrierLiteral(radix85Carrier(paddedContainerPrefix(12618 + 2)))), constantLimit);
    ok &= require(constantLimitedContainer.containers.size() == 1 &&
                      constantLimitedContainer.containers.front().parse_status == luraph::ContainerParseStatus::CountLimitExceeded,
        "constant count limit was not enforced");
    ok &= require(hasDiagnostic(constantLimitedContainer, "LPH_CONTAINER_COUNT_LIMIT"), "container count-limit diagnostic is missing");

    std::vector<unsigned char> signedOverflowBytes;
    appendUleb(signedOverflowBytes, 12618);
    signedOverflowBytes.push_back(0);
    appendUleb(signedOverflowBytes, 87799 + 1);
    appendUleb(signedOverflowBytes, 0);
    appendUleb(signedOverflowBytes, 7379 + 1);
    appendUleb(signedOverflowBytes, uint64_t{1} << 53u);
    while (signedOverflowBytes.size() % 4 != 0)
        signedOverflowBytes.push_back(0);
    const luraph::EnvelopeAnalysis signedOverflowContainer =
        luraph::analyzeEnvelope(wrapperFixture(longCarrierLiteral(radix85Carrier(signedOverflowBytes))));
    ok &= require(signedOverflowContainer.containers.size() == 1 &&
                      signedOverflowContainer.containers.front().parse_status == luraph::ContainerParseStatus::SignedFoldOverflow,
        "out-of-domain signed-fold word was accepted");
    ok &= require(hasDiagnostic(signedOverflowContainer, "LPH_SIGNED_FOLD_OVERFLOW"), "signed-fold overflow diagnostic is missing");

    luraph::AnalysisLimits trailerLimit;
    trailerLimit.max_preserved_trailer_bytes = containerFixture.trailer.empty() ? 0 : containerFixture.trailer.size() - 1;
    const luraph::EnvelopeAnalysis trailerLimitedContainer =
        luraph::analyzeEnvelope(wrapperFixture(longCarrierLiteral(containerFixture.carrier)), trailerLimit);
    ok &= require(trailerLimitedContainer.containers.size() == 1 &&
                      trailerLimitedContainer.containers.front().parse_status == luraph::ContainerParseStatus::TrailerLimitExceeded &&
                      trailerLimitedContainer.containers.front().trailer_bytes.empty(),
        "trailer preservation limit was not enforced atomically");
    ok &= require(hasDiagnostic(trailerLimitedContainer, "LPH_TRAILER_LIMIT"), "trailer-limit diagnostic is missing");

    const luraph::EnvelopeAnalysis quoted = luraph::analyzeEnvelope(wrapperFixture("\"LPH@A\\x42\\067\\n\\u{44}\\z   E\""));
    ok &= require(quoted.static_decode.complete, "quoted carrier decoding should complete");
    ok &= require(quoted.carriers.size() == 1, "quoted carrier record is missing");
    if (!quoted.carriers.empty())
    {
        ok &= require(quoted.carriers.front().literal_kind == luraph::CarrierLiteralKind::QuotedString, "quoted carrier kind is incorrect");
        ok &= require(decodedBytes(quoted.carriers.front()) == "LPH@ABC\nDE", "quoted Luau escapes were decoded incorrectly");
    }

    const luraph::EnvelopeAnalysis initialNewline = luraph::analyzeEnvelope(wrapperFixture("[=[\r\nLPH@line1\r\nline2]=]"));
    ok &= require(initialNewline.carriers.size() == 1, "long-bracket newline fixture carrier is missing");
    if (!initialNewline.carriers.empty())
        ok &= require(decodedBytes(initialNewline.carriers.front()) == "LPH@line1\nline2", "long-bracket newlines were not normalized");

    const luraph::EnvelopeAnalysis malformed = luraph::analyzeEnvelope(wrapperFixture("\"LPH@\\xG1\""));
    ok &= require(malformed.complete, "malformed literal should not make the structural token scan incomplete");
    ok &= require(!malformed.static_decode.complete, "malformed literal must make static decoding incomplete");
    ok &= require(malformed.static_decode.carrier_failure_count == 1, "malformed carrier failure metric is incorrect");
    ok &= require(malformed.carriers.size() == 1, "malformed carrier status record is missing");
    if (!malformed.carriers.empty())
    {
        ok &= require(malformed.carriers.front().status == luraph::CarrierDecodeStatus::InvalidLiteral, "malformed carrier status is incorrect");
        ok &= require(malformed.carriers.front().bytes.empty(), "malformed carrier retained partial decoded bytes");
        ok &= require(malformed.carriers.front().error_range.has_value(), "malformed carrier error range is missing");
    }
    ok &= require(hasDiagnostic(malformed, "CARRIER_LITERAL_INVALID"), "malformed carrier diagnostic is missing");

    const luraph::EnvelopeAnalysis interpolated = luraph::analyzeEnvelope(wrapperFixture("`LPH@{dynamic}`"));
    ok &= require(!interpolated.static_decode.complete, "interpolated carrier must remain opaque");
    ok &= require(interpolated.carriers.size() == 1, "interpolated carrier status record is missing");
    if (!interpolated.carriers.empty())
        ok &= require(interpolated.carriers.front().status == luraph::CarrierDecodeStatus::UnsupportedLiteral && interpolated.carriers.front().bytes.empty(),
            "interpolated carrier was evaluated or retained");
    ok &= require(hasDiagnostic(interpolated, "CARRIER_LITERAL_UNSUPPORTED"), "interpolated carrier diagnostic is missing");

    luraph::AnalysisLimits decodeLimit;
    decodeLimit.max_decoded_carrier_bytes = 8;
    const luraph::EnvelopeAnalysis decodeLimited = luraph::analyzeEnvelope(wrapperFixture("\"LPH@0123456789\""), decodeLimit);
    ok &= require(!decodeLimited.static_decode.complete, "byte-limited decoding must be incomplete");
    ok &= require(decodeLimited.static_decode.byte_limit_hit_count == 1, "decode byte-limit metric is incorrect");
    ok &= require(decodeLimited.static_decode.decoded_carrier_bytes == 0, "byte-limited carrier must not contribute partial bytes");
    ok &= require(decodeLimited.carriers.size() == 1 && decodeLimited.carriers.front().bytes.empty(), "byte-limited carrier retained partial bytes");
    ok &= require(hasDiagnostic(decodeLimited, "CARRIER_DECODE_BYTE_LIMIT"), "decode byte-limit diagnostic is missing");

    luraph::AnalysisLimits carrierTrackLimit;
    carrierTrackLimit.max_tracked_blob_candidates = 0;
    const luraph::EnvelopeAnalysis carrierTrackLimited = luraph::analyzeEnvelope(wrapperFixture("\"LPH@tracked\""), carrierTrackLimit);
    ok &= require(carrierTrackLimited.static_decode.carrier_candidate_count == 1, "track-limited carrier candidate was not counted");
    ok &= require(carrierTrackLimited.static_decode.carrier_attempt_count == 0 && carrierTrackLimited.static_decode.carrier_skipped_count == 1,
        "carrier tracking limit metrics are incorrect");
    ok &= require(carrierTrackLimited.carriers.empty(), "track-limited carrier was retained");
    ok &= require(hasDiagnostic(carrierTrackLimited, "CARRIER_TRACK_LIMIT"), "carrier tracking-limit diagnostic is missing");

    luraph::AnalysisLimits readerTrackLimit;
    readerTrackLimit.max_tracked_reader_metadata = 1;
    const luraph::EnvelopeAnalysis readerTrackLimited = luraph::analyzeEnvelope(wrapperFixture("\"LPH@reader\""), readerTrackLimit);
    ok &= require(!readerTrackLimited.static_decode.complete, "reader metadata truncation must make static decoding incomplete");
    ok &= require(readerTrackLimited.static_decode.reader_metadata_count == 1 && readerTrackLimited.static_decode.reader_definition_count == 2,
        "reader tracking limit metrics are incorrect");
    ok &= require(hasDiagnostic(readerTrackLimited, "READER_METADATA_LIMIT"), "reader metadata-limit diagnostic is missing");

    const luraph::EnvelopeAnalysis unsupported = luraph::analyzeEnvelope(fixture("15.0"));
    ok &= require(unsupported.family_detected, "unsupported Luraph version should still be attributed to Luraph");
    ok &= require(!unsupported.version_supported, "v15.0 must not be accepted by the v14.7 adapter");
    ok &= require(hasDiagnostic(unsupported, "UNSUPPORTED_VERSION"), "unsupported version diagnostic is missing");
    ok &= require(!unsupported.source_recovery_attempted, "unsupported version must not claim source recovery");
    ok &= require(!unsupported.static_decode.attempted && unsupported.carriers.empty(), "unsupported version must not decode carrier literals");

    luraph::AnalysisLimits sourceLimit;
    sourceLimit.max_source_bytes = 32;
    const luraph::EnvelopeAnalysis limited = luraph::analyzeEnvelope(supportedSource, sourceLimit);
    ok &= require(!limited.complete, "source-limited scan must be incomplete");
    ok &= require(hasDiagnostic(limited, "SOURCE_LIMIT"), "source limit diagnostic is missing");

    luraph::AnalysisLimits tokenLimit;
    tokenLimit.max_tokens = 8;
    const luraph::EnvelopeAnalysis tokenLimited = luraph::analyzeEnvelope(supportedSource, tokenLimit);
    ok &= require(!tokenLimited.complete, "token-limited scan must be incomplete");
    ok &= require(tokenLimited.family_detected, "banner attribution should survive a token limit");
    ok &= require(hasDiagnostic(tokenLimited, "TOKEN_LIMIT"), "token limit diagnostic is missing");
    ok &= require(!tokenLimited.static_decode.attempted && tokenLimited.carriers.empty(), "token-limited wrapper was treated as proven");

    const luraph::EnvelopeAnalysis plain = luraph::analyzeEnvelope("print(\"plain\")\n");
    ok &= require(!plain.family_detected, "ordinary Luau was falsely attributed to Luraph");
    ok &= require(!plain.source_recovery_attempted, "ordinary analysis must not claim recovery");
    ok &= require(!plain.static_decode.eligible && !plain.static_decode.attempted, "ordinary Luau was sent through static carrier decoding");

    std::string generatedInterpreter = "local V=...;return({yield=coroutine.yield,buffer=buffer,bit=bit32,";
    const std::string generatedPadding(384, 'x');
    for (size_t index = 0; index < 40; ++index)
    {
        if (index > 0)
            generatedInterpreter += ',';
        generatedInterpreter += "handler_" + std::to_string(index) + "=function()local p='" + generatedPadding +
            "';local t={[1]=p,[2]=p};while true do break end;return t[1] end";
    }
    generatedInterpreter += "}):handler_0()";
    const luraph::EnvelopeAnalysis generated = luraph::analyzeEnvelope(generatedInterpreter);
    ok &= require(generated.complete, "generated interpreter scan should complete");
    ok &= require(generated.generated_interpreter, "generated interpreter structure was not recognized");
    ok &= require(generated.family_detected, "generated interpreter was not attributed to Luraph");
    ok &= require(!generated.version_supported, "generated interpreter alone must not claim a banner version");
    ok &= require(generated.confidence.level == luraph::ConfidenceLevel::High, "generated interpreter confidence should be high");
    ok &= require(hasDiagnostic(generated, "LURAPH_GENERATED_INTERPRETER_DETECTED"), "generated interpreter diagnostic is missing");

    const std::string incompleteWrapper =
        "-- This file was protected using Luraph Obfuscator v14.7 [https://lura.ph/]\nlocal payload=[=[LPH@opaque]=]";
    const luraph::EnvelopeAnalysis unproven = luraph::analyzeEnvelope(incompleteWrapper);
    ok &= require(unproven.counts.encoded_blob_candidate_count == 1, "unproven wrapper carrier candidate was not counted");
    ok &= require(!unproven.static_decode.eligible && !unproven.static_decode.attempted, "unproven wrapper carrier was decoded");
    ok &= require(unproven.carriers.empty(), "unproven wrapper retained carrier bytes");
    ok &= require(hasDiagnostic(unproven, "STATIC_DECODE_SKIPPED_UNPROVEN_WRAPPER"), "unproven wrapper skip diagnostic is missing");

    if (!ok)
        return 1;
    std::cout << "luraph-adapter-unit-ok\n";
    return 0;
}
