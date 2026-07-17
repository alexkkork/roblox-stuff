#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace alex::deobfuscator::luraph
{

struct SourceRange
{
    size_t begin = 0;
    size_t end = 0;

    [[nodiscard]] size_t size() const
    {
        return end >= begin ? end - begin : 0;
    }
};

struct ByteSpan
{
    size_t begin = 0;
    size_t end = 0;

    [[nodiscard]] size_t size() const
    {
        return end >= begin ? end - begin : 0;
    }
};

enum class DiagnosticSeverity
{
    Info,
    Warning,
    Error,
};

enum class WrapperKind
{
    None,
    ReturnedTable,
    ReturnedTableMethodDispatch,
};

enum class BlobKind
{
    OpaquePrintable,
    LphMarker,
    LphAmpersand,
    LphDollar,
};

enum class CarrierLiteralKind
{
    QuotedString,
    LongBracketString,
};

enum class CarrierDecodeStatus
{
    NotAttempted,
    DecodedLiteral,
    InvalidLiteral,
    UnsupportedLiteral,
    ByteLimitExceeded,
};

enum class ReaderValueKind
{
    UnsignedInteger,
    SignedInteger,
    FloatingPoint,
    ByteString,
};

enum class ReaderEvidenceKind
{
    IdentifierHint,
    RuntimeMemberBinding,
    BodyVerified,
};

enum class ByteOrder
{
    Unknown,
    LittleEndian,
    BigEndian,
};

enum class ContainerDecodeStatus
{
    NotAttempted,
    Decoded,
    InvalidPrefix,
    MisalignedBody,
    InvalidCharacter,
    Radix85Overflow,
    OutputLimitExceeded,
};

enum class ContainerParseStatus
{
    NotAttempted,
    Parsed,
    StructuralMetadataRecovered,
    UnsupportedSchema,
    Truncated,
    UlebOverflow,
    NonCanonicalUleb,
    CountUnderflow,
    CountLimitExceeded,
    SignedFoldOverflow,
    TrailerLimitExceeded,
};

enum class FamilyKind
{
    Unknown,
    Luraph147LphAmpersand,
    LuaAuthLphDollar,
    InterpreterLike,
};

enum class SupportLevel
{
    None,
    EnvelopeRecognized,
    TransportDecoded,
    StructuralSchemaRecovered,
};

enum class RecordLaneKind
{
    ConstantPoolMode,
    ConstantCount,
    ConstantTag,
    ConstantPayload,
    PrototypeCount,
    PrototypeRecord,
    DescriptorCount,
    DescriptorRecord,
    PrototypeMetadata,
    RangeMapCount,
    RangeMapRecord,
    InstructionCount,
    InstructionWords,
    RelocationTriple,
    RootSelector,
};

enum class ConstantKind
{
    Opaque,
    String,
    Integer,
    Boolean,
    Float,
    Nil,
};

enum class StageKind
{
    ProtectionBanner,
    WrapperConstruction,
    EncodedPayload,
    ReaderSetup,
    InterpreterScaffolding,
    EntrypointDispatch,
};

enum class ConfidenceLevel
{
    None,
    Low,
    Medium,
    High,
};

struct AnalysisLimits
{
    size_t max_source_bytes = 2 * 1024 * 1024;
    size_t max_tokens = 500000;
    size_t max_nesting = 512;
    size_t max_tracked_blob_candidates = 16;
    size_t max_decoded_carrier_bytes = 2 * 1024 * 1024;
    size_t max_decoded_container_bytes = 2 * 1024 * 1024;
    size_t max_container_constants = 100000;
    size_t max_container_prototypes = 10000;
    size_t max_container_instructions = 1000000;
    size_t max_container_descriptors = 200000;
    size_t max_preserved_trailer_bytes = 2 * 1024 * 1024;
    size_t max_tracked_reader_metadata = 32;
    size_t max_diagnostics = 32;
};

struct BannerInfo
{
    bool present = false;
    bool exact_product_marker = false;
    bool official_url_marker = false;
    std::string product;
    std::string version;
    std::optional<unsigned int> major;
    std::optional<unsigned int> minor;
    std::optional<unsigned int> patch;
    std::optional<SourceRange> range;
};

struct LuaAuthLauncherInfo
{
    bool present = false;
    bool exact_assignment_shape = false;
    bool official_url_marker = false;
    bool metadata_removed_from_body = false;
    size_t code_digit_count = 0;
    size_t script_id_byte_count = 0;
    std::optional<SourceRange> range;
    std::optional<SourceRange> protected_body_range;
};

struct WrapperShape
{
    WrapperKind kind = WrapperKind::None;
    bool top_level_return = false;
    bool parenthesized_table = false;
    bool balanced_table = false;
    bool zero_argument_method_call = false;
    bool forwards_varargs = false;
    bool consumes_entire_chunk = false;
    std::string method_name;
    size_t table_field_count = 0;
    size_t function_member_count = 0;
    std::optional<SourceRange> table_range;
    std::optional<SourceRange> invocation_range;
};

struct EnvelopeCounts
{
    size_t source_bytes = 0;
    size_t token_count = 0;
    size_t comment_count = 0;
    size_t identifier_count = 0;
    size_t numeric_literal_count = 0;
    size_t string_literal_count = 0;
    size_t string_literal_source_bytes = 0;
    size_t encoded_string_candidate_count = 0;
    size_t encoded_blob_candidate_count = 0;
    size_t encoded_blob_source_bytes = 0;
    size_t table_constructor_count = 0;
    size_t function_literal_count = 0;
    size_t loop_construct_count = 0;
    size_t indexed_access_count = 0;
    size_t reader_primitive_reference_count = 0;
};

struct BlobCandidate
{
    BlobKind kind = BlobKind::OpaquePrintable;
    SourceRange range;
    size_t source_bytes = 0;
    size_t distinct_byte_count = 0;
    double printable_ratio = 0.0;
    double whitespace_ratio = 0.0;
    bool long_bracket_literal = false;
    bool has_lph_marker = false;
};

struct CarrierExtraction
{
    BlobKind kind = BlobKind::OpaquePrintable;
    CarrierLiteralKind literal_kind = CarrierLiteralKind::QuotedString;
    CarrierDecodeStatus status = CarrierDecodeStatus::NotAttempted;
    SourceRange literal_range;
    SourceRange content_range;
    std::optional<SourceRange> error_range;
    size_t literal_source_bytes = 0;
    size_t decoded_byte_count = 0;
    std::optional<size_t> lph_marker_offset;
    std::optional<size_t> container_index;
    std::vector<unsigned char> bytes;
};

struct ConstantMetadata
{
    size_t index = 0;
    unsigned char tag = 0;
    ConstantKind kind = ConstantKind::Nil;
    ByteSpan span;
    ByteSpan tag_span;
    std::optional<ByteSpan> length_span;
    ByteSpan data_span;
    size_t data_bytes = 0;
    std::optional<int64_t> signed_integer_value;
    std::optional<uint64_t> unsigned_integer_value;
    std::optional<bool> boolean_value;
    std::optional<float> float32_value;
    std::optional<double> float64_value;
    std::optional<uint32_t> float32_bits;
    std::optional<uint64_t> float64_bits;
    std::vector<unsigned char> string_bytes;
};

struct DescriptorMetadata
{
    size_t index = 0;
    uint64_t raw_value = 0;
    unsigned int kind = 0;
    uint64_t referenced_index = 0;
    // The verified LuaAuth LPH$ schema proves that descriptors are closure
    // captures. Other container families retain only the generic split above.
    bool capture_semantics_verified = false;
    unsigned int capture_kind_code = 0;
    uint64_t capture_source_index = 0;
    std::optional<size_t> parent_prototype_index;
    bool source_index_validated = false;
    bool source_index_in_bounds = false;
    ByteSpan span;
};

struct PrototypeReferenceMetadata
{
    size_t instruction_index = 0;
    size_t operand_word_index = 0;
    int64_t raw_operand = 0;
    int64_t wrapper_index = 0;
    std::optional<size_t> metadata_index;
    bool in_bounds = false;
    int64_t opcode = 0;
    bool closure_target = false;
    size_t capture_descriptor_count = 0;
    ByteSpan span;
};

struct InstructionWordMetadata
{
    int64_t value = 0;
    ByteSpan span;
};

struct InstructionMetadata
{
    size_t index = 0;
    ByteSpan span;
    std::array<InstructionWordMetadata, 4> words{};
};

struct PrototypeMetadata
{
    size_t index = 0;
    ByteSpan span;
    uint64_t meta = 0;
    ByteSpan meta_span;
    uint64_t secondary_meta = 0;
    ByteSpan secondary_meta_span;
    uint64_t register_capacity = 0;
    bool register_capacity_verified = false;
    size_t range_map_count = 0;
    ByteSpan range_map_count_span;
    ByteSpan range_map_span;
    size_t instruction_count = 0;
    ByteSpan instruction_count_span;
    ByteSpan instruction_words_span;
    size_t descriptor_count = 0;
    ByteSpan descriptor_count_span;
    ByteSpan descriptors_span;
    uint64_t final_value = 0;
    ByteSpan final_span;
    std::vector<InstructionMetadata> instructions;
    std::vector<DescriptorMetadata> descriptors;
    std::vector<PrototypeReferenceMetadata> prototype_references;
    size_t incoming_prototype_reference_count = 0;
    std::optional<size_t> parent_prototype_index;
};

struct ContainerAnalysis
{
    size_t carrier_index = 0;
    ContainerDecodeStatus decode_status = ContainerDecodeStatus::NotAttempted;
    ContainerParseStatus parse_status = ContainerParseStatus::NotAttempted;
    size_t encoded_carrier_bytes = 0;
    size_t encoded_body_bytes = 0;
    size_t radix85_group_count = 0;
    size_t radix85_zero_group_count = 0;
    size_t decoded_bytes = 0;
    std::string decoded_sha256;
    unsigned char marker = 0;
    ByteOrder transport_byte_order = ByteOrder::Unknown;
    bool randomized_tag_semantics = false;
    bool tag_semantic_mapping_recovered = false;
    std::optional<size_t> encoded_error_offset;
    std::optional<size_t> parse_error_offset;
    size_t constant_count = 0;
    ByteSpan constant_count_span;
    unsigned char constant_pool_mode = 0;
    ByteSpan constant_pool_mode_span;
    ByteSpan constants_span;
    size_t prototype_count = 0;
    ByteSpan prototype_count_span;
    ByteSpan prototypes_span;
    size_t instruction_count = 0;
    size_t descriptor_count = 0;
    uint64_t root_selector = 0;
    std::optional<size_t> root_metadata_index;
    bool root_selector_in_bounds = false;
    bool root_selector_graph_validated = false;
    ByteSpan root_selector_span;
    size_t prototype_reference_count = 0;
    size_t valid_prototype_reference_count = 0;
    size_t invalid_prototype_reference_count = 0;
    size_t closure_target_count = 0;
    size_t generic_prototype_reference_count = 0;
    size_t prototypes_with_capture_descriptors = 0;
    size_t validated_capture_descriptor_count = 0;
    size_t invalid_capture_descriptor_count = 0;
    bool prototype_graph_complete = false;
    ByteSpan trailer_span;
    std::vector<ConstantMetadata> constants;
    std::vector<PrototypeMetadata> prototypes;
    std::vector<unsigned char> trailer_bytes;
    std::vector<unsigned char> decoded_data;
};

struct ContainerMetrics
{
    size_t candidate_count = 0;
    size_t attempt_count = 0;
    size_t decoded_count = 0;
    size_t parsed_count = 0;
    size_t structural_count = 0;
    size_t failure_count = 0;
    size_t encoded_body_bytes = 0;
    size_t radix85_group_count = 0;
    size_t radix85_zero_group_count = 0;
    size_t decoded_bytes = 0;
    size_t constant_count = 0;
    size_t prototype_count = 0;
    size_t instruction_count = 0;
    size_t descriptor_count = 0;
    size_t trailer_bytes = 0;
};

struct ReaderMetadata
{
    std::string name;
    // Type and width are name-derived hints; the function body is never evaluated.
    ReaderValueKind value_kind = ReaderValueKind::UnsignedInteger;
    ByteOrder byte_order = ByteOrder::Unknown;
    size_t bit_width = 0;
    size_t byte_width = 0;
    size_t reference_count = 0;
    bool definition_present = false;
    bool inferred_from_identifier = true;
    bool implementation_verified = false;
    SourceRange name_range;
    std::optional<SourceRange> definition_range;
    ReaderEvidenceKind evidence = ReaderEvidenceKind::IdentifierHint;
    std::optional<size_t> state_slot;
    bool cursor_advancing = false;
    size_t cursor_advance_bytes = 0;
};

struct ReaderBindingMetadata
{
    std::string primitive;
    ReaderValueKind value_kind = ReaderValueKind::UnsignedInteger;
    ReaderEvidenceKind evidence = ReaderEvidenceKind::IdentifierHint;
    ByteOrder byte_order = ByteOrder::Unknown;
    size_t bit_width = 0;
    size_t byte_width = 0;
    size_t state_slot = 0;
    bool cursor_advancing = false;
    size_t cursor_advance_bytes = 0;
    SourceRange evidence_range;
};

struct RecordLaneMetadata
{
    RecordLaneKind kind = RecordLaneKind::ConstantPoolMode;
    size_t order = 0;
    std::optional<size_t> reader_slot;
    std::optional<uint64_t> numeric_bias;
    bool repeated = false;
    bool semantics_known = false;
    SourceRange evidence_range;
};

struct RootCandidateMetadata
{
    bool present = false;
    bool prototype_table_index = false;
    bool selector_value_known = false;
    bool selector_in_bounds = false;
    bool selector_graph_validated = false;
    std::optional<size_t> reader_slot;
    std::optional<uint64_t> wrapper_index;
    std::optional<size_t> metadata_index;
    ByteSpan selector_span;
    SourceRange evidence_range;
};

struct TagScheduleMetadata
{
    bool present = false;
    bool randomized = false;
    bool semantic_mapping_recovered = false;
    std::optional<size_t> tag_reader_slot;
    std::vector<uint64_t> decision_boundaries;
    SourceRange evidence_range;
};

struct KeyScheduleMetadata
{
    bool candidate_present = false;
    bool applied_to_container_proven = false;
    bool semantic_mapping_recovered = false;
    size_t opaque_word_count = 0;
    SourceRange evidence_range;
};

struct LphDollarSchemaMetadata
{
    bool detected = false;
    bool reader_bindings_verified = false;
    bool variable_integer_reader_verified = false;
    bool record_lanes_recovered = false;
    bool root_selection_recovered = false;
    ByteOrder scalar_byte_order = ByteOrder::Unknown;
    std::optional<size_t> variable_integer_reader_slot;
    std::vector<ReaderBindingMetadata> reader_bindings;
    std::vector<RecordLaneMetadata> record_lanes;
    RootCandidateMetadata root;
    TagScheduleMetadata tags;
    KeyScheduleMetadata keys;
};

struct StaticDecodeMetrics
{
    bool eligible = false;
    bool attempted = false;
    bool complete = false;
    bool literal_complete = false;
    bool transport_complete = false;
    bool schema_complete = false;
    bool semantic_complete = false;
    // These fields refer to protected-program/VM decoding, not container framing.
    bool payload_decode_attempted = false;
    bool payload_decoded = false;
    size_t carrier_candidate_count = 0;
    size_t carrier_attempt_count = 0;
    size_t carrier_decoded_count = 0;
    size_t carrier_failure_count = 0;
    size_t carrier_skipped_count = 0;
    size_t carrier_literal_source_bytes = 0;
    size_t decoded_carrier_bytes = 0;
    size_t byte_limit_hit_count = 0;
    size_t reader_metadata_count = 0;
    size_t reader_definition_count = 0;
    size_t reader_reference_count = 0;
};

struct Stage
{
    StageKind kind = StageKind::ProtectionBanner;
    double confidence = 0.0;
    std::string summary;
    std::optional<SourceRange> range;
};

struct ConfidenceEvidence
{
    std::string code;
    double weight = 0.0;
    std::string description;
};

struct Confidence
{
    double score = 0.0;
    ConfidenceLevel level = ConfidenceLevel::None;
    std::vector<ConfidenceEvidence> evidence;
};

struct Diagnostic
{
    DiagnosticSeverity severity = DiagnosticSeverity::Info;
    std::string code;
    std::string message;
    std::optional<SourceRange> range;
};

struct EnvelopeAnalysis
{
    bool complete = false;
    bool bounded = true;
    bool family_detected = false;
    bool version_supported = false;
    FamilyKind family_kind = FamilyKind::Unknown;
    SupportLevel support_level = SupportLevel::None;
    bool generated_interpreter = false;
    bool source_recovery_attempted = false;
    BannerInfo banner;
    LuaAuthLauncherInfo luaauth_launcher;
    WrapperShape wrapper;
    EnvelopeCounts counts;
    std::vector<BlobCandidate> blobs;
    StaticDecodeMetrics static_decode;
    std::vector<CarrierExtraction> carriers;
    ContainerMetrics container_metrics;
    std::vector<ContainerAnalysis> containers;
    std::vector<ReaderMetadata> readers;
    LphDollarSchemaMetadata lph_dollar_schema;
    std::vector<Stage> stages;
    Confidence confidence;
    std::vector<Diagnostic> diagnostics;
};

// Performs source-only structural analysis plus bounded decoding of exact Luau literals
// and proven LPH& container framing. It never evaluates input or recovers source.
EnvelopeAnalysis analyzeEnvelope(std::string_view source, const AnalysisLimits& limits = {});

// Builds a side-effect-free, call-focused trace probe for the supported v14.7
// interpreter shape. The returned source remains protected and is intended only
// for bounded execution by the offline runtime.
std::optional<std::string> buildCallTraceProbe(
    std::string_view source,
    uint64_t fullTraceStart = 0,
    uint64_t fullTraceEnd = 0);

std::string_view toString(DiagnosticSeverity severity);
std::string_view toString(WrapperKind kind);
std::string_view toString(BlobKind kind);
std::string_view toString(CarrierLiteralKind kind);
std::string_view toString(CarrierDecodeStatus status);
std::string_view toString(ReaderValueKind kind);
std::string_view toString(ReaderEvidenceKind kind);
std::string_view toString(ByteOrder byteOrder);
std::string_view toString(ContainerDecodeStatus status);
std::string_view toString(ContainerParseStatus status);
std::string_view toString(FamilyKind kind);
std::string_view toString(SupportLevel level);
std::string_view toString(RecordLaneKind kind);
std::string_view toString(ConstantKind kind);
std::string_view toString(StageKind kind);
std::string_view toString(ConfidenceLevel level);

} // namespace alex::deobfuscator::luraph
