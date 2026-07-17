#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace rbx::runtime
{

struct NilValue
{
    friend constexpr bool operator==(NilValue, NilValue) = default;
};

struct OpaqueValue
{
    std::shared_ptr<const void> storage;
    std::string typeName;

    friend bool operator==(const OpaqueValue& lhs, const OpaqueValue& rhs)
    {
        return lhs.storage == rhs.storage && lhs.typeName == rhs.typeName;
    }
};

class RuntimeValue
{
public:
    using Storage = std::variant<NilValue, bool, int64_t, double, std::string, OpaqueValue>;

    RuntimeValue() = default;
    RuntimeValue(NilValue value)
        : value_(value)
    {
    }
    RuntimeValue(bool value)
        : value_(value)
    {
    }
    RuntimeValue(int value)
        : value_(int64_t(value))
    {
    }
    RuntimeValue(int64_t value)
        : value_(value)
    {
    }
    RuntimeValue(double value)
        : value_(value)
    {
    }
    RuntimeValue(std::string value)
        : value_(std::move(value))
    {
    }
    RuntimeValue(const char* value)
        : value_(std::string(value ? value : ""))
    {
    }
    RuntimeValue(OpaqueValue value)
        : value_(std::move(value))
    {
    }

    static RuntimeValue nil()
    {
        return NilValue{};
    }

    template<typename T>
    static RuntimeValue opaque(std::shared_ptr<const T> value, std::string typeName)
    {
        return OpaqueValue{std::static_pointer_cast<const void>(std::move(value)), std::move(typeName)};
    }

    bool isNil() const
    {
        return std::holds_alternative<NilValue>(value_);
    }

    const Storage& storage() const
    {
        return value_;
    }

    template<typename T>
    const T* getIf() const
    {
        return std::get_if<T>(&value_);
    }

    std::string typeName() const
    {
        if (std::holds_alternative<NilValue>(value_))
            return "nil";
        if (std::holds_alternative<bool>(value_))
            return "boolean";
        if (std::holds_alternative<int64_t>(value_) || std::holds_alternative<double>(value_))
            return "number";
        if (std::holds_alternative<std::string>(value_))
            return "string";
        return std::get<OpaqueValue>(value_).typeName;
    }

    friend bool operator==(const RuntimeValue&, const RuntimeValue&) = default;

private:
    Storage value_ = NilValue{};
};

using RuntimeValues = std::vector<RuntimeValue>;

} // namespace rbx::runtime
