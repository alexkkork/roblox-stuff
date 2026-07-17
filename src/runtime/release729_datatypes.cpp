#include "release729_datatypes.hpp"

#include "runtime_context.hpp"
#include "../runtime_v2.hpp"

#include "lualib.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <deque>
#include <iomanip>
#include <limits>
#include <map>
#include <memory>
#include <new>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <variant>
#include <vector>

namespace rbx::runtime
{
namespace
{

enum class Kind : uint8_t
{
    Axes,
    Faces,
    Region3int16,
    Font,
    FloatCurveKey,
    RotationCurveKey,
    ValueCurveKey,
    Content,
    DockWidgetPluginGuiInfo,
    CatalogSearchParams,
    SecurityCapabilities,
    PathWaypoint,
    Path2DControlPoint,
    SharedTable,
};

constexpr int kFirstTag = 64;
constexpr int kReferenceSlots = 12;
constexpr int tagFor(Kind kind)
{
    return kFirstTag + static_cast<int>(kind);
}

struct Value
{
    Kind kind = Kind::Axes;
    uint32_t mask = 0;
    std::array<double, 8> numbers{};
    std::array<bool, 4> flags{};
    std::array<int, kReferenceSlots> references{};
    std::string primary;
    std::string secondary;
    std::vector<std::string> names;

    Value()
    {
        references.fill(LUA_NOREF);
    }
};

constexpr std::array<const char*, 14> kTypeNames = {
    "Axes",
    "Faces",
    "Region3int16",
    "Font",
    "FloatCurveKey",
    "RotationCurveKey",
    "ValueCurveKey",
    "Content",
    "DockWidgetPluginGuiInfo",
    "CatalogSearchParams",
    "SecurityCapabilities",
    "PathWaypoint",
    "Path2DControlPoint",
    "SharedTable",
};

const char* typeName(Kind kind)
{
    return kTypeNames.at(static_cast<size_t>(kind));
}

void destroyValue(lua_State* state, void* pointer)
{
    auto* value = static_cast<Value*>(pointer);
    for (int reference : value->references)
    {
        if (reference != LUA_NOREF)
            lua_unref(state, reference);
    }
    value->~Value();
}

Value* valueAt(lua_State* state, int index)
{
    if (!lua_isuserdata(state, index))
        luaL_typeerror(state, index, "Roblox datatype");
    const int tag = lua_userdatatag(state, index);
    if (tag < kFirstTag || tag >= kFirstTag + static_cast<int>(kTypeNames.size()))
        luaL_typeerror(state, index, "Roblox datatype");
    return static_cast<Value*>(lua_touserdatatagged(state, index, tag));
}

Value* valueAt(lua_State* state, int index, Kind expected)
{
    Value* value = valueAt(state, index);
    if (value->kind != expected)
        luaL_typeerror(state, index, typeName(expected));
    return value;
}

Value* pushValue(lua_State* state, Kind kind)
{
    void* storage = lua_newuserdatatagged(state, sizeof(Value), tagFor(kind));
    auto* value = new (storage) Value();
    value->kind = kind;
    lua_getuserdatametatable(state, tagFor(kind));
    lua_setmetatable(state, -2);
    return value;
}

void setReference(lua_State* state, Value& value, size_t slot, int index)
{
    if (slot >= value.references.size())
        throw std::out_of_range("release-729 datatype reference slot");
    if (value.references[slot] != LUA_NOREF)
        lua_unref(state, value.references[slot]);
    index = lua_absindex(state, index);
    lua_pushvalue(state, index);
    value.references[slot] = lua_ref(state, -1);
    lua_pop(state, 1);
}

void pushReference(lua_State* state, const Value& value, size_t slot)
{
    if (slot >= value.references.size() || value.references[slot] == LUA_NOREF)
        lua_pushnil(state);
    else
        lua_getref(state, value.references[slot]);
}

std::string stackString(lua_State* state, int index)
{
    size_t length = 0;
    const char* data = lua_tolstring(state, index, &length);
    return data ? std::string(data, length) : std::string();
}

std::string valueType(lua_State* state, int index)
{
    index = lua_absindex(state, index);
    if (lua_isuserdata(state, index) && lua_getmetatable(state, index))
    {
        lua_rawgetfield(state, -1, "__type");
        if (lua_isstring(state, -1))
        {
            std::string result = stackString(state, -1);
            lua_pop(state, 2);
            return result;
        }
        lua_pop(state, 2);
    }
    lua_getglobal(state, "typeof");
    if (lua_isfunction(state, -1))
    {
        lua_pushvalue(state, index);
        if (lua_pcall(state, 1, 1, 0) == LUA_OK && lua_isstring(state, -1))
        {
            std::string result = stackString(state, -1);
            lua_pop(state, 1);
            return result;
        }
        lua_pop(state, 1);
    }
    else
        lua_pop(state, 1);
    return lua_typename(state, lua_type(state, index));
}

void requireType(lua_State* state, int index, std::string_view expected)
{
    if (valueType(state, index) != expected)
        luaL_error(state, "invalid argument #%d (%s expected)", index, std::string(expected).c_str());
}

bool enumIdentity(lua_State* state, int index, std::string& enumType, std::string& item)
{
    if (valueType(state, index) != "EnumItem")
        return false;
    index = lua_absindex(state, index);
    lua_getfield(state, index, "Name");
    item = stackString(state, -1);
    lua_pop(state, 1);
    lua_getfield(state, index, "EnumType");
    lua_getfield(state, -1, "Name");
    enumType = stackString(state, -1);
    lua_pop(state, 2);
    return !enumType.empty() && !item.empty();
}

bool isEnum(lua_State* state, int index, std::string_view expectedType, std::string* item = nullptr)
{
    std::string actualType;
    std::string actualItem;
    if (!enumIdentity(state, index, actualType, actualItem) || actualType != expectedType)
        return false;
    if (item)
        *item = std::move(actualItem);
    return true;
}

void requireEnum(lua_State* state, int index, std::string_view expectedType)
{
    if (!isEnum(state, index, expectedType))
        luaL_error(state, "invalid argument #%d (Enum.%s expected)", index, std::string(expectedType).c_str());
}

void pushEnum(lua_State* state, const char* enumType, const char* item)
{
    lua_getglobal(state, "Enum");
    lua_getfield(state, -1, enumType);
    lua_remove(state, -2);
    lua_getfield(state, -1, item);
    lua_remove(state, -2);
}

double enumNumericValue(lua_State* state, int index)
{
    index = lua_absindex(state, index);
    lua_getfield(state, index, "Value");
    const double value = lua_tonumber(state, -1);
    lua_pop(state, 1);
    return value;
}

bool finite(double value)
{
    return std::isfinite(value);
}

double checkedFinite(lua_State* state, int index, const char* description)
{
    const double result = luaL_checknumber(state, index);
    if (!finite(result))
        luaL_error(state, "%s must be finite", description);
    return result;
}

int callConstructor(lua_State* state, const char* global, const char* member, int argumentCount)
{
    const int firstArgument = lua_gettop(state) - argumentCount + 1;
    lua_getglobal(state, global);
    lua_getfield(state, -1, member);
    lua_remove(state, -2);
    lua_insert(state, firstArgument);
    if (lua_pcall(state, argumentCount, 1, 0) != LUA_OK)
    {
        lua_error(state);
        return 0;
    }
    return 1;
}

void pushDefaultUDim2(lua_State* state)
{
    callConstructor(state, "UDim2", "new", 0);
}

void pushVector3int16(lua_State* state, double x, double y, double z)
{
    lua_pushnumber(state, x);
    lua_pushnumber(state, y);
    lua_pushnumber(state, z);
    callConstructor(state, "Vector3int16", "new", 3);
}

void readVector3int16(lua_State* state, int index, std::array<double, 3>& output)
{
    requireType(state, index, "Vector3int16");
    index = lua_absindex(state, index);
    for (size_t component = 0; component < 3; ++component)
    {
        static constexpr const char* names[] = {"X", "Y", "Z"};
        lua_getfield(state, index, names[component]);
        output[component] = luaL_checknumber(state, -1);
        lua_pop(state, 1);
    }
}

std::string joined(const std::vector<std::string>& values, std::string_view separator)
{
    std::ostringstream output;
    for (size_t index = 0; index < values.size(); ++index)
    {
        if (index)
            output << separator;
        output << values[index];
    }
    return output.str();
}

void normalizeNames(std::vector<std::string>& values)
{
    std::sort(values.begin(), values.end());
    values.erase(std::unique(values.begin(), values.end()), values.end());
}

int l_axes_new(lua_State* state)
{
    Value* value = pushValue(state, Kind::Axes);
    for (int index = 1; index <= lua_gettop(state) - 1; ++index)
    {
        std::string enumType;
        std::string item;
        if (!enumIdentity(state, index, enumType, item))
            continue;
        if (enumType == "Axis")
        {
            if (item == "X") value->mask |= 1u;
            if (item == "Y") value->mask |= 2u;
            if (item == "Z") value->mask |= 4u;
        }
        else if (enumType == "NormalId")
        {
            if (item == "Left" || item == "Right") value->mask |= 1u;
            if (item == "Top" || item == "Bottom") value->mask |= 2u;
            if (item == "Front" || item == "Back") value->mask |= 4u;
        }
    }
    return 1;
}

int l_faces_new(lua_State* state)
{
    Value* value = pushValue(state, Kind::Faces);
    for (int index = 1; index <= lua_gettop(state) - 1; ++index)
    {
        std::string item;
        if (!isEnum(state, index, "NormalId", &item))
            continue; // Roblox silently ignores non-NormalId arguments.
        static constexpr std::array<const char*, 6> names = {"Right", "Top", "Back", "Left", "Bottom", "Front"};
        for (size_t bit = 0; bit < names.size(); ++bit)
            if (item == names[bit]) value->mask |= uint32_t(1) << bit;
    }
    return 1;
}

int l_region3int16_new(lua_State* state)
{
    std::array<double, 3> minimum{};
    std::array<double, 3> maximum{};
    readVector3int16(state, 1, minimum);
    readVector3int16(state, 2, maximum);
    Value* value = pushValue(state, Kind::Region3int16);
    for (size_t index = 0; index < 3; ++index)
    {
        value->numbers[index] = minimum[index];
        value->numbers[index + 3] = maximum[index];
    }
    return 1;
}

void setDefaultEnumReference(lua_State* state, Value& value, size_t slot, const char* enumType, const char* item)
{
    pushEnum(state, enumType, item);
    setReference(state, value, slot, -1);
    lua_pop(state, 1);
}

void initializeFont(lua_State* state, Value& value, int argumentCount, int familyIndex, int weightIndex, int styleIndex)
{
    if (valueType(state, familyIndex) == "Content")
        setReference(state, value, 0, familyIndex);
    else
    {
        size_t length = 0;
        const char* family = luaL_checklstring(state, familyIndex, &length);
        value.primary.assign(family, length);
    }
    if (weightIndex > argumentCount || lua_isnil(state, weightIndex))
        setDefaultEnumReference(state, value, 1, "FontWeight", "Regular");
    else
    {
        requireEnum(state, weightIndex, "FontWeight");
        setReference(state, value, 1, weightIndex);
    }
    if (styleIndex > argumentCount || lua_isnil(state, styleIndex))
        setDefaultEnumReference(state, value, 2, "FontStyle", "Normal");
    else
    {
        requireEnum(state, styleIndex, "FontStyle");
        setReference(state, value, 2, styleIndex);
    }
}

int l_font_new(lua_State* state)
{
    const int argumentCount = lua_gettop(state);
    if (argumentCount < 1)
        luaL_error(state, "missing argument #1 to 'new' (Content or string expected)");
    Value* value = pushValue(state, Kind::Font);
    initializeFont(state, *value, argumentCount, 1, 2, 3);
    return 1;
}

int pushFontWithFamily(lua_State* state, std::string family, int argumentCount, int weightIndex, int styleIndex)
{
    Value* value = pushValue(state, Kind::Font);
    value->primary = std::move(family);
    if (weightIndex > argumentCount || lua_isnil(state, weightIndex)) setDefaultEnumReference(state, *value, 1, "FontWeight", "Regular");
    else { requireEnum(state, weightIndex, "FontWeight"); setReference(state, *value, 1, weightIndex); }
    if (styleIndex > argumentCount || lua_isnil(state, styleIndex)) setDefaultEnumReference(state, *value, 2, "FontStyle", "Normal");
    else { requireEnum(state, styleIndex, "FontStyle"); setReference(state, *value, 2, styleIndex); }
    return 1;
}

int l_font_from_name(lua_State* state)
{
    const int argumentCount = lua_gettop(state);
    const std::string name = luaL_checkstring(state, 1);
    if (name.empty() || !std::all_of(name.begin(), name.end(), [](unsigned char character) {
            return std::isalnum(character) || character == '_' || character == '-';
        }))
        luaL_error(state, "Font.fromName name may contain only letters, digits, underscores, and hyphens");
    return pushFontWithFamily(state, "rbxasset://fonts/families/" + name + ".json", argumentCount, 2, 3);
}

int l_font_from_id(lua_State* state)
{
    const int argumentCount = lua_gettop(state);
    const double input = checkedFinite(state, 1, "Font asset id");
    if (input < 0 || std::floor(input) != input || input > 9007199254740991.0)
        luaL_error(state, "Font asset id must be a non-negative integer");
    std::ostringstream family;
    family << "rbxassetid://" << std::fixed << std::setprecision(0) << input;
    return pushFontWithFamily(state, family.str(), argumentCount, 2, 3);
}

int l_font_from_enum(lua_State* state)
{
    std::string item;
    if (!isEnum(state, 1, "Font", &item) || item == "Unknown")
        luaL_error(state, "invalid argument #1 to 'fromEnum' (Enum.Font expected, excluding Unknown)");
    std::string familyName = item;
    std::string weight = "Regular";
    if (familyName.size() >= 4 && familyName.substr(familyName.size() - 4) == "Bold")
    {
        familyName.resize(familyName.size() - 4);
        weight = "Bold";
    }
    else if (familyName.size() >= 6 && familyName.substr(familyName.size() - 6) == "Medium")
    {
        familyName.resize(familyName.size() - 6);
        weight = "Medium";
    }
    Value* value = pushValue(state, Kind::Font);
    value->primary = "rbxasset://fonts/families/" + familyName + ".json";
    setDefaultEnumReference(state, *value, 1, "FontWeight", weight.c_str());
    setDefaultEnumReference(state, *value, 2, "FontStyle", "Normal");
    return 1;
}

int curveNew(lua_State* state, Kind kind)
{
    const int argumentCount = lua_gettop(state);
    const double time = checkedFinite(state, 1, "curve key time");
    if (kind == Kind::FloatCurveKey)
        checkedFinite(state, 2, "curve key value");
    else if (kind == Kind::RotationCurveKey)
        requireType(state, 2, "CFrame");
    Value* value = pushValue(state, kind);
    value->numbers[0] = time;
    setReference(state, *value, 0, 2);
    if (argumentCount < 3 || lua_isnil(state, 3))
        setDefaultEnumReference(state, *value, 1, "KeyInterpolationMode", "Linear");
    else
    {
        requireEnum(state, 3, "KeyInterpolationMode");
        setReference(state, *value, 1, 3);
    }
    return 1;
}

int l_float_curve_new(lua_State* state) { return curveNew(state, Kind::FloatCurveKey); }
int l_rotation_curve_new(lua_State* state) { return curveNew(state, Kind::RotationCurveKey); }
int l_value_curve_new(lua_State* state) { return curveNew(state, Kind::ValueCurveKey); }

int pushContentNone(lua_State* state)
{
    lua_getglobal(state, "Content");
    lua_getfield(state, -1, "none");
    lua_remove(state, -2);
    return 1;
}

int l_content_from_uri(lua_State* state)
{
    size_t length = 0;
    const char* uri = luaL_checklstring(state, 1, &length);
    if (length == 0)
        return pushContentNone(state);
    Value* value = pushValue(state, Kind::Content);
    value->mask = 1;
    value->primary.assign(uri, length);
    return 1;
}

int l_content_from_asset_id(lua_State* state)
{
    const double id = checkedFinite(state, 1, "Content asset id");
    if (id < 0 || std::floor(id) != id || id > 9007199254740991.0)
        luaL_error(state, "Content asset id must be a non-negative integer");
    if (id == 0)
        return pushContentNone(state);
    Value* value = pushValue(state, Kind::Content);
    value->mask = 1;
    std::ostringstream uri;
    uri << "rbxassetid://" << std::fixed << std::setprecision(0) << id;
    value->primary = uri.str();
    return 1;
}

int l_content_from_object(lua_State* state)
{
    if (lua_isnoneornil(state, 1) || (!rbx::v2::isInstance(state, 1) && valueType(state, 1) != "Instance"))
        luaL_error(state, "Content.fromObject expects a non-nil Object");
    Value* value = pushValue(state, Kind::Content);
    value->mask = 2;
    setReference(state, *value, 0, 1);
    return 1;
}

int l_dock_widget_new(lua_State* state)
{
    const int argumentCount = lua_gettop(state);
    Value* value = pushValue(state, Kind::DockWidgetPluginGuiInfo);
    if (argumentCount < 1 || lua_isnil(state, 1)) setDefaultEnumReference(state, *value, 0, "InitialDockState", "Right");
    else { requireEnum(state, 1, "InitialDockState"); setReference(state, *value, 0, 1); }
    value->flags[0] = argumentCount >= 2 && lua_toboolean(state, 2) != 0;
    value->flags[1] = argumentCount >= 3 && lua_toboolean(state, 3) != 0;
    for (int index = 4; index <= 7; ++index)
    {
        const double number = index <= argumentCount ? luaL_optnumber(state, index, 0) : 0;
        if (!finite(number)) luaL_error(state, "DockWidgetPluginGuiInfo dimensions must be finite");
        value->numbers[index - 4] = number;
    }
    return 1;
}

void setFrozenArray(lua_State* state, Value& value, size_t slot, int index, std::string_view enumType)
{
    luaL_checktype(state, index, LUA_TTABLE);
    index = lua_absindex(state, index);
    const int count = lua_objlen(state, index);
    lua_createtable(state, count, 0);
    for (int item = 1; item <= count; ++item)
    {
        lua_rawgeti(state, index, item);
        requireEnum(state, -1, enumType);
        lua_rawseti(state, -2, item);
    }
    lua_setreadonly(state, -1, true);
    setReference(state, value, slot, -1);
    lua_pop(state, 1);
}

int l_catalog_search_new(lua_State* state)
{
    if (lua_gettop(state) != 0)
        luaL_error(state, "CatalogSearchParams.new expects no arguments");
    Value* value = pushValue(state, Kind::CatalogSearchParams);
    setDefaultEnumReference(state, *value, 0, "CatalogSortType", "Relevance");
    setDefaultEnumReference(state, *value, 1, "CatalogSortAggregation", "AllTime");
    setDefaultEnumReference(state, *value, 2, "CatalogCategoryFilter", "None");
    setDefaultEnumReference(state, *value, 3, "SalesTypeFilter", "All");
    lua_newtable(state); lua_setreadonly(state, -1, true); setReference(state, *value, 4, -1); lua_pop(state, 1);
    lua_newtable(state); lua_setreadonly(state, -1, true); setReference(state, *value, 5, -1); lua_pop(state, 1);
    setDefaultEnumReference(state, *value, 6, "CreatorTypeFilter", "All");
    value->numbers[3] = 30;
    return 1;
}

bool isCapabilitiesValue(lua_State* state, int index)
{
    return lua_isuserdata(state, index) && lua_userdatatag(state, index) == tagFor(Kind::SecurityCapabilities);
}

void addCapabilitiesFromArguments(lua_State* state, std::vector<std::string>& names, int first)
{
    const int top = lua_gettop(state);
    for (int index = first; index <= top; ++index)
    {
        if (isCapabilitiesValue(state, index))
        {
            const Value* other = valueAt(state, index, Kind::SecurityCapabilities);
            names.insert(names.end(), other->names.begin(), other->names.end());
            continue;
        }
        std::string item;
        if (!isEnum(state, index, "SecurityCapability", &item))
            luaL_error(state, "SecurityCapabilities expects Enum.SecurityCapability values or another SecurityCapabilities value");
        names.push_back(std::move(item));
    }
    normalizeNames(names);
}

int pushCapabilities(lua_State* state, std::vector<std::string> names)
{
    Value* value = pushValue(state, Kind::SecurityCapabilities);
    value->names = std::move(names);
    normalizeNames(value->names);
    return 1;
}

int l_capabilities_new(lua_State* state)
{
    std::vector<std::string> names;
    addCapabilitiesFromArguments(state, names, 1);
    return pushCapabilities(state, std::move(names));
}

int l_capabilities_from_current(lua_State* state)
{
    std::vector<std::string> names;
    if (RuntimeContext* context = RuntimeContext::from(state))
    {
        const CapabilitySet& capabilities = context->thread(state).security.capabilities;
        auto addIf = [&](Capability capability, const char* name) {
            if (capabilities.contains(capability)) names.emplace_back(name);
        };
        addIf(Capability::CreateInstances, "CreateInstances");
        if (capabilities.contains(Capability::ReadDataModel) || capabilities.contains(Capability::WriteDataModel)) names.emplace_back("Basic");
        addIf(Capability::LocalUser, "LocalUser");
        if (capabilities.contains(Capability::HttpPublic) || capabilities.contains(Capability::HttpPrivate)) names.emplace_back("Network");
        addIf(Capability::DataStore, "DataStore");
        addIf(Capability::Plugin, "Plugin");
        addIf(Capability::RobloxScript, "RobloxScript");
        addIf(Capability::LoadString, "LoadString");
    }
    return pushCapabilities(state, std::move(names));
}

int l_capabilities_add(lua_State* state)
{
    Value* value = valueAt(state, 1, Kind::SecurityCapabilities);
    std::vector<std::string> names = value->names;
    addCapabilitiesFromArguments(state, names, 2);
    return pushCapabilities(state, std::move(names));
}

int l_capabilities_remove(lua_State* state)
{
    Value* value = valueAt(state, 1, Kind::SecurityCapabilities);
    std::vector<std::string> removed;
    addCapabilitiesFromArguments(state, removed, 2);
    std::vector<std::string> names;
    std::set_difference(value->names.begin(), value->names.end(), removed.begin(), removed.end(), std::back_inserter(names));
    return pushCapabilities(state, std::move(names));
}

int l_capabilities_contains(lua_State* state)
{
    Value* value = valueAt(state, 1, Kind::SecurityCapabilities);
    std::vector<std::string> required;
    addCapabilitiesFromArguments(state, required, 2);
    lua_pushboolean(state, std::includes(value->names.begin(), value->names.end(), required.begin(), required.end()));
    return 1;
}

int l_path_waypoint_new(lua_State* state)
{
    const int argumentCount = lua_gettop(state);
    requireType(state, 1, "Vector3");
    Value* value = pushValue(state, Kind::PathWaypoint);
    setReference(state, *value, 0, 1);
    if (argumentCount < 2 || lua_isnil(state, 2)) setDefaultEnumReference(state, *value, 1, "PathWaypointAction", "Walk");
    else { requireEnum(state, 2, "PathWaypointAction"); setReference(state, *value, 1, 2); }
    value->primary = argumentCount >= 3 ? luaL_optstring(state, 3, "") : "";
    return 1;
}

int l_path2d_control_new(lua_State* state)
{
    const int argumentCount = lua_gettop(state);
    if (argumentCount != 0 && argumentCount != 1 && argumentCount != 3)
        luaL_error(state, "Trying to create a Path2DControlPoint with wrong number of arguments");
    Value* value = pushValue(state, Kind::Path2DControlPoint);
    for (size_t slot = 0; slot < 3; ++slot)
    {
        const int argument = static_cast<int>(slot + 1);
        if (argument > argumentCount)
        {
            pushDefaultUDim2(state);
            setReference(state, *value, slot, -1);
            lua_pop(state, 1);
        }
        else
        {
            if (valueType(state, argument) != "UDim2")
                luaL_typeerror(state, argument, "UDim2");
            setReference(state, *value, slot, argument);
        }
    }
    return 1;
}

struct SharedKey
{
    bool numeric = false;
    uint32_t number = 0;
    std::string text;

    friend bool operator<(const SharedKey& left, const SharedKey& right)
    {
        if (left.numeric != right.numeric)
            return left.numeric; // Numeric keys iterate before string keys.
        return left.numeric ? left.number < right.number : left.text < right.text;
    }
};

struct SharedNode;
using SharedNodePointer = std::shared_ptr<SharedNode>;
using SharedAtom = std::variant<bool, double, std::string, SharedNodePointer>;

struct SharedNode
{
    std::map<SharedKey, SharedAtom> values;
    size_t externalRoots = 0;
    bool frozen = false;
};

class SharedStore
{
public:
    ~SharedStore()
    {
        // Explicitly break every graph edge so self-referential and mutually
        // referential SharedTables cannot outlive their RuntimeContext.
        std::vector<SharedNodePointer> live;
        for (const std::weak_ptr<SharedNode>& candidate : nodes_)
            if (SharedNodePointer node = candidate.lock()) live.push_back(std::move(node));
        for (const SharedNodePointer& node : live)
            node->values.clear();
    }

    SharedNodePointer create()
    {
        SharedNodePointer node = std::make_shared<SharedNode>();
        nodes_.push_back(node);
        return node;
    }

    void collectCycles()
    {
        std::vector<SharedNodePointer> live;
        live.reserve(nodes_.size());
        nodes_.erase(std::remove_if(nodes_.begin(), nodes_.end(), [&](const std::weak_ptr<SharedNode>& candidate) {
            SharedNodePointer node = candidate.lock();
            if (!node)
                return true;
            live.push_back(std::move(node));
            return false;
        }), nodes_.end());

        std::unordered_set<SharedNode*> reachable;
        std::deque<SharedNodePointer> pending;
        for (const SharedNodePointer& node : live)
        {
            if (node->externalRoots != 0 && reachable.insert(node.get()).second)
                pending.push_back(node);
        }
        while (!pending.empty())
        {
            SharedNodePointer node = std::move(pending.front());
            pending.pop_front();
            for (const auto& [_, atom] : node->values)
            {
                if (const auto* child = std::get_if<SharedNodePointer>(&atom); child && *child && reachable.insert(child->get()).second)
                    pending.push_back(*child);
            }
        }
        for (const SharedNodePointer& node : live)
        {
            if (!reachable.count(node.get()))
                node->values.clear();
        }
    }

private:
    std::vector<std::weak_ptr<SharedNode>> nodes_;
};

struct SharedStoreSlot
{
    std::shared_ptr<SharedStore> store = std::make_shared<SharedStore>();
};

struct SharedHandle
{
    std::shared_ptr<SharedStore> store;
    SharedNodePointer node;
};

constexpr std::string_view kSharedStoreSubsystem = "runtime.release729-shared-table";

std::shared_ptr<SharedStore> sharedStoreFor(lua_State* state)
{
    RuntimeContext* context = RuntimeContext::from(state);
    if (!context)
        throw std::logic_error("SharedTable requires an attached RuntimeContext");
    SharedStoreSlot* slot = context->subsystem<SharedStoreSlot>(kSharedStoreSubsystem);
    if (!slot)
        slot = &context->emplaceSubsystem<SharedStoreSlot>(std::string(kSharedStoreSubsystem));
    return slot->store;
}

SharedHandle* sharedAt(lua_State* state, int index)
{
    void* pointer = lua_touserdatatagged(state, index, tagFor(Kind::SharedTable));
    if (!pointer)
        luaL_typeerror(state, index, "SharedTable");
    return static_cast<SharedHandle*>(pointer);
}

int pushShared(lua_State* state, std::shared_ptr<SharedStore> store, SharedNodePointer node)
{
    if (!store || !node)
        throw std::invalid_argument("SharedTable handle requires a store and node");
    void* storage = lua_newuserdatatagged(state, sizeof(SharedHandle), tagFor(Kind::SharedTable));
    auto* handle = new (storage) SharedHandle{std::move(store), std::move(node)};
    ++handle->node->externalRoots;
    lua_getuserdatametatable(state, tagFor(Kind::SharedTable));
    lua_setmetatable(state, -2);
    return 1;
}

void destroyShared(lua_State*, void* pointer)
{
    auto* handle = static_cast<SharedHandle*>(pointer);
    std::shared_ptr<SharedStore> store = handle->store;
    SharedNodePointer node = handle->node;
    if (node && node->externalRoots != 0)
        --node->externalRoots;
    handle->~SharedHandle();
    if (store)
        store->collectCycles();
}

SharedKey sharedKeyAt(lua_State* state, int index)
{
    const int type = lua_type(state, index);
    if (type == LUA_TSTRING)
    {
        size_t length = 0;
        const char* data = lua_tolstring(state, index, &length);
        return SharedKey{false, 0, std::string(data, length)};
    }
    if (type == LUA_TNUMBER || type == LUA_TINTEGER)
    {
        const double number = lua_tonumber(state, index);
        if (finite(number) && std::floor(number) == number && number >= 0 && number < 4294967296.0)
            return SharedKey{true, static_cast<uint32_t>(number), {}};
    }
    luaL_error(state, "SharedTable keys must be strings or non-negative integers below 2^32");
}

void pushSharedKey(lua_State* state, const SharedKey& key)
{
    if (key.numeric) lua_pushnumber(state, static_cast<double>(key.number));
    else lua_pushlstring(state, key.text.data(), key.text.size());
}

SharedNodePointer tableToShared(
    lua_State* state,
    const std::shared_ptr<SharedStore>& store,
    int index,
    std::unordered_map<const void*, SharedNodePointer>& seen,
    int depth);

SharedAtom atomAt(
    lua_State* state,
    const std::shared_ptr<SharedStore>& store,
    int index,
    bool allowPlainTable,
    std::unordered_map<const void*, SharedNodePointer>* seen = nullptr,
    int depth = 0)
{
    switch (lua_type(state, index))
    {
    case LUA_TBOOLEAN:
        return lua_toboolean(state, index) != 0;
    case LUA_TNUMBER:
    case LUA_TINTEGER:
        return lua_tonumber(state, index);
    case LUA_TSTRING:
        return stackString(state, index);
    case LUA_TUSERDATA:
        if (lua_userdatatag(state, index) == tagFor(Kind::SharedTable))
            return sharedAt(state, index)->node;
        break;
    case LUA_TTABLE:
        if (allowPlainTable && seen)
            return tableToShared(state, store, index, *seen, depth + 1);
        break;
    default:
        break;
    }
    luaL_error(state, "unsupported SharedTable value type %s", valueType(state, index).c_str());
}

SharedNodePointer tableToShared(
    lua_State* state,
    const std::shared_ptr<SharedStore>& store,
    int index,
    std::unordered_map<const void*, SharedNodePointer>& seen,
    int depth)
{
    if (depth > 64)
        luaL_error(state, "SharedTable initial value exceeds maximum nesting depth");
    index = lua_absindex(state, index);
    const void* identity = lua_topointer(state, index);
    if (auto found = seen.find(identity); found != seen.end())
        return found->second;
    SharedNodePointer node = store->create();
    seen.emplace(identity, node);
    lua_pushnil(state);
    while (lua_next(state, index) != 0)
    {
        SharedKey key = sharedKeyAt(state, -2);
        if (!lua_isnil(state, -1))
            node->values.insert_or_assign(std::move(key), atomAt(state, store, -1, true, &seen, depth));
        lua_pop(state, 1);
    }
    return node;
}

void pushAtom(lua_State* state, const std::shared_ptr<SharedStore>& store, const SharedAtom& atom)
{
    if (const bool* value = std::get_if<bool>(&atom)) lua_pushboolean(state, *value);
    else if (const double* value = std::get_if<double>(&atom)) lua_pushnumber(state, *value);
    else if (const std::string* value = std::get_if<std::string>(&atom)) lua_pushlstring(state, value->data(), value->size());
    else pushShared(state, store, std::get<SharedNodePointer>(atom));
}

void assignShared(lua_State* state, SharedHandle& handle, SharedKey key, int valueIndex)
{
    if (handle.node->frozen)
        luaL_error(state, "attempt to modify a frozen SharedTable");
    if (lua_isnil(state, valueIndex))
        handle.node->values.erase(key);
    else
        handle.node->values.insert_or_assign(std::move(key), atomAt(state, handle.store, valueIndex, false));
}

SharedNodePointer cloneSharedGraph(
    const std::shared_ptr<SharedStore>& store,
    const SharedNodePointer& source,
    bool deep,
    bool freeze,
    std::unordered_map<SharedNode*, SharedNodePointer>& copied)
{
    if (auto found = copied.find(source.get()); found != copied.end())
        return found->second;
    SharedNodePointer clone = store->create();
    clone->frozen = freeze;
    copied.emplace(source.get(), clone);
    for (const auto& [key, atom] : source->values)
    {
        if (deep)
        {
            if (const auto* child = std::get_if<SharedNodePointer>(&atom))
                clone->values.emplace(key, cloneSharedGraph(store, *child, true, freeze, copied));
            else
                clone->values.emplace(key, atom);
        }
        else
            clone->values.emplace(key, atom);
    }
    return clone;
}

int l_shared_new(lua_State* state)
{
    const int argumentCount = lua_gettop(state);
    std::shared_ptr<SharedStore> store = sharedStoreFor(state);
    SharedNodePointer node;
    if (argumentCount == 0 || lua_isnil(state, 1))
        node = store->create();
    else if (lua_istable(state, 1))
    {
        std::unordered_map<const void*, SharedNodePointer> seen;
        node = tableToShared(state, store, 1, seen, 0);
    }
    else if (lua_isuserdata(state, 1) && lua_userdatatag(state, 1) == tagFor(Kind::SharedTable))
    {
        std::unordered_map<SharedNode*, SharedNodePointer> copied;
        node = cloneSharedGraph(store, sharedAt(state, 1)->node, false, false, copied);
    }
    else
        luaL_error(state, "SharedTable.new expects no argument, a table, or a SharedTable");
    return pushShared(state, std::move(store), std::move(node));
}

int l_shared_index(lua_State* state)
{
    SharedHandle* handle = sharedAt(state, 1);
    SharedKey key = sharedKeyAt(state, 2);
    auto found = handle->node->values.find(key);
    if (found == handle->node->values.end()) lua_pushnil(state);
    else pushAtom(state, handle->store, found->second);
    return 1;
}

int l_shared_newindex(lua_State* state)
{
    SharedHandle* handle = sharedAt(state, 1);
    assignShared(state, *handle, sharedKeyAt(state, 2), 3);
    return 0;
}

int l_shared_equal(lua_State* state)
{
    SharedHandle* left = sharedAt(state, 1);
    const bool sameTag = lua_isuserdata(state, 2) && lua_userdatatag(state, 2) == tagFor(Kind::SharedTable);
    lua_pushboolean(state, sameTag && left->node == sharedAt(state, 2)->node);
    return 1;
}

int l_shared_tostring(lua_State* state)
{
    (void)sharedAt(state, 1);
    lua_pushliteral(state, "SharedTable");
    return 1;
}

int l_shared_length(lua_State* state)
{
    lua_pushnumber(state, static_cast<double>(sharedAt(state, 1)->node->values.size()));
    return 1;
}

int l_shared_iter(lua_State* state)
{
    SharedHandle* handle = sharedAt(state, 1);
    lua_getglobal(state, "next");
    lua_createtable(state, 0, static_cast<int>(handle->node->values.size()));
    for (const auto& [key, atom] : handle->node->values)
    {
        pushSharedKey(state, key);
        pushAtom(state, handle->store, atom);
        lua_settable(state, -3);
    }
    lua_pushnil(state);
    return 3;
}

int l_shared_clone(lua_State* state)
{
    SharedHandle* source = sharedAt(state, 1);
    const bool deep = lua_toboolean(state, 2) != 0;
    std::unordered_map<SharedNode*, SharedNodePointer> copied;
    return pushShared(state, source->store, cloneSharedGraph(source->store, source->node, deep, false, copied));
}

int l_shared_clone_frozen(lua_State* state)
{
    SharedHandle* source = sharedAt(state, 1);
    const bool deep = lua_toboolean(state, 2) != 0;
    std::unordered_map<SharedNode*, SharedNodePointer> copied;
    return pushShared(state, source->store, cloneSharedGraph(source->store, source->node, deep, true, copied));
}

int l_shared_clear(lua_State* state)
{
    SharedHandle* handle = sharedAt(state, 1);
    if (handle->node->frozen)
        luaL_error(state, "attempt to modify a frozen SharedTable");
    handle->node->values.clear();
    handle->store->collectCycles();
    return 0;
}

int l_shared_size(lua_State* state)
{
    lua_pushnumber(state, static_cast<double>(sharedAt(state, 1)->node->values.size()));
    return 1;
}

int l_shared_is_frozen(lua_State* state)
{
    lua_pushboolean(state, sharedAt(state, 1)->node->frozen);
    return 1;
}

int l_shared_is_shared(lua_State* state)
{
    lua_pushboolean(state, lua_isuserdata(state, 1) && lua_userdatatag(state, 1) == tagFor(Kind::SharedTable));
    return 1;
}

int l_shared_increment(lua_State* state)
{
    SharedHandle* handle = sharedAt(state, 1);
    SharedKey key = sharedKeyAt(state, 2);
    const double delta = luaL_optnumber(state, 3, 1);
    if (!finite(delta))
        luaL_error(state, "SharedTable.increment delta must be finite");
    double current = 0;
    if (auto found = handle->node->values.find(key); found != handle->node->values.end())
    {
        const double* number = std::get_if<double>(&found->second);
        if (!number)
            luaL_error(state, "SharedTable.increment target must be a number or nil");
        current = *number;
    }
    const double result = current + delta;
    if (!finite(result))
        luaL_error(state, "SharedTable.increment result must be finite");
    assignShared(state, *handle, std::move(key), [&]() {
        lua_pushnumber(state, result);
        return lua_gettop(state);
    }());
    lua_pop(state, 1);
    lua_pushnumber(state, result);
    return 1;
}

int l_shared_update(lua_State* state)
{
    SharedHandle* handle = sharedAt(state, 1);
    SharedKey key = sharedKeyAt(state, 2);
    luaL_checktype(state, 3, LUA_TFUNCTION);
    if (handle->node->frozen)
        luaL_error(state, "attempt to modify a frozen SharedTable");
    lua_pushvalue(state, 3);
    if (auto found = handle->node->values.find(key); found != handle->node->values.end()) pushAtom(state, handle->store, found->second);
    else lua_pushnil(state);
    if (lua_pcall(state, 1, 1, 0) != LUA_OK)
    {
        lua_error(state);
        return 0;
    }
    assignShared(state, *handle, std::move(key), -1);
    lua_pop(state, 1);
    return 0;
}

void registerSharedMetatable(lua_State* state)
{
    static const luaL_Reg functions[] = {
        {"__index", l_shared_index},
        {"__newindex", l_shared_newindex},
        {"__eq", l_shared_equal},
        {"__tostring", l_shared_tostring},
        {"__len", l_shared_length},
        {"__iter", l_shared_iter},
        {nullptr, nullptr},
    };
    luaL_newmetatable(state, "RBXRelease729.SharedTable");
    luaL_register(state, nullptr, functions);
    lua_pushliteral(state, "SharedTable");
    lua_rawsetfield(state, -2, "__type");
    lua_pushliteral(state, "The metatable is locked");
    lua_rawsetfield(state, -2, "__metatable");
    lua_setreadonly(state, -1, true);
    lua_pushvalue(state, -1);
    lua_setuserdatametatable(state, tagFor(Kind::SharedTable));
    lua_pop(state, 1);
    lua_setuserdatadtor(state, tagFor(Kind::SharedTable), destroyShared);
}

bool maskProperty(const Value& value, std::string_view key, bool& result)
{
    if (value.kind == Kind::Axes)
    {
        if (key == "X" || key == "Left" || key == "Right") { result = (value.mask & 1u) != 0; return true; }
        if (key == "Y" || key == "Top" || key == "Bottom") { result = (value.mask & 2u) != 0; return true; }
        if (key == "Z" || key == "Front" || key == "Back") { result = (value.mask & 4u) != 0; return true; }
        return false;
    }
    if (value.kind == Kind::Faces)
    {
        static constexpr std::array<const char*, 6> names = {"Right", "Top", "Back", "Left", "Bottom", "Front"};
        for (size_t bit = 0; bit < names.size(); ++bit)
        {
            if (key == names[bit])
            {
                result = (value.mask & (uint32_t(1) << bit)) != 0;
                return true;
            }
        }
    }
    return false;
}

int l_value_index(lua_State* state)
{
    Value* value = valueAt(state, 1);
    const std::string key = luaL_checkstring(state, 2);
    bool maskResult = false;
    if (maskProperty(*value, key, maskResult))
    {
        lua_pushboolean(state, maskResult);
        return 1;
    }

    switch (value->kind)
    {
    case Kind::Axes:
    case Kind::Faces:
        break;
    case Kind::Region3int16:
        if (key == "Min") pushVector3int16(state, value->numbers[0], value->numbers[1], value->numbers[2]);
        else if (key == "Max") pushVector3int16(state, value->numbers[3], value->numbers[4], value->numbers[5]);
        else break;
        return 1;
    case Kind::Font:
        if (key == "Family")
        {
            if (value->references[0] != LUA_NOREF) pushReference(state, *value, 0);
            else lua_pushlstring(state, value->primary.data(), value->primary.size());
        }
        else if (key == "Weight") pushReference(state, *value, 1);
        else if (key == "Style") pushReference(state, *value, 2);
        else if (key == "Bold")
        {
            pushReference(state, *value, 1);
            const bool bold = !lua_isnil(state, -1) && enumNumericValue(state, -1) >= 600;
            lua_pop(state, 1);
            lua_pushboolean(state, bold);
        }
        else break;
        return 1;
    case Kind::FloatCurveKey:
    case Kind::RotationCurveKey:
    case Kind::ValueCurveKey:
        if (key == "Time") lua_pushnumber(state, value->numbers[0]);
        else if (key == "Value") pushReference(state, *value, 0);
        else if (key == "Interpolation") pushReference(state, *value, 1);
        else if (key == "LeftTangent") lua_pushnumber(state, value->numbers[1]);
        else if (key == "RightTangent") lua_pushnumber(state, value->numbers[2]);
        else break;
        return 1;
    case Kind::Content:
        if (key == "SourceType")
        {
            static constexpr const char* items[] = {"None", "Uri", "Object", "Opaque"};
            pushEnum(state, "ContentSourceType", items[std::min<uint32_t>(value->mask, 3)]);
        }
        else if (key == "Uri")
        {
            if (value->mask == 1) lua_pushlstring(state, value->primary.data(), value->primary.size());
            else lua_pushnil(state);
        }
        else if (key == "Object")
        {
            if (value->mask == 2) pushReference(state, *value, 0);
            else lua_pushnil(state);
        }
        else if (key == "Opaque") lua_pushnil(state);
        else break;
        return 1;
    case Kind::DockWidgetPluginGuiInfo:
        if (key == "InitialDockState") pushReference(state, *value, 0);
        else if (key == "InitialEnabled") lua_pushboolean(state, value->flags[0]);
        else if (key == "InitialEnabledShouldOverrideRestore") lua_pushboolean(state, value->flags[1]);
        else if (key == "FloatingXSize") lua_pushnumber(state, value->numbers[0]);
        else if (key == "FloatingYSize") lua_pushnumber(state, value->numbers[1]);
        else if (key == "MinWidth") lua_pushnumber(state, value->numbers[2]);
        else if (key == "MinHeight") lua_pushnumber(state, value->numbers[3]);
        else break;
        return 1;
    case Kind::CatalogSearchParams:
        if (key == "SearchKeyword") lua_pushlstring(state, value->primary.data(), value->primary.size());
        else if (key == "MinPrice") lua_pushnumber(state, value->numbers[0]);
        else if (key == "MaxPrice") lua_pushnumber(state, value->numbers[1]);
        else if (key == "SortType") pushReference(state, *value, 0);
        else if (key == "SortAggregation") pushReference(state, *value, 1);
        else if (key == "CategoryFilter") pushReference(state, *value, 2);
        else if (key == "SalesTypeFilter") pushReference(state, *value, 3);
        else if (key == "BundleTypes") pushReference(state, *value, 4);
        else if (key == "AssetTypes") pushReference(state, *value, 5);
        else if (key == "IncludeOffSale") lua_pushboolean(state, value->flags[0]);
        else if (key == "CreatorName") lua_pushlstring(state, value->secondary.data(), value->secondary.size());
        else if (key == "CreatorType") pushReference(state, *value, 6);
        else if (key == "CreatorId") lua_pushnumber(state, value->numbers[2]);
        else if (key == "Limit") lua_pushnumber(state, value->numbers[3]);
        else break;
        return 1;
    case Kind::SecurityCapabilities:
        if (key == "Add") lua_pushcfunction(state, l_capabilities_add, "SecurityCapabilities.Add");
        else if (key == "Remove") lua_pushcfunction(state, l_capabilities_remove, "SecurityCapabilities.Remove");
        else if (key == "Contains") lua_pushcfunction(state, l_capabilities_contains, "SecurityCapabilities.Contains");
        else break;
        return 1;
    case Kind::PathWaypoint:
        if (key == "Position") pushReference(state, *value, 0);
        else if (key == "Action") pushReference(state, *value, 1);
        else if (key == "Label") lua_pushlstring(state, value->primary.data(), value->primary.size());
        else break;
        return 1;
    case Kind::Path2DControlPoint:
        if (key == "Position") pushReference(state, *value, 0);
        else if (key == "LeftTangent") pushReference(state, *value, 1);
        else if (key == "RightTangent") pushReference(state, *value, 2);
        else break;
        return 1;
    case Kind::SharedTable:
        break; // Dedicated userdata/metamethod implementation; unreachable here.
    }
    luaL_error(state, "%s is not a valid member of %s", key.c_str(), typeName(value->kind));
}

void replaceFontFamily(lua_State* state, Value& value, int index)
{
    if (value.references[0] != LUA_NOREF)
    {
        lua_unref(state, value.references[0]);
        value.references[0] = LUA_NOREF;
    }
    if (valueType(state, index) == "Content") setReference(state, value, 0, index);
    else value.primary = luaL_checkstring(state, index);
}

void setCurveProperty(lua_State* state, Value& value, const std::string& key)
{
    if (key == "Time") value.numbers[0] = checkedFinite(state, 3, "curve key time");
    else if (key == "Value")
    {
        if (value.kind == Kind::FloatCurveKey) checkedFinite(state, 3, "curve key value");
        else if (value.kind == Kind::RotationCurveKey) requireType(state, 3, "CFrame");
        setReference(state, value, 0, 3);
    }
    else if (key == "Interpolation")
    {
        requireEnum(state, 3, "KeyInterpolationMode");
        setReference(state, value, 1, 3);
    }
    else if (key == "LeftTangent") value.numbers[1] = checkedFinite(state, 3, "curve key left tangent");
    else if (key == "RightTangent")
    {
        pushReference(state, value, 1);
        std::string interpolation;
        const bool cubic = isEnum(state, -1, "KeyInterpolationMode", &interpolation) && interpolation == "Cubic";
        lua_pop(state, 1);
        if (!cubic)
            luaL_error(state, "RightTangent can only be assigned when Interpolation is Enum.KeyInterpolationMode.Cubic");
        value.numbers[2] = checkedFinite(state, 3, "curve key right tangent");
    }
    else luaL_error(state, "%s is not a valid member of %s", key.c_str(), typeName(value.kind));
}

void setCatalogProperty(lua_State* state, Value& value, const std::string& key)
{
    if (key == "SearchKeyword") value.primary = luaL_checkstring(state, 3);
    else if (key == "MinPrice") value.numbers[0] = checkedFinite(state, 3, "CatalogSearchParams.MinPrice");
    else if (key == "MaxPrice") value.numbers[1] = checkedFinite(state, 3, "CatalogSearchParams.MaxPrice");
    else if (key == "SortType") { requireEnum(state, 3, "CatalogSortType"); setReference(state, value, 0, 3); }
    else if (key == "SortAggregation") { requireEnum(state, 3, "CatalogSortAggregation"); setReference(state, value, 1, 3); }
    else if (key == "CategoryFilter") { requireEnum(state, 3, "CatalogCategoryFilter"); setReference(state, value, 2, 3); }
    else if (key == "SalesTypeFilter") { requireEnum(state, 3, "SalesTypeFilter"); setReference(state, value, 3, 3); }
    else if (key == "BundleTypes") setFrozenArray(state, value, 4, 3, "BundleType");
    else if (key == "AssetTypes") setFrozenArray(state, value, 5, 3, "AvatarAssetType");
    else if (key == "IncludeOffSale") { luaL_checktype(state, 3, LUA_TBOOLEAN); value.flags[0] = lua_toboolean(state, 3) != 0; }
    else if (key == "CreatorName") value.secondary = luaL_checkstring(state, 3);
    else if (key == "CreatorType") { requireEnum(state, 3, "CreatorTypeFilter"); setReference(state, value, 6, 3); }
    else if (key == "CreatorId") value.numbers[2] = checkedFinite(state, 3, "CatalogSearchParams.CreatorId");
    else if (key == "Limit")
    {
        const double limit = checkedFinite(state, 3, "CatalogSearchParams.Limit");
        static constexpr std::array<double, 5> allowed = {10, 28, 30, 60, 120};
        if (std::find(allowed.begin(), allowed.end(), limit) == allowed.end())
            luaL_error(state, "CatalogSearchParams.Limit must be one of 10, 28, 30, 60, or 120");
        value.numbers[3] = limit;
    }
    else luaL_error(state, "%s is not a valid member of CatalogSearchParams", key.c_str());
}

int l_value_newindex(lua_State* state)
{
    Value* value = valueAt(state, 1);
    const std::string key = luaL_checkstring(state, 2);
    if (value->kind == Kind::CatalogSearchParams)
    {
        setCatalogProperty(state, *value, key);
        return 0;
    }
    if (value->kind == Kind::Font)
    {
        if (key == "Family") replaceFontFamily(state, *value, 3);
        else if (key == "Weight") { requireEnum(state, 3, "FontWeight"); setReference(state, *value, 1, 3); }
        else if (key == "Style") { requireEnum(state, 3, "FontStyle"); setReference(state, *value, 2, 3); }
        else if (key == "Bold")
        {
            luaL_checktype(state, 3, LUA_TBOOLEAN);
            setDefaultEnumReference(state, *value, 1, "FontWeight", lua_toboolean(state, 3) ? "Bold" : "Regular");
        }
        else luaL_error(state, "%s is not a valid member of Font", key.c_str());
        return 0;
    }
    if (value->kind == Kind::FloatCurveKey || value->kind == Kind::RotationCurveKey || value->kind == Kind::ValueCurveKey)
    {
        setCurveProperty(state, *value, key);
        return 0;
    }
    luaL_error(state, "%s is immutable; member %s cannot be assigned", typeName(value->kind), key.c_str());
}

bool referencesEqual(lua_State* state, const Value& left, const Value& right, size_t slot)
{
    pushReference(state, left, slot);
    pushReference(state, right, slot);
    const bool equal = lua_equal(state, -1, -2) != 0;
    lua_pop(state, 2);
    return equal;
}

std::string referenceText(lua_State* state, const Value& value, size_t slot)
{
    pushReference(state, value, slot);
    size_t length = 0;
    const char* text = luaL_tolstring(state, -1, &length);
    std::string result(text ? text : "", length);
    lua_pop(state, 2); // tostring result and referenced value
    return result;
}

int l_value_equal(lua_State* state)
{
    Value* left = valueAt(state, 1);
    if (!lua_isuserdata(state, 2) || lua_userdatatag(state, 2) != tagFor(left->kind))
    {
        lua_pushboolean(state, false);
        return 1;
    }
    Value* right = valueAt(state, 2, left->kind);
    bool equal = left->mask == right->mask && left->numbers == right->numbers && left->flags == right->flags &&
        left->primary == right->primary && left->secondary == right->secondary && left->names == right->names;
    for (size_t slot = 0; equal && slot < left->references.size(); ++slot)
        equal = referencesEqual(state, *left, *right, slot);
    lua_pushboolean(state, equal);
    return 1;
}

int l_value_tostring(lua_State* state)
{
    Value* value = valueAt(state, 1);
    std::ostringstream output;
    switch (value->kind)
    {
    case Kind::Axes:
        if (value->mask & 1u) output << "X";
        if (value->mask & 2u) output << (output.tellp() > 0 ? ", Y" : "Y");
        if (value->mask & 4u) output << (output.tellp() > 0 ? ", Z" : "Z");
        break;
    case Kind::Faces:
    {
        static constexpr std::array<const char*, 6> names = {"Right", "Top", "Back", "Left", "Bottom", "Front"};
        std::vector<std::string> selected;
        for (size_t bit = 0; bit < names.size(); ++bit) if (value->mask & (uint32_t(1) << bit)) selected.emplace_back(names[bit]);
        output << joined(selected, ", ");
        break;
    }
    case Kind::Region3int16:
        output << value->numbers[0] << ", " << value->numbers[1] << ", " << value->numbers[2] << "; "
               << value->numbers[3] << ", " << value->numbers[4] << ", " << value->numbers[5];
        break;
    case Kind::Font:
        output << value->primary;
        break;
    case Kind::Content:
        output << (value->mask == 1 ? value->primary : typeName(value->kind));
        break;
    case Kind::SecurityCapabilities:
        output << "SecurityCapabilities(" << joined(value->names, ", ") << ")";
        break;
    case Kind::Path2DControlPoint:
        output << "Path2DControlPoint { Position = " << referenceText(state, *value, 0)
               << ", LeftTangent = " << referenceText(state, *value, 1)
               << ", RightTangent = " << referenceText(state, *value, 2) << " }";
        break;
    default:
        output << typeName(value->kind);
        break;
    }
    const std::string text = output.str();
    lua_pushlstring(state, text.data(), text.size());
    return 1;
}

void registerMetatable(lua_State* state, Kind kind)
{
    static const luaL_Reg functions[] = {
        {"__index", l_value_index},
        {"__newindex", l_value_newindex},
        {"__eq", l_value_equal},
        {"__tostring", l_value_tostring},
        {nullptr, nullptr},
    };
    const std::string name = std::string("RBXRelease729.") + typeName(kind);
    luaL_newmetatable(state, name.c_str());
    luaL_register(state, nullptr, functions);
    lua_pushstring(state, typeName(kind));
    lua_rawsetfield(state, -2, "__type");
    lua_pushliteral(state, "The metatable is locked");
    lua_rawsetfield(state, -2, "__metatable");
    lua_setreadonly(state, -1, true);
    lua_pushvalue(state, -1);
    lua_setuserdatametatable(state, tagFor(kind));
    lua_pop(state, 1);
    lua_setuserdatadtor(state, tagFor(kind), destroyValue);
}

void registerConstructor(lua_State* state, const char* name, const luaL_Reg* functions)
{
    lua_newtable(state);
    luaL_register(state, nullptr, functions);
    lua_setreadonly(state, -1, true);
    lua_setglobal(state, name);
}

} // namespace

std::span<const DatatypeCatalogEntry> release729DatatypeCatalog()
{
    static constexpr std::array entries = {
        DatatypeCatalogEntry{"AdReward", DatatypeAvailability::Unsupported, false, false, false},
        DatatypeCatalogEntry{"Axes", DatatypeAvailability::Release729Pack, true, true, false},
        DatatypeCatalogEntry{"BrickColor", DatatypeAvailability::ExistingShim, true, true, false},
        DatatypeCatalogEntry{"CatalogSearchParams", DatatypeAvailability::Release729Pack, true, true, true},
        DatatypeCatalogEntry{"CFrame", DatatypeAvailability::ExistingNative, true, true, false},
        DatatypeCatalogEntry{"Color3", DatatypeAvailability::ExistingNative, true, true, false},
        DatatypeCatalogEntry{"ColorSequence", DatatypeAvailability::ExistingNative, true, true, false},
        DatatypeCatalogEntry{"ColorSequenceKeypoint", DatatypeAvailability::ExistingNative, true, true, false},
        DatatypeCatalogEntry{"Content", DatatypeAvailability::Release729Pack, true, true, false},
        DatatypeCatalogEntry{"DateTime", DatatypeAvailability::ExistingNative, true, true, false},
        DatatypeCatalogEntry{"DockWidgetPluginGuiInfo", DatatypeAvailability::Release729Pack, true, true, false},
        DatatypeCatalogEntry{"Enum", DatatypeAvailability::ExistingNative, true, false, false},
        DatatypeCatalogEntry{"EnumItem", DatatypeAvailability::ExistingNative, false, false, false},
        DatatypeCatalogEntry{"Enums", DatatypeAvailability::ExistingNative, false, false, false},
        DatatypeCatalogEntry{"Faces", DatatypeAvailability::Release729Pack, true, true, false},
        DatatypeCatalogEntry{"FloatCurveKey", DatatypeAvailability::Release729Pack, true, true, true},
        DatatypeCatalogEntry{"Font", DatatypeAvailability::Release729Pack, true, true, true},
        DatatypeCatalogEntry{"Instance", DatatypeAvailability::ExistingNative, true, true, true},
        DatatypeCatalogEntry{"NumberRange", DatatypeAvailability::ExistingNative, true, true, false},
        DatatypeCatalogEntry{"NumberSequence", DatatypeAvailability::ExistingNative, true, true, false},
        DatatypeCatalogEntry{"NumberSequenceKeypoint", DatatypeAvailability::ExistingNative, true, true, false},
        DatatypeCatalogEntry{"OverlapParams", DatatypeAvailability::ExistingNative, true, true, true},
        DatatypeCatalogEntry{"Path2DControlPoint", DatatypeAvailability::Release729Pack, true, true, false},
        DatatypeCatalogEntry{"PathWaypoint", DatatypeAvailability::Release729Pack, true, true, false},
        DatatypeCatalogEntry{"PhysicalProperties", DatatypeAvailability::ExistingShim, true, true, false},
        DatatypeCatalogEntry{"Random", DatatypeAvailability::ExistingShim, true, true, true},
        DatatypeCatalogEntry{"Ray", DatatypeAvailability::ExistingNative, true, true, false},
        DatatypeCatalogEntry{"RaycastParams", DatatypeAvailability::ExistingNative, true, true, true},
        DatatypeCatalogEntry{"RaycastResult", DatatypeAvailability::EngineProduced, false, false, false},
        DatatypeCatalogEntry{"RBXScriptConnection", DatatypeAvailability::EngineProduced, false, false, true},
        DatatypeCatalogEntry{"RBXScriptSignal", DatatypeAvailability::EngineProduced, false, false, false},
        DatatypeCatalogEntry{"Rect", DatatypeAvailability::ExistingShim, true, true, false},
        DatatypeCatalogEntry{"Region3", DatatypeAvailability::ExistingShim, true, true, false},
        DatatypeCatalogEntry{"Region3int16", DatatypeAvailability::Release729Pack, true, true, false},
        DatatypeCatalogEntry{"RotationCurveKey", DatatypeAvailability::Release729Pack, true, true, true},
        DatatypeCatalogEntry{"Secret", DatatypeAvailability::Inaccessible, false, false, false},
        DatatypeCatalogEntry{"SecurityCapabilities", DatatypeAvailability::Release729Pack, true, true, false},
        DatatypeCatalogEntry{"SharedTable", DatatypeAvailability::Release729Pack, true, true, true},
        DatatypeCatalogEntry{"TweenInfo", DatatypeAvailability::ExistingNative, true, true, false},
        DatatypeCatalogEntry{"UDim", DatatypeAvailability::ExistingNative, true, true, false},
        DatatypeCatalogEntry{"UDim2", DatatypeAvailability::ExistingNative, true, true, false},
        DatatypeCatalogEntry{"User", DatatypeAvailability::Unsupported, true, true, false},
        DatatypeCatalogEntry{"ValueCurveKey", DatatypeAvailability::Release729Pack, true, true, true},
        DatatypeCatalogEntry{"Vector2", DatatypeAvailability::ExistingNative, true, true, false},
        DatatypeCatalogEntry{"Vector2int16", DatatypeAvailability::ExistingShim, true, true, false},
        DatatypeCatalogEntry{"Vector3", DatatypeAvailability::ExistingNative, true, true, false},
        DatatypeCatalogEntry{"Vector3int16", DatatypeAvailability::ExistingShim, true, true, false},
    };
    return entries;
}

std::string_view toString(DatatypeAvailability availability)
{
    switch (availability)
    {
    case DatatypeAvailability::ExistingNative: return "existing-native";
    case DatatypeAvailability::ExistingShim: return "existing-shim";
    case DatatypeAvailability::Release729Pack: return "release-729-pack";
    case DatatypeAvailability::EngineProduced: return "engine-produced";
    case DatatypeAvailability::Inaccessible: return "inaccessible";
    case DatatypeAvailability::Unsupported: return "unsupported";
    }
    return "unsupported";
}

void installRelease729Datatypes(lua_State* state)
{
    if (!state)
        throw std::invalid_argument("release-729 datatypes require a Lua state");
    for (int index = 0; index < static_cast<int>(Kind::SharedTable); ++index)
        registerMetatable(state, static_cast<Kind>(index));
    registerSharedMetatable(state);
    (void)sharedStoreFor(state);

    static const luaL_Reg axes[] = {{"new", l_axes_new}, {nullptr, nullptr}};
    static const luaL_Reg faces[] = {{"new", l_faces_new}, {nullptr, nullptr}};
    static const luaL_Reg region[] = {{"new", l_region3int16_new}, {nullptr, nullptr}};
    static const luaL_Reg font[] = {
        {"new", l_font_new}, {"fromName", l_font_from_name}, {"fromId", l_font_from_id}, {"fromEnum", l_font_from_enum}, {nullptr, nullptr}};
    static const luaL_Reg floatKey[] = {{"new", l_float_curve_new}, {nullptr, nullptr}};
    static const luaL_Reg rotationKey[] = {{"new", l_rotation_curve_new}, {nullptr, nullptr}};
    static const luaL_Reg valueKey[] = {{"new", l_value_curve_new}, {nullptr, nullptr}};
    static const luaL_Reg content[] = {
        {"fromUri", l_content_from_uri}, {"fromAssetId", l_content_from_asset_id}, {"fromObject", l_content_from_object}, {nullptr, nullptr}};
    static const luaL_Reg dock[] = {{"new", l_dock_widget_new}, {nullptr, nullptr}};
    static const luaL_Reg catalog[] = {{"new", l_catalog_search_new}, {nullptr, nullptr}};
    static const luaL_Reg capabilities[] = {{"new", l_capabilities_new}, {"fromCurrent", l_capabilities_from_current}, {nullptr, nullptr}};
    static const luaL_Reg waypoint[] = {{"new", l_path_waypoint_new}, {nullptr, nullptr}};
    static const luaL_Reg path2d[] = {{"new", l_path2d_control_new}, {nullptr, nullptr}};
    static const luaL_Reg sharedTable[] = {
        {"new", l_shared_new},
        {"clone", l_shared_clone},
        {"cloneAndFreeze", l_shared_clone_frozen},
        {"clear", l_shared_clear},
        {"increment", l_shared_increment},
        {"update", l_shared_update},
        {"size", l_shared_size},
        {"isFrozen", l_shared_is_frozen},
        {"isShared", l_shared_is_shared},
        {nullptr, nullptr},
    };

    registerConstructor(state, "Axes", axes);
    registerConstructor(state, "Faces", faces);
    registerConstructor(state, "Region3int16", region);
    registerConstructor(state, "Font", font);
    registerConstructor(state, "FloatCurveKey", floatKey);
    registerConstructor(state, "RotationCurveKey", rotationKey);
    registerConstructor(state, "ValueCurveKey", valueKey);
    registerConstructor(state, "Content", content);
    lua_getglobal(state, "Content");
    lua_setreadonly(state, -1, false);
    pushValue(state, Kind::Content)->mask = 0;
    lua_setfield(state, -2, "none");
    lua_setreadonly(state, -1, true);
    lua_pop(state, 1);
    registerConstructor(state, "DockWidgetPluginGuiInfo", dock);
    registerConstructor(state, "CatalogSearchParams", catalog);
    registerConstructor(state, "SecurityCapabilities", capabilities);
    registerConstructor(state, "PathWaypoint", waypoint);
    registerConstructor(state, "Path2DControlPoint", path2d);
    registerConstructor(state, "SharedTable", sharedTable);
}

} // namespace rbx::runtime
