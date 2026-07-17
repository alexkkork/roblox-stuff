-- Luraph environment-order compatibility probe
local environment = getfenv(0)
local index = 0
for key, value in next, environment do
    index += 1
    local valueType = type(value)
    local detail = ""
    if valueType == "function" then
        detail = debug.info(value, "n")
    elseif valueType == "table" then
        local nested = {}
        for nestedKey, nestedValue in next, value do
            if type(nestedValue) == "function" then
                table.insert(nested, tostring(nestedKey) .. ":" .. debug.info(nestedValue, "n"))
            end
        end
        detail = table.concat(nested, ",")
    end
    print("ENV", index, tostring(key), valueType, detail)
end
print("ENV_COUNT", index)

for _, name in ipairs({
    "UDim2", "Path2DControlPoint", "Vector2", "Vector3", "CFrame", "Color3",
}) do
    local value = environment[name]
    if type(value) == "table" then
        local nestedIndex = 0
        for key, nestedValue in next, value do
            nestedIndex += 1
            print("CTOR", name, nestedIndex, tostring(key), type(nestedValue),
                type(nestedValue) == "function" and debug.info(nestedValue, "n") or "")
        end
    end
end

local function inspectEnvironment(label, target)
    local ok, targetEnvironment = pcall(getfenv, target)
    print("TARGET_ENV", label, ok, type(targetEnvironment), targetEnvironment == environment)
    if not ok or type(targetEnvironment) ~= "table" then
        return
    end
    local count = 0
    for key, value in next, targetEnvironment do
        count += 1
        if key == "UDim2" or key == "Path2DControlPoint" or
            (type(value) == "table" and (value.new == UDim2.new or value.new == Path2DControlPoint.new)) then
            print("TARGET_ENV_KEY", label, count, tostring(key),
                type(value) == "table" and value.new == UDim2.new and "UDim2.new" or
                type(value) == "table" and value.new == Path2DControlPoint.new and "Path2DControlPoint.new" or "")
        end
    end
    print("TARGET_ENV_COUNT", label, count)
end

inspectEnvironment("type", type)
inspectEnvironment("loadstring", loadstring)
inspectEnvironment("Instance.new", Instance.new)
inspectEnvironment("debug.info", debug.info)

local environmentMetatable = getmetatable(environment)
print("ENV_METATABLE", type(environmentMetatable), tostring(environmentMetatable))
if type(environmentMetatable) == "table" then
    inspectEnvironment("env.__index", environmentMetatable.__index)
end
