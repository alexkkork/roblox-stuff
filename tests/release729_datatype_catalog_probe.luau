-- Release-729 datatype/global inventory probe.  This intentionally checks
-- exposure only; behavior conformance lives in release729_datatypes_native.luau.
local names = {
    "Axes",
    "BrickColor",
    "CatalogSearchParams",
    "CFrame",
    "Color3",
    "ColorSequence",
    "ColorSequenceKeypoint",
    "Content",
    "DateTime",
    "DockWidgetPluginGuiInfo",
    "Faces",
    "FloatCurveKey",
    "Font",
    "NumberRange",
    "NumberSequence",
    "NumberSequenceKeypoint",
    "OverlapParams",
    "Path2DControlPoint",
    "PathWaypoint",
    "PhysicalProperties",
    "Random",
    "Ray",
    "RaycastParams",
    "Rect",
    "Region3",
    "Region3int16",
    "RotationCurveKey",
    "SecurityCapabilities",
    "SharedTable",
    "TweenInfo",
    "UDim",
    "UDim2",
    "ValueCurveKey",
    "Vector2",
    "Vector2int16",
    "Vector3",
    "Vector3int16",
}

local present = {}
local missing = {}
for _, name in ipairs(names) do
    if rawget(getfenv(0), name) ~= nil then
        table.insert(present, name)
    else
        table.insert(missing, name)
    end
end

print("release729-datatypes-present=" .. table.concat(present, ","))
print("release729-datatypes-missing=" .. table.concat(missing, ","))
assert(#missing == 0, "release-729 datatype globals missing: " .. table.concat(missing, ","))
print("release729-datatype-catalog-ok")
return { present = present, missing = missing }
