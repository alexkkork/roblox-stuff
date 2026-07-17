-- Release 729 constructor-table contracts captured from Studio 0.729.0.7290838.
-- This test intentionally covers public behavior only; table iteration order is
-- exercised by the separate Studio surface oracle.

local function expectNative(name, value)
    assert(type(value) == "function", name .. " must exist")
    assert(iscclosure == nil or iscclosure(value), name .. " must be a native closure")
    assert(islclosure == nil or not islclosure(value), name .. " must not expose a Luau wrapper")
    assert(debug.info(value, "s") == "[C]", name .. " must report [C]")
end

expectNative("Vector2.min", Vector2.min)
expectNative("Vector2.max", Vector2.max)
assert(Vector2.one == Vector2.new(1, 1))
assert(Vector2.min(Vector2.new(4, -2), Vector2.new(1, 8)) == Vector2.new(1, -2))
assert(Vector2.max(Vector2.new(4, -2), Vector2.new(1, 8)) == Vector2.new(4, 8))
assert(Vector2.min(Vector2.new(9, 8), Vector2.new(7, 10), Vector2.new(6, 4)) == Vector2.new(6, 4))
assert(Vector2.max(Vector2.new(9, 8), Vector2.new(7, 10), Vector2.new(6, 4)) == Vector2.new(9, 10))
assert(not pcall(Vector2.min))
assert(not pcall(Vector2.max, Vector2.zero, "not a Vector2"))

expectNative("Vector3.min", Vector3.min)
expectNative("Vector3.max", Vector3.max)
expectNative("Vector3.fromAxis", Vector3.fromAxis)
expectNative("Vector3.FromAxis", Vector3.FromAxis)
expectNative("Vector3.fromNormalId", Vector3.fromNormalId)
expectNative("Vector3.FromNormalId", Vector3.FromNormalId)
assert(Vector3.one == Vector3.new(1, 1, 1))
assert(Vector3.min(Vector3.new(4, -2, 5), Vector3.new(1, 8, 3)) == Vector3.new(1, -2, 3))
assert(Vector3.max(Vector3.new(4, -2, 5), Vector3.new(1, 8, 3)) == Vector3.new(4, 8, 5))

local axisVectors = {
    [Enum.Axis.X] = Vector3.new(1, 0, 0),
    [Enum.Axis.Y] = Vector3.new(0, 1, 0),
    [Enum.Axis.Z] = Vector3.new(0, 0, 1),
}
for axis, expected in pairs(axisVectors) do
    assert(Vector3.fromAxis(axis) == expected)
    assert(Vector3.FromAxis(axis) == expected)
end

local normalVectors = {
    [Enum.NormalId.Right] = Vector3.new(1, 0, 0),
    [Enum.NormalId.Top] = Vector3.new(0, 1, 0),
    [Enum.NormalId.Back] = Vector3.new(0, 0, 1),
    [Enum.NormalId.Left] = Vector3.new(-1, 0, 0),
    [Enum.NormalId.Bottom] = Vector3.new(0, -1, 0),
    [Enum.NormalId.Front] = Vector3.new(0, 0, -1),
}
for normal, expected in pairs(normalVectors) do
    assert(Vector3.fromNormalId(normal) == expected)
    assert(Vector3.FromNormalId(normal) == expected)
end
assert(not pcall(Vector3.fromAxis))
assert(not pcall(Vector3.fromAxis, Enum.NormalId.Right))
assert(not pcall(Vector3.fromNormalId))
assert(not pcall(Vector3.fromNormalId, Enum.Axis.X))
-- Constructor validation is identity-based. A value must not become an enum
-- merely because its __tostring output resembles one.
local fakeAxis = setmetatable({}, {__tostring = function() return "Enum.Axis.X" end})
local fakeNormal = setmetatable({}, {__tostring = function() return "Enum.NormalId.Right" end})
assert(not pcall(Vector3.fromAxis, fakeAxis))
assert(not pcall(Vector3.fromNormalId, fakeNormal))

expectNative("Instance.fromExisting", Instance.fromExisting)
local source = Instance.new("Part")
source.Name = "ShallowSource"
source.Size = Vector3.new(7, 8, 9)
source.Archivable = false
Instance.new("Folder", source).Name = "MustNotBeCopied"

local copy = Instance.fromExisting(source)
assert(copy ~= source and copy.ClassName == "Part")
assert(copy.Name == source.Name and copy.Size == source.Size)
assert(copy.Archivable == false, "property values must be copied")
assert(copy.Parent == nil, "the returned root must be unparented")
assert(#copy:GetChildren() == 0, "fromExisting must not copy descendants")
assert(not pcall(Instance.fromExisting))
assert(not pcall(Instance.fromExisting, "not an Instance"))

print("release729-vector-instance-globals-ok")
