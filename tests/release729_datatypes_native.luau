local function immutable(value, member, replacement)
    local ok = pcall(function()
        value[member] = replacement
    end)
    assert(not ok, typeof(value) .. " unexpectedly allowed assignment to " .. member)
end

local axes = Axes.new(Enum.Axis.X, Enum.NormalId.Top, "ignored")
assert(typeof(axes) == "Axes")
assert(axes.X and axes.Left and axes.Right)
assert(axes.Y and axes.Top and axes.Bottom)
assert(not axes.Z and not axes.Front and not axes.Back)
immutable(axes, "X", false)
assert(getmetatable(axes) == "The metatable is locked")

local faces = Faces.new(Enum.NormalId.Front, Enum.NormalId.Left, Enum.Axis.X, false)
assert(typeof(faces) == "Faces")
assert(faces.Front and faces.Left)
assert(not faces.Right and not faces.Top and not faces.Bottom and not faces.Back)
immutable(faces, "Front", false)

local minimum = Vector3int16.new(-4, 2, 8)
local maximum = Vector3int16.new(10, 20, 30)
local region = Region3int16.new(minimum, maximum)
assert(typeof(region) == "Region3int16")
assert(region.Min.X == -4 and region.Min.Y == 2 and region.Min.Z == 8)
assert(region.Max.X == 10 and region.Max.Y == 20 and region.Max.Z == 30)
immutable(region, "Min", maximum)

local font = Font.new("rbxasset://fonts/families/BuilderSans.json")
assert(typeof(font) == "Font")
assert(font.Family == "rbxasset://fonts/families/BuilderSans.json")
assert(font.Weight == Enum.FontWeight.Regular and font.Style == Enum.FontStyle.Normal)
assert(font.Bold == false)
font.Bold = true
assert(font.Bold and font.Weight == Enum.FontWeight.Bold)
font.Weight = Enum.FontWeight.SemiBold
assert(font.Bold)
font.Style = Enum.FontStyle.Italic
assert(font.Style == Enum.FontStyle.Italic)
assert(Font.fromName("Roboto_Mono").Family == "rbxasset://fonts/families/Roboto_Mono.json")
assert(Font.fromId(12345).Family == "rbxassetid://12345")
assert(typeof(Font.fromEnum(Enum.Font.BuilderSans)) == "Font")

local floatKey = FloatCurveKey.new(0.25, 12.5)
assert(typeof(floatKey) == "FloatCurveKey")
assert(floatKey.Time == 0.25 and floatKey.Value == 12.5)
assert(floatKey.Interpolation == Enum.KeyInterpolationMode.Linear)
assert(not pcall(function() floatKey.RightTangent = 2 end))
floatKey.Interpolation = Enum.KeyInterpolationMode.Cubic
floatKey.LeftTangent = -1
floatKey.RightTangent = 2
assert(floatKey.LeftTangent == -1 and floatKey.RightTangent == 2)

local rotationKey = RotationCurveKey.new(1, CFrame.Angles(0, 1, 0), Enum.KeyInterpolationMode.Constant)
assert(typeof(rotationKey) == "RotationCurveKey" and typeof(rotationKey.Value) == "CFrame")
local valueKey = ValueCurveKey.new(2, Color3.new(1, 0, 0))
assert(typeof(valueKey) == "ValueCurveKey" and typeof(valueKey.Value) == "Color3")

assert(typeof(Content.none) == "Content")
assert(Content.none.SourceType == Enum.ContentSourceType.None)
assert(Content.none.Uri == nil and Content.none.Object == nil)
assert(Content.fromUri("") == Content.none)
local uriContent = Content.fromUri("rbxasset://textures/example.png")
assert(uriContent.SourceType == Enum.ContentSourceType.Uri)
assert(uriContent.Uri == "rbxasset://textures/example.png")
assert(Content.fromAssetId(123).Uri == "rbxassetid://123")
local part = Instance.new("Part")
local objectContent = Content.fromObject(part)
assert(objectContent.SourceType == Enum.ContentSourceType.Object and objectContent.Object == part)
immutable(uriContent, "Uri", "nope")

local dock = DockWidgetPluginGuiInfo.new(Enum.InitialDockState.Float, true, false, 400, 300, 100, 80)
assert(typeof(dock) == "DockWidgetPluginGuiInfo")
assert(dock.InitialDockState == Enum.InitialDockState.Float)
assert(dock.InitialEnabled and not dock.InitialEnabledShouldOverrideRestore)
assert(dock.FloatingXSize == 400 and dock.FloatingYSize == 300 and dock.MinWidth == 100 and dock.MinHeight == 80)
immutable(dock, "MinWidth", 1)

local catalog = CatalogSearchParams.new()
assert(typeof(catalog) == "CatalogSearchParams")
assert(catalog.SortType == Enum.CatalogSortType.Relevance and catalog.Limit == 30)
catalog.SearchKeyword = "builder"
catalog.MinPrice = 10
catalog.MaxPrice = 100
catalog.BundleTypes = { Enum.BundleType.Animations, Enum.BundleType.BodyParts }
catalog.AssetTypes = { Enum.AvatarAssetType.Hat }
catalog.IncludeOffSale = true
catalog.Limit = 60
assert(catalog.SearchKeyword == "builder" and catalog.MinPrice == 10 and catalog.MaxPrice == 100)
assert(catalog.BundleTypes[1] == Enum.BundleType.Animations and table.isfrozen(catalog.BundleTypes))
assert(catalog.AssetTypes[1] == Enum.AvatarAssetType.Hat and catalog.IncludeOffSale and catalog.Limit == 60)
assert(not pcall(function() catalog.Limit = 11 end))

local emptyCapabilities = SecurityCapabilities.new()
local capabilities = emptyCapabilities:Add(Enum.SecurityCapability.Basic, Enum.SecurityCapability.Players)
assert(typeof(capabilities) == "SecurityCapabilities")
assert(not emptyCapabilities:Contains(Enum.SecurityCapability.Basic))
assert(capabilities:Contains(Enum.SecurityCapability.Basic))
assert(capabilities:Contains(SecurityCapabilities.new(Enum.SecurityCapability.Basic, Enum.SecurityCapability.Players)))
local withoutPlayers = capabilities:Remove(Enum.SecurityCapability.Players)
assert(withoutPlayers:Contains(Enum.SecurityCapability.Basic) and not withoutPlayers:Contains(Enum.SecurityCapability.Players))
assert(typeof(SecurityCapabilities.fromCurrent()) == "SecurityCapabilities")
immutable(capabilities, "Basic", false)

local waypoint = PathWaypoint.new(Vector3.new(1, 2, 3), Enum.PathWaypointAction.Jump, "ladder")
assert(typeof(waypoint) == "PathWaypoint")
assert(waypoint.Position == Vector3.new(1, 2, 3) and waypoint.Action == Enum.PathWaypointAction.Jump and waypoint.Label == "ladder")
immutable(waypoint, "Label", "changed")

local point = Path2DControlPoint.new(UDim2.fromScale(0.5, 0.25))
assert(typeof(point) == "Path2DControlPoint")
assert(point.Position == UDim2.fromScale(0.5, 0.25))
assert(point.LeftTangent == UDim2.new() and point.RightTangent == UDim2.new())
assert(tostring(Path2DControlPoint.new()) ==
    "Path2DControlPoint { Position = {0, 0}, {0, 0}, LeftTangent = {0, 0}, {0, 0}, RightTangent = {0, 0}, {0, 0} }")
local explicitNilOk, explicitNilError = pcall(Path2DControlPoint.new, nil)
assert(not explicitNilOk)
assert(explicitNilError == "invalid argument #1 to 'new' (UDim2 expected, got nil)", explicitNilError)
assert(not pcall(Path2DControlPoint.new, UDim2.new(), nil, UDim2.new()))
assert(not pcall(Path2DControlPoint.new, UDim2.new(), UDim2.new()))
assert(not pcall(Path2DControlPoint.new, UDim2.new(), UDim2.new(), UDim2.new(), UDim2.new()))
immutable(point, "Position", UDim2.new())

local quantizedUDim2 = UDim2.fromScale(0.14632558139534885, 0.3175555851851852)
assert(quantizedUDim2.X.Scale == 0.14632558822631836)
assert(quantizedUDim2.Y.Scale == 0.31755557656288147)

local shared = SharedTable.new({ [1] = "first", count = 2, nested = { value = true } })
assert(typeof(shared) == "SharedTable" and SharedTable.isShared(shared))
assert(not SharedTable.isShared({}) and SharedTable.size(shared) == 3 and #shared == 3)
assert(shared[1] == "first" and shared.count == 2 and typeof(shared.nested) == "SharedTable")
shared.self = shared
assert(shared.self == shared)
assert(SharedTable.increment(shared, "count", 3) == 5 and shared.count == 5)
SharedTable.update(shared, "count", function(value) return value * 2 end)
assert(shared.count == 10)
local shallow = SharedTable.clone(shared)
assert(shallow ~= shared and shallow.nested == shared.nested and shallow.self == shared)
local deep = SharedTable.clone(shared, true)
assert(deep ~= shared and deep.nested ~= shared.nested and deep.self == deep)
local frozen = SharedTable.cloneAndFreeze(shared, true)
assert(SharedTable.isFrozen(frozen) and SharedTable.isFrozen(frozen.nested))
assert(not pcall(function() frozen.count = 0 end))
assert(not pcall(function() SharedTable.clear(frozen) end))
assert(not pcall(function() shared[true] = 1 end))
assert(not pcall(function() shared.bad = function() end end))
local observed = {}
for key, value in shared do observed[key] = value end
assert(observed[1] == "first" and observed.count == 10 and observed.self == shared)
SharedTable.update(shared, "count", function() return nil end)
assert(shared.count == nil)
SharedTable.clear(shallow)
assert(SharedTable.size(shallow) == 0)

-- Exercise the graph collector with self-cycles that have no remaining Lua
-- roots. This is a regression guard against a per-run C++ shared_ptr leak.
for _ = 1, 1000 do
    local cycle = SharedTable.new()
    cycle.self = cycle
end

for _, constructor in ipairs({
    Axes, Faces, Region3int16, Font, FloatCurveKey, RotationCurveKey, ValueCurveKey,
    Content, DockWidgetPluginGuiInfo, CatalogSearchParams, SecurityCapabilities,
    PathWaypoint, Path2DControlPoint, SharedTable,
}) do
    assert(table.isfrozen(constructor), "constructor table must be frozen")
end

print("release729-datatypes-native-ok")
return true
