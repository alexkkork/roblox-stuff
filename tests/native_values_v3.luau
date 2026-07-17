local function expectNative(value, expectedType)
    assert(type(value) == "userdata", expectedType .. " must be native userdata")
    assert(typeof(value) == expectedType)
    assert(getmetatable(value) == "The metatable is locked")
end

local function expectReadOnly(value, key, replacement)
    assert(not pcall(function()
        value[key] = replacement
    end), tostring(value) .. "." .. key .. " must be read only")
end

expectNative(Enum, "Enums")
assert(tostring(Enum) == "Enums" and not pcall(function() Enum.EasingStyle = nil end))

local easingType = Enum.EasingStyle
expectNative(easingType, "Enum")
assert(easingType.Name == "EasingStyle" and tostring(easingType) == "Enum.EasingStyle")
expectReadOnly(easingType, "Name", "Fake")
local linearItem = easingType.Linear
expectNative(linearItem, "EnumItem")
assert(linearItem.Name == "Linear" and type(linearItem.Value) == "number")
assert(linearItem.EnumType == easingType and linearItem == Enum.EasingStyle.Linear)
assert(tostring(linearItem) == "Enum.EasingStyle.Linear")
expectReadOnly(linearItem, "Name", "Fake")
assert(not pcall(function() return linearItem.__type end))
assert(not pcall(function() return easingType.__enumName end))
local easingItems = easingType:GetEnumItems()
assert(type(easingItems) == "table" and table.find(easingItems, linearItem))
easingItems[1] = nil
assert(#easingType:GetEnumItems() > 0, "GetEnumItems leaked its registry array")
assert(Enum.Axis.Left == Enum.Axis.X, "legacy Enum aliases must preserve singleton identity")

local defaults = TweenInfo.new()
expectNative(defaults, "TweenInfo")
assert(defaults.Time == 1 and defaults.EasingStyle == Enum.EasingStyle.Quad)
assert(defaults.EasingDirection == Enum.EasingDirection.Out, tostring(defaults.EasingDirection))
assert(defaults.RepeatCount == 0, tostring(defaults.RepeatCount) .. ":" .. typeof(defaults.RepeatCount))
assert(defaults.Reverses == false and defaults.DelayTime == 0)
expectReadOnly(defaults, "Time", 4)

local tween = TweenInfo.new(0.5, Enum.EasingStyle.Linear, Enum.EasingDirection.InOut, -1, true, 0.25)
assert(tween.Time == 0.5 and tween.EasingStyle == Enum.EasingStyle.Linear)
assert(tween.EasingDirection == Enum.EasingDirection.InOut and tween.RepeatCount == -1)
assert(tween.Reverses and tween.DelayTime == 0.25 and tostring(tween) == "TweenInfo")
assert(tween == TweenInfo.new(0.5, Enum.EasingStyle.Linear, Enum.EasingDirection.InOut, -1, true, 0.25))
assert(not pcall(TweenInfo.new, 1, Enum.KeyCode.A))

local range = NumberRange.new(2, 4)
expectNative(range, "NumberRange")
assert(range.Min == 2 and range.Max == 4 and tostring(range) == "2 4")
assert(range == NumberRange.new(2, 4) and NumberRange.new(3).Min == 3)
expectReadOnly(range, "Min", 0)
assert(not pcall(NumberRange.new, 4, 2))

local middle = NumberSequenceKeypoint.new(0.5, 8, 0.25)
expectNative(middle, "NumberSequenceKeypoint")
assert(middle.Time == 0.5 and middle.Value == 8 and middle.Envelope == 0.25)
expectReadOnly(middle, "Value", 0)

local sequence = NumberSequence.new({
    NumberSequenceKeypoint.new(0, 1),
    middle,
    NumberSequenceKeypoint.new(1, 3),
})
expectNative(sequence, "NumberSequence")
local numberPoints = sequence.Keypoints
assert(table.isfrozen(numberPoints) and #numberPoints == 3)
assert(typeof(numberPoints[2]) == "NumberSequenceKeypoint" and numberPoints[2] == middle)
assert(NumberSequence.new(2, 5).Keypoints[2].Value == 5)
expectReadOnly(sequence, "Keypoints", {})
assert(not pcall(NumberSequence.new, {middle, NumberSequenceKeypoint.new(1, 3)}))

local red = Color3.new(1, 0, 0)
local blue = Color3.new(0, 0, 1)
assert(type(red) == "userdata" and typeof(red) == "Color3", "existing native Color3 constructor was replaced")
local colorMiddle = ColorSequenceKeypoint.new(0.5, red)
expectNative(colorMiddle, "ColorSequenceKeypoint")
assert(colorMiddle.Time == 0.5 and colorMiddle.Value == red)
local colors = ColorSequence.new({
    ColorSequenceKeypoint.new(0, blue),
    colorMiddle,
    ColorSequenceKeypoint.new(1, red),
})
expectNative(colors, "ColorSequence")
local colorPoints = colors.Keypoints
assert(table.isfrozen(colorPoints) and #colorPoints == 3)
assert(typeof(colorPoints[1].Value) == "Color3" and colorPoints[1].Value == blue)
expectReadOnly(colors, "Keypoints", {})

local folder = Instance.new("Folder")
local part = Instance.new("Part", folder)
local raycast = RaycastParams.new()
expectNative(raycast, "RaycastParams")
assert(raycast.FilterType == Enum.RaycastFilterType.Exclude)
assert(raycast.IgnoreWater == false and raycast.RespectCanCollide == false)
assert(raycast.BruteForceAllSlow == false and raycast.CollisionGroup == "Default")
raycast.FilterDescendantsInstances = {folder}
local firstFilter = raycast.FilterDescendantsInstances
firstFilter[1] = nil
assert(#raycast.FilterDescendantsInstances == 1, "filter getter leaked mutable internal storage")
raycast:AddToFilter(part)
assert(#raycast.FilterDescendantsInstances == 2)
raycast.FilterType = Enum.RaycastFilterType.Include
raycast.IgnoreWater = true
raycast.RespectCanCollide = true
raycast.BruteForceAllSlow = true
raycast.CollisionGroup = "Queries"
assert(raycast.FilterType == Enum.RaycastFilterType.Include and raycast.IgnoreWater)
assert(raycast.RespectCanCollide and raycast.BruteForceAllSlow and raycast.CollisionGroup == "Queries")
assert(not pcall(function() raycast.MaxParts = 1 end))

local overlap = OverlapParams.new()
expectNative(overlap, "OverlapParams")
overlap.MaxParts = 12
overlap.Tolerance = 1
overlap.RespectCanCollide = true
overlap:AddToFilter({folder, part})
assert(overlap.MaxParts == 12 and overlap.Tolerance == 0.05)
assert(overlap.RespectCanCollide and #overlap.FilterDescendantsInstances == 2)
assert(not pcall(function() overlap.IgnoreWater = true end))

local date = DateTime.fromUnixTimestamp(1.5)
expectNative(date, "DateTime")
assert(date.UnixTimestamp == 1 and date.UnixTimestampMillis == 1500)
assert(date:ToUnixTimestamp() == 1 and date:ToUnixTimestampMillis() == 1500)
assert(date:ToIsoDate() == "1970-01-01T00:00:01Z")
assert(date == DateTime.fromUnixTimestampMillis(1500))
expectReadOnly(date, "UnixTimestampMillis", 0)
assert(typeof(DateTime.now()) == "DateTime")

for _, name in ipairs({
    "__rbx_value_enum_type_new", "__rbx_value_enum_item_new",
    "__rbx_value_tween_info_new", "__rbx_value_raycast_params_new", "__rbx_value_overlap_params_new",
    "__rbx_value_number_range_new", "__rbx_value_number_keypoint_new", "__rbx_value_number_sequence_new",
    "__rbx_value_color_keypoint_new", "__rbx_value_color_sequence_new", "__rbx_value_datetime_new_millis",
    "__rbx_value_random_bind_new",
}) do
    assert(_G[name] == nil, name .. " leaked into the script environment")
end

print("native-values-v3-ok")
