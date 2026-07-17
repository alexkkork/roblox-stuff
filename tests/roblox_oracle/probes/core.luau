local HttpService = game:GetService("HttpService")
local result = {}

local folder = Instance.new("Folder")
folder.Name = "OracleFolder"
local part = Instance.new("Part")
part.Name = "OraclePart"
part:SetAttribute("Level", 7)
part:AddTag("Enemy")
part.Parent = folder

result.instance = {
    type = type(part),
    typeof = typeof(part),
    class = part.ClassName,
    is_base_part = part:IsA("BasePart"),
    child_lookup = folder.OraclePart == part,
    child_count = #folder:GetChildren(),
    attribute = part:GetAttribute("Level"),
    tag = part:HasTag("Enemy"),
}

local order = {}
table.insert(order, "start")
task.defer(function() table.insert(order, "defer") end)
task.spawn(function()
    table.insert(order, "spawn")
    task.wait()
    table.insert(order, "spawn-resume")
end)
task.delay(0, function() table.insert(order, "delay") end)
table.insert(order, "after")
task.wait(0.05)
result.scheduler = order

local changed = 0
part:GetPropertyChangedSignal("Name"):Connect(function() changed += 1 end)
part.Name = "Renamed"
task.wait()
result.property_changed = changed

result.types = {
    vector = tostring(Vector3.new(1, 2, 3)),
    vector_type = typeof(Vector3.new()),
    cframe_type = typeof(CFrame.new()),
    range_type = typeof(NumberRange.new(1, 2)),
    enum = tostring(Enum.UserInputState.Begin),
}

local badClassOk, badClassError = pcall(function() Instance.new("DefinitelyNotAClass") end)
result.errors = {
    bad_class_ok = badClassOk,
    bad_class_mentions_class = string.find(tostring(badClassError), "DefinitelyNotAClass", 1, true) ~= nil,
}

print("RBX_ORACLE_JSON:" .. HttpService:JSONEncode(result))
