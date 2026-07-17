-- Public Roblox constructors are native APIs. Keep the public closure native
-- while preserving the setup layer's defaults and parent sequencing.
assert(type(Instance) == "table")
assert(type(Instance.new) == "function")
assert(iscclosure(Instance.new), "Instance.new must be a native C closure")
assert(not islclosure(Instance.new), "Instance.new must not expose the Luau setup wrapper")
assert(debug.info(Instance.new, "s") == "[C]", "Instance.new leaked its setup-script source")
assert(type(Instance.fromExisting) == "function" and iscclosure(Instance.fromExisting))
assert(debug.info(Instance.fromExisting, "s") == "[C]")

local parent = Instance.new("Folder")
parent.Name = "ConstructorParent"

local part = Instance.new("Part", parent)
assert(typeof(part) == "Instance" and part.ClassName == "Part")
assert(part.Name == "Part" and part.Parent == parent)
assert(parent:FindFirstChild("Part") == part)

-- These values are applied by the current setup wrapper. A native facade must
-- not bypass them when it forwards construction.
assert(part.Size == Vector3.new(4, 1, 2))

part.Name = "SourcePart"
part.Archivable = false
part:SetAttribute("answer", 42)
part:AddTag("copied")
local child = Instance.new("Folder", part)
local existingCopy = Instance.fromExisting(part)
assert(existingCopy ~= part and existingCopy.ClassName == "Part")
assert(existingCopy.Name == "SourcePart" and existingCopy.Archivable == false)
assert(existingCopy.Parent == nil and #existingCopy:GetChildren() == 0)
assert(existingCopy:GetAttribute("answer") == 42 and existingCopy:HasTag("copied"))
child:Destroy()
assert(part.CanCollide == true and part.CanQuery == true and part.CanTouch == true)
assert(part.Transparency == 0 and part.Reflectance == 0)

local ok, message = pcall(Instance.new, "DefinitelyNotAClass")
assert(not ok and string.find(tostring(message), "DefinitelyNotAClass", 1, true) ~= nil)

print("instance-constructor-native-v3-ok")
