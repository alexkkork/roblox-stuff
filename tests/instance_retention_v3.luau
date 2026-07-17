local iterations = math.max(0, math.floor(tonumber(RETENTION_ITERATIONS) or 2500))

local stale = Instance.new("Folder")
stale.Name = "RetainedIdentity"
stale.Archivable = false
stale:Destroy()

assert(typeof(stale) == "Instance")
assert(stale.ClassName == "Folder" and stale.Name == "RetainedIdentity")
assert(stale.Parent == nil and stale.Archivable == false)
assert(tostring(stale) == "RetainedIdentity")
assert(stale:IsA("Instance") and stale:GetFullName() == "RetainedIdentity")
stale:Destroy()

local readable, readError = pcall(function()
    return stale:GetChildren()
end)
assert(not readable and string.find(tostring(readError), "destroyed Instance", 1, true))
assert(not pcall(function()
    stale.Name = "mutated"
end))

for index = 1, iterations do
    local value = Instance.new("Folder")
    value.Name = "Transient" .. tostring(index % 32)
    value:SetAttribute("Index", index)
    value:Destroy()
    if index % 256 == 0 and type(collectgarbage) == "function" then
        pcall(collectgarbage, "collect")
    end
end

if type(collectgarbage) == "function" then
    pcall(collectgarbage, "collect")
    pcall(collectgarbage, "collect")
end

print("instance-retention-v3-ok:" .. tostring(iterations))
return iterations
