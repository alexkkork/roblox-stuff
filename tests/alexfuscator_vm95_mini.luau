local RunService = game:GetService("RunService")

local total = 0
for i = 1, 4 do
    total += i
end

local words = {"alex", "vm", "ok"}
local i = 0
local joined = ""
while i < #words do
    i += 1
    joined = joined .. words[i]
    if i < #words then
        joined = joined .. "-"
    end
end

local info = {
    mode = joined,
    total = total,
    client = RunService:IsClient(),
    vectorType = typeof(Vector3.new(1, 2, 3)),
}

return info.mode .. ":" .. tostring(info.total) .. ":" .. tostring(info.client) .. ":" .. info.vectorType
