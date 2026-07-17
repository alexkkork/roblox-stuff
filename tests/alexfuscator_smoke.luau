local RunService = game:GetService("RunService")
local message = table.concat({"alex", "fuscator", "smoke"}, "-")

local function describe(value: number)
    local shifted = value + 7
    if typeof(Vector3.new(1, 2, 3)) == "Vector3" and RunService:IsClient() then
        return message .. ":" .. tostring(shifted)
    end
    return "unexpected"
end

return describe(35)
