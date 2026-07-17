local pendingParent = Instance.new("Folder")
pendingParent.Name = "PendingParent"
pendingParent.Parent = workspace

task.spawn(function()
    local ok, result = pcall(function()
        return pendingParent:WaitForChild("NeverCreated", 0.05)
    end)
    print("WAIT_DESTROYED_PENDING", ok, result == nil, tostring(result))
end)

task.defer(function()
    pendingParent:Destroy()
end)

local alreadyDestroyed = Instance.new("Folder")
alreadyDestroyed.Name = "AlreadyDestroyed"
alreadyDestroyed:Destroy()

task.spawn(function()
    local ok, result = pcall(function()
        return alreadyDestroyed:WaitForChild("NeverCreated", 0.05)
    end)
    print("WAIT_DESTROYED_EXISTING", ok, result == nil, tostring(result))
end)

task.wait(0.2)
