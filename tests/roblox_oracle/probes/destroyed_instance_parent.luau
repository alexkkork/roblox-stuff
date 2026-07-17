local destroyedParent = Instance.new("Folder")
destroyedParent.Name = "DestroyedParent"
destroyedParent:Destroy()

local constructorOk, constructorResult = pcall(Instance.new, "Folder", destroyedParent)
local assignedChild = Instance.new("Folder")
local assignmentOk, assignmentError = pcall(function()
    assignedChild.Parent = destroyedParent
end)

print(
    "DESTROYED_PARENT_ORACLE",
    constructorOk,
    constructorOk and typeof(constructorResult) or tostring(constructorResult),
    constructorOk and tostring(constructorResult.Parent) or "-",
    assignmentOk,
    assignmentOk and tostring(assignedChild.Parent) or tostring(assignmentError),
    destroyedParent.Name,
    tostring(destroyedParent.Parent)
)
