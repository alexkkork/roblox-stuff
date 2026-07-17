local CollectionService = game:GetService("CollectionService")

-- Studio exposes constructors through native locked tables. In particular,
-- Instance.new must not be a script wrapper whose source/environment can be
-- observed or replaced by protected-loader integrity checks.
assert(iscclosure == nil or iscclosure(Instance.new))
assert(islclosure == nil or not islclosure(Instance.new))
assert(debug.info(Instance.new, "s") == "[C]")

-- Canonical aliases share storage and property signals with their preferred
-- descriptor, and equal assignments never emit a change.
local part = Instance.new("Part")
assert(getmetatable(game) == "The metatable is locked")
assert(getmetatable(part) == "The metatable is locked")
assert(typeof(part.Changed) == "RBXScriptSignal" and part.Changed.Fire == nil)
local lockedConnection = part.Changed:Connect(function() end)
assert(typeof(lockedConnection) == "RBXScriptConnection" and lockedConnection.Connected == true)
assert(debug.info(lockedConnection.Disconnect, "n") == "Disconnect")
assert(not pcall(function() lockedConnection.Connected = false end))
lockedConnection:Disconnect()
assert(lockedConnection.Connected == false)
local nameChanges = 0
local archivableChanges = 0
part:GetPropertyChangedSignal("Name"):Connect(function() nameChanges += 1 end)
part:GetPropertyChangedSignal("archivable"):Connect(function() archivableChanges += 1 end)
part.Name = "Part"
part.Name = "Renamed"
part.Name = "Renamed"
part.archivable = false
part.Archivable = false
task.wait()
assert(nameChanges == 1)
assert(archivableChanges == 1)
assert(part.className == "Part" and part.archivable == false)
assert(part:isA("BasePart"))

-- Attribute names and value types are validated, removals use nil, and signals
-- are suppressed when the semantic value is unchanged.
local attributeChanges = 0
part:GetAttributeChangedSignal("Health"):Connect(function() attributeChanges += 1 end)
part:SetAttribute("Health", 100)
part:SetAttribute("Health", 100)
part:SetAttribute("Health", nil)
part:SetAttribute("Health", nil)
task.wait()
assert(attributeChanges == 2 and part:GetAttribute("Health") == nil)
assert(not pcall(function() part:SetAttribute("bad name", 1) end))
assert(not pcall(function() part:SetAttribute("RBXInternal", 1) end))
assert(not pcall(function() part:SetAttribute("Unsupported", {}) end))

-- Moving a rooted subtree reports every descendant to the old/new ancestor and
-- gives each descendant its own identity and unchanged direct Parent.
local destination = Instance.new("Folder", workspace)
local root = Instance.new("Folder")
local branch = Instance.new("Folder", root)
local leaf = Instance.new("Part", branch)
local added, removing = {}, {}
destination.DescendantAdded:Connect(function(value) table.insert(added, value) end)
destination.DescendantRemoving:Connect(function(value) table.insert(removing, value) end)
local ancestryChild, ancestryParent
leaf.AncestryChanged:Connect(function(child, parent)
    ancestryChild, ancestryParent = child, parent
end)
root.Parent = destination
task.wait()
assert(#added == 3 and table.find(added, root) and table.find(added, branch) and table.find(added, leaf))
assert(ancestryChild == leaf and ancestryParent == branch)
root.Parent = nil
task.wait()
assert(#removing == 3 and table.find(removing, root) and table.find(removing, branch) and table.find(removing, leaf))

-- Clone is two-pass: Instance-valued properties that point inside the cloned
-- graph are redirected to the corresponding clone, not the original graph.
local model = Instance.new("Model")
model.Name = "CloneSource"
assert(model.PrimaryPart == nil)
local primary = Instance.new("Part", model)
primary.Name = "Primary"
model.PrimaryPart = primary
local clone = model:Clone()
assert(clone ~= model and clone.Primary ~= primary)
assert(clone.PrimaryPart == clone.Primary)
local cameraWithReadOnlyDefaults = Instance.new("Camera")
assert(cameraWithReadOnlyDefaults.ViewportSize == Vector2.new(1920, 1080) and cameraWithReadOnlyDefaults.CameraSubject == nil)

local testedHumanoid = Instance.new("Humanoid")
local healthEvents, diedEvents = {}, 0
testedHumanoid.HealthChanged:Connect(function(value) table.insert(healthEvents, value) end)
testedHumanoid.Died:Connect(function() diedEvents += 1 end)
testedHumanoid:TakeDamage(25)
testedHumanoid:TakeDamage(1000)
testedHumanoid:TakeDamage(1)
task.wait()
assert(testedHumanoid.Health == 0 and #healthEvents == 2 and healthEvents[1] == 75 and healthEvents[2] == 0 and diedEvents == 1)
testedHumanoid:Move(Vector3.new(1, 0, 0))
assert(testedHumanoid.MoveDirection == Vector3.new(1, 0, 0))
local oldState = testedHumanoid:GetState()
testedHumanoid:ChangeState(Enum.HumanoidStateType.Jumping)
assert(oldState ~= testedHumanoid:GetState() and testedHumanoid:GetState() == Enum.HumanoidStateType.Jumping)

local originalBindable = Instance.new("BindableEvent")
local originalFires = 0
originalBindable.Event:Connect(function() originalFires += 1 end)
local clonedBindable = originalBindable:Clone()
clonedBindable:Fire()
task.wait()
assert(originalFires == 0)

-- Class-qualified method dispatch prevents an unrelated implementation with the
-- same member name from being selected.
assert(not pcall(function() part:Play() end))
local sound = Instance.new("Sound")
sound:Play()
assert(sound.Playing == true)

-- The native tag index includes unparented live Instances and emits collection
-- signals for direct Instance:AddTag calls exactly once.
local taggedAdded, taggedRemoved = 0, 0
CollectionService:GetInstanceAddedSignal("DirectTag"):Connect(function(value)
    if value == part then taggedAdded += 1 end
end)
CollectionService:GetInstanceRemovedSignal("DirectTag"):Connect(function(value)
    if value == part then taggedRemoved += 1 end
end)
part:AddTag("DirectTag")
part:AddTag("DirectTag")
task.wait()
assert(taggedAdded == 1 and table.find(CollectionService:GetTagged("DirectTag"), part))
part:RemoveTag("DirectTag")
part:RemoveTag("DirectTag")
task.wait()
assert(taggedRemoved == 1 and not table.find(CollectionService:GetTagged("DirectTag"), part))

local doomed = Instance.new("Folder")
local destroyingFired, destroyedTagRemoved = 0, 0
doomed:AddTag("DestroyedTag")
local destroyingConnection = doomed.Destroying:Connect(function() destroyingFired += 1 end)
CollectionService:GetInstanceRemovedSignal("DestroyedTag"):Connect(function(value)
    if value == doomed then destroyedTagRemoved += 1 end
end)
doomed:Destroy()
task.wait()
assert(destroyingFired == 1 and destroyedTagRemoved == 1 and destroyingConnection.Connected == false)
local constructorChild = Instance.new("Folder", doomed)
assert(constructorChild.Parent == doomed)
local assignedChild = Instance.new("Folder")
assignedChild.Parent = doomed
assert(assignedChild.Parent == doomed)
constructorChild:Destroy()
assignedChild:Destroy()

local waitTarget = Instance.new("Folder", workspace)
waitTarget.Name = "NativeWaitTarget"
assert(debug.info(workspace.WaitForChild, "s") == "[C]")
assert(debug.info(workspace.WaitForChild, "n") == "WaitForChild")
assert(not pcall(setfenv, workspace.WaitForChild, {}))
assert(workspace:WaitForChild("NativeWaitTarget") == waitTarget)
assert(workspace:WaitForChild("MissingWaitTarget", 0) == nil)
waitTarget:Destroy()

-- Full metadata drives read-only enforcement and strict unsupported reads.
assert(not pcall(function() part.AssemblyMass = 4 end))
assert(not pcall(function() return part.AssemblyMass end))

local range = NumberRange.new(2, 4)
assert(typeof(range) == "NumberRange" and type(range) == "userdata")
assert(getmetatable(range) == "The metatable is locked" and not pcall(function() range.Min = 0 end))
local zeroPoint = Path2DControlPoint.new()
local position = UDim2.new(0.25, 2, 0.5, 4)
local left = UDim2.new(0, -1, 0, -2)
local right = UDim2.new(0, 1, 0, 2)
local onePoint = Path2DControlPoint.new(position)
local fullPoint = Path2DControlPoint.new(position, left, right)
assert(typeof(zeroPoint) == "Path2DControlPoint" and type(zeroPoint) == "userdata")
assert(getmetatable(zeroPoint) == "The metatable is locked")
assert(zeroPoint.Position == UDim2.new() and zeroPoint.LeftTangent == UDim2.new() and zeroPoint.RightTangent == UDim2.new())
assert(onePoint.Position == position and onePoint.LeftTangent == UDim2.new() and onePoint.RightTangent == UDim2.new())
assert(fullPoint.Position == position and fullPoint.LeftTangent == left and fullPoint.RightTangent == right)
assert(not pcall(function() fullPoint.Position = UDim2.new() end))
assert(not pcall(function() Path2DControlPoint.new(Vector2.new()) end))
assert(not pcall(Path2DControlPoint.new, nil))
assert(not pcall(Path2DControlPoint.new, position, nil, right))
local path2D = Instance.new("Path2D")
assert(path2D:GetMaxControlPoints() == 100 and path2D:GetLength() == 0)
path2D:SetControlPoints({ onePoint, fullPoint })
local controlPoints = path2D:GetControlPoints()
assert(#controlPoints == 2 and controlPoints[1] == onePoint and path2D:GetControlPoint(2) == fullPoint)
controlPoints[1] = zeroPoint
assert(path2D:GetControlPoint(1) == onePoint)
assert(not pcall(path2D.SetControlPoints, path2D, nil))
assert(not pcall(path2D.SetControlPoints, path2D, { onePoint, "invalid" }))
local screenGui = Instance.new("ScreenGui")
local pathFrame = Instance.new("Frame")
pathFrame.Size = UDim2.fromOffset(258, 270)
pathFrame.Parent = screenGui
path2D.Parent = pathFrame
path2D:SetControlPoints({
    Path2DControlPoint.new(UDim2.new(0.3125, -10, 0.375, -10), UDim2.new(0, -1, 0, -6), UDim2.new(0.125, 6, 0, -1)),
    Path2DControlPoint.new(UDim2.new(0.125, -5, 0.5, -3), UDim2.new(), UDim2.new(0, 5, 0, 6)),
    Path2DControlPoint.new(UDim2.new(0, -7, 0.25, 0), UDim2.new(0, -7, 0, 5), UDim2.new(0, -5, 0, -5)),
    Path2DControlPoint.new(UDim2.new(0.5, 3, 0.5, -3), UDim2.new(0, -7, 0, -8), UDim2.new(0, -6, -0.125, -3)),
    Path2DControlPoint.new(UDim2.new(0, -10, 0, 6), UDim2.new(0.125, -5, 0, 2), UDim2.new(0.125, -6, 0.125, 0)),
})
assert(math.abs(path2D:GetLength() - 504.99163818359375) < 0.01)
local curvePosition = path2D:GetPositionOnCurve(0.6000000238418579)
assert(math.abs(curvePosition.X.Scale - 0.14632564783096313) < 0.000001 and curvePosition.X.Offset == 0)
assert(math.abs(curvePosition.Y.Scale - 0.31755557656288147) < 0.000001 and curvePosition.Y.Offset == 0)
local secondCurvePosition = path2D:GetPositionOnCurve(0.4545454680919647)
assert(secondCurvePosition.X.Scale == -0.02389647625386715)
assert(secondCurvePosition.Y.Scale == 0.2793847620487213)
local firstSignal = game.DescendantRemoving
local signalKeys = { [firstSignal] = true }
local secondSignal = game.DescendantRemoving
assert(firstSignal == secondSignal)
assert(signalKeys[firstSignal] == true and signalKeys[secondSignal] == nil)
assert(debug.info(firstSignal.Connect, "n") == "Connect")
assert(debug.info(firstSignal.Once, "n") == "Once")
assert(debug.info(firstSignal.Wait, "n") == "Wait")
local randomA, randomB = Random.new(), Random.new()
local randomA1, randomA2 = randomA:NextInteger(1, 100000), randomA:NextInteger(1, 100000)
local randomB1, randomB2 = randomB:NextInteger(1, 100000), randomB:NextInteger(1, 100000)
assert(typeof(randomA) == "Random" and randomA1 >= 1 and randomA1 <= 100000 and randomA2 >= 1 and randomA2 <= 100000)
assert(randomA1 ~= randomB1 or randomA2 ~= randomB2)
local seededA, seededB = Random.new(729), Random.new(729)
assert(seededA:NextInteger(-1000, 1000) == seededB:NextInteger(-1000, 1000))
assert(seededA:NextNumber() == seededB:NextNumber())
assert(__rbx_instance_internal_property == nil and __rbx_instance_set_default == nil and __rbx_instance_tagged == nil)
assert(__rbx_class_methods == nil and __rbx_collection_tag_changed == nil)

print("instance-reflection-v3-ok")
