type Pair<T> = { first: T, second: T }

local function multi(value)
    return value, nil, value + 2
end

local function gather(prefix, ...)
    local a, b, c = ...
    return prefix, a, b, c
end

local prefix, a, b, c = gather("g", multi(4))
local grouped = (multi(5))
local expanded = {0, multi(7)}

local function factorial(value)
    if value <= 1 then
        return 1
    end
    return value * factorial(value - 1)
end

local repeatTotal = 0
local repeatIndex = 0
repeat
    repeatIndex += 1
    if repeatIndex == 2 then
        continue
    end
    repeatTotal += repeatIndex
    if repeatIndex == 4 then
        break
    end
until repeatIndex > 20

local values = {alpha = 2, beta = 3, gamma = 5}
local genericTotal = 0
for _, value in pairs(values) do
    genericTotal += value
end

local numericTotal = 0
for index = 1, 8 do
    if index == 3 then
        continue
    end
    if index == 7 then
        break
    end
    numericTotal += index
end

local scoped = 1
do
    local scoped = 9
    scoped += 2
end

local Object = {value = 10}
function Object:add(amount)
    self.value += amount
    return self.value
end

local targetHits = 0
local target = {value = 6}
local function targetKey()
    targetHits += 1
    return "value"
end
target[targetKey()] += 4

local order = ""
local assignmentTarget = {slot = 0}
local function targetObject()
    order ..= "o"
    return assignmentTarget
end
local function assignmentKey()
    order ..= "k"
    return "slot"
end
local function assignmentValue()
    order ..= "v"
    return 17
end
targetObject()[assignmentKey()] = assignmentValue()

local metaValue = setmetatable({n = 4}, {
    __add = function(left, right)
        return left.n + right
    end,
    __len = function(self)
        return self.n * 2
    end,
    __call = function(self, value)
        return self.n + value
    end,
})

local callbackResult = ({pcall(function(value)
    return value * 3
end, 6)})[2]

local coroutineValue = 0
local thread = coroutine.create(function(value)
    local resumed = coroutine.yield(value + 1)
    return resumed + 2
end)
local firstOk, firstValue = coroutine.resume(thread, 20)
local secondOk, secondValue = coroutine.resume(thread, 30)
if firstOk and secondOk then
    coroutineValue = firstValue + secondValue
end

local conditional = if numericTotal > 0 then "yes" else "no"
local interpolated = `state:{conditional}:{Object.value}`

print(
    prefix,
    a,
    tostring(b),
    c,
    grouped,
    expanded[1],
    expanded[2],
    tostring(expanded[3]),
    expanded[4],
    factorial(6),
    repeatTotal,
    genericTotal,
    numericTotal,
    scoped,
    Object:add(5),
    targetHits,
    target.value,
    order,
    assignmentTarget.slot,
    metaValue + 3,
    #metaValue,
    metaValue(8),
    callbackResult,
    coroutineValue,
    interpolated
)
