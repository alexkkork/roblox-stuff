local function weightedSum(...)
    local values = {...}
    local total = 0
    for index, value in ipairs(values) do
        total += index * value
    end
    return total
end

local function makeCounter(startValue)
    local currentValue = startValue
    return function(amount)
        currentValue += amount or 1
        return currentValue
    end
end

local function factorial(value)
    if value <= 1 then
        return 1
    end
    return value * factorial(value - 1)
end

local function pair(value)
    return value, value + 1
end

local counter = makeCounter(10)
local first = counter(2)
local second = counter()
local left, right = pair(4)
local total = 0

for index = 1, 5 do
    if index == 3 then
        continue
    end
    total += index
end

repeat
    total += 1
until total >= 13

local object = {base = 10}
object.add = function(self, value)
    return self.base + value
end

local methodResult = object:add(5)
local weighted = weightedSum(2, 4, 6)
local choice = if total > 0 then "yes" else "no"
local label = `alex {choice}`

print("alex1-semantics", first, second, left, right, total, methodResult, weighted, factorial(5), label)
return first, second, weighted
