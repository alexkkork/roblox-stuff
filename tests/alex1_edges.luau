-- A line comment must not become floor division.
-- A paired Luau fixture is the runtime semantic oracle for the Alex frontend.
local function triple(value)
    return value, value + 1, value + 2
end

local function addThree(first, second, third)
    return first + second + third
end

local function factorial(value)
    if value <= 1 then
        return 1
    end
    return value * factorial(value - 1)
end

local function makeStepper(startValue)
    local currentValue = startValue
    return function(amount)
        currentValue += amount or 1
        return currentValue
    end
end

local function forward(...)
    return ...
end

local floorValue = 17 // 5
floorValue //= 2
local negativeFloor = -17 // 5

local first, second, third = forward(triple(4))
local expanded = addThree(1, triple(2))
local truncated = addThree((triple(7)), 8, 9)

local trace = ""
local storage = {value = 10}

local function targetObject()
    trace ..= "O"
    return storage
end

local function targetKey()
    trace ..= "K"
    return "value"
end

local function assignedValue()
    trace ..= "R"
    return 5
end

targetObject()[targetKey()] += assignedValue()

local loopTotal = 0
for index = 1, 10 do
    if index == 2 then
        continue
    end
    if index == 6 then
        break
    end
    loopTotal += index
end

local whileCount = 0
while whileCount < 4 do
    whileCount += 1
    if whileCount == 2 then
        continue
    end
    loopTotal += whileCount
end

repeat
    loopTotal += 1
until loopTotal >= 22

for index, value in ipairs({2, 3}) do
    loopTotal += index * value
end

local stepper = makeStepper(10)
local stepOne = stepper(2)
local stepTwo = stepper()
local label = `edge {floorValue}:{factorial(5)}:{trace}`

print(
    "alex1-edges",
    floorValue,
    negativeFloor,
    first,
    second,
    third,
    expanded,
    truncated,
    storage.value,
    trace,
    loopTotal,
    stepOne,
    stepTwo,
    label
)

return floorValue, negativeFloor, storage.value, loopTotal, stepTwo
