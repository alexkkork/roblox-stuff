-- Reconstructed from the Prometheus register VM used by WeAreDevs v1.
local effect_count = 0
local effect_trace = ""
local branch_result = "miss"

local function mark(label, value)
    effect_count += 1
    effect_trace ..= label .. tostring(effect_count)
    return value
end

local function many()
    return 11, 29
end

local function countValues(...)
    return select("#", ...), ...
end

local function consume(callback)
    return callback(5)
end

local temporary
local local_2, local_3, local_5, local_9, local_11, local_13, local_15, local_16, local_17, local_18
temporary = many()
local_2, local_3 = temporary
temporary = mark("A", 4)
local_5 = temporary + mark("B", 6)
temporary = mark("C", true)
if temporary then
    branch_result = "hit"
end

temporary = mark("M", 7)
local_11 = temporary + temporary

temporary = mark("I", 8)
effect_trace ..= "|gap|"
local_13 = temporary + 1

temporary = function(value)
    return mark("D", value * 3)
end
local callback = temporary
local_9 = consume(callback)

temporary = many()
local_15, local_16, local_17 = countValues(temporary)

temporary = many()
local_18 = {temporary}

return local_2, local_3, local_5, effect_trace, branch_result, local_9, local_11, local_13, effect_count,
    local_15, local_16, local_17, #local_18, local_18[1], local_18[2]
