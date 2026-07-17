local function expectNativeFunction(value, name)
    assert(type(value) == "function", name .. " must be a function")
    assert(debug.info(value, "s") == "[C]", name .. " must report [C]")
    if type(iscclosure) == "function" then
        assert(iscclosure(value), name .. " must be a native closure")
    end
    if type(islclosure) == "function" then
        assert(not islclosure(value), name .. " must not be a Luau closure")
    end
end

assert(type(Random) == "table" and table.isfrozen(Random))
expectNativeFunction(Random.new, "Random.new")

local value = Random.new(729)
assert(type(value) == "userdata" and typeof(value) == "Random")
assert(tostring(value) == "Random")
assert(getmetatable(value) == "The metatable is locked")
assert(not pcall(function() value.state = 0 end))
assert(not pcall(function() return value._next end))

for _, name in {"Clone", "NextInteger", "NextNumber", "NextUnitVector", "Shuffle"} do
    expectNativeFunction(value[name], "Random:" .. name)
end

assert(typeof(Random.new(nil)) == "Random")
assert(typeof(Random.new("1")) == "Random", "numeric seed compatibility changed")
local okNewArity, newArityError = pcall(Random.new, 1, 2)
assert(not okNewArity and string.find(tostring(newArityError), "Random.new requires 0 or 1 argument", 1, true))
local okNumberArity, numberArityError = pcall(function() return value:NextNumber(1) end)
assert(not okNumberArity and string.find(tostring(numberArityError), "Random:NextNumber requires 0 or 2 arguments", 1, true))
assert(not pcall(function() return value:NextInteger(1) end))

local first = Random.new(729)
local second = Random.new(729)
for _ = 1, 100 do
    assert(first:NextInteger(-100000, 100000) == second:NextInteger(-100000, 100000))
    assert(first:NextNumber(-2, 2) == second:NextNumber(-2, 2))
end

-- Release-729 Studio oracle values for Roblox's PCG XSH-RR implementation.
local compatibility = Random.new(729)
assert(compatibility:NextNumber() == 0.7973870493781697)
assert(compatibility:NextNumber() == 0.38987666349787914)
assert(Random.new(729):NextInteger(-2, 2) == -1)

local original = Random.new(12345)
original:NextNumber()
original:NextInteger(1, 100)
local clone = original:Clone()
assert(clone ~= original and typeof(clone) == "Random")
assert(original:NextNumber() == clone:NextNumber(), "Clone must copy the current state")
original:NextNumber()
assert(clone:NextNumber() ~= original:NextNumber(), "Clone state must be independent")

local vectorA = Random.new(999):NextUnitVector()
local vectorB = Random.new(999):NextUnitVector()
assert(typeof(vectorA) == "Vector3" and vectorA == vectorB)
assert(math.abs(vectorA.Magnitude - 1) < 1e-6)

local threaded = Random.new(2026)
local coroutineValue
local coroutineThread = coroutine.create(function()
    coroutineValue = threaded:NextNumber()
end)
assert(coroutine.resume(coroutineThread) and type(coroutineValue) == "number")
assert(coroutine.status(coroutineThread) == "dead")

local shuffledA = {"a", "b", "c", "d", "e"}
local shuffledB = {"a", "b", "c", "d", "e"}
local shuffleA = Random.new(42)
local shuffleB = Random.new(42)
assert(select("#", shuffleA:Shuffle(shuffledA)) == 0)
shuffleB:Shuffle(shuffledB)
assert(table.concat(shuffledA, ",") == table.concat(shuffledB, ","))
table.sort(shuffledA)
assert(table.concat(shuffledA, ",") == "a,b,c,d,e")

local sparse = {[1] = "a", [3] = "c"}
local okSparse, sparseError = pcall(function() Random.new(42):Shuffle(sparse) end)
assert(not okSparse and string.find(tostring(sparseError),
    "Attempted to shuffle table containing nil values. This is not allowed because the table length may change.", 1, true))

local withDictionaryKey = {"a", "b", marker = "preserved"}
Random.new(42):Shuffle(withDictionaryKey)
assert(withDictionaryKey.marker == "preserved")
assert(not pcall(function() Random.new(42):Shuffle(table.freeze({1, 2, 3})) end))

local unseededA, unseededB = Random.new(), Random.new()
local a1, a2 = unseededA:NextInteger(1, 1000000), unseededA:NextInteger(1, 1000000)
local b1, b2 = unseededB:NextInteger(1, 1000000), unseededB:NextInteger(1, 1000000)
assert(a1 ~= b1 or a2 ~= b2, "sequential no-seed objects must use distinct streams")

assert(_G.__rbx_value_random_bind_new == nil)
assert(getfenv(0).__rbx_value_random_bind_new == nil)

print("native-random-v3-ok")
