local environment = getfenv(0)
local missingKey = "native_trace_missing"
local missingValue = environment[missingKey]
local stringLibrary = rawget(environment, "string")

_G.native_trace_shared = 41
local sharedValue = _G.native_trace_shared

native_trace_written = sharedValue + 1
local writtenValue = native_trace_written

local loaded = assert(loadstring("return math.abs(-4), rawget(getfenv(0), 'table') ~= nil"))
setfenv(loaded, {math = math, table = table, rawget = rawget, getfenv = getfenv})
local loadedValue, loadedEnvironmentHit = loaded()

assert(missingValue == nil)
assert(type(stringLibrary) == "table")
assert(writtenValue == 42)
assert(loadedValue == 4)
assert(loadedEnvironmentHit)
print("native-environment-trace-ok")
