local function expect(condition, message)
    if not condition then
        error(message, 0)
    end
end

local function constantFunction()
    return "before"
end

expect(islclosure(constantFunction), "protected closure should be an L closure")
expect(not iscclosure(constantFunction), "protected closure should not be a C closure")
expect(isourclosure(constantFunction), "protected closure classification failed")
expect(getconstant(constantFunction, 1) == "before", "constant read failed")
setconstant(constantFunction, 1, "after")
expect(constantFunction() == "after", "constant mutation did not affect execution")

local captured = 11
local function capturedFunction(delta)
    captured += delta
    return captured
end

local capturedIndex = nil
for index, value in ipairs(getupvalues(capturedFunction)) do
    if value == 11 then
        capturedIndex = index
        break
    end
end
expect(capturedIndex ~= nil, "captured upvalue was not exposed")
setupvalue(capturedFunction, capturedIndex, 20)
expect(capturedFunction(2) == 22, "upvalue mutation did not affect execution")

local function parent(value)
    local function child(extra)
        return value + extra
    end
    return child(3)
end

expect(parent(7) == 10, "parent closure execution failed")
local protos = getprotos(parent)
expect(#protos == 1, "child prototype count is incorrect")
expect(#getproto(parent, 1, true) == 1, "active prototype was not retained")
expect(getproto(parent, 1, true)[1](5) == 12, "active prototype contract failed")

local cloned = clonefunction(parent)
local original = hookfunction(parent, function()
    return 99
end)
expect(parent(4) == 99, "hooked closure did not redirect")
expect(original(4) == 7, "hookfunction did not return the original behavior")
expect(cloned(5) == 8, "cloned closure changed with hook")
restorefunction(parent)
expect(parent(6) == 9, "restorefunction did not restore the closure")

local function environmentFunction()
    return CONTRACT_VALUE
end
setfenv(environmentFunction, {CONTRACT_VALUE = 73})
expect(environmentFunction() == 73, "protected environment binding failed")
expect(getfenv(environmentFunction).CONTRACT_VALUE == 73, "protected environment read failed")

local source, line, name, parameterCount, vararg = debug.info(parent, "slna")
expect(source == "=[Alexfuscator]", "synthetic debug source leaked internals")
expect(type(line) == "number", "synthetic line info missing")
expect(type(name) == "string", "synthetic function name missing")
expect(parameterCount == 1 and vararg == false, "synthetic arity info is incorrect")

local info = getinfo(parent, "slnau")
expect(info.what == "Lua" and info.numparams == 1, "getinfo contract failed")
expect(type(getfunctionhash(parent)) == "string", "function hash contract failed")
expect(string.sub(getfunctionbytecode(parent), 1, 1) == string.char(27), "bytecode alias contract failed")

print("opiumware-contract-ok")
