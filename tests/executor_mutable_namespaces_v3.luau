local executor = type(identifyexecutor) == "function"
assert(type(shared) == "table" and not table.isfrozen(shared))
shared.__release729_shared_probe = 729
assert(shared.__release729_shared_probe == 729)
shared.__release729_shared_probe = nil
local namespaces = {
    string,
    table,
    math,
    coroutine,
}

for index, namespace in ipairs(namespaces) do
    local ok, message = pcall(function()
        namespace.__release729_write_probe = index
    end)
    if executor then
        assert(ok, tostring(message))
        assert(namespace.__release729_write_probe == index)
        namespace.__release729_write_probe = nil
        assert(not table.isfrozen(namespace))
    else
        assert(not ok, "roblox-client namespace unexpectedly allowed a write")
        assert(table.isfrozen(namespace))
    end
end

for _, locked in ipairs({ task, Instance, Path2DControlPoint, SharedTable, Enum }) do
    assert(table.isfrozen(locked), "Roblox/native namespace unexpectedly became writable")
end

if executor then
    assert(iscclosure(identifyexecutor), "identifyexecutor must be a native executor primitive")
    assert(iscclosure(getexecutorname), "getexecutorname must be a native executor primitive")
    for _, callback in ipairs({ getgenv, getrenv, getsenv, gethui, cloneref, compareinstances, checkcaller }) do
        assert(iscclosure(callback) and not islclosure(callback), "executor primitive must be a native closure")
        assert(debug.info(callback, "s") == "[C]", "executor primitive leaked its setup wrapper")
    end
    local executorName, executorVersion = identifyexecutor()
    assert(executorName == "RobloxLuauRuntime" and executorVersion == "3.0")
    assert(getexecutorname() == executorName)

    local dynamic = assert(loadstring("return 1"))
    assert(debug.info(dynamic, "s") == "[string \"return 1\"]",
        "loadstring did not derive its default chunk name from the source")
    assert(dynamic() == 1)

    local originalByte = string.byte
    string.byte = function() return 321 end
    assert(string.byte("A") == 321, "safeenv/import cache ignored the private string library")
    string.byte = originalByte

    local scriptEnvironment = getfenv(0)
    local scriptMetatable = getmetatable(scriptEnvironment)
    assert(type(scriptMetatable) == "table" and not table.isfrozen(scriptMetatable), "executor environment proxy stayed frozen")

    -- Private executor namespaces must retain the sealed host table's native
    -- node layout. Rebuilding a table through next/rawset can expose a
    -- different next() sequence even when every key/value is identical.
    local hostEnvironment = rawget(scriptMetatable, "__index")
    assert(type(hostEnvironment) == "table", "executor environment proxy lost its sealed host environment")
    for _, namespaceName in ipairs({ "debug", "utf8" }) do
        local privateNamespace = rawget(scriptEnvironment, namespaceName)
        local sealedNamespace = rawget(hostEnvironment, namespaceName)
        assert(type(privateNamespace) == "table", namespaceName .. " private namespace is missing")
        assert(type(sealedNamespace) == "table", namespaceName .. " sealed namespace is missing")
        assert(privateNamespace ~= sealedNamespace, namespaceName .. " leaked the sealed namespace into executor-client")
        assert(not table.isfrozen(privateNamespace), namespaceName .. " private namespace stayed frozen")
        assert(table.isfrozen(sealedNamespace), namespaceName .. " host namespace unexpectedly became mutable")

        local privateKey = nil
        local sealedKey = nil
        while true do
            privateKey = next(privateNamespace, privateKey)
            sealedKey = next(sealedNamespace, sealedKey)
            assert(privateKey == sealedKey,
                namespaceName .. " next() order differs from the sealed release-729 namespace: "
                    .. tostring(privateKey) .. " ~= " .. tostring(sealedKey))
            if privateKey == nil then
                break
            end
        end
    end

    scriptMetatable.__release729_proxy_probe = true
    assert(scriptMetatable.__release729_proxy_probe == true)
    scriptMetatable.__release729_proxy_probe = nil

    local runtimeEnvironment = getrenv()
    assert(type(runtimeEnvironment) == "table" and not table.isfrozen(runtimeEnvironment), "getrenv exposed the frozen host environment")
    assert(runtimeEnvironment ~= scriptEnvironment, "getrenv should use an isolated overlay")
    assert(runtimeEnvironment.game == game and runtimeEnvironment.string == string, "getrenv overlay lost script-visible APIs")
    runtimeEnvironment.__release729_runtime_probe = 729
    assert(runtimeEnvironment.__release729_runtime_probe == 729)
    runtimeEnvironment.__release729_runtime_probe = nil

    for _, compatibilityNamespace in ipairs({ syn, http }) do
        assert(type(compatibilityNamespace) == "table" and not table.isfrozen(compatibilityNamespace))
        compatibilityNamespace.__release729_write_probe = true
        compatibilityNamespace.__release729_write_probe = nil
    end
else
    assert(table.isfrozen(getmetatable(getfenv(0))), "roblox-client environment proxy unexpectedly became writable")
    assert(getrenv == nil and getgenv == nil, "roblox-client exposed executor environments")
end

-- Namespace copies must retain the native entries and locked value behavior.
assert(string.byte("A") == 65)
assert(typeof(Path2DControlPoint.new()) == "Path2DControlPoint")
assert(typeof(SharedTable.new()) == "SharedTable")
assert(iscclosure == nil or iscclosure(Path2DControlPoint.new))

print(executor and "executor-mutable-namespaces-v3-ok" or "roblox-readonly-namespaces-v3-ok")
return true
