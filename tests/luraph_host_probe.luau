-- Luraph compatibility probe
print("LOAD", type(loadstring), typeof(loadstring), tostring(loadstring))
print("INFO_S", debug.info(loadstring, "s"))
print("INFO_N", debug.info(loadstring, "n"))
print("INFO_A", debug.info(loadstring, "a"))
local ok, message = pcall(loadstring)
print("NOARG", ok, message)
local chunk, compileError = loadstring("return 42", "=luraph-probe")
print("COMPILE", type(chunk), compileError)
if chunk then
    print("RUN", chunk())
end
local instanceOk, instanceError = pcall(Instance.new)
print("INSTANCE_NEW_NOARG", instanceOk, instanceError)
local instanceNilOk, instanceNilError = pcall(Instance.new, nil)
print("INSTANCE_NEW_NIL", instanceNilOk, instanceNilError)
