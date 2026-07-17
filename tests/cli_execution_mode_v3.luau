local _ = CLI_EXECUTION_MODE_MISSING_GLOBAL
assert(iscclosure(pcall), "faithful mode replaced the native pcall primitive")
local typeofOk, typeofError = pcall(typeof)
assert(not typeofOk and tostring(typeofError) == "missing argument #1", "typeof() lost the release-729 missing-argument contract")
assert(typeof(nil) == "nil", "typeof(nil) must remain distinct from a missing argument")
print("cli-execution-mode-v3-ok")
return true
