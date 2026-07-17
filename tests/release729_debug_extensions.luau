local expected = {
    dumpcodesize = true,
    dumpheap = true,
    dumprefs = true,
    getmemorycategory = true,
    info = true,
    loadmodule = true,
    profilebegin = true,
    profileend = true,
    resetmemorycategory = true,
    setmemorycategory = true,
    tracerefs = true,
    traceback = true,
}

local count = 0
for name, value in next, debug do
    assert(expected[name], "unexpected debug member " .. tostring(name))
    assert(type(value) == "function" and debug.info(value, "s") == "[C]", name .. " must be native")
    count += 1
end
assert(count == 12, "release 729 exposes exactly twelve Studio-visible debug members")

local automatic = debug.getmemorycategory()
assert(type(automatic) == "string" and #automatic > 0)
assert(debug.setmemorycategory("LuraphRunnerTest") == nil)
assert(debug.getmemorycategory() == "LuraphRunnerTest")
assert(debug.resetmemorycategory() == nil)
assert(debug.getmemorycategory() == automatic)

debug.profilebegin("outer")
debug.profilebegin("inner")
debug.profileend()
debug.profileend()
debug.profileend() -- unmatched blocks are a non-fatal profiler diagnostic

local ok, message = pcall(debug.dumpcodesize)
assert(not ok and string.find(message, "CommandBar", 1, true))
for _, name in ipairs({ "dumpheap", "dumprefs", "tracerefs", "loadmodule" }) do
    local available, diagnostic = pcall(debug[name])
    assert(not available and string.find(diagnostic, "not enabled", 1, true))
end
assert(not pcall(debug.setmemorycategory, ""))

print("release729-debug-extensions-ok")
