assert(readfile("fixtures/hello.txt") == "hello from scenario v2")
assert(isfile("fixtures/hello.txt"))
assert(isfolder("fixtures"))

writefile("workspace/program.luau", "return false, 'memory-only'")
appendfile("workspace/program.luau", " -- appended")
local chunk, compileError = loadfile("workspace/program.luau")
assert(chunk, compileError)
local first, second = chunk()
assert(first == false and second == "memory-only")

makefolder("workspace/nested")
writefile("workspace/nested/binary.dat", "a\0b")
assert(readfile("workspace/nested/binary.dat") == "a\0b")
local listed = listfiles("workspace")
assert(#listed == 2)
assert(listed[1] == "workspace/nested" and listed[2] == "workspace/program.luau")

assert(not pcall(readfile, "../host-secret"))
assert(not pcall(writefile, "/tmp/host-file", "blocked"))
delfile("workspace/nested/binary.dat")
delfolder("workspace/nested")
assert(not isfolder("workspace/nested"))

print("executor-memory-filesystem-v3-ok")
return true
