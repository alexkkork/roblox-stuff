assert(type(loadstring) == "function", "forced Luraph mode did not expose loadstring")
assert(debug.info(loadstring, "s") == "[C]", "loadstring did not report native [C] metadata")
assert(iscclosure == nil or iscclosure(loadstring), "loadstring was not a native C closure")
assert(islclosure == nil or not islclosure(loadstring), "loadstring unexpectedly exposed a Luau wrapper")

local chunk, compileError = loadstring("return 42")
assert(chunk, compileError)
assert(chunk() == 42, "compiled loadstring chunk returned the wrong value")

print("forced-luraph-native-loadstring-ok")
