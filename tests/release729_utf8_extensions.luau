local function expectNativeFunction(value, label)
    assert(type(value) == "function", label .. " must be a function")
    assert(debug.info(value, "s") == "[C]", label .. " must be native")
end

expectNativeFunction(utf8.graphemes, "utf8.graphemes")
expectNativeFunction(utf8.nfcnormalize, "utf8.nfcnormalize")
expectNativeFunction(utf8.nfdnormalize, "utf8.nfdnormalize")

local decomposed = "e" .. utf8.char(0x301)
local composed = utf8.char(0xe9)
assert(utf8.nfcnormalize(decomposed) == composed)
assert(utf8.nfdnormalize(composed) == decomposed)
assert(utf8.nfcnormalize("plain ASCII") == "plain ASCII")

local subject = "A" .. decomposed .. "B"
local clusters = {}
for first, last in utf8.graphemes(subject) do
    table.insert(clusters, subject:sub(first, last))
end
assert(#clusters == 3)
assert(clusters[1] == "A" and clusters[2] == decomposed and clusters[3] == "B")

local ranged = {}
for first, last in utf8.graphemes(subject, 2, 4) do
    table.insert(ranged, subject:sub(first, last))
end
assert(#ranged == 1 and ranged[1] == decomposed)

assert(not pcall(utf8.nfcnormalize, "\255"), "normalization must reject invalid UTF-8")

print("release729-utf8-extensions-ok")
