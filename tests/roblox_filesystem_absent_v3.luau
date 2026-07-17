for _, name in ipairs({
    "readfile", "writefile", "appendfile", "makefolder", "delfile",
    "delfolder", "isfile", "isfolder", "listfiles", "loadfile",
}) do
    assert(getfenv(0)[name] == nil, name .. " leaked into roblox-client")
end
print("roblox-filesystem-absent-v3-ok")
return true
