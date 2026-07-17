local retained = {}
while true do
    retained[#retained + 1] = string.rep("memory-limit-contract", 65536) .. tostring(#retained)
end
