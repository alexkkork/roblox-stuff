local parts = {}

for i = 0, 255 do
    parts[#parts + 1] = string.char(i)
end

return table.concat(parts):rep(4)
