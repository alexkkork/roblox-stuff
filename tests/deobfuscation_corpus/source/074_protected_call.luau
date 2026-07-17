-- corpus: protected_call; variant: 4
local ok, message = pcall(function()
  if 74 % 2 == 0 then error("even-74") end
  return "odd-74"
end)
print(ok, message)
