-- corpus: protected_call; variant: 5
local ok, message = pcall(function()
  if 94 % 2 == 0 then error("even-94") end
  return "odd-94"
end)
print(ok, message)
