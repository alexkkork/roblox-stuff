-- corpus: protected_call; variant: 1
local ok, message = pcall(function()
  if 14 % 2 == 0 then error("even-14") end
  return "odd-14"
end)
print(ok, message)
