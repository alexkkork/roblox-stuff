-- corpus: protected_call; variant: 2
local ok, message = pcall(function()
  if 34 % 2 == 0 then error("even-34") end
  return "odd-34"
end)
print(ok, message)
