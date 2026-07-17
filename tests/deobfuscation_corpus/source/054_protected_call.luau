-- corpus: protected_call; variant: 3
local ok, message = pcall(function()
  if 54 % 2 == 0 then error("even-54") end
  return "odd-54"
end)
print(ok, message)
