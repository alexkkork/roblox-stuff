-- corpus: recursion; variant: 5
local function fib(x)
  if x < 2 then return x end
  return fib(x - 1) + fib(x - 2)
end
print(fib(9))
