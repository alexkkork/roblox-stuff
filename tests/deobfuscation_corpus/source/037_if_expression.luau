-- corpus: if_expression; variant: 2
local value = 37
local label = if value % 3 == 0 then "three" elseif value % 2 == 0 then "two" else "other"
print(label)
