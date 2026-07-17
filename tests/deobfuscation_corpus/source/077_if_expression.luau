-- corpus: if_expression; variant: 4
local value = 77
local label = if value % 3 == 0 then "three" elseif value % 2 == 0 then "two" else "other"
print(label)
