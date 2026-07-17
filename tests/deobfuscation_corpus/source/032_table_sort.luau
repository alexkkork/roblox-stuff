-- corpus: table_sort; variant: 2
local values = {39, 32, 35, 31}
table.sort(values)
print(table.concat(values, ","))
