-- corpus: table_sort; variant: 5
local values = {99, 92, 95, 91}
table.sort(values)
print(table.concat(values, ","))
