local item = Enum.Axis.Z

print("ENUM_ITEM_TYPE", typeof(item), type(item), tostring(item), item.Name, item.Value)
for _, className in ipairs({ "EnumItem", "Axis", "Instance", "userdata" }) do
	local ok, result = pcall(function()
		return item:IsA(className)
	end)
	print("ENUM_ITEM_ISA", className, ok, result)
end

local ok, result = pcall(function()
	return item.IsA("EnumItem")
end)
print("ENUM_ITEM_DOT", ok, result)

for _, name in ipairs({ "Z", "z", "Missing" }) do
	local lookupOk, lookupResult = pcall(function()
		return Enum.Axis:FromName(name)
	end)
	print("ENUM_FROM_NAME", name, lookupOk, lookupResult)
end

for _, value in ipairs({ 2, 99 }) do
	local lookupOk, lookupResult = pcall(function()
		return Enum.Axis:FromValue(value)
	end)
	print("ENUM_FROM_VALUE", value, lookupOk, lookupResult)
end

local fromNameDotOk, fromNameDotResult = pcall(function()
	return Enum.Axis.FromName("Z")
end)
print("ENUM_FROM_NAME_DOT", fromNameDotOk, fromNameDotResult)

print("ENUM_TYPE", typeof(Enum.Axis), type(Enum.Axis), tostring(Enum.Axis))
local enumNameOk, enumNameResult = pcall(function()
	return Enum.Axis.Name
end)
print("ENUM_TYPE_NAME", enumNameOk, enumNameResult)
for _, className in ipairs({ "Enum", "Axis", "EnumItem", "userdata" }) do
	local enumOk, enumResult = pcall(function()
		return Enum.Axis:IsA(className)
	end)
	print("ENUM_TYPE_ISA", className, enumOk, enumResult)
end

for _, methodName in ipairs({ "FromName", "FromValue", "GetEnumItems" }) do
	local method = Enum.Axis[methodName]
	print("ENUM_METHOD_INFO", methodName, debug.info(method, "s"), debug.info(method, "n"), debug.info(method, "a"))
end
