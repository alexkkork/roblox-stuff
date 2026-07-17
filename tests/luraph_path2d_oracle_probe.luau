local path = Instance.new("Path2D")

local function probe(label, callback)
    local values = table.pack(pcall(callback))
    local rendered = {}
    for index = 2, values.n do
        rendered[#rendered + 1] = string.format("%s:%s", typeof(values[index]), tostring(values[index]))
    end
    print(label, values[1], table.concat(rendered, " | "))
end

probe("new", function()
    return path:GetMaxControlPoints(), path:GetLength(), path:GetControlPoints()
end)
probe("set-empty", function()
    path:SetControlPoints({})
    return #path:GetControlPoints()
end)
probe("set-nil", function()
    path:SetControlPoints(nil)
end)
probe("set-valid", function()
    path:SetControlPoints({
        Path2DControlPoint.new(UDim2.fromOffset(1, 2)),
        Path2DControlPoint.new(UDim2.fromOffset(3, 4)),
    })
    local points = path:GetControlPoints()
    return #points, points[1], points[2], path:GetControlPoint(1), path:GetControlPoint(0)
end)
probe("set-invalid-member", function()
    path:SetControlPoints({ Path2DControlPoint.new(), "bad" })
end)
probe("insert", function()
    path:SetControlPoints({ Path2DControlPoint.new(), Path2DControlPoint.new() })
    path:InsertControlPoint(2, Path2DControlPoint.new(UDim2.fromOffset(9, 9)))
    return #path:GetControlPoints(), path:GetControlPoint(2)
end)
probe("update", function()
    path:UpdateControlPoint(1, Path2DControlPoint.new(UDim2.fromOffset(8, 8)))
    return path:GetControlPoint(1)
end)
probe("remove", function()
    path:RemoveControlPoint(1)
    return #path:GetControlPoints()
end)
