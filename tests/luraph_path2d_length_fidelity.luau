local screenGui = Instance.new("ScreenGui")
local frame = Instance.new("Frame")
frame.Size = UDim2.fromOffset(118, 210)
frame.Parent = screenGui

local path = Instance.new("Path2D")
path.Parent = frame
path:SetControlPoints({
    Path2DControlPoint.new(UDim2.new(0, 2, 0.5, 5), UDim2.new(), UDim2.new(0, 4, 0.0625, -3)),
    Path2DControlPoint.new(UDim2.new(0.375, -5, 0.5, -7), UDim2.new(0, -4, -0.125, -4), UDim2.new(-0.125, -2, 0.125, -1)),
    Path2DControlPoint.new(UDim2.new(0.25, -5, 0.375, 3), UDim2.new(0.125, 3, 0, 0), UDim2.new(0, 6, 0.0625, 5)),
    Path2DControlPoint.new(UDim2.new(0, -8, 0.25, 8), UDim2.new(0, -4, 0, 1), UDim2.new()),
    Path2DControlPoint.new(UDim2.new(0, 2, 0.5, 0), UDim2.new(0, -4, 0.0625, 2), UDim2.new(0, -6, 0.125, 5)),
    Path2DControlPoint.new(UDim2.new(0.25, 6, 0.125, -3), UDim2.new(0, -4, 0, -6), UDim2.new(0, 5, 0, -5)),
})

local function assertNear(actual, expected, tolerance, label)
    assert(math.abs(actual - expected) <= tolerance, string.format(
        "%s: expected %.9f +/- %.9f, got %.9f",
        label,
        expected,
        tolerance,
        actual
    ))
end

assert(frame.AbsoluteSize == Vector2.new(118, 210), "Path2D parent size mismatch")
assertNear(path:GetLength(), 292.3517150878906, 0.001, "Path2D total length")
local controlPoints = path:GetControlPoints()
local expectedSegmentLengths = {
    52.56000518798828,
    39.83837127685547,
    47.92051696777344,
    52.39527893066406,
    99.63754272460938,
}
for index = 1, #controlPoints - 1 do
    local segment = Instance.new("Path2D")
    segment.Parent = frame
    segment:SetControlPoints({ controlPoints[index], controlPoints[index + 1] })
    assertNear(segment:GetLength(), expectedSegmentLengths[index], 0.001, "Path2D segment " .. index)
end

local twoThirdsTangent = path:GetTangentOnCurveArcLength(2 / 3)
assertNear(twoThirdsTangent.X, -11.624759674072266, 0.002, "Path2D 2/3 tangent X")
assertNear(twoThirdsTangent.Y, 70.69113159179688, 0.01, "Path2D 2/3 tangent Y")

local sixSeventhsPosition = path:GetPositionOnCurveArcLength(6 / 7)
local sixSeventhsTangent = path:GetTangentOnCurveArcLength(6 / 7)
assertNear(sixSeventhsPosition.X.Scale, 0.16616514325141907, 0.0001, "Path2D 6/7 position X")
assertNear(sixSeventhsPosition.Y.Scale, 0.2870262563228607, 0.0001, "Path2D 6/7 position Y")
assertNear(sixSeventhsTangent.X, 52.696144104003906, 0.002, "Path2D 6/7 tangent X")
assertNear(sixSeventhsTangent.Y, -150.8509063720703, 0.01, "Path2D 6/7 tangent Y")

print("luraph-path2d-release729-ok")
