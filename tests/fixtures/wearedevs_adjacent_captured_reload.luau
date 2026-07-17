-- Reconstructed from the Prometheus register VM used by WeAreDevs v1.
local captured_value_1
local local_1, local_2

captured_value_1 = {Value = 3}
local_1 = captured_value_1
local_1.Value = 9

local_2 = captured_value_1
task.wait()
local_2.Value = 12

captured_value_1 = {Value = captured_value_1.Value}
return captured_value_1.Value
