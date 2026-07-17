-- Reconstructed from the Prometheus register VM used by WeAreDevs v1.
local local_1, local_2, local_3, local_4
local_1 = {}
local_1[1] = 4
local_1[2] = 3
local_2 = function(step)
    local_1[1] += step
    return function(multiplier)
        local_1[1] *= multiplier
        local_1[2] += 1
        return local_1[1] + local_1[2]
    end
end
local_3 = local_2(5)
local_4 = local_3(2)
return local_4, local_1[1], local_1[2]
