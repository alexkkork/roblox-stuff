local HttpService = game:GetService("HttpService")
local sample = {
    guid = HttpService:GenerateGUID(false),
    integer = Random.new():NextInteger(1, 1000000000),
    fraction = math.random(),
    now = DateTime.now().UnixTimestampMillis,
    tick = tick(),
    time = time(),
}

print("cli-parity-v3", HttpService:JSONEncode(sample))
return false, sample
