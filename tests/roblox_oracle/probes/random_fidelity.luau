local function sample(random)
	return random:NextNumber(), random:NextInteger(-1000, 1000), random:NextNumber(-2, 3)
end

for _, seed in {0, 1, 42, 729, -1, 2147483647} do
	print("RANDOM_SEEDED", seed, sample(Random.new(seed)))
end

local unseededA = Random.new()
local unseededB = Random.new()
print("RANDOM_UNSEEDED_A", sample(unseededA))
print("RANDOM_UNSEEDED_B", sample(unseededB))

local original = Random.new(729)
original:NextNumber()
local clone = original:Clone()
print("RANDOM_CLONE_ORIGINAL", sample(original))
print("RANDOM_CLONE_COPY", sample(clone))

local unitVector = Random.new(999):NextUnitVector()
print("RANDOM_UNIT_VECTOR", unitVector, unitVector.Magnitude)

print("RANDOM_INFO", debug.info(Random.new, "sna"))
for _, method in {"Clone", "NextInteger", "NextNumber", "NextUnitVector", "Shuffle"} do
	print("RANDOM_INFO", method, debug.info(Random.new(1)[method], "sna"))
end
