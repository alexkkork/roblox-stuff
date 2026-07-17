-- corpus: bit32; variant: 1
local encoded = bit32.bxor(1843, 0x5A5A)
print(bit32.band(encoded, 0xFFFF))
