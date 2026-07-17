-- corpus: bit32; variant: 4
local encoded = bit32.bxor(7663, 0x5A5A)
print(bit32.band(encoded, 0xFFFF))
