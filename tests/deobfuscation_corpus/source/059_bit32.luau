-- corpus: bit32; variant: 3
local encoded = bit32.bxor(5723, 0x5A5A)
print(bit32.band(encoded, 0xFFFF))
