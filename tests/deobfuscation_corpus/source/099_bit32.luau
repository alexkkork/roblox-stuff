-- corpus: bit32; variant: 5
local encoded = bit32.bxor(9603, 0x5A5A)
print(bit32.band(encoded, 0xFFFF))
