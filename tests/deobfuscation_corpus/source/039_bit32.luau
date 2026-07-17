-- corpus: bit32; variant: 2
local encoded = bit32.bxor(3783, 0x5A5A)
print(bit32.band(encoded, 0xFFFF))
