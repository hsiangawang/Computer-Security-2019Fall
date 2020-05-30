.global your_asm_fn
.section .text

your_asm_fn:

push	%ebp
mov	%esp,%ebp

push $0xc105ed
mov %esp,%ebx

push $0X00000000
push $0x646F6F66
push $0x6c6F6F63
mov %esp,%edx

push %edx
push %ebx
push $0xacce55ed

call practice

leave
ret
