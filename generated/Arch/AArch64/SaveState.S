/* Auto-generated file! Don't modify! */

str x0, [x28, #544]
str x1, [x28, #560]
str x2, [x28, #576]
str x3, [x28, #592]
str x4, [x28, #608]
str x5, [x28, #624]
str x6, [x28, #640]
str x7, [x28, #656]
str x8, [x28, #672]
str x9, [x28, #688]
str x10, [x28, #704]
str x11, [x28, #720]
str x12, [x28, #736]
str x13, [x28, #752]
str x14, [x28, #768]
str x15, [x28, #784]
str x16, [x28, #800]
str x17, [x28, #816]
str x18, [x28, #832]
str x19, [x28, #848]
str x20, [x28, #864]
str x21, [x28, #880]
str x22, [x28, #896]
str x23, [x28, #912]
str x24, [x28, #928]
str x25, [x28, #944]
str x26, [x28, #960]
str x27, [x28, #976]
str x29, [x28, #1008]
str x30, [x28, #1024]
mov x29, sp
str x29, [x28, #1040]
mov x29, #1
strb w29, [x28, #1129]
b.mi 1f
strb wzr, [x28, #1129]
1:
strb w29, [x28, #1131]
b.eq 1f
strb wzr, [x28, #1131]
1:
strb w29, [x28, #1133]
b.cs 1f
strb wzr, [x28, #1133]
1:
strb w29, [x28, #1135]
b.vs 1f
strb wzr, [x28, #1135]
1:
ldr x29, [x28, #1008]
mrs x1, nzcv
str x1, [x28, #1072]
mrs x1, fpcr
str x1, [x28, #1080]
mrs x1, fpsr
str x1, [x28, #1088]
mrs x1, tpidr_el0
str x1, [x28, #1104]
mrs x1, tpidrro_el0
str x1, [x28, #1120]
ldr x1, [x28, #560]
