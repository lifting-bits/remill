/* Auto-generated file! Don't modify! */

str x0, [x30, #544]
str x1, [x30, #560]
str x2, [x30, #576]
str x3, [x30, #592]
str x4, [x30, #608]
str x5, [x30, #624]
str x6, [x30, #640]
str x7, [x30, #656]
str x8, [x30, #672]
str x9, [x30, #688]
str x10, [x30, #704]
str x11, [x30, #720]
str x12, [x30, #736]
str x13, [x30, #752]
str x14, [x30, #768]
str x15, [x30, #784]
str x16, [x30, #800]
str x17, [x30, #816]
str x18, [x30, #832]
str x19, [x30, #848]
str x20, [x30, #864]
str x21, [x30, #880]
str x22, [x30, #896]
str x23, [x30, #912]
str x24, [x30, #928]
str x25, [x30, #944]
str x26, [x30, #960]
str x27, [x30, #976]
str x28, [x30, #992]
str x29, [x30, #1008]
mov x29, sp
str x29, [x30, #1040]
mov x29, #1
strb w29, [x30, #1129]
b.mi 1f
strb wzr, [x30, #1129]
1:
strb w29, [x30, #1131]
b.eq 1f
strb wzr, [x30, #1131]
1:
strb w29, [x30, #1133]
b.cs 1f
strb wzr, [x30, #1133]
1:
strb w29, [x30, #1135]
b.vs 1f
strb wzr, [x30, #1135]
1:
ldr x29, [x30, #1008]
mrs x1, nzcv
str x1, [x30, #1072]
mrs x1, fpcr
str x1, [x30, #1080]
mrs x1, fpsr
str x1, [x30, #1088]
mrs x1, tpidr_el0
str x1, [x30, #1104]
mrs x1, tpidrro_el0
str x1, [x30, #1120]
ldr x1, [x30, #560]
