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
strb w29, [x28, #1137]
b.mi 1f
strb wzr, [x28, #1137]
1:
strb w29, [x28, #1139]
b.eq 1f
strb wzr, [x28, #1139]
1:
strb w29, [x28, #1141]
b.cs 1f
strb wzr, [x28, #1141]
1:
strb w29, [x28, #1143]
b.vs 1f
strb wzr, [x28, #1143]
1:
mrs x1, nzcv
str x1, [x28, #1072]
mrs x1, fpcr
str x1, [x28, #1080]
mrs x1, fpsr
str x1, [x28, #1088]
ubfx x29, x1, #0, #1
strb w29, [x28, #1153]
ubfx x29, x1, #2, #1
strb w29, [x28, #1147]
ubfx x29, x1, #3, #1
strb w29, [x28, #1149]
ubfx x29, x1, #4, #1
strb w29, [x28, #1145]
ubfx x29, x1, #6, #1
strb w29, [x28, #1151]
ldr x29, [x28, #1008]
mrs x1, tpidr_el0
str x1, [x28, #1112]
mrs x1, tpidrro_el0
str x1, [x28, #1128]
add x1, x28, #16
stur q0, [x1, #0]
stur q1, [x1, #16]
stur q2, [x1, #32]
stur q3, [x1, #48]
stur q4, [x1, #64]
stur q5, [x1, #80]
stur q6, [x1, #96]
stur q7, [x1, #112]
stur q8, [x1, #128]
stur q9, [x1, #144]
stur q10, [x1, #160]
stur q11, [x1, #176]
stur q12, [x1, #192]
stur q13, [x1, #208]
stur q14, [x1, #224]
stur q15, [x1, #240]
add x1, x28, #272
stur q16, [x1, #0]
stur q17, [x1, #16]
stur q18, [x1, #32]
stur q19, [x1, #48]
stur q20, [x1, #64]
stur q21, [x1, #80]
stur q22, [x1, #96]
stur q23, [x1, #112]
stur q24, [x1, #128]
stur q25, [x1, #144]
stur q26, [x1, #160]
stur q27, [x1, #176]
stur q28, [x1, #192]
stur q29, [x1, #208]
stur q30, [x1, #224]
stur q31, [x1, #240]
ldr x1, [x28, #560]
