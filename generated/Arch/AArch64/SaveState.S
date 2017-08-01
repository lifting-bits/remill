/* Auto-generated file! Don't modify! */

stp x1, x2, [x30, #560]
stp x3, x4, [x30, #592]
stp x5, x6, [x30, #624]
stp x7, x8, [x30, #656]
stp x9, x10, [x30, #688]
stp x11, x12, [x30, #720]
stp x13, x14, [x30, #752]
stp x15, x16, [x30, #784]
stp x17, x18, [x30, #816]
stp x19, x20, [x30, #848]
stp x21, x22, [x30, #880]
stp x23, x24, [x30, #912]
stp x25, x26, [x30, #944]
stp x27, x28, [x30, #976]
stp x29, x0, [x30, #1008]
str sp, [x30, #1040]
strb #1, [x30, #1129]
b.n .Ln_is_set
strb xzr, [x30, #1129]
.Ln_is_set:
strb #1, [x30, #1131]
b.z .Lz_is_set
strb xzr, [x30, #1131]
.Lz_is_set:
strb #1, [x30, #1133]
b.c .Lc_is_set
strb xzr, [x30, #1133]
.Lc_is_set:
strb #1, [x30, #1135]
b.v .Lv_is_set
strb xzr, [x30, #1135]
.Lv_is_set:
mrs x1, nzcv
str x1, [x30, #1072]
mrs x1, fpcr
str x1, [x30, #1080]
mrs x1, fpsr
str x1, [x30, #1088]
msr x1, tpidr_el0
str x1, [x30, #1104]
msr x1, tpidrro_el0
str x1, [x30, #1120]
ldr x1, [x30, #560]
