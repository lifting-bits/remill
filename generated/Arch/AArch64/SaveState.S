/* Auto-generated file! Don't modify! */

stp x1, x2, [x0, #560], 0
stp x3, x4, [x0, #592], 0
stp x5, x6, [x0, #624], 0
stp x7, x8, [x0, #656], 0
stp x9, x10, [x0, #688], 0
stp x11, x12, [x0, #720], 0
stp x13, x14, [x0, #752], 0
stp x15, x16, [x0, #784], 0
stp x17, x18, [x0, #816], 0
stp x19, x20, [x0, #848], 0
stp x21, x22, [x0, #880], 0
stp x23, x24, [x0, #912], 0
stp x25, x26, [x0, #944], 0
stp x27, x28, [x0, #976], 0
stp x29, x30, [x0, #1008], 0
strb #1, [x0, #1129]
b.n .Ln_is_set
strb xzr, [x0, #1129]
.Ln_is_set:
strb #1, [x0, #1131]
b.z .Lz_is_set
strb xzr, [x0, #1131]
.Lz_is_set:
strb #1, [x0, #1133]
b.c .Lc_is_set
strb xzr, [x0, #1133]
.Lc_is_set:
strb #1, [x0, #1135]
b.v .Lv_is_set
strb xzr, [x0, #1135]
.Lv_is_set:
mrs x1, nzcv
str x1, [x0, #1072], 0
mrs x1, fpcr
str x1, [x0, #1080], 0
mrs x1, fpsr
str x1, [x0, #1088], 0
msr x1, tpidr_el0
str x1, [x0, #1104], 0
msr x1, tpidrro_el0
str x1, [x0, #1120], 0
