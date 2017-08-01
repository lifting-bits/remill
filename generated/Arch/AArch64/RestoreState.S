/* Auto-generated file! Don't modify! */

mov x2, #0
ldrb x1, [x30, #1129]
orr x2, x2, x1 LSL 31
ldrb x1, [x30, #1131]
orr x2, x2, x1 LSL 30
ldrb x1, [x30, #1133]
orr x2, x2, x1 LSL 29
ldrb x1, [x30, #1135]
orr x2, x2, x1 LSL 28
str x2, [x30, #1072]
msr nzcv, x2
ldr x1, [x30, #1080]
msr fpcr, x1
ldr x1, [x30, #1088]
msr fpsr, x1
ldr x1, [x30, #1104]
msr tpidr_el0, x1
ldp x1, x2, [x30, #560]
ldp x3, x4, [x30, #592]
ldp x5, x6, [x30, #624]
ldp x7, x8, [x30, #656]
ldp x9, x10, [x30, #688]
ldp x11, x12, [x30, #720]
ldp x13, x14, [x30, #752]
ldp x15, x16, [x30, #784]
ldp x17, x18, [x30, #816]
ldp x19, x20, [x30, #848]
ldp x21, x22, [x30, #880]
ldp x23, x24, [x30, #912]
ldp x25, x26, [x30, #944]
ldp x27, x28, [x30, #976]
ldp x29, x0, [x30, #1008]
ldp sp, [x30, #1040]
