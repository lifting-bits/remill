/* SPDX-License-Identifier: Apache-2.0 */

/* Logical ST(0..7), padded exactly as in an FXSAVE image. */
.macro X87_INPUT name, significand, exponent, rhs=0x8000000000000000, rhs_exp=0x3fff
    .data
    .balign 16
\name:
    .quad \significand
    .short \exponent
    .zero 6
    .quad \rhs
    .short \rhs_exp
    .zero 6
    .irp reg, 2,3,4,5,6,7
        .quad 0x8000000000000000 + \reg
        .short 0x4000
        .zero 6
    .endr
    .text
.endm
