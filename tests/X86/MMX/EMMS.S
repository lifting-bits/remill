/* SPDX-License-Identifier: Apache-2.0 */

X87_INPUT emms_normal, 0x8000000000000001, 0x4000, 0x8000000000000002, 0xc001
X87_INPUT emms_raw, 0x8765432101234567, 0xffff, 0x0123456789abcdef, 0xffff

TEST_BEGIN_FPU(EMMS_PRESERVE, 3, 0x7fff, TEST_FPU_INPUTS | TEST_FPU_RAW_REGISTERS | TEST_FPU_TAGS | TEST_SINGLE_FLAGS)
    .data
    .balign 8
4:
    .irp value, emms_normal,emms_raw
    .irp top, 0,1,2,3,4,5,6,7
        .quad \value, 0x37f | ((0x4721 | (\top << 11)) << 16), 0x1f80
    .endr
    .endr
5:
    .quad 0,0,0
    .text
    emms
TEST_END
