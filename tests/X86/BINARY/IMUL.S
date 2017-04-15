/*
 * Copyright (c) 2017 Trail of Bits, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Note: older versions of the Intel manual have SF undefined for IMUL.
 */

TEST_BEGIN(IMULal, 2)
TEST_IGNORE_FLAGS(SF ZF AF PF)
TEST_INPUTS(
    0, 0,
    0xFF, 0xFF)

    mov eax, ARG1_32
    mov ebx, ARG2_32

    imul bl
TEST_END

TEST_BEGIN(IMULax, 2)
TEST_IGNORE_FLAGS(SF ZF AF PF)
TEST_INPUTS(
    0, 0,
    1, 0x7FFF,
    1, 0xFFFF,
    0xFFFF, 0xFFFF)

    mov eax, ARG1_32
    mov ebx, ARG2_32

    imul bx
TEST_END

TEST_BEGIN(IMULeax, 2)
TEST_IGNORE_FLAGS(SF ZF AF PF)
TEST_INPUTS(
    0, 0,
    0xFFFF, 0xFFFF,
    0xFFFFFFFF, 0xFFFF,
    0xFFFFFFFF, 0xFFFFFFFF)

    mov eax, ARG1_32
    mov ebx, ARG2_32

    imul ebx
TEST_END

TEST_BEGIN_64(IMULrax_64, 2)
TEST_IGNORE_FLAGS(SF ZF AF PF)
TEST_INPUTS(
    0, 0,
    0xFFFF, 0xFFFF,
    0xFFFFFFFF, 0xFFFF,
    0xFFFFFFFF, 0xFFFFFFFF,
    0xFFFFFFFFFFFFFFFF, 0xFFFFFFFF,
    0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF)

    mov rax, ARG1_64
    mov rbx, ARG2_64

    imul rbx
TEST_END_64

TEST_BEGIN(IMULr16r16, 2)
TEST_IGNORE_FLAGS(SF ZF AF PF)
TEST_INPUTS(
    0, 0,
    1, 0x7FFF,
    1, 0xFFFF,
    0xFFFF, 0xFFFF)

    imul ARG1_16, ARG2_16
TEST_END

TEST_BEGIN(IMULr32r32, 2)
TEST_IGNORE_FLAGS(SF ZF AF PF)
TEST_INPUTS(
    0, 0,
    0xFFFF, 0xFFFF,
    0xFFFFFFFF, 0xFFFF,
    0xFFFFFFFF, 0xFFFFFFFF)

    imul ARG1_32, ARG2_32
TEST_END

TEST_BEGIN_64(IMULr64r64_64, 2)
TEST_IGNORE_FLAGS(SF ZF AF PF)
TEST_INPUTS(
    0, 1,
    0xFFFF, 0xFFFF,
    0xFFFFFFFF, 0xFFFF,
    0xFFFFFFFF, 0xFFFFFFFF,
    0xFFFFFFFF, 0x7FFFFFFF,
    0x7FFFFFFF, 0xFFFFFFFF,
    0xFFFFFFFFFFFFFFFF, 0xFFFFFFFF,
    0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF)

    imul ARG1_64, ARG2_64
TEST_END_64

TEST_BEGIN(IMULr16r16i8, 2)
TEST_IGNORE_FLAGS(SF ZF AF PF)
TEST_INPUTS(
    0,
    1,
    2,
    0x7FFF,
    0xFFFF)

    imul ax, ARG1_16, 7
TEST_END

TEST_BEGIN(IMULr16r16i16, 1)
TEST_IGNORE_FLAGS(SF ZF AF PF)
TEST_INPUTS(
    0,
    1,
    2,
    0x7FFF,
    0xFFFF)

    imul ax, ARG1_16, 0x7FFF
TEST_END

TEST_BEGIN(IMULr32r32i8, 1)
TEST_IGNORE_FLAGS(SF ZF AF PF)
TEST_INPUTS(
    0,
    1,
    2,
    0x7FFF,
    0xFFFF,
    0x7FFFFFFF,
    0xFFFFFFFF)

    imul eax, ARG1_32, 7
TEST_END

TEST_BEGIN(IMULr32r32s32, 1)
TEST_IGNORE_FLAGS(SF ZF AF PF)
TEST_INPUTS(
    0,
    1,
    2,
    0x7FFF,
    0xFFFF,
    0x7FFFFFFF,
    0xFFFFFFFF)

    imul eax, ARG1_32, 0xFFFFFFF
TEST_END

TEST_BEGIN(IMULr32r32u32, 1)
TEST_IGNORE_FLAGS(SF ZF AF PF)
TEST_INPUTS(
    0,
    1,
    2,
    0x7FFF,
    0xFFFF,
    0x7FFFFFFF,
    0xFFFFFFFF)

    imul eax, ARG1_32, 0x7FFFFFFF
TEST_END

TEST_BEGIN_64(IMULr64r64i8_64, 2)
TEST_IGNORE_FLAGS(SF ZF AF PF)
TEST_INPUTS(
    0,
    1,
    2,
    0x7FFF,
    0xFFFF,
    0x7FFFFFFF,
    0xFFFFFFFF,
    0x7FFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF)

    imul rax, ARG1_64, 7
TEST_END_64

TEST_BEGIN_64(IMULr64r64s32_64, 1)
TEST_IGNORE_FLAGS(SF ZF AF PF)
TEST_INPUTS(
    0,
    1,
    2,
    0x7FFF,
    0xFFFF,
    0x7FFFFFFF,
    0xFFFFFFFF,
    0x7FFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF)

    imul rax, ARG1_64, 0xFFFFFFF
TEST_END_64

TEST_BEGIN_64(IMULr64r64u32_64, 1)
TEST_IGNORE_FLAGS(SF ZF AF PF)
TEST_INPUTS(
    0,
    1,
    2,
    0x7FFF,
    0xFFFF,
    0x7FFFFFFF,
    0xFFFFFFFF,
    0x7FFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF)

    imul rax, ARG1_64, 0x7FFFFFFF
TEST_END_64
