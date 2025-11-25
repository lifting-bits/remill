/*
 * Copyright (c) 2025 Trail of Bits, Inc.
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

/* BLSR - Reset Lowest Set Bit
 * Format: BLSR r32, r/m32
 * Operation: dest = (src - 1) & src
 * Flags: CF set if src==0; ZF, SF set based on result; OF cleared; AF, PF undefined
 */

#if HAS_FEATURE_AVX

TEST_BEGIN(BLSRr32r32_zero, 1)
TEST_IGNORE_FLAGS(AF PF)
TEST_INPUTS(0)

    mov eax, ARG1_32
    blsr edx, eax

TEST_END

TEST_BEGIN(BLSRr32r32_single_bit, 1)
TEST_IGNORE_FLAGS(AF PF)
TEST_INPUTS(
    1,           // Result: 0, CF=0, ZF=1
    2,           // Result: 0, CF=0, ZF=1
    4,           // Result: 0, CF=0, ZF=1
    8,           // Result: 0, CF=0, ZF=1
    0x00000100,  // Result: 0, CF=0, ZF=1
    0x00010000,  // Result: 0, CF=0, ZF=1
    0x40000000,  // Result: 0, CF=0, ZF=1
    0x80000000)  // Result: 0, CF=0, ZF=1 (MSB)

    mov eax, ARG1_32
    blsr edx, eax

TEST_END

TEST_BEGIN(BLSRr32r32_multiple_bits, 1)
TEST_IGNORE_FLAGS(AF PF)
TEST_INPUTS(
    3,           // (2) & 3 = 2, CF=0
    5,           // (4) & 5 = 4, CF=0
    7,           // (6) & 7 = 6, CF=0
    0xFFFFFFFF,  // (0xFFFFFFFE) & 0xFFFFFFFF = 0xFFFFFFFE (SF=1), CF=0
    0xFFFFFFFE,  // Result: 0xFFFFFFFC (SF=1), CF=0
    0x12345678,  // Clear bit 3 (LSB)
    0xAAAAAAAA,  // Clear bit 1, result: 0xAAAAAAA8 (SF=1)
    0x55555555,  // Clear bit 0, result: 0x55555554
    0x80000001,  // Clear bit 0, result: 0x80000000 (SF=1)
    0x7FFFFFFF)  // Clear bit 0, result: 0x7FFFFFFE

    mov eax, ARG1_32
    blsr edx, eax

TEST_END

TEST_BEGIN_64(BLSRr64r64_zero, 1)
TEST_IGNORE_FLAGS(AF PF)
TEST_INPUTS(0)

    mov rax, ARG1_64
    blsr rdx, rax

TEST_END_64

TEST_BEGIN_64(BLSRr64r64_single_bit, 1)
TEST_IGNORE_FLAGS(AF PF)
TEST_INPUTS(
    1,
    2,
    0x0000000000000100,
    0x0000000000010000,
    0x0000000100000000,
    0x4000000000000000,
    0x8000000000000000)  // MSB

    mov rax, ARG1_64
    blsr rdx, rax

TEST_END_64

TEST_BEGIN_64(BLSRr64r64_multiple_bits, 1)
TEST_IGNORE_FLAGS(AF PF)
TEST_INPUTS(
    3,
    5,
    7,
    0xFFFFFFFFFFFFFFFF,  // Result: 0xFFFFFFFFFFFFFFFE (SF=1)
    0xFFFFFFFFFFFFFFFE,  // Result: 0xFFFFFFFFFFFFFFFC (SF=1)
    0x123456789ABCDEF0,  // Clear bit 4
    0xAAAAAAAAAAAAAAAA,  // Clear bit 1, result: 0xAAAAAAAAAAAAAAA8 (SF=1)
    0x5555555555555555,  // Clear bit 0, result: 0x5555555555555554
    0x8000000000000001,  // Clear bit 0, result: 0x8000000000000000 (SF=1)
    0x7FFFFFFFFFFFFFFF)  // Clear bit 0, result: 0x7FFFFFFFFFFFFFFE

    mov rax, ARG1_64
    blsr rdx, rax

TEST_END_64

TEST_BEGIN(BLSRr32m32, 1)
TEST_IGNORE_FLAGS(AF PF)
TEST_INPUTS(
    0,
    1,
    0xFFFFFFFF,
    0x12345678)

    push ARG1_64
    blsr edx, DWORD PTR [rsp]
    add rsp, 8

TEST_END

TEST_BEGIN_64(BLSRr64m64, 1)
TEST_IGNORE_FLAGS(AF PF)
TEST_INPUTS(
    0,
    1,
    0xFFFFFFFFFFFFFFFF,
    0x123456789ABCDEF0)

    push ARG1_64
    blsr rdx, QWORD PTR [rsp]
    add rsp, 8

TEST_END_64

#endif  // HAS_FEATURE_AVX
