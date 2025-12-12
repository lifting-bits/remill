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

#if HAS_FEATURE_AVX

TEST_BEGIN(BLSMSKr32r32_zero, 1)
TEST_IGNORE_FLAGS(AF PF)
TEST_INPUTS(0)

    // Check CPU for BMI1 support (cpuid fn 0x00000007, bit 3 of ebx)
    mov eax, 0x00000007
    mov ecx, 0x0
    cpuid
    and ebx, 0x00000008
    jz blsmsk_nop1

    // BLMSK supported, proceed with test:
    mov eax, ARG1_32
    blsmsk edx, eax

blsmsk_nop1: nop

TEST_END

TEST_BEGIN(BLSMSKr32r32_basic, 1)
TEST_IGNORE_FLAGS(AF PF)
TEST_INPUTS(
    1,           // (0) ^ 1 = 1, CF=0
    2,           // (1) ^ 2 = 3, CF=0
    3,           // (2) ^ 3 = 1, CF=0
    4,           // (3) ^ 4 = 7, CF=0
    0x80000000,  // Result: 0x7FFFFFFF ^ 0x80000000 = 0xFFFFFFFF (SF=1), CF=0
    0xFFFFFFFF,  // (0xFFFFFFFE) ^ 0xFFFFFFFF = 1, CF=0
    0xFFFFFFFE,  // Result: 3, CF=0
    0x12345678,  // Result based on bit 3 (LSB at position 3)
    0xAAAAAAAA,  // Alternating bits, LSB at position 1
    0x55555555)  // Alternating bits, LSB at position 0

    // Check CPU for BMI1 support (cpuid fn 0x00000007, bit 3 of ebx)
    mov eax, 0x00000007
    mov ecx, 0x0
    cpuid
    and ebx, 0x00000008
    jz blsmsk_nop2

    // BLSMSK supported, proceed with test:
    mov eax, ARG1_32
    blsmsk edx, eax

blsmsk_nop2: nop

TEST_END

TEST_BEGIN(BLSMSKr32r32_powers_of_two, 1)
TEST_IGNORE_FLAGS(AF PF)
TEST_INPUTS(
    0x00000001,  // Result: 1
    0x00000002,  // Result: 3
    0x00000004,  // Result: 7
    0x00000008,  // Result: 15
    0x00000100,  // Result: 0xFF
    0x00010000,  // Result: 0xFFFF
    0x40000000,  // Result: 0x7FFFFFFF
    0x80000000)  // Result: 0xFFFFFFFF (all bits, SF=1)

    // Check CPU for BMI1 support (cpuid fn 0x00000007, bit 3 of ebx)
    mov eax, 0x00000007
    mov ecx, 0x0
    cpuid
    and ebx, 0x00000008
    jz blsmsk_nop3

    // BLSMSK supported, proceed with test:
    mov eax, ARG1_32
    blsmsk edx, eax

blsmsk_nop3: nop

TEST_END

TEST_BEGIN_64(BLSMSKr64r64_zero, 1)
TEST_IGNORE_FLAGS(AF PF)
TEST_INPUTS(0)

    // Check CPU for BMI1 support (cpuid fn 0x00000007, bit 3 of ebx)
    mov eax, 0x00000007
    mov ecx, 0x0
    cpuid
    and ebx, 0x00000008
    jz blsmsk_nop4

    // BLSMSK supported, proceed with test:
    mov rax, ARG1_64
    blsmsk rdx, rax

blsmsk_nop4: nop

TEST_END_64

TEST_BEGIN_64(BLSMSKr64r64_basic, 1)
TEST_IGNORE_FLAGS(AF PF)
TEST_INPUTS(
    1,
    2,
    3,
    0x8000000000000000,  // Result: 0xFFFFFFFFFFFFFFFF (SF=1)
    0xFFFFFFFFFFFFFFFF,  // Result: 1
    0xFFFFFFFFFFFFFFFE,  // Result: 3
    0x123456789ABCDEF0,  // Result based on bit 4
    0xAAAAAAAAAAAAAAAA,  // Result: 3
    0x5555555555555555)  // Result: 1

    // Check CPU for BMI1 support (cpuid fn 0x00000007, bit 3 of ebx)
    mov eax, 0x00000007
    mov ecx, 0x0
    cpuid
    and ebx, 0x00000008
    jz blsmsk_nop5

    // BLSMSK supported, proceed with test:
    mov rax, ARG1_64
    blsmsk rdx, rax

blsmsk_nop5: nop

TEST_END_64

TEST_BEGIN_64(BLSMSKr64r64_powers_of_two, 1)
TEST_IGNORE_FLAGS(AF PF)
TEST_INPUTS(
    0x0000000000000001,  // Result: 1
    0x0000000000000002,  // Result: 3
    0x0000000000000100,  // Result: 0xFF
    0x0000000000010000,  // Result: 0xFFFF
    0x0000000100000000,  // Result: 0xFFFFFFFF
    0x4000000000000000,  // Result: 0x3FFFFFFFFFFFFFFF
    0x8000000000000000)  // Result: 0xFFFFFFFFFFFFFFFF (SF=1)

    // Check CPU for BMI1 support (cpuid fn 0x00000007, bit 3 of ebx)
    mov eax, 0x00000007
    mov ecx, 0x0
    cpuid
    and ebx, 0x00000008
    jz blsmsk_nop6

    // BLSMSK supported, proceed with test:
    mov rax, ARG1_64
    blsmsk rdx, rax

blsmsk_nop6: nop

TEST_END_64

TEST_BEGIN(BLSMSKr32m32, 1)
TEST_IGNORE_FLAGS(AF PF)
TEST_INPUTS(
    0,
    0x00000001,
    0x12345678)

    // Check CPU for BMI1 support (cpuid fn 0x00000007, bit 3 of ebx)
    mov eax, 0x00000007
    mov ecx, 0x0
    cpuid
    and ebx, 0x00000008
    jz blsmsk_nop7

    // BLSMSK supported, proceed with test:
    push ARG1_64
    blsmsk edx, DWORD PTR [rsp]
    add rsp, 8

blsmsk_nop7: nop

TEST_END

TEST_BEGIN_64(BLSMSKr64m64, 1)
TEST_IGNORE_FLAGS(AF PF)
TEST_INPUTS(
    0,
    0x0000000000000001,
    0x123456789ABCDEF0)

    // Check CPU for BMI1 support (cpuid fn 0x00000007, bit 3 of ebx)
    mov eax, 0x00000007
    mov ecx, 0x0
    cpuid
    and ebx, 0x00000008
    jz blsmsk_nop8

    // BLSMSK supported, proceed with test:
    push ARG1_64
    blsmsk rdx, QWORD PTR [rsp]
    add rsp, 8

blsmsk_nop8: nop

TEST_END_64

#endif  // HAS_FEATURE_AVX
