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

TEST_BEGIN(BLSIr32r32_zero, 1)
TEST_IGNORE_FLAGS(AF PF)
TEST_INPUTS(0)

    // Check CPU for BMI1 support (cpuid fn 0x00000007, bit 3 of ebx)
    mov eax, 0x00000007
    mov ecx, 0x0
    cpuid
    and ebx, 0x00000008
    jz blsi_nop1

    // BLSI supported, proceed with test:
    mov eax, ARG1_32
    blsi edx, eax

blsi_nop1: nop

TEST_END

TEST_BEGIN(BLSIr32r32_basic, 1)
TEST_IGNORE_FLAGS(AF PF)
TEST_INPUTS(
    1,           // Result: 1, CF=1
    2,           // Result: 2, CF=1
    3,           // Result: 1 (lowest bit), CF=1
    0x80000000,  // MSB set: result=0x80000000 (SF=1), CF=1
    0x80000001,  // MSB and LSB: result=1, CF=1
    0xFFFFFFFF,  // All bits: result=1 (lowest), CF=1
    0xFFFFFFFE,  // All but LSB: result=2, CF=1
    0x12345678,  // Result: 8 (bit 3), CF=1
    0xAAAAAAAA,  // Alternating bits: result=2, CF=1
    0x55555555)  // Alternating bits: result=1, CF=1

    // Check CPU for BMI1 support (cpuid fn 0x00000007, bit 3 of ebx)
    mov eax, 0x00000007
    mov ecx, 0x0
    cpuid
    and ebx, 0x00000008
    jz blsi_nop2

    // BLSI supported, proceed with test:
    mov eax, ARG1_32
    blsi edx, eax

blsi_nop2: nop

TEST_END

TEST_BEGIN(BLSIr32r32_powers_of_two, 1)
TEST_IGNORE_FLAGS(AF PF)
TEST_INPUTS(
    0x00000001,  // 2^0
    0x00000002,  // 2^1
    0x00000004,  // 2^2
    0x00000100,  // 2^8
    0x00010000,  // 2^16
    0x40000000,  // 2^30
    0x80000000)  // 2^31 (sign bit)

    // Check CPU for BMI1 support (cpuid fn 0x00000007, bit 3 of ebx)
    mov eax, 0x00000007
    mov ecx, 0x0
    cpuid
    and ebx, 0x00000008
    jz blsi_nop3

    // BLSI supported, proceed with test:
    mov eax, ARG1_32
    blsi edx, eax

blsi_nop3: nop

TEST_END

TEST_BEGIN_64(BLSIr64r64_zero, 1)
TEST_IGNORE_FLAGS(AF PF)
TEST_INPUTS(0)

    // Check CPU for BMI1 support (cpuid fn 0x00000007, bit 3 of ebx)
    mov eax, 0x00000007
    mov ecx, 0x0
    cpuid
    and ebx, 0x00000008
    jz blsi_nop4

    // BLSI supported, proceed with test:
    mov rax, ARG1_64
    blsi rdx, rax

blsi_nop4: nop

TEST_END_64

TEST_BEGIN_64(BLSIr64r64_basic, 1)
TEST_IGNORE_FLAGS(AF PF)
TEST_INPUTS(
    1,
    2,
    3,
    0x8000000000000000,  // MSB: result=0x8000000000000000 (SF=1)
    0x8000000000000001,  // MSB and LSB: result=1
    0xFFFFFFFFFFFFFFFF,  // All bits: result=1
    0xFFFFFFFFFFFFFFFE,  // All but LSB: result=2
    0x123456789ABCDEF0,  // Result: 0x10 (bit 4)
    0xAAAAAAAAAAAAAAAA,  // Result: 2
    0x5555555555555555)  // Result: 1

    // Check CPU for BMI1 support (cpuid fn 0x00000007, bit 3 of ebx)
    mov eax, 0x00000007
    mov ecx, 0x0
    cpuid
    and ebx, 0x00000008
    jz blsi_nop5

    // BLSI supported, proceed with test:
    mov rax, ARG1_64
    blsi rdx, rax

blsi_nop5: nop

TEST_END_64

TEST_BEGIN(BLSIr32m32, 1)
TEST_IGNORE_FLAGS(AF PF)
TEST_INPUTS(
    0,
    0xFFFFFFFF,
    0x12345678)

    // Check CPU for BMI1 support (cpuid fn 0x00000007, bit 3 of ebx)
    mov eax, 0x00000007
    mov ecx, 0x0
    cpuid
    and ebx, 0x00000008
    jz blsi_nop6

    // BLSI supported, proceed with test:
    push ARG1_64
    blsi edx, DWORD PTR [rsp]
    add rsp, 8

blsi_nop6: nop

TEST_END

TEST_BEGIN_64(BLSIr64m64, 1)
TEST_IGNORE_FLAGS(AF PF)
TEST_INPUTS(
    0,
    0xFFFFFFFFFFFFFFFF,
    0x123456789ABCDEF0)

    // Check CPU for BMI1 support (cpuid fn 0x00000007, bit 3 of ebx)
    mov eax, 0x00000007
    mov ecx, 0x0
    cpuid
    and ebx, 0x00000008
    jz blsi_nop7

    // BLSI supported, proceed with test:
    push ARG1_64
    blsi rdx, QWORD PTR [rsp]
    add rsp, 8

blsi_nop7: nop

TEST_END_64

#endif  // HAS_FEATURE_AVX
