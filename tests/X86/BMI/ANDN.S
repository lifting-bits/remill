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

TEST_BEGIN(ANDNr32r32r32_basic, 2)
TEST_IGNORE_FLAGS(AF PF)
TEST_INPUTS(
    0x00000000, 0x00000000,  // (~0) & 0 = 0xFFFFFFFF & 0 = 0
    0x00000000, 0xFFFFFFFF,  // (~0) & 0xFFFFFFFF = 0xFFFFFFFF (all bits set)
    0xFFFFFFFF, 0x00000000,  // (~0xFFFFFFFF) & 0 = 0 (zero result, ZF=1)
    0xFFFFFFFF, 0xFFFFFFFF,  // (~0xFFFFFFFF) & 0xFFFFFFFF = 0 (ZF=1)
    0xAAAAAAAA, 0x55555555,  // (~0xAAAAAAAA) & 0x55555555 = 0x55555555 & 0x55555555
    0x12345678, 0x9ABCDEF0,  // Mixed bits
    0x80000000, 0x80000000,  // Sign bit: (~0x80000000) & 0x80000000 = 0
    0x7FFFFFFF, 0xFFFFFFFF)  // (~0x7FFFFFFF) & 0xFFFFFFFF = 0x80000000 (SF=1)

    // Check CPU for BMI1 support (cpuid fn 0x00000007, bit 3 of ebx)
    mov eax, 0x00000007
    mov ecx, 0x0
    cpuid
    and ebx, 0x00000008
    jz andn_nop1

    // ANDN supported, proceed with test:
    mov eax, ARG1_32
    mov edx, ARG2_32
    andn ecx, eax, edx

andn_nop1: nop

TEST_END

TEST_BEGIN_64(ANDNr64r64r64_basic, 2)
TEST_IGNORE_FLAGS(AF PF)
TEST_INPUTS(
    0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF, 0x0000000000000000,  // Zero result
    0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,  // Zero result
    0xAAAAAAAAAAAAAAAA, 0x5555555555555555,
    0x123456789ABCDEF0, 0xFEDCBA9876543210,
    0x8000000000000000, 0x8000000000000000,  // Sign bit
    0x7FFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF)  // Result: 0x8000000000000000 (SF=1)

    // Check CPU for BMI1 support (cpuid fn 0x00000007, bit 3 of ebx)
    mov eax, 0x00000007
    mov ecx, 0x0
    cpuid
    and ebx, 0x00000008
    jz andn_nop2

    // ANDN supported, proceed with test:
    mov rax, ARG1_64
    mov rdx, ARG2_64
    andn rcx, rax, rdx

andn_nop2: nop

TEST_END_64

TEST_BEGIN(ANDNr32r32m32, 2)
TEST_IGNORE_FLAGS(AF PF)
TEST_INPUTS(
    0xFFFFFFFF, 0x12345678,
    0x00000000, 0xABCDEF01,
    0x55555555, 0xAAAAAAAA)

    // Check CPU for BMI1 support (cpuid fn 0x00000007, bit 3 of ebx)
    mov eax, 0x00000007
    mov ecx, 0x0
    cpuid
    and ebx, 0x00000008
    jz andn_nop3

    // ANDN supported, proceed with test:
    push ARG2_64
    mov eax, ARG1_32
    andn ecx, eax, DWORD PTR [rsp]
    add rsp, 8

andn_nop3: nop

TEST_END

TEST_BEGIN_64(ANDNr64r64m64, 2)
TEST_IGNORE_FLAGS(AF PF)
TEST_INPUTS(
    0xFFFFFFFFFFFFFFFF, 0x123456789ABCDEF0,
    0x0000000000000000, 0xFEDCBA9876543210,
    0xAAAAAAAAAAAAAAAA, 0x5555555555555555)

    // Check CPU for BMI1 support (cpuid fn 0x00000007, bit 3 of ebx)
    mov eax, 0x00000007
    mov ecx, 0x0
    cpuid
    and ebx, 0x00000008
    jz andn_nop4

    // ANDN supported, proceed with test:
    push ARG2_64
    mov rax, ARG1_64
    andn rcx, rax, QWORD PTR [rsp]
    add rsp, 8

andn_nop4: nop

TEST_END_64

#endif  // HAS_FEATURE_AVX
