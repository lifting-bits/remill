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

TEST_BEGIN(BEXTRr32r32r32_basic, 2)
TEST_IGNORE_FLAGS(AF SF PF)
TEST_INPUTS(
    0xFFFFFFFF, 0x0800,  // Extract 8 bits starting at position 0
    0x12345678, 0x0808,  // Extract 8 bits starting at position 8
    0xABCDEF01, 0x1000,  // Extract 16 bits starting at position 0
    0xDEADBEEF, 0x0810,  // Extract 8 bits starting at position 16
    0x87654321, 0x2000,  // Extract 32 bits starting at position 0
    0xFFFFFFFF, 0x0000,  // Extract 0 bits (length=0)
    0x12345678, 0x0100,  // Extract 1 bit at position 0
    0xAAAAAAAA, 0x0401)  // Extract 4 bits starting at position 1

    // Check CPU for BMI1 support (cpuid fn 0x00000007, bit 3 of ebx)
    mov eax, 0x00000007
    mov ecx, 0x0
    cpuid
    and ebx, 0x00000008
    jz bextr_nop1

    // BEXTR supported, proceed with test:
    mov eax, ARG1_32
    mov edx, ARG2_32
    bextr ecx, eax, edx

bextr_nop1: nop

TEST_END

TEST_BEGIN(BEXTRr32r32r32_zero, 2)
TEST_IGNORE_FLAGS(AF SF PF)
TEST_INPUTS(
    0x00000000, 0x0800,  // Extract from zero source
    0xFFFFFFFF, 0x081F,  // Extract 8 bits at position 31 (should be zero)
    0x12345678, 0x0820)  // Extract 8 bits at position 32+ (should be zero)

    // Check CPU for BMI1 support (cpuid fn 0x00000007, bit 3 of ebx)
    mov eax, 0x00000007
    mov ecx, 0x0
    cpuid
    and ebx, 0x00000008
    jz bextr_nop2

    // BEXTR supported, proceed with test:
    mov eax, ARG1_32
    mov edx, ARG2_32
    bextr ecx, eax, edx

bextr_nop2: nop

TEST_END

TEST_BEGIN_64(BEXTRr64r64r64_basic, 2)
TEST_IGNORE_FLAGS(AF SF PF)
TEST_INPUTS(
    0xFFFFFFFFFFFFFFFF, 0x0800,  // Extract 8 bits starting at position 0
    0x123456789ABCDEF0, 0x0808,  // Extract 8 bits starting at position 8
    0xDEADBEEFCAFEBABE, 0x1000,  // Extract 16 bits starting at position 0
    0x0123456789ABCDEF, 0x0820,  // Extract 8 bits starting at position 32
    0xFFFFFFFF00000000, 0x2020,  // Extract 32 bits starting at position 32
    0xAAAAAAAAAAAAAAAA, 0x4000,  // Extract 64 bits starting at position 0
    0x123456789ABCDEF0, 0x0000,  // Extract 0 bits (length=0)
    0x8000000000000000, 0x013F)  // Extract 1 bit at position 63

    // Check CPU for BMI1 support (cpuid fn 0x00000007, bit 3 of ebx)
    mov eax, 0x00000007
    mov ecx, 0x0
    cpuid
    and ebx, 0x00000008
    jz bextr_nop3

    // BEXTR supported, proceed with test:
    mov rax, ARG1_64
    mov rdx, ARG2_64
    bextr rcx, rax, rdx

bextr_nop3: nop

TEST_END_64

TEST_BEGIN_64(BEXTRr64r64r64_zero, 2)
TEST_IGNORE_FLAGS(AF SF PF)
TEST_INPUTS(
    0x0000000000000000, 0x0800,  // Extract from zero source
    0xFFFFFFFFFFFFFFFF, 0x083F,  // Extract 8 bits at position 63 (should be 1 bit)
    0x123456789ABCDEF0, 0x0840)  // Extract 8 bits at position 64+ (should be zero)

    // Check CPU for BMI1 support (cpuid fn 0x00000007, bit 3 of ebx)
    mov eax, 0x00000007
    mov ecx, 0x0
    cpuid
    and ebx, 0x00000008
    jz bextr_nop4

    // BEXTR supported, proceed with test:
    mov rax, ARG1_64
    mov rdx, ARG2_64
    bextr rcx, rax, rdx

bextr_nop4: nop

TEST_END_64

TEST_BEGIN(BEXTRr32m32r32, 2)
TEST_IGNORE_FLAGS(AF SF PF)
TEST_INPUTS(
    0xDEADBEEF, 0x0800,
    0x12345678, 0x0C10,
    0xFFFFFFFF, 0x1000)

    // Check CPU for BMI1 support (cpuid fn 0x00000007, bit 3 of ebx)
    mov eax, 0x00000007
    mov ecx, 0x0
    cpuid
    and ebx, 0x00000008
    jz bextr_nop5

    // BEXTR supported, proceed with test:
    push ARG1_64
    mov edx, ARG2_32
    bextr ecx, DWORD PTR [rsp], edx
    add rsp, 8

bextr_nop5: nop

TEST_END

TEST_BEGIN_64(BEXTRr64m64r64, 2)
TEST_IGNORE_FLAGS(AF SF PF)
TEST_INPUTS(
    0xDEADBEEFCAFEBABE, 0x0800,
    0x123456789ABCDEF0, 0x1010,
    0xFFFFFFFFFFFFFFFF, 0x2000)

    // Check CPU for BMI1 support (cpuid fn 0x00000007, bit 3 of ebx)
    mov eax, 0x00000007
    mov ecx, 0x0
    cpuid
    and ebx, 0x00000008
    jz bextr_nop6

    // BEXTR supported, proceed with test:
    push ARG1_64
    mov rdx, ARG2_64
    bextr rcx, QWORD PTR [rsp], rdx
    add rsp, 8

bextr_nop6: nop

TEST_END_64

#endif  // HAS_FEATURE_AVX
