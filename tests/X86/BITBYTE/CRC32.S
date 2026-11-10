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

TEST_BEGIN(CRC32r32r8, 2)
TEST_INPUTS(
    0, 0,
    0xFFFFFFFF, 0xFF,
    0x12345678, 0xAB,
    0x89ABCDEF, 0x80,
    0xDEADBEEF, 0x01)

    SAVE_CPUID_REGS
    mov eax, 0x00000001
    cpuid
    test ecx, 0x00100000
    RESTORE_CPUID_REGS
    jz crc32_nop1

    mov eax, ARG1_32
    mov ebx, ARG2_32
    crc32 eax, bl

crc32_nop1: nop
TEST_END

TEST_BEGIN(CRC32r32r32, 2)
TEST_INPUTS(
    0, 0,
    0xFFFFFFFF, 0xFFFFFFFF,
    0x12345678, 0xABCDEF01,
    0x89ABCDEF, 0x80000000,
    0xDEADBEEF, 0x01020304)

    SAVE_CPUID_REGS
    mov eax, 0x00000001
    cpuid
    test ecx, 0x00100000
    RESTORE_CPUID_REGS
    jz crc32_nop2

    mov eax, ARG1_32
    mov ebx, ARG2_32
    crc32 eax, ebx

crc32_nop2: nop
TEST_END

TEST_BEGIN_64(CRC32r64r8, 2)
TEST_INPUTS(
    0, 0,
    0xFFFFFFFFFFFFFFFF, 0xFF,
    0x123456789ABCDEF0, 0xAB,
    0x89ABCDEF01234567, 0x80,
    0xDEADBEEFCAFEBABE, 0x01)

    SAVE_CPUID_REGS
    mov eax, 0x00000001
    cpuid
    test ecx, 0x00100000
    RESTORE_CPUID_REGS
    jz crc32_nop3

    mov rax, ARG1_64
    mov rbx, ARG2_64
    crc32 rax, bl

crc32_nop3: nop
TEST_END_64

TEST_BEGIN_64(CRC32r64r64, 2)
TEST_INPUTS(
    0, 0,
    0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
    0x123456789ABCDEF0, 0xABCDEF0102030405,
    0x89ABCDEF01234567, 0x8000000000000000,
    0xDEADBEEFCAFEBABE, 0x0102030405060708)

    SAVE_CPUID_REGS
    mov eax, 0x00000001
    cpuid
    test ecx, 0x00100000
    RESTORE_CPUID_REGS
    jz crc32_nop4

    mov rax, ARG1_64
    mov rbx, ARG2_64
    crc32 rax, rbx

crc32_nop4: nop
TEST_END_64
