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

TEST_BEGIN(LZCNTr16r16, 1)
TEST_IGNORE_FLAGS(OF SF AF PF)
TEST_INPUTS(
    0,
    1,
    0x8000,
    0x8001,
    0xFFFF,
    0x0080,
    0x0800)

    // check CPU for LZCNT support first. (cpuid fn 0x80000001, bit 5 of ecx)
    mov eax, 0x80000001
    mov ecx, 0x0
    cpuid
    and ecx, 0x00000020
    jz lzcnt_nop1

    // LZCNT supported, proceed with test:
    mov eax, ARG1_32
    lzcnt dx, ax

lzcnt_nop1: nop

TEST_END

TEST_BEGIN(LZCNTr32r32, 1)
TEST_IGNORE_FLAGS(OF SF AF PF)
TEST_INPUTS(
    0,
    1,
    0x80000000,
    0x80000001,
    0xFFFFFFFF,
    0x00000080,
    0x08000000)

    // check CPU for LZCNT support first. (cpuid fn 0x80000001, bit 5 of ecx)
    mov eax, 0x80000001
    mov ecx, 0x0
    cpuid
    and ecx, 0x00000020
    jz lzcnt_nop2

    // LZCNT supported, proceed with test:
    mov eax, ARG1_32
    lzcnt edx, eax

lzcnt_nop2: nop

TEST_END

TEST_BEGIN_64(LZCNTr64r64, 1)
TEST_IGNORE_FLAGS(OF SF AF PF)
TEST_INPUTS(
    0,
    1,
    0x8000000000000000,
    0x8000000000000001,
    0xFFFFFFFFFFFFFFFF,
    0x0000000000000080,
    0x0800000000000000)

    // check CPU for LZCNT support first. (cpuid fn 0x80000001, bit 5 of ecx)
    mov eax, 0x80000001
    mov ecx, 0x0
    cpuid
    and ecx, 0x00000020
    jz lzcnt_nop3

    // LZCNT supported, proceed with test:
    mov rax, ARG1_64
    lzcnt rdx, rax

lzcnt_nop3: nop

TEST_END_64

