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

#if APPLE_SAFE_TESTS

TEST_BEGIN(CVTPI2PSv128m64, 2)
TEST_INPUTS(
    0x0, 0x0,
    0xFFFFFFFF, 0x0,
    0x0, 0xFFFFFFFF,
    0xFFFFFFFF, 0xFFFFFFFF,
    0x41414141, 0xABABABAB)  // 99999.5

    mov DWORD PTR [rsp - 4], ARG1_32
    mov DWORD PTR [rsp - 8], ARG2_32
    cvtpi2ps xmm0, QWORD PTR [rsp - 8]
TEST_END

TEST_BEGIN(CVTPI2PSv128mm64, 2)
TEST_INPUTS(
    0x0, 0x0,
    0xFFFFFFFF, 0x0,
    0x0, 0xFFFFFFFF,
    0xFFFFFFFF, 0xFFFFFFFF,
    0x41414141, 0xABABABAB)  // 99999.5

    mov DWORD PTR [rsp - 4], ARG1_32
    mov DWORD PTR [rsp - 8], ARG2_32
    movq mm0, [rsp - 8]
    cvtpi2ps xmm0, mm0
TEST_END

// TODO(pag): Test CVTPI2PD_XMMpd_MMXq

#endif  // APPLE_SAFE_TESTS

#if defined(IN_TEST_GENERATOR) && ADDRESS_SIZE_BITS == 32
    .code32
#endif

/* SET_VEC in the harness supplies nonzero upper lanes. */
TEST_BEGIN(CVTPI2PS_PRESERVE_MEMORY, 2)
TEST_INPUTS(1, 0xfffffffe, 0x7fffffff, 0x80000000)
    lea SP_ADDR, [SP_ADDR - 16]
    mov DWORD PTR [SP_ADDR], ARG1_32
    mov DWORD PTR [SP_ADDR + 4], ARG2_32
    cvtpi2ps xmm0, QWORD PTR [SP_ADDR]
TEST_END

TEST_BEGIN(CVTPI2PS_PRESERVE_REGISTER, 2)
TEST_INPUTS(1, 0xfffffffe, 0x7fffffff, 0x80000000)
    lea SP_ADDR, [SP_ADDR - 16]
    mov DWORD PTR [SP_ADDR], ARG1_32
    mov DWORD PTR [SP_ADDR + 4], ARG2_32
    movq mm1, QWORD PTR [SP_ADDR]
    cvtpi2ps xmm0, mm1
TEST_END

#if defined(IN_TEST_GENERATOR) && ADDRESS_SIZE_BITS == 32
    .code64
#endif
