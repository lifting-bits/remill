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

TEST_BEGIN_64(PSUBBr64r64, 2)
TEST_INPUTS_MMX_2()
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    psubb mm0, mm1
TEST_END_64

TEST_BEGIN_64(PSUBBr64m64, 2)
TEST_INPUTS_MMX_2()
    push ARG2_64
    movq mm0, ARG1_64
    psubb mm0, qword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PSUBBv128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    psubb xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PSUBBv128m128, 2)
TEST_INPUTS_MMX_2()
    push 0
    push ARG2_64
    movq xmm0, ARG1_64
    psubb xmm0, xmmword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PSUBWr64r64, 2)
TEST_INPUTS_MMX_2()
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    psubw mm0, mm1
TEST_END_64

TEST_BEGIN_64(PSUBWr64m64, 2)
TEST_INPUTS_MMX_2()
    push ARG2_64
    movq mm0, ARG1_64
    psubw mm0, qword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PSUBWv128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    psubw xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PSUBWv128m128, 2)
TEST_INPUTS_MMX_2()
    push 0
    push ARG2_64
    movq xmm0, ARG1_64
    psubw xmm0, xmmword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PSUBDr64r64, 2)
TEST_INPUTS_MMX_2()
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    psubd mm0, mm1
TEST_END_64

TEST_BEGIN_64(PSUBDr64m64, 2)
TEST_INPUTS_MMX_2()
    push ARG2_64
    movq mm0, ARG1_64
    psubd mm0, qword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PSUBDv128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    psubd xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PSUBDv128m128, 2)
TEST_INPUTS_MMX_2()
    push 0
    push ARG2_64
    movq xmm0, ARG1_64
    psubd xmm0, xmmword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PSUBQr64r64, 2)
TEST_INPUTS_MMX_2()
    movq mm0, ARG1_64;
    movq mm1, ARG2_64;
    psubq mm0, mm1;
TEST_END_64

TEST_BEGIN_64(PSUBQr64m64, 2)
TEST_INPUTS_MMX_2()
    push ARG2_64;
    movq mm0, ARG1_64;
    psubq mm0, qword ptr [rsp];
TEST_END_64

TEST_BEGIN_64(PSUBQv128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm0, ARG1_64;
    movq xmm1, ARG2_64;
    psubq xmm0, xmm1;
TEST_END_64

TEST_BEGIN_64(PSUBQv128m128, 2)
TEST_INPUTS_MMX_2()
    push 0;
    push ARG2_64;
    movq xmm0, ARG1_64;
    psubq xmm0, xmmword ptr [rsp];
TEST_END_64

#if HAS_FEATURE_AVX

TEST_BEGIN_64(VPSUBDv128v128m128, 2)
TEST_INPUTS_MMX_2()
    push 0;
    push ARG2_64;
    movq xmm0, ARG1_64;
    vpsubd xmm1, xmm0, xmmword ptr [rsp];
TEST_END_64

TEST_BEGIN_64(VPSUBDv128v128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm0, ARG1_64;
    movq xmm1, ARG2_64;
    vpsubd xmm2, xmm1, xmm0;
TEST_END_64

TEST_BEGIN_64(VPSUBQv128v128m128, 2)
TEST_INPUTS_MMX_2()
    push 0;
    push ARG2_64;
    movq xmm0, ARG1_64;
    vpsubq xmm1, xmm0, xmmword ptr [rsp];
TEST_END_64

TEST_BEGIN_64(VPSUBQv128v128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm0, ARG1_64;
    movq xmm1, ARG2_64;
    vpsubq xmm2, xmm1, xmm0;
TEST_END_64

#endif  // HAS_FEATURE_AVX

TEST_BEGIN_64(PSUBUSBr64r64, 2)
TEST_INPUTS_MMX_2()
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    psubusb mm0, mm1
TEST_END_64

TEST_BEGIN_64(PSUBUSBr64m64, 2)
TEST_INPUTS_MMX_2()
    push ARG2_64
    movq mm0, ARG1_64
    psubusb mm0, qword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PSUBUSBv128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    psubusb xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PSUBUSBv128m128, 2)
TEST_INPUTS_MMX_2()
    push 0
    push ARG2_64
    movq xmm0, ARG1_64
    psubusb xmm0, xmmword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PSUBUSWr64r64, 2)
TEST_INPUTS_MMX_2()
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    psubusw mm0, mm1
TEST_END_64

TEST_BEGIN_64(PSUBUSWr64m64, 2)
TEST_INPUTS_MMX_2()
    push ARG2_64
    movq mm0, ARG1_64
    psubusw mm0, qword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PSUBUSWv128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    psubusw xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PSUBUSWv128m128, 2)
TEST_INPUTS_MMX_2()
    push 0
    push ARG2_64
    movq xmm0, ARG1_64
    psubusw xmm0, xmmword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PHSUBWr64r64, 2)
TEST_INPUTS_MMX_2()
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    phsubw mm0, mm1
TEST_END_64

TEST_BEGIN_64(PHSUBWr64m64, 2)
TEST_INPUTS_MMX_2()
    push ARG2_64
    movq mm0, ARG1_64
    phsubw mm0, qword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PHSUBWv128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    phsubw xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PHSUBWv128m128, 2)
TEST_INPUTS_MMX_2()
    push 0
    push ARG2_64
    movq xmm0, ARG1_64
    phsubw xmm0, xmmword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PHSUBDr64r64, 2)
TEST_INPUTS_MMX_2()
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    phsubd mm0, mm1
TEST_END_64

TEST_BEGIN_64(PHSUBDr64m64, 2)
TEST_INPUTS_MMX_2()
    push ARG2_64
    movq mm0, ARG1_64
    phsubd mm0, qword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PHSUBDv128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    phsubd xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PHSUBDv128m128, 2)
TEST_INPUTS_MMX_2()
    push 0
    push ARG2_64
    movq xmm0, ARG1_64
    phsubd xmm0, xmmword ptr [rsp]
TEST_END_64
