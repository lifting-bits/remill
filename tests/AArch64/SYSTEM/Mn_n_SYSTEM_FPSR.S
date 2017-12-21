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

/* SPECIAL CASE TESTING: `MSR FPSR, <Xn>` AND `MRS <Xn>, FPSR` */
TEST_BEGIN(MRS_RS_SYSTEM_FPSR, msr_sr_system_fpsr, 1)
TEST_INPUTS(0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80, 0x100, 0x200, 0x400, 0x800)
    mov x3, ARG1_64
    msr fpsr, x3
    mrs x3, fpsr
TEST_END
