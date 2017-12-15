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

/* SPECIAL CASE TESTING: `MSR FPCR, <Xn>` AND `MRS <Xn>, FPCR` */
TEST_BEGIN(MRS_RS_SYSTEM_FPCR, msr_sr_system_fpcr, 1)
TEST_INPUTS(0x400000, 0x800000, 0xc00000, 0x1000000, 0x2000000, 0x4000000)
    mov x3, ARG1_64
    msr fpcr, x3
    mrs x3, fpcr
TEST_END
