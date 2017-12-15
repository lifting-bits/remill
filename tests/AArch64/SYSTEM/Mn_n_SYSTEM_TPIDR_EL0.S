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

/* MRS <Xn>, TPIDR_EL0 AND MSR TPIDR_EL0, <Xn> */
TEST_BEGIN(MRS_RS_SYSTEM_TPIDR_EL0, mrs_rs_system_tpidr_el0, 1)
TEST_INPUTS(0)
    mrs x3, tpidr_el0 
    msr tpidr_el0, x3
TEST_END
