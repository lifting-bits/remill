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


TEST_BEGIN(MVNI_ASIMDIMM_L_HL_4H, mvni_4h, 1)
TEST_INPUTS(0)
    mvni v1.4h, #0
    mvni v2.4h, #0x41
    mvni v3.4h, #0x41, LSL #0
    mvni v4.4h, #0x41, LSL #8
TEST_END

TEST_BEGIN(MVNI_ASIMDIMM_L_HL_8H, mvni_8h, 1)
TEST_INPUTS(0)
    mvni v1.8h, #0
    mvni v2.8h, #0x41
    mvni v3.8h, #0x41, LSL #0
    mvni v4.8h, #0x41, LSL #8
TEST_END

TEST_BEGIN(MVNI_ASIMDIMM_L_SL_2S, mvni_2s, 1)
TEST_INPUTS(0)
    mvni v1.2s, #0
    mvni v2.2s, #0x41
    mvni v3.2s, #0x41, LSL #0
    mvni v4.2s, #0x41, LSL #8
    mvni v5.2s, #0x41, LSL #16
    mvni v6.2s, #0x41, LSL #24
TEST_END

TEST_BEGIN(MVNI_ASIMDIMM_L_SL_4S, mvni_4s, 1)
TEST_INPUTS(0)
    mvni v1.4s, #0
    mvni v2.4s, #0x41
    mvni v3.4s, #0x41, LSL #0
    mvni v4.4s, #0x41, LSL #8
    mvni v5.4s, #0x41, LSL #16
    mvni v6.4s, #0x41, LSL #24
TEST_END

TEST_BEGIN(MVNI_ASIMDIMM_M_SM_2S, mvni_2s_msl, 1)
TEST_INPUTS(0)
    mvni v1.2s, #0x41, MSL #8
    mvni v2.2s, #0x41, MSL #16
TEST_END

TEST_BEGIN(MVNI_ASIMDIMM_M_SM_4S, mvni_4s_msl, 1)
TEST_INPUTS(0)
    mvni v1.4s, #0x41, MSL #8
    mvni v2.4s, #0x41, MSL #16
TEST_END
