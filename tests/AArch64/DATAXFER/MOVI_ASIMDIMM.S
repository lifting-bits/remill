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

TEST_BEGIN(MOVI_ASIMDIMM_N_B_8B, movi_8b, 1)
TEST_INPUTS(0)
    movi v1.8b, #0
    movi v2.8b, #0x41
TEST_END

TEST_BEGIN(MOVI_ASIMDIMM_N_B_16B, movi_16b, 1)
TEST_INPUTS(0)
    movi v1.16b, #0
    movi v2.16b, #0x41
TEST_END

TEST_BEGIN(MOVI_ASIMDIMM_L_HL_4H, movi_4h, 1)
TEST_INPUTS(0)
    movi v1.4h, #0
    movi v2.4h, #0x41
    movi v3.4h, #0x41, LSL #0
    movi v4.4h, #0x41, LSL #8
TEST_END

TEST_BEGIN(MOVI_ASIMDIMM_L_HL_8H, movi_8h, 1)
TEST_INPUTS(0)
    movi v1.8h, #0
    movi v2.8h, #0x41
    movi v3.8h, #0x41, LSL #0
    movi v4.8h, #0x41, LSL #8
TEST_END

TEST_BEGIN(MOVI_ASIMDIMM_L_SL_2S, movi_2s, 1)
TEST_INPUTS(0)
    movi v1.2s, #0
    movi v2.2s, #0x41
    movi v3.2s, #0x41, LSL #0
    movi v4.2s, #0x41, LSL #8
    movi v5.2s, #0x41, LSL #16
    movi v6.2s, #0x41, LSL #24
TEST_END

TEST_BEGIN(MOVI_ASIMDIMM_L_SL_4S, movi_4s, 1)
TEST_INPUTS(0)
    movi v1.4s, #0
    movi v2.4s, #0x41
    movi v3.4s, #0x41, LSL #0
    movi v4.4s, #0x41, LSL #8
    movi v5.4s, #0x41, LSL #16
    movi v6.4s, #0x41, LSL #24
TEST_END

TEST_BEGIN(MOVI_ASIMDIMM_M_SM_2S, movi_2s_msl, 1)
TEST_INPUTS(0)
    movi v1.2s, #0x41, MSL #8
    movi v2.2s, #0x41, MSL #16
TEST_END

TEST_BEGIN(MOVI_ASIMDIMM_M_SM_4S, movi_4s_msl, 1)
TEST_INPUTS(0)
    movi v1.4s, #0x41, MSL #8
    movi v2.4s, #0x41, MSL #16
TEST_END

TEST_BEGIN(MOVI_ASIMDIMM_D_DS, movi_d, 1)
    movi d1, #0
    movi d2, #0xFF
    movi d3, #0x00FF00FF00FF00FF
TEST_END

TEST_BEGIN(MOVI_ASIMDIMM_D2_D, movi_2d, 1)
TEST_INPUTS(0)
    movi v1.2d, #0
    movi v2.2d, #0xFF
    movi v3.2d, #0x00FF00FF00FF00FF
TEST_END
