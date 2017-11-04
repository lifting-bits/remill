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

TEST_BEGIN(CMEQ_ASIMDSAME_ONLY_8B, cmeq_v123x8b, 1)
TEST_INPUTS(0)
    cmeq v0.8b, v1.8b, v2.8b
    cmeq v1.8b, v2.8b, v3.8b
    cmeq v2.8b, v3.8b, v4.8b
TEST_END

TEST_BEGIN(CMGT_ASIMDSAME_ONLY_8B, cmgt_v123x8b, 1)
TEST_INPUTS(0)
    cmgt v0.8b, v1.8b, v2.8b
    cmgt v1.8b, v2.8b, v3.8b
    cmgt v2.8b, v3.8b, v4.8b
TEST_END

TEST_BEGIN(CMGE_ASIMDSAME_ONLY_8B, cmge_v123x8b, 1)
TEST_INPUTS(0)
    cmge v0.8b, v1.8b, v2.8b
    cmge v1.8b, v2.8b, v3.8b
    cmge v2.8b, v3.8b, v4.8b
TEST_END

TEST_BEGIN(CMEQ_ASIMDSAME_ONLY_16B, cmeq_v123x16b, 1)
TEST_INPUTS(0)
    cmeq v0.16b, v1.16b, v2.16b
    cmeq v1.16b, v2.16b, v3.16b
    cmeq v2.16b, v3.16b, v4.16b
TEST_END

TEST_BEGIN(CMGT_ASIMDSAME_ONLY_16B, cmgt_v123x16b, 1)
TEST_INPUTS(0)
    cmgt v0.16b, v1.16b, v2.16b
    cmgt v1.16b, v2.16b, v3.16b
    cmgt v2.16b, v3.16b, v4.16b
TEST_END

TEST_BEGIN(CMGE_ASIMDSAME_ONLY_16B, cmge_v123x16b, 1)
TEST_INPUTS(0)
    cmge v0.16b, v1.16b, v2.16b
    cmge v1.16b, v2.16b, v3.16b
    cmge v2.16b, v3.16b, v4.16b
TEST_END

TEST_BEGIN(CMEQ_ASIMDSAME_ONLY_4H, cmeq_v123x4h, 1)
TEST_INPUTS(0)
    cmeq v0.4h, v1.4h, v2.4h
    cmeq v1.4h, v2.4h, v3.4h
    cmeq v2.4h, v3.4h, v4.4h
TEST_END

TEST_BEGIN(CMGT_ASIMDSAME_ONLY_4H, cmgt_v123x4h, 1)
TEST_INPUTS(0)
    cmgt v0.4h, v1.4h, v2.4h
    cmgt v1.4h, v2.4h, v3.4h
    cmgt v2.4h, v3.4h, v4.4h
TEST_END

TEST_BEGIN(CMGE_ASIMDSAME_ONLY_4H, cmge_v123x4h, 1)
TEST_INPUTS(0)
    cmge v0.4h, v1.4h, v2.4h
    cmge v1.4h, v2.4h, v3.4h
    cmge v2.4h, v3.4h, v4.4h
TEST_END

TEST_BEGIN(CMEQ_ASIMDSAME_ONLY_8H, cmeq_v123x8h, 1)
TEST_INPUTS(0)
    cmeq v0.8h, v1.8h, v2.8h
    cmeq v1.8h, v2.8h, v3.8h
    cmeq v2.8h, v3.8h, v4.8h
TEST_END

TEST_BEGIN(CMGT_ASIMDSAME_ONLY_8H, cmgt_v123x8h, 1)
TEST_INPUTS(0)
    cmgt v0.8h, v1.8h, v2.8h
    cmgt v1.8h, v2.8h, v3.8h
    cmgt v2.8h, v3.8h, v4.8h
TEST_END

TEST_BEGIN(CMGE_ASIMDSAME_ONLY_8H, cmge_v123x8h, 1)
TEST_INPUTS(0)
    cmge v0.8h, v1.8h, v2.8h
    cmge v1.8h, v2.8h, v3.8h
    cmge v2.8h, v3.8h, v4.8h
TEST_END

TEST_BEGIN(CMEQ_ASIMDSAME_ONLY_2S, cmeq_v123x2s, 1)
TEST_INPUTS(0)
    cmeq v0.2s, v1.2s, v2.2s
    cmeq v1.2s, v2.2s, v3.2s
    cmeq v2.2s, v3.2s, v4.2s
TEST_END

TEST_BEGIN(CMGT_ASIMDSAME_ONLY_2S, cmgt_v123x2s, 1)
TEST_INPUTS(0)
    cmgt v0.2s, v1.2s, v2.2s
    cmgt v1.2s, v2.2s, v3.2s
    cmgt v2.2s, v3.2s, v4.2s
TEST_END

TEST_BEGIN(CMGE_ASIMDSAME_ONLY_2S, cmge_v123x2s, 1)
TEST_INPUTS(0)
    cmge v0.2s, v1.2s, v2.2s
    cmge v1.2s, v2.2s, v3.2s
    cmge v2.2s, v3.2s, v4.2s
TEST_END

TEST_BEGIN(CMEQ_ASIMDSAME_ONLY_4S, cmeq_v123x4s, 1)
TEST_INPUTS(0)
    cmeq v0.4s, v1.4s, v2.4s
    cmeq v1.4s, v2.4s, v3.4s
    cmeq v2.4s, v3.4s, v4.4s
TEST_END

TEST_BEGIN(CMGT_ASIMDSAME_ONLY_4S, cmgt_v123x4s, 1)
TEST_INPUTS(0)
    cmgt v0.4s, v1.4s, v2.4s
    cmgt v1.4s, v2.4s, v3.4s
    cmgt v2.4s, v3.4s, v4.4s
TEST_END

TEST_BEGIN(CMGE_ASIMDSAME_ONLY_4S, cmge_v123x4s, 1)
TEST_INPUTS(0)
    cmge v0.4s, v1.4s, v2.4s
    cmge v1.4s, v2.4s, v3.4s
    cmge v2.4s, v3.4s, v4.4s
TEST_END

TEST_BEGIN(CMEQ_ASIMDSAME_ONLY_2D, cmeq_v123x2d, 1)
TEST_INPUTS(0)
    cmeq v0.2d, v1.2d, v2.2d
    cmeq v1.2d, v2.2d, v3.2d
    cmeq v2.2d, v3.2d, v4.2d
TEST_END

TEST_BEGIN(CMGT_ASIMDSAME_ONLY_2D, cmgt_v123x2d, 1)
TEST_INPUTS(0)
    cmgt v0.2d, v1.2d, v2.2d
    cmgt v1.2d, v2.2d, v3.2d
    cmgt v2.2d, v3.2d, v4.2d
TEST_END

TEST_BEGIN(CMGE_ASIMDSAME_ONLY_2D, cmge_v123x2d, 1)
TEST_INPUTS(0)
    cmge v0.2d, v1.2d, v2.2d
    cmge v1.2d, v2.2d, v3.2d
    cmge v2.2d, v3.2d, v4.2d
TEST_END
