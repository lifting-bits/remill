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


TEST_BEGIN(ADD_ASIMDSAME_ONLY_8B, add_v123x8b, 1)
TEST_INPUTS(0)
    add v0.8b, v1.8b, v2.8b
TEST_END

TEST_BEGIN(ADD_ASIMDSAME_ONLY_16B, add_v123x16b, 1)
TEST_INPUTS(0)
    add v0.16b, v1.16b, v2.16b
TEST_END

TEST_BEGIN(ADD_ASIMDSAME_ONLY_4H, add_v123x4h, 1)
TEST_INPUTS(0)
    add v0.4h, v1.4h, v2.4h
TEST_END

TEST_BEGIN(ADD_ASIMDSAME_ONLY_8H, add_v123x8h, 1)
TEST_INPUTS(0)
    add v0.8h, v1.8h, v2.8h
TEST_END

TEST_BEGIN(ADD_ASIMDSAME_ONLY_2S, add_v123x2s, 1)
TEST_INPUTS(0)
    add v0.2s, v1.2s, v2.2s
TEST_END

TEST_BEGIN(ADD_ASIMDSAME_ONLY_4S, add_v123x4s, 1)
TEST_INPUTS(0)
    add v0.4s, v1.4s, v2.4s
TEST_END

TEST_BEGIN(ADD_ASIMDSAME_ONLY_2D, add_v123x2d, 1)
TEST_INPUTS(0)
    add v0.2d, v1.2d, v2.2d
TEST_END
