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

TEST_BEGIN(NOT_ASIMDMISC_R_8B, not_v8b, 1)
TEST_INPUTS(0)
    not v1.8b, v0.8b
    not v2.8b, v1.8b
    not v3.8b, v2.8b
    not v4.8b, v3.8b
TEST_END

TEST_BEGIN(NOT_ASIMDMISC_R_16B, not_v16b, 1)
TEST_INPUTS(0)
    not v1.16b, v0.16b
    not v2.16b, v1.16b
    not v3.16b, v2.16b
    not v4.16b, v3.16b
TEST_END
