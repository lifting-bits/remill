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

TEST_BEGIN(SETBr8, 1)
TEST_INPUTS(0)
    setb al
TEST_END

TEST_BEGIN(SETLr8, 1)
TEST_INPUTS(0)
    setl al
TEST_END

TEST_BEGIN(SETOr8, 1)
TEST_INPUTS(0)
    seto al
TEST_END

TEST_BEGIN(SETPr8, 1)
TEST_INPUTS(0)
    setp al
TEST_END

TEST_BEGIN(SETZr8, 1)
TEST_INPUTS(0)
    setz al
TEST_END

TEST_BEGIN(SETSr8, 1)
TEST_INPUTS(0)
    sets al
TEST_END

TEST_BEGIN(SETNOr8, 1)
TEST_INPUTS(0)
    setno al
TEST_END

TEST_BEGIN(SETNLr8, 1)
TEST_INPUTS(0)
    setnl al
TEST_END

TEST_BEGIN(SETNBr8, 1)
TEST_INPUTS(0)
    setnb al
TEST_END

TEST_BEGIN(SETNZr8, 1)
TEST_INPUTS(0)
    setnz al
TEST_END

TEST_BEGIN(SETNSr8, 1)
TEST_INPUTS(0)
    setns al
TEST_END

TEST_BEGIN(SETNPr8, 1)
TEST_INPUTS(0)
    setnp al
TEST_END

TEST_BEGIN(SETNBEr8, 1)
TEST_INPUTS(0)
    setnbe al
TEST_END

TEST_BEGIN(SETLEr8, 1)
TEST_INPUTS(0)
    setle al
TEST_END

TEST_BEGIN(SETNLEr8, 1)
TEST_INPUTS(0)
    setnle al
TEST_END

TEST_BEGIN(SETBEr8, 1)
TEST_INPUTS(0)
    setbe al
TEST_END
