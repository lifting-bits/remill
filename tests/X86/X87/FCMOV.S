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

TEST_BEGIN(FCMOVNU, 1)
TEST_INPUTS(0)
    fld1
    fldpi
    fldl2t
    fldl2e
    fcmovnu st(0), st(1)
TEST_END

TEST_BEGIN(FCMOVNB, 1)
TEST_INPUTS(0)
    fld1
    fldpi
    fldl2t
    fldl2e
    fcmovnb st(0), st(1)
TEST_END

TEST_BEGIN(FCMOVNE, 1)
TEST_INPUTS(0)
    fld1
    fldpi
    fldl2t
    fldl2e
    fcmovne st(0), st(1)
TEST_END

TEST_BEGIN(FCMOVBE, 1)
TEST_INPUTS(0)
    fld1
    fldpi
    fldl2t
    fldl2e
    fcmovbe st(0), st(1)
TEST_END

TEST_BEGIN(FCMOVNBE, 1)
TEST_INPUTS(0)
    fld1
    fldpi
    fldl2t
    fldl2e
    fcmovnbe st(0), st(1)
TEST_END

TEST_BEGIN(FCMOVU, 1)
TEST_INPUTS(0)
    fld1
    fldpi
    fldl2t
    fldl2e
    fcmovu st(0), st(1)
TEST_END

TEST_BEGIN(FCMOVE, 1)
TEST_INPUTS(0)
    fld1
    fldpi
    fldl2t
    fldl2e
    fcmove st(0), st(1)
TEST_END

TEST_BEGIN(FCMOVB, 1)
TEST_INPUTS(0)
    fld1
    fldpi
    fldl2t
    fldl2e
    fcmovb st(0), st(1)
TEST_END

