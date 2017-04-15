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

TEST_BEGIN(FXCHst0st0, 1)
TEST_INPUTS(0)
    fldl2e
    fldlg2
    fxch st(0)
TEST_END

TEST_BEGIN(FXCHst0st1, 1)
TEST_INPUTS(0)
    fldl2e
    fldlg2
    fxch
TEST_END

TEST_BEGIN(FXCHst0st2, 1)
TEST_INPUTS(0)
    fldl2e
    fldlg2
    fldpi
    fxch st(2)
TEST_END
