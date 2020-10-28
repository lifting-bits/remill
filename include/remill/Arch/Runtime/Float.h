/*
 * Copyright (c) 2020 Trail of Bits, Inc.
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

#pragma once

#include <cfloat>

// Windows doesn't have the following macros defined
#ifndef _SW_INEXACT
#  define _SW_INEXACT 0x00000001  // Inexact (precision)
#  define _SW_UNDERFLOW 0x00000002  // Underflow
#  define _SW_OVERFLOW 0x00000004  // Overflow
#  define _SW_ZERODIVIDE 0x00000008  // Divide by zero
#  define _SW_INVALID 0x00000010  // Invalid
#  define _SW_DENORMAL 0x00080000  // Denormal status bit
#  define _MCW_RC 0x00000300  // Rounding Control
#  define _RC_NEAR 0x00000000  //     near
#  define _RC_DOWN 0x00000100  //     down
#  define _RC_UP 0x00000200  //     up
#  define _RC_CHOP 0x00000300  //     chop
#endif

#include <cfenv>
#include <cmath>

// macOS does not have this flag
#ifndef __FE_DENORM
#  define __FE_DENORM 0x02
#endif
