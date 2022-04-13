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

#include <cstdint>

namespace remill {

/// Rotate `val` to the right `rot` positions.
inline static uint64_t RotateRight64(uint64_t val, unsigned rot) {

// NOTE: if we ever move to C++20, there are builtin rotation functions in the
//       standard library, which we should use instead.
#ifdef __has_builtin
#  if !__has_builtin(__builtin_rotateright64)
#    define REMILL_NEEDS_ROR64 1
#  else
#    define REMILL_NEEDS_ROR64 0
#  endif
#elif !defined(__clang__)
#  define REMILL_NEEDS_ROR64 1
#endif

#if REMILL_NEEDS_ROR64
  if (!rot)
    return val;
  return (val >> rot) | (val << (64u - (rot % 64u)));
#else
  return __builtin_rotateright64(val, rot);
#endif
#undef REMILL_NEEDS_ROR64
}

/// Rotate `val` to the left `rot` positions.
inline static uint32_t RotateLeft32(uint32_t val, unsigned rot) {

// NOTE: if we ever move to C++20, there are builtin rotation functions in the
//       standard library, which we should use instead.
#ifdef __has_builtin
#  if !__has_builtin(__builtin_rotateleft32)
#    define REMILL_NEEDS_ROL32 1
#  else
#    define REMILL_NEEDS_ROL32 0
#  endif
#elif !defined(__clang__)
#  define REMILL_NEEDS_ROL32 1
#endif

#if REMILL_NEEDS_ROL32
  if (!rot)
    return val;
  return (val << rot) | (val >> (32u - (rot % 32u)));
#else
  return __builtin_rotateleft32(val, rot);
#endif
#undef REMILL_NEEDS_ROL32
}

/// Rotate `val` to the right `rot` positions.
inline static uint32_t RotateRight32(uint32_t val, unsigned rot) {

// NOTE: if we ever move to C++20, there are builtin rotation functions in the
//       standard library, which we should use instead.
#ifdef __has_builtin
#  if !__has_builtin(__builtin_rotateright32)
#    define REMILL_NEEDS_ROR32 1
#  else
#    define REMILL_NEEDS_ROR32 0
#  endif
#elif !defined(__clang__)
#  define REMILL_NEEDS_ROR32 1
#endif

#if REMILL_NEEDS_ROR32
  if (!rot)
    return val;
  return (val >> rot) | (val << (32u - (rot % 32u)));
#else
  return __builtin_rotateright32(val, rot);
#endif
#undef REMILL_NEEDS_ROR32
}

}  // namespace remill
