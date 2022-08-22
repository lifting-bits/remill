/*
 * Copyright (c) 2022 Trail of Bits, Inc.
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

#include "Builtin.h"

#if __has_include(<cstdint>)
#  include <cstdint>
#elif __has_include(<cinttypes>)
#  include <cinttypes>
#else

#define REMILL_CUSTOM_INT_TYPES 1

using size_t = decltype(sizeof(int));

template <size_t kDesiredSize, typename... Ts>
struct TypeSelector;

template <size_t kDesiredSize, size_t kXorSize, typename... Ts>
struct TypeSelectorImpl;

template <size_t kDesiredSize, size_t kXorSize, typename T, typename... Ts>
struct TypeSelectorImpl<kDesiredSize, kXorSize, T, Ts...>
  : public TypeSelector<kDesiredSize, Ts...> {};

template <size_t kDesiredSize, typename T, typename... Ts>
struct TypeSelectorImpl<kDesiredSize, 0, T, Ts...> {
  using Type = T;
};

template <size_t kDesiredSize>
struct TypeSelector<kDesiredSize> {
  using Type = void;
};

template <size_t kDesiredSize, typename T, typename... Ts>
struct TypeSelector<kDesiredSize, T, Ts...>
    : public TypeSelectorImpl<kDesiredSize, sizeof(T) ^ kDesiredSize, T, Ts...> {};

using int8_t = signed char;
using uint8_t = unsigned char;
using int16_t = TypeSelector<2, short, int, long, long long>::Type;
using uint16_t = TypeSelector<2, unsigned short, unsigned, unsigned long, unsigned long long>::Type;
using int32_t = TypeSelector<4, int, long, long long>::Type;
using uint32_t = TypeSelector<4, unsigned, unsigned long, unsigned long long>::Type;
using int64_t = TypeSelector<8, int, long, long long>::Type;
using uint64_t = TypeSelector<8, unsigned, unsigned long, unsigned long long>::Type;

#endif  // cstint, cinttypes

#if !defined(REMILL_DISABLE_INT128)
#if defined(__x86_64__) || defined(__i386__) || defined(_M_X86) || defined (__arm__)
typedef unsigned uint128_t __attribute__((mode(TI)));
typedef int int128_t __attribute__((mode(TI)));
#elif defined(__aarch64__)
typedef __uint128_t uint128_t;
typedef __int128_t int128_t;
#elif defined(__sparc__)
typedef __uint128_t uint128_t;
typedef __int128_t int128_t;
#elif defined(__is_identifier) && __is_identifier(_BitInt)
typedef unsigned _BitInt(128) uint128_t;
typedef signed _BitInt(128) int128_t;
#elif defined(__is_identifier) && __is_identifier(_ExtInt)
typedef unsigned _ExtInt(128) uint128_t;
typedef signed _ExtInt(128) int128_t;
#else
#error "Unable to identify u/int128 type."
#endif

static_assert(sizeof(int128_t) == 16, "Invalid size for `int128_t`.");
static_assert(sizeof(uint128_t) == 16, "Invalid size for `uint128_t`.");
#endif  // `!defined(REMILL_DISABLE_INT128)`

#ifdef REMILL_CUSTOM_INT_TYPES
namespace std {
inline namespace __remill {
using size_t = ::size_t;
using uint8_t = ::uint8_t;
using uint16_t = ::uint16_t;
using uint32_t = ::uint32_t;
using uint64_t = ::uint64_t;
using int8_t = ::int8_t;
using int16_t = ::int16_t;
using int32_t = ::int32_t;
using int64_t = ::int64_t;
}  // namespace __remill
}  // namespace std
#endif  // REMILL_CUSTOM_INT_TYPES
