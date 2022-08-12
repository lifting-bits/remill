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

#if __has_include(<type_traits>)
#  include <type_traits>
#else
#  include "Int.h"

namespace std {

template <typename T>
struct is_signed;

template <typename T>
struct is_unsigned;

#define MAKE_SIGNED(type, val) \
    template <> \
    struct is_signed<type> { \
      static constexpr bool value = val; \
    }

MAKE_SIGNED(int8_t, true);
MAKE_SIGNED(int16_t, true);
MAKE_SIGNED(int32_t, true);
MAKE_SIGNED(int64_t, true);

MAKE_SIGNED(uint8_t, false);
MAKE_SIGNED(uint16_t, false);
MAKE_SIGNED(uint32_t, false);
MAKE_SIGNED(uint64_t, false);

#undef MAKE_SIGNED

#define MAKE_UNSIGNED(type, val) \
    template <> \
    struct is_unsigned<type> { \
      static constexpr bool value = val; \
    }

MAKE_UNSIGNED(int8_t, false);
MAKE_UNSIGNED(int16_t, false);
MAKE_UNSIGNED(int32_t, false);
MAKE_UNSIGNED(int64_t, false);

MAKE_UNSIGNED(uint8_t, true);
MAKE_UNSIGNED(uint16_t, true);
MAKE_UNSIGNED(uint32_t, true);
MAKE_UNSIGNED(uint64_t, true);

#undef MAKE_UNSIGNED

template <typename A, typename B>
struct is_same {
  static constexpr bool value = false;
};

template <typename A>
struct is_same<A, A> {
  static constexpr bool value = true;
};

}  // namespace std

#endif
