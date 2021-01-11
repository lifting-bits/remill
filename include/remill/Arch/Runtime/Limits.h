/*
 * Copyright (c) 2021 Trail of Bits, Inc.
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

#if __has_include(<limits>)
#  include <limits>
#else
#include "Int.h"

namespace std {

template <typename T>
struct numeric_limits;

template <>
struct numeric_limits<uint8_t> {
  inline static uint8_t max(void) noexcept {
    return static_cast<uint8_t>(~0u);
  }
  inline static uint8_t min(void) noexcept {
    return static_cast<uint8_t>(0u);
  }
};

template <>
struct numeric_limits<int8_t> {
  inline static int8_t max(void) noexcept {
    return static_cast<int8_t>(127);
  }
  inline static int8_t min(void) noexcept {
    return static_cast<int8_t>(-128);
  }
};

template <>
struct numeric_limits<uint16_t> {
  inline static uint16_t max(void) noexcept {
    return static_cast<uint16_t>(65535l);
  }
  inline static uint16_t min(void) noexcept {
    return static_cast<uint16_t>(0u);
  }
};

template <>
struct numeric_limits<int16_t> {
  inline static int16_t max(void) noexcept {
    return static_cast<int16_t>(32767l);
  }
  inline static int16_t min(void) noexcept {
    return static_cast<int16_t>(-32768l);
  }
};

template <>
struct numeric_limits<uint32_t> {
  inline static uint32_t max(void) noexcept {
    return static_cast<uint32_t>(4294967295ull);
  }
  inline static uint32_t min(void) noexcept {
    return static_cast<uint32_t>(0u);
  }
};

template <>
struct numeric_limits<int32_t> {
  inline static int32_t max(void) noexcept {
    return static_cast<int32_t>(2147483647ll);
  }
  inline static int32_t min(void) noexcept {
    return static_cast<int32_t>(-2147483648ll);
  }
};

template <>
struct numeric_limits<uint64_t> {
  inline static uint64_t max(void) noexcept {
    return static_cast<uint64_t>(18446744073709551615ull);
  }
  inline static uint64_t min(void) noexcept {
    return static_cast<uint64_t>(0u);
  }
};

template <>
struct numeric_limits<int64_t> {
  inline static int64_t max(void) noexcept {
    return static_cast<int64_t>(9223372036854775807ll);
  }
  inline static int64_t min(void) noexcept {
    return static_cast<int64_t>(0x8000000000000000ull);
  }
};


//template <>
//struct numeric_limits<int8_t> {
//  inline static int8_t max(void) noexcept {
//    return ~0_u8;
//  }
//  inline static int8_t min(void) noexcept {
//    return 0_u8;
//  }
//};

}  // namespace std

#endif
