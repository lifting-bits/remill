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

#pragma once

#define TEST_FPU_TAGS 1
#define TEST_FPU_RAW_REGISTERS 2
#define TEST_FPU_MXCSR 4
// ARG1: eight padded ext80 registers; ARG2: CW | (SW << 16);
// ARG3: MXCSR | (lifted-host rounding mode << 32).
#define TEST_FPU_INPUTS 8
#define TEST_SINGLE_FLAGS 16
#define TEST_TWO_FLAGS 32
#define TEST_HOST_FLAGS 64

#ifndef __ASSEMBLER__
struct State;
struct Memory;

namespace test {

enum : size_t { kPageSize = 4096, kMaxInstrLen = 15 };

struct alignas(128) TestInfo {
  const uintptr_t test_begin;
  const uintptr_t test_end;
  const char *test_name;
  const uint64_t *const args_begin;
  const uint64_t *const args_end;
  const uint64_t num_args;
  const uint64_t ignored_flags_mask;
  const uint64_t fpu_status_mask;
  const uint64_t fpu_checks;
} __attribute__((packed));

extern "C" {
extern const TestInfo __x86_test_table_begin[];
extern const TestInfo __x86_test_table_end[];
}  // extern C

}  // namespace test
#endif  // !__ASSEMBLER__
