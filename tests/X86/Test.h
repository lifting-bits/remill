/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef TESTS_X86_TEST_H_
#define TESTS_X86_TEST_H_

struct State;
struct Memory;

namespace test {

enum : size_t {
  kPageSize = 4096,
  kMaxInstrLen = 15
};

struct alignas(128) TestInfo {
  const uintptr_t test_begin;
  const uintptr_t test_end;
  const char *test_name;
  const uint64_t * const args_begin;
  const uint64_t * const args_end;
  void (* const lifted_func)(State *, Memory *, uintptr_t);
  const uint64_t num_args;
  const uint64_t ignored_flags_mask;
} __attribute__((packed));

extern "C" {
extern const TestInfo __x86_test_table_begin[];
extern const TestInfo __x86_test_table_end[];
}  // extern C

}  // namespace test

#endif  // TESTS_X86_TEST_H_
