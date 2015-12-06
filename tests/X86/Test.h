/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef TESTS_X86_TEST_H_
#define TESTS_X86_TEST_H_

namespace test {

enum : size_t {
  kPageSize = 4096,
  kMaxInstrLen = 15
};

struct alignas(8) TestInfo {
  int32_t test_begin;
  int32_t test_end;
  int32_t test_name;
  int32_t instr_begin;
  int32_t instr_end;
  int32_t lifted_func;
  uint32_t num_args;
};

extern "C" {
extern const TestInfo __x86_test_table_begin[];
extern const TestInfo __x86_test_table_end[];
}  // extern C

}  // namespace test

#endif  // TESTS_X86_TEST_H_
