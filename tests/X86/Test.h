/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef TESTS_X86_TEST_H_
#define TESTS_X86_TEST_H_

namespace test {

enum : size_t {
  kPageSize = 4096,
  kMaxInstrLen = 15
};

enum : uint32_t {
  kFeatureMMX = (1U << 0),
  kFeatureSSE = (1U << 1),
  kFeatureAVX = (1U << 2),
  kFeatureAVX512 = (1U << 3),
  kFeature64BitOnly = (1 << 4),
  kFeature32BitOnly = (1 << 5)
};

struct TestInfo {
  uintptr_t test_begin;
  uintptr_t test_end;
  uintptr_t test_name;
  uintptr_t instr_begin;
  uintptr_t instr_end;
  uintptr_t lifted_func;
  uint32_t num_args;
  uint32_t features;
};

extern "C" {
extern const TestInfo __x86_test_table_begin[];
extern const TestInfo __x86_test_table_end[];
}  // extern C

}  // namespace test

#endif  // TESTS_X86_TEST_H_
