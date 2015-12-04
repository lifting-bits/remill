/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <cstdint>
#include <iostream>

#include "tests/X86/Test.h"

namespace test {


struct alignas(128) Stack {
  uint8_t bytes[kPageSize];
};


static Stack gStack;

static void CreateTest(const TestInfo &test) {
  uintptr_t test_begin = test.test_begin;
  uintptr_t test_end = test.test_end;
  uintptr_t test_instr = test.instr_begin;
  const char *test_name = reinterpret_cast<const char *>(
      static_cast<uintptr_t>(test.test_name));

  std::cout << test_name << std::endl;
}

}  // namespace

extern "C" {
extern const TestInfo __x86_test_table_begin[];
extern const TestInfo __x86_test_table_end[];
}  // extern C

extern "C" int main(void) {
  for (auto i = 0U; ; ++i) {
    const auto &test = __x86_test_table_begin[i];
    if (&test >= &(__x86_test_table_end[0])) break;
    CreateTest(test);
  }

  return 0;
}
