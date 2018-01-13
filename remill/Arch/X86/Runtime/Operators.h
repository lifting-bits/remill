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

#ifndef REMILL_ARCH_X86_RUNTIME_OPERATORS_H_
#define REMILL_ARCH_X86_RUNTIME_OPERATORS_H_

namespace {

// Read a register directly. Sometimes this is needed for suppressed operands.
ALWAYS_INLINE static
IF_64BIT_ELSE(uint64_t, uint32_t) _Read(Memory *, Reg reg) {
  return reg.IF_64BIT_ELSE(qword, dword);
}

// Write directly to a register. This is sometimes needed for suppressed
// register operands.
ALWAYS_INLINE static
void _Write(Memory *, Reg &reg, IF_64BIT_ELSE(uint64_t, uint32_t) val) {
  reg.IF_64BIT_ELSE(qword, dword) = val;
}

ALWAYS_INLINE static
dec80_t _ReadDec80(Memory *memory, Mn<dec80_t> op) {
  dec80_t dec = {};
  const auto num_digit_pairs = sizeof(dec.digits);

  _Pragma("unroll")
  for (addr_t i = 0; i < num_digit_pairs; i++) {
    dec.digits[i] = __remill_read_memory_8(memory, op.addr + i);
  }
  auto msb = __remill_read_memory_8(memory, op.addr + num_digit_pairs);
  dec.is_negative = msb >> 7;

  return dec;
}

#define ReadDec80(op) _ReadDec80(memory, op)

}  // namespace

#endif  // REMILL_ARCH_X86_RUNTIME_OPERATORS_H_
