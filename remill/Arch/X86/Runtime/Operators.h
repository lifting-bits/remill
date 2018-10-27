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
bcd80_t _ReadBCD80(Memory *memory, Mn<bcd80_t> op) {
  bcd80_t bcd = {};
  const auto num_digit_pairs = sizeof(bcd.digit_pairs);

  _Pragma("unroll")
  for (addr_t i = 0; i < num_digit_pairs; i++) {
    bcd.digit_pairs[i].u8 = __remill_read_memory_8(memory, op.addr + i);
  }
  auto msb = __remill_read_memory_8(memory, op.addr + num_digit_pairs);
  bcd.is_negative = msb >> 7;

  return bcd;
}

#define ReadBCD80(op) _ReadBCD80(memory, op)

ALWAYS_INLINE static
Memory *_WriteBCD80(Memory *memory, MBCD80W dst, bcd80_t src) {
  const auto num_digit_pairs = sizeof(src.digit_pairs);

  _Pragma("unroll")
  for (addr_t i = 0; i < num_digit_pairs; i++) {
    memory = __remill_write_memory_8(memory, dst.addr + i, src.digit_pairs[i].u8);
  }

  uint8_t msb = static_cast<uint8_t>(src.is_negative << 7);
  memory = __remill_write_memory_8(memory, dst.addr + num_digit_pairs, msb);

  return memory;
}

#define WriteBCD80(op, val) _WriteBCD80(memory, op, val)

ALWAYS_INLINE static
Memory *_WriteBCD80Indefinite(Memory *memory, MBCD80W dst) {
  const uint8_t indefinite[sizeof(bcd80_t)] = {
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xc0, 0xff, 0xff,
  };

  _Pragma("unroll")
  for (addr_t i = 0; i < sizeof(indefinite); i++) {
    memory = __remill_write_memory_8(memory, dst.addr + i, indefinite[i]);
  }

  return memory;
}

#define WriteBCD80Indefinite(op) _WriteBCD80Indefinite(memory, op)

}  // namespace
