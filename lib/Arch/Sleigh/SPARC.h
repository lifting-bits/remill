/*
 * Copyright (c) 2026 Trail of Bits, Inc.
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

#include <remill/Arch/Instruction.h>

#include <cstdint>
#include <variant>

namespace remill::sparc {

// A function that returns a structure returns past the `unimp <size>` that
// follows the delay slot of its call: `jmpl %o7 + 12, %g0` (`jmp %o7 + 12`)
// in a leaf function, `jmpl %i7 + 12, %g0` otherwise. Ghidra treats these
// as indirect jumps, and only `+ 8` as returns; categorize them as returns
// too, as the hand-written SPARC decoder did.
inline void CategorizeStructReturn(Instruction &inst) {
  if (inst.bytes.size() < 4u ||
      !std::holds_alternative<Instruction::IndirectJump>(inst.flows)) {
    return;
  }

  const auto bits = (static_cast<uint32_t>(uint8_t(inst.bytes[0])) << 24u) |
                    (static_cast<uint32_t>(uint8_t(inst.bytes[1])) << 16u) |
                    (static_cast<uint32_t>(uint8_t(inst.bytes[2])) << 8u) |
                    static_cast<uint32_t>(uint8_t(inst.bytes[3]));
  const auto op = bits >> 30u;
  const auto rd = (bits >> 25u) & 0x1fu;
  const auto op3 = (bits >> 19u) & 0x3fu;
  const auto rs1 = (bits >> 14u) & 0x1fu;
  const auto i = (bits >> 13u) & 1u;
  const auto simm13 = bits & 0x1fffu;

  constexpr auto kOpArith = 2u;
  constexpr auto kOp3Jmpl = 0x38u;
  constexpr auto kRegO7 = 15u;
  constexpr auto kRegI7 = 31u;
  if (op == kOpArith && op3 == kOp3Jmpl && rd == 0u && i == 1u &&
      simm13 == 12u && (rs1 == kRegO7 || rs1 == kRegI7)) {
    inst.flows = Instruction::FunctionReturn(
        std::get<Instruction::IndirectJump>(inst.flows).taken_flow);
    inst.category = Instruction::kCategoryFunctionReturn;
  }
}

}  // namespace remill::sparc
