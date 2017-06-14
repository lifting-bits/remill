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

#ifndef REMILL_ARCH_AARCH64_RUNTIME_OPERATORS_H_
#define REMILL_ARCH_AARCH64_RUNTIME_OPERATORS_H_

namespace {

// Read a register directly. Sometimes this is needed for suppressed operands.
ALWAYS_INLINE static IF_64BIT_ELSE(uint64_t, uint32_t)
    _Read(Memory *, Reg reg) {
  return reg.IF_64BIT_ELSE(qword, dword);
}

// Write directly to a register. This is sometimes needed for suppressed
// register operands.
ALWAYS_INLINE static void _Write(Memory *, Reg &reg,
                                 IF_64BIT_ELSE(uint64_t, uint32_t) val) {
  reg.aword = val;
}

}  // namespace

#endif  // REMILL_ARCH_AARCH64_RUNTIME_OPERATORS_H_
