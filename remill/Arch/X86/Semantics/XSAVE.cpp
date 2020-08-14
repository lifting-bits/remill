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

namespace {

DEF_SEM(DoXGETBV, PC next_pc) {
  switch (Read(REG_ECX)) {

    // Current state of the `xcr0` register.
    case 0:
      WriteZExt(IF_64BIT_ELSE(REG_RAX, REG_EAX), state.xcr0.eax);
      WriteZExt(IF_64BIT_ELSE(REG_RDX, REG_EDX), state.xcr0.edx);
      break;

    // Current state of the `xcr0` register, anded with the `xinuse` register.
    // We fake this as saying: this is what
    case 1: {
      XCR0 xcr0 = {};
      xcr0.x87_fpu_mmx = 1;
      xcr0.xmm = 1;
      IF_AVX(xcr0.ymm = 1;)
      IF_AVX512(xcr0.opmask = 1;)
      IF_AVX512(xcr0.zmm_hi256 = 1;)
      IF_AVX512(xcr0.hi16_zmm = 1;)
      break;
    }

    default: WriteZExt(REG_PC, Read(next_pc)); StopFailure();
  }
  return memory;
}

}  // namespace

DEF_ISEL(XGETBV) = DoXGETBV;
