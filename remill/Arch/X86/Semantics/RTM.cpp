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

// Note: The taken branch is the transaction failed fallback path.
DEF_SEM(XBEGIN, R8W cond, PC taken, PC not_taken,
        IF_32BIT_ELSE(R32W, R64W) pc_dst) {
  Write(cond, true);
  Write(pc_dst, Read(taken));
  WriteZExt(REG_XAX, static_cast<addr_t>(8));
  return memory;
}

DEF_SEM(DoXTEST) {
  Write(FLAG_ZF, true);
  return memory;
}

DEF_SEM(DoXEND, PC next_pc) {
  WriteZExt(REG_PC, Read(next_pc));
  StopFailure();
}

DEF_SEM(XABORT, I8) {
  return memory;  // We treat RTM as inactive, so this is a NOP.
}

}  // namespace

DEF_ISEL(XBEGIN_RELBRz_16) = XBEGIN;
DEF_ISEL(XBEGIN_RELBRz_32) = XBEGIN;
DEF_ISEL(XEND) = DoXEND;
DEF_ISEL(XTEST) = DoXTEST;
DEF_ISEL(XABORT_IMMb) = XABORT;

/*
522 XEND XEND COND_BR RTM RTM ATTRIBUTES:
 */
