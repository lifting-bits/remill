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

#if 32 == ADDRESS_SIZE_BITS
template <typename S1, typename S2>
DEF_SEM(BOUND, R8W cond, S1 src1, S2 src2, R32W) {
  auto index = Read(src1);
  auto lower_bound = Read(src2);
  auto upper_bound = Read(GetElementPtr(src2, Literal<S2>(1)));
  HYPER_CALL = AsyncHyperCall::kX86Bound;
  INTERRUPT_VECTOR = 5;
  Write(cond, BOr(UCmpLt(index, lower_bound), UCmpLt(upper_bound, index)));
  return memory;
}
#endif

DEF_SEM(DoINT_IMMb, I8 num, IF_32BIT_ELSE(R32W, R64W)) {
  INTERRUPT_VECTOR = Read(num);
  HYPER_CALL = AsyncHyperCall::kX86IntN;
  return memory;
}

DEF_SEM(DoINT1, IF_32BIT_ELSE(R32W, R64W)) {
  INTERRUPT_VECTOR = 1;
  HYPER_CALL = AsyncHyperCall::kX86Int1;
  return memory;
}

DEF_SEM(DoINT3, IF_32BIT_ELSE(R32W, R64W)) {
  INTERRUPT_VECTOR = 3;
  HYPER_CALL = AsyncHyperCall::kX86Int3;
  return memory;
}

#if 32 == ADDRESS_SIZE_BITS
DEF_SEM(DoINTO, R8W cond, R32W) {
  Write(cond, FLAG_OF);
  INTERRUPT_VECTOR = 4;
  HYPER_CALL = AsyncHyperCall::kX86IntO;
  return memory;
}

#endif  // 32 == ADDRESS_SIZE_BITS
}  // namespace

DEF_ISEL(INT_IMMb) = DoINT_IMMb;
DEF_ISEL(INT1) = DoINT1;
DEF_ISEL(INT3) = DoINT3;

#if 32 == ADDRESS_SIZE_BITS
DEF_ISEL(INTO) = DoINTO;
DEF_ISEL(BOUND_GPRv_MEMa16_16) = BOUND<R16, M16>;
DEF_ISEL(BOUND_GPRv_MEMa32_32) = BOUND<R32, M32>;
#endif  // 32 == ADDRESS_SIZE_BITS
