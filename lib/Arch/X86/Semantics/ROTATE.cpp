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

template <typename D, typename S1, typename S2>
DEF_SEM(ROL, D dst, S1 src1, S2 src2) {
  auto val = Read(src1);
  auto count = ZExtTo<S1>(Read(src2));
  auto one = Literal<S1>(1);
  auto long_mask = Literal<S1>(0x3F);
  auto short_mask = Literal<S1>(0x1F);
  auto op_size = BitSizeOf(src1);
  auto count_mask = Select(UCmpEq(op_size, 64), long_mask, short_mask);
  auto masked_count = UAnd(count, count_mask);
  auto temp_count = URem(masked_count, op_size);
  if (temp_count) {
    auto new_val =
        UOr(UShl(val, temp_count), UShr(val, USub(op_size, temp_count)));
    WriteZExt(dst, new_val);
    Write(FLAG_CF, UCmpEq(UAnd(new_val, one), one));
    if (1 == temp_count) {
      Write(FLAG_OF, BXor(FLAG_CF, SignFlag(new_val)));
    // OF undefined for `1 != temp_count`.
    } else {
      Write(FLAG_OF, BUndefined());
    }
  } else {
    WriteZExt(dst, val);
  }
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(ROR, D dst, S1 src1, S2 src2) {
  auto val = Read(src1);
  auto count = ZExtTo<S1>(Read(src2));
  auto one = Literal<S1>(1);
  auto long_mask = Literal<S1>(0x3F);
  auto short_mask = Literal<S1>(0x1F);
  auto op_size = BitSizeOf(src1);
  auto count_mask = Select(UCmpEq(op_size, 64), long_mask, short_mask);
  auto masked_count = UAnd(count, count_mask);
  auto temp_count = URem(masked_count, op_size);
  if (temp_count) {
    auto new_val =
        UOr(UShr(val, temp_count), UShl(val, USub(op_size, temp_count)));
    WriteZExt(dst, new_val);
    Write(FLAG_CF, SignFlag(new_val));
    // OF undefined for `1 != temp_count`.
    if (temp_count == 1)
      Write(FLAG_OF, BXor(FLAG_CF, SignFlag(UShl(new_val, one))));
    else
      Write(FLAG_OF, BUndefined());

  } else {
    WriteZExt(dst, val);
  }
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(RORX, D dst, S1 src1, S2 src2) {
  auto val = Read(src1);
  auto count = ZExtTo<S1>(Read(src2));
  auto long_mask = Literal<S1>(0x3F);
  auto short_mask = Literal<S1>(0x1F);
  auto op_size = BitSizeOf(src1);
  auto count_mask = Select(UCmpEq(op_size, 64), long_mask, short_mask);
  auto masked_count = UAnd(count, count_mask);
  auto temp_count = URem(masked_count, op_size);
  auto new_val =
      UOr(UShr(val, temp_count), UShl(val, USub(op_size, temp_count)));
  WriteZExt(dst, new_val);
  return memory;
}

}  // namespace

DEF_ISEL(ROL_MEMb_IMMb) = ROL<M8W, M8, I8>;
DEF_ISEL(ROL_GPR8_IMMb) = ROL<R8W, R8, I8>;
DEF_ISEL_MnW_Mn_In(ROL_MEMv_IMMb, ROL);
DEF_ISEL_RnW_Rn_In(ROL_GPRv_IMMb, ROL);
DEF_ISEL(ROL_MEMb_ONE) = ROL<M8W, M8, I8>;
DEF_ISEL(ROL_GPR8_ONE) = ROL<R8W, R8, I8>;
DEF_ISEL_MnW_Mn_In(ROL_MEMv_ONE, ROL);
DEF_ISEL_RnW_Rn_In(ROL_GPRv_ONE, ROL);
DEF_ISEL(ROL_MEMb_CL) = ROL<M8W, M8, R8>;
DEF_ISEL(ROL_GPR8_CL) = ROL<R8W, R8, R8>;
DEF_ISEL_MnW_Mn_Rn(ROL_MEMv_CL, ROL);
DEF_ISEL_RnW_Rn_Rn(ROL_GPRv_CL, ROL);

DEF_ISEL(ROR_MEMb_IMMb) = ROR<M8W, M8, I8>;
DEF_ISEL(ROR_GPR8_IMMb) = ROR<R8W, R8, I8>;
DEF_ISEL_MnW_Mn_In(ROR_MEMv_IMMb, ROR);
DEF_ISEL_RnW_Rn_In(ROR_GPRv_IMMb, ROR);
DEF_ISEL(ROR_MEMb_ONE) = ROR<M8W, M8, I8>;
DEF_ISEL(ROR_GPR8_ONE) = ROR<R8W, R8, I8>;
DEF_ISEL_MnW_Mn_In(ROR_MEMv_ONE, ROR);
DEF_ISEL_RnW_Rn_In(ROR_GPRv_ONE, ROR);
DEF_ISEL(ROR_MEMb_CL) = ROR<M8W, M8, R8>;
DEF_ISEL(ROR_GPR8_CL) = ROR<R8W, R8, R8>;
DEF_ISEL_MnW_Mn_Rn(ROR_MEMv_CL, ROR);
DEF_ISEL_RnW_Rn_Rn(ROR_GPRv_CL, ROR);

DEF_ISEL(RORX_GPR32d_GPR32d_IMMb) = RORX<R32W, R32, I8>;
DEF_ISEL(RORX_GPR32d_MEMd_IMMb) = RORX<R32W, M32, I8>;
DEF_ISEL(RORX_GPR64q_GPR64q_IMMb) = RORX<R64W, R64, I8>;
DEF_ISEL(RORX_GPR64q_MEMq_IMMb) = RORX<R64W, M64, I8>;

namespace {

template <typename D, typename S1, typename S2>
DEF_SEM(RCL, D dst, S1 src1, S2 src2) {
  auto val = Read(src1);
  auto count = ZExtTo<S1>(Read(src2));
  auto zero = Literal<S1>(0);
  auto one = Literal<S1>(1);
  auto long_mask = Literal<S1>(0x3F);
  auto short_mask = Literal<S1>(0x1F);
  auto op_size = BitSizeOf(src1);
  auto count_mask = Select(UCmpEq(op_size, 64), long_mask, short_mask);
  auto count_mod =
      Select(UCmpLt(op_size, 32), UAdd(op_size, one), UAdd(count_mask, one));

  auto masked_count = UAnd(count, count_mask);
  auto temp_count = URem(masked_count, count_mod);
  auto carry = Select(FLAG_CF, one, zero);

  if (temp_count) {
    auto right = UShr(val, USub(op_size, temp_count));
    auto new_val =
        UOr(UOr(UShl(val, temp_count), UShl(carry, USub(temp_count, one))),
            UShr(right, one));
    WriteZExt(dst, new_val);
    Write(FLAG_CF, SignFlag(UShl(val, USub(temp_count, one))));
    // OF undefined for `1 != temp_count`.
    if (temp_count == 1) {
      Write(FLAG_OF, BXor(FLAG_CF, SignFlag(new_val)));
    } else {
      Write(FLAG_OF, BUndefined());
    }

  } else {
    WriteZExt(dst, val);
  }
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(RCR, D dst, S1 src1, S2 src2) {
  auto val = Read(src1);
  auto count = ZExtTo<S1>(Read(src2));
  auto one = Literal<S1>(1);
  auto zero = Literal<S1>(0);
  auto long_mask = Literal<S1>(0x3F);
  auto short_mask = Literal<S1>(0x1F);
  auto op_size = BitSizeOf(src1);
  auto count_mask = Select(UCmpEq(op_size, 64), long_mask, short_mask);
  auto count_mod =
      Select(UCmpLt(op_size, 32), UAdd(op_size, one), UAdd(count_mask, one));

  auto masked_count = UAnd(count, count_mask);
  auto temp_count = URem(masked_count, count_mod);
  auto carry = Select(FLAG_CF, one, zero);

  if (temp_count) {
    auto left = UShr(val, USub(temp_count, one));
    auto right = UShl(val, USub(op_size, temp_count));
    auto new_val =
        UOr(UOr(UShr(left, one), UShl(carry, USub(op_size, temp_count))),
            UShl(right, one));
    WriteZExt(dst, new_val);
    Write(FLAG_CF, UCmpNeq(UAnd(left, one), zero));
    if (temp_count == 1) {
      Write(FLAG_OF, BXor(SignFlag(UShl(new_val, one)), SignFlag(new_val)));
    } else {
      Write(FLAG_OF, BUndefined());
    }

  // OF undefined for `1 == temp_count`.
  } else {
    WriteZExt(dst, val);
  }
  return memory;
}

}  // namespace

DEF_ISEL(RCL_MEMb_IMMb) = RCL<M8W, M8, I8>;
DEF_ISEL(RCL_GPR8_IMMb) = RCL<R8W, R8, I8>;
DEF_ISEL_MnW_Mn_In(RCL_MEMv_IMMb, RCL);
DEF_ISEL_RnW_Rn_In(RCL_GPRv_IMMb, RCL);
DEF_ISEL(RCL_MEMb_ONE) = RCL<M8W, M8, I8>;
DEF_ISEL(RCL_GPR8_ONE) = RCL<R8W, R8, I8>;
DEF_ISEL_MnW_Mn_In(RCL_MEMv_ONE, RCL);
DEF_ISEL_RnW_Rn_In(RCL_GPRv_ONE, RCL);
DEF_ISEL(RCL_MEMb_CL) = RCL<M8W, M8, R8>;
DEF_ISEL(RCL_GPR8_CL) = RCL<R8W, R8, R8>;
DEF_ISEL_MnW_Mn_Rn(RCL_MEMv_CL, RCL);
DEF_ISEL_RnW_Rn_Rn(RCL_GPRv_CL, RCL);

DEF_ISEL(RCR_MEMb_IMMb) = RCR<M8W, M8, I8>;
DEF_ISEL(RCR_GPR8_IMMb) = RCR<R8W, R8, I8>;
DEF_ISEL_MnW_Mn_In(RCR_MEMv_IMMb, RCR);
DEF_ISEL_RnW_Rn_In(RCR_GPRv_IMMb, RCR);
DEF_ISEL(RCR_MEMb_ONE) = RCR<M8W, M8, I8>;
DEF_ISEL(RCR_GPR8_ONE) = RCR<R8W, R8, I8>;
DEF_ISEL_MnW_Mn_In(RCR_MEMv_ONE, RCR);
DEF_ISEL_RnW_Rn_In(RCR_GPRv_ONE, RCR);
DEF_ISEL(RCR_MEMb_CL) = RCR<M8W, M8, R8>;
DEF_ISEL(RCR_GPR8_CL) = RCR<R8W, R8, R8>;
DEF_ISEL_MnW_Mn_Rn(RCR_MEMv_CL, RCR);
DEF_ISEL_RnW_Rn_Rn(RCR_GPRv_CL, RCR);
