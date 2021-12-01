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
template <typename D, typename S1>
DEF_SEM(CMOVNLE, D dst, S1 src1) {
  WriteZExt(
      dst,
      Select(__remill_compare_sgt(BAnd(BNot(FLAG_ZF), BXnor(FLAG_SF, FLAG_OF))),
             Read(src1), TruncTo<S1>(Read(dst))));
  return memory;
}

template <typename D, typename S1>
DEF_SEM(CMOVNS, D dst, S1 src1) {
  WriteZExt(dst, Select(BNot(FLAG_SF), Read(src1), TruncTo<S1>(Read(dst))));
  return memory;
}

template <typename D, typename S1>
DEF_SEM(CMOVL, D dst, S1 src1) {
  WriteZExt(dst, Select(__remill_compare_slt(BXor(FLAG_SF, FLAG_OF)),
                        Read(src1), TruncTo<S1>(Read(dst))));
  return memory;
}

template <typename D, typename S1>
DEF_SEM(CMOVNP, D dst, S1 src1) {
  WriteZExt(dst, Select(BNot(FLAG_PF), Read(src1), TruncTo<S1>(Read(dst))));
  return memory;
}

template <typename D, typename S1>
DEF_SEM(CMOVNZ, D dst, S1 src1) {
  WriteZExt(dst, Select(__remill_compare_neq(BNot(FLAG_ZF)), Read(src1),
                        TruncTo<S1>(Read(dst))));
  return memory;
}

template <typename D, typename S1>
DEF_SEM(CMOVNB, D dst, S1 src1) {
  WriteZExt(dst, Select(__remill_compare_uge(BNot(FLAG_CF)), Read(src1),
                        TruncTo<S1>(Read(dst))));
  return memory;
}

template <typename D, typename S1>
DEF_SEM(CMOVNO, D dst, S1 src1) {
  WriteZExt(dst, Select(BNot(FLAG_OF), Read(src1), TruncTo<S1>(Read(dst))));
  return memory;
}


template <typename D, typename S1>
DEF_SEM(CMOVNL, D dst, S1 src1) {
  WriteZExt(dst, Select(__remill_compare_sge(BXnor(FLAG_SF, FLAG_OF)),
                        Read(src1), TruncTo<S1>(Read(dst))));
  return memory;
}

template <typename D, typename S1>
DEF_SEM(CMOVNBE, D dst, S1 src1) {
  WriteZExt(dst, Select(__remill_compare_ugt(BNot(BOr(FLAG_CF, FLAG_ZF))),
                        Read(src1), TruncTo<S1>(Read(dst))));
  return memory;
}

template <typename D, typename S1>
DEF_SEM(CMOVBE, D dst, S1 src1) {
  WriteZExt(dst, Select(__remill_compare_ule(BOr(FLAG_CF, FLAG_ZF)), Read(src1),
                        TruncTo<S1>(Read(dst))));
  return memory;
}

template <typename D, typename S1>
DEF_SEM(CMOVZ, D dst, S1 src1) {
  WriteZExt(dst, Select(__remill_compare_eq(FLAG_ZF), Read(src1),
                        TruncTo<S1>(Read(dst))));
  return memory;
}

template <typename D, typename S1>
DEF_SEM(CMOVP, D dst, S1 src1) {
  WriteZExt(dst, Select(FLAG_PF, Read(src1), TruncTo<S1>(Read(dst))));
  return memory;
}

template <typename D, typename S1>
DEF_SEM(CMOVS, D dst, S1 src1) {
  WriteZExt(dst, Select(FLAG_SF, Read(src1), TruncTo<S1>(Read(dst))));
  return memory;
}

template <typename D, typename S1>
DEF_SEM(CMOVO, D dst, S1 src1) {
  WriteZExt(dst, Select(FLAG_OF, Read(src1), TruncTo<S1>(Read(dst))));
  return memory;
}

template <typename D, typename S1>
DEF_SEM(CMOVB, D dst, S1 src1) {
  WriteZExt(dst, Select(__remill_compare_ult(FLAG_CF), Read(src1),
                        TruncTo<S1>(Read(dst))));
  return memory;
}

template <typename D, typename S1>
DEF_SEM(CMOVLE, D dst, S1 src1) {
  WriteZExt(dst,
            Select(__remill_compare_sle(BOr(FLAG_ZF, BXor(FLAG_SF, FLAG_OF))),
                   Read(src1), TruncTo<S1>(Read(dst))));
  return memory;
}

}  // namespace

DEF_ISEL_RnW_Mn(CMOVBE_GPRv_MEMv, CMOVBE);
DEF_ISEL_RnW_Rn(CMOVBE_GPRv_GPRv, CMOVBE);
DEF_ISEL_RnW_Mn(CMOVLE_GPRv_MEMv, CMOVLE);
DEF_ISEL_RnW_Rn(CMOVLE_GPRv_GPRv, CMOVLE);
DEF_ISEL_RnW_Mn(CMOVNLE_GPRv_MEMv, CMOVNLE);
DEF_ISEL_RnW_Rn(CMOVNLE_GPRv_GPRv, CMOVNLE);
DEF_ISEL_RnW_Mn(CMOVNP_GPRv_MEMv, CMOVNP);
DEF_ISEL_RnW_Rn(CMOVNP_GPRv_GPRv, CMOVNP);
DEF_ISEL_RnW_Mn(CMOVNZ_GPRv_MEMv, CMOVNZ);
DEF_ISEL_RnW_Rn(CMOVNZ_GPRv_GPRv, CMOVNZ);
DEF_ISEL_RnW_Mn(CMOVNS_GPRv_MEMv, CMOVNS);
DEF_ISEL_RnW_Rn(CMOVNS_GPRv_GPRv, CMOVNS);
DEF_ISEL_RnW_Mn(CMOVNO_GPRv_MEMv, CMOVNO);
DEF_ISEL_RnW_Rn(CMOVNO_GPRv_GPRv, CMOVNO);
DEF_ISEL_RnW_Mn(CMOVNL_GPRv_MEMv, CMOVNL);
DEF_ISEL_RnW_Rn(CMOVNL_GPRv_GPRv, CMOVNL);
DEF_ISEL_RnW_Mn(CMOVNB_GPRv_MEMv, CMOVNB);
DEF_ISEL_RnW_Rn(CMOVNB_GPRv_GPRv, CMOVNB);
DEF_ISEL_RnW_Mn(CMOVO_GPRv_MEMv, CMOVO);
DEF_ISEL_RnW_Rn(CMOVO_GPRv_GPRv, CMOVO);
DEF_ISEL_RnW_Mn(CMOVZ_GPRv_MEMv, CMOVZ);
DEF_ISEL_RnW_Rn(CMOVZ_GPRv_GPRv, CMOVZ);
DEF_ISEL_RnW_Mn(CMOVP_GPRv_MEMv, CMOVP);
DEF_ISEL_RnW_Rn(CMOVP_GPRv_GPRv, CMOVP);
DEF_ISEL_RnW_Mn(CMOVS_GPRv_MEMv, CMOVS);
DEF_ISEL_RnW_Rn(CMOVS_GPRv_GPRv, CMOVS);
DEF_ISEL_RnW_Mn(CMOVL_GPRv_MEMv, CMOVL);
DEF_ISEL_RnW_Rn(CMOVL_GPRv_GPRv, CMOVL);
DEF_ISEL_RnW_Mn(CMOVB_GPRv_MEMv, CMOVB);
DEF_ISEL_RnW_Rn(CMOVB_GPRv_GPRv, CMOVB);
DEF_ISEL_RnW_Mn(CMOVNBE_GPRv_MEMv, CMOVNBE);
DEF_ISEL_RnW_Rn(CMOVNBE_GPRv_GPRv, CMOVNBE);
