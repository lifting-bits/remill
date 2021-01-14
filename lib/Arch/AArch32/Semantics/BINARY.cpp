/*
 * Copyright (c) 2020 Trail of Bits, Inc.
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

template <typename T>
T AddWithCarryNZCV(State &state, T lhs, T rhs, T carry) {
  auto unsigned_result = UAdd(UAdd(ZExt(lhs), ZExt(rhs)), ZExt(carry));
  auto signed_result = SAdd(SAdd(SExt(lhs), SExt(rhs)), Signed(ZExt(carry)));
  auto result = TruncTo<T>(unsigned_result);
  state.sr.n = SignFlag(result);
  state.sr.z = ZeroFlag(result);
  state.sr.c = UCmpNeq(ZExt(result), unsigned_result);
  state.sr.v = SCmpNeq(SExt(result), signed_result);
  return result;
}

DEF_COND_SEM(AND, R32W dst, R32 src1, I32 src2) {
  auto value = Read(src2);
  Write(dst, UAnd(Read(src1), value));
  return memory;
}

DEF_COND_SEM(ANDS, R32W dst, R32 src1, I32 src2, I8 carry_out) {
  auto value = Read(src2);
  auto res = UAnd(Read(src1), value);
  WriteZExt(dst, res);
  state.sr.n = SignFlag(res);
  state.sr.z = ZeroFlag(res);
  state.sr.c = Read(carry_out);
  // PSTATE.V unchanged
  return memory;
}

DEF_COND_SEM(EOR, R32W dst, R32 src1, I32 src2) {
  auto value = Read(src2);
  Write(dst, UXor(Read(src1), value));
  return memory;
}

DEF_COND_SEM(EORS, R32W dst, R32 src1, I32 src2, I8 carry_out) {
  auto value = Read(src2);
  auto res = UXor(Read(src1), value);
  Write(dst, res);
  state.sr.n = SignFlag(res);
  state.sr.z = ZeroFlag(res);
  state.sr.c = Read(carry_out);
  // PSTATE.V unchanged
  return memory;
}

DEF_COND_SEM(RSB, R32W dst, R32 src1, I32 src2) {
  auto value = Read(src2);
  Write(dst, USub(value, Read(src1)));
  return memory;
}

DEF_COND_SEM(RSBS, R32W dst, R32 src1, I32 src2, I8 carry_out) {
  auto rhs = Read(src2);
  auto lhs = Read(src1);
  auto res = AddWithCarryNZCV(state, UNot(lhs), rhs, uint32_t(1));
  Write(dst, res);
  return memory;
}

DEF_COND_SEM(SUB, R32W dst, R32 src1, I32 src2) {
  auto value = Read(src2);
  Write(dst, USub(Read(src1), value));
  return memory;
}

DEF_COND_SEM(SUBS, R32W dst, R32 src1, I32 src2, I8 carry_out) {
  auto rhs = Read(src2);
  auto lhs = Read(src1);
  auto res = AddWithCarryNZCV(state, lhs, UNot(rhs), uint32_t(1));
  Write(dst, res);
  return memory;
}

DEF_COND_SEM(ADD, R32W dst, R32 src1, I32 src2) {
  auto value = Read(src2);
  Write(dst, UAdd(Read(src1), value));
  return memory;
}

DEF_COND_SEM(ADDS, R32W dst, R32 src1, I32 src2, I8 carry_out) {
  auto rhs = Read(src2);
  auto lhs = Read(src1);
  auto res = AddWithCarryNZCV(state, lhs, rhs, uint32_t(0));
  Write(dst, res);
  return memory;
}

DEF_COND_SEM(ADC, R32W dst, R32 src1, I32 src2) {
  auto value = Read(src2);
  Write(dst, UAdd(UAdd(Read(src1),value), uint32_t(state.sr.c)));
  return memory;
}

DEF_COND_SEM(ADCS, R32W dst, R32 src1, I32 src2, I8 carry_out) {
  auto rhs = Read(src2);
  auto lhs = Read(src1);
  auto res = AddWithCarryNZCV(state, lhs, rhs, uint32_t(state.sr.c));
  Write(dst, res);
  return memory;
}

DEF_COND_SEM(SBC, R32W dst, R32 src1, I32 src2) {
  auto value = Read(src2);
  Write(dst, UAdd(UAdd(Read(src1), UNot(value)), uint32_t(state.sr.c)));
  return memory;
}

DEF_COND_SEM(SBCS, R32W dst, R32 src1, I32 src2, I8 carry_out) {
  auto rhs = Read(src2);
  auto lhs = Read(src1);
  auto res = AddWithCarryNZCV(state, lhs, UNot(rhs), uint32_t(state.sr.c));
  Write(dst, res);
  return memory;
}

DEF_COND_SEM(RSC, R32W dst, R32 src1, I32 src2) {
  auto value = Read(src2);
  Write(dst, UAdd(UAdd(value, UNot(Read(src1))), uint32_t(state.sr.c)));
  return memory;
}

DEF_COND_SEM(RSCS, R32W dst, R32 src1, I32 src2, I8 carry_out) {
  auto rhs = Read(src2);
  auto lhs = Read(src1);
  auto res = AddWithCarryNZCV(state, UNot(lhs), rhs, uint32_t(state.sr.c));
  Write(dst, res);
  return memory;
}
}  // namespace

DEF_ISEL(ANDrr) = AND;
DEF_ISEL(ANDSrr) = ANDS;
DEF_ISEL(EORrr) = EOR;
DEF_ISEL(EORSrr) = EORS;
DEF_ISEL(ADDrr) = ADD;
DEF_ISEL(ADDSrr) = ADDS;
DEF_ISEL(ADCrr) = ADC;
DEF_ISEL(ADCSrr) = ADCS;
DEF_ISEL(RSBrr) = RSB;
DEF_ISEL(RSBSrr) = RSBS;
DEF_ISEL(SUBrr) = SUB;
DEF_ISEL(SUBSrr) = SUBS;
DEF_ISEL(SBCrr) = SBC;
DEF_ISEL(SBCSrr) = SBCS;
DEF_ISEL(RSCrr) = RSC;
DEF_ISEL(RSCSrr) = RSCS;

// Multiply and Accumulate
namespace {
DEF_COND_SEM(MUL, R32W dst, R32 src1, R32 src2, R32 src3) {
  auto rhs = Signed(Read(src2));
  auto lhs = Signed(Read(src1));
  auto acc = Signed(Read(src3));
  auto res = Unsigned(SAdd(SMul(lhs, rhs), acc));
  Write(dst, res);
  return memory;
}

DEF_COND_SEM(MULS, R32W dst, R32 src1, R32 src2, R32 src3) {
  auto rhs = Signed(Read(src2));
  auto lhs = Signed(Read(src1));
  auto acc = Signed(Read(src3));
  auto res = Unsigned(SAdd(SMul(lhs, rhs), acc));
  state.sr.n = SignFlag(res);
  state.sr.z = ZeroFlag(res);
  // PSTATE.C, PSTATE.V unchanged
  Write(dst, res);
  return memory;
}

DEF_COND_SEM(UMAAL, R32W dst_hi, R32W dst_lo, R32 src1, R32 src2, R32 src3, R32 src4) {
  auto rhs = ZExt(Read(src3));
  auto lhs = ZExt(Read(src2));
  auto acc_hi = ZExt(Read(src1));
  auto acc_lo = ZExt(Read(src4));
  auto res = UAdd(UAdd(UMul(lhs, rhs), acc_hi), acc_lo);
  Write(dst_lo, TruncTo<uint32_t>(res));
  Write(dst_hi, TruncTo<uint32_t>(UShr(res, 32ul)));
  return memory;
}

DEF_COND_SEM(MLS, R32W dst, R32 src1, R32 src2, R32 src3) {
  auto rhs = Signed(Read(src2));
  auto lhs = Signed(Read(src1));
  auto acc = Signed(Read(src3));
  auto res = Unsigned(SSub(acc, SMul(lhs, rhs)));
  Write(dst, res);
  return memory;
}

DEF_COND_SEM(UMULL, R32W dst_hi, R32W dst_lo, R32 src1, R32 src2, R32 src3, R32 src4) {
  auto rhs = ZExt(Read(src3));
  auto lhs = ZExt(Read(src2));
  auto acc = UOr(UShl(ZExt(Read(src1)), 32ul), ZExt(Read(src4))); // UInt(R[dHi]:R[dLo])
  auto res = UAdd(UMul(lhs, rhs), acc);
  Write(dst_hi, TruncTo<uint32_t>(UShr(res, 32ul)));
  Write(dst_lo, TruncTo<uint32_t>(res));
  return memory;
}

DEF_COND_SEM(UMULLS, R32W dst_hi, R32W dst_lo, R32 src1, R32 src2, R32 src3, R32 src4) {
  auto rhs = ZExt(Read(src3));
  auto lhs = ZExt(Read(src2));
  auto acc = UOr(UShl(ZExt(Read(src1)), 32ul), ZExt(Read(src4))); // UInt(R[dHi]:R[dLo])
  auto res = UAdd(UMul(lhs, rhs), acc);
  state.sr.n = SignFlag(res);
  state.sr.z = ZeroFlag(res);
  // PSTATE.C, PSTATE.V unchanged
  Write(dst_hi, TruncTo<uint32_t>(UShr(res, 32ul)));
  Write(dst_lo, TruncTo<uint32_t>(res));
  return memory;
}

DEF_COND_SEM(SMULL, R32W dst_hi, R32W dst_lo, R32 src1, R32 src2, R32 src3, R32 src4) {
  auto rhs = SExt(Signed(Read(src3)));
  auto lhs = SExt(Signed(Read(src2)));
  auto acc = SOr(SShl(SExt(Read(src1)), 32ul), Signed(ZExt(Read(src4)))); // UInt(R[dHi]:R[dLo])
  auto res = SAdd(SMul(lhs, rhs), acc);
  Write(dst_hi, TruncTo<uint32_t>(SShr(res, 32ul)));
  Write(dst_lo, TruncTo<uint32_t>(res));
  return memory;
}

DEF_COND_SEM(SMULLS, R32W dst_hi, R32W dst_lo, R32 src1, R32 src2, R32 src3, R32 src4) {
  auto rhs = SExt(Signed(Read(src3)));
  auto lhs = SExt(Signed(Read(src2)));
  auto acc = SOr(SShl(SExt(Read(src1)), 32ul), Signed(ZExt(Read(src4)))); // UInt(R[dHi]:R[dLo])
  auto res = SAdd(SMul(lhs, rhs), acc);
  state.sr.n = SignFlag(res);
  state.sr.z = ZeroFlag(res);
  // PSTATE.C, PSTATE.V unchanged
  Write(dst_hi, TruncTo<uint32_t>(SShr(res, 32ul)));
  Write(dst_lo, TruncTo<uint32_t>(res));
  return memory;
}
} // namespace

DEF_ISEL(MUL) = MUL;
DEF_ISEL(MULS) = MULS;
DEF_ISEL(MLA) = MUL;
DEF_ISEL(MLAS) = MULS;
DEF_ISEL(MLS) = MLS;
DEF_ISEL(UMAAL) = UMAAL;
DEF_ISEL(UMULL) = UMULL;
DEF_ISEL(UMULLS) = UMULLS;
DEF_ISEL(UMLAL) = UMULL;
DEF_ISEL(UMLALS) = UMULLS;
DEF_ISEL(SMULL) = SMULL;
DEF_ISEL(SMULLS) = SMULLS;
DEF_ISEL(SMLAL) = SMULL;
DEF_ISEL(SMLALS) = SMULLS;

// Halfword Multiply and Accumulate
namespace {
DEF_COND_SEM(SMLAh, R32W dst, R32 src1, R32 src2, R32 src3) {
  auto rhs = SExt<uint64_t>(Read(src2));
  auto lhs = SExt<uint64_t>(Read(src1));
  auto acc = SExt<uint64_t>(Read(src3));
  auto res = SAdd(SMul(lhs, rhs), acc);
  auto trun_res = TruncTo<uint32_t>(res);
  Write(dst, trun_res);

  //  if result != SInt(result<31:0>) then  // Signed overflow
  //          PSTATE.Q = '1';
  state.sr.q = Select(SCmpNeq(res, SExt<uint64_t>(trun_res)),
                      uint8_t(1), state.sr.q);
  return memory;
}

DEF_COND_SEM(SMULWh, R32W dst, R32 src1, R32 src2) {
  auto rhs = SExt<uint64_t>(Read(src2));
  auto lhs = SExt<uint64_t>(Read(src1));
  auto res = SShr(SMul(lhs, rhs), 16ul); // R[d] = result<47:16>
  auto trun_res = TruncTo<uint32_t>(res);
  Write(dst, trun_res);
  return memory;
}

DEF_COND_SEM(SMLAWh, R32W dst, R32 src1, R32 src2, R32 src3) {
  auto rhs = SExt<uint64_t>(Read(src2));
  auto lhs = SExt<uint64_t>(Read(src1));
  auto acc = SShl(SExt<uint64_t>(Read(src3)), 16ul); // SInt(R[a]) << 16
  auto res = SShr(SAdd(SMul(lhs, rhs), acc), 16ul); // R[d] = result<47:16>
  auto trun_res = TruncTo<uint32_t>(res);
  Write(dst, trun_res);

  //  if (result >> 16) != SInt(R[d]) then  // Signed overflow
  //          PSTATE.Q = '1';
  state.sr.q = Select(SCmpNeq(res, SExt<uint64_t>(trun_res)),
                      uint8_t(1), state.sr.q);
  return memory;
}

DEF_COND_SEM(SMULh, R32W dst, R32 src1, R32 src2) {
  auto rhs = Signed(Read(src2));
  auto lhs = Signed(Read(src1));
  auto res = SMul(lhs, rhs);
  Write(dst, TruncTo<uint32_t>(res));
  return memory;
  // Signed overflow cannot occur
}

DEF_COND_SEM(SMLALh, R32W dst_hi, R32W dst_lo, R32 src1, R32 src2, R32 src3, R32 src4) {
  auto rhs = SExt<uint64_t>(Read(src3));
  auto lhs = SExt<uint64_t>(Read(src2));
  auto acc = SOr(SShl(SExt<int64_t>(Signed(Read(src1))), 32ul), Signed(ZExt<uint64_t>(Read(src4)))); // UInt(R[dHi]:R[dLo])
  auto res = SAdd(SMul(lhs, rhs), acc);
  Write(dst_hi, TruncTo<uint32_t>(SShr(res, 32ul)));
  Write(dst_lo, TruncTo<uint32_t>(res));
  return memory;
}

}// namespace

DEF_ISEL(SMLABB) = SMLAh;
DEF_ISEL(SMLABT) = SMLAh;
DEF_ISEL(SMLATB) = SMLAh;
DEF_ISEL(SMLATT) = SMLAh;
DEF_ISEL(SMLAWB) = SMLAWh;
DEF_ISEL(SMULWB) = SMULWh;
DEF_ISEL(SMLAWT) = SMLAWh;
DEF_ISEL(SMULWT) = SMULWh;
DEF_ISEL(SMULBB) = SMULh;
DEF_ISEL(SMULBT) = SMULh;
DEF_ISEL(SMULTB) = SMULh;
DEF_ISEL(SMULTT) = SMULh;
DEF_ISEL(SMLALBB) = SMLALh;
DEF_ISEL(SMLALBT) = SMLALh;
DEF_ISEL(SMLALTB) = SMLALh;
DEF_ISEL(SMLALTT) = SMLALh;

// Integer Saturating Arithmetic
namespace {
template <typename T>
T SignedSatQ(State &state, T res, int32_t nbits) {
  nbits--;
  auto upper_bound = T((1 << nbits) - 1);
  auto lower_bound = T(-(1 << nbits));
  state.sr.q = Select(SOr(SCmpGt(res, upper_bound), SCmpLt(res, lower_bound)),
                      uint8_t(1u), state.sr.q);
  res = Select(SCmpGt(res, upper_bound), upper_bound, res);
  res = Select(SCmpLt(res, lower_bound), lower_bound, res);
  return res;
}

DEF_COND_SEM(QADD, R32W dst, R32 src1, R32 src2) {
  auto rhs = SExt<int64_t>(Signed(Read(src2)));
  auto lhs = SExt<int64_t>(Signed(Read(src1)));
  auto res = SAdd(lhs, rhs);
  res = SignedSatQ(state, res, 32u);
  Write(dst, TruncTo<uint32_t>(res));
  return memory;
}

DEF_COND_SEM(QDADD, R32W dst, R32 src1, R32 src2) {
  auto rhs = SExt<int64_t>(Signed(Read(src2)));
  auto lhs = SExt<int64_t>(Signed(Read(src1)));
  rhs = SignedSatQ(state, SShl(rhs, 1u), 32u);
  auto res = SAdd(lhs, rhs);
  res = SignedSatQ(state, res, 32u);
  Write(dst, TruncTo<uint32_t>(res));
  return memory;
}

DEF_COND_SEM(QSUB, R32W dst, R32 src1, R32 src2) {
  auto rhs = SExt<int64_t>(Signed(Read(src2)));
  auto lhs = SExt<int64_t>(Signed(Read(src1)));
  auto res = SSub(lhs, rhs);
  res = SignedSatQ(state, res, 32u);
  Write(dst, TruncTo<uint32_t>(res));
  return memory;
}

DEF_COND_SEM(QDSUB, R32W dst, R32 src1, R32 src2) {
  auto rhs = SExt<int64_t>(Signed(Read(src2)));
  auto lhs = SExt<int64_t>(Signed(Read(src1)));
  rhs = SignedSatQ(state, SShl(rhs, 1u), 32u);
  auto res = SSub(lhs, rhs);
  res = SignedSatQ(state, res, 32u);
  Write(dst, TruncTo<uint32_t>(res));
  return memory;
}
} // namespace

DEF_ISEL(QADD) = QADD;
DEF_ISEL(QDADD) = QDADD;
DEF_ISEL(QSUB) = QSUB;
DEF_ISEL(QDSUB) = QDSUB;

// Signed multiply, Divide
namespace {
DEF_COND_SEM(SMLAD, R32W dst, R32 src1, R32 src2, R32 src3) { // rn rm ra
  auto rn = Read(src1);
  auto rm = Read(src2);
  auto ra = Signed(Read(src3));
  auto prod1 = SMul(SExt<int64_t>(Trunc(rn)),
                    SExt<int64_t>(Trunc(rm)));
  auto prod2 = SMul(SExt<int64_t>(SShr(Signed(rn), 16u)),
                    SExt<int64_t>(SShr(Signed(rm), 16u)));
  auto res = SAdd(SAdd(prod1, prod2), SExt<int64_t>(ra));
  WriteTrunc(dst, Unsigned(res));

  //  if result != SInt(result<31:0>) then  // Signed overflow
  //      PSTATE.Q = '1';
  state.sr.q = Select(SCmpNeq(res, SExt<int64_t>(Trunc(res))),
                        uint8_t(1), state.sr.q);
  return memory;
}

DEF_COND_SEM(SMLSD, R32W dst, R32 src1, R32 src2, R32 src3) { // rn rm ra
  auto rn = Read(src1);
  auto rm = Read(src2);
  auto ra = Read(src3);
  auto prod1 = SMul(SExt<int64_t>(Signed(Trunc(rn))),
                    SExt<int64_t>(Signed(Trunc(rm))));
  auto prod2 = SMul(SExt<int64_t>(SShr(Signed(rn), 16u)),
                    SExt<int64_t>(SShr(Signed(rm), 16u)));
  auto res = SAdd(SSub(prod1, prod2), SExt<int64_t>(ra));
  WriteTrunc(dst, Unsigned(res));

  //  if result != SInt(result<31:0>) then  // Signed overflow
  //      PSTATE.Q = '1';
  state.sr.q = Select(SCmpNeq(res, SExt<int64_t>(Trunc(res))),
                        uint8_t(1), state.sr.q);
  return memory;
}

DEF_COND_SEM(SDIV, R32W dst, R32 src1, R32 src2, R32 src3) { // rn rm
  auto rn = Signed(Read(src1));
  auto rm = Signed(Read(src2));
  if (!rm) {
    WriteZExt(dst, uint32_t(0));
  } else {
    WriteZExt(dst, Unsigned(SDiv(rn, rm)));
  }
  return memory;
}

DEF_COND_SEM(UDIV, R32W dst, R32 src1, R32 src2, R32 src3) { // rn rm
  auto rn = Read(src1);
  auto rm = Read(src2);
  if (!rm) {
    WriteZExt(dst, uint32_t(0));
  } else {
    WriteZExt(dst, UDiv(rn, rm));
  }
  return memory;
}

DEF_COND_SEM(SMLALD, R32W dst_lo, R32W dst_hi, R32 src1, R32 src2, R32 src3, R32 src4) { // ra - lo rd - hi rn rm ra - lo rd - hi
  auto rn = Read(src1);
  auto rm = Read(src2);
  auto lo = SExt<int64_t>(Signed(Read(src3)));
  auto hi = SExt<int64_t>(Signed(Read(src4)));
  auto prod1 = SMul(SExt<int64_t>(Trunc(rn)),
                    SExt<int64_t>(Trunc(rm)));
  auto prod2 = SMul(SExt<int64_t>(SShr(Signed(rn), 16u)),
                    SExt<int64_t>(SShr(Signed(rm), 16u)));
  auto res = SAdd(SAdd(prod1, prod2), SOr(lo, SShl(hi, 32u)));
  WriteTrunc(dst_lo, Unsigned(res));
  WriteTrunc(dst_hi, Unsigned(SShr(res, 32u)));
  return memory;
}

DEF_COND_SEM(SMLSLD, R32W dst_lo, R32W dst_hi, R32 src1, R32 src2, R32 src3, R32 src4) { // ra - lo rd - hi rn rm ra - lo rd - hi
  auto rn = Read(src1);
  auto rm = Read(src2);
  auto lo = SExt<int64_t>(Signed(Read(src3)));
  auto hi = SExt<int64_t>(Signed(Read(src4)));
  auto prod1 = SMul(SExt<int64_t>(Trunc(rn)),
                    SExt<int64_t>(Trunc(rm)));
  auto prod2 = SMul(SExt<int64_t>(SShr(Signed(rn), 16u)),
                    SExt<int64_t>(SShr(Signed(rm), 16u)));
  auto res = SAdd(SSub(prod1, prod2), SOr(lo, SShl(hi, 32u)));
  WriteTrunc(dst_lo, Unsigned(res));
  WriteTrunc(dst_hi, Unsigned(SShr(res, 32u)));
  return memory;
}

DEF_COND_SEM(SMMLA, R32W dst, R32 src1, R32 src2, R32 src3, I32 src4) {
  auto rhs = SExt(Signed(Read(src2)));
  auto lhs = SExt(Signed(Read(src1)));
  auto acc = SShl(SExt(Signed(Read(src3))), 32u);
  auto round = Signed(ZExt(Read(src4)));
  auto res = SShr(SAdd(SAdd(acc, SMul(lhs, rhs)), round), 32u);
  WriteTrunc(dst, Unsigned(res));
  return memory;
}

DEF_COND_SEM(SMMLS, R32W dst, R32 src1, R32 src2, R32 src3, I32 src4) {
  auto rhs = SExt(Signed(Read(src2)));
  auto lhs = SExt(Signed(Read(src1)));
  auto acc = SShl(SExt(Signed(Read(src3))), 32u);
  auto round = Signed(ZExt(Read(src4)));
  auto res = SShr(SAdd(SSub(acc, SMul(lhs, rhs)), round), 32u);
  WriteTrunc(dst, Unsigned(res));
  return memory;
}
} // namespace

DEF_ISEL(SMLAD) = SMLAD;
DEF_ISEL(SMLADX) = SMLAD;
DEF_ISEL(SMLSD) = SMLSD;
DEF_ISEL(SMLSDX) = SMLSD;
DEF_ISEL(SMUAD) = SMLAD;
DEF_ISEL(SMUADX) = SMLAD;
DEF_ISEL(SMUSD) = SMLSD;
DEF_ISEL(SMUSDX) = SMLSD;
DEF_ISEL(SDIV) = SDIV;
DEF_ISEL(UDIV) = UDIV;
DEF_ISEL(SMLALD) = SMLALD;
DEF_ISEL(SMLALDX) = SMLALD;
DEF_ISEL(SMLSLD) = SMLSLD;
DEF_ISEL(SMLSLDX) = SMLSLD;
DEF_ISEL(SMMLA) = SMMLA;
DEF_ISEL(SMMLAR) = SMMLA;
DEF_ISEL(SMMLS) = SMMLS;
DEF_ISEL(SMMLSR) = SMMLS;
DEF_ISEL(SMMUL) = SMMLA;
DEF_ISEL(SMMULR) = SMMLA;

