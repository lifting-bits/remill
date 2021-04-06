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

DEF_COND_SEM(AND, R32W dst, R32 src1, I32 src2, R32W maybe_next_pc_dst) {
  auto value = Read(src2);
  Write(dst, UAnd(Read(src1), value));
  Write(maybe_next_pc_dst, Read(REG_PC));
  return memory;
}

DEF_COND_SEM(ANDS, R32W dst, R32 src1, I32 src2, I8 carry_out,
             R32W maybe_next_pc_dst) {
  auto value = Read(src2);
  auto res = UAnd(Read(src1), value);
  WriteZExt(dst, res);
  state.sr.n = SignFlag(res);
  state.sr.z = ZeroFlag(res);
  state.sr.c = Read(carry_out);

  // PSTATE.V unchanged
  Write(maybe_next_pc_dst, Read(REG_PC));
  return memory;
}

DEF_COND_SEM(EOR, R32W dst, R32 src1, I32 src2, R32W maybe_next_pc_dst) {
  auto value = Read(src2);
  Write(dst, UXor(Read(src1), value));
  Write(maybe_next_pc_dst, Read(REG_PC));
  return memory;
}

DEF_COND_SEM(EORS, R32W dst, R32 src1, I32 src2, I8 carry_out,
             R32W maybe_next_pc_dst) {
  auto value = Read(src2);
  auto res = UXor(Read(src1), value);
  Write(dst, res);
  state.sr.n = SignFlag(res);
  state.sr.z = ZeroFlag(res);
  state.sr.c = Read(carry_out);

  // PSTATE.V unchanged
  Write(maybe_next_pc_dst, Read(REG_PC));
  return memory;
}

DEF_COND_SEM(RSB, R32W dst, R32 src1, I32 src2, R32W maybe_next_pc_dst) {
  auto value = Read(src2);
  Write(dst, USub(value, Read(src1)));
  Write(maybe_next_pc_dst, Read(REG_PC));
  return memory;
}

DEF_COND_SEM(RSBS, R32W dst, R32 src1, I32 src2, I8 carry_out,
             R32W maybe_next_pc_dst) {
  auto rhs = Read(src2);
  auto lhs = Read(src1);
  auto res = AddWithCarryNZCV(state, UNot(lhs), rhs, uint32_t(1));
  Write(dst, res);
  Write(maybe_next_pc_dst, Read(REG_PC));
  return memory;
}

DEF_COND_SEM(SUB, R32W dst, R32 src1, I32 src2, R32W maybe_next_pc_dst) {
  auto value = Read(src2);
  Write(dst, USub(Read(src1), value));
  Write(maybe_next_pc_dst, Read(REG_PC));
  return memory;
}

DEF_COND_SEM(SUBS, R32W dst, R32 src1, I32 src2, I8 carry_out,
             R32W maybe_next_pc_dst) {
  auto rhs = Read(src2);
  auto lhs = Read(src1);
  auto res = AddWithCarryNZCV(state, lhs, UNot(rhs), uint32_t(1));
  Write(dst, res);
  Write(maybe_next_pc_dst, Read(REG_PC));
  return memory;
}

DEF_COND_SEM(ADD, R32W dst, R32 src1, I32 src2, R32W maybe_next_pc_dst) {
  auto value = Read(src2);
  Write(dst, UAdd(Read(src1), value));
  Write(maybe_next_pc_dst, Read(REG_PC));
  return memory;
}

DEF_COND_SEM(ADDS, R32W dst, R32 src1, I32 src2, I8 carry_out,
             R32W maybe_next_pc_dst) {
  auto rhs = Read(src2);
  auto lhs = Read(src1);
  auto res = AddWithCarryNZCV(state, lhs, rhs, uint32_t(0));
  Write(dst, res);
  Write(maybe_next_pc_dst, Read(REG_PC));
  return memory;
}

DEF_COND_SEM(ADC, R32W dst, R32 src1, I32 src2, R32W maybe_next_pc_dst) {
  auto value = Read(src2);
  Write(dst, UAdd(UAdd(Read(src1), value), uint32_t(state.sr.c)));
  Write(maybe_next_pc_dst, Read(REG_PC));
  return memory;
}

DEF_COND_SEM(ADCS, R32W dst, R32 src1, I32 src2, I8 carry_out,
             R32W maybe_next_pc_dst) {
  auto rhs = Read(src2);
  auto lhs = Read(src1);
  auto res = AddWithCarryNZCV(state, lhs, rhs, uint32_t(state.sr.c));
  Write(dst, res);
  Write(maybe_next_pc_dst, Read(REG_PC));
  return memory;
}

DEF_COND_SEM(SBC, R32W dst, R32 src1, I32 src2, R32W maybe_next_pc_dst) {
  auto value = Read(src2);
  Write(dst, UAdd(UAdd(Read(src1), UNot(value)), uint32_t(state.sr.c)));
  Write(maybe_next_pc_dst, Read(REG_PC));
  return memory;
}

DEF_COND_SEM(SBCS, R32W dst, R32 src1, I32 src2, I8 carry_out,
             R32W maybe_next_pc_dst) {
  auto rhs = Read(src2);
  auto lhs = Read(src1);
  auto res = AddWithCarryNZCV(state, lhs, UNot(rhs), uint32_t(state.sr.c));
  Write(dst, res);
  Write(maybe_next_pc_dst, Read(REG_PC));
  return memory;
}

DEF_COND_SEM(RSC, R32W dst, R32 src1, I32 src2, R32W maybe_next_pc_dst) {
  auto value = Read(src2);
  Write(dst, UAdd(UAdd(value, UNot(Read(src1))), uint32_t(state.sr.c)));
  Write(maybe_next_pc_dst, Read(REG_PC));
  return memory;
}

DEF_COND_SEM(RSCS, R32W dst, R32 src1, I32 src2, I8 carry_out,
             R32W maybe_next_pc_dst) {
  auto rhs = Read(src2);
  auto lhs = Read(src1);
  auto res = AddWithCarryNZCV(state, UNot(lhs), rhs, uint32_t(state.sr.c));
  Write(dst, res);
  Write(maybe_next_pc_dst, Read(REG_PC));
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

DEF_COND_SEM(UMAAL, R32W dst_hi, R32W dst_lo, R32 src1, R32 src2, R32 src3,
             R32 src4) {
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

DEF_COND_SEM(UMULL, R32W dst_hi, R32W dst_lo, R32 src1, R32 src2, R32 src3,
             R32 src4) {
  auto rhs = ZExt(Read(src3));
  auto lhs = ZExt(Read(src2));
  auto acc = UOr(UShl(ZExt(Read(src1)), 32ul),
                 ZExt(Read(src4)));  // UInt(R[dHi]:R[dLo])
  auto res = UAdd(UMul(lhs, rhs), acc);
  Write(dst_hi, TruncTo<uint32_t>(UShr(res, 32ul)));
  Write(dst_lo, TruncTo<uint32_t>(res));
  return memory;
}

DEF_COND_SEM(UMULLS, R32W dst_hi, R32W dst_lo, R32 src1, R32 src2, R32 src3,
             R32 src4) {
  auto rhs = ZExt(Read(src3));
  auto lhs = ZExt(Read(src2));
  auto acc = UOr(UShl(ZExt(Read(src1)), 32ul),
                 ZExt(Read(src4)));  // UInt(R[dHi]:R[dLo])
  auto res = UAdd(UMul(lhs, rhs), acc);
  state.sr.n = SignFlag(res);
  state.sr.z = ZeroFlag(res);

  // PSTATE.C, PSTATE.V unchanged
  Write(dst_hi, TruncTo<uint32_t>(UShr(res, 32ul)));
  Write(dst_lo, TruncTo<uint32_t>(res));
  return memory;
}

DEF_COND_SEM(SMULL, R32W dst_hi, R32W dst_lo, R32 src1, R32 src2, R32 src3,
             R32 src4) {
  auto rhs = SExt(Signed(Read(src3)));
  auto lhs = SExt(Signed(Read(src2)));
  auto acc = SOr(SShl(SExt(Read(src1)), 32ul),
                 Signed(ZExt(Read(src4))));  // UInt(R[dHi]:R[dLo])
  auto res = SAdd(SMul(lhs, rhs), acc);
  Write(dst_hi, TruncTo<uint32_t>(SShr(res, 32ul)));
  Write(dst_lo, TruncTo<uint32_t>(res));
  return memory;
}

DEF_COND_SEM(SMULLS, R32W dst_hi, R32W dst_lo, R32 src1, R32 src2, R32 src3,
             R32 src4) {
  auto rhs = SExt(Signed(Read(src3)));
  auto lhs = SExt(Signed(Read(src2)));
  auto acc = SOr(SShl(SExt(Read(src1)), 32ul),
                 Signed(ZExt(Read(src4))));  // UInt(R[dHi]:R[dLo])
  auto res = SAdd(SMul(lhs, rhs), acc);
  state.sr.n = SignFlag(res);
  state.sr.z = ZeroFlag(res);

  // PSTATE.C, PSTATE.V unchanged
  Write(dst_hi, TruncTo<uint32_t>(SShr(res, 32ul)));
  Write(dst_lo, TruncTo<uint32_t>(res));
  return memory;
}
}  // namespace

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
  auto rhs = SExt(Signed(Read(src2)));
  auto lhs = SExt(Signed(Read(src1)));
  auto acc = SExt(Signed(Read(src3)));
  auto res = SAdd(SMul(lhs, rhs), acc);
  auto trun_res = TruncTo<uint32_t>(res);
  Write(dst, trun_res);

  //  if result != SInt(result<31:0>) then  // Signed overflow
  //          PSTATE.Q = '1';
  state.sr.q = Select(SCmpNeq(res, SExt(trun_res)), uint8_t(1), state.sr.q);
  return memory;
}

DEF_COND_SEM(SMULWh, R32W dst, R32 src1, R32 src2) {
  auto rhs = SExt(Signed(Read(src2)));
  auto lhs = SExt(Signed(Read(src1)));
  auto res = SShr(SMul(lhs, rhs), 16ul);  // R[d] = result<47:16>
  auto trun_res = TruncTo<uint32_t>(res);
  Write(dst, trun_res);
  return memory;
}

DEF_COND_SEM(SMLAWh, R32W dst, R32 src1, R32 src2, R32 src3) {
  auto rhs = SExt(Signed(Read(src2)));
  auto lhs = SExt(Signed(Read(src1)));
  auto acc = SShl(SExt(Signed(Read(src3))), 16ul);  // SInt(R[a]) << 16
  auto res = SShr(SAdd(SMul(lhs, rhs), acc), 16ul);  // R[d] = result<47:16>
  auto trun_res = TruncTo<uint32_t>(res);
  Write(dst, trun_res);

  //  if (result >> 16) != SInt(R[d]) then  // Signed overflow
  //          PSTATE.Q = '1';
  state.sr.q = Select(SCmpNeq(res, SExt(trun_res)), uint8_t(1), state.sr.q);
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

DEF_COND_SEM(SMLALh, R32W dst_hi, R32W dst_lo, R32 src1, R32 src2, R32 src3,
             R32 src4) {
  auto rhs = SExt(Signed(Read(src3)));
  auto lhs = SExt(Signed(Read(src2)));
  auto acc = SOr(SShl(SExt(Signed(Read(src1))), 32ul),
                 Signed(ZExt(Read(src4))));  // UInt(R[dHi]:R[dLo])
  auto res = SAdd(SMul(lhs, rhs), acc);
  Write(dst_hi, TruncTo<uint32_t>(SShr(res, 32ul)));
  Write(dst_lo, TruncTo<uint32_t>(res));
  return memory;
}

}  // namespace

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

// Saturate 16-bit && Saturate 32-bit
namespace {
template <typename T>
T UnsignedSatQ(State &state, T res, uint32_t nbits) {
  auto upper_bound = T((1 << nbits) - 1);
  auto lower_bound = T(0);
  state.sr.q = Select(BOr(UCmpGt(res, upper_bound), UCmpLt(res, lower_bound)),
                      uint8_t(1u), state.sr.q);
  res = Select(UCmpGt(res, upper_bound), upper_bound, res);
  res = Select(UCmpLt(res, lower_bound), lower_bound, res);
  return res;
}

template <typename T>
T SignedSatQ(State &state, T res, int32_t nbits) {
  nbits--;
  auto upper_bound = T((1 << nbits) - 1);
  auto lower_bound = T(-(1 << nbits));
  state.sr.q = Select(BOr(SCmpGt(res, upper_bound), SCmpLt(res, lower_bound)),
                      uint8_t(1u), state.sr.q);
  res = Select(SCmpGt(res, upper_bound), upper_bound, res);
  res = Select(SCmpLt(res, lower_bound), lower_bound, res);
  return res;
}

DEF_COND_SEM(USAT, R32W dst, I32 imm, R32 src) {
  auto res = UnsignedSatQ(state, Read(src), Read(imm));
  Write(dst, res);
  return memory;
}

DEF_COND_SEM(SSAT, R32W dst, I32 imm, R32 src) {
  auto res = SignedSatQ(state, Signed(Read(src)), Signed(Read(imm)));
  Write(dst, Unsigned(res));
  return memory;
}

DEF_COND_SEM(USAT16, R32W dst, I32 imm1, R32 src1) {
  auto src = Read(src1);
  auto imm = Read(imm1);
  auto high = UnsignedSatQ(state, Trunc(UShr(src, 16u)), imm);
  auto low = UnsignedSatQ(state, Trunc(src), imm);
  auto res = UOr(UShl(ZExt(high), 16u), ZExt(low));
  Write(dst, res);
  return memory;
}

DEF_COND_SEM(SSAT16, R32W dst, I32 imm1, R32 src1) {
  auto src = Signed(Read(src1));
  auto imm = Signed(Read(imm1));
  auto high = SignedSatQ(state, Trunc(SShr(src, 16u)), imm);
  auto low = SignedSatQ(state, Trunc(src), imm);
  auto res = SOr(SShl(SExt(high), 16u), Signed(ZExt(low)));
  Write(dst, Unsigned(res));
  return memory;
}
}  // namespace

DEF_ISEL(USAT) = USAT;
DEF_ISEL(SSAT) = SSAT;
DEF_ISEL(USAT16) = USAT16;
DEF_ISEL(SSAT16) = SSAT16;

// Integer Saturating Arithmetic
namespace {
DEF_COND_SEM(QADD, R32W dst, R32 src1, R32 src2) {
  auto rhs = SExt(Signed(Read(src2)));
  auto lhs = SExt(Signed(Read(src1)));
  auto res = SAdd(lhs, rhs);
  res = SignedSatQ(state, res, 32);
  Write(dst, Trunc(Unsigned(res)));
  return memory;
}

DEF_COND_SEM(QDADD, R32W dst, R32 src1, R32 src2) {
  auto rhs = SExt(Signed(Read(src2)));
  auto lhs = SExt(Signed(Read(src1)));
  rhs = SignedSatQ(state, SShl(rhs, 1u), 32);
  auto res = SAdd(lhs, rhs);
  res = SignedSatQ(state, res, 32);
  Write(dst, Trunc(Unsigned(res)));
  return memory;
}

DEF_COND_SEM(QSUB, R32W dst, R32 src1, R32 src2) {
  auto rhs = SExt(Signed(Read(src2)));
  auto lhs = SExt(Signed(Read(src1)));
  auto res = SSub(lhs, rhs);
  res = SignedSatQ(state, res, 32);
  Write(dst, Trunc(Unsigned(res)));
  return memory;
}

DEF_COND_SEM(QDSUB, R32W dst, R32 src1, R32 src2) {
  auto rhs = SExt(Signed(Read(src2)));
  auto lhs = SExt(Signed(Read(src1)));
  rhs = SignedSatQ(state, SShl(rhs, 1u), 32);
  auto res = SSub(lhs, rhs);
  res = SignedSatQ(state, res, 32);
  Write(dst, Trunc(Unsigned(res)));
  return memory;
}
}  // namespace

DEF_ISEL(QADD) = QADD;
DEF_ISEL(QDADD) = QDADD;
DEF_ISEL(QSUB) = QSUB;
DEF_ISEL(QDSUB) = QDSUB;

// TODO Signed multiply, Divide
namespace {
DEF_COND_SEM(SMLAD, R32W dst, R32 src1, R32 src2, R32 src3) {  // rn rm ra
  auto rn = Signed(Read(src1));
  auto rm = Signed(Read(src2));
  auto ra = Signed(Read(src3));
  auto prod1 = SMul(SExtTo<int64_t>(Trunc(rn)), SExtTo<int64_t>(Trunc(rm)));
  auto prod2 =
      SMul(SExtTo<int64_t>(SShr(rn, 16u)), SExtTo<int64_t>(SShr(rm, 16u)));
  auto res = SAdd(SAdd(prod1, prod2), SExt(ra));
  WriteTrunc(dst, Unsigned(res));

  //  if result != SInt(result<31:0>) then  // Signed overflow
  //      PSTATE.Q = '1';
  state.sr.q =
      Select(SCmpNeq(res, SExtTo<int64_t>(Trunc(res))), uint8_t(1), state.sr.q);
  return memory;
}

DEF_COND_SEM(SMLSD, R32W dst, R32 src1, R32 src2, R32 src3) {  // rn rm ra
  auto rn = Signed(Read(src1));
  auto rm = Signed(Read(src2));
  auto ra = Signed(Read(src3));
  auto prod1 = SMul(SExtTo<int64_t>(Signed(Trunc(rn))),
                    SExtTo<int64_t>(Signed(Trunc(rm))));
  auto prod2 =
      SMul(SExtTo<int64_t>(SShr(rn, 16u)), SExtTo<int64_t>(SShr(rm, 16u)));
  auto res = SAdd(SSub(prod1, prod2), SExt(ra));
  WriteTrunc(dst, Unsigned(res));

  //  if result != SInt(result<31:0>) then  // Signed overflow
  //      PSTATE.Q = '1';
  state.sr.q =
      Select(SCmpNeq(res, SExtTo<int64_t>(Trunc(res))), uint8_t(1), state.sr.q);
  return memory;
}

DEF_COND_SEM(SDIV, R32W dst, R32 src1, R32 src2, R32 src3) {  // rn rm
  auto rn = Signed(Read(src1));
  auto rm = Signed(Read(src2));
  if (!rm) {
    WriteZExt(dst, uint32_t(0));
  } else {
    WriteZExt(dst, Unsigned(SDiv(rn, rm)));
  }
  return memory;
}

DEF_COND_SEM(UDIV, R32W dst, R32 src1, R32 src2, R32 src3) {  // rn rm
  auto rn = Read(src1);
  auto rm = Read(src2);
  if (!rm) {
    WriteZExt(dst, uint32_t(0));
  } else {
    WriteZExt(dst, UDiv(rn, rm));
  }
  return memory;
}

DEF_COND_SEM(SMLALD, R32W dst_lo, R32W dst_hi, R32 src1, R32 src2, R32 src3,
             R32 src4) {  // ra - lo rd - hi rn rm ra - lo rd - hi
  auto rn = Signed(Read(src1));
  auto rm = Signed(Read(src2));
  auto lo = SExt(Signed(Read(src3)));
  auto hi = SExt(Signed(Read(src4)));
  auto prod1 = SMul(SExtTo<int64_t>(Trunc(rn)), SExtTo<int64_t>(Trunc(rm)));
  auto prod2 =
      SMul(SExtTo<int64_t>(SShr(rn, 16u)), SExtTo<int64_t>(SShr(rm, 16u)));
  auto res = SAdd(SAdd(prod1, prod2), SOr(lo, SShl(hi, 32u)));
  WriteTrunc(dst_lo, Unsigned(res));
  WriteTrunc(dst_hi, Unsigned(SShr(res, 32u)));
  return memory;
}

DEF_COND_SEM(SMLSLD, R32W dst_lo, R32W dst_hi, R32 src1, R32 src2, R32 src3,
             R32 src4) {  // ra - lo rd - hi rn rm ra - lo rd - hi
  auto rn = Signed(Read(src1));
  auto rm = Signed(Read(src2));
  auto lo = SExt(Signed(Read(src3)));
  auto hi = SExt(Signed(Read(src4)));
  auto prod1 = SMul(SExtTo<int64_t>(Trunc(rn)), SExtTo<int64_t>(Trunc(rm)));
  auto prod2 =
      SMul(SExtTo<int64_t>(SShr(rn, 16u)), SExtTo<int64_t>(SShr(rm, 16u)));
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
}  // namespace

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


// Extend and Add
namespace {
template <typename T>
T ROR_C(T val, T shift, T nbits) {
  if (shift == 0) {
    return val;
  }

  auto m = URem(shift, nbits);
  auto shr = UShr(val, m);
  auto shl = UShl(val, nbits - m);
  auto res = UOr(shr, shl);
  return res;
}

DEF_COND_SEM(SXTAB16, R32W dst, R32 src1, R32 src2, I32 src3) {
  auto src = Read(src2);
  auto src_add = Read(src1);
  auto rot = Read(src3);

  src = ROR_C(src, rot, 32u);

  // low/high 16 bits of rn + the low byte sign extended of the low/high 16 bits of rm
  auto low =
      ZExt(UAdd(Trunc(src_add),
                Unsigned(SExtTo<uint16_t>(Signed(TruncTo<uint8_t>(src))))));
  auto high = SExt(UAdd(
      Trunc(UShr(src_add, 16u)),
      Unsigned(SExtTo<uint16_t>(Signed(TruncTo<uint8_t>(UShr(src, 16u)))))));
  auto res = UOr(low, UShl(Unsigned(high), 16u));

  Write(dst, res);
  return memory;
}

DEF_COND_SEM(SXTAB, R32W dst, R32 src1, R32 src2, I32 src3) {
  auto src = Read(src2);
  auto src_add = Read(src1);
  auto rot = Read(src3);

  src = ROR_C(src, rot, 32u);

  // Extract low byte
  auto res =
      UAdd(Unsigned(SExtTo<uint32_t>(Signed(TruncTo<uint8_t>(src)))), src_add);

  Write(dst, res);
  return memory;
}

DEF_COND_SEM(SXTAH, R32W dst, R32 src1, R32 src2, I32 src3) {
  auto src = Read(src2);
  auto src_add = Read(src1);
  auto rot = Read(src3);

  src = ROR_C(src, rot, 32u);

  // Extract low 2 bytes and sign extend
  auto res = UAdd(Unsigned(SExt(Signed(Trunc(src)))), src_add);

  Write(dst, res);
  return memory;
}

DEF_COND_SEM(UXTAB16, R32W dst, R32 src1, R32 src2, I32 src3) {
  auto src = Read(src2);
  auto src_add = Read(src1);
  auto rot = Read(src3);

  src = ROR_C(src, rot, 32u);

  // low/high 16 bits of rn + the low byte of the low/high 16 bits of rm
  auto low = ZExt(UAdd(Trunc(src_add), UAnd(Trunc(src), uint16_t(255u))));
  auto high = ZExt(UAdd(Trunc(UShr(src_add, 16u)),
                        UAnd(Trunc(UShr(src, 16u)), uint16_t(255u))));
  auto res = UOr(low, UShl(high, 16u));

  Write(dst, res);
  return memory;
}

DEF_COND_SEM(UXTAB, R32W dst, R32 src1, R32 src2, I32 src3) {
  auto src = Read(src2);
  auto src_add = Read(src1);
  auto rot = Read(src3);

  src = ROR_C(src, rot, 32u);

  // Extract low byte i.e. 0b11111111 = 255
  auto res = UAdd(UAnd(src, uint32_t(255u)), src_add);

  Write(dst, res);
  return memory;
}

DEF_COND_SEM(UXTAH, R32W dst, R32 src1, R32 src2, I32 src3) {
  auto src = Read(src2);
  auto src_add = Read(src1);
  auto rot = Read(src3);

  src = ROR_C(src, rot, 32u);

  // Extract low 2 bytes i.e. 0b1111111111111111 = 65535
  auto res = UAdd(UAnd(src, uint32_t(65535u)), src_add);

  Write(dst, res);
  return memory;
}
}  // namespace

DEF_ISEL(SXTAB16) = SXTAB16;
DEF_ISEL(SXTB16) = SXTAB16;
DEF_ISEL(SXTAB) = SXTAB;
DEF_ISEL(SXTB) = SXTAB;
DEF_ISEL(SXTAH) = SXTAH;
DEF_ISEL(SXTH) = SXTAH;
DEF_ISEL(UXTAB16) = UXTAB16;
DEF_ISEL(UXTB16) = UXTAB16;
DEF_ISEL(UXTAB) = UXTAB;
DEF_ISEL(UXTB) = UXTAB;
DEF_ISEL(UXTAH) = UXTAH;
DEF_ISEL(UXTH) = UXTAH;
