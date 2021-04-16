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

#define PUSH_X87_STACK(x) \
  do { \
    auto __x = x; \
    state.st.elems[7].val = state.st.elems[6].val; \
    state.st.elems[6].val = state.st.elems[5].val; \
    state.st.elems[5].val = state.st.elems[4].val; \
    state.st.elems[4].val = state.st.elems[3].val; \
    state.st.elems[3].val = state.st.elems[2].val; \
    state.st.elems[2].val = state.st.elems[1].val; \
    state.st.elems[1].val = state.st.elems[0].val; \
    state.st.elems[0].val = __x; \
    state.x87.fxsave.swd.top = \
        static_cast<uint16_t>((state.x87.fxsave.swd.top + 7) % 8); \
  } while (false)


// Ideally we'd want to assign `__remill_undefined_f64` to the last element,
// but this more closely mimics the ring nature of the x87 stack.
#define POP_X87_STACK() \
  ({ \
    auto __x = state.st.elems[0].val; \
    state.st.elems[0].val = state.st.elems[1].val; \
    state.st.elems[1].val = state.st.elems[2].val; \
    state.st.elems[2].val = state.st.elems[3].val; \
    state.st.elems[3].val = state.st.elems[4].val; \
    state.st.elems[4].val = state.st.elems[5].val; \
    state.st.elems[5].val = state.st.elems[6].val; \
    state.st.elems[6].val = state.st.elems[7].val; \
    state.st.elems[7].val = __x; \
    state.x87.fxsave.swd.top = \
        static_cast<uint16_t>((state.x87.fxsave.swd.top + 9) % 8); \
    __x; \
  })

namespace {

#define SetFPUIpOp() \
  do { \
    state.x87.fxsave.fop = Read(fop); \
    IF_32BIT(state.x87.fxsave32.ip = Read(pc);) \
    IF_32BIT(state.x87.fxsave32.cs.flat = state.seg.cs.flat;) \
    IF_64BIT(state.x87.fxsave64.ip = Read(pc);) \
  } while (false)

// TODO(pag): Assume for now that FPU instructions only access memory via the
//            `DS` data segment selector.
#define SetFPUDp(mem) \
  do { \
    IF_32BIT(state.x87.fxsave32.dp = AddressOf(mem);) \
    IF_32BIT(state.x87.fxsave32.ds.flat = state.seg.ds.flat;) \
    IF_64BIT(state.x87.fxsave64.dp = AddressOf(mem);) \
  } while (false)

#define DEF_FPU_SEM(name, ...) DEF_SEM(name, ##__VA_ARGS__, PC pc, I16 fop)

// TODO(joe): Loss of precision, see issue #199.
DEF_FPU_SEM(FBLD, RF80W, MBCD80 src1) {
  SetFPUIpOp();
  SetFPUDp(src1);

  auto src1_bcd = ReadBCD80(src1);
  double val = 0.0;  // Decoded BCD value
  double mag = 1.0;  // Magnitude of decimal position

  // Iterate through pairs of digits, encoded as bytes.
  _Pragma("unroll") for (addr_t i = 0; i < sizeof(src1_bcd.digit_pairs); i++) {

    // We expect each half-byte to be a valid binary-coded decimal
    // digit (0-9). If not, the decoding result is undefined. The
    // native behavior seems to continue as if each encoding were
    // valid, so we do the same.
    auto b = src1_bcd.digit_pairs[i].u8;
    auto lo = b & 0xf;
    auto hi = b >> 4;

    // Accumulate positional decimal value of decoded digits.
    val += static_cast<double>(lo) * mag;
    mag *= 10.0;
    val += static_cast<double>(hi) * mag;
    mag *= 10.0;
  }

  if (src1_bcd.is_negative) {
    val = -val;
  }

  PUSH_X87_STACK(val);
  return memory;
}

template <typename T>
DEF_FPU_SEM(FILD, RF80W, T src1) {
  SetFPUIpOp();
  SetFPUDp(src1);
  PUSH_X87_STACK(Float64(Signed(Read(src1))));
  return memory;
}

template <typename T>
DEF_FPU_SEM(FLD, RF80W, T src1) {
  SetFPUIpOp();
  auto val = Read(src1);
  state.sw.ie |= IsSignalingNaN(val);
  state.sw.de = IsDenormal(val);
  auto res = Float64(val);

  // Quietize if signaling NaN.
  if (state.sw.ie) {
    nan64_t res_nan = {res};
    res_nan.is_quiet_nan = 1;
    res = res_nan.d;
  }

  PUSH_X87_STACK(res);
  return memory;
}

DEF_FPU_SEM(FLDfromstack, RF80W, RF80 src1) {
  SetFPUIpOp();
  state.sw.ie = 0;
  state.sw.de = 0;
  PUSH_X87_STACK(Read(src1));
  return memory;
}

template <typename T>
DEF_FPU_SEM(FLDmem, RF80W dst, T src1) {
  SetFPUDp(src1);
  return FLD(memory, state, dst, src1, pc, fop);
}

DEF_FPU_SEM(DoFLDLN2) {
  SetFPUIpOp();
  uint64_t ln_2 = 0x3fe62e42fefa39efULL;
  PUSH_X87_STACK(reinterpret_cast<float64_t &>(ln_2));
  return memory;
}

DEF_FPU_SEM(DoFLD1) {
  SetFPUIpOp();
  PUSH_X87_STACK(1.0);  // +1.0.
  return memory;
}

DEF_FPU_SEM(DoFLDZ) {
  SetFPUIpOp();
  PUSH_X87_STACK(0.0);  // +0.0.
  return memory;
}

DEF_FPU_SEM(DoFLDLG2) {
  SetFPUIpOp();
  uint64_t log10_2 = 0x3fd34413509f79ffULL;
  PUSH_X87_STACK(reinterpret_cast<float64_t &>(log10_2));
  return memory;
}

DEF_FPU_SEM(DoFLDL2T) {
  SetFPUIpOp();
  uint64_t log2_10 = 0x400a934f0979a371ULL;
  PUSH_X87_STACK(reinterpret_cast<float64_t &>(log2_10));
  return memory;
}

DEF_FPU_SEM(DoFLDL2E) {
  SetFPUIpOp();
  uint64_t log2_e = 0x3ff71547652b82feULL;
  PUSH_X87_STACK(reinterpret_cast<float64_t &>(log2_e));
  return memory;
}

DEF_FPU_SEM(DoFLDPI) {
  SetFPUIpOp();
  uint64_t pi = 0x400921fb54442d18ULL;
  PUSH_X87_STACK(reinterpret_cast<float64_t &>(pi));
  return memory;
}

DEF_FPU_SEM(DoFABS) {
  SetFPUIpOp();
  float64_t st0 = Read(X87_ST0);
  float64_t res = CheckedFloatUnaryOp(state, FAbs64, st0);
  Write(X87_ST0, res);
  return memory;
}

DEF_FPU_SEM(DoFCHS) {
  SetFPUIpOp();
  float64_t st0 = Read(X87_ST0);
  float64_t res = CheckedFloatUnaryOp(state, FNeg64, st0);
  Write(X87_ST0, res);
  return memory;
}

#define WRAP_BUILTIN(name, type, builtin) \
  ALWAYS_INLINE static type name(type x) { \
    return builtin(x); \
  }

WRAP_BUILTIN(FCos64, float64_t, __builtin_cos)
WRAP_BUILTIN(FSin64, float64_t, __builtin_sin)
WRAP_BUILTIN(FTan64, float64_t, __builtin_tan)
WRAP_BUILTIN(FSqrt64, float64_t, __builtin_sqrt)

// NOTE(pag): This only sort of, but doesn't really make sense. That is, it's
//            a reasonable guess-y way to say whether or not a given value can
//            be precisely represented. If it's got low order bits set, then
//            we'll assume it's not quite precise.
ALWAYS_INLINE static uint8_t IsImprecise(float32_t x) {
  return 0 != (reinterpret_cast<uint32_t &>(x) & 0xF);
}

ALWAYS_INLINE static uint8_t IsImprecise(float64_t x) {
  return 0 != (reinterpret_cast<uint64_t &>(x) & 0xFF);
}

DEF_FPU_SEM(DoFCOS) {
  SetFPUIpOp();
  float64_t st0 = Read(X87_ST0);
  state.sw.ie |= IsSignalingNaN(st0) | IsInfinite(st0);
  state.sw.de = IsDenormal(st0);
  auto res = CheckedFloatUnaryOp(state, FCos64, st0);
  if (!IsNaN(res)) {
    state.sw.pe = IsImprecise(res);
  }
  Write(X87_ST0, res);
  return memory;
}

DEF_FPU_SEM(DoFSIN) {
  SetFPUIpOp();
  float64_t st0 = Read(X87_ST0);
  state.sw.ie |= IsSignalingNaN(st0) | IsInfinite(st0);
  state.sw.de = IsDenormal(st0);
  auto res = CheckedFloatUnaryOp(state, FSin64, st0);
  if (!IsNaN(res)) {
    state.sw.pe = IsImprecise(res);
  }
  Write(X87_ST0, res);
  return memory;
}

DEF_FPU_SEM(DoFPTAN) {
  SetFPUIpOp();
  float64_t st0 = Read(X87_ST0);
  state.sw.ie |= IsSignalingNaN(st0) | IsInfinite(st0);
  state.sw.de = IsDenormal(st0);
  auto res = CheckedFloatUnaryOp(state, FTan64, st0);
  if (!IsNaN(res)) {
    state.sw.pe = IsImprecise(res);
  }
  Write(X87_ST0, res);
  PUSH_X87_STACK(1.0);
  return memory;
}

DEF_FPU_SEM(DoFPATAN) {
  SetFPUIpOp();

  float64_t st0 = Read(X87_ST0);
  float64_t st1 = Read(X87_ST1);
  float64_t res = CheckedFloatBinOp(state, FDiv64, st1, st0);
  if (!state.sw.ie) {
    state.sw.ie = IsSignalingNaN(res) | IsInfinite(res);
    state.sw.de = IsDenormal(res);
    state.sw.pe = IsImprecise(res);
  }

  Write(X87_ST1, __builtin_atan(res));
  (void) POP_X87_STACK();
  return memory;
}

DEF_FPU_SEM(DoFSQRT) {
  SetFPUIpOp();
  float64_t st0 = Read(X87_ST0);
  if (IsZero(st0)) {
    state.sw.ie = 0;
    state.sw.de = 0;
    state.sw.pe = 0;
    Write(X87_ST0, st0);
  } else {
    state.sw.ie |= IsSignalingNaN(st0) | IsNegative(st0);
    state.sw.de = IsDenormal(st0);
    float64_t res = CheckedFloatUnaryOp(state, FSqrt64, st0);
    if (!IsNaN(res)) {
      state.sw.pe = IsImprecise(res);
    }
    Write(X87_ST0, res);
  }
  return memory;
}

DEF_FPU_SEM(DoFSINCOS) {
  SetFPUIpOp();
  auto st0 = Read(X87_ST0);
  state.sw.ie |= IsSignalingNaN(st0) | IsInfinite(st0);
  state.sw.de = IsDenormal(st0);
  auto sin_res = CheckedFloatUnaryOp(state, FSin64, st0);
  auto cos_res = CheckedFloatUnaryOp(state, FCos64, st0);
  if (!IsNaN(sin_res) && !IsNaN(cos_res)) {
    state.sw.pe = IsImprecise(sin_res) | IsImprecise(cos_res);
  }
  Write(X87_ST0, sin_res);
  PUSH_X87_STACK(cos_res);
  return memory;
}

DEF_FPU_SEM(DoFSCALE) {
  SetFPUIpOp();
  auto st1_int = __builtin_trunc(Read(X87_ST1));  // Round toward zero.
  auto shift = __builtin_exp2(st1_int);
  Write(X87_ST0, FMul(Read(X87_ST0), shift));
  return memory;
}

DEF_FPU_SEM(DoF2XM1) {
  SetFPUIpOp();
  auto st0 = Read(X87_ST0);
  state.sw.ie |= IsSignalingNaN(st0) | IsInfinite(st0);
  state.sw.de = IsDenormal(st0);
  state.sw.ue = 0;  // TODO(pag): Not sure.
  auto res = FSub(__builtin_exp2(st0), 1.0);
  if (!IsNaN(res)) {
    state.sw.pe = IsImprecise(res);  // TODO(pag): Not sure.
  }
  Write(X87_ST0, res);
  return memory;
}

DEF_FPU_SEM(DoFPREM) {
  SetFPUIpOp();
  float64_t st0 = Read(X87_ST0);
  float64_t st1 = Read(X87_ST1);
  auto rem = __builtin_fmod(st0, st1);
  Write(X87_ST0, rem);

  auto quot = Int64(FTruncTowardZero64(FDiv(st0, st1)));
  auto quot_lsb = TruncTo<uint8_t>(UInt64(SAbs(quot)));
  state.sw.c0 = UAnd(UShr(quot_lsb, 2_u8), 1_u8);  // Q2.
  state.sw.c2 = 0;  // Assumes it's not a partial remainder.
  state.sw.c1 = UAnd(UShr(quot_lsb, 0_u8), 1_u8);  // Q0.
  state.sw.c3 = UAnd(UShr(quot_lsb, 1_u8), 1_u8);  // Q1.
  return memory;
}

DEF_FPU_SEM(DoFPREM1) {
  SetFPUIpOp();
  float64_t st0 = Read(X87_ST0);
  float64_t st1 = Read(X87_ST1);
  auto rem = __builtin_remainder(st0, st1);
  Write(X87_ST0, rem);
  auto quot = Float64ToInt64(FDiv(st0, st1));
  auto quot_lsb = TruncTo<uint8_t>(UInt64(SAbs(quot)));
  state.sw.c0 = UAnd(UShr(quot_lsb, 2_u8), 1_u8);  // Q2.
  state.sw.c2 = 0;  // Assumes it's not a partial remainder.
  state.sw.c1 = UAnd(UShr(quot_lsb, 0_u8), 1_u8);  // Q0.
  state.sw.c3 = UAnd(UShr(quot_lsb, 1_u8), 1_u8);  // Q1.
  return memory;
}

DEF_FPU_SEM(FPU_NOP) {
  SetFPUIpOp();
  return memory;
}

DEF_SEM(DoFWAIT) {
  feraiseexcept(fetestexcept(FE_ALL_EXCEPT));
  return memory;
}

DEF_SEM(DoFNCLEX) {
  feclearexcept(FE_ALL_EXCEPT);
  return memory;
}

}  // namespace

DEF_ISEL(FBLD_ST0_MEMmem80dec) = FBLD;

DEF_ISEL(FILD_ST0_MEMmem16int) = FILD<M16>;
DEF_ISEL(FILD_ST0_MEMmem32int) = FILD<M32>;
DEF_ISEL(FILD_ST0_MEMm64int) = FILD<M64>;

DEF_ISEL(FLD_ST0_MEMmem32real) = FLDmem<MF32>;
DEF_ISEL(FLD_ST0_X87) = FLDfromstack;
DEF_ISEL(FLD_ST0_MEMm64real) = FLDmem<MF64>;
DEF_ISEL(FLD_ST0_MEMmem80real) = FLDmem<MF80>;

DEF_ISEL(FLDLN2) = DoFLDLN2;
DEF_ISEL(FLD1) = DoFLD1;
DEF_ISEL(FLDZ) = DoFLDZ;
DEF_ISEL(FLDLG2) = DoFLDLG2;
DEF_ISEL(FLDL2T) = DoFLDL2T;
DEF_ISEL(FLDL2E) = DoFLDL2E;
DEF_ISEL(FLDPI) = DoFLDPI;

DEF_ISEL(FNOP) = FPU_NOP;
DEF_ISEL(FWAIT) = DoFWAIT;
DEF_ISEL(FNCLEX) = DoFNCLEX;
DEF_ISEL(FABS) = DoFABS;
DEF_ISEL(FCHS) = DoFCHS;
DEF_ISEL(FCOS) = DoFCOS;
DEF_ISEL(FSIN) = DoFSIN;
DEF_ISEL(FPTAN) = DoFPTAN;
DEF_ISEL(FPATAN) = DoFPATAN;
DEF_ISEL(FSQRT) = DoFSQRT;
DEF_ISEL(FSINCOS) = DoFSINCOS;
DEF_ISEL(FSCALE) = DoFSCALE;
DEF_ISEL(F2XM1) = DoF2XM1;
DEF_ISEL(FPREM) = DoFPREM;
DEF_ISEL(FPREM1) = DoFPREM1;

namespace {

template <typename T>
DEF_FPU_SEM(FSUB, RF80W dst, RF80 src1, T src2) {
  SetFPUIpOp();
  Write(dst, CheckedFloatBinOp(state, FSub64, Read(src1), Float64(Read(src2))));
  return memory;
}

template <typename T>
DEF_FPU_SEM(FSUBmem, RF80W dst, RF80 src1, T src2) {
  SetFPUDp(src2);
  return FSUB(memory, state, dst, src1, src2, pc, fop);
}

template <typename T>
DEF_FPU_SEM(FSUBP, RF80W dst, RF80 src1, T src2) {
  SetFPUIpOp();
  memory = FSUB<T>(memory, state, dst, src1, src2, pc, fop);
  (void) POP_X87_STACK();
  return memory;
}

template <typename T>
DEF_FPU_SEM(FISUB, RF80W dst, RF80 src1, T src2) {
  SetFPUIpOp();
  SetFPUDp(src2);
  Write(dst, CheckedFloatBinOp(state, FSub64, Read(src1),
                               Float64(Signed(Read(src2)))));
  return memory;
}

template <typename T>
DEF_FPU_SEM(FSUBR, RF80W dst, RF80 src1, T src2) {
  SetFPUIpOp();
  Write(dst, CheckedFloatBinOp(state, FSub64, Float64(Read(src2)), Read(src1)));
  return memory;
}

template <typename T>
DEF_FPU_SEM(FSUBRmem, RF80W dst, RF80 src1, T src2) {
  SetFPUDp(src2);
  return FSUBR(memory, state, dst, src1, src2, pc, fop);
}

template <typename T>
DEF_FPU_SEM(FSUBRP, RF80W dst, RF80 src1, T src2) {
  SetFPUIpOp();
  memory = FSUBR<T>(memory, state, dst, src1, src2, pc, fop);
  (void) POP_X87_STACK();
  return memory;
}

template <typename T>
DEF_FPU_SEM(FISUBR, RF80W dst, RF80 src1, T src2) {
  SetFPUIpOp();
  SetFPUDp(src2);
  Write(dst, CheckedFloatBinOp(state, FSub64, Float64(Signed(Read(src2))),
                               Read(src1)));
  return memory;
}
}  // namespace

DEF_ISEL(FSUB_ST0_MEMmem32real) = FSUBmem<MF32>;
DEF_ISEL(FSUB_ST0_MEMm64real) = FSUBmem<MF64>;
DEF_ISEL(FSUB_ST0_X87) = FSUB<RF80>;
DEF_ISEL(FSUB_X87_ST0) = FSUB<RF80>;
DEF_ISEL(FSUBP_X87_ST0) = FSUBP<RF80>;

DEF_ISEL(FSUBR_ST0_MEMmem32real) = FSUBRmem<MF32>;
DEF_ISEL(FSUBR_ST0_MEMm64real) = FSUBRmem<MF64>;
DEF_ISEL(FSUBR_ST0_X87) = FSUBR<RF80>;
DEF_ISEL(FSUBR_X87_ST0) = FSUBR<RF80>;
DEF_ISEL(FSUBRP_X87_ST0) = FSUBRP<RF80>;

DEF_ISEL(FISUB_ST0_MEMmem32int) = FISUB<M32>;
DEF_ISEL(FISUB_ST0_MEMmem16int) = FISUB<M16>;
DEF_ISEL(FISUBR_ST0_MEMmem32int) = FISUBR<M32>;
DEF_ISEL(FISUBR_ST0_MEMmem16int) = FISUBR<M16>;

namespace {

template <typename T>
DEF_FPU_SEM(FADD, RF80W dst, RF80 src1, T src2) {
  SetFPUIpOp();
  Write(dst, CheckedFloatBinOp(state, FAdd64, Read(src1), Float64(Read(src2))));

  //  state.sw.c1 = 1;
  state.sw.c0 = UUndefined8();
  state.sw.c2 = UUndefined8();
  state.sw.c3 = UUndefined8();
  return memory;
}

template <typename T>
DEF_FPU_SEM(FADDmem, RF80W dst, RF80 src1, T src2) {
  SetFPUDp(src2);
  return FADD(memory, state, dst, src1, src2, pc, fop);
}

template <typename T>
DEF_FPU_SEM(FADDP, RF80W dst, RF80 src1, T src2) {
  memory = FADD<T>(memory, state, dst, src1, src2, pc, fop);
  (void) POP_X87_STACK();
  return memory;
}

template <typename T>
DEF_FPU_SEM(FIADD, RF80W dst, RF80 src1, T src2) {
  SetFPUIpOp();
  SetFPUDp(src2);
  Write(dst, CheckedFloatBinOp(state, FAdd64, Read(src1),
                               Float64(Signed(Read(src2)))));
  return memory;
}

}  // namespace

DEF_ISEL(FADD_ST0_MEMmem32real) = FADDmem<MF32>;
DEF_ISEL(FADD_ST0_X87) = FADD<RF80>;
DEF_ISEL(FADD_ST0_MEMm64real) = FADDmem<MF64>;
DEF_ISEL(FADD_X87_ST0) = FADD<RF80>;
DEF_ISEL(FADDP_X87_ST0) = FADDP<RF80>;
DEF_ISEL(FIADD_ST0_MEMmem32int) = FIADD<M32>;
DEF_ISEL(FIADD_ST0_MEMmem16int) = FIADD<M16>;

namespace {

template <typename T>
DEF_FPU_SEM(FMUL, RF80W dst, RF80 src1, T src2) {
  SetFPUIpOp();
  Write(dst, CheckedFloatBinOp(state, FMul64, Read(src1), Float64(Read(src2))));
  return memory;
}

template <typename T>
DEF_FPU_SEM(FMULmem, RF80W dst, RF80 src1, T src2) {
  SetFPUDp(src2);
  return FMUL(memory, state, dst, src1, src2, pc, fop);
}

template <typename T>
DEF_FPU_SEM(FMULP, RF80W dst, RF80 src1, T src2) {
  memory = FMUL<T>(memory, state, dst, src1, src2, pc, fop);
  (void) POP_X87_STACK();
  return memory;
}

template <typename T>
DEF_FPU_SEM(FIMUL, RF80W dst, RF80 src1, T src2) {
  SetFPUIpOp();
  SetFPUDp(src2);
  Write(dst, CheckedFloatBinOp(state, FMul64, Read(src1),
                               Float64(Signed(Read(src2)))));
  return memory;
}

}  // namespace

DEF_ISEL(FMUL_ST0_MEMmem32real) = FMULmem<MF32>;
DEF_ISEL(FMUL_ST0_X87) = FMUL<RF80>;
DEF_ISEL(FMUL_ST0_MEMm64real) = FMULmem<MF64>;
DEF_ISEL(FMUL_X87_ST0) = FMUL<RF80>;
DEF_ISEL(FMULP_X87_ST0) = FMULP<RF80>;
DEF_ISEL(FIMUL_ST0_MEMmem32int) = FIMUL<M32>;
DEF_ISEL(FIMUL_ST0_MEMmem16int) = FIMUL<M16>;

namespace {

template <typename T>
DEF_FPU_SEM(FDIV, RF80W dst, RF80 src1, T src2) {
  SetFPUIpOp();
  Write(dst, CheckedFloatBinOp(state, FDiv64, Read(src1), Float64(Read(src2))));
  return memory;
}

template <typename T>
DEF_FPU_SEM(FDIVmem, RF80W dst, RF80 src1, T src2) {
  SetFPUDp(src2);
  return FDIV(memory, state, dst, src1, src2, pc, fop);
}

template <typename T>
DEF_FPU_SEM(FDIVP, RF80W dst, RF80 src1, T src2) {
  memory = FDIV<T>(memory, state, dst, src1, src2, pc, fop);
  (void) POP_X87_STACK();
  return memory;
}

template <typename T>
DEF_FPU_SEM(FIDIV, RF80W dst, RF80 src1, T src2) {
  SetFPUIpOp();
  SetFPUDp(src2);
  Write(dst, CheckedFloatBinOp(state, FDiv64, Read(src1),
                               Float64(Signed(Read(src2)))));
  return memory;
}

template <typename T>
DEF_FPU_SEM(FDIVR, RF80W dst, RF80 src1, T src2) {
  SetFPUIpOp();
  Write(dst, CheckedFloatBinOp(state, FDiv64, Float64(Read(src2)), Read(src1)));
  return memory;
}

template <typename T>
DEF_FPU_SEM(FDIVRmem, RF80W dst, RF80 src1, T src2) {
  SetFPUDp(src2);
  return FDIVR(memory, state, dst, src1, src2, pc, fop);
}

template <typename T>
DEF_FPU_SEM(FDIVRP, RF80W dst, RF80 src1, T src2) {
  memory = FDIVR<T>(memory, state, dst, src1, src2, pc, fop);
  (void) POP_X87_STACK();
  return memory;
}

template <typename T>
DEF_FPU_SEM(FIDIVR, RF80W dst, RF80 src1, T src2) {
  SetFPUIpOp();
  SetFPUDp(src2);
  Write(dst, CheckedFloatBinOp(state, FDiv64, Float64(Signed(Read(src2))),
                               Read(src1)));
  return memory;
}

}  // namespace

DEF_ISEL(FDIV_ST0_MEMmem32real) = FDIVmem<MF32>;
DEF_ISEL(FDIV_ST0_MEMm64real) = FDIVmem<MF64>;
DEF_ISEL(FDIV_ST0_X87) = FDIV<RF80>;
DEF_ISEL(FDIV_X87_ST0) = FDIV<RF80>;
DEF_ISEL(FDIVP_X87_ST0) = FDIVP<RF80>;

DEF_ISEL(FDIVR_ST0_MEMmem32real) = FDIVRmem<MF32>;
DEF_ISEL(FDIVR_ST0_MEMm64real) = FDIVRmem<MF64>;
DEF_ISEL(FDIVR_ST0_X87) = FDIVR<RF80>;
DEF_ISEL(FDIVR_X87_ST0) = FDIVR<RF80>;
DEF_ISEL(FDIVRP_X87_ST0) = FDIVRP<RF80>;

DEF_ISEL(FIDIV_ST0_MEMmem32int) = FIDIV<M32>;
DEF_ISEL(FIDIV_ST0_MEMmem16int) = FIDIV<M16>;
DEF_ISEL(FIDIVR_ST0_MEMmem32int) = FIDIVR<M32>;
DEF_ISEL(FIDIVR_ST0_MEMmem16int) = FIDIVR<M16>;

namespace {

DEF_FPU_SEM(FBSTP, MBCD80W dst, RF80 src) {
  SetFPUIpOp();
  bcd80_t out_bcd = {};

  auto read = Float64(Read(src));
  auto rounded = FRoundUsingMode64(read);
  auto rounded_abs = FAbs(rounded);

  // Any larger double aliases an integer out of 80-bit packed BCD range.
  constexpr double max_bcd80_float = 1e18 - 65;
  auto out_of_range = rounded_abs > max_bcd80_float;

  if (out_of_range || IsNaN(read) || IsInfinite(read)) {
    state.sw.ie = 1;
    state.sw.pe = 0;
    (void) POP_X87_STACK();
    return WriteBCD80Indefinite(dst);
  }

  // Was it rounded?
  if (rounded != read) {
    state.sw.pe = 1;

    // Was it rounded up (towards infinity)?
    if (read < rounded) {
      state.sw.c1 = 1;
    }
  }

  if (IsNegative(rounded)) {
    out_bcd.is_negative = true;
  }

  auto casted = static_cast<uint64_t>(rounded_abs);

  // Encode the double into packed BCD. By the range checks above, we know this
  // will succeed.
  for (uint64_t i = 0; i < sizeof(out_bcd.digit_pairs); i++) {
    out_bcd.digit_pairs[i].pair.lsd = static_cast<uint8_t>(casted % 10);
    casted /= 10;
    out_bcd.digit_pairs[i].pair.msd = static_cast<uint8_t>(casted % 10);
    casted /= 10;
  }

  memory = WriteBCD80(dst, out_bcd);

  (void) POP_X87_STACK();
  return memory;
}

template <typename T>
DEF_FPU_SEM(FST, T dst, RF80 src) {
  SetFPUIpOp();
  typedef typename BaseType<T>::BT BT;
  auto res = CheckedFloatUnaryOp(
      state, [=](float64_t x) { return static_cast<BT>(x); }, Read(src));
  Write(dst, res);
  return memory;
}

template <typename T>
DEF_FPU_SEM(FSTmem, T dst, RF80 src) {
  SetFPUDp(dst);
  return FST(memory, state, dst, src, pc, fop);
}

template <typename T>
DEF_FPU_SEM(FSTP, T dst, RF80 src) {
  memory = FST<T>(memory, state, dst, src, pc, fop);
  (void) POP_X87_STACK();
  return memory;
}

template <typename T>
DEF_FPU_SEM(FSTPmem, T dst, RF80 src) {
  SetFPUDp(dst);
  return FSTP(memory, state, dst, src, pc, fop);
}

template <typename C1, typename C2>
DEF_HELPER(ConvertToInt, C1 cast, C2 convert, float64_t input)
    ->decltype(cast(input)) {
  auto rounded = FRoundUsingMode64(input);
  auto casted = CheckedFloatUnaryOp(state, cast, rounded);
  auto converted = convert(rounded);
  auto back = static_cast<float64_t>(converted);

  if (!state.sw.ie && !state.sw.pe) {
    if (converted != casted || IsInfinite(input) || IsNaN(input)) {
      state.sw.ie = 1;
      state.sw.pe = 0;
    } else {
      if (back != rounded) {
        state.sw.ie = static_cast<uint8_t>(FAbs(back) < FAbs(input));
        state.sw.pe = 1 - state.sw.ie;
      } else {
        state.sw.pe = static_cast<uint8_t>(rounded != input);
        state.sw.ie = 0;
      }
    }
  }

  return converted;
}

DEF_FPU_SEM(FISTm16, M16W dst, RF80 src) {
  SetFPUIpOp();
  SetFPUDp(dst);
  auto res =
      ConvertToInt(memory, state, Int16<float64_t>, Float64ToInt16, Read(src));
  Write(dst, Unsigned(res));
  return memory;
}

DEF_FPU_SEM(FISTm32, M32W dst, RF80 src) {
  SetFPUIpOp();
  SetFPUDp(dst);
  auto res =
      ConvertToInt(memory, state, Int32<float64_t>, Float64ToInt32, Read(src));
  Write(dst, Unsigned(res));
  return memory;
}

DEF_FPU_SEM(FISTPm16, M16W dst, RF80 src) {
  memory = FISTm16(memory, state, dst, src, pc, fop);
  (void) POP_X87_STACK();
  return memory;
}

DEF_FPU_SEM(FISTPm32, M32W dst, RF80 src) {
  memory = FISTm32(memory, state, dst, src, pc, fop);
  (void) POP_X87_STACK();
  return memory;
}

DEF_FPU_SEM(FISTPm64, M64W dst, RF80 src) {
  SetFPUIpOp();
  SetFPUDp(dst);
  auto res =
      ConvertToInt(memory, state, Int64<float64_t>, Float64ToInt64, Read(src));
  Write(dst, Unsigned(res));
  (void) POP_X87_STACK();
  return memory;
}

DEF_FPU_SEM(DoFINCSTP) {
  SetFPUIpOp();
  (void) POP_X87_STACK();
  return memory;
}

DEF_FPU_SEM(DoFDECSTP) {
  SetFPUIpOp();
  PUSH_X87_STACK(X87_ST7);
  return memory;
}

}  // namespace

DEF_ISEL(FBSTP_MEMmem80dec_ST0) = FBSTP;
DEF_ISEL(FSTP_MEMmem32real_ST0) = FSTPmem<MF32W>;
DEF_ISEL(FSTP_MEMmem80real_ST0) = FSTPmem<MF80W>;
DEF_ISEL(FSTP_MEMm64real_ST0) = FSTPmem<MF64W>;
DEF_ISEL(FSTP_X87_ST0) = FSTP<RF80W>;
DEF_ISEL(FSTP_X87_ST0_DFD0) = FSTP<RF80W>;
DEF_ISEL(FSTP_X87_ST0_DFD1) = FSTP<RF80W>;
DEF_ISEL(FST_MEMmem32real_ST0) = FSTmem<MF32W>;
DEF_ISEL(FST_MEMm64real_ST0) = FSTmem<MF64W>;
DEF_ISEL(FST_X87_ST0) = FST<RF80W>;
DEF_ISEL(FIST_MEMmem16int_ST0) = FISTm16;
DEF_ISEL(FIST_MEMmem32int_ST0) = FISTm32;
DEF_ISEL(FISTP_MEMmem16int_ST0) = FISTPm16;
DEF_ISEL(FISTP_MEMmem32int_ST0) = FISTPm32;
DEF_ISEL(FISTP_MEMm64int_ST0) = FISTPm64;
DEF_ISEL(FDECSTP) = DoFDECSTP;
DEF_ISEL(FINCSTP) = DoFINCSTP;

// TODO(pag): According to XED: empty top of stack behavior differs from FSTP
IF_32BIT(DEF_ISEL(FSTPNCE_X87_ST0) = FSTP<RF80W>;)

template <typename C1, typename C2>
DEF_HELPER(TruncateToInt, C1 cast, C2 convert, float64_t input)
    ->decltype(cast(input)) {
  auto truncated = FTruncTowardZero64(input);
  auto casted = CheckedFloatUnaryOp(state, cast, truncated);
  auto converted = convert(truncated);
  auto back = static_cast<float64_t>(converted);

  if (!state.sw.ie && !state.sw.pe) {
    if (converted != casted || IsInfinite(input) || IsNaN(input)) {
      state.sw.ie = 1;
      state.sw.pe = 0;
    } else {
      if (back != truncated) {
        state.sw.ie = static_cast<uint8_t>(FAbs(back) < FAbs(input));
        state.sw.pe = 1 - state.sw.ie;
      } else {
        state.sw.pe = static_cast<uint8_t>(truncated != input);
        state.sw.ie = 0;
      }
    }
  }

  return converted;
}

namespace {
DEF_FPU_SEM(FISTTPm16, M16W dst, RF80 src) {
  SetFPUIpOp();
  SetFPUDp(dst);
  auto res =
      TruncateToInt(memory, state, Int16<float64_t>, Float64ToInt16, Read(src));
  Write(dst, Unsigned(res));
  (void) POP_X87_STACK();
  return memory;
}

DEF_FPU_SEM(FISTTPm32, M32W dst, RF80 src) {
  SetFPUIpOp();
  SetFPUDp(dst);
  auto res =
      TruncateToInt(memory, state, Int32<float64_t>, Float64ToInt32, Read(src));
  Write(dst, Unsigned(res));
  (void) POP_X87_STACK();
  return memory;
}

DEF_FPU_SEM(FISTTPm64, M64W dst, RF80 src) {
  SetFPUIpOp();
  SetFPUDp(dst);
  auto res =
      TruncateToInt(memory, state, Int64<float64_t>, Float64ToInt64, Read(src));
  Write(dst, Unsigned(res));
  (void) POP_X87_STACK();
  return memory;
}

}  // namespace

DEF_ISEL(FISTTP_MEMmem16int_ST0) = FISTTPm16;
DEF_ISEL(FISTTP_MEMmem32int_ST0) = FISTTPm32;
DEF_ISEL(FISTTP_MEMm64int_ST0) = FISTTPm64;

namespace {

DEF_FPU_SEM(FXCH, RF80W dst1, RF80 src1, RF80W dst2, RF80 src2) {
  SetFPUIpOp();
  auto st0 = Read(src1);
  auto sti = Read(src2);
  Write(dst1, sti);
  Write(dst2, st0);
  return memory;
}

}  // namespace

DEF_ISEL(FXCH_ST0_X87) = FXCH;
DEF_ISEL(FXCH_ST0_X87_DFC1) = FXCH;
DEF_ISEL(FXCH_ST0_X87_DDC1) = FXCH;

namespace {

DEF_FPU_SEM(DoFXAM) {
  SetFPUIpOp();
  auto st0 = Read(X87_ST0);

  uint8_t sign = __builtin_signbit(st0) == 0 ? 0_u8 : 1_u8;
  auto c = __builtin_fpclassify(FP_NAN, FP_INFINITE, FP_NORMAL, FP_SUBNORMAL,
                                FP_ZERO, st0);
  switch (c) {
    case FP_NAN:
      state.sw.c0 = 1;
      state.sw.c1 = 0;  // Weird.
      state.sw.c2 = 0;
      state.sw.c3 = 0;
      break;

    case FP_INFINITE:
      state.sw.c0 = 1;
      state.sw.c1 = 0;  // Weird.
      state.sw.c2 = 1;
      state.sw.c3 = 0;
      break;

    case FP_ZERO:
      state.sw.c0 = 0;
      state.sw.c1 = 0;  // Weird.
      state.sw.c2 = 0;
      state.sw.c3 = 1;
      break;

    case FP_SUBNORMAL:
      state.sw.c0 = 0;
      state.sw.c1 = sign;
      state.sw.c2 = 1;
      state.sw.c3 = 1;
      break;

    case FP_NORMAL:
      state.sw.c0 = 0;
      state.sw.c1 = sign;
      state.sw.c2 = 1;
      state.sw.c3 = 0;
      break;

    // Using empty or unsupported is valid here, though we use unsupported
    // because we don't actually model empty FPU stack slots.
    default:
      state.sw.c0 = 0;
      state.sw.c1 = 0;  // Maybe??
      state.sw.c2 = 0;
      state.sw.c3 = 0;
      break;
  }
  return memory;
}

DEF_HELPER(OrderedCompare, float64_t src1, float64_t src2)->void {
  state.sw.de = IsDenormal(src1) | IsDenormal(src2);
  state.sw.ie = 0;

  if (__builtin_isunordered(src1, src2)) {
    state.sw.c0 = 1;
    state.sw.c2 = 1;
    state.sw.c3 = 1;
    state.sw.ie = 1;
  } else if (__builtin_isless(src1, src2)) {
    state.sw.c0 = 1;
    state.sw.c2 = 0;
    state.sw.c3 = 0;

  } else if (__builtin_isgreater(src1, src2)) {
    state.sw.c0 = 0;
    state.sw.c2 = 0;
    state.sw.c3 = 0;

  } else {  // Equal.
    state.sw.c0 = 0;
    state.sw.c2 = 0;
    state.sw.c3 = 1;
  }
}

DEF_HELPER(UnorderedCompare, float64_t src1, float64_t src2)->void {
  state.sw.de = IsDenormal(src1) | IsDenormal(src2);
  state.sw.ie = 0;

  if (__builtin_isunordered(src1, src2)) {
    state.sw.c0 = 1;
    state.sw.c2 = 1;
    state.sw.c3 = 1;
    state.sw.ie = IsSignalingNaN(src1) | IsSignalingNaN(src1);
  } else if (__builtin_isless(src1, src2)) {
    state.sw.c0 = 1;
    state.sw.c2 = 0;
    state.sw.c3 = 0;

  } else if (__builtin_isgreater(src1, src2)) {
    state.sw.c0 = 0;
    state.sw.c2 = 0;
    state.sw.c3 = 0;

  } else {  // Equal.
    state.sw.c0 = 0;
    state.sw.c2 = 0;
    state.sw.c3 = 1;
  }
}

DEF_FPU_SEM(DoFTST) {
  SetFPUIpOp();
  auto st0 = Read(X87_ST0);
  state.sw.c1 = 0;

  // NOTE(pag): This instruction performs an unordered compare, but sets the
  //            flags more similarly to an ordered compare. Really, the
  //            difference between ordered/unordered is that unordered compares
  //            are silent on SNaNs, whereas ordered ones aren't.
  OrderedCompare(memory, state, st0, 0.0);
  return memory;
}

template <typename S2>
DEF_FPU_SEM(FUCOM, RF80 src1, S2 src2) {
  SetFPUIpOp();
  auto st0 = Read(src1);
  auto sti = Float64(Read(src2));

  // Note:  Don't modify c1. The docs only state that c1=0 if there was a
  //        stack underflow.
  UnorderedCompare(memory, state, st0, sti);
  return memory;
}

template <typename S2>
DEF_FPU_SEM(FCOM, RF80 src1, S2 src2) {
  SetFPUIpOp();
  auto st0 = Read(src1);
  auto sti = Float64(Read(src2));

  // Note:  Don't modify c1. The docs only state that c1=0 if there was a
  //        stack underflow.
  OrderedCompare(memory, state, st0, sti);
  return memory;
}

template <typename S2>
DEF_FPU_SEM(FUCOMmem, RF80 src1, S2 src2) {
  SetFPUDp(src2);
  return FUCOM(memory, state, src1, src2, pc, fop);
}

template <typename S2>
DEF_FPU_SEM(FCOMmem, RF80 src1, S2 src2) {
  SetFPUDp(src2);
  return FCOM(memory, state, src1, src2, pc, fop);
}

template <typename S2>
DEF_FPU_SEM(FUCOMP, RF80 src1, S2 src2) {
  memory = FUCOM<S2>(memory, state, src1, src2, pc, fop);
  (void) POP_X87_STACK();
  return memory;
}

template <typename S2>
DEF_FPU_SEM(FCOMP, RF80 src1, S2 src2) {
  memory = FCOM<S2>(memory, state, src1, src2, pc, fop);
  (void) POP_X87_STACK();
  return memory;
}

template <typename S2>
DEF_FPU_SEM(FUCOMPmem, RF80 src1, S2 src2) {
  SetFPUDp(src2);
  return FUCOMP(memory, state, src1, src2, pc, fop);
}

template <typename S2>
DEF_FPU_SEM(FCOMPmem, RF80 src1, S2 src2) {
  SetFPUDp(src2);
  return FCOMP(memory, state, src1, src2, pc, fop);
}

DEF_FPU_SEM(DoFUCOMPP) {
  RF80 st0 = {X87_ST0};
  RF80 st1 = {X87_ST1};
  memory = FUCOM<RF80>(memory, state, st0, st1, pc, fop);
  (void) POP_X87_STACK();
  (void) POP_X87_STACK();
  return memory;
}

DEF_FPU_SEM(DoFCOMPP) {
  RF80 st0 = {X87_ST0};
  RF80 st1 = {X87_ST1};
  memory = FCOM<RF80>(memory, state, st0, st1, pc, fop);
  (void) POP_X87_STACK();
  (void) POP_X87_STACK();
  return memory;
}

DEF_HELPER(UnorderedCompareEflags, float64_t src1, float64_t src2)->void {
  state.sw.de = IsDenormal(src1) | IsDenormal(src2);
  state.sw.ie = 0;

  if (__builtin_isunordered(src1, src2)) {
    FLAG_CF = 1;
    FLAG_PF = 1;
    FLAG_ZF = 1;
    state.sw.ie = IsSignalingNaN(src1) | IsSignalingNaN(src1);

  } else if (__builtin_isless(src1, src2)) {
    FLAG_CF = 1;
    FLAG_PF = 0;
    FLAG_ZF = 0;

  } else if (__builtin_isgreater(src1, src2)) {
    FLAG_CF = 0;
    FLAG_PF = 0;
    FLAG_ZF = 0;

  } else {  // Equal.
    FLAG_CF = 0;
    FLAG_PF = 0;
    FLAG_ZF = 1;
  }
}

DEF_HELPER(OrderedCompareEflags, float64_t src1, float64_t src2)->void {
  state.sw.de = IsDenormal(src1) | IsDenormal(src2);
  state.sw.ie = 0;

  if (__builtin_isunordered(src1, src2)) {
    FLAG_CF = 1;
    FLAG_PF = 1;
    FLAG_ZF = 1;
    state.sw.ie = 1;

  } else if (__builtin_isless(src1, src2)) {
    FLAG_CF = 1;
    FLAG_PF = 0;
    FLAG_ZF = 0;

  } else if (__builtin_isgreater(src1, src2)) {
    FLAG_CF = 0;
    FLAG_PF = 0;
    FLAG_ZF = 0;

  } else {  // Equal.
    FLAG_CF = 0;
    FLAG_PF = 0;
    FLAG_ZF = 1;
  }
}

DEF_FPU_SEM(FUCOMI, RF80 src1, RF80 src2) {
  SetFPUIpOp();
  auto st0 = Read(src1);
  auto sti = Read(src2);
  state.sw.c1 = 0;
  FLAG_OF = 0;
  FLAG_SF = 0;
  FLAG_AF = 0;
  UnorderedCompareEflags(memory, state, st0, sti);
  return memory;
}

DEF_FPU_SEM(FUCOMIP, RF80 src1, RF80 src2) {
  memory = FUCOMI(memory, state, src1, src2, pc, fop);
  (void) POP_X87_STACK();
  return memory;
}

DEF_FPU_SEM(FCOMI, RF80 src1, RF80 src2) {
  SetFPUIpOp();
  auto st0 = Read(src1);
  auto sti = Read(src2);
  state.sw.c1 = 0;
  FLAG_OF = 0;
  FLAG_SF = 0;
  FLAG_AF = 0;
  OrderedCompareEflags(memory, state, st0, sti);
  return memory;
}

DEF_FPU_SEM(FCOMIP, RF80 src1, RF80 src2) {
  memory = FCOMI(memory, state, src1, src2, pc, fop);
  (void) POP_X87_STACK();
  return memory;
}

}  // namespace

DEF_ISEL(FXAM) = DoFXAM;
DEF_ISEL(FTST) = DoFTST;

DEF_ISEL(FUCOM_ST0_X87) = FUCOM<RF80>;
DEF_ISEL(FUCOMP_ST0_X87) = FUCOMP<RF80>;
DEF_ISEL(FUCOMPP) = DoFUCOMPP;

DEF_ISEL(FUCOMI_ST0_X87) = FUCOMI;
DEF_ISEL(FUCOMIP_ST0_X87) = FUCOMIP;

DEF_ISEL(FCOMI_ST0_X87) = FCOMI;
DEF_ISEL(FCOMIP_ST0_X87) = FCOMIP;

DEF_ISEL(FCOM_ST0_X87) = FCOM<RF80>;
DEF_ISEL(FCOM_ST0_X87_DCD0) = FCOM<RF80>;
DEF_ISEL(FCOM_ST0_MEMmem32real) = FCOMmem<MF32>;
DEF_ISEL(FCOM_ST0_MEMm64real) = FCOMmem<MF64>;

DEF_ISEL(FCOMP_ST0_X87) = FCOMP<RF80>;
DEF_ISEL(FCOMP_ST0_MEMmem32real) = FCOMPmem<MF32>;
DEF_ISEL(FCOMP_ST0_MEMm64real) = FCOMPmem<MF64>;
DEF_ISEL(FCOMP_ST0_X87_DCD1) = FCOMP<RF80>;
DEF_ISEL(FCOMP_ST0_X87_DED0) = FCOMP<RF80>;
DEF_ISEL(FCOMPP) = DoFCOMPP;

namespace {

template <typename D>
DEF_SEM(FNSTSW, D dst) {
  auto &sw = state.x87.fxsave.swd;
  sw.c0 = state.sw.c0;
  sw.c1 = state.sw.c1;
  sw.c2 = state.sw.c2;
  sw.c3 = state.sw.c3;
  sw.pe = state.sw.pe;
  sw.ue = state.sw.ue;
  sw.oe = state.sw.oe;
  sw.ze = state.sw.ze;
  sw.de = state.sw.de;
  sw.ie = state.sw.ie;
  Write(dst, sw.flat);
  return memory;
}

DEF_SEM(FNSTCW, M16W dst) {
  auto &cw = state.x87.fxsave.cwd;
  cw.pc = kPrecisionSingle;

  //cw.flat = 0x027F_u16;  // Our default, with double-precision.
  switch (fegetround()) {
    default:
    case FE_TONEAREST: cw.rc = kFPURoundToNearestEven; break;
    case FE_DOWNWARD: cw.rc = kFPURoundDownNegInf; break;
    case FE_UPWARD: cw.rc = kFPURoundUpInf; break;
    case FE_TOWARDZERO: cw.rc = kFPURoundToZero; break;
  }
  Write(dst, cw.flat);
  return memory;
}

DEF_SEM(FLDCW, M16 cwd) {
  auto &cw = state.x87.fxsave.cwd;
  cw.flat = Read(cwd);
  cw.pc = kPrecisionSingle;
  int rounding_mode = FE_TONEAREST;
  switch (cw.rc) {
    case kFPURoundToNearestEven: rounding_mode = FE_TONEAREST; break;

    case kFPURoundDownNegInf: rounding_mode = FE_DOWNWARD; break;

    case kFPURoundUpInf: rounding_mode = FE_UPWARD; break;

    case kFPURoundToZero: rounding_mode = FE_TOWARDZERO; break;
  }
  fesetround(rounding_mode);
  return memory;
}

}  // namespace

DEF_ISEL(FNSTSW_MEMmem16) = FNSTSW<M16W>;
DEF_ISEL(FNSTSW_AX) = FNSTSW<R16W>;
DEF_ISEL(FNSTCW_MEMmem16) = FNSTCW;
DEF_ISEL(FLDCW_MEMmem16) = FLDCW;

namespace {

DEF_FPU_SEM(DoFRNDINT) {
  SetFPUIpOp();
  auto st0 = Read(X87_ST0);
  auto rounded = FRoundUsingMode64(st0);
  state.sw.ie |= IsSignalingNaN(st0);
  state.sw.de = IsDenormal(st0);
  if (!IsNaN(rounded)) {
    state.sw.pe = st0 != rounded;
  }
  // state.sw.c1 = __builtin_isgreater(FAbs(rounded), FAbs(st0)) ? 1_u8 : 0_u8;
  Write(X87_ST0, rounded);
  return memory;
}

DEF_FPU_SEM(DoFYL2X) {
  SetFPUIpOp();
  auto st0 = Read(X87_ST0);
  auto st1 = Read(X87_ST1);
  state.sw.ze = IsZero(st0);
  state.sw.de = IsDenormal(st0) | IsDenormal(st1);
  state.sw.ie = (IsSignalingNaN(st0) | IsSignalingNaN(st1)) ||
                (IsNegative(st0) && !IsInfinite(st0) && !state.sw.ze);
  auto res = FMul64(st1, __builtin_log2(st0));
  state.sw.pe = IsImprecise(res);
  Write(X87_ST1, res);
  (void) POP_X87_STACK();
  return memory;
}

DEF_FPU_SEM(DoFYL2XP1) {
  SetFPUIpOp();
  auto st0 = Read(X87_ST0);
  auto st1 = Read(X87_ST1);
  state.sw.ze = IsZero(st0);
  state.sw.de = IsDenormal(st0) | IsDenormal(st1);
  state.sw.ie = IsSignalingNaN(st0) | IsSignalingNaN(st1);
  auto res = FMul(st1, __builtin_log2(FAdd(st0, 1.0)));
  state.sw.pe = IsImprecise(res);
  Write(X87_ST1, res);
  (void) POP_X87_STACK();
  return memory;
}

DEF_FPU_SEM(FFREE, RF80 src) {
  SetFPUIpOp();
  (void) src;
  return memory;
}

DEF_FPU_SEM(FFREEP, RF80 src) {
  SetFPUIpOp();
  (void) POP_X87_STACK();
  (void) src;
  return memory;
}

}  // namespace

DEF_ISEL(FRNDINT) = DoFRNDINT;
DEF_ISEL(FYL2X) = DoFYL2X;
DEF_ISEL(FYL2XP1) = DoFYL2XP1;

DEF_ISEL(FFREE_X87) = FFREE;
DEF_ISEL(FFREEP_X87) = FFREEP;

namespace {

template <typename D, typename S1>
DEF_FPU_SEM(FCMOVNP, D dst, S1 src1) {
  SetFPUIpOp();
  Write(dst, Select(BNot(FLAG_PF), Read(src1), Read(dst)));
  return memory;
}

template <typename D, typename S1>
DEF_FPU_SEM(FCMOVNZ, D dst, S1 src1) {
  SetFPUIpOp();
  Write(dst, Select(BNot(FLAG_ZF), Read(src1), Read(dst)));
  return memory;
}

template <typename D, typename S1>
DEF_FPU_SEM(FCMOVNB, D dst, S1 src1) {
  SetFPUIpOp();
  Write(dst, Select(BNot(FLAG_CF), Read(src1), Read(dst)));
  return memory;
}

template <typename D, typename S1>
DEF_FPU_SEM(FCMOVNBE, D dst, S1 src1) {
  SetFPUIpOp();
  Write(dst, Select(BNot(BOr(FLAG_CF, FLAG_ZF)), Read(src1), Read(dst)));
  return memory;
}

template <typename D, typename S1>
DEF_FPU_SEM(FCMOVBE, D dst, S1 src1) {
  SetFPUIpOp();
  Write(dst, Select(BOr(FLAG_CF, FLAG_ZF), Read(src1), Read(dst)));
  return memory;
}

template <typename D, typename S1>
DEF_FPU_SEM(FCMOVP, D dst, S1 src1) {
  SetFPUIpOp();
  Write(dst, Select(FLAG_PF, Read(src1), Read(dst)));
  return memory;
}

template <typename D, typename S1>
DEF_FPU_SEM(FCMOVZ, D dst, S1 src1) {
  SetFPUIpOp();
  Write(dst, Select(FLAG_ZF, Read(src1), Read(dst)));
  return memory;
}

template <typename D, typename S1>
DEF_FPU_SEM(FCMOVB, D dst, S1 src1) {
  SetFPUIpOp();
  Write(dst, Select(FLAG_CF, Read(src1), Read(dst)));
  return memory;
}

}  // namespace

DEF_ISEL(FCMOVNU_ST0_X87) = FCMOVNP<RF80W, RF80>;
DEF_ISEL(FCMOVNB_ST0_X87) = FCMOVNB<RF80W, RF80>;
DEF_ISEL(FCMOVNE_ST0_X87) = FCMOVNZ<RF80W, RF80>;
DEF_ISEL(FCMOVBE_ST0_X87) = FCMOVBE<RF80W, RF80>;
DEF_ISEL(FCMOVNBE_ST0_X87) = FCMOVNBE<RF80W, RF80>;
DEF_ISEL(FCMOVU_ST0_X87) = FCMOVP<RF80W, RF80>;
DEF_ISEL(FCMOVE_ST0_X87) = FCMOVZ<RF80W, RF80>;
DEF_ISEL(FCMOVB_ST0_X87) = FCMOVB<RF80W, RF80>;

namespace {

DEF_SEM(DoFNINIT) {

  // Initialize the FPU state without checking error conditions.
  // "Word" and opcode fields are always 16-bit. Pointer fields are either
  // 32-bit or 64-bit, but regardless, they are set to 0.
  state.x87.fsave.cwd.flat = 0x037F;  // FPUControlWord
  state.x87.fsave.swd.flat = 0x0000;  // FPUStatusWord
  state.x87.fsave.ftw.flat =
      0x0000;  // FPUTagWord (0xFFFF in the manual, 0x0000 in testing)
  state.x87.fsave.dp = 0x0;  // FPUDataPointer
  state.x87.fsave.ip = 0x0;  // FPUInstructionPointer
  state.x87.fsave.fop = 0x0;  // FPULastInstructionOpcode
  state.x87.fsave.ds.flat = 0x0000;  // FPU code segment selector
  state.x87.fsave.cs.flat = 0x0000;  // FPU data operand segment selector

  // Mask all floating-point exceptions:
  std::feclearexcept(FE_ALL_EXCEPT);

  // Set FPU rounding mode to nearest:
  std::fesetround(FE_TONEAREST);

  // TODO: Set the FPU precision to 64 bits

  return memory;
}

}  // namespace

DEF_ISEL(FNINIT) = DoFNINIT;

/*
23 FICOMP FICOMP_ST0_MEMmem32int X87_ALU X87 X87 ATTRIBUTES: NOTSX
24 FICOMP FICOMP_ST0_MEMmem16int X87_ALU X87 X87 ATTRIBUTES: NOTSX
889 FICOM FICOM_ST0_MEMmem32int X87_ALU X87 X87 ATTRIBUTES: NOTSX
890 FICOM FICOM_ST0_MEMmem16int X87_ALU X87 X87 ATTRIBUTES: NOTSX

1200 FLDENV FLDENV_MEMmem14 X87_ALU X87 X87 ATTRIBUTES: NOTSX X87_CONTROL
1201 FLDENV FLDENV_MEMmem28 X87_ALU X87 X87 ATTRIBUTES: NOTSX X87_CONTROL
102 FNSAVE FNSAVE_MEMmem94 X87_ALU X87 X87 ATTRIBUTES: NOTSX X87_CONTROL X87_MMX_STATE_R X87_MMX_STATE_W X87_NOWAIT
103 FNSAVE FNSAVE_MEMmem108 X87_ALU X87 X87 ATTRIBUTES: NOTSX X87_CONTROL X87_MMX_STATE_R X87_MMX_STATE_W X87_NOWAIT
357 FXTRACT FXTRACT_ST0_ST1 X87_ALU X87 X87 ATTRIBUTES: NOTSX
401 FENI8087_NOP FENI8087_NOP X87_ALU X87 X87 ATTRIBUTES: NOP NOTSX
546 FSETPM287_NOP FSETPM287_NOP X87_ALU X87 X87 ATTRIBUTES: NOP NOTSX

1200 FLDENV FLDENV_MEMmem14 X87_ALU X87 X87 ATTRIBUTES: NOTSX X87_CONTROL
1201 FLDENV FLDENV_MEMmem28 X87_ALU X87 X87 ATTRIBUTES: NOTSX X87_CONTROL
1262 FBLD FBLD_ST0_MEMmem80dec X87_ALU X87 X87 ATTRIBUTES: NOTSX
1286 FDISI8087_NOP FDISI8087_NOP X87_ALU X87 X87 ATTRIBUTES: NOP NOTSX
1593 FRSTOR FRSTOR_MEMmem94 X87_ALU X87 X87 ATTRIBUTES: NOTSX X87_CONTROL X87_MMX_STATE_W
1594 FRSTOR FRSTOR_MEMmem108 X87_ALU X87 X87 ATTRIBUTES: NOTSX X87_CONTROL X87_MMX_STATE_W
1735 FBSTP FBSTP_MEMmem80dec_ST0 X87_ALU X87 X87 ATTRIBUTES: NOTSX
1762 FNSTENV FNSTENV_MEMmem14 X87_ALU X87 X87 ATTRIBUTES: NOTSX X87_CONTROL X87_NOWAIT
1763 FNSTENV FNSTENV_MEMmem28 X87_ALU X87 X87 ATTRIBUTES: NOTSX X87_CONTROL X87_NOWAIT
 */
