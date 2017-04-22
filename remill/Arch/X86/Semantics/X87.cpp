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

#ifndef REMILL_ARCH_X86_SEMANTICS_X87_H_
#define REMILL_ARCH_X86_SEMANTICS_X87_H_

#define PUSH_X87_STACK(x) \
  do { \
    auto __x = x; \
    state.st.elems[7].val = state.st.elems[6].val ; \
    state.st.elems[6].val = state.st.elems[5].val ; \
    state.st.elems[5].val = state.st.elems[4].val ; \
    state.st.elems[4].val = state.st.elems[3].val ; \
    state.st.elems[3].val = state.st.elems[2].val ; \
    state.st.elems[2].val = state.st.elems[1].val ; \
    state.st.elems[1].val = state.st.elems[0].val ; \
    state.st.elems[0].val = __x;\
  } while (false)


// Ideally we'd want to assign `__remill_undefined_f64` to the last element,
// but this more closely mimics the ring nature of the x87 stack.
#define POP_X87_STACK() ({\
  auto x = state.st.elems[0].val ; \
  state.st.elems[0].val = state.st.elems[1].val ; \
  state.st.elems[1].val = state.st.elems[2].val ; \
  state.st.elems[2].val = state.st.elems[3].val ; \
  state.st.elems[3].val = state.st.elems[4].val ; \
  state.st.elems[4].val = state.st.elems[5].val ; \
  state.st.elems[5].val = state.st.elems[6].val ; \
  state.st.elems[6].val = state.st.elems[7].val ; \
  state.st.elems[7].val = x; \
  x; })

namespace {

template <typename T>
DEF_SEM(FILD, RF80W, T src1) {
  PUSH_X87_STACK(Float64(Signed(Read(src1))));
  return memory;
}

template <typename T>
DEF_SEM(FLD, RF80W, T src1) {
  PUSH_X87_STACK(Float64(Read(src1)));
  return memory;
}

DEF_SEM(DoFLDLN2) {
  uint64_t ln_2 = 0x3fe62e42fefa39efULL;
  PUSH_X87_STACK(reinterpret_cast<float64_t &>(ln_2));
  return memory;
}

DEF_SEM(DoFLD1) {
  PUSH_X87_STACK(1.0);  // +1.0.
  return memory;
}

DEF_SEM(DoFLDZ) {
  PUSH_X87_STACK(0.0);  // +0.0.
  return memory;
}

DEF_SEM(DoFLDLG2) {
  uint64_t log10_2 = 0x3fd34413509f79ffULL;
  PUSH_X87_STACK(reinterpret_cast<float64_t &>(log10_2));
  return memory;
}

DEF_SEM(DoFLDL2T) {
  uint64_t log2_10 = 0x400a934f0979a371ULL;
  PUSH_X87_STACK(reinterpret_cast<float64_t &>(log2_10));
  return memory;
}

DEF_SEM(DoFLDL2E) {
  uint64_t log2_e = 0x3ff71547652b82feULL;
  PUSH_X87_STACK(reinterpret_cast<float64_t &>(log2_e));
  return memory;
}

DEF_SEM(DoFLDPI) {
  uint64_t pi = 0x400921fb54442d18ULL;
  PUSH_X87_STACK(reinterpret_cast<float64_t &>(pi));
  return memory;
}

DEF_SEM(DoFABS) {
  Write(X87_ST0, FAbs(Read(X87_ST0)));
  return memory;
}

DEF_SEM(DoFCHS) {
  Write(X87_ST0, FNeg(Read(X87_ST0)));
  return memory;
}

DEF_SEM(DoFCOS) {
  Write(X87_ST0, __builtin_cos(Read(X87_ST0)));
  return memory;
}

DEF_SEM(DoFSIN) {
  Write(X87_ST0, __builtin_sin(Read(X87_ST0)));
  return memory;
}

DEF_SEM(DoFPTAN) {
  Write(X87_ST0, __builtin_tan(Read(X87_ST0)));
  PUSH_X87_STACK(1.0);
  return memory;
}

DEF_SEM(DoFPATAN) {
  Write(X87_ST1, __builtin_atan(FDiv(Read(X87_ST1), Read(X87_ST0))));
  (void) POP_X87_STACK();
  return memory;
}

DEF_SEM(DoFSQRT) {
  Write(X87_ST0, __builtin_sqrt(Read(X87_ST0)));
  return memory;
}

DEF_SEM(DoFSINCOS) {
  auto val = Read(X87_ST0);
  Write(X87_ST0, __builtin_sin(val));
  PUSH_X87_STACK(__builtin_cos(val));
  return memory;
}

DEF_SEM(DoFSCALE) {
  auto st1_int = __builtin_trunc(Read(X87_ST1));  // Round toward zero.
  auto shift = __builtin_exp2(st1_int);
  Write(X87_ST0, FMul(Read(X87_ST0), shift));
  return memory;
}

DEF_SEM(DoF2XM1) {
  Write(X87_ST0, FSub(__builtin_exp2(Read(X87_ST0)), 1.0));
  return memory;
}

DEF_SEM(DoFPREM) {
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

DEF_SEM(DoFPREM1) {
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

DEF_SEM(FPU_NOP) {
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


DEF_ISEL(FILD_ST0_MEMmem16int) = FILD<M16>;
DEF_ISEL(FILD_ST0_MEMmem32int) = FILD<M32>;
DEF_ISEL(FILD_ST0_MEMm64int) = FILD<M64>;

DEF_ISEL(FLD_ST0_MEMmem32real) = FLD<MF32>;
DEF_ISEL(FLD_ST0_X87) = FLD<RF80>;
DEF_ISEL(FLD_ST0_MEMm64real) = FLD<MF64>;
DEF_ISEL(FLD_ST0_MEMmem80real) = FLD<MF80>;

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
DEF_SEM(FSUB, RF80W dst, RF80 src1, T src2) {
  Write(dst, Read(src1) - Float64(Read(src2)));
  return memory;
}

template <typename T>
DEF_SEM(FSUBP, RF80W dst, RF80 src1, T src2) {
  memory = FSUB<T>(memory, state, dst, src1, src2);
  (void) POP_X87_STACK();
  return memory;
}

template <typename T>
DEF_SEM(FISUB, RF80W dst, RF80 src1, T src2) {
  Write(dst, Read(src1) - Float64(Signed(Read(src2))));
  return memory;
}

template <typename T>
DEF_SEM(FSUBR, RF80W dst, RF80 src1, T src2) {
  Write(dst, Float64(Read(src2) - Read(src1)));
  return memory;
}

template <typename T>
DEF_SEM(FSUBRP, RF80W dst, RF80 src1, T src2) {
  memory = FSUBR<T>(memory, state, dst, src1, src2);
  (void) POP_X87_STACK();
  return memory;
}

template <typename T>
DEF_SEM(FISUBR, RF80W dst, RF80 src1, T src2) {
  Write(dst, Float64(Signed(Read(src2))) - Read(src1));
  return memory;
}
}  // namespace

DEF_ISEL(FSUB_ST0_MEMmem32real) = FSUB<MF32>;
DEF_ISEL(FSUB_ST0_MEMm64real) = FSUB<MF64>;
DEF_ISEL(FSUB_ST0_X87) = FSUB<RF80>;
DEF_ISEL(FSUB_X87_ST0) = FSUB<RF80>;
DEF_ISEL(FSUBP_X87_ST0) = FSUBP<RF80>;

DEF_ISEL(FSUBR_ST0_MEMmem32real) = FSUBR<MF32>;
DEF_ISEL(FSUBR_ST0_MEMm64real) = FSUBR<MF64>;
DEF_ISEL(FSUBR_ST0_X87) = FSUBR<RF80>;
DEF_ISEL(FSUBR_X87_ST0) = FSUBR<RF80>;
DEF_ISEL(FSUBRP_X87_ST0) = FSUBRP<RF80>;

DEF_ISEL(FISUB_ST0_MEMmem32int) = FISUB<M32>;
DEF_ISEL(FISUB_ST0_MEMmem16int) = FISUB<M16>;
DEF_ISEL(FISUBR_ST0_MEMmem32int) = FISUBR<M32>;
DEF_ISEL(FISUBR_ST0_MEMmem16int) = FISUBR<M16>;

namespace {
template <typename T>
DEF_SEM(FADD, RF80W dst, RF80 src1, T src2) {
  Write(dst, Read(src1) + Float64(Read(src2)));
//  state.sw.c1 = 1;
  state.sw.c0 = UUndefined8();
  state.sw.c2 = UUndefined8();
  state.sw.c3 = UUndefined8();
  return memory;
}

template <typename T>
DEF_SEM(FADDP, RF80W dst, RF80 src1, T src2) {
  memory = FADD<T>(memory, state, dst, src1, src2);
  (void) POP_X87_STACK();
  return memory;
}

template <typename T>
DEF_SEM(FIADD, RF80W dst, RF80 src1, T src2) {
  Write(dst, Read(src1) + Float64(Signed(Read(src2))));
  return memory;
}

}  // namespace

DEF_ISEL(FADD_ST0_MEMmem32real) = FADD<MF32>;
DEF_ISEL(FADD_ST0_X87) = FADD<RF80>;
DEF_ISEL(FADD_ST0_MEMm64real) = FADD<MF64>;
DEF_ISEL(FADD_X87_ST0) = FADD<RF80>;
DEF_ISEL(FADDP_X87_ST0) = FADDP<RF80>;
DEF_ISEL(FIADD_ST0_MEMmem32int) = FIADD<M32>;
DEF_ISEL(FIADD_ST0_MEMmem16int) = FIADD<M16>;

namespace {
template <typename T>
DEF_SEM(FMUL, RF80W dst, RF80 src1, T src2) {
  Write(dst, Read(src1) * Float64(Read(src2)));
  return memory;
}

template <typename T>
DEF_SEM(FMULP, RF80W dst, RF80 src1, T src2) {
  memory = FMUL<T>(memory, state, dst, src1, src2);
  (void) POP_X87_STACK();
  return memory;
}

template <typename T>
DEF_SEM(FIMUL, RF80W dst, RF80 src1, T src2) {
  Write(dst, Read(src1) * Float64(Signed(Read(src2))));
  return memory;
}

}  // namespace

DEF_ISEL(FMUL_ST0_MEMmem32real) = FMUL<MF32>;
DEF_ISEL(FMUL_ST0_X87) = FMUL<RF80>;
DEF_ISEL(FMUL_ST0_MEMm64real) = FMUL<MF64>;
DEF_ISEL(FMUL_X87_ST0) = FMUL<RF80>;
DEF_ISEL(FMULP_X87_ST0) = FMULP<RF80>;
DEF_ISEL(FIMUL_ST0_MEMmem32int) = FIMUL<M32>;
DEF_ISEL(FIMUL_ST0_MEMmem16int) = FIMUL<M16>;

namespace {

template <typename T>
DEF_SEM(FDIV, RF80W dst, RF80 src1, T src2) {
  Write(dst, Read(src1) / Float64(Read(src2)));
  return memory;
}

template <typename T>
DEF_SEM(FDIVP, RF80W dst, RF80 src1, T src2) {
  memory = FDIV<T>(memory, state, dst, src1, src2);
  (void) POP_X87_STACK();
  return memory;
}

template <typename T>
DEF_SEM(FIDIV, RF80W dst, RF80 src1, T src2) {
  Write(dst, Read(src1) / Float64(Signed(Read(src2))));
  return memory;
}

template <typename T>
DEF_SEM(FDIVR, RF80W dst, RF80 src1, T src2) {
  Write(dst, Float64(Read(src2) / Read(src1)));
  return memory;
}

template <typename T>
DEF_SEM(FDIVRP, RF80W dst, RF80 src1, T src2) {
  memory = FDIVR<T>(memory, state, dst, src1, src2);
  (void) POP_X87_STACK();
  return memory;
}

template <typename T>
DEF_SEM(FIDIVR, RF80W dst, RF80 src1, T src2) {
  Write(dst, Float64(Signed(Read(src2))) / Read(src1));
  return memory;
}

}  // namespace

DEF_ISEL(FDIV_ST0_MEMmem32real) = FDIV<MF32>;
DEF_ISEL(FDIV_ST0_MEMm64real) = FDIV<MF64>;
DEF_ISEL(FDIV_ST0_X87) = FDIV<RF80>;
DEF_ISEL(FDIV_X87_ST0) = FDIV<RF80>;
DEF_ISEL(FDIVP_X87_ST0) = FDIVP<RF80>;

DEF_ISEL(FDIVR_ST0_MEMmem32real) = FDIVR<MF32>;
DEF_ISEL(FDIVR_ST0_MEMm64real) = FDIVR<MF64>;
DEF_ISEL(FDIVR_ST0_X87) = FDIVR<RF80>;
DEF_ISEL(FDIVR_X87_ST0) = FDIVR<RF80>;
DEF_ISEL(FDIVRP_X87_ST0) = FDIVRP<RF80>;

DEF_ISEL(FIDIV_ST0_MEMmem32int) = FIDIV<M32>;
DEF_ISEL(FIDIV_ST0_MEMmem16int) = FIDIV<M16>;
DEF_ISEL(FIDIVR_ST0_MEMmem32int) = FIDIVR<M32>;
DEF_ISEL(FIDIVR_ST0_MEMmem16int) = FIDIVR<M16>;

namespace {

template <typename T>
DEF_SEM(FST, T dst, RF80 src) {
  typedef typename BaseType<T>::BT BT;
  Write(dst, BT(Read(src)));
  return memory;
}

template <typename T>
DEF_SEM(FSTP, T dst, RF80 src) {
  memory = FST<T>(memory, state, dst, src);
  (void) POP_X87_STACK();
  return memory;
}

DEF_SEM(FISTm16, M16W dst, RF80 src) {
  Write(dst, Unsigned(Float64ToInt16(FRoundUsingMode64(Read(src)))));
  return memory;
}

DEF_SEM(FISTm32, M32W dst, RF80 src) {
  Write(dst, Unsigned(Float64ToInt32(FRoundUsingMode64(Read(src)))));
  return memory;
}

DEF_SEM(FISTPm16, M16W dst, RF80 src) {
  memory = FISTm16(memory, state, dst, src);
  (void) POP_X87_STACK();
  return memory;
}

DEF_SEM(FISTPm32, M32W dst, RF80 src) {
  memory = FISTm32(memory, state, dst, src);
  (void) POP_X87_STACK();
  return memory;
}

DEF_SEM(FISTPm64, M64W dst, RF80 src) {
  Write(dst, Unsigned(Float64ToInt64(FRoundUsingMode64(Read(src)))));
  (void) POP_X87_STACK();
  return memory;
}

DEF_SEM(DoFINCSTP) {
  (void) POP_X87_STACK();
  return memory;
}

DEF_SEM(DoFDECSTP) {
  PUSH_X87_STACK(X87_ST7);
  return memory;
}

}  // namespace

DEF_ISEL(FSTP_MEMmem32real_ST0) = FSTP<MF32W>;
DEF_ISEL(FSTP_MEMmem80real_ST0) = FSTP<MF80W>;
DEF_ISEL(FSTP_MEMm64real_ST0) = FSTP<MF64W>;
DEF_ISEL(FSTP_X87_ST0) = FSTP<RF80W>;
DEF_ISEL(FSTP_X87_ST0_DFD0) = FSTP<RF80W>;
DEF_ISEL(FSTP_X87_ST0_DFD1) = FSTP<RF80W>;
DEF_ISEL(FST_MEMmem32real_ST0) = FST<MF32W>;
DEF_ISEL(FST_MEMm64real_ST0) = FST<MF64W>;
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

namespace {
DEF_SEM(FISTTPm16, M16W dst, RF80 src) {
  Write(dst, Unsigned(Float64ToInt16(FTruncTowardZero64(Read(src)))));
  (void) POP_X87_STACK();
  return memory;
}

DEF_SEM(FISTTPm32, M32W dst, RF80 src) {
  Write(dst, Unsigned(Float64ToInt32(FTruncTowardZero64(Read(src)))));
  (void) POP_X87_STACK();
  return memory;
}

DEF_SEM(FISTTPm64, M64W dst, RF80 src) {
  Write(dst, Unsigned(Float64ToInt64(FTruncTowardZero64(Read(src)))));
  (void) POP_X87_STACK();
  return memory;
}

}  // namespace

DEF_ISEL(FISTTP_MEMmem16int_ST0) = FISTTPm16;
DEF_ISEL(FISTTP_MEMmem32int_ST0) = FISTTPm32;
DEF_ISEL(FISTTP_MEMm64int_ST0) = FISTTPm64;

namespace {

DEF_SEM(FXCH, RF80W dst1, RF80 src1, RF80W dst2, RF80 src2) {
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

DEF_SEM(DoFXAM) {
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

DEF_HELPER(UnorderedCompare, float64_t src1, float64_t src2) -> void {
  if (__builtin_isunordered(src1, src2)) {
    state.sw.c0 = 1;
    state.sw.c2 = 1;
    state.sw.c3 = 1;
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

DEF_SEM(DoFTST) {
  auto st0 = Read(X87_ST0);
  state.sw.c1 = 0;
  UnorderedCompare(memory, state, st0, 0.0);
  return memory;
}

template <typename S2>
DEF_SEM(FUCOM, RF80 src1, S2 src2) {
  auto st0 = Read(src1);
  auto sti = Float64(Read(src2));
  // Note:  Don't modify c1. The docs only state that c1=0 if there was a
  //        stack underflow.
  UnorderedCompare(memory, state, st0, sti);
  return memory;
}

template <typename S2>
DEF_SEM(FUCOMP, RF80 src1, S2 src2) {
  memory = FUCOM<S2>(memory, state, src1, src2);
  (void) POP_X87_STACK();
  return memory;
}

DEF_SEM(DoFUCOMPP) {
  RF80 st0 = {X87_ST0};
  RF80 st1 = {X87_ST1};
  memory = FUCOM<RF80>(memory, state, st0, st1);
  (void) POP_X87_STACK();
  (void) POP_X87_STACK();
  return memory;
}

DEF_HELPER(UnorderedCompareEflags, float64_t src1, float64_t src2) -> void {
  if (__builtin_isunordered(src1, src2)) {
    FLAG_CF = 1;
    FLAG_PF = 1;
    FLAG_ZF = 1;
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

DEF_SEM(FUCOMI, RF80 src1, RF80 src2) {
  auto st0 = Read(src1);
  auto sti = Read(src2);
  state.sw.c1 = 0;
  FLAG_OF = 0;
  FLAG_SF = 0;
  FLAG_AF = 0;
  UnorderedCompareEflags(memory, state, st0, sti);
  return memory;
}

DEF_SEM(FUCOMIP, RF80 src1, RF80 src2) {
  memory = FUCOMI(memory, state, src1, src2);
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

DEF_ISEL(FCOMI_ST0_X87) = FUCOMI;
DEF_ISEL(FCOMIP_ST0_X87) = FUCOMIP;

DEF_ISEL(FCOM_ST0_X87) = FUCOM<RF80>;
DEF_ISEL(FCOM_ST0_X87_DCD0) = FUCOM<RF80>;
DEF_ISEL(FCOM_ST0_MEMmem32real) = FUCOM<MF32>;
DEF_ISEL(FCOM_ST0_MEMm64real) = FUCOM<MF64>;

DEF_ISEL(FCOMP_ST0_X87) = FUCOMP<RF80>;
DEF_ISEL(FCOMP_ST0_MEMmem32real) = FUCOMP<MF32>;
DEF_ISEL(FCOMP_ST0_MEMm64real) = FUCOMP<MF64>;
DEF_ISEL(FCOMP_ST0_X87_DCD1) = FUCOMP<RF80>;
DEF_ISEL(FCOMP_ST0_X87_DED0) = FUCOMP<RF80>;
DEF_ISEL(FCOMPP) = DoFUCOMPP;

namespace {

template <typename D>
DEF_SEM(FNSTSW, D dst) {
  FPUStatusWord sw = {};
  sw.c0 = state.sw.c0;
  sw.c1 = state.sw.c1;
  sw.c2 = state.sw.c2;
  sw.c3 = state.sw.c3;
  Write(dst, sw.flat);
  return memory;
}

DEF_SEM(FNSTCW, M16W dst) {
  FPUControlWord cw = {};
  cw.flat = 0x027F_u16;  // Our default, with double-precision.
  switch (fegetround()) {
    default:
    case FE_TONEAREST:
      cw.rc = kFPURoundToNearestEven;
      break;
    case FE_DOWNWARD:
      cw.rc = kFPURoundDownNegInf;
      break;
    case FE_UPWARD:
      cw.rc = kFPURoundUpInf;
      break;
    case FE_TOWARDZERO:
      cw.rc = kFPURoundToZero;
      break;
  }
  Write(dst, cw.flat);
  return memory;
}

DEF_SEM(FLDCW, M16 cwd) {
  FPUControlWord cw = {};
  cw.flat = Read(cwd);
  int rounding_mode = FE_TONEAREST;
  switch (cw.rc) {
    case kFPURoundToNearestEven:
      rounding_mode = FE_TONEAREST;
      break;

    case kFPURoundDownNegInf:
      rounding_mode = FE_DOWNWARD;
      break;

    case kFPURoundUpInf:
      rounding_mode = FE_UPWARD;
      break;

    case kFPURoundToZero:
      rounding_mode = FE_TOWARDZERO;
      break;
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

DEF_SEM(DoFRNDINT) {
  auto st0 = Read(X87_ST0);
  auto rounded = FRoundUsingMode64(st0);
  // state.sw.c1 = __builtin_isgreater(FAbs(rounded), FAbs(st0)) ? 1_u8 : 0_u8;
  Write(X87_ST0, rounded);
  return memory;
}

DEF_SEM(DoFYL2X) {
  auto st0 = Read(X87_ST0);
  auto st1 = Read(X87_ST1);
  Write(X87_ST1, FMul(st1, __builtin_log2(st0)));
  (void) POP_X87_STACK();
  return memory;
}

DEF_SEM(DoFYL2XP1) {
  auto st0 = Read(X87_ST0);
  auto st1 = Read(X87_ST1);
  Write(X87_ST1, FMul(st1, __builtin_log2(FAdd(st0, 1.0))));
  (void) POP_X87_STACK();
  return memory;
}

DEF_SEM(FFREE, RF80) {
  return memory;
}

DEF_SEM(FFREEP, RF80) {
  (void) POP_X87_STACK();
  return memory;
}

}  // namespace

DEF_ISEL(FRNDINT) = DoFRNDINT;
DEF_ISEL(FYL2X) = DoFYL2X;
DEF_ISEL(FYL2XP1) = DoFYL2XP1;

DEF_ISEL(FFREE_X87) = FFREE;
DEF_ISEL(FFREEP_X87) = FFREEP;

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
817 FNINIT FNINIT X87_ALU X87 X87 ATTRIBUTES: NOTSX X87_CONTROL X87_MMX_STATE_W X87_NOWAIT
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

#endif  // REMILL_ARCH_X86_SEMANTICS_X87_H_
