/* Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef REMILL_ARCH_X86_SEMANTICS_X87_H_
#define REMILL_ARCH_X86_SEMANTICS_X87_H_

#define PUSH_X87_STACK(x) \
  state.st.elems[7].val = state.st.elems[6].val ; \
  state.st.elems[6].val = state.st.elems[5].val ; \
  state.st.elems[5].val = state.st.elems[4].val ; \
  state.st.elems[4].val = state.st.elems[3].val ; \
  state.st.elems[3].val = state.st.elems[2].val ; \
  state.st.elems[2].val = state.st.elems[1].val ; \
  state.st.elems[1].val = state.st.elems[0].val ; \
  state.st.elems[0].val = x


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
}

template <typename T>
DEF_SEM(FLD, RF80W, T src1) {
  PUSH_X87_STACK(Float64(Read(src1)));
}

DEF_SEM(FLDLN2, RF80W) {
  uint64_t ln_2 = 0x3fe62e42fefa39efULL;
  PUSH_X87_STACK(reinterpret_cast<float64_t &>(ln_2));
}

DEF_SEM(FLD1, RF80W) {
  PUSH_X87_STACK(1.0);  // +1.0.
}

DEF_SEM(FLDZ, RF80W) {
  PUSH_X87_STACK(0.0);  // +0.0.
}

DEF_SEM(FLDLG2, RF80W) {
  uint64_t log10_2 = 0x3fd34413509f79ffULL;
  PUSH_X87_STACK(reinterpret_cast<float64_t &>(log10_2));
}

DEF_SEM(FLDL2T, RF80W) {
  uint64_t log2_10 = 0x400a934f0979a371ULL;
  PUSH_X87_STACK(reinterpret_cast<float64_t &>(log2_10));
}

DEF_SEM(FLDL2E, RF80W) {
  uint64_t log2_e = 0x3ff71547652b82feULL;
  PUSH_X87_STACK(reinterpret_cast<float64_t &>(log2_e));
}

DEF_SEM(FLDPI, RF80W) {
  uint64_t pi = 0x400921fb54442d18ULL;
  PUSH_X87_STACK(reinterpret_cast<float64_t &>(pi));
}

DEF_SEM(FABS, RF80W dst, RF80 src) {
  Write(dst, FAbs(Read(src)));
}

DEF_SEM(FCHS, RF80W dst, RF80 src) {
  Write(dst, FNeg(Read(src)));
}

DEF_SEM(FCOS, RF80W dst, RF80 src) {
  Write(dst, __builtin_cos(Read(src)));
}

DEF_SEM(FSIN, RF80W dst, RF80 src) {
  Write(dst, __builtin_sin(Read(src)));
}

DEF_SEM(FPTAN, RF80W dst, RF80 src, RF80W) {
  Write(dst, __builtin_tan(Read(src)));
  PUSH_X87_STACK(1.0);
}

DEF_SEM(FPATAN, RF80 st0, RF80W st1_dst, RF80 st1) {
  Write(st1_dst, __builtin_atan(FDiv(Read(st1), Read(st0))));
  (void) POP_X87_STACK();
}


//DEF_SEM(FLDCW, M16 cwd) {
//  (void) Read(cwd);
//}
//
//DEF_SEM(FSTCW, M16W cwd) {
//  Write(cwd, 0x27F_u16);
//}

DEF_SEM(FPU_NOP) {}

}  // namespace

//DEF_ISEL(FLDCW_MEMmem16) = FLDCW;
//DEF_ISEL(FNSTCW_MEMmem16) = FSTCW;


DEF_ISEL(FILD_ST0_MEMmem16int) = FILD<M16>;
DEF_ISEL(FILD_ST0_MEMmem32int) = FILD<M32>;
DEF_ISEL(FILD_ST0_MEMm64int) = FILD<M64>;

DEF_ISEL(FLD_ST0_MEMmem32real) = FLD<MF32>;
DEF_ISEL(FLD_ST0_X87) = FLD<RF80>;
DEF_ISEL(FLD_ST0_MEMm64real) = FLD<MF64>;
DEF_ISEL(FLD_ST0_MEMmem80real) = FLD<MF80>;

DEF_ISEL(FLDLN2_ST0) = FLDLN2;
DEF_ISEL(FLD1_ST0) = FLD1;
DEF_ISEL(FLDZ_ST0) = FLDZ;
DEF_ISEL(FLDLG2_ST0) = FLDLG2;
DEF_ISEL(FLDL2T_ST0) = FLDL2T;
DEF_ISEL(FLDL2E_ST0) = FLDL2E;
DEF_ISEL(FLDPI_ST0) = FLDPI;

DEF_ISEL(FNOP) = FPU_NOP;
DEF_ISEL(FWAIT) = FPU_NOP;
DEF_ISEL(FABS_ST0) = FABS;
DEF_ISEL(FCHS_ST0) = FCHS;
DEF_ISEL(FCOS_ST0) = FCOS;
DEF_ISEL(FSIN_ST0) = FSIN;
DEF_ISEL(FPTAN_ST0_ST1) = FPTAN;
DEF_ISEL(FPATAN_ST0_ST1) = FPATAN;

namespace {

template <typename T>
DEF_SEM(FSUB, RF80W dst, RF80 src1, T src2) {
  Write(dst, Read(src1) - Float64(Read(src2)));
}

template <typename T>
DEF_SEM(FSUBP, RF80W dst, RF80 src1, T src2) {
  FSUB<T>(memory, state, dst, src1, src2);
  (void) POP_X87_STACK();
}

template <typename T>
DEF_SEM(FISUB, RF80W dst, RF80 src1, T src2) {
  Write(dst, Read(src1) - Float64(Signed(Read(src2))));
}

template <typename T>
DEF_SEM(FSUBR, RF80W dst, RF80 src1, T src2) {
  Write(dst, Float64(Read(src2) - Read(src1)));
}

template <typename T>
DEF_SEM(FSUBRP, RF80W dst, RF80 src1, T src2) {
  FSUBR<T>(memory, state, dst, src1, src2);
  (void) POP_X87_STACK();
}

template <typename T>
DEF_SEM(FISUBR, RF80W dst, RF80 src1, T src2) {
  Write(dst, Float64(Signed(Read(src2))) - Read(src1));
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
}

template <typename T>
DEF_SEM(FADDP, RF80W dst, RF80 src1, T src2) {
  FADD<T>(memory, state, dst, src1, src2);
  (void) POP_X87_STACK();
}

template <typename T>
DEF_SEM(FIADD, RF80W dst, RF80 src1, T src2) {
  Write(dst, Read(src1) + Float64(Signed(Read(src2))));
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
}

template <typename T>
DEF_SEM(FMULP, RF80W dst, RF80 src1, T src2) {
  FMUL<T>(memory, state, dst, src1, src2);
  (void) POP_X87_STACK();
}

template <typename T>
DEF_SEM(FIMUL, RF80W dst, RF80 src1, T src2) {
  Write(dst, Read(src1) * Float64(Signed(Read(src2))));
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
}

template <typename T>
DEF_SEM(FDIVP, RF80W dst, RF80 src1, T src2) {
  FDIV<T>(memory, state, dst, src1, src2);
  (void) POP_X87_STACK();
}

template <typename T>
DEF_SEM(FIDIV, RF80W dst, RF80 src1, T src2) {
  Write(dst, Read(src1) / Float64(Signed(Read(src2))));
}

template <typename T>
DEF_SEM(FDIVR, RF80W dst, RF80 src1, T src2) {
  Write(dst, Float64(Read(src2) / Read(src1)));
}

template <typename T>
DEF_SEM(FDIVRP, RF80W dst, RF80 src1, T src2) {
  FDIVR<T>(memory, state, dst, src1, src2);
  (void) POP_X87_STACK();
}

template <typename T>
DEF_SEM(FIDIVR, RF80W dst, RF80 src1, T src2) {
  Write(dst, Float64(Signed(Read(src2))) / Read(src1));
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
}

template <typename T>
DEF_SEM(FSTP, T dst, RF80 src) {
  FST<T>(memory, state, dst, src);
  (void) POP_X87_STACK();
}

DEF_SEM(FISTm16, M16W dst, RF80 src) {
  Write(dst, Unsigned(Float64ToInt16(FRoundNearest64(Read(src)))));
}

DEF_SEM(FISTm32, M32W dst, RF80 src) {
  Write(dst, Unsigned(Float64ToInt32(FRoundNearest64(Read(src)))));
}

DEF_SEM(FISTPm16, M16W dst, RF80 src) {
  FISTm16(memory, state, dst, src);
  (void) POP_X87_STACK();
}

DEF_SEM(FISTPm32, M32W dst, RF80 src) {
  FISTm32(memory, state, dst, src);
  (void) POP_X87_STACK();
}

DEF_SEM(FISTPm64, M64W dst, RF80 src) {
  Write(dst, Unsigned(Float64ToInt64(FRoundNearest64(Read(src)))));
  (void) POP_X87_STACK();
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


#if 0

1085 FISTTP FISTTP_MEMmem32int_ST0 X87_ALU SSE3 SSE3 ATTRIBUTES: NOTSX
1086 FISTTP FISTTP_MEMm64int_ST0 X87_ALU SSE3 SSE3 ATTRIBUTES: NOTSX UNALIGNED
1087 FISTTP FISTTP_MEMmem16int_ST0 X87_ALU SSE3 SSE3 ATTRIBUTES: NOTSX

namespace {

template <typename T>
DEF_SEM(FICOM_ST0_int, RF80 src1, T src2) {
  auto lhs = Read(src1);
  auto rhs = Float64(Signed(Read(src2)));
  uint16_t mask = 0;
  if (__builtin_isunordered(lhs, rhs)) {
    mask = 0x4500_u16;
  } else if (FCmpGt(lhs, rhs)) {
    mask = 0;
  } else if (FCmpLt(lhs, rhs)) {
    mask = 0x0100_u16;
  } else if (FCmpEq(lhs, rhs)) {
    mask = 0x4000_u16;
  } else {
    // TODO(pag): Hrmmm.
  }
  Write(state.fpu.swd.flat, UOr(mask, UAnd(state.fpu.swd.flat, 0xb8ff_u16)));
}

}  // namespace

DEF_ISEL(FICOM_ST0_MEMmem16int) = FICOM_ST0_int<M16>;
DEF_ISEL(FICOM_ST0_MEMmem32int) = FICOM_ST0_int<M32>;

DEF_ISEL_SEM(FICOMP_ST0_MEMmem16int, RF80 src1, M16 src2) {
  FICOM_ST0_int<M16>(memory, state, src1, src2);
  (void) POP_X87_STACK(_);
}

DEF_ISEL_SEM(FICOMP_ST0_MEMmem32int, RF80 src1, M32 src2) {
  FICOM_ST0_int<M32>(memory, state, src1, src2);
  (void) POP_X87_STACK(_);
}

DEF_ISEL_SEM(FUCOM_ST0_X87, RF80 src1, RF80 src2) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  uint16_t mask = 0;
  if (__builtin_isunordered(lhs, rhs)) {
    mask = 0x4500_u16;
  } else if (FCmpGt(lhs, rhs)) {
    mask = 0;
  } else if (FCmpLt(lhs, rhs)) {
    mask = 0x0100_u16;
  } else if (FCmpEq(lhs, rhs)) {
    mask = 0x4000_u16;
  } else {
    // TODO(pag): Hrmmm.
  }

  // TODO(pag): Currently ignore stack underflow detection.
  Write(state.fpu.swd.flat, UOr(mask, UAnd(state.fpu.swd.flat, 0xbaff_u16)));
}

DEF_ISEL_SEM(FUCOMP_ST0_X87, RF80 src1, RF80 src2) {
  FUCOM_ST0_X87(memory, state, src1, src2);
  (void) POP_X87_STACK(_);
}

DEF_ISEL_SEM(FCOMPP_ST0_ST1, RF80 src1, RF80 src2) {
  FUCOM_ST0_X87(memory, state, src1, src2);
  (void) POP_X87_STACK(_);
  (void) POP_X87_STACK(_);
}

DEF_ISEL_SEM(FUCOMI_ST0_X87, RF80 src1, RF80 src2) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  if (__builtin_isunordered(lhs, rhs)) {
    Write(FLAG_ZF, true);
    Write(FLAG_PF, true);
    Write(FLAG_CF, true);
  } else if (FCmpGt(lhs, rhs)) {
    Write(FLAG_ZF, false);
    Write(FLAG_PF, false);
    Write(FLAG_CF, false);
  } else if (FCmpLt(lhs, rhs)) {
    Write(FLAG_ZF, false);
    Write(FLAG_PF, false);
    Write(FLAG_CF, true);
  } else if (FCmpEq(lhs, rhs)) {
    Write(FLAG_ZF, true);
    Write(FLAG_PF, false);
    Write(FLAG_CF, false);
  } else {
    // TODO(pag): Hrmmm.
  }
}

DEF_ISEL_SEM(FUCOMIP_ST0_X87, RF80 src1, RF80 src2) {
  FUCOMI_ST0_X87(memory, state, src1, src2);
  (void) POP_X87_STACK(_);
}

// TODO(pag): This is wrong but hopefully right enough.
DEF_ISEL(FCOMI_ST0_X87) = FUCOMI_ST0_X87;
DEF_ISEL(FCOMIP_ST0_X87) = FUCOMIP_ST0_X87;

#endif

/*
1200 FLDENV FLDENV_MEMmem14 X87_ALU X87 X87 ATTRIBUTES: NOTSX X87_CONTROL
1201 FLDENV FLDENV_MEMmem28 X87_ALU X87 X87 ATTRIBUTES: NOTSX X87_CONTROL
88 FCOMI  X87_ALU X87 PPRO ATTRIBUTES: NOTSX
232 FCOMIP  X87_ALU X87 PPRO ATTRIBUTES: NOTSX
366 FCOMPP  X87_ALU X87 X87 ATTRIBUTES: NOTSX
394 FCOMP FCOMP_ST0_MEMmem32real X87_ALU X87 X87 ATTRIBUTES: NOTSX
395 FCOMP FCOMP_ST0_X87 X87_ALU X87 X87 ATTRIBUTES: NOTSX
396 FCOMP FCOMP_ST0_X87_DCD1 X87_ALU X87 X87 ATTRIBUTES: NOTSX
397 FCOMP FCOMP_ST0_X87_DED0 X87_ALU X87 X87 ATTRIBUTES: NOTSX
398 FCOMP FCOMP_ST0_MEMm64real X87_ALU X87 X87 ATTRIBUTES: NOTSX
734 FCOM FCOM_ST0_MEMmem32real X87_ALU X87 X87 ATTRIBUTES: NOTSX
735 FCOM FCOM_ST0_MEMm64real X87_ALU X87 X87 ATTRIBUTES: NOTSX
736 FCOM FCOM_ST0_X87 X87_ALU X87 X87 ATTRIBUTES: NOTSX
737 FCOM FCOM_ST0_X87_DCD0 X87_ALU X87 X87 ATTRIBUTES: NOTSX
102 FNSAVE FNSAVE_MEMmem94 X87_ALU X87 X87 ATTRIBUTES: NOTSX X87_CONTROL X87_MMX_STATE_R X87_MMX_STATE_W X87_NOWAIT
103 FNSAVE FNSAVE_MEMmem108 X87_ALU X87 X87 ATTRIBUTES: NOTSX X87_CONTROL X87_MMX_STATE_R X87_MMX_STATE_W X87_NOWAIT
194 FYL2X FYL2X_ST0_ST1 X87_ALU X87 X87 ATTRIBUTES: NOTSX
357 FXTRACT FXTRACT_ST0_ST1 X87_ALU X87 X87 ATTRIBUTES: NOTSX
401 FENI8087_NOP FENI8087_NOP X87_ALU X87 X87 ATTRIBUTES: NOP NOTSX
529 FYL2XP1 FYL2XP1_ST0_ST1 X87_ALU X87 X87 ATTRIBUTES: NOTSX
538 FRNDINT FRNDINT_ST0 X87_ALU X87 X87 ATTRIBUTES: NOTSX
546 FSETPM287_NOP FSETPM287_NOP X87_ALU X87 X87 ATTRIBUTES: NOP NOTSX
595 FNCLEX FNCLEX X87_ALU X87 X87 ATTRIBUTES: NOTSX X87_CONTROL X87_NOWAIT
718 FSCALE FSCALE_ST0_ST1 X87_ALU X87 X87 ATTRIBUTES: NOTSX
747 FXAM FXAM_ST0 X87_ALU X87 X87 ATTRIBUTES: NOTSX
761 FFREE FFREE_X87 X87_ALU X87 X87 ATTRIBUTES: NOTSX X87_CONTROL
762 FFREEP FFREEP_X87 X87_ALU X87 X87 ATTRIBUTES: NOTSX X87_CONTROL
769 FPREM1 FPREM1_ST0_ST1 X87_ALU X87 X87 ATTRIBUTES: NOTSX
817 FNINIT FNINIT X87_ALU X87 X87 ATTRIBUTES: NOTSX X87_CONTROL X87_MMX_STATE_W X87_NOWAIT
942 FNSTSW FNSTSW_MEMmem16 X87_ALU X87 X87 ATTRIBUTES: NOTSX X87_CONTROL X87_NOWAIT
943 FNSTSW FNSTSW_AX X87_ALU X87 X87 ATTRIBUTES: NOTSX X87_CONTROL X87_NOWAIT
1040 FSTPNCE FSTPNCE_X87_ST0 X87_ALU X87 X87 ATTRIBUTES: NOTSX
1110 F2XM1 F2XM1_ST0 X87_ALU X87 X87 ATTRIBUTES: NOTSX
1115 FPREM FPREM_ST0_ST1 X87_ALU X87 X87 ATTRIBUTES: NOTSX
1148 FINCSTP FINCSTP X87_ALU X87 X87 ATTRIBUTES: NOTSX X87_CONTROL
1172 FTST FTST_ST0 X87_ALU X87 X87 ATTRIBUTES: NOTSX
1200 FLDENV FLDENV_MEMmem14 X87_ALU X87 X87 ATTRIBUTES: NOTSX X87_CONTROL
1201 FLDENV FLDENV_MEMmem28 X87_ALU X87 X87 ATTRIBUTES: NOTSX X87_CONTROL
1261 FDIVRP FDIVRP_X87_ST0 X87_ALU X87 X87 ATTRIBUTES: NOTSX
1262 FBLD FBLD_ST0_MEMmem80dec X87_ALU X87 X87 ATTRIBUTES: NOTSX
1286 FDISI8087_NOP FDISI8087_NOP X87_ALU X87 X87 ATTRIBUTES: NOP NOTSX
1404 FLDCW FLDCW_MEMmem16 X87_ALU X87 X87 ATTRIBUTES: NOTSX X87_CONTROL
1418 FSQRT FSQRT_ST0 X87_ALU X87 X87 ATTRIBUTES: NOTSX
1593 FRSTOR FRSTOR_MEMmem94 X87_ALU X87 X87 ATTRIBUTES: NOTSX X87_CONTROL X87_MMX_STATE_W
1594 FRSTOR FRSTOR_MEMmem108 X87_ALU X87 X87 ATTRIBUTES: NOTSX X87_CONTROL X87_MMX_STATE_W
1606 FXCH FXCH_ST0_X87 X87_ALU X87 X87 ATTRIBUTES: NOTSX
1607 FXCH FXCH_ST0_X87_DFC1 X87_ALU X87 X87 ATTRIBUTES: NOTSX
1608 FXCH FXCH_ST0_X87_DDC1 X87_ALU X87 X87 ATTRIBUTES: NOTSX
1684 FDECSTP FDECSTP X87_ALU X87 X87 ATTRIBUTES: NOTSX X87_CONTROL
1735 FBSTP FBSTP_MEMmem80dec_ST0 X87_ALU X87 X87 ATTRIBUTES: NOTSX
1743 FUCOMPP FUCOMPP_ST0_ST1 X87_ALU X87 X87 ATTRIBUTES: NOTSX
1762 FNSTENV FNSTENV_MEMmem14 X87_ALU X87 X87 ATTRIBUTES: NOTSX X87_CONTROL X87_NOWAIT
1763 FNSTENV FNSTENV_MEMmem28 X87_ALU X87 X87 ATTRIBUTES: NOTSX X87_CONTROL X87_NOWAIT
1860 FSINCOS FSINCOS_ST0_ST1 X87_ALU X87 X87 ATTRIBUTES: NOTSX
1891 FNSTCW FNSTCW_MEMmem16 X87_ALU X87 X87 ATTRIBUTES: NOTSX X87_CONTROL X87_NOWAIT
 */

#endif  // REMILL_ARCH_X86_SEMANTICS_X87_H_
