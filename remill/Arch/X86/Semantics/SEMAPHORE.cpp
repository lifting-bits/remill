/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

namespace {
/*
912 CMPXCHG CMPXCHG_MEMb_GPR8 SEMAPHORE BASE I486REAL ATTRIBUTES: BYTEOP LOCKABLE
 4
  0 MEM0 EXPLICIT RCW IMM_CONST U8
  1 REG0 EXPLICIT R NT_LOOKUP_FN INVALID GPR8_R
  2 REG1 SUPPRESSED RCW REG INVALID AL
  3 REG2 SUPPRESSED W NT_LOOKUP_FN INVALID RFLAGS

 */

#define MAKE_CMPXCHG_XAX(xax) \
    template <typename D, typename S1, typename S2> \
    DEF_SEM(CMPXCHG_ ## xax, D dst, S1 src1, S2 src2) { \
      auto curr_val = Read(src1); \
      auto desired_val = Read(src2); \
      auto check_val = Read(REG_ ## xax); \
      auto replace = UCmpEq(curr_val, check_val); \
      Write(FLAG_ZF, replace); \
      WriteZExt(dst, Select(replace, desired_val, curr_val)); \
      WriteZExt(REG_ ## xax, Select(replace, curr_val, check_val)); \
    }

MAKE_CMPXCHG_XAX(AL)
MAKE_CMPXCHG_XAX(AX)
MAKE_CMPXCHG_XAX(EAX)
IF_64BIT(MAKE_CMPXCHG_XAX(RAX))

}  // namespace

DEF_ISEL(CMPXCHG_MEMb_GPR8) = CMPXCHG_AL<M8W, M8, R8>;
DEF_ISEL(CMPXCHG_GPR8_GPR8) = CMPXCHG_AL<R8W, R8, R8>;

DEF_ISEL(CMPXCHG_MEMv_GPRv_8) = CMPXCHG_AL<M8W, M8, R8>;
DEF_ISEL(CMPXCHG_GPRv_GPRv_8) = CMPXCHG_AL<R8W, R8, R8>;

DEF_ISEL(CMPXCHG_MEMv_GPRv_16) = CMPXCHG_AX<M16W, M16, R16>;
DEF_ISEL(CMPXCHG_GPRv_GPRv_16) = CMPXCHG_AX<R16W, R16, R16>;

DEF_ISEL(CMPXCHG_MEMv_GPRv_32) = CMPXCHG_EAX<M32W, M32, R32>;
DEF_ISEL(CMPXCHG_GPRv_GPRv_32) = CMPXCHG_EAX<R32W, R32, R32>;

IF_64BIT(DEF_ISEL(CMPXCHG_MEMv_GPRv_64) = CMPXCHG_RAX<M64W, M64, R64>;)
IF_64BIT(DEF_ISEL(CMPXCHG_GPRv_GPRv_64) = CMPXCHG_RAX<R64W, R64, R64>;)

/*
  0 MEM0 EXPLICIT RCW IMM_CONST I32
  1 REG0 SUPPRESSED RCW REG INVALID RDX
  2 REG1 SUPPRESSED RCW REG INVALID RAX
  3 REG2 SUPPRESSED R REG INVALID RCX
  4 REG3 SUPPRESSED R REG INVALID RBX
  5 REG4 SUPPRESSED W NT_LOOKUP_FN INVALID RFLAGS
 */

DEF_ISEL_SEM(CMPXCHG8B_MEMq, M64W dst, M64 src1) {
  auto curr_val = Read(src1);
  auto xdx = Read(REG_EDX);
  auto xax = Read(REG_EAX);
  auto xcx = Read(REG_ECX);
  auto xbx = Read(REG_EBX);
  auto desired_val = UOr(UShl(ZExt(xcx), 32), ZExt(xbx));
  auto check_val = UOr(UShl(ZExt(xdx), 32), ZExt(xax));
  auto replace = UCmpEq(curr_val, check_val);
  Write(FLAG_ZF, replace);
  Write(dst, Select(replace, desired_val, curr_val));
  Write(REG_EDX, Select(replace, Trunc(UShr(curr_val, 32)), xdx));
  Write(REG_EAX, Select(replace, Trunc(UShr(curr_val, 32)), xax));
}

#if 64 == ADDRESS_SIZE_BITS
DEF_ISEL_SEM(CMPXCHG16B_MEMdq, M128W dst, M128 src1) {
  auto curr_val = Read(src1);
  auto xdx = Read(REG_RDX);
  auto xax = Read(REG_RAX);
  auto xcx = Read(REG_RCX);
  auto xbx = Read(REG_RBX);
  auto desired_val = UOr(UShl(ZExt(xcx), 64), ZExt(xbx));
  auto check_val = UOr(UShl(ZExt(xdx), 64), ZExt(xax));
  auto replace = UCmpEq(curr_val, check_val);
  Write(FLAG_ZF, replace);
  Write(dst, Select(replace, desired_val, curr_val));
  Write(REG_RDX, Select(replace, Trunc(UShr(curr_val, 64)), xdx));
  Write(REG_RAX, Select(replace, Trunc(UShr(curr_val, 64)), xax));
}
#endif  // 64 == ADDRESS_SIZE_BITS
/*

1385 CMPXCHG16B CMPXCHG16B_MEMdq SEMAPHORE LONGMODE CMPXCHG16B ATTRIBUTES: LOCKABLE REQUIRES_ALIGNMENT
1751 CMPXCHG8B  SEMAPHORE BASE PENTIUMREAL ATTRIBUTES: LOCKABLE
 */
