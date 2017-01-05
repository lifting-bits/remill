/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

namespace {

#define MAKE_CMPXCHG_XAX(xax) \
    template <typename D, typename S1, typename S2> \
    DEF_SEM(CMPXCHG_ ## xax, D dst, S1 src1, S2 src2) { \
      auto curr_val = Read(src1); \
      auto desired_val = Read(src2); \
      auto check_val = Read(REG_ ## xax); \
      auto cmp_res = USub(check_val, curr_val); \
      auto replace = UCmpEq(cmp_res, 0); \
      WriteFlagsAddSub<tag_sub>(state, check_val, curr_val, cmp_res); \
      WriteZExt(dst, Select(replace, desired_val, curr_val)); \
      WriteZExt(REG_ ## xax, Select(replace, check_val, curr_val)); \
    }

MAKE_CMPXCHG_XAX(AL)
MAKE_CMPXCHG_XAX(AX)
MAKE_CMPXCHG_XAX(EAX)
IF_64BIT(MAKE_CMPXCHG_XAX(RAX))

DEF_SEM(DoCMPXCHG8B_MEMq, M64W dst, M64 src1) {
  auto curr_val = Read(src1);
  auto xdx = Read(REG_EDX);
  auto xax = Read(REG_EAX);
  auto xcx = Read(REG_ECX);
  auto xbx = Read(REG_EBX);
  auto desired_val = UOr(UShl(ZExt(xcx), 32), ZExt(xbx));
  auto check_val = UOr(UShl(ZExt(xdx), 32), ZExt(xax));
  auto cmp_res = USub(check_val, curr_val);
  auto replace = UCmpEq(cmp_res, 0);
  Write(FLAG_ZF, replace);
  Write(dst, Select(replace, desired_val, curr_val));
  Write(REG_EDX, Select(replace, xdx, Trunc(UShr(curr_val, 32))));
  Write(REG_EAX, Select(replace, xax, Trunc(curr_val)));
}
#if 64 == ADDRESS_SIZE_BITS
DEF_SEM(DoCMPXCHG16B_MEMdq, M128W dst, M128 src1) {
  auto curr_val = Read(src1);
  auto xdx = Read(REG_RDX);
  auto xax = Read(REG_RAX);
  auto xcx = Read(REG_RCX);
  auto xbx = Read(REG_RBX);
  auto desired_val = UOr(UShl(ZExt(xcx), 64), ZExt(xbx));
  auto check_val = UOr(UShl(ZExt(xdx), 64), ZExt(xax));
  auto cmp_res = USub(check_val, curr_val);
  auto replace = UCmpEq(cmp_res, 0);
  Write(FLAG_ZF, replace);
  Write(dst, Select(replace, desired_val, curr_val));
  Write(REG_RDX, Select(replace, xdx, Trunc(UShr(curr_val, 64))));
  Write(REG_RAX, Select(replace, xax, Trunc(curr_val)));
}
#endif  // 64 == ADDRESS_SIZE_BITS
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

DEF_ISEL(CMPXCHG8B_MEMq) = DoCMPXCHG8B_MEMq;

#if 64 == ADDRESS_SIZE_BITS
DEF_ISEL(CMPXCHG16B_MEMdq) = DoCMPXCHG16B_MEMdq;
#endif  // 64 == ADDRESS_SIZE_BITS

namespace {

// Atomic fetch-add.
template <typename D1, typename S1, typename D2, typename S2>
DEF_SEM(XADD, D1 dst1, S1 src1, D2 dst2, S2 src2) {

  // Our lifter only injects atomic begin/end around memory access instructions
  // but this instruction is a full memory barrier, even when registers are
  // accessed.
  if (IsRegister(dst1)) {
    BarrierStoreLoad();
  }

  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto sum = UAdd(lhs, rhs);
  WriteZExt(dst1, sum);
  WriteZExt(dst2, lhs);
  WriteFlagsAddSub<tag_add>(state, lhs, rhs, sum);
}

}  // namespace

DEF_ISEL(XADD_MEMb_GPR8) = XADD<M8W, M8, R8W, R8>;
DEF_ISEL(XADD_GPR8_GPR8) = XADD<R8W, R8, R8W, R8>;
DEF_ISEL_MnW_Mn_RnW_Rn(XADD_MEMv_GPRv, XADD);
DEF_ISEL_RnW_Rn_RnW_Rn(XADD_GPRv_GPRv, XADD);

