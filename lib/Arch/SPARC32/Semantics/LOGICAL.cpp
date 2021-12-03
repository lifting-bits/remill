/*
 * Copyright (c) 2020 Trail of Bits, Inc.
 */

namespace {

template <typename T>
ALWAYS_INLINE void SetFlagsLogical(State &state, T lhs, T rhs, T res) {
  FLAG_ICC_CF = false;
  FLAG_ICC_ZF = ZeroFlag(res, lhs, rhs);
  FLAG_ICC_NF = SignFlag(res, lhs, rhs);
  FLAG_ICC_VF = false;
}

template <typename S1, typename S2, typename D>
DEF_SEM(AND, S1 src1, S2 src2, D dst) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto res = UAnd(lhs, rhs);
  Write(dst, res);
  return memory;
}

template <typename S1, typename S2, typename D>
DEF_SEM(ANDcc, S1 src1, S2 src2, D dst) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto res = UAnd(lhs, rhs);
  Write(dst, res);
  SetFlagsLogical(state, lhs, rhs, res);
  return memory;
}

template <typename S1, typename S2, typename D>
DEF_SEM(ANDN, S1 src1, S2 src2, D dst) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto res = UAnd(lhs, UNot(rhs));
  WriteZExt(dst, res);
  return memory;
}

template <typename S1, typename S2, typename D>
DEF_SEM(ANDNcc, S1 src1, S2 src2, D dst) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto res = UAnd(lhs, UNot(rhs));
  WriteZExt(dst, res);
  SetFlagsLogical(state, lhs, rhs, res);
  return memory;
}

template <typename S1, typename S2, typename D>
DEF_SEM(OR, S1 src1, S2 src2, D dst) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto res = UOr(lhs, rhs);
  Write(dst, res);
  return memory;
}

template <typename S1, typename S2, typename D>
DEF_SEM(ORcc, S1 src1, S2 src2, D dst) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto res = UOr(lhs, rhs);
  Write(dst, res);
  SetFlagsLogical(state, lhs, rhs, res);
  return memory;
}

template <typename S1, typename S2, typename D>
DEF_SEM(ORN, S1 src1, S2 src2, D dst) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto res = UOr(lhs, UNot(rhs));
  WriteZExt(dst, res);
  return memory;
}

template <typename S1, typename S2, typename D>
DEF_SEM(ORNcc, S1 src1, S2 src2, D dst) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto res = UOr(lhs, UNot(rhs));
  WriteZExt(dst, res);
  SetFlagsLogical(state, lhs, rhs, res);
  return memory;
}

template <typename S1, typename S2, typename D>
DEF_SEM(XOR, S1 src1, S2 src2, D dst) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto res = UXor(lhs, rhs);
  WriteZExt(dst, res);
  return memory;
}

template <typename S1, typename S2, typename D>
DEF_SEM(XORcc, S1 src1, S2 src2, D dst) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto res = UXor(lhs, rhs);
  WriteZExt(dst, res);
  SetFlagsLogical(state, lhs, rhs, res);
  return memory;
}

template <typename S1, typename S2, typename D>
DEF_SEM(XNOR, S1 src1, S2 src2, D dst) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto res = UXor(lhs, UNot(rhs));
  WriteZExt(dst, res);
  return memory;
}

template <typename S1, typename S2, typename D>
DEF_SEM(XNORcc, S1 src1, S2 src2, D dst) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto res = UXor(lhs, UNot(rhs));
  WriteZExt(dst, res);
  SetFlagsLogical(state, lhs, rhs, res);
  return memory;
}

}  // namespace

DEF_ISEL(AND) = AND<R32, R32, R32W>;
DEF_ISEL(ANDcc) = ANDcc<R32, R32, R32W>;
DEF_ISEL(ANDN) = ANDN<R32, R32, R32W>;
DEF_ISEL(ANDNcc) = ANDNcc<R32, R32, R32W>;

DEF_ISEL(AND_I32) = AND<R32, I32, R32W>;
DEF_ISEL(ANDcc_I32) = ANDcc<R32, I32, R32W>;
DEF_ISEL(ANDN_I32) = ANDN<R32, I32, R32W>;
DEF_ISEL(ANDNcc_I32) = ANDNcc<R32, I32, R32W>;

DEF_ISEL(OR) = OR<R32, R32, R32W>;
DEF_ISEL(ORcc) = ORcc<R32, R32, R32W>;
DEF_ISEL(ORN) = ORN<R32, R32, R32W>;
DEF_ISEL(ORNcc) = ORNcc<R32, R32, R32W>;

DEF_ISEL(OR_I32) = OR<R32, I32, R32W>;
DEF_ISEL(ORcc_I32) = ORcc<R32, I32, R32W>;
DEF_ISEL(ORN_I32) = ORN<R32, I32, R32W>;
DEF_ISEL(ORNcc_I32) = ORNcc<R32, I32, R32W>;

DEF_ISEL(XOR) = XOR<R32, R32, R32W>;
DEF_ISEL(XORcc) = XORcc<R32, R32, R32W>;
DEF_ISEL(XNOR) = XNOR<R32, R32, R32W>;
DEF_ISEL(XNORcc) = XNORcc<R32, R32, R32W>;

DEF_ISEL(XOR_I32) = XOR<R32, I32, R32W>;
DEF_ISEL(XORcc_I32) = XORcc<R32, I32, R32W>;
DEF_ISEL(XNOR_I32) = XNOR<R32, I32, R32W>;
DEF_ISEL(XNORcc_I32) = XNORcc<R32, I32, R32W>;

namespace {

template <typename S1, typename S2, typename D>
DEF_SEM(SLL, S1 src1, S2 src2, D dst) {
  auto value = Read(src1);
  auto shift = Read(src2);
  auto res = UShl(value, shift);
  Write(dst, res);
  return memory;
}

template <typename S1, typename S2, typename D>
DEF_SEM(SRL, S1 src1, S2 src2, D dst) {
  auto value = Read(src1);
  auto shift = Read(src2);
  auto res = UShr(value, shift);
  Write(dst, res);
  return memory;
}

template <typename S1, typename S2, typename D>
DEF_SEM(SRA, S1 src1, S2 src2, D dst) {
  auto val = Signed(Read(src1));
  auto shift = Read(src2);
  auto res = SShr(val, Signed(shift));
  Write(dst, Unsigned(res));
  return memory;
}

}  // namespace

DEF_ISEL(SLL) = SLL<R32, I32, R32W>;
DEF_ISEL(SRL) = SRL<R32, I32, R32W>;
DEF_ISEL(SRA) = SRA<R32, I32, R32W>;
