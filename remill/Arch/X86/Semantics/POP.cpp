/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef REMILL_ARCH_X86_SEMANTICS_POP_H_
#define REMILL_ARCH_X86_SEMANTICS_POP_H_

namespace {

template <typename T>
DEF_HELPER(PopFromStack) -> T {
  addr_t op_size = TruncTo<addr_t>(sizeof(T));
  addr_t old_xsp = Read(REG_XSP);
  addr_t new_xsp = UAdd(old_xsp, op_size);
  T val = Read(ReadPtr<T>(old_xsp _IF_32BIT(REG_SS_BASE)));
  Write(REG_XSP, new_xsp);
  return val;
}

// Note: Special handling of `dst` when it has the form `POP [xSP + ...]`
//       is handled in the arch-specific instruction operand lifter.
//
//       The case of `POP xSP` is correctly handled without special casing.
template <typename D>
DEF_SEM(POP, D dst) {
  addr_t op_size = ZExtTo<D>(ByteSizeOf(dst));
  addr_t old_xsp = Read(REG_XSP);
  addr_t new_xsp = UAdd(old_xsp, op_size);
  WriteZExt(dst, Read(ReadPtr<D>(old_xsp _IF_32BIT(REG_SS_BASE))));
  Write(REG_XSP, new_xsp);
}
#if 32 == ADDRESS_SIZE_BITS
DEF_SEM(DoPOPA) {
  Write(REG_DI, PopFromStack<uint16_t>(memory, state));
  Write(REG_SI, PopFromStack<uint16_t>(memory, state));
  Write(REG_BP, PopFromStack<uint16_t>(memory, state));
  (void) PopFromStack<uint16_t>(memory, state);  // Ignore SP.
  Write(REG_BX, PopFromStack<uint16_t>(memory, state));
  Write(REG_DX, PopFromStack<uint16_t>(memory, state));
  Write(REG_CX, PopFromStack<uint16_t>(memory, state));
  Write(REG_AX, PopFromStack<uint16_t>(memory, state));
}
DEF_SEM(DoPOPAD) {
  Write(REG_EDI, PopFromStack<uint32_t>(memory, state));
  Write(REG_ESI, PopFromStack<uint32_t>(memory, state));
  Write(REG_EBP, PopFromStack<uint32_t>(memory, state));
  (void) PopFromStack<uint32_t>(memory, state);  // Ignore ESP.
  Write(REG_EBX, PopFromStack<uint32_t>(memory, state));
  Write(REG_EDX, PopFromStack<uint32_t>(memory, state));
  Write(REG_ECX, PopFromStack<uint32_t>(memory, state));
  Write(REG_EAX, PopFromStack<uint32_t>(memory, state));
}
#endif

#if 32 == ADDRESS_SIZE_BITS
DEF_SEM(DoPOPFD) {
  Flags f;
  f.flat = ZExt(PopFromStack<uint32_t>(memory, state));
  state.aflag.af = f.af;
  state.aflag.cf = f.cf;
  state.aflag.df = f.df;
  state.aflag.of = f.of;
  state.aflag.pf = f.pf;
  state.aflag.sf = f.sf;
  state.aflag.zf = f.zf;

  state.rflag.id = f.id;
//  state.rflag.ac = f.ac;
//  state.rflag.tf = f.tf;
//  state.rflag.nt = f.nt;
}
#else
DEF_SEM(DoPOPFQ) {
  Flags f;
  f.flat = PopFromStack<uint64_t>(memory, state);
  state.aflag.af = f.af;
  state.aflag.cf = f.cf;
  state.aflag.df = f.df;
  state.aflag.of = f.of;
  state.aflag.pf = f.pf;
  state.aflag.sf = f.sf;
  state.aflag.zf = f.zf;

  state.rflag.id = f.id;
//  state.rflag.ac = f.ac;
//  state.rflag.tf = f.tf;
//  state.rflag.nt = f.nt;
}
#endif  // 32 == ADDRESS_SIZE_BITS

// TODO(pag): Make behaviour conditional on `rflag.cpl`.
DEF_SEM(DoPOPF) {
  Flags f;
  f.flat = ZExt(ZExt(PopFromStack<uint16_t>(memory, state)));
  state.aflag.af = f.af;
  state.aflag.cf = f.cf;
  state.aflag.df = f.df;
  state.aflag.of = f.of;
  state.aflag.pf = f.pf;
  state.aflag.sf = f.sf;
  state.aflag.zf = f.zf;
}
}  // namespace

DEF_ISEL(POP_GPRv_8F_16) = POP<R16W>;
DEF_ISEL_R32or64W(POP_GPRv_8F, POP);

DEF_ISEL(POP_GPRv_51_16) = POP<R16W>;
DEF_ISEL_R32or64W(POP_GPRv_51, POP);

DEF_ISEL(POP_MEMv_16) = POP<M16W>;
DEF_ISEL_M32or64W(POP_MEMv, POP);

#if 32 == ADDRESS_SIZE_BITS
DEF_ISEL(POPA) = DoPOPA;

DEF_ISEL(POPAD) = DoPOPAD;
#endif

DEF_ISEL(POPF) = DoPOPF;

#if 32 == ADDRESS_SIZE_BITS
DEF_ISEL(POPFD) = DoPOPFD;
#else
DEF_ISEL(POPFQ) = DoPOPFQ;
#endif  // 32 == ADDRESS_SIZE_BITS

/*
1391 POP POP_ES POP BASE I86 ATTRIBUTES: FIXED_BASE0 NOTSX SCALABLE STACKPOP0
1392 POP POP_SS POP BASE I86 ATTRIBUTES: FIXED_BASE0 NOTSX SCALABLE STACKPOP0
1393 POP POP_DS POP BASE I86 ATTRIBUTES: FIXED_BASE0 NOTSX SCALABLE STACKPOP0
1395 POP POP_FS POP BASE I86 ATTRIBUTES: FIXED_BASE0 NOTSX SCALABLE STACKPOP0
1396 POP POP_GS POP BASE I86 ATTRIBUTES: FIXED_BASE0 NOTSX SCALABLE STACKPOP0
 */

#endif  // REMILL_ARCH_X86_SEMANTICS_POP_H_
