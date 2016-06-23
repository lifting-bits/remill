/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef REMILL_ARCH_X86_SEMANTICS_STRINGOP_H_
#define REMILL_ARCH_X86_SEMANTICS_STRINGOP_H_

#define MAKE_STOS(name, type, read_sel) \
    DEF_ISEL_SEM(name) { \
      const addr_t addr = R(state.gpr.rdi); \
      MnW<type> dst = {addr}; \
      W(dst) = R(state.gpr.rax.read_sel); \
      if (!state.aflag.df) { \
        W(state.gpr.rdi) = addr + sizeof(type); \
      } else { \
        W(state.gpr.rdi) = addr - sizeof(type); \
      } \
    }

MAKE_STOS(STOSB, uint8_t, byte.low)
MAKE_STOS(STOSW, uint16_t, word)
MAKE_STOS(STOSD, uint32_t, dword)
IF_64BIT(MAKE_STOS(STOSQ, uint64_t, qword))

#undef MAKE_STOS

// TODO(pag): How to handle `addr32` prefixes that make the `SCAS` use `EDI`
//            as the base register of the memory operand instead of `RDI`? This
//            could lead to some problems if `RDI != ZExtend(EDI)`.

#define MAKE_SCAS(name, type, read_sel) \
    DEF_ISEL_SEM(name) { \
      const addr_t addr = R(state.gpr.rdi); \
      Mn<type> rhs_addr = {addr}; \
      const type lhs = R(state.gpr.rax.read_sel); \
      const type rhs = R(rhs_addr); \
      const type res = lhs - rhs; \
      SetFlagsAddSub<tag_sub>(state, lhs, rhs, res); \
      if (!state.aflag.df) { \
        W(state.gpr.rdi) = addr + sizeof(type); \
      } else { \
        W(state.gpr.rdi) = addr - sizeof(type); \
      } \
    }

MAKE_SCAS(SCASB, uint8_t, byte.low)
MAKE_SCAS(SCASW, uint16_t, word)
MAKE_SCAS(SCASD, uint32_t, dword)
IF_64BIT(MAKE_SCAS(SCASQ, uint64_t, qword))

#undef MAKE_LODS

#define MAKE_LODS(name, type, write_sel) \
    DEF_ISEL_SEM(name) { \
      const addr_t addr = R(state.gpr.rsi); \
      Mn<type> src = {addr}; \
      W(state.gpr.rax.write_sel) = R(src); \
      if (!state.aflag.df) { \
        W(state.gpr.rsi) = addr + sizeof(type); \
      } else { \
        W(state.gpr.rsi) = addr - sizeof(type); \
      } \
    }

MAKE_LODS(LODSB, uint8_t, byte.low)
MAKE_LODS(LODSW, uint16_t, word)
MAKE_LODS(LODSD, uint32_t, IF_64BIT_ELSE(qword, dword))
IF_64BIT(MAKE_LODS(LODSQ, uint64_t, qword))

#undef MAKE_LODS

#define MAKE_MOVS(name, type, read_sel) \
    DEF_ISEL_SEM(name) { \
      const addr_t src_addr = R(state.gpr.rsi); \
      const addr_t dst_addr = R(state.gpr.rdi); \
      MnW<type> dst = {dst_addr}; \
      Mn<type> src = {src_addr}; \
      W(dst) = R(src); \
      if (!state.aflag.df) { \
        W(state.gpr.rdi) = dst_addr + sizeof(type); \
        W(state.gpr.rsi) = src_addr + sizeof(type); \
      } else { \
        W(state.gpr.rdi) = dst_addr - sizeof(type); \
        W(state.gpr.rsi) = src_addr - sizeof(type); \
      } \
    }

MAKE_MOVS(MOVSB, uint8_t, byte.low)
MAKE_MOVS(MOVSW, uint16_t, word)
MAKE_MOVS(MOVSD, uint32_t,dword)
IF_64BIT(MAKE_MOVS(MOVSQ, uint64_t, qword))

#undef MAKE_CMPS

#define MAKE_CMPS(name, type) \
    DEF_ISEL_SEM(name) { \
      const addr_t src1_addr = R(state.gpr.rsi); \
      const addr_t src2_addr = R(state.gpr.rdi); \
      Mn<type> src1 = {src1_addr}; \
      Mn<type> src2 = {src2_addr}; \
      const type lhs = R(src1); \
      const type rhs = R(src2); \
      const type res = lhs - rhs; \
      SetFlagsAddSub<tag_sub>(state, lhs, rhs, res); \
      if (!state.aflag.df) { \
        W(state.gpr.rdi) = src2_addr + sizeof(type); \
        W(state.gpr.rsi) = src1_addr + sizeof(type); \
      } else { \
        W(state.gpr.rdi) = src2_addr - sizeof(type); \
        W(state.gpr.rsi) = src1_addr - sizeof(type); \
      } \
    }

MAKE_CMPS(CMPSB, uint8_t)
MAKE_CMPS(CMPSW, uint16_t)
MAKE_CMPS(CMPSD, uint32_t)
IF_64BIT(MAKE_CMPS(CMPSQ, uint64_t))

#undef MAKE_MOVS

#define MAKE_REP(base) \
    DEF_ISEL_SEM(REP_ ## base) { \
      auto count_reg = R(state.gpr.rcx); \
      while (count_reg) { \
        base(state, next_pc); \
        count_reg = count_reg - 1; \
        W(state.gpr.rcx) = count_reg; \
      } \
    }

MAKE_REP(LODSB)
MAKE_REP(LODSW)
MAKE_REP(LODSD)
IF_64BIT(MAKE_REP(LODSQ))

MAKE_REP(MOVSB)
MAKE_REP(MOVSW)
MAKE_REP(MOVSD)
IF_64BIT(MAKE_REP(MOVSQ))

MAKE_REP(STOSB)
MAKE_REP(STOSW)
MAKE_REP(STOSD)
IF_64BIT(MAKE_REP(STOSQ))
#undef MAKE_REP

#define MAKE_REPE(base) \
    DEF_ISEL_SEM(REPE_ ## base) { \
      auto count_reg = R(state.gpr.rcx); \
      if (!count_reg) return; \
      do { \
        base(state, next_pc); \
        count_reg = count_reg - 1; \
        W(state.gpr.rcx) = count_reg; \
      } while (count_reg && state.aflag.zf); \
    }

MAKE_REPE(CMPSB)
MAKE_REPE(CMPSW)
MAKE_REPE(CMPSD)
IF_64BIT(MAKE_REPE(CMPSQ))

MAKE_REPE(SCASB)
MAKE_REPE(SCASW)
MAKE_REPE(SCASD)
IF_64BIT(MAKE_REPE(SCASQ))

#undef MAKE_REPE

#define MAKE_REPNE(base) \
    DEF_ISEL_SEM(REPNE_ ## base) { \
      auto count_reg = R(state.gpr.rcx); \
      if (!count_reg) return; \
      do { \
        base(state, next_pc); \
        count_reg = count_reg - 1; \
        W(state.gpr.rcx) = count_reg; \
      } while (count_reg && !state.aflag.zf); \
    }

MAKE_REPNE(CMPSB)
MAKE_REPNE(CMPSW)
MAKE_REPNE(CMPSD)
IF_64BIT(MAKE_REPNE(CMPSQ))

MAKE_REPNE(SCASB)
MAKE_REPNE(SCASW)
MAKE_REPNE(SCASD)
IF_64BIT(MAKE_REPNE(SCASQ))

#undef MAKE_REPNE

/*
30 OUTSW OUTSW IOSTRINGOP BASE I186 ATTRIBUTES: FIXED_BASE0 NOTSX
36 OUTSB OUTSB IOSTRINGOP BASE I186 ATTRIBUTES: BYTEOP FIXED_BASE0 NOTSX
37 OUTSD OUTSD IOSTRINGOP BASE I386 ATTRIBUTES: FIXED_BASE0 NOTSX
38 OUTSD OUTSD IOSTRINGOP BASE I386 ATTRIBUTES: FIXED_BASE0 NOTSX
907 REP_INSW REP_INSW IOSTRINGOP BASE I186 ATTRIBUTES: FIXED_BASE0 NOTSX REP
908 REP_INSW REP_INSW IOSTRINGOP BASE I186 ATTRIBUTES: FIXED_BASE0 NOTSX REP
916 REP_INSB REP_INSB IOSTRINGOP BASE I186 ATTRIBUTES: BYTEOP FIXED_BASE0 NOTSX REP
917 REP_INSB REP_INSB IOSTRINGOP BASE I186 ATTRIBUTES: BYTEOP FIXED_BASE0 NOTSX REP
918 REP_INSD REP_INSD IOSTRINGOP BASE I386 ATTRIBUTES: FIXED_BASE0 NOTSX REP
919 REP_INSD REP_INSD IOSTRINGOP BASE I386 ATTRIBUTES: FIXED_BASE0 NOTSX REP
920 REP_INSD REP_INSD IOSTRINGOP BASE I386 ATTRIBUTES: FIXED_BASE0 NOTSX REP
921 REP_INSD REP_INSD IOSTRINGOP BASE I386 ATTRIBUTES: FIXED_BASE0 NOTSX REP
1118 REP_OUTSW REP_OUTSW IOSTRINGOP BASE I186 ATTRIBUTES: FIXED_BASE0 NOTSX REP
1119 REP_OUTSW REP_OUTSW IOSTRINGOP BASE I186 ATTRIBUTES: FIXED_BASE0 NOTSX REP
1129 REP_OUTSB REP_OUTSB IOSTRINGOP BASE I186 ATTRIBUTES: BYTEOP FIXED_BASE0 NOTSX REP
1130 REP_OUTSB REP_OUTSB IOSTRINGOP BASE I186 ATTRIBUTES: BYTEOP FIXED_BASE0 NOTSX REP
1135 REP_OUTSD REP_OUTSD IOSTRINGOP BASE I386 ATTRIBUTES: FIXED_BASE0 NOTSX REP
1136 REP_OUTSD REP_OUTSD IOSTRINGOP BASE I386 ATTRIBUTES: FIXED_BASE0 NOTSX REP
1137 REP_OUTSD REP_OUTSD IOSTRINGOP BASE I386 ATTRIBUTES: FIXED_BASE0 NOTSX REP
1138 REP_OUTSD REP_OUTSD IOSTRINGOP BASE I386 ATTRIBUTES: FIXED_BASE0 NOTSX REP
1326 INSB INSB IOSTRINGOP BASE I186 ATTRIBUTES: BYTEOP FIXED_BASE0 NOTSX
1328 INSD INSD IOSTRINGOP BASE I386 ATTRIBUTES: FIXED_BASE0 NOTSX
1329 INSD INSD IOSTRINGOP BASE I386 ATTRIBUTES: FIXED_BASE0 NOTSX
1366 INSW INSW IOSTRINGOP BASE I186 ATTRIBUTES: FIXED_BASE0 NOTSX
 */

#endif  // REMILL_ARCH_X86_SEMANTICS_STRINGOP_H_
