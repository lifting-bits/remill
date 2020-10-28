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

#define MAKE_STOS(name, type, read_sel) \
  namespace { \
  DEF_SEM(Do##name) { \
    const addr_t addr = Read(REG_XDI); \
    const addr_t num_bytes = sizeof(type); \
    Write(WritePtr<type>(addr _IF_32BIT(REG_ES_BASE)), \
          Read(state.gpr.rax.read_sel)); \
    addr_t next_addr = 0; \
    if (BNot(FLAG_DF)) { \
      next_addr = UAdd(addr, num_bytes); \
    } else { \
      next_addr = USub(addr, num_bytes); \
    } \
    Write(REG_XDI, next_addr); \
    return memory; \
  } \
  } \
  DEF_ISEL(name) = Do##name;

MAKE_STOS(STOSB, uint8_t, byte.low)
MAKE_STOS(STOSW, uint16_t, word)
MAKE_STOS(STOSD, uint32_t, dword)
IF_64BIT(MAKE_STOS(STOSQ, uint64_t, qword))

#undef MAKE_STOS

// TODO(pag): How to handle `addr32` prefixes that make the `SCAS` use `EDI`
//            as the base register of the memory operand instead of `RDI`? This
//            could lead to some problems if `RDI != ZExtend(EDI)`.

#define MAKE_SCAS(name, type, read_sel) \
  namespace { \
  DEF_SEM(Do##name) { \
    const addr_t addr = Read(REG_XDI); \
    const addr_t num_bytes = sizeof(type); \
    const type lhs = Read(state.gpr.rax.read_sel); \
    const type rhs = Read(ReadPtr<type>(addr _IF_32BIT(REG_ES_BASE))); \
    const type res = USub(lhs, rhs); \
    WriteFlagsAddSub<tag_sub>(state, lhs, rhs, res); \
    addr_t next_addr = 0; \
    if (BNot(FLAG_DF)) { \
      next_addr = UAdd(addr, num_bytes); \
    } else { \
      next_addr = USub(addr, num_bytes); \
    } \
    Write(REG_XDI, next_addr); \
    return memory; \
  } \
  } \
  DEF_ISEL(name) = Do##name;

MAKE_SCAS(SCASB, uint8_t, byte.low)
MAKE_SCAS(SCASW, uint16_t, word)
MAKE_SCAS(SCASD, uint32_t, dword)
IF_64BIT(MAKE_SCAS(SCASQ, uint64_t, qword))

#undef MAKE_LODS

#define MAKE_LODS(name, type, write_sel) \
  namespace { \
  DEF_SEM(Do##name) { \
    const addr_t addr = Read(REG_XSI); \
    const addr_t num_bytes = sizeof(type); \
    WriteZExt(state.gpr.rax.write_sel, \
              Read(ReadPtr<type>(addr _IF_32BIT(REG_DS_BASE)))); \
    addr_t next_addr = 0; \
    if (BNot(FLAG_DF)) { \
      next_addr = UAdd(addr, num_bytes); \
    } else { \
      next_addr = USub(addr, num_bytes); \
    } \
    Write(REG_XSI, next_addr); \
    return memory; \
  } \
  } \
  DEF_ISEL(name) = Do##name;

MAKE_LODS(LODSB, uint8_t, byte.low)
MAKE_LODS(LODSW, uint16_t, word)
MAKE_LODS(LODSD, uint32_t, IF_64BIT_ELSE(qword, dword))
IF_64BIT(MAKE_LODS(LODSQ, uint64_t, qword))

#undef MAKE_LODS

#define MAKE_MOVS(name, type, read_sel) \
  namespace { \
  DEF_SEM(Do##name) { \
    const addr_t src_addr = Read(REG_XSI); \
    const addr_t dst_addr = Read(REG_XDI); \
    const addr_t num_bytes = sizeof(type); \
    Write(WritePtr<type>(dst_addr _IF_32BIT(REG_ES_BASE)), \
          Read(ReadPtr<type>(src_addr _IF_32BIT(REG_DS_BASE)))); \
    addr_t next_dst_addr = 0; \
    addr_t next_src_addr = 0; \
    if (BNot(FLAG_DF)) { \
      next_dst_addr = UAdd(dst_addr, num_bytes); \
      next_src_addr = UAdd(src_addr, num_bytes); \
    } else { \
      next_dst_addr = USub(dst_addr, num_bytes); \
      next_src_addr = USub(src_addr, num_bytes); \
    } \
    Write(REG_XDI, next_dst_addr); \
    Write(REG_XSI, next_src_addr); \
    return memory; \
  } \
  } \
  DEF_ISEL(name) = Do##name;

MAKE_MOVS(MOVSB, uint8_t, byte.low)
MAKE_MOVS(MOVSW, uint16_t, word)
MAKE_MOVS(MOVSD, uint32_t, dword)
IF_64BIT(MAKE_MOVS(MOVSQ, uint64_t, qword))

#undef MAKE_CMPS

#define MAKE_CMPS(name, type) \
  namespace { \
  DEF_SEM(Do##name) { \
    const addr_t src1_addr = Read(REG_XSI); \
    const addr_t src2_addr = Read(REG_XDI); \
    const addr_t num_bytes = sizeof(type); \
    const type lhs = Read(ReadPtr<type>(src1_addr _IF_32BIT(REG_DS_BASE))); \
    const type rhs = Read(ReadPtr<type>(src2_addr _IF_32BIT(REG_ES_BASE))); \
    const type res = USub(lhs, rhs); \
    WriteFlagsAddSub<tag_sub>(state, lhs, rhs, res); \
    addr_t next_src1_addr = 0; \
    addr_t next_src2_addr = 0; \
    if (BNot(FLAG_DF)) { \
      next_src1_addr = UAdd(src1_addr, num_bytes); \
      next_src2_addr = UAdd(src2_addr, num_bytes); \
    } else { \
      next_src1_addr = USub(src1_addr, num_bytes); \
      next_src2_addr = USub(src2_addr, num_bytes); \
    } \
    Write(REG_XDI, next_src2_addr); \
    Write(REG_XSI, next_src1_addr); \
    return memory; \
  } \
  } \
  DEF_ISEL(name) = Do##name;

MAKE_CMPS(CMPSB, uint8_t)
MAKE_CMPS(CMPSW, uint16_t)
MAKE_CMPS(CMPSD, uint32_t)
IF_64BIT(MAKE_CMPS(CMPSQ, uint64_t))

#undef MAKE_MOVS

#define MAKE_REP(base) \
  namespace { \
  DEF_SEM(Do##REP_##base) { \
    auto count_reg = Read(REG_XCX); \
    while (UCmpNeq(count_reg, 0)) { \
      memory = Do##base(memory, state); \
      count_reg = USub(count_reg, 1); \
      Write(REG_XCX, count_reg); \
    } \
    return memory; \
  } \
  } \
  DEF_ISEL(REP_##base) = Do##REP_##base;

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
  namespace { \
  DEF_SEM(Do##REPE_##base) { \
    auto count_reg = Read(REG_XCX); \
    if (UCmpEq(count_reg, 0)) { \
      return memory; \
    } \
    do { \
      memory = Do##base(memory, state); \
      count_reg = USub(count_reg, 1); \
      Write(REG_XCX, count_reg); \
    } while (BAnd(UCmpNeq(count_reg, 0), FLAG_ZF)); \
    return memory; \
  } \
  } \
  DEF_ISEL(REPE_##base) = Do##REPE_##base;

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
  namespace { \
  DEF_SEM(Do##REPNE_##base) { \
    auto count_reg = Read(REG_XCX); \
    if (UCmpEq(count_reg, 0)) { \
      return memory; \
    } \
    do { \
      memory = Do##base(memory, state); \
      count_reg = USub(count_reg, 1); \
      Write(REG_XCX, count_reg); \
    } while (BAnd(UCmpNeq(count_reg, 0), BNot(FLAG_ZF))); \
    return memory; \
  } \
  } \
  DEF_ISEL(REPNE_##base) = Do##REPNE_##base;

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
