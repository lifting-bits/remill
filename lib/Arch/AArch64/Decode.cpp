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

#include "Decode.h"

namespace remill {
namespace aarch64 {

// CINC  <Wd>, <Wn>, <cond>
bool TryDecodeCINC_CSINC_32_CONDSEL(const InstData &data, Instruction &inst) {
  return false;
}

// CINC  <Xd>, <Xn>, <cond>
bool TryDecodeCINC_CSINC_64_CONDSEL(const InstData &data, Instruction &inst) {
  return false;
}

// CSET  <Wd>, <cond>
bool TryDecodeCSET_CSINC_32_CONDSEL(const InstData &data, Instruction &inst) {
  return false;
}

// CSET  <Xd>, <cond>
bool TryDecodeCSET_CSINC_64_CONDSEL(const InstData &data, Instruction &inst) {
  return false;
}

// CINV  <Wd>, <Wn>, <cond>
bool TryDecodeCINV_CSINV_32_CONDSEL(const InstData &data, Instruction &inst) {
  return false;
}

// CINV  <Xd>, <Xn>, <cond>
bool TryDecodeCINV_CSINV_64_CONDSEL(const InstData &data, Instruction &inst) {
  return false;
}

// CSETM  <Wd>, <cond>
bool TryDecodeCSETM_CSINV_32_CONDSEL(const InstData &data, Instruction &inst) {
  return false;
}

// CSETM  <Xd>, <cond>
bool TryDecodeCSETM_CSINV_64_CONDSEL(const InstData &data, Instruction &inst) {
  return false;
}

// UMULL  <Xd>, <Wn>, <Wm>
bool TryDecodeUMULL_UMADDL_64WA_DP_3SRC(const InstData &, Instruction &) {
  return false;
}

// UBFIZ  <Wd>, <Wn>, #<lsb>, #<width>
bool TryDecodeUBFIZ_UBFM_32M_BITFIELD(const InstData &, Instruction &) {
  return false;
}

// UBFIZ  <Xd>, <Xn>, #<lsb>, #<width>
bool TryDecodeUBFIZ_UBFM_64M_BITFIELD(const InstData &, Instruction &) {
  return false;
}

// UBFX  <Wd>, <Wn>, #<lsb>, #<width>
bool TryDecodeUBFX_UBFM_32M_BITFIELD(const InstData &, Instruction &) {
  return false;
}

// UBFX  <Xd>, <Xn>, #<lsb>, #<width>
bool TryDecodeUBFX_UBFM_64M_BITFIELD(const InstData &, Instruction &) {
  return false;
}

// MOV  <Wd|WSP>, #<imm>
bool TryDecodeMOV_ORR_32_LOG_IMM(const InstData &, Instruction &) {
  return false;
}

// MOV  <Xd|SP>, #<imm>
bool TryDecodeMOV_ORR_64_LOG_IMM(const InstData &, Instruction &) {
  return false;
}

// ASR  <Wd>, <Wn>, #<shift>
bool TryDecodeASR_SBFM_32M_BITFIELD(const InstData &, Instruction &) {
  return false;
}

// ASR  <Xd>, <Xn>, #<shift>
bool TryDecodeASR_SBFM_64M_BITFIELD(const InstData &, Instruction &) {
  return false;
}

// LSR  <Wd>, <Wn>, #<shift>
bool TryDecodeLSR_UBFM_32M_BITFIELD(const InstData &, Instruction &) {
  return false;
}

// LSR  <Xd>, <Xn>, #<shift>
bool TryDecodeLSR_UBFM_64M_BITFIELD(const InstData &, Instruction &) {
  return false;
}

// LSL  <Wd>, <Wn>, #<shift>
bool TryDecodeLSL_UBFM_32M_BITFIELD(const InstData &, Instruction &) {
  return false;
}

// LSL  <Xd>, <Xn>, #<shift>
bool TryDecodeLSL_UBFM_64M_BITFIELD(const InstData &, Instruction &) {
  return false;
}

// MOV  <Wd>, #<imm>
bool TryDecodeMOV_MOVN_32_MOVEWIDE(const InstData &, Instruction &) {
  return false;
}

// MOV  <Xd>, #<imm>
bool TryDecodeMOV_MOVN_64_MOVEWIDE(const InstData &, Instruction &) {
  return false;
}

// CMP  <Wn>, <Wm>{, <shift> #<amount>}
bool TryDecodeCMP_SUBS_32_ADDSUB_SHIFT(const InstData &, Instruction &) {
  return false;
}

// CMP  <Xn>, <Xm>{, <shift> #<amount>}
bool TryDecodeCMP_SUBS_64_ADDSUB_SHIFT(const InstData &, Instruction &) {
  return false;
}

// CMP  <Xn|SP>, #<imm>{, <shift>}
bool TryDecodeCMP_SUBS_64S_ADDSUB_IMM(const InstData &, Instruction &) {
  return false;
}

// CMP  <Wn|WSP>, #<imm>{, <shift>}
bool TryDecodeCMP_SUBS_32S_ADDSUB_IMM(const InstData &, Instruction &) {
  return false;
}

// CMP  <Wn|WSP>, <Wm>{, <extend> {#<amount>}}
bool TryDecodeCMP_SUBS_32S_ADDSUB_EXT(const InstData &, Instruction &) {
  return false;
}

// CMP  <Xn|SP>, <R><m>{, <extend> {#<amount>}}
bool TryDecodeCMP_SUBS_64S_ADDSUB_EXT(const InstData &, Instruction &) {
  return false;
}

// CMN  <Wn|WSP>, #<imm>{, <shift>}
bool TryDecodeCMN_ADDS_32S_ADDSUB_IMM(const InstData &, Instruction &) {
  return false;
}

// CMN  <Xn|SP>, #<imm>{, <shift>}
bool TryDecodeCMN_ADDS_64S_ADDSUB_IMM(const InstData &, Instruction &) {
  return false;
}

// CMN  <Wn>, <Wm>{, <shift> #<amount>}
bool TryDecodeCMN_ADDS_32_ADDSUB_SHIFT(const InstData &, Instruction &) {
  return false;
}

// CMN  <Xn>, <Xm>{, <shift> #<amount>}
bool TryDecodeCMN_ADDS_64_ADDSUB_SHIFT(const InstData &, Instruction &) {
  return false;
}

// CMN  <Wn|WSP>, <Wm>{, <extend> {#<amount>}}
bool TryDecodeCMN_ADDS_32S_ADDSUB_EXT(const InstData &, Instruction &) {
  return false;
}

// CMN  <Xn|SP>, <R><m>{, <extend> {#<amount>}}
bool TryDecodeCMN_ADDS_64S_ADDSUB_EXT(const InstData &, Instruction &) {
  return false;
}

// MOV  <Wd>, #<imm>
bool TryDecodeMOV_MOVZ_32_MOVEWIDE(const InstData &, Instruction &) {
  return false;
}

// MOV  <Xd>, #<imm>
bool TryDecodeMOV_MOVZ_64_MOVEWIDE(const InstData &, Instruction &) {
  return false;
}

// MOV  <Wd|WSP>, <Wn|WSP>
bool TryDecodeMOV_ADD_32_ADDSUB_IMM(const InstData &, Instruction &) {
  return false;
}

// MOV  <Xd|SP>, <Xn|SP>
bool TryDecodeMOV_ADD_64_ADDSUB_IMM(const InstData &, Instruction &) {
  return false;
}

// MOV  <Wd>, <Wm>
bool TryDecodeMOV_ORR_32_LOG_SHIFT(const InstData &, Instruction &) {
  return false;
}

// MOV  <Xd>, <Xm>
bool TryDecodeMOV_ORR_64_LOG_SHIFT(const InstData &, Instruction &) {
  return false;
}

// FRECPX FRECPX_asisdmiscfp16_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 opcode   0
//  13 1 opcode   1
//  14 1 opcode   2
//  15 1 opcode   3
//  16 1 opcode   4
//  17 0
//  18 0
//  19 1
//  20 1
//  21 1
//  22 1
//  23 1 a        0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// FRECPX  <Hd>, <Hn>
bool TryDecodeFRECPX_ASISDMISCFP16_R(const InstData &, Instruction &) {
  return false;
}

// FRECPX FRECPX_asisdmisc_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 opcode   0
//  13 1 opcode   1
//  14 1 opcode   2
//  15 1 opcode   3
//  16 1 opcode   4
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x sz       0
//  23 1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// FRECPX  <V><d>, <V><n>
bool TryDecodeFRECPX_ASISDMISC_R(const InstData &, Instruction &) {
  return false;
}

// STSMAXH STSMAXH_32S_memop:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 0 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 0 size     1
// STSMAXH  <Ws>, [<Xn|SP>]
bool TryDecodeSTSMAXH_32S_MEMOP(const InstData &, Instruction &) {
  return false;
}

// STSMAXLH STSMAXLH_32S_memop:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 0 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 0 size     1
// STSMAXLH  <Ws>, [<Xn|SP>]
bool TryDecodeSTSMAXLH_32S_MEMOP(const InstData &, Instruction &) {
  return false;
}

// FADDP FADDP_asimdsamefp16_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 opcode   0
//  12 1 opcode   1
//  13 0 opcode   2
//  14 0
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 1
//  23 0 a        0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// FADDP  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeFADDP_ASIMDSAMEFP16_ONLY(const InstData &, Instruction &) {
  return false;
}

// FADDP FADDP_asimdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 opcode   0
//  12 1 opcode   1
//  13 0 opcode   2
//  14 1 opcode   3
//  15 1 opcode   4
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x sz       0
//  23 0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// FADDP  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeFADDP_ASIMDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// FABS FABS_asimdmiscfp16_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 opcode   0
//  13 1 opcode   1
//  14 1 opcode   2
//  15 1 opcode   3
//  16 0 opcode   4
//  17 0
//  18 0
//  19 1
//  20 1
//  21 1
//  22 1
//  23 1 a        0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// FABS  <Vd>.<T>, <Vn>.<T>
bool TryDecodeFABS_ASIMDMISCFP16_R(const InstData &, Instruction &) {
  return false;
}

// FABS FABS_asimdmisc_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 opcode   0
//  13 1 opcode   1
//  14 1 opcode   2
//  15 1 opcode   3
//  16 0 opcode   4
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x sz       0
//  23 1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// FABS  <Vd>.<T>, <Vn>.<T>
bool TryDecodeFABS_ASIMDMISC_R(const InstData &, Instruction &) {
  return false;
}

// SCVTF SCVTF_asisdshf_C:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 opcode   0
//  12 0 opcode   1
//  13 1 opcode   2
//  14 1 opcode   3
//  15 1 opcode   4
//  16 x immb     0
//  17 x immb     1
//  18 x immb     2
//  19 x immh     0
//  20 x immh     1
//  21 x immh     2
//  22 x immh     3
//  23 0
//  24 1
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// SCVTF  <V><d>, <V><n>, #<fbits>
bool TryDecodeSCVTF_ASISDSHF_C(const InstData &, Instruction &) {
  return false;
}

// SCVTF SCVTF_asimdshf_C:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 opcode   0
//  12 0 opcode   1
//  13 1 opcode   2
//  14 1 opcode   3
//  15 1 opcode   4
//  16 x immb     0
//  17 x immb     1
//  18 x immb     2
//  19 x immh     0
//  20 x immh     1
//  21 x immh     2
//  22 x immh     3
//  23 0
//  24 1
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// SCVTF  <Vd>.<T>, <Vn>.<T>, #<fbits>
bool TryDecodeSCVTF_ASIMDSHF_C(const InstData &, Instruction &) {
  return false;
}

// CLZ CLZ_asimdmisc_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 opcode   0
//  13 0 opcode   1
//  14 1 opcode   2
//  15 0 opcode   3
//  16 0 opcode   4
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// CLZ  <Vd>.<T>, <Vn>.<T>
bool TryDecodeCLZ_ASIMDMISC_R(const InstData &, Instruction &) {
  return false;
}

// FCVT FCVT_SH_floatdp1:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 1
//  15 0 opc      0
//  16 0 opc      1
//  17 1
//  18 0
//  19 0
//  20 0
//  21 1
//  22 1 type     0
//  23 1 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 M        0
// FCVT  <Sd>, <Hn>
bool TryDecodeFCVT_SH_FLOATDP1(const InstData &, Instruction &) {
  return false;
}

// FCVT FCVT_DH_floatdp1:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 1
//  15 1 opc      0
//  16 0 opc      1
//  17 1
//  18 0
//  19 0
//  20 0
//  21 1
//  22 1 type     0
//  23 1 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 M        0
// FCVT  <Dd>, <Hn>
bool TryDecodeFCVT_DH_FLOATDP1(const InstData &, Instruction &) {
  return false;
}

// FCVT FCVT_HS_floatdp1:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 1
//  15 1 opc      0
//  16 1 opc      1
//  17 1
//  18 0
//  19 0
//  20 0
//  21 1
//  22 0 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 M        0
// FCVT  <Hd>, <Sn>
bool TryDecodeFCVT_HS_FLOATDP1(const InstData &, Instruction &) {
  return false;
}

// LDLARH LDLARH_LR32_ldstexcl:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 Rt2      0
//  11 1 Rt2      1
//  12 1 Rt2      2
//  13 1 Rt2      3
//  14 1 Rt2      4
//  15 0 o0       0
//  16 1 Rs       0
//  17 1 Rs       1
//  18 1 Rs       2
//  19 1 Rs       3
//  20 1 Rs       4
//  21 0 o1       0
//  22 1 L        0
//  23 1 o2       0
//  24 0
//  25 0
//  26 0
//  27 1
//  28 0
//  29 0
//  30 1 size     0
//  31 0 size     1
// LDLARH  <Wt>, [<Xn|SP>{,#0}]
bool TryDecodeLDLARH_LR32_LDSTEXCL(const InstData &, Instruction &) {
  return false;
}

// LSRV LSR_LSRV_32_dp_2src:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 op2      0
//  11 0 op2      1
//  12 0 opcode2  2
//  13 1 opcode2  3
//  14 0 opcode2  4
//  15 0 opcode2  5
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 1
//  23 1
//  24 0
//  25 1
//  26 0
//  27 1
//  28 1
//  29 0 S        0
//  30 0 op       0
//  31 0 sf       0
// LSR  <Wd>, <Wn>, <Wm>
bool TryDecodeLSR_LSRV_32_DP_2SRC(const InstData &, Instruction &) {
  return false;
}

// LSRV LSR_LSRV_64_dp_2src:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 op2      0
//  11 0 op2      1
//  12 0 opcode2  2
//  13 1 opcode2  3
//  14 0 opcode2  4
//  15 0 opcode2  5
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 1
//  23 1
//  24 0
//  25 1
//  26 0
//  27 1
//  28 1
//  29 0 S        0
//  30 0 op       0
//  31 1 sf       0
// LSR  <Xd>, <Xn>, <Xm>
bool TryDecodeLSR_LSRV_64_DP_2SRC(const InstData &, Instruction &) {
  return false;
}

// FCVTN FCVTN_asimdmisc_N:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 opcode   0
//  13 1 opcode   1
//  14 1 opcode   2
//  15 0 opcode   3
//  16 1 opcode   4
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x sz       0
//  23 0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// FCVTN{2}  <Vd>.<Tb>, <Vn>.<Ta>
bool TryDecodeFCVTN_ASIMDMISC_N(const InstData &, Instruction &) {
  return false;
}

// CSNEG CNEG_CSNEG_32_condsel:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 o2       0
//  11 0
//  12 x cond     0
//  13 x cond     1
//  14 x cond     2
//  15 x cond     3
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 0
//  23 1
//  24 0
//  25 1
//  26 0
//  27 1
//  28 1
//  29 0 S        0
//  30 1 op       0
//  31 0 sf       0
// CNEG  <Wd>, <Wn>, <cond>
bool TryDecodeCNEG_CSNEG_32_CONDSEL(const InstData &, Instruction &) {
  return false;
}

// CSNEG CNEG_CSNEG_64_condsel:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 o2       0
//  11 0
//  12 x cond     0
//  13 x cond     1
//  14 x cond     2
//  15 x cond     3
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 0
//  23 1
//  24 0
//  25 1
//  26 0
//  27 1
//  28 1
//  29 0 S        0
//  30 1 op       0
//  31 1 sf       0
// CNEG  <Xd>, <Xn>, <cond>
bool TryDecodeCNEG_CSNEG_64_CONDSEL(const InstData &, Instruction &) {
  return false;
}

// ABS ABS_asisdmisc_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 opcode   0
//  13 1 opcode   1
//  14 0 opcode   2
//  15 1 opcode   3
//  16 0 opcode   4
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// ABS  <V><d>, <V><n>
bool TryDecodeABS_ASISDMISC_R(const InstData &, Instruction &) {
  return false;
}

// ABS ABS_asimdmisc_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 opcode   0
//  13 1 opcode   1
//  14 0 opcode   2
//  15 1 opcode   3
//  16 0 opcode   4
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// ABS  <Vd>.<T>, <Vn>.<T>
bool TryDecodeABS_ASIMDMISC_R(const InstData &, Instruction &) {
  return false;
}

// FMAX FMAX_asimdsamefp16_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 opcode   0
//  12 1 opcode   1
//  13 1 opcode   2
//  14 0
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 1
//  23 0 o1       0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// FMAX  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeFMAX_ASIMDSAMEFP16_ONLY(const InstData &, Instruction &) {
  return false;
}

// FMAX FMAX_asimdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 opcode   0
//  12 1 opcode   1
//  13 1 opcode   2
//  14 1 opcode   3
//  15 1 opcode   4
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x sz       0
//  23 0 o1       0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// FMAX  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeFMAX_ASIMDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// FMIN FMIN_H_floatdp2:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 op       0
//  13 0 op       1
//  14 1
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 1 type     0
//  23 1 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 M        0
// FMIN  <Hd>, <Hn>, <Hm>
bool TryDecodeFMIN_H_FLOATDP2(const InstData &, Instruction &) {
  return false;
}

// FMIN FMIN_S_floatdp2:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 op       0
//  13 0 op       1
//  14 1
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 0 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 M        0
// FMIN  <Sd>, <Sn>, <Sm>
bool TryDecodeFMIN_S_FLOATDP2(const InstData &, Instruction &) {
  return false;
}

// FMIN FMIN_D_floatdp2:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 op       0
//  13 0 op       1
//  14 1
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 1 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 M        0
// FMIN  <Dd>, <Dn>, <Dm>
bool TryDecodeFMIN_D_FLOATDP2(const InstData &, Instruction &) {
  return false;
}

// UMLSL UMLSL_asimdelem_L:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 x H        0
//  12 0
//  13 1
//  14 1 o2       0
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x M        0
//  21 x L        0
//  22 x size     0
//  23 x size     1
//  24 1
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// UMLSL{2}  <Vd>.<Ta>, <Vn>.<Tb>, <Vm>.<Ts>[<index>]
bool TryDecodeUMLSL_ASIMDELEM_L(const InstData &, Instruction &) {
  return false;
}

// FMAXNM FMAXNM_asimdsamefp16_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 Op3      0
//  12 0 Op3      1
//  13 0 Op3      2
//  14 0
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 1
//  23 0 a        0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// FMAXNM  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeFMAXNM_ASIMDSAMEFP16_ONLY(const InstData &, Instruction &) {
  return false;
}

// FMAXNM FMAXNM_asimdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 opcode   0
//  12 0 opcode   1
//  13 0 opcode   2
//  14 1 opcode   3
//  15 1 opcode   4
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x sz       0
//  23 0 o1       0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// FMAXNM  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeFMAXNM_ASIMDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// FCVTPS FCVTPS_32H_float2int:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 0
//  15 0
//  16 0 opcode   0
//  17 0 opcode   1
//  18 0 opcode   2
//  19 1 rmode    0
//  20 0 rmode    1
//  21 1
//  22 1 type     0
//  23 1 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 sf       0
// FCVTPS  <Wd>, <Hn>
bool TryDecodeFCVTPS_32H_FLOAT2INT(const InstData &, Instruction &) {
  return false;
}

// FCVTPS FCVTPS_64H_float2int:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 0
//  15 0
//  16 0 opcode   0
//  17 0 opcode   1
//  18 0 opcode   2
//  19 1 rmode    0
//  20 0 rmode    1
//  21 1
//  22 1 type     0
//  23 1 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 1 sf       0
// FCVTPS  <Xd>, <Hn>
bool TryDecodeFCVTPS_64H_FLOAT2INT(const InstData &, Instruction &) {
  return false;
}

// FCVTPS FCVTPS_32S_float2int:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 0
//  15 0
//  16 0 opcode   0
//  17 0 opcode   1
//  18 0 opcode   2
//  19 1 rmode    0
//  20 0 rmode    1
//  21 1
//  22 0 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 sf       0
// FCVTPS  <Wd>, <Sn>
bool TryDecodeFCVTPS_32S_FLOAT2INT(const InstData &, Instruction &) {
  return false;
}

// FCVTPS FCVTPS_64S_float2int:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 0
//  15 0
//  16 0 opcode   0
//  17 0 opcode   1
//  18 0 opcode   2
//  19 1 rmode    0
//  20 0 rmode    1
//  21 1
//  22 0 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 1 sf       0
// FCVTPS  <Xd>, <Sn>
bool TryDecodeFCVTPS_64S_FLOAT2INT(const InstData &, Instruction &) {
  return false;
}

// FCVTPS FCVTPS_32D_float2int:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 0
//  15 0
//  16 0 opcode   0
//  17 0 opcode   1
//  18 0 opcode   2
//  19 1 rmode    0
//  20 0 rmode    1
//  21 1
//  22 1 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 sf       0
// FCVTPS  <Wd>, <Dn>
bool TryDecodeFCVTPS_32D_FLOAT2INT(const InstData &, Instruction &) {
  return false;
}

// FCVTPS FCVTPS_64D_float2int:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 0
//  15 0
//  16 0 opcode   0
//  17 0 opcode   1
//  18 0 opcode   2
//  19 1 rmode    0
//  20 0 rmode    1
//  21 1
//  22 1 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 1 sf       0
// FCVTPS  <Xd>, <Dn>
bool TryDecodeFCVTPS_64D_FLOAT2INT(const InstData &, Instruction &) {
  return false;
}

// FMINNM FMINNM_H_floatdp2:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 op       0
//  13 1 op       1
//  14 1
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 1 type     0
//  23 1 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 M        0
// FMINNM  <Hd>, <Hn>, <Hm>
bool TryDecodeFMINNM_H_FLOATDP2(const InstData &, Instruction &) {
  return false;
}

// FMINNM FMINNM_S_floatdp2:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 op       0
//  13 1 op       1
//  14 1
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 0 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 M        0
// FMINNM  <Sd>, <Sn>, <Sm>
bool TryDecodeFMINNM_S_FLOATDP2(const InstData &, Instruction &) {
  return false;
}

// FMINNM FMINNM_D_floatdp2:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 op       0
//  13 1 op       1
//  14 1
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 1 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 M        0
// FMINNM  <Dd>, <Dn>, <Dm>
bool TryDecodeFMINNM_D_FLOATDP2(const InstData &, Instruction &) {
  return false;
}

// LDTRSW LDTRSW_64_ldst_unpriv:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 x imm9     0
//  13 x imm9     1
//  14 x imm9     2
//  15 x imm9     3
//  16 x imm9     4
//  17 x imm9     5
//  18 x imm9     6
//  19 x imm9     7
//  20 x imm9     8
//  21 0
//  22 0 opc      0
//  23 1 opc      1
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 1 size     1
// LDTRSW  <Xt>, [<Xn|SP>{, #<simm>}]
bool TryDecodeLDTRSW_64_LDST_UNPRIV(const InstData &, Instruction &) {
  return false;
}

// FSQRT FSQRT_H_floatdp1:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 1
//  15 1 opc      0
//  16 1 opc      1
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 1 type     0
//  23 1 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 M        0
// FSQRT  <Hd>, <Hn>
bool TryDecodeFSQRT_H_FLOATDP1(const InstData &, Instruction &) {
  return false;
}

// FSQRT FSQRT_S_floatdp1:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 1
//  15 1 opc      0
//  16 1 opc      1
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 0 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 M        0
// FSQRT  <Sd>, <Sn>
bool TryDecodeFSQRT_S_FLOATDP1(const InstData &, Instruction &) {
  return false;
}

// FSQRT FSQRT_D_floatdp1:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 1
//  15 1 opc      0
//  16 1 opc      1
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 1 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 M        0
// FSQRT  <Dd>, <Dn>
bool TryDecodeFSQRT_D_FLOATDP1(const InstData &, Instruction &) {
  return false;
}

// LDEORA LDEORA_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 1 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 1 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 1 size     1
// LDEORA  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDEORA_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDEORAL LDEORAL_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 1 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 1 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 1 size     1
// LDEORAL  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDEORAL_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDEOR LDEOR_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 1 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 1 size     1
// LDEOR  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDEOR_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDEORL LDEORL_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 1 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 1 size     1
// LDEORL  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDEORL_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDEORA LDEORA_64_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 1 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 1 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 1 size     1
// LDEORA  <Xs>, <Xt>, [<Xn|SP>]
bool TryDecodeLDEORA_64_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDEORAL LDEORAL_64_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 1 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 1 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 1 size     1
// LDEORAL  <Xs>, <Xt>, [<Xn|SP>]
bool TryDecodeLDEORAL_64_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDEOR LDEOR_64_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 1 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 1 size     1
// LDEOR  <Xs>, <Xt>, [<Xn|SP>]
bool TryDecodeLDEOR_64_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDEORL LDEORL_64_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 1 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 1 size     1
// LDEORL  <Xs>, <Xt>, [<Xn|SP>]
bool TryDecodeLDEORL_64_MEMOP(const InstData &, Instruction &) {
  return false;
}

// SHRN SHRN_asimdshf_N:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 op       0
//  12 0
//  13 0
//  14 0
//  15 1
//  16 x immb     0
//  17 x immb     1
//  18 x immb     2
//  19 x immh     0
//  20 x immh     1
//  21 x immh     2
//  22 x immh     3
//  23 0
//  24 1
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// SHRN{2}  <Vd>.<Tb>, <Vn>.<Ta>, #<shift>
bool TryDecodeSHRN_ASIMDSHF_N(const InstData &, Instruction &) {
  return false;
}

// FRINTM FRINTM_H_floatdp1:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 1
//  15 0 rmode    0
//  16 1 rmode    1
//  17 0 rmode    2
//  18 1
//  19 0
//  20 0
//  21 1
//  22 1 type     0
//  23 1 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 M        0
// FRINTM  <Hd>, <Hn>
bool TryDecodeFRINTM_H_FLOATDP1(const InstData &, Instruction &) {
  return false;
}

// FRINTM FRINTM_S_floatdp1:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 1
//  15 0 rmode    0
//  16 1 rmode    1
//  17 0 rmode    2
//  18 1
//  19 0
//  20 0
//  21 1
//  22 0 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 M        0
// FRINTM  <Sd>, <Sn>
bool TryDecodeFRINTM_S_FLOATDP1(const InstData &, Instruction &) {
  return false;
}

// FRINTM FRINTM_D_floatdp1:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 1
//  15 0 rmode    0
//  16 1 rmode    1
//  17 0 rmode    2
//  18 1
//  19 0
//  20 0
//  21 1
//  22 1 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 M        0
// FRINTM  <Dd>, <Dn>
bool TryDecodeFRINTM_D_FLOATDP1(const InstData &, Instruction &) {
  return false;
}

// LDUMINAB LDUMINAB_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 1 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 1 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 0 size     1
// LDUMINAB  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDUMINAB_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDUMINALB LDUMINALB_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 1 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 1 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 0 size     1
// LDUMINALB  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDUMINALB_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDUMINB LDUMINB_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 1 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 0 size     1
// LDUMINB  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDUMINB_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDUMINLB LDUMINLB_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 1 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 0 size     1
// LDUMINLB  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDUMINLB_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// SHA256SU0 SHA256SU0_VV_cryptosha2:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 opcode   0
//  13 1 opcode   1
//  14 0 opcode   2
//  15 0 opcode   3
//  16 0 opcode   4
//  17 0
//  18 0
//  19 1
//  20 0
//  21 1
//  22 0 size     0
//  23 0 size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0
//  30 1
//  31 0
// SHA256SU0  <Vd>.4S, <Vn>.4S
bool TryDecodeSHA256SU0_VV_CRYPTOSHA2(const InstData &, Instruction &) {
  return false;
}

// FMINP FMINP_asimdsamefp16_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 opcode   0
//  12 1 opcode   1
//  13 1 opcode   2
//  14 0
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 1
//  23 1 o1       0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// FMINP  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeFMINP_ASIMDSAMEFP16_ONLY(const InstData &, Instruction &) {
  return false;
}

// FMINP FMINP_asimdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 opcode   0
//  12 1 opcode   1
//  13 1 opcode   2
//  14 1 opcode   3
//  15 1 opcode   4
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x sz       0
//  23 1 o1       0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// FMINP  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeFMINP_ASIMDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// SQRDMLSH SQRDMLSH_asisdelem_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 x H        0
//  12 1
//  13 1 S        0
//  14 1
//  15 1
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x M        0
//  21 x L        0
//  22 x size     0
//  23 x size     1
//  24 1
//  25 1
//  26 1
//  27 1
//  28 1
//  29 1 U        0
//  30 1
//  31 0
// SQRDMLSH  <V><d>, <V><n>, <Vm>.<Ts>[<index>]
bool TryDecodeSQRDMLSH_ASISDELEM_R(const InstData &, Instruction &) {
  return false;
}

// SQRDMLSH SQRDMLSH_asimdelem_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 x H        0
//  12 1
//  13 1 S        0
//  14 1
//  15 1
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x M        0
//  21 x L        0
//  22 x size     0
//  23 x size     1
//  24 1
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// SQRDMLSH  <Vd>.<T>, <Vn>.<T>, <Vm>.<Ts>[<index>]
bool TryDecodeSQRDMLSH_ASIMDELEM_R(const InstData &, Instruction &) {
  return false;
}

// LDCLRA LDCLRA_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 0 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 1 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 1 size     1
// LDCLRA  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDCLRA_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDCLRAL LDCLRAL_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 0 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 1 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 1 size     1
// LDCLRAL  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDCLRAL_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDCLR LDCLR_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 0 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 1 size     1
// LDCLR  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDCLR_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDCLRL LDCLRL_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 0 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 1 size     1
// LDCLRL  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDCLRL_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDCLRA LDCLRA_64_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 0 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 1 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 1 size     1
// LDCLRA  <Xs>, <Xt>, [<Xn|SP>]
bool TryDecodeLDCLRA_64_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDCLRAL LDCLRAL_64_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 0 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 1 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 1 size     1
// LDCLRAL  <Xs>, <Xt>, [<Xn|SP>]
bool TryDecodeLDCLRAL_64_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDCLR LDCLR_64_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 0 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 1 size     1
// LDCLR  <Xs>, <Xt>, [<Xn|SP>]
bool TryDecodeLDCLR_64_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDCLRL LDCLRL_64_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 0 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 1 size     1
// LDCLRL  <Xs>, <Xt>, [<Xn|SP>]
bool TryDecodeLDCLRL_64_MEMOP(const InstData &, Instruction &) {
  return false;
}

// UABD UABD_asimdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 ac       0
//  12 1
//  13 1
//  14 1
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// UABD  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeUABD_ASIMDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// FRINTA FRINTA_asimdmiscfp16_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 o1       0
//  13 0
//  14 0
//  15 1
//  16 1
//  17 0
//  18 0
//  19 1
//  20 1
//  21 1
//  22 1
//  23 0 o2       0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// FRINTA  <Vd>.<T>, <Vn>.<T>
bool TryDecodeFRINTA_ASIMDMISCFP16_R(const InstData &, Instruction &) {
  return false;
}

// FRINTA FRINTA_asimdmisc_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 o1       0
//  13 0
//  14 0
//  15 1
//  16 1
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x sz       0
//  23 0 o2       0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// FRINTA  <Vd>.<T>, <Vn>.<T>
bool TryDecodeFRINTA_ASIMDMISC_R(const InstData &, Instruction &) {
  return false;
}

// STXP STXP_SP32_ldstexcl:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x Rt2      0
//  11 x Rt2      1
//  12 x Rt2      2
//  13 x Rt2      3
//  14 x Rt2      4
//  15 0 o0       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1 o1       0
//  22 0 L        0
//  23 0 o2       0
//  24 0
//  25 0
//  26 0
//  27 1
//  28 0
//  29 0
//  30 0 sz       0
//  31 1
// STXP  <Ws>, <Wt1>, <Wt2>, [<Xn|SP>{,#0}]
bool TryDecodeSTXP_SP32_LDSTEXCL(const InstData &, Instruction &) {
  return false;
}

// STXP STXP_SP64_ldstexcl:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x Rt2      0
//  11 x Rt2      1
//  12 x Rt2      2
//  13 x Rt2      3
//  14 x Rt2      4
//  15 0 o0       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1 o1       0
//  22 0 L        0
//  23 0 o2       0
//  24 0
//  25 0
//  26 0
//  27 1
//  28 0
//  29 0
//  30 1 sz       0
//  31 1
// STXP  <Ws>, <Xt1>, <Xt2>, [<Xn|SP>{,#0}]
bool TryDecodeSTXP_SP64_LDSTEXCL(const InstData &, Instruction &) {
  return false;
}

// SBFM SBFX_SBFM_32M_bitfield:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x imms     0
//  11 x imms     1
//  12 x imms     2
//  13 x imms     3
//  14 x imms     4
//  15 x imms     5
//  16 x immr     0
//  17 x immr     1
//  18 x immr     2
//  19 x immr     3
//  20 x immr     4
//  21 x immr     5
//  22 0 N        0
//  23 0
//  24 1
//  25 1
//  26 0
//  27 0
//  28 1
//  29 0 opc      0
//  30 0 opc      1
//  31 0 sf       0
// SBFX  <Wd>, <Wn>, #<lsb>, #<width>
bool TryDecodeSBFX_SBFM_32M_BITFIELD(const InstData &, Instruction &) {
  return false;
}

// SBFM SBFX_SBFM_64M_bitfield:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x imms     0
//  11 x imms     1
//  12 x imms     2
//  13 x imms     3
//  14 x imms     4
//  15 x imms     5
//  16 x immr     0
//  17 x immr     1
//  18 x immr     2
//  19 x immr     3
//  20 x immr     4
//  21 x immr     5
//  22 1 N        0
//  23 0
//  24 1
//  25 1
//  26 0
//  27 0
//  28 1
//  29 0 opc      0
//  30 0 opc      1
//  31 1 sf       0
// SBFX  <Xd>, <Xn>, #<lsb>, #<width>
bool TryDecodeSBFX_SBFM_64M_BITFIELD(const InstData &, Instruction &) {
  return false;
}

// LDXP LDXP_LP32_ldstexcl:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x Rt2      0
//  11 x Rt2      1
//  12 x Rt2      2
//  13 x Rt2      3
//  14 x Rt2      4
//  15 0 o0       0
//  16 1 Rs       0
//  17 1 Rs       1
//  18 1 Rs       2
//  19 1 Rs       3
//  20 1 Rs       4
//  21 1 o1       0
//  22 1 L        0
//  23 0 o2       0
//  24 0
//  25 0
//  26 0
//  27 1
//  28 0
//  29 0
//  30 0 sz       0
//  31 1
// LDXP  <Wt1>, <Wt2>, [<Xn|SP>{,#0}]
bool TryDecodeLDXP_LP32_LDSTEXCL(const InstData &, Instruction &) {
  return false;
}

// LDXP LDXP_LP64_ldstexcl:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x Rt2      0
//  11 x Rt2      1
//  12 x Rt2      2
//  13 x Rt2      3
//  14 x Rt2      4
//  15 0 o0       0
//  16 1 Rs       0
//  17 1 Rs       1
//  18 1 Rs       2
//  19 1 Rs       3
//  20 1 Rs       4
//  21 1 o1       0
//  22 1 L        0
//  23 0 o2       0
//  24 0
//  25 0
//  26 0
//  27 1
//  28 0
//  29 0
//  30 1 sz       0
//  31 1
// LDXP  <Xt1>, <Xt2>, [<Xn|SP>{,#0}]
bool TryDecodeLDXP_LP64_LDSTEXCL(const InstData &, Instruction &) {
  return false;
}

// UCVTF UCVTF_asisdmiscfp16_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 opcode   0
//  13 0 opcode   1
//  14 1 opcode   2
//  15 1 opcode   3
//  16 1 opcode   4
//  17 0
//  18 0
//  19 1
//  20 1
//  21 1
//  22 1
//  23 0 a        0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 1 U        0
//  30 1
//  31 0
// UCVTF  <Hd>, <Hn>
bool TryDecodeUCVTF_ASISDMISCFP16_R(const InstData &, Instruction &) {
  return false;
}

// UCVTF UCVTF_asisdmisc_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 opcode   0
//  13 0 opcode   1
//  14 1 opcode   2
//  15 1 opcode   3
//  16 1 opcode   4
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x sz       0
//  23 0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 1 U        0
//  30 1
//  31 0
// UCVTF  <V><d>, <V><n>
bool TryDecodeUCVTF_ASISDMISC_R(const InstData &, Instruction &) {
  return false;
}

// UCVTF UCVTF_asimdmiscfp16_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 opcode   0
//  13 0 opcode   1
//  14 1 opcode   2
//  15 1 opcode   3
//  16 1 opcode   4
//  17 0
//  18 0
//  19 1
//  20 1
//  21 1
//  22 1
//  23 0 a        0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// UCVTF  <Vd>.<T>, <Vn>.<T>
bool TryDecodeUCVTF_ASIMDMISCFP16_R(const InstData &, Instruction &) {
  return false;
}

// UCVTF UCVTF_asimdmisc_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 opcode   0
//  13 0 opcode   1
//  14 1 opcode   2
//  15 1 opcode   3
//  16 1 opcode   4
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x sz       0
//  23 0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// UCVTF  <Vd>.<T>, <Vn>.<T>
bool TryDecodeUCVTF_ASIMDMISC_R(const InstData &, Instruction &) {
  return false;
}

// SQDMULH SQDMULH_asisdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 opcode   0
//  12 1 opcode   1
//  13 1 opcode   2
//  14 0 opcode   3
//  15 1 opcode   4
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// SQDMULH  <V><d>, <V><n>, <V><m>
bool TryDecodeSQDMULH_ASISDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// SQDMULH SQDMULH_asimdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 opcode   0
//  12 1 opcode   1
//  13 1 opcode   2
//  14 0 opcode   3
//  15 1 opcode   4
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// SQDMULH  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeSQDMULH_ASIMDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// FCVTL FCVTL_asimdmisc_L:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 opcode   0
//  13 1 opcode   1
//  14 1 opcode   2
//  15 0 opcode   3
//  16 1 opcode   4
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x sz       0
//  23 0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// FCVTL{2}  <Vd>.<Ta>, <Vn>.<Tb>
bool TryDecodeFCVTL_ASIMDMISC_L(const InstData &, Instruction &) {
  return false;
}

// YIELD YIELD_HI_system:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 1 op2      0
//   6 0 op2      1
//   7 0 op2      2
//   8 0 CRm      0
//   9 0 CRm      1
//  10 0 CRm      2
//  11 0 CRm      3
//  12 0 CRn      0
//  13 1 CRn      1
//  14 0 CRn      2
//  15 0 CRn      3
//  16 1 op1      0
//  17 1 op1      1
//  18 0 op1      2
//  19 0 op0      0
//  20 0 op0      1
//  21 0 L        0
//  22 0
//  23 0
//  24 1
//  25 0
//  26 1
//  27 0
//  28 1
//  29 0
//  30 1
//  31 1
// YIELD
bool TryDecodeYIELD_HI_SYSTEM(const InstData &, Instruction &) {
  return false;
}

// UBFM UXTH_UBFM_32M_bitfield:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 imms     0
//  11 1 imms     1
//  12 1 imms     2
//  13 1 imms     3
//  14 0 imms     4
//  15 0 imms     5
//  16 0 immr     0
//  17 0 immr     1
//  18 0 immr     2
//  19 0 immr     3
//  20 0 immr     4
//  21 0 immr     5
//  22 0 N        0
//  23 0
//  24 1
//  25 1
//  26 0
//  27 0
//  28 1
//  29 0 opc      0
//  30 1 opc      1
//  31 0 sf       0
// UXTH  <Wd>, <Wn>
bool TryDecodeUXTH_UBFM_32M_BITFIELD(const InstData &, Instruction &) {
  return false;
}

// STADD STADD_32S_memop:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 0 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 1 size     1
// STADD  <Ws>, [<Xn|SP>]
bool TryDecodeSTADD_32S_MEMOP(const InstData &, Instruction &) {
  return false;
}

// STADDL STADDL_32S_memop:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 0 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 1 size     1
// STADDL  <Ws>, [<Xn|SP>]
bool TryDecodeSTADDL_32S_MEMOP(const InstData &, Instruction &) {
  return false;
}

// STADD STADD_64S_memop:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 0 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 1 size     1
// STADD  <Xs>, [<Xn|SP>]
bool TryDecodeSTADD_64S_MEMOP(const InstData &, Instruction &) {
  return false;
}

// STADDL STADDL_64S_memop:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 0 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 1 size     1
// STADDL  <Xs>, [<Xn|SP>]
bool TryDecodeSTADDL_64S_MEMOP(const InstData &, Instruction &) {
  return false;
}

// USRA USRA_asisdshf_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0
//  12 1 o0       0
//  13 0 o1       0
//  14 0
//  15 0
//  16 x immb     0
//  17 x immb     1
//  18 x immb     2
//  19 x immh     0
//  20 x immh     1
//  21 x immh     2
//  22 x immh     3
//  23 0
//  24 1
//  25 1
//  26 1
//  27 1
//  28 1
//  29 1 U        0
//  30 1
//  31 0
// USRA  <V><d>, <V><n>, #<shift>
bool TryDecodeUSRA_ASISDSHF_R(const InstData &, Instruction &) {
  return false;
}

// USRA USRA_asimdshf_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0
//  12 1 o0       0
//  13 0 o1       0
//  14 0
//  15 0
//  16 x immb     0
//  17 x immb     1
//  18 x immb     2
//  19 x immh     0
//  20 x immh     1
//  21 x immh     2
//  22 x immh     3
//  23 0
//  24 1
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// USRA  <Vd>.<T>, <Vn>.<T>, #<shift>
bool TryDecodeUSRA_ASIMDSHF_R(const InstData &, Instruction &) {
  return false;
}

// MLS MLS_asimdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 opcode   0
//  12 1 opcode   1
//  13 0 opcode   2
//  14 0 opcode   3
//  15 1 opcode   4
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// MLS  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeMLS_ASIMDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// ST1 ST1_asisdlse_R3_3v:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x size     0
//  11 x size     1
//  12 0 opcode   0
//  13 1 opcode   1
//  14 1 opcode   2
//  15 0 opcode   3
//  16 0
//  17 0
//  18 0
//  19 0
//  20 0
//  21 0
//  22 0 L        0
//  23 0
//  24 0
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// ST1  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T> }, [<Xn|SP>]
bool TryDecodeST1_ASISDLSE_R3_3V(const InstData &, Instruction &) {
  return false;
}

// ST1 ST1_asisdlse_R4_4v:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x size     0
//  11 x size     1
//  12 0 opcode   0
//  13 1 opcode   1
//  14 0 opcode   2
//  15 0 opcode   3
//  16 0
//  17 0
//  18 0
//  19 0
//  20 0
//  21 0
//  22 0 L        0
//  23 0
//  24 0
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// ST1  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T>, <Vt4>.<T> }, [<Xn|SP>]
bool TryDecodeST1_ASISDLSE_R4_4V(const InstData &, Instruction &) {
  return false;
}

// ST1 ST1_asisdlsep_I1_i1:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x size     0
//  11 x size     1
//  12 1 opcode   0
//  13 1 opcode   1
//  14 1 opcode   2
//  15 0 opcode   3
//  16 1 Rm       0
//  17 1 Rm       1
//  18 1 Rm       2
//  19 1 Rm       3
//  20 1 Rm       4
//  21 0
//  22 0 L        0
//  23 1
//  24 0
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// ST1  { <Vt>.<T> }, [<Xn|SP>], <imm>
bool TryDecodeST1_ASISDLSEP_I1_I1(const InstData &, Instruction &) {
  return false;
}

// ST1 ST1_asisdlsep_R1_r1:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x size     0
//  11 x size     1
//  12 1 opcode   0
//  13 1 opcode   1
//  14 1 opcode   2
//  15 0 opcode   3
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 0 L        0
//  23 1
//  24 0
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// ST1  { <Vt>.<T> }, [<Xn|SP>], <Xm>
bool TryDecodeST1_ASISDLSEP_R1_R1(const InstData &, Instruction &) {
  return false;
}

// ST1 ST1_asisdlsep_R2_r2:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x size     0
//  11 x size     1
//  12 0 opcode   0
//  13 1 opcode   1
//  14 0 opcode   2
//  15 1 opcode   3
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 0 L        0
//  23 1
//  24 0
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// ST1  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>], <Xm>
bool TryDecodeST1_ASISDLSEP_R2_R2(const InstData &, Instruction &) {
  return false;
}

// ST1 ST1_asisdlsep_I3_i3:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x size     0
//  11 x size     1
//  12 0 opcode   0
//  13 1 opcode   1
//  14 1 opcode   2
//  15 0 opcode   3
//  16 1 Rm       0
//  17 1 Rm       1
//  18 1 Rm       2
//  19 1 Rm       3
//  20 1 Rm       4
//  21 0
//  22 0 L        0
//  23 1
//  24 0
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// ST1  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T> }, [<Xn|SP>], <imm>
bool TryDecodeST1_ASISDLSEP_I3_I3(const InstData &, Instruction &) {
  return false;
}

// ST1 ST1_asisdlsep_R3_r3:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x size     0
//  11 x size     1
//  12 0 opcode   0
//  13 1 opcode   1
//  14 1 opcode   2
//  15 0 opcode   3
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 0 L        0
//  23 1
//  24 0
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// ST1  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T> }, [<Xn|SP>], <Xm>
bool TryDecodeST1_ASISDLSEP_R3_R3(const InstData &, Instruction &) {
  return false;
}

// ST1 ST1_asisdlsep_I4_i4:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x size     0
//  11 x size     1
//  12 0 opcode   0
//  13 1 opcode   1
//  14 0 opcode   2
//  15 0 opcode   3
//  16 1 Rm       0
//  17 1 Rm       1
//  18 1 Rm       2
//  19 1 Rm       3
//  20 1 Rm       4
//  21 0
//  22 0 L        0
//  23 1
//  24 0
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// ST1  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T>, <Vt4>.<T> }, [<Xn|SP>], <imm>
bool TryDecodeST1_ASISDLSEP_I4_I4(const InstData &, Instruction &) {
  return false;
}

// ST1 ST1_asisdlsep_R4_r4:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x size     0
//  11 x size     1
//  12 0 opcode   0
//  13 1 opcode   1
//  14 0 opcode   2
//  15 0 opcode   3
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 0 L        0
//  23 1
//  24 0
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// ST1  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T>, <Vt4>.<T> }, [<Xn|SP>], <Xm>
bool TryDecodeST1_ASISDLSEP_R4_R4(const InstData &, Instruction &) {
  return false;
}

// AESIMC AESIMC_B_cryptoaes:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 D        0
//  13 1
//  14 1
//  15 0
//  16 0
//  17 0
//  18 0
//  19 1
//  20 0
//  21 1
//  22 0 size     0
//  23 0 size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0
//  30 1
//  31 0
// AESIMC  <Vd>.16B, <Vn>.16B
bool TryDecodeAESIMC_B_CRYPTOAES(const InstData &, Instruction &) {
  return false;
}

// UADDW UADDW_asimddiff_W:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1
//  13 0 o1       0
//  14 0
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// UADDW{2}  <Vd>.<Ta>, <Vn>.<Ta>, <Vm>.<Tb>
bool TryDecodeUADDW_ASIMDDIFF_W(const InstData &, Instruction &) {
  return false;
}

// STUMAXB STUMAXB_32S_memop:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 1 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 0 size     1
// STUMAXB  <Ws>, [<Xn|SP>]
bool TryDecodeSTUMAXB_32S_MEMOP(const InstData &, Instruction &) {
  return false;
}

// STUMAXLB STUMAXLB_32S_memop:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 1 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 0 size     1
// STUMAXLB  <Ws>, [<Xn|SP>]
bool TryDecodeSTUMAXLB_32S_MEMOP(const InstData &, Instruction &) {
  return false;
}

// CMHI CMHI_asisdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 eq       0
//  12 1
//  13 1
//  14 0
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 1 U        0
//  30 1
//  31 0
// CMHI  <V><d>, <V><n>, <V><m>
bool TryDecodeCMHI_ASISDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// CMHI CMHI_asimdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 eq       0
//  12 1
//  13 1
//  14 0
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// CMHI  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeCMHI_ASIMDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// SQDMLAL SQDMLAL_asisddiff_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1
//  13 0 o1       0
//  14 0
//  15 1
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// SQDMLAL  <Va><d>, <Vb><n>, <Vb><m>
bool TryDecodeSQDMLAL_ASISDDIFF_ONLY(const InstData &, Instruction &) {
  return false;
}

// SQDMLAL SQDMLAL_asimddiff_L:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1
//  13 0 o1       0
//  14 0
//  15 1
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// SQDMLAL{2}  <Vd>.<Ta>, <Vn>.<Tb>, <Vm>.<Tb>
bool TryDecodeSQDMLAL_ASIMDDIFF_L(const InstData &, Instruction &) {
  return false;
}

// SEVL SEVL_HI_system:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 1 op2      0
//   6 0 op2      1
//   7 1 op2      2
//   8 0 CRm      0
//   9 0 CRm      1
//  10 0 CRm      2
//  11 0 CRm      3
//  12 0 CRn      0
//  13 1 CRn      1
//  14 0 CRn      2
//  15 0 CRn      3
//  16 1 op1      0
//  17 1 op1      1
//  18 0 op1      2
//  19 0 op0      0
//  20 0 op0      1
//  21 0 L        0
//  22 0
//  23 0
//  24 1
//  25 0
//  26 1
//  27 0
//  28 1
//  29 0
//  30 1
//  31 1
// SEVL
bool TryDecodeSEVL_HI_SYSTEM(const InstData &, Instruction &) {
  return false;
}

// FRINTX FRINTX_H_floatdp1:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 1
//  15 0 rmode    0
//  16 1 rmode    1
//  17 1 rmode    2
//  18 1
//  19 0
//  20 0
//  21 1
//  22 1 type     0
//  23 1 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 M        0
// FRINTX  <Hd>, <Hn>
bool TryDecodeFRINTX_H_FLOATDP1(const InstData &, Instruction &) {
  return false;
}

// FRINTX FRINTX_S_floatdp1:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 1
//  15 0 rmode    0
//  16 1 rmode    1
//  17 1 rmode    2
//  18 1
//  19 0
//  20 0
//  21 1
//  22 0 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 M        0
// FRINTX  <Sd>, <Sn>
bool TryDecodeFRINTX_S_FLOATDP1(const InstData &, Instruction &) {
  return false;
}

// FRINTX FRINTX_D_floatdp1:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 1
//  15 0 rmode    0
//  16 1 rmode    1
//  17 1 rmode    2
//  18 1
//  19 0
//  20 0
//  21 1
//  22 1 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 M        0
// FRINTX  <Dd>, <Dn>
bool TryDecodeFRINTX_D_FLOATDP1(const InstData &, Instruction &) {
  return false;
}

// LDUMAXAB LDUMAXAB_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 1 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 1 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 0 size     1
// LDUMAXAB  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDUMAXAB_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDUMAXALB LDUMAXALB_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 1 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 1 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 0 size     1
// LDUMAXALB  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDUMAXALB_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDUMAXB LDUMAXB_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 1 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 0 size     1
// LDUMAXB  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDUMAXB_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDUMAXLB LDUMAXLB_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 1 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 0 size     1
// LDUMAXLB  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDUMAXLB_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// AESE AESE_B_cryptoaes:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 D        0
//  13 0
//  14 1
//  15 0
//  16 0
//  17 0
//  18 0
//  19 1
//  20 0
//  21 1
//  22 0 size     0
//  23 0 size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0
//  30 1
//  31 0
// AESE  <Vd>.16B, <Vn>.16B
bool TryDecodeAESE_B_CRYPTOAES(const InstData &, Instruction &) {
  return false;
}

// STXR STXR_SR32_ldstexcl:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 Rt2      0
//  11 1 Rt2      1
//  12 1 Rt2      2
//  13 1 Rt2      3
//  14 1 Rt2      4
//  15 0 o0       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 0 o1       0
//  22 0 L        0
//  23 0 o2       0
//  24 0
//  25 0
//  26 0
//  27 1
//  28 0
//  29 0
//  30 0 size     0
//  31 1 size     1
// STXR  <Ws>, <Wt>, [<Xn|SP>{,#0}]
bool TryDecodeSTXR_SR32_LDSTEXCL(const InstData &, Instruction &) {
  return false;
}

// STXR STXR_SR64_ldstexcl:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 Rt2      0
//  11 1 Rt2      1
//  12 1 Rt2      2
//  13 1 Rt2      3
//  14 1 Rt2      4
//  15 0 o0       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 0 o1       0
//  22 0 L        0
//  23 0 o2       0
//  24 0
//  25 0
//  26 0
//  27 1
//  28 0
//  29 0
//  30 1 size     0
//  31 1 size     1
// STXR  <Ws>, <Xt>, [<Xn|SP>{,#0}]
bool TryDecodeSTXR_SR64_LDSTEXCL(const InstData &, Instruction &) {
  return false;
}

// CMLT CMLT_asisdmisc_Z:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 opcode   0
//  13 1 opcode   1
//  14 0 opcode   2
//  15 1 opcode   3
//  16 0 opcode   4
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// CMLT  <V><d>, <V><n>, #0
bool TryDecodeCMLT_ASISDMISC_Z(const InstData &, Instruction &) {
  return false;
}

// FCMEQ FCMEQ_asisdsamefp16_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 ac       0
//  12 0
//  13 1
//  14 0
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 1
//  23 0 E        0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// FCMEQ  <Hd>, <Hn>, <Hm>
bool TryDecodeFCMEQ_ASISDSAMEFP16_ONLY(const InstData &, Instruction &) {
  return false;
}

// FCMEQ FCMEQ_asisdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 ac       0
//  12 0
//  13 1
//  14 1
//  15 1
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x sz       0
//  23 0 E        0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// FCMEQ  <V><d>, <V><n>, <V><m>
bool TryDecodeFCMEQ_ASISDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// FCMEQ FCMEQ_asimdsamefp16_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 ac       0
//  12 0
//  13 1
//  14 0
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 1
//  23 0 E        0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// FCMEQ  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeFCMEQ_ASIMDSAMEFP16_ONLY(const InstData &, Instruction &) {
  return false;
}

// FCMEQ FCMEQ_asimdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 ac       0
//  12 0
//  13 1
//  14 1
//  15 1
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x sz       0
//  23 0 E        0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// FCMEQ  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeFCMEQ_ASIMDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// CLREX CLREX_BN_system:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 0 op2      0
//   6 1 op2      1
//   7 0 op2      2
//   8 x CRm      0
//   9 x CRm      1
//  10 x CRm      2
//  11 x CRm      3
//  12 1 CRn      0
//  13 1 CRn      1
//  14 0 CRn      2
//  15 0 CRn      3
//  16 1 op1      0
//  17 1 op1      1
//  18 0 op1      2
//  19 0 op0      0
//  20 0 op0      1
//  21 0 L        0
//  22 0
//  23 0
//  24 1
//  25 0
//  26 1
//  27 0
//  28 1
//  29 0
//  30 1
//  31 1
// CLREX  {#<imm>}
bool TryDecodeCLREX_BN_SYSTEM(const InstData &, Instruction &) {
  return false;
}

// FSUB FSUB_asimdsamefp16_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 opcode   0
//  12 1 opcode   1
//  13 0 opcode   2
//  14 0
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 1
//  23 1 a        0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// FSUB  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeFSUB_ASIMDSAMEFP16_ONLY(const InstData &, Instruction &) {
  return false;
}

// FSUB FSUB_asimdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 opcode   0
//  12 1 opcode   1
//  13 0 opcode   2
//  14 1 opcode   3
//  15 1 opcode   4
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x sz       0
//  23 1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// FSUB  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeFSUB_ASIMDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// SHLL SHLL_asimdmisc_S:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 opcode   0
//  13 1 opcode   1
//  14 0 opcode   2
//  15 0 opcode   3
//  16 1 opcode   4
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// SHLL{2}  <Vd>.<Ta>, <Vn>.<Tb>, #<shift>
bool TryDecodeSHLL_ASIMDMISC_S(const InstData &, Instruction &) {
  return false;
}

// SQADD SQADD_asisdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1 opcode   0
//  12 0 opcode   1
//  13 0 opcode   2
//  14 0 opcode   3
//  15 0 opcode   4
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// SQADD  <V><d>, <V><n>, <V><m>
bool TryDecodeSQADD_ASISDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// SQADD SQADD_asimdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1 opcode   0
//  12 0 opcode   1
//  13 0 opcode   2
//  14 0 opcode   3
//  15 0 opcode   4
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// SQADD  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeSQADD_ASIMDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// SUB SUB_asisdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 opcode   0
//  12 0 opcode   1
//  13 0 opcode   2
//  14 0 opcode   3
//  15 1 opcode   4
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 1 U        0
//  30 1
//  31 0
// SUB  <V><d>, <V><n>, <V><m>
bool TryDecodeSUB_ASISDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// SWPA SWPA_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 0 opc      1
//  14 0 opc      2
//  15 1 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 1 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 1 size     1
// SWPA  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeSWPA_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// SWPAL SWPAL_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 0 opc      1
//  14 0 opc      2
//  15 1 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 1 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 1 size     1
// SWPAL  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeSWPAL_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// SWP SWP_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 0 opc      1
//  14 0 opc      2
//  15 1 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 1 size     1
// SWP  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeSWP_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// SWPL SWPL_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 0 opc      1
//  14 0 opc      2
//  15 1 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 1 size     1
// SWPL  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeSWPL_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// SWPA SWPA_64_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 0 opc      1
//  14 0 opc      2
//  15 1 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 1 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 1 size     1
// SWPA  <Xs>, <Xt>, [<Xn|SP>]
bool TryDecodeSWPA_64_MEMOP(const InstData &, Instruction &) {
  return false;
}

// SWPAL SWPAL_64_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 0 opc      1
//  14 0 opc      2
//  15 1 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 1 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 1 size     1
// SWPAL  <Xs>, <Xt>, [<Xn|SP>]
bool TryDecodeSWPAL_64_MEMOP(const InstData &, Instruction &) {
  return false;
}

// SWP SWP_64_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 0 opc      1
//  14 0 opc      2
//  15 1 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 1 size     1
// SWP  <Xs>, <Xt>, [<Xn|SP>]
bool TryDecodeSWP_64_MEMOP(const InstData &, Instruction &) {
  return false;
}

// SWPL SWPL_64_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 0 opc      1
//  14 0 opc      2
//  15 1 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 1 size     1
// SWPL  <Xs>, <Xt>, [<Xn|SP>]
bool TryDecodeSWPL_64_MEMOP(const InstData &, Instruction &) {
  return false;
}

// SMC SMC_EX_exception:
//   0 1 LL       0
//   1 1 LL       1
//   2 0 op2      0
//   3 0 op2      1
//   4 0 op2      2
//   5 x imm16    0
//   6 x imm16    1
//   7 x imm16    2
//   8 x imm16    3
//   9 x imm16    4
//  10 x imm16    5
//  11 x imm16    6
//  12 x imm16    7
//  13 x imm16    8
//  14 x imm16    9
//  15 x imm16    10
//  16 x imm16    11
//  17 x imm16    12
//  18 x imm16    13
//  19 x imm16    14
//  20 x imm16    15
//  21 0 opc      0
//  22 0 opc      1
//  23 0 opc      2
//  24 0
//  25 0
//  26 1
//  27 0
//  28 1
//  29 0
//  30 1
//  31 1
// SMC  #<imm>
bool TryDecodeSMC_EX_EXCEPTION(const InstData &, Instruction &) {
  return false;
}


// CMGE CMGE_asisdmisc_Z:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 op       0
//  13 0
//  14 0
//  15 1
//  16 0
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 1 U        0
//  30 1
//  31 0
// CMGE  <V><d>, <V><n>, #0
bool TryDecodeCMGE_ASISDMISC_Z(const InstData &, Instruction &) {
  return false;
}

// UCVTF UCVTF_asisdshf_C:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 opcode   0
//  12 0 opcode   1
//  13 1 opcode   2
//  14 1 opcode   3
//  15 1 opcode   4
//  16 x immb     0
//  17 x immb     1
//  18 x immb     2
//  19 x immh     0
//  20 x immh     1
//  21 x immh     2
//  22 x immh     3
//  23 0
//  24 1
//  25 1
//  26 1
//  27 1
//  28 1
//  29 1 U        0
//  30 1
//  31 0
// UCVTF  <V><d>, <V><n>, #<fbits>
bool TryDecodeUCVTF_ASISDSHF_C(const InstData &, Instruction &) {
  return false;
}

// UCVTF UCVTF_asimdshf_C:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 opcode   0
//  12 0 opcode   1
//  13 1 opcode   2
//  14 1 opcode   3
//  15 1 opcode   4
//  16 x immb     0
//  17 x immb     1
//  18 x immb     2
//  19 x immh     0
//  20 x immh     1
//  21 x immh     2
//  22 x immh     3
//  23 0
//  24 1
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// UCVTF  <Vd>.<T>, <Vn>.<T>, #<fbits>
bool TryDecodeUCVTF_ASIMDSHF_C(const InstData &, Instruction &) {
  return false;
}

// STLLR STLLR_SL32_ldstexcl:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 Rt2      0
//  11 1 Rt2      1
//  12 1 Rt2      2
//  13 1 Rt2      3
//  14 1 Rt2      4
//  15 0 o0       0
//  16 1 Rs       0
//  17 1 Rs       1
//  18 1 Rs       2
//  19 1 Rs       3
//  20 1 Rs       4
//  21 0 o1       0
//  22 0 L        0
//  23 1 o2       0
//  24 0
//  25 0
//  26 0
//  27 1
//  28 0
//  29 0
//  30 0 size     0
//  31 1 size     1
// STLLR  <Wt>, [<Xn|SP>{,#0}]
bool TryDecodeSTLLR_SL32_LDSTEXCL(const InstData &, Instruction &) {
  return false;
}

// STLLR STLLR_SL64_ldstexcl:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 Rt2      0
//  11 1 Rt2      1
//  12 1 Rt2      2
//  13 1 Rt2      3
//  14 1 Rt2      4
//  15 0 o0       0
//  16 1 Rs       0
//  17 1 Rs       1
//  18 1 Rs       2
//  19 1 Rs       3
//  20 1 Rs       4
//  21 0 o1       0
//  22 0 L        0
//  23 1 o2       0
//  24 0
//  25 0
//  26 0
//  27 1
//  28 0
//  29 0
//  30 1 size     0
//  31 1 size     1
// STLLR  <Xt>, [<Xn|SP>{,#0}]
bool TryDecodeSTLLR_SL64_LDSTEXCL(const InstData &, Instruction &) {
  return false;
}

// SSUBL SSUBL_asimddiff_L:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 1 o1       0
//  14 0
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// SSUBL{2}  <Vd>.<Ta>, <Vn>.<Tb>, <Vm>.<Tb>
bool TryDecodeSSUBL_ASIMDDIFF_L(const InstData &, Instruction &) {
  return false;
}

// SMLSL SMLSL_asimddiff_L:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 1 o1       0
//  14 0
//  15 1
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// SMLSL{2}  <Vd>.<Ta>, <Vn>.<Tb>, <Vm>.<Tb>
bool TryDecodeSMLSL_ASIMDDIFF_L(const InstData &, Instruction &) {
  return false;
}

// STTRB STTRB_32_ldst_unpriv:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 x imm9     0
//  13 x imm9     1
//  14 x imm9     2
//  15 x imm9     3
//  16 x imm9     4
//  17 x imm9     5
//  18 x imm9     6
//  19 x imm9     7
//  20 x imm9     8
//  21 0
//  22 0 opc      0
//  23 0 opc      1
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 0 size     1
// STTRB  <Wt>, [<Xn|SP>{, #<simm>}]
bool TryDecodeSTTRB_32_LDST_UNPRIV(const InstData &, Instruction &) {
  return false;
}

// ANDS TST_ANDS_32S_log_imm:
//   0 1 Rd       0
//   1 1 Rd       1
//   2 1 Rd       2
//   3 1 Rd       3
//   4 1 Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x imms     0
//  11 x imms     1
//  12 x imms     2
//  13 x imms     3
//  14 x imms     4
//  15 x imms     5
//  16 x immr     0
//  17 x immr     1
//  18 x immr     2
//  19 x immr     3
//  20 x immr     4
//  21 x immr     5
//  22 0 N        0
//  23 0
//  24 0
//  25 1
//  26 0
//  27 0
//  28 1
//  29 1 opc      0
//  30 1 opc      1
//  31 0 sf       0
// TST  <Wn>, #<imm>
bool TryDecodeTST_ANDS_32S_LOG_IMM(const InstData &, Instruction &) {
  return false;
}

// ANDS TST_ANDS_64S_log_imm:
//   0 1 Rd       0
//   1 1 Rd       1
//   2 1 Rd       2
//   3 1 Rd       3
//   4 1 Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x imms     0
//  11 x imms     1
//  12 x imms     2
//  13 x imms     3
//  14 x imms     4
//  15 x imms     5
//  16 x immr     0
//  17 x immr     1
//  18 x immr     2
//  19 x immr     3
//  20 x immr     4
//  21 x immr     5
//  22 x N        0
//  23 0
//  24 0
//  25 1
//  26 0
//  27 0
//  28 1
//  29 1 opc      0
//  30 1 opc      1
//  31 1 sf       0
// TST  <Xn>, #<imm>
bool TryDecodeTST_ANDS_64S_LOG_IMM(const InstData &, Instruction &) {
  return false;
}

// STLXP STLXP_SP32_ldstexcl:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x Rt2      0
//  11 x Rt2      1
//  12 x Rt2      2
//  13 x Rt2      3
//  14 x Rt2      4
//  15 1 o0       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1 o1       0
//  22 0 L        0
//  23 0 o2       0
//  24 0
//  25 0
//  26 0
//  27 1
//  28 0
//  29 0
//  30 0 sz       0
//  31 1
// STLXP  <Ws>, <Wt1>, <Wt2>, [<Xn|SP>{,#0}]
bool TryDecodeSTLXP_SP32_LDSTEXCL(const InstData &, Instruction &) {
  return false;
}

// STLXP STLXP_SP64_ldstexcl:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x Rt2      0
//  11 x Rt2      1
//  12 x Rt2      2
//  13 x Rt2      3
//  14 x Rt2      4
//  15 1 o0       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1 o1       0
//  22 0 L        0
//  23 0 o2       0
//  24 0
//  25 0
//  26 0
//  27 1
//  28 0
//  29 0
//  30 1 sz       0
//  31 1
// STLXP  <Ws>, <Xt1>, <Xt2>, [<Xn|SP>{,#0}]
bool TryDecodeSTLXP_SP64_LDSTEXCL(const InstData &, Instruction &) {
  return false;
}

// SQRSHL SQRSHL_asisdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1 S        0
//  12 1 R        0
//  13 0
//  14 1
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// SQRSHL  <V><d>, <V><n>, <V><m>
bool TryDecodeSQRSHL_ASISDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// SQRSHL SQRSHL_asimdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1 S        0
//  12 1 R        0
//  13 0
//  14 1
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// SQRSHL  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeSQRSHL_ASIMDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// UABAL UABAL_asimddiff_L:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1
//  13 0 op       0
//  14 1
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// UABAL{2}  <Vd>.<Ta>, <Vn>.<Tb>, <Vm>.<Tb>
bool TryDecodeUABAL_ASIMDDIFF_L(const InstData &, Instruction &) {
  return false;
}

// INS MOV_INS_asimdins_IV_v:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 x imm4     0
//  12 x imm4     1
//  13 x imm4     2
//  14 x imm4     3
//  15 0
//  16 x imm5     0
//  17 x imm5     1
//  18 x imm5     2
//  19 x imm5     3
//  20 x imm5     4
//  21 0
//  22 0
//  23 0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 op       0
//  30 1 Q        0
//  31 0
// MOV  <Vd>.<Ts>[<index1>], <Vn>.<Ts>[<index2>]
bool TryDecodeMOV_INS_ASIMDINS_IV_V(const InstData &, Instruction &) {
  return false;
}

// SRSHR SRSHR_asisdshf_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0
//  12 0 o0       0
//  13 1 o1       0
//  14 0
//  15 0
//  16 x immb     0
//  17 x immb     1
//  18 x immb     2
//  19 x immh     0
//  20 x immh     1
//  21 x immh     2
//  22 x immh     3
//  23 0
//  24 1
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// SRSHR  <V><d>, <V><n>, #<shift>
bool TryDecodeSRSHR_ASISDSHF_R(const InstData &, Instruction &) {
  return false;
}

// SRSHR SRSHR_asimdshf_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0
//  12 0 o0       0
//  13 1 o1       0
//  14 0
//  15 0
//  16 x immb     0
//  17 x immb     1
//  18 x immb     2
//  19 x immh     0
//  20 x immh     1
//  21 x immh     2
//  22 x immh     3
//  23 0
//  24 1
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// SRSHR  <Vd>.<T>, <Vn>.<T>, #<shift>
bool TryDecodeSRSHR_ASIMDSHF_R(const InstData &, Instruction &) {
  return false;
}

// CLS CLS_32_dp_1src:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 op       0
//  11 0 opcode   1
//  12 1 opcode   2
//  13 0 opcode   3
//  14 0 opcode   4
//  15 0 opcode   5
//  16 0 opcode2  0
//  17 0 opcode2  1
//  18 0 opcode2  2
//  19 0 opcode2  3
//  20 0 opcode2  4
//  21 0
//  22 1
//  23 1
//  24 0
//  25 1
//  26 0
//  27 1
//  28 1
//  29 0 S        0
//  30 1
//  31 0 sf       0
// CLS  <Wd>, <Wn>
bool TryDecodeCLS_32_DP_1SRC(const InstData &, Instruction &) {
  return false;
}

// CLS CLS_64_dp_1src:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 op       0
//  11 0 opcode   1
//  12 1 opcode   2
//  13 0 opcode   3
//  14 0 opcode   4
//  15 0 opcode   5
//  16 0 opcode2  0
//  17 0 opcode2  1
//  18 0 opcode2  2
//  19 0 opcode2  3
//  20 0 opcode2  4
//  21 0
//  22 1
//  23 1
//  24 0
//  25 1
//  26 0
//  27 1
//  28 1
//  29 0 S        0
//  30 1
//  31 1 sf       0
// CLS  <Xd>, <Xn>
bool TryDecodeCLS_64_DP_1SRC(const InstData &, Instruction &) {
  return false;
}

// SEV SEV_HI_system:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 0 op2      0
//   6 0 op2      1
//   7 1 op2      2
//   8 0 CRm      0
//   9 0 CRm      1
//  10 0 CRm      2
//  11 0 CRm      3
//  12 0 CRn      0
//  13 1 CRn      1
//  14 0 CRn      2
//  15 0 CRn      3
//  16 1 op1      0
//  17 1 op1      1
//  18 0 op1      2
//  19 0 op0      0
//  20 0 op0      1
//  21 0 L        0
//  22 0
//  23 0
//  24 1
//  25 0
//  26 1
//  27 0
//  28 1
//  29 0
//  30 1
//  31 1
// SEV
bool TryDecodeSEV_HI_SYSTEM(const InstData &, Instruction &) {
  return false;
}

// FMULX FMULX_asisdsamefp16_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1 opcode   0
//  12 1 opcode   1
//  13 0 opcode   2
//  14 0
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 1
//  23 0 a        0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// FMULX  <Hd>, <Hn>, <Hm>
bool TryDecodeFMULX_ASISDSAMEFP16_ONLY(const InstData &, Instruction &) {
  return false;
}

// FMULX FMULX_asisdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1 opcode   0
//  12 1 opcode   1
//  13 0 opcode   2
//  14 1 opcode   3
//  15 1 opcode   4
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x sz       0
//  23 0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// FMULX  <V><d>, <V><n>, <V><m>
bool TryDecodeFMULX_ASISDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// FMULX FMULX_asimdsamefp16_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1 opcode   0
//  12 1 opcode   1
//  13 0 opcode   2
//  14 0
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 1
//  23 0 a        0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// FMULX  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeFMULX_ASIMDSAMEFP16_ONLY(const InstData &, Instruction &) {
  return false;
}

// FMULX FMULX_asimdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1 opcode   0
//  12 1 opcode   1
//  13 0 opcode   2
//  14 1 opcode   3
//  15 1 opcode   4
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x sz       0
//  23 0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// FMULX  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeFMULX_ASIMDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// UQSHL UQSHL_asisdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1 S        0
//  12 0 R        0
//  13 0
//  14 1
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 1 U        0
//  30 1
//  31 0
// UQSHL  <V><d>, <V><n>, <V><m>
bool TryDecodeUQSHL_ASISDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// UQSHL UQSHL_asimdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1 S        0
//  12 0 R        0
//  13 0
//  14 1
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// UQSHL  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeUQSHL_ASIMDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// STEORB STEORB_32S_memop:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 1 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 0 size     1
// STEORB  <Ws>, [<Xn|SP>]
bool TryDecodeSTEORB_32S_MEMOP(const InstData &, Instruction &) {
  return false;
}

// STEORLB STEORLB_32S_memop:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 1 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 0 size     1
// STEORLB  <Ws>, [<Xn|SP>]
bool TryDecodeSTEORLB_32S_MEMOP(const InstData &, Instruction &) {
  return false;
}

// STUMAXH STUMAXH_32S_memop:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 1 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 0 size     1
// STUMAXH  <Ws>, [<Xn|SP>]
bool TryDecodeSTUMAXH_32S_MEMOP(const InstData &, Instruction &) {
  return false;
}

// STUMAXLH STUMAXLH_32S_memop:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 1 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 0 size     1
// STUMAXLH  <Ws>, [<Xn|SP>]
bool TryDecodeSTUMAXLH_32S_MEMOP(const InstData &, Instruction &) {
  return false;
}

// UABA UABA_asimdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1 ac       0
//  12 1
//  13 1
//  14 1
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// UABA  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeUABA_ASIMDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// STSMINB STSMINB_32S_memop:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 0 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 0 size     1
// STSMINB  <Ws>, [<Xn|SP>]
bool TryDecodeSTSMINB_32S_MEMOP(const InstData &, Instruction &) {
  return false;
}

// STSMINLB STSMINLB_32S_memop:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 0 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 0 size     1
// STSMINLB  <Ws>, [<Xn|SP>]
bool TryDecodeSTSMINLB_32S_MEMOP(const InstData &, Instruction &) {
  return false;
}

// FCMGE FCMGE_asisdmiscfp16_FZ:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 op       0
//  13 0
//  14 1
//  15 1
//  16 0
//  17 0
//  18 0
//  19 1
//  20 1
//  21 1
//  22 1
//  23 1 a        0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 1 U        0
//  30 1
//  31 0
// FCMGE  <Hd>, <Hn>, #0.0
bool TryDecodeFCMGE_ASISDMISCFP16_FZ(const InstData &, Instruction &) {
  return false;
}

// FCMGE FCMGE_asisdmisc_FZ:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 op       0
//  13 0
//  14 1
//  15 1
//  16 0
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x sz       0
//  23 1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 1 U        0
//  30 1
//  31 0
// FCMGE  <V><d>, <V><n>, #0.0
bool TryDecodeFCMGE_ASISDMISC_FZ(const InstData &, Instruction &) {
  return false;
}

// FCMGE FCMGE_asimdmiscfp16_FZ:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 op       0
//  13 0
//  14 1
//  15 1
//  16 0
//  17 0
//  18 0
//  19 1
//  20 1
//  21 1
//  22 1
//  23 1 a        0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// FCMGE  <Vd>.<T>, <Vn>.<T>, #0.0
bool TryDecodeFCMGE_ASIMDMISCFP16_FZ(const InstData &, Instruction &) {
  return false;
}

// FCMGE FCMGE_asimdmisc_FZ:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 op       0
//  13 0
//  14 1
//  15 1
//  16 0
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x sz       0
//  23 1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// FCMGE  <Vd>.<T>, <Vn>.<T>, #0.0
bool TryDecodeFCMGE_ASIMDMISC_FZ(const InstData &, Instruction &) {
  return false;
}

// STLLRB STLLRB_SL32_ldstexcl:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 Rt2      0
//  11 1 Rt2      1
//  12 1 Rt2      2
//  13 1 Rt2      3
//  14 1 Rt2      4
//  15 0 o0       0
//  16 1 Rs       0
//  17 1 Rs       1
//  18 1 Rs       2
//  19 1 Rs       3
//  20 1 Rs       4
//  21 0 o1       0
//  22 0 L        0
//  23 1 o2       0
//  24 0
//  25 0
//  26 0
//  27 1
//  28 0
//  29 0
//  30 0 size     0
//  31 0 size     1
// STLLRB  <Wt>, [<Xn|SP>{,#0}]
bool TryDecodeSTLLRB_SL32_LDSTEXCL(const InstData &, Instruction &) {
  return false;
}

// FRINTZ FRINTZ_asimdmiscfp16_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 o1       0
//  13 0
//  14 0
//  15 1
//  16 1
//  17 0
//  18 0
//  19 1
//  20 1
//  21 1
//  22 1
//  23 1 o2       0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// FRINTZ  <Vd>.<T>, <Vn>.<T>
bool TryDecodeFRINTZ_ASIMDMISCFP16_R(const InstData &, Instruction &) {
  return false;
}

// FRINTZ FRINTZ_asimdmisc_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 o1       0
//  13 0
//  14 0
//  15 1
//  16 1
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x sz       0
//  23 1 o2       0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// FRINTZ  <Vd>.<T>, <Vn>.<T>
bool TryDecodeFRINTZ_ASIMDMISC_R(const InstData &, Instruction &) {
  return false;
}

// STXRH STXRH_SR32_ldstexcl:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 Rt2      0
//  11 1 Rt2      1
//  12 1 Rt2      2
//  13 1 Rt2      3
//  14 1 Rt2      4
//  15 0 o0       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 0 o1       0
//  22 0 L        0
//  23 0 o2       0
//  24 0
//  25 0
//  26 0
//  27 1
//  28 0
//  29 0
//  30 1 size     0
//  31 0 size     1
// STXRH  <Ws>, <Wt>, [<Xn|SP>{,#0}]
bool TryDecodeSTXRH_SR32_LDSTEXCL(const InstData &, Instruction &) {
  return false;
}

// STEORH STEORH_32S_memop:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 1 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 0 size     1
// STEORH  <Ws>, [<Xn|SP>]
bool TryDecodeSTEORH_32S_MEMOP(const InstData &, Instruction &) {
  return false;
}

// STEORLH STEORLH_32S_memop:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 1 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 0 size     1
// STEORLH  <Ws>, [<Xn|SP>]
bool TryDecodeSTEORLH_32S_MEMOP(const InstData &, Instruction &) {
  return false;
}

// FMINNMP FMINNMP_asimdsamefp16_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 Op3      0
//  12 0 Op3      1
//  13 0 Op3      2
//  14 0
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 1
//  23 1 a        0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// FMINNMP  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeFMINNMP_ASIMDSAMEFP16_ONLY(const InstData &, Instruction &) {
  return false;
}

// FMINNMP FMINNMP_asimdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 opcode   0
//  12 0 opcode   1
//  13 0 opcode   2
//  14 1 opcode   3
//  15 1 opcode   4
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x sz       0
//  23 1 o1       0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// FMINNMP  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeFMINNMP_ASIMDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// LDLAR LDLAR_LR32_ldstexcl:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 Rt2      0
//  11 1 Rt2      1
//  12 1 Rt2      2
//  13 1 Rt2      3
//  14 1 Rt2      4
//  15 0 o0       0
//  16 1 Rs       0
//  17 1 Rs       1
//  18 1 Rs       2
//  19 1 Rs       3
//  20 1 Rs       4
//  21 0 o1       0
//  22 1 L        0
//  23 1 o2       0
//  24 0
//  25 0
//  26 0
//  27 1
//  28 0
//  29 0
//  30 0 size     0
//  31 1 size     1
// LDLAR  <Wt>, [<Xn|SP>{,#0}]
bool TryDecodeLDLAR_LR32_LDSTEXCL(const InstData &, Instruction &) {
  return false;
}

// LDLAR LDLAR_LR64_ldstexcl:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 Rt2      0
//  11 1 Rt2      1
//  12 1 Rt2      2
//  13 1 Rt2      3
//  14 1 Rt2      4
//  15 0 o0       0
//  16 1 Rs       0
//  17 1 Rs       1
//  18 1 Rs       2
//  19 1 Rs       3
//  20 1 Rs       4
//  21 0 o1       0
//  22 1 L        0
//  23 1 o2       0
//  24 0
//  25 0
//  26 0
//  27 1
//  28 0
//  29 0
//  30 1 size     0
//  31 1 size     1
// LDLAR  <Xt>, [<Xn|SP>{,#0}]
bool TryDecodeLDLAR_LR64_LDSTEXCL(const InstData &, Instruction &) {
  return false;
}

// SSHLL SSHLL_asimdshf_L:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 opcode   0
//  12 0 opcode   1
//  13 1 opcode   2
//  14 0 opcode   3
//  15 1 opcode   4
//  16 x immb     0
//  17 x immb     1
//  18 x immb     2
//  19 x immh     0
//  20 x immh     1
//  21 x immh     2
//  22 x immh     3
//  23 0
//  24 1
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// SSHLL{2}  <Vd>.<Ta>, <Vn>.<Tb>, #<shift>
bool TryDecodeSSHLL_ASIMDSHF_L(const InstData &, Instruction &) {
  return false;
}

// STCLRB STCLRB_32S_memop:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 0 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 0 size     1
// STCLRB  <Ws>, [<Xn|SP>]
bool TryDecodeSTCLRB_32S_MEMOP(const InstData &, Instruction &) {
  return false;
}

// STCLRLB STCLRLB_32S_memop:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 0 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 0 size     1
// STCLRLB  <Ws>, [<Xn|SP>]
bool TryDecodeSTCLRLB_32S_MEMOP(const InstData &, Instruction &) {
  return false;
}

// STSMAX STSMAX_32S_memop:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 0 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 1 size     1
// STSMAX  <Ws>, [<Xn|SP>]
bool TryDecodeSTSMAX_32S_MEMOP(const InstData &, Instruction &) {
  return false;
}

// STSMAXL STSMAXL_32S_memop:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 0 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 1 size     1
// STSMAXL  <Ws>, [<Xn|SP>]
bool TryDecodeSTSMAXL_32S_MEMOP(const InstData &, Instruction &) {
  return false;
}

// STSMAX STSMAX_64S_memop:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 0 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 1 size     1
// STSMAX  <Xs>, [<Xn|SP>]
bool TryDecodeSTSMAX_64S_MEMOP(const InstData &, Instruction &) {
  return false;
}

// STSMAXL STSMAXL_64S_memop:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 0 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 1 size     1
// STSMAXL  <Xs>, [<Xn|SP>]
bool TryDecodeSTSMAXL_64S_MEMOP(const InstData &, Instruction &) {
  return false;
}

// SQDMULL SQDMULL_asisdelem_L:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 x H        0
//  12 1 opcode   0
//  13 1 opcode   1
//  14 0 opcode   2
//  15 1 opcode   3
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x M        0
//  21 x L        0
//  22 x size     0
//  23 x size     1
//  24 1
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// SQDMULL  <Va><d>, <Vb><n>, <Vm>.<Ts>[<index>]
bool TryDecodeSQDMULL_ASISDELEM_L(const InstData &, Instruction &) {
  return false;
}

// SQDMULL SQDMULL_asimdelem_L:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 x H        0
//  12 1 opcode   0
//  13 1 opcode   1
//  14 0 opcode   2
//  15 1 opcode   3
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x M        0
//  21 x L        0
//  22 x size     0
//  23 x size     1
//  24 1
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// SQDMULL{2}  <Vd>.<Ta>, <Vn>.<Tb>, <Vm>.<Ts>[<index>]
bool TryDecodeSQDMULL_ASIMDELEM_L(const InstData &, Instruction &) {
  return false;
}

// LD1 LD1_asisdlso_B1_1b:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x size     0
//  11 x size     1
//  12 x S        0
//  13 0 opcode   0
//  14 0 opcode   1
//  15 0 opcode   2
//  16 0
//  17 0
//  18 0
//  19 0
//  20 0
//  21 0 R        0
//  22 1 L        0
//  23 0
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// LD1  { <Vt>.B }[<index>], [<Xn|SP>]
bool TryDecodeLD1_ASISDLSO_B1_1B(const InstData &, Instruction &) {
  return false;
}

// LD1 LD1_asisdlso_H1_1h:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0 size     0
//  11 x size     1
//  12 x S        0
//  13 0 opcode   0
//  14 1 opcode   1
//  15 0 opcode   2
//  16 0
//  17 0
//  18 0
//  19 0
//  20 0
//  21 0 R        0
//  22 1 L        0
//  23 0
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// LD1  { <Vt>.H }[<index>], [<Xn|SP>]
bool TryDecodeLD1_ASISDLSO_H1_1H(const InstData &, Instruction &) {
  return false;
}

// LD1 LD1_asisdlso_S1_1s:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0 size     0
//  11 0 size     1
//  12 x S        0
//  13 0 opcode   0
//  14 0 opcode   1
//  15 1 opcode   2
//  16 0
//  17 0
//  18 0
//  19 0
//  20 0
//  21 0 R        0
//  22 1 L        0
//  23 0
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// LD1  { <Vt>.S }[<index>], [<Xn|SP>]
bool TryDecodeLD1_ASISDLSO_S1_1S(const InstData &, Instruction &) {
  return false;
}

// LD1 LD1_asisdlso_D1_1d:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 size     0
//  11 0 size     1
//  12 0 S        0
//  13 0 opcode   0
//  14 0 opcode   1
//  15 1 opcode   2
//  16 0
//  17 0
//  18 0
//  19 0
//  20 0
//  21 0 R        0
//  22 1 L        0
//  23 0
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// LD1  { <Vt>.D }[<index>], [<Xn|SP>]
bool TryDecodeLD1_ASISDLSO_D1_1D(const InstData &, Instruction &) {
  return false;
}

// LD1 LD1_asisdlsop_B1_i1b:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x size     0
//  11 x size     1
//  12 x S        0
//  13 0 opcode   0
//  14 0 opcode   1
//  15 0 opcode   2
//  16 1 Rm       0
//  17 1 Rm       1
//  18 1 Rm       2
//  19 1 Rm       3
//  20 1 Rm       4
//  21 0 R        0
//  22 1 L        0
//  23 1
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// LD1  { <Vt>.B }[<index>], [<Xn|SP>], #1
bool TryDecodeLD1_ASISDLSOP_B1_I1B(const InstData &, Instruction &) {
  return false;
}

// LD1 LD1_asisdlsop_BX1_r1b:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x size     0
//  11 x size     1
//  12 x S        0
//  13 0 opcode   0
//  14 0 opcode   1
//  15 0 opcode   2
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0 R        0
//  22 1 L        0
//  23 1
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// LD1  { <Vt>.B }[<index>], [<Xn|SP>], <Xm>
bool TryDecodeLD1_ASISDLSOP_BX1_R1B(const InstData &, Instruction &) {
  return false;
}

// LD1 LD1_asisdlsop_H1_i1h:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0 size     0
//  11 x size     1
//  12 x S        0
//  13 0 opcode   0
//  14 1 opcode   1
//  15 0 opcode   2
//  16 1 Rm       0
//  17 1 Rm       1
//  18 1 Rm       2
//  19 1 Rm       3
//  20 1 Rm       4
//  21 0 R        0
//  22 1 L        0
//  23 1
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// LD1  { <Vt>.H }[<index>], [<Xn|SP>], #2
bool TryDecodeLD1_ASISDLSOP_H1_I1H(const InstData &, Instruction &) {
  return false;
}

// LD1 LD1_asisdlsop_HX1_r1h:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0 size     0
//  11 x size     1
//  12 x S        0
//  13 0 opcode   0
//  14 1 opcode   1
//  15 0 opcode   2
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0 R        0
//  22 1 L        0
//  23 1
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// LD1  { <Vt>.H }[<index>], [<Xn|SP>], <Xm>
bool TryDecodeLD1_ASISDLSOP_HX1_R1H(const InstData &, Instruction &) {
  return false;
}

// LD1 LD1_asisdlsop_S1_i1s:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0 size     0
//  11 0 size     1
//  12 x S        0
//  13 0 opcode   0
//  14 0 opcode   1
//  15 1 opcode   2
//  16 1 Rm       0
//  17 1 Rm       1
//  18 1 Rm       2
//  19 1 Rm       3
//  20 1 Rm       4
//  21 0 R        0
//  22 1 L        0
//  23 1
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// LD1  { <Vt>.S }[<index>], [<Xn|SP>], #4
bool TryDecodeLD1_ASISDLSOP_S1_I1S(const InstData &, Instruction &) {
  return false;
}

// LD1 LD1_asisdlsop_SX1_r1s:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0 size     0
//  11 0 size     1
//  12 x S        0
//  13 0 opcode   0
//  14 0 opcode   1
//  15 1 opcode   2
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0 R        0
//  22 1 L        0
//  23 1
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// LD1  { <Vt>.S }[<index>], [<Xn|SP>], <Xm>
bool TryDecodeLD1_ASISDLSOP_SX1_R1S(const InstData &, Instruction &) {
  return false;
}

// LD1 LD1_asisdlsop_D1_i1d:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 size     0
//  11 0 size     1
//  12 0 S        0
//  13 0 opcode   0
//  14 0 opcode   1
//  15 1 opcode   2
//  16 1 Rm       0
//  17 1 Rm       1
//  18 1 Rm       2
//  19 1 Rm       3
//  20 1 Rm       4
//  21 0 R        0
//  22 1 L        0
//  23 1
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// LD1  { <Vt>.D }[<index>], [<Xn|SP>], #8
bool TryDecodeLD1_ASISDLSOP_D1_I1D(const InstData &, Instruction &) {
  return false;
}

// LD1 LD1_asisdlsop_DX1_r1d:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 size     0
//  11 0 size     1
//  12 0 S        0
//  13 0 opcode   0
//  14 0 opcode   1
//  15 1 opcode   2
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0 R        0
//  22 1 L        0
//  23 1
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// LD1  { <Vt>.D }[<index>], [<Xn|SP>], <Xm>
bool TryDecodeLD1_ASISDLSOP_DX1_R1D(const InstData &, Instruction &) {
  return false;
}

// CCMN CCMN_32_condcmp_reg:
//   0 x nzcv     0
//   1 x nzcv     1
//   2 x nzcv     2
//   3 x nzcv     3
//   4 0 o3       0
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0 o2       0
//  11 0
//  12 x cond     0
//  13 x cond     1
//  14 x cond     2
//  15 x cond     3
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 1
//  23 0
//  24 0
//  25 1
//  26 0
//  27 1
//  28 1
//  29 1 S        0
//  30 0 op       0
//  31 0 sf       0
// CCMN  <Wn>, <Wm>, #<nzcv>, <cond>
bool TryDecodeCCMN_32_CONDCMP_REG(const InstData &, Instruction &) {
  return false;
}

// CCMN CCMN_64_condcmp_reg:
//   0 x nzcv     0
//   1 x nzcv     1
//   2 x nzcv     2
//   3 x nzcv     3
//   4 0 o3       0
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0 o2       0
//  11 0
//  12 x cond     0
//  13 x cond     1
//  14 x cond     2
//  15 x cond     3
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 1
//  23 0
//  24 0
//  25 1
//  26 0
//  27 1
//  28 1
//  29 1 S        0
//  30 0 op       0
//  31 1 sf       0
// CCMN  <Xn>, <Xm>, #<nzcv>, <cond>
bool TryDecodeCCMN_64_CONDCMP_REG(const InstData &, Instruction &) {
  return false;
}

// STNP STNP_S_ldstnapair_offs:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x Rt2      0
//  11 x Rt2      1
//  12 x Rt2      2
//  13 x Rt2      3
//  14 x Rt2      4
//  15 x imm7     0
//  16 x imm7     1
//  17 x imm7     2
//  18 x imm7     3
//  19 x imm7     4
//  20 x imm7     5
//  21 x imm7     6
//  22 0 L        0
//  23 0
//  24 0
//  25 0
//  26 1 V        0
//  27 1
//  28 0
//  29 1
//  30 0 opc      0
//  31 0 opc      1
// STNP  <St1>, <St2>, [<Xn|SP>{, #<imm>}]
bool TryDecodeSTNP_S_LDSTNAPAIR_OFFS(const InstData &, Instruction &) {
  return false;
}

// STNP STNP_D_ldstnapair_offs:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x Rt2      0
//  11 x Rt2      1
//  12 x Rt2      2
//  13 x Rt2      3
//  14 x Rt2      4
//  15 x imm7     0
//  16 x imm7     1
//  17 x imm7     2
//  18 x imm7     3
//  19 x imm7     4
//  20 x imm7     5
//  21 x imm7     6
//  22 0 L        0
//  23 0
//  24 0
//  25 0
//  26 1 V        0
//  27 1
//  28 0
//  29 1
//  30 1 opc      0
//  31 0 opc      1
// STNP  <Dt1>, <Dt2>, [<Xn|SP>{, #<imm>}]
bool TryDecodeSTNP_D_LDSTNAPAIR_OFFS(const InstData &, Instruction &) {
  return false;
}

// STNP STNP_Q_ldstnapair_offs:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x Rt2      0
//  11 x Rt2      1
//  12 x Rt2      2
//  13 x Rt2      3
//  14 x Rt2      4
//  15 x imm7     0
//  16 x imm7     1
//  17 x imm7     2
//  18 x imm7     3
//  19 x imm7     4
//  20 x imm7     5
//  21 x imm7     6
//  22 0 L        0
//  23 0
//  24 0
//  25 0
//  26 1 V        0
//  27 1
//  28 0
//  29 1
//  30 0 opc      0
//  31 1 opc      1
// STNP  <Qt1>, <Qt2>, [<Xn|SP>{, #<imm>}]
bool TryDecodeSTNP_Q_LDSTNAPAIR_OFFS(const InstData &, Instruction &) {
  return false;
}

// ASRV ASR_ASRV_32_dp_2src:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0 op2      0
//  11 1 op2      1
//  12 0 opcode2  2
//  13 1 opcode2  3
//  14 0 opcode2  4
//  15 0 opcode2  5
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 1
//  23 1
//  24 0
//  25 1
//  26 0
//  27 1
//  28 1
//  29 0 S        0
//  30 0 op       0
//  31 0 sf       0
// ASR  <Wd>, <Wn>, <Wm>
bool TryDecodeASR_ASRV_32_DP_2SRC(const InstData &, Instruction &) {
  return false;
}

// ASRV ASR_ASRV_64_dp_2src:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0 op2      0
//  11 1 op2      1
//  12 0 opcode2  2
//  13 1 opcode2  3
//  14 0 opcode2  4
//  15 0 opcode2  5
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 1
//  23 1
//  24 0
//  25 1
//  26 0
//  27 1
//  28 1
//  29 0 S        0
//  30 0 op       0
//  31 1 sf       0
// ASR  <Xd>, <Xn>, <Xm>
bool TryDecodeASR_ASRV_64_DP_2SRC(const InstData &, Instruction &) {
  return false;
}

// FCMGT FCMGT_asisdsamefp16_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 ac       0
//  12 0
//  13 1
//  14 0
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 1
//  23 1 E        0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 1 U        0
//  30 1
//  31 0
// FCMGT  <Hd>, <Hn>, <Hm>
bool TryDecodeFCMGT_ASISDSAMEFP16_ONLY(const InstData &, Instruction &) {
  return false;
}

// FCMGT FCMGT_asisdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 ac       0
//  12 0
//  13 1
//  14 1
//  15 1
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x sz       0
//  23 1 E        0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 1 U        0
//  30 1
//  31 0
// FCMGT  <V><d>, <V><n>, <V><m>
bool TryDecodeFCMGT_ASISDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// FCMGT FCMGT_asimdsamefp16_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 ac       0
//  12 0
//  13 1
//  14 0
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 1
//  23 1 E        0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// FCMGT  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeFCMGT_ASIMDSAMEFP16_ONLY(const InstData &, Instruction &) {
  return false;
}

// FCMGT FCMGT_asimdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 ac       0
//  12 0
//  13 1
//  14 1
//  15 1
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x sz       0
//  23 1 E        0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// FCMGT  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeFCMGT_ASIMDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// USUBW USUBW_asimddiff_W:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1
//  13 1 o1       0
//  14 0
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// USUBW{2}  <Vd>.<Ta>, <Vn>.<Ta>, <Vm>.<Tb>
bool TryDecodeUSUBW_ASIMDDIFF_W(const InstData &, Instruction &) {
  return false;
}

// FSQRT FSQRT_asimdmiscfp16_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 opcode   0
//  13 1 opcode   1
//  14 1 opcode   2
//  15 1 opcode   3
//  16 1 opcode   4
//  17 0
//  18 0
//  19 1
//  20 1
//  21 1
//  22 1
//  23 1 a        0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// FSQRT  <Vd>.<T>, <Vn>.<T>
bool TryDecodeFSQRT_ASIMDMISCFP16_R(const InstData &, Instruction &) {
  return false;
}

// FSQRT FSQRT_asimdmisc_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 opcode   0
//  13 1 opcode   1
//  14 1 opcode   2
//  15 1 opcode   3
//  16 1 opcode   4
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x sz       0
//  23 1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// FSQRT  <Vd>.<T>, <Vn>.<T>
bool TryDecodeFSQRT_ASIMDMISC_R(const InstData &, Instruction &) {
  return false;
}

// LSLV LSL_LSLV_32_dp_2src:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0 op2      0
//  11 0 op2      1
//  12 0 opcode2  2
//  13 1 opcode2  3
//  14 0 opcode2  4
//  15 0 opcode2  5
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 1
//  23 1
//  24 0
//  25 1
//  26 0
//  27 1
//  28 1
//  29 0 S        0
//  30 0 op       0
//  31 0 sf       0
// LSL  <Wd>, <Wn>, <Wm>
bool TryDecodeLSL_LSLV_32_DP_2SRC(const InstData &, Instruction &) {
  return false;
}

// LSLV LSL_LSLV_64_dp_2src:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0 op2      0
//  11 0 op2      1
//  12 0 opcode2  2
//  13 1 opcode2  3
//  14 0 opcode2  4
//  15 0 opcode2  5
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 1
//  23 1
//  24 0
//  25 1
//  26 0
//  27 1
//  28 1
//  29 0 S        0
//  30 0 op       0
//  31 1 sf       0
// LSL  <Xd>, <Xn>, <Xm>
bool TryDecodeLSL_LSLV_64_DP_2SRC(const InstData &, Instruction &) {
  return false;
}

// FCVTAU FCVTAU_asisdmiscfp16_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 opcode   0
//  13 0 opcode   1
//  14 1 opcode   2
//  15 1 opcode   3
//  16 1 opcode   4
//  17 0
//  18 0
//  19 1
//  20 1
//  21 1
//  22 1
//  23 0 size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 1 U        0
//  30 1
//  31 0
// FCVTAU  <Hd>, <Hn>
bool TryDecodeFCVTAU_ASISDMISCFP16_R(const InstData &, Instruction &) {
  return false;
}

// FCVTAU FCVTAU_asisdmisc_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 opcode   0
//  13 0 opcode   1
//  14 1 opcode   2
//  15 1 opcode   3
//  16 1 opcode   4
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x sz       0
//  23 0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 1 U        0
//  30 1
//  31 0
// FCVTAU  <V><d>, <V><n>
bool TryDecodeFCVTAU_ASISDMISC_R(const InstData &, Instruction &) {
  return false;
}

// FCVTAU FCVTAU_asimdmiscfp16_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 opcode   0
//  13 0 opcode   1
//  14 1 opcode   2
//  15 1 opcode   3
//  16 1 opcode   4
//  17 0
//  18 0
//  19 1
//  20 1
//  21 1
//  22 1
//  23 0 a        0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// FCVTAU  <Vd>.<T>, <Vn>.<T>
bool TryDecodeFCVTAU_ASIMDMISCFP16_R(const InstData &, Instruction &) {
  return false;
}

// FCVTAU FCVTAU_asimdmisc_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 opcode   0
//  13 0 opcode   1
//  14 1 opcode   2
//  15 1 opcode   3
//  16 1 opcode   4
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x sz       0
//  23 0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// FCVTAU  <Vd>.<T>, <Vn>.<T>
bool TryDecodeFCVTAU_ASIMDMISC_R(const InstData &, Instruction &) {
  return false;
}

// BFM BFXIL_BFM_32M_bitfield:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x imms     0
//  11 x imms     1
//  12 x imms     2
//  13 x imms     3
//  14 x imms     4
//  15 x imms     5
//  16 x immr     0
//  17 x immr     1
//  18 x immr     2
//  19 x immr     3
//  20 x immr     4
//  21 x immr     5
//  22 0 N        0
//  23 0
//  24 1
//  25 1
//  26 0
//  27 0
//  28 1
//  29 1 opc      0
//  30 0 opc      1
//  31 0 sf       0
// BFXIL  <Wd>, <Wn>, #<lsb>, #<width>
bool TryDecodeBFXIL_BFM_32M_BITFIELD(const InstData &, Instruction &) {
  return false;
}

// BFM BFXIL_BFM_64M_bitfield:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x imms     0
//  11 x imms     1
//  12 x imms     2
//  13 x imms     3
//  14 x imms     4
//  15 x imms     5
//  16 x immr     0
//  17 x immr     1
//  18 x immr     2
//  19 x immr     3
//  20 x immr     4
//  21 x immr     5
//  22 1 N        0
//  23 0
//  24 1
//  25 1
//  26 0
//  27 0
//  28 1
//  29 1 opc      0
//  30 0 opc      1
//  31 1 sf       0
// BFXIL  <Xd>, <Xn>, #<lsb>, #<width>
bool TryDecodeBFXIL_BFM_64M_BITFIELD(const InstData &, Instruction &) {
  return false;
}

// ZIP1 ZIP1_asimdperm_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1
//  13 1
//  14 0 op       0
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// ZIP1  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeZIP1_ASIMDPERM_ONLY(const InstData &, Instruction &) {
  return false;
}

// LDSETAH LDSETAH_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 1 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 1 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 0 size     1
// LDSETAH  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDSETAH_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDSETALH LDSETALH_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 1 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 1 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 0 size     1
// LDSETALH  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDSETALH_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDSETH LDSETH_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 1 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 0 size     1
// LDSETH  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDSETH_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDSETLH LDSETLH_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 1 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 0 size     1
// LDSETLH  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDSETLH_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDADDAH LDADDAH_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 0 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 1 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 0 size     1
// LDADDAH  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDADDAH_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDADDALH LDADDALH_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 0 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 1 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 0 size     1
// LDADDALH  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDADDALH_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDADDH LDADDH_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 0 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 0 size     1
// LDADDH  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDADDH_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDADDLH LDADDLH_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 0 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 0 size     1
// LDADDLH  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDADDLH_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LD3 LD3_asisdlsep_I3_i:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x size     0
//  11 x size     1
//  12 0 opcode   0
//  13 0 opcode   1
//  14 1 opcode   2
//  15 0 opcode   3
//  16 1 Rm       0
//  17 1 Rm       1
//  18 1 Rm       2
//  19 1 Rm       3
//  20 1 Rm       4
//  21 0
//  22 1 L        0
//  23 1
//  24 0
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// LD3  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T> }, [<Xn|SP>], <imm>
bool TryDecodeLD3_ASISDLSEP_I3_I(const InstData &, Instruction &) {
  return false;
}

// LD3 LD3_asisdlsep_R3_r:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x size     0
//  11 x size     1
//  12 0 opcode   0
//  13 0 opcode   1
//  14 1 opcode   2
//  15 0 opcode   3
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 1 L        0
//  23 1
//  24 0
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// LD3  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T> }, [<Xn|SP>], <Xm>
bool TryDecodeLD3_ASISDLSEP_R3_R(const InstData &, Instruction &) {
  return false;
}

// UADALP UADALP_asimdmisc_P:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0
//  13 1
//  14 1 op       0
//  15 0
//  16 0
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// UADALP  <Vd>.<Ta>, <Vn>.<Tb>
bool TryDecodeUADALP_ASIMDMISC_P(const InstData &, Instruction &) {
  return false;
}

// FRINTX FRINTX_asimdmiscfp16_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 o1       0
//  13 0
//  14 0
//  15 1
//  16 1
//  17 0
//  18 0
//  19 1
//  20 1
//  21 1
//  22 1
//  23 0 o2       0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// FRINTX  <Vd>.<T>, <Vn>.<T>
bool TryDecodeFRINTX_ASIMDMISCFP16_R(const InstData &, Instruction &) {
  return false;
}

// FRINTX FRINTX_asimdmisc_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 o1       0
//  13 0
//  14 0
//  15 1
//  16 1
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x sz       0
//  23 0 o2       0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// FRINTX  <Vd>.<T>, <Vn>.<T>
bool TryDecodeFRINTX_ASIMDMISC_R(const InstData &, Instruction &) {
  return false;
}

// HLT HLT_EX_exception:
//   0 0 LL       0
//   1 0 LL       1
//   2 0 op2      0
//   3 0 op2      1
//   4 0 op2      2
//   5 x imm16    0
//   6 x imm16    1
//   7 x imm16    2
//   8 x imm16    3
//   9 x imm16    4
//  10 x imm16    5
//  11 x imm16    6
//  12 x imm16    7
//  13 x imm16    8
//  14 x imm16    9
//  15 x imm16    10
//  16 x imm16    11
//  17 x imm16    12
//  18 x imm16    13
//  19 x imm16    14
//  20 x imm16    15
//  21 0 opc      0
//  22 1 opc      1
//  23 0 opc      2
//  24 0
//  25 0
//  26 1
//  27 0
//  28 1
//  29 0
//  30 1
//  31 1
// HLT  #<imm>
bool TryDecodeHLT_EX_EXCEPTION(const InstData &, Instruction &) {
  return false;
}

// SABA SABA_asimdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1 ac       0
//  12 1
//  13 1
//  14 1
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// SABA  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeSABA_ASIMDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// FMAX FMAX_H_floatdp2:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 op       0
//  13 0 op       1
//  14 1
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 1 type     0
//  23 1 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 M        0
// FMAX  <Hd>, <Hn>, <Hm>
bool TryDecodeFMAX_H_FLOATDP2(const InstData &, Instruction &) {
  return false;
}

// FMAX FMAX_S_floatdp2:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 op       0
//  13 0 op       1
//  14 1
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 0 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 M        0
// FMAX  <Sd>, <Sn>, <Sm>
bool TryDecodeFMAX_S_FLOATDP2(const InstData &, Instruction &) {
  return false;
}

// FMAX FMAX_D_floatdp2:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 op       0
//  13 0 op       1
//  14 1
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 1 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 M        0
// FMAX  <Dd>, <Dn>, <Dm>
bool TryDecodeFMAX_D_FLOATDP2(const InstData &, Instruction &) {
  return false;
}

// AESD AESD_B_cryptoaes:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 D        0
//  13 0
//  14 1
//  15 0
//  16 0
//  17 0
//  18 0
//  19 1
//  20 0
//  21 1
//  22 0 size     0
//  23 0 size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0
//  30 1
//  31 0
// AESD  <Vd>.16B, <Vn>.16B
bool TryDecodeAESD_B_CRYPTOAES(const InstData &, Instruction &) {
  return false;
}

// AESMC AESMC_B_cryptoaes:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 D        0
//  13 1
//  14 1
//  15 0
//  16 0
//  17 0
//  18 0
//  19 1
//  20 0
//  21 1
//  22 0 size     0
//  23 0 size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0
//  30 1
//  31 0
// AESMC  <Vd>.16B, <Vn>.16B
bool TryDecodeAESMC_B_CRYPTOAES(const InstData &, Instruction &) {
  return false;
}

// LD2 LD2_asisdlso_B2_2b:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x size     0
//  11 x size     1
//  12 x S        0
//  13 0 opcode   0
//  14 0 opcode   1
//  15 0 opcode   2
//  16 0
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1 R        0
//  22 1 L        0
//  23 0
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// LD2  { <Vt>.B, <Vt2>.B }[<index>], [<Xn|SP>]
bool TryDecodeLD2_ASISDLSO_B2_2B(const InstData &, Instruction &) {
  return false;
}

// LD2 LD2_asisdlso_H2_2h:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0 size     0
//  11 x size     1
//  12 x S        0
//  13 0 opcode   0
//  14 1 opcode   1
//  15 0 opcode   2
//  16 0
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1 R        0
//  22 1 L        0
//  23 0
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// LD2  { <Vt>.H, <Vt2>.H }[<index>], [<Xn|SP>]
bool TryDecodeLD2_ASISDLSO_H2_2H(const InstData &, Instruction &) {
  return false;
}

// LD2 LD2_asisdlso_S2_2s:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0 size     0
//  11 0 size     1
//  12 x S        0
//  13 0 opcode   0
//  14 0 opcode   1
//  15 1 opcode   2
//  16 0
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1 R        0
//  22 1 L        0
//  23 0
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// LD2  { <Vt>.S, <Vt2>.S }[<index>], [<Xn|SP>]
bool TryDecodeLD2_ASISDLSO_S2_2S(const InstData &, Instruction &) {
  return false;
}

// LD2 LD2_asisdlso_D2_2d:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 size     0
//  11 0 size     1
//  12 0 S        0
//  13 0 opcode   0
//  14 0 opcode   1
//  15 1 opcode   2
//  16 0
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1 R        0
//  22 1 L        0
//  23 0
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// LD2  { <Vt>.D, <Vt2>.D }[<index>], [<Xn|SP>]
bool TryDecodeLD2_ASISDLSO_D2_2D(const InstData &, Instruction &) {
  return false;
}

// LD2 LD2_asisdlsop_B2_i2b:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x size     0
//  11 x size     1
//  12 x S        0
//  13 0 opcode   0
//  14 0 opcode   1
//  15 0 opcode   2
//  16 1 Rm       0
//  17 1 Rm       1
//  18 1 Rm       2
//  19 1 Rm       3
//  20 1 Rm       4
//  21 1 R        0
//  22 1 L        0
//  23 1
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// LD2  { <Vt>.B, <Vt2>.B }[<index>], [<Xn|SP>], #2
bool TryDecodeLD2_ASISDLSOP_B2_I2B(const InstData &, Instruction &) {
  return false;
}

// LD2 LD2_asisdlsop_BX2_r2b:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x size     0
//  11 x size     1
//  12 x S        0
//  13 0 opcode   0
//  14 0 opcode   1
//  15 0 opcode   2
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1 R        0
//  22 1 L        0
//  23 1
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// LD2  { <Vt>.B, <Vt2>.B }[<index>], [<Xn|SP>], <Xm>
bool TryDecodeLD2_ASISDLSOP_BX2_R2B(const InstData &, Instruction &) {
  return false;
}

// LD2 LD2_asisdlsop_H2_i2h:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0 size     0
//  11 x size     1
//  12 x S        0
//  13 0 opcode   0
//  14 1 opcode   1
//  15 0 opcode   2
//  16 1 Rm       0
//  17 1 Rm       1
//  18 1 Rm       2
//  19 1 Rm       3
//  20 1 Rm       4
//  21 1 R        0
//  22 1 L        0
//  23 1
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// LD2  { <Vt>.H, <Vt2>.H }[<index>], [<Xn|SP>], #4
bool TryDecodeLD2_ASISDLSOP_H2_I2H(const InstData &, Instruction &) {
  return false;
}

// LD2 LD2_asisdlsop_HX2_r2h:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0 size     0
//  11 x size     1
//  12 x S        0
//  13 0 opcode   0
//  14 1 opcode   1
//  15 0 opcode   2
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1 R        0
//  22 1 L        0
//  23 1
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// LD2  { <Vt>.H, <Vt2>.H }[<index>], [<Xn|SP>], <Xm>
bool TryDecodeLD2_ASISDLSOP_HX2_R2H(const InstData &, Instruction &) {
  return false;
}

// LD2 LD2_asisdlsop_S2_i2s:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0 size     0
//  11 0 size     1
//  12 x S        0
//  13 0 opcode   0
//  14 0 opcode   1
//  15 1 opcode   2
//  16 1 Rm       0
//  17 1 Rm       1
//  18 1 Rm       2
//  19 1 Rm       3
//  20 1 Rm       4
//  21 1 R        0
//  22 1 L        0
//  23 1
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// LD2  { <Vt>.S, <Vt2>.S }[<index>], [<Xn|SP>], #8
bool TryDecodeLD2_ASISDLSOP_S2_I2S(const InstData &, Instruction &) {
  return false;
}

// LD2 LD2_asisdlsop_SX2_r2s:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0 size     0
//  11 0 size     1
//  12 x S        0
//  13 0 opcode   0
//  14 0 opcode   1
//  15 1 opcode   2
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1 R        0
//  22 1 L        0
//  23 1
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// LD2  { <Vt>.S, <Vt2>.S }[<index>], [<Xn|SP>], <Xm>
bool TryDecodeLD2_ASISDLSOP_SX2_R2S(const InstData &, Instruction &) {
  return false;
}

// LD2 LD2_asisdlsop_D2_i2d:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 size     0
//  11 0 size     1
//  12 0 S        0
//  13 0 opcode   0
//  14 0 opcode   1
//  15 1 opcode   2
//  16 1 Rm       0
//  17 1 Rm       1
//  18 1 Rm       2
//  19 1 Rm       3
//  20 1 Rm       4
//  21 1 R        0
//  22 1 L        0
//  23 1
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// LD2  { <Vt>.D, <Vt2>.D }[<index>], [<Xn|SP>], #16
bool TryDecodeLD2_ASISDLSOP_D2_I2D(const InstData &, Instruction &) {
  return false;
}

// LD2 LD2_asisdlsop_DX2_r2d:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 size     0
//  11 0 size     1
//  12 0 S        0
//  13 0 opcode   0
//  14 0 opcode   1
//  15 1 opcode   2
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1 R        0
//  22 1 L        0
//  23 1
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// LD2  { <Vt>.D, <Vt2>.D }[<index>], [<Xn|SP>], <Xm>
bool TryDecodeLD2_ASISDLSOP_DX2_R2D(const InstData &, Instruction &) {
  return false;
}

// FCVTZU FCVTZU_asisdmiscfp16_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 o1       0
//  13 1
//  14 0
//  15 1
//  16 1
//  17 0
//  18 0
//  19 1
//  20 1
//  21 1
//  22 1
//  23 1 o2       0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 1 U        0
//  30 1
//  31 0
// FCVTZU  <Hd>, <Hn>
bool TryDecodeFCVTZU_ASISDMISCFP16_R(const InstData &, Instruction &) {
  return false;
}

// FCVTZU FCVTZU_asisdmisc_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 o1       0
//  13 1
//  14 0
//  15 1
//  16 1
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x sz       0
//  23 1 o2       0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 1 U        0
//  30 1
//  31 0
// FCVTZU  <V><d>, <V><n>
bool TryDecodeFCVTZU_ASISDMISC_R(const InstData &, Instruction &) {
  return false;
}

// FCVTZU FCVTZU_asimdmiscfp16_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 o1       0
//  13 1
//  14 0
//  15 1
//  16 1
//  17 0
//  18 0
//  19 1
//  20 1
//  21 1
//  22 1
//  23 1 o2       0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// FCVTZU  <Vd>.<T>, <Vn>.<T>
bool TryDecodeFCVTZU_ASIMDMISCFP16_R(const InstData &, Instruction &) {
  return false;
}

// FCVTZU FCVTZU_asimdmisc_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 o1       0
//  13 1
//  14 0
//  15 1
//  16 1
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x sz       0
//  23 1 o2       0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// FCVTZU  <Vd>.<T>, <Vn>.<T>
bool TryDecodeFCVTZU_ASIMDMISC_R(const InstData &, Instruction &) {
  return false;
}

// ORN MVN_ORN_32_log_shift:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 1 Rn       0
//   6 1 Rn       1
//   7 1 Rn       2
//   8 1 Rn       3
//   9 1 Rn       4
//  10 x imm6     0
//  11 x imm6     1
//  12 x imm6     2
//  13 x imm6     3
//  14 x imm6     4
//  15 x imm6     5
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1 N        0
//  22 x shift    0
//  23 x shift    1
//  24 0
//  25 1
//  26 0
//  27 1
//  28 0
//  29 1 opc      0
//  30 0 opc      1
//  31 0 sf       0
// MVN  <Wd>, <Wm>{, <shift> #<amount>}
bool TryDecodeMVN_ORN_32_LOG_SHIFT(const InstData &, Instruction &) {
  return false;
}

// ORN MVN_ORN_64_log_shift:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 1 Rn       0
//   6 1 Rn       1
//   7 1 Rn       2
//   8 1 Rn       3
//   9 1 Rn       4
//  10 x imm6     0
//  11 x imm6     1
//  12 x imm6     2
//  13 x imm6     3
//  14 x imm6     4
//  15 x imm6     5
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1 N        0
//  22 x shift    0
//  23 x shift    1
//  24 0
//  25 1
//  26 0
//  27 1
//  28 0
//  29 1 opc      0
//  30 0 opc      1
//  31 1 sf       0
// MVN  <Xd>, <Xm>{, <shift> #<amount>}
bool TryDecodeMVN_ORN_64_LOG_SHIFT(const InstData &, Instruction &) {
  return false;
}

// STEOR STEOR_32S_memop:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 1 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 1 size     1
// STEOR  <Ws>, [<Xn|SP>]
bool TryDecodeSTEOR_32S_MEMOP(const InstData &, Instruction &) {
  return false;
}

// STEORL STEORL_32S_memop:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 1 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 1 size     1
// STEORL  <Ws>, [<Xn|SP>]
bool TryDecodeSTEORL_32S_MEMOP(const InstData &, Instruction &) {
  return false;
}

// STEOR STEOR_64S_memop:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 1 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 1 size     1
// STEOR  <Xs>, [<Xn|SP>]
bool TryDecodeSTEOR_64S_MEMOP(const InstData &, Instruction &) {
  return false;
}

// STEORL STEORL_64S_memop:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 1 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 1 size     1
// STEORL  <Xs>, [<Xn|SP>]
bool TryDecodeSTEORL_64S_MEMOP(const InstData &, Instruction &) {
  return false;
}

// TBX TBX_asimdtbl_L2_2:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 op       0
//  13 1 len      0
//  14 0 len      1
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 0 op2      0
//  23 0 op2      1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// TBX  <Vd>.<Ta>, { <Vn>.16B, <Vn+1>.16B }, <Vm>.<Ta>
bool TryDecodeTBX_ASIMDTBL_L2_2(const InstData &, Instruction &) {
  return false;
}

// TBX TBX_asimdtbl_L3_3:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 op       0
//  13 0 len      0
//  14 1 len      1
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 0 op2      0
//  23 0 op2      1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// TBX  <Vd>.<Ta>, { <Vn>.16B, <Vn+1>.16B, <Vn+2>.16B }, <Vm>.<Ta>
bool TryDecodeTBX_ASIMDTBL_L3_3(const InstData &, Instruction &) {
  return false;
}

// TBX TBX_asimdtbl_L4_4:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 op       0
//  13 1 len      0
//  14 1 len      1
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 0 op2      0
//  23 0 op2      1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// TBX  <Vd>.<Ta>, { <Vn>.16B, <Vn+1>.16B, <Vn+2>.16B, <Vn+3>.16B }, <Vm>.<Ta>
bool TryDecodeTBX_ASIMDTBL_L4_4(const InstData &, Instruction &) {
  return false;
}

// TBX TBX_asimdtbl_L1_1:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 op       0
//  13 0 len      0
//  14 0 len      1
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 0 op2      0
//  23 0 op2      1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// TBX  <Vd>.<Ta>, { <Vn>.16B }, <Vm>.<Ta>
bool TryDecodeTBX_ASIMDTBL_L1_1(const InstData &, Instruction &) {
  return false;
}

// UMLAL UMLAL_asimdelem_L:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 x H        0
//  12 0
//  13 1
//  14 0 o2       0
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x M        0
//  21 x L        0
//  22 x size     0
//  23 x size     1
//  24 1
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// UMLAL{2}  <Vd>.<Ta>, <Vn>.<Tb>, <Vm>.<Ts>[<index>]
bool TryDecodeUMLAL_ASIMDELEM_L(const InstData &, Instruction &) {
  return false;
}

// CMLE CMLE_asisdmisc_Z:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 op       0
//  13 0
//  14 0
//  15 1
//  16 0
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 1 U        0
//  30 1
//  31 0
// CMLE  <V><d>, <V><n>, #0
bool TryDecodeCMLE_ASISDMISC_Z(const InstData &, Instruction &) {
  return false;
}

// CMEQ CMEQ_asisdmisc_Z:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 op       0
//  13 0
//  14 0
//  15 1
//  16 0
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// CMEQ  <V><d>, <V><n>, #0
bool TryDecodeCMEQ_ASISDMISC_Z(const InstData &, Instruction &) {
  return false;
}

// LDUMAXAH LDUMAXAH_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 1 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 1 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 0 size     1
// LDUMAXAH  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDUMAXAH_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDUMAXALH LDUMAXALH_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 1 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 1 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 0 size     1
// LDUMAXALH  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDUMAXALH_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDUMAXH LDUMAXH_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 1 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 0 size     1
// LDUMAXH  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDUMAXH_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDUMAXLH LDUMAXLH_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 1 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 0 size     1
// LDUMAXLH  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDUMAXLH_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// ST3 ST3_asisdlso_B3_3b:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x size     0
//  11 x size     1
//  12 x S        0
//  13 1 opcode   0
//  14 0 opcode   1
//  15 0 opcode   2
//  16 0
//  17 0
//  18 0
//  19 0
//  20 0
//  21 0 R        0
//  22 0 L        0
//  23 0
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// ST3  { <Vt>.B, <Vt2>.B, <Vt3>.B }[<index>], [<Xn|SP>]
bool TryDecodeST3_ASISDLSO_B3_3B(const InstData &, Instruction &) {
  return false;
}

// ST3 ST3_asisdlso_H3_3h:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0 size     0
//  11 x size     1
//  12 x S        0
//  13 1 opcode   0
//  14 1 opcode   1
//  15 0 opcode   2
//  16 0
//  17 0
//  18 0
//  19 0
//  20 0
//  21 0 R        0
//  22 0 L        0
//  23 0
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// ST3  { <Vt>.H, <Vt2>.H, <Vt3>.H }[<index>], [<Xn|SP>]
bool TryDecodeST3_ASISDLSO_H3_3H(const InstData &, Instruction &) {
  return false;
}

// ST3 ST3_asisdlso_S3_3s:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0 size     0
//  11 0 size     1
//  12 x S        0
//  13 1 opcode   0
//  14 0 opcode   1
//  15 1 opcode   2
//  16 0
//  17 0
//  18 0
//  19 0
//  20 0
//  21 0 R        0
//  22 0 L        0
//  23 0
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// ST3  { <Vt>.S, <Vt2>.S, <Vt3>.S }[<index>], [<Xn|SP>]
bool TryDecodeST3_ASISDLSO_S3_3S(const InstData &, Instruction &) {
  return false;
}

// ST3 ST3_asisdlso_D3_3d:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 size     0
//  11 0 size     1
//  12 0 S        0
//  13 1 opcode   0
//  14 0 opcode   1
//  15 1 opcode   2
//  16 0
//  17 0
//  18 0
//  19 0
//  20 0
//  21 0 R        0
//  22 0 L        0
//  23 0
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// ST3  { <Vt>.D, <Vt2>.D, <Vt3>.D }[<index>], [<Xn|SP>]
bool TryDecodeST3_ASISDLSO_D3_3D(const InstData &, Instruction &) {
  return false;
}

// ST3 ST3_asisdlsop_B3_i3b:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x size     0
//  11 x size     1
//  12 x S        0
//  13 1 opcode   0
//  14 0 opcode   1
//  15 0 opcode   2
//  16 1 Rm       0
//  17 1 Rm       1
//  18 1 Rm       2
//  19 1 Rm       3
//  20 1 Rm       4
//  21 0 R        0
//  22 0 L        0
//  23 1
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// ST3  { <Vt>.B, <Vt2>.B, <Vt3>.B }[<index>], [<Xn|SP>], #3
bool TryDecodeST3_ASISDLSOP_B3_I3B(const InstData &, Instruction &) {
  return false;
}

// ST3 ST3_asisdlsop_BX3_r3b:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x size     0
//  11 x size     1
//  12 x S        0
//  13 1 opcode   0
//  14 0 opcode   1
//  15 0 opcode   2
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0 R        0
//  22 0 L        0
//  23 1
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// ST3  { <Vt>.B, <Vt2>.B, <Vt3>.B }[<index>], [<Xn|SP>], <Xm>
bool TryDecodeST3_ASISDLSOP_BX3_R3B(const InstData &, Instruction &) {
  return false;
}

// ST3 ST3_asisdlsop_H3_i3h:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0 size     0
//  11 x size     1
//  12 x S        0
//  13 1 opcode   0
//  14 1 opcode   1
//  15 0 opcode   2
//  16 1 Rm       0
//  17 1 Rm       1
//  18 1 Rm       2
//  19 1 Rm       3
//  20 1 Rm       4
//  21 0 R        0
//  22 0 L        0
//  23 1
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// ST3  { <Vt>.H, <Vt2>.H, <Vt3>.H }[<index>], [<Xn|SP>], #6
bool TryDecodeST3_ASISDLSOP_H3_I3H(const InstData &, Instruction &) {
  return false;
}

// ST3 ST3_asisdlsop_HX3_r3h:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0 size     0
//  11 x size     1
//  12 x S        0
//  13 1 opcode   0
//  14 1 opcode   1
//  15 0 opcode   2
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0 R        0
//  22 0 L        0
//  23 1
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// ST3  { <Vt>.H, <Vt2>.H, <Vt3>.H }[<index>], [<Xn|SP>], <Xm>
bool TryDecodeST3_ASISDLSOP_HX3_R3H(const InstData &, Instruction &) {
  return false;
}

// ST3 ST3_asisdlsop_S3_i3s:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0 size     0
//  11 0 size     1
//  12 x S        0
//  13 1 opcode   0
//  14 0 opcode   1
//  15 1 opcode   2
//  16 1 Rm       0
//  17 1 Rm       1
//  18 1 Rm       2
//  19 1 Rm       3
//  20 1 Rm       4
//  21 0 R        0
//  22 0 L        0
//  23 1
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// ST3  { <Vt>.S, <Vt2>.S, <Vt3>.S }[<index>], [<Xn|SP>], #12
bool TryDecodeST3_ASISDLSOP_S3_I3S(const InstData &, Instruction &) {
  return false;
}

// ST3 ST3_asisdlsop_SX3_r3s:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0 size     0
//  11 0 size     1
//  12 x S        0
//  13 1 opcode   0
//  14 0 opcode   1
//  15 1 opcode   2
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0 R        0
//  22 0 L        0
//  23 1
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// ST3  { <Vt>.S, <Vt2>.S, <Vt3>.S }[<index>], [<Xn|SP>], <Xm>
bool TryDecodeST3_ASISDLSOP_SX3_R3S(const InstData &, Instruction &) {
  return false;
}

// ST3 ST3_asisdlsop_D3_i3d:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 size     0
//  11 0 size     1
//  12 0 S        0
//  13 1 opcode   0
//  14 0 opcode   1
//  15 1 opcode   2
//  16 1 Rm       0
//  17 1 Rm       1
//  18 1 Rm       2
//  19 1 Rm       3
//  20 1 Rm       4
//  21 0 R        0
//  22 0 L        0
//  23 1
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// ST3  { <Vt>.D, <Vt2>.D, <Vt3>.D }[<index>], [<Xn|SP>], #24
bool TryDecodeST3_ASISDLSOP_D3_I3D(const InstData &, Instruction &) {
  return false;
}

// ST3 ST3_asisdlsop_DX3_r3d:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 size     0
//  11 0 size     1
//  12 0 S        0
//  13 1 opcode   0
//  14 0 opcode   1
//  15 1 opcode   2
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0 R        0
//  22 0 L        0
//  23 1
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// ST3  { <Vt>.D, <Vt2>.D, <Vt3>.D }[<index>], [<Xn|SP>], <Xm>
bool TryDecodeST3_ASISDLSOP_DX3_R3D(const InstData &, Instruction &) {
  return false;
}


// LDADDA LDADDA_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 0 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 1 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 1 size     1
// LDADDA  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDADDA_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDADDAL LDADDAL_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 0 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 1 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 1 size     1
// LDADDAL  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDADDAL_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDADD LDADD_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 0 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 1 size     1
// LDADD  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDADD_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDADDL LDADDL_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 0 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 1 size     1
// LDADDL  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDADDL_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDADDA LDADDA_64_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 0 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 1 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 1 size     1
// LDADDA  <Xs>, <Xt>, [<Xn|SP>]
bool TryDecodeLDADDA_64_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDADDAL LDADDAL_64_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 0 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 1 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 1 size     1
// LDADDAL  <Xs>, <Xt>, [<Xn|SP>]
bool TryDecodeLDADDAL_64_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDADD LDADD_64_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 0 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 1 size     1
// LDADD  <Xs>, <Xt>, [<Xn|SP>]
bool TryDecodeLDADD_64_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDADDL LDADDL_64_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 0 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 1 size     1
// LDADDL  <Xs>, <Xt>, [<Xn|SP>]
bool TryDecodeLDADDL_64_MEMOP(const InstData &, Instruction &) {
  return false;
}

// FCVTZS FCVTZS_asisdshf_C:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1 opcode   0
//  12 1 opcode   1
//  13 1 opcode   2
//  14 1 opcode   3
//  15 1 opcode   4
//  16 x immb     0
//  17 x immb     1
//  18 x immb     2
//  19 x immh     0
//  20 x immh     1
//  21 x immh     2
//  22 x immh     3
//  23 0
//  24 1
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// FCVTZS  <V><d>, <V><n>, #<fbits>
bool TryDecodeFCVTZS_ASISDSHF_C(const InstData &, Instruction &) {
  return false;
}

// FCVTZS FCVTZS_asimdshf_C:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1 opcode   0
//  12 1 opcode   1
//  13 1 opcode   2
//  14 1 opcode   3
//  15 1 opcode   4
//  16 x immb     0
//  17 x immb     1
//  18 x immb     2
//  19 x immh     0
//  20 x immh     1
//  21 x immh     2
//  22 x immh     3
//  23 0
//  24 1
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// FCVTZS  <Vd>.<T>, <Vn>.<T>, #<fbits>
bool TryDecodeFCVTZS_ASIMDSHF_C(const InstData &, Instruction &) {
  return false;
}

// ST2 ST2_asisdlso_B2_2b:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x size     0
//  11 x size     1
//  12 x S        0
//  13 0 opcode   0
//  14 0 opcode   1
//  15 0 opcode   2
//  16 0
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1 R        0
//  22 0 L        0
//  23 0
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// ST2  { <Vt>.B, <Vt2>.B }[<index>], [<Xn|SP>]
bool TryDecodeST2_ASISDLSO_B2_2B(const InstData &, Instruction &) {
  return false;
}

// ST2 ST2_asisdlso_H2_2h:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0 size     0
//  11 x size     1
//  12 x S        0
//  13 0 opcode   0
//  14 1 opcode   1
//  15 0 opcode   2
//  16 0
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1 R        0
//  22 0 L        0
//  23 0
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// ST2  { <Vt>.H, <Vt2>.H }[<index>], [<Xn|SP>]
bool TryDecodeST2_ASISDLSO_H2_2H(const InstData &, Instruction &) {
  return false;
}

// ST2 ST2_asisdlso_S2_2s:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0 size     0
//  11 0 size     1
//  12 x S        0
//  13 0 opcode   0
//  14 0 opcode   1
//  15 1 opcode   2
//  16 0
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1 R        0
//  22 0 L        0
//  23 0
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// ST2  { <Vt>.S, <Vt2>.S }[<index>], [<Xn|SP>]
bool TryDecodeST2_ASISDLSO_S2_2S(const InstData &, Instruction &) {
  return false;
}

// ST2 ST2_asisdlso_D2_2d:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 size     0
//  11 0 size     1
//  12 0 S        0
//  13 0 opcode   0
//  14 0 opcode   1
//  15 1 opcode   2
//  16 0
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1 R        0
//  22 0 L        0
//  23 0
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// ST2  { <Vt>.D, <Vt2>.D }[<index>], [<Xn|SP>]
bool TryDecodeST2_ASISDLSO_D2_2D(const InstData &, Instruction &) {
  return false;
}

// ST2 ST2_asisdlsop_B2_i2b:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x size     0
//  11 x size     1
//  12 x S        0
//  13 0 opcode   0
//  14 0 opcode   1
//  15 0 opcode   2
//  16 1 Rm       0
//  17 1 Rm       1
//  18 1 Rm       2
//  19 1 Rm       3
//  20 1 Rm       4
//  21 1 R        0
//  22 0 L        0
//  23 1
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// ST2  { <Vt>.B, <Vt2>.B }[<index>], [<Xn|SP>], #2
bool TryDecodeST2_ASISDLSOP_B2_I2B(const InstData &, Instruction &) {
  return false;
}

// ST2 ST2_asisdlsop_BX2_r2b:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x size     0
//  11 x size     1
//  12 x S        0
//  13 0 opcode   0
//  14 0 opcode   1
//  15 0 opcode   2
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1 R        0
//  22 0 L        0
//  23 1
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// ST2  { <Vt>.B, <Vt2>.B }[<index>], [<Xn|SP>], <Xm>
bool TryDecodeST2_ASISDLSOP_BX2_R2B(const InstData &, Instruction &) {
  return false;
}

// ST2 ST2_asisdlsop_H2_i2h:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0 size     0
//  11 x size     1
//  12 x S        0
//  13 0 opcode   0
//  14 1 opcode   1
//  15 0 opcode   2
//  16 1 Rm       0
//  17 1 Rm       1
//  18 1 Rm       2
//  19 1 Rm       3
//  20 1 Rm       4
//  21 1 R        0
//  22 0 L        0
//  23 1
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// ST2  { <Vt>.H, <Vt2>.H }[<index>], [<Xn|SP>], #4
bool TryDecodeST2_ASISDLSOP_H2_I2H(const InstData &, Instruction &) {
  return false;
}

// ST2 ST2_asisdlsop_HX2_r2h:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0 size     0
//  11 x size     1
//  12 x S        0
//  13 0 opcode   0
//  14 1 opcode   1
//  15 0 opcode   2
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1 R        0
//  22 0 L        0
//  23 1
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// ST2  { <Vt>.H, <Vt2>.H }[<index>], [<Xn|SP>], <Xm>
bool TryDecodeST2_ASISDLSOP_HX2_R2H(const InstData &, Instruction &) {
  return false;
}

// ST2 ST2_asisdlsop_S2_i2s:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0 size     0
//  11 0 size     1
//  12 x S        0
//  13 0 opcode   0
//  14 0 opcode   1
//  15 1 opcode   2
//  16 1 Rm       0
//  17 1 Rm       1
//  18 1 Rm       2
//  19 1 Rm       3
//  20 1 Rm       4
//  21 1 R        0
//  22 0 L        0
//  23 1
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// ST2  { <Vt>.S, <Vt2>.S }[<index>], [<Xn|SP>], #8
bool TryDecodeST2_ASISDLSOP_S2_I2S(const InstData &, Instruction &) {
  return false;
}

// ST2 ST2_asisdlsop_SX2_r2s:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0 size     0
//  11 0 size     1
//  12 x S        0
//  13 0 opcode   0
//  14 0 opcode   1
//  15 1 opcode   2
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1 R        0
//  22 0 L        0
//  23 1
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// ST2  { <Vt>.S, <Vt2>.S }[<index>], [<Xn|SP>], <Xm>
bool TryDecodeST2_ASISDLSOP_SX2_R2S(const InstData &, Instruction &) {
  return false;
}

// ST2 ST2_asisdlsop_D2_i2d:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 size     0
//  11 0 size     1
//  12 0 S        0
//  13 0 opcode   0
//  14 0 opcode   1
//  15 1 opcode   2
//  16 1 Rm       0
//  17 1 Rm       1
//  18 1 Rm       2
//  19 1 Rm       3
//  20 1 Rm       4
//  21 1 R        0
//  22 0 L        0
//  23 1
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// ST2  { <Vt>.D, <Vt2>.D }[<index>], [<Xn|SP>], #16
bool TryDecodeST2_ASISDLSOP_D2_I2D(const InstData &, Instruction &) {
  return false;
}

// ST2 ST2_asisdlsop_DX2_r2d:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 size     0
//  11 0 size     1
//  12 0 S        0
//  13 0 opcode   0
//  14 0 opcode   1
//  15 1 opcode   2
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1 R        0
//  22 0 L        0
//  23 1
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// ST2  { <Vt>.D, <Vt2>.D }[<index>], [<Xn|SP>], <Xm>
bool TryDecodeST2_ASISDLSOP_DX2_R2D(const InstData &, Instruction &) {
  return false;
}

// RADDHN RADDHN_asimddiff_N:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0 o1       0
//  14 1
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// RADDHN{2}  <Vd>.<Tb>, <Vn>.<Ta>, <Vm>.<Ta>
bool TryDecodeRADDHN_ASIMDDIFF_N(const InstData &, Instruction &) {
  return false;
}

// CLS CLS_asimdmisc_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 opcode   0
//  13 0 opcode   1
//  14 1 opcode   2
//  15 0 opcode   3
//  16 0 opcode   4
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// CLS  <Vd>.<T>, <Vn>.<T>
bool TryDecodeCLS_ASIMDMISC_R(const InstData &, Instruction &) {
  return false;
}

// SADDL SADDL_asimddiff_L:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0 o1       0
//  14 0
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// SADDL{2}  <Vd>.<Ta>, <Vn>.<Tb>, <Vm>.<Tb>
bool TryDecodeSADDL_ASIMDDIFF_L(const InstData &, Instruction &) {
  return false;
}

// ADDP ADDP_asisdpair_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 opcode   0
//  13 1 opcode   1
//  14 0 opcode   2
//  15 1 opcode   3
//  16 1 opcode   4
//  17 0
//  18 0
//  19 0
//  20 1
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// ADDP  <V><d>, <Vn>.<T>
bool TryDecodeADDP_ASISDPAIR_ONLY(const InstData &, Instruction &) {
  return false;
}

// STR STR_B_ldst_immpost:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0
//  12 x imm9     0
//  13 x imm9     1
//  14 x imm9     2
//  15 x imm9     3
//  16 x imm9     4
//  17 x imm9     5
//  18 x imm9     6
//  19 x imm9     7
//  20 x imm9     8
//  21 0
//  22 0 opc      0
//  23 0 opc      1
//  24 0
//  25 0
//  26 1 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 0 size     1
// STR  <Bt>, [<Xn|SP>], #<simm>
bool TryDecodeSTR_B_LDST_IMMPOST(const InstData &, Instruction &) {
  return false;
}

// STR STR_H_ldst_immpost:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0
//  12 x imm9     0
//  13 x imm9     1
//  14 x imm9     2
//  15 x imm9     3
//  16 x imm9     4
//  17 x imm9     5
//  18 x imm9     6
//  19 x imm9     7
//  20 x imm9     8
//  21 0
//  22 0 opc      0
//  23 0 opc      1
//  24 0
//  25 0
//  26 1 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 0 size     1
// STR  <Ht>, [<Xn|SP>], #<simm>
bool TryDecodeSTR_H_LDST_IMMPOST(const InstData &, Instruction &) {
  return false;
}

// STR STR_S_ldst_immpost:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0
//  12 x imm9     0
//  13 x imm9     1
//  14 x imm9     2
//  15 x imm9     3
//  16 x imm9     4
//  17 x imm9     5
//  18 x imm9     6
//  19 x imm9     7
//  20 x imm9     8
//  21 0
//  22 0 opc      0
//  23 0 opc      1
//  24 0
//  25 0
//  26 1 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 1 size     1
// STR  <St>, [<Xn|SP>], #<simm>
bool TryDecodeSTR_S_LDST_IMMPOST(const InstData &, Instruction &) {
  return false;
}

// STR STR_D_ldst_immpost:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0
//  12 x imm9     0
//  13 x imm9     1
//  14 x imm9     2
//  15 x imm9     3
//  16 x imm9     4
//  17 x imm9     5
//  18 x imm9     6
//  19 x imm9     7
//  20 x imm9     8
//  21 0
//  22 0 opc      0
//  23 0 opc      1
//  24 0
//  25 0
//  26 1 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 1 size     1
// STR  <Dt>, [<Xn|SP>], #<simm>
bool TryDecodeSTR_D_LDST_IMMPOST(const InstData &, Instruction &) {
  return false;
}

// STR STR_Q_ldst_immpost:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0
//  12 x imm9     0
//  13 x imm9     1
//  14 x imm9     2
//  15 x imm9     3
//  16 x imm9     4
//  17 x imm9     5
//  18 x imm9     6
//  19 x imm9     7
//  20 x imm9     8
//  21 0
//  22 0 opc      0
//  23 1 opc      1
//  24 0
//  25 0
//  26 1 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 0 size     1
// STR  <Qt>, [<Xn|SP>], #<simm>
bool TryDecodeSTR_Q_LDST_IMMPOST(const InstData &, Instruction &) {
  return false;
}

// STR STR_B_ldst_immpre:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1
//  12 x imm9     0
//  13 x imm9     1
//  14 x imm9     2
//  15 x imm9     3
//  16 x imm9     4
//  17 x imm9     5
//  18 x imm9     6
//  19 x imm9     7
//  20 x imm9     8
//  21 0
//  22 0 opc      0
//  23 0 opc      1
//  24 0
//  25 0
//  26 1 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 0 size     1
// STR  <Bt>, [<Xn|SP>, #<simm>]!
bool TryDecodeSTR_B_LDST_IMMPRE(const InstData &, Instruction &) {
  return false;
}

// STR STR_H_ldst_immpre:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1
//  12 x imm9     0
//  13 x imm9     1
//  14 x imm9     2
//  15 x imm9     3
//  16 x imm9     4
//  17 x imm9     5
//  18 x imm9     6
//  19 x imm9     7
//  20 x imm9     8
//  21 0
//  22 0 opc      0
//  23 0 opc      1
//  24 0
//  25 0
//  26 1 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 0 size     1
// STR  <Ht>, [<Xn|SP>, #<simm>]!
bool TryDecodeSTR_H_LDST_IMMPRE(const InstData &, Instruction &) {
  return false;
}

// STR STR_S_ldst_immpre:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1
//  12 x imm9     0
//  13 x imm9     1
//  14 x imm9     2
//  15 x imm9     3
//  16 x imm9     4
//  17 x imm9     5
//  18 x imm9     6
//  19 x imm9     7
//  20 x imm9     8
//  21 0
//  22 0 opc      0
//  23 0 opc      1
//  24 0
//  25 0
//  26 1 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 1 size     1
// STR  <St>, [<Xn|SP>, #<simm>]!
bool TryDecodeSTR_S_LDST_IMMPRE(const InstData &, Instruction &) {
  return false;
}

// STR STR_D_ldst_immpre:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1
//  12 x imm9     0
//  13 x imm9     1
//  14 x imm9     2
//  15 x imm9     3
//  16 x imm9     4
//  17 x imm9     5
//  18 x imm9     6
//  19 x imm9     7
//  20 x imm9     8
//  21 0
//  22 0 opc      0
//  23 0 opc      1
//  24 0
//  25 0
//  26 1 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 1 size     1
// STR  <Dt>, [<Xn|SP>, #<simm>]!
bool TryDecodeSTR_D_LDST_IMMPRE(const InstData &, Instruction &) {
  return false;
}

// LDSETAB LDSETAB_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 1 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 1 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 0 size     1
// LDSETAB  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDSETAB_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDSETALB LDSETALB_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 1 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 1 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 0 size     1
// LDSETALB  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDSETALB_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDSETB LDSETB_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 1 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 0 size     1
// LDSETB  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDSETB_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDSETLB LDSETLB_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 1 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 0 size     1
// LDSETLB  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDSETLB_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// FRINTP FRINTP_H_floatdp1:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 1
//  15 1 rmode    0
//  16 0 rmode    1
//  17 0 rmode    2
//  18 1
//  19 0
//  20 0
//  21 1
//  22 1 type     0
//  23 1 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 M        0
// FRINTP  <Hd>, <Hn>
bool TryDecodeFRINTP_H_FLOATDP1(const InstData &, Instruction &) {
  return false;
}

// FRINTP FRINTP_S_floatdp1:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 1
//  15 1 rmode    0
//  16 0 rmode    1
//  17 0 rmode    2
//  18 1
//  19 0
//  20 0
//  21 1
//  22 0 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 M        0
// FRINTP  <Sd>, <Sn>
bool TryDecodeFRINTP_S_FLOATDP1(const InstData &, Instruction &) {
  return false;
}

// FRINTP FRINTP_D_floatdp1:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 1
//  15 1 rmode    0
//  16 0 rmode    1
//  17 0 rmode    2
//  18 1
//  19 0
//  20 0
//  21 1
//  22 1 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 M        0
// FRINTP  <Dd>, <Dn>
bool TryDecodeFRINTP_D_FLOATDP1(const InstData &, Instruction &) {
  return false;
}

// CASA CASA_C32_ldstexcl:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 Rt2      0
//  11 1 Rt2      1
//  12 1 Rt2      2
//  13 1 Rt2      3
//  14 1 Rt2      4
//  15 0 o0       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1 o1       0
//  22 1 L        0
//  23 1 o2       0
//  24 0
//  25 0
//  26 0
//  27 1
//  28 0
//  29 0
//  30 0 size     0
//  31 1 size     1
// CASA  <Ws>, <Wt>, [<Xn|SP>{,#0}]
bool TryDecodeCASA_C32_LDSTEXCL(const InstData &, Instruction &) {
  return false;
}

// CASAL CASAL_C32_ldstexcl:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 Rt2      0
//  11 1 Rt2      1
//  12 1 Rt2      2
//  13 1 Rt2      3
//  14 1 Rt2      4
//  15 1 o0       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1 o1       0
//  22 1 L        0
//  23 1 o2       0
//  24 0
//  25 0
//  26 0
//  27 1
//  28 0
//  29 0
//  30 0 size     0
//  31 1 size     1
// CASAL  <Ws>, <Wt>, [<Xn|SP>{,#0}]
bool TryDecodeCASAL_C32_LDSTEXCL(const InstData &, Instruction &) {
  return false;
}

// CAS CAS_C32_ldstexcl:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 Rt2      0
//  11 1 Rt2      1
//  12 1 Rt2      2
//  13 1 Rt2      3
//  14 1 Rt2      4
//  15 0 o0       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1 o1       0
//  22 0 L        0
//  23 1 o2       0
//  24 0
//  25 0
//  26 0
//  27 1
//  28 0
//  29 0
//  30 0 size     0
//  31 1 size     1
// CAS  <Ws>, <Wt>, [<Xn|SP>{,#0}]
bool TryDecodeCAS_C32_LDSTEXCL(const InstData &, Instruction &) {
  return false;
}

// CASL CASL_C32_ldstexcl:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 Rt2      0
//  11 1 Rt2      1
//  12 1 Rt2      2
//  13 1 Rt2      3
//  14 1 Rt2      4
//  15 1 o0       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1 o1       0
//  22 0 L        0
//  23 1 o2       0
//  24 0
//  25 0
//  26 0
//  27 1
//  28 0
//  29 0
//  30 0 size     0
//  31 1 size     1
// CASL  <Ws>, <Wt>, [<Xn|SP>{,#0}]
bool TryDecodeCASL_C32_LDSTEXCL(const InstData &, Instruction &) {
  return false;
}

// CASA CASA_C64_ldstexcl:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 Rt2      0
//  11 1 Rt2      1
//  12 1 Rt2      2
//  13 1 Rt2      3
//  14 1 Rt2      4
//  15 0 o0       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1 o1       0
//  22 1 L        0
//  23 1 o2       0
//  24 0
//  25 0
//  26 0
//  27 1
//  28 0
//  29 0
//  30 1 size     0
//  31 1 size     1
// CASA  <Xs>, <Xt>, [<Xn|SP>{,#0}]
bool TryDecodeCASA_C64_LDSTEXCL(const InstData &, Instruction &) {
  return false;
}

// CASAL CASAL_C64_ldstexcl:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 Rt2      0
//  11 1 Rt2      1
//  12 1 Rt2      2
//  13 1 Rt2      3
//  14 1 Rt2      4
//  15 1 o0       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1 o1       0
//  22 1 L        0
//  23 1 o2       0
//  24 0
//  25 0
//  26 0
//  27 1
//  28 0
//  29 0
//  30 1 size     0
//  31 1 size     1
// CASAL  <Xs>, <Xt>, [<Xn|SP>{,#0}]
bool TryDecodeCASAL_C64_LDSTEXCL(const InstData &, Instruction &) {
  return false;
}

// CAS CAS_C64_ldstexcl:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 Rt2      0
//  11 1 Rt2      1
//  12 1 Rt2      2
//  13 1 Rt2      3
//  14 1 Rt2      4
//  15 0 o0       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1 o1       0
//  22 0 L        0
//  23 1 o2       0
//  24 0
//  25 0
//  26 0
//  27 1
//  28 0
//  29 0
//  30 1 size     0
//  31 1 size     1
// CAS  <Xs>, <Xt>, [<Xn|SP>{,#0}]
bool TryDecodeCAS_C64_LDSTEXCL(const InstData &, Instruction &) {
  return false;
}

// CASL CASL_C64_ldstexcl:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 Rt2      0
//  11 1 Rt2      1
//  12 1 Rt2      2
//  13 1 Rt2      3
//  14 1 Rt2      4
//  15 1 o0       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1 o1       0
//  22 0 L        0
//  23 1 o2       0
//  24 0
//  25 0
//  26 0
//  27 1
//  28 0
//  29 0
//  30 1 size     0
//  31 1 size     1
// CASL  <Xs>, <Xt>, [<Xn|SP>{,#0}]
bool TryDecodeCASL_C64_LDSTEXCL(const InstData &, Instruction &) {
  return false;
}

// WFE WFE_HI_system:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 0 op2      0
//   6 1 op2      1
//   7 0 op2      2
//   8 0 CRm      0
//   9 0 CRm      1
//  10 0 CRm      2
//  11 0 CRm      3
//  12 0 CRn      0
//  13 1 CRn      1
//  14 0 CRn      2
//  15 0 CRn      3
//  16 1 op1      0
//  17 1 op1      1
//  18 0 op1      2
//  19 0 op0      0
//  20 0 op0      1
//  21 0 L        0
//  22 0
//  23 0
//  24 1
//  25 0
//  26 1
//  27 0
//  28 1
//  29 0
//  30 1
//  31 1
// WFE
bool TryDecodeWFE_HI_SYSTEM(const InstData &, Instruction &) {
  return false;
}

// LDUMINA LDUMINA_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 1 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 1 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 1 size     1
// LDUMINA  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDUMINA_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDUMINAL LDUMINAL_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 1 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 1 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 1 size     1
// LDUMINAL  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDUMINAL_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDUMIN LDUMIN_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 1 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 1 size     1
// LDUMIN  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDUMIN_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDUMINL LDUMINL_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 1 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 1 size     1
// LDUMINL  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDUMINL_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDUMINA LDUMINA_64_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 1 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 1 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 1 size     1
// LDUMINA  <Xs>, <Xt>, [<Xn|SP>]
bool TryDecodeLDUMINA_64_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDUMINAL LDUMINAL_64_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 1 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 1 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 1 size     1
// LDUMINAL  <Xs>, <Xt>, [<Xn|SP>]
bool TryDecodeLDUMINAL_64_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDUMIN LDUMIN_64_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 1 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 1 size     1
// LDUMIN  <Xs>, <Xt>, [<Xn|SP>]
bool TryDecodeLDUMIN_64_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDUMINL LDUMINL_64_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 1 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 1 size     1
// LDUMINL  <Xs>, <Xt>, [<Xn|SP>]
bool TryDecodeLDUMINL_64_MEMOP(const InstData &, Instruction &) {
  return false;
}

// STXRB STXRB_SR32_ldstexcl:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 Rt2      0
//  11 1 Rt2      1
//  12 1 Rt2      2
//  13 1 Rt2      3
//  14 1 Rt2      4
//  15 0 o0       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 0 o1       0
//  22 0 L        0
//  23 0 o2       0
//  24 0
//  25 0
//  26 0
//  27 1
//  28 0
//  29 0
//  30 0 size     0
//  31 0 size     1
// STXRB  <Ws>, <Wt>, [<Xn|SP>{,#0}]
bool TryDecodeSTXRB_SR32_LDSTEXCL(const InstData &, Instruction &) {
  return false;
}

// STLXRH STLXRH_SR32_ldstexcl:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 Rt2      0
//  11 1 Rt2      1
//  12 1 Rt2      2
//  13 1 Rt2      3
//  14 1 Rt2      4
//  15 1 o0       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 0 o1       0
//  22 0 L        0
//  23 0 o2       0
//  24 0
//  25 0
//  26 0
//  27 1
//  28 0
//  29 0
//  30 1 size     0
//  31 0 size     1
// STLXRH  <Ws>, <Wt>, [<Xn|SP>{,#0}]
bool TryDecodeSTLXRH_SR32_LDSTEXCL(const InstData &, Instruction &) {
  return false;
}

// STLLRH STLLRH_SL32_ldstexcl:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 Rt2      0
//  11 1 Rt2      1
//  12 1 Rt2      2
//  13 1 Rt2      3
//  14 1 Rt2      4
//  15 0 o0       0
//  16 1 Rs       0
//  17 1 Rs       1
//  18 1 Rs       2
//  19 1 Rs       3
//  20 1 Rs       4
//  21 0 o1       0
//  22 0 L        0
//  23 1 o2       0
//  24 0
//  25 0
//  26 0
//  27 1
//  28 0
//  29 0
//  30 1 size     0
//  31 0 size     1
// STLLRH  <Wt>, [<Xn|SP>{,#0}]
bool TryDecodeSTLLRH_SL32_LDSTEXCL(const InstData &, Instruction &) {
  return false;
}

// LDUMINAH LDUMINAH_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 1 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 1 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 0 size     1
// LDUMINAH  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDUMINAH_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDUMINALH LDUMINALH_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 1 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 1 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 0 size     1
// LDUMINALH  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDUMINALH_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDUMINH LDUMINH_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 1 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 0 size     1
// LDUMINH  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDUMINH_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDUMINLH LDUMINLH_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 1 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 0 size     1
// LDUMINLH  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDUMINLH_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// CMGT CMGT_asisdmisc_Z:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 op       0
//  13 0
//  14 0
//  15 1
//  16 0
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// CMGT  <V><d>, <V><n>, #0
bool TryDecodeCMGT_ASISDMISC_Z(const InstData &, Instruction &) {
  return false;
}

// SMLAL SMLAL_asimdelem_L:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 x H        0
//  12 0
//  13 1
//  14 0 o2       0
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x M        0
//  21 x L        0
//  22 x size     0
//  23 x size     1
//  24 1
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// SMLAL{2}  <Vd>.<Ta>, <Vn>.<Tb>, <Vm>.<Ts>[<index>]
bool TryDecodeSMLAL_ASIMDELEM_L(const InstData &, Instruction &) {
  return false;
}

// STCLR STCLR_32S_memop:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 0 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 1 size     1
// STCLR  <Ws>, [<Xn|SP>]
bool TryDecodeSTCLR_32S_MEMOP(const InstData &, Instruction &) {
  return false;
}

// STCLRL STCLRL_32S_memop:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 0 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 1 size     1
// STCLRL  <Ws>, [<Xn|SP>]
bool TryDecodeSTCLRL_32S_MEMOP(const InstData &, Instruction &) {
  return false;
}

// STCLR STCLR_64S_memop:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 0 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 1 size     1
// STCLR  <Xs>, [<Xn|SP>]
bool TryDecodeSTCLR_64S_MEMOP(const InstData &, Instruction &) {
  return false;
}

// STCLRL STCLRL_64S_memop:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 0 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 1 size     1
// STCLRL  <Xs>, [<Xn|SP>]
bool TryDecodeSTCLRL_64S_MEMOP(const InstData &, Instruction &) {
  return false;
}

// CMEQ CMEQ_asisdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1 opcode   0
//  12 0 opcode   1
//  13 0 opcode   2
//  14 0 opcode   3
//  15 1 opcode   4
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 1 U        0
//  30 1
//  31 0
// CMEQ  <V><d>, <V><n>, <V><m>
bool TryDecodeCMEQ_ASISDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// CRC32CB CRC32CB_32C_dp_2src:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0 sz       0
//  11 0 sz       1
//  12 1 C        0
//  13 0 opcode2  3
//  14 1 opcode2  4
//  15 0 opcode2  5
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 1
//  23 1
//  24 0
//  25 1
//  26 0
//  27 1
//  28 1
//  29 0 S        0
//  30 0 op       0
//  31 0 sf       0
// CRC32CB  <Wd>, <Wn>, <Wm>
bool TryDecodeCRC32CB_32C_DP_2SRC(const InstData &, Instruction &) {
  return false;
}

// CRC32CH CRC32CH_32C_dp_2src:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 sz       0
//  11 0 sz       1
//  12 1 C        0
//  13 0 opcode2  3
//  14 1 opcode2  4
//  15 0 opcode2  5
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 1
//  23 1
//  24 0
//  25 1
//  26 0
//  27 1
//  28 1
//  29 0 S        0
//  30 0 op       0
//  31 0 sf       0
// CRC32CH  <Wd>, <Wn>, <Wm>
bool TryDecodeCRC32CH_32C_DP_2SRC(const InstData &, Instruction &) {
  return false;
}

// CRC32CW CRC32CW_32C_dp_2src:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0 sz       0
//  11 1 sz       1
//  12 1 C        0
//  13 0 opcode2  3
//  14 1 opcode2  4
//  15 0 opcode2  5
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 1
//  23 1
//  24 0
//  25 1
//  26 0
//  27 1
//  28 1
//  29 0 S        0
//  30 0 op       0
//  31 0 sf       0
// CRC32CW  <Wd>, <Wn>, <Wm>
bool TryDecodeCRC32CW_32C_DP_2SRC(const InstData &, Instruction &) {
  return false;
}

// CRC32CX CRC32CX_64C_dp_2src:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 sz       0
//  11 1 sz       1
//  12 1 C        0
//  13 0 opcode2  3
//  14 1 opcode2  4
//  15 0 opcode2  5
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 1
//  23 1
//  24 0
//  25 1
//  26 0
//  27 1
//  28 1
//  29 0 S        0
//  30 0 op       0
//  31 1 sf       0
// CRC32CX  <Wd>, <Wn>, <Xm>
bool TryDecodeCRC32CX_64C_DP_2SRC(const InstData &, Instruction &) {
  return false;
}

// UADDLP UADDLP_asimdmisc_P:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0
//  13 1
//  14 0 op       0
//  15 0
//  16 0
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// UADDLP  <Vd>.<Ta>, <Vn>.<Tb>
bool TryDecodeUADDLP_ASIMDMISC_P(const InstData &, Instruction &) {
  return false;
}

// LDEORAH LDEORAH_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 1 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 1 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 0 size     1
// LDEORAH  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDEORAH_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDEORALH LDEORALH_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 1 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 1 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 0 size     1
// LDEORALH  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDEORALH_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDEORH LDEORH_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 1 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 0 size     1
// LDEORH  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDEORH_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDEORLH LDEORLH_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 1 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 0 size     1
// LDEORLH  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDEORLH_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// XTN XTN_asimdmisc_N:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 opcode   0
//  13 1 opcode   1
//  14 0 opcode   2
//  15 0 opcode   3
//  16 1 opcode   4
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// XTN{2}  <Vd>.<Tb>, <Vn>.<Ta>
bool TryDecodeXTN_ASIMDMISC_N(const InstData &, Instruction &) {
  return false;
}

// USQADD USQADD_asisdmisc_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 opcode   0
//  13 1 opcode   1
//  14 0 opcode   2
//  15 0 opcode   3
//  16 0 opcode   4
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 1 U        0
//  30 1
//  31 0
// USQADD  <V><d>, <V><n>
bool TryDecodeUSQADD_ASISDMISC_R(const InstData &, Instruction &) {
  return false;
}

// USQADD USQADD_asimdmisc_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 opcode   0
//  13 1 opcode   1
//  14 0 opcode   2
//  15 0 opcode   3
//  16 0 opcode   4
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// USQADD  <Vd>.<T>, <Vn>.<T>
bool TryDecodeUSQADD_ASIMDMISC_R(const InstData &, Instruction &) {
  return false;
}

// FCVTZS FCVTZS_32H_float2fix:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x scale    0
//  11 x scale    1
//  12 x scale    2
//  13 x scale    3
//  14 x scale    4
//  15 x scale    5
//  16 0 opcode   0
//  17 0 opcode   1
//  18 0 opcode   2
//  19 1 rmode    0
//  20 1 rmode    1
//  21 0
//  22 1 type     0
//  23 1 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 sf       0
// FCVTZS  <Wd>, <Hn>, #<fbits>
bool TryDecodeFCVTZS_32H_FLOAT2FIX(const InstData &, Instruction &) {
  return false;
}

// FCVTZS FCVTZS_64H_float2fix:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x scale    0
//  11 x scale    1
//  12 x scale    2
//  13 x scale    3
//  14 x scale    4
//  15 x scale    5
//  16 0 opcode   0
//  17 0 opcode   1
//  18 0 opcode   2
//  19 1 rmode    0
//  20 1 rmode    1
//  21 0
//  22 1 type     0
//  23 1 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 1 sf       0
// FCVTZS  <Xd>, <Hn>, #<fbits>
bool TryDecodeFCVTZS_64H_FLOAT2FIX(const InstData &, Instruction &) {
  return false;
}

// FCVTZS FCVTZS_32S_float2fix:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x scale    0
//  11 x scale    1
//  12 x scale    2
//  13 x scale    3
//  14 x scale    4
//  15 x scale    5
//  16 0 opcode   0
//  17 0 opcode   1
//  18 0 opcode   2
//  19 1 rmode    0
//  20 1 rmode    1
//  21 0
//  22 0 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 sf       0
// FCVTZS  <Wd>, <Sn>, #<fbits>
bool TryDecodeFCVTZS_32S_FLOAT2FIX(const InstData &, Instruction &) {
  return false;
}

// FCVTZS FCVTZS_64S_float2fix:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x scale    0
//  11 x scale    1
//  12 x scale    2
//  13 x scale    3
//  14 x scale    4
//  15 x scale    5
//  16 0 opcode   0
//  17 0 opcode   1
//  18 0 opcode   2
//  19 1 rmode    0
//  20 1 rmode    1
//  21 0
//  22 0 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 1 sf       0
// FCVTZS  <Xd>, <Sn>, #<fbits>
bool TryDecodeFCVTZS_64S_FLOAT2FIX(const InstData &, Instruction &) {
  return false;
}

// FCVTZS FCVTZS_32D_float2fix:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x scale    0
//  11 x scale    1
//  12 x scale    2
//  13 x scale    3
//  14 x scale    4
//  15 x scale    5
//  16 0 opcode   0
//  17 0 opcode   1
//  18 0 opcode   2
//  19 1 rmode    0
//  20 1 rmode    1
//  21 0
//  22 1 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 sf       0
// FCVTZS  <Wd>, <Dn>, #<fbits>
bool TryDecodeFCVTZS_32D_FLOAT2FIX(const InstData &, Instruction &) {
  return false;
}

// FCVTZS FCVTZS_64D_float2fix:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x scale    0
//  11 x scale    1
//  12 x scale    2
//  13 x scale    3
//  14 x scale    4
//  15 x scale    5
//  16 0 opcode   0
//  17 0 opcode   1
//  18 0 opcode   2
//  19 1 rmode    0
//  20 1 rmode    1
//  21 0
//  22 1 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 1 sf       0
// FCVTZS  <Xd>, <Dn>, #<fbits>
bool TryDecodeFCVTZS_64D_FLOAT2FIX(const InstData &, Instruction &) {
  return false;
}

// UQADD UQADD_asisdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1 opcode   0
//  12 0 opcode   1
//  13 0 opcode   2
//  14 0 opcode   3
//  15 0 opcode   4
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 1 U        0
//  30 1
//  31 0
// UQADD  <V><d>, <V><n>, <V><m>
bool TryDecodeUQADD_ASISDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// UQADD UQADD_asimdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1 opcode   0
//  12 0 opcode   1
//  13 0 opcode   2
//  14 0 opcode   3
//  15 0 opcode   4
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// UQADD  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeUQADD_ASIMDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// FNMSUB FNMSUB_H_floatdp3:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x Ra       0
//  11 x Ra       1
//  12 x Ra       2
//  13 x Ra       3
//  14 x Ra       4
//  15 1 o0       0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1 o1       0
//  22 1 type     0
//  23 1 type     1
//  24 1
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 M        0
// FNMSUB  <Hd>, <Hn>, <Hm>, <Ha>
bool TryDecodeFNMSUB_H_FLOATDP3(const InstData &, Instruction &) {
  return false;
}

// FNMSUB FNMSUB_S_floatdp3:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x Ra       0
//  11 x Ra       1
//  12 x Ra       2
//  13 x Ra       3
//  14 x Ra       4
//  15 1 o0       0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1 o1       0
//  22 0 type     0
//  23 0 type     1
//  24 1
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 M        0
// FNMSUB  <Sd>, <Sn>, <Sm>, <Sa>
bool TryDecodeFNMSUB_S_FLOATDP3(const InstData &, Instruction &) {
  return false;
}

// FNMSUB FNMSUB_D_floatdp3:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x Ra       0
//  11 x Ra       1
//  12 x Ra       2
//  13 x Ra       3
//  14 x Ra       4
//  15 1 o0       0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1 o1       0
//  22 1 type     0
//  23 0 type     1
//  24 1
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 M        0
// FNMSUB  <Dd>, <Dn>, <Dm>, <Da>
bool TryDecodeFNMSUB_D_FLOATDP3(const InstData &, Instruction &) {
  return false;
}

// SHA1M SHA1M_QSV_cryptosha3:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opcode   0
//  13 1 opcode   1
//  14 0 opcode   2
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 0 size     0
//  23 0 size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0
//  30 1
//  31 0
// SHA1M  <Qd>, <Sn>, <Vm>.4S
bool TryDecodeSHA1M_QSV_CRYPTOSHA3(const InstData &, Instruction &) {
  return false;
}

// LDAXP LDAXP_LP32_ldstexcl:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x Rt2      0
//  11 x Rt2      1
//  12 x Rt2      2
//  13 x Rt2      3
//  14 x Rt2      4
//  15 1 o0       0
//  16 1 Rs       0
//  17 1 Rs       1
//  18 1 Rs       2
//  19 1 Rs       3
//  20 1 Rs       4
//  21 1 o1       0
//  22 1 L        0
//  23 0 o2       0
//  24 0
//  25 0
//  26 0
//  27 1
//  28 0
//  29 0
//  30 0 sz       0
//  31 1
// LDAXP  <Wt1>, <Wt2>, [<Xn|SP>{,#0}]
bool TryDecodeLDAXP_LP32_LDSTEXCL(const InstData &, Instruction &) {
  return false;
}

// LDAXP LDAXP_LP64_ldstexcl:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x Rt2      0
//  11 x Rt2      1
//  12 x Rt2      2
//  13 x Rt2      3
//  14 x Rt2      4
//  15 1 o0       0
//  16 1 Rs       0
//  17 1 Rs       1
//  18 1 Rs       2
//  19 1 Rs       3
//  20 1 Rs       4
//  21 1 o1       0
//  22 1 L        0
//  23 0 o2       0
//  24 0
//  25 0
//  26 0
//  27 1
//  28 0
//  29 0
//  30 1 sz       0
//  31 1
// LDAXP  <Xt1>, <Xt2>, [<Xn|SP>{,#0}]
bool TryDecodeLDAXP_LP64_LDSTEXCL(const InstData &, Instruction &) {
  return false;
}

// CASPA CASPA_CP32_ldstexcl:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 Rt2      0
//  11 1 Rt2      1
//  12 1 Rt2      2
//  13 1 Rt2      3
//  14 1 Rt2      4
//  15 0 o0       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1 o1       0
//  22 1 L        0
//  23 0 o2       0
//  24 0
//  25 0
//  26 0
//  27 1
//  28 0
//  29 0
//  30 0 sz       0
//  31 0
// CASPA  <Ws>, <W(s+1)>, <Wt>, <W(t+1)>, [<Xn|SP>{,#0}]
bool TryDecodeCASPA_CP32_LDSTEXCL(const InstData &, Instruction &) {
  return false;
}

// CASPAL CASPAL_CP32_ldstexcl:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 Rt2      0
//  11 1 Rt2      1
//  12 1 Rt2      2
//  13 1 Rt2      3
//  14 1 Rt2      4
//  15 1 o0       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1 o1       0
//  22 1 L        0
//  23 0 o2       0
//  24 0
//  25 0
//  26 0
//  27 1
//  28 0
//  29 0
//  30 0 sz       0
//  31 0
// CASPAL  <Ws>, <W(s+1)>, <Wt>, <W(t+1)>, [<Xn|SP>{,#0}]
bool TryDecodeCASPAL_CP32_LDSTEXCL(const InstData &, Instruction &) {
  return false;
}

// CASP CASP_CP32_ldstexcl:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 Rt2      0
//  11 1 Rt2      1
//  12 1 Rt2      2
//  13 1 Rt2      3
//  14 1 Rt2      4
//  15 0 o0       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1 o1       0
//  22 0 L        0
//  23 0 o2       0
//  24 0
//  25 0
//  26 0
//  27 1
//  28 0
//  29 0
//  30 0 sz       0
//  31 0
// CASP  <Ws>, <W(s+1)>, <Wt>, <W(t+1)>, [<Xn|SP>{,#0}]
bool TryDecodeCASP_CP32_LDSTEXCL(const InstData &, Instruction &) {
  return false;
}

// CASPL CASPL_CP32_ldstexcl:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 Rt2      0
//  11 1 Rt2      1
//  12 1 Rt2      2
//  13 1 Rt2      3
//  14 1 Rt2      4
//  15 1 o0       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1 o1       0
//  22 0 L        0
//  23 0 o2       0
//  24 0
//  25 0
//  26 0
//  27 1
//  28 0
//  29 0
//  30 0 sz       0
//  31 0
// CASPL  <Ws>, <W(s+1)>, <Wt>, <W(t+1)>, [<Xn|SP>{,#0}]
bool TryDecodeCASPL_CP32_LDSTEXCL(const InstData &, Instruction &) {
  return false;
}

// CASPA CASPA_CP64_ldstexcl:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 Rt2      0
//  11 1 Rt2      1
//  12 1 Rt2      2
//  13 1 Rt2      3
//  14 1 Rt2      4
//  15 0 o0       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1 o1       0
//  22 1 L        0
//  23 0 o2       0
//  24 0
//  25 0
//  26 0
//  27 1
//  28 0
//  29 0
//  30 1 sz       0
//  31 0
// CASPA  <Xs>, <X(s+1)>, <Xt>, <X(t+1)>, [<Xn|SP>{,#0}]
bool TryDecodeCASPA_CP64_LDSTEXCL(const InstData &, Instruction &) {
  return false;
}

// CASPAL CASPAL_CP64_ldstexcl:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 Rt2      0
//  11 1 Rt2      1
//  12 1 Rt2      2
//  13 1 Rt2      3
//  14 1 Rt2      4
//  15 1 o0       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1 o1       0
//  22 1 L        0
//  23 0 o2       0
//  24 0
//  25 0
//  26 0
//  27 1
//  28 0
//  29 0
//  30 1 sz       0
//  31 0
// CASPAL  <Xs>, <X(s+1)>, <Xt>, <X(t+1)>, [<Xn|SP>{,#0}]
bool TryDecodeCASPAL_CP64_LDSTEXCL(const InstData &, Instruction &) {
  return false;
}

// CASP CASP_CP64_ldstexcl:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 Rt2      0
//  11 1 Rt2      1
//  12 1 Rt2      2
//  13 1 Rt2      3
//  14 1 Rt2      4
//  15 0 o0       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1 o1       0
//  22 0 L        0
//  23 0 o2       0
//  24 0
//  25 0
//  26 0
//  27 1
//  28 0
//  29 0
//  30 1 sz       0
//  31 0
// CASP  <Xs>, <X(s+1)>, <Xt>, <X(t+1)>, [<Xn|SP>{,#0}]
bool TryDecodeCASP_CP64_LDSTEXCL(const InstData &, Instruction &) {
  return false;
}

// CASPL CASPL_CP64_ldstexcl:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 Rt2      0
//  11 1 Rt2      1
//  12 1 Rt2      2
//  13 1 Rt2      3
//  14 1 Rt2      4
//  15 1 o0       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1 o1       0
//  22 0 L        0
//  23 0 o2       0
//  24 0
//  25 0
//  26 0
//  27 1
//  28 0
//  29 0
//  30 1 sz       0
//  31 0
// CASPL  <Xs>, <X(s+1)>, <Xt>, <X(t+1)>, [<Xn|SP>{,#0}]
bool TryDecodeCASPL_CP64_LDSTEXCL(const InstData &, Instruction &) {
  return false;
}

// FCVTZU FCVTZU_32H_float2fix:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x scale    0
//  11 x scale    1
//  12 x scale    2
//  13 x scale    3
//  14 x scale    4
//  15 x scale    5
//  16 1 opcode   0
//  17 0 opcode   1
//  18 0 opcode   2
//  19 1 rmode    0
//  20 1 rmode    1
//  21 0
//  22 1 type     0
//  23 1 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 sf       0
// FCVTZU  <Wd>, <Hn>, #<fbits>
bool TryDecodeFCVTZU_32H_FLOAT2FIX(const InstData &, Instruction &) {
  return false;
}

// FCVTZU FCVTZU_64H_float2fix:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x scale    0
//  11 x scale    1
//  12 x scale    2
//  13 x scale    3
//  14 x scale    4
//  15 x scale    5
//  16 1 opcode   0
//  17 0 opcode   1
//  18 0 opcode   2
//  19 1 rmode    0
//  20 1 rmode    1
//  21 0
//  22 1 type     0
//  23 1 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 1 sf       0
// FCVTZU  <Xd>, <Hn>, #<fbits>
bool TryDecodeFCVTZU_64H_FLOAT2FIX(const InstData &, Instruction &) {
  return false;
}

// FCVTZU FCVTZU_32S_float2fix:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x scale    0
//  11 x scale    1
//  12 x scale    2
//  13 x scale    3
//  14 x scale    4
//  15 x scale    5
//  16 1 opcode   0
//  17 0 opcode   1
//  18 0 opcode   2
//  19 1 rmode    0
//  20 1 rmode    1
//  21 0
//  22 0 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 sf       0
// FCVTZU  <Wd>, <Sn>, #<fbits>
bool TryDecodeFCVTZU_32S_FLOAT2FIX(const InstData &, Instruction &) {
  return false;
}

// FCVTZU FCVTZU_64S_float2fix:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x scale    0
//  11 x scale    1
//  12 x scale    2
//  13 x scale    3
//  14 x scale    4
//  15 x scale    5
//  16 1 opcode   0
//  17 0 opcode   1
//  18 0 opcode   2
//  19 1 rmode    0
//  20 1 rmode    1
//  21 0
//  22 0 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 1 sf       0
// FCVTZU  <Xd>, <Sn>, #<fbits>
bool TryDecodeFCVTZU_64S_FLOAT2FIX(const InstData &, Instruction &) {
  return false;
}

// FCVTZU FCVTZU_32D_float2fix:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x scale    0
//  11 x scale    1
//  12 x scale    2
//  13 x scale    3
//  14 x scale    4
//  15 x scale    5
//  16 1 opcode   0
//  17 0 opcode   1
//  18 0 opcode   2
//  19 1 rmode    0
//  20 1 rmode    1
//  21 0
//  22 1 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 sf       0
// FCVTZU  <Wd>, <Dn>, #<fbits>
bool TryDecodeFCVTZU_32D_FLOAT2FIX(const InstData &, Instruction &) {
  return false;
}

// FCVTZU FCVTZU_64D_float2fix:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x scale    0
//  11 x scale    1
//  12 x scale    2
//  13 x scale    3
//  14 x scale    4
//  15 x scale    5
//  16 1 opcode   0
//  17 0 opcode   1
//  18 0 opcode   2
//  19 1 rmode    0
//  20 1 rmode    1
//  21 0
//  22 1 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 1 sf       0
// FCVTZU  <Xd>, <Dn>, #<fbits>
bool TryDecodeFCVTZU_64D_FLOAT2FIX(const InstData &, Instruction &) {
  return false;
}

// SHA1P SHA1P_QSV_cryptosha3:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opcode   0
//  13 0 opcode   1
//  14 0 opcode   2
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 0 size     0
//  23 0 size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0
//  30 1
//  31 0
// SHA1P  <Qd>, <Sn>, <Vm>.4S
bool TryDecodeSHA1P_QSV_CRYPTOSHA3(const InstData &, Instruction &) {
  return false;
}

// TBL TBL_asimdtbl_L2_2:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 op       0
//  13 1 len      0
//  14 0 len      1
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 0 op2      0
//  23 0 op2      1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// TBL  <Vd>.<Ta>, { <Vn>.16B, <Vn+1>.16B }, <Vm>.<Ta>
bool TryDecodeTBL_ASIMDTBL_L2_2(const InstData &, Instruction &) {
  return false;
}

// TBL TBL_asimdtbl_L3_3:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 op       0
//  13 0 len      0
//  14 1 len      1
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 0 op2      0
//  23 0 op2      1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// TBL  <Vd>.<Ta>, { <Vn>.16B, <Vn+1>.16B, <Vn+2>.16B }, <Vm>.<Ta>
bool TryDecodeTBL_ASIMDTBL_L3_3(const InstData &, Instruction &) {
  return false;
}

// TBL TBL_asimdtbl_L4_4:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 op       0
//  13 1 len      0
//  14 1 len      1
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 0 op2      0
//  23 0 op2      1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// TBL  <Vd>.<Ta>, { <Vn>.16B, <Vn+1>.16B, <Vn+2>.16B, <Vn+3>.16B }, <Vm>.<Ta>
bool TryDecodeTBL_ASIMDTBL_L4_4(const InstData &, Instruction &) {
  return false;
}

// TBL TBL_asimdtbl_L1_1:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 op       0
//  13 0 len      0
//  14 0 len      1
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 0 op2      0
//  23 0 op2      1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// TBL  <Vd>.<Ta>, { <Vn>.16B }, <Vm>.<Ta>
bool TryDecodeTBL_ASIMDTBL_L1_1(const InstData &, Instruction &) {
  return false;
}

// FMAXNMP FMAXNMP_asisdpair_only_H:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 opcode   0
//  13 0 opcode   1
//  14 1 opcode   2
//  15 1 opcode   3
//  16 0 opcode   4
//  17 0
//  18 0
//  19 0
//  20 1
//  21 1
//  22 0 sz       0
//  23 0 o1       0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// FMAXNMP  <V><d>, <Vn>.<T>
bool TryDecodeFMAXNMP_ASISDPAIR_ONLY_H(const InstData &, Instruction &) {
  return false;
}

// FMAXNMP FMAXNMP_asisdpair_only_SD:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 opcode   0
//  13 0 opcode   1
//  14 1 opcode   2
//  15 1 opcode   3
//  16 0 opcode   4
//  17 0
//  18 0
//  19 0
//  20 1
//  21 1
//  22 x sz       0
//  23 0 o1       0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 1 U        0
//  30 1
//  31 0
// FMAXNMP  <V><d>, <Vn>.<T>
bool TryDecodeFMAXNMP_ASISDPAIR_ONLY_SD(const InstData &, Instruction &) {
  return false;
}

// FNMUL FNMUL_H_floatdp2:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0
//  13 0
//  14 0
//  15 1 op       0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 1 type     0
//  23 1 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 M        0
// FNMUL  <Hd>, <Hn>, <Hm>
bool TryDecodeFNMUL_H_FLOATDP2(const InstData &, Instruction &) {
  return false;
}

// FNMUL FNMUL_S_floatdp2:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0
//  13 0
//  14 0
//  15 1 op       0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 0 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 M        0
// FNMUL  <Sd>, <Sn>, <Sm>
bool TryDecodeFNMUL_S_FLOATDP2(const InstData &, Instruction &) {
  return false;
}

// FNMUL FNMUL_D_floatdp2:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0
//  13 0
//  14 0
//  15 1 op       0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 1 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 M        0
// FNMUL  <Dd>, <Dn>, <Dm>
bool TryDecodeFNMUL_D_FLOATDP2(const InstData &, Instruction &) {
  return false;
}

// SQSUB SQSUB_asisdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1 opcode   0
//  12 0 opcode   1
//  13 1 opcode   2
//  14 0 opcode   3
//  15 0 opcode   4
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// SQSUB  <V><d>, <V><n>, <V><m>
bool TryDecodeSQSUB_ASISDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// SQSUB SQSUB_asimdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1 opcode   0
//  12 0 opcode   1
//  13 1 opcode   2
//  14 0 opcode   3
//  15 0 opcode   4
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// SQSUB  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeSQSUB_ASIMDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// SQXTN SQXTN_asisdmisc_N:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 opcode   0
//  13 0 opcode   1
//  14 1 opcode   2
//  15 0 opcode   3
//  16 1 opcode   4
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// SQXTN  <Vb><d>, <Va><n>
bool TryDecodeSQXTN_ASISDMISC_N(const InstData &, Instruction &) {
  return false;
}

// SQXTN SQXTN_asimdmisc_N:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 opcode   0
//  13 0 opcode   1
//  14 1 opcode   2
//  15 0 opcode   3
//  16 1 opcode   4
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// SQXTN{2}  <Vd>.<Tb>, <Vn>.<Ta>
bool TryDecodeSQXTN_ASIMDMISC_N(const InstData &, Instruction &) {
  return false;
}

// ORR MOV_ORR_asimdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1 opcode   0
//  12 1 opcode   1
//  13 0 opcode   2
//  14 0 opcode   3
//  15 0 opcode   4
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 0 size     0
//  23 1 size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// MOV  <Vd>.<T>, <Vn>.<T>
bool TryDecodeMOV_ORR_ASIMDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// REV REV64_REV_64_dp_1src:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 opc      0
//  11 1 opc      1
//  12 0 opcode   2
//  13 0 opcode   3
//  14 0 opcode   4
//  15 0 opcode   5
//  16 0 opcode2  0
//  17 0 opcode2  1
//  18 0 opcode2  2
//  19 0 opcode2  3
//  20 0 opcode2  4
//  21 0
//  22 1
//  23 1
//  24 0
//  25 1
//  26 0
//  27 1
//  28 1
//  29 0 S        0
//  30 1
//  31 1 sf       0
// REV64  <Xd>, <Xn>
bool TryDecodeREV64_REV_64_DP_1SRC(const InstData &, Instruction &) {
  return false;
}

// STLXRB STLXRB_SR32_ldstexcl:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 Rt2      0
//  11 1 Rt2      1
//  12 1 Rt2      2
//  13 1 Rt2      3
//  14 1 Rt2      4
//  15 1 o0       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 0 o1       0
//  22 0 L        0
//  23 0 o2       0
//  24 0
//  25 0
//  26 0
//  27 1
//  28 0
//  29 0
//  30 0 size     0
//  31 0 size     1
// STLXRB  <Ws>, <Wt>, [<Xn|SP>{,#0}]
bool TryDecodeSTLXRB_SR32_LDSTEXCL(const InstData &, Instruction &) {
  return false;
}

// STTRH STTRH_32_ldst_unpriv:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 x imm9     0
//  13 x imm9     1
//  14 x imm9     2
//  15 x imm9     3
//  16 x imm9     4
//  17 x imm9     5
//  18 x imm9     6
//  19 x imm9     7
//  20 x imm9     8
//  21 0
//  22 0 opc      0
//  23 0 opc      1
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 0 size     1
// STTRH  <Wt>, [<Xn|SP>{, #<simm>}]
bool TryDecodeSTTRH_32_LDST_UNPRIV(const InstData &, Instruction &) {
  return false;
}

// SHA256SU1 SHA256SU1_VVV_cryptosha3:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opcode   0
//  13 1 opcode   1
//  14 1 opcode   2
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 0 size     0
//  23 0 size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0
//  30 1
//  31 0
// SHA256SU1  <Vd>.4S, <Vn>.4S, <Vm>.4S
bool TryDecodeSHA256SU1_VVV_CRYPTOSHA3(const InstData &, Instruction &) {
  return false;
}

// FMSUB FMSUB_H_floatdp3:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x Ra       0
//  11 x Ra       1
//  12 x Ra       2
//  13 x Ra       3
//  14 x Ra       4
//  15 1 o0       0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0 o1       0
//  22 1 type     0
//  23 1 type     1
//  24 1
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 M        0
// FMSUB  <Hd>, <Hn>, <Hm>, <Ha>
bool TryDecodeFMSUB_H_FLOATDP3(const InstData &, Instruction &) {
  return false;
}

// FMSUB FMSUB_S_floatdp3:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x Ra       0
//  11 x Ra       1
//  12 x Ra       2
//  13 x Ra       3
//  14 x Ra       4
//  15 1 o0       0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0 o1       0
//  22 0 type     0
//  23 0 type     1
//  24 1
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 M        0
// FMSUB  <Sd>, <Sn>, <Sm>, <Sa>
bool TryDecodeFMSUB_S_FLOATDP3(const InstData &, Instruction &) {
  return false;
}

// FMSUB FMSUB_D_floatdp3:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x Ra       0
//  11 x Ra       1
//  12 x Ra       2
//  13 x Ra       3
//  14 x Ra       4
//  15 1 o0       0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0 o1       0
//  22 1 type     0
//  23 0 type     1
//  24 1
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 M        0
// FMSUB  <Dd>, <Dn>, <Dm>, <Da>
bool TryDecodeFMSUB_D_FLOATDP3(const InstData &, Instruction &) {
  return false;
}

// SBCS NGCS_SBCS_32_addsub_carry:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 1 Rn       0
//   6 1 Rn       1
//   7 1 Rn       2
//   8 1 Rn       3
//   9 1 Rn       4
//  10 0 opcode2  0
//  11 0 opcode2  1
//  12 0 opcode2  2
//  13 0 opcode2  3
//  14 0 opcode2  4
//  15 0 opcode2  5
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 0
//  23 0
//  24 0
//  25 1
//  26 0
//  27 1
//  28 1
//  29 1 S        0
//  30 1 op       0
//  31 0 sf       0
// NGCS  <Wd>, <Wm>
bool TryDecodeNGCS_SBCS_32_ADDSUB_CARRY(const InstData &, Instruction &) {
  return false;
}

// SBCS NGCS_SBCS_64_addsub_carry:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 1 Rn       0
//   6 1 Rn       1
//   7 1 Rn       2
//   8 1 Rn       3
//   9 1 Rn       4
//  10 0 opcode2  0
//  11 0 opcode2  1
//  12 0 opcode2  2
//  13 0 opcode2  3
//  14 0 opcode2  4
//  15 0 opcode2  5
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 0
//  23 0
//  24 0
//  25 1
//  26 0
//  27 1
//  28 1
//  29 1 S        0
//  30 1 op       0
//  31 1 sf       0
// NGCS  <Xd>, <Xm>
bool TryDecodeNGCS_SBCS_64_ADDSUB_CARRY(const InstData &, Instruction &) {
  return false;
}

// INS INS_asimdins_IV_v:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 x imm4     0
//  12 x imm4     1
//  13 x imm4     2
//  14 x imm4     3
//  15 0
//  16 x imm5     0
//  17 x imm5     1
//  18 x imm5     2
//  19 x imm5     3
//  20 x imm5     4
//  21 0
//  22 0
//  23 0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 op       0
//  30 1 Q        0
//  31 0
// INS  <Vd>.<Ts>[<index1>], <Vn>.<Ts>[<index2>]
bool TryDecodeINS_ASIMDINS_IV_V(const InstData &, Instruction &) {
  return false;
}

// DCPS2 DCPS2_DC_exception:
//   0 0 LL       0
//   1 1 LL       1
//   2 0 op2      0
//   3 0 op2      1
//   4 0 op2      2
//   5 x imm16    0
//   6 x imm16    1
//   7 x imm16    2
//   8 x imm16    3
//   9 x imm16    4
//  10 x imm16    5
//  11 x imm16    6
//  12 x imm16    7
//  13 x imm16    8
//  14 x imm16    9
//  15 x imm16    10
//  16 x imm16    11
//  17 x imm16    12
//  18 x imm16    13
//  19 x imm16    14
//  20 x imm16    15
//  21 1 opc      0
//  22 0 opc      1
//  23 1 opc      2
//  24 0
//  25 0
//  26 1
//  27 0
//  28 1
//  29 0
//  30 1
//  31 1
// DCPS2  {#<imm>}
bool TryDecodeDCPS2_DC_EXCEPTION(const InstData &, Instruction &) {
  return false;
}

// ANDS TST_ANDS_32_log_shift:
//   0 1 Rd       0
//   1 1 Rd       1
//   2 1 Rd       2
//   3 1 Rd       3
//   4 1 Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x imm6     0
//  11 x imm6     1
//  12 x imm6     2
//  13 x imm6     3
//  14 x imm6     4
//  15 x imm6     5
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0 N        0
//  22 x shift    0
//  23 x shift    1
//  24 0
//  25 1
//  26 0
//  27 1
//  28 0
//  29 1 opc      0
//  30 1 opc      1
//  31 0 sf       0
// TST  <Wn>, <Wm>{, <shift> #<amount>}
bool TryDecodeTST_ANDS_32_LOG_SHIFT(const InstData &, Instruction &) {
  return false;
}

// ANDS TST_ANDS_64_log_shift:
//   0 1 Rd       0
//   1 1 Rd       1
//   2 1 Rd       2
//   3 1 Rd       3
//   4 1 Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x imm6     0
//  11 x imm6     1
//  12 x imm6     2
//  13 x imm6     3
//  14 x imm6     4
//  15 x imm6     5
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0 N        0
//  22 x shift    0
//  23 x shift    1
//  24 0
//  25 1
//  26 0
//  27 1
//  28 0
//  29 1 opc      0
//  30 1 opc      1
//  31 1 sf       0
// TST  <Xn>, <Xm>{, <shift> #<amount>}
bool TryDecodeTST_ANDS_64_LOG_SHIFT(const InstData &, Instruction &) {
  return false;
}

// DCPS1 DCPS1_DC_exception:
//   0 1 LL       0
//   1 0 LL       1
//   2 0 op2      0
//   3 0 op2      1
//   4 0 op2      2
//   5 x imm16    0
//   6 x imm16    1
//   7 x imm16    2
//   8 x imm16    3
//   9 x imm16    4
//  10 x imm16    5
//  11 x imm16    6
//  12 x imm16    7
//  13 x imm16    8
//  14 x imm16    9
//  15 x imm16    10
//  16 x imm16    11
//  17 x imm16    12
//  18 x imm16    13
//  19 x imm16    14
//  20 x imm16    15
//  21 1 opc      0
//  22 0 opc      1
//  23 1 opc      2
//  24 0
//  25 0
//  26 1
//  27 0
//  28 1
//  29 0
//  30 1
//  31 1
// DCPS1  {#<imm>}
bool TryDecodeDCPS1_DC_EXCEPTION(const InstData &, Instruction &) {
  return false;
}

// FMLA FMLA_asisdelem_RH_H:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 x H        0
//  12 1
//  13 0
//  14 0 o2       0
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x M        0
//  21 x L        0
//  22 0 size     0
//  23 0 size     1
//  24 1
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// FMLA  <Hd>, <Hn>, <Vm>.H[<index>]
bool TryDecodeFMLA_ASISDELEM_RH_H(const InstData &, Instruction &) {
  return false;
}

// FMLA FMLA_asisdelem_R_SD:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 x H        0
//  12 1
//  13 0
//  14 0 o2       0
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x M        0
//  21 x L        0
//  22 x sz       0
//  23 1
//  24 1
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// FMLA  <V><d>, <V><n>, <Vm>.<Ts>[<index>]
bool TryDecodeFMLA_ASISDELEM_R_SD(const InstData &, Instruction &) {
  return false;
}

// FMLA FMLA_asimdelem_RH_H:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 x H        0
//  12 1
//  13 0
//  14 0 o2       0
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x M        0
//  21 x L        0
//  22 0 size     0
//  23 0 size     1
//  24 1
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// FMLA  <Vd>.<T>, <Vn>.<T>, <Vm>.H[<index>]
bool TryDecodeFMLA_ASIMDELEM_RH_H(const InstData &, Instruction &) {
  return false;
}

// FMLA FMLA_asimdelem_R_SD:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 x H        0
//  12 1
//  13 0
//  14 0 o2       0
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x M        0
//  21 x L        0
//  22 x sz       0
//  23 1
//  24 1
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// FMLA  <Vd>.<T>, <Vn>.<T>, <Vm>.<Ts>[<index>]
bool TryDecodeFMLA_ASIMDELEM_R_SD(const InstData &, Instruction &) {
  return false;
}

// SCVTF SCVTF_asisdmiscfp16_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 opcode   0
//  13 0 opcode   1
//  14 1 opcode   2
//  15 1 opcode   3
//  16 1 opcode   4
//  17 0
//  18 0
//  19 1
//  20 1
//  21 1
//  22 1
//  23 0 a        0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// SCVTF  <Hd>, <Hn>
bool TryDecodeSCVTF_ASISDMISCFP16_R(const InstData &, Instruction &) {
  return false;
}

// SCVTF SCVTF_asisdmisc_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 opcode   0
//  13 0 opcode   1
//  14 1 opcode   2
//  15 1 opcode   3
//  16 1 opcode   4
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x sz       0
//  23 0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// SCVTF  <V><d>, <V><n>
bool TryDecodeSCVTF_ASISDMISC_R(const InstData &, Instruction &) {
  return false;
}

// SCVTF SCVTF_asimdmiscfp16_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 opcode   0
//  13 0 opcode   1
//  14 1 opcode   2
//  15 1 opcode   3
//  16 1 opcode   4
//  17 0
//  18 0
//  19 1
//  20 1
//  21 1
//  22 1
//  23 0 a        0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// SCVTF  <Vd>.<T>, <Vn>.<T>
bool TryDecodeSCVTF_ASIMDMISCFP16_R(const InstData &, Instruction &) {
  return false;
}

// SCVTF SCVTF_asimdmisc_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 opcode   0
//  13 0 opcode   1
//  14 1 opcode   2
//  15 1 opcode   3
//  16 1 opcode   4
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x sz       0
//  23 0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// SCVTF  <Vd>.<T>, <Vn>.<T>
bool TryDecodeSCVTF_ASIMDMISC_R(const InstData &, Instruction &) {
  return false;
}

// UMULL UMULL_asimddiff_L:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opcode   0
//  13 0 opcode   1
//  14 1 opcode   2
//  15 1 opcode   3
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// UMULL{2}  <Vd>.<Ta>, <Vn>.<Tb>, <Vm>.<Tb>
bool TryDecodeUMULL_ASIMDDIFF_L(const InstData &, Instruction &) {
  return false;
}

// FMUL FMUL_asimdsamefp16_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1 opcode   0
//  12 1 opcode   1
//  13 0 opcode   2
//  14 0
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 1
//  23 0 a        0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// FMUL  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeFMUL_ASIMDSAMEFP16_ONLY(const InstData &, Instruction &) {
  return false;
}

// FMUL FMUL_asimdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1 opcode   0
//  12 1 opcode   1
//  13 0 opcode   2
//  14 1 opcode   3
//  15 1 opcode   4
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x sz       0
//  23 0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// FMUL  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeFMUL_ASIMDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// FMLA FMLA_asimdsamefp16_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1 opcode   0
//  12 0 opcode   1
//  13 0 opcode   2
//  14 0
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 1
//  23 0 a        0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// FMLA  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeFMLA_ASIMDSAMEFP16_ONLY(const InstData &, Instruction &) {
  return false;
}

// FMLA FMLA_asimdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1 opcode   0
//  12 0 opcode   1
//  13 0 opcode   2
//  14 1 opcode   3
//  15 1 opcode   4
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x sz       0
//  23 0 op       0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// FMLA  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeFMLA_ASIMDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// SMSUBL SMNEGL_SMSUBL_64WA_dp_3src:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 Ra       0
//  11 1 Ra       1
//  12 1 Ra       2
//  13 1 Ra       3
//  14 1 Ra       4
//  15 1 o0       0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 0
//  23 0 U        0
//  24 1
//  25 1
//  26 0
//  27 1
//  28 1
//  29 0 op54     0
//  30 0 op54     1
//  31 1 sf       0
// SMNEGL  <Xd>, <Wn>, <Wm>
bool TryDecodeSMNEGL_SMSUBL_64WA_DP_3SRC(const InstData &, Instruction &) {
  return false;
}

// DUP MOV_DUP_asisdone_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 imm4     0
//  12 0 imm4     1
//  13 0 imm4     2
//  14 0 imm4     3
//  15 0
//  16 x imm5     0
//  17 x imm5     1
//  18 x imm5     2
//  19 x imm5     3
//  20 x imm5     4
//  21 0
//  22 0
//  23 0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 op       0
//  30 1
//  31 0
// MOV  <V><d>, <Vn>.<T>[<index>]
bool TryDecodeMOV_DUP_ASISDONE_ONLY(const InstData &, Instruction &) {
  return false;
}

// SMADDL SMULL_SMADDL_64WA_dp_3src:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 Ra       0
//  11 1 Ra       1
//  12 1 Ra       2
//  13 1 Ra       3
//  14 1 Ra       4
//  15 0 o0       0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 0
//  23 0 U        0
//  24 1
//  25 1
//  26 0
//  27 1
//  28 1
//  29 0 op54     0
//  30 0 op54     1
//  31 1 sf       0
// SMULL  <Xd>, <Wn>, <Wm>
bool TryDecodeSMULL_SMADDL_64WA_DP_3SRC(const InstData &, Instruction &) {
  return false;
}

// ZIP2 ZIP2_asimdperm_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1
//  13 1
//  14 1 op       0
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// ZIP2  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeZIP2_ASIMDPERM_ONLY(const InstData &, Instruction &) {
  return false;
}

// LDAXRB LDAXRB_LR32_ldstexcl:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 Rt2      0
//  11 1 Rt2      1
//  12 1 Rt2      2
//  13 1 Rt2      3
//  14 1 Rt2      4
//  15 1 o0       0
//  16 1 Rs       0
//  17 1 Rs       1
//  18 1 Rs       2
//  19 1 Rs       3
//  20 1 Rs       4
//  21 0 o1       0
//  22 1 L        0
//  23 0 o2       0
//  24 0
//  25 0
//  26 0
//  27 1
//  28 0
//  29 0
//  30 0 size     0
//  31 0 size     1
// LDAXRB  <Wt>, [<Xn|SP>{,#0}]
bool TryDecodeLDAXRB_LR32_LDSTEXCL(const InstData &, Instruction &) {
  return false;
}

// MSUB MNEG_MSUB_32A_dp_3src:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 Ra       0
//  11 1 Ra       1
//  12 1 Ra       2
//  13 1 Ra       3
//  14 1 Ra       4
//  15 1 o0       0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0 op31     0
//  22 0 op31     1
//  23 0 op31     2
//  24 1
//  25 1
//  26 0
//  27 1
//  28 1
//  29 0 op54     0
//  30 0 op54     1
//  31 0 sf       0
// MNEG  <Wd>, <Wn>, <Wm>
bool TryDecodeMNEG_MSUB_32A_DP_3SRC(const InstData &, Instruction &) {
  return false;
}

// MSUB MNEG_MSUB_64A_dp_3src:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 Ra       0
//  11 1 Ra       1
//  12 1 Ra       2
//  13 1 Ra       3
//  14 1 Ra       4
//  15 1 o0       0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0 op31     0
//  22 0 op31     1
//  23 0 op31     2
//  24 1
//  25 1
//  26 0
//  27 1
//  28 1
//  29 0 op54     0
//  30 0 op54     1
//  31 1 sf       0
// MNEG  <Xd>, <Xn>, <Xm>
bool TryDecodeMNEG_MSUB_64A_DP_3SRC(const InstData &, Instruction &) {
  return false;
}

// HVC HVC_EX_exception:
//   0 0 LL       0
//   1 1 LL       1
//   2 0 op2      0
//   3 0 op2      1
//   4 0 op2      2
//   5 x imm16    0
//   6 x imm16    1
//   7 x imm16    2
//   8 x imm16    3
//   9 x imm16    4
//  10 x imm16    5
//  11 x imm16    6
//  12 x imm16    7
//  13 x imm16    8
//  14 x imm16    9
//  15 x imm16    10
//  16 x imm16    11
//  17 x imm16    12
//  18 x imm16    13
//  19 x imm16    14
//  20 x imm16    15
//  21 0 opc      0
//  22 0 opc      1
//  23 0 opc      2
//  24 0
//  25 0
//  26 1
//  27 0
//  28 1
//  29 0
//  30 1
//  31 1
// HVC  #<imm>
bool TryDecodeHVC_EX_EXCEPTION(const InstData &, Instruction &) {
  return false;
}

// DCPS3 DCPS3_DC_exception:
//   0 1 LL       0
//   1 1 LL       1
//   2 0 op2      0
//   3 0 op2      1
//   4 0 op2      2
//   5 x imm16    0
//   6 x imm16    1
//   7 x imm16    2
//   8 x imm16    3
//   9 x imm16    4
//  10 x imm16    5
//  11 x imm16    6
//  12 x imm16    7
//  13 x imm16    8
//  14 x imm16    9
//  15 x imm16    10
//  16 x imm16    11
//  17 x imm16    12
//  18 x imm16    13
//  19 x imm16    14
//  20 x imm16    15
//  21 1 opc      0
//  22 0 opc      1
//  23 1 opc      2
//  24 0
//  25 0
//  26 1
//  27 0
//  28 1
//  29 0
//  30 1
//  31 1
// DCPS3  {#<imm>}
bool TryDecodeDCPS3_DC_EXCEPTION(const InstData &, Instruction &) {
  return false;
}

// FCVTNU FCVTNU_asisdmiscfp16_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 o1       0
//  13 1
//  14 0
//  15 1
//  16 1
//  17 0
//  18 0
//  19 1
//  20 1
//  21 1
//  22 1
//  23 0 o2       0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 1 U        0
//  30 1
//  31 0
// FCVTNU  <Hd>, <Hn>
bool TryDecodeFCVTNU_ASISDMISCFP16_R(const InstData &, Instruction &) {
  return false;
}

// FCVTNU FCVTNU_asisdmisc_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 o1       0
//  13 1
//  14 0
//  15 1
//  16 1
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x sz       0
//  23 0 o2       0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 1 U        0
//  30 1
//  31 0
// FCVTNU  <V><d>, <V><n>
bool TryDecodeFCVTNU_ASISDMISC_R(const InstData &, Instruction &) {
  return false;
}

// FCVTNU FCVTNU_asimdmiscfp16_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 o1       0
//  13 1
//  14 0
//  15 1
//  16 1
//  17 0
//  18 0
//  19 1
//  20 1
//  21 1
//  22 1
//  23 0 o2       0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// FCVTNU  <Vd>.<T>, <Vn>.<T>
bool TryDecodeFCVTNU_ASIMDMISCFP16_R(const InstData &, Instruction &) {
  return false;
}

// FCVTNU FCVTNU_asimdmisc_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 o1       0
//  13 1
//  14 0
//  15 1
//  16 1
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x sz       0
//  23 0 o2       0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// FCVTNU  <Vd>.<T>, <Vn>.<T>
bool TryDecodeFCVTNU_ASIMDMISC_R(const InstData &, Instruction &) {
  return false;
}

// STUMINB STUMINB_32S_memop:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 1 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 0 size     1
// STUMINB  <Ws>, [<Xn|SP>]
bool TryDecodeSTUMINB_32S_MEMOP(const InstData &, Instruction &) {
  return false;
}

// STUMINLB STUMINLB_32S_memop:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 1 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 0 size     1
// STUMINLB  <Ws>, [<Xn|SP>]
bool TryDecodeSTUMINLB_32S_MEMOP(const InstData &, Instruction &) {
  return false;
}

// STCLRH STCLRH_32S_memop:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 0 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 0 size     1
// STCLRH  <Ws>, [<Xn|SP>]
bool TryDecodeSTCLRH_32S_MEMOP(const InstData &, Instruction &) {
  return false;
}

// STCLRLH STCLRLH_32S_memop:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 0 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 0 size     1
// STCLRLH  <Ws>, [<Xn|SP>]
bool TryDecodeSTCLRLH_32S_MEMOP(const InstData &, Instruction &) {
  return false;
}

// FCVTMU FCVTMU_asisdmiscfp16_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 o1       0
//  13 1
//  14 0
//  15 1
//  16 1
//  17 0
//  18 0
//  19 1
//  20 1
//  21 1
//  22 1
//  23 0 o2       0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 1 U        0
//  30 1
//  31 0
// FCVTMU  <Hd>, <Hn>
bool TryDecodeFCVTMU_ASISDMISCFP16_R(const InstData &, Instruction &) {
  return false;
}

// FCVTMU FCVTMU_asisdmisc_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 o1       0
//  13 1
//  14 0
//  15 1
//  16 1
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x sz       0
//  23 0 o2       0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 1 U        0
//  30 1
//  31 0
// FCVTMU  <V><d>, <V><n>
bool TryDecodeFCVTMU_ASISDMISC_R(const InstData &, Instruction &) {
  return false;
}

// FCVTMU FCVTMU_asimdmiscfp16_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 o1       0
//  13 1
//  14 0
//  15 1
//  16 1
//  17 0
//  18 0
//  19 1
//  20 1
//  21 1
//  22 1
//  23 0 o2       0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// FCVTMU  <Vd>.<T>, <Vn>.<T>
bool TryDecodeFCVTMU_ASIMDMISCFP16_R(const InstData &, Instruction &) {
  return false;
}

// FCVTMU FCVTMU_asimdmisc_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 o1       0
//  13 1
//  14 0
//  15 1
//  16 1
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x sz       0
//  23 0 o2       0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// FCVTMU  <Vd>.<T>, <Vn>.<T>
bool TryDecodeFCVTMU_ASIMDMISC_R(const InstData &, Instruction &) {
  return false;
}

// FMAXNMP FMAXNMP_asimdsamefp16_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 Op3      0
//  12 0 Op3      1
//  13 0 Op3      2
//  14 0
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 1
//  23 0 a        0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// FMAXNMP  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeFMAXNMP_ASIMDSAMEFP16_ONLY(const InstData &, Instruction &) {
  return false;
}

// FMAXNMP FMAXNMP_asimdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 opcode   0
//  12 0 opcode   1
//  13 0 opcode   2
//  14 1 opcode   3
//  15 1 opcode   4
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x sz       0
//  23 0 o1       0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// FMAXNMP  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeFMAXNMP_ASIMDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// FMOV FMOV_32H_float2int:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 0
//  15 0
//  16 0 opcode   0
//  17 1 opcode   1
//  18 1 opcode   2
//  19 0 rmode    0
//  20 0 rmode    1
//  21 1
//  22 1 type     0
//  23 1 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 sf       0
// FMOV  <Wd>, <Hn>
bool TryDecodeFMOV_32H_FLOAT2INT(const InstData &, Instruction &) {
  return false;
}

// FMOV FMOV_64H_float2int:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 0
//  15 0
//  16 0 opcode   0
//  17 1 opcode   1
//  18 1 opcode   2
//  19 0 rmode    0
//  20 0 rmode    1
//  21 1
//  22 1 type     0
//  23 1 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 1 sf       0
// FMOV  <Xd>, <Hn>
bool TryDecodeFMOV_64H_FLOAT2INT(const InstData &, Instruction &) {
  return false;
}

// FMOV FMOV_H32_float2int:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 0
//  15 0
//  16 1 opcode   0
//  17 1 opcode   1
//  18 1 opcode   2
//  19 0 rmode    0
//  20 0 rmode    1
//  21 1
//  22 1 type     0
//  23 1 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 sf       0
// FMOV  <Hd>, <Wn>
bool TryDecodeFMOV_H32_FLOAT2INT(const InstData &, Instruction &) {
  return false;
}

// FMOV FMOV_H64_float2int:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 0
//  15 0
//  16 1 opcode   0
//  17 1 opcode   1
//  18 1 opcode   2
//  19 0 rmode    0
//  20 0 rmode    1
//  21 1
//  22 1 type     0
//  23 1 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 1 sf       0
// FMOV  <Hd>, <Xn>
bool TryDecodeFMOV_H64_FLOAT2INT(const InstData &, Instruction &) {
  return false;
}

// LDCLRAH LDCLRAH_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 0 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 1 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 0 size     1
// LDCLRAH  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDCLRAH_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDCLRALH LDCLRALH_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 0 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 1 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 0 size     1
// LDCLRALH  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDCLRALH_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDCLRH LDCLRH_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 0 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 0 size     1
// LDCLRH  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDCLRH_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDCLRLH LDCLRLH_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 0 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 0 size     1
// LDCLRLH  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDCLRLH_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// SABAL SABAL_asimddiff_L:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1
//  13 0 op       0
//  14 1
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// SABAL{2}  <Vd>.<Ta>, <Vn>.<Tb>, <Vm>.<Tb>
bool TryDecodeSABAL_ASIMDDIFF_L(const InstData &, Instruction &) {
  return false;
}

// LDSETA LDSETA_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 1 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 1 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 1 size     1
// LDSETA  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDSETA_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDSETAL LDSETAL_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 1 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 1 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 1 size     1
// LDSETAL  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDSETAL_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDSET LDSET_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 1 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 1 size     1
// LDSET  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDSET_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDSETL LDSETL_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 1 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 1 size     1
// LDSETL  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDSETL_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDSETA LDSETA_64_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 1 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 1 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 1 size     1
// LDSETA  <Xs>, <Xt>, [<Xn|SP>]
bool TryDecodeLDSETA_64_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDSETAL LDSETAL_64_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 1 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 1 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 1 size     1
// LDSETAL  <Xs>, <Xt>, [<Xn|SP>]
bool TryDecodeLDSETAL_64_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDSET LDSET_64_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 1 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 1 size     1
// LDSET  <Xs>, <Xt>, [<Xn|SP>]
bool TryDecodeLDSET_64_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDSETL LDSETL_64_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 1 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 1 size     1
// LDSETL  <Xs>, <Xt>, [<Xn|SP>]
bool TryDecodeLDSETL_64_MEMOP(const InstData &, Instruction &) {
  return false;
}

// FRECPS FRECPS_asisdsamefp16_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1 opcode   0
//  12 1 opcode   1
//  13 1 opcode   2
//  14 0
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 1
//  23 0 a        0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// FRECPS  <Hd>, <Hn>, <Hm>
bool TryDecodeFRECPS_ASISDSAMEFP16_ONLY(const InstData &, Instruction &) {
  return false;
}

// FRECPS FRECPS_asisdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1 opcode   0
//  12 1 opcode   1
//  13 1 opcode   2
//  14 1 opcode   3
//  15 1 opcode   4
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x sz       0
//  23 0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// FRECPS  <V><d>, <V><n>, <V><m>
bool TryDecodeFRECPS_ASISDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// FRECPS FRECPS_asimdsamefp16_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1 opcode   0
//  12 1 opcode   1
//  13 1 opcode   2
//  14 0
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 1
//  23 0 a        0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// FRECPS  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeFRECPS_ASIMDSAMEFP16_ONLY(const InstData &, Instruction &) {
  return false;
}

// FRECPS FRECPS_asimdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1 opcode   0
//  12 1 opcode   1
//  13 1 opcode   2
//  14 1 opcode   3
//  15 1 opcode   4
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x sz       0
//  23 0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// FRECPS  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeFRECPS_ASIMDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// SMLAL SMLAL_asimddiff_L:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0 o1       0
//  14 0
//  15 1
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// SMLAL{2}  <Vd>.<Ta>, <Vn>.<Tb>, <Vm>.<Tb>
bool TryDecodeSMLAL_ASIMDDIFF_L(const InstData &, Instruction &) {
  return false;
}

// LDSMINAH LDSMINAH_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 0 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 1 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 0 size     1
// LDSMINAH  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDSMINAH_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDSMINALH LDSMINALH_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 0 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 1 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 0 size     1
// LDSMINALH  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDSMINALH_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDSMINH LDSMINH_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 0 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 0 size     1
// LDSMINH  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDSMINH_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDSMINLH LDSMINLH_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 0 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 0 size     1
// LDSMINLH  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDSMINLH_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// FRINTI FRINTI_H_floatdp1:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 1
//  15 1 rmode    0
//  16 1 rmode    1
//  17 1 rmode    2
//  18 1
//  19 0
//  20 0
//  21 1
//  22 1 type     0
//  23 1 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 M        0
// FRINTI  <Hd>, <Hn>
bool TryDecodeFRINTI_H_FLOATDP1(const InstData &, Instruction &) {
  return false;
}

// FRINTI FRINTI_S_floatdp1:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 1
//  15 1 rmode    0
//  16 1 rmode    1
//  17 1 rmode    2
//  18 1
//  19 0
//  20 0
//  21 1
//  22 0 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 M        0
// FRINTI  <Sd>, <Sn>
bool TryDecodeFRINTI_S_FLOATDP1(const InstData &, Instruction &) {
  return false;
}

// FRINTI FRINTI_D_floatdp1:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 1
//  15 1 rmode    0
//  16 1 rmode    1
//  17 1 rmode    2
//  18 1
//  19 0
//  20 0
//  21 1
//  22 1 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 M        0
// FRINTI  <Dd>, <Dn>
bool TryDecodeFRINTI_D_FLOATDP1(const InstData &, Instruction &) {
  return false;
}

// FMADD FMADD_H_floatdp3:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x Ra       0
//  11 x Ra       1
//  12 x Ra       2
//  13 x Ra       3
//  14 x Ra       4
//  15 0 o0       0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0 o1       0
//  22 1 type     0
//  23 1 type     1
//  24 1
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 M        0
// FMADD  <Hd>, <Hn>, <Hm>, <Ha>
bool TryDecodeFMADD_H_FLOATDP3(const InstData &, Instruction &) {
  return false;
}

// SRSHL SRSHL_asisdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 S        0
//  12 1 R        0
//  13 0
//  14 1
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// SRSHL  <V><d>, <V><n>, <V><m>
bool TryDecodeSRSHL_ASISDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// SRSHL SRSHL_asimdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 S        0
//  12 1 R        0
//  13 0
//  14 1
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// SRSHL  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeSRSHL_ASIMDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// FMULX FMULX_asisdelem_RH_H:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 x H        0
//  12 1 opcode   0
//  13 0 opcode   1
//  14 0 opcode   2
//  15 1 opcode   3
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x M        0
//  21 x L        0
//  22 0 size     0
//  23 0 size     1
//  24 1
//  25 1
//  26 1
//  27 1
//  28 1
//  29 1 U        0
//  30 1
//  31 0
// FMULX  <Hd>, <Hn>, <Vm>.H[<index>]
bool TryDecodeFMULX_ASISDELEM_RH_H(const InstData &, Instruction &) {
  return false;
}

// FMULX FMULX_asisdelem_R_SD:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 x H        0
//  12 1 opcode   0
//  13 0 opcode   1
//  14 0 opcode   2
//  15 1 opcode   3
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x M        0
//  21 x L        0
//  22 x sz       0
//  23 1
//  24 1
//  25 1
//  26 1
//  27 1
//  28 1
//  29 1 U        0
//  30 1
//  31 0
// FMULX  <V><d>, <V><n>, <Vm>.<Ts>[<index>]
bool TryDecodeFMULX_ASISDELEM_R_SD(const InstData &, Instruction &) {
  return false;
}

// FMULX FMULX_asimdelem_RH_H:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 x H        0
//  12 1 opcode   0
//  13 0 opcode   1
//  14 0 opcode   2
//  15 1 opcode   3
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x M        0
//  21 x L        0
//  22 0 size     0
//  23 0 size     1
//  24 1
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// FMULX  <Vd>.<T>, <Vn>.<T>, <Vm>.H[<index>]
bool TryDecodeFMULX_ASIMDELEM_RH_H(const InstData &, Instruction &) {
  return false;
}

// FMULX FMULX_asimdelem_R_SD:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 x H        0
//  12 1 opcode   0
//  13 0 opcode   1
//  14 0 opcode   2
//  15 1 opcode   3
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x M        0
//  21 x L        0
//  22 x sz       0
//  23 1
//  24 1
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// FMULX  <Vd>.<T>, <Vn>.<T>, <Vm>.<Ts>[<index>]
bool TryDecodeFMULX_ASIMDELEM_R_SD(const InstData &, Instruction &) {
  return false;
}

// BIC BIC_asimdimm_L_hl:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x h        0
//   6 x g        0
//   7 x f        0
//   8 x e        0
//   9 x d        0
//  10 1
//  11 0 o2       0
//  12 1 cmode    0
//  13 x cmode    1
//  14 0 cmode    2
//  15 1 cmode    3
//  16 x c        0
//  17 x b        0
//  18 x a        0
//  19 0
//  20 0
//  21 0
//  22 0
//  23 0
//  24 1
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 op       0
//  30 x Q        0
//  31 0
// BIC  <Vd>.<T>, #<imm8>{, LSL #<amount>}
bool TryDecodeBIC_ASIMDIMM_L_HL(const InstData &, Instruction &) {
  return false;
}

// BIC BIC_asimdimm_L_sl:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x h        0
//   6 x g        0
//   7 x f        0
//   8 x e        0
//   9 x d        0
//  10 1
//  11 0 o2       0
//  12 1 cmode    0
//  13 x cmode    1
//  14 x cmode    2
//  15 0 cmode    3
//  16 x c        0
//  17 x b        0
//  18 x a        0
//  19 0
//  20 0
//  21 0
//  22 0
//  23 0
//  24 1
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 op       0
//  30 x Q        0
//  31 0
// BIC  <Vd>.<T>, #<imm8>{, LSL #<amount>}
bool TryDecodeBIC_ASIMDIMM_L_SL(const InstData &, Instruction &) {
  return false;
}

// SYS DC_SYS_CR_system:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x op2      0
//   6 x op2      1
//   7 x op2      2
//   8 x CRm      0
//   9 x CRm      1
//  10 x CRm      2
//  11 x CRm      3
//  12 1 CRn      0
//  13 1 CRn      1
//  14 1 CRn      2
//  15 0 CRn      3
//  16 x op1      0
//  17 x op1      1
//  18 x op1      2
//  19 1 op0      0
//  20 0 op0      1
//  21 0 L        0
//  22 0
//  23 0
//  24 1
//  25 0
//  26 1
//  27 0
//  28 1
//  29 0
//  30 1
//  31 1
// DC  <dc_op>, <Xt>
bool TryDecodeDC_SYS_CR_SYSTEM(const InstData &, Instruction &) {
  return false;
}

// PRFM PRFM_P_ldst_regoff:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 x S        0
//  13 x option   0
//  14 x option   1
//  15 x option   2
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 0 opc      0
//  23 1 opc      1
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 1 size     1
// PRFM  (<prfop>|#<imm5>), [<Xn|SP>, (<Wm>|<Xm>){, <extend> {<amount>}}]
bool TryDecodePRFM_P_LDST_REGOFF(const InstData &, Instruction &) {
  return false;
}

// STUMINH STUMINH_32S_memop:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 1 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 0 size     1
// STUMINH  <Ws>, [<Xn|SP>]
bool TryDecodeSTUMINH_32S_MEMOP(const InstData &, Instruction &) {
  return false;
}

// STUMINLH STUMINLH_32S_memop:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 1 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 0 size     1
// STUMINLH  <Ws>, [<Xn|SP>]
bool TryDecodeSTUMINLH_32S_MEMOP(const InstData &, Instruction &) {
  return false;
}

// ORR ORR_asimdimm_L_hl:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x h        0
//   6 x g        0
//   7 x f        0
//   8 x e        0
//   9 x d        0
//  10 1
//  11 0 o2       0
//  12 1 cmode    0
//  13 x cmode    1
//  14 0 cmode    2
//  15 1 cmode    3
//  16 x c        0
//  17 x b        0
//  18 x a        0
//  19 0
//  20 0
//  21 0
//  22 0
//  23 0
//  24 1
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 op       0
//  30 x Q        0
//  31 0
// ORR  <Vd>.<T>, #<imm8>{, LSL #<amount>}
bool TryDecodeORR_ASIMDIMM_L_HL(const InstData &, Instruction &) {
  return false;
}

// ORR ORR_asimdimm_L_sl:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x h        0
//   6 x g        0
//   7 x f        0
//   8 x e        0
//   9 x d        0
//  10 1
//  11 0 o2       0
//  12 1 cmode    0
//  13 x cmode    1
//  14 x cmode    2
//  15 0 cmode    3
//  16 x c        0
//  17 x b        0
//  18 x a        0
//  19 0
//  20 0
//  21 0
//  22 0
//  23 0
//  24 1
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 op       0
//  30 x Q        0
//  31 0
// ORR  <Vd>.<T>, #<imm8>{, LSL #<amount>}
bool TryDecodeORR_ASIMDIMM_L_SL(const InstData &, Instruction &) {
  return false;
}

// FCVTAU FCVTAU_32H_float2int:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 0
//  15 0
//  16 1 opcode   0
//  17 0 opcode   1
//  18 1 opcode   2
//  19 0 rmode    0
//  20 0 rmode    1
//  21 1
//  22 1 type     0
//  23 1 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 sf       0
// FCVTAU  <Wd>, <Hn>
bool TryDecodeFCVTAU_32H_FLOAT2INT(const InstData &, Instruction &) {
  return false;
}

// FCVTAU FCVTAU_64H_float2int:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 0
//  15 0
//  16 1 opcode   0
//  17 0 opcode   1
//  18 1 opcode   2
//  19 0 rmode    0
//  20 0 rmode    1
//  21 1
//  22 1 type     0
//  23 1 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 1 sf       0
// FCVTAU  <Xd>, <Hn>
bool TryDecodeFCVTAU_64H_FLOAT2INT(const InstData &, Instruction &) {
  return false;
}

// FCVTAU FCVTAU_32S_float2int:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 0
//  15 0
//  16 1 opcode   0
//  17 0 opcode   1
//  18 1 opcode   2
//  19 0 rmode    0
//  20 0 rmode    1
//  21 1
//  22 0 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 sf       0
// FCVTAU  <Wd>, <Sn>
bool TryDecodeFCVTAU_32S_FLOAT2INT(const InstData &, Instruction &) {
  return false;
}

// FCVTAU FCVTAU_64S_float2int:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 0
//  15 0
//  16 1 opcode   0
//  17 0 opcode   1
//  18 1 opcode   2
//  19 0 rmode    0
//  20 0 rmode    1
//  21 1
//  22 0 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 1 sf       0
// FCVTAU  <Xd>, <Sn>
bool TryDecodeFCVTAU_64S_FLOAT2INT(const InstData &, Instruction &) {
  return false;
}

// FCVTAU FCVTAU_32D_float2int:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 0
//  15 0
//  16 1 opcode   0
//  17 0 opcode   1
//  18 1 opcode   2
//  19 0 rmode    0
//  20 0 rmode    1
//  21 1
//  22 1 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 sf       0
// FCVTAU  <Wd>, <Dn>
bool TryDecodeFCVTAU_32D_FLOAT2INT(const InstData &, Instruction &) {
  return false;
}

// FCVTAU FCVTAU_64D_float2int:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 0
//  15 0
//  16 1 opcode   0
//  17 0 opcode   1
//  18 1 opcode   2
//  19 0 rmode    0
//  20 0 rmode    1
//  21 1
//  22 1 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 1 sf       0
// FCVTAU  <Xd>, <Dn>
bool TryDecodeFCVTAU_64D_FLOAT2INT(const InstData &, Instruction &) {
  return false;
}

// SYS TLBI_SYS_CR_system:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x op2      0
//   6 x op2      1
//   7 x op2      2
//   8 x CRm      0
//   9 x CRm      1
//  10 x CRm      2
//  11 x CRm      3
//  12 0 CRn      0
//  13 0 CRn      1
//  14 0 CRn      2
//  15 1 CRn      3
//  16 x op1      0
//  17 x op1      1
//  18 x op1      2
//  19 1 op0      0
//  20 0 op0      1
//  21 0 L        0
//  22 0
//  23 0
//  24 1
//  25 0
//  26 1
//  27 0
//  28 1
//  29 0
//  30 1
//  31 1
// TLBI  <tlbi_op>{, <Xt>}
bool TryDecodeTLBI_SYS_CR_SYSTEM(const InstData &, Instruction &) {
  return false;
}

// FRSQRTS FRSQRTS_asisdsamefp16_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1 opcode   0
//  12 1 opcode   1
//  13 1 opcode   2
//  14 0
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 1
//  23 1 a        0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// FRSQRTS  <Hd>, <Hn>, <Hm>
bool TryDecodeFRSQRTS_ASISDSAMEFP16_ONLY(const InstData &, Instruction &) {
  return false;
}

// FRSQRTS FRSQRTS_asisdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1 opcode   0
//  12 1 opcode   1
//  13 1 opcode   2
//  14 1 opcode   3
//  15 1 opcode   4
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x sz       0
//  23 1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// FRSQRTS  <V><d>, <V><n>, <V><m>
bool TryDecodeFRSQRTS_ASISDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// FRSQRTS FRSQRTS_asimdsamefp16_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1 opcode   0
//  12 1 opcode   1
//  13 1 opcode   2
//  14 0
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 1
//  23 1 a        0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// FRSQRTS  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeFRSQRTS_ASIMDSAMEFP16_ONLY(const InstData &, Instruction &) {
  return false;
}

// FRSQRTS FRSQRTS_asimdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1 opcode   0
//  12 1 opcode   1
//  13 1 opcode   2
//  14 1 opcode   3
//  15 1 opcode   4
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x sz       0
//  23 1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// FRSQRTS  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeFRSQRTS_ASIMDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// FRINTN FRINTN_H_floatdp1:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 1
//  15 0 rmode    0
//  16 0 rmode    1
//  17 0 rmode    2
//  18 1
//  19 0
//  20 0
//  21 1
//  22 1 type     0
//  23 1 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 M        0
// FRINTN  <Hd>, <Hn>
bool TryDecodeFRINTN_H_FLOATDP1(const InstData &, Instruction &) {
  return false;
}

// FRINTN FRINTN_S_floatdp1:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 1
//  15 0 rmode    0
//  16 0 rmode    1
//  17 0 rmode    2
//  18 1
//  19 0
//  20 0
//  21 1
//  22 0 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 M        0
// FRINTN  <Sd>, <Sn>
bool TryDecodeFRINTN_S_FLOATDP1(const InstData &, Instruction &) {
  return false;
}

// FRINTN FRINTN_D_floatdp1:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 1
//  15 0 rmode    0
//  16 0 rmode    1
//  17 0 rmode    2
//  18 1
//  19 0
//  20 0
//  21 1
//  22 1 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 M        0
// FRINTN  <Dd>, <Dn>
bool TryDecodeFRINTN_D_FLOATDP1(const InstData &, Instruction &) {
  return false;
}

// ESB ESB_HI_system:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 0 op2      0
//   6 0 op2      1
//   7 0 op2      2
//   8 0 CRm      0
//   9 1 CRm      1
//  10 0 CRm      2
//  11 0 CRm      3
//  12 0 CRn      0
//  13 1 CRn      1
//  14 0 CRn      2
//  15 0 CRn      3
//  16 1 op1      0
//  17 1 op1      1
//  18 0 op1      2
//  19 0 op0      0
//  20 0 op0      1
//  21 0 L        0
//  22 0
//  23 0
//  24 1
//  25 0
//  26 1
//  27 0
//  28 1
//  29 0
//  30 1
//  31 1
// ESB
bool TryDecodeESB_HI_SYSTEM(const InstData &, Instruction &) {
  return false;
}

// FCMLT FCMLT_asisdmiscfp16_FZ:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 opcode   0
//  13 1 opcode   1
//  14 1 opcode   2
//  15 1 opcode   3
//  16 0 opcode   4
//  17 0
//  18 0
//  19 1
//  20 1
//  21 1
//  22 1
//  23 1 a        0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// FCMLT  <Hd>, <Hn>, #0.0
bool TryDecodeFCMLT_ASISDMISCFP16_FZ(const InstData &, Instruction &) {
  return false;
}

// FCMLT FCMLT_asisdmisc_FZ:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 opcode   0
//  13 1 opcode   1
//  14 1 opcode   2
//  15 1 opcode   3
//  16 0 opcode   4
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x sz       0
//  23 1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// FCMLT  <V><d>, <V><n>, #0.0
bool TryDecodeFCMLT_ASISDMISC_FZ(const InstData &, Instruction &) {
  return false;
}

// FCMLT FCMLT_asimdmiscfp16_FZ:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 opcode   0
//  13 1 opcode   1
//  14 1 opcode   2
//  15 1 opcode   3
//  16 0 opcode   4
//  17 0
//  18 0
//  19 1
//  20 1
//  21 1
//  22 1
//  23 1 a        0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// FCMLT  <Vd>.<T>, <Vn>.<T>, #0.0
bool TryDecodeFCMLT_ASIMDMISCFP16_FZ(const InstData &, Instruction &) {
  return false;
}

// FCMLT FCMLT_asimdmisc_FZ:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 opcode   0
//  13 1 opcode   1
//  14 1 opcode   2
//  15 1 opcode   3
//  16 0 opcode   4
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x sz       0
//  23 1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// FCMLT  <Vd>.<T>, <Vn>.<T>, #0.0
bool TryDecodeFCMLT_ASIMDMISC_FZ(const InstData &, Instruction &) {
  return false;
}

// SQRDMULH SQRDMULH_asisdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 opcode   0
//  12 1 opcode   1
//  13 1 opcode   2
//  14 0 opcode   3
//  15 1 opcode   4
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 1 U        0
//  30 1
//  31 0
// SQRDMULH  <V><d>, <V><n>, <V><m>
bool TryDecodeSQRDMULH_ASISDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// SQRDMULH SQRDMULH_asimdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 opcode   0
//  12 1 opcode   1
//  13 1 opcode   2
//  14 0 opcode   3
//  15 1 opcode   4
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// SQRDMULH  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeSQRDMULH_ASIMDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// SWPAH SWPAH_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 0 opc      1
//  14 0 opc      2
//  15 1 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 1 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 0 size     1
// SWPAH  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeSWPAH_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// SWPALH SWPALH_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 0 opc      1
//  14 0 opc      2
//  15 1 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 1 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 0 size     1
// SWPALH  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeSWPALH_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// SWPH SWPH_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 0 opc      1
//  14 0 opc      2
//  15 1 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 0 size     1
// SWPH  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeSWPH_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// SWPLH SWPLH_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 0 opc      1
//  14 0 opc      2
//  15 1 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 0 size     1
// SWPLH  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeSWPLH_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// DUP DUP_asisdone_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 imm4     0
//  12 0 imm4     1
//  13 0 imm4     2
//  14 0 imm4     3
//  15 0
//  16 x imm5     0
//  17 x imm5     1
//  18 x imm5     2
//  19 x imm5     3
//  20 x imm5     4
//  21 0
//  22 0
//  23 0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 op       0
//  30 1
//  31 0
// DUP  <V><d>, <Vn>.<T>[<index>]
bool TryDecodeDUP_ASISDONE_ONLY(const InstData &, Instruction &) {
  return false;
}

// DUP DUP_asimdins_DV_v:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 imm4     0
//  12 0 imm4     1
//  13 0 imm4     2
//  14 0 imm4     3
//  15 0
//  16 x imm5     0
//  17 x imm5     1
//  18 x imm5     2
//  19 x imm5     3
//  20 x imm5     4
//  21 0
//  22 0
//  23 0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 op       0
//  30 x Q        0
//  31 0
// DUP  <Vd>.<T>, <Vn>.<Ts>[<index>]
bool TryDecodeDUP_ASIMDINS_DV_V(const InstData &, Instruction &) {
  return false;
}

// STLRH STLRH_SL32_ldstexcl:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 Rt2      0
//  11 1 Rt2      1
//  12 1 Rt2      2
//  13 1 Rt2      3
//  14 1 Rt2      4
//  15 1 o0       0
//  16 1 Rs       0
//  17 1 Rs       1
//  18 1 Rs       2
//  19 1 Rs       3
//  20 1 Rs       4
//  21 0 o1       0
//  22 0 L        0
//  23 1 o2       0
//  24 0
//  25 0
//  26 0
//  27 1
//  28 0
//  29 0
//  30 1 size     0
//  31 0 size     1
// STLRH  <Wt>, [<Xn|SP>{,#0}]
bool TryDecodeSTLRH_SL32_LDSTEXCL(const InstData &, Instruction &) {
  return false;
}

// LDUMAXA LDUMAXA_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 1 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 1 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 1 size     1
// LDUMAXA  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDUMAXA_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDUMAXAL LDUMAXAL_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 1 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 1 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 1 size     1
// LDUMAXAL  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDUMAXAL_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDUMAX LDUMAX_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 1 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 1 size     1
// LDUMAX  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDUMAX_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDUMAXL LDUMAXL_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 1 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 1 size     1
// LDUMAXL  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDUMAXL_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDUMAXA LDUMAXA_64_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 1 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 1 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 1 size     1
// LDUMAXA  <Xs>, <Xt>, [<Xn|SP>]
bool TryDecodeLDUMAXA_64_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDUMAXAL LDUMAXAL_64_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 1 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 1 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 1 size     1
// LDUMAXAL  <Xs>, <Xt>, [<Xn|SP>]
bool TryDecodeLDUMAXAL_64_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDUMAX LDUMAX_64_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 1 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 1 size     1
// LDUMAX  <Xs>, <Xt>, [<Xn|SP>]
bool TryDecodeLDUMAX_64_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDUMAXL LDUMAXL_64_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 1 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 1 size     1
// LDUMAXL  <Xs>, <Xt>, [<Xn|SP>]
bool TryDecodeLDUMAXL_64_MEMOP(const InstData &, Instruction &) {
  return false;
}

// SQNEG SQNEG_asisdmisc_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 opcode   0
//  13 1 opcode   1
//  14 1 opcode   2
//  15 0 opcode   3
//  16 0 opcode   4
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 1 U        0
//  30 1
//  31 0
// SQNEG  <V><d>, <V><n>
bool TryDecodeSQNEG_ASISDMISC_R(const InstData &, Instruction &) {
  return false;
}

// SQNEG SQNEG_asimdmisc_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 opcode   0
//  13 1 opcode   1
//  14 1 opcode   2
//  15 0 opcode   3
//  16 0 opcode   4
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// SQNEG  <Vd>.<T>, <Vn>.<T>
bool TryDecodeSQNEG_ASIMDMISC_R(const InstData &, Instruction &) {
  return false;
}

// UHADD UHADD_asimdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 opcode   0
//  12 0 opcode   1
//  13 0 opcode   2
//  14 0 opcode   3
//  15 0 opcode   4
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// UHADD  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeUHADD_ASIMDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// CASAH CASAH_C32_ldstexcl:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 Rt2      0
//  11 1 Rt2      1
//  12 1 Rt2      2
//  13 1 Rt2      3
//  14 1 Rt2      4
//  15 0 o0       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1 o1       0
//  22 1 L        0
//  23 1 o2       0
//  24 0
//  25 0
//  26 0
//  27 1
//  28 0
//  29 0
//  30 1 size     0
//  31 0 size     1
// CASAH  <Ws>, <Wt>, [<Xn|SP>{,#0}]
bool TryDecodeCASAH_C32_LDSTEXCL(const InstData &, Instruction &) {
  return false;
}

// CASALH CASALH_C32_ldstexcl:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 Rt2      0
//  11 1 Rt2      1
//  12 1 Rt2      2
//  13 1 Rt2      3
//  14 1 Rt2      4
//  15 1 o0       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1 o1       0
//  22 1 L        0
//  23 1 o2       0
//  24 0
//  25 0
//  26 0
//  27 1
//  28 0
//  29 0
//  30 1 size     0
//  31 0 size     1
// CASALH  <Ws>, <Wt>, [<Xn|SP>{,#0}]
bool TryDecodeCASALH_C32_LDSTEXCL(const InstData &, Instruction &) {
  return false;
}

// CASH CASH_C32_ldstexcl:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 Rt2      0
//  11 1 Rt2      1
//  12 1 Rt2      2
//  13 1 Rt2      3
//  14 1 Rt2      4
//  15 0 o0       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1 o1       0
//  22 0 L        0
//  23 1 o2       0
//  24 0
//  25 0
//  26 0
//  27 1
//  28 0
//  29 0
//  30 1 size     0
//  31 0 size     1
// CASH  <Ws>, <Wt>, [<Xn|SP>{,#0}]
bool TryDecodeCASH_C32_LDSTEXCL(const InstData &, Instruction &) {
  return false;
}

// CASLH CASLH_C32_ldstexcl:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 Rt2      0
//  11 1 Rt2      1
//  12 1 Rt2      2
//  13 1 Rt2      3
//  14 1 Rt2      4
//  15 1 o0       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1 o1       0
//  22 0 L        0
//  23 1 o2       0
//  24 0
//  25 0
//  26 0
//  27 1
//  28 0
//  29 0
//  30 1 size     0
//  31 0 size     1
// CASLH  <Ws>, <Wt>, [<Xn|SP>{,#0}]
bool TryDecodeCASLH_C32_LDSTEXCL(const InstData &, Instruction &) {
  return false;
}

// ADCS ADCS_32_addsub_carry:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0 opcode2  0
//  11 0 opcode2  1
//  12 0 opcode2  2
//  13 0 opcode2  3
//  14 0 opcode2  4
//  15 0 opcode2  5
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 0
//  23 0
//  24 0
//  25 1
//  26 0
//  27 1
//  28 1
//  29 1 S        0
//  30 0 op       0
//  31 0 sf       0
// ADCS  <Wd>, <Wn>, <Wm>
bool TryDecodeADCS_32_ADDSUB_CARRY(const InstData &, Instruction &) {
  return false;
}

// ADCS ADCS_64_addsub_carry:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0 opcode2  0
//  11 0 opcode2  1
//  12 0 opcode2  2
//  13 0 opcode2  3
//  14 0 opcode2  4
//  15 0 opcode2  5
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 0
//  23 0
//  24 0
//  25 1
//  26 0
//  27 1
//  28 1
//  29 1 S        0
//  30 0 op       0
//  31 1 sf       0
// ADCS  <Xd>, <Xn>, <Xm>
bool TryDecodeADCS_64_ADDSUB_CARRY(const InstData &, Instruction &) {
  return false;
}

// FRINTZ FRINTZ_H_floatdp1:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 1
//  15 1 rmode    0
//  16 1 rmode    1
//  17 0 rmode    2
//  18 1
//  19 0
//  20 0
//  21 1
//  22 1 type     0
//  23 1 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 M        0
// FRINTZ  <Hd>, <Hn>
bool TryDecodeFRINTZ_H_FLOATDP1(const InstData &, Instruction &) {
  return false;
}

// FRINTZ FRINTZ_S_floatdp1:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 1
//  15 1 rmode    0
//  16 1 rmode    1
//  17 0 rmode    2
//  18 1
//  19 0
//  20 0
//  21 1
//  22 0 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 M        0
// FRINTZ  <Sd>, <Sn>
bool TryDecodeFRINTZ_S_FLOATDP1(const InstData &, Instruction &) {
  return false;
}

// FRINTZ FRINTZ_D_floatdp1:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 1
//  15 1 rmode    0
//  16 1 rmode    1
//  17 0 rmode    2
//  18 1
//  19 0
//  20 0
//  21 1
//  22 1 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 M        0
// FRINTZ  <Dd>, <Dn>
bool TryDecodeFRINTZ_D_FLOATDP1(const InstData &, Instruction &) {
  return false;
}

// SCVTF SCVTF_H32_float2fix:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x scale    0
//  11 x scale    1
//  12 x scale    2
//  13 x scale    3
//  14 x scale    4
//  15 x scale    5
//  16 0 opcode   0
//  17 1 opcode   1
//  18 0 opcode   2
//  19 0 rmode    0
//  20 0 rmode    1
//  21 0
//  22 1 type     0
//  23 1 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 sf       0
// SCVTF  <Hd>, <Wn>, #<fbits>
bool TryDecodeSCVTF_H32_FLOAT2FIX(const InstData &, Instruction &) {
  return false;
}

// SCVTF SCVTF_S32_float2fix:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x scale    0
//  11 x scale    1
//  12 x scale    2
//  13 x scale    3
//  14 x scale    4
//  15 x scale    5
//  16 0 opcode   0
//  17 1 opcode   1
//  18 0 opcode   2
//  19 0 rmode    0
//  20 0 rmode    1
//  21 0
//  22 0 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 sf       0
// SCVTF  <Sd>, <Wn>, #<fbits>
bool TryDecodeSCVTF_S32_FLOAT2FIX(const InstData &, Instruction &) {
  return false;
}

// SCVTF SCVTF_D32_float2fix:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x scale    0
//  11 x scale    1
//  12 x scale    2
//  13 x scale    3
//  14 x scale    4
//  15 x scale    5
//  16 0 opcode   0
//  17 1 opcode   1
//  18 0 opcode   2
//  19 0 rmode    0
//  20 0 rmode    1
//  21 0
//  22 1 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 sf       0
// SCVTF  <Dd>, <Wn>, #<fbits>
bool TryDecodeSCVTF_D32_FLOAT2FIX(const InstData &, Instruction &) {
  return false;
}

// SCVTF SCVTF_H64_float2fix:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x scale    0
//  11 x scale    1
//  12 x scale    2
//  13 x scale    3
//  14 x scale    4
//  15 x scale    5
//  16 0 opcode   0
//  17 1 opcode   1
//  18 0 opcode   2
//  19 0 rmode    0
//  20 0 rmode    1
//  21 0
//  22 1 type     0
//  23 1 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 1 sf       0
// SCVTF  <Hd>, <Xn>, #<fbits>
bool TryDecodeSCVTF_H64_FLOAT2FIX(const InstData &, Instruction &) {
  return false;
}

// SCVTF SCVTF_S64_float2fix:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x scale    0
//  11 x scale    1
//  12 x scale    2
//  13 x scale    3
//  14 x scale    4
//  15 x scale    5
//  16 0 opcode   0
//  17 1 opcode   1
//  18 0 opcode   2
//  19 0 rmode    0
//  20 0 rmode    1
//  21 0
//  22 0 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 1 sf       0
// SCVTF  <Sd>, <Xn>, #<fbits>
bool TryDecodeSCVTF_S64_FLOAT2FIX(const InstData &, Instruction &) {
  return false;
}

// SCVTF SCVTF_D64_float2fix:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x scale    0
//  11 x scale    1
//  12 x scale    2
//  13 x scale    3
//  14 x scale    4
//  15 x scale    5
//  16 0 opcode   0
//  17 1 opcode   1
//  18 0 opcode   2
//  19 0 rmode    0
//  20 0 rmode    1
//  21 0
//  22 1 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 1 sf       0
// SCVTF  <Dd>, <Xn>, #<fbits>
bool TryDecodeSCVTF_D64_FLOAT2FIX(const InstData &, Instruction &) {
  return false;
}

// SQDMLAL SQDMLAL_asisdelem_L:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 x H        0
//  12 1
//  13 1
//  14 0 o2       0
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x M        0
//  21 x L        0
//  22 x size     0
//  23 x size     1
//  24 1
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// SQDMLAL  <Va><d>, <Vb><n>, <Vm>.<Ts>[<index>]
bool TryDecodeSQDMLAL_ASISDELEM_L(const InstData &, Instruction &) {
  return false;
}

// SQDMLAL SQDMLAL_asimdelem_L:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 x H        0
//  12 1
//  13 1
//  14 0 o2       0
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x M        0
//  21 x L        0
//  22 x size     0
//  23 x size     1
//  24 1
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// SQDMLAL{2}  <Vd>.<Ta>, <Vn>.<Tb>, <Vm>.<Ts>[<index>]
bool TryDecodeSQDMLAL_ASIMDELEM_L(const InstData &, Instruction &) {
  return false;
}

// SHL SHL_asisdshf_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 opcode   0
//  12 1 opcode   1
//  13 0 opcode   2
//  14 1 opcode   3
//  15 0 opcode   4
//  16 x immb     0
//  17 x immb     1
//  18 x immb     2
//  19 x immh     0
//  20 x immh     1
//  21 x immh     2
//  22 x immh     3
//  23 0
//  24 1
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// SHL  <V><d>, <V><n>, #<shift>
bool TryDecodeSHL_ASISDSHF_R(const InstData &, Instruction &) {
  return false;
}

// SHL SHL_asimdshf_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 opcode   0
//  12 1 opcode   1
//  13 0 opcode   2
//  14 1 opcode   3
//  15 0 opcode   4
//  16 x immb     0
//  17 x immb     1
//  18 x immb     2
//  19 x immh     0
//  20 x immh     1
//  21 x immh     2
//  22 x immh     3
//  23 0
//  24 1
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// SHL  <Vd>.<T>, <Vn>.<T>, #<shift>
bool TryDecodeSHL_ASIMDSHF_R(const InstData &, Instruction &) {
  return false;
}

// STADDB STADDB_32S_memop:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 0 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 0 size     1
// STADDB  <Ws>, [<Xn|SP>]
bool TryDecodeSTADDB_32S_MEMOP(const InstData &, Instruction &) {
  return false;
}

// STADDLB STADDLB_32S_memop:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 0 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 0 size     1
// STADDLB  <Ws>, [<Xn|SP>]
bool TryDecodeSTADDLB_32S_MEMOP(const InstData &, Instruction &) {
  return false;
}

// STUMAX STUMAX_32S_memop:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 1 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 1 size     1
// STUMAX  <Ws>, [<Xn|SP>]
bool TryDecodeSTUMAX_32S_MEMOP(const InstData &, Instruction &) {
  return false;
}

// STUMAXL STUMAXL_32S_memop:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 1 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 1 size     1
// STUMAXL  <Ws>, [<Xn|SP>]
bool TryDecodeSTUMAXL_32S_MEMOP(const InstData &, Instruction &) {
  return false;
}

// STUMAX STUMAX_64S_memop:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 1 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 1 size     1
// STUMAX  <Xs>, [<Xn|SP>]
bool TryDecodeSTUMAX_64S_MEMOP(const InstData &, Instruction &) {
  return false;
}

// STUMAXL STUMAXL_64S_memop:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 1 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 1 size     1
// STUMAXL  <Xs>, [<Xn|SP>]
bool TryDecodeSTUMAXL_64S_MEMOP(const InstData &, Instruction &) {
  return false;
}

// SQDMULH SQDMULH_asisdelem_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 x H        0
//  12 0 op       0
//  13 0
//  14 1
//  15 1
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x M        0
//  21 x L        0
//  22 x size     0
//  23 x size     1
//  24 1
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// SQDMULH  <V><d>, <V><n>, <Vm>.<Ts>[<index>]
bool TryDecodeSQDMULH_ASISDELEM_R(const InstData &, Instruction &) {
  return false;
}

// SQDMULH SQDMULH_asimdelem_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 x H        0
//  12 0 op       0
//  13 0
//  14 1
//  15 1
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x M        0
//  21 x L        0
//  22 x size     0
//  23 x size     1
//  24 1
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// SQDMULH  <Vd>.<T>, <Vn>.<T>, <Vm>.<Ts>[<index>]
bool TryDecodeSQDMULH_ASIMDELEM_R(const InstData &, Instruction &) {
  return false;
}

// FRSQRTE FRSQRTE_asisdmiscfp16_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 opcode   0
//  13 0 opcode   1
//  14 1 opcode   2
//  15 1 opcode   3
//  16 1 opcode   4
//  17 0
//  18 0
//  19 1
//  20 1
//  21 1
//  22 1
//  23 1 a        0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 1 U        0
//  30 1
//  31 0
// FRSQRTE  <Hd>, <Hn>
bool TryDecodeFRSQRTE_ASISDMISCFP16_R(const InstData &, Instruction &) {
  return false;
}

// FRSQRTE FRSQRTE_asisdmisc_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 opcode   0
//  13 0 opcode   1
//  14 1 opcode   2
//  15 1 opcode   3
//  16 1 opcode   4
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x sz       0
//  23 1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 1 U        0
//  30 1
//  31 0
// FRSQRTE  <V><d>, <V><n>
bool TryDecodeFRSQRTE_ASISDMISC_R(const InstData &, Instruction &) {
  return false;
}

// FRSQRTE FRSQRTE_asimdmiscfp16_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 opcode   0
//  13 0 opcode   1
//  14 1 opcode   2
//  15 1 opcode   3
//  16 1 opcode   4
//  17 0
//  18 0
//  19 1
//  20 1
//  21 1
//  22 1
//  23 1 a        0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// FRSQRTE  <Vd>.<T>, <Vn>.<T>
bool TryDecodeFRSQRTE_ASIMDMISCFP16_R(const InstData &, Instruction &) {
  return false;
}

// FRSQRTE FRSQRTE_asimdmisc_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 opcode   0
//  13 0 opcode   1
//  14 1 opcode   2
//  15 1 opcode   3
//  16 1 opcode   4
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x sz       0
//  23 1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// FRSQRTE  <Vd>.<T>, <Vn>.<T>
bool TryDecodeFRSQRTE_ASIMDMISC_R(const InstData &, Instruction &) {
  return false;
}

// ADD ADD_asisdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 opcode   0
//  12 0 opcode   1
//  13 0 opcode   2
//  14 0 opcode   3
//  15 1 opcode   4
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// ADD  <V><d>, <V><n>, <V><m>
bool TryDecodeADD_ASISDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// SABDL SABDL_asimddiff_L:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1
//  13 1 op       0
//  14 1
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// SABDL{2}  <Vd>.<Ta>, <Vn>.<Tb>, <Vm>.<Tb>
bool TryDecodeSABDL_ASIMDDIFF_L(const InstData &, Instruction &) {
  return false;
}

// RORV ROR_RORV_32_dp_2src:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 op2      0
//  11 1 op2      1
//  12 0 opcode2  2
//  13 1 opcode2  3
//  14 0 opcode2  4
//  15 0 opcode2  5
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 1
//  23 1
//  24 0
//  25 1
//  26 0
//  27 1
//  28 1
//  29 0 S        0
//  30 0 op       0
//  31 0 sf       0
// ROR  <Wd>, <Wn>, <Wm>
bool TryDecodeROR_RORV_32_DP_2SRC(const InstData &, Instruction &) {
  return false;
}

// RORV ROR_RORV_64_dp_2src:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 op2      0
//  11 1 op2      1
//  12 0 opcode2  2
//  13 1 opcode2  3
//  14 0 opcode2  4
//  15 0 opcode2  5
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 1
//  23 1
//  24 0
//  25 1
//  26 0
//  27 1
//  28 1
//  29 0 S        0
//  30 0 op       0
//  31 1 sf       0
// ROR  <Xd>, <Xn>, <Xm>
bool TryDecodeROR_RORV_64_DP_2SRC(const InstData &, Instruction &) {
  return false;
}

// UCVTF UCVTF_H32_float2fix:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x scale    0
//  11 x scale    1
//  12 x scale    2
//  13 x scale    3
//  14 x scale    4
//  15 x scale    5
//  16 1 opcode   0
//  17 1 opcode   1
//  18 0 opcode   2
//  19 0 rmode    0
//  20 0 rmode    1
//  21 0
//  22 1 type     0
//  23 1 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 sf       0
// UCVTF  <Hd>, <Wn>, #<fbits>
bool TryDecodeUCVTF_H32_FLOAT2FIX(const InstData &, Instruction &) {
  return false;
}

// UCVTF UCVTF_S32_float2fix:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x scale    0
//  11 x scale    1
//  12 x scale    2
//  13 x scale    3
//  14 x scale    4
//  15 x scale    5
//  16 1 opcode   0
//  17 1 opcode   1
//  18 0 opcode   2
//  19 0 rmode    0
//  20 0 rmode    1
//  21 0
//  22 0 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 sf       0
// UCVTF  <Sd>, <Wn>, #<fbits>
bool TryDecodeUCVTF_S32_FLOAT2FIX(const InstData &, Instruction &) {
  return false;
}

// UCVTF UCVTF_D32_float2fix:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x scale    0
//  11 x scale    1
//  12 x scale    2
//  13 x scale    3
//  14 x scale    4
//  15 x scale    5
//  16 1 opcode   0
//  17 1 opcode   1
//  18 0 opcode   2
//  19 0 rmode    0
//  20 0 rmode    1
//  21 0
//  22 1 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 sf       0
// UCVTF  <Dd>, <Wn>, #<fbits>
bool TryDecodeUCVTF_D32_FLOAT2FIX(const InstData &, Instruction &) {
  return false;
}

// UCVTF UCVTF_H64_float2fix:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x scale    0
//  11 x scale    1
//  12 x scale    2
//  13 x scale    3
//  14 x scale    4
//  15 x scale    5
//  16 1 opcode   0
//  17 1 opcode   1
//  18 0 opcode   2
//  19 0 rmode    0
//  20 0 rmode    1
//  21 0
//  22 1 type     0
//  23 1 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 1 sf       0
// UCVTF  <Hd>, <Xn>, #<fbits>
bool TryDecodeUCVTF_H64_FLOAT2FIX(const InstData &, Instruction &) {
  return false;
}

// UCVTF UCVTF_S64_float2fix:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x scale    0
//  11 x scale    1
//  12 x scale    2
//  13 x scale    3
//  14 x scale    4
//  15 x scale    5
//  16 1 opcode   0
//  17 1 opcode   1
//  18 0 opcode   2
//  19 0 rmode    0
//  20 0 rmode    1
//  21 0
//  22 0 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 1 sf       0
// UCVTF  <Sd>, <Xn>, #<fbits>
bool TryDecodeUCVTF_S64_FLOAT2FIX(const InstData &, Instruction &) {
  return false;
}

// UCVTF UCVTF_D64_float2fix:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x scale    0
//  11 x scale    1
//  12 x scale    2
//  13 x scale    3
//  14 x scale    4
//  15 x scale    5
//  16 1 opcode   0
//  17 1 opcode   1
//  18 0 opcode   2
//  19 0 rmode    0
//  20 0 rmode    1
//  21 0
//  22 1 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 1 sf       0
// UCVTF  <Dd>, <Xn>, #<fbits>
bool TryDecodeUCVTF_D64_FLOAT2FIX(const InstData &, Instruction &) {
  return false;
}

// SQRDMLAH SQRDMLAH_asisdelem_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 x H        0
//  12 1
//  13 0 S        0
//  14 1
//  15 1
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x M        0
//  21 x L        0
//  22 x size     0
//  23 x size     1
//  24 1
//  25 1
//  26 1
//  27 1
//  28 1
//  29 1 U        0
//  30 1
//  31 0
// SQRDMLAH  <V><d>, <V><n>, <Vm>.<Ts>[<index>]
bool TryDecodeSQRDMLAH_ASISDELEM_R(const InstData &, Instruction &) {
  return false;
}

// SQRDMLAH SQRDMLAH_asimdelem_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 x H        0
//  12 1
//  13 0 S        0
//  14 1
//  15 1
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x M        0
//  21 x L        0
//  22 x size     0
//  23 x size     1
//  24 1
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// SQRDMLAH  <Vd>.<T>, <Vn>.<T>, <Vm>.<Ts>[<index>]
bool TryDecodeSQRDMLAH_ASIMDELEM_R(const InstData &, Instruction &) {
  return false;
}

// FMAXP FMAXP_asisdpair_only_H:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 opcode   0
//  13 1 opcode   1
//  14 1 opcode   2
//  15 1 opcode   3
//  16 0 opcode   4
//  17 0
//  18 0
//  19 0
//  20 1
//  21 1
//  22 0 sz       0
//  23 0 o1       0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// FMAXP  <V><d>, <Vn>.<T>
bool TryDecodeFMAXP_ASISDPAIR_ONLY_H(const InstData &, Instruction &) {
  return false;
}

// FMAXP FMAXP_asisdpair_only_SD:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 opcode   0
//  13 1 opcode   1
//  14 1 opcode   2
//  15 1 opcode   3
//  16 0 opcode   4
//  17 0
//  18 0
//  19 0
//  20 1
//  21 1
//  22 x sz       0
//  23 0 o1       0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 1 U        0
//  30 1
//  31 0
// FMAXP  <V><d>, <Vn>.<T>
bool TryDecodeFMAXP_ASISDPAIR_ONLY_SD(const InstData &, Instruction &) {
  return false;
}

// FCMLE FCMLE_asisdmiscfp16_FZ:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 op       0
//  13 0
//  14 1
//  15 1
//  16 0
//  17 0
//  18 0
//  19 1
//  20 1
//  21 1
//  22 1
//  23 1 a        0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 1 U        0
//  30 1
//  31 0
// FCMLE  <Hd>, <Hn>, #0.0
bool TryDecodeFCMLE_ASISDMISCFP16_FZ(const InstData &, Instruction &) {
  return false;
}

// FCMLE FCMLE_asisdmisc_FZ:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 op       0
//  13 0
//  14 1
//  15 1
//  16 0
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x sz       0
//  23 1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 1 U        0
//  30 1
//  31 0
// FCMLE  <V><d>, <V><n>, #0.0
bool TryDecodeFCMLE_ASISDMISC_FZ(const InstData &, Instruction &) {
  return false;
}

// FCMLE FCMLE_asimdmiscfp16_FZ:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 op       0
//  13 0
//  14 1
//  15 1
//  16 0
//  17 0
//  18 0
//  19 1
//  20 1
//  21 1
//  22 1
//  23 1 a        0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// FCMLE  <Vd>.<T>, <Vn>.<T>, #0.0
bool TryDecodeFCMLE_ASIMDMISCFP16_FZ(const InstData &, Instruction &) {
  return false;
}

// FCMLE FCMLE_asimdmisc_FZ:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 op       0
//  13 0
//  14 1
//  15 1
//  16 0
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x sz       0
//  23 1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// FCMLE  <Vd>.<T>, <Vn>.<T>, #0.0
bool TryDecodeFCMLE_ASIMDMISC_FZ(const InstData &, Instruction &) {
  return false;
}

// DRPS DRPS_64E_branch_reg:
//   0 0 op4      0
//   1 0 op4      1
//   2 0 op4      2
//   3 0 op4      3
//   4 0 op4      4
//   5 1 Rt       0
//   6 1 Rt       1
//   7 1 Rt       2
//   8 1 Rt       3
//   9 1 Rt       4
//  10 0 op3      0
//  11 0 op3      1
//  12 0 op3      2
//  13 0 op3      3
//  14 0 op3      4
//  15 0 op3      5
//  16 1 op2      0
//  17 1 op2      1
//  18 1 op2      2
//  19 1 op2      3
//  20 1 op2      4
//  21 1 opc      0
//  22 0 opc      1
//  23 1 opc      2
//  24 0 opc      3
//  25 1
//  26 1
//  27 0
//  28 1
//  29 0
//  30 1
//  31 1
// DRPS
bool TryDecodeDRPS_64E_BRANCH_REG(const InstData &, Instruction &) {
  return false;
}

// SLI SLI_asisdshf_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 opcode   0
//  12 1 opcode   1
//  13 0 opcode   2
//  14 1 opcode   3
//  15 0 opcode   4
//  16 x immb     0
//  17 x immb     1
//  18 x immb     2
//  19 x immh     0
//  20 x immh     1
//  21 x immh     2
//  22 x immh     3
//  23 0
//  24 1
//  25 1
//  26 1
//  27 1
//  28 1
//  29 1 U        0
//  30 1
//  31 0
// SLI  <V><d>, <V><n>, #<shift>
bool TryDecodeSLI_ASISDSHF_R(const InstData &, Instruction &) {
  return false;
}

// SLI SLI_asimdshf_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 opcode   0
//  12 1 opcode   1
//  13 0 opcode   2
//  14 1 opcode   3
//  15 0 opcode   4
//  16 x immb     0
//  17 x immb     1
//  18 x immb     2
//  19 x immh     0
//  20 x immh     1
//  21 x immh     2
//  22 x immh     3
//  23 0
//  24 1
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// SLI  <Vd>.<T>, <Vn>.<T>, #<shift>
bool TryDecodeSLI_ASIMDSHF_R(const InstData &, Instruction &) {
  return false;
}

// LDAXRH LDAXRH_LR32_ldstexcl:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 Rt2      0
//  11 1 Rt2      1
//  12 1 Rt2      2
//  13 1 Rt2      3
//  14 1 Rt2      4
//  15 1 o0       0
//  16 1 Rs       0
//  17 1 Rs       1
//  18 1 Rs       2
//  19 1 Rs       3
//  20 1 Rs       4
//  21 0 o1       0
//  22 1 L        0
//  23 0 o2       0
//  24 0
//  25 0
//  26 0
//  27 1
//  28 0
//  29 0
//  30 1 size     0
//  31 0 size     1
// LDAXRH  <Wt>, [<Xn|SP>{,#0}]
bool TryDecodeLDAXRH_LR32_LDSTEXCL(const InstData &, Instruction &) {
  return false;
}

// BFM BFI_BFM_32M_bitfield:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x imms     0
//  11 x imms     1
//  12 x imms     2
//  13 x imms     3
//  14 x imms     4
//  15 x imms     5
//  16 x immr     0
//  17 x immr     1
//  18 x immr     2
//  19 x immr     3
//  20 x immr     4
//  21 x immr     5
//  22 0 N        0
//  23 0
//  24 1
//  25 1
//  26 0
//  27 0
//  28 1
//  29 1 opc      0
//  30 0 opc      1
//  31 0 sf       0
// BFI  <Wd>, <Wn>, #<lsb>, #<width>
bool TryDecodeBFI_BFM_32M_BITFIELD(const InstData &, Instruction &) {
  return false;
}

// BFM BFI_BFM_64M_bitfield:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x imms     0
//  11 x imms     1
//  12 x imms     2
//  13 x imms     3
//  14 x imms     4
//  15 x imms     5
//  16 x immr     0
//  17 x immr     1
//  18 x immr     2
//  19 x immr     3
//  20 x immr     4
//  21 x immr     5
//  22 1 N        0
//  23 0
//  24 1
//  25 1
//  26 0
//  27 0
//  28 1
//  29 1 opc      0
//  30 0 opc      1
//  31 1 sf       0
// BFI  <Xd>, <Xn>, #<lsb>, #<width>
bool TryDecodeBFI_BFM_64M_BITFIELD(const InstData &, Instruction &) {
  return false;
}

// LDADDAB LDADDAB_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 0 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 1 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 0 size     1
// LDADDAB  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDADDAB_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDADDALB LDADDALB_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 0 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 1 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 0 size     1
// LDADDALB  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDADDALB_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDADDB LDADDB_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 0 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 0 size     1
// LDADDB  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDADDB_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDADDLB LDADDLB_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 0 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 0 size     1
// LDADDLB  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDADDLB_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// SBFM SXTB_SBFM_32M_bitfield:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 imms     0
//  11 1 imms     1
//  12 1 imms     2
//  13 0 imms     3
//  14 0 imms     4
//  15 0 imms     5
//  16 0 immr     0
//  17 0 immr     1
//  18 0 immr     2
//  19 0 immr     3
//  20 0 immr     4
//  21 0 immr     5
//  22 0 N        0
//  23 0
//  24 1
//  25 1
//  26 0
//  27 0
//  28 1
//  29 0 opc      0
//  30 0 opc      1
//  31 0 sf       0
// SXTB  <Wd>, <Wn>
bool TryDecodeSXTB_SBFM_32M_BITFIELD(const InstData &, Instruction &) {
  return false;
}

// SBFM SXTB_SBFM_64M_bitfield:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 imms     0
//  11 1 imms     1
//  12 1 imms     2
//  13 0 imms     3
//  14 0 imms     4
//  15 0 imms     5
//  16 0 immr     0
//  17 0 immr     1
//  18 0 immr     2
//  19 0 immr     3
//  20 0 immr     4
//  21 0 immr     5
//  22 1 N        0
//  23 0
//  24 1
//  25 1
//  26 0
//  27 0
//  28 1
//  29 0 opc      0
//  30 0 opc      1
//  31 1 sf       0
// SXTB  <Xd>, <Wn>
bool TryDecodeSXTB_SBFM_64M_BITFIELD(const InstData &, Instruction &) {
  return false;
}

// ERET ERET_64E_branch_reg:
//   0 0 op4      0
//   1 0 op4      1
//   2 0 op4      2
//   3 0 op4      3
//   4 0 op4      4
//   5 1 Rt       0
//   6 1 Rt       1
//   7 1 Rt       2
//   8 1 Rt       3
//   9 1 Rt       4
//  10 0 op3      0
//  11 0 op3      1
//  12 0 op3      2
//  13 0 op3      3
//  14 0 op3      4
//  15 0 op3      5
//  16 1 op2      0
//  17 1 op2      1
//  18 1 op2      2
//  19 1 op2      3
//  20 1 op2      4
//  21 0 opc      0
//  22 0 opc      1
//  23 1 opc      2
//  24 0 opc      3
//  25 1
//  26 1
//  27 0
//  28 1
//  29 0
//  30 1
//  31 1
// ERET
bool TryDecodeERET_64E_BRANCH_REG(const InstData &, Instruction &) {
  return false;
}

// STUMIN STUMIN_32S_memop:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 1 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 1 size     1
// STUMIN  <Ws>, [<Xn|SP>]
bool TryDecodeSTUMIN_32S_MEMOP(const InstData &, Instruction &) {
  return false;
}

// STUMINL STUMINL_32S_memop:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 1 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 1 size     1
// STUMINL  <Ws>, [<Xn|SP>]
bool TryDecodeSTUMINL_32S_MEMOP(const InstData &, Instruction &) {
  return false;
}

// STUMIN STUMIN_64S_memop:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 1 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 1 size     1
// STUMIN  <Xs>, [<Xn|SP>]
bool TryDecodeSTUMIN_64S_MEMOP(const InstData &, Instruction &) {
  return false;
}

// STUMINL STUMINL_64S_memop:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 1 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 1 size     1
// STUMINL  <Xs>, [<Xn|SP>]
bool TryDecodeSTUMINL_64S_MEMOP(const InstData &, Instruction &) {
  return false;
}

// SHA1SU1 SHA1SU1_VV_cryptosha2:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 opcode   0
//  13 0 opcode   1
//  14 0 opcode   2
//  15 0 opcode   3
//  16 0 opcode   4
//  17 0
//  18 0
//  19 1
//  20 0
//  21 1
//  22 0 size     0
//  23 0 size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0
//  30 1
//  31 0
// SHA1SU1  <Vd>.4S, <Vn>.4S
bool TryDecodeSHA1SU1_VV_CRYPTOSHA2(const InstData &, Instruction &) {
  return false;
}

// LD1 LD1_asisdlsep_R1_r1:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x size     0
//  11 x size     1
//  12 1 opcode   0
//  13 1 opcode   1
//  14 1 opcode   2
//  15 0 opcode   3
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 1 L        0
//  23 1
//  24 0
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// LD1  { <Vt>.<T> }, [<Xn|SP>], <Xm>
bool TryDecodeLD1_ASISDLSEP_R1_R1(const InstData &, Instruction &) {
  return false;
}

// LD1 LD1_asisdlsep_R2_r2:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x size     0
//  11 x size     1
//  12 0 opcode   0
//  13 1 opcode   1
//  14 0 opcode   2
//  15 1 opcode   3
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 1 L        0
//  23 1
//  24 0
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// LD1  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>], <Xm>
bool TryDecodeLD1_ASISDLSEP_R2_R2(const InstData &, Instruction &) {
  return false;
}

// LD1 LD1_asisdlsep_R3_r3:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x size     0
//  11 x size     1
//  12 0 opcode   0
//  13 1 opcode   1
//  14 1 opcode   2
//  15 0 opcode   3
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 1 L        0
//  23 1
//  24 0
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// LD1  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T> }, [<Xn|SP>], <Xm>
bool TryDecodeLD1_ASISDLSEP_R3_R3(const InstData &, Instruction &) {
  return false;
}

// LD1 LD1_asisdlsep_R4_r4:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x size     0
//  11 x size     1
//  12 0 opcode   0
//  13 1 opcode   1
//  14 0 opcode   2
//  15 0 opcode   3
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 1 L        0
//  23 1
//  24 0
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// LD1  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T>, <Vt4>.<T> }, [<Xn|SP>], <Xm>
bool TryDecodeLD1_ASISDLSEP_R4_R4(const InstData &, Instruction &) {
  return false;
}

// SHA1H SHA1H_SS_cryptosha2:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 opcode   0
//  13 0 opcode   1
//  14 0 opcode   2
//  15 0 opcode   3
//  16 0 opcode   4
//  17 0
//  18 0
//  19 1
//  20 0
//  21 1
//  22 0 size     0
//  23 0 size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0
//  30 1
//  31 0
// SHA1H  <Sd>, <Sn>
bool TryDecodeSHA1H_SS_CRYPTOSHA2(const InstData &, Instruction &) {
  return false;
}

// FRINTM FRINTM_asimdmiscfp16_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 o1       0
//  13 0
//  14 0
//  15 1
//  16 1
//  17 0
//  18 0
//  19 1
//  20 1
//  21 1
//  22 1
//  23 0 o2       0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// FRINTM  <Vd>.<T>, <Vn>.<T>
bool TryDecodeFRINTM_ASIMDMISCFP16_R(const InstData &, Instruction &) {
  return false;
}

// FRINTM FRINTM_asimdmisc_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 o1       0
//  13 0
//  14 0
//  15 1
//  16 1
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x sz       0
//  23 0 o2       0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// FRINTM  <Vd>.<T>, <Vn>.<T>
bool TryDecodeFRINTM_ASIMDMISC_R(const InstData &, Instruction &) {
  return false;
}

// SQSHLU SQSHLU_asisdshf_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0
//  12 0 op       0
//  13 1
//  14 1
//  15 0
//  16 x immb     0
//  17 x immb     1
//  18 x immb     2
//  19 x immh     0
//  20 x immh     1
//  21 x immh     2
//  22 x immh     3
//  23 0
//  24 1
//  25 1
//  26 1
//  27 1
//  28 1
//  29 1 U        0
//  30 1
//  31 0
// SQSHLU  <V><d>, <V><n>, #<shift>
bool TryDecodeSQSHLU_ASISDSHF_R(const InstData &, Instruction &) {
  return false;
}

// SQSHLU SQSHLU_asimdshf_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0
//  12 0 op       0
//  13 1
//  14 1
//  15 0
//  16 x immb     0
//  17 x immb     1
//  18 x immb     2
//  19 x immh     0
//  20 x immh     1
//  21 x immh     2
//  22 x immh     3
//  23 0
//  24 1
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// SQSHLU  <Vd>.<T>, <Vn>.<T>, #<shift>
bool TryDecodeSQSHLU_ASIMDSHF_R(const InstData &, Instruction &) {
  return false;
}

// UMULL UMULL_asimdelem_L:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 x H        0
//  12 0 opcode   0
//  13 1 opcode   1
//  14 0 opcode   2
//  15 1 opcode   3
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x M        0
//  21 x L        0
//  22 x size     0
//  23 x size     1
//  24 1
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// UMULL{2}  <Vd>.<Ta>, <Vn>.<Tb>, <Vm>.<Ts>[<index>]
bool TryDecodeUMULL_ASIMDELEM_L(const InstData &, Instruction &) {
  return false;
}

// SWPAB SWPAB_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 0 opc      1
//  14 0 opc      2
//  15 1 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 1 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 0 size     1
// SWPAB  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeSWPAB_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// SWPALB SWPALB_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 0 opc      1
//  14 0 opc      2
//  15 1 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 1 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 0 size     1
// SWPALB  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeSWPALB_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// SWPB SWPB_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 0 opc      1
//  14 0 opc      2
//  15 1 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 0 size     1
// SWPB  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeSWPB_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// SWPLB SWPLB_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 0 opc      1
//  14 0 opc      2
//  15 1 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 0 size     1
// SWPLB  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeSWPLB_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// FMOV FMOV_asimdimm_H_h:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x h        0
//   6 x g        0
//   7 x f        0
//   8 x e        0
//   9 x d        0
//  10 1
//  11 1 o2       0
//  12 1 cmode    0
//  13 1 cmode    1
//  14 1 cmode    2
//  15 1 cmode    3
//  16 x c        0
//  17 x b        0
//  18 x a        0
//  19 0
//  20 0
//  21 0
//  22 0
//  23 0
//  24 1
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 op       0
//  30 x Q        0
//  31 0
// FMOV  <Vd>.<T>, #<imm>
bool TryDecodeFMOV_ASIMDIMM_H_H(const InstData &, Instruction &) {
  return false;
}

// FMOV FMOV_asimdimm_S_s:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x h        0
//   6 x g        0
//   7 x f        0
//   8 x e        0
//   9 x d        0
//  10 1
//  11 0 o2       0
//  12 1 cmode    0
//  13 1 cmode    1
//  14 1 cmode    2
//  15 1 cmode    3
//  16 x c        0
//  17 x b        0
//  18 x a        0
//  19 0
//  20 0
//  21 0
//  22 0
//  23 0
//  24 1
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 op       0
//  30 x Q        0
//  31 0
// FMOV  <Vd>.<T>, #<imm>
bool TryDecodeFMOV_ASIMDIMM_S_S(const InstData &, Instruction &) {
  return false;
}

// FMOV FMOV_asimdimm_D2_d:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x h        0
//   6 x g        0
//   7 x f        0
//   8 x e        0
//   9 x d        0
//  10 1
//  11 0 o2       0
//  12 1 cmode    0
//  13 1 cmode    1
//  14 1 cmode    2
//  15 1 cmode    3
//  16 x c        0
//  17 x b        0
//  18 x a        0
//  19 0
//  20 0
//  21 0
//  22 0
//  23 0
//  24 1
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 op       0
//  30 1 Q        0
//  31 0
// FMOV  <Vd>.2D, #<imm>
bool TryDecodeFMOV_ASIMDIMM_D2_D(const InstData &, Instruction &) {
  return false;
}

// FMIN FMIN_asimdsamefp16_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 opcode   0
//  12 1 opcode   1
//  13 1 opcode   2
//  14 0
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 1
//  23 1 o1       0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// FMIN  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeFMIN_ASIMDSAMEFP16_ONLY(const InstData &, Instruction &) {
  return false;
}

// FMIN FMIN_asimdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 opcode   0
//  12 1 opcode   1
//  13 1 opcode   2
//  14 1 opcode   3
//  15 1 opcode   4
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x sz       0
//  23 1 o1       0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// FMIN  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeFMIN_ASIMDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// SQXTUN SQXTUN_asisdmisc_N:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 opcode   0
//  13 1 opcode   1
//  14 0 opcode   2
//  15 0 opcode   3
//  16 1 opcode   4
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 1 U        0
//  30 1
//  31 0
// SQXTUN  <Vb><d>, <Va><n>
bool TryDecodeSQXTUN_ASISDMISC_N(const InstData &, Instruction &) {
  return false;
}

// SQXTUN SQXTUN_asimdmisc_N:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 opcode   0
//  13 1 opcode   1
//  14 0 opcode   2
//  15 0 opcode   3
//  16 1 opcode   4
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// SQXTUN{2}  <Vd>.<Tb>, <Vn>.<Ta>
bool TryDecodeSQXTUN_ASIMDMISC_N(const InstData &, Instruction &) {
  return false;
}

// LDEORAB LDEORAB_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 1 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 1 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 0 size     1
// LDEORAB  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDEORAB_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDEORALB LDEORALB_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 1 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 1 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 0 size     1
// LDEORALB  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDEORALB_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDEORB LDEORB_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 1 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 0 size     1
// LDEORB  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDEORB_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDEORLB LDEORLB_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 1 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 0 size     1
// LDEORLB  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDEORLB_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// FCVTPS FCVTPS_asisdmiscfp16_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 o1       0
//  13 1
//  14 0
//  15 1
//  16 1
//  17 0
//  18 0
//  19 1
//  20 1
//  21 1
//  22 1
//  23 1 o2       0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// FCVTPS  <Hd>, <Hn>
bool TryDecodeFCVTPS_ASISDMISCFP16_R(const InstData &, Instruction &) {
  return false;
}

// FCVTPS FCVTPS_asisdmisc_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 o1       0
//  13 1
//  14 0
//  15 1
//  16 1
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x sz       0
//  23 1 o2       0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// FCVTPS  <V><d>, <V><n>
bool TryDecodeFCVTPS_ASISDMISC_R(const InstData &, Instruction &) {
  return false;
}

// FCVTPS FCVTPS_asimdmiscfp16_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 o1       0
//  13 1
//  14 0
//  15 1
//  16 1
//  17 0
//  18 0
//  19 1
//  20 1
//  21 1
//  22 1
//  23 1 o2       0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// FCVTPS  <Vd>.<T>, <Vn>.<T>
bool TryDecodeFCVTPS_ASIMDMISCFP16_R(const InstData &, Instruction &) {
  return false;
}

// FCVTPS FCVTPS_asimdmisc_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 o1       0
//  13 1
//  14 0
//  15 1
//  16 1
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x sz       0
//  23 1 o2       0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// FCVTPS  <Vd>.<T>, <Vn>.<T>
bool TryDecodeFCVTPS_ASIMDMISC_R(const InstData &, Instruction &) {
  return false;
}

// FRINTP FRINTP_asimdmiscfp16_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 o1       0
//  13 0
//  14 0
//  15 1
//  16 1
//  17 0
//  18 0
//  19 1
//  20 1
//  21 1
//  22 1
//  23 1 o2       0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// FRINTP  <Vd>.<T>, <Vn>.<T>
bool TryDecodeFRINTP_ASIMDMISCFP16_R(const InstData &, Instruction &) {
  return false;
}

// FRINTP FRINTP_asimdmisc_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 o1       0
//  13 0
//  14 0
//  15 1
//  16 1
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x sz       0
//  23 1 o2       0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// FRINTP  <Vd>.<T>, <Vn>.<T>
bool TryDecodeFRINTP_ASIMDMISC_R(const InstData &, Instruction &) {
  return false;
}

// LDLARB LDLARB_LR32_ldstexcl:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 Rt2      0
//  11 1 Rt2      1
//  12 1 Rt2      2
//  13 1 Rt2      3
//  14 1 Rt2      4
//  15 0 o0       0
//  16 1 Rs       0
//  17 1 Rs       1
//  18 1 Rs       2
//  19 1 Rs       3
//  20 1 Rs       4
//  21 0 o1       0
//  22 1 L        0
//  23 1 o2       0
//  24 0
//  25 0
//  26 0
//  27 1
//  28 0
//  29 0
//  30 0 size     0
//  31 0 size     1
// LDLARB  <Wt>, [<Xn|SP>{,#0}]
bool TryDecodeLDLARB_LR32_LDSTEXCL(const InstData &, Instruction &) {
  return false;
}

// FNEG FNEG_asimdmiscfp16_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 opcode   0
//  13 1 opcode   1
//  14 1 opcode   2
//  15 1 opcode   3
//  16 0 opcode   4
//  17 0
//  18 0
//  19 1
//  20 1
//  21 1
//  22 1
//  23 1 a        0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// FNEG  <Vd>.<T>, <Vn>.<T>
bool TryDecodeFNEG_ASIMDMISCFP16_R(const InstData &, Instruction &) {
  return false;
}

// FNEG FNEG_asimdmisc_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 opcode   0
//  13 1 opcode   1
//  14 1 opcode   2
//  15 1 opcode   3
//  16 0 opcode   4
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x sz       0
//  23 1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// FNEG  <Vd>.<T>, <Vn>.<T>
bool TryDecodeFNEG_ASIMDMISC_R(const InstData &, Instruction &) {
  return false;
}

// ADDHN ADDHN_asimddiff_N:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0 o1       0
//  14 1
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// ADDHN{2}  <Vd>.<Tb>, <Vn>.<Ta>, <Vm>.<Ta>
bool TryDecodeADDHN_ASIMDDIFF_N(const InstData &, Instruction &) {
  return false;
}

// LDNP LDNP_32_ldstnapair_offs:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x Rt2      0
//  11 x Rt2      1
//  12 x Rt2      2
//  13 x Rt2      3
//  14 x Rt2      4
//  15 x imm7     0
//  16 x imm7     1
//  17 x imm7     2
//  18 x imm7     3
//  19 x imm7     4
//  20 x imm7     5
//  21 x imm7     6
//  22 1 L        0
//  23 0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 0
//  29 1
//  30 0 opc      0
//  31 0 opc      1
// LDNP  <Wt1>, <Wt2>, [<Xn|SP>{, #<imm>}]
bool TryDecodeLDNP_32_LDSTNAPAIR_OFFS(const InstData &, Instruction &) {
  return false;
}

// LDNP LDNP_64_ldstnapair_offs:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x Rt2      0
//  11 x Rt2      1
//  12 x Rt2      2
//  13 x Rt2      3
//  14 x Rt2      4
//  15 x imm7     0
//  16 x imm7     1
//  17 x imm7     2
//  18 x imm7     3
//  19 x imm7     4
//  20 x imm7     5
//  21 x imm7     6
//  22 1 L        0
//  23 0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 0
//  29 1
//  30 0 opc      0
//  31 1 opc      1
// LDNP  <Xt1>, <Xt2>, [<Xn|SP>{, #<imm>}]
bool TryDecodeLDNP_64_LDSTNAPAIR_OFFS(const InstData &, Instruction &) {
  return false;
}

// SQRSHRN SQRSHRN_asisdshf_N:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1 op       0
//  12 1
//  13 0
//  14 0
//  15 1
//  16 x immb     0
//  17 x immb     1
//  18 x immb     2
//  19 x immh     0
//  20 x immh     1
//  21 x immh     2
//  22 x immh     3
//  23 0
//  24 1
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// SQRSHRN  <Vb><d>, <Va><n>, #<shift>
bool TryDecodeSQRSHRN_ASISDSHF_N(const InstData &, Instruction &) {
  return false;
}

// SQRSHRN SQRSHRN_asimdshf_N:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1 op       0
//  12 1
//  13 0
//  14 0
//  15 1
//  16 x immb     0
//  17 x immb     1
//  18 x immb     2
//  19 x immh     0
//  20 x immh     1
//  21 x immh     2
//  22 x immh     3
//  23 0
//  24 1
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// SQRSHRN{2}  <Vd>.<Tb>, <Vn>.<Ta>, #<shift>
bool TryDecodeSQRSHRN_ASIMDSHF_N(const InstData &, Instruction &) {
  return false;
}

// CMGT CMGT_asisdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 eq       0
//  12 1
//  13 1
//  14 0
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// CMGT  <V><d>, <V><n>, <V><m>
bool TryDecodeCMGT_ASISDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// ST4 ST4_asisdlse_R4:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x size     0
//  11 x size     1
//  12 0 opcode   0
//  13 0 opcode   1
//  14 0 opcode   2
//  15 0 opcode   3
//  16 0
//  17 0
//  18 0
//  19 0
//  20 0
//  21 0
//  22 0 L        0
//  23 0
//  24 0
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// ST4  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T>, <Vt4>.<T> }, [<Xn|SP>]
bool TryDecodeST4_ASISDLSE_R4(const InstData &, Instruction &) {
  return false;
}

// ST4 ST4_asisdlsep_I4_i:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x size     0
//  11 x size     1
//  12 0 opcode   0
//  13 0 opcode   1
//  14 0 opcode   2
//  15 0 opcode   3
//  16 1 Rm       0
//  17 1 Rm       1
//  18 1 Rm       2
//  19 1 Rm       3
//  20 1 Rm       4
//  21 0
//  22 0 L        0
//  23 1
//  24 0
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// ST4  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T>, <Vt4>.<T> }, [<Xn|SP>], <imm>
bool TryDecodeST4_ASISDLSEP_I4_I(const InstData &, Instruction &) {
  return false;
}

// ST4 ST4_asisdlsep_R4_r:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x size     0
//  11 x size     1
//  12 0 opcode   0
//  13 0 opcode   1
//  14 0 opcode   2
//  15 0 opcode   3
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 0 L        0
//  23 1
//  24 0
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// ST4  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T>, <Vt4>.<T> }, [<Xn|SP>], <Xm>
bool TryDecodeST4_ASISDLSEP_R4_R(const InstData &, Instruction &) {
  return false;
}

// UHSUB UHSUB_asimdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 opcode   0
//  12 0 opcode   1
//  13 1 opcode   2
//  14 0 opcode   3
//  15 0 opcode   4
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// UHSUB  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeUHSUB_ASIMDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// CMHS CMHS_asisdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1 eq       0
//  12 1
//  13 1
//  14 0
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 1 U        0
//  30 1
//  31 0
// CMHS  <V><d>, <V><n>, <V><m>
bool TryDecodeCMHS_ASISDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// CMHS CMHS_asimdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1 eq       0
//  12 1
//  13 1
//  14 0
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// CMHS  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeCMHS_ASIMDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// SADDW SADDW_asimddiff_W:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1
//  13 0 o1       0
//  14 0
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// SADDW{2}  <Vd>.<Ta>, <Vn>.<Ta>, <Vm>.<Tb>
bool TryDecodeSADDW_ASIMDDIFF_W(const InstData &, Instruction &) {
  return false;
}

// SADDLP SADDLP_asimdmisc_P:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0
//  13 1
//  14 0 op       0
//  15 0
//  16 0
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// SADDLP  <Vd>.<Ta>, <Vn>.<Tb>
bool TryDecodeSADDLP_ASIMDMISC_P(const InstData &, Instruction &) {
  return false;
}

// UMSUBL UMNEGL_UMSUBL_64WA_dp_3src:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 Ra       0
//  11 1 Ra       1
//  12 1 Ra       2
//  13 1 Ra       3
//  14 1 Ra       4
//  15 1 o0       0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 0
//  23 1 U        0
//  24 1
//  25 1
//  26 0
//  27 1
//  28 1
//  29 0 op54     0
//  30 0 op54     1
//  31 1 sf       0
// UMNEGL  <Xd>, <Wn>, <Wm>
bool TryDecodeUMNEGL_UMSUBL_64WA_DP_3SRC(const InstData &, Instruction &) {
  return false;
}

// ST2 ST2_asisdlse_R2:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x size     0
//  11 x size     1
//  12 0 opcode   0
//  13 0 opcode   1
//  14 0 opcode   2
//  15 1 opcode   3
//  16 0
//  17 0
//  18 0
//  19 0
//  20 0
//  21 0
//  22 0 L        0
//  23 0
//  24 0
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// ST2  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>]
bool TryDecodeST2_ASISDLSE_R2(const InstData &, Instruction &) {
  return false;
}

// ST2 ST2_asisdlsep_I2_i:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x size     0
//  11 x size     1
//  12 0 opcode   0
//  13 0 opcode   1
//  14 0 opcode   2
//  15 1 opcode   3
//  16 1 Rm       0
//  17 1 Rm       1
//  18 1 Rm       2
//  19 1 Rm       3
//  20 1 Rm       4
//  21 0
//  22 0 L        0
//  23 1
//  24 0
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// ST2  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>], <imm>
bool TryDecodeST2_ASISDLSEP_I2_I(const InstData &, Instruction &) {
  return false;
}

// ST2 ST2_asisdlsep_R2_r:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x size     0
//  11 x size     1
//  12 0 opcode   0
//  13 0 opcode   1
//  14 0 opcode   2
//  15 1 opcode   3
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 0 L        0
//  23 1
//  24 0
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// ST2  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>], <Xm>
bool TryDecodeST2_ASISDLSEP_R2_R(const InstData &, Instruction &) {
  return false;
}

// USHLL UXTL_USHLL_asimdshf_L:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 opcode   0
//  12 0 opcode   1
//  13 1 opcode   2
//  14 0 opcode   3
//  15 1 opcode   4
//  16 0 immb     0
//  17 0 immb     1
//  18 0 immb     2
//  19 x immh     0
//  20 x immh     1
//  21 x immh     2
//  22 x immh     3
//  23 0
//  24 1
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// UXTL{2}  <Vd>.<Ta>, <Vn>.<Tb>
bool TryDecodeUXTL_USHLL_ASIMDSHF_L(const InstData &, Instruction &) {
  return false;
}

// LDSMINA LDSMINA_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 0 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 1 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 1 size     1
// LDSMINA  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDSMINA_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDSMINAL LDSMINAL_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 0 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 1 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 1 size     1
// LDSMINAL  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDSMINAL_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDSMIN LDSMIN_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 0 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 1 size     1
// LDSMIN  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDSMIN_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDSMINL LDSMINL_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 0 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 1 size     1
// LDSMINL  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDSMINL_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDSMINA LDSMINA_64_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 0 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 1 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 1 size     1
// LDSMINA  <Xs>, <Xt>, [<Xn|SP>]
bool TryDecodeLDSMINA_64_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDSMINAL LDSMINAL_64_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 0 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 1 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 1 size     1
// LDSMINAL  <Xs>, <Xt>, [<Xn|SP>]
bool TryDecodeLDSMINAL_64_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDSMIN LDSMIN_64_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 0 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 1 size     1
// LDSMIN  <Xs>, <Xt>, [<Xn|SP>]
bool TryDecodeLDSMIN_64_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDSMINL LDSMINL_64_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 0 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 1 size     1
// LDSMINL  <Xs>, <Xt>, [<Xn|SP>]
bool TryDecodeLDSMINL_64_MEMOP(const InstData &, Instruction &) {
  return false;
}

// PSB PSB_HC_system:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 1 op2      0
//   6 0 op2      1
//   7 0 op2      2
//   8 0 CRm      0
//   9 1 CRm      1
//  10 0 CRm      2
//  11 0 CRm      3
//  12 0 CRn      0
//  13 1 CRn      1
//  14 0 CRn      2
//  15 0 CRn      3
//  16 1 op1      0
//  17 1 op1      1
//  18 0 op1      2
//  19 0 op0      0
//  20 0 op0      1
//  21 0 L        0
//  22 0
//  23 0
//  24 1
//  25 0
//  26 1
//  27 0
//  28 1
//  29 0
//  30 1
//  31 1
// PSB CSYNC
bool TryDecodePSB_HC_SYSTEM(const InstData &, Instruction &) {
  return false;
}

// FMUL FMUL_asisdelem_RH_H:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 x H        0
//  12 1 opcode   0
//  13 0 opcode   1
//  14 0 opcode   2
//  15 1 opcode   3
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x M        0
//  21 x L        0
//  22 0 size     0
//  23 0 size     1
//  24 1
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// FMUL  <Hd>, <Hn>, <Vm>.H[<index>]
bool TryDecodeFMUL_ASISDELEM_RH_H(const InstData &, Instruction &) {
  return false;
}

// FMUL FMUL_asisdelem_R_SD:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 x H        0
//  12 1 opcode   0
//  13 0 opcode   1
//  14 0 opcode   2
//  15 1 opcode   3
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x M        0
//  21 x L        0
//  22 x sz       0
//  23 1
//  24 1
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// FMUL  <V><d>, <V><n>, <Vm>.<Ts>[<index>]
bool TryDecodeFMUL_ASISDELEM_R_SD(const InstData &, Instruction &) {
  return false;
}

// FMUL FMUL_asimdelem_RH_H:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 x H        0
//  12 1 opcode   0
//  13 0 opcode   1
//  14 0 opcode   2
//  15 1 opcode   3
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x M        0
//  21 x L        0
//  22 0 size     0
//  23 0 size     1
//  24 1
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// FMUL  <Vd>.<T>, <Vn>.<T>, <Vm>.H[<index>]
bool TryDecodeFMUL_ASIMDELEM_RH_H(const InstData &, Instruction &) {
  return false;
}

// FMUL FMUL_asimdelem_R_SD:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 x H        0
//  12 1 opcode   0
//  13 0 opcode   1
//  14 0 opcode   2
//  15 1 opcode   3
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x M        0
//  21 x L        0
//  22 x sz       0
//  23 1
//  24 1
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// FMUL  <Vd>.<T>, <Vn>.<T>, <Vm>.<Ts>[<index>]
bool TryDecodeFMUL_ASIMDELEM_R_SD(const InstData &, Instruction &) {
  return false;
}

// SHADD SHADD_asimdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 opcode   0
//  12 0 opcode   1
//  13 0 opcode   2
//  14 0 opcode   3
//  15 0 opcode   4
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// SHADD  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeSHADD_ASIMDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// FMINP FMINP_asisdpair_only_H:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 opcode   0
//  13 1 opcode   1
//  14 1 opcode   2
//  15 1 opcode   3
//  16 0 opcode   4
//  17 0
//  18 0
//  19 0
//  20 1
//  21 1
//  22 0 sz       0
//  23 1 o1       0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// FMINP  <V><d>, <Vn>.<T>
bool TryDecodeFMINP_ASISDPAIR_ONLY_H(const InstData &, Instruction &) {
  return false;
}

// FMINP FMINP_asisdpair_only_SD:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 opcode   0
//  13 1 opcode   1
//  14 1 opcode   2
//  15 1 opcode   3
//  16 0 opcode   4
//  17 0
//  18 0
//  19 0
//  20 1
//  21 1
//  22 x sz       0
//  23 1 o1       0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 1 U        0
//  30 1
//  31 0
// FMINP  <V><d>, <Vn>.<T>
bool TryDecodeFMINP_ASISDPAIR_ONLY_SD(const InstData &, Instruction &) {
  return false;
}

// SSUBW SSUBW_asimddiff_W:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1
//  13 1 o1       0
//  14 0
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// SSUBW{2}  <Vd>.<Ta>, <Vn>.<Ta>, <Vm>.<Tb>
bool TryDecodeSSUBW_ASIMDDIFF_W(const InstData &, Instruction &) {
  return false;
}

// UMOV MOV_UMOV_asimdins_W_w:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1 imm4     0
//  12 1 imm4     1
//  13 1 imm4     2
//  14 0 imm4     3
//  15 0
//  16 0 imm5     0
//  17 0 imm5     1
//  18 1 imm5     2
//  19 x imm5     3
//  20 x imm5     4
//  21 0
//  22 0
//  23 0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 op       0
//  30 0 Q        0
//  31 0
// MOV  <Wd>, <Vn>.S[<index>]
bool TryDecodeMOV_UMOV_ASIMDINS_W_W(const InstData &, Instruction &) {
  return false;
}

// UMOV MOV_UMOV_asimdins_X_x:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1 imm4     0
//  12 1 imm4     1
//  13 1 imm4     2
//  14 0 imm4     3
//  15 0
//  16 0 imm5     0
//  17 0 imm5     1
//  18 0 imm5     2
//  19 1 imm5     3
//  20 x imm5     4
//  21 0
//  22 0
//  23 0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 op       0
//  30 1 Q        0
//  31 0
// MOV  <Xd>, <Vn>.D[<index>]
bool TryDecodeMOV_UMOV_ASIMDINS_X_X(const InstData &, Instruction &) {
  return false;
}

// MLS MLS_asimdelem_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 x H        0
//  12 0
//  13 0
//  14 1 o2       0
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x M        0
//  21 x L        0
//  22 x size     0
//  23 x size     1
//  24 1
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// MLS  <Vd>.<T>, <Vn>.<T>, <Vm>.<Ts>[<index>]
bool TryDecodeMLS_ASIMDELEM_R(const InstData &, Instruction &) {
  return false;
}

// SQDMLSL SQDMLSL_asisdelem_L:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 x H        0
//  12 1
//  13 1
//  14 1 o2       0
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x M        0
//  21 x L        0
//  22 x size     0
//  23 x size     1
//  24 1
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// SQDMLSL  <Va><d>, <Vb><n>, <Vm>.<Ts>[<index>]
bool TryDecodeSQDMLSL_ASISDELEM_L(const InstData &, Instruction &) {
  return false;
}

// SQDMLSL SQDMLSL_asimdelem_L:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 x H        0
//  12 1
//  13 1
//  14 1 o2       0
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x M        0
//  21 x L        0
//  22 x size     0
//  23 x size     1
//  24 1
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// SQDMLSL{2}  <Vd>.<Ta>, <Vn>.<Tb>, <Vm>.<Ts>[<index>]
bool TryDecodeSQDMLSL_ASIMDELEM_L(const InstData &, Instruction &) {
  return false;
}


// FCVTZU FCVTZU_asisdshf_C:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1 opcode   0
//  12 1 opcode   1
//  13 1 opcode   2
//  14 1 opcode   3
//  15 1 opcode   4
//  16 x immb     0
//  17 x immb     1
//  18 x immb     2
//  19 x immh     0
//  20 x immh     1
//  21 x immh     2
//  22 x immh     3
//  23 0
//  24 1
//  25 1
//  26 1
//  27 1
//  28 1
//  29 1 U        0
//  30 1
//  31 0
// FCVTZU  <V><d>, <V><n>, #<fbits>
bool TryDecodeFCVTZU_ASISDSHF_C(const InstData &, Instruction &) {
  return false;
}

// FCVTZU FCVTZU_asimdshf_C:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1 opcode   0
//  12 1 opcode   1
//  13 1 opcode   2
//  14 1 opcode   3
//  15 1 opcode   4
//  16 x immb     0
//  17 x immb     1
//  18 x immb     2
//  19 x immh     0
//  20 x immh     1
//  21 x immh     2
//  22 x immh     3
//  23 0
//  24 1
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// FCVTZU  <Vd>.<T>, <Vn>.<T>, #<fbits>
bool TryDecodeFCVTZU_ASIMDSHF_C(const InstData &, Instruction &) {
  return false;
}

// SSHL SSHL_asisdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 S        0
//  12 0 R        0
//  13 0
//  14 1
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// SSHL  <V><d>, <V><n>, <V><m>
bool TryDecodeSSHL_ASISDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// SSHL SSHL_asimdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 S        0
//  12 0 R        0
//  13 0
//  14 1
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// SSHL  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeSSHL_ASIMDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// UBFM UXTB_UBFM_32M_bitfield:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 imms     0
//  11 1 imms     1
//  12 1 imms     2
//  13 0 imms     3
//  14 0 imms     4
//  15 0 imms     5
//  16 0 immr     0
//  17 0 immr     1
//  18 0 immr     2
//  19 0 immr     3
//  20 0 immr     4
//  21 0 immr     5
//  22 0 N        0
//  23 0
//  24 1
//  25 1
//  26 0
//  27 0
//  28 1
//  29 0 opc      0
//  30 1 opc      1
//  31 0 sf       0
// UXTB  <Wd>, <Wn>
bool TryDecodeUXTB_UBFM_32M_BITFIELD(const InstData &, Instruction &) {
  return false;
}

// SSRA SSRA_asisdshf_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0
//  12 1 o0       0
//  13 0 o1       0
//  14 0
//  15 0
//  16 x immb     0
//  17 x immb     1
//  18 x immb     2
//  19 x immh     0
//  20 x immh     1
//  21 x immh     2
//  22 x immh     3
//  23 0
//  24 1
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// SSRA  <V><d>, <V><n>, #<shift>
bool TryDecodeSSRA_ASISDSHF_R(const InstData &, Instruction &) {
  return false;
}

// SSRA SSRA_asimdshf_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0
//  12 1 o0       0
//  13 0 o1       0
//  14 0
//  15 0
//  16 x immb     0
//  17 x immb     1
//  18 x immb     2
//  19 x immh     0
//  20 x immh     1
//  21 x immh     2
//  22 x immh     3
//  23 0
//  24 1
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// SSRA  <Vd>.<T>, <Vn>.<T>, #<shift>
bool TryDecodeSSRA_ASIMDSHF_R(const InstData &, Instruction &) {
  return false;
}

// SQSHL SQSHL_asisdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1 S        0
//  12 0 R        0
//  13 0
//  14 1
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// SQSHL  <V><d>, <V><n>, <V><m>
bool TryDecodeSQSHL_ASISDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// SQSHL SQSHL_asimdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1 S        0
//  12 0 R        0
//  13 0
//  14 1
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// SQSHL  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeSQSHL_ASIMDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// PMUL PMUL_asimdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1 opcode   0
//  12 1 opcode   1
//  13 0 opcode   2
//  14 0 opcode   3
//  15 1 opcode   4
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// PMUL  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodePMUL_ASIMDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// SMLSL SMLSL_asimdelem_L:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 x H        0
//  12 0
//  13 1
//  14 1 o2       0
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x M        0
//  21 x L        0
//  22 x size     0
//  23 x size     1
//  24 1
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// SMLSL{2}  <Vd>.<Ta>, <Vn>.<Tb>, <Vm>.<Ts>[<index>]
bool TryDecodeSMLSL_ASIMDELEM_L(const InstData &, Instruction &) {
  return false;
}

// SUB NEG_SUB_32_addsub_shift:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 1 Rn       0
//   6 1 Rn       1
//   7 1 Rn       2
//   8 1 Rn       3
//   9 1 Rn       4
//  10 x imm6     0
//  11 x imm6     1
//  12 x imm6     2
//  13 x imm6     3
//  14 x imm6     4
//  15 x imm6     5
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 x shift    0
//  23 x shift    1
//  24 1
//  25 1
//  26 0
//  27 1
//  28 0
//  29 0 S        0
//  30 1 op       0
//  31 0 sf       0
// NEG  <Wd>, <Wm>{, <shift> #<amount>}
bool TryDecodeNEG_SUB_32_ADDSUB_SHIFT(const InstData &, Instruction &) {
  return false;
}

// SUB NEG_SUB_64_addsub_shift:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 1 Rn       0
//   6 1 Rn       1
//   7 1 Rn       2
//   8 1 Rn       3
//   9 1 Rn       4
//  10 x imm6     0
//  11 x imm6     1
//  12 x imm6     2
//  13 x imm6     3
//  14 x imm6     4
//  15 x imm6     5
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 x shift    0
//  23 x shift    1
//  24 1
//  25 1
//  26 0
//  27 1
//  28 0
//  29 0 S        0
//  30 1 op       0
//  31 1 sf       0
// NEG  <Xd>, <Xm>{, <shift> #<amount>}
bool TryDecodeNEG_SUB_64_ADDSUB_SHIFT(const InstData &, Instruction &) {
  return false;
}

// FCMP FCMP_H_floatcmp:
//   0 0
//   1 0
//   2 0
//   3 0 opc      0
//   4 0 opc      1
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 1
//  14 0 op       0
//  15 0 op       1
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 1 type     0
//  23 1 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 M        0
// FCMP  <Hn>, <Hm>
bool TryDecodeFCMP_H_FLOATCMP(const InstData &, Instruction &) {
  return false;
}

// FCMP FCMP_HZ_floatcmp:
//   0 0
//   1 0
//   2 0
//   3 1 opc      0
//   4 0 opc      1
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 1
//  14 0 op       0
//  15 0 op       1
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 1 type     0
//  23 1 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 M        0
// FCMP  <Hn>, #0.0
bool TryDecodeFCMP_HZ_FLOATCMP(const InstData &, Instruction &) {
  return false;
}

// SHA1SU0 SHA1SU0_VVV_cryptosha3:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opcode   0
//  13 1 opcode   1
//  14 0 opcode   2
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 0 size     0
//  23 0 size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0
//  30 1
//  31 0
// SHA1SU0  <Vd>.4S, <Vn>.4S, <Vm>.4S
bool TryDecodeSHA1SU0_VVV_CRYPTOSHA3(const InstData &, Instruction &) {
  return false;
}

// STSET STSET_32S_memop:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 1 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 1 size     1
// STSET  <Ws>, [<Xn|SP>]
bool TryDecodeSTSET_32S_MEMOP(const InstData &, Instruction &) {
  return false;
}

// STSETL STSETL_32S_memop:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 1 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 1 size     1
// STSETL  <Ws>, [<Xn|SP>]
bool TryDecodeSTSETL_32S_MEMOP(const InstData &, Instruction &) {
  return false;
}

// STSET STSET_64S_memop:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 1 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 1 size     1
// STSET  <Xs>, [<Xn|SP>]
bool TryDecodeSTSET_64S_MEMOP(const InstData &, Instruction &) {
  return false;
}

// STSETL STSETL_64S_memop:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 1 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 1 size     1
// STSETL  <Xs>, [<Xn|SP>]
bool TryDecodeSTSETL_64S_MEMOP(const InstData &, Instruction &) {
  return false;
}

// MLA MLA_asimdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 opcode   0
//  12 1 opcode   1
//  13 0 opcode   2
//  14 0 opcode   3
//  15 1 opcode   4
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// MLA  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeMLA_ASIMDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// LD3R LD3R_asisdlso_R3:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x size     0
//  11 x size     1
//  12 0 S        0
//  13 1 opcode   0
//  14 1 opcode   1
//  15 1 opcode   2
//  16 0
//  17 0
//  18 0
//  19 0
//  20 0
//  21 0 R        0
//  22 1 L        0
//  23 0
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// LD3R  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T> }, [<Xn|SP>]
bool TryDecodeLD3R_ASISDLSO_R3(const InstData &, Instruction &) {
  return false;
}

// LD3R LD3R_asisdlsop_R3_i:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x size     0
//  11 x size     1
//  12 0 S        0
//  13 1 opcode   0
//  14 1 opcode   1
//  15 1 opcode   2
//  16 1 Rm       0
//  17 1 Rm       1
//  18 1 Rm       2
//  19 1 Rm       3
//  20 1 Rm       4
//  21 0 R        0
//  22 1 L        0
//  23 1
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// LD3R  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T> }, [<Xn|SP>], <imm>
bool TryDecodeLD3R_ASISDLSOP_R3_I(const InstData &, Instruction &) {
  return false;
}

// LD3R LD3R_asisdlsop_RX3_r:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x size     0
//  11 x size     1
//  12 0 S        0
//  13 1 opcode   0
//  14 1 opcode   1
//  15 1 opcode   2
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0 R        0
//  22 1 L        0
//  23 1
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// LD3R  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T> }, [<Xn|SP>], <Xm>
bool TryDecodeLD3R_ASISDLSOP_RX3_R(const InstData &, Instruction &) {
  return false;
}

// PRFM PRFM_P_loadlit:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x imm19    0
//   6 x imm19    1
//   7 x imm19    2
//   8 x imm19    3
//   9 x imm19    4
//  10 x imm19    5
//  11 x imm19    6
//  12 x imm19    7
//  13 x imm19    8
//  14 x imm19    9
//  15 x imm19    10
//  16 x imm19    11
//  17 x imm19    12
//  18 x imm19    13
//  19 x imm19    14
//  20 x imm19    15
//  21 x imm19    16
//  22 x imm19    17
//  23 x imm19    18
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 0
//  30 1 opc      0
//  31 1 opc      1
// PRFM  (<prfop>|#<imm5>), <label>
bool TryDecodePRFM_P_LOADLIT(const InstData &, Instruction &) {
  return false;
}

// CASAB CASAB_C32_ldstexcl:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 Rt2      0
//  11 1 Rt2      1
//  12 1 Rt2      2
//  13 1 Rt2      3
//  14 1 Rt2      4
//  15 0 o0       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1 o1       0
//  22 1 L        0
//  23 1 o2       0
//  24 0
//  25 0
//  26 0
//  27 1
//  28 0
//  29 0
//  30 0 size     0
//  31 0 size     1
// CASAB  <Ws>, <Wt>, [<Xn|SP>{,#0}]
bool TryDecodeCASAB_C32_LDSTEXCL(const InstData &, Instruction &) {
  return false;
}

// CASALB CASALB_C32_ldstexcl:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 Rt2      0
//  11 1 Rt2      1
//  12 1 Rt2      2
//  13 1 Rt2      3
//  14 1 Rt2      4
//  15 1 o0       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1 o1       0
//  22 1 L        0
//  23 1 o2       0
//  24 0
//  25 0
//  26 0
//  27 1
//  28 0
//  29 0
//  30 0 size     0
//  31 0 size     1
// CASALB  <Ws>, <Wt>, [<Xn|SP>{,#0}]
bool TryDecodeCASALB_C32_LDSTEXCL(const InstData &, Instruction &) {
  return false;
}

// CASB CASB_C32_ldstexcl:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 Rt2      0
//  11 1 Rt2      1
//  12 1 Rt2      2
//  13 1 Rt2      3
//  14 1 Rt2      4
//  15 0 o0       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1 o1       0
//  22 0 L        0
//  23 1 o2       0
//  24 0
//  25 0
//  26 0
//  27 1
//  28 0
//  29 0
//  30 0 size     0
//  31 0 size     1
// CASB  <Ws>, <Wt>, [<Xn|SP>{,#0}]
bool TryDecodeCASB_C32_LDSTEXCL(const InstData &, Instruction &) {
  return false;
}

// CASLB CASLB_C32_ldstexcl:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 Rt2      0
//  11 1 Rt2      1
//  12 1 Rt2      2
//  13 1 Rt2      3
//  14 1 Rt2      4
//  15 1 o0       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1 o1       0
//  22 0 L        0
//  23 1 o2       0
//  24 0
//  25 0
//  26 0
//  27 1
//  28 0
//  29 0
//  30 0 size     0
//  31 0 size     1
// CASLB  <Ws>, <Wt>, [<Xn|SP>{,#0}]
bool TryDecodeCASLB_C32_LDSTEXCL(const InstData &, Instruction &) {
  return false;
}

// SUBS NEGS_SUBS_32_addsub_shift:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 1 Rn       0
//   6 1 Rn       1
//   7 1 Rn       2
//   8 1 Rn       3
//   9 1 Rn       4
//  10 x imm6     0
//  11 x imm6     1
//  12 x imm6     2
//  13 x imm6     3
//  14 x imm6     4
//  15 x imm6     5
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 x shift    0
//  23 x shift    1
//  24 1
//  25 1
//  26 0
//  27 1
//  28 0
//  29 1 S        0
//  30 1 op       0
//  31 0 sf       0
// NEGS  <Wd>, <Wm>{, <shift> #<amount>}
bool TryDecodeNEGS_SUBS_32_ADDSUB_SHIFT(const InstData &, Instruction &) {
  return false;
}

// SUBS NEGS_SUBS_64_addsub_shift:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 1 Rn       0
//   6 1 Rn       1
//   7 1 Rn       2
//   8 1 Rn       3
//   9 1 Rn       4
//  10 x imm6     0
//  11 x imm6     1
//  12 x imm6     2
//  13 x imm6     3
//  14 x imm6     4
//  15 x imm6     5
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 x shift    0
//  23 x shift    1
//  24 1
//  25 1
//  26 0
//  27 1
//  28 0
//  29 1 S        0
//  30 1 op       0
//  31 1 sf       0
// NEGS  <Xd>, <Xm>{, <shift> #<amount>}
bool TryDecodeNEGS_SUBS_64_ADDSUB_SHIFT(const InstData &, Instruction &) {
  return false;
}

// LDSMAXAH LDSMAXAH_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 0 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 1 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 0 size     1
// LDSMAXAH  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDSMAXAH_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDSMAXALH LDSMAXALH_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 0 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 1 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 0 size     1
// LDSMAXALH  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDSMAXALH_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDSMAXH LDSMAXH_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 0 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 0 size     1
// LDSMAXH  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDSMAXH_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDSMAXLH LDSMAXLH_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 0 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 0 size     1
// LDSMAXLH  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDSMAXLH_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// UQXTN UQXTN_asisdmisc_N:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 opcode   0
//  13 0 opcode   1
//  14 1 opcode   2
//  15 0 opcode   3
//  16 1 opcode   4
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 1 U        0
//  30 1
//  31 0
// UQXTN  <Vb><d>, <Va><n>
bool TryDecodeUQXTN_ASISDMISC_N(const InstData &, Instruction &) {
  return false;
}

// UQXTN UQXTN_asimdmisc_N:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 opcode   0
//  13 0 opcode   1
//  14 1 opcode   2
//  15 0 opcode   3
//  16 1 opcode   4
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// UQXTN{2}  <Vd>.<Tb>, <Vn>.<Ta>
bool TryDecodeUQXTN_ASIMDMISC_N(const InstData &, Instruction &) {
  return false;
}


// FCVTZS FCVTZS_asisdmiscfp16_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 o1       0
//  13 1
//  14 0
//  15 1
//  16 1
//  17 0
//  18 0
//  19 1
//  20 1
//  21 1
//  22 1
//  23 1 o2       0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// FCVTZS  <Hd>, <Hn>
bool TryDecodeFCVTZS_ASISDMISCFP16_R(const InstData &, Instruction &) {
  return false;
}

// FCVTZS FCVTZS_asisdmisc_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 o1       0
//  13 1
//  14 0
//  15 1
//  16 1
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x sz       0
//  23 1 o2       0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// FCVTZS  <V><d>, <V><n>
bool TryDecodeFCVTZS_ASISDMISC_R(const InstData &, Instruction &) {
  return false;
}

// FCVTZS FCVTZS_asimdmiscfp16_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 o1       0
//  13 1
//  14 0
//  15 1
//  16 1
//  17 0
//  18 0
//  19 1
//  20 1
//  21 1
//  22 1
//  23 1 o2       0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// FCVTZS  <Vd>.<T>, <Vn>.<T>
bool TryDecodeFCVTZS_ASIMDMISCFP16_R(const InstData &, Instruction &) {
  return false;
}

// FCVTZS FCVTZS_asimdmisc_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 o1       0
//  13 1
//  14 0
//  15 1
//  16 1
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x sz       0
//  23 1 o2       0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// FCVTZS  <Vd>.<T>, <Vn>.<T>
bool TryDecodeFCVTZS_ASIMDMISC_R(const InstData &, Instruction &) {
  return false;
}

// FMAXNM FMAXNM_H_floatdp2:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 op       0
//  13 1 op       1
//  14 1
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 1 type     0
//  23 1 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 M        0
// FMAXNM  <Hd>, <Hn>, <Hm>
bool TryDecodeFMAXNM_H_FLOATDP2(const InstData &, Instruction &) {
  return false;
}

// FMAXNM FMAXNM_S_floatdp2:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 op       0
//  13 1 op       1
//  14 1
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 0 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 M        0
// FMAXNM  <Sd>, <Sn>, <Sm>
bool TryDecodeFMAXNM_S_FLOATDP2(const InstData &, Instruction &) {
  return false;
}

// FMAXNM FMAXNM_D_floatdp2:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 op       0
//  13 1 op       1
//  14 1
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 1 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 M        0
// FMAXNM  <Dd>, <Dn>, <Dm>
bool TryDecodeFMAXNM_D_FLOATDP2(const InstData &, Instruction &) {
  return false;
}

// CNT CNT_asimdmisc_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 opcode   0
//  13 0 opcode   1
//  14 1 opcode   2
//  15 0 opcode   3
//  16 0 opcode   4
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// CNT  <Vd>.<T>, <Vn>.<T>
bool TryDecodeCNT_ASIMDMISC_R(const InstData &, Instruction &) {
  return false;
}

// SQSHL SQSHL_asisdshf_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0
//  12 1 op       0
//  13 1
//  14 1
//  15 0
//  16 x immb     0
//  17 x immb     1
//  18 x immb     2
//  19 x immh     0
//  20 x immh     1
//  21 x immh     2
//  22 x immh     3
//  23 0
//  24 1
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// SQSHL  <V><d>, <V><n>, #<shift>
bool TryDecodeSQSHL_ASISDSHF_R(const InstData &, Instruction &) {
  return false;
}

// SQSHL SQSHL_asimdshf_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0
//  12 1 op       0
//  13 1
//  14 1
//  15 0
//  16 x immb     0
//  17 x immb     1
//  18 x immb     2
//  19 x immh     0
//  20 x immh     1
//  21 x immh     2
//  22 x immh     3
//  23 0
//  24 1
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// SQSHL  <Vd>.<T>, <Vn>.<T>, #<shift>
bool TryDecodeSQSHL_ASIMDSHF_R(const InstData &, Instruction &) {
  return false;
}

// LDTR LDTR_32_ldst_unpriv:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 x imm9     0
//  13 x imm9     1
//  14 x imm9     2
//  15 x imm9     3
//  16 x imm9     4
//  17 x imm9     5
//  18 x imm9     6
//  19 x imm9     7
//  20 x imm9     8
//  21 0
//  22 1 opc      0
//  23 0 opc      1
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 1 size     1
// LDTR  <Wt>, [<Xn|SP>{, #<simm>}]
bool TryDecodeLDTR_32_LDST_UNPRIV(const InstData &, Instruction &) {
  return false;
}

// LDTR LDTR_64_ldst_unpriv:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 x imm9     0
//  13 x imm9     1
//  14 x imm9     2
//  15 x imm9     3
//  16 x imm9     4
//  17 x imm9     5
//  18 x imm9     6
//  19 x imm9     7
//  20 x imm9     8
//  21 0
//  22 1 opc      0
//  23 0 opc      1
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 1 size     1
// LDTR  <Xt>, [<Xn|SP>{, #<simm>}]
bool TryDecodeLDTR_64_LDST_UNPRIV(const InstData &, Instruction &) {
  return false;
}

// UZP2 UZP2_asimdperm_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1
//  13 0
//  14 1 op       0
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// UZP2  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeUZP2_ASIMDPERM_ONLY(const InstData &, Instruction &) {
  return false;
}

// SQRDMLSH SQRDMLSH_asisdsame2_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1 S        0
//  12 0
//  13 0
//  14 0
//  15 1
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 1 U        0
//  30 1
//  31 0
// SQRDMLSH  <V><d>, <V><n>, <V><m>
bool TryDecodeSQRDMLSH_ASISDSAME2_ONLY(const InstData &, Instruction &) {
  return false;
}

// SQRDMLSH SQRDMLSH_asimdsame2_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1 S        0
//  12 0
//  13 0
//  14 0
//  15 1
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// SQRDMLSH  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeSQRDMLSH_ASIMDSAME2_ONLY(const InstData &, Instruction &) {
  return false;
}

// INS MOV_INS_asimdins_IR_r:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1 imm4     0
//  12 1 imm4     1
//  13 0 imm4     2
//  14 0 imm4     3
//  15 0
//  16 x imm5     0
//  17 x imm5     1
//  18 x imm5     2
//  19 x imm5     3
//  20 x imm5     4
//  21 0
//  22 0
//  23 0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 op       0
//  30 1 Q        0
//  31 0
// MOV  <Vd>.<Ts>[<index>], <R><n>
bool TryDecodeMOV_INS_ASIMDINS_IR_R(const InstData &, Instruction &) {
  return false;
}

// LDTRSB LDTRSB_32_ldst_unpriv:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 x imm9     0
//  13 x imm9     1
//  14 x imm9     2
//  15 x imm9     3
//  16 x imm9     4
//  17 x imm9     5
//  18 x imm9     6
//  19 x imm9     7
//  20 x imm9     8
//  21 0
//  22 1 opc      0
//  23 1 opc      1
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 0 size     1
// LDTRSB  <Wt>, [<Xn|SP>{, #<simm>}]
bool TryDecodeLDTRSB_32_LDST_UNPRIV(const InstData &, Instruction &) {
  return false;
}

// LDTRSB LDTRSB_64_ldst_unpriv:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 x imm9     0
//  13 x imm9     1
//  14 x imm9     2
//  15 x imm9     3
//  16 x imm9     4
//  17 x imm9     5
//  18 x imm9     6
//  19 x imm9     7
//  20 x imm9     8
//  21 0
//  22 0 opc      0
//  23 1 opc      1
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 0 size     1
// LDTRSB  <Xt>, [<Xn|SP>{, #<simm>}]
bool TryDecodeLDTRSB_64_LDST_UNPRIV(const InstData &, Instruction &) {
  return false;
}

// URHADD URHADD_asimdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 opcode   0
//  12 1 opcode   1
//  13 0 opcode   2
//  14 0 opcode   3
//  15 0 opcode   4
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// URHADD  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeURHADD_ASIMDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// SABD SABD_asimdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 ac       0
//  12 1
//  13 1
//  14 1
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// SABD  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeSABD_ASIMDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// FCMGE FCMGE_asisdsamefp16_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 ac       0
//  12 0
//  13 1
//  14 0
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 1
//  23 0 E        0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 1 U        0
//  30 1
//  31 0
// FCMGE  <Hd>, <Hn>, <Hm>
bool TryDecodeFCMGE_ASISDSAMEFP16_ONLY(const InstData &, Instruction &) {
  return false;
}

// FCMGE FCMGE_asisdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 ac       0
//  12 0
//  13 1
//  14 1
//  15 1
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x sz       0
//  23 0 E        0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 1 U        0
//  30 1
//  31 0
// FCMGE  <V><d>, <V><n>, <V><m>
bool TryDecodeFCMGE_ASISDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// FCMGE FCMGE_asimdsamefp16_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 ac       0
//  12 0
//  13 1
//  14 0
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 1
//  23 0 E        0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// FCMGE  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeFCMGE_ASIMDSAMEFP16_ONLY(const InstData &, Instruction &) {
  return false;
}

// FCMGE FCMGE_asimdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 ac       0
//  12 0
//  13 1
//  14 1
//  15 1
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x sz       0
//  23 0 E        0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// FCMGE  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeFCMGE_ASIMDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// NOT MVN_NOT_asimdmisc_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 opcode   0
//  13 0 opcode   1
//  14 1 opcode   2
//  15 0 opcode   3
//  16 0 opcode   4
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 0 size     0
//  23 0 size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// MVN  <Vd>.<T>, <Vn>.<T>
bool TryDecodeMVN_NOT_ASIMDMISC_R(const InstData &, Instruction &) {
  return false;
}

// STSMIN STSMIN_32S_memop:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 0 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 1 size     1
// STSMIN  <Ws>, [<Xn|SP>]
bool TryDecodeSTSMIN_32S_MEMOP(const InstData &, Instruction &) {
  return false;
}

// STSMINL STSMINL_32S_memop:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 0 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 1 size     1
// STSMINL  <Ws>, [<Xn|SP>]
bool TryDecodeSTSMINL_32S_MEMOP(const InstData &, Instruction &) {
  return false;
}

// STSMIN STSMIN_64S_memop:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 0 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 1 size     1
// STSMIN  <Xs>, [<Xn|SP>]
bool TryDecodeSTSMIN_64S_MEMOP(const InstData &, Instruction &) {
  return false;
}

// STSMINL STSMINL_64S_memop:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 0 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 1 size     1
// STSMINL  <Xs>, [<Xn|SP>]
bool TryDecodeSTSMINL_64S_MEMOP(const InstData &, Instruction &) {
  return false;
}

// TRN1 TRN1_asimdperm_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0
//  13 1
//  14 0 op       0
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// TRN1  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeTRN1_ASIMDPERM_ONLY(const InstData &, Instruction &) {
  return false;
}

// SMULL SMULL_asimddiff_L:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opcode   0
//  13 0 opcode   1
//  14 1 opcode   2
//  15 1 opcode   3
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// SMULL{2}  <Vd>.<Ta>, <Vn>.<Tb>, <Vm>.<Tb>
bool TryDecodeSMULL_ASIMDDIFF_L(const InstData &, Instruction &) {
  return false;
}

// URSQRTE URSQRTE_asimdmisc_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 opcode   0
//  13 0 opcode   1
//  14 1 opcode   2
//  15 1 opcode   3
//  16 1 opcode   4
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x sz       0
//  23 1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// URSQRTE  <Vd>.<T>, <Vn>.<T>
bool TryDecodeURSQRTE_ASIMDMISC_R(const InstData &, Instruction &) {
  return false;
}

// FCCMPE FCCMPE_H_floatccmp:
//   0 x nzcv     0
//   1 x nzcv     1
//   2 x nzcv     2
//   3 x nzcv     3
//   4 1 op       0
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0
//  12 x cond     0
//  13 x cond     1
//  14 x cond     2
//  15 x cond     3
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 1 type     0
//  23 1 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 M        0
// FCCMPE  <Hn>, <Hm>, #<nzcv>, <cond>
bool TryDecodeFCCMPE_H_FLOATCCMP(const InstData &, Instruction &) {
  return false;
}

// FCCMPE FCCMPE_S_floatccmp:
//   0 x nzcv     0
//   1 x nzcv     1
//   2 x nzcv     2
//   3 x nzcv     3
//   4 1 op       0
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0
//  12 x cond     0
//  13 x cond     1
//  14 x cond     2
//  15 x cond     3
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 0 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 M        0
// FCCMPE  <Sn>, <Sm>, #<nzcv>, <cond>
bool TryDecodeFCCMPE_S_FLOATCCMP(const InstData &, Instruction &) {
  return false;
}

// FCCMPE FCCMPE_D_floatccmp:
//   0 x nzcv     0
//   1 x nzcv     1
//   2 x nzcv     2
//   3 x nzcv     3
//   4 1 op       0
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0
//  12 x cond     0
//  13 x cond     1
//  14 x cond     2
//  15 x cond     3
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 1 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 M        0
// FCCMPE  <Dn>, <Dm>, #<nzcv>, <cond>
bool TryDecodeFCCMPE_D_FLOATCCMP(const InstData &, Instruction &) {
  return false;
}

// FMAXP FMAXP_asimdsamefp16_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 opcode   0
//  12 1 opcode   1
//  13 1 opcode   2
//  14 0
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 1
//  23 0 o1       0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// FMAXP  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeFMAXP_ASIMDSAMEFP16_ONLY(const InstData &, Instruction &) {
  return false;
}

// FMAXP FMAXP_asimdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 opcode   0
//  12 1 opcode   1
//  13 1 opcode   2
//  14 1 opcode   3
//  15 1 opcode   4
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x sz       0
//  23 0 o1       0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// FMAXP  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeFMAXP_ASIMDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// MADD MUL_MADD_32A_dp_3src:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 Ra       0
//  11 1 Ra       1
//  12 1 Ra       2
//  13 1 Ra       3
//  14 1 Ra       4
//  15 0 o0       0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0 op31     0
//  22 0 op31     1
//  23 0 op31     2
//  24 1
//  25 1
//  26 0
//  27 1
//  28 1
//  29 0 op54     0
//  30 0 op54     1
//  31 0 sf       0
// MUL  <Wd>, <Wn>, <Wm>
bool TryDecodeMUL_MADD_32A_DP_3SRC(const InstData &, Instruction &) {
  return false;
}

// MADD MUL_MADD_64A_dp_3src:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 Ra       0
//  11 1 Ra       1
//  12 1 Ra       2
//  13 1 Ra       3
//  14 1 Ra       4
//  15 0 o0       0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0 op31     0
//  22 0 op31     1
//  23 0 op31     2
//  24 1
//  25 1
//  26 0
//  27 1
//  28 1
//  29 0 op54     0
//  30 0 op54     1
//  31 1 sf       0
// MUL  <Xd>, <Xn>, <Xm>
bool TryDecodeMUL_MADD_64A_DP_3SRC(const InstData &, Instruction &) {
  return false;
}

// STTR STTR_32_ldst_unpriv:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 x imm9     0
//  13 x imm9     1
//  14 x imm9     2
//  15 x imm9     3
//  16 x imm9     4
//  17 x imm9     5
//  18 x imm9     6
//  19 x imm9     7
//  20 x imm9     8
//  21 0
//  22 0 opc      0
//  23 0 opc      1
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 1 size     1
// STTR  <Wt>, [<Xn|SP>{, #<simm>}]
bool TryDecodeSTTR_32_LDST_UNPRIV(const InstData &, Instruction &) {
  return false;
}

// STTR STTR_64_ldst_unpriv:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 x imm9     0
//  13 x imm9     1
//  14 x imm9     2
//  15 x imm9     3
//  16 x imm9     4
//  17 x imm9     5
//  18 x imm9     6
//  19 x imm9     7
//  20 x imm9     8
//  21 0
//  22 0 opc      0
//  23 0 opc      1
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 1 size     1
// STTR  <Xt>, [<Xn|SP>{, #<simm>}]
bool TryDecodeSTTR_64_LDST_UNPRIV(const InstData &, Instruction &) {
  return false;
}

// FCMGT FCMGT_asisdmiscfp16_FZ:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 op       0
//  13 0
//  14 1
//  15 1
//  16 0
//  17 0
//  18 0
//  19 1
//  20 1
//  21 1
//  22 1
//  23 1 a        0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// FCMGT  <Hd>, <Hn>, #0.0
bool TryDecodeFCMGT_ASISDMISCFP16_FZ(const InstData &, Instruction &) {
  return false;
}

// FCMGT FCMGT_asisdmisc_FZ:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 op       0
//  13 0
//  14 1
//  15 1
//  16 0
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x sz       0
//  23 1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// FCMGT  <V><d>, <V><n>, #0.0
bool TryDecodeFCMGT_ASISDMISC_FZ(const InstData &, Instruction &) {
  return false;
}

// FCMGT FCMGT_asimdmiscfp16_FZ:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 op       0
//  13 0
//  14 1
//  15 1
//  16 0
//  17 0
//  18 0
//  19 1
//  20 1
//  21 1
//  22 1
//  23 1 a        0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// FCMGT  <Vd>.<T>, <Vn>.<T>, #0.0
bool TryDecodeFCMGT_ASIMDMISCFP16_FZ(const InstData &, Instruction &) {
  return false;
}

// FCMGT FCMGT_asimdmisc_FZ:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 op       0
//  13 0
//  14 1
//  15 1
//  16 0
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x sz       0
//  23 1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// FCMGT  <Vd>.<T>, <Vn>.<T>, #0.0
bool TryDecodeFCMGT_ASIMDMISC_FZ(const InstData &, Instruction &) {
  return false;
}

// UQSUB UQSUB_asisdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1 opcode   0
//  12 0 opcode   1
//  13 1 opcode   2
//  14 0 opcode   3
//  15 0 opcode   4
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 1 U        0
//  30 1
//  31 0
// UQSUB  <V><d>, <V><n>, <V><m>
bool TryDecodeUQSUB_ASISDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// UQSUB UQSUB_asimdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1 opcode   0
//  12 0 opcode   1
//  13 1 opcode   2
//  14 0 opcode   3
//  15 0 opcode   4
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// UQSUB  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeUQSUB_ASIMDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// WFI WFI_HI_system:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 1 op2      0
//   6 1 op2      1
//   7 0 op2      2
//   8 0 CRm      0
//   9 0 CRm      1
//  10 0 CRm      2
//  11 0 CRm      3
//  12 0 CRn      0
//  13 1 CRn      1
//  14 0 CRn      2
//  15 0 CRn      3
//  16 1 op1      0
//  17 1 op1      1
//  18 0 op1      2
//  19 0 op0      0
//  20 0 op0      1
//  21 0 L        0
//  22 0
//  23 0
//  24 1
//  25 0
//  26 1
//  27 0
//  28 1
//  29 0
//  30 1
//  31 1
// WFI
bool TryDecodeWFI_HI_SYSTEM(const InstData &, Instruction &) {
  return false;
}

// LDXRH LDXRH_LR32_ldstexcl:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 Rt2      0
//  11 1 Rt2      1
//  12 1 Rt2      2
//  13 1 Rt2      3
//  14 1 Rt2      4
//  15 0 o0       0
//  16 1 Rs       0
//  17 1 Rs       1
//  18 1 Rs       2
//  19 1 Rs       3
//  20 1 Rs       4
//  21 0 o1       0
//  22 1 L        0
//  23 0 o2       0
//  24 0
//  25 0
//  26 0
//  27 1
//  28 0
//  29 0
//  30 1 size     0
//  31 0 size     1
// LDXRH  <Wt>, [<Xn|SP>{,#0}]
bool TryDecodeLDXRH_LR32_LDSTEXCL(const InstData &, Instruction &) {
  return false;
}

// STLRB STLRB_SL32_ldstexcl:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 Rt2      0
//  11 1 Rt2      1
//  12 1 Rt2      2
//  13 1 Rt2      3
//  14 1 Rt2      4
//  15 1 o0       0
//  16 1 Rs       0
//  17 1 Rs       1
//  18 1 Rs       2
//  19 1 Rs       3
//  20 1 Rs       4
//  21 0 o1       0
//  22 0 L        0
//  23 1 o2       0
//  24 0
//  25 0
//  26 0
//  27 1
//  28 0
//  29 0
//  30 0 size     0
//  31 0 size     1
// STLRB  <Wt>, [<Xn|SP>{,#0}]
bool TryDecodeSTLRB_SL32_LDSTEXCL(const InstData &, Instruction &) {
  return false;
}

// ST3 ST3_asisdlse_R3:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x size     0
//  11 x size     1
//  12 0 opcode   0
//  13 0 opcode   1
//  14 1 opcode   2
//  15 0 opcode   3
//  16 0
//  17 0
//  18 0
//  19 0
//  20 0
//  21 0
//  22 0 L        0
//  23 0
//  24 0
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// ST3  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T> }, [<Xn|SP>]
bool TryDecodeST3_ASISDLSE_R3(const InstData &, Instruction &) {
  return false;
}

// ST3 ST3_asisdlsep_I3_i:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x size     0
//  11 x size     1
//  12 0 opcode   0
//  13 0 opcode   1
//  14 1 opcode   2
//  15 0 opcode   3
//  16 1 Rm       0
//  17 1 Rm       1
//  18 1 Rm       2
//  19 1 Rm       3
//  20 1 Rm       4
//  21 0
//  22 0 L        0
//  23 1
//  24 0
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// ST3  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T> }, [<Xn|SP>], <imm>
bool TryDecodeST3_ASISDLSEP_I3_I(const InstData &, Instruction &) {
  return false;
}

// ST3 ST3_asisdlsep_R3_r:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x size     0
//  11 x size     1
//  12 0 opcode   0
//  13 0 opcode   1
//  14 1 opcode   2
//  15 0 opcode   3
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 0 L        0
//  23 1
//  24 0
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// ST3  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T> }, [<Xn|SP>], <Xm>
bool TryDecodeST3_ASISDLSEP_R3_R(const InstData &, Instruction &) {
  return false;
}

// SQRDMULH SQRDMULH_asisdelem_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 x H        0
//  12 1 op       0
//  13 0
//  14 1
//  15 1
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x M        0
//  21 x L        0
//  22 x size     0
//  23 x size     1
//  24 1
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// SQRDMULH  <V><d>, <V><n>, <Vm>.<Ts>[<index>]
bool TryDecodeSQRDMULH_ASISDELEM_R(const InstData &, Instruction &) {
  return false;
}

// SQRDMULH SQRDMULH_asimdelem_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 x H        0
//  12 1 op       0
//  13 0
//  14 1
//  15 1
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x M        0
//  21 x L        0
//  22 x size     0
//  23 x size     1
//  24 1
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// SQRDMULH  <Vd>.<T>, <Vn>.<T>, <Vm>.<Ts>[<index>]
bool TryDecodeSQRDMULH_ASIMDELEM_R(const InstData &, Instruction &) {
  return false;
}

// SBFM SXTW_SBFM_64M_bitfield:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 imms     0
//  11 1 imms     1
//  12 1 imms     2
//  13 1 imms     3
//  14 1 imms     4
//  15 0 imms     5
//  16 0 immr     0
//  17 0 immr     1
//  18 0 immr     2
//  19 0 immr     3
//  20 0 immr     4
//  21 0 immr     5
//  22 1 N        0
//  23 0
//  24 1
//  25 1
//  26 0
//  27 0
//  28 1
//  29 0 opc      0
//  30 0 opc      1
//  31 1 sf       0
// SXTW  <Xd>, <Wn>
bool TryDecodeSXTW_SBFM_64M_BITFIELD(const InstData &, Instruction &) {
  return false;
}

// FCMEQ FCMEQ_asisdmiscfp16_FZ:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 op       0
//  13 0
//  14 1
//  15 1
//  16 0
//  17 0
//  18 0
//  19 1
//  20 1
//  21 1
//  22 1
//  23 1 a        0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// FCMEQ  <Hd>, <Hn>, #0.0
bool TryDecodeFCMEQ_ASISDMISCFP16_FZ(const InstData &, Instruction &) {
  return false;
}

// FCMEQ FCMEQ_asisdmisc_FZ:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 op       0
//  13 0
//  14 1
//  15 1
//  16 0
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x sz       0
//  23 1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// FCMEQ  <V><d>, <V><n>, #0.0
bool TryDecodeFCMEQ_ASISDMISC_FZ(const InstData &, Instruction &) {
  return false;
}

// FCMEQ FCMEQ_asimdmiscfp16_FZ:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 op       0
//  13 0
//  14 1
//  15 1
//  16 0
//  17 0
//  18 0
//  19 1
//  20 1
//  21 1
//  22 1
//  23 1 a        0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// FCMEQ  <Vd>.<T>, <Vn>.<T>, #0.0
bool TryDecodeFCMEQ_ASIMDMISCFP16_FZ(const InstData &, Instruction &) {
  return false;
}

// FCMEQ FCMEQ_asimdmisc_FZ:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 op       0
//  13 0
//  14 1
//  15 1
//  16 0
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x sz       0
//  23 1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// FCMEQ  <Vd>.<T>, <Vn>.<T>, #0.0
bool TryDecodeFCMEQ_ASIMDMISC_FZ(const InstData &, Instruction &) {
  return false;
}

// FACGE FACGE_asisdsamefp16_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1 ac       0
//  12 0
//  13 1
//  14 0
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 1
//  23 0 E        0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 1 U        0
//  30 1
//  31 0
// FACGE  <Hd>, <Hn>, <Hm>
bool TryDecodeFACGE_ASISDSAMEFP16_ONLY(const InstData &, Instruction &) {
  return false;
}

// FACGE FACGE_asisdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1 ac       0
//  12 0
//  13 1
//  14 1
//  15 1
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x sz       0
//  23 0 E        0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 1 U        0
//  30 1
//  31 0
// FACGE  <V><d>, <V><n>, <V><m>
bool TryDecodeFACGE_ASISDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// FACGE FACGE_asimdsamefp16_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1 ac       0
//  12 0
//  13 1
//  14 0
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 1
//  23 0 E        0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// FACGE  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeFACGE_ASIMDSAMEFP16_ONLY(const InstData &, Instruction &) {
  return false;
}

// FACGE FACGE_asimdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1 ac       0
//  12 0
//  13 1
//  14 1
//  15 1
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x sz       0
//  23 0 E        0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// FACGE  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeFACGE_ASIMDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// FCVTAS FCVTAS_32H_float2int:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 0
//  15 0
//  16 0 opcode   0
//  17 0 opcode   1
//  18 1 opcode   2
//  19 0 rmode    0
//  20 0 rmode    1
//  21 1
//  22 1 type     0
//  23 1 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 sf       0
// FCVTAS  <Wd>, <Hn>
bool TryDecodeFCVTAS_32H_FLOAT2INT(const InstData &, Instruction &) {
  return false;
}

// FCVTAS FCVTAS_64H_float2int:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 0
//  15 0
//  16 0 opcode   0
//  17 0 opcode   1
//  18 1 opcode   2
//  19 0 rmode    0
//  20 0 rmode    1
//  21 1
//  22 1 type     0
//  23 1 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 1 sf       0
// FCVTAS  <Xd>, <Hn>
bool TryDecodeFCVTAS_64H_FLOAT2INT(const InstData &, Instruction &) {
  return false;
}

// FCVTAS FCVTAS_32S_float2int:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 0
//  15 0
//  16 0 opcode   0
//  17 0 opcode   1
//  18 1 opcode   2
//  19 0 rmode    0
//  20 0 rmode    1
//  21 1
//  22 0 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 sf       0
// FCVTAS  <Wd>, <Sn>
bool TryDecodeFCVTAS_32S_FLOAT2INT(const InstData &, Instruction &) {
  return false;
}

// FCVTAS FCVTAS_64S_float2int:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 0
//  15 0
//  16 0 opcode   0
//  17 0 opcode   1
//  18 1 opcode   2
//  19 0 rmode    0
//  20 0 rmode    1
//  21 1
//  22 0 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 1 sf       0
// FCVTAS  <Xd>, <Sn>
bool TryDecodeFCVTAS_64S_FLOAT2INT(const InstData &, Instruction &) {
  return false;
}

// FCVTAS FCVTAS_32D_float2int:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 0
//  15 0
//  16 0 opcode   0
//  17 0 opcode   1
//  18 1 opcode   2
//  19 0 rmode    0
//  20 0 rmode    1
//  21 1
//  22 1 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 sf       0
// FCVTAS  <Wd>, <Dn>
bool TryDecodeFCVTAS_32D_FLOAT2INT(const InstData &, Instruction &) {
  return false;
}

// FCVTAS FCVTAS_64D_float2int:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 0
//  15 0
//  16 0 opcode   0
//  17 0 opcode   1
//  18 1 opcode   2
//  19 0 rmode    0
//  20 0 rmode    1
//  21 1
//  22 1 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 1 sf       0
// FCVTAS  <Xd>, <Dn>
bool TryDecodeFCVTAS_64D_FLOAT2INT(const InstData &, Instruction &) {
  return false;
}

// LDURSH LDURSH_64_ldst_unscaled:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 x imm9     0
//  13 x imm9     1
//  14 x imm9     2
//  15 x imm9     3
//  16 x imm9     4
//  17 x imm9     5
//  18 x imm9     6
//  19 x imm9     7
//  20 x imm9     8
//  21 0
//  22 0 opc      0
//  23 1 opc      1
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 0 size     1
// LDURSH  <Xt>, [<Xn|SP>{, #<simm>}]
bool TryDecodeLDURSH_64_LDST_UNSCALED(const InstData &, Instruction &) {
  return false;
}

// SSHLL SXTL_SSHLL_asimdshf_L:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 opcode   0
//  12 0 opcode   1
//  13 1 opcode   2
//  14 0 opcode   3
//  15 1 opcode   4
//  16 0 immb     0
//  17 0 immb     1
//  18 0 immb     2
//  19 x immh     0
//  20 x immh     1
//  21 x immh     2
//  22 x immh     3
//  23 0
//  24 1
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// SXTL{2}  <Vd>.<Ta>, <Vn>.<Tb>
bool TryDecodeSXTL_SSHLL_ASIMDSHF_L(const InstData &, Instruction &) {
  return false;
}

// ST1 ST1_asisdlso_B1_1b:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x size     0
//  11 x size     1
//  12 x S        0
//  13 0 opcode   0
//  14 0 opcode   1
//  15 0 opcode   2
//  16 0
//  17 0
//  18 0
//  19 0
//  20 0
//  21 0 R        0
//  22 0 L        0
//  23 0
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// ST1  { <Vt>.B }[<index>], [<Xn|SP>]
bool TryDecodeST1_ASISDLSO_B1_1B(const InstData &, Instruction &) {
  return false;
}

// ST1 ST1_asisdlso_H1_1h:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0 size     0
//  11 x size     1
//  12 x S        0
//  13 0 opcode   0
//  14 1 opcode   1
//  15 0 opcode   2
//  16 0
//  17 0
//  18 0
//  19 0
//  20 0
//  21 0 R        0
//  22 0 L        0
//  23 0
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// ST1  { <Vt>.H }[<index>], [<Xn|SP>]
bool TryDecodeST1_ASISDLSO_H1_1H(const InstData &, Instruction &) {
  return false;
}

// ST1 ST1_asisdlso_S1_1s:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0 size     0
//  11 0 size     1
//  12 x S        0
//  13 0 opcode   0
//  14 0 opcode   1
//  15 1 opcode   2
//  16 0
//  17 0
//  18 0
//  19 0
//  20 0
//  21 0 R        0
//  22 0 L        0
//  23 0
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// ST1  { <Vt>.S }[<index>], [<Xn|SP>]
bool TryDecodeST1_ASISDLSO_S1_1S(const InstData &, Instruction &) {
  return false;
}

// ST1 ST1_asisdlso_D1_1d:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 size     0
//  11 0 size     1
//  12 0 S        0
//  13 0 opcode   0
//  14 0 opcode   1
//  15 1 opcode   2
//  16 0
//  17 0
//  18 0
//  19 0
//  20 0
//  21 0 R        0
//  22 0 L        0
//  23 0
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// ST1  { <Vt>.D }[<index>], [<Xn|SP>]
bool TryDecodeST1_ASISDLSO_D1_1D(const InstData &, Instruction &) {
  return false;
}

// ST1 ST1_asisdlsop_B1_i1b:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x size     0
//  11 x size     1
//  12 x S        0
//  13 0 opcode   0
//  14 0 opcode   1
//  15 0 opcode   2
//  16 1 Rm       0
//  17 1 Rm       1
//  18 1 Rm       2
//  19 1 Rm       3
//  20 1 Rm       4
//  21 0 R        0
//  22 0 L        0
//  23 1
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// ST1  { <Vt>.B }[<index>], [<Xn|SP>], #1
bool TryDecodeST1_ASISDLSOP_B1_I1B(const InstData &, Instruction &) {
  return false;
}

// ST1 ST1_asisdlsop_BX1_r1b:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x size     0
//  11 x size     1
//  12 x S        0
//  13 0 opcode   0
//  14 0 opcode   1
//  15 0 opcode   2
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0 R        0
//  22 0 L        0
//  23 1
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// ST1  { <Vt>.B }[<index>], [<Xn|SP>], <Xm>
bool TryDecodeST1_ASISDLSOP_BX1_R1B(const InstData &, Instruction &) {
  return false;
}

// ST1 ST1_asisdlsop_H1_i1h:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0 size     0
//  11 x size     1
//  12 x S        0
//  13 0 opcode   0
//  14 1 opcode   1
//  15 0 opcode   2
//  16 1 Rm       0
//  17 1 Rm       1
//  18 1 Rm       2
//  19 1 Rm       3
//  20 1 Rm       4
//  21 0 R        0
//  22 0 L        0
//  23 1
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// ST1  { <Vt>.H }[<index>], [<Xn|SP>], #2
bool TryDecodeST1_ASISDLSOP_H1_I1H(const InstData &, Instruction &) {
  return false;
}

// ST1 ST1_asisdlsop_HX1_r1h:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0 size     0
//  11 x size     1
//  12 x S        0
//  13 0 opcode   0
//  14 1 opcode   1
//  15 0 opcode   2
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0 R        0
//  22 0 L        0
//  23 1
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// ST1  { <Vt>.H }[<index>], [<Xn|SP>], <Xm>
bool TryDecodeST1_ASISDLSOP_HX1_R1H(const InstData &, Instruction &) {
  return false;
}

// ST1 ST1_asisdlsop_S1_i1s:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0 size     0
//  11 0 size     1
//  12 x S        0
//  13 0 opcode   0
//  14 0 opcode   1
//  15 1 opcode   2
//  16 1 Rm       0
//  17 1 Rm       1
//  18 1 Rm       2
//  19 1 Rm       3
//  20 1 Rm       4
//  21 0 R        0
//  22 0 L        0
//  23 1
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// ST1  { <Vt>.S }[<index>], [<Xn|SP>], #4
bool TryDecodeST1_ASISDLSOP_S1_I1S(const InstData &, Instruction &) {
  return false;
}

// ST1 ST1_asisdlsop_SX1_r1s:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0 size     0
//  11 0 size     1
//  12 x S        0
//  13 0 opcode   0
//  14 0 opcode   1
//  15 1 opcode   2
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0 R        0
//  22 0 L        0
//  23 1
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// ST1  { <Vt>.S }[<index>], [<Xn|SP>], <Xm>
bool TryDecodeST1_ASISDLSOP_SX1_R1S(const InstData &, Instruction &) {
  return false;
}

// ST1 ST1_asisdlsop_D1_i1d:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 size     0
//  11 0 size     1
//  12 0 S        0
//  13 0 opcode   0
//  14 0 opcode   1
//  15 1 opcode   2
//  16 1 Rm       0
//  17 1 Rm       1
//  18 1 Rm       2
//  19 1 Rm       3
//  20 1 Rm       4
//  21 0 R        0
//  22 0 L        0
//  23 1
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// ST1  { <Vt>.D }[<index>], [<Xn|SP>], #8
bool TryDecodeST1_ASISDLSOP_D1_I1D(const InstData &, Instruction &) {
  return false;
}

// ST1 ST1_asisdlsop_DX1_r1d:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 size     0
//  11 0 size     1
//  12 0 S        0
//  13 0 opcode   0
//  14 0 opcode   1
//  15 1 opcode   2
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0 R        0
//  22 0 L        0
//  23 1
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// ST1  { <Vt>.D }[<index>], [<Xn|SP>], <Xm>
bool TryDecodeST1_ASISDLSOP_DX1_R1D(const InstData &, Instruction &) {
  return false;
}

// UZP1 UZP1_asimdperm_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1
//  13 0
//  14 0 op       0
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// UZP1  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeUZP1_ASIMDPERM_ONLY(const InstData &, Instruction &) {
  return false;
}

// MLA MLA_asimdelem_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 x H        0
//  12 0
//  13 0
//  14 0 o2       0
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x M        0
//  21 x L        0
//  22 x size     0
//  23 x size     1
//  24 1
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// MLA  <Vd>.<T>, <Vn>.<T>, <Vm>.<Ts>[<index>]
bool TryDecodeMLA_ASIMDELEM_R(const InstData &, Instruction &) {
  return false;
}

// FCVTPU FCVTPU_32H_float2int:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 0
//  15 0
//  16 1 opcode   0
//  17 0 opcode   1
//  18 0 opcode   2
//  19 1 rmode    0
//  20 0 rmode    1
//  21 1
//  22 1 type     0
//  23 1 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 sf       0
// FCVTPU  <Wd>, <Hn>
bool TryDecodeFCVTPU_32H_FLOAT2INT(const InstData &, Instruction &) {
  return false;
}

// FCVTPU FCVTPU_64H_float2int:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 0
//  15 0
//  16 1 opcode   0
//  17 0 opcode   1
//  18 0 opcode   2
//  19 1 rmode    0
//  20 0 rmode    1
//  21 1
//  22 1 type     0
//  23 1 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 1 sf       0
// FCVTPU  <Xd>, <Hn>
bool TryDecodeFCVTPU_64H_FLOAT2INT(const InstData &, Instruction &) {
  return false;
}

// FCVTPU FCVTPU_32S_float2int:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 0
//  15 0
//  16 1 opcode   0
//  17 0 opcode   1
//  18 0 opcode   2
//  19 1 rmode    0
//  20 0 rmode    1
//  21 1
//  22 0 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 sf       0
// FCVTPU  <Wd>, <Sn>
bool TryDecodeFCVTPU_32S_FLOAT2INT(const InstData &, Instruction &) {
  return false;
}

// FCVTPU FCVTPU_64S_float2int:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 0
//  15 0
//  16 1 opcode   0
//  17 0 opcode   1
//  18 0 opcode   2
//  19 1 rmode    0
//  20 0 rmode    1
//  21 1
//  22 0 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 1 sf       0
// FCVTPU  <Xd>, <Sn>
bool TryDecodeFCVTPU_64S_FLOAT2INT(const InstData &, Instruction &) {
  return false;
}

// FCVTPU FCVTPU_32D_float2int:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 0
//  15 0
//  16 1 opcode   0
//  17 0 opcode   1
//  18 0 opcode   2
//  19 1 rmode    0
//  20 0 rmode    1
//  21 1
//  22 1 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 sf       0
// FCVTPU  <Wd>, <Dn>
bool TryDecodeFCVTPU_32D_FLOAT2INT(const InstData &, Instruction &) {
  return false;
}

// FCVTPU FCVTPU_64D_float2int:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 0
//  15 0
//  16 1 opcode   0
//  17 0 opcode   1
//  18 0 opcode   2
//  19 1 rmode    0
//  20 0 rmode    1
//  21 1
//  22 1 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 1 sf       0
// FCVTPU  <Xd>, <Dn>
bool TryDecodeFCVTPU_64D_FLOAT2INT(const InstData &, Instruction &) {
  return false;
}

// STSETH STSETH_32S_memop:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 1 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 0 size     1
// STSETH  <Ws>, [<Xn|SP>]
bool TryDecodeSTSETH_32S_MEMOP(const InstData &, Instruction &) {
  return false;
}

// STSETLH STSETLH_32S_memop:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 1 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 0 size     1
// STSETLH  <Ws>, [<Xn|SP>]
bool TryDecodeSTSETLH_32S_MEMOP(const InstData &, Instruction &) {
  return false;
}

// DSB DSB_BO_system:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 0 opc      0
//   6 0 opc      1
//   7 1
//   8 x CRm      0
//   9 x CRm      1
//  10 x CRm      2
//  11 x CRm      3
//  12 1 CRn      0
//  13 1 CRn      1
//  14 0 CRn      2
//  15 0 CRn      3
//  16 1 op1      0
//  17 1 op1      1
//  18 0 op1      2
//  19 0 op0      0
//  20 0 op0      1
//  21 0 L        0
//  22 0
//  23 0
//  24 1
//  25 0
//  26 1
//  27 0
//  28 1
//  29 0
//  30 1
//  31 1
// DSB  <option>|#<imm>
bool TryDecodeDSB_BO_SYSTEM(const InstData &, Instruction &) {
  return false;
}

// FCVTMS FCVTMS_32H_float2int:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 0
//  15 0
//  16 0 opcode   0
//  17 0 opcode   1
//  18 0 opcode   2
//  19 0 rmode    0
//  20 1 rmode    1
//  21 1
//  22 1 type     0
//  23 1 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 sf       0
// FCVTMS  <Wd>, <Hn>
bool TryDecodeFCVTMS_32H_FLOAT2INT(const InstData &, Instruction &) {
  return false;
}

// FCVTMS FCVTMS_64H_float2int:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 0
//  15 0
//  16 0 opcode   0
//  17 0 opcode   1
//  18 0 opcode   2
//  19 0 rmode    0
//  20 1 rmode    1
//  21 1
//  22 1 type     0
//  23 1 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 1 sf       0
// FCVTMS  <Xd>, <Hn>
bool TryDecodeFCVTMS_64H_FLOAT2INT(const InstData &, Instruction &) {
  return false;
}

// FCVTMS FCVTMS_32S_float2int:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 0
//  15 0
//  16 0 opcode   0
//  17 0 opcode   1
//  18 0 opcode   2
//  19 0 rmode    0
//  20 1 rmode    1
//  21 1
//  22 0 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 sf       0
// FCVTMS  <Wd>, <Sn>
bool TryDecodeFCVTMS_32S_FLOAT2INT(const InstData &, Instruction &) {
  return false;
}

// FCVTMS FCVTMS_64S_float2int:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 0
//  15 0
//  16 0 opcode   0
//  17 0 opcode   1
//  18 0 opcode   2
//  19 0 rmode    0
//  20 1 rmode    1
//  21 1
//  22 0 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 1 sf       0
// FCVTMS  <Xd>, <Sn>
bool TryDecodeFCVTMS_64S_FLOAT2INT(const InstData &, Instruction &) {
  return false;
}

// FCVTMS FCVTMS_32D_float2int:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 0
//  15 0
//  16 0 opcode   0
//  17 0 opcode   1
//  18 0 opcode   2
//  19 0 rmode    0
//  20 1 rmode    1
//  21 1
//  22 1 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 sf       0
// FCVTMS  <Wd>, <Dn>
bool TryDecodeFCVTMS_32D_FLOAT2INT(const InstData &, Instruction &) {
  return false;
}

// FCVTMS FCVTMS_64D_float2int:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 0
//  15 0
//  16 0 opcode   0
//  17 0 opcode   1
//  18 0 opcode   2
//  19 0 rmode    0
//  20 1 rmode    1
//  21 1
//  22 1 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 1 sf       0
// FCVTMS  <Xd>, <Dn>
bool TryDecodeFCVTMS_64D_FLOAT2INT(const InstData &, Instruction &) {
  return false;
}

// STSMINH STSMINH_32S_memop:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 0 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 0 size     1
// STSMINH  <Ws>, [<Xn|SP>]
bool TryDecodeSTSMINH_32S_MEMOP(const InstData &, Instruction &) {
  return false;
}

// STSMINLH STSMINLH_32S_memop:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 0 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 0 size     1
// STSMINLH  <Ws>, [<Xn|SP>]
bool TryDecodeSTSMINLH_32S_MEMOP(const InstData &, Instruction &) {
  return false;
}

// ST4 ST4_asisdlso_B4_4b:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x size     0
//  11 x size     1
//  12 x S        0
//  13 1 opcode   0
//  14 0 opcode   1
//  15 0 opcode   2
//  16 0
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1 R        0
//  22 0 L        0
//  23 0
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// ST4  { <Vt>.B, <Vt2>.B, <Vt3>.B, <Vt4>.B }[<index>], [<Xn|SP>]
bool TryDecodeST4_ASISDLSO_B4_4B(const InstData &, Instruction &) {
  return false;
}

// ST4 ST4_asisdlso_H4_4h:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0 size     0
//  11 x size     1
//  12 x S        0
//  13 1 opcode   0
//  14 1 opcode   1
//  15 0 opcode   2
//  16 0
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1 R        0
//  22 0 L        0
//  23 0
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// ST4  { <Vt>.H, <Vt2>.H, <Vt3>.H, <Vt4>.H }[<index>], [<Xn|SP>]
bool TryDecodeST4_ASISDLSO_H4_4H(const InstData &, Instruction &) {
  return false;
}

// ST4 ST4_asisdlso_S4_4s:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0 size     0
//  11 0 size     1
//  12 x S        0
//  13 1 opcode   0
//  14 0 opcode   1
//  15 1 opcode   2
//  16 0
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1 R        0
//  22 0 L        0
//  23 0
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// ST4  { <Vt>.S, <Vt2>.S, <Vt3>.S, <Vt4>.S }[<index>], [<Xn|SP>]
bool TryDecodeST4_ASISDLSO_S4_4S(const InstData &, Instruction &) {
  return false;
}

// ST4 ST4_asisdlso_D4_4d:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 size     0
//  11 0 size     1
//  12 0 S        0
//  13 1 opcode   0
//  14 0 opcode   1
//  15 1 opcode   2
//  16 0
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1 R        0
//  22 0 L        0
//  23 0
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// ST4  { <Vt>.D, <Vt2>.D, <Vt3>.D, <Vt4>.D }[<index>], [<Xn|SP>]
bool TryDecodeST4_ASISDLSO_D4_4D(const InstData &, Instruction &) {
  return false;
}

// ST4 ST4_asisdlsop_B4_i4b:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x size     0
//  11 x size     1
//  12 x S        0
//  13 1 opcode   0
//  14 0 opcode   1
//  15 0 opcode   2
//  16 1 Rm       0
//  17 1 Rm       1
//  18 1 Rm       2
//  19 1 Rm       3
//  20 1 Rm       4
//  21 1 R        0
//  22 0 L        0
//  23 1
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// ST4  { <Vt>.B, <Vt2>.B, <Vt3>.B, <Vt4>.B }[<index>], [<Xn|SP>], #4
bool TryDecodeST4_ASISDLSOP_B4_I4B(const InstData &, Instruction &) {
  return false;
}

// ST4 ST4_asisdlsop_BX4_r4b:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x size     0
//  11 x size     1
//  12 x S        0
//  13 1 opcode   0
//  14 0 opcode   1
//  15 0 opcode   2
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1 R        0
//  22 0 L        0
//  23 1
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// ST4  { <Vt>.B, <Vt2>.B, <Vt3>.B, <Vt4>.B }[<index>], [<Xn|SP>], <Xm>
bool TryDecodeST4_ASISDLSOP_BX4_R4B(const InstData &, Instruction &) {
  return false;
}

// ST4 ST4_asisdlsop_H4_i4h:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0 size     0
//  11 x size     1
//  12 x S        0
//  13 1 opcode   0
//  14 1 opcode   1
//  15 0 opcode   2
//  16 1 Rm       0
//  17 1 Rm       1
//  18 1 Rm       2
//  19 1 Rm       3
//  20 1 Rm       4
//  21 1 R        0
//  22 0 L        0
//  23 1
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// ST4  { <Vt>.H, <Vt2>.H, <Vt3>.H, <Vt4>.H }[<index>], [<Xn|SP>], #8
bool TryDecodeST4_ASISDLSOP_H4_I4H(const InstData &, Instruction &) {
  return false;
}

// ST4 ST4_asisdlsop_HX4_r4h:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0 size     0
//  11 x size     1
//  12 x S        0
//  13 1 opcode   0
//  14 1 opcode   1
//  15 0 opcode   2
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1 R        0
//  22 0 L        0
//  23 1
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// ST4  { <Vt>.H, <Vt2>.H, <Vt3>.H, <Vt4>.H }[<index>], [<Xn|SP>], <Xm>
bool TryDecodeST4_ASISDLSOP_HX4_R4H(const InstData &, Instruction &) {
  return false;
}

// ST4 ST4_asisdlsop_S4_i4s:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0 size     0
//  11 0 size     1
//  12 x S        0
//  13 1 opcode   0
//  14 0 opcode   1
//  15 1 opcode   2
//  16 1 Rm       0
//  17 1 Rm       1
//  18 1 Rm       2
//  19 1 Rm       3
//  20 1 Rm       4
//  21 1 R        0
//  22 0 L        0
//  23 1
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// ST4  { <Vt>.S, <Vt2>.S, <Vt3>.S, <Vt4>.S }[<index>], [<Xn|SP>], #16
bool TryDecodeST4_ASISDLSOP_S4_I4S(const InstData &, Instruction &) {
  return false;
}

// ST4 ST4_asisdlsop_SX4_r4s:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0 size     0
//  11 0 size     1
//  12 x S        0
//  13 1 opcode   0
//  14 0 opcode   1
//  15 1 opcode   2
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1 R        0
//  22 0 L        0
//  23 1
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// ST4  { <Vt>.S, <Vt2>.S, <Vt3>.S, <Vt4>.S }[<index>], [<Xn|SP>], <Xm>
bool TryDecodeST4_ASISDLSOP_SX4_R4S(const InstData &, Instruction &) {
  return false;
}

// ST4 ST4_asisdlsop_D4_i4d:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 size     0
//  11 0 size     1
//  12 0 S        0
//  13 1 opcode   0
//  14 0 opcode   1
//  15 1 opcode   2
//  16 1 Rm       0
//  17 1 Rm       1
//  18 1 Rm       2
//  19 1 Rm       3
//  20 1 Rm       4
//  21 1 R        0
//  22 0 L        0
//  23 1
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// ST4  { <Vt>.D, <Vt2>.D, <Vt3>.D, <Vt4>.D }[<index>], [<Xn|SP>], #32
bool TryDecodeST4_ASISDLSOP_D4_I4D(const InstData &, Instruction &) {
  return false;
}

// ST4 ST4_asisdlsop_DX4_r4d:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 size     0
//  11 0 size     1
//  12 0 S        0
//  13 1 opcode   0
//  14 0 opcode   1
//  15 1 opcode   2
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1 R        0
//  22 0 L        0
//  23 1
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// ST4  { <Vt>.D, <Vt2>.D, <Vt3>.D, <Vt4>.D }[<index>], [<Xn|SP>], <Xm>
bool TryDecodeST4_ASISDLSOP_DX4_R4D(const InstData &, Instruction &) {
  return false;
}

// LDNP LDNP_S_ldstnapair_offs:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x Rt2      0
//  11 x Rt2      1
//  12 x Rt2      2
//  13 x Rt2      3
//  14 x Rt2      4
//  15 x imm7     0
//  16 x imm7     1
//  17 x imm7     2
//  18 x imm7     3
//  19 x imm7     4
//  20 x imm7     5
//  21 x imm7     6
//  22 1 L        0
//  23 0
//  24 0
//  25 0
//  26 1 V        0
//  27 1
//  28 0
//  29 1
//  30 0 opc      0
//  31 0 opc      1
// LDNP  <St1>, <St2>, [<Xn|SP>{, #<imm>}]
bool TryDecodeLDNP_S_LDSTNAPAIR_OFFS(const InstData &, Instruction &) {
  return false;
}

// LDNP LDNP_D_ldstnapair_offs:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x Rt2      0
//  11 x Rt2      1
//  12 x Rt2      2
//  13 x Rt2      3
//  14 x Rt2      4
//  15 x imm7     0
//  16 x imm7     1
//  17 x imm7     2
//  18 x imm7     3
//  19 x imm7     4
//  20 x imm7     5
//  21 x imm7     6
//  22 1 L        0
//  23 0
//  24 0
//  25 0
//  26 1 V        0
//  27 1
//  28 0
//  29 1
//  30 1 opc      0
//  31 0 opc      1
// LDNP  <Dt1>, <Dt2>, [<Xn|SP>{, #<imm>}]
bool TryDecodeLDNP_D_LDSTNAPAIR_OFFS(const InstData &, Instruction &) {
  return false;
}

// LDNP LDNP_Q_ldstnapair_offs:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x Rt2      0
//  11 x Rt2      1
//  12 x Rt2      2
//  13 x Rt2      3
//  14 x Rt2      4
//  15 x imm7     0
//  16 x imm7     1
//  17 x imm7     2
//  18 x imm7     3
//  19 x imm7     4
//  20 x imm7     5
//  21 x imm7     6
//  22 1 L        0
//  23 0
//  24 0
//  25 0
//  26 1 V        0
//  27 1
//  28 0
//  29 1
//  30 0 opc      0
//  31 1 opc      1
// LDNP  <Qt1>, <Qt2>, [<Xn|SP>{, #<imm>}]
bool TryDecodeLDNP_Q_LDSTNAPAIR_OFFS(const InstData &, Instruction &) {
  return false;
}

// URSHL URSHL_asisdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 S        0
//  12 1 R        0
//  13 0
//  14 1
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 1 U        0
//  30 1
//  31 0
// URSHL  <V><d>, <V><n>, <V><m>
bool TryDecodeURSHL_ASISDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// URSHL URSHL_asimdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 S        0
//  12 1 R        0
//  13 0
//  14 1
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// URSHL  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeURSHL_ASIMDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// SQRSHRUN SQRSHRUN_asisdshf_N:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1 op       0
//  12 0
//  13 0
//  14 0
//  15 1
//  16 x immb     0
//  17 x immb     1
//  18 x immb     2
//  19 x immh     0
//  20 x immh     1
//  21 x immh     2
//  22 x immh     3
//  23 0
//  24 1
//  25 1
//  26 1
//  27 1
//  28 1
//  29 1 U        0
//  30 1
//  31 0
// SQRSHRUN  <Vb><d>, <Va><n>, #<shift>
bool TryDecodeSQRSHRUN_ASISDSHF_N(const InstData &, Instruction &) {
  return false;
}

// SQRSHRUN SQRSHRUN_asimdshf_N:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1 op       0
//  12 0
//  13 0
//  14 0
//  15 1
//  16 x immb     0
//  17 x immb     1
//  18 x immb     2
//  19 x immh     0
//  20 x immh     1
//  21 x immh     2
//  22 x immh     3
//  23 0
//  24 1
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// SQRSHRUN{2}  <Vd>.<Tb>, <Vn>.<Ta>, #<shift>
bool TryDecodeSQRSHRUN_ASIMDSHF_N(const InstData &, Instruction &) {
  return false;
}

// EXTR ROR_EXTR_32_extract:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x imms     0
//  11 x imms     1
//  12 x imms     2
//  13 x imms     3
//  14 x imms     4
//  15 0 imms     5
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0 o0       0
//  22 0 N        0
//  23 1
//  24 1
//  25 1
//  26 0
//  27 0
//  28 1
//  29 0 op21     0
//  30 0 op21     1
//  31 0 sf       0
// ROR  <Wd>, <Ws>, #<shift>
bool TryDecodeROR_EXTR_32_EXTRACT(const InstData &, Instruction &) {
  return false;
}

// EXTR ROR_EXTR_64_extract:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x imms     0
//  11 x imms     1
//  12 x imms     2
//  13 x imms     3
//  14 x imms     4
//  15 x imms     5
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0 o0       0
//  22 1 N        0
//  23 1
//  24 1
//  25 1
//  26 0
//  27 0
//  28 1
//  29 0 op21     0
//  30 0 op21     1
//  31 1 sf       0
// ROR  <Xd>, <Xs>, #<shift>
bool TryDecodeROR_EXTR_64_EXTRACT(const InstData &, Instruction &) {
  return false;
}

// FRINTI FRINTI_asimdmiscfp16_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 o1       0
//  13 0
//  14 0
//  15 1
//  16 1
//  17 0
//  18 0
//  19 1
//  20 1
//  21 1
//  22 1
//  23 1 o2       0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// FRINTI  <Vd>.<T>, <Vn>.<T>
bool TryDecodeFRINTI_ASIMDMISCFP16_R(const InstData &, Instruction &) {
  return false;
}

// FRINTI FRINTI_asimdmisc_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 o1       0
//  13 0
//  14 0
//  15 1
//  16 1
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x sz       0
//  23 1 o2       0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// FRINTI  <Vd>.<T>, <Vn>.<T>
bool TryDecodeFRINTI_ASIMDMISC_R(const InstData &, Instruction &) {
  return false;
}

// LDXRB LDXRB_LR32_ldstexcl:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 Rt2      0
//  11 1 Rt2      1
//  12 1 Rt2      2
//  13 1 Rt2      3
//  14 1 Rt2      4
//  15 0 o0       0
//  16 1 Rs       0
//  17 1 Rs       1
//  18 1 Rs       2
//  19 1 Rs       3
//  20 1 Rs       4
//  21 0 o1       0
//  22 1 L        0
//  23 0 o2       0
//  24 0
//  25 0
//  26 0
//  27 1
//  28 0
//  29 0
//  30 0 size     0
//  31 0 size     1
// LDXRB  <Wt>, [<Xn|SP>{,#0}]
bool TryDecodeLDXRB_LR32_LDSTEXCL(const InstData &, Instruction &) {
  return false;
}

// STP STP_S_ldstpair_post:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x Rt2      0
//  11 x Rt2      1
//  12 x Rt2      2
//  13 x Rt2      3
//  14 x Rt2      4
//  15 x imm7     0
//  16 x imm7     1
//  17 x imm7     2
//  18 x imm7     3
//  19 x imm7     4
//  20 x imm7     5
//  21 x imm7     6
//  22 0 L        0
//  23 1
//  24 0
//  25 0
//  26 1 V        0
//  27 1
//  28 0
//  29 1
//  30 0 opc      0
//  31 0 opc      1
// STP  <St1>, <St2>, [<Xn|SP>], #<imm>
bool TryDecodeSTP_S_LDSTPAIR_POST(const InstData &, Instruction &) {
  return false;
}

// STP STP_D_ldstpair_post:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x Rt2      0
//  11 x Rt2      1
//  12 x Rt2      2
//  13 x Rt2      3
//  14 x Rt2      4
//  15 x imm7     0
//  16 x imm7     1
//  17 x imm7     2
//  18 x imm7     3
//  19 x imm7     4
//  20 x imm7     5
//  21 x imm7     6
//  22 0 L        0
//  23 1
//  24 0
//  25 0
//  26 1 V        0
//  27 1
//  28 0
//  29 1
//  30 1 opc      0
//  31 0 opc      1
// STP  <Dt1>, <Dt2>, [<Xn|SP>], #<imm>
bool TryDecodeSTP_D_LDSTPAIR_POST(const InstData &, Instruction &) {
  return false;
}

// STP STP_Q_ldstpair_post:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x Rt2      0
//  11 x Rt2      1
//  12 x Rt2      2
//  13 x Rt2      3
//  14 x Rt2      4
//  15 x imm7     0
//  16 x imm7     1
//  17 x imm7     2
//  18 x imm7     3
//  19 x imm7     4
//  20 x imm7     5
//  21 x imm7     6
//  22 0 L        0
//  23 1
//  24 0
//  25 0
//  26 1 V        0
//  27 1
//  28 0
//  29 1
//  30 0 opc      0
//  31 1 opc      1
// STP  <Qt1>, <Qt2>, [<Xn|SP>], #<imm>
bool TryDecodeSTP_Q_LDSTPAIR_POST(const InstData &, Instruction &) {
  return false;
}

// STP STP_S_ldstpair_pre:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x Rt2      0
//  11 x Rt2      1
//  12 x Rt2      2
//  13 x Rt2      3
//  14 x Rt2      4
//  15 x imm7     0
//  16 x imm7     1
//  17 x imm7     2
//  18 x imm7     3
//  19 x imm7     4
//  20 x imm7     5
//  21 x imm7     6
//  22 0 L        0
//  23 1
//  24 1
//  25 0
//  26 1 V        0
//  27 1
//  28 0
//  29 1
//  30 0 opc      0
//  31 0 opc      1
// STP  <St1>, <St2>, [<Xn|SP>, #<imm>]!
bool TryDecodeSTP_S_LDSTPAIR_PRE(const InstData &, Instruction &) {
  return false;
}

// STP STP_D_ldstpair_pre:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x Rt2      0
//  11 x Rt2      1
//  12 x Rt2      2
//  13 x Rt2      3
//  14 x Rt2      4
//  15 x imm7     0
//  16 x imm7     1
//  17 x imm7     2
//  18 x imm7     3
//  19 x imm7     4
//  20 x imm7     5
//  21 x imm7     6
//  22 0 L        0
//  23 1
//  24 1
//  25 0
//  26 1 V        0
//  27 1
//  28 0
//  29 1
//  30 1 opc      0
//  31 0 opc      1
// STP  <Dt1>, <Dt2>, [<Xn|SP>, #<imm>]!
bool TryDecodeSTP_D_LDSTPAIR_PRE(const InstData &, Instruction &) {
  return false;
}

// STP STP_Q_ldstpair_pre:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x Rt2      0
//  11 x Rt2      1
//  12 x Rt2      2
//  13 x Rt2      3
//  14 x Rt2      4
//  15 x imm7     0
//  16 x imm7     1
//  17 x imm7     2
//  18 x imm7     3
//  19 x imm7     4
//  20 x imm7     5
//  21 x imm7     6
//  22 0 L        0
//  23 1
//  24 1
//  25 0
//  26 1 V        0
//  27 1
//  28 0
//  29 1
//  30 0 opc      0
//  31 1 opc      1
// STP  <Qt1>, <Qt2>, [<Xn|SP>, #<imm>]!
bool TryDecodeSTP_Q_LDSTPAIR_PRE(const InstData &, Instruction &) {
  return false;
}

// LDSMINAB LDSMINAB_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 0 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 1 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 0 size     1
// LDSMINAB  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDSMINAB_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDSMINALB LDSMINALB_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 0 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 1 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 0 size     1
// LDSMINALB  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDSMINALB_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDSMINB LDSMINB_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 0 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 0 size     1
// LDSMINB  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDSMINB_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDSMINLB LDSMINLB_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 0 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 0 size     1
// LDSMINLB  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDSMINLB_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LD4 LD4_asisdlso_B4_4b:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x size     0
//  11 x size     1
//  12 x S        0
//  13 1 opcode   0
//  14 0 opcode   1
//  15 0 opcode   2
//  16 0
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1 R        0
//  22 1 L        0
//  23 0
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// LD4  { <Vt>.B, <Vt2>.B, <Vt3>.B, <Vt4>.B }[<index>], [<Xn|SP>]
bool TryDecodeLD4_ASISDLSO_B4_4B(const InstData &, Instruction &) {
  return false;
}

// LD4 LD4_asisdlso_H4_4h:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0 size     0
//  11 x size     1
//  12 x S        0
//  13 1 opcode   0
//  14 1 opcode   1
//  15 0 opcode   2
//  16 0
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1 R        0
//  22 1 L        0
//  23 0
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// LD4  { <Vt>.H, <Vt2>.H, <Vt3>.H, <Vt4>.H }[<index>], [<Xn|SP>]
bool TryDecodeLD4_ASISDLSO_H4_4H(const InstData &, Instruction &) {
  return false;
}

// LD4 LD4_asisdlso_S4_4s:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0 size     0
//  11 0 size     1
//  12 x S        0
//  13 1 opcode   0
//  14 0 opcode   1
//  15 1 opcode   2
//  16 0
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1 R        0
//  22 1 L        0
//  23 0
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// LD4  { <Vt>.S, <Vt2>.S, <Vt3>.S, <Vt4>.S }[<index>], [<Xn|SP>]
bool TryDecodeLD4_ASISDLSO_S4_4S(const InstData &, Instruction &) {
  return false;
}

// LD4 LD4_asisdlso_D4_4d:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 size     0
//  11 0 size     1
//  12 0 S        0
//  13 1 opcode   0
//  14 0 opcode   1
//  15 1 opcode   2
//  16 0
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1 R        0
//  22 1 L        0
//  23 0
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// LD4  { <Vt>.D, <Vt2>.D, <Vt3>.D, <Vt4>.D }[<index>], [<Xn|SP>]
bool TryDecodeLD4_ASISDLSO_D4_4D(const InstData &, Instruction &) {
  return false;
}

// LD4 LD4_asisdlsop_B4_i4b:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x size     0
//  11 x size     1
//  12 x S        0
//  13 1 opcode   0
//  14 0 opcode   1
//  15 0 opcode   2
//  16 1 Rm       0
//  17 1 Rm       1
//  18 1 Rm       2
//  19 1 Rm       3
//  20 1 Rm       4
//  21 1 R        0
//  22 1 L        0
//  23 1
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// LD4  { <Vt>.B, <Vt2>.B, <Vt3>.B, <Vt4>.B }[<index>], [<Xn|SP>], #4
bool TryDecodeLD4_ASISDLSOP_B4_I4B(const InstData &, Instruction &) {
  return false;
}

// LD4 LD4_asisdlsop_BX4_r4b:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x size     0
//  11 x size     1
//  12 x S        0
//  13 1 opcode   0
//  14 0 opcode   1
//  15 0 opcode   2
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1 R        0
//  22 1 L        0
//  23 1
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// LD4  { <Vt>.B, <Vt2>.B, <Vt3>.B, <Vt4>.B }[<index>], [<Xn|SP>], <Xm>
bool TryDecodeLD4_ASISDLSOP_BX4_R4B(const InstData &, Instruction &) {
  return false;
}

// LD4 LD4_asisdlsop_H4_i4h:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0 size     0
//  11 x size     1
//  12 x S        0
//  13 1 opcode   0
//  14 1 opcode   1
//  15 0 opcode   2
//  16 1 Rm       0
//  17 1 Rm       1
//  18 1 Rm       2
//  19 1 Rm       3
//  20 1 Rm       4
//  21 1 R        0
//  22 1 L        0
//  23 1
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// LD4  { <Vt>.H, <Vt2>.H, <Vt3>.H, <Vt4>.H }[<index>], [<Xn|SP>], #8
bool TryDecodeLD4_ASISDLSOP_H4_I4H(const InstData &, Instruction &) {
  return false;
}

// LD4 LD4_asisdlsop_HX4_r4h:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0 size     0
//  11 x size     1
//  12 x S        0
//  13 1 opcode   0
//  14 1 opcode   1
//  15 0 opcode   2
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1 R        0
//  22 1 L        0
//  23 1
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// LD4  { <Vt>.H, <Vt2>.H, <Vt3>.H, <Vt4>.H }[<index>], [<Xn|SP>], <Xm>
bool TryDecodeLD4_ASISDLSOP_HX4_R4H(const InstData &, Instruction &) {
  return false;
}

// LD4 LD4_asisdlsop_S4_i4s:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0 size     0
//  11 0 size     1
//  12 x S        0
//  13 1 opcode   0
//  14 0 opcode   1
//  15 1 opcode   2
//  16 1 Rm       0
//  17 1 Rm       1
//  18 1 Rm       2
//  19 1 Rm       3
//  20 1 Rm       4
//  21 1 R        0
//  22 1 L        0
//  23 1
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// LD4  { <Vt>.S, <Vt2>.S, <Vt3>.S, <Vt4>.S }[<index>], [<Xn|SP>], #16
bool TryDecodeLD4_ASISDLSOP_S4_I4S(const InstData &, Instruction &) {
  return false;
}

// LD4 LD4_asisdlsop_SX4_r4s:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0 size     0
//  11 0 size     1
//  12 x S        0
//  13 1 opcode   0
//  14 0 opcode   1
//  15 1 opcode   2
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1 R        0
//  22 1 L        0
//  23 1
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// LD4  { <Vt>.S, <Vt2>.S, <Vt3>.S, <Vt4>.S }[<index>], [<Xn|SP>], <Xm>
bool TryDecodeLD4_ASISDLSOP_SX4_R4S(const InstData &, Instruction &) {
  return false;
}

// LD4 LD4_asisdlsop_D4_i4d:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 size     0
//  11 0 size     1
//  12 0 S        0
//  13 1 opcode   0
//  14 0 opcode   1
//  15 1 opcode   2
//  16 1 Rm       0
//  17 1 Rm       1
//  18 1 Rm       2
//  19 1 Rm       3
//  20 1 Rm       4
//  21 1 R        0
//  22 1 L        0
//  23 1
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// LD4  { <Vt>.D, <Vt2>.D, <Vt3>.D, <Vt4>.D }[<index>], [<Xn|SP>], #32
bool TryDecodeLD4_ASISDLSOP_D4_I4D(const InstData &, Instruction &) {
  return false;
}

// LD4 LD4_asisdlsop_DX4_r4d:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 size     0
//  11 0 size     1
//  12 0 S        0
//  13 1 opcode   0
//  14 0 opcode   1
//  15 1 opcode   2
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1 R        0
//  22 1 L        0
//  23 1
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// LD4  { <Vt>.D, <Vt2>.D, <Vt3>.D, <Vt4>.D }[<index>], [<Xn|SP>], <Xm>
bool TryDecodeLD4_ASISDLSOP_DX4_R4D(const InstData &, Instruction &) {
  return false;
}

// CRC32B CRC32B_32C_dp_2src:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0 sz       0
//  11 0 sz       1
//  12 0 C        0
//  13 0 opcode2  3
//  14 1 opcode2  4
//  15 0 opcode2  5
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 1
//  23 1
//  24 0
//  25 1
//  26 0
//  27 1
//  28 1
//  29 0 S        0
//  30 0 op       0
//  31 0 sf       0
// CRC32B  <Wd>, <Wn>, <Wm>
bool TryDecodeCRC32B_32C_DP_2SRC(const InstData &, Instruction &) {
  return false;
}

// CRC32H CRC32H_32C_dp_2src:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 sz       0
//  11 0 sz       1
//  12 0 C        0
//  13 0 opcode2  3
//  14 1 opcode2  4
//  15 0 opcode2  5
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 1
//  23 1
//  24 0
//  25 1
//  26 0
//  27 1
//  28 1
//  29 0 S        0
//  30 0 op       0
//  31 0 sf       0
// CRC32H  <Wd>, <Wn>, <Wm>
bool TryDecodeCRC32H_32C_DP_2SRC(const InstData &, Instruction &) {
  return false;
}

// CRC32W CRC32W_32C_dp_2src:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0 sz       0
//  11 1 sz       1
//  12 0 C        0
//  13 0 opcode2  3
//  14 1 opcode2  4
//  15 0 opcode2  5
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 1
//  23 1
//  24 0
//  25 1
//  26 0
//  27 1
//  28 1
//  29 0 S        0
//  30 0 op       0
//  31 0 sf       0
// CRC32W  <Wd>, <Wn>, <Wm>
bool TryDecodeCRC32W_32C_DP_2SRC(const InstData &, Instruction &) {
  return false;
}

// CRC32X CRC32X_64C_dp_2src:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 sz       0
//  11 1 sz       1
//  12 0 C        0
//  13 0 opcode2  3
//  14 1 opcode2  4
//  15 0 opcode2  5
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 1
//  23 1
//  24 0
//  25 1
//  26 0
//  27 1
//  28 1
//  29 0 S        0
//  30 0 op       0
//  31 1 sf       0
// CRC32X  <Wd>, <Wn>, <Xm>
bool TryDecodeCRC32X_64C_DP_2SRC(const InstData &, Instruction &) {
  return false;
}

// URSHR URSHR_asisdshf_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0
//  12 0 o0       0
//  13 1 o1       0
//  14 0
//  15 0
//  16 x immb     0
//  17 x immb     1
//  18 x immb     2
//  19 x immh     0
//  20 x immh     1
//  21 x immh     2
//  22 x immh     3
//  23 0
//  24 1
//  25 1
//  26 1
//  27 1
//  28 1
//  29 1 U        0
//  30 1
//  31 0
// URSHR  <V><d>, <V><n>, #<shift>
bool TryDecodeURSHR_ASISDSHF_R(const InstData &, Instruction &) {
  return false;
}

// URSHR URSHR_asimdshf_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0
//  12 0 o0       0
//  13 1 o1       0
//  14 0
//  15 0
//  16 x immb     0
//  17 x immb     1
//  18 x immb     2
//  19 x immh     0
//  20 x immh     1
//  21 x immh     2
//  22 x immh     3
//  23 0
//  24 1
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// URSHR  <Vd>.<T>, <Vn>.<T>, #<shift>
bool TryDecodeURSHR_ASIMDSHF_R(const InstData &, Instruction &) {
  return false;
}

// PRFM PRFM_P_ldst_pos:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x imm12    0
//  11 x imm12    1
//  12 x imm12    2
//  13 x imm12    3
//  14 x imm12    4
//  15 x imm12    5
//  16 x imm12    6
//  17 x imm12    7
//  18 x imm12    8
//  19 x imm12    9
//  20 x imm12    10
//  21 x imm12    11
//  22 0 opc      0
//  23 1 opc      1
//  24 1
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 1 size     1
// PRFM  (<prfop>|#<imm5>), [<Xn|SP>{, #<pimm>}]
bool TryDecodePRFM_P_LDST_POS(const InstData &, Instruction &) {
  return false;
}

// SYSL SYSL_RC_system:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x op2      0
//   6 x op2      1
//   7 x op2      2
//   8 x CRm      0
//   9 x CRm      1
//  10 x CRm      2
//  11 x CRm      3
//  12 x CRn      0
//  13 x CRn      1
//  14 x CRn      2
//  15 x CRn      3
//  16 x op1      0
//  17 x op1      1
//  18 x op1      2
//  19 1 op0      0
//  20 0 op0      1
//  21 1 L        0
//  22 0
//  23 0
//  24 1
//  25 0
//  26 1
//  27 0
//  28 1
//  29 0
//  30 1
//  31 1
// SYSL  <Xt>, #<op1>, <Cn>, <Cm>, #<op2>
bool TryDecodeSYSL_RC_SYSTEM(const InstData &, Instruction &) {
  return false;
}

// SMSUBL SMSUBL_64WA_dp_3src:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x Ra       0
//  11 x Ra       1
//  12 x Ra       2
//  13 x Ra       3
//  14 x Ra       4
//  15 1 o0       0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 0
//  23 0 U        0
//  24 1
//  25 1
//  26 0
//  27 1
//  28 1
//  29 0 op54     0
//  30 0 op54     1
//  31 1 sf       0
// SMSUBL  <Xd>, <Wn>, <Wm>, <Xa>
bool TryDecodeSMSUBL_64WA_DP_3SRC(const InstData &, Instruction &) {
  return false;
}

// URSRA URSRA_asisdshf_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0
//  12 1 o0       0
//  13 1 o1       0
//  14 0
//  15 0
//  16 x immb     0
//  17 x immb     1
//  18 x immb     2
//  19 x immh     0
//  20 x immh     1
//  21 x immh     2
//  22 x immh     3
//  23 0
//  24 1
//  25 1
//  26 1
//  27 1
//  28 1
//  29 1 U        0
//  30 1
//  31 0
// URSRA  <V><d>, <V><n>, #<shift>
bool TryDecodeURSRA_ASISDSHF_R(const InstData &, Instruction &) {
  return false;
}

// URSRA URSRA_asimdshf_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0
//  12 1 o0       0
//  13 1 o1       0
//  14 0
//  15 0
//  16 x immb     0
//  17 x immb     1
//  18 x immb     2
//  19 x immh     0
//  20 x immh     1
//  21 x immh     2
//  22 x immh     3
//  23 0
//  24 1
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// URSRA  <Vd>.<T>, <Vn>.<T>, #<shift>
bool TryDecodeURSRA_ASIMDSHF_R(const InstData &, Instruction &) {
  return false;
}

// SRI SRI_asisdshf_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 opcode   0
//  12 0 opcode   1
//  13 0 opcode   2
//  14 1 opcode   3
//  15 0 opcode   4
//  16 x immb     0
//  17 x immb     1
//  18 x immb     2
//  19 x immh     0
//  20 x immh     1
//  21 x immh     2
//  22 x immh     3
//  23 0
//  24 1
//  25 1
//  26 1
//  27 1
//  28 1
//  29 1 U        0
//  30 1
//  31 0
// SRI  <V><d>, <V><n>, #<shift>
bool TryDecodeSRI_ASISDSHF_R(const InstData &, Instruction &) {
  return false;
}

// SRI SRI_asimdshf_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 opcode   0
//  12 0 opcode   1
//  13 0 opcode   2
//  14 1 opcode   3
//  15 0 opcode   4
//  16 x immb     0
//  17 x immb     1
//  18 x immb     2
//  19 x immh     0
//  20 x immh     1
//  21 x immh     2
//  22 x immh     3
//  23 0
//  24 1
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// SRI  <Vd>.<T>, <Vn>.<T>, #<shift>
bool TryDecodeSRI_ASIMDSHF_R(const InstData &, Instruction &) {
  return false;
}

// SYS IC_SYS_CR_system:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x op2      0
//   6 x op2      1
//   7 x op2      2
//   8 x CRm      0
//   9 x CRm      1
//  10 x CRm      2
//  11 x CRm      3
//  12 1 CRn      0
//  13 1 CRn      1
//  14 1 CRn      2
//  15 0 CRn      3
//  16 x op1      0
//  17 x op1      1
//  18 x op1      2
//  19 1 op0      0
//  20 0 op0      1
//  21 0 L        0
//  22 0
//  23 0
//  24 1
//  25 0
//  26 1
//  27 0
//  28 1
//  29 0
//  30 1
//  31 1
// IC  <ic_op>{, <Xt>}
bool TryDecodeIC_SYS_CR_SYSTEM(const InstData &, Instruction &) {
  return false;
}

// LDTRSH LDTRSH_32_ldst_unpriv:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 x imm9     0
//  13 x imm9     1
//  14 x imm9     2
//  15 x imm9     3
//  16 x imm9     4
//  17 x imm9     5
//  18 x imm9     6
//  19 x imm9     7
//  20 x imm9     8
//  21 0
//  22 1 opc      0
//  23 1 opc      1
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 0 size     1
// LDTRSH  <Wt>, [<Xn|SP>{, #<simm>}]
bool TryDecodeLDTRSH_32_LDST_UNPRIV(const InstData &, Instruction &) {
  return false;
}

// LDTRSH LDTRSH_64_ldst_unpriv:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 x imm9     0
//  13 x imm9     1
//  14 x imm9     2
//  15 x imm9     3
//  16 x imm9     4
//  17 x imm9     5
//  18 x imm9     6
//  19 x imm9     7
//  20 x imm9     8
//  21 0
//  22 0 opc      0
//  23 1 opc      1
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 0 size     1
// LDTRSH  <Xt>, [<Xn|SP>{, #<simm>}]
bool TryDecodeLDTRSH_64_LDST_UNPRIV(const InstData &, Instruction &) {
  return false;
}

// SADALP SADALP_asimdmisc_P:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0
//  13 1
//  14 1 op       0
//  15 0
//  16 0
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// SADALP  <Vd>.<Ta>, <Vn>.<Tb>
bool TryDecodeSADALP_ASIMDMISC_P(const InstData &, Instruction &) {
  return false;
}

// LDTRH LDTRH_32_ldst_unpriv:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 x imm9     0
//  13 x imm9     1
//  14 x imm9     2
//  15 x imm9     3
//  16 x imm9     4
//  17 x imm9     5
//  18 x imm9     6
//  19 x imm9     7
//  20 x imm9     8
//  21 0
//  22 1 opc      0
//  23 0 opc      1
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 0 size     1
// LDTRH  <Wt>, [<Xn|SP>{, #<simm>}]
bool TryDecodeLDTRH_32_LDST_UNPRIV(const InstData &, Instruction &) {
  return false;
}

// FCVTPU FCVTPU_asisdmiscfp16_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 o1       0
//  13 1
//  14 0
//  15 1
//  16 1
//  17 0
//  18 0
//  19 1
//  20 1
//  21 1
//  22 1
//  23 1 o2       0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 1 U        0
//  30 1
//  31 0
// FCVTPU  <Hd>, <Hn>
bool TryDecodeFCVTPU_ASISDMISCFP16_R(const InstData &, Instruction &) {
  return false;
}

// FCVTPU FCVTPU_asisdmisc_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 o1       0
//  13 1
//  14 0
//  15 1
//  16 1
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x sz       0
//  23 1 o2       0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 1 U        0
//  30 1
//  31 0
// FCVTPU  <V><d>, <V><n>
bool TryDecodeFCVTPU_ASISDMISC_R(const InstData &, Instruction &) {
  return false;
}

// FCVTPU FCVTPU_asimdmiscfp16_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 o1       0
//  13 1
//  14 0
//  15 1
//  16 1
//  17 0
//  18 0
//  19 1
//  20 1
//  21 1
//  22 1
//  23 1 o2       0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// FCVTPU  <Vd>.<T>, <Vn>.<T>
bool TryDecodeFCVTPU_ASIMDMISCFP16_R(const InstData &, Instruction &) {
  return false;
}

// FCVTPU FCVTPU_asimdmisc_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 o1       0
//  13 1
//  14 0
//  15 1
//  16 1
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x sz       0
//  23 1 o2       0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// FCVTPU  <Vd>.<T>, <Vn>.<T>
bool TryDecodeFCVTPU_ASIMDMISC_R(const InstData &, Instruction &) {
  return false;
}

// UQRSHL UQRSHL_asisdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1 S        0
//  12 1 R        0
//  13 0
//  14 1
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 1 U        0
//  30 1
//  31 0
// UQRSHL  <V><d>, <V><n>, <V><m>
bool TryDecodeUQRSHL_ASISDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// UQRSHL UQRSHL_asimdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1 S        0
//  12 1 R        0
//  13 0
//  14 1
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// UQRSHL  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeUQRSHL_ASIMDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// FCVTXN FCVTXN_asisdmisc_N:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 opcode   0
//  13 1 opcode   1
//  14 1 opcode   2
//  15 0 opcode   3
//  16 1 opcode   4
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x sz       0
//  23 0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 1 U        0
//  30 1
//  31 0
// FCVTXN  <Vb><d>, <Va><n>
bool TryDecodeFCVTXN_ASISDMISC_N(const InstData &, Instruction &) {
  return false;
}

// FCVTXN FCVTXN_asimdmisc_N:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 opcode   0
//  13 1 opcode   1
//  14 1 opcode   2
//  15 0 opcode   3
//  16 1 opcode   4
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x sz       0
//  23 0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// FCVTXN{2}  <Vd>.<Tb>, <Vn>.<Ta>
bool TryDecodeFCVTXN_ASIMDMISC_N(const InstData &, Instruction &) {
  return false;
}

// MSR MSR_SI_system:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 x op2      0
//   6 x op2      1
//   7 x op2      2
//   8 x CRm      0
//   9 x CRm      1
//  10 x CRm      2
//  11 x CRm      3
//  12 0 CRn      0
//  13 0 CRn      1
//  14 1 CRn      2
//  15 0 CRn      3
//  16 x op1      0
//  17 x op1      1
//  18 x op1      2
//  19 0 op0      0
//  20 0 op0      1
//  21 0 L        0
//  22 0
//  23 0
//  24 1
//  25 0
//  26 1
//  27 0
//  28 1
//  29 0
//  30 1
//  31 1
// MSR  <pstatefield>, #<imm>
bool TryDecodeMSR_SI_SYSTEM(const InstData &, Instruction &) {
  return false;
}

// UABDL UABDL_asimddiff_L:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1
//  13 1 op       0
//  14 1
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// UABDL{2}  <Vd>.<Ta>, <Vn>.<Tb>, <Vm>.<Tb>
bool TryDecodeUABDL_ASIMDDIFF_L(const InstData &, Instruction &) {
  return false;
}

// UQSHL UQSHL_asisdshf_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0
//  12 1 op       0
//  13 1
//  14 1
//  15 0
//  16 x immb     0
//  17 x immb     1
//  18 x immb     2
//  19 x immh     0
//  20 x immh     1
//  21 x immh     2
//  22 x immh     3
//  23 0
//  24 1
//  25 1
//  26 1
//  27 1
//  28 1
//  29 1 U        0
//  30 1
//  31 0
// UQSHL  <V><d>, <V><n>, #<shift>
bool TryDecodeUQSHL_ASISDSHF_R(const InstData &, Instruction &) {
  return false;
}

// UQSHL UQSHL_asimdshf_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0
//  12 1 op       0
//  13 1
//  14 1
//  15 0
//  16 x immb     0
//  17 x immb     1
//  18 x immb     2
//  19 x immh     0
//  20 x immh     1
//  21 x immh     2
//  22 x immh     3
//  23 0
//  24 1
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// UQSHL  <Vd>.<T>, <Vn>.<T>, #<shift>
bool TryDecodeUQSHL_ASIMDSHF_R(const InstData &, Instruction &) {
  return false;
}

// FMINNMP FMINNMP_asisdpair_only_H:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 opcode   0
//  13 0 opcode   1
//  14 1 opcode   2
//  15 1 opcode   3
//  16 0 opcode   4
//  17 0
//  18 0
//  19 0
//  20 1
//  21 1
//  22 0 sz       0
//  23 1 o1       0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// FMINNMP  <V><d>, <Vn>.<T>
bool TryDecodeFMINNMP_ASISDPAIR_ONLY_H(const InstData &, Instruction &) {
  return false;
}

// FMINNMP FMINNMP_asisdpair_only_SD:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 opcode   0
//  13 0 opcode   1
//  14 1 opcode   2
//  15 1 opcode   3
//  16 0 opcode   4
//  17 0
//  18 0
//  19 0
//  20 1
//  21 1
//  22 x sz       0
//  23 1 o1       0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 1 U        0
//  30 1
//  31 0
// FMINNMP  <V><d>, <Vn>.<T>
bool TryDecodeFMINNMP_ASISDPAIR_ONLY_SD(const InstData &, Instruction &) {
  return false;
}

// FMOV FMOV_H_floatdp1:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 1
//  15 0 opc      0
//  16 0 opc      1
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 1 type     0
//  23 1 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 M        0
// FMOV  <Hd>, <Hn>
bool TryDecodeFMOV_H_FLOATDP1(const InstData &, Instruction &) {
  return false;
}

// SRHADD SRHADD_asimdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 opcode   0
//  12 1 opcode   1
//  13 0 opcode   2
//  14 0 opcode   3
//  15 0 opcode   4
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// SRHADD  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeSRHADD_ASIMDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// SBC NGC_SBC_32_addsub_carry:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 1 Rn       0
//   6 1 Rn       1
//   7 1 Rn       2
//   8 1 Rn       3
//   9 1 Rn       4
//  10 0 opcode2  0
//  11 0 opcode2  1
//  12 0 opcode2  2
//  13 0 opcode2  3
//  14 0 opcode2  4
//  15 0 opcode2  5
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 0
//  23 0
//  24 0
//  25 1
//  26 0
//  27 1
//  28 1
//  29 0 S        0
//  30 1 op       0
//  31 0 sf       0
// NGC  <Wd>, <Wm>
bool TryDecodeNGC_SBC_32_ADDSUB_CARRY(const InstData &, Instruction &) {
  return false;
}

// SBC NGC_SBC_64_addsub_carry:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 1 Rn       0
//   6 1 Rn       1
//   7 1 Rn       2
//   8 1 Rn       3
//   9 1 Rn       4
//  10 0 opcode2  0
//  11 0 opcode2  1
//  12 0 opcode2  2
//  13 0 opcode2  3
//  14 0 opcode2  4
//  15 0 opcode2  5
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 0
//  23 0
//  24 0
//  25 1
//  26 0
//  27 1
//  28 1
//  29 0 S        0
//  30 1 op       0
//  31 1 sf       0
// NGC  <Xd>, <Xm>
bool TryDecodeNGC_SBC_64_ADDSUB_CARRY(const InstData &, Instruction &) {
  return false;
}

// SBFM SBFIZ_SBFM_32M_bitfield:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x imms     0
//  11 x imms     1
//  12 x imms     2
//  13 x imms     3
//  14 x imms     4
//  15 x imms     5
//  16 x immr     0
//  17 x immr     1
//  18 x immr     2
//  19 x immr     3
//  20 x immr     4
//  21 x immr     5
//  22 0 N        0
//  23 0
//  24 1
//  25 1
//  26 0
//  27 0
//  28 1
//  29 0 opc      0
//  30 0 opc      1
//  31 0 sf       0
// SBFIZ  <Wd>, <Wn>, #<lsb>, #<width>
bool TryDecodeSBFIZ_SBFM_32M_BITFIELD(const InstData &, Instruction &) {
  return false;
}

// SBFM SBFIZ_SBFM_64M_bitfield:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x imms     0
//  11 x imms     1
//  12 x imms     2
//  13 x imms     3
//  14 x imms     4
//  15 x imms     5
//  16 x immr     0
//  17 x immr     1
//  18 x immr     2
//  19 x immr     3
//  20 x immr     4
//  21 x immr     5
//  22 1 N        0
//  23 0
//  24 1
//  25 1
//  26 0
//  27 0
//  28 1
//  29 0 opc      0
//  30 0 opc      1
//  31 1 sf       0
// SBFIZ  <Xd>, <Xn>, #<lsb>, #<width>
bool TryDecodeSBFIZ_SBFM_64M_BITFIELD(const InstData &, Instruction &) {
  return false;
}

// UMSUBL UMSUBL_64WA_dp_3src:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x Ra       0
//  11 x Ra       1
//  12 x Ra       2
//  13 x Ra       3
//  14 x Ra       4
//  15 1 o0       0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 0
//  23 1 U        0
//  24 1
//  25 1
//  26 0
//  27 1
//  28 1
//  29 0 op54     0
//  30 0 op54     1
//  31 1 sf       0
// UMSUBL  <Xd>, <Wn>, <Wm>, <Xa>
bool TryDecodeUMSUBL_64WA_DP_3SRC(const InstData &, Instruction &) {
  return false;
}

// FCVTMU FCVTMU_32H_float2int:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 0
//  15 0
//  16 1 opcode   0
//  17 0 opcode   1
//  18 0 opcode   2
//  19 0 rmode    0
//  20 1 rmode    1
//  21 1
//  22 1 type     0
//  23 1 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 sf       0
// FCVTMU  <Wd>, <Hn>
bool TryDecodeFCVTMU_32H_FLOAT2INT(const InstData &, Instruction &) {
  return false;
}

// FCVTMU FCVTMU_64H_float2int:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 0
//  15 0
//  16 1 opcode   0
//  17 0 opcode   1
//  18 0 opcode   2
//  19 0 rmode    0
//  20 1 rmode    1
//  21 1
//  22 1 type     0
//  23 1 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 1 sf       0
// FCVTMU  <Xd>, <Hn>
bool TryDecodeFCVTMU_64H_FLOAT2INT(const InstData &, Instruction &) {
  return false;
}

// FCVTMU FCVTMU_32S_float2int:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 0
//  15 0
//  16 1 opcode   0
//  17 0 opcode   1
//  18 0 opcode   2
//  19 0 rmode    0
//  20 1 rmode    1
//  21 1
//  22 0 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 sf       0
// FCVTMU  <Wd>, <Sn>
bool TryDecodeFCVTMU_32S_FLOAT2INT(const InstData &, Instruction &) {
  return false;
}

// FCVTMU FCVTMU_64S_float2int:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 0
//  15 0
//  16 1 opcode   0
//  17 0 opcode   1
//  18 0 opcode   2
//  19 0 rmode    0
//  20 1 rmode    1
//  21 1
//  22 0 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 1 sf       0
// FCVTMU  <Xd>, <Sn>
bool TryDecodeFCVTMU_64S_FLOAT2INT(const InstData &, Instruction &) {
  return false;
}

// FCVTMU FCVTMU_32D_float2int:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 0
//  15 0
//  16 1 opcode   0
//  17 0 opcode   1
//  18 0 opcode   2
//  19 0 rmode    0
//  20 1 rmode    1
//  21 1
//  22 1 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 sf       0
// FCVTMU  <Wd>, <Dn>
bool TryDecodeFCVTMU_32D_FLOAT2INT(const InstData &, Instruction &) {
  return false;
}

// FCVTMU FCVTMU_64D_float2int:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 0
//  15 0
//  16 1 opcode   0
//  17 0 opcode   1
//  18 0 opcode   2
//  19 0 rmode    0
//  20 1 rmode    1
//  21 1
//  22 1 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 1 sf       0
// FCVTMU  <Xd>, <Dn>
bool TryDecodeFCVTMU_64D_FLOAT2INT(const InstData &, Instruction &) {
  return false;
}

// FCVTZU FCVTZU_64H_float2int:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 0
//  15 0
//  16 1 opcode   0
//  17 0 opcode   1
//  18 0 opcode   2
//  19 1 rmode    0
//  20 1 rmode    1
//  21 1
//  22 1 type     0
//  23 1 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 1 sf       0
// FCVTZU  <Xd>, <Hn>
bool TryDecodeFCVTZU_64H_FLOAT2INT(const InstData &, Instruction &) {
  return false;
}

// FCVTZU FCVTZU_32H_float2int:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 0
//  15 0
//  16 1 opcode   0
//  17 0 opcode   1
//  18 0 opcode   2
//  19 1 rmode    0
//  20 1 rmode    1
//  21 1
//  22 1 type     0
//  23 1 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 sf       0
// FCVTZU  <Wd>, <Hn>
bool TryDecodeFCVTZU_32H_FLOAT2INT(const InstData &, Instruction &) {
  return false;
}

// URECPE URECPE_asimdmisc_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 opcode   0
//  13 0 opcode   1
//  14 1 opcode   2
//  15 1 opcode   3
//  16 1 opcode   4
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x sz       0
//  23 1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// URECPE  <Vd>.<T>, <Vn>.<T>
bool TryDecodeURECPE_ASIMDMISC_R(const InstData &, Instruction &) {
  return false;
}

// ISB ISB_BI_system:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 0 opc      0
//   6 1 opc      1
//   7 1
//   8 x CRm      0
//   9 x CRm      1
//  10 x CRm      2
//  11 x CRm      3
//  12 1 CRn      0
//  13 1 CRn      1
//  14 0 CRn      2
//  15 0 CRn      3
//  16 1 op1      0
//  17 1 op1      1
//  18 0 op1      2
//  19 0 op0      0
//  20 0 op0      1
//  21 0 L        0
//  22 0
//  23 0
//  24 1
//  25 0
//  26 1
//  27 0
//  28 1
//  29 0
//  30 1
//  31 1
// ISB  {<option>|#<imm>}
bool TryDecodeISB_BI_SYSTEM(const InstData &, Instruction &) {
  return false;
}

// RSUBHN RSUBHN_asimddiff_N:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 1 o1       0
//  14 1
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// RSUBHN{2}  <Vd>.<Tb>, <Vn>.<Ta>, <Vm>.<Ta>
bool TryDecodeRSUBHN_ASIMDDIFF_N(const InstData &, Instruction &) {
  return false;
}

// SMULL SMULL_asimdelem_L:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 x H        0
//  12 0 opcode   0
//  13 1 opcode   1
//  14 0 opcode   2
//  15 1 opcode   3
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x M        0
//  21 x L        0
//  22 x size     0
//  23 x size     1
//  24 1
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// SMULL{2}  <Vd>.<Ta>, <Vn>.<Tb>, <Vm>.<Ts>[<index>]
bool TryDecodeSMULL_ASIMDELEM_L(const InstData &, Instruction &) {
  return false;
}

// SUQADD SUQADD_asisdmisc_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 opcode   0
//  13 1 opcode   1
//  14 0 opcode   2
//  15 0 opcode   3
//  16 0 opcode   4
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// SUQADD  <V><d>, <V><n>
bool TryDecodeSUQADD_ASISDMISC_R(const InstData &, Instruction &) {
  return false;
}

// SUQADD SUQADD_asimdmisc_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 opcode   0
//  13 1 opcode   1
//  14 0 opcode   2
//  15 0 opcode   3
//  16 0 opcode   4
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// SUQADD  <Vd>.<T>, <Vn>.<T>
bool TryDecodeSUQADD_ASIMDMISC_R(const InstData &, Instruction &) {
  return false;
}

// FABS FABS_H_floatdp1:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 1
//  15 1 opc      0
//  16 0 opc      1
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 1 type     0
//  23 1 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 M        0
// FABS  <Hd>, <Hn>
bool TryDecodeFABS_H_FLOATDP1(const InstData &, Instruction &) {
  return false;
}

// SYS AT_SYS_CR_system:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x op2      0
//   6 x op2      1
//   7 x op2      2
//   8 x CRm      0
//   9 0 CRm      1
//  10 0 CRm      2
//  11 1 CRm      3
//  12 1 CRn      0
//  13 1 CRn      1
//  14 1 CRn      2
//  15 0 CRn      3
//  16 x op1      0
//  17 x op1      1
//  18 x op1      2
//  19 1 op0      0
//  20 0 op0      1
//  21 0 L        0
//  22 0
//  23 0
//  24 1
//  25 0
//  26 1
//  27 0
//  28 1
//  29 0
//  30 1
//  31 1
// AT  <at_op>, <Xt>
bool TryDecodeAT_SYS_CR_SYSTEM(const InstData &, Instruction &) {
  return false;
}

// UQRSHRN UQRSHRN_asisdshf_N:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1 op       0
//  12 1
//  13 0
//  14 0
//  15 1
//  16 x immb     0
//  17 x immb     1
//  18 x immb     2
//  19 x immh     0
//  20 x immh     1
//  21 x immh     2
//  22 x immh     3
//  23 0
//  24 1
//  25 1
//  26 1
//  27 1
//  28 1
//  29 1 U        0
//  30 1
//  31 0
// UQRSHRN  <Vb><d>, <Va><n>, #<shift>
bool TryDecodeUQRSHRN_ASISDSHF_N(const InstData &, Instruction &) {
  return false;
}

// UQRSHRN UQRSHRN_asimdshf_N:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1 op       0
//  12 1
//  13 0
//  14 0
//  15 1
//  16 x immb     0
//  17 x immb     1
//  18 x immb     2
//  19 x immh     0
//  20 x immh     1
//  21 x immh     2
//  22 x immh     3
//  23 0
//  24 1
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// UQRSHRN{2}  <Vd>.<Tb>, <Vn>.<Ta>, #<shift>
bool TryDecodeUQRSHRN_ASIMDSHF_N(const InstData &, Instruction &) {
  return false;
}

// STNP STNP_32_ldstnapair_offs:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x Rt2      0
//  11 x Rt2      1
//  12 x Rt2      2
//  13 x Rt2      3
//  14 x Rt2      4
//  15 x imm7     0
//  16 x imm7     1
//  17 x imm7     2
//  18 x imm7     3
//  19 x imm7     4
//  20 x imm7     5
//  21 x imm7     6
//  22 0 L        0
//  23 0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 0
//  29 1
//  30 0 opc      0
//  31 0 opc      1
// STNP  <Wt1>, <Wt2>, [<Xn|SP>{, #<imm>}]
bool TryDecodeSTNP_32_LDSTNAPAIR_OFFS(const InstData &, Instruction &) {
  return false;
}

// STNP STNP_64_ldstnapair_offs:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x Rt2      0
//  11 x Rt2      1
//  12 x Rt2      2
//  13 x Rt2      3
//  14 x Rt2      4
//  15 x imm7     0
//  16 x imm7     1
//  17 x imm7     2
//  18 x imm7     3
//  19 x imm7     4
//  20 x imm7     5
//  21 x imm7     6
//  22 0 L        0
//  23 0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 0
//  29 1
//  30 0 opc      0
//  31 1 opc      1
// STNP  <Xt1>, <Xt2>, [<Xn|SP>{, #<imm>}]
bool TryDecodeSTNP_64_LDSTNAPAIR_OFFS(const InstData &, Instruction &) {
  return false;
}

// SRSRA SRSRA_asisdshf_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0
//  12 1 o0       0
//  13 1 o1       0
//  14 0
//  15 0
//  16 x immb     0
//  17 x immb     1
//  18 x immb     2
//  19 x immh     0
//  20 x immh     1
//  21 x immh     2
//  22 x immh     3
//  23 0
//  24 1
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// SRSRA  <V><d>, <V><n>, #<shift>
bool TryDecodeSRSRA_ASISDSHF_R(const InstData &, Instruction &) {
  return false;
}

// SRSRA SRSRA_asimdshf_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0
//  12 1 o0       0
//  13 1 o1       0
//  14 0
//  15 0
//  16 x immb     0
//  17 x immb     1
//  18 x immb     2
//  19 x immh     0
//  20 x immh     1
//  21 x immh     2
//  22 x immh     3
//  23 0
//  24 1
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// SRSRA  <Vd>.<T>, <Vn>.<T>, #<shift>
bool TryDecodeSRSRA_ASIMDSHF_R(const InstData &, Instruction &) {
  return false;
}

// CMGE CMGE_asisdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1 eq       0
//  12 1
//  13 1
//  14 0
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// CMGE  <V><d>, <V><n>, <V><m>
bool TryDecodeCMGE_ASISDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// FADD FADD_asimdsamefp16_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 opcode   0
//  12 1 opcode   1
//  13 0 opcode   2
//  14 0
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 1
//  23 0 a        0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// FADD  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeFADD_ASIMDSAMEFP16_ONLY(const InstData &, Instruction &) {
  return false;
}

// FADD FADD_asimdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 opcode   0
//  12 1 opcode   1
//  13 0 opcode   2
//  14 1 opcode   3
//  15 1 opcode   4
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x sz       0
//  23 0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// FADD  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeFADD_ASIMDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// SQRDMLAH SQRDMLAH_asisdsame2_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 S        0
//  12 0
//  13 0
//  14 0
//  15 1
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 1 U        0
//  30 1
//  31 0
// SQRDMLAH  <V><d>, <V><n>, <V><m>
bool TryDecodeSQRDMLAH_ASISDSAME2_ONLY(const InstData &, Instruction &) {
  return false;
}

// SQRDMLAH SQRDMLAH_asimdsame2_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 S        0
//  12 0
//  13 0
//  14 0
//  15 1
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// SQRDMLAH  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeSQRDMLAH_ASIMDSAME2_ONLY(const InstData &, Instruction &) {
  return false;
}

// ORN ORN_asimdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1 opcode   0
//  12 1 opcode   1
//  13 0 opcode   2
//  14 0 opcode   3
//  15 0 opcode   4
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 1 size     0
//  23 1 size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// ORN  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeORN_ASIMDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// STSETB STSETB_32S_memop:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 1 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 0 size     1
// STSETB  <Ws>, [<Xn|SP>]
bool TryDecodeSTSETB_32S_MEMOP(const InstData &, Instruction &) {
  return false;
}

// STSETLB STSETLB_32S_memop:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 1 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 0 size     1
// STSETLB  <Ws>, [<Xn|SP>]
bool TryDecodeSTSETLB_32S_MEMOP(const InstData &, Instruction &) {
  return false;
}

// ADC ADC_32_addsub_carry:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0 opcode2  0
//  11 0 opcode2  1
//  12 0 opcode2  2
//  13 0 opcode2  3
//  14 0 opcode2  4
//  15 0 opcode2  5
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 0
//  23 0
//  24 0
//  25 1
//  26 0
//  27 1
//  28 1
//  29 0 S        0
//  30 0 op       0
//  31 0 sf       0
// ADC  <Wd>, <Wn>, <Wm>
bool TryDecodeADC_32_ADDSUB_CARRY(const InstData &, Instruction &) {
  return false;
}

// ADC ADC_64_addsub_carry:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0 opcode2  0
//  11 0 opcode2  1
//  12 0 opcode2  2
//  13 0 opcode2  3
//  14 0 opcode2  4
//  15 0 opcode2  5
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 0
//  23 0
//  24 0
//  25 1
//  26 0
//  27 1
//  28 1
//  29 0 S        0
//  30 0 op       0
//  31 1 sf       0
// ADC  <Xd>, <Xn>, <Xm>
bool TryDecodeADC_64_ADDSUB_CARRY(const InstData &, Instruction &) {
  return false;
}

// BFM BFC_BFM_32M_bitfield:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 1 Rn       0
//   6 1 Rn       1
//   7 1 Rn       2
//   8 1 Rn       3
//   9 1 Rn       4
//  10 x imms     0
//  11 x imms     1
//  12 x imms     2
//  13 x imms     3
//  14 x imms     4
//  15 x imms     5
//  16 x immr     0
//  17 x immr     1
//  18 x immr     2
//  19 x immr     3
//  20 x immr     4
//  21 x immr     5
//  22 0 N        0
//  23 0
//  24 1
//  25 1
//  26 0
//  27 0
//  28 1
//  29 1 opc      0
//  30 0 opc      1
//  31 0 sf       0
// BFC  <Wd>, #<lsb>, #<width>
bool TryDecodeBFC_BFM_32M_BITFIELD(const InstData &, Instruction &) {
  return false;
}

// BFM BFC_BFM_64M_bitfield:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 1 Rn       0
//   6 1 Rn       1
//   7 1 Rn       2
//   8 1 Rn       3
//   9 1 Rn       4
//  10 x imms     0
//  11 x imms     1
//  12 x imms     2
//  13 x imms     3
//  14 x imms     4
//  15 x imms     5
//  16 x immr     0
//  17 x immr     1
//  18 x immr     2
//  19 x immr     3
//  20 x immr     4
//  21 x immr     5
//  22 1 N        0
//  23 0
//  24 1
//  25 1
//  26 0
//  27 0
//  28 1
//  29 1 opc      0
//  30 0 opc      1
//  31 1 sf       0
// BFC  <Xd>, #<lsb>, #<width>
bool TryDecodeBFC_BFM_64M_BITFIELD(const InstData &, Instruction &) {
  return false;
}

// LD2R LD2R_asisdlso_R2:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x size     0
//  11 x size     1
//  12 0 S        0
//  13 0 opcode   0
//  14 1 opcode   1
//  15 1 opcode   2
//  16 0
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1 R        0
//  22 1 L        0
//  23 0
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// LD2R  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>]
bool TryDecodeLD2R_ASISDLSO_R2(const InstData &, Instruction &) {
  return false;
}

// LD2R LD2R_asisdlsop_R2_i:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x size     0
//  11 x size     1
//  12 0 S        0
//  13 0 opcode   0
//  14 1 opcode   1
//  15 1 opcode   2
//  16 1 Rm       0
//  17 1 Rm       1
//  18 1 Rm       2
//  19 1 Rm       3
//  20 1 Rm       4
//  21 1 R        0
//  22 1 L        0
//  23 1
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// LD2R  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>], <imm>
bool TryDecodeLD2R_ASISDLSOP_R2_I(const InstData &, Instruction &) {
  return false;
}

// LD2R LD2R_asisdlsop_RX2_r:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x size     0
//  11 x size     1
//  12 0 S        0
//  13 0 opcode   0
//  14 1 opcode   1
//  15 1 opcode   2
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1 R        0
//  22 1 L        0
//  23 1
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// LD2R  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>], <Xm>
bool TryDecodeLD2R_ASISDLSOP_RX2_R(const InstData &, Instruction &) {
  return false;
}
// FMLS FMLS_asisdelem_RH_H:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 x H        0
//  12 1
//  13 0
//  14 1 o2       0
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x M        0
//  21 x L        0
//  22 0 size     0
//  23 0 size     1
//  24 1
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// FMLS  <Hd>, <Hn>, <Vm>.H[<index>]
bool TryDecodeFMLS_ASISDELEM_RH_H(const InstData &, Instruction &) {
  return false;
}

// FMLS FMLS_asisdelem_R_SD:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 x H        0
//  12 1
//  13 0
//  14 1 o2       0
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x M        0
//  21 x L        0
//  22 x sz       0
//  23 1
//  24 1
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// FMLS  <V><d>, <V><n>, <Vm>.<Ts>[<index>]
bool TryDecodeFMLS_ASISDELEM_R_SD(const InstData &, Instruction &) {
  return false;
}

// FMLS FMLS_asimdelem_RH_H:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 x H        0
//  12 1
//  13 0
//  14 1 o2       0
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x M        0
//  21 x L        0
//  22 0 size     0
//  23 0 size     1
//  24 1
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// FMLS  <Vd>.<T>, <Vn>.<T>, <Vm>.H[<index>]
bool TryDecodeFMLS_ASIMDELEM_RH_H(const InstData &, Instruction &) {
  return false;
}

// FMLS FMLS_asimdelem_R_SD:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 x H        0
//  12 1
//  13 0
//  14 1 o2       0
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x M        0
//  21 x L        0
//  22 x sz       0
//  23 1
//  24 1
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// FMLS  <Vd>.<T>, <Vn>.<T>, <Vm>.<Ts>[<index>]
bool TryDecodeFMLS_ASIMDELEM_R_SD(const InstData &, Instruction &) {
  return false;
}

// SHA256H2 SHA256H2_QQV_cryptosha3:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 P        0
//  13 0
//  14 1
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 0 size     0
//  23 0 size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0
//  30 1
//  31 0
// SHA256H2  <Qd>, <Qn>, <Vm>.4S
bool TryDecodeSHA256H2_QQV_CRYPTOSHA3(const InstData &, Instruction &) {
  return false;
}

// RBIT RBIT_asimdmisc_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 opcode   0
//  13 0 opcode   1
//  14 1 opcode   2
//  15 0 opcode   3
//  16 0 opcode   4
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 1 size     0
//  23 0 size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// RBIT  <Vd>.<T>, <Vn>.<T>
bool TryDecodeRBIT_ASIMDMISC_R(const InstData &, Instruction &) {
  return false;
}

// RSHRN RSHRN_asimdshf_N:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1 op       0
//  12 0
//  13 0
//  14 0
//  15 1
//  16 x immb     0
//  17 x immb     1
//  18 x immb     2
//  19 x immh     0
//  20 x immh     1
//  21 x immh     2
//  22 x immh     3
//  23 0
//  24 1
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// RSHRN{2}  <Vd>.<Tb>, <Vn>.<Ta>, #<shift>
bool TryDecodeRSHRN_ASIMDSHF_N(const InstData &, Instruction &) {
  return false;
}

// FCVTZS FCVTZS_32H_float2int:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 0
//  15 0
//  16 0 opcode   0
//  17 0 opcode   1
//  18 0 opcode   2
//  19 1 rmode    0
//  20 1 rmode    1
//  21 1
//  22 1 type     0
//  23 1 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 sf       0
// FCVTZS  <Wd>, <Hn>
bool TryDecodeFCVTZS_32H_FLOAT2INT(const InstData &, Instruction &) {
  return false;
}

// FCVTZS FCVTZS_64H_float2int:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 0
//  15 0
//  16 0 opcode   0
//  17 0 opcode   1
//  18 0 opcode   2
//  19 1 rmode    0
//  20 1 rmode    1
//  21 1
//  22 1 type     0
//  23 1 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 1 sf       0
// FCVTZS  <Xd>, <Hn>
bool TryDecodeFCVTZS_64H_FLOAT2INT(const InstData &, Instruction &) {
  return false;
}

// FCVTMS FCVTMS_asisdmiscfp16_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 o1       0
//  13 1
//  14 0
//  15 1
//  16 1
//  17 0
//  18 0
//  19 1
//  20 1
//  21 1
//  22 1
//  23 0 o2       0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// FCVTMS  <Hd>, <Hn>
bool TryDecodeFCVTMS_ASISDMISCFP16_R(const InstData &, Instruction &) {
  return false;
}

// FCVTMS FCVTMS_asisdmisc_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 o1       0
//  13 1
//  14 0
//  15 1
//  16 1
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x sz       0
//  23 0 o2       0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// FCVTMS  <V><d>, <V><n>
bool TryDecodeFCVTMS_ASISDMISC_R(const InstData &, Instruction &) {
  return false;
}

// FCVTMS FCVTMS_asimdmiscfp16_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 o1       0
//  13 1
//  14 0
//  15 1
//  16 1
//  17 0
//  18 0
//  19 1
//  20 1
//  21 1
//  22 1
//  23 0 o2       0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// FCVTMS  <Vd>.<T>, <Vn>.<T>
bool TryDecodeFCVTMS_ASIMDMISCFP16_R(const InstData &, Instruction &) {
  return false;
}

// FCVTMS FCVTMS_asimdmisc_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 o1       0
//  13 1
//  14 0
//  15 1
//  16 1
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x sz       0
//  23 0 o2       0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// FCVTMS  <Vd>.<T>, <Vn>.<T>
bool TryDecodeFCVTMS_ASIMDMISC_R(const InstData &, Instruction &) {
  return false;
}

// FRINTA FRINTA_H_floatdp1:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 1
//  15 0 rmode    0
//  16 0 rmode    1
//  17 1 rmode    2
//  18 1
//  19 0
//  20 0
//  21 1
//  22 1 type     0
//  23 1 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 M        0
// FRINTA  <Hd>, <Hn>
bool TryDecodeFRINTA_H_FLOATDP1(const InstData &, Instruction &) {
  return false;
}

// FRINTA FRINTA_S_floatdp1:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 1
//  15 0 rmode    0
//  16 0 rmode    1
//  17 1 rmode    2
//  18 1
//  19 0
//  20 0
//  21 1
//  22 0 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 M        0
// FRINTA  <Sd>, <Sn>
bool TryDecodeFRINTA_S_FLOATDP1(const InstData &, Instruction &) {
  return false;
}

// FRINTA FRINTA_D_floatdp1:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 1
//  15 0 rmode    0
//  16 0 rmode    1
//  17 1 rmode    2
//  18 1
//  19 0
//  20 0
//  21 1
//  22 1 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 M        0
// FRINTA  <Dd>, <Dn>
bool TryDecodeFRINTA_D_FLOATDP1(const InstData &, Instruction &) {
  return false;
}

// FCSEL FCSEL_H_floatsel:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1
//  12 x cond     0
//  13 x cond     1
//  14 x cond     2
//  15 x cond     3
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 1 type     0
//  23 1 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 M        0
// FCSEL  <Hd>, <Hn>, <Hm>, <cond>
bool TryDecodeFCSEL_H_FLOATSEL(const InstData &, Instruction &) {
  return false;
}

// FCSEL FCSEL_S_floatsel:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1
//  12 x cond     0
//  13 x cond     1
//  14 x cond     2
//  15 x cond     3
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 0 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 M        0
// FCSEL  <Sd>, <Sn>, <Sm>, <cond>
bool TryDecodeFCSEL_S_FLOATSEL(const InstData &, Instruction &) {
  return false;
}

// FCSEL FCSEL_D_floatsel:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1
//  12 x cond     0
//  13 x cond     1
//  14 x cond     2
//  15 x cond     3
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 1 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 M        0
// FCSEL  <Dd>, <Dn>, <Dm>, <cond>
bool TryDecodeFCSEL_D_FLOATSEL(const InstData &, Instruction &) {
  return false;
}

// SUBHN SUBHN_asimddiff_N:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 1 o1       0
//  14 1
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// SUBHN{2}  <Vd>.<Tb>, <Vn>.<Ta>, <Vm>.<Ta>
bool TryDecodeSUBHN_ASIMDDIFF_N(const InstData &, Instruction &) {
  return false;
}

// FACGT FACGT_asisdsamefp16_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1 ac       0
//  12 0
//  13 1
//  14 0
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 1
//  23 1 E        0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 1 U        0
//  30 1
//  31 0
// FACGT  <Hd>, <Hn>, <Hm>
bool TryDecodeFACGT_ASISDSAMEFP16_ONLY(const InstData &, Instruction &) {
  return false;
}

// FACGT FACGT_asisdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1 ac       0
//  12 0
//  13 1
//  14 1
//  15 1
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x sz       0
//  23 1 E        0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 1 U        0
//  30 1
//  31 0
// FACGT  <V><d>, <V><n>, <V><m>
bool TryDecodeFACGT_ASISDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// FACGT FACGT_asimdsamefp16_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1 ac       0
//  12 0
//  13 1
//  14 0
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 1
//  23 1 E        0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// FACGT  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeFACGT_ASIMDSAMEFP16_ONLY(const InstData &, Instruction &) {
  return false;
}

// FACGT FACGT_asimdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1 ac       0
//  12 0
//  13 1
//  14 1
//  15 1
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x sz       0
//  23 1 E        0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// FACGT  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeFACGT_ASIMDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// NEG NEG_asisdmisc_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 opcode   0
//  13 1 opcode   1
//  14 0 opcode   2
//  15 1 opcode   3
//  16 0 opcode   4
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 1 U        0
//  30 1
//  31 0
// NEG  <V><d>, <V><n>
bool TryDecodeNEG_ASISDMISC_R(const InstData &, Instruction &) {
  return false;
}

// NEG NEG_asimdmisc_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 opcode   0
//  13 1 opcode   1
//  14 0 opcode   2
//  15 1 opcode   3
//  16 0 opcode   4
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// NEG  <Vd>.<T>, <Vn>.<T>
bool TryDecodeNEG_ASIMDMISC_R(const InstData &, Instruction &) {
  return false;
}

// UMLAL UMLAL_asimddiff_L:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0 o1       0
//  14 0
//  15 1
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// UMLAL{2}  <Vd>.<Ta>, <Vn>.<Tb>, <Vm>.<Tb>
bool TryDecodeUMLAL_ASIMDDIFF_L(const InstData &, Instruction &) {
  return false;
}

// PMULL PMULL_asimddiff_L:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opcode   0
//  13 1 opcode   1
//  14 1 opcode   2
//  15 1 opcode   3
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// PMULL{2}  <Vd>.<Ta>, <Vn>.<Tb>, <Vm>.<Tb>
bool TryDecodePMULL_ASIMDDIFF_L(const InstData &, Instruction &) {
  return false;
}

// FMLS FMLS_asimdsamefp16_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1 opcode   0
//  12 0 opcode   1
//  13 0 opcode   2
//  14 0
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 1
//  23 1 a        0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// FMLS  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeFMLS_ASIMDSAMEFP16_ONLY(const InstData &, Instruction &) {
  return false;
}

// FMLS FMLS_asimdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1 opcode   0
//  12 0 opcode   1
//  13 0 opcode   2
//  14 1 opcode   3
//  15 1 opcode   4
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x sz       0
//  23 1 op       0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// FMLS  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeFMLS_ASIMDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// LDSMAXA LDSMAXA_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 0 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 1 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 1 size     1
// LDSMAXA  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDSMAXA_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDSMAXAL LDSMAXAL_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 0 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 1 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 1 size     1
// LDSMAXAL  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDSMAXAL_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDSMAX LDSMAX_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 0 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 1 size     1
// LDSMAX  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDSMAX_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDSMAXL LDSMAXL_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 0 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 1 size     1
// LDSMAXL  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDSMAXL_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDSMAXA LDSMAXA_64_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 0 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 1 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 1 size     1
// LDSMAXA  <Xs>, <Xt>, [<Xn|SP>]
bool TryDecodeLDSMAXA_64_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDSMAXAL LDSMAXAL_64_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 0 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 1 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 1 size     1
// LDSMAXAL  <Xs>, <Xt>, [<Xn|SP>]
bool TryDecodeLDSMAXAL_64_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDSMAX LDSMAX_64_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 0 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 1 size     1
// LDSMAX  <Xs>, <Xt>, [<Xn|SP>]
bool TryDecodeLDSMAX_64_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDSMAXL LDSMAXL_64_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 0 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 1 size     1
// LDSMAXL  <Xs>, <Xt>, [<Xn|SP>]
bool TryDecodeLDSMAXL_64_MEMOP(const InstData &, Instruction &) {
  return false;
}

// SYS SYS_CR_system:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x op2      0
//   6 x op2      1
//   7 x op2      2
//   8 x CRm      0
//   9 x CRm      1
//  10 x CRm      2
//  11 x CRm      3
//  12 x CRn      0
//  13 x CRn      1
//  14 x CRn      2
//  15 x CRn      3
//  16 x op1      0
//  17 x op1      1
//  18 x op1      2
//  19 1 op0      0
//  20 0 op0      1
//  21 0 L        0
//  22 0
//  23 0
//  24 1
//  25 0
//  26 1
//  27 0
//  28 1
//  29 0
//  30 1
//  31 1
// SYS  #<op1>, <Cn>, <Cm>, #<op2>{, <Xt>}
bool TryDecodeSYS_CR_SYSTEM(const InstData &, Instruction &) {
  return false;
}

// SQABS SQABS_asisdmisc_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 opcode   0
//  13 1 opcode   1
//  14 1 opcode   2
//  15 0 opcode   3
//  16 0 opcode   4
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// SQABS  <V><d>, <V><n>
bool TryDecodeSQABS_ASISDMISC_R(const InstData &, Instruction &) {
  return false;
}

// SQABS SQABS_asimdmisc_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 opcode   0
//  13 1 opcode   1
//  14 1 opcode   2
//  15 0 opcode   3
//  16 0 opcode   4
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// SQABS  <Vd>.<T>, <Vn>.<T>
bool TryDecodeSQABS_ASIMDMISC_R(const InstData &, Instruction &) {
  return false;
}

// STADDH STADDH_32S_memop:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 0 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 0 size     1
// STADDH  <Ws>, [<Xn|SP>]
bool TryDecodeSTADDH_32S_MEMOP(const InstData &, Instruction &) {
  return false;
}

// STADDLH STADDLH_32S_memop:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 0 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 0 size     1
// STADDLH  <Ws>, [<Xn|SP>]
bool TryDecodeSTADDLH_32S_MEMOP(const InstData &, Instruction &) {
  return false;
}

// FCVTAS FCVTAS_asisdmiscfp16_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 opcode   0
//  13 0 opcode   1
//  14 1 opcode   2
//  15 1 opcode   3
//  16 1 opcode   4
//  17 0
//  18 0
//  19 1
//  20 1
//  21 1
//  22 1
//  23 0 size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// FCVTAS  <Hd>, <Hn>
bool TryDecodeFCVTAS_ASISDMISCFP16_R(const InstData &, Instruction &) {
  return false;
}

// FCVTAS FCVTAS_asisdmisc_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 opcode   0
//  13 0 opcode   1
//  14 1 opcode   2
//  15 1 opcode   3
//  16 1 opcode   4
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x sz       0
//  23 0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// FCVTAS  <V><d>, <V><n>
bool TryDecodeFCVTAS_ASISDMISC_R(const InstData &, Instruction &) {
  return false;
}

// FCVTAS FCVTAS_asimdmiscfp16_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 opcode   0
//  13 0 opcode   1
//  14 1 opcode   2
//  15 1 opcode   3
//  16 1 opcode   4
//  17 0
//  18 0
//  19 1
//  20 1
//  21 1
//  22 1
//  23 0 a        0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// FCVTAS  <Vd>.<T>, <Vn>.<T>
bool TryDecodeFCVTAS_ASIMDMISCFP16_R(const InstData &, Instruction &) {
  return false;
}

// FCVTAS FCVTAS_asimdmisc_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 opcode   0
//  13 0 opcode   1
//  14 1 opcode   2
//  15 1 opcode   3
//  16 1 opcode   4
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x sz       0
//  23 0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// FCVTAS  <Vd>.<T>, <Vn>.<T>
bool TryDecodeFCVTAS_ASIMDMISC_R(const InstData &, Instruction &) {
  return false;
}

// UQSHRN UQSHRN_asisdshf_N:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 op       0
//  12 1
//  13 0
//  14 0
//  15 1
//  16 x immb     0
//  17 x immb     1
//  18 x immb     2
//  19 x immh     0
//  20 x immh     1
//  21 x immh     2
//  22 x immh     3
//  23 0
//  24 1
//  25 1
//  26 1
//  27 1
//  28 1
//  29 1 U        0
//  30 1
//  31 0
// UQSHRN  <Vb><d>, <Va><n>, #<shift>
bool TryDecodeUQSHRN_ASISDSHF_N(const InstData &, Instruction &) {
  return false;
}

// UQSHRN UQSHRN_asimdshf_N:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 op       0
//  12 1
//  13 0
//  14 0
//  15 1
//  16 x immb     0
//  17 x immb     1
//  18 x immb     2
//  19 x immh     0
//  20 x immh     1
//  21 x immh     2
//  22 x immh     3
//  23 0
//  24 1
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// UQSHRN{2}  <Vd>.<Tb>, <Vn>.<Ta>, #<shift>
bool TryDecodeUQSHRN_ASIMDSHF_N(const InstData &, Instruction &) {
  return false;
}

// USHL USHL_asisdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 S        0
//  12 0 R        0
//  13 0
//  14 1
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 1 U        0
//  30 1
//  31 0
// USHL  <V><d>, <V><n>, <V><m>
bool TryDecodeUSHL_ASISDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// USHL USHL_asimdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 S        0
//  12 0 R        0
//  13 0
//  14 1
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// USHL  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeUSHL_ASIMDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// FADDP FADDP_asisdpair_only_H:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 opcode   0
//  13 0 opcode   1
//  14 1 opcode   2
//  15 1 opcode   3
//  16 0 opcode   4
//  17 0
//  18 0
//  19 0
//  20 1
//  21 1
//  22 0 sz       0
//  23 0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// FADDP  <V><d>, <Vn>.<T>
bool TryDecodeFADDP_ASISDPAIR_ONLY_H(const InstData &, Instruction &) {
  return false;
}

// FADDP FADDP_asisdpair_only_SD:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 opcode   0
//  13 0 opcode   1
//  14 1 opcode   2
//  15 1 opcode   3
//  16 0 opcode   4
//  17 0
//  18 0
//  19 0
//  20 1
//  21 1
//  22 x sz       0
//  23 0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 1 U        0
//  30 1
//  31 0
// FADDP  <V><d>, <Vn>.<T>
bool TryDecodeFADDP_ASISDPAIR_ONLY_SD(const InstData &, Instruction &) {
  return false;
}

// SSHR SSHR_asisdshf_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0
//  12 0 o0       0
//  13 0 o1       0
//  14 0
//  15 0
//  16 x immb     0
//  17 x immb     1
//  18 x immb     2
//  19 x immh     0
//  20 x immh     1
//  21 x immh     2
//  22 x immh     3
//  23 0
//  24 1
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// SSHR  <V><d>, <V><n>, #<shift>
bool TryDecodeSSHR_ASISDSHF_R(const InstData &, Instruction &) {
  return false;
}

// SSHR SSHR_asimdshf_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0
//  12 0 o0       0
//  13 0 o1       0
//  14 0
//  15 0
//  16 x immb     0
//  17 x immb     1
//  18 x immb     2
//  19 x immh     0
//  20 x immh     1
//  21 x immh     2
//  22 x immh     3
//  23 0
//  24 1
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// SSHR  <Vd>.<T>, <Vn>.<T>, #<shift>
bool TryDecodeSSHR_ASIMDSHF_R(const InstData &, Instruction &) {
  return false;
}

// SHSUB SHSUB_asimdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 opcode   0
//  12 0 opcode   1
//  13 1 opcode   2
//  14 0 opcode   3
//  15 0 opcode   4
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// SHSUB  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeSHSUB_ASIMDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// FMINNM FMINNM_asimdsamefp16_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 Op3      0
//  12 0 Op3      1
//  13 0 Op3      2
//  14 0
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 1
//  23 1 a        0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// FMINNM  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeFMINNM_ASIMDSAMEFP16_ONLY(const InstData &, Instruction &) {
  return false;
}

// FMINNM FMINNM_asimdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 opcode   0
//  12 0 opcode   1
//  13 0 opcode   2
//  14 1 opcode   3
//  15 1 opcode   4
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x sz       0
//  23 1 o1       0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// FMINNM  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeFMINNM_ASIMDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// UMLSL UMLSL_asimddiff_L:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 1 o1       0
//  14 0
//  15 1
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// UMLSL{2}  <Vd>.<Ta>, <Vn>.<Tb>, <Vm>.<Tb>
bool TryDecodeUMLSL_ASIMDDIFF_L(const InstData &, Instruction &) {
  return false;
}

// USHLL USHLL_asimdshf_L:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 opcode   0
//  12 0 opcode   1
//  13 1 opcode   2
//  14 0 opcode   3
//  15 1 opcode   4
//  16 x immb     0
//  17 x immb     1
//  18 x immb     2
//  19 x immh     0
//  20 x immh     1
//  21 x immh     2
//  22 x immh     3
//  23 0
//  24 1
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// USHLL{2}  <Vd>.<Ta>, <Vn>.<Tb>, #<shift>
bool TryDecodeUSHLL_ASIMDSHF_L(const InstData &, Instruction &) {
  return false;
}

// STLR STLR_SL64_ldstexcl:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 Rt2      0
//  11 1 Rt2      1
//  12 1 Rt2      2
//  13 1 Rt2      3
//  14 1 Rt2      4
//  15 1 o0       0
//  16 1 Rs       0
//  17 1 Rs       1
//  18 1 Rs       2
//  19 1 Rs       3
//  20 1 Rs       4
//  21 0 o1       0
//  22 0 L        0
//  23 1 o2       0
//  24 0
//  25 0
//  26 0
//  27 1
//  28 0
//  29 0
//  30 1 size     0
//  31 1 size     1
// STLR  <Xt>, [<Xn|SP>{,#0}]
bool TryDecodeSTLR_SL64_LDSTEXCL(const InstData &, Instruction &) {
  return false;
}

// STSMAXB STSMAXB_32S_memop:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 0 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 0 size     1
// STSMAXB  <Ws>, [<Xn|SP>]
bool TryDecodeSTSMAXB_32S_MEMOP(const InstData &, Instruction &) {
  return false;
}

// STSMAXLB STSMAXLB_32S_memop:
//   0 1 Rt       0
//   1 1 Rt       1
//   2 1 Rt       2
//   3 1 Rt       3
//   4 1 Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 0 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 0 size     1
// STSMAXLB  <Ws>, [<Xn|SP>]
bool TryDecodeSTSMAXLB_32S_MEMOP(const InstData &, Instruction &) {
  return false;
}

// FCVTNS FCVTNS_32H_float2int:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 0
//  15 0
//  16 0 opcode   0
//  17 0 opcode   1
//  18 0 opcode   2
//  19 0 rmode    0
//  20 0 rmode    1
//  21 1
//  22 1 type     0
//  23 1 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 sf       0
// FCVTNS  <Wd>, <Hn>
bool TryDecodeFCVTNS_32H_FLOAT2INT(const InstData &, Instruction &) {
  return false;
}

// FCVTNS FCVTNS_64H_float2int:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 0
//  15 0
//  16 0 opcode   0
//  17 0 opcode   1
//  18 0 opcode   2
//  19 0 rmode    0
//  20 0 rmode    1
//  21 1
//  22 1 type     0
//  23 1 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 1 sf       0
// FCVTNS  <Xd>, <Hn>
bool TryDecodeFCVTNS_64H_FLOAT2INT(const InstData &, Instruction &) {
  return false;
}

// FCVTNS FCVTNS_32S_float2int:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 0
//  15 0
//  16 0 opcode   0
//  17 0 opcode   1
//  18 0 opcode   2
//  19 0 rmode    0
//  20 0 rmode    1
//  21 1
//  22 0 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 sf       0
// FCVTNS  <Wd>, <Sn>
bool TryDecodeFCVTNS_32S_FLOAT2INT(const InstData &, Instruction &) {
  return false;
}

// FCVTNS FCVTNS_64S_float2int:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 0
//  15 0
//  16 0 opcode   0
//  17 0 opcode   1
//  18 0 opcode   2
//  19 0 rmode    0
//  20 0 rmode    1
//  21 1
//  22 0 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 1 sf       0
// FCVTNS  <Xd>, <Sn>
bool TryDecodeFCVTNS_64S_FLOAT2INT(const InstData &, Instruction &) {
  return false;
}

// FCVTNS FCVTNS_32D_float2int:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 0
//  15 0
//  16 0 opcode   0
//  17 0 opcode   1
//  18 0 opcode   2
//  19 0 rmode    0
//  20 0 rmode    1
//  21 1
//  22 1 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 sf       0
// FCVTNS  <Wd>, <Dn>
bool TryDecodeFCVTNS_32D_FLOAT2INT(const InstData &, Instruction &) {
  return false;
}

// FCVTNS FCVTNS_64D_float2int:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 0
//  15 0
//  16 0 opcode   0
//  17 0 opcode   1
//  18 0 opcode   2
//  19 0 rmode    0
//  20 0 rmode    1
//  21 1
//  22 1 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 1 sf       0
// FCVTNS  <Xd>, <Dn>
bool TryDecodeFCVTNS_64D_FLOAT2INT(const InstData &, Instruction &) {
  return false;
}

// SQSHRN SQSHRN_asisdshf_N:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 op       0
//  12 1
//  13 0
//  14 0
//  15 1
//  16 x immb     0
//  17 x immb     1
//  18 x immb     2
//  19 x immh     0
//  20 x immh     1
//  21 x immh     2
//  22 x immh     3
//  23 0
//  24 1
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// SQSHRN  <Vb><d>, <Va><n>, #<shift>
bool TryDecodeSQSHRN_ASISDSHF_N(const InstData &, Instruction &) {
  return false;
}

// SQSHRN SQSHRN_asimdshf_N:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 op       0
//  12 1
//  13 0
//  14 0
//  15 1
//  16 x immb     0
//  17 x immb     1
//  18 x immb     2
//  19 x immh     0
//  20 x immh     1
//  21 x immh     2
//  22 x immh     3
//  23 0
//  24 1
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// SQSHRN{2}  <Vd>.<Tb>, <Vn>.<Ta>, #<shift>
bool TryDecodeSQSHRN_ASIMDSHF_N(const InstData &, Instruction &) {
  return false;
}

// LDTRB LDTRB_32_ldst_unpriv:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 x imm9     0
//  13 x imm9     1
//  14 x imm9     2
//  15 x imm9     3
//  16 x imm9     4
//  17 x imm9     5
//  18 x imm9     6
//  19 x imm9     7
//  20 x imm9     8
//  21 0
//  22 1 opc      0
//  23 0 opc      1
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 0 size     1
// LDTRB  <Wt>, [<Xn|SP>{, #<simm>}]
bool TryDecodeLDTRB_32_LDST_UNPRIV(const InstData &, Instruction &) {
  return false;
}

// SBFM SXTH_SBFM_32M_bitfield:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 imms     0
//  11 1 imms     1
//  12 1 imms     2
//  13 1 imms     3
//  14 0 imms     4
//  15 0 imms     5
//  16 0 immr     0
//  17 0 immr     1
//  18 0 immr     2
//  19 0 immr     3
//  20 0 immr     4
//  21 0 immr     5
//  22 0 N        0
//  23 0
//  24 1
//  25 1
//  26 0
//  27 0
//  28 1
//  29 0 opc      0
//  30 0 opc      1
//  31 0 sf       0
// SXTH  <Wd>, <Wn>
bool TryDecodeSXTH_SBFM_32M_BITFIELD(const InstData &, Instruction &) {
  return false;
}

// SBFM SXTH_SBFM_64M_bitfield:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 imms     0
//  11 1 imms     1
//  12 1 imms     2
//  13 1 imms     3
//  14 0 imms     4
//  15 0 imms     5
//  16 0 immr     0
//  17 0 immr     1
//  18 0 immr     2
//  19 0 immr     3
//  20 0 immr     4
//  21 0 immr     5
//  22 1 N        0
//  23 0
//  24 1
//  25 1
//  26 0
//  27 0
//  28 1
//  29 0 opc      0
//  30 0 opc      1
//  31 1 sf       0
// SXTH  <Xd>, <Wn>
bool TryDecodeSXTH_SBFM_64M_BITFIELD(const InstData &, Instruction &) {
  return false;
}

// LDURSB LDURSB_64_ldst_unscaled:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 x imm9     0
//  13 x imm9     1
//  14 x imm9     2
//  15 x imm9     3
//  16 x imm9     4
//  17 x imm9     5
//  18 x imm9     6
//  19 x imm9     7
//  20 x imm9     8
//  21 0
//  22 0 opc      0
//  23 1 opc      1
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 0 size     1
// LDURSB  <Xt>, [<Xn|SP>{, #<simm>}]
bool TryDecodeLDURSB_64_LDST_UNSCALED(const InstData &, Instruction &) {
  return false;
}

// SHA256H SHA256H_QQV_cryptosha3:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 P        0
//  13 0
//  14 1
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 0 size     0
//  23 0 size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0
//  30 1
//  31 0
// SHA256H  <Qd>, <Qn>, <Vm>.4S
bool TryDecodeSHA256H_QQV_CRYPTOSHA3(const InstData &, Instruction &) {
  return false;
}

// LD4R LD4R_asisdlso_R4:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x size     0
//  11 x size     1
//  12 0 S        0
//  13 1 opcode   0
//  14 1 opcode   1
//  15 1 opcode   2
//  16 0
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1 R        0
//  22 1 L        0
//  23 0
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// LD4R  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T>, <Vt4>.<T> }, [<Xn|SP>]
bool TryDecodeLD4R_ASISDLSO_R4(const InstData &, Instruction &) {
  return false;
}

// LD4R LD4R_asisdlsop_R4_i:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x size     0
//  11 x size     1
//  12 0 S        0
//  13 1 opcode   0
//  14 1 opcode   1
//  15 1 opcode   2
//  16 1 Rm       0
//  17 1 Rm       1
//  18 1 Rm       2
//  19 1 Rm       3
//  20 1 Rm       4
//  21 1 R        0
//  22 1 L        0
//  23 1
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// LD4R  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T>, <Vt4>.<T> }, [<Xn|SP>], <imm>
bool TryDecodeLD4R_ASISDLSOP_R4_I(const InstData &, Instruction &) {
  return false;
}

// LD4R LD4R_asisdlsop_RX4_r:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x size     0
//  11 x size     1
//  12 0 S        0
//  13 1 opcode   0
//  14 1 opcode   1
//  15 1 opcode   2
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1 R        0
//  22 1 L        0
//  23 1
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// LD4R  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T>, <Vt4>.<T> }, [<Xn|SP>], <Xm>
bool TryDecodeLD4R_ASISDLSOP_RX4_R(const InstData &, Instruction &) {
  return false;
}

// FCVTNS FCVTNS_asisdmiscfp16_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 o1       0
//  13 1
//  14 0
//  15 1
//  16 1
//  17 0
//  18 0
//  19 1
//  20 1
//  21 1
//  22 1
//  23 0 o2       0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// FCVTNS  <Hd>, <Hn>
bool TryDecodeFCVTNS_ASISDMISCFP16_R(const InstData &, Instruction &) {
  return false;
}

// FCVTNS FCVTNS_asisdmisc_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 o1       0
//  13 1
//  14 0
//  15 1
//  16 1
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x sz       0
//  23 0 o2       0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// FCVTNS  <V><d>, <V><n>
bool TryDecodeFCVTNS_ASISDMISC_R(const InstData &, Instruction &) {
  return false;
}

// FCVTNS FCVTNS_asimdmiscfp16_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 o1       0
//  13 1
//  14 0
//  15 1
//  16 1
//  17 0
//  18 0
//  19 1
//  20 1
//  21 1
//  22 1
//  23 0 o2       0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// FCVTNS  <Vd>.<T>, <Vn>.<T>
bool TryDecodeFCVTNS_ASIMDMISCFP16_R(const InstData &, Instruction &) {
  return false;
}

// FCVTNS FCVTNS_asimdmisc_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 o1       0
//  13 1
//  14 0
//  15 1
//  16 1
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x sz       0
//  23 0 o2       0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// FCVTNS  <Vd>.<T>, <Vn>.<T>
bool TryDecodeFCVTNS_ASIMDMISC_R(const InstData &, Instruction &) {
  return false;
}

// FDIV FDIV_asimdsamefp16_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1 opcode   0
//  12 1 opcode   1
//  13 1 opcode   2
//  14 0
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 1
//  23 0 a        0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// FDIV  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeFDIV_ASIMDSAMEFP16_ONLY(const InstData &, Instruction &) {
  return false;
}

// FDIV FDIV_asimdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1 opcode   0
//  12 1 opcode   1
//  13 1 opcode   2
//  14 1 opcode   3
//  15 1 opcode   4
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x sz       0
//  23 0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// FDIV  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeFDIV_ASIMDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// FRECPE FRECPE_asisdmiscfp16_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 opcode   0
//  13 0 opcode   1
//  14 1 opcode   2
//  15 1 opcode   3
//  16 1 opcode   4
//  17 0
//  18 0
//  19 1
//  20 1
//  21 1
//  22 1
//  23 1 size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// FRECPE  <Hd>, <Hn>
bool TryDecodeFRECPE_ASISDMISCFP16_R(const InstData &, Instruction &) {
  return false;
}

// FRECPE FRECPE_asisdmisc_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 opcode   0
//  13 0 opcode   1
//  14 1 opcode   2
//  15 1 opcode   3
//  16 1 opcode   4
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x sz       0
//  23 1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// FRECPE  <V><d>, <V><n>
bool TryDecodeFRECPE_ASISDMISC_R(const InstData &, Instruction &) {
  return false;
}

// FRECPE FRECPE_asimdmiscfp16_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 opcode   0
//  13 0 opcode   1
//  14 1 opcode   2
//  15 1 opcode   3
//  16 1 opcode   4
//  17 0
//  18 0
//  19 1
//  20 1
//  21 1
//  22 1
//  23 1 a        0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// FRECPE  <Vd>.<T>, <Vn>.<T>
bool TryDecodeFRECPE_ASIMDMISCFP16_R(const InstData &, Instruction &) {
  return false;
}

// FRECPE FRECPE_asimdmisc_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 1 opcode   0
//  13 0 opcode   1
//  14 1 opcode   2
//  15 1 opcode   3
//  16 1 opcode   4
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x sz       0
//  23 1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// FRECPE  <Vd>.<T>, <Vn>.<T>
bool TryDecodeFRECPE_ASIMDMISC_R(const InstData &, Instruction &) {
  return false;
}

// LD1R LD1R_asisdlso_R1:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x size     0
//  11 x size     1
//  12 0 S        0
//  13 0 opcode   0
//  14 1 opcode   1
//  15 1 opcode   2
//  16 0
//  17 0
//  18 0
//  19 0
//  20 0
//  21 0 R        0
//  22 1 L        0
//  23 0
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// LD1R  { <Vt>.<T> }, [<Xn|SP>]
bool TryDecodeLD1R_ASISDLSO_R1(const InstData &, Instruction &) {
  return false;
}

// LD1R LD1R_asisdlsop_R1_i:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x size     0
//  11 x size     1
//  12 0 S        0
//  13 0 opcode   0
//  14 1 opcode   1
//  15 1 opcode   2
//  16 1 Rm       0
//  17 1 Rm       1
//  18 1 Rm       2
//  19 1 Rm       3
//  20 1 Rm       4
//  21 0 R        0
//  22 1 L        0
//  23 1
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// LD1R  { <Vt>.<T> }, [<Xn|SP>], <imm>
bool TryDecodeLD1R_ASISDLSOP_R1_I(const InstData &, Instruction &) {
  return false;
}

// LD1R LD1R_asisdlsop_RX1_r:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x size     0
//  11 x size     1
//  12 0 S        0
//  13 0 opcode   0
//  14 1 opcode   1
//  15 1 opcode   2
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0 R        0
//  22 1 L        0
//  23 1
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// LD1R  { <Vt>.<T> }, [<Xn|SP>], <Xm>
bool TryDecodeLD1R_ASISDLSOP_RX1_R(const InstData &, Instruction &) {
  return false;
}

// MUL MUL_asimdelem_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 x H        0
//  12 0 opcode   0
//  13 0 opcode   1
//  14 0 opcode   2
//  15 1 opcode   3
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x M        0
//  21 x L        0
//  22 x size     0
//  23 x size     1
//  24 1
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// MUL  <Vd>.<T>, <Vn>.<T>, <Vm>.<Ts>[<index>]
bool TryDecodeMUL_ASIMDELEM_R(const InstData &, Instruction &) {
  return false;
}

// FNEG FNEG_H_floatdp1:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 1
//  15 0 opc      0
//  16 1 opc      1
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 1 type     0
//  23 1 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 M        0
// FNEG  <Hd>, <Hn>
bool TryDecodeFNEG_H_FLOATDP1(const InstData &, Instruction &) {
  return false;
}

// USUBL USUBL_asimddiff_L:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 1 o1       0
//  14 0
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// USUBL{2}  <Vd>.<Ta>, <Vn>.<Tb>, <Vm>.<Tb>
bool TryDecodeUSUBL_ASIMDDIFF_L(const InstData &, Instruction &) {
  return false;
}

// SHA1C SHA1C_QSV_cryptosha3:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opcode   0
//  13 0 opcode   1
//  14 0 opcode   2
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 0 size     0
//  23 0 size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0
//  30 1
//  31 0
// SHA1C  <Qd>, <Sn>, <Vm>.4S
bool TryDecodeSHA1C_QSV_CRYPTOSHA3(const InstData &, Instruction &) {
  return false;
}

// SQDMLSL SQDMLSL_asisddiff_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1
//  13 1 o1       0
//  14 0
//  15 1
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// SQDMLSL  <Va><d>, <Vb><n>, <Vb><m>
bool TryDecodeSQDMLSL_ASISDDIFF_ONLY(const InstData &, Instruction &) {
  return false;
}

// SQDMLSL SQDMLSL_asimddiff_L:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1
//  13 1 o1       0
//  14 0
//  15 1
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// SQDMLSL{2}  <Vd>.<Ta>, <Vn>.<Tb>, <Vm>.<Tb>
bool TryDecodeSQDMLSL_ASIMDDIFF_L(const InstData &, Instruction &) {
  return false;
}

// PRFUM PRFUM_P_ldst_unscaled:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 x imm9     0
//  13 x imm9     1
//  14 x imm9     2
//  15 x imm9     3
//  16 x imm9     4
//  17 x imm9     5
//  18 x imm9     6
//  19 x imm9     7
//  20 x imm9     8
//  21 0
//  22 0 opc      0
//  23 1 opc      1
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 1 size     1
// PRFUM (<prfop>|#<imm5>), [<Xn|SP>{, #<simm>}]
bool TryDecodePRFUM_P_LDST_UNSCALED(const InstData &, Instruction &) {
  return false;
}

// LDSMAXAB LDSMAXAB_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 0 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 1 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 0 size     1
// LDSMAXAB  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDSMAXAB_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDSMAXALB LDSMAXALB_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 0 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 1 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 0 size     1
// LDSMAXALB  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDSMAXALB_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDSMAXB LDSMAXB_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 0 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 0 size     1
// LDSMAXB  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDSMAXB_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDSMAXLB LDSMAXLB_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0 opc      0
//  13 0 opc      1
//  14 1 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 0 size     1
// LDSMAXLB  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDSMAXLB_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// FABD FABD_asisdsamefp16_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 opcode   0
//  12 1 opcode   1
//  13 0 opcode   2
//  14 0
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 1
//  23 1 a        0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 1 U        0
//  30 1
//  31 0
// FABD  <Hd>, <Hn>, <Hm>
bool TryDecodeFABD_ASISDSAMEFP16_ONLY(const InstData &, Instruction &) {
  return false;
}

// FABD FABD_asisdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 opcode   0
//  12 1 opcode   1
//  13 0 opcode   2
//  14 1 opcode   3
//  15 1 opcode   4
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x sz       0
//  23 1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 1 U        0
//  30 1
//  31 0
// FABD  <V><d>, <V><n>, <V><m>
bool TryDecodeFABD_ASISDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// FABD FABD_asimdsamefp16_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 opcode   0
//  12 1 opcode   1
//  13 0 opcode   2
//  14 0
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 1
//  23 1 a        0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// FABD  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeFABD_ASIMDSAMEFP16_ONLY(const InstData &, Instruction &) {
  return false;
}

// FABD FABD_asimdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 opcode   0
//  12 1 opcode   1
//  13 0 opcode   2
//  14 1 opcode   3
//  15 1 opcode   4
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x sz       0
//  23 1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// FABD  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeFABD_ASIMDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// FCVTNU FCVTNU_32H_float2int:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 0
//  15 0
//  16 1 opcode   0
//  17 0 opcode   1
//  18 0 opcode   2
//  19 0 rmode    0
//  20 0 rmode    1
//  21 1
//  22 1 type     0
//  23 1 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 sf       0
// FCVTNU  <Wd>, <Hn>
bool TryDecodeFCVTNU_32H_FLOAT2INT(const InstData &, Instruction &) {
  return false;
}

// FCVTNU FCVTNU_64H_float2int:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 0
//  15 0
//  16 1 opcode   0
//  17 0 opcode   1
//  18 0 opcode   2
//  19 0 rmode    0
//  20 0 rmode    1
//  21 1
//  22 1 type     0
//  23 1 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 1 sf       0
// FCVTNU  <Xd>, <Hn>
bool TryDecodeFCVTNU_64H_FLOAT2INT(const InstData &, Instruction &) {
  return false;
}

// FCVTNU FCVTNU_32S_float2int:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 0
//  15 0
//  16 1 opcode   0
//  17 0 opcode   1
//  18 0 opcode   2
//  19 0 rmode    0
//  20 0 rmode    1
//  21 1
//  22 0 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 sf       0
// FCVTNU  <Wd>, <Sn>
bool TryDecodeFCVTNU_32S_FLOAT2INT(const InstData &, Instruction &) {
  return false;
}

// FCVTNU FCVTNU_64S_float2int:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 0
//  15 0
//  16 1 opcode   0
//  17 0 opcode   1
//  18 0 opcode   2
//  19 0 rmode    0
//  20 0 rmode    1
//  21 1
//  22 0 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 1 sf       0
// FCVTNU  <Xd>, <Sn>
bool TryDecodeFCVTNU_64S_FLOAT2INT(const InstData &, Instruction &) {
  return false;
}

// FCVTNU FCVTNU_32D_float2int:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 0
//  15 0
//  16 1 opcode   0
//  17 0 opcode   1
//  18 0 opcode   2
//  19 0 rmode    0
//  20 0 rmode    1
//  21 1
//  22 1 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 sf       0
// FCVTNU  <Wd>, <Dn>
bool TryDecodeFCVTNU_32D_FLOAT2INT(const InstData &, Instruction &) {
  return false;
}

// FCVTNU FCVTNU_64D_float2int:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0
//  14 0
//  15 0
//  16 1 opcode   0
//  17 0 opcode   1
//  18 0 opcode   2
//  19 0 rmode    0
//  20 0 rmode    1
//  21 1
//  22 1 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 1 sf       0
// FCVTNU  <Xd>, <Dn>
bool TryDecodeFCVTNU_64D_FLOAT2INT(const InstData &, Instruction &) {
  return false;
}

// MUL MUL_asimdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1 opcode   0
//  12 1 opcode   1
//  13 0 opcode   2
//  14 0 opcode   3
//  15 1 opcode   4
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// MUL  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeMUL_ASIMDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// CMTST CMTST_asisdsame_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 1 opcode   0
//  12 0 opcode   1
//  13 0 opcode   2
//  14 0 opcode   3
//  15 1 opcode   4
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// CMTST  <V><d>, <V><n>, <V><m>
bool TryDecodeCMTST_ASISDSAME_ONLY(const InstData &, Instruction &) {
  return false;
}

// UADDL UADDL_asimddiff_L:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 0
//  13 0 o1       0
//  14 0
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// UADDL{2}  <Vd>.<Ta>, <Vn>.<Tb>, <Vm>.<Tb>
bool TryDecodeUADDL_ASIMDDIFF_L(const InstData &, Instruction &) {
  return false;
}

// TRN2 TRN2_asimdperm_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0
//  13 1
//  14 1 op       0
//  15 0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// TRN2  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeTRN2_ASIMDPERM_ONLY(const InstData &, Instruction &) {
  return false;
}

// SQSHRUN SQSHRUN_asisdshf_N:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 op       0
//  12 0
//  13 0
//  14 0
//  15 1
//  16 x immb     0
//  17 x immb     1
//  18 x immb     2
//  19 x immh     0
//  20 x immh     1
//  21 x immh     2
//  22 x immh     3
//  23 0
//  24 1
//  25 1
//  26 1
//  27 1
//  28 1
//  29 1 U        0
//  30 1
//  31 0
// SQSHRUN  <Vb><d>, <Va><n>, #<shift>
bool TryDecodeSQSHRUN_ASISDSHF_N(const InstData &, Instruction &) {
  return false;
}

// SQSHRUN SQSHRUN_asimdshf_N:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0 op       0
//  12 0
//  13 0
//  14 0
//  15 1
//  16 x immb     0
//  17 x immb     1
//  18 x immb     2
//  19 x immh     0
//  20 x immh     1
//  21 x immh     2
//  22 x immh     3
//  23 0
//  24 1
//  25 1
//  26 1
//  27 1
//  28 0
//  29 1 U        0
//  30 x Q        0
//  31 0
// SQSHRUN{2}  <Vd>.<Tb>, <Vn>.<Ta>, #<shift>
bool TryDecodeSQSHRUN_ASIMDSHF_N(const InstData &, Instruction &) {
  return false;
}

// SQDMULL SQDMULL_asisddiff_only:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opcode   0
//  13 0 opcode   1
//  14 1 opcode   2
//  15 1 opcode   3
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 U        0
//  30 1
//  31 0
// SQDMULL  <Va><d>, <Vb><n>, <Vb><m>
bool TryDecodeSQDMULL_ASISDDIFF_ONLY(const InstData &, Instruction &) {
  return false;
}

// SQDMULL SQDMULL_asimddiff_L:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opcode   0
//  13 0 opcode   1
//  14 1 opcode   2
//  15 1 opcode   3
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 x size     0
//  23 x size     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// SQDMULL{2}  <Vd>.<Ta>, <Vn>.<Tb>, <Vm>.<Tb>
bool TryDecodeSQDMULL_ASIMDDIFF_L(const InstData &, Instruction &) {
  return false;
}

// FNMADD FNMADD_H_floatdp3:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x Ra       0
//  11 x Ra       1
//  12 x Ra       2
//  13 x Ra       3
//  14 x Ra       4
//  15 0 o0       0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1 o1       0
//  22 1 type     0
//  23 1 type     1
//  24 1
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 M        0
// FNMADD  <Hd>, <Hn>, <Hm>, <Ha>
bool TryDecodeFNMADD_H_FLOATDP3(const InstData &, Instruction &) {
  return false;
}

// FNMADD FNMADD_S_floatdp3:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x Ra       0
//  11 x Ra       1
//  12 x Ra       2
//  13 x Ra       3
//  14 x Ra       4
//  15 0 o0       0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1 o1       0
//  22 0 type     0
//  23 0 type     1
//  24 1
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 M        0
// FNMADD  <Sd>, <Sn>, <Sm>, <Sa>
bool TryDecodeFNMADD_S_FLOATDP3(const InstData &, Instruction &) {
  return false;
}

// FNMADD FNMADD_D_floatdp3:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x Ra       0
//  11 x Ra       1
//  12 x Ra       2
//  13 x Ra       3
//  14 x Ra       4
//  15 0 o0       0
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1 o1       0
//  22 1 type     0
//  23 0 type     1
//  24 1
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 M        0
// FNMADD  <Dd>, <Dn>, <Dm>, <Da>
bool TryDecodeFNMADD_D_FLOATDP3(const InstData &, Instruction &) {
  return false;
}

// FCCMP FCCMP_H_floatccmp:
//   0 x nzcv     0
//   1 x nzcv     1
//   2 x nzcv     2
//   3 x nzcv     3
//   4 0 op       0
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0
//  12 x cond     0
//  13 x cond     1
//  14 x cond     2
//  15 x cond     3
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 1 type     0
//  23 1 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 M        0
// FCCMP  <Hn>, <Hm>, #<nzcv>, <cond>
bool TryDecodeFCCMP_H_FLOATCCMP(const InstData &, Instruction &) {
  return false;
}

// FCCMP FCCMP_S_floatccmp:
//   0 x nzcv     0
//   1 x nzcv     1
//   2 x nzcv     2
//   3 x nzcv     3
//   4 0 op       0
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0
//  12 x cond     0
//  13 x cond     1
//  14 x cond     2
//  15 x cond     3
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 0 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 M        0
// FCCMP  <Sn>, <Sm>, #<nzcv>, <cond>
bool TryDecodeFCCMP_S_FLOATCCMP(const InstData &, Instruction &) {
  return false;
}

// FCCMP FCCMP_D_floatccmp:
//   0 x nzcv     0
//   1 x nzcv     1
//   2 x nzcv     2
//   3 x nzcv     3
//   4 0 op       0
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1
//  11 0
//  12 x cond     0
//  13 x cond     1
//  14 x cond     2
//  15 x cond     3
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 1 type     0
//  23 0 type     1
//  24 0
//  25 1
//  26 1
//  27 1
//  28 1
//  29 0 S        0
//  30 0
//  31 0 M        0
// FCCMP  <Dn>, <Dm>, #<nzcv>, <cond>
bool TryDecodeFCCMP_D_FLOATCCMP(const InstData &, Instruction &) {
  return false;
}

// LD3 LD3_asisdlso_B3_3b:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x size     0
//  11 x size     1
//  12 x S        0
//  13 1 opcode   0
//  14 0 opcode   1
//  15 0 opcode   2
//  16 0
//  17 0
//  18 0
//  19 0
//  20 0
//  21 0 R        0
//  22 1 L        0
//  23 0
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// LD3  { <Vt>.B, <Vt2>.B, <Vt3>.B }[<index>], [<Xn|SP>]
bool TryDecodeLD3_ASISDLSO_B3_3B(const InstData &, Instruction &) {
  return false;
}

// LD3 LD3_asisdlso_H3_3h:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0 size     0
//  11 x size     1
//  12 x S        0
//  13 1 opcode   0
//  14 1 opcode   1
//  15 0 opcode   2
//  16 0
//  17 0
//  18 0
//  19 0
//  20 0
//  21 0 R        0
//  22 1 L        0
//  23 0
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// LD3  { <Vt>.H, <Vt2>.H, <Vt3>.H }[<index>], [<Xn|SP>]
bool TryDecodeLD3_ASISDLSO_H3_3H(const InstData &, Instruction &) {
  return false;
}

// LD3 LD3_asisdlso_S3_3s:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0 size     0
//  11 0 size     1
//  12 x S        0
//  13 1 opcode   0
//  14 0 opcode   1
//  15 1 opcode   2
//  16 0
//  17 0
//  18 0
//  19 0
//  20 0
//  21 0 R        0
//  22 1 L        0
//  23 0
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// LD3  { <Vt>.S, <Vt2>.S, <Vt3>.S }[<index>], [<Xn|SP>]
bool TryDecodeLD3_ASISDLSO_S3_3S(const InstData &, Instruction &) {
  return false;
}

// LD3 LD3_asisdlso_D3_3d:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 size     0
//  11 0 size     1
//  12 0 S        0
//  13 1 opcode   0
//  14 0 opcode   1
//  15 1 opcode   2
//  16 0
//  17 0
//  18 0
//  19 0
//  20 0
//  21 0 R        0
//  22 1 L        0
//  23 0
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// LD3  { <Vt>.D, <Vt2>.D, <Vt3>.D }[<index>], [<Xn|SP>]
bool TryDecodeLD3_ASISDLSO_D3_3D(const InstData &, Instruction &) {
  return false;
}

// LD3 LD3_asisdlsop_B3_i3b:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x size     0
//  11 x size     1
//  12 x S        0
//  13 1 opcode   0
//  14 0 opcode   1
//  15 0 opcode   2
//  16 1 Rm       0
//  17 1 Rm       1
//  18 1 Rm       2
//  19 1 Rm       3
//  20 1 Rm       4
//  21 0 R        0
//  22 1 L        0
//  23 1
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// LD3  { <Vt>.B, <Vt2>.B, <Vt3>.B }[<index>], [<Xn|SP>], #3
bool TryDecodeLD3_ASISDLSOP_B3_I3B(const InstData &, Instruction &) {
  return false;
}

// LD3 LD3_asisdlsop_BX3_r3b:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 x size     0
//  11 x size     1
//  12 x S        0
//  13 1 opcode   0
//  14 0 opcode   1
//  15 0 opcode   2
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0 R        0
//  22 1 L        0
//  23 1
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// LD3  { <Vt>.B, <Vt2>.B, <Vt3>.B }[<index>], [<Xn|SP>], <Xm>
bool TryDecodeLD3_ASISDLSOP_BX3_R3B(const InstData &, Instruction &) {
  return false;
}

// LD3 LD3_asisdlsop_H3_i3h:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0 size     0
//  11 x size     1
//  12 x S        0
//  13 1 opcode   0
//  14 1 opcode   1
//  15 0 opcode   2
//  16 1 Rm       0
//  17 1 Rm       1
//  18 1 Rm       2
//  19 1 Rm       3
//  20 1 Rm       4
//  21 0 R        0
//  22 1 L        0
//  23 1
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// LD3  { <Vt>.H, <Vt2>.H, <Vt3>.H }[<index>], [<Xn|SP>], #6
bool TryDecodeLD3_ASISDLSOP_H3_I3H(const InstData &, Instruction &) {
  return false;
}

// LD3 LD3_asisdlsop_HX3_r3h:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0 size     0
//  11 x size     1
//  12 x S        0
//  13 1 opcode   0
//  14 1 opcode   1
//  15 0 opcode   2
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0 R        0
//  22 1 L        0
//  23 1
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// LD3  { <Vt>.H, <Vt2>.H, <Vt3>.H }[<index>], [<Xn|SP>], <Xm>
bool TryDecodeLD3_ASISDLSOP_HX3_R3H(const InstData &, Instruction &) {
  return false;
}

// LD3 LD3_asisdlsop_S3_i3s:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0 size     0
//  11 0 size     1
//  12 x S        0
//  13 1 opcode   0
//  14 0 opcode   1
//  15 1 opcode   2
//  16 1 Rm       0
//  17 1 Rm       1
//  18 1 Rm       2
//  19 1 Rm       3
//  20 1 Rm       4
//  21 0 R        0
//  22 1 L        0
//  23 1
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// LD3  { <Vt>.S, <Vt2>.S, <Vt3>.S }[<index>], [<Xn|SP>], #12
bool TryDecodeLD3_ASISDLSOP_S3_I3S(const InstData &, Instruction &) {
  return false;
}

// LD3 LD3_asisdlsop_SX3_r3s:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0 size     0
//  11 0 size     1
//  12 x S        0
//  13 1 opcode   0
//  14 0 opcode   1
//  15 1 opcode   2
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0 R        0
//  22 1 L        0
//  23 1
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// LD3  { <Vt>.S, <Vt2>.S, <Vt3>.S }[<index>], [<Xn|SP>], <Xm>
bool TryDecodeLD3_ASISDLSOP_SX3_R3S(const InstData &, Instruction &) {
  return false;
}

// LD3 LD3_asisdlsop_D3_i3d:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 size     0
//  11 0 size     1
//  12 0 S        0
//  13 1 opcode   0
//  14 0 opcode   1
//  15 1 opcode   2
//  16 1 Rm       0
//  17 1 Rm       1
//  18 1 Rm       2
//  19 1 Rm       3
//  20 1 Rm       4
//  21 0 R        0
//  22 1 L        0
//  23 1
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// LD3  { <Vt>.D, <Vt2>.D, <Vt3>.D }[<index>], [<Xn|SP>], #24
bool TryDecodeLD3_ASISDLSOP_D3_I3D(const InstData &, Instruction &) {
  return false;
}

// LD3 LD3_asisdlsop_DX3_r3d:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 1 size     0
//  11 0 size     1
//  12 0 S        0
//  13 1 opcode   0
//  14 0 opcode   1
//  15 1 opcode   2
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 0 R        0
//  22 1 L        0
//  23 1
//  24 1
//  25 0
//  26 1
//  27 1
//  28 0
//  29 0
//  30 x Q        0
//  31 0
// LD3  { <Vt>.D, <Vt2>.D, <Vt3>.D }[<index>], [<Xn|SP>], <Xm>
bool TryDecodeLD3_ASISDLSOP_DX3_R3D(const InstData &, Instruction &) {
  return false;
}

// FRINTN FRINTN_asimdmiscfp16_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 o1       0
//  13 0
//  14 0
//  15 1
//  16 1
//  17 0
//  18 0
//  19 1
//  20 1
//  21 1
//  22 1
//  23 0 o2       0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// FRINTN  <Vd>.<T>, <Vn>.<T>
bool TryDecodeFRINTN_ASIMDMISCFP16_R(const InstData &, Instruction &) {
  return false;
}

// FRINTN FRINTN_asimdmisc_R:
//   0 x Rd       0
//   1 x Rd       1
//   2 x Rd       2
//   3 x Rd       3
//   4 x Rd       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 0 o1       0
//  13 0
//  14 0
//  15 1
//  16 1
//  17 0
//  18 0
//  19 0
//  20 0
//  21 1
//  22 x sz       0
//  23 0 o2       0
//  24 0
//  25 1
//  26 1
//  27 1
//  28 0
//  29 0 U        0
//  30 x Q        0
//  31 0
// FRINTN  <Vd>.<T>, <Vn>.<T>
bool TryDecodeFRINTN_ASIMDMISC_R(const InstData &, Instruction &) {
  return false;
}

// STR STR_B_ldst_regoff:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 x S        0
//  13 x option   0
//  14 x option   1
//  15 x option   2
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 0 opc      0
//  23 0 opc      1
//  24 0
//  25 0
//  26 1 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 0 size     1
// STR  <Bt>, [<Xn|SP>, (<Wm>|<Xm>), <extend> {<amount>}]
bool TryDecodeSTR_B_LDST_REGOFF(const InstData &, Instruction &) {
  return false;
}

// STR STR_BL_ldst_regoff:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 x S        0
//  13 1 option   0
//  14 1 option   1
//  15 0 option   2
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 0 opc      0
//  23 0 opc      1
//  24 0
//  25 0
//  26 1 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 0 size     1
// STR  <Bt>, [<Xn|SP>, <Xm>{, LSL <amount>}]
bool TryDecodeSTR_BL_LDST_REGOFF(const InstData &, Instruction &) {
  return false;
}

// STR STR_H_ldst_regoff:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 x S        0
//  13 x option   0
//  14 x option   1
//  15 x option   2
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 0 opc      0
//  23 0 opc      1
//  24 0
//  25 0
//  26 1 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 0 size     1
// STR  <Ht>, [<Xn|SP>, (<Wm>|<Xm>){, <extend> {<amount>}}]
bool TryDecodeSTR_H_LDST_REGOFF(const InstData &, Instruction &) {
  return false;
}

// STR STR_S_ldst_regoff:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 x S        0
//  13 x option   0
//  14 x option   1
//  15 x option   2
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 0 opc      0
//  23 0 opc      1
//  24 0
//  25 0
//  26 1 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 1 size     1
// STR  <St>, [<Xn|SP>, (<Wm>|<Xm>){, <extend> {<amount>}}]
bool TryDecodeSTR_S_LDST_REGOFF(const InstData &, Instruction &) {
  return false;
}

// STR STR_D_ldst_regoff:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 x S        0
//  13 x option   0
//  14 x option   1
//  15 x option   2
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 0 opc      0
//  23 0 opc      1
//  24 0
//  25 0
//  26 1 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 1 size     1
// STR  <Dt>, [<Xn|SP>, (<Wm>|<Xm>){, <extend> {<amount>}}]
bool TryDecodeSTR_D_LDST_REGOFF(const InstData &, Instruction &) {
  return false;
}

// LDCLRAB LDCLRAB_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 0 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 1 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 0 size     1
// LDCLRAB  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDCLRAB_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDCLRALB LDCLRALB_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 0 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 1 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 0 size     1
// LDCLRALB  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDCLRALB_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDCLRB LDCLRB_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 0 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 0 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 0 size     1
// LDCLRB  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDCLRB_32_MEMOP(const InstData &, Instruction &) {
  return false;
}

// LDCLRLB LDCLRLB_32_memop:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 0
//  12 1 opc      0
//  13 0 opc      1
//  14 0 opc      2
//  15 0 o3       0
//  16 x Rs       0
//  17 x Rs       1
//  18 x Rs       2
//  19 x Rs       3
//  20 x Rs       4
//  21 1
//  22 1 R        0
//  23 0 A        0
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 0 size     1
// LDCLRLB  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDCLRLB_32_MEMOP(const InstData &, Instruction &) {
  return false;
}


namespace {

static bool (*const kDecoder[])(const InstData &data, Instruction &inst) = {

    TryDecodeABS_ASIMDMISC_R,
    TryDecodeABS_ASISDMISC_R,
    TryDecodeADCS_32_ADDSUB_CARRY,
    TryDecodeADCS_64_ADDSUB_CARRY,
    TryDecodeADC_32_ADDSUB_CARRY,
    TryDecodeADC_64_ADDSUB_CARRY,
    TryDecodeADDHN_ASIMDDIFF_N,
    TryDecodeADDP_ASIMDSAME_ONLY,
    TryDecodeADDP_ASISDPAIR_ONLY,
    TryDecodeADDS_32S_ADDSUB_EXT,
    TryDecodeADDS_32S_ADDSUB_IMM,
    TryDecodeADDS_32_ADDSUB_SHIFT,
    TryDecodeADDS_64S_ADDSUB_EXT,
    TryDecodeADDS_64S_ADDSUB_IMM,
    TryDecodeADDS_64_ADDSUB_SHIFT,
    TryDecodeADDV_ASIMDALL_ONLY,
    TryDecodeADD_32_ADDSUB_EXT,
    TryDecodeADD_32_ADDSUB_IMM,
    TryDecodeADD_32_ADDSUB_SHIFT,
    TryDecodeADD_64_ADDSUB_EXT,
    TryDecodeADD_64_ADDSUB_IMM,
    TryDecodeADD_64_ADDSUB_SHIFT,
    TryDecodeADD_ASIMDSAME_ONLY,
    TryDecodeADD_ASISDSAME_ONLY,
    TryDecodeADRP_ONLY_PCRELADDR,
    TryDecodeADR_ONLY_PCRELADDR,
    TryDecodeAESD_B_CRYPTOAES,
    TryDecodeAESE_B_CRYPTOAES,
    TryDecodeAESIMC_B_CRYPTOAES,
    TryDecodeAESMC_B_CRYPTOAES,
    TryDecodeANDS_32S_LOG_IMM,
    TryDecodeANDS_32_LOG_SHIFT,
    TryDecodeANDS_64S_LOG_IMM,
    TryDecodeANDS_64_LOG_SHIFT,
    TryDecodeAND_32_LOG_IMM,
    TryDecodeAND_32_LOG_SHIFT,
    TryDecodeAND_64_LOG_IMM,
    TryDecodeAND_64_LOG_SHIFT,
    TryDecodeAND_ASIMDSAME_ONLY,
    TryDecodeASRV_32_DP_2SRC,
    TryDecodeASRV_64_DP_2SRC,
    TryDecodeASR_ASRV_32_DP_2SRC,
    TryDecodeASR_ASRV_64_DP_2SRC,
    TryDecodeASR_SBFM_32M_BITFIELD,
    TryDecodeASR_SBFM_64M_BITFIELD,
    TryDecodeAT_SYS_CR_SYSTEM,
    TryDecodeBFC_BFM_32M_BITFIELD,
    TryDecodeBFC_BFM_64M_BITFIELD,
    TryDecodeBFI_BFM_32M_BITFIELD,
    TryDecodeBFI_BFM_64M_BITFIELD,
    TryDecodeBFM_32M_BITFIELD,
    TryDecodeBFM_64M_BITFIELD,
    TryDecodeBFXIL_BFM_32M_BITFIELD,
    TryDecodeBFXIL_BFM_64M_BITFIELD,
    TryDecodeBICS_32_LOG_SHIFT,
    TryDecodeBICS_64_LOG_SHIFT,
    TryDecodeBIC_32_LOG_SHIFT,
    TryDecodeBIC_64_LOG_SHIFT,
    TryDecodeBIC_ASIMDIMM_L_HL,
    TryDecodeBIC_ASIMDIMM_L_SL,
    TryDecodeBIC_ASIMDSAME_ONLY,
    TryDecodeBIF_ASIMDSAME_ONLY,
    TryDecodeBIT_ASIMDSAME_ONLY,
    TryDecodeBLR_64_BRANCH_REG,
    TryDecodeBL_ONLY_BRANCH_IMM,
    TryDecodeBRK_EX_EXCEPTION,
    TryDecodeBR_64_BRANCH_REG,
    TryDecodeBSL_ASIMDSAME_ONLY,
    TryDecodeB_ONLY_BRANCH_IMM,
    TryDecodeB_ONLY_CONDBRANCH,
    TryDecodeCASAB_C32_LDSTEXCL,
    TryDecodeCASAH_C32_LDSTEXCL,
    TryDecodeCASALB_C32_LDSTEXCL,
    TryDecodeCASALH_C32_LDSTEXCL,
    TryDecodeCASAL_C32_LDSTEXCL,
    TryDecodeCASAL_C64_LDSTEXCL,
    TryDecodeCASA_C32_LDSTEXCL,
    TryDecodeCASA_C64_LDSTEXCL,
    TryDecodeCASB_C32_LDSTEXCL,
    TryDecodeCASH_C32_LDSTEXCL,
    TryDecodeCASLB_C32_LDSTEXCL,
    TryDecodeCASLH_C32_LDSTEXCL,
    TryDecodeCASL_C32_LDSTEXCL,
    TryDecodeCASL_C64_LDSTEXCL,
    TryDecodeCASPAL_CP32_LDSTEXCL,
    TryDecodeCASPAL_CP64_LDSTEXCL,
    TryDecodeCASPA_CP32_LDSTEXCL,
    TryDecodeCASPA_CP64_LDSTEXCL,
    TryDecodeCASPL_CP32_LDSTEXCL,
    TryDecodeCASPL_CP64_LDSTEXCL,
    TryDecodeCASP_CP32_LDSTEXCL,
    TryDecodeCASP_CP64_LDSTEXCL,
    TryDecodeCAS_C32_LDSTEXCL,
    TryDecodeCAS_C64_LDSTEXCL,
    TryDecodeCBNZ_32_COMPBRANCH,
    TryDecodeCBNZ_64_COMPBRANCH,
    TryDecodeCBZ_32_COMPBRANCH,
    TryDecodeCBZ_64_COMPBRANCH,
    TryDecodeCCMN_32_CONDCMP_IMM,
    TryDecodeCCMN_32_CONDCMP_REG,
    TryDecodeCCMN_64_CONDCMP_IMM,
    TryDecodeCCMN_64_CONDCMP_REG,
    TryDecodeCCMP_32_CONDCMP_IMM,
    TryDecodeCCMP_32_CONDCMP_REG,
    TryDecodeCCMP_64_CONDCMP_IMM,
    TryDecodeCCMP_64_CONDCMP_REG,
    TryDecodeCINC_CSINC_32_CONDSEL,
    TryDecodeCINC_CSINC_64_CONDSEL,
    TryDecodeCINV_CSINV_32_CONDSEL,
    TryDecodeCINV_CSINV_64_CONDSEL,
    TryDecodeCLREX_BN_SYSTEM,
    TryDecodeCLS_32_DP_1SRC,
    TryDecodeCLS_64_DP_1SRC,
    TryDecodeCLS_ASIMDMISC_R,
    TryDecodeCLZ_32_DP_1SRC,
    TryDecodeCLZ_64_DP_1SRC,
    TryDecodeCLZ_ASIMDMISC_R,
    TryDecodeCMEQ_ASIMDMISC_Z,
    TryDecodeCMEQ_ASIMDSAME_ONLY,
    TryDecodeCMEQ_ASISDMISC_Z,
    TryDecodeCMEQ_ASISDSAME_ONLY,
    TryDecodeCMGE_ASIMDMISC_Z,
    TryDecodeCMGE_ASIMDSAME_ONLY,
    TryDecodeCMGE_ASISDMISC_Z,
    TryDecodeCMGE_ASISDSAME_ONLY,
    TryDecodeCMGT_ASIMDMISC_Z,
    TryDecodeCMGT_ASIMDSAME_ONLY,
    TryDecodeCMGT_ASISDMISC_Z,
    TryDecodeCMGT_ASISDSAME_ONLY,
    TryDecodeCMHI_ASIMDSAME_ONLY,
    TryDecodeCMHI_ASISDSAME_ONLY,
    TryDecodeCMHS_ASIMDSAME_ONLY,
    TryDecodeCMHS_ASISDSAME_ONLY,
    TryDecodeCMLE_ASIMDMISC_Z,
    TryDecodeCMLE_ASISDMISC_Z,
    TryDecodeCMLT_ASIMDMISC_Z,
    TryDecodeCMLT_ASISDMISC_Z,
    TryDecodeCMN_ADDS_32S_ADDSUB_EXT,
    TryDecodeCMN_ADDS_32S_ADDSUB_IMM,
    TryDecodeCMN_ADDS_32_ADDSUB_SHIFT,
    TryDecodeCMN_ADDS_64S_ADDSUB_EXT,
    TryDecodeCMN_ADDS_64S_ADDSUB_IMM,
    TryDecodeCMN_ADDS_64_ADDSUB_SHIFT,
    TryDecodeCMP_SUBS_32S_ADDSUB_EXT,
    TryDecodeCMP_SUBS_32S_ADDSUB_IMM,
    TryDecodeCMP_SUBS_32_ADDSUB_SHIFT,
    TryDecodeCMP_SUBS_64S_ADDSUB_EXT,
    TryDecodeCMP_SUBS_64S_ADDSUB_IMM,
    TryDecodeCMP_SUBS_64_ADDSUB_SHIFT,
    TryDecodeCMTST_ASIMDSAME_ONLY,
    TryDecodeCMTST_ASISDSAME_ONLY,
    TryDecodeCNEG_CSNEG_32_CONDSEL,
    TryDecodeCNEG_CSNEG_64_CONDSEL,
    TryDecodeCNT_ASIMDMISC_R,
    TryDecodeCRC32B_32C_DP_2SRC,
    TryDecodeCRC32CB_32C_DP_2SRC,
    TryDecodeCRC32CH_32C_DP_2SRC,
    TryDecodeCRC32CW_32C_DP_2SRC,
    TryDecodeCRC32CX_64C_DP_2SRC,
    TryDecodeCRC32H_32C_DP_2SRC,
    TryDecodeCRC32W_32C_DP_2SRC,
    TryDecodeCRC32X_64C_DP_2SRC,
    TryDecodeCSEL_32_CONDSEL,
    TryDecodeCSEL_64_CONDSEL,
    TryDecodeCSETM_CSINV_32_CONDSEL,
    TryDecodeCSETM_CSINV_64_CONDSEL,
    TryDecodeCSET_CSINC_32_CONDSEL,
    TryDecodeCSET_CSINC_64_CONDSEL,
    TryDecodeCSINC_32_CONDSEL,
    TryDecodeCSINC_64_CONDSEL,
    TryDecodeCSINV_32_CONDSEL,
    TryDecodeCSINV_64_CONDSEL,
    TryDecodeCSNEG_32_CONDSEL,
    TryDecodeCSNEG_64_CONDSEL,
    TryDecodeDCPS1_DC_EXCEPTION,
    TryDecodeDCPS2_DC_EXCEPTION,
    TryDecodeDCPS3_DC_EXCEPTION,
    TryDecodeDC_SYS_CR_SYSTEM,
    TryDecodeDMB_BO_SYSTEM,
    TryDecodeDRPS_64E_BRANCH_REG,
    TryDecodeDSB_BO_SYSTEM,
    TryDecodeDUP_ASIMDINS_DR_R,
    TryDecodeDUP_ASIMDINS_DV_V,
    TryDecodeDUP_ASISDONE_ONLY,
    TryDecodeEON_32_LOG_SHIFT,
    TryDecodeEON_64_LOG_SHIFT,
    TryDecodeEOR_32_LOG_IMM,
    TryDecodeEOR_32_LOG_SHIFT,
    TryDecodeEOR_64_LOG_IMM,
    TryDecodeEOR_64_LOG_SHIFT,
    TryDecodeEOR_ASIMDSAME_ONLY,
    TryDecodeERET_64E_BRANCH_REG,
    TryDecodeESB_HI_SYSTEM,
    TryDecodeEXTR_32_EXTRACT,
    TryDecodeEXTR_64_EXTRACT,
    TryDecodeEXT_ASIMDEXT_ONLY,
    TryDecodeFABD_ASIMDSAME_ONLY,
    TryDecodeFABD_ASIMDSAMEFP16_ONLY,
    TryDecodeFABD_ASISDSAME_ONLY,
    TryDecodeFABD_ASISDSAMEFP16_ONLY,
    TryDecodeFABS_D_FLOATDP1,
    TryDecodeFABS_H_FLOATDP1,
    TryDecodeFABS_S_FLOATDP1,
    TryDecodeFABS_ASIMDMISC_R,
    TryDecodeFABS_ASIMDMISCFP16_R,
    TryDecodeFACGE_ASIMDSAME_ONLY,
    TryDecodeFACGE_ASIMDSAMEFP16_ONLY,
    TryDecodeFACGE_ASISDSAME_ONLY,
    TryDecodeFACGE_ASISDSAMEFP16_ONLY,
    TryDecodeFACGT_ASIMDSAME_ONLY,
    TryDecodeFACGT_ASIMDSAMEFP16_ONLY,
    TryDecodeFACGT_ASISDSAME_ONLY,
    TryDecodeFACGT_ASISDSAMEFP16_ONLY,
    TryDecodeFADDP_ASIMDSAME_ONLY,
    TryDecodeFADDP_ASIMDSAMEFP16_ONLY,
    TryDecodeFADDP_ASISDPAIR_ONLY_H,
    TryDecodeFADDP_ASISDPAIR_ONLY_SD,
    TryDecodeFADD_D_FLOATDP2,
    TryDecodeFADD_H_FLOATDP2,
    TryDecodeFADD_S_FLOATDP2,
    TryDecodeFADD_ASIMDSAME_ONLY,
    TryDecodeFADD_ASIMDSAMEFP16_ONLY,
    TryDecodeFCCMPE_D_FLOATCCMP,
    TryDecodeFCCMPE_H_FLOATCCMP,
    TryDecodeFCCMPE_S_FLOATCCMP,
    TryDecodeFCCMP_D_FLOATCCMP,
    TryDecodeFCCMP_H_FLOATCCMP,
    TryDecodeFCCMP_S_FLOATCCMP,
    TryDecodeFCMEQ_ASIMDMISC_FZ,
    TryDecodeFCMEQ_ASIMDMISCFP16_FZ,
    TryDecodeFCMEQ_ASIMDSAME_ONLY,
    TryDecodeFCMEQ_ASIMDSAMEFP16_ONLY,
    TryDecodeFCMEQ_ASISDMISC_FZ,
    TryDecodeFCMEQ_ASISDMISCFP16_FZ,
    TryDecodeFCMEQ_ASISDSAME_ONLY,
    TryDecodeFCMEQ_ASISDSAMEFP16_ONLY,
    TryDecodeFCMGE_ASIMDMISC_FZ,
    TryDecodeFCMGE_ASIMDMISCFP16_FZ,
    TryDecodeFCMGE_ASIMDSAME_ONLY,
    TryDecodeFCMGE_ASIMDSAMEFP16_ONLY,
    TryDecodeFCMGE_ASISDMISC_FZ,
    TryDecodeFCMGE_ASISDMISCFP16_FZ,
    TryDecodeFCMGE_ASISDSAME_ONLY,
    TryDecodeFCMGE_ASISDSAMEFP16_ONLY,
    TryDecodeFCMGT_ASIMDMISC_FZ,
    TryDecodeFCMGT_ASIMDMISCFP16_FZ,
    TryDecodeFCMGT_ASIMDSAME_ONLY,
    TryDecodeFCMGT_ASIMDSAMEFP16_ONLY,
    TryDecodeFCMGT_ASISDMISC_FZ,
    TryDecodeFCMGT_ASISDMISCFP16_FZ,
    TryDecodeFCMGT_ASISDSAME_ONLY,
    TryDecodeFCMGT_ASISDSAMEFP16_ONLY,
    TryDecodeFCMLE_ASIMDMISC_FZ,
    TryDecodeFCMLE_ASIMDMISCFP16_FZ,
    TryDecodeFCMLE_ASISDMISC_FZ,
    TryDecodeFCMLE_ASISDMISCFP16_FZ,
    TryDecodeFCMLT_ASIMDMISC_FZ,
    TryDecodeFCMLT_ASIMDMISCFP16_FZ,
    TryDecodeFCMLT_ASISDMISC_FZ,
    TryDecodeFCMLT_ASISDMISCFP16_FZ,
    TryDecodeFCMPE_DZ_FLOATCMP,
    TryDecodeFCMPE_D_FLOATCMP,
    TryDecodeFCMPE_HZ_FLOATCMP,
    TryDecodeFCMPE_H_FLOATCMP,
    TryDecodeFCMPE_SZ_FLOATCMP,
    TryDecodeFCMPE_S_FLOATCMP,
    TryDecodeFCMP_DZ_FLOATCMP,
    TryDecodeFCMP_D_FLOATCMP,
    TryDecodeFCMP_HZ_FLOATCMP,
    TryDecodeFCMP_H_FLOATCMP,
    TryDecodeFCMP_SZ_FLOATCMP,
    TryDecodeFCMP_S_FLOATCMP,
    TryDecodeFCSEL_D_FLOATSEL,
    TryDecodeFCSEL_H_FLOATSEL,
    TryDecodeFCSEL_S_FLOATSEL,
    TryDecodeFCVTAS_32D_FLOAT2INT,
    TryDecodeFCVTAS_32H_FLOAT2INT,
    TryDecodeFCVTAS_32S_FLOAT2INT,
    TryDecodeFCVTAS_64D_FLOAT2INT,
    TryDecodeFCVTAS_64H_FLOAT2INT,
    TryDecodeFCVTAS_64S_FLOAT2INT,
    TryDecodeFCVTAS_ASIMDMISC_R,
    TryDecodeFCVTAS_ASIMDMISCFP16_R,
    TryDecodeFCVTAS_ASISDMISC_R,
    TryDecodeFCVTAS_ASISDMISCFP16_R,
    TryDecodeFCVTAU_32D_FLOAT2INT,
    TryDecodeFCVTAU_32H_FLOAT2INT,
    TryDecodeFCVTAU_32S_FLOAT2INT,
    TryDecodeFCVTAU_64D_FLOAT2INT,
    TryDecodeFCVTAU_64H_FLOAT2INT,
    TryDecodeFCVTAU_64S_FLOAT2INT,
    TryDecodeFCVTAU_ASIMDMISC_R,
    TryDecodeFCVTAU_ASIMDMISCFP16_R,
    TryDecodeFCVTAU_ASISDMISC_R,
    TryDecodeFCVTAU_ASISDMISCFP16_R,
    TryDecodeFCVTL_ASIMDMISC_L,
    TryDecodeFCVTMS_32D_FLOAT2INT,
    TryDecodeFCVTMS_32H_FLOAT2INT,
    TryDecodeFCVTMS_32S_FLOAT2INT,
    TryDecodeFCVTMS_64D_FLOAT2INT,
    TryDecodeFCVTMS_64H_FLOAT2INT,
    TryDecodeFCVTMS_64S_FLOAT2INT,
    TryDecodeFCVTMS_ASIMDMISC_R,
    TryDecodeFCVTMS_ASIMDMISCFP16_R,
    TryDecodeFCVTMS_ASISDMISC_R,
    TryDecodeFCVTMS_ASISDMISCFP16_R,
    TryDecodeFCVTMU_32D_FLOAT2INT,
    TryDecodeFCVTMU_32H_FLOAT2INT,
    TryDecodeFCVTMU_32S_FLOAT2INT,
    TryDecodeFCVTMU_64D_FLOAT2INT,
    TryDecodeFCVTMU_64H_FLOAT2INT,
    TryDecodeFCVTMU_64S_FLOAT2INT,
    TryDecodeFCVTMU_ASIMDMISC_R,
    TryDecodeFCVTMU_ASIMDMISCFP16_R,
    TryDecodeFCVTMU_ASISDMISC_R,
    TryDecodeFCVTMU_ASISDMISCFP16_R,
    TryDecodeFCVTNS_32D_FLOAT2INT,
    TryDecodeFCVTNS_32H_FLOAT2INT,
    TryDecodeFCVTNS_32S_FLOAT2INT,
    TryDecodeFCVTNS_64D_FLOAT2INT,
    TryDecodeFCVTNS_64H_FLOAT2INT,
    TryDecodeFCVTNS_64S_FLOAT2INT,
    TryDecodeFCVTNS_ASIMDMISC_R,
    TryDecodeFCVTNS_ASIMDMISCFP16_R,
    TryDecodeFCVTNS_ASISDMISC_R,
    TryDecodeFCVTNS_ASISDMISCFP16_R,
    TryDecodeFCVTNU_32D_FLOAT2INT,
    TryDecodeFCVTNU_32H_FLOAT2INT,
    TryDecodeFCVTNU_32S_FLOAT2INT,
    TryDecodeFCVTNU_64D_FLOAT2INT,
    TryDecodeFCVTNU_64H_FLOAT2INT,
    TryDecodeFCVTNU_64S_FLOAT2INT,
    TryDecodeFCVTNU_ASIMDMISC_R,
    TryDecodeFCVTNU_ASIMDMISCFP16_R,
    TryDecodeFCVTNU_ASISDMISC_R,
    TryDecodeFCVTNU_ASISDMISCFP16_R,
    TryDecodeFCVTN_ASIMDMISC_N,
    TryDecodeFCVTPS_32D_FLOAT2INT,
    TryDecodeFCVTPS_32H_FLOAT2INT,
    TryDecodeFCVTPS_32S_FLOAT2INT,
    TryDecodeFCVTPS_64D_FLOAT2INT,
    TryDecodeFCVTPS_64H_FLOAT2INT,
    TryDecodeFCVTPS_64S_FLOAT2INT,
    TryDecodeFCVTPS_ASIMDMISC_R,
    TryDecodeFCVTPS_ASIMDMISCFP16_R,
    TryDecodeFCVTPS_ASISDMISC_R,
    TryDecodeFCVTPS_ASISDMISCFP16_R,
    TryDecodeFCVTPU_32D_FLOAT2INT,
    TryDecodeFCVTPU_32H_FLOAT2INT,
    TryDecodeFCVTPU_32S_FLOAT2INT,
    TryDecodeFCVTPU_64D_FLOAT2INT,
    TryDecodeFCVTPU_64H_FLOAT2INT,
    TryDecodeFCVTPU_64S_FLOAT2INT,
    TryDecodeFCVTPU_ASIMDMISC_R,
    TryDecodeFCVTPU_ASIMDMISCFP16_R,
    TryDecodeFCVTPU_ASISDMISC_R,
    TryDecodeFCVTPU_ASISDMISCFP16_R,
    TryDecodeFCVTXN_ASIMDMISC_N,
    TryDecodeFCVTXN_ASISDMISC_N,
    TryDecodeFCVTZS_32D_FLOAT2FIX,
    TryDecodeFCVTZS_32D_FLOAT2INT,
    TryDecodeFCVTZS_32H_FLOAT2FIX,
    TryDecodeFCVTZS_32H_FLOAT2INT,
    TryDecodeFCVTZS_32S_FLOAT2FIX,
    TryDecodeFCVTZS_32S_FLOAT2INT,
    TryDecodeFCVTZS_64D_FLOAT2FIX,
    TryDecodeFCVTZS_64D_FLOAT2INT,
    TryDecodeFCVTZS_64H_FLOAT2FIX,
    TryDecodeFCVTZS_64H_FLOAT2INT,
    TryDecodeFCVTZS_64S_FLOAT2FIX,
    TryDecodeFCVTZS_64S_FLOAT2INT,
    TryDecodeFCVTZS_ASIMDMISC_R,
    TryDecodeFCVTZS_ASIMDMISCFP16_R,
    TryDecodeFCVTZS_ASIMDSHF_C,
    TryDecodeFCVTZS_ASISDMISC_R,
    TryDecodeFCVTZS_ASISDMISCFP16_R,
    TryDecodeFCVTZS_ASISDSHF_C,
    TryDecodeFCVTZU_32D_FLOAT2FIX,
    TryDecodeFCVTZU_32D_FLOAT2INT,
    TryDecodeFCVTZU_32H_FLOAT2FIX,
    TryDecodeFCVTZU_32H_FLOAT2INT,
    TryDecodeFCVTZU_32S_FLOAT2FIX,
    TryDecodeFCVTZU_32S_FLOAT2INT,
    TryDecodeFCVTZU_64D_FLOAT2FIX,
    TryDecodeFCVTZU_64D_FLOAT2INT,
    TryDecodeFCVTZU_64H_FLOAT2FIX,
    TryDecodeFCVTZU_64H_FLOAT2INT,
    TryDecodeFCVTZU_64S_FLOAT2FIX,
    TryDecodeFCVTZU_64S_FLOAT2INT,
    TryDecodeFCVTZU_ASIMDMISC_R,
    TryDecodeFCVTZU_ASIMDMISCFP16_R,
    TryDecodeFCVTZU_ASIMDSHF_C,
    TryDecodeFCVTZU_ASISDMISC_R,
    TryDecodeFCVTZU_ASISDMISCFP16_R,
    TryDecodeFCVTZU_ASISDSHF_C,
    TryDecodeFCVT_DH_FLOATDP1,
    TryDecodeFCVT_DS_FLOATDP1,
    TryDecodeFCVT_HD_FLOATDP1,
    TryDecodeFCVT_HS_FLOATDP1,
    TryDecodeFCVT_SD_FLOATDP1,
    TryDecodeFCVT_SH_FLOATDP1,
    TryDecodeFDIV_D_FLOATDP2,
    TryDecodeFDIV_H_FLOATDP2,
    TryDecodeFDIV_S_FLOATDP2,
    TryDecodeFDIV_ASIMDSAME_ONLY,
    TryDecodeFDIV_ASIMDSAMEFP16_ONLY,
    TryDecodeFMADD_D_FLOATDP3,
    TryDecodeFMADD_H_FLOATDP3,
    TryDecodeFMADD_S_FLOATDP3,
    TryDecodeFMAXNMP_ASIMDSAME_ONLY,
    TryDecodeFMAXNMP_ASIMDSAMEFP16_ONLY,
    TryDecodeFMAXNMP_ASISDPAIR_ONLY_H,
    TryDecodeFMAXNMP_ASISDPAIR_ONLY_SD,
    TryDecodeFMAXNMV_ASIMDALL_ONLY_H,
    TryDecodeFMAXNMV_ASIMDALL_ONLY_SD,
    TryDecodeFMAXNM_D_FLOATDP2,
    TryDecodeFMAXNM_H_FLOATDP2,
    TryDecodeFMAXNM_S_FLOATDP2,
    TryDecodeFMAXNM_ASIMDSAME_ONLY,
    TryDecodeFMAXNM_ASIMDSAMEFP16_ONLY,
    TryDecodeFMAXP_ASIMDSAME_ONLY,
    TryDecodeFMAXP_ASIMDSAMEFP16_ONLY,
    TryDecodeFMAXP_ASISDPAIR_ONLY_H,
    TryDecodeFMAXP_ASISDPAIR_ONLY_SD,
    TryDecodeFMAXV_ASIMDALL_ONLY_H,
    TryDecodeFMAXV_ASIMDALL_ONLY_SD,
    TryDecodeFMAX_D_FLOATDP2,
    TryDecodeFMAX_H_FLOATDP2,
    TryDecodeFMAX_S_FLOATDP2,
    TryDecodeFMAX_ASIMDSAME_ONLY,
    TryDecodeFMAX_ASIMDSAMEFP16_ONLY,
    TryDecodeFMINNMP_ASIMDSAME_ONLY,
    TryDecodeFMINNMP_ASIMDSAMEFP16_ONLY,
    TryDecodeFMINNMP_ASISDPAIR_ONLY_H,
    TryDecodeFMINNMP_ASISDPAIR_ONLY_SD,
    TryDecodeFMINNMV_ASIMDALL_ONLY_H,
    TryDecodeFMINNMV_ASIMDALL_ONLY_SD,
    TryDecodeFMINNM_D_FLOATDP2,
    TryDecodeFMINNM_H_FLOATDP2,
    TryDecodeFMINNM_S_FLOATDP2,
    TryDecodeFMINNM_ASIMDSAME_ONLY,
    TryDecodeFMINNM_ASIMDSAMEFP16_ONLY,
    TryDecodeFMINP_ASIMDSAME_ONLY,
    TryDecodeFMINP_ASIMDSAMEFP16_ONLY,
    TryDecodeFMINP_ASISDPAIR_ONLY_H,
    TryDecodeFMINP_ASISDPAIR_ONLY_SD,
    TryDecodeFMINV_ASIMDALL_ONLY_H,
    TryDecodeFMINV_ASIMDALL_ONLY_SD,
    TryDecodeFMIN_D_FLOATDP2,
    TryDecodeFMIN_H_FLOATDP2,
    TryDecodeFMIN_S_FLOATDP2,
    TryDecodeFMIN_ASIMDSAME_ONLY,
    TryDecodeFMIN_ASIMDSAMEFP16_ONLY,
    TryDecodeFMLA_ASIMDELEM_RH_H,
    TryDecodeFMLA_ASIMDELEM_R_SD,
    TryDecodeFMLA_ASIMDSAME_ONLY,
    TryDecodeFMLA_ASIMDSAMEFP16_ONLY,
    TryDecodeFMLA_ASISDELEM_RH_H,
    TryDecodeFMLA_ASISDELEM_R_SD,
    TryDecodeFMLS_ASIMDELEM_RH_H,
    TryDecodeFMLS_ASIMDELEM_R_SD,
    TryDecodeFMLS_ASIMDSAME_ONLY,
    TryDecodeFMLS_ASIMDSAMEFP16_ONLY,
    TryDecodeFMLS_ASISDELEM_RH_H,
    TryDecodeFMLS_ASISDELEM_R_SD,
    TryDecodeFMOV_32H_FLOAT2INT,
    TryDecodeFMOV_32S_FLOAT2INT,
    TryDecodeFMOV_64D_FLOAT2INT,
    TryDecodeFMOV_64H_FLOAT2INT,
    TryDecodeFMOV_64VX_FLOAT2INT,
    TryDecodeFMOV_D64_FLOAT2INT,
    TryDecodeFMOV_D_FLOATDP1,
    TryDecodeFMOV_D_FLOATIMM,
    TryDecodeFMOV_H32_FLOAT2INT,
    TryDecodeFMOV_H64_FLOAT2INT,
    TryDecodeFMOV_H_FLOATDP1,
    TryDecodeFMOV_H_FLOATIMM,
    TryDecodeFMOV_S32_FLOAT2INT,
    TryDecodeFMOV_S_FLOATDP1,
    TryDecodeFMOV_S_FLOATIMM,
    TryDecodeFMOV_V64I_FLOAT2INT,
    TryDecodeFMOV_ASIMDIMM_D2_D,
    TryDecodeFMOV_ASIMDIMM_H_H,
    TryDecodeFMOV_ASIMDIMM_S_S,
    TryDecodeFMSUB_D_FLOATDP3,
    TryDecodeFMSUB_H_FLOATDP3,
    TryDecodeFMSUB_S_FLOATDP3,
    TryDecodeFMULX_ASIMDELEM_RH_H,
    TryDecodeFMULX_ASIMDELEM_R_SD,
    TryDecodeFMULX_ASIMDSAME_ONLY,
    TryDecodeFMULX_ASIMDSAMEFP16_ONLY,
    TryDecodeFMULX_ASISDELEM_RH_H,
    TryDecodeFMULX_ASISDELEM_R_SD,
    TryDecodeFMULX_ASISDSAME_ONLY,
    TryDecodeFMULX_ASISDSAMEFP16_ONLY,
    TryDecodeFMUL_D_FLOATDP2,
    TryDecodeFMUL_H_FLOATDP2,
    TryDecodeFMUL_S_FLOATDP2,
    TryDecodeFMUL_ASIMDELEM_RH_H,
    TryDecodeFMUL_ASIMDELEM_R_SD,
    TryDecodeFMUL_ASIMDSAME_ONLY,
    TryDecodeFMUL_ASIMDSAMEFP16_ONLY,
    TryDecodeFMUL_ASISDELEM_RH_H,
    TryDecodeFMUL_ASISDELEM_R_SD,
    TryDecodeFNEG_D_FLOATDP1,
    TryDecodeFNEG_H_FLOATDP1,
    TryDecodeFNEG_S_FLOATDP1,
    TryDecodeFNEG_ASIMDMISC_R,
    TryDecodeFNEG_ASIMDMISCFP16_R,
    TryDecodeFNMADD_D_FLOATDP3,
    TryDecodeFNMADD_H_FLOATDP3,
    TryDecodeFNMADD_S_FLOATDP3,
    TryDecodeFNMSUB_D_FLOATDP3,
    TryDecodeFNMSUB_H_FLOATDP3,
    TryDecodeFNMSUB_S_FLOATDP3,
    TryDecodeFNMUL_D_FLOATDP2,
    TryDecodeFNMUL_H_FLOATDP2,
    TryDecodeFNMUL_S_FLOATDP2,
    TryDecodeFRECPE_ASIMDMISC_R,
    TryDecodeFRECPE_ASIMDMISCFP16_R,
    TryDecodeFRECPE_ASISDMISC_R,
    TryDecodeFRECPE_ASISDMISCFP16_R,
    TryDecodeFRECPS_ASIMDSAME_ONLY,
    TryDecodeFRECPS_ASIMDSAMEFP16_ONLY,
    TryDecodeFRECPS_ASISDSAME_ONLY,
    TryDecodeFRECPS_ASISDSAMEFP16_ONLY,
    TryDecodeFRECPX_ASISDMISC_R,
    TryDecodeFRECPX_ASISDMISCFP16_R,
    TryDecodeFRINTA_D_FLOATDP1,
    TryDecodeFRINTA_H_FLOATDP1,
    TryDecodeFRINTA_S_FLOATDP1,
    TryDecodeFRINTA_ASIMDMISC_R,
    TryDecodeFRINTA_ASIMDMISCFP16_R,
    TryDecodeFRINTI_D_FLOATDP1,
    TryDecodeFRINTI_H_FLOATDP1,
    TryDecodeFRINTI_S_FLOATDP1,
    TryDecodeFRINTI_ASIMDMISC_R,
    TryDecodeFRINTI_ASIMDMISCFP16_R,
    TryDecodeFRINTM_D_FLOATDP1,
    TryDecodeFRINTM_H_FLOATDP1,
    TryDecodeFRINTM_S_FLOATDP1,
    TryDecodeFRINTM_ASIMDMISC_R,
    TryDecodeFRINTM_ASIMDMISCFP16_R,
    TryDecodeFRINTN_D_FLOATDP1,
    TryDecodeFRINTN_H_FLOATDP1,
    TryDecodeFRINTN_S_FLOATDP1,
    TryDecodeFRINTN_ASIMDMISC_R,
    TryDecodeFRINTN_ASIMDMISCFP16_R,
    TryDecodeFRINTP_D_FLOATDP1,
    TryDecodeFRINTP_H_FLOATDP1,
    TryDecodeFRINTP_S_FLOATDP1,
    TryDecodeFRINTP_ASIMDMISC_R,
    TryDecodeFRINTP_ASIMDMISCFP16_R,
    TryDecodeFRINTX_D_FLOATDP1,
    TryDecodeFRINTX_H_FLOATDP1,
    TryDecodeFRINTX_S_FLOATDP1,
    TryDecodeFRINTX_ASIMDMISC_R,
    TryDecodeFRINTX_ASIMDMISCFP16_R,
    TryDecodeFRINTZ_D_FLOATDP1,
    TryDecodeFRINTZ_H_FLOATDP1,
    TryDecodeFRINTZ_S_FLOATDP1,
    TryDecodeFRINTZ_ASIMDMISC_R,
    TryDecodeFRINTZ_ASIMDMISCFP16_R,
    TryDecodeFRSQRTE_ASIMDMISC_R,
    TryDecodeFRSQRTE_ASIMDMISCFP16_R,
    TryDecodeFRSQRTE_ASISDMISC_R,
    TryDecodeFRSQRTE_ASISDMISCFP16_R,
    TryDecodeFRSQRTS_ASIMDSAME_ONLY,
    TryDecodeFRSQRTS_ASIMDSAMEFP16_ONLY,
    TryDecodeFRSQRTS_ASISDSAME_ONLY,
    TryDecodeFRSQRTS_ASISDSAMEFP16_ONLY,
    TryDecodeFSQRT_D_FLOATDP1,
    TryDecodeFSQRT_H_FLOATDP1,
    TryDecodeFSQRT_S_FLOATDP1,
    TryDecodeFSQRT_ASIMDMISC_R,
    TryDecodeFSQRT_ASIMDMISCFP16_R,
    TryDecodeFSUB_D_FLOATDP2,
    TryDecodeFSUB_H_FLOATDP2,
    TryDecodeFSUB_S_FLOATDP2,
    TryDecodeFSUB_ASIMDSAME_ONLY,
    TryDecodeFSUB_ASIMDSAMEFP16_ONLY,
    TryDecodeHINT_1,
    TryDecodeHINT_2,
    TryDecodeHINT_3,
    TryDecodeHLT_EX_EXCEPTION,
    TryDecodeHVC_EX_EXCEPTION,
    TryDecodeIC_SYS_CR_SYSTEM,
    TryDecodeINS_ASIMDINS_IR_R,
    TryDecodeINS_ASIMDINS_IV_V,
    TryDecodeISB_BI_SYSTEM,
    TryDecodeLD1R_ASISDLSO_R1,
    TryDecodeLD1R_ASISDLSOP_R1_I,
    TryDecodeLD1R_ASISDLSOP_RX1_R,
    TryDecodeLD1_ASISDLSE_R1_1V,
    TryDecodeLD1_ASISDLSE_R2_2V,
    TryDecodeLD1_ASISDLSE_R3_3V,
    TryDecodeLD1_ASISDLSE_R4_4V,
    TryDecodeLD1_ASISDLSEP_I1_I1,
    TryDecodeLD1_ASISDLSEP_I2_I2,
    TryDecodeLD1_ASISDLSEP_I3_I3,
    TryDecodeLD1_ASISDLSEP_I4_I4,
    TryDecodeLD1_ASISDLSEP_R1_R1,
    TryDecodeLD1_ASISDLSEP_R2_R2,
    TryDecodeLD1_ASISDLSEP_R3_R3,
    TryDecodeLD1_ASISDLSEP_R4_R4,
    TryDecodeLD1_ASISDLSO_B1_1B,
    TryDecodeLD1_ASISDLSO_D1_1D,
    TryDecodeLD1_ASISDLSO_H1_1H,
    TryDecodeLD1_ASISDLSO_S1_1S,
    TryDecodeLD1_ASISDLSOP_B1_I1B,
    TryDecodeLD1_ASISDLSOP_BX1_R1B,
    TryDecodeLD1_ASISDLSOP_D1_I1D,
    TryDecodeLD1_ASISDLSOP_DX1_R1D,
    TryDecodeLD1_ASISDLSOP_H1_I1H,
    TryDecodeLD1_ASISDLSOP_HX1_R1H,
    TryDecodeLD1_ASISDLSOP_S1_I1S,
    TryDecodeLD1_ASISDLSOP_SX1_R1S,
    TryDecodeLD2R_ASISDLSO_R2,
    TryDecodeLD2R_ASISDLSOP_R2_I,
    TryDecodeLD2R_ASISDLSOP_RX2_R,
    TryDecodeLD2_ASISDLSE_R2,
    TryDecodeLD2_ASISDLSEP_I2_I,
    TryDecodeLD2_ASISDLSEP_R2_R,
    TryDecodeLD2_ASISDLSO_B2_2B,
    TryDecodeLD2_ASISDLSO_D2_2D,
    TryDecodeLD2_ASISDLSO_H2_2H,
    TryDecodeLD2_ASISDLSO_S2_2S,
    TryDecodeLD2_ASISDLSOP_B2_I2B,
    TryDecodeLD2_ASISDLSOP_BX2_R2B,
    TryDecodeLD2_ASISDLSOP_D2_I2D,
    TryDecodeLD2_ASISDLSOP_DX2_R2D,
    TryDecodeLD2_ASISDLSOP_H2_I2H,
    TryDecodeLD2_ASISDLSOP_HX2_R2H,
    TryDecodeLD2_ASISDLSOP_S2_I2S,
    TryDecodeLD2_ASISDLSOP_SX2_R2S,
    TryDecodeLD3R_ASISDLSO_R3,
    TryDecodeLD3R_ASISDLSOP_R3_I,
    TryDecodeLD3R_ASISDLSOP_RX3_R,
    TryDecodeLD3_ASISDLSE_R3,
    TryDecodeLD3_ASISDLSEP_I3_I,
    TryDecodeLD3_ASISDLSEP_R3_R,
    TryDecodeLD3_ASISDLSO_B3_3B,
    TryDecodeLD3_ASISDLSO_D3_3D,
    TryDecodeLD3_ASISDLSO_H3_3H,
    TryDecodeLD3_ASISDLSO_S3_3S,
    TryDecodeLD3_ASISDLSOP_B3_I3B,
    TryDecodeLD3_ASISDLSOP_BX3_R3B,
    TryDecodeLD3_ASISDLSOP_D3_I3D,
    TryDecodeLD3_ASISDLSOP_DX3_R3D,
    TryDecodeLD3_ASISDLSOP_H3_I3H,
    TryDecodeLD3_ASISDLSOP_HX3_R3H,
    TryDecodeLD3_ASISDLSOP_S3_I3S,
    TryDecodeLD3_ASISDLSOP_SX3_R3S,
    TryDecodeLD4R_ASISDLSO_R4,
    TryDecodeLD4R_ASISDLSOP_R4_I,
    TryDecodeLD4R_ASISDLSOP_RX4_R,
    TryDecodeLD4_ASISDLSE_R4,
    TryDecodeLD4_ASISDLSEP_I4_I,
    TryDecodeLD4_ASISDLSEP_R4_R,
    TryDecodeLD4_ASISDLSO_B4_4B,
    TryDecodeLD4_ASISDLSO_D4_4D,
    TryDecodeLD4_ASISDLSO_H4_4H,
    TryDecodeLD4_ASISDLSO_S4_4S,
    TryDecodeLD4_ASISDLSOP_B4_I4B,
    TryDecodeLD4_ASISDLSOP_BX4_R4B,
    TryDecodeLD4_ASISDLSOP_D4_I4D,
    TryDecodeLD4_ASISDLSOP_DX4_R4D,
    TryDecodeLD4_ASISDLSOP_H4_I4H,
    TryDecodeLD4_ASISDLSOP_HX4_R4H,
    TryDecodeLD4_ASISDLSOP_S4_I4S,
    TryDecodeLD4_ASISDLSOP_SX4_R4S,
    TryDecodeLDADDAB_32_MEMOP,
    TryDecodeLDADDAH_32_MEMOP,
    TryDecodeLDADDALB_32_MEMOP,
    TryDecodeLDADDALH_32_MEMOP,
    TryDecodeLDADDAL_32_MEMOP,
    TryDecodeLDADDAL_64_MEMOP,
    TryDecodeLDADDA_32_MEMOP,
    TryDecodeLDADDA_64_MEMOP,
    TryDecodeLDADDB_32_MEMOP,
    TryDecodeLDADDH_32_MEMOP,
    TryDecodeLDADDLB_32_MEMOP,
    TryDecodeLDADDLH_32_MEMOP,
    TryDecodeLDADDL_32_MEMOP,
    TryDecodeLDADDL_64_MEMOP,
    TryDecodeLDADD_32_MEMOP,
    TryDecodeLDADD_64_MEMOP,
    TryDecodeLDARB_LR32_LDSTEXCL,
    TryDecodeLDARH_LR32_LDSTEXCL,
    TryDecodeLDAR_LR32_LDSTEXCL,
    TryDecodeLDAR_LR64_LDSTEXCL,
    TryDecodeLDAXP_LP32_LDSTEXCL,
    TryDecodeLDAXP_LP64_LDSTEXCL,
    TryDecodeLDAXRB_LR32_LDSTEXCL,
    TryDecodeLDAXRH_LR32_LDSTEXCL,
    TryDecodeLDAXR_LR32_LDSTEXCL,
    TryDecodeLDAXR_LR64_LDSTEXCL,
    TryDecodeLDCLRAB_32_MEMOP,
    TryDecodeLDCLRAH_32_MEMOP,
    TryDecodeLDCLRALB_32_MEMOP,
    TryDecodeLDCLRALH_32_MEMOP,
    TryDecodeLDCLRAL_32_MEMOP,
    TryDecodeLDCLRAL_64_MEMOP,
    TryDecodeLDCLRA_32_MEMOP,
    TryDecodeLDCLRA_64_MEMOP,
    TryDecodeLDCLRB_32_MEMOP,
    TryDecodeLDCLRH_32_MEMOP,
    TryDecodeLDCLRLB_32_MEMOP,
    TryDecodeLDCLRLH_32_MEMOP,
    TryDecodeLDCLRL_32_MEMOP,
    TryDecodeLDCLRL_64_MEMOP,
    TryDecodeLDCLR_32_MEMOP,
    TryDecodeLDCLR_64_MEMOP,
    TryDecodeLDEORAB_32_MEMOP,
    TryDecodeLDEORAH_32_MEMOP,
    TryDecodeLDEORALB_32_MEMOP,
    TryDecodeLDEORALH_32_MEMOP,
    TryDecodeLDEORAL_32_MEMOP,
    TryDecodeLDEORAL_64_MEMOP,
    TryDecodeLDEORA_32_MEMOP,
    TryDecodeLDEORA_64_MEMOP,
    TryDecodeLDEORB_32_MEMOP,
    TryDecodeLDEORH_32_MEMOP,
    TryDecodeLDEORLB_32_MEMOP,
    TryDecodeLDEORLH_32_MEMOP,
    TryDecodeLDEORL_32_MEMOP,
    TryDecodeLDEORL_64_MEMOP,
    TryDecodeLDEOR_32_MEMOP,
    TryDecodeLDEOR_64_MEMOP,
    TryDecodeLDLARB_LR32_LDSTEXCL,
    TryDecodeLDLARH_LR32_LDSTEXCL,
    TryDecodeLDLAR_LR32_LDSTEXCL,
    TryDecodeLDLAR_LR64_LDSTEXCL,
    TryDecodeLDNP_32_LDSTNAPAIR_OFFS,
    TryDecodeLDNP_64_LDSTNAPAIR_OFFS,
    TryDecodeLDNP_D_LDSTNAPAIR_OFFS,
    TryDecodeLDNP_Q_LDSTNAPAIR_OFFS,
    TryDecodeLDNP_S_LDSTNAPAIR_OFFS,
    TryDecodeLDPSW_64_LDSTPAIR_OFF,
    TryDecodeLDPSW_64_LDSTPAIR_POST,
    TryDecodeLDPSW_64_LDSTPAIR_PRE,
    TryDecodeLDP_32_LDSTPAIR_OFF,
    TryDecodeLDP_32_LDSTPAIR_POST,
    TryDecodeLDP_32_LDSTPAIR_PRE,
    TryDecodeLDP_64_LDSTPAIR_OFF,
    TryDecodeLDP_64_LDSTPAIR_POST,
    TryDecodeLDP_64_LDSTPAIR_PRE,
    TryDecodeLDP_D_LDSTPAIR_OFF,
    TryDecodeLDP_D_LDSTPAIR_POST,
    TryDecodeLDP_D_LDSTPAIR_PRE,
    TryDecodeLDP_Q_LDSTPAIR_OFF,
    TryDecodeLDP_Q_LDSTPAIR_POST,
    TryDecodeLDP_Q_LDSTPAIR_PRE,
    TryDecodeLDP_S_LDSTPAIR_OFF,
    TryDecodeLDP_S_LDSTPAIR_POST,
    TryDecodeLDP_S_LDSTPAIR_PRE,
    TryDecodeLDRB_32BL_LDST_REGOFF,
    TryDecodeLDRB_32B_LDST_REGOFF,
    TryDecodeLDRB_32_LDST_IMMPOST,
    TryDecodeLDRB_32_LDST_IMMPRE,
    TryDecodeLDRB_32_LDST_POS,
    TryDecodeLDRH_32_LDST_IMMPOST,
    TryDecodeLDRH_32_LDST_IMMPRE,
    TryDecodeLDRH_32_LDST_POS,
    TryDecodeLDRH_32_LDST_REGOFF,
    TryDecodeLDRSB_32BL_LDST_REGOFF,
    TryDecodeLDRSB_32B_LDST_REGOFF,
    TryDecodeLDRSB_32_LDST_IMMPOST,
    TryDecodeLDRSB_32_LDST_IMMPRE,
    TryDecodeLDRSB_32_LDST_POS,
    TryDecodeLDRSB_64BL_LDST_REGOFF,
    TryDecodeLDRSB_64B_LDST_REGOFF,
    TryDecodeLDRSB_64_LDST_IMMPOST,
    TryDecodeLDRSB_64_LDST_IMMPRE,
    TryDecodeLDRSB_64_LDST_POS,
    TryDecodeLDRSH_32_LDST_IMMPOST,
    TryDecodeLDRSH_32_LDST_IMMPRE,
    TryDecodeLDRSH_32_LDST_POS,
    TryDecodeLDRSH_32_LDST_REGOFF,
    TryDecodeLDRSH_64_LDST_IMMPOST,
    TryDecodeLDRSH_64_LDST_IMMPRE,
    TryDecodeLDRSH_64_LDST_POS,
    TryDecodeLDRSH_64_LDST_REGOFF,
    TryDecodeLDRSW_64_LDST_IMMPOST,
    TryDecodeLDRSW_64_LDST_IMMPRE,
    TryDecodeLDRSW_64_LDST_POS,
    TryDecodeLDRSW_64_LDST_REGOFF,
    TryDecodeLDRSW_64_LOADLIT,
    TryDecodeLDR_32_LDST_IMMPOST,
    TryDecodeLDR_32_LDST_IMMPRE,
    TryDecodeLDR_32_LDST_POS,
    TryDecodeLDR_32_LDST_REGOFF,
    TryDecodeLDR_32_LOADLIT,
    TryDecodeLDR_64_LDST_IMMPOST,
    TryDecodeLDR_64_LDST_IMMPRE,
    TryDecodeLDR_64_LDST_POS,
    TryDecodeLDR_64_LDST_REGOFF,
    TryDecodeLDR_64_LOADLIT,
    TryDecodeLDR_BL_LDST_REGOFF,
    TryDecodeLDR_B_LDST_IMMPOST,
    TryDecodeLDR_B_LDST_IMMPRE,
    TryDecodeLDR_B_LDST_POS,
    TryDecodeLDR_B_LDST_REGOFF,
    TryDecodeLDR_D_LDST_IMMPOST,
    TryDecodeLDR_D_LDST_IMMPRE,
    TryDecodeLDR_D_LDST_POS,
    TryDecodeLDR_D_LDST_REGOFF,
    TryDecodeLDR_D_LOADLIT,
    TryDecodeLDR_H_LDST_IMMPOST,
    TryDecodeLDR_H_LDST_IMMPRE,
    TryDecodeLDR_H_LDST_POS,
    TryDecodeLDR_H_LDST_REGOFF,
    TryDecodeLDR_Q_LDST_IMMPOST,
    TryDecodeLDR_Q_LDST_IMMPRE,
    TryDecodeLDR_Q_LDST_POS,
    TryDecodeLDR_Q_LDST_REGOFF,
    TryDecodeLDR_Q_LOADLIT,
    TryDecodeLDR_S_LDST_IMMPOST,
    TryDecodeLDR_S_LDST_IMMPRE,
    TryDecodeLDR_S_LDST_POS,
    TryDecodeLDR_S_LDST_REGOFF,
    TryDecodeLDR_S_LOADLIT,
    TryDecodeLDSETAB_32_MEMOP,
    TryDecodeLDSETAH_32_MEMOP,
    TryDecodeLDSETALB_32_MEMOP,
    TryDecodeLDSETALH_32_MEMOP,
    TryDecodeLDSETAL_32_MEMOP,
    TryDecodeLDSETAL_64_MEMOP,
    TryDecodeLDSETA_32_MEMOP,
    TryDecodeLDSETA_64_MEMOP,
    TryDecodeLDSETB_32_MEMOP,
    TryDecodeLDSETH_32_MEMOP,
    TryDecodeLDSETLB_32_MEMOP,
    TryDecodeLDSETLH_32_MEMOP,
    TryDecodeLDSETL_32_MEMOP,
    TryDecodeLDSETL_64_MEMOP,
    TryDecodeLDSET_32_MEMOP,
    TryDecodeLDSET_64_MEMOP,
    TryDecodeLDSMAXAB_32_MEMOP,
    TryDecodeLDSMAXAH_32_MEMOP,
    TryDecodeLDSMAXALB_32_MEMOP,
    TryDecodeLDSMAXALH_32_MEMOP,
    TryDecodeLDSMAXAL_32_MEMOP,
    TryDecodeLDSMAXAL_64_MEMOP,
    TryDecodeLDSMAXA_32_MEMOP,
    TryDecodeLDSMAXA_64_MEMOP,
    TryDecodeLDSMAXB_32_MEMOP,
    TryDecodeLDSMAXH_32_MEMOP,
    TryDecodeLDSMAXLB_32_MEMOP,
    TryDecodeLDSMAXLH_32_MEMOP,
    TryDecodeLDSMAXL_32_MEMOP,
    TryDecodeLDSMAXL_64_MEMOP,
    TryDecodeLDSMAX_32_MEMOP,
    TryDecodeLDSMAX_64_MEMOP,
    TryDecodeLDSMINAB_32_MEMOP,
    TryDecodeLDSMINAH_32_MEMOP,
    TryDecodeLDSMINALB_32_MEMOP,
    TryDecodeLDSMINALH_32_MEMOP,
    TryDecodeLDSMINAL_32_MEMOP,
    TryDecodeLDSMINAL_64_MEMOP,
    TryDecodeLDSMINA_32_MEMOP,
    TryDecodeLDSMINA_64_MEMOP,
    TryDecodeLDSMINB_32_MEMOP,
    TryDecodeLDSMINH_32_MEMOP,
    TryDecodeLDSMINLB_32_MEMOP,
    TryDecodeLDSMINLH_32_MEMOP,
    TryDecodeLDSMINL_32_MEMOP,
    TryDecodeLDSMINL_64_MEMOP,
    TryDecodeLDSMIN_32_MEMOP,
    TryDecodeLDSMIN_64_MEMOP,
    TryDecodeLDTRB_32_LDST_UNPRIV,
    TryDecodeLDTRH_32_LDST_UNPRIV,
    TryDecodeLDTRSB_32_LDST_UNPRIV,
    TryDecodeLDTRSB_64_LDST_UNPRIV,
    TryDecodeLDTRSH_32_LDST_UNPRIV,
    TryDecodeLDTRSH_64_LDST_UNPRIV,
    TryDecodeLDTRSW_64_LDST_UNPRIV,
    TryDecodeLDTR_32_LDST_UNPRIV,
    TryDecodeLDTR_64_LDST_UNPRIV,
    TryDecodeLDUMAXAB_32_MEMOP,
    TryDecodeLDUMAXAH_32_MEMOP,
    TryDecodeLDUMAXALB_32_MEMOP,
    TryDecodeLDUMAXALH_32_MEMOP,
    TryDecodeLDUMAXAL_32_MEMOP,
    TryDecodeLDUMAXAL_64_MEMOP,
    TryDecodeLDUMAXA_32_MEMOP,
    TryDecodeLDUMAXA_64_MEMOP,
    TryDecodeLDUMAXB_32_MEMOP,
    TryDecodeLDUMAXH_32_MEMOP,
    TryDecodeLDUMAXLB_32_MEMOP,
    TryDecodeLDUMAXLH_32_MEMOP,
    TryDecodeLDUMAXL_32_MEMOP,
    TryDecodeLDUMAXL_64_MEMOP,
    TryDecodeLDUMAX_32_MEMOP,
    TryDecodeLDUMAX_64_MEMOP,
    TryDecodeLDUMINAB_32_MEMOP,
    TryDecodeLDUMINAH_32_MEMOP,
    TryDecodeLDUMINALB_32_MEMOP,
    TryDecodeLDUMINALH_32_MEMOP,
    TryDecodeLDUMINAL_32_MEMOP,
    TryDecodeLDUMINAL_64_MEMOP,
    TryDecodeLDUMINA_32_MEMOP,
    TryDecodeLDUMINA_64_MEMOP,
    TryDecodeLDUMINB_32_MEMOP,
    TryDecodeLDUMINH_32_MEMOP,
    TryDecodeLDUMINLB_32_MEMOP,
    TryDecodeLDUMINLH_32_MEMOP,
    TryDecodeLDUMINL_32_MEMOP,
    TryDecodeLDUMINL_64_MEMOP,
    TryDecodeLDUMIN_32_MEMOP,
    TryDecodeLDUMIN_64_MEMOP,
    TryDecodeLDURB_32_LDST_UNSCALED,
    TryDecodeLDURH_32_LDST_UNSCALED,
    TryDecodeLDURSB_32_LDST_UNSCALED,
    TryDecodeLDURSB_64_LDST_UNSCALED,
    TryDecodeLDURSH_32_LDST_UNSCALED,
    TryDecodeLDURSH_64_LDST_UNSCALED,
    TryDecodeLDURSW_64_LDST_UNSCALED,
    TryDecodeLDUR_32_LDST_UNSCALED,
    TryDecodeLDUR_64_LDST_UNSCALED,
    TryDecodeLDUR_B_LDST_UNSCALED,
    TryDecodeLDUR_D_LDST_UNSCALED,
    TryDecodeLDUR_H_LDST_UNSCALED,
    TryDecodeLDUR_Q_LDST_UNSCALED,
    TryDecodeLDUR_S_LDST_UNSCALED,
    TryDecodeLDXP_LP32_LDSTEXCL,
    TryDecodeLDXP_LP64_LDSTEXCL,
    TryDecodeLDXRB_LR32_LDSTEXCL,
    TryDecodeLDXRH_LR32_LDSTEXCL,
    TryDecodeLDXR_LR32_LDSTEXCL,
    TryDecodeLDXR_LR64_LDSTEXCL,
    TryDecodeLSLV_32_DP_2SRC,
    TryDecodeLSLV_64_DP_2SRC,
    TryDecodeLSL_LSLV_32_DP_2SRC,
    TryDecodeLSL_LSLV_64_DP_2SRC,
    TryDecodeLSL_UBFM_32M_BITFIELD,
    TryDecodeLSL_UBFM_64M_BITFIELD,
    TryDecodeLSRV_32_DP_2SRC,
    TryDecodeLSRV_64_DP_2SRC,
    TryDecodeLSR_LSRV_32_DP_2SRC,
    TryDecodeLSR_LSRV_64_DP_2SRC,
    TryDecodeLSR_UBFM_32M_BITFIELD,
    TryDecodeLSR_UBFM_64M_BITFIELD,
    TryDecodeMADD_32A_DP_3SRC,
    TryDecodeMADD_64A_DP_3SRC,
    TryDecodeMLA_ASIMDELEM_R,
    TryDecodeMLA_ASIMDSAME_ONLY,
    TryDecodeMLS_ASIMDELEM_R,
    TryDecodeMLS_ASIMDSAME_ONLY,
    TryDecodeMNEG_MSUB_32A_DP_3SRC,
    TryDecodeMNEG_MSUB_64A_DP_3SRC,
    TryDecodeMOVI_ASIMDIMM_D2_D,
    TryDecodeMOVI_ASIMDIMM_D_DS,
    TryDecodeMOVI_ASIMDIMM_L_HL,
    TryDecodeMOVI_ASIMDIMM_L_SL,
    TryDecodeMOVI_ASIMDIMM_M_SM,
    TryDecodeMOVI_ASIMDIMM_N_B,
    TryDecodeMOVK_32_MOVEWIDE,
    TryDecodeMOVK_64_MOVEWIDE,
    TryDecodeMOVN_32_MOVEWIDE,
    TryDecodeMOVN_64_MOVEWIDE,
    TryDecodeMOVZ_32_MOVEWIDE,
    TryDecodeMOVZ_64_MOVEWIDE,
    TryDecodeMOV_ADD_32_ADDSUB_IMM,
    TryDecodeMOV_ADD_64_ADDSUB_IMM,
    TryDecodeMOV_DUP_ASISDONE_ONLY,
    TryDecodeMOV_INS_ASIMDINS_IR_R,
    TryDecodeMOV_INS_ASIMDINS_IV_V,
    TryDecodeMOV_MOVN_32_MOVEWIDE,
    TryDecodeMOV_MOVN_64_MOVEWIDE,
    TryDecodeMOV_MOVZ_32_MOVEWIDE,
    TryDecodeMOV_MOVZ_64_MOVEWIDE,
    TryDecodeMOV_ORR_32_LOG_IMM,
    TryDecodeMOV_ORR_32_LOG_SHIFT,
    TryDecodeMOV_ORR_64_LOG_IMM,
    TryDecodeMOV_ORR_64_LOG_SHIFT,
    TryDecodeMOV_ORR_ASIMDSAME_ONLY,
    TryDecodeMOV_UMOV_ASIMDINS_W_W,
    TryDecodeMOV_UMOV_ASIMDINS_X_X,
    TryDecodeMRS_RS_SYSTEM,
    TryDecodeMSR_SI_SYSTEM,
    TryDecodeMSR_SR_SYSTEM,
    TryDecodeMSUB_32A_DP_3SRC,
    TryDecodeMSUB_64A_DP_3SRC,
    TryDecodeMUL_MADD_32A_DP_3SRC,
    TryDecodeMUL_MADD_64A_DP_3SRC,
    TryDecodeMUL_ASIMDELEM_R,
    TryDecodeMUL_ASIMDSAME_ONLY,
    TryDecodeMVNI_ASIMDIMM_L_HL,
    TryDecodeMVNI_ASIMDIMM_L_SL,
    TryDecodeMVNI_ASIMDIMM_M_SM,
    TryDecodeMVN_NOT_ASIMDMISC_R,
    TryDecodeMVN_ORN_32_LOG_SHIFT,
    TryDecodeMVN_ORN_64_LOG_SHIFT,
    TryDecodeNEGS_SUBS_32_ADDSUB_SHIFT,
    TryDecodeNEGS_SUBS_64_ADDSUB_SHIFT,
    TryDecodeNEG_SUB_32_ADDSUB_SHIFT,
    TryDecodeNEG_SUB_64_ADDSUB_SHIFT,
    TryDecodeNEG_ASIMDMISC_R,
    TryDecodeNEG_ASISDMISC_R,
    TryDecodeNGCS_SBCS_32_ADDSUB_CARRY,
    TryDecodeNGCS_SBCS_64_ADDSUB_CARRY,
    TryDecodeNGC_SBC_32_ADDSUB_CARRY,
    TryDecodeNGC_SBC_64_ADDSUB_CARRY,
    TryDecodeNOP_HI_SYSTEM,
    TryDecodeNOT_ASIMDMISC_R,
    TryDecodeORN_32_LOG_SHIFT,
    TryDecodeORN_64_LOG_SHIFT,
    TryDecodeORN_ASIMDSAME_ONLY,
    TryDecodeORR_32_LOG_IMM,
    TryDecodeORR_32_LOG_SHIFT,
    TryDecodeORR_64_LOG_IMM,
    TryDecodeORR_64_LOG_SHIFT,
    TryDecodeORR_ASIMDIMM_L_HL,
    TryDecodeORR_ASIMDIMM_L_SL,
    TryDecodeORR_ASIMDSAME_ONLY,
    TryDecodePMULL_ASIMDDIFF_L,
    TryDecodePMUL_ASIMDSAME_ONLY,
    TryDecodePRFM_P_LDST_POS,
    TryDecodePRFM_P_LDST_REGOFF,
    TryDecodePRFM_P_LOADLIT,
    TryDecodePRFUM_P_LDST_UNSCALED,
    TryDecodePSB_HC_SYSTEM,
    TryDecodeRADDHN_ASIMDDIFF_N,
    TryDecodeRBIT_32_DP_1SRC,
    TryDecodeRBIT_64_DP_1SRC,
    TryDecodeRBIT_ASIMDMISC_R,
    TryDecodeRET_64R_BRANCH_REG,
    TryDecodeREV16_32_DP_1SRC,
    TryDecodeREV16_64_DP_1SRC,
    TryDecodeREV16_ASIMDMISC_R,
    TryDecodeREV32_64_DP_1SRC,
    TryDecodeREV32_ASIMDMISC_R,
    TryDecodeREV64_REV_64_DP_1SRC,
    TryDecodeREV64_ASIMDMISC_R,
    TryDecodeREV_32_DP_1SRC,
    TryDecodeREV_64_DP_1SRC,
    TryDecodeRORV_32_DP_2SRC,
    TryDecodeRORV_64_DP_2SRC,
    TryDecodeROR_EXTR_32_EXTRACT,
    TryDecodeROR_EXTR_64_EXTRACT,
    TryDecodeROR_RORV_32_DP_2SRC,
    TryDecodeROR_RORV_64_DP_2SRC,
    TryDecodeRSHRN_ASIMDSHF_N,
    TryDecodeRSUBHN_ASIMDDIFF_N,
    TryDecodeSABAL_ASIMDDIFF_L,
    TryDecodeSABA_ASIMDSAME_ONLY,
    TryDecodeSABDL_ASIMDDIFF_L,
    TryDecodeSABD_ASIMDSAME_ONLY,
    TryDecodeSADALP_ASIMDMISC_P,
    TryDecodeSADDLP_ASIMDMISC_P,
    TryDecodeSADDLV_ASIMDALL_ONLY,
    TryDecodeSADDL_ASIMDDIFF_L,
    TryDecodeSADDW_ASIMDDIFF_W,
    TryDecodeSBCS_32_ADDSUB_CARRY,
    TryDecodeSBCS_64_ADDSUB_CARRY,
    TryDecodeSBC_32_ADDSUB_CARRY,
    TryDecodeSBC_64_ADDSUB_CARRY,
    TryDecodeSBFIZ_SBFM_32M_BITFIELD,
    TryDecodeSBFIZ_SBFM_64M_BITFIELD,
    TryDecodeSBFM_32M_BITFIELD,
    TryDecodeSBFM_64M_BITFIELD,
    TryDecodeSBFX_SBFM_32M_BITFIELD,
    TryDecodeSBFX_SBFM_64M_BITFIELD,
    TryDecodeSCVTF_D32_FLOAT2FIX,
    TryDecodeSCVTF_D32_FLOAT2INT,
    TryDecodeSCVTF_D64_FLOAT2FIX,
    TryDecodeSCVTF_D64_FLOAT2INT,
    TryDecodeSCVTF_H32_FLOAT2FIX,
    TryDecodeSCVTF_H32_FLOAT2INT,
    TryDecodeSCVTF_H64_FLOAT2FIX,
    TryDecodeSCVTF_H64_FLOAT2INT,
    TryDecodeSCVTF_S32_FLOAT2FIX,
    TryDecodeSCVTF_S32_FLOAT2INT,
    TryDecodeSCVTF_S64_FLOAT2FIX,
    TryDecodeSCVTF_S64_FLOAT2INT,
    TryDecodeSCVTF_ASIMDMISC_R,
    TryDecodeSCVTF_ASIMDMISCFP16_R,
    TryDecodeSCVTF_ASIMDSHF_C,
    TryDecodeSCVTF_ASISDMISC_R,
    TryDecodeSCVTF_ASISDMISCFP16_R,
    TryDecodeSCVTF_ASISDSHF_C,
    TryDecodeSDIV_32_DP_2SRC,
    TryDecodeSDIV_64_DP_2SRC,
    TryDecodeSEVL_HI_SYSTEM,
    TryDecodeSEV_HI_SYSTEM,
    TryDecodeSHA1C_QSV_CRYPTOSHA3,
    TryDecodeSHA1H_SS_CRYPTOSHA2,
    TryDecodeSHA1M_QSV_CRYPTOSHA3,
    TryDecodeSHA1P_QSV_CRYPTOSHA3,
    TryDecodeSHA1SU0_VVV_CRYPTOSHA3,
    TryDecodeSHA1SU1_VV_CRYPTOSHA2,
    TryDecodeSHA256H2_QQV_CRYPTOSHA3,
    TryDecodeSHA256H_QQV_CRYPTOSHA3,
    TryDecodeSHA256SU0_VV_CRYPTOSHA2,
    TryDecodeSHA256SU1_VVV_CRYPTOSHA3,
    TryDecodeSHADD_ASIMDSAME_ONLY,
    TryDecodeSHLL_ASIMDMISC_S,
    TryDecodeSHL_ASIMDSHF_R,
    TryDecodeSHL_ASISDSHF_R,
    TryDecodeSHRN_ASIMDSHF_N,
    TryDecodeSHSUB_ASIMDSAME_ONLY,
    TryDecodeSLI_ASIMDSHF_R,
    TryDecodeSLI_ASISDSHF_R,
    TryDecodeSMADDL_64WA_DP_3SRC,
    TryDecodeSMAXP_ASIMDSAME_ONLY,
    TryDecodeSMAXV_ASIMDALL_ONLY,
    TryDecodeSMAX_ASIMDSAME_ONLY,
    TryDecodeSMC_EX_EXCEPTION,
    TryDecodeSMINP_ASIMDSAME_ONLY,
    TryDecodeSMINV_ASIMDALL_ONLY,
    TryDecodeSMIN_ASIMDSAME_ONLY,
    TryDecodeSMLAL_ASIMDDIFF_L,
    TryDecodeSMLAL_ASIMDELEM_L,
    TryDecodeSMLSL_ASIMDDIFF_L,
    TryDecodeSMLSL_ASIMDELEM_L,
    TryDecodeSMNEGL_SMSUBL_64WA_DP_3SRC,
    TryDecodeSMOV_ASIMDINS_W_W,
    TryDecodeSMOV_ASIMDINS_X_X,
    TryDecodeSMSUBL_64WA_DP_3SRC,
    TryDecodeSMULH_64_DP_3SRC,
    TryDecodeSMULL_SMADDL_64WA_DP_3SRC,
    TryDecodeSMULL_ASIMDDIFF_L,
    TryDecodeSMULL_ASIMDELEM_L,
    TryDecodeSQABS_ASIMDMISC_R,
    TryDecodeSQABS_ASISDMISC_R,
    TryDecodeSQADD_ASIMDSAME_ONLY,
    TryDecodeSQADD_ASISDSAME_ONLY,
    TryDecodeSQDMLAL_ASIMDDIFF_L,
    TryDecodeSQDMLAL_ASIMDELEM_L,
    TryDecodeSQDMLAL_ASISDDIFF_ONLY,
    TryDecodeSQDMLAL_ASISDELEM_L,
    TryDecodeSQDMLSL_ASIMDDIFF_L,
    TryDecodeSQDMLSL_ASIMDELEM_L,
    TryDecodeSQDMLSL_ASISDDIFF_ONLY,
    TryDecodeSQDMLSL_ASISDELEM_L,
    TryDecodeSQDMULH_ASIMDELEM_R,
    TryDecodeSQDMULH_ASIMDSAME_ONLY,
    TryDecodeSQDMULH_ASISDELEM_R,
    TryDecodeSQDMULH_ASISDSAME_ONLY,
    TryDecodeSQDMULL_ASIMDDIFF_L,
    TryDecodeSQDMULL_ASIMDELEM_L,
    TryDecodeSQDMULL_ASISDDIFF_ONLY,
    TryDecodeSQDMULL_ASISDELEM_L,
    TryDecodeSQNEG_ASIMDMISC_R,
    TryDecodeSQNEG_ASISDMISC_R,
    TryDecodeSQRDMLAH_ASIMDELEM_R,
    TryDecodeSQRDMLAH_ASIMDSAME2_ONLY,
    TryDecodeSQRDMLAH_ASISDELEM_R,
    TryDecodeSQRDMLAH_ASISDSAME2_ONLY,
    TryDecodeSQRDMLSH_ASIMDELEM_R,
    TryDecodeSQRDMLSH_ASIMDSAME2_ONLY,
    TryDecodeSQRDMLSH_ASISDELEM_R,
    TryDecodeSQRDMLSH_ASISDSAME2_ONLY,
    TryDecodeSQRDMULH_ASIMDELEM_R,
    TryDecodeSQRDMULH_ASIMDSAME_ONLY,
    TryDecodeSQRDMULH_ASISDELEM_R,
    TryDecodeSQRDMULH_ASISDSAME_ONLY,
    TryDecodeSQRSHL_ASIMDSAME_ONLY,
    TryDecodeSQRSHL_ASISDSAME_ONLY,
    TryDecodeSQRSHRN_ASIMDSHF_N,
    TryDecodeSQRSHRN_ASISDSHF_N,
    TryDecodeSQRSHRUN_ASIMDSHF_N,
    TryDecodeSQRSHRUN_ASISDSHF_N,
    TryDecodeSQSHLU_ASIMDSHF_R,
    TryDecodeSQSHLU_ASISDSHF_R,
    TryDecodeSQSHL_ASIMDSAME_ONLY,
    TryDecodeSQSHL_ASIMDSHF_R,
    TryDecodeSQSHL_ASISDSAME_ONLY,
    TryDecodeSQSHL_ASISDSHF_R,
    TryDecodeSQSHRN_ASIMDSHF_N,
    TryDecodeSQSHRN_ASISDSHF_N,
    TryDecodeSQSHRUN_ASIMDSHF_N,
    TryDecodeSQSHRUN_ASISDSHF_N,
    TryDecodeSQSUB_ASIMDSAME_ONLY,
    TryDecodeSQSUB_ASISDSAME_ONLY,
    TryDecodeSQXTN_ASIMDMISC_N,
    TryDecodeSQXTN_ASISDMISC_N,
    TryDecodeSQXTUN_ASIMDMISC_N,
    TryDecodeSQXTUN_ASISDMISC_N,
    TryDecodeSRHADD_ASIMDSAME_ONLY,
    TryDecodeSRI_ASIMDSHF_R,
    TryDecodeSRI_ASISDSHF_R,
    TryDecodeSRSHL_ASIMDSAME_ONLY,
    TryDecodeSRSHL_ASISDSAME_ONLY,
    TryDecodeSRSHR_ASIMDSHF_R,
    TryDecodeSRSHR_ASISDSHF_R,
    TryDecodeSRSRA_ASIMDSHF_R,
    TryDecodeSRSRA_ASISDSHF_R,
    TryDecodeSSHLL_ASIMDSHF_L,
    TryDecodeSSHL_ASIMDSAME_ONLY,
    TryDecodeSSHL_ASISDSAME_ONLY,
    TryDecodeSSHR_ASIMDSHF_R,
    TryDecodeSSHR_ASISDSHF_R,
    TryDecodeSSRA_ASIMDSHF_R,
    TryDecodeSSRA_ASISDSHF_R,
    TryDecodeSSUBL_ASIMDDIFF_L,
    TryDecodeSSUBW_ASIMDDIFF_W,
    TryDecodeST1_ASISDLSE_R1_1V,
    TryDecodeST1_ASISDLSE_R2_2V,
    TryDecodeST1_ASISDLSE_R3_3V,
    TryDecodeST1_ASISDLSE_R4_4V,
    TryDecodeST1_ASISDLSEP_I1_I1,
    TryDecodeST1_ASISDLSEP_I2_I2,
    TryDecodeST1_ASISDLSEP_I3_I3,
    TryDecodeST1_ASISDLSEP_I4_I4,
    TryDecodeST1_ASISDLSEP_R1_R1,
    TryDecodeST1_ASISDLSEP_R2_R2,
    TryDecodeST1_ASISDLSEP_R3_R3,
    TryDecodeST1_ASISDLSEP_R4_R4,
    TryDecodeST1_ASISDLSO_B1_1B,
    TryDecodeST1_ASISDLSO_D1_1D,
    TryDecodeST1_ASISDLSO_H1_1H,
    TryDecodeST1_ASISDLSO_S1_1S,
    TryDecodeST1_ASISDLSOP_B1_I1B,
    TryDecodeST1_ASISDLSOP_BX1_R1B,
    TryDecodeST1_ASISDLSOP_D1_I1D,
    TryDecodeST1_ASISDLSOP_DX1_R1D,
    TryDecodeST1_ASISDLSOP_H1_I1H,
    TryDecodeST1_ASISDLSOP_HX1_R1H,
    TryDecodeST1_ASISDLSOP_S1_I1S,
    TryDecodeST1_ASISDLSOP_SX1_R1S,
    TryDecodeST2_ASISDLSE_R2,
    TryDecodeST2_ASISDLSEP_I2_I,
    TryDecodeST2_ASISDLSEP_R2_R,
    TryDecodeST2_ASISDLSO_B2_2B,
    TryDecodeST2_ASISDLSO_D2_2D,
    TryDecodeST2_ASISDLSO_H2_2H,
    TryDecodeST2_ASISDLSO_S2_2S,
    TryDecodeST2_ASISDLSOP_B2_I2B,
    TryDecodeST2_ASISDLSOP_BX2_R2B,
    TryDecodeST2_ASISDLSOP_D2_I2D,
    TryDecodeST2_ASISDLSOP_DX2_R2D,
    TryDecodeST2_ASISDLSOP_H2_I2H,
    TryDecodeST2_ASISDLSOP_HX2_R2H,
    TryDecodeST2_ASISDLSOP_S2_I2S,
    TryDecodeST2_ASISDLSOP_SX2_R2S,
    TryDecodeST3_ASISDLSE_R3,
    TryDecodeST3_ASISDLSEP_I3_I,
    TryDecodeST3_ASISDLSEP_R3_R,
    TryDecodeST3_ASISDLSO_B3_3B,
    TryDecodeST3_ASISDLSO_D3_3D,
    TryDecodeST3_ASISDLSO_H3_3H,
    TryDecodeST3_ASISDLSO_S3_3S,
    TryDecodeST3_ASISDLSOP_B3_I3B,
    TryDecodeST3_ASISDLSOP_BX3_R3B,
    TryDecodeST3_ASISDLSOP_D3_I3D,
    TryDecodeST3_ASISDLSOP_DX3_R3D,
    TryDecodeST3_ASISDLSOP_H3_I3H,
    TryDecodeST3_ASISDLSOP_HX3_R3H,
    TryDecodeST3_ASISDLSOP_S3_I3S,
    TryDecodeST3_ASISDLSOP_SX3_R3S,
    TryDecodeST4_ASISDLSE_R4,
    TryDecodeST4_ASISDLSEP_I4_I,
    TryDecodeST4_ASISDLSEP_R4_R,
    TryDecodeST4_ASISDLSO_B4_4B,
    TryDecodeST4_ASISDLSO_D4_4D,
    TryDecodeST4_ASISDLSO_H4_4H,
    TryDecodeST4_ASISDLSO_S4_4S,
    TryDecodeST4_ASISDLSOP_B4_I4B,
    TryDecodeST4_ASISDLSOP_BX4_R4B,
    TryDecodeST4_ASISDLSOP_D4_I4D,
    TryDecodeST4_ASISDLSOP_DX4_R4D,
    TryDecodeST4_ASISDLSOP_H4_I4H,
    TryDecodeST4_ASISDLSOP_HX4_R4H,
    TryDecodeST4_ASISDLSOP_S4_I4S,
    TryDecodeST4_ASISDLSOP_SX4_R4S,
    TryDecodeSTADDB_32S_MEMOP,
    TryDecodeSTADDH_32S_MEMOP,
    TryDecodeSTADDLB_32S_MEMOP,
    TryDecodeSTADDLH_32S_MEMOP,
    TryDecodeSTADDL_32S_MEMOP,
    TryDecodeSTADDL_64S_MEMOP,
    TryDecodeSTADD_32S_MEMOP,
    TryDecodeSTADD_64S_MEMOP,
    TryDecodeSTCLRB_32S_MEMOP,
    TryDecodeSTCLRH_32S_MEMOP,
    TryDecodeSTCLRLB_32S_MEMOP,
    TryDecodeSTCLRLH_32S_MEMOP,
    TryDecodeSTCLRL_32S_MEMOP,
    TryDecodeSTCLRL_64S_MEMOP,
    TryDecodeSTCLR_32S_MEMOP,
    TryDecodeSTCLR_64S_MEMOP,
    TryDecodeSTEORB_32S_MEMOP,
    TryDecodeSTEORH_32S_MEMOP,
    TryDecodeSTEORLB_32S_MEMOP,
    TryDecodeSTEORLH_32S_MEMOP,
    TryDecodeSTEORL_32S_MEMOP,
    TryDecodeSTEORL_64S_MEMOP,
    TryDecodeSTEOR_32S_MEMOP,
    TryDecodeSTEOR_64S_MEMOP,
    TryDecodeSTLLRB_SL32_LDSTEXCL,
    TryDecodeSTLLRH_SL32_LDSTEXCL,
    TryDecodeSTLLR_SL32_LDSTEXCL,
    TryDecodeSTLLR_SL64_LDSTEXCL,
    TryDecodeSTLRB_SL32_LDSTEXCL,
    TryDecodeSTLRH_SL32_LDSTEXCL,
    TryDecodeSTLR_SL32_LDSTEXCL,
    TryDecodeSTLR_SL64_LDSTEXCL,
    TryDecodeSTLXP_SP32_LDSTEXCL,
    TryDecodeSTLXP_SP64_LDSTEXCL,
    TryDecodeSTLXRB_SR32_LDSTEXCL,
    TryDecodeSTLXRH_SR32_LDSTEXCL,
    TryDecodeSTLXR_SR32_LDSTEXCL,
    TryDecodeSTLXR_SR64_LDSTEXCL,
    TryDecodeSTNP_32_LDSTNAPAIR_OFFS,
    TryDecodeSTNP_64_LDSTNAPAIR_OFFS,
    TryDecodeSTNP_D_LDSTNAPAIR_OFFS,
    TryDecodeSTNP_Q_LDSTNAPAIR_OFFS,
    TryDecodeSTNP_S_LDSTNAPAIR_OFFS,
    TryDecodeSTP_32_LDSTPAIR_OFF,
    TryDecodeSTP_32_LDSTPAIR_POST,
    TryDecodeSTP_32_LDSTPAIR_PRE,
    TryDecodeSTP_64_LDSTPAIR_OFF,
    TryDecodeSTP_64_LDSTPAIR_POST,
    TryDecodeSTP_64_LDSTPAIR_PRE,
    TryDecodeSTP_D_LDSTPAIR_OFF,
    TryDecodeSTP_D_LDSTPAIR_POST,
    TryDecodeSTP_D_LDSTPAIR_PRE,
    TryDecodeSTP_Q_LDSTPAIR_OFF,
    TryDecodeSTP_Q_LDSTPAIR_POST,
    TryDecodeSTP_Q_LDSTPAIR_PRE,
    TryDecodeSTP_S_LDSTPAIR_OFF,
    TryDecodeSTP_S_LDSTPAIR_POST,
    TryDecodeSTP_S_LDSTPAIR_PRE,
    TryDecodeSTRB_32BL_LDST_REGOFF,
    TryDecodeSTRB_32B_LDST_REGOFF,
    TryDecodeSTRB_32_LDST_IMMPOST,
    TryDecodeSTRB_32_LDST_IMMPRE,
    TryDecodeSTRB_32_LDST_POS,
    TryDecodeSTRH_32_LDST_IMMPOST,
    TryDecodeSTRH_32_LDST_IMMPRE,
    TryDecodeSTRH_32_LDST_POS,
    TryDecodeSTRH_32_LDST_REGOFF,
    TryDecodeSTR_32_LDST_IMMPOST,
    TryDecodeSTR_32_LDST_IMMPRE,
    TryDecodeSTR_32_LDST_POS,
    TryDecodeSTR_32_LDST_REGOFF,
    TryDecodeSTR_64_LDST_IMMPOST,
    TryDecodeSTR_64_LDST_IMMPRE,
    TryDecodeSTR_64_LDST_POS,
    TryDecodeSTR_64_LDST_REGOFF,
    TryDecodeSTR_BL_LDST_REGOFF,
    TryDecodeSTR_B_LDST_IMMPOST,
    TryDecodeSTR_B_LDST_IMMPRE,
    TryDecodeSTR_B_LDST_POS,
    TryDecodeSTR_B_LDST_REGOFF,
    TryDecodeSTR_D_LDST_IMMPOST,
    TryDecodeSTR_D_LDST_IMMPRE,
    TryDecodeSTR_D_LDST_POS,
    TryDecodeSTR_D_LDST_REGOFF,
    TryDecodeSTR_H_LDST_IMMPOST,
    TryDecodeSTR_H_LDST_IMMPRE,
    TryDecodeSTR_H_LDST_POS,
    TryDecodeSTR_H_LDST_REGOFF,
    TryDecodeSTR_Q_LDST_IMMPOST,
    TryDecodeSTR_Q_LDST_IMMPRE,
    TryDecodeSTR_Q_LDST_POS,
    TryDecodeSTR_Q_LDST_REGOFF,
    TryDecodeSTR_S_LDST_IMMPOST,
    TryDecodeSTR_S_LDST_IMMPRE,
    TryDecodeSTR_S_LDST_POS,
    TryDecodeSTR_S_LDST_REGOFF,
    TryDecodeSTSETB_32S_MEMOP,
    TryDecodeSTSETH_32S_MEMOP,
    TryDecodeSTSETLB_32S_MEMOP,
    TryDecodeSTSETLH_32S_MEMOP,
    TryDecodeSTSETL_32S_MEMOP,
    TryDecodeSTSETL_64S_MEMOP,
    TryDecodeSTSET_32S_MEMOP,
    TryDecodeSTSET_64S_MEMOP,
    TryDecodeSTSMAXB_32S_MEMOP,
    TryDecodeSTSMAXH_32S_MEMOP,
    TryDecodeSTSMAXLB_32S_MEMOP,
    TryDecodeSTSMAXLH_32S_MEMOP,
    TryDecodeSTSMAXL_32S_MEMOP,
    TryDecodeSTSMAXL_64S_MEMOP,
    TryDecodeSTSMAX_32S_MEMOP,
    TryDecodeSTSMAX_64S_MEMOP,
    TryDecodeSTSMINB_32S_MEMOP,
    TryDecodeSTSMINH_32S_MEMOP,
    TryDecodeSTSMINLB_32S_MEMOP,
    TryDecodeSTSMINLH_32S_MEMOP,
    TryDecodeSTSMINL_32S_MEMOP,
    TryDecodeSTSMINL_64S_MEMOP,
    TryDecodeSTSMIN_32S_MEMOP,
    TryDecodeSTSMIN_64S_MEMOP,
    TryDecodeSTTRB_32_LDST_UNPRIV,
    TryDecodeSTTRH_32_LDST_UNPRIV,
    TryDecodeSTTR_32_LDST_UNPRIV,
    TryDecodeSTTR_64_LDST_UNPRIV,
    TryDecodeSTUMAXB_32S_MEMOP,
    TryDecodeSTUMAXH_32S_MEMOP,
    TryDecodeSTUMAXLB_32S_MEMOP,
    TryDecodeSTUMAXLH_32S_MEMOP,
    TryDecodeSTUMAXL_32S_MEMOP,
    TryDecodeSTUMAXL_64S_MEMOP,
    TryDecodeSTUMAX_32S_MEMOP,
    TryDecodeSTUMAX_64S_MEMOP,
    TryDecodeSTUMINB_32S_MEMOP,
    TryDecodeSTUMINH_32S_MEMOP,
    TryDecodeSTUMINLB_32S_MEMOP,
    TryDecodeSTUMINLH_32S_MEMOP,
    TryDecodeSTUMINL_32S_MEMOP,
    TryDecodeSTUMINL_64S_MEMOP,
    TryDecodeSTUMIN_32S_MEMOP,
    TryDecodeSTUMIN_64S_MEMOP,
    TryDecodeSTURB_32_LDST_UNSCALED,
    TryDecodeSTURH_32_LDST_UNSCALED,
    TryDecodeSTUR_32_LDST_UNSCALED,
    TryDecodeSTUR_64_LDST_UNSCALED,
    TryDecodeSTUR_B_LDST_UNSCALED,
    TryDecodeSTUR_D_LDST_UNSCALED,
    TryDecodeSTUR_H_LDST_UNSCALED,
    TryDecodeSTUR_Q_LDST_UNSCALED,
    TryDecodeSTUR_S_LDST_UNSCALED,
    TryDecodeSTXP_SP32_LDSTEXCL,
    TryDecodeSTXP_SP64_LDSTEXCL,
    TryDecodeSTXRB_SR32_LDSTEXCL,
    TryDecodeSTXRH_SR32_LDSTEXCL,
    TryDecodeSTXR_SR32_LDSTEXCL,
    TryDecodeSTXR_SR64_LDSTEXCL,
    TryDecodeSUBHN_ASIMDDIFF_N,
    TryDecodeSUBS_32S_ADDSUB_EXT,
    TryDecodeSUBS_32S_ADDSUB_IMM,
    TryDecodeSUBS_32_ADDSUB_SHIFT,
    TryDecodeSUBS_64S_ADDSUB_EXT,
    TryDecodeSUBS_64S_ADDSUB_IMM,
    TryDecodeSUBS_64_ADDSUB_SHIFT,
    TryDecodeSUB_32_ADDSUB_EXT,
    TryDecodeSUB_32_ADDSUB_IMM,
    TryDecodeSUB_32_ADDSUB_SHIFT,
    TryDecodeSUB_64_ADDSUB_EXT,
    TryDecodeSUB_64_ADDSUB_IMM,
    TryDecodeSUB_64_ADDSUB_SHIFT,
    TryDecodeSUB_ASIMDSAME_ONLY,
    TryDecodeSUB_ASISDSAME_ONLY,
    TryDecodeSUQADD_ASIMDMISC_R,
    TryDecodeSUQADD_ASISDMISC_R,
    TryDecodeSVC_EX_EXCEPTION,
    TryDecodeSWPAB_32_MEMOP,
    TryDecodeSWPAH_32_MEMOP,
    TryDecodeSWPALB_32_MEMOP,
    TryDecodeSWPALH_32_MEMOP,
    TryDecodeSWPAL_32_MEMOP,
    TryDecodeSWPAL_64_MEMOP,
    TryDecodeSWPA_32_MEMOP,
    TryDecodeSWPA_64_MEMOP,
    TryDecodeSWPB_32_MEMOP,
    TryDecodeSWPH_32_MEMOP,
    TryDecodeSWPLB_32_MEMOP,
    TryDecodeSWPLH_32_MEMOP,
    TryDecodeSWPL_32_MEMOP,
    TryDecodeSWPL_64_MEMOP,
    TryDecodeSWP_32_MEMOP,
    TryDecodeSWP_64_MEMOP,
    TryDecodeSXTB_SBFM_32M_BITFIELD,
    TryDecodeSXTB_SBFM_64M_BITFIELD,
    TryDecodeSXTH_SBFM_32M_BITFIELD,
    TryDecodeSXTH_SBFM_64M_BITFIELD,
    TryDecodeSXTL_SSHLL_ASIMDSHF_L,
    TryDecodeSXTW_SBFM_64M_BITFIELD,
    TryDecodeSYSL_RC_SYSTEM,
    TryDecodeSYS_CR_SYSTEM,
    TryDecodeTBL_ASIMDTBL_L1_1,
    TryDecodeTBL_ASIMDTBL_L2_2,
    TryDecodeTBL_ASIMDTBL_L3_3,
    TryDecodeTBL_ASIMDTBL_L4_4,
    TryDecodeTBNZ_ONLY_TESTBRANCH,
    TryDecodeTBX_ASIMDTBL_L1_1,
    TryDecodeTBX_ASIMDTBL_L2_2,
    TryDecodeTBX_ASIMDTBL_L3_3,
    TryDecodeTBX_ASIMDTBL_L4_4,
    TryDecodeTBZ_ONLY_TESTBRANCH,
    TryDecodeTLBI_SYS_CR_SYSTEM,
    TryDecodeTRN1_ASIMDPERM_ONLY,
    TryDecodeTRN2_ASIMDPERM_ONLY,
    TryDecodeTST_ANDS_32S_LOG_IMM,
    TryDecodeTST_ANDS_32_LOG_SHIFT,
    TryDecodeTST_ANDS_64S_LOG_IMM,
    TryDecodeTST_ANDS_64_LOG_SHIFT,
    TryDecodeUABAL_ASIMDDIFF_L,
    TryDecodeUABA_ASIMDSAME_ONLY,
    TryDecodeUABDL_ASIMDDIFF_L,
    TryDecodeUABD_ASIMDSAME_ONLY,
    TryDecodeUADALP_ASIMDMISC_P,
    TryDecodeUADDLP_ASIMDMISC_P,
    TryDecodeUADDLV_ASIMDALL_ONLY,
    TryDecodeUADDL_ASIMDDIFF_L,
    TryDecodeUADDW_ASIMDDIFF_W,
    TryDecodeUBFIZ_UBFM_32M_BITFIELD,
    TryDecodeUBFIZ_UBFM_64M_BITFIELD,
    TryDecodeUBFM_32M_BITFIELD,
    TryDecodeUBFM_64M_BITFIELD,
    TryDecodeUBFX_UBFM_32M_BITFIELD,
    TryDecodeUBFX_UBFM_64M_BITFIELD,
    TryDecodeUCVTF_D32_FLOAT2FIX,
    TryDecodeUCVTF_D32_FLOAT2INT,
    TryDecodeUCVTF_D64_FLOAT2FIX,
    TryDecodeUCVTF_D64_FLOAT2INT,
    TryDecodeUCVTF_H32_FLOAT2FIX,
    TryDecodeUCVTF_H32_FLOAT2INT,
    TryDecodeUCVTF_H64_FLOAT2FIX,
    TryDecodeUCVTF_H64_FLOAT2INT,
    TryDecodeUCVTF_S32_FLOAT2FIX,
    TryDecodeUCVTF_S32_FLOAT2INT,
    TryDecodeUCVTF_S64_FLOAT2FIX,
    TryDecodeUCVTF_S64_FLOAT2INT,
    TryDecodeUCVTF_ASIMDMISC_R,
    TryDecodeUCVTF_ASIMDMISCFP16_R,
    TryDecodeUCVTF_ASIMDSHF_C,
    TryDecodeUCVTF_ASISDMISC_R,
    TryDecodeUCVTF_ASISDMISCFP16_R,
    TryDecodeUCVTF_ASISDSHF_C,
    TryDecodeUDIV_32_DP_2SRC,
    TryDecodeUDIV_64_DP_2SRC,
    TryDecodeUHADD_ASIMDSAME_ONLY,
    TryDecodeUHSUB_ASIMDSAME_ONLY,
    TryDecodeUMADDL_64WA_DP_3SRC,
    TryDecodeUMAXP_ASIMDSAME_ONLY,
    TryDecodeUMAXV_ASIMDALL_ONLY,
    TryDecodeUMAX_ASIMDSAME_ONLY,
    TryDecodeUMINP_ASIMDSAME_ONLY,
    TryDecodeUMINV_ASIMDALL_ONLY,
    TryDecodeUMIN_ASIMDSAME_ONLY,
    TryDecodeUMLAL_ASIMDDIFF_L,
    TryDecodeUMLAL_ASIMDELEM_L,
    TryDecodeUMLSL_ASIMDDIFF_L,
    TryDecodeUMLSL_ASIMDELEM_L,
    TryDecodeUMNEGL_UMSUBL_64WA_DP_3SRC,
    TryDecodeUMOV_ASIMDINS_W_W,
    TryDecodeUMOV_ASIMDINS_X_X,
    TryDecodeUMSUBL_64WA_DP_3SRC,
    TryDecodeUMULH_64_DP_3SRC,
    TryDecodeUMULL_UMADDL_64WA_DP_3SRC,
    TryDecodeUMULL_ASIMDDIFF_L,
    TryDecodeUMULL_ASIMDELEM_L,
    TryDecodeUQADD_ASIMDSAME_ONLY,
    TryDecodeUQADD_ASISDSAME_ONLY,
    TryDecodeUQRSHL_ASIMDSAME_ONLY,
    TryDecodeUQRSHL_ASISDSAME_ONLY,
    TryDecodeUQRSHRN_ASIMDSHF_N,
    TryDecodeUQRSHRN_ASISDSHF_N,
    TryDecodeUQSHL_ASIMDSAME_ONLY,
    TryDecodeUQSHL_ASIMDSHF_R,
    TryDecodeUQSHL_ASISDSAME_ONLY,
    TryDecodeUQSHL_ASISDSHF_R,
    TryDecodeUQSHRN_ASIMDSHF_N,
    TryDecodeUQSHRN_ASISDSHF_N,
    TryDecodeUQSUB_ASIMDSAME_ONLY,
    TryDecodeUQSUB_ASISDSAME_ONLY,
    TryDecodeUQXTN_ASIMDMISC_N,
    TryDecodeUQXTN_ASISDMISC_N,
    TryDecodeURECPE_ASIMDMISC_R,
    TryDecodeURHADD_ASIMDSAME_ONLY,
    TryDecodeURSHL_ASIMDSAME_ONLY,
    TryDecodeURSHL_ASISDSAME_ONLY,
    TryDecodeURSHR_ASIMDSHF_R,
    TryDecodeURSHR_ASISDSHF_R,
    TryDecodeURSQRTE_ASIMDMISC_R,
    TryDecodeURSRA_ASIMDSHF_R,
    TryDecodeURSRA_ASISDSHF_R,
    TryDecodeUSHLL_ASIMDSHF_L,
    TryDecodeUSHL_ASIMDSAME_ONLY,
    TryDecodeUSHL_ASISDSAME_ONLY,
    TryDecodeUSHR_ASIMDSHF_R,
    TryDecodeUSHR_ASISDSHF_R,
    TryDecodeUSQADD_ASIMDMISC_R,
    TryDecodeUSQADD_ASISDMISC_R,
    TryDecodeUSRA_ASIMDSHF_R,
    TryDecodeUSRA_ASISDSHF_R,
    TryDecodeUSUBL_ASIMDDIFF_L,
    TryDecodeUSUBW_ASIMDDIFF_W,
    TryDecodeUXTB_UBFM_32M_BITFIELD,
    TryDecodeUXTH_UBFM_32M_BITFIELD,
    TryDecodeUXTL_USHLL_ASIMDSHF_L,
    TryDecodeUZP1_ASIMDPERM_ONLY,
    TryDecodeUZP2_ASIMDPERM_ONLY,
    TryDecodeWFE_HI_SYSTEM,
    TryDecodeWFI_HI_SYSTEM,
    TryDecodeXTN_ASIMDMISC_N,
    TryDecodeYIELD_HI_SYSTEM,
    TryDecodeZIP1_ASIMDPERM_ONLY,
    TryDecodeZIP2_ASIMDPERM_ONLY,
};

}  // namespace


bool TryDecode(const InstData &data, Instruction &inst) {
  auto iform_num = static_cast<unsigned>(data.iform);
  return kDecoder[iform_num - 1](data, inst);
}

}  // namespace aarch64
}  // namespace remill
