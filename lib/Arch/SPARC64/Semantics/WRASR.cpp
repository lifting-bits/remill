/*
 * Copyright (c) 2019 Trail of Bits, Inc.
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

// Implements semantics of instructions accessing
// the control and status registers

#define MAKE_SEMANTICS_WR(op) \
  namespace { \
  DEF_SEM(WR##op, R32 src1, I32 src2) { \
    auto lhs = Read(src1); \
    auto rhs = Read(src2); \
    auto res = UXor(lhs, rhs); \
    WriteZExt(ASR_##op, res); \
    return memory; \
  } \
  } \
  DEF_ISEL(WR##op) = WR##op;

MAKE_SEMANTICS_WR(Y)
MAKE_SEMANTICS_WR(PAUSE)
MAKE_SEMANTICS_WR(STICK_CMPR)
MAKE_SEMANTICS_WR(SOFTINT)
MAKE_SEMANTICS_WR(FPRS)
MAKE_SEMANTICS_WR(GSR)
MAKE_SEMANTICS_WR(ASI)

#define MAKE_SEMANTICS_RD(op) \
  namespace { \
  DEF_SEM(RD##op, R64W dst) { \
    auto asr = Read(ASR_##op); \
    WriteZExt(dst, asr); \
    return memory; \
  } \
  } \
  DEF_ISEL(RD##op) = RD##op;

MAKE_SEMANTICS_RD(Y)
MAKE_SEMANTICS_RD(ASI)

//MAKE_SEMANTICS_RD(PC)
MAKE_SEMANTICS_RD(FPRS)


namespace {

template <typename R>
DEF_SEM(WRPRTPC, R64 src1, R src2) {
  auto rs1 = Read(src1);
  auto rs2 = Read(src2);
  auto res = UXor(rs1, rs2);
  Write(PSR_TPC, res);
  return memory;
}

template <typename R>
DEF_SEM(WRPRTNPC, R64 src1, R src2) {
  auto rs1 = Read(src1);
  auto rs2 = Read(src2);
  auto res = UXor(rs1, rs2);
  Write(PSR_TNPC, res);
  return memory;
}

template <typename R>
DEF_SEM(WRPRTSTATE, R64 src1, R src2) {
  auto rs1 = Read(src1);
  auto rs2 = Read(src2);
  auto res = UXor(rs1, rs2);
  Write(PSR_TSTATE, res);
  return memory;
}

template <typename R>
DEF_SEM(WRPRTT, R64 src1, R src2) {
  auto rs1 = Read(src1);
  auto rs2 = Read(src2);
  auto res = UXor(rs1, rs2);
  WriteTrunc(PSR_TT, res);
  return memory;
}

template <typename R>
DEF_SEM(WRPRTBA, R64 src1, R src2) {
  auto rs1 = Read(src1);
  auto rs2 = Read(src2);
  auto res = UXor(rs1, rs2);
  Write(PSR_TBA, res);
  return memory;
}

template <typename R>
DEF_SEM(WRPRPSTATE, R64 src1, R src2) {
  auto rs1 = Read(src1);
  auto rs2 = Read(src2);
  auto res = UXor(rs1, rs2);
  WriteTrunc(PSR_PSTATE, res);
  return memory;
}

template <typename R>
DEF_SEM(WRPRTL, R64 src1, R src2) {
  auto rs1 = Read(src1);
  auto rs2 = Read(src2);
  auto res = UXor(rs1, rs2);
  WriteTrunc(PSR_TL, res);
  return memory;
}

template <typename R>
DEF_SEM(WRPRPIL, R64 src1, R src2) {
  auto rs1 = Read(src1);
  auto rs2 = Read(src2);
  auto res = UXor(rs1, rs2);
  WriteTrunc(PSR_PIL, res);
  return memory;
}

template <typename R>
DEF_SEM(WRPRCWP, R64 src1, R src2) {
  auto rs1 = Read(src1);
  auto rs2 = Read(src2);
  auto res = UXor(rs1, rs2);
  WriteTrunc(PSR_CWP, res);
  return memory;
}

template <typename R>
DEF_SEM(WRPRCANSAVE, R64 src1, R src2) {
  auto rs1 = Read(src1);
  auto rs2 = Read(src2);
  auto res = UXor(rs1, rs2);
  WriteTrunc(PSR_CANSAVE, res);
  return memory;
}

template <typename R>
DEF_SEM(WRPRCANRESTORE, R64 src1, R src2) {
  auto rs1 = Read(src1);
  auto rs2 = Read(src2);
  auto res = UXor(rs1, rs2);
  WriteTrunc(PSR_CANRESTORE, res);
  return memory;
}

template <typename R>
DEF_SEM(WRPRCLEANWIN, R64 src1, R src2) {
  auto rs1 = Read(src1);
  auto rs2 = Read(src2);
  auto res = UXor(rs1, rs2);
  WriteTrunc(PSR_CLEANWIN, res);
  return memory;
}

template <typename R>
DEF_SEM(WRPROTHERWIN, R64 src1, R src2) {
  auto rs1 = Read(src1);
  auto rs2 = Read(src2);
  auto res = UXor(rs1, rs2);
  WriteTrunc(PSR_OTHERWIN, res);
  return memory;
}

template <typename R>
DEF_SEM(WRPRWSTATE, R64 src1, R src2) {
  auto rs1 = Read(src1);
  auto rs2 = Read(src2);
  auto res = UXor(rs1, rs2);
  WriteTrunc(PSR_WSTATE, res);
  return memory;
}

template <typename R>
DEF_SEM(WRPRGL, R64 src1, R src2) {
  auto rs1 = Read(src1);
  auto rs2 = Read(src2);
  auto res = UXor(rs1, rs2);
  WriteTrunc(PSR_GL, res);
  return memory;
}
}  // namespace

DEF_ISEL(WRPRTPC) = WRPRTPC<R64>;
DEF_ISEL(WRPRTPC_IMM) = WRPRTPC<I64>;
DEF_ISEL(WRPRTNPC) = WRPRTNPC<R64>;
DEF_ISEL(WRPRTNPC_IMM) = WRPRTNPC<I64>;
DEF_ISEL(WRPRTSTATE) = WRPRTSTATE<R64>;
DEF_ISEL(WRPRTSTATE_IMM) = WRPRTSTATE<I64>;
DEF_ISEL(WRPRTT) = WRPRTT<R64>;
DEF_ISEL(WRPRTT_IMM) = WRPRTT<I64>;
DEF_ISEL(WRPRTBA) = WRPRTBA<R64>;
DEF_ISEL(WRPRTBA_IMM) = WRPRTBA<I64>;
DEF_ISEL(WRPRPSTATE) = WRPRPSTATE<R64>;
DEF_ISEL(WRPRPSTATE_IMM) = WRPRPSTATE<I64>;
DEF_ISEL(WRPRTL) = WRPRTL<R64>;
DEF_ISEL(WRPRTL_IMM) = WRPRTL<I64>;
DEF_ISEL(WRPRPIL) = WRPRPIL<R64>;
DEF_ISEL(WRPRPIL_IMM) = WRPRPIL<I64>;
DEF_ISEL(WRPRCWP) = WRPRCWP<R64>;
DEF_ISEL(WRPRCWP_IMM) = WRPRCWP<I64>;
DEF_ISEL(WRPRCANSAVE) = WRPRCANSAVE<R64>;
DEF_ISEL(WRPRCANSAVE_IMM) = WRPRCANSAVE<I64>;
DEF_ISEL(WRPRCANRESTORE) = WRPRCANRESTORE<R64>;
DEF_ISEL(WRPRCANRESTORE_IMM) = WRPRCANRESTORE<I64>;
DEF_ISEL(WRPRCLEANWIN) = WRPRCLEANWIN<R64>;
DEF_ISEL(WRPRCLEANWIN_IMM) = WRPRCLEANWIN<I64>;
DEF_ISEL(WRPROTHERWIN) = WRPROTHERWIN<R64>;
DEF_ISEL(WRPROTHERWIN_IMM) = WRPROTHERWIN<I64>;
DEF_ISEL(WRPRWSTATE) = WRPRWSTATE<R64>;
DEF_ISEL(WRPRWSTATE_IMM) = WRPRWSTATE<I64>;
DEF_ISEL(WRPRGL) = WRPRGL<R64>;
DEF_ISEL(WRPRGL_IMM) = WRPRGL<I64>;
