/*
 * Copyright (c) 2026-present Trail of Bits, Inc.
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

#include <cstdint>
#include <cstring>
#include <string>

namespace riscv {

inline uint32_t BitsFromFloat(float value) {
  uint32_t bits = 0;
  static_assert(sizeof(bits) == sizeof(value));
  std::memcpy(&bits, &value, sizeof(bits));
  return bits;
}

inline uint64_t BitsFromDouble(double value) {
  uint64_t bits = 0;
  static_assert(sizeof(bits) == sizeof(value));
  std::memcpy(&bits, &value, sizeof(bits));
  return bits;
}

constexpr uint32_t kOpcodeOpImm = 0x13U;
constexpr uint32_t kOpcodeOp = 0x33U;
constexpr uint32_t kOpcodeLoad = 0x03U;
constexpr uint32_t kOpcodeLoadFp = 0x07U;
constexpr uint32_t kOpcodeStore = 0x23U;
constexpr uint32_t kOpcodeStoreFp = 0x27U;
constexpr uint32_t kOpcodeBranch = 0x63U;
constexpr uint32_t kOpcodeAmo = 0x2FU;
constexpr uint32_t kOpcodeLui = 0x37U;
constexpr uint32_t kOpcodeAuipc = 0x17U;
constexpr uint32_t kOpcodeJal = 0x6FU;
constexpr uint32_t kOpcodeJalr = 0x67U;
constexpr uint32_t kOpcodeSystem = 0x73U;
constexpr uint32_t kOpcodeOpFp = 0x53U;
constexpr uint32_t kOpcodeOpImm32 = 0x1BU;
constexpr uint32_t kOpcodeOp32 = 0x3BU;
constexpr uint32_t kOpcodeMiscMem = 0x0FU;

inline std::string Bytes16(uint16_t halfword) {
  std::string bytes;
  bytes.resize(2);
  bytes[0] = static_cast<char>(halfword & 0xFFu);
  bytes[1] = static_cast<char>((halfword >> 8) & 0xFFu);
  return bytes;
}

inline std::string Bytes32(uint32_t word) {
  std::string bytes;
  bytes.resize(4);
  bytes[0] = static_cast<char>(word & 0xFFu);
  bytes[1] = static_cast<char>((word >> 8) & 0xFFu);
  bytes[2] = static_cast<char>((word >> 16) & 0xFFu);
  bytes[3] = static_cast<char>((word >> 24) & 0xFFu);
  return bytes;
}

inline uint32_t EncodeR(uint32_t opcode, uint32_t rd, uint32_t funct3,
                        uint32_t rs1, uint32_t rs2, uint32_t funct7) {
  return ((funct7 & 0x7FU) << 25) | ((rs2 & 0x1FU) << 20) |
         ((rs1 & 0x1FU) << 15) | ((funct3 & 0x7U) << 12) |
         ((rd & 0x1FU) << 7) | (opcode & 0x7FU);
}

inline uint32_t EncodeAmo(uint32_t funct5, bool aq, bool rl, uint32_t rd,
                          uint32_t funct3, uint32_t rs1, uint32_t rs2) {
  const uint32_t funct7 = ((funct5 & 0x1FU) << 2) |
                          ((aq ? 1U : 0U) << 1) |
                          (rl ? 1U : 0U);
  return EncodeR(kOpcodeAmo, rd, funct3, rs1, rs2, funct7);
}

inline uint32_t EncodeLrW(uint32_t rd, uint32_t rs1, bool aq = false,
                          bool rl = false) {
  return EncodeAmo(/*funct5=*/0x2U, aq, rl, rd, /*funct3=*/0x2U, rs1, /*rs2=*/0);
}

inline uint32_t EncodeScW(uint32_t rd, uint32_t rs2, uint32_t rs1,
                          bool aq = false, bool rl = false) {
  return EncodeAmo(/*funct5=*/0x3U, aq, rl, rd, /*funct3=*/0x2U, rs1, rs2);
}

inline uint32_t EncodeLrD(uint32_t rd, uint32_t rs1, bool aq = false,
                          bool rl = false) {
  return EncodeAmo(/*funct5=*/0x2U, aq, rl, rd, /*funct3=*/0x3U, rs1, /*rs2=*/0);
}

inline uint32_t EncodeScD(uint32_t rd, uint32_t rs2, uint32_t rs1,
                          bool aq = false, bool rl = false) {
  return EncodeAmo(/*funct5=*/0x3U, aq, rl, rd, /*funct3=*/0x3U, rs1, rs2);
}

inline uint32_t EncodeI(uint32_t opcode, uint32_t rd, uint32_t funct3,
                        uint32_t rs1, int32_t imm12) {
  const uint32_t imm = static_cast<uint32_t>(imm12) & 0xFFFU;
  return (imm << 20) | ((rs1 & 0x1FU) << 15) | ((funct3 & 0x7U) << 12) |
         ((rd & 0x1FU) << 7) | (opcode & 0x7FU);
}

inline uint32_t EncodeS(uint32_t opcode, uint32_t funct3, uint32_t rs1,
                        uint32_t rs2, int32_t imm12) {
  const uint32_t imm = static_cast<uint32_t>(imm12) & 0xFFFU;
  const uint32_t imm_lo = imm & 0x1FU;
  const uint32_t imm_hi = (imm >> 5) & 0x7FU;
  return (imm_hi << 25) | ((rs2 & 0x1FU) << 20) | ((rs1 & 0x1FU) << 15) |
         ((funct3 & 0x7U) << 12) | (imm_lo << 7) | (opcode & 0x7FU);
}

inline uint32_t EncodeB(uint32_t opcode, uint32_t funct3, uint32_t rs1,
                        uint32_t rs2, int32_t imm13) {
  const uint32_t imm = static_cast<uint32_t>(imm13) & 0x1FFFU;

  const uint32_t imm_12 = (imm >> 12) & 0x1U;
  const uint32_t imm_10_5 = (imm >> 5) & 0x3FU;
  const uint32_t imm_4_1 = (imm >> 1) & 0xFU;
  const uint32_t imm_11 = (imm >> 11) & 0x1U;

  return (imm_12 << 31) | (imm_10_5 << 25) | ((rs2 & 0x1FU) << 20) |
         ((rs1 & 0x1FU) << 15) | ((funct3 & 0x7U) << 12) |
         (imm_4_1 << 8) | (imm_11 << 7) | (opcode & 0x7FU);
}

inline uint32_t EncodeU(uint32_t opcode, uint32_t rd, int32_t imm20) {
  const uint32_t imm = static_cast<uint32_t>(imm20) & 0xFFFFFU;
  return (imm << 12) | ((rd & 0x1FU) << 7) | (opcode & 0x7FU);
}

inline uint32_t EncodeJ(uint32_t opcode, uint32_t rd, int32_t imm21) {
  const uint32_t imm = static_cast<uint32_t>(imm21) & 0x1FFFFFU;

  const uint32_t imm_20 = (imm >> 20) & 0x1U;
  const uint32_t imm_10_1 = (imm >> 1) & 0x3FFU;
  const uint32_t imm_11 = (imm >> 11) & 0x1U;
  const uint32_t imm_19_12 = (imm >> 12) & 0xFFU;

  return (imm_20 << 31) | (imm_10_1 << 21) | (imm_11 << 20) |
         (imm_19_12 << 12) | ((rd & 0x1FU) << 7) | (opcode & 0x7FU);
}

inline uint32_t EncodeShiftI32(uint32_t funct3, uint32_t rd, uint32_t rs1,
                               uint32_t shamt, uint32_t funct7) {
  const uint32_t imm = ((funct7 & 0x7FU) << 5) | (shamt & 0x1FU);
  return EncodeI(kOpcodeOpImm, rd, funct3, rs1, static_cast<int32_t>(imm));
}

inline uint32_t EncodeShiftI64(uint32_t funct3, uint32_t rd, uint32_t rs1,
                               uint32_t shamt, uint32_t funct6) {
  const uint32_t imm = ((funct6 & 0x3FU) << 6) | (shamt & 0x3FU);
  return EncodeI(kOpcodeOpImm, rd, funct3, rs1, static_cast<int32_t>(imm));
}

inline uint16_t EncodeCAddi(uint32_t rd, int32_t imm6) {
  const uint32_t imm = static_cast<uint32_t>(imm6) & 0x3FU;
  const uint32_t imm_5 = (imm >> 5) & 0x1U;
  const uint32_t imm_4_0 = imm & 0x1FU;

  // Quadrant 1, funct3=000: C.ADDI
  // [15:13]=000 [12]=imm[5] [11:7]=rd/rs1 [6:2]=imm[4:0] [1:0]=01
  return static_cast<uint16_t>(((0U & 0x7U) << 13) | (imm_5 << 12) |
                               ((rd & 0x1FU) << 7) | (imm_4_0 << 2) | 0x1U);
}

inline uint16_t EncodeCLw(uint32_t rd, uint32_t rs1, uint32_t uimm) {
  // Quadrant 0, funct3=010: C.LW
  // rd/rs1 use the compressed register encoding (x8-x15).
  const uint32_t rd_p = (rd - 8U) & 0x7U;
  const uint32_t rs1_p = (rs1 - 8U) & 0x7U;

  const uint32_t imm_6 = (uimm >> 6) & 0x1U;
  const uint32_t imm_2 = (uimm >> 2) & 0x1U;
  const uint32_t imm_5_3 = (uimm >> 3) & 0x7U;

  return static_cast<uint16_t>(((0x2U & 0x7U) << 13) | (imm_5_3 << 10) |
                               ((rs1_p & 0x7U) << 7) | (imm_2 << 6) |
                               (imm_6 << 5) | ((rd_p & 0x7U) << 2) |
                               0x0U);
}

inline uint16_t EncodeCSw(uint32_t rs2, uint32_t rs1, uint32_t uimm) {
  // Quadrant 0, funct3=110: C.SW
  // rs2/rs1 use the compressed register encoding (x8-x15).
  const uint32_t rs2_p = (rs2 - 8U) & 0x7U;
  const uint32_t rs1_p = (rs1 - 8U) & 0x7U;

  const uint32_t imm_6 = (uimm >> 6) & 0x1U;
  const uint32_t imm_2 = (uimm >> 2) & 0x1U;
  const uint32_t imm_5_3 = (uimm >> 3) & 0x7U;

  return static_cast<uint16_t>(((0x6U & 0x7U) << 13) | (imm_5_3 << 10) |
                               ((rs1_p & 0x7U) << 7) | (imm_2 << 6) |
                               (imm_6 << 5) | ((rs2_p & 0x7U) << 2) |
                               0x0U);
}

inline uint16_t EncodeCJ(int32_t imm12) {
  // Quadrant 1, funct3=101: C.J
  // Immediate is signed and is always a multiple of 2.
  const uint32_t imm = static_cast<uint32_t>(imm12) & 0x0FFFU;
  const uint32_t imm_11 = (imm >> 11) & 0x1U;
  const uint32_t imm_10 = (imm >> 10) & 0x1U;
  const uint32_t imm_9_8 = (imm >> 8) & 0x3U;
  const uint32_t imm_7 = (imm >> 7) & 0x1U;
  const uint32_t imm_6 = (imm >> 6) & 0x1U;
  const uint32_t imm_5 = (imm >> 5) & 0x1U;
  const uint32_t imm_4 = (imm >> 4) & 0x1U;
  const uint32_t imm_3_1 = (imm >> 1) & 0x7U;

  return static_cast<uint16_t>(((0x5U & 0x7U) << 13) | (imm_11 << 12) |
                               (imm_4 << 11) | (imm_9_8 << 9) |
                               (imm_10 << 8) | (imm_6 << 7) | (imm_7 << 6) |
                               (imm_3_1 << 3) | (imm_5 << 2) | 0x1U);
}

inline uint16_t EncodeCBeqz(uint32_t rs1, int32_t imm9) {
  // Quadrant 1, funct3=110: C.BEQZ
  const uint32_t rs1_p = (rs1 - 8U) & 0x7U;
  const uint32_t imm = static_cast<uint32_t>(imm9) & 0x01FFU;

  const uint32_t imm_8 = (imm >> 8) & 0x1U;
  const uint32_t imm_7_6 = (imm >> 6) & 0x3U;
  const uint32_t imm_5 = (imm >> 5) & 0x1U;
  const uint32_t imm_4_3 = (imm >> 3) & 0x3U;
  const uint32_t imm_2_1 = (imm >> 1) & 0x3U;

  return static_cast<uint16_t>(((0x6U & 0x7U) << 13) | (imm_8 << 12) |
                               (imm_4_3 << 10) | ((rs1_p & 0x7U) << 7) |
                               (imm_7_6 << 5) | (imm_2_1 << 3) |
                               (imm_5 << 2) | 0x1U);
}

inline uint16_t EncodeCBnez(uint32_t rs1, int32_t imm9) {
  // Quadrant 1, funct3=111: C.BNEZ
  const uint32_t rs1_p = (rs1 - 8U) & 0x7U;
  const uint32_t imm = static_cast<uint32_t>(imm9) & 0x01FFU;

  const uint32_t imm_8 = (imm >> 8) & 0x1U;
  const uint32_t imm_7_6 = (imm >> 6) & 0x3U;
  const uint32_t imm_5 = (imm >> 5) & 0x1U;
  const uint32_t imm_4_3 = (imm >> 3) & 0x3U;
  const uint32_t imm_2_1 = (imm >> 1) & 0x3U;

  return static_cast<uint16_t>(((0x7U & 0x7U) << 13) | (imm_8 << 12) |
                               (imm_4_3 << 10) | ((rs1_p & 0x7U) << 7) |
                               (imm_7_6 << 5) | (imm_2_1 << 3) |
                               (imm_5 << 2) | 0x1U);
}

inline uint16_t EncodeCJr(uint32_t rs1) {
  // Quadrant 2, funct3=100, bit12=0, rs2=0: C.JR
  return static_cast<uint16_t>(((0x4U & 0x7U) << 13) | ((rs1 & 0x1FU) << 7) |
                               0x2U);
}

inline uint16_t EncodeCJalr(uint32_t rs1) {
  // Quadrant 2, funct3=100, bit12=1, rs2=0: C.JALR
  return static_cast<uint16_t>(((0x4U & 0x7U) << 13) | (0x1U << 12) |
                               ((rs1 & 0x1FU) << 7) | 0x2U);
}

inline uint16_t EncodeCLi(uint32_t rd, int32_t imm6) {
  // Quadrant 1, funct3=010: C.LI (like ADDI rd, x0, imm)
  // [15:13]=010 [12]=imm[5] [11:7]=rd [6:2]=imm[4:0] [1:0]=01
  const uint32_t imm = static_cast<uint32_t>(imm6) & 0x3FU;
  const uint32_t imm_5 = (imm >> 5) & 0x1U;
  const uint32_t imm_4_0 = imm & 0x1FU;
  return static_cast<uint16_t>((0x2U << 13) | (imm_5 << 12) |
                               ((rd & 0x1FU) << 7) | (imm_4_0 << 2) | 0x1U);
}

inline uint16_t EncodeCMv(uint32_t rd, uint32_t rs2) {
  // Quadrant 2, funct3=100, bit12=0: C.MV
  // [15:13]=100 [12]=0 [11:7]=rd [6:2]=rs2 [1:0]=10
  return static_cast<uint16_t>((0x4U << 13) | ((rd & 0x1FU) << 7) |
                               ((rs2 & 0x1FU) << 2) | 0x2U);
}

inline uint16_t EncodeCAdd(uint32_t rd, uint32_t rs2) {
  // Quadrant 2, funct3=100, bit12=1: C.ADD
  // [15:13]=100 [12]=1 [11:7]=rd/rs1 [6:2]=rs2 [1:0]=10
  return static_cast<uint16_t>((0x4U << 13) | (0x1U << 12) |
                               ((rd & 0x1FU) << 7) |
                               ((rs2 & 0x1FU) << 2) | 0x2U);
}

inline uint16_t EncodeCSlli(uint32_t rd, uint32_t shamt) {
  // Quadrant 2, funct3=000: C.SLLI
  // [15:13]=000 [12]=shamt[5] [11:7]=rd/rs1 [6:2]=shamt[4:0] [1:0]=10
  const uint32_t shamt_5 = (shamt >> 5) & 0x1U;
  const uint32_t shamt_4_0 = shamt & 0x1FU;
  return static_cast<uint16_t>((shamt_5 << 12) | ((rd & 0x1FU) << 7) |
                               (shamt_4_0 << 2) | 0x2U);
}

// --- FMA opcodes (R4-type) ---
constexpr uint32_t kOpcodeMadd = 0x43U;
constexpr uint32_t kOpcodeMsub = 0x47U;
constexpr uint32_t kOpcodeNmsub = 0x4BU;
constexpr uint32_t kOpcodeNmadd = 0x4FU;

inline uint32_t EncodeR4(uint32_t opcode, uint32_t rd, uint32_t rm,
                          uint32_t rs1, uint32_t rs2, uint32_t rs3,
                          uint32_t fmt) {
  const uint32_t funct7 = ((rs3 & 0x1FU) << 2) | (fmt & 0x3U);
  return EncodeR(opcode, rd, rm, rs1, rs2, funct7);
}

// --- C extension encoding helpers ---

// C.ADDI4SPN: CIW format, Q0 funct3=000
// nzuimm bits in instruction: [5:4|9:6|2|3]
inline uint16_t EncodeCAddi4spn(uint32_t rd, uint32_t nzuimm) {
  const uint32_t rd_p = (rd - 8U) & 0x7U;
  return static_cast<uint16_t>(
      (0x0U << 13) |
      (((nzuimm >> 5) & 1U) << 12) |
      (((nzuimm >> 4) & 1U) << 11) |
      (((nzuimm >> 9) & 1U) << 10) |
      (((nzuimm >> 8) & 1U) << 9) |
      (((nzuimm >> 7) & 1U) << 8) |
      (((nzuimm >> 6) & 1U) << 7) |
      (((nzuimm >> 2) & 1U) << 6) |
      (((nzuimm >> 3) & 1U) << 5) |
      (rd_p << 2) |
      0x0U);
}

// C.JAL (RV32 only): Q1 funct3=001, same layout as C.J
inline uint16_t EncodeCJal(int32_t imm12) {
  const uint32_t imm = static_cast<uint32_t>(imm12) & 0x0FFFU;
  return static_cast<uint16_t>(
      (0x1U << 13) |
      (((imm >> 11) & 1U) << 12) |
      (((imm >> 4) & 1U) << 11) |
      (((imm >> 8) & 3U) << 9) |
      (((imm >> 10) & 1U) << 8) |
      (((imm >> 6) & 1U) << 7) |
      (((imm >> 7) & 1U) << 6) |
      (((imm >> 1) & 7U) << 3) |
      (((imm >> 5) & 1U) << 2) |
      0x1U);
}

// C.ADDI16SP: Q1 funct3=011, rd=2
// nzimm bits: [9|4|6|8:7|5]
inline uint16_t EncodeCAddi16sp(int32_t nzimm) {
  const uint32_t imm = static_cast<uint32_t>(nzimm) & 0x3FFU;
  return static_cast<uint16_t>(
      (0x3U << 13) |
      (((imm >> 9) & 1U) << 12) |
      (2U << 7) |
      (((imm >> 4) & 1U) << 6) |
      (((imm >> 6) & 1U) << 5) |
      (((imm >> 8) & 1U) << 4) |
      (((imm >> 7) & 1U) << 3) |
      (((imm >> 5) & 1U) << 2) |
      0x1U);
}

// C.LUI: Q1 funct3=011, nzimm[17|16:12]
inline uint16_t EncodeCLui(uint32_t rd, int32_t nzimm) {
  const uint32_t imm = static_cast<uint32_t>(nzimm) & 0x3FU;
  return static_cast<uint16_t>(
      (0x3U << 13) |
      (((imm >> 5) & 1U) << 12) |
      ((rd & 0x1FU) << 7) |
      ((imm & 0x1FU) << 2) |
      0x1U);
}

// C.SRLI: Q1 funct3=100, funct2=00
inline uint16_t EncodeCSrli(uint32_t rd, uint32_t shamt) {
  const uint32_t rd_p = (rd - 8U) & 0x7U;
  return static_cast<uint16_t>(
      (0x4U << 13) |
      (((shamt >> 5) & 1U) << 12) |
      (0x0U << 10) |
      (rd_p << 7) |
      ((shamt & 0x1FU) << 2) |
      0x1U);
}

// C.SRAI: Q1 funct3=100, funct2=01
inline uint16_t EncodeCSrai(uint32_t rd, uint32_t shamt) {
  const uint32_t rd_p = (rd - 8U) & 0x7U;
  return static_cast<uint16_t>(
      (0x4U << 13) |
      (((shamt >> 5) & 1U) << 12) |
      (0x1U << 10) |
      (rd_p << 7) |
      ((shamt & 0x1FU) << 2) |
      0x1U);
}

// C.ANDI: Q1 funct3=100, funct2=10
inline uint16_t EncodeCAndi(uint32_t rd, int32_t imm6) {
  const uint32_t rd_p = (rd - 8U) & 0x7U;
  const uint32_t imm = static_cast<uint32_t>(imm6) & 0x3FU;
  return static_cast<uint16_t>(
      (0x4U << 13) |
      (((imm >> 5) & 1U) << 12) |
      (0x2U << 10) |
      (rd_p << 7) |
      ((imm & 0x1FU) << 2) |
      0x1U);
}

// CA-type helper for C.SUB/C.XOR/C.OR/C.AND/C.SUBW/C.ADDW
inline uint16_t EncodeCA(uint32_t rd, uint32_t rs2,
                          uint32_t funct6, uint32_t funct2) {
  const uint32_t rd_p = (rd - 8U) & 0x7U;
  const uint32_t rs2_p = (rs2 - 8U) & 0x7U;
  return static_cast<uint16_t>(
      ((funct6 & 0x3FU) << 10) |
      (rd_p << 7) |
      ((funct2 & 0x3U) << 5) |
      (rs2_p << 2) |
      0x1U);
}

inline uint16_t EncodeCSub(uint32_t rd, uint32_t rs2) {
  return EncodeCA(rd, rs2, 0x23U, 0x0U);
}
inline uint16_t EncodeCXor(uint32_t rd, uint32_t rs2) {
  return EncodeCA(rd, rs2, 0x23U, 0x1U);
}
inline uint16_t EncodeCOr(uint32_t rd, uint32_t rs2) {
  return EncodeCA(rd, rs2, 0x23U, 0x2U);
}
inline uint16_t EncodeCAnd(uint32_t rd, uint32_t rs2) {
  return EncodeCA(rd, rs2, 0x23U, 0x3U);
}
inline uint16_t EncodeCSubw(uint32_t rd, uint32_t rs2) {
  return EncodeCA(rd, rs2, 0x27U, 0x0U);
}
inline uint16_t EncodeCAddw(uint32_t rd, uint32_t rs2) {
  return EncodeCA(rd, rs2, 0x27U, 0x1U);
}

// C.LWSP: Q2 funct3=010
inline uint16_t EncodeCLwsp(uint32_t rd, uint32_t uimm) {
  return static_cast<uint16_t>(
      (0x2U << 13) |
      (((uimm >> 5) & 1U) << 12) |
      ((rd & 0x1FU) << 7) |
      (((uimm >> 2) & 0x7U) << 4) |
      (((uimm >> 6) & 0x3U) << 2) |
      0x2U);
}

// C.SWSP: Q2 funct3=110
inline uint16_t EncodeCSwsp(uint32_t rs2, uint32_t uimm) {
  return static_cast<uint16_t>(
      (0x6U << 13) |
      (((uimm >> 2) & 0xFU) << 9) |
      (((uimm >> 6) & 0x3U) << 7) |
      ((rs2 & 0x1FU) << 2) |
      0x2U);
}

// C.ADDIW (RV64 only): Q1 funct3=001
inline uint16_t EncodeCAddiw(uint32_t rd, int32_t imm6) {
  const uint32_t imm = static_cast<uint32_t>(imm6) & 0x3FU;
  return static_cast<uint16_t>(
      (0x1U << 13) |
      (((imm >> 5) & 1U) << 12) |
      ((rd & 0x1FU) << 7) |
      ((imm & 0x1FU) << 2) |
      0x1U);
}

// C.LD (RV64): Q0 funct3=011, uimm[5:3|7:6]
inline uint16_t EncodeCLd(uint32_t rd, uint32_t rs1, uint32_t uimm) {
  const uint32_t rd_p = (rd - 8U) & 0x7U;
  const uint32_t rs1_p = (rs1 - 8U) & 0x7U;
  return static_cast<uint16_t>(
      (0x3U << 13) |
      (((uimm >> 3) & 0x7U) << 10) |
      (rs1_p << 7) |
      (((uimm >> 6) & 0x3U) << 5) |
      (rd_p << 2) |
      0x0U);
}

// C.SD (RV64): Q0 funct3=111, uimm[5:3|7:6]
inline uint16_t EncodeCSd(uint32_t rs2, uint32_t rs1, uint32_t uimm) {
  const uint32_t rs2_p = (rs2 - 8U) & 0x7U;
  const uint32_t rs1_p = (rs1 - 8U) & 0x7U;
  return static_cast<uint16_t>(
      (0x7U << 13) |
      (((uimm >> 3) & 0x7U) << 10) |
      (rs1_p << 7) |
      (((uimm >> 6) & 0x3U) << 5) |
      (rs2_p << 2) |
      0x0U);
}

// C.LDSP (RV64): Q2 funct3=011, uimm[5|4:3|8:6]
inline uint16_t EncodeCLdsp(uint32_t rd, uint32_t uimm) {
  return static_cast<uint16_t>(
      (0x3U << 13) |
      (((uimm >> 5) & 1U) << 12) |
      ((rd & 0x1FU) << 7) |
      (((uimm >> 3) & 0x3U) << 5) |
      (((uimm >> 6) & 0x7U) << 2) |
      0x2U);
}

// C.SDSP (RV64): Q2 funct3=111, uimm[5:3|8:6]
inline uint16_t EncodeCSdsp(uint32_t rs2, uint32_t uimm) {
  return static_cast<uint16_t>(
      (0x7U << 13) |
      (((uimm >> 3) & 0x7U) << 10) |
      (((uimm >> 6) & 0x7U) << 7) |
      ((rs2 & 0x1FU) << 2) |
      0x2U);
}

// C.FLD: Q0 funct3=001, same layout as C.LD
inline uint16_t EncodeCFld(uint32_t rd, uint32_t rs1, uint32_t uimm) {
  const uint32_t rd_p = (rd - 8U) & 0x7U;
  const uint32_t rs1_p = (rs1 - 8U) & 0x7U;
  return static_cast<uint16_t>(
      (0x1U << 13) |
      (((uimm >> 3) & 0x7U) << 10) |
      (rs1_p << 7) |
      (((uimm >> 6) & 0x3U) << 5) |
      (rd_p << 2) |
      0x0U);
}

// C.FSD: Q0 funct3=101
inline uint16_t EncodeCFsd(uint32_t rs2, uint32_t rs1, uint32_t uimm) {
  const uint32_t rs2_p = (rs2 - 8U) & 0x7U;
  const uint32_t rs1_p = (rs1 - 8U) & 0x7U;
  return static_cast<uint16_t>(
      (0x5U << 13) |
      (((uimm >> 3) & 0x7U) << 10) |
      (rs1_p << 7) |
      (((uimm >> 6) & 0x3U) << 5) |
      (rs2_p << 2) |
      0x0U);
}

// C.FLW (RV32 only): Q0 funct3=011, word-scaled
inline uint16_t EncodeCFlw(uint32_t rd, uint32_t rs1, uint32_t uimm) {
  const uint32_t rd_p = (rd - 8U) & 0x7U;
  const uint32_t rs1_p = (rs1 - 8U) & 0x7U;
  return static_cast<uint16_t>(
      (0x3U << 13) |
      (((uimm >> 3) & 0x7U) << 10) |
      (rs1_p << 7) |
      (((uimm >> 2) & 1U) << 6) |
      (((uimm >> 6) & 1U) << 5) |
      (rd_p << 2) |
      0x0U);
}

// C.FSW (RV32 only): Q0 funct3=111
inline uint16_t EncodeCFsw(uint32_t rs2, uint32_t rs1, uint32_t uimm) {
  const uint32_t rs2_p = (rs2 - 8U) & 0x7U;
  const uint32_t rs1_p = (rs1 - 8U) & 0x7U;
  return static_cast<uint16_t>(
      (0x7U << 13) |
      (((uimm >> 3) & 0x7U) << 10) |
      (rs1_p << 7) |
      (((uimm >> 2) & 1U) << 6) |
      (((uimm >> 6) & 1U) << 5) |
      (rs2_p << 2) |
      0x0U);
}

// C.FLDSP: Q2 funct3=001, same layout as C.LDSP
inline uint16_t EncodeCFldsp(uint32_t rd, uint32_t uimm) {
  return static_cast<uint16_t>(
      (0x1U << 13) |
      (((uimm >> 5) & 1U) << 12) |
      ((rd & 0x1FU) << 7) |
      (((uimm >> 3) & 0x3U) << 5) |
      (((uimm >> 6) & 0x7U) << 2) |
      0x2U);
}

// C.FSDSP: Q2 funct3=101
inline uint16_t EncodeCFsdsp(uint32_t rs2, uint32_t uimm) {
  return static_cast<uint16_t>(
      (0x5U << 13) |
      (((uimm >> 3) & 0x7U) << 10) |
      (((uimm >> 6) & 0x7U) << 7) |
      ((rs2 & 0x1FU) << 2) |
      0x2U);
}

// C.FLWSP (RV32 only): Q2 funct3=011, word-scaled
inline uint16_t EncodeCFlwsp(uint32_t rd, uint32_t uimm) {
  return static_cast<uint16_t>(
      (0x3U << 13) |
      (((uimm >> 5) & 1U) << 12) |
      ((rd & 0x1FU) << 7) |
      (((uimm >> 2) & 0x7U) << 4) |
      (((uimm >> 6) & 0x3U) << 2) |
      0x2U);
}

// C.FSWSP (RV32 only): Q2 funct3=111
inline uint16_t EncodeCFswsp(uint32_t rs2, uint32_t uimm) {
  return static_cast<uint16_t>(
      (0x7U << 13) |
      (((uimm >> 2) & 0xFU) << 9) |
      (((uimm >> 6) & 0x3U) << 7) |
      ((rs2 & 0x1FU) << 2) |
      0x2U);
}

}  // namespace riscv
