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
#include <string>

namespace riscv {

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

}  // namespace riscv
