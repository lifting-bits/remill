/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef TOOLS_VMILL_EMULATOR_BYTECODE_OPERATION_H_
#define TOOLS_VMILL_EMULATOR_BYTECODE_OPERATION_H_

#include <cstdint>
#include <string>

#include "remill/Arch/Runtime/HyperCall.h"

namespace remill {
namespace vmill {

using VarId = uint8_t;

#define PACKED __attribute__((packed))

class OpCode final {
 public:
  enum Name : uint8_t {
#define OP(name, num_op_slots, bytes_read, bytes_written) \
    k ## name,
#include "Operation.inc"
  };

  static const uint64_t kNumOpSlots[];
  static const uint64_t kNumBytesRead[];
  static const uint64_t kNumBitsRead[];
  static const uint64_t kNumBytesWritten[];
  static const uint64_t kNumBitsWritten[];
  static const char * const kName[];
};

class Intrinsic final {
 public:
  enum Name : uint8_t {
    kPopCount,
    kNumLeadingZeros,
    kNumTrailingZeros,
    kByteSwap,
    kInvalid
  };

  static const char * const kName[];
};

class FPIntrinsic final {
 public:
  enum Name : uint8_t {
    kSin,
    kCos,
    kTan,
    kArcTan,
    kRoundToNearestInt,
    kTruncToNearestInt,
    kInvalid
  };

  static const char * const kName[];
};

struct Operation final {

  // Serialize the operation into a string (for debugging).
  std::string Serialize(void) const;

  OpCode::Name op_code;
  uint32_t _0:24;

  struct Enter32 final {
    OpCode::Name op_code;
    uint8_t _0;
    uint16_t state_size;  // State size in bytes, including stack.
    uint32_t pc;

    inline uint64_t ProgramCounter(void) const {
      return static_cast<uint64_t>(pc);
    }
  } PACKED;

  static_assert(8 == sizeof(Enter32),
                "Invalid packing of `struct Enter`.");

  // May use a delay slot for alignment.
  struct Enter64 final {
    OpCode::Name op_code;
    uint8_t _0;
    uint16_t state_size;  // State size in bytes, including stack.
    uint64_t pc;

    inline uint64_t ProgramCounter(void) const {
      return pc;
    }
  } PACKED;

  static_assert(12 == sizeof(Enter64),
                "Invalid packing of `struct Enter`.");

  struct Exit final {
    OpCode::Name op_code;
    uint8_t _0;
    uint8_t _1;
    VarId pc_var;
  } PACKED;

  static_assert(4 == sizeof(Exit),
                "Invalid packing of `struct Exit`.");

  struct GoTo final {
    OpCode::Name op_code;
    VarId cond_var;
    VarId true_var;
    VarId false_var;
  } PACKED;

  static_assert(4 == sizeof(GoTo),
                "Invalid packing of `struct GoTo`.");

  struct Jump final {
    OpCode::Name op_code;
    uint8_t _0;
    int16_t rel_offset;
  } PACKED;

  static_assert(4 == sizeof(Jump),
                "Invalid packing of `struct Jump`.");

  struct JumpFar final {
    OpCode::Name op_code;
    uint32_t rel_offset:24;
  } PACKED;

  static_assert(4 == sizeof(JumpFar),
                "Invalid packing of `struct JumpFar`.");
  // ITE.
  struct ITE final {
    OpCode::Name op_code;
    VarId cond_var;
    VarId true_var;
    VarId false_var;
  } PACKED;

  static_assert(4 == sizeof(ITE),
                "Invalid packing of `struct ITE`.");

  // Arithmetic, bitwise, comparisons.
  struct Binary final {
    OpCode::Name op_code;
    uint8_t _1;
    VarId src1_var;
    VarId src2_var;
  } PACKED;

  static_assert(4 == sizeof(Binary),
                "Invalid packing of `struct Binary`.");

  // Conversions, and arithmetic and bitwise negation.
  struct Unary final {
    OpCode::Name op_code;
    uint8_t _1;
    uint8_t _2;
    VarId src_var;
  } PACKED;

  static_assert(4 == sizeof(Unary),
                "Invalid packing of `struct Unary`.");

  // The opcode of `Constant` will have value 0, so that the operation itself
  // can be treated as a 32-bit unsigned offset into the global constant pool.
  struct Constant final {
    OpCode::Name op_code;
    uint32_t offset:24;
  } PACKED;

  static_assert(4 == sizeof(Constant),
                "Invalid packing of `struct Constant`.");

  static_assert(OpCode::kConstant == 0,
                "Assumption broken! kOpConstant must be zero!");

  struct Pow2 final {
    OpCode::Name op_code;
    uint8_t _0;
    uint8_t _1;
    uint8_t shift;
  } PACKED;

  static_assert(4 == sizeof(Pow2),
                "Invalid packing of `struct Pow2`.");

  struct PositiveInteger final {
    OpCode::Name op_code;
    uint8_t _0;
    uint16_t val;
  } PACKED;

  static_assert(4 == sizeof(PositiveInteger),
                "Invalid packing of `struct PositiveInteger`.");

  struct NegativeInteger final {
    OpCode::Name op_code;
    uint8_t _0;
    int16_t val;
  } PACKED;

  static_assert(4 == sizeof(NegativeInteger),
                "Invalid packing of `struct NegativeInteger`.");

  struct HyperCall final {
    OpCode::Name op_code;
    uint8_t _0;
    SyncHyperCall::Name call:16;
  } PACKED;

  static_assert(4 == sizeof(HyperCall),
                "Invalid packing of `struct HyperCall`.");

  struct IntrinsicCall final {
    OpCode::Name op_code;
    Intrinsic::Name call;
    VarId src1_var;
    VarId src2_var;  // Optional.
  } PACKED;

  static_assert(4 == sizeof(IntrinsicCall),
                "Invalid packing of `struct IntrinsicCall`.");

  struct FPIntrinsicCall final {
    OpCode::Name op_code;
    FPIntrinsic::Name call;
    VarId src2_var;  // Optional.
    VarId src1_var;
  } PACKED;

  static_assert(4 == sizeof(FPIntrinsicCall),
                "Invalid packing of `struct FPIntrinsicCall`.");

  struct Mem final {
    OpCode::Name op_code;
    uint8_t _0;
    VarId src_var;
    VarId addr_var;
  } PACKED;

  static_assert(4 == sizeof(Mem),
                "Invalid packing of `struct ReadMem`.");

  // Loads of state structure, allocas, or PHI nodes.
  struct State final {
    OpCode::Name op_code;
    VarId src_var;
    uint16_t offset;
  } PACKED;

  static_assert(4 == sizeof(State),
                "Invalid packing of `struct ReadState`.");
} PACKED;

static_assert(4 == sizeof(Operation),
              "Invalid packing of `struct Operation`.");

#undef PACKED

}  // namespace vmill
}  // namespace remill

#endif  // TOOLS_VMILL_EMULATOR_BYTECODE_OPERATION_H_
