/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

// VMILL ByteCode virtual machine:
//
// The VM has 4 key sections:
//
//    ops:      This is where VM operations (instructions) are store. The
//              operations are executed sequentially, and can contain internal
//              and external branching. The ops section is split into logical
//              sections by virtue of special Enter32 and Enter64 operations.
//              These refer to entering into the implementation of a basic
//              block of machine code, and setting the logical instruction
//              pointer to a 32- or 64-bit value. An Enter32 does not
//              categorically imply that the following operations emulate 64-
//              bit code. Instead, it implies that the logical program counter
//              can be represented as a signed, 32-bit integer.
//
//    state:    This is where the architecture-specific `State` struct is
//              stored.
//
//    stack:    This is where the "stack" goes. This is used in cases where
//              the lifted bitcode uses `alloca` instructions. This is pretty
//              rare, but will happen for things like vector instructions.
//
//    data:     Every operation corresponds to exactly one 8-byte data slot.
//              An operation that produces a value, e.g. addition, will store
//              its value into the data slot corresponding to the instruction.
//              Some instructions produce 128-bit values, which cannot fit
//              into a single data slot. In this case, a kind of delay operation
//              is introduced into the operations list that ensures that two
//              data slots are available for a 128-bit write.
//
//    const:    A constant pool, containing constants used by the instructions.
//              The constant pool is memory mapped from disk, and is not
//              globally deduplicated. The granularity of deduplication is a
//              "translation unit". When asked to translate previously
//              unseen code, VMILL will recursively decode machine code
//              instructions from the emulated process's executable memory
//              areas. The discovered machine code is a translation unit. Its
//              size is dependent on how much code is statically discoverable
//              from the translation request's entry point.

#ifndef OP
# define OP(name, num_op_slots, bytes_read, bytes_written)
#endif

#define SPAN_OP_8_TO_128(name) \
  OP(name ## 8, 1, 1, 1) \
  OP(name ## 16, 1, 1, 2) \
  OP(name ## 32, 1, 4, 4) \
  OP(name ## 64, 1, 8, 8) \
  OP(name ## 128, 1, 16, 16)

#define SPAN_OP_32_TO_64(name) \
  OP(name ## 32, 1, 4, 4) \
  OP(name ## 64, 1, 8, 8)

// Load an immediate untyped constant into a temporary location from
// the constant pool.
//
// Note: This must go fist. We represent this operation as:
//               8               24
//          +---------+--------------------------+
//          | op code | index into constant pool |
//          +---------+--------------------------+
//
//       We don't want to have to mask out the opcode byte in order to get
//       at the index into the constant pool, so we ensure that the opcode
//       is zero so that the whole Operation, when treated as an integer,
//       can be used as an index into the pool.
//
// Note: Though this is declared as storing 8 bytes, it is possible that it
//       "read" 16 bytes indirectly. This is implemented by having a Zero
//       delay slot following the constant, effectively zeroing the high
//       8 bytes of a 16-byte constant.
OP(Constant, 1, 0, 8)

// No-op that allocates "overflow" space in the data store.
//
//    v6: Add128 v2, v4        // Add two 128-bit integers
//    v7: AllocOverflowData    // Ensures that the 128-bit result of v6 can
//                             // overwrite two data slots without conflict.
//
// The above would performs the following operation:
//
//    data[7:6] = data[3:2] + data[4:4]
//
// Thus, the `Add128` that writes to `data[7:6]` is named by `v6`, so future
// operations reading the value can read out 128-bits, but this is only made
// legal by having the overflow delay slot that ensures that the high 8 bytes
// of the result doesn't clobber another valid operation.
OP(AllocOverflowData, 1, 0, 8)

// Enter into some new code section, marking the section with a 32-bit PC.
//
// Note: This operation spans two Operations.
//          +---------+-------+
//          | op code | empty |
//          +---------+-------+
//          |     32-bit PC   |
//          +-----------------+
OP(Enter32, 2, 0, 0)

// Enter into some new code section, marking the section with a 64-bit, little
// endian PC.
//
// Note: This operation spans two Operations.
//          +---------+-------+
//          | op code | empty |
//          +---------+-------+
//          |     PC[0:31]    |
//          +-----------------+
//          |     PC[32:63]   |
//          +-----------------+
OP(Enter64, 3, 0, 0)

// Exit to a different code section.
OP(ExitCall, 1, 0, 0)
OP(ExitRet, 1, 0, 0)
OP(ExitJump, 1, 0, 0)
OP(ExitAsyncHyperCall, 1, 0, 0)
OP(ExitError, 1, 0, 0)

// Control flow.

OP(GoTo, 1, 0, 0)
OP(CondGoTo, 1, 1, 0)

// Relative jump to the next basic block. This is represented as:
//               8        8              16
//          +---------+-------+---------------------+
//          | op code | empty | signed displacement |
//          +---------+-------+---------------------+
OP(Jump, 1, 0, 0)

// Relative jump to the next basic block, where the next basic block is
// forward or backward in the operations stream. We separate forward from
// backward so that we don't need to sign-extend a 24-bit relative value.
//               8               24
//          +---------+-----------------------+
//          | op code | unsigned displacement |
//          +---------+-----------------------+
OP(JumpFarBackward, 1, 0, 0)
OP(JumpFarForward, 1, 0, 0)

// Synchronous hyper call. This is for things like unsupported instructions,
// as well as instructions that interact directly with the hardware and cannot
// be independently modelled (e.g. reading the time stamp counter, or CPU
// features).
OP(SyncHyperCall, 1, 0, 0)

// Calls out to compiler builtin intrinsics. These are for things like
// counting leading/trailing zero bits, counting the number of 1 bits, etc.
// Intrinsics may take two operands, but usually just one.
//               8       8      8       8
//          +---------+-----+-------+-------+
//          | op code | ID  | var 1 | var 2 |
//          +---------+-----+-------+-------+
OP(Intrinsic8, 1, 1, 1)
OP(Intrinsic16, 1, 2, 2)
OP(Intrinsic32, 1, 4, 4)
OP(Intrinsic64, 1, 8, 8)
OP(Intrinsic128, 1, 16, 16)

// Calls out to floating-point compiler builtin intrinsics. These are for
// things like `sin`, `cos`, etc. More mundane uses are for floating point
// rounding and truncation. These have the same representation as integer
// intrinsics.
OP(FPIntrinsic32, 1, 4, 4)
OP(FPIntrinsic64, 1, 8, 8)

// Read and write register data from the state struct.
//
//    v6: Read16 8      // data[6] = (uint64_t) *((uint16_t *) &state[8])
//
SPAN_OP_8_TO_128(Read)
SPAN_OP_8_TO_128(Write)

// Read and write data from the stack.
SPAN_OP_8_TO_128(ReadStack)
SPAN_OP_8_TO_128(WriteStack)

// Put a 0 into a data slot.
//
//    v6: Zero        // data[6] = 0
//
OP(Zero, 1, 0, 8)

// Put a 1 into a data slot.
//
//    v6: One         // data[6] = 1
//
OP(One, 1, 0, 8)

// Put a non-zero, 64-bit power of 2, into a data slot.
//
//    v6: kOpPow2 6    // data[6] = 1 << 6
//
OP(Pow2, 1, 0, 8)
OP(NegPow2, 1, 0, 8)

// Integers that can be represented as positive or negative 16-bit values.
OP(Positive16, 1, 0, 8)
OP(Negative16, 1, 0, 8)

// Read and write data from memory to/from a temporary location.
OP(ReadMem8, 1, 1, 1)
OP(ReadMem16, 1, 2, 2)
OP(ReadMem32, 1, 4, 4)
OP(ReadMem64, 1, 8, 8)
OP(ReadMemFP80, 1, 0, 8)

OP(WriteMem8, 1, 8, 0)
OP(WriteMem16, 1, 8, 0)
OP(WriteMem32, 1, 8, 0)
OP(WriteMem64, 1, 8, 0)
OP(WriteMemFP80, 1, 8, 0)

SPAN_OP_8_TO_128(ITE)

// Arithmetic binary operators.
SPAN_OP_8_TO_128(Add)
SPAN_OP_8_TO_128(Sub)
SPAN_OP_8_TO_128(Mul)
SPAN_OP_8_TO_128(UDiv)
SPAN_OP_8_TO_128(SDiv)
SPAN_OP_8_TO_128(URem)
SPAN_OP_8_TO_128(SRem)

// Logical binary operators.
SPAN_OP_8_TO_128(Shl)
SPAN_OP_8_TO_128(LShr)
SPAN_OP_8_TO_128(AShr)
SPAN_OP_8_TO_128(And)
SPAN_OP_8_TO_128(Or)
SPAN_OP_8_TO_128(Xor)

SPAN_OP_32_TO_64(FAdd)
SPAN_OP_32_TO_64(FSub)
SPAN_OP_32_TO_64(FMul)
SPAN_OP_32_TO_64(FDiv)
SPAN_OP_32_TO_64(FRem)

// Unary operators.
SPAN_OP_8_TO_128(Neg)
SPAN_OP_8_TO_128(Not)

// Unary cast operators.
OP(TruncTo8, 1, 8, 1)
OP(TruncTo16, 1, 8, 2)
OP(TruncTo32, 1, 8, 4)
OP(TruncTo64, 1, 16, 8)

OP(ZExtFrom8, 1, 1, 8)
OP(ZExtFrom16, 1, 2, 8)
OP(ZExtFrom32, 1, 4, 8)
OP(ZExtFrom64, 1, 8, 16)

OP(SExtFrom8, 1, 1, 8)
OP(SExtFrom16, 1, 2, 8)
OP(SExtFrom32, 1, 4, 8)
OP(SExtFrom64, 1, 8, 16)

OP(FPTrunc64To32, 1, 8, 4)
OP(FPExt32To64, 1, 4, 8)

OP(FP64ToUI64, 1, 8, 8)
OP(FP64ToUI32, 1, 8, 4)
OP(FP32ToUI64, 1, 4, 8)
OP(FP32ToUI32, 1, 4, 4)

OP(FP64ToSI64, 1, 8, 8)
OP(FP64ToSI32, 1, 8, 4)
OP(FP32ToSI64, 1, 4, 8)
OP(FP32ToSI32, 1, 4, 4)

OP(UI64ToFP64, 1, 1, 8)
OP(UI32ToFP64, 1, 1, 8)
OP(UI64ToFP32, 1, 1, 4)
OP(UI32ToFP32, 1, 1, 4)

OP(SI64ToFP64, 1, 8, 8)
OP(SI32ToFP64, 1, 4, 8)
OP(SI64ToFP32, 1, 8, 4)
OP(SI32ToFP32, 1, 4, 4)

// Binary comparison operators.
SPAN_OP_32_TO_64(FCmpEq)
SPAN_OP_32_TO_64(FCmpGt)
SPAN_OP_32_TO_64(FCmpGe)
SPAN_OP_32_TO_64(FCmpLt)
SPAN_OP_32_TO_64(FCmpLe)
SPAN_OP_32_TO_64(FCmpNe)

SPAN_OP_8_TO_128(ICmpEq)
SPAN_OP_8_TO_128(ICmpNe)
SPAN_OP_8_TO_128(ICmpUgt)
SPAN_OP_8_TO_128(ICmpUge)
SPAN_OP_8_TO_128(ICmpUlt)
SPAN_OP_8_TO_128(ICmpUle)
SPAN_OP_8_TO_128(ICmpSgt)
SPAN_OP_8_TO_128(ICmpSge)
SPAN_OP_8_TO_128(ICmpSlt)
SPAN_OP_8_TO_128(ICmpSle)

// Generic representation for barriers, these are interruptible locations.
OP(SafePoint, 1, 0, 0)

OP(Invalid, 1, 0, 0)

#undef SPAN_OP_8_TO_128
#undef SPAN_OP_32_TO_64

#ifdef OP
# undef OP
#endif
