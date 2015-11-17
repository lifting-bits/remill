/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef MCSEMA_ARCH_SEMANTICS_MACROS_INC_
#define MCSEMA_ARCH_SEMANTICS_MACROS_INC_

#if 64 == ADDRESS_SIZE_BITS
# define IF_32BIT(...)
# define IF_64BIT(...) __VA_ARGS__
#else
# define IF_32BIT(...) __VA_ARGS__
# define IF_64BIT(...)
#endif

#define ALWAYS_INLINE [[gnu::always_inline, gnu::gnu_inline, gnu::flatten]]
#define INSTR_ATTRIBS ALWAYS_INLINE

// Define a specific instruction selection variable.
#define DEF_ISEL(name) \
  extern "C" constexpr auto name [[gnu::used]]

// Define a semantics implementing function.
#define DEF_SEM(name, ...) \
    INSTR_ATTRIBS static inline void name (State &state, ##__VA_ARGS__) noexcept

// An instruction where the implementation is the same for all operand sizes.
#define DEF_ISEL_ALL(name, func) \
    DEF_ISEL(name ## _8) = func ; \
    DEF_ISEL(name ## _16) = func ; \
    DEF_ISEL(name ## _32) = func ; \
    DEF_ISEL(name ## _64) = func

// An instruction where the implementation is the same for all operand sizes
// and where only 32- and 64-bit operand sizes are supported.
#define DEF_ISEL_32UP(name, func) \
    DEF_ISEL(name ## _32) = func \
    IF_64BIT( ; DEF_ISEL(name ## _64) = func )

// An instruction with no explicit destination operand that reads either a
// 32- or a 64-bit value (register or immediate).
#define DEF_ISEL_READONLY_32OR64(name, func) \
    IF_32BIT( DEF_ISEL(name ## _32) = func<uint32_t> ) \
    IF_64BIT( DEF_ISEL(name ## _64) = func<uint64_t> )

// An instruction with a single 32- or 64-bit register destination operand.
#define DEF_ISEL_R32OR64(name, func) \
    IF_32BIT( DEF_ISEL(name ## _32) = func<R32W> ) \
    IF_64BIT( DEF_ISEL(name ## _64) = func<R64W> )

// An instruction with a single 32- or 64-bit memory destination operand.
#define DEF_ISEL_M32OR64(name, func) \
    IF_32BIT( DEF_ISEL(name ## _32) = func<M32> ) \
    IF_64BIT( DEF_ISEL(name ## _64) = func<M64> )

// An instruction with no explicit destination operand and a register source.
#define DEF_ISEL_READONLY_Rn(name, tpl_func) \
    DEF_ISEL(name ## _8) = tpl_func<R8> ; \
    DEF_ISEL(name ## _16) = tpl_func<R16> ; \
    DEF_ISEL(name ## _32) = tpl_func<R32> \
    IF_64BIT( ; DEF_ISEL(name ## _64) = tpl_func<R64> )

// An instruction with a single, explicit destination operand (register).
#define DEF_ISEL_Rn(name, tpl_func) \
    DEF_ISEL(name ## _8) = tpl_func<R8W> ; \
    DEF_ISEL(name ## _16) = tpl_func<R16W> ; \
    DEF_ISEL(name ## _32) = tpl_func<R32W> \
    IF_64BIT( ; DEF_ISEL(name ## _64) = tpl_func<R64W> )

// An instruction with a single, explicit destination operand (memory).
#define DEF_ISEL_Mn(name, tpl_func) \
    DEF_ISEL(name ## _8) = tpl_func<M8> ; \
    DEF_ISEL(name ## _16) = tpl_func<M16> ; \
    DEF_ISEL(name ## _32) = tpl_func<M32> \
    IF_64BIT( ; DEF_ISEL(name ## _64) = tpl_func<M64> )

// An instruction with no explicit destination operand and an immediate source.
#define DEF_ISEL_READONLY_In(name, tpl_func) \
    DEF_ISEL(name ## _8) = tpl_func<I8> ; \
    DEF_ISEL(name ## _16) = tpl_func<I16> ; \
    DEF_ISEL(name ## _32) = tpl_func<I32> \
    IF_64BIT( ; DEF_ISEL(name ## _64) = tpl_func<I64> )

// Two operand: REG <- MEM
#define DEF_ISEL_Rn_Mn(name, tpl_func) \
    DEF_ISEL(name ## _8) = tpl_func<R8W, M8> ; \
    DEF_ISEL(name ## _16) = tpl_func<R16W, M16> ; \
    DEF_ISEL(name ## _32) = tpl_func<R32W, M32> \
    IF_64BIT( ; DEF_ISEL(name ## _64) = tpl_func<R64W, M64> )

// Two operand: REG <- REG
#define DEF_ISEL_Rn_Rn(name, tpl_func) \
    DEF_ISEL(name ## _8) = tpl_func<R8W, R8> ; \
    DEF_ISEL(name ## _16) = tpl_func<R16W, R16> ; \
    DEF_ISEL(name ## _32) = tpl_func<R32W, R32> \
    IF_64BIT( ; DEF_ISEL(name ## _64) = tpl_func<R64W, R64> )

// Two operand: REG <- IMM
#define DEF_ISEL_Rn_In(name, tpl_func) \
    DEF_ISEL(name ## _8) = tpl_func<R8W, I8> ; \
    DEF_ISEL(name ## _16) = tpl_func<R16W, I16> ; \
    DEF_ISEL(name ## _32) = tpl_func<R32W, I32> \
    IF_64BIT( ; DEF_ISEL(name ## _64) = tpl_func<R64W, I64> )

// Two operand: MEM <- IMM
#define DEF_ISEL_Mn_In(name, tpl_func) \
    DEF_ISEL(name ## _8) = tpl_func<M8, I8> ; \
    DEF_ISEL(name ## _16) = tpl_func<M16, I16> ; \
    DEF_ISEL(name ## _32) = tpl_func<M32, I32> \
    IF_64BIT( ; DEF_ISEL(name ## _64) = tpl_func<M64, I64> )

// Two operand: MEM <- REG
#define DEF_ISEL_Mn_Rn(name, tpl_func) \
    DEF_ISEL(name ## _8) = tpl_func<M8, R8> ; \
    DEF_ISEL(name ## _16) = tpl_func<M16, R16> ; \
    DEF_ISEL(name ## _32) = tpl_func<M32, R32> \
    IF_64BIT( ; DEF_ISEL(name ## _64) = tpl_func<M64, R64> )

// Two operand: MEM <- MEM
#define DEF_ISEL_Mn_Mn(name, tpl_func) \
    DEF_ISEL(name ## _8) = tpl_func<M8> ; \
    DEF_ISEL(name ## _16) = tpl_func<M16> ; \
    DEF_ISEL(name ## _32) = tpl_func<M32> \
    IF_64BIT( ; DEF_ISEL(name ## _64) = tpl_func<M64> )

// Two operand instruction with no explicit destination operand, but that
// reads a register and memory location.
#define DEF_ISEL_READONLY_Rn_Mn(name, tpl_func) \
    DEF_ISEL(name ## _8) = tpl_func<R8, M8> ; \
    DEF_ISEL(name ## _16) = tpl_func<R16, M16> ; \
    DEF_ISEL(name ## _32) = tpl_func<R32, M32> \
    IF_64BIT( ; DEF_ISEL(name ## _64) = tpl_func<R64, M64> )

// Two operand instruction with no explicit destination operand, but that
// reads two register operands.
#define DEF_ISEL_READONLY_Rn_Rn(name, tpl_func) \
    DEF_ISEL(name ## _8) = tpl_func<R8, R8> ; \
    DEF_ISEL(name ## _16) = tpl_func<R16, R16> ; \
    DEF_ISEL(name ## _32) = tpl_func<R32, R32> \
    IF_64BIT( ; DEF_ISEL(name ## _64) = tpl_func<R64, R64> )

// Two operand instruction with no explicit destination operand, but that
// reads a register and immediate operand.
#define DEF_ISEL_READONLY_Rn_In(name, tpl_func) \
    DEF_ISEL(name ## _8) = tpl_func<R8, I8> ; \
    DEF_ISEL(name ## _16) = tpl_func<R16, I16> ; \
    DEF_ISEL(name ## _32) = tpl_func<R32, I32> \
    IF_64BIT( ; DEF_ISEL(name ## _64) = tpl_func<R64, I64> )

// Two operand instruction with no explicit destination operand, but that
// reads a register an memory location, or immediate and memory.
#define DEF_ISEL_READONLY_Mn_In DEF_ISEL_Mn_In
#define DEF_ISEL_READONLY_Mn_Rn DEF_ISEL_Mn_Rn

// Three operand: REG_a <- REG_a OP MEM.
#define DEF_ISEL_Rn_Rn_Mn(name, tpl_func) \
    DEF_ISEL(name ## _8) = tpl_func<R8W, R8, M8> ; \
    DEF_ISEL(name ## _16) = tpl_func<R16W, R16, M16> ; \
    DEF_ISEL(name ## _32) = tpl_func<R32W, R32, M32> \
    IF_64BIT( ; DEF_ISEL(name ## _64) = tpl_func<R64W, R64, M64> )

// Three operand: REG_a <- REG_a OP REG_b.
#define DEF_ISEL_Rn_Rn_Rn(name, tpl_func) \
    DEF_ISEL(name ## _8) = tpl_func<R8W, R8, R8> ; \
    DEF_ISEL(name ## _16) = tpl_func<R16W, R16, R16> ; \
    DEF_ISEL(name ## _32) = tpl_func<R32W, R32, R32> \
    IF_64BIT( ; DEF_ISEL(name ## _64) = tpl_func<R64W, R64, R64> )

// Three operand: REG_a <- REG_a OP IMM.
#define DEF_ISEL_Rn_Rn_In(name, tpl_func) \
    DEF_ISEL(name ## _8) = tpl_func<R8W, R8, I8> ; \
    DEF_ISEL(name ## _16) = tpl_func<R16W, R16, I16> ; \
    DEF_ISEL(name ## _32) = tpl_func<R32W, R32, I32> \
    IF_64BIT( ; DEF_ISEL(name ## _64) = tpl_func<R64W, R64, I64> )

// Three operand: MEM_a <- MEM_a OP IMM.
#define DEF_ISEL_Mn_Mn_In(name, tpl_func) \
    DEF_ISEL(name ## _8) = tpl_func<M8, I8> ; \
    DEF_ISEL(name ## _16) = tpl_func<M16, I16> ; \
    DEF_ISEL(name ## _32) = tpl_func<M32, I32> \
    IF_64BIT( ; DEF_ISEL(name ## _64) = tpl_func<M64, I64> )

// Three operand: MEM_a <- MEM_a OP REG.
#define DEF_ISEL_Mn_Mn_Rn(name, tpl_func) \
    DEF_ISEL(name ## _8) = tpl_func<M8, R8> ; \
    DEF_ISEL(name ## _16) = tpl_func<M16, R16> ; \
    DEF_ISEL(name ## _32) = tpl_func<M32, R32> \
    IF_64BIT( ; DEF_ISEL(name ## _64) = tpl_func<M64, R64> )

#endif  // MCSEMA_ARCH_SEMANTICS_MACROS_INC_
