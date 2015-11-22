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


// Used to enable/disable "transparent" behaviors.
//
// This is hopped to enable more aggressive optimization of code that is
// emitted by sane compilers. The idea is that the flags register is typically
// "dead" after a conditional branch, and before an indirect jump,
// a function/system/interrupt call, and a function/system/interrupt return.
// In these cases, we will try to kill all the flags with the hope that the
// compiler will see this and perform dead store elimination on all prior
// flags computations.
//
// TODO(pag): Enable a switch if/when this turns out to be a bad idea.
#define IF_NOT_TRANSPARENT(...) __VA_ARGS__

// Attributes that will force inlining of specific code.
#define ALWAYS_INLINE [[gnu::always_inline, gnu::gnu_inline, gnu::flatten]]
#define INSTR_ATTRIBS ALWAYS_INLINE

// Define a specific instruction selection variable.
#define DEF_ISEL(name) \
  extern "C" constexpr auto name [[gnu::used]]

// Define a semantics implementing function.
#define DEF_SEM(name, ...) \
    INSTR_ATTRIBS \
    static inline void name (State &state, ##__VA_ARGS__) noexcept

// An instruction where the implementation is the same for all operand sizes.
#define DEF_ISEL_ALL(name, func) \
    DEF_ISEL(name ## _8) = func ; \
    DEF_ISEL(name ## _16) = func ; \
    DEF_ISEL(name ## _32) = func ; \
    DEF_ISEL(name ## _64) = func

// An instruction where the implementation is the same for all operand sizes
// and where only 32- and 64-bit operand sizes are supported.
#define DEF_ISEL_32or64(name, func) \
    IF_32BIT( DEF_ISEL(name ## _32) = func ) \
    IF_64BIT( DEF_ISEL(name ## _64) = func )

// An instruction with no explicit destination operand that reads either a
// 32- or a 64-bit register or immediate value.
#define DEF_ISEL_RI32or64(name, func) \
    IF_32BIT( DEF_ISEL(name ## _32) = func<uint32_t> ) \
    IF_64BIT( DEF_ISEL(name ## _64) = func<uint64_t> )

// An instruction with a single 32- or 64-bit register destination operand.
#define DEF_ISEL_R32or64W(name, func) \
    IF_32BIT( DEF_ISEL(name ## _32) = func<R32W> ) \
    IF_64BIT( DEF_ISEL(name ## _64) = func<R64W> )

// An instruction with a single 32- or 64-bit memory destination operand.
#define DEF_ISEL_M32or64(name, func) \
    IF_32BIT( DEF_ISEL(name ## _32) = func<M32> ) \
    IF_64BIT( DEF_ISEL(name ## _64) = func<M64> )

// An instruction with a single 32- or 64-bit memory destination operand.
#define DEF_ISEL_M32or64W(name, func) \
    IF_32BIT( DEF_ISEL(name ## _32) = func<M32W> ) \
    IF_64BIT( DEF_ISEL(name ## _64) = func<M64W> )

// An instruction with a single, explicit source operand (register).
#define DEF_ISEL_Rn(name, tpl_func) \
    DEF_ISEL(name ## _8) = tpl_func<R8> ; \
    DEF_ISEL(name ## _16) = tpl_func<R16> ; \
    DEF_ISEL(name ## _32) = tpl_func<R32> \
    IF_64BIT( ; DEF_ISEL(name ## _64) = tpl_func<R64> )

// An instruction with a single, explicit destination operand (register).
#define DEF_ISEL_RnW(name, tpl_func) \
    DEF_ISEL(name ## _8) = tpl_func<R8W> ; \
    DEF_ISEL(name ## _16) = tpl_func<R16W> ; \
    DEF_ISEL(name ## _32) = tpl_func<R32W> \
    IF_64BIT( ; DEF_ISEL(name ## _64) = tpl_func<R64W> )

// An instruction with a single, explicit source operand (memory).
#define DEF_ISEL_Mn(name, tpl_func) \
    DEF_ISEL(name ## _8) = tpl_func<M8> ; \
    DEF_ISEL(name ## _16) = tpl_func<M16> ; \
    DEF_ISEL(name ## _32) = tpl_func<M32> \
    IF_64BIT( ; DEF_ISEL(name ## _64) = tpl_func<M64> )

// An instruction with a single, explicit destination operand (memory).
#define DEF_ISEL_MnW(name, tpl_func) \
    DEF_ISEL(name ## _8) = tpl_func<M8W> ; \
    DEF_ISEL(name ## _16) = tpl_func<M16W> ; \
    DEF_ISEL(name ## _32) = tpl_func<M32W> \
    IF_64BIT( ; DEF_ISEL(name ## _64) = tpl_func<M64W> )

// An instruction with no explicit destination operand and an immediate source.
#define DEF_ISEL_In(name, tpl_func) \
    DEF_ISEL(name ## _8) = tpl_func<I8> ; \
    DEF_ISEL(name ## _16) = tpl_func<I16> ; \
    DEF_ISEL(name ## _32) = tpl_func<I32> \
    IF_64BIT( ; DEF_ISEL(name ## _64) = tpl_func<I64> )

// Two source operand instruction
#define _DEF_ISEL_Xn_Yn(X, Y, name, tpl_func) \
  DEF_ISEL(name ## _8) = tpl_func<X ## 8, Y ## 8> ; \
  DEF_ISEL(name ## _16) = tpl_func<X ## 16, Y ## 16> ; \
  DEF_ISEL(name ## _32) = tpl_func<X ## 32, Y ## 32> \
  IF_64BIT( ; DEF_ISEL(name ## _64) = tpl_func<X ## 64, Y ## 64> )


#define DEF_ISEL_Rn_Mn(name, tpl_func) \
    _DEF_ISEL_Xn_Yn(R, M, name, tpl_func)

#define DEF_ISEL_Rn_Rn(name, tpl_func) \
    _DEF_ISEL_Xn_Yn(R, R, name, tpl_func)

#define DEF_ISEL_Rn_In(name, tpl_func) \
    _DEF_ISEL_Xn_Yn(R, I, name, tpl_func)

#define DEF_ISEL_Mn_In(name, tpl_func) \
    _DEF_ISEL_Xn_Yn(M, I, name, tpl_func)

#define DEF_ISEL_Mn_Rn(name, tpl_func) \
    _DEF_ISEL_Xn_Yn(M, R, name, tpl_func)

// One destination, one source operand instruction.
#define _DEF_ISEL_XnW_Yn(X, Y, name, tpl_func) \
  DEF_ISEL(name ## _8) = tpl_func<X ## 8W, Y ## 8> ; \
  DEF_ISEL(name ## _16) = tpl_func<X ## 16W, Y ## 16> ; \
  DEF_ISEL(name ## _32) = tpl_func<X ## 32W, Y ## 32> \
  IF_64BIT( ; DEF_ISEL(name ## _64) = tpl_func<X ## 64W, Y ## 64> )

#define DEF_ISEL_RnW_Mn(name, tpl_func) \
    _DEF_ISEL_XnW_Yn(R, M, name, tpl_func)

#define DEF_ISEL_RnW_Rn(name, tpl_func) \
    _DEF_ISEL_XnW_Yn(R, R, name, tpl_func)

#define DEF_ISEL_RnW_In(name, tpl_func) \
    _DEF_ISEL_XnW_Yn(R, I, name, tpl_func)

#define DEF_ISEL_MnW_In(name, tpl_func) \
    _DEF_ISEL_XnW_Yn(M, I, name, tpl_func)

#define DEF_ISEL_MnW_Rn(name, tpl_func) \
    _DEF_ISEL_XnW_Yn(M, R, name, tpl_func)

#define DEF_ISEL_MnW_Mn(name, tpl_func) \
    _DEF_ISEL_XnW_Yn(M, M, name, tpl_func)

// One destination, two source operand instruction
#define _DEF_ISEL_XnW_Yn_Zn(X, Y, Z, name, tpl_func) \
  DEF_ISEL(name ## _8) = tpl_func<X ## 8W, Y ## 8, Z ## 8> ; \
  DEF_ISEL(name ## _16) = tpl_func<X ## 16W, Y ## 16, Z ## 16> ; \
  DEF_ISEL(name ## _32) = tpl_func<X ## 32W, Y ## 32, Z ## 32> \
  IF_64BIT( ; DEF_ISEL(name ## _64) = tpl_func<X ## 64W, Y ## 64, Z ## 64> )

#define DEF_ISEL_RnW_Rn_Mn(name, tpl_func) \
    _DEF_ISEL_XnW_Yn_Zn(R, R, M, name, tpl_func)

// Three operand: REG_a <- REG_a OP REG_b.
#define DEF_ISEL_RnW_Rn_Rn(name, tpl_func) \
    _DEF_ISEL_XnW_Yn_Zn(R, R, R, name, tpl_func)

// Three operand: REG_a <- REG_a OP IMM.
#define DEF_ISEL_RnW_Rn_In(name, tpl_func) \
    _DEF_ISEL_XnW_Yn_Zn(R, R, I, name, tpl_func)

#define DEF_ISEL_RnW_Mn_In(name, tpl_func) \
    _DEF_ISEL_XnW_Yn_Zn(R, M, I, name, tpl_func)

#define DEF_ISEL_MnW_Mn_Rn(name, tpl_func) \
    _DEF_ISEL_XnW_Yn_Zn(M, M, R, name, tpl_func)

#define DEF_ISEL_MnW_Mn_In(name, tpl_func) \
    _DEF_ISEL_XnW_Yn_Zn(M, M, I, name, tpl_func)

#endif  // MCSEMA_ARCH_SEMANTICS_MACROS_INC_
