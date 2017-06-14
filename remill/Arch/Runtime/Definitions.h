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

#ifndef REMILL_ARCH_RUNTIME_DEFINITIONS_H_
#define REMILL_ARCH_RUNTIME_DEFINITIONS_H_

#ifndef ADDRESS_SIZE_BITS
# define ADDRESS_SIZE_BITS 64UL
#endif

#ifndef ADDRESS_SIZE_BYTES
# define ADDRESS_SIZE_BYTES static_cast<addr_t>(ADDRESS_SIZE_BITS / 8)
#endif

#if 64 == ADDRESS_SIZE_BITS
# define IF_32BIT(...)
# define IF_64BIT(...) __VA_ARGS__
# define _IF_32BIT(...)
# define _IF_64BIT(...) , __VA_ARGS__
# define IF_64BIT_ELSE(a, b) a
#else
# define IF_32BIT(...) __VA_ARGS__
# define IF_64BIT(...)
# define _IF_32BIT(...) , __VA_ARGS__
# define _IF_64BIT(...)
# define IF_64BIT_ELSE(a, b) b
#endif

// Attributes that will force inlining of specific code.
#define ALWAYS_INLINE \
  [[gnu::always_inline, gnu::gnu_inline]] \
  inline

#define NEVER_INLINE [[gnu::noinline]]

// Define a specific instruction selection variable.
#define DEF_ISEL(name) \
  extern "C" constexpr auto ISEL_ ## name [[gnu::used]]

// Define a conditional execution function.
#define DEF_COND(name) \
  extern "C" constexpr auto COND_ ## name [[gnu::used]]

// Define a semantics implementing function.
#define DEF_SEM(name, ...) \
    ALWAYS_INLINE __attribute__((flatten)) static Memory *name ( \
        Memory *memory, State &state, ##__VA_ARGS__)

// Define a semantics implementing function.
#define DEF_HELPER(name, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static auto name ( \
      Memory *&memory, State &state, ##__VA_ARGS__)

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
    IF_32BIT( DEF_ISEL(name ## _32) = func<I32> ) \
    IF_64BIT( DEF_ISEL(name ## _64) = func<I64> )

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

#define _DEF_ISEL_XnW_Xn_Yn_Zn(X, Y, Z, name, tpl_func) \
  DEF_ISEL(name ## _8) = tpl_func<X ## 8W, X ## 8, Y ## 8, Z ## 8> ; \
  DEF_ISEL(name ## _16) = tpl_func<X ## 16W, X ## 16, Y ## 16, Z ## 16> ; \
  DEF_ISEL(name ## _32) = tpl_func<X ## 32W, X ## 32, Y ## 32, Z ## 32> \
  IF_64BIT( ; DEF_ISEL(name ## _64) = tpl_func<X ## 64W, X ## 64, Y ## 64, Z ## 64> )

#define DEF_ISEL_RnW_Rn_Mn(name, tpl_func) \
    _DEF_ISEL_XnW_Yn_Zn(R, R, M, name, tpl_func)

// Three operand: REG_a <- REG_a OP REG_b.
#define DEF_ISEL_RnW_Rn_Rn(name, tpl_func) \
    _DEF_ISEL_XnW_Yn_Zn(R, R, R, name, tpl_func)

// Three operand: REG_a <- REG_a OP IMM.
#define DEF_ISEL_RnW_Rn_In(name, tpl_func) \
    _DEF_ISEL_XnW_Yn_Zn(R, R, I, name, tpl_func)

#define _DEF_ISEL_XnW_Xn_YnW_Yn(X, Y, name, tpl_func) \
  DEF_ISEL(name ## _8) = tpl_func<X ## 8W, X ## 8, Y ## 8W, Y ## 8> ; \
  DEF_ISEL(name ## _16) = tpl_func<X ## 16W, X ## 16, Y ## 16W, Y ## 16> ; \
  DEF_ISEL(name ## _32) = tpl_func<X ## 32W, X ## 32, Y ## 32W, Y ## 32> \
  IF_64BIT( ; DEF_ISEL(name ## _64) = tpl_func<X ## 64W, X ## 64, Y ## 64W, Y ## 64> )

#define DEF_ISEL_MnW_Mn_RnW_Rn(name, tpl_func) \
  _DEF_ISEL_XnW_Xn_YnW_Yn(M, R, name, tpl_func)

#define DEF_ISEL_RnW_Rn_RnW_Rn(name, tpl_func) \
  _DEF_ISEL_XnW_Xn_YnW_Yn(R, R, name, tpl_func)

#define DEF_ISEL_RnW_Mn_In(name, tpl_func) \
    _DEF_ISEL_XnW_Yn_Zn(R, M, I, name, tpl_func)

#define DEF_ISEL_MnW_Mn_Rn(name, tpl_func) \
    _DEF_ISEL_XnW_Yn_Zn(M, M, R, name, tpl_func)

#define DEF_ISEL_MnW_Mn_In(name, tpl_func) \
    _DEF_ISEL_XnW_Yn_Zn(M, M, I, name, tpl_func)

#define DEF_ISEL_MnW_Mn_Rn_In(name, tpl_func) \
  _DEF_ISEL_XnW_Xn_Yn_Zn(M, R, I, name, tpl_func)

#define DEF_ISEL_RnW_Rn_Rn_In(name, tpl_func) \
  _DEF_ISEL_XnW_Xn_Yn_Zn(R, R, I, name, tpl_func)

#define DEF_ISEL_MnW_Mn_Rn_Rn(name, tpl_func) \
  _DEF_ISEL_XnW_Xn_Yn_Zn(M, R, R, name, tpl_func)

#define DEF_ISEL_RnW_Rn_Rn_Rn(name, tpl_func) \
  _DEF_ISEL_XnW_Xn_Yn_Zn(R, R, R, name, tpl_func)

#endif  // REMILL_ARCH_RUNTIME_DEFINITIONS_H_
