# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What is Remill?

Remill is a static binary translator that lifts machine code instructions into LLVM bitcode. It supports x86/amd64 (including AVX/AVX512), AArch64, AArch32, SPARC32/64, and PPC architectures. Remill is designed as a library for binary analysis tools like McSema.

## Build Commands

### Build Dependencies (First Time)
```bash
# Build dependencies including LLVM from source
cmake -G Ninja -S dependencies -B dependencies/build
cmake --build dependencies/build

# Or with external LLVM (macOS with Homebrew)
brew install llvm@17
cmake -G Ninja -S dependencies -B dependencies/build -DUSE_EXTERNAL_LLVM=ON \
  "-DCMAKE_PREFIX_PATH:PATH=$(brew --prefix llvm@17)"
cmake --build dependencies/build
```

### Build Remill
```bash
cmake -G Ninja -B build "-DCMAKE_PREFIX_PATH:PATH=$(pwd)/dependencies/install" \
  -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

### Run Tests
```bash
# Build test dependencies
cmake --build build --target test_dependencies

# Run all tests
cd build && ctest

# Run architecture-specific tests
ctest -R amd64
ctest -R aarch64
```

## Architecture

### Core Concepts

**Intrinsics System**: Remill defers memory/control-flow semantics to downstream consumers via intrinsics (`__remill_read_memory_*`, `__remill_write_memory_*`, etc.). This allows tools to implement their own memory models.

**SEM (Semantics)**: Generic C++ template functions implementing instruction behavior. Named after the instruction mnemonic (e.g., `AND`, `ADD`).

**ISEL (Instruction Selection)**: Specific instantiations of semantics for particular encodings. Named with operand types (e.g., `AND_GPRv_MEMv_32`).

**State Structure**: Per-architecture register/flag state (`State.h`). Uniform size across generations enables mixing translated bitcode.

**Basic Block Lifting**: Core function `__remill_basic_block(State&, addr_t, Memory*)` - variables correspond to register names, decoder and lifter synchronize via this naming convention.

### Key Directories
- `lib/Arch/X86/Semantics/` - x86/amd64 instruction semantics by category (BINARY.cpp, LOGICAL.cpp, AVX.cpp, SSE.cpp, etc.)
- `lib/BC/InstructionLifter.cpp` - Converts decoded instructions to LLVM IR
- `include/remill/Arch/Runtime/` - State structures, intrinsics, operators, types
- `tests/X86/`, `tests/AArch64/` - Architecture-specific test suites

## Writing Instruction Semantics

### Semantic Function Pattern
```cpp
template <typename D, typename S1, typename S2>
DEF_SEM(INSTR_NAME, D dst, S1 src1, S2 src2) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto res = UAdd(lhs, rhs);  // or UAnd, UMul, etc.
  WriteZExt(dst, res);
  // Update flags last
  return memory;
}
```

### Operator Naming Convention
- **Signed**: `SAdd`, `SSub`, `SMul`, `SDiv`
- **Unsigned**: `UAdd`, `USub`, `UMul`, `UDiv`, `UAnd`, `UOr`, `UXor`
- **Floating-point**: `FAdd`, `FSub`, `FMul`, `FDiv`
- **Vector ops**: `UAddV32`, `FMulV64`, `UReadV32`, `FWriteV64`

### ISEL Definition
```cpp
// For SCALABLE instructions, suffix with operand size
DEF_ISEL(AND_GPRv_MEMv_8) = AND<R8W, R8, M8>;
DEF_ISEL(AND_GPRv_MEMv_16) = AND<R16W, R16, M16>;
DEF_ISEL(AND_GPRv_MEMv_32) = AND<R32W, R32, M32>;
IF_64BIT(DEF_ISEL(AND_GPRv_MEMv_64) = AND<R64W, R64, M64>;)

// Or use shorthand macro
DEF_ISEL_RnW_Rn_Mn(AND_GPRv_MEMv, AND);
```

### Operand Types
- `R8`, `R16`, `R32`, `R64` - Register reads
- `R8W`, `R16W`, `R32W`, `R64W` - Register writes
- `M8`, `M16`, `M32`, `M64` - Memory operands
- `V128W` - SIMD destination (always 128-bit for writes)

### Order of Operations in Semantics
1. `Read()` all source operands first
2. Perform computations
3. `Write()`/`WriteZExt()` to destinations
4. Update suppressed operands (flags) last

This ordering limits state mutations if memory access violations occur.

## Writing Tests

Test files go in `tests/{ARCH}/{CATEGORY}/` and must be included in `Tests.S`.

```asm
TEST_BEGIN(ANDr32r32, 2)
TEST_IGNORE_FLAGS(AF)
TEST_INPUTS(
    0, 0,
    1, 0,
    0xFFFFFFFF, 1,
    0x7FFFFFFF, 1)

    and ARG1_32, ARG2_32
TEST_END
```

- `TEST_BEGIN(name, num_args)` - Start test with N input arguments
- `TEST_IGNORE_FLAGS(...)` - Flags left in undefined state
- `TEST_INPUTS(...)` - Comma-separated input values (grouped by num_args)
- `ARG1_32`, `ARG2_64`, etc. - Input argument registers by size

## Code Style

- **Format**: Google style via `.clang-format` (80-char line limit, 2-space indent)
- **Standard**: C++17
- Run `clang-format -i <file>` before committing

## XED Tables Reference

For x86 instruction details, consult `docs/XED/xed.txt`. Key fields:
- Instruction category (LOGICAL, BINARY, etc.) → determines which `.cpp` file
- `SCALABLE` attribute → needs size-suffixed ISELs
- `EXPLICIT`/`IMPLICIT`/`SUPPRESSED` → determines semantic function parameters
- `R`/`W`/`RW` → operand mutability (RW generates two parameters: write first, read second)
