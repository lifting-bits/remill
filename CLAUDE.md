# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Remill is a static binary translator library that converts machine code instructions into LLVM bitcode. It lifts low-level machine instructions to architecture-neutral LLVM IR for analysis, transformation, and execution.

**Supported Architectures**: x86/x86-64 (with AVX/AVX512), AArch64, AArch32 (in progress), SPARC32/64, PowerPC

## Build Commands

```bash
# Build dependencies (LLVM, XED, gflags, glog, googletest)
cmake -G Ninja -S dependencies -B dependencies/build
cmake --build dependencies/build

# Build remill
cmake -G Ninja -B build -DCMAKE_PREFIX_PATH=$(pwd)/dependencies/install
cmake --build build

# Run tests
cmake --build build --target test_dependencies
CTEST_OUTPUT_ON_FAILURE=1 cmake --build build --target test

# Run specific test category (e.g., X86 MOV instructions)
./build/tests/X86/Run --gtest_filter="*MOV*"

# Build and run remill-lift tool
./build/bin/remill-lift --arch x86_64 --os linux --bytes "90 c3" --address 0x1000
```

## Architecture & Key Components

### Core Library Structure

**Instruction Lifting Pipeline**:
1. **Decode** (`lib/Arch/*/Decode.cpp`): Machine bytes → Instruction data structure
2. **Lift** (`lib/BC/InstructionLifter.cpp`): Instruction → LLVM function using semantic functions
3. **Optimize** (`lib/BC/Optimizer.cpp`): Apply LLVM optimizations
4. **Output**: LLVM IR/bitcode

**Key Classes**:
- `TraceLifter` (`lib/BC/TraceLifter.cpp`): Recursively decodes and lifts instruction traces
- `SleighLifter` (`lib/BC/SleighLifter.cpp`): Ghidra Sleigh-based lifting for newer architectures
- `InstructionLifter` (`lib/BC/InstructionLifter.cpp`): Base class for lifting individual instructions
- `Instruction` (`include/remill/Arch/Instruction.h`): Decoded instruction representation

### Semantics Implementation

**Location**: `lib/Arch/{ARCH}/Semantics/`
- X86 has 33 semantic files (MOV, BINARY, LOGICAL, SSE, AVX, X87, etc.)
- Each file contains C++ template functions implementing instruction behavior
- Templates instantiated via ISEL (instruction selection) mechanism

**State Structure**: `include/remill/Arch/{ARCH}/Runtime/State.h`
- Represents complete machine state (all registers)
- Passed between lifted basic blocks
- Carefully designed to prevent unwanted compiler optimizations

**Intrinsics**: `include/remill/Arch/Runtime/Intrinsics.h`
- Memory operations: `__remill_read_memory_*`, `__remill_write_memory_*`
- Control flow: `__remill_function_call`, `__remill_function_return`
- Deferred operations for downstream tools to handle

## Development Workflow

### Adding New Instructions

1. Identify instruction category and semantic file location
2. Add semantic function template in appropriate file (e.g., `lib/Arch/X86/Semantics/MOV.cpp`)
3. Register ISEL entries mapping opcodes to semantic functions
4. Add test cases in `tests/{ARCH}/` following existing patterns
5. See `docs/ADD_AN_INSTRUCTION.md` for detailed walkthrough

### Testing Changes

```bash
# Build test dependencies first
cmake --build build --target test_dependencies

# Run all tests
CTEST_OUTPUT_ON_FAILURE=1 cmake --build build --target test

# Run specific architecture tests
ctest --test-dir build -R "X86|AArch64|SPARC"

# Run differential tester for X86
./build/bin/differential_tester_x86
```

### Code Formatting

```bash
# Format C++ files
./scripts/format-files
```

## Important Files & Locations

- **Semantics**: `lib/Arch/{ARCH}/Semantics/` - Instruction implementations
- **Tests**: `tests/{ARCH}/` - Architecture-specific test suites
- **Lifting Logic**: `lib/BC/` - Core lifting infrastructure
- **Public API**: `include/remill/` - Headers for library users
- **Documentation**: `docs/` - Design docs and guides

## LLVM Versions

Supported: LLVM 15, 16, 17, 18, 19, 20, 21
CI tests all versions on Ubuntu 22.04 and macOS.

## Common Development Tasks

```bash
# Debug lifting issues
./build/bin/remill-lift --arch x86_64 --os linux --bytes "48 89 e5" --address 0x1000 --bc_out /tmp/out.bc

# Inspect lifted bitcode
llvm-dis-15 /tmp/out.bc -o -

# Run specific test with verbose output
./build/tests/X86/Run --gtest_filter="*MOVAPD*" --v=1

# Check for memory leaks (Linux)
valgrind --leak-check=full ./build/tests/X86/Run --gtest_filter="*specific_test*"
```

## Architecture-Specific Notes

**X86**: Most mature implementation with comprehensive AVX/AVX512 support
**AArch64**: Full 64-bit ARMv8 support
**SPARC**: Both 32-bit and 64-bit versions supported
**PowerPC**: Uses Sleigh-based lifting, still in development
**AArch32/Thumb**: Work in progress

## Contribution Guidelines

1. Create GitHub issue describing your contribution
2. Create feature branch: `issue_N_feature_description`
3. Make incremental PRs when milestones complete
4. Ensure all tests pass before submitting PR
5. Follow existing code patterns in semantic files