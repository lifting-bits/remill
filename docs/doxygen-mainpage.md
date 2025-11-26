# Remill API Documentation {#mainpage}

![Remill Logo](remill_logo.png)

## Overview

Remill is a static binary translator that translates machine code instructions into [LLVM bitcode](http://llvm.org/docs/LangRef.html). 

### Supported Architectures

Remill supports the following architectures:
- **x86 and AMD64** (including AVX and AVX512)
- **AArch64** (64-bit ARMv8)
- **AArch32** (32-bit ARMv8 / ARMv7)
- **SPARC32** (SPARCv8)
- **SPARC64** (SPARCv9)
- **PowerPC** (PPC)

## Key Components

### Architecture Support (remill::Arch)

The @ref remill::Arch class is the main entry point for architecture-specific functionality. It provides:
- Instruction decoding
- Register definitions
- Architecture-specific semantics
- LLVM module initialization

See @ref remill/Arch/Arch.h for the main architecture interface.

### Instruction Lifting

Remill provides several classes for lifting machine code to LLVM bitcode:

- @ref remill::InstructionLifter - Lifts individual instructions
- @ref remill::TraceLifter - Lifts sequences of instructions (traces)
- @ref remill::OperandLifter - Base class for lifting operands

See @ref remill/BC/InstructionLifter.h and @ref remill/BC/TraceLifter.h for details.

### Intrinsics

Remill uses intrinsics to defer implementation of memory accesses and certain control flow operations to consumers of the bitcode. This allows downstream tools to customize behavior.

See @ref remill/Arch/Runtime/Intrinsics.h for available intrinsics.

## Getting Started

### Basic Usage Example

```cpp
#include <remill/Arch/Arch.h>
#include <remill/BC/InstructionLifter.h>
#include <llvm/IR/LLVMContext.h>

// Create LLVM context
llvm::LLVMContext context;

// Get architecture instance
auto arch = remill::Arch::Get(context, "linux", "amd64");

// Decode an instruction
remill::Instruction inst;
auto bytes = /* your instruction bytes */;
arch->DecodeInstruction(address, bytes, inst);

// Lift the instruction
remill::InstructionLifter lifter(arch.get(), intrinsics);
lifter.LiftIntoBlock(inst, basic_block, state_ptr);
```

## Documentation Sections

### Architecture Documentation
- @ref remill::Arch - Main architecture interface
- @ref remill::Instruction - Decoded instruction representation
- @ref remill::Register - Register definitions
- @ref remill::DecodingContext - Context for instruction decoding

### Bitcode Generation
- @ref remill::InstructionLifter - Single instruction lifting
- @ref remill::TraceLifter - Trace lifting
- @ref remill::IntrinsicTable - Intrinsic function management
- @ref remill::OperandLifter - Operand lifting interface

### Utilities
- @ref remill::BC - Bitcode utilities
- @ref remill::OS - Operating system abstractions

## Additional Resources

For more detailed information, see:
- [Design and Architecture](DESIGN.md)
- [Life of an Instruction](LIFE_OF_AN_INSTRUCTION.md)
- [How to Add an Instruction](ADD_AN_INSTRUCTION.md)
- [Intrinsics Documentation](INTRINSICS.md)
- [Contributing Guide](CONTRIBUTING.md)

## License

Remill is licensed under the Apache License 2.0. See the LICENSE file for details.

## Support

For questions and support:
- GitHub Issues: https://github.com/lifting-bits/remill/issues
- Slack: #binary-lifting channel on [Empire Hacking Slack](https://slack.empirehacking.nyc/)

## Project Information

- **Project Homepage**: https://github.com/lifting-bits/remill
- **Developed by**: Trail of Bits
- **Related Projects**: [McSema](https://github.com/lifting-bits/mcsema)

