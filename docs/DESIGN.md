# Design and architecture of Remill

Remill translates machine code, and *only* machine code, into LLVM bitcode. The translation process defers many decisions to downstream consumers on how the translated bitcode should be interpreted.

## Intrinsics

Remill defers the "implementation" of memory accesses and certain types of control flows to the consumers of the produced bitcode. Deferral in this takes the form of Remill [intrinsics](/include/remill/Arch/Runtime/Intrinsics.h).

For example, the `__remill_read_memory_8` intrinsic function represents the action of reading 8 bits of memory. Via this and similar intrinsics, downstream tools can distinguish LLVM `load` and `store` instructions from accesses to the modeled program's memory. Downstream tools can, of course, implement memory intrinsics using LLVM's own memory access instructions.

## Instruction semantics

Instruction semantics are implemented using C++, and tested against their native counterparts. Often, the high-level semantics of an instruction are implemented using a C++ function template. This template is then instantiated for each possible encoding of the modeled instruction.

## Machine state

The register state of a machine is represented by a single `State` structure. For example, the x86/amd64 state structure is defined in [State.h](/include/remill/Arch/X86/Runtime/State.h). State structures are carefully designed to maintain the following properties:

- They should actively prevent certain compiler optimizations that obscure the semantics of the translated machine code. For example, special [tear fields](https://github.com/lifting-bits/remill/blob/a6abbb818c3c523dfb806cf4e8a0211f3a8d56e4/include/remill/Arch/X86/Runtime/State.h#L698) are introduced so as to prevent load and store coalescing, and to preserve the semantics that write to logical units of data to remain as such.
- They should have a uniform size across all architecture revisions and generations. This permits things such as:
     - Mixing separately translated bitcode from two x86 binaries, one with and
         one without AVX support.
     - Mixing 32-bit ad 64-bit translated bitcode, or cross-compiling 32-bit and
         64-bit bitcode.
- They should accurately describe all register state maintained by the emulated machine.
- It should be easy to convert to/from Remill's state structures and actual machine-derived state.

## Memory model

Remill-produced bitcode has a memory model that includes memory barriers and atomic regions. It also explicitly distinguishes loads/stores to the modeled program's memory from loads and stores to "runtime memory."

## Runtime

Remill-produced bitcode can be thought of as an emulator for a program. Through this lens, the memory used to store a `State` structure or any local variables (`alloca`s in LLVM) needed to support the emulation must be treated as distinct from the modeled program's memory itself. This separation enables Remill to maintain [transparency](http://www.burningcutlery.com/derek/docs/transparency-VEE12.pdf) with respect to memory accesses.
