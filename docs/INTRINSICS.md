# Remill Intrinsics

Remill models the semantics of instruction logic and its effects on processor and memory state, but it does not model memory _access_ behaviors or certain types of control flow. Remill defers the "implementation" of those to the consumers of the produced bitcode. Deferral is performed using Remill _intrinsics_, declared in [`Intrinsics.h`](/include/remill/Arch/Runtime/Intrinsics.h) and defined in [`Intrinsics.cpp`](/lib/Arch/Runtime/Intrinsics.cpp).

In Remill's implementation of an instruction, memory operands are represented by their addresses, but accessed only via intrinsics. For example, the `__remill_read_memory_8` intrinsic function represents the action of reading 8 bits of memory. Via this and similar intrinsics, downstream tools can distinguish LLVM `load` and `store` instructions from accesses to the modeled program's memory. Downstream tools can, of course, implement memory intrinsics using LLVM's own memory access instructions.

The typical developer working on extending Remill does not need to work with Remill's memory access intrinsics directly, because they are actually wrapped by Remill's _operators_. Refer to the [Operators documentation](OPERATORS.md) for more information on those.

For an example of how Remill's control flow intrinsics are used, see how the [Remill instruction test-runner](/tests/X86/Run.cpp) uses `__remill_sync_hyper_call` to virtualize the behavior of instructions like `cpuid` (get CPU capabilities) or `readtsc` (read time stamp counter).
