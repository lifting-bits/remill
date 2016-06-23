# Remill [![Build Status](https://travis-ci.com/trailofbits/remill.svg?token=T1UToSpCvaMxn511Cddb&branch=master)](https://travis-ci.com/trailofbits/remill)

Remill is a static binary translator that translates machine code into
[LLVM bitcode](http://llvm.org/docs/LangRef.html). It translates
x86 and amd64 machine code (including AVX and
AVX512) into LLVM bitcode.

## Purpose

Remill translates machine code, and *only* machine code, into LLVM bitcode.
Remill's translation approach is inspired by
[dynamic](https://software.intel.com/en-us/articles/pin-a-dynamic-binary-instrumentation-tool)
[binary](https://github.com/DynamoRIO/dynamorio)
[translators](https://github.com/Granary/granary2). Remill translates one
[basic block](https://en.wikipedia.org/wiki/Basic_block) of machine code into
LLVM bitcode at a time. The translation process defers to downstream consumers
many decisions on how the translated bitcode should be interpreted.

## Goals

Remill was designed with the following goals in mind.

- It should be easy to add new instruction implementations. Instruction
  semantics are implemented using C++. Instruction implementations should be
  thoroughly tested.

- Remill-produced bitcode should achieve the sometimes conflicting goals of
  maintaining the semantics of the translated machine code, and enabling
  aggressive optimization of the produced bitcode.

- Decisions affecting the use of the produced bitcode should be deferred via
  intrinsics. Remill-produced bitcode should not commit a consumer of that
  bitcode to one use case.

## Design

### Intrinsics

Remill defers the "implementation" of memory accesses and certain types of
control flows to the consumers of the produced bitcode. Deferral in this takes
the form of Remill [intrinsics](remill/Arch/Runtime/Intrinsics.h).

For example, the `__remill_read_memory_8` intrinsic function represents the
action of reading 8 bits of memory. Via this and similar intrinsics, downstream
tools can distinguish between LLVM `load` and `store` instructions from accesses
to the modelled program's memory. Downstream tools can, of course, implement
memory intrinsics using LLVM's own memory access instructions. 

### Instruction Semantics

Instruction semantics are implemented using C++, and tested against their
native counterparts. Often, the high-level semantics of an instruction are
implemented using a C++ function template. This template is then instantiated
for each possible encoding of the modelled instruction.

### Machine State

The register state of a machine is represented by a single `State` structure.
For example, the x86/amd64 state structure is defined in
[State.h](remill/Arch/X86/Runtime/State.h). State structures are carefully
designed to maintain the following properties.

 - They should actively prevent certain compiler optimizations that obscure the
   semantics of the translated machine code. For example, special
   [tear fields](https://github.com/trailofbits/remill/blob/master/remill/Arch/X86/Runtime/State.h#L211)
   are introduced so as to prevent load and store coalescing, and preserve the
   semantics that writes to logical units of data remain as such.
 - They should have a uniform size across all architecture revisions and
   generations. This permits things such as:
    - Mixing separately translated bitcode from two binaries, one with and one without AVX support.
    - Mixing 32-bit ad 64-bit translated bitcode, or cross-compiling 32-bit and
      64-bit bitcode.
 - They should accurately describe all register state maintained by the
    emulated machine.
 - It should be easy to convert to/from Remill's state structures and actual
    machine-derived state.

### Memory Model and the Remill Runtime

Remill-produced bitcode has a memory model that includes memory barriers and atomic region.
It also explicitly distinguishes loads/stores to the modelled program's memory from
loads and stores to "runtime memory."

Remill-produced bitcode can be thought of as an emulator for a program.
Through this lens, the memory used to store a `State` structure or any local
variables (`alloca`s in LLVM) needed to support the emulation must be treated
as distinct from the modelled program's memory itself. This separation enables
Remill to maintain [transparency](http://www.burningcutlery.com/derek/docs/transparency-VEE12.pdf)
with respect to memory accesses.

# Setup

## Linux-specific
```sh
sudo apt-get install libunwind8 libunwind8-dev
sudo pip install futures
```

## Generic
```sh
./scripts/bootstrap.sh
```

### Example

First, extract the control-flow graph information from your binary.

```sh
BIN=/path/to/binary
CFG=$(./scripts/ida_get_cfg.sh $BIN)
```

This script will tell you where it puts the CFG. For example, it might output something like `/tmp/tmp.E3RWcczulG.cfg`.

Lets assume that `/path/to/binary` is a 32-bit ELF file. Now you can do the following:

```sh
/path/to/remill/build/cfg_to_bc \
    --arch_in=x86 --arch_out=x86 --os_in=linux --os_out=linux \
    --bc_in=/path/to/remill/generated/sem_x86.bc --bc_out=$BIN.bc --cfg=$CFG
```

For 64-bit x86 programs, specificy `--arch_in=amd64`. If you intend to run a 32-bit binary as a 64-bit program then specify `--arch_in=x86 --arch_out=amd64`. Similar switching can be done for the OS. The `--bc_in` flag also needs to be changes to point at the AMD64 semantics bitcode file. For example, `sem_amd64.bc`. If your lifted code uses AVX, then you can use `sem_amd64_avx.bc`.

**Note:** This arch/OS switching only affects the ABI used by the bitcode, and how instructions are decoded. The translator itself has no other concept of arch/OS types. It is up to the next tool in the pipeline to implement the desired behavior.

**Note:** Always use absolute paths when specifying files to Remill. I have no patience for handling paths in a 100% correct, generic way in C++. To that end, users of the tool should make it as easy as possible for Remill to do the right thing.

#### Optimizing the bitcode

There are a few ways to optimize the produced bitcode. The first is to tell remill to perform a data flow analysis and to try to kill things like dead registers.

The data flow analyzer is enabled by specifying a maximum number of data flow analysis iterations to perform. By default, the maximum number is `0` (disabled). For a comprehensive analysis, specify a large number, e.g.:

```sh
/path/to/remill/build/cfg_to_bc ... --max_dataflow_analysis_iterations=99999 ...
```

In order to maintain correctness, the data-flow analysis is conservative. However, if all code is avaiable for analysis within the CFG file, then a more agressive analysis can be performed. This analysis will try to propagate data flow information across function returns, for instance. It is enabled with the `--aggressive_dataflow_analysis` flag.

Once bitcode has been produced, it can be optimized using the remill-specific LLVM optimization plugin. The following will produce optimized bitcode in a file named by `$OPT`.

```sh
OPT=$(./scripts/optimize_bitcode.sh $BIN.bc)
```

### Miscellaneous

To recompile the code, run `./scripts/build.py`. Ideally, you should install the `concurrent.futures` package to make the build faster, though it is not required.

To recompile the semantics (if you add an instruction) then run `./scripts/compile_semantics.sh`. If you want to test your new semantics, then also recompile the code using the above command.

If you make any changes to the register machine `State` structure, then before recompiling, run the script `./scripts/print_x86_save_state_asm.sh`. This produces an assembly source code file used by the unit tests for marshaling the machine state to/from the `State` structure.

## Third-Party Dependencies

### Intel XED

Remill depends on and redistributes [Intel XED](https://software.intel.com/en-us/articles/xed-x86-encoder-decoder-software-library), the highest-quality x86 instruction
encoder and decoder. XED is licensed under the What If pre-release license. A copy of this license can be found [here](blob/xed/LICENSE.md).

### LLVM

Remill depends on the [LLVM Compiler Infrastructure](http://llvm.org). A copy of this license can be found [here](http://llvm.org/releases/3.8.0/LICENSE.TXT).

### IDA Pro

Remill depends on [IDA Pro](https://www.hex-rays.com/products/ida) to
accurately disassemble program binaries.

### Binary Ninja

An alternative to IDA Pro is [Binary Ninja](https://binary.ninja). Remill can use Binary Ninja to accurately disassemble program binaries.
