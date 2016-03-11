## mcsema2
[![Build Status](https://travis-ci.com/trailofbits/mcsema2.svg?token=T1UToSpCvaMxn511Cddb)](https://travis-ci.com/trailofbits/mcsema2)

### Setup

## Linux-specific
```
sudo apt-get install libunwind8 libunwind8-dev
sudo pip install futures
```

## Generic
```
./scripts/bootstrap.sh
```

### Example

First, extract the control-flow graph information from your binary.

```
BIN=/path/to/binary
CFG=$(./scripts/ida_get_cfg.sh $BIN)
```

This script will tell you where it puts the CFG. For example, it might output something
like `/tmp/tmp.E3RWcczulG.cfg`.

Lets assume that `/path/to/binary` is a 32-bit ELF file. Now you can do the following:

```
./build/cfg_to_bc --arch_in=x86 --arch_out=x86 --os_in=linux --os_out=linux --bc_in=./generated/sem_x86.bc --bc_out=$BIN.bc --cfg=$CFG
```

For 64-bit x86 programs, specificy `--arch_in=amd64`. If you intend to run a 32-bit
binary as a 64-bit program then specify `--arch_in=x86 --arch_out=amd64`.
Similar switching can be done for the OS. The `--bc_in` flag also needs to
be changes to point at the AMD64 semantics bitcode file. For example, `sem_amd64.bc`.
If your lifted code uses AVX, then you can use `sem_amd64_avx.bc`.

*Note:* This arch/OS switching only affects the ABI used by the bitcode, and how
instructions are decoded. The translator itself has no other concept of arch/OS
types. It is up to the next tool in the pipeline to implement the desired behavior.

#### Optimizing the bitcode

There are a few ways to optimize the produced bitcode. The first is to tell
mcsema2 to perform a data flow analysis and to try to kill things like dead
registers.

The data flow analyzer is enabled by specifying a maximum number of data flow
analysis iterations to perform. By default, the maximum number is `0` (disabled).
For a comprehensive analysis, specify a large number, e.g.:

```
./build/cfg_to_bc ... --max_dataflow_analysis_iterations=99999 ...
```

In order to maintain correctness, the data-flow analysis is conservative.
However, if all code is avaiable for analysis within the CFG file, then a more
agressive analysis can be performed. This analysis will try to propagate
data flow information across function returns, for instance. It is enabled
with the `--aggressive_dataflow_analysis` flag.

Once bitcode has been produced, it can be optimized using the mcsema2-specific
LLVM optimization plugin. The following will produce optimized bitcode in a
file named by `$OPT`.

```
OPT=$(./scripts/optimize_bitcode.sh $BIN.bc)
```

### Miscellaneous

To recompile the code, run `./scripts/build.py`. Ideally, you should install
the `concurrent.futures` package to make the build faster, though it is not
required.

To recompile the semantics, e.g. if you add an instruction, then run `./scripts/compile_semantics.sh`.
If you want to test your new semantics, then also recompile the code using the
above command.

If you make any changes to the register machine `State` structure, then
before recompiling, run the script `./scripts/print_x86_save_state_asm.sh`.
This produces an assembly source code file uses by the unit tests for marshaling
the machine state to/from the `State` structure.

