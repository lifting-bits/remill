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
./scripts/ida_get_cfg.sh /path/to/binary
```

This script will tell you where it puts the CFG. For example, it might output something
like `/tmp/tmp.E3RWcczulG.cfg`.

Lets assume that `/path/to/binary` is a 32-bit ELF file. Now you can do the following:

```
./build/cfg_to_bc --arch_in=x86 --arch_out=x86 --os_in=linux --os_out=linux --bc_in=./generated/sem_x86.bc --bc_out=/tmp/out.bc --cfg=/tmp/tmp.E3RWcczulG.cfg
```

For 64-bit x86 programs, specificy `--arch_in=amd64`. If you intend to run a 32-bit
binary as a 64-bit program then specify `--arch_in=x86 --arch_out=amd64`.
Similar switching can be done for the OS.

*Note:* This arch/OS switching only affects the ABI used by the bitcode. The
translator itself has no other concept of arch/OS types. It is up to the next
tool in the pipeline to implement the desired behavior.

Great! Now you have a massive bitcode file. Enjoy!

### Miscellaneous

To recompile the code, run `./scripts/build.py`. Ideally, you should install
the `concurrent.futures` package to make the build faster, though it is not
required.

To recompile the semantics, e.g. if you add an instruction, then run `./scripts/compile_semantics.sh`.
If you want to test your new semantics, then also recompile the code using the
above command.]
