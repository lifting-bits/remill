## mcsema2
[![Build Status](https://travis-ci.com/trailofbits/mcsema2.svg?token=T1UToSpCvaMxn511Cddb)](https://travis-ci.com/trailofbits/mcsema2)

### Setup

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
./build/cfg_to_bc --arch=x86 --os=linux --bc_out=/tmp/out.bc --cfg=/tmp/tmp.E3RWcczulG.cfg
```

For 64-bit x86 programs, specificy `--arch=amd64`.

Great! Now you have a massive bitcode file. Enjoy!
