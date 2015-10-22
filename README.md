## mcsema2

### Setup

```
./bootstrap.sh
```

### Example

First, extract the control-flow graph information from your binary.

```
./scripts/ida_get_cfg.sh /path/to/binary
```

This script will tell you where it puts the CFG. For example, it might output something
like `/tmp/tmp.E3RWcczulG.cfg`.

Lets assume that `/path/to/binary` is a 64-bit ELF file. Now you can do the following:

```
./build/cfg_to_bc --arch=x86 --os=linux --bc_out=/tmp/out.bc --cfg=/tmp/tmp.E3RWcczulG.cfg
```

Great! Now you have a massive bitcode file. Enjoy!