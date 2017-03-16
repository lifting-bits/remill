# Debugging control flow divergences

Debugging divergences produced by incorrect instruction translations or system call emulations can be challenging. It helps to have a ground truth against which comparisons can be made. There are several ways to obtain a ground truth: other binary translators (PIN, DynamoRIO), debuggers (GDB), and extensive unit tests.

Sometimes getting a ground truth is easier said than done. Finding the point of divergence of control flow can usually be discovered using GDB. However, often the point of divergence is really a symptom of the true divergence. Pinpointing the true point of divergence can be complicated by minor issues like the runtime address of the call stack being slightly different between GDB and the `vmill-snapshot`ed execution.

This directory provides a PIN tool that makes it easier to diagnose execution divergences.

## The snapshot and trace PIN tool

A PIN tool is provided in this directory that, when executed on a 32-bit binary, will produce both a snapshot file and a trace of the program's execution. This tool is a stand-in for `vmill-snapshot`, which uses `ptrace` for producing a snapshot file.

The PIN tool can be compiled as follows:

```shell
export PIN_ROOT=/opt/pin-3.2-81205-gcc-linux/
./build.sh
```

The following is an example of how to use this tool.

**Note:** The `PIN_ROOT` environment variable must be defined as the directory containing the `pin` executable. 

```shell
LD_LIBRARY_PATH=/tmp/php ./vmill-pinshot --arch x86 --workspace /tmp/php --breakpoint 0x8401260 --trace_file /tmp/native_trace -- /tmp/php /tmp/php/input.php
```

This tool uses PIN to instrument the program `/tmp/php` on the input file `/tmp/php/input.php`. The tool produces a snapshot file when execution first reaches the instruction at the address `0x8401260`. The snapshot file contains the contents of memory and the machine registers, and is saved into the `/tmp/php` directory.

After producing the snapshot file, the tool proceeds to print out the values of all registers before every executed instruction. This register trace is saved into the `/tmp/native_trace` file.

