# remill-lift [![Slack Chat](http://empireslacking.herokuapp.com/badge.svg)](https://empireslacking.herokuapp.com/)

`remill-lift` is an example program that shows how to use some of the Remill
APIs, specifically, the `TraceLifter` API.

Here is an example usage of `remill-lift`:

```bash
remill-lift-6.0 --arch amd64 --ir_out /dev/stdout --bytes c704ba01000000
```

This lifts the AMD64 `mov DWORD PTR [rdx + rdi * 4], 1` to LLVM bitcode. It will output the lifted module to the `stdout`, showing something similar to the following:

```llvm
; Function Attrs: noinline nounwind ssp
define %struct.Memory* @sub_0(%struct.State* noalias dereferenceable(3280), i64, %struct.Memory* noalias) local_unnamed_addr #0 {
entry:
  %3 = getelementptr inbounds %struct.State, %struct.State* %0, i64 0, i32 6, i32 33, i32 0, i32 0
  %4 = getelementptr inbounds %struct.State, %struct.State* %0, i64 0, i32 6, i32 7, i32 0, i32 0
  %5 = getelementptr inbounds %struct.State, %struct.State* %0, i64 0, i32 6, i32 11, i32 0, i32 0
  %6 = load i64, i64* %4, align 8
  %7 = load i64, i64* %5, align 8
  %8 = shl i64 %7, 2
  %9 = add i64 %8, %6
  %10 = add i64 %1, 7
  store i64 %10, i64* %3, align 8
  %11 = tail call %struct.Memory* @__remill_write_memory_32(%struct.Memory* %2, i64 %9, i32 1) #3
  %12 = tail call %struct.Memory* @__remill_missing_block(%struct.State* nonnull %0, i64 %10, %struct.Memory* %11)
  ret %struct.Memory* %12
}
```

There are several other options available.

`--bc_out`: Used to specify a file where the LLVM bitcode should be saved.

`--address`: Used to specify the virtual address corresponding with the first byte in `--bytes`. If not specified, then this defaults to `0`.

`--entry_address`: Used to specify the address at which decoding and lifting should begin. If not specified, then this defaults to `--address`.

`--os`: Used to specify the operating system that is representative of what will be used to "run" the IR. This isn't as meaningful for this tool, but if you intend to compile the IR on Windows, for example, then you should specify `--os windows`.

`--arch`: Used to specify the architecture of the bytes in `--bytes`. Valid architectures include `x86`, `x86_avx`, `amd64`, `amd64_avx`, and `aarch64`.

