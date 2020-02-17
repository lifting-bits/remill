# Building
The only tool you need is docker to build the web version:
all tools and repositories are installed/checked out within the container.
For example, ccache is installed within the container and is already setup.

```bash
# Generate the cmake/ninja build files
./web/generate.sh
# Build them into js/wasm files
./web/build.sh
```

# Using Lift
To see the web demo host an http server in the directory `web/build/tools/lift`.
The `index.html` has an example of how to execute it.

To run it under node:
```bash
./web/build/tools/lift/index.js --bytes=90 --ir_out=out.ll
```

# Using the library
You can link against `web/build/libremill.a` which contains wasm binaries.

# Debugging CMake
It is useful to specify `-DCMAKE_VERBOSE_MAKEFILE=ON` in any of the
generator calls to cmake inside the `Dockerfile` to see the exact
commands being passed to Emscriptens compiler and linker.

# Issues

### Warnings
There are several warnings due to conversions between signed/unsigned, pointer sizes, etc.
To enable all warnings again remove `-Wno-everything` in the `Dockerfile`.

There are also warnings with CMake mostly related to the use of deprecated functions or that
Emscripten does not support dynamic linking (dll/so) and therefore reverts to static linkage.
To enable all these warnings remove all occurances of `-Wno-deprecated` and `-Wno-dev`.

### Debug
Right now all the libraries are built in Release because in debug some libraries
such as LLVM end up specifying specific debug formats like dwarf and this breaks Emscripten.
This most likely can be fixed with a patch/sed to the LLVM cmake files.

### 64 Bit
We're only doing 32 bit x86 right now because wasm64 support is still in the works.
Moreover, remill does not support targeting x64 from x86 (see `CMAKE_SIZEOF_VOID_P`).
We would also need to change the define `-D__i386__` and `-DADDRESS_SIZE_BITS=32` in the `CMakeLists.txt`.

Because remill needs to load the semantic files, we embed `x86.bc` into the generated JavaScript.
Alternatively, instead of using `--embed-file` we could use `--preload-file` which is more efficient,
but does not work directly in NodeJS without polyfills:

```
--embed-file ${CMAKE_CURRENT_SOURCE_DIR}/web/build/remill/Arch/X86/Runtime/x86.bc@/share/remill/11.0/semantics/x86.bc
```

### Undefined symbols in LLVM
Currently we use `-s ERROR_ON_UNDEFINED_SYMBOLS=0` to avoid the following errors, but patches/sed would be better.
```
warning: undefined symbol: __deregister_frame
warning: undefined symbol: __register_frame
warning: undefined symbol: posix_spawn_file_actions_adddup2
warning: undefined symbol: posix_spawn_file_actions_addopen
warning: undefined symbol: posix_spawn_file_actions_destroy
warning: undefined symbol: posix_spawn_file_actions_init
```

### Undefined symbols in remill
The most notable undefined symbol in remill is `popen`.
Emscripten does not have an implementation for `popen` as there is no process model.
The other errors are most likely from linking LLVM.
```
warning: undefined symbol: popen
warning: undefined symbol: posix_spawn_file_actions_adddup2
warning: undefined symbol: posix_spawn_file_actions_addopen
warning: undefined symbol: posix_spawn_file_actions_destroy
warning: undefined symbol: posix_spawn_file_actions_init
```

### Unrolling loops
Compiling under Emscripten fails with `_Pragma("unroll")` and produces the warning:
```
remill/Arch/X86/Semantics/SSE.cpp:937:9: warning: loop not unrolled:
the optimizer was unable to perform the requested transformation;
the transformation might be disabled or specified as part of an unsupported transformation ordering
[-Wpass-failed=transform-warning]
```

Another interesting note is that this pragma is most likely also embedded into the llvm
bitcode files because a similar warning is reported at runtime in wasm when the bitcode files are loaded:
```
remill-lift-10.0.js:6361 warning: <unknown>:0:0: loop not unrolled:
the optimizer was unable to perform the requested transformation;
the transformation might be disabled or specified as part of an unsupported transformation ordering
```

### Calling main once in Lift
Emscripten supports tearing down the state after main is called (global destructors, etc.)
by using `-s EXIT_RUNTIME=1` however it does not support calling main a second time.
A workaround is to expose a function that can be invoked more than once that is not `main` or
`callMain`. This can be done easily with Embind and passing `--bind` in `CMakeLists.txt`.