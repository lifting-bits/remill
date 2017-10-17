# How to add a new instruction

## Instruction support

This section focuses on x86 instructions until such time as there are more supported architectures.

### Implementing instructions

So, you want to add support for an instruction, but don't know where to add it, how to name it, or how the code for writing semantics works.

We use the following nomenclature:
 - *SEM*: The semantics of an instruction. This is code that implements an instruction's behaviour in a generic way.
 - *ISEL*: An instruction 'selection'. Think of this as an instantiation of some semantics for a particular encoding of an instruction. Different encodings of the same high-level instruction can affect different sizes and types of operands.

#### Choosing an instruction

Start by finding your instruction within the [XED tables document](XED/xed.txt).
We will use `AND` as a running example.

To start off, here are two entries from the tables document:
```
1191 AND AND_GPRv_MEMv LOGICAL BASE I86 ATTRIBUTES: SCALABLE 
 3 
  0 REG0 EXPLICIT RW NT_LOOKUP_FN INVALID GPRV_R 
  1 MEM0 EXPLICIT R IMM_CONST INT 
  2 REG1 SUPPRESSED W NT_LOOKUP_FN INVALID RFLAGS 

1193 AND AND_OrAX_IMMz LOGICAL BASE I86 ATTRIBUTES: SCALABLE 
 3 
  0 REG0 IMPLICIT RW NT_LOOKUP_FN INVALID ORAX 
  1 IMM0 EXPLICIT R IMM_CONST INT 
  2 REG1 SUPPRESSED W NT_LOOKUP_FN INVALID RFLAGS 
```

There entries contain a lot of information and are quite dense. Below are descriptions of the salient parts.
 - `AND`: The name of the instruction. This is typically the opcode, though sometimes it will be more specific. In general, there is a one-to-one correspondence between an instruction name and its *SEM*: a generic function that you will define that implements the variants of this instruction.
 - `LOGICAL`: This is the category of the instruction. This will generally tell you where to put your instruction code. In this case, we would implement the instruction in the [LOGICAL.cpp](/remill/Arch/X86/Semantics/LOGICAL.cpp) file.
 - `AND_GPRv_MEMv`: This is the *ISEL*: an instantiation of your instruction's semantics functions.
 - `SCALABLE`: This tells you that a particular *ISEL* can actually relate to a number of different operand sizes. We have short forms and naming conventions for writing one *ISEL* for all the operand sizes; however, this can be done manually as well. One XED convention is that if you see a `z` or `v` within the *ISEL* then the instruction is probably scalable.
 - `EXPLICIT`: This is an explicit operand. If you were to try to type out this instruction and assemble it, then an explicit operand is one that you need to write out. In Remill, your semantics functions will have at least one argument for each explicit operand.
 - `IMPLICIT`: This is an implicit operand. You can think of this as being an operand that you could write out in assembly. Alternatively, you can see it as an operand that is explicit in at least one *ISEL*. In Remill, your semantics functions will have at least one argument for each explicit operand.
 - `SUPPRESSD`: This is an operand that is never written out in assembly, but is operated on internally by the semantics of an instruction. In Remill, you
   *do not* associate any arguments in your semantics functions with suppressed operands.
 - `R`, `RW`, `W`, `CR`, `CW`, `RCW`: These describe how the semantics operate on a particular instruction. `R` stands for read, `W` stands for write, and `C` stands for condition. Therefore, `RCW` states that the semantics will read and conditionally write to the associated operand.
 - `REG`, `MEM`, `IMM`: This is the type of the operand within a particular instruction selection. Remill has C++ type names associated with each operand type and size.

We will ignore condition code computation within the following code examples. Most instructions that manipulate condition codes have already been implemented.

The semantics function for the `AND` instruction will look like this:
```C++
template <typename D, typename S1, typename S2>
DEF_SEM(AND, D dst, S1 src1, S2 src2) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto res = UAnd(lhs, rhs);
  WriteZExt(dst, res);
  // SetFlagsLogical(state, lhs, rhs, res);
}
```

The first operand to the `DEF_SEM` macro -- `AND` -- is the *SEM*, i.e. the name of the instruction. Sometimes you will need to implement multiple semantics functions. This will happen when a single *SEM* function cannot generically apply to all *ISEL*s.

The remaining operands are the arguments to the *SEM* function. Lets go back to look at the XED tables document and look at the explicit and implicit operands for `AND`:
```
  0 REG0 EXPLICIT RW NT_LOOKUP_FN INVALID GPRV_R 
  1 MEM0 EXPLICIT R IMM_CONST INT 
```

We see two operands here, but there are three specified to the `DEF_SEM` macro. Every XED table operand will generate at most two arguments to the `DEF_SEM` macro. If the operand is `R`, `CR`, `W`, or `CW`, then it will only generate one semantics argument. If the operand is `RW`, `CRW`, or `RCW`, then it will generate two semantics arguments. In this latter case, the write version of the operand is the first listed argument. Relating this back to the semantics code, we can see that `0 REG0 EXPLICIT RW` expands into `D dst, S1 src1`.

The semantics code can read, write, and operate on operands. To read an operand, one must use the `Read` function. In practice, you should only read from
"source" operands. There are two ways to write to a "destination" operand:
`Write(dst, ...)` and `WriteZExt(dst, ...)`. The `ZExt` version is a convenience function that specifies that if what is being written to `dst` *may* not as wide as `dst`, then the value being written will be zero-extended to the width of `dst`. This is an x86ism that helps us hand things like `mov eax, ebx`. When compiled as a 64-bit instruction, the value of `ebx` is zero-extended to 64 bits, and this value is actually written to `rax`.

Semantics code should be as explicit as possible. We could write `auto res = lhs & rhs;`
but to be more explicit, we specify that it is an unsigned logical and of `lhs` and `rhs`. There are signed, unsigned, and floating point variants of most operators. The naming of these operators generally follows the naming of [LLVM instructions](http://llvm.org/docs/LangRef.html#binary-operations). For example, there are `UAdd`, `SAdd`, and `FAdd` for implementing unsigned, signed, and floating point addition, respectively.

In general, when writing *SEM* functions, you want to put all your `Read`s up front, computations in the middle, then `Write`s to destination arguments,
*then* writes to suppressed operands (e.g. condition codes). The reason for this ordering is to hopefully limit the scope of register and memory state mutations in the face of memory access violations (e.g. segmentation fault).

Most *SEM* functions will be function templates, and therefore defined with template argument (`template <typename D, ...>`). Function templates are what enable a *SEM* to implement multiple *ISEL*s. If we choose to specify the
*ISEL* for `AND_GPRv_MEMv` then we would have to write the following:

```C++
DEF_ISEL(AND_GPRv_MEMv_8) = AND<R8W, R8, M8>;
DEF_ISEL(AND_GPRv_MEMv_16) = AND<R16W, R16, M16>;
DEF_ISEL(AND_GPRv_MEMv_32) = AND<R32W, R32, M32>;
IF_64BIT(DEF_ISEL(AND_GPRv_MEMv_64) = AND<R64W, R64, M64>;)
```

Recall that `AND` has the `SCALABLE` attribute. Not every instruction has this attribute. When they do, we suffix the `ISEL` with an explicit operand size, for example `_8`, `_16`, *etc.*

The operand types follow a predictable format. `R8W` an 8-bit register
*destination* operand, i.e. the `W` suffix means that the semantics function writes to the register. Read-only operands have no such suffix: `R8` is an
8-bit register, and `M8` is an 8-bit value in memory.

The semantics code is compiled multiple times for different x86 variants:
32-bit and 64-bit, and with or without AVX(512) support. `AND_GPRv_MEMv_64` is not valid for a 32-bit build, so we stub it out as only applying to 64-bit builds using `IF_64BIT(...)`.

A shorter way of specifying the semantics for `SCALABLE` attributed instructions is:

```C++
DEF_ISEL_RnW_Rn_Mn(AND_GPRv_MEMv, AND);
```

In this case, the `DEF_ISEL_...` macro explicitly documents what types of argument type instantiations will be performed.

#### Vector instructions

Vector instructions follow similar, albeit more nuanced formats. Below is an example implementation of `PAND`: a vectorized version of `AND`:

```C++
template <typename D, typename S1, typename S2>
DEF_SEM(PAND, D dst, S1 src1, S2 src2) {
  UWriteV32(dst, UAndV32(UReadV32(src1), UReadV32(src2)));
}
```

At a high level, we see the following conventions:
 - `UReadV32`: Reads in a vector of unsigned, 32-bit integers.
 - `UAndV32`: Performs a logical AND operation on a vector if unsigned,
    32-bit integers.
 - `UWriteV32` writes to `dst` a vector of unsigned, 32-bit integers.

The "types" of the operators must always match. If you intend to implement new vector instructions, then start by looking at some existing, more complicated [examples](/remill/Arch/X86/Semantics/CONVERT.cpp).

### Testing instructions

You must implement instruction test cases before committing making a pull request. Do not make a pull request until all tests pass. Again, recall that you can make incremental pull requests: you don't need to finish all milestones of a particular issue in order to contribute.

#### Writing your first tests

We will revisit the above example of the `AND` instruction. We start by creating
[`AND.S`](/tests/X86/LOGICAL/AND.S) within the category- and architecture-specific sub-directory of the [tests](/tests) directory.

Each *ISEL* should be tested separately. For example, a test for the `AND_GPRv_GPRv_32`
*ISEL* would be:

```assembly
TEST_BEGIN(ANDr32r32, 2)
TEST_IGNORE_FLAGS(AF)
TEST_INPUTS(
    0, 0,
    1, 0,
    0xFFFFFFFF, 1,
    0xFFFFFFFF, 0xFFFFFFFF,
    0x7FFFFFFF, 1,
    0, 0x10,
    0x7F, 0x10)

    and ARG1_32, ARG2_32
TEST_END
```

This expands into some assembly functions and data structures via black magic. Here's what the various parts mean:
 - `TEST_BEGIN`: All tests must being with this macro invocation.
 - `ANDr32r32`: This is the name of the test case. This should be unique.
 - `2` is the number of arguments that each execution of the instruction test case will evaluate.
 - `TEST_IGNORE_FLAGS(AF)`: This says that the `AND` instruction will leave the `AF` condition code in an undefined state (see the [x86 manuals](http://www.intel.com/content/www/us/en/processors/architectures-software-developer-manuals.html)).
 - `TEST_INPUTS`: This specifies the inputs to the test. All the inputs are listed out in sequence, but we specified that the test takes two arguments, and so the test runner will evaluate the instruction on each pair of inputs. We list them with two inputs per line to document this.
 - `ARG1_32`: This gives the test access to a 32-bit register containing the first argument supplied to the test. There are other variants, such as `ARG1_64`, `ARG1_16`, etc.
 - `and ...`: This is the assembly of the instruction that will be tested.
 - `TEST_END`: This denotes the end of the test.

## Quickstart for aarch64 hacking

### Setting up the `ISEL`

Currently instructions that alias to another instruction (`MOV`, `CMP`, etc) are extracted as the instruction that they alias and are not their own separate class.

All of the `ISEL` function extracting and decoding shells are auto-generated by the tool at `remill/Arch/AArch64/Etc/GenOpMap.py` that parses the [architecture documentation reference](https://developer.arm.com/-/media/developer/products/architecture/armv8-a-architecture/A64_v82A_ISA_xml_00bet3.2.tar.gz), producing the following files:


* `remill/Arch/AArch64/Extract.cpp` is responsible for parsing the bit sequence of an instruction and assigning it to a corresponding selector, in the process populating the `InstData` structure with the correct fields, which can be located at `remill/Arch/AArch64/Decode.h`. 
	* Any logical processing other than passing down the raw bit values should be done in the semantic definition, not here or in the decoding pipeline.

* `remill/Arch/AArch64/Decode.cpp` is filled with function skeletons that will receive the populated `InstData` struct and use it to push `Operand` objects into our `Instruction` class that will be later used in the semantic definition. Cut and paste the skeleton into `./Arch.cpp` and fill it out accordingly, using other functions in the file as a reference.
	* The order in which operands (immediates, registers, memory displacements, etc) is important and will be reflected in the semantic definition parameters.
	* `inst.function` of type `Instruction` contains the semantic name of the target, you can manipulate this to give you a greater granularity at the semantic level later on by, for example by appending a conditional qualifer like `_EQ` or `_GE` to the semantic.

### Defining the semantic

Under `remill/Arch/AArch64/Semantics/` figure out which class of functions your instruction fits under. If creating a new semantic class file, make sure it is included in `../Instructions.cpp`.


Similar to `X86` semantics, you will use the `DEF_ISEL` and `DEF_COND_ISEL` to implement the semantic. Below are some interesting gotchas:
* SIMD registers and Floating point registers will always have the type of `V128W` if they are the target of a write operation, regardless of their actual width class. In the semantic write however using the `UWriteV` or `FWriteV` variants, you want to match the width specifier.
* For floating point operations, you need to be careful about setting the different exception flags in the status register, see `./Flags.cpp` for some functions that seek to do this proceduraly -- however there are cornercases that need to be further inspected.
* For branches, the decoding function actually should populate an operand that acts as a "write" destination for the evaluated condition of the branch that needs to be set for the lifter, so make sure you do that.
* For instructions that alter the status of the flag registers, make sure you set them accordingly.

### Writting and running the test

Like `X86`, the tests can be found under `remill/tests/AArch64/*`. When adding a test make sure it is included in the `./Tests.S` file. A usefull process to allow you to partially recompile/build for fixing tests can be found below (from the `remill-build` directory)

```bash
#!/bin/sh

set -e
touch ../remill/Arch/AArch64/Runtime/BasicBlock.cpp
touch ../remill/Arch/AArch64/Runtime/Instructions.cpp
rm -f tests/AArch64/lift-*
rm -f tests/AArch64/run-*
make
make build_aarch64_tests
```
If you come across errors in the build process that an instruction not matching the test could not be found, double check to make sure your `DEF_ISEL` and test class are matching up (this will test against whatever was set for the `instr.function` string). 

### Debugging tips
When getting a semantic error mismatch, debugging with gdb can be helpful in narrowing down where exactly the mismatch occurs. Most of this will be using the `State` struct located at `remill/Arch/AArch64/Runtime/State.h`.

In the following snippet, assuming the testcase we are debugging is:
```c
TEST_BEGIN(UDIV_32_DP_2SRC, udiv_w3_w0_w1, 2)
TEST_INPUTS(
    0, 0,
    1, 0,
    0xffffffff, 1,
    1, 0xffffffff,
    0xffffffff, 0xffffffff,
    1, 2,
    5, 2,
    5, 3,
    5, 4)

    udiv w3, ARG1_32, ARG2_32
TEST_END
```

Fire up gdb by running it against the built lifted tester: `gdb remill-build/tests/AArch64/run-aarch64-tests`
The first steps you want to do in gdb is to alias the `State` structs of the respective native and lifted code semantics:
```bash
set $native = (State *)&gNativeState
set $lifted = (State *)&gLiftedState
```
Afterwards we can set breakpoints at `udiv_w3_w0_w1_2` for the native and (naming convention is testname_N where `N` is the number of arguments you specify in the test) `udiv_w3_w0_w1_2_lifted` for our semantic test.
Upon breakpointing on the lifted code, you can compare the two state objects for differences after stepping over or through the lifted assembly to when the basic block is refilled. Usually it is sufficient to narrow down the differences between the particular registers/status fields involved, but a complete diff of the entire `State` struct is also helpful (in the lifter some fields are intentionally zeroed out post basic block fill so make sure to account for those). A contrived example can be seen below:
```bash
Breakpoint 1, 0x000000000329b5d0 in fmadd_s_pos_floatdp3_2_lifted ()
=> 0x000000000329b5d0 <fmadd_s_pos_floatdp3_2_lifted+0>:        ea 0f 1c fc     str     d10, [sp,#-64]!
(gdb) n
Single stepping until exit from function fmadd_s_pos_floatdp3_2_lifted,
which has no line number information.
__remill_missing_block (memory=0x0) at /home/chris/tob/remill/tests/AArch64/Run.cpp:168
168       return memory;
=> 0x000000000044299c <__remill_missing_block(AArch64State&, addr_t, Memory*)+0>:       e0 03 02 aa     mov     x0, x2
   0x00000000004429a0 <__remill_missing_block(AArch64State&, addr_t, Memory*)+4>:       c0 03 5f d6     ret
(gdb) n
RunWithFlags (info=0x3306400, flags=..., desc=<incomplete type>, arg1=0, arg2=0, arg3=<optimized out>) at /home/chris/tob/remill/tests/AArch64/Run.cpp:306
306       native_state->gpr.pc.qword = info->test_end;
=> 0x00000000004432fc <RunWithFlags(test::TestInfo const*, NZCV, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >, unsigned long, unsigned long, unsigned long)+776>:    c8 06 40 f9ldr     x8, [x22,#8]
(gdb) n
322       EXPECT_TRUE(lifted_state->sr.n == native_state->sr.n);
=> 0x0000000000443300 <RunWithFlags(test::TestInfo const*, NZCV, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >, unsigned long, unsigned long, unsigned long)+780>:    89 c6 51 39ldrb    w9, [x20,#1137]
(gdb) p/x $native->sr
$1 = {_0 = 0x0, tpidr_el0 = {{dword = 0xb7ff06f0, qword = 0xffffb7ff06f0}}, _1 = 0x0, tpidrro_el0 = {{dword = 0x0, qword = 0x0}}, _2 = 0x0, n = 0x0, _3 = 0x0, z = 0x0, _4 = 0x0, c = 0x0, _5 = 0x0, v = 0x0, _6 = 0x0, ixc = 0x0, _7 = 0x0, ofc = 0x0, _8 = 0x0, ufc = 0x0, _9 = 0x0, idc = 0x0}
(gdb) p/x $lifted->sr
$2 = {_0 = 0x0, tpidr_el0 = {{dword = 0xb7ff06f0, qword = 0xffffb7ff06f0}}, _1 = 0x0, tpidrro_el0 = {{dword = 0x0, qword = 0x0}}, _2 = 0x0, n = 0x0, _3 = 0x0, z = 0x0, _4 = 0x0, c = 0x0, _5 = 0x0, v = 0x0, _6 = 0x0, ixc = 0x0, _7 = 0x0, ofc = 0x0, _8 = 0x0, ufc = 0x0, _9 = 0x0, idc = 0x0}
(gdb) p/x $native->simd.v[3]
$3 = {dqwords = {elems = {0x00000000000000000000000041100000}}, bytes = {elems = {0x0, 0x0, 0x10, 0x41, 0x0 <repeats 12 times>}}, words = {elems = {0x0, 0x4110, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}}, dwords = {elems = {0x41100000, 0x0, 0x0, 0x0}}, qwords = {elems = {0x41100000, 0x0}}, floats = {elems = {0x9, 0x0, 0x0, 0x0}}, doubles = {elems = {0x0, 0x0}}, sbytes = {elems = {0x0, 0x0, 0x10, 0x41, 0x0 <repeats 12 times>}}, swords = {elems = {0x0, 0x4110, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}}, sdwords = {elems = {0x41100000, 0x0, 0x0, 0x0}}, sqwords = {elems = {0x41100000, 0x0}}, sdqwords = {elems = {0x00000000000000000000000041100000}}}
(gdb) p/x $lifted->simd.v[3]
$4 = {dqwords = {elems = {0x00000000000000000000000041100000}}, bytes = {elems = {0x0, 0x0, 0x10, 0x41, 0x0 <repeats 12 times>}}, words = {elems = {0x0, 0x4110, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}}, dwords = {elems = {0x41100000, 0x0, 0x0, 0x0}}, qwords = {elems = {0x41100000, 0x0}}, floats = {elems = {0x9, 0x0, 0x0, 0x0}}, doubles = {elems = {0x0, 0x0}}, sbytes = {elems = {0x0, 0x0, 0x10, 0x41, 0x0 <repeats 12 times>}}, swords = {elems = {0x0, 0x4110, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}}, sdwords = {elems = {0x41100000, 0x0, 0x0, 0x0}}, sqwords = {elems = {0x41100000, 0x0}}, sdqwords = {elems = {0x00000000000000000000000041100000}}}
(gdb)
```

