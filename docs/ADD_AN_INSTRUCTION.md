# How to add a new instruction

## Instruction support

This section focuses on x86 instructions until such time as there are more supported architectures.

### Implementing instructions

So, you want to add support for an instruction, but don't know where to add it, how to name it, or how the code for writing semantics works.

We use the following nomenclature:
 - *SEM*: The semantics of an instruction. This is code that implements an instruction's behaviour in a generic way.
 - *ISEL*: An instruction 'selection'. Think of this as an instantiation of some semantics for a particular encoding of an instruction. Different encodings of the same high-level instruction can affect different sizes and types of operands.

#### Choosing an instruction

Start by finding your instruction within the [XED tables document](/trailofbits/remill/master/blob/xed/xed.txt).
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
 - `LOGICAL`: This is the category of the instruction. This will generally tell you where to put your instruction code. In this case, we would implement the instruction in the [LOGICAL.h](/trailofbits/remill/blob/master/remill/Arch/X86/Semantics/LOGICAL.h) file.
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

The "types" of the operators must always match. If you intend to implement new vector instructions, then start by looking at some existing, more complicated [examples](/trailofbits/remill/blob/master/remill/Arch/X86/Semantics/CONVERT.h).

### Testing instructions

You must implement instruction test cases before committing making a pull request. Do not make a pull request until all tests pass. Again, recall that you can make incremental pull requests: you don't need to finish all milestones of a particular issue in order to contribute.

#### Writing your first tests

We will revisit the above example of the `AND` instruction. We start by creating
[`AND.S`](/trailofbits/remill/blob/master/tests/X86/LOGICAL/AND.S) within the category- and architecture-specific sub-directory of the [tests](/trailofbits/remill/tests) directory.

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
