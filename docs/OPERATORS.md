# Remill Operators

In implementing a semantic function for a particular instruction in Remill, one must use Remill `Read` and `Write` _operators_ to access memory. Operators are convenience functions that wrap Remill's abstracted memory types (as defined in [Types.h](/include/remill/Arch/X86/Runtime/Types.h)) and memory-access types _intrinsics_, which are integral to how Remill models memory state without defining implementations of memory access behaviors (those are deferred to the consumer of Remill to implement).

Operators, defined in [Operators.h](/include/remill/Arch/Runtime/Operators.h), are architecture-independent methods for accessing and manipulating specific data-widths of memory (the Remill memory types in `Types.h`). Operators are defined as preprocessor macros and generically using C++ templates, which is an efficient way to create signed, unsigned, and floating point variants of each operator. The naming of these operators generally follows the naming of [LLVM instructions](http://llvm.org/docs/LangRef.html#binary-operations). For example, there are `UAdd`, `SAdd`, and `FAdd` for implementing unsigned, signed, and floating point addition, respectively.

A rundown of commonly used Remill operators and their usages follows. This list and the examples are not exhaustive, and will not be as up-to-date as the source itself. But this document ought to serve as a guide to what kind of operators are available and which ones you should use in implementing your instruction semantic functions.

## Format of a Remill Operator

Most Remill operators are formed as a concatenation of:

- the value's data type: `F` for floating-point, `U` for unsigned integer, `S` for signed integer
- the operation: `Read`, `Write`, etc.
- (optional) vector type indicator `V`
- the type-width of the aforementioned value or vector-element: `8`, `6`, `32`, `64`, `128`

Together these form, for example, the operator `UWriteV32` which writes a vector of unsigned 32-bit integers to a destination operand (also a vector of equal width), or the operator `FReadV64` which reads in a source operand as a vector of 64-bit (a.k.a. double precision) floating-point values.

## Operators for Reading from Source Operands

If a source operand is any type containing a single value, you only need to `Read(src)` in order to store and start working with its value:

```C++
template <typename D, typename S>
DEF_SEM(MYINSTR, D dst, S src1, S src2) {
  auto src_operand1 = Read(src1);
  auto src_operand2 = Read(src2);
  ...
```

The above example illustrates a templated semantic function handling data types generically, to support variants of `MYINSTR` that take in source operands that are memory locations, or registers, or of different data-widths.

## Operators for Writing to Destination Operands

Writing is similar to reading, but with a few more options to allow for a conversion into the destination data type.

- `Write(dst, ...)` simply writes the second argument into the destination in the first argument.
- `WriteZExt(dst, ...)`: the `ZExt` version specifies that if what is being written to `dst` *may* not as wide as `dst`, then the value being written will be zero-extended to the width of `dst`. This is useful for things like writing to a possibly wider version of a register, but not knowing (or not explicitly specifying) exactly how wide the wider version is.
- `WriteSExt`: writes while sign-extending an integer to twice its current width.
- `WriteTrunc`: writes while truncating an integer to half its current width, preserving its signededness.

Example of how zero-extending allows a single templated semantic function to be instantiated for multiple types (data widths) of operands:

```C++
// ORN: perform the operation (X | ~Y)
template <typename D, typename S1, typename S2>
DEF_SEM(ORN, D dst, S1 src1, S2 src2) {
  WriteZExt(dst, UOr(Read(src1), UNot(Read(src2))));
  return memory;
}
```

The `Uor` and `UNot` are Remill operators too, and are covered further down in this document.

## Reading and Writing Vectorized Operands

Vectorized operands require their own set of read and write operators:

- `ReadV`: copy in a _vector_ source operand (the entire vector, not one of its values)
- `WriteV`: write out a vector to a destination operand (the entire vector, not one of its values)
- `ExtractV`: copy in _one of the values_ in a vector (specified by the index in the second argument, where `0` indicates the lowest or least-significant value of the vector)
- `InsertV`: assign or write _one of the values_ in a vector (specified by the index in the second argument)
- `ClearV`: zero out a vector

These building blocks become the operators `SExtractV32`, `FInsertV64`, `UClearV32`, etc.

In the example here, the low 64 bits of each source vector operand are stored as individual 64-bit floating point values, and then after the work is done (the `...`), the resulting 128-bit vector of floating points, `result`, is written to the destination operand, `dst`:

```C++
DEF_SEM(DO64BITVECTORSTUFF, V128W dst, V64 src1, V64 src2) {
  auto val1 = FExtractV64(FReadV64(src1), 0);
  auto val2 = FExtractV64(FReadV64(src2), 0);
  ...
  FWriteV64(dst, result);
  return memory;
}
```

## Operators for Working with Values as Pointers

- `ReadPtr` casts a value as a read-pointer.
- `WritePtr` casts a value as a write-pointer.
- `VReadPtr` and `VWritePtr` are vector variants of `ReadPtr` and `WritePtr`.
- `AddressOf`
- `DisplaceAddress`

These operators are used as templates along with an address-width, to treat a value as a pointer. Examples:

```C++
// Take the pointer represented by the contents of `program_counter` and write
// it into the register REG_FOO as a pointer:
Write(WritePtr<addr_t>(REG_FOO), Read(program_counter));

// Write into the destination REG_FOO what you read from the source operand
// REG_FOO2 as a pointer:
Write(REG_FOO, Read(ReadPtr<addr_t>REG_FOO2));
```

## Operators for Bitwise Logic

Bitwise operators are relatively self explanatory, and include:

- `Add`
- `Sub`
- `Mul`
- `Div`
- `Rem`
- `And`
- `AndN`
- `Or`
- `Xor`
- `Shl` and `Shr`
- `Neg`
- `Not`

Again, these are all templated definitions, and become the operators `FAddV32`, `UNot`, etc.

## Miscellaneous Operators

Most of these are templated wrappers around standard C++ library functions that work on native types, so that they can be used with Remill's abstracted memory operand types.

### Floating Point Value Operators

- `IsNaN`
- `IsSignalingNaN`
- `IsDenormal`
- `IsNegative`
- `IsZero`
- `IsInfinite`
- `Maximize`
- `Minimize`
- Float `ToInt` operators
- Float-rounding operators

### Type-conversion Operators

- `Literal`
- `ULiteral`
- `SLiteral`
- `ZExt`
- `ZExtTo`
- `SExt`
- `SExtTo`
- `Trunc`
- `TruncTo`

### Compiler Barriers

- `BarrierReorder`
- `BarrierUsedHere`