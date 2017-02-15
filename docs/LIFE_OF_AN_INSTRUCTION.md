# Machine code to bitcode: the life of an instruction

This document describes how machine code instructions are lifted into LLVM bitcode. It should provide a detailed, inside-out overview of how Remill performs binary translation.

### Running example

This document will use the instructions in the following basic block as a running example.

![Sample basic block](images/instruction_life_block.png)

## Step 1: CFG protocol buffer representation

The first step to lifting involves getting the machine code instructions of some binary file into a format the Remill understands. We use a common and simple format so that Remill doesn't need to understand the many executable file formats ([ELF](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format), [Mach-O](https://en.wikipedia.org/wiki/Mach-O), [PE](https://en.wikipedia.org/wiki/Portable_Executable), etc.).

The file format used by Remill is a [CFG protocol buffer](CFG_FORMAT.md). This file is produced using plug-in scripts for [Binary Ninja](https://binary.ninja) and [IDA Pro](https://www.hex-rays.com/products/ida). The CFG file for the above code block contains the following data.

```protobuf
Module {
  blocks = [
    Block {
      address = 0x804b7a3;
      is_addressable = false;
      instructions = [

        // mov    eax, 0x1
        Instr {
          bytes = "\xb8\x01\x00\x00\x00";
          address = 0x804b7a3;
        },

        // push   ebx
        Instr {
          bytes = "\x53";
          address = 0x0804b7a8;
        },

        // mov    ebx, dword [esp+0x8]
        Instr {
          bytes = "\x8b\x5c\x24\x08";
          address = 0x0804b7a9;
        },

        // int    0x80
        Instr {
          bytes = "\xcd\x80";
          address = 0x0804b7ad;
        } ]
    } ]
  named_blocks = [ ];
  referenced_blocks = [ ];
}      
```

## Step 2: Creating LLVM functions for each `Block`

Remill's unit of translation is a [basic block](https://en.wikipedia.org/wiki/Basic_block). Whereas [McSema](https://github.com/trailofbits/mcsema) translates a function in a binary into an LLVM bitcode function, Remill translates each basic block of code into an LLVM bitcode function.

The translator creates an LLVM function for every `Block` in the CFG protocol buffer's `Module` message. In this example, Remill will create the function `__remill_sub_804b7a3`. This function will be a copy of the [`__remill_basic_block`](https://github.com/trailofbits/remill/blob/master/remill/Arch/X86/Runtime/BasicBlock.cpp) function. What this means is that all of the code and variable definitions within `__remill_basic_block` will also be in `__remill_sub_804b7a3`.

### The `__remill_basic_block` function

The `__remill_basic_block` function is very important. There are *a lot* of variables defined in this function, and the comments are mildy useful. For now, we will focus on the variable definitions that relate to machine code registers. Specifically, we will look at how the translator maps `ebx` from `push ebx` into `EBX`.

```C++
// Method that will implement a basic block. We will clone this method for
// each basic block in the code being lifted.
[[gnu::used]]
void __remill_basic_block(State &state, Memory &memory, addr_t curr_pc) {
  ...
  auto &EAX = state.gpr.rax.dword;
  auto &EBX = state.gpr.rbx.dword;
  ...
}
```

Remill is designed to be able to translate arbitrary machine code to LLVM bitcode. As of this writing, only the x86 and x64 architectures are supported. Nevertheless, there needs to be a kind of "common language" that the architecture-neutral LLVM side of things, and the architecture-specific semantics functions and machine instruction decoders can use to negotiate the translation process. This common language is variable names within the `__remill_basic_block` function.

Ideally, we don't want the LLVM translation side to understand machine registers. And yet, if you take a look at the [`Instruction`](/remill/Arch/Instruction.h) data structure, then you will see something like the following:

```C++
class Register {
 public:
  ...
  std::string name;  // Variable name in `__remill_basic_block`.
  size_t size;
};
```

If we look deep into the bowels of [`DecodeRegister`](/remill/Arch/X86/Arch.cpp#L406), the function that pulls out architecture-specific register operand information from [Intel's XED](https://software.intel.com/en-us/articles/xed-x86-encoder-decoder-software-library), we find that that a register operand can be built as follows:

```C++
  if (xed_operand_read(xedo)) {
    ...
    op.reg = ReadOp(reg);  // Returns `EBX`.
    instr->operands.push_back(op);
  }
```

In the case of the `push ebx` instruction from our example block, `ReadOp` will actually return the string `"EBX"`. Recall that each basic block of machine code is lifted into an LLVM function, and that function is a clone of `__remill_basic_block`. This means that the LLVM function implementing the basic block will have `EBX` defined. So, the translator doesn't actually know what `ebx` is, it just understands variable names, and the instruction decoder will produce variable names for registers, knowing that those variables are defined in `__remill_basic_block`, and therefore will be available within all of its clones.

## Step 3: Calling semantics functions for each `Instr`

The previous section described how the architecture-specific instruction decoder can communicate things like registers to the higher-level translation system. The decoder tells the translator to look for specific variables representing register values, knowing that those variables will be available to each block function.

The "[How to add a new instruction](ADD_AN_INSTRUCTION.md)" document describes the different between *SEM*s, functions implementing instruction semantics, and *ISEL*s, specialisations of those functions that are specific to an instruction form or encoding. The instruction decoder knows about the names of *ISEL*s, and it uses these names to [direct the translator](/remill/Arch/Instruction.h#L79-L80) to find and call the right function for each instruction being lifted.

The [operands](/remill/Arch/Instruction.h#L123) of the instruction data structure tell the translator how to find and compute values to pass as arguments to the semantics functions. In the last section, we showed how the `ebx` register in `push ebx` is represented as a register operand, whose variable name is `EBX`. The translator loads this value and passes it as an argument to the [`PUSH_GPRv_32`](/remill/Arch/X86/Semantics/PUSH.cpp#L28) *ISEL* function, as implemented by the [`PUSH`](/remill/Arch/X86/Semantics/PUSH.cpp#L17-L20) *SEM* function.

Here's what the unoptimised bitcode for the example basic block looks like:

```llvm
; Function Attrs: alwaysinline inlinehint nounwind
define private fastcc void @__remill_sub_804b7a3(%struct.State* dereferenceable(3200) %state, %struct.Memory* nonnull %memory, i32 %pc) #7 {
  %MEMORY = alloca %struct.Memory*, align 4
  store %struct.Memory* %memory, %struct.Memory** %MEMORY, align 4
  %1 = getelementptr inbounds %struct.State, %struct.State* %state, i32 0, i32 5, i32 33
  %2 = bitcast %union.Flags* %1 to i32*
  %3 = getelementptr inbounds %struct.State, %struct.State* %state, i32 0, i32 5, i32 1
  %4 = bitcast %union.Flags* %3 to i32*
  %5 = getelementptr inbounds %struct.State, %struct.State* %state, i32 0, i32 5, i32 3
  %6 = bitcast %union.Flags* %5 to i32*
  %7 = getelementptr inbounds %struct.State, %struct.State* %state, i32 0, i32 5, i32 3
  %8 = bitcast %union.Flags* %7 to i32*
  %9 = getelementptr inbounds %struct.State, %struct.State* %state, i32 0, i32 5, i32 13
  %10 = bitcast %union.Flags* %9 to i32*
  %11 = getelementptr inbounds %struct.State, %struct.State* %state, i32 0, i32 4, i32 1
  %12 = add i32 %pc, 5
  store i32 %12, i32* %2, align 4
  call void @void (anonymous namespace)::MOV<RnW<unsigned int>, In<unsigned int> >(State&, Memory*&, RnW<unsigned int>, In<unsigned int>)(%struct.State* nonnull %state, %struct.Memory** nonnull %MEMORY, i32* %4, i32 1)
  %13 = load i32, i32* %2, align 4
  %14 = add i32 %13, 1
  store i32 %14, i32* %2, align 4
  %15 = load i32, i32* %6, align 4
  call void @void (anonymous namespace)::PUSH<unsigned int>(State&, Memory*&, unsigned int)(%struct.State* nonnull %state, %struct.Memory** nonnull %MEMORY, i32 %15)
  %16 = load i32, i32* %2, align 4
  %17 = add i32 %16, 4
  store i32 %17, i32* %2, align 4
  %18 = load i32, i32* %10, align 4
  %19 = load i16, i16* %11, align 2
  %20 = zext i16 %19 to i32
  %21 = add i32 %18, 8
  %22 = call i32 @__remill_compute_address(i32 %21, i32 %20)
  call void @void (anonymous namespace)::MOV<RnW<unsigned int>, Mn<unsigned int> >(State&, Memory*&, RnW<unsigned int>, Mn<unsigned int>)(%struct.State* nonnull %state, %struct.Memory** nonnull %MEMORY, i32* %8, i32 %22)
  %23 = load i32, i32* %2, align 4
  %24 = add i32 %23, 2
  store i32 %24, i32* %2, align 4
  call void @INT_IMMb(%struct.State* nonnull %state, %struct.Memory** nonnull %MEMORY, i32 128)
  %25 = load i32, i32* %2, align 4
  %26 = load %struct.Memory*, %struct.Memory** %MEMORY, align 4
  musttail call fastcc void @__remill_interrupt_call(%struct.State* nonnull %state, %struct.Memory* %26, i32 %25)
  ret void
}
```

Yikes! That is a lot of code. Here's what it would look like if it was written directly in C++:

```C++
void __remill_sub_804b7a3(State *state, Memory *memory, addr_t pc) {
  auto &EIP = state.gpr.rip.dword;
  auto &EAX = state.gpr.rax.dword;
  auto &EBX = state.gpr.rbx.dword;
  auto &ESP = state.gpr.rsp.dword;

  // mov    eax, 0x1
  pc += 5;
  EIP = pc;
  MOV<R32W, I32>(state, &memory, &EAX, 1);
  
  // push   ebx
  EIP += 1;
  PUSH<R32>(state, &memory, EBX);

  // mov    ebx, dword [esp+0x8]
  EIP += 4;
  MOV<R32W, M32>(state, &memory, &EBX, ESP + 0x8);

  // int    0x80
  EIP += 2;
  INT_IMMb<I8>(state, &memory, 0x80);

  return __remill_interrupt_call(state, memory, EIP)
}
```

This is somewhat better. We can see that some of the mechanics of instructions happen outside of the instruction semantics function calls. Specifically, we see the program counter incremented before each semantics function call.

There `State *state` parameter to `__remill_sub_804b7a3` holds all [machine register state](/remill/Arch/X86/Runtime/State.h). The `Memory *memory` parameter is curious. It is passed to each semantics function by pointer, implying that it is updated within. The `Memory` type is never actually defined, but it is crucial to Remill's [memory model](https://en.wikipedia.org/wiki/Memory_model_(programming)) and enforcing [memory ordering](https://en.wikipedia.org/wiki/Memory_ordering). We can see more of this when we apply and [inlining](https://en.wikipedia.org/wiki/Inline_expansion) optimisation.

## Step 4: Optimizing the bitcode

```llvm
; Function Attrs: alwaysinline inlinehint nounwind
define private fastcc void @__remill_sub_804b7a3(%struct.State* dereferenceable(3200) %state, %struct.Memory* nonnull %memory, i32 %pc) #8 {
  %1 = getelementptr inbounds %struct.State, %struct.State* %state, i64 0, i32 5, i32 33
  %2 = bitcast %union.Flags* %1 to i32*
  %3 = getelementptr inbounds %struct.State, %struct.State* %state, i64 0, i32 5, i32 1
  %4 = bitcast %union.Flags* %3 to i32*
  %5 = getelementptr inbounds %struct.State, %struct.State* %state, i64 0, i32 5, i32 3
  %6 = bitcast %union.Flags* %5 to i32*
  %7 = getelementptr inbounds %struct.State, %struct.State* %state, i64 0, i32 5, i32 13
  %8 = bitcast %union.Flags* %7 to i32*
  %9 = getelementptr inbounds %struct.State, %struct.State* %state, i64 0, i32 4, i32 1
  store i32 1, i32* %4, align 4
  %10 = load i32, i32* %6, align 4
  %11 = load i32, i32* %8, align 8
  %12 = add i32 %11, -4
  %13 = load i16, i16* %9, align 2
  %14 = zext i16 %13 to i32
  %15 = tail call i32 @__remill_compute_address(i32 %12, i32 %14) #15
  %16 = tail call %struct.Memory* @__remill_write_memory_32(%struct.Memory* nonnull %memory, i32 %15, i32 %10) #15
  store i32 %12, i32* %8, align 4
  %17 = add i32 %11, 4
  %18 = tail call i32 @__remill_compute_address(i32 %17, i32 %14)
  %19 = tail call i32 @__remill_read_memory_32(%struct.Memory* %16, i32 %18) #15
  store i32 %19, i32* %6, align 4
  %20 = add i32 %pc, 12
  store i32 %20, i32* %2, align 4
  %21 = getelementptr inbounds %struct.State, %struct.State* %state, i64 0, i32 9
  store volatile i32 128, i32* %21, align 4
  %22 = getelementptr inbounds %struct.State, %struct.State* %state, i64 0, i32 12
  store volatile i8 1, i8* %22, align 2
  %23 = load i32, i32* %2, align 4
  musttail call fastcc void @__remill_interrupt_call(%struct.State* nonnull %state, %struct.Memory* %16, i32 %23)
  ret void
}
```

After inlining, the bitcode starts to show off its memory model. Again, lets see what things would look like if we translated this code into C++.

```C++
void __remill_sub_804b7a3(State *state, Memory *memory, addr_t pc) {
  auto &EIP = state.gpr.rip.dword;
  auto &EAX = state.gpr.rax.dword;
  auto &EBX = state.gpr.rbx.dword;
  auto &ESP = state.gpr.rsp.dword;
  auto &SS = state.seg.ss;

  // mov    eax, 0x1
  EAX = 1;
  
  // push   ebx
  ESP -= 4;
  addr_t push_addr = __remill_compute_address(ESP, SS);
  memory = __remill_write_memory_32(memory, push_addr, EBX);

  // mov    ebx, dword [esp+0x8]
  addr_t read_addr = __remill_compute_address(ESP + 0x8, SS);
  EBX = __remill_read_memory_32(memory, read_addr);

  // int    0x80
  state.interrupt_vector = 0x80;  // This is a wart. See Issue #53.

  EIP = pc + 12;

  return __remill_interrupt_call(state, memory, EIP)
}
```

### The Remill runtime exposed

In the case of Remill, we want to be explicit about accesses to the "modelled program's memory", and to the "runtime's memory". Take another look above at the optimized bitcode. We can see many `load` and `store` instructions. These instruction's are LLVM's way of representing memory reads and writes. Conceptually, the `State` structure is not part of a program's memory -- if you ran the program natively, then our `State` structure would not be present. In Remill, we consider the "runtime" to be made of the following:

1. Memory accesses to `alloca`'d space: local variables needed to support more elaborate computations.
2. Memory accesses to the `State` structure. The `State` structure is passed by pointer, so it must be accessed via `load` and `store` instructions.
3. All of the various intrinsics, e.g. `__remill_interrupt_call`, `__remill_read_memory_32`, etc.

The naming of "runtime" does not mean that the bitcode itself needs to be executed, nor does it mean that the intrinsics must be implemented in any specific way. Remill's intrinsics provide semantic value (in terms of their naming). A user of Remill bitcode can do anything they want with these intrinsics. For example, they could convert all of the memory intrinsics into LLVM `load` and `store` instructions.

Anyway, back to the memory model and memory ordering. Notice that the `memory` pointer is passed into every memory access intrinsic. The `memory` pointer is also replaced in the case of memory write intrinsics. This is to enforce a total order across all memory writes, and a partial order between memory reads and writes.

The `__remill_interrupt_call` and `__remill_compute_address` intrinsics are examples of lower level abstractions that cannot be directly modelled by Remill.

The `__remill_compute_address` is used to model [memory segmentation](https://en.wikipedia.org/wiki/Memory_segmentation#x86_architecture). In x86 (32-bit) code, segmentation is widespread -- this intrinsic rarely shows up in x64 code. Memory segmentation is supported by the [local](https://en.wikipedia.org/wiki/Global_Descriptor_Table#Local_Descriptor_Table) and [global](https://en.wikipedia.org/wiki/Global_Descriptor_Table) descriptor tables.

The `__remill_interrupt_call` instruction instructs the "runtime" that an explicit [interrupt](https://en.wikipedia.org/wiki/Interrupt) (`int 0x80`) happens. Again, Remill has no way of knowing what this actually means or how it works -- that falls under the purview of the operating system kernel. What Remill *does* know is that an interrupt is a kind of ["indirect" control flow](https://en.wikipedia.org/wiki/Indirect_branch), and so it models is like all other indirect control flows.

All Remill control-flow intrinsics and Remill lifted basic block functions share the same argument structure:

1. A pointer to the `State` structure.
2. A pointer to the opaque `Memory` structure.
3. The program counter on entry to the lifted basic block.

In the case of the `__remill_interrupt_call`, the third argument, the program counter address, is computed to be the address following the `int 0x80` instruction.

## Concluding remarks

Remill has a lot of moving parts, and it takes a lot to go from machine code to bitcode. The end result produces predictably structured bitcode that models enough of the machine behaviour to be accurate.

A key goal of Remill is to be explicit about control flows, memory ordering, and memory accesses. This isn't always obvious when looked at from the perspective of implementing instruction semantics. However, the bitcode doesn't lie.

The design of the intrinsics is such that a user of the bitcode isn't overly pigeonholed into a specific use case. Remill *has* been designed for certain use cases and not others, but in most cases, one can do as they please when it comes to implementing, removing, or changing the intrinsics. They are not defined for a reason!
