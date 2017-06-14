# Machine code to bitcode: the life of an instruction

This document describes how machine code instructions are lifted into LLVM bitcode. It should provide a detailed, inside-out overview of how Remill performs binary translation.

### Running example

This document will use the instructions in the following basic block as a running example.

![Sample basic block](images/instruction_life_block.png)

## Decoding instructions

The first step to lifting is to decode the bytes of an instruction. This decoding step takes raw instruction bytes, and turns them into a higher-level [`Instruction`](/remill/Arch/Instruction.h) data structure. This data structure represents the logical operands to the machine code instructions. These operands have a one-to-one correspondence with arguments that will be passed to semantics functions.

Below is a string representation of the data structures representing our example assembly.

```lisp
;; mov eax, 1
(X86_INSTR 8048098 5 MOV_GPRv_IMMv_32
  (WRITE_OP (REG_32 EAX))
  (READ_OP (IMM_32 1)))

;; push ebx
(X86_INSTR 804809d 1 PUSH_GPRv_50_32
  (READ_OP (REG_32 EBX)))

;; mov ebx, dword ptr [esp + 8]
(X86_INSTR 804809e 4 MOV_GPRv_MEMv_32
  (WRITE_OP (REG_32 EBX))
  (READ_OP (ADDR_32 DWORD (SEGMENT SS_BASE) ESP + 0x8))))

;; int 0x80
(X86_INSTR 80480a2 2 INT_IMMb
  (READ_OP (IMM_8 80)))
```

## From architecture-specific to architecture-neutral

Decoded instructions must be lifted into a compatible function. Compatible functions are clones of the [`__remill_basic_block`](/remill/Arch/X86/Runtime/BasicBlock.cpp) function. The `__remill_basic_block` function is special because it defines local variables that "point into" the [`State`](/remill/Arch/X86/Runtime/State.h)) structure, which represents the machine's register state. 

The following is an example of the `__remill_basic_block` function for X86.

```C++
// Instructions will be lifted into clones of this function.
Memory *__remill_basic_block(Memory *memory, State &state, addr_t curr_pc) {
  
  ...

  auto &EAX = state.gpr.rax.dword;
  auto &EBX = state.gpr.rbx.dword;\
  auto &ESP = state.gpr.rsp.dword;

  ...

  auto &SS_BASE = zero;
  
  ...

  // Lifted code will be placed here in clones versions of this function.
  return memory;
}
```

In the case of the `push ebx` instruction from our example block, our decoder understands that `ebx` is a register. Surprisingly, the lifting side of Remill has no concept of what `ebx` is! Remill is designed to be able to translate arbitrary machine code to LLVM bitcode. To that end, there needs to be a kind of "common language" that the architecture-neutral LLVM side of things, and the architecture-specific semantics functions and machine instruction decoders can use to negotiate the translation process. This common language is variable names within the `__remill_basic_block` function. The instruction decoder ensures that decoded register names correspond to variables defined in `__remill_basic_block`. The programmer implementing `__remill_basic_block` ensures the same things. The conversion from `Instruction` data structures to LLVM bitcode _assumes_ that this correspondence exists.


Let's hammer this home. If we scroll up, we see that the `Instruction` data structure corresponding to `push ebx` has `EBX` in one of its `(READ_OP (REG_32 EBX))` register operands. This operand corresponds to the following `Register` data structure.

```C++
class Register {
 public:
  ...
  std::string name;  // Variable name in `__remill_basic_block`.
  size_t size;
};
```

The decoder initialized the `name` field with `"EBX"`, and the lifter can look up the variable name `EBX` in any cloned copies of `__remill_basic_block`.

## What does lifted code look like?

In spirit, the lifted code for the instructions in our running example looks like the following C++ code.

```C++
void __remill_sub_804b7a3(Memory *memory, State *state, addr_t pc) {
  auto &EIP = state.gpr.rip.dword;
  auto &EAX = state.gpr.rax.dword;
  auto &EBX = state.gpr.rbx.dword;
  auto &ESP = state.gpr.rsp.dword;

  EIP = pc;

  // mov    eax, 0x1
  EIP += 5;
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

  return __remill_interrupt_call(memory, state, EIP)
}
```

Earlier this documented mentioned that there is a one-to-one correspondence between operands in the `Instruction` data structure and arguments to semantics functions. We can see that with the `MOV` instruction.

The data structure of `mov ebx, dword [esp+0x8]` was:

```lisp
;; mov ebx, dword ptr [esp + 8]
(X86_INSTR 804809e 4 MOV_GPRv_MEMv_32
  (WRITE_OP (REG_32 EBX))
  (READ_OP (ADDR_32 DWORD (SEGMENT SS_BASE) ESP + 0x8))))
```

The semantics function implementing the `mov` instruction is:

```c++
template <typename D, typename S>
DEF_SEM(MOV, D dst, const S src) {
  WriteZExt(dst, Read(src));
  return memory;
}
```

The `(REG_32 EBX)` corresponds with the `dst` parameter, and the `(ADDR_32 DWORD (SEGMENT SS_BASE) ESP + 0x8))` corresponds with the `src` paremter. What links the `Instruction` data structure and the `MOV` semantics function together is the weird `MOV_GPRv_MEMv_32` name that we see. This name is stored in the `Instruction::function` field. The lifting code "discovers" the `MOV` semantics function via this name, and that association is made using the following special syntax.

```c++
DEF_ISEL(MOV_GPRv_MEMv_32) = MOV<R32W, M32>;
```

You can head on over to the [how to add an instruction](ADD_AN_INSTRUCTION.md) document to better understand the meaning of `DEF_SEM` and `DEF_ISEL`.


## We must go deeper

The spiritual lifted code makes one function call per lifted instruction, where the actual implementation of each function can be arbitrarily complex. If we optimize the bitcode that Remill produces for our few example instructions, then what we get, if translated back to C++, looks like the following. 


```C++
void __remill_sub_804b7a3(Memory *memory, State *state, addr_t pc) {
  auto &EIP = state.gpr.rip.dword;
  auto &EAX = state.gpr.rax.dword;
  auto &EBX = state.gpr.rbx.dword;
  auto &ESP = state.gpr.rsp.dword;
  auto &SS_BASE = 0;

  // mov    eax, 0x1
  EAX = 1;
  
  // push   ebx
  ESP -= 4;
  addr_t push_addr = ESP + SS_BASE;
  memory = __remill_write_memory_32(memory, push_addr, EBX);

  // mov    ebx, dword [esp+0x8]
  addr_t read_addr = __remill_compute_address(ESP + 0x8, SS);
  EBX = __remill_read_memory_32(memory, read_addr);

  // int    0x80
  state.hyper_call = AsyncHyperCall::kX86IntN;
  state.interrupt_vector = 0x80;

  EIP = pc + 12;

  return __remill_async_hyper_call(state, memory, EIP)
}
```

## The Remill runtime exposed

In the case of Remill, we want to be explicit about accesses to the "modelled program's memory", and to the "runtime's memory". Take another look above at the optimized bitcode. We can see many `load` and `store` instructions. These instruction's are LLVM's way of representing memory reads and writes. Conceptually, the `State` structure is not part of a program's memory -- if you ran the program natively, then our `State` structure would not be present. In Remill, we consider the "runtime" to be made of the following:

1. Memory accesses to `alloca`'d space: local variables needed to support more elaborate computations.
2. Memory accesses to the `State` structure. The `State` structure is passed by pointer, so it must be accessed via `load` and `store` instructions.
3. All of the various intrinsics, e.g. `__remill_async_hyper_call`, `__remill_read_memory_32`, etc.

The naming of "runtime" does not mean that the bitcode itself needs to be executed, nor does it mean that the intrinsics must be implemented in any specific way. Remill's intrinsics provide semantic value (in terms of their naming). A user of Remill bitcode can do anything they want with these intrinsics. For example, they could convert all of the memory intrinsics into LLVM `load` and `store` instructions.

Anyway, back to the memory model and memory ordering. Notice that the `memory` pointer is passed into every memory access intrinsic. The `memory` pointer is also replaced in the case of memory write intrinsics. This is to enforce a total order across all memory writes, and a partial order between memory reads and writes.

The `__remill_async_hyper_call` instruction instructs the "runtime" that an explicit [interrupt](https://en.wikipedia.org/wiki/Interrupt) (`int 0x80`) happens. Again, Remill has no way of knowing what this actually means or how it works -- that falls under the purview of the operating system kernel. What Remill *does* know is that an interrupt is a kind of ["indirect" control flow](https://en.wikipedia.org/wiki/Indirect_branch), and so it models is like all other indirect control flows.

All Remill control-flow intrinsics and Remill lifted basic block functions share the same argument structure:

1. A pointer to the opaque `Memory` structure.
2. A pointer to the `State` structure.
3. The program counter on entry to the lifted basic block.

In the case of the `__remill_async_hyper_call`, the third argument, the program counter address, is computed to be the address following the `int 0x80` instruction.

## Concluding remarks

Remill has a lot of moving parts, and it takes a lot to go from machine code to bitcode. The end result produces predictably structured bitcode that models enough of the machine behaviour to be accurate.

A key goal of Remill is to be explicit about control flows, memory ordering, and memory accesses. This isn't always obvious when looked at from the perspective of implementing instruction semantics. However, the bitcode doesn't lie.

The design of the intrinsics is such that a user of the bitcode isn't overly pigeonholed into a specific use case. Remill *has* been designed for certain use cases and not others, but in most cases, one can do as they please when it comes to implementing, removing, or changing the intrinsics. They are not defined for a reason!
