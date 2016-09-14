# Remill documentation

This document provides an index for topics relating to the design, implementation, and workings of Remill. Remill is an open-source, permissively licensed program. Persons interested in helping with the development of Remill should consult the "[How to contribute](CONTRIBUTING.md)" document.

Remill is a [static binary translator](https://en.wikipedia.org/wiki/Binary_translation#Static_binary_translation). It consumes [machine code instructions](https://en.wikipedia.org/wiki/Machine_code#Machine_code_instructions), and produces [LLVM bitcode](http://llvm.org/docs/LangRef.html) modules that accurately represents the semantics and operations performed by those instructions. These modules can be compiled back to machine code or analysed statically.

The operations, or semantics, of instructions are implemented using C++ functions. The "[How to add and test an instruction](ADD_AN_INSTRUCTION.md)"" document describes the formatting and structure of these C++ functions.

Remill does not consume binary programs directly. It depends on third-party tools like [Binary Ninja](http://binary.ninja) or [IDA Pro](https://www.hex-rays.com/products/ida) to disassemble binaries and produce "control-flow graph" (CFG) messages that tell Remill about [basic blocks](https://en.wikipedia.org/wiki/Basic_block) of machine code. The "[How to represent and format machine code](CFG_FORMAT.md)" document describes the structure and contents of the CFG file format.

Remill is designed with a narrow purpose: it only lifts machine code to LLVM bitcode. 