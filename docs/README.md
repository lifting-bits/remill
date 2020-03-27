# Remill documentation

This document provides an index for topics relating to the design, implementation, and workings of Remill. Remill is an open-source, permissively licensed program. Persons interested in helping with the development of Remill should consult the "[How to contribute](CONTRIBUTING.md)" document.

Remill is a [machine code](https://en.wikipedia.org/wiki/Machine_code#Machine_code_instructions) to [LLVM bitcode](http://llvm.org/docs/LangRef.html) [binary translation](https://en.wikipedia.org/wiki/Binary_translation) library. It provides APIs that enable other tools (e.g. [McSema](https://github.com/lifting-bits/mcsema)) to lift the instructions of binary programs into equivalent LLVM bitcode. Remill can and has been used by both static and dynamic binary translators.

Remill's approach to instruction lifting is showcased in the "[How instructions are lifted](LIFE_OF_AN_INSTRUCTION.md)" document. It shows how machine code bytes are decoded and mapped to C++ functions that implement the operational semantics of instructions. The "[How to add and test an instruction](ADD_AN_INSTRUCTION.md)" document describes the formatting and structure of these C++ functions.
