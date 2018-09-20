Just-In-Time Compiler Toy
=========================

Lately I've been interested in [just-in-time (JIT)
compilers](https://en.wikipedia.org/wiki/Just-in-time_compilation), so I
decided to try and build a small one for the experience. This was a fun little
project to work on, and pretty easy to build. It's still a work in progress,
but hopefully this inspires others to build their own JIT!

A very basic IR is defined with a handful of useful operations. There's an
interpreter which can be used to run the IR in software, and the main JIT
portion which translates the IR to native X86-64 code for execution on your
system (provided you have an X86-64 system, of course).

Background
----------
The basic setup is inspired by QEMU's excellent
[TCG](https://git.qemu.org/?p=qemu.git;a=blob_plain;f=tcg/README;hb=HEAD). TCG
facilitates emulation of a CPU's instructions by first translating (or
*lifting*) the emulated instructions into an intermediate representation (IR)
in groups of instructions called *basic blocks*, terminated by a branch. The
system responsible for translation from the emulated architecture to the IR is
called the *front-end*.

The IR, like other instruction sets, is composed of many basic instructions
which can be combined to emulate the *behavior* of the emulated instruction
set, while additionally tracking the changes made to the CPU state by the
respective instruction. It's often the case that one input instruction
generates several output IR instructions.

Next, QEMU will translate the IR instructions into the native machine code of
the host which the user is running on. The system which translates IR to
another instruction set architecture is called the *back-end*. TCG
historically has roots for use in a compiler, and a compiler operates much the
same way--except of course that the input to the front-end is usually some
programming language (C, for instance).

This project is a *very* rudimentary version of all this: just the back-end
portion which generates X86-64 compatible code from an intermediate
representation.

How It Works
------------
A basic block composed of IR instructions is created. Note: This could be done
by parsing some scripting language, disassembling CPU code, or something...
this project doesn't touch on that part yet and I've hard-coded the IR by hand
in the source file. Next the IR block is then either (a) interpreted or (b)
translated.

Interpretation works by decoding the IR instruction, then executing some C
code which performs the operation. This can be slower or faster depending on
the circumstance (what's being emulated vs how long it takes to JIT code,
etc). Generally speaking though the goal here anyway is to translate to our
CPU's architecture for native execution. For translation, the IR instructions
are examined, and corresponding machine code instructions are emitted.
Finally, the machine code can then be executed. The machine code is written to
an allocated page in memory and then jumped to from our C code.

Applications
------------
JITs can (and are) used in many places from emulation, to acceleration of
scripting languages and beyond--basically, any application that demands
performance. I didn't mention it above, but many JITs will perform
optimization as well--this could be a basic pass over the IR or more advanced
with runtime monitoring and re-compiling.

TODO
----
- Error handling (valid label/reg numbers, TB overflows, etc)
- Support more instructions
- Support more registers
- Support calling helper functions
- Example CPU emulator
- Block chaining
- Forward jumps in translated code
- Improve branch condition handling
- Improve block prologue/epilogue
