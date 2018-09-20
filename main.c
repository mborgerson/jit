/*
 * Copyright (c) 2018 Matt Borgerson
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <stdbool.h>
#include <unistd.h>
#define __USE_GNU
#include <signal.h>
#include <stdio.h>
#include <malloc.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/mman.h>
#include <ucontext.h>

#define MAX_REGS   4
#define MAX_LABELS 5

/*
 * All supported instruction opcodes
 */
enum JitIrOpcode {
	END_OF_BLOCK, // Marks the end of the IR

	OP_MARK,      // arg: addr

	OP_LABEL,     // arg: label-id
	              // op:  bb->labels[label-id] = pc

	OP_BRANCH,    // arg: type, label-id
	              // op:  if (cond(type)) goto bb->labels[label-id];

	OP_EXIT,      // arg: (none)
	              // op:  exit current block

	OP_CMP,       // arg: r1, r2
	              // op: compare(r1, r2), sets flags (not accessible directly)

	OP_LOADI,     // arg: r1, imm
	              // op:  reg[r1] = imm

	OP_LOAD,      // arg: r1, r2
	              // op:  reg[r1] = mem[reg[r2]]

	OP_STORE,     // arg: r1, r2
	              // op:  mem[reg[r1]] = reg[r2]

	OP_ADD,       // arg: r1, r2
	              // op:  reg[r1] = reg[r1] + reg[r2]

	OP_SUB,       // arg: r1, r2
	              // op:  reg[r1] = reg[r1] - reg[r2]

	OP__MAX
};

/*
 * Branch conditions
 */
enum JitIrBranchCond {
	BC_ALWAYS,
	BC_EQUAL,
	BC_NOTEQUAL,
	BC__MAX
};

/*
 * Branch condition names, used for pretty-printing
 */
char *cond_names[BC__MAX] = {
	[BC_ALWAYS]   = "BC_ALWAYS",
	[BC_EQUAL]    = "BC_EQUAL",
	[BC_NOTEQUAL] = "BC_NOTEQUAL",
};

/*
 * Encoding of a single instruction, 64 bits
 */
union JitIrInst {
	struct {
		uint8_t  op;
		uint8_t  args_map; // if bit X is set, that argument follows as 64b value
		uint16_t args[3];
		uint64_t ext_args[];
	};
	uint64_t raw;
};

/*
 * Get total instruction length (in number of qwords)
 */
size_t jit_get_instruction_len(union JitIrInst *inst)
{
	size_t len = 1;

	for (size_t i = 0; i < 8; i++) {
		if (inst->args_map & (1 << i)) {
			len++;
		}
	}

	return len;
}

/*
 * Get the value of an argument from encoded instruction
 */
uint64_t jit_get_arg(union JitIrInst *inst, size_t arg)
{
	assert(arg < 3);

	if (!(inst->args_map & (1 << arg))) {
		/* Operand is encoded with instruction */
		return inst->args[arg];
	}

	/* Operand follows instruction, determine correct offset */
	int ext = 0;

	for (int i = 0; i < arg; i++) {
		if (inst->args_map & (1 << i)) {
			ext++;
		}
	}

	return inst->ext_args[ext];
}

/*
 * Block of instructions
 */
struct JitIrBlock {
	union JitIrInst *code;
};

/*
 * Instruction definition structure for pretty-printing
 */
struct JitIrOpDef {
	char *name;
	int   args_num;
	char *args_spec;
};

/*
 * Instruction names and argument types for pretty-printing.
 */
const struct JitIrOpDef op_defs[OP__MAX] = {
#define OP_DEF(NAME, NARGS, SPEC) \
	[NAME] = { .name = #NAME, .args_num = NARGS, .args_spec = SPEC },
	OP_DEF(OP_MARK,   1, "i")
	OP_DEF(OP_LABEL,  1, "l")
	OP_DEF(OP_BRANCH, 2, "cl")
	OP_DEF(OP_EXIT,   1, "i")
	OP_DEF(OP_CMP,    2, "rr")
	OP_DEF(OP_LOADI,  2, "ri")
	OP_DEF(OP_LOAD,   2, "rr")
	OP_DEF(OP_STORE,  2, "rr")
	OP_DEF(OP_ADD,    2, "rr")
	OP_DEF(OP_SUB,    2, "rr")
#undef OP_DEF
};

/*
 * Pretty-print a single instruction.
 */
void jit_pprint_inst(union JitIrInst *inst)
{
	const struct JitIrOpDef *op_def = &op_defs[inst->op];

	if (inst->op == OP_MARK) {
		printf(">>> ");
	} else {
		printf("%-9s", op_def->name+3);
	}

	for (size_t j = 0; j < op_def->args_num; j++) {
		uint64_t operand_value = jit_get_arg(inst, j);

		if (j > 0) {
			printf(", ");
		}

		// Print operand according to spec
		switch (op_def->args_spec[j]) {
		case 'i': printf("%#lx",      operand_value); break;
		case 'l': printf("LBL_%ld",   operand_value); break;
		case 'r': printf("$r%ld",     operand_value); break;
		case 'c': printf("%s",        cond_names[operand_value]); break;
		default:  printf("(%lx)?",    operand_value); break;
		}
	}

	printf("\n");
}

/*
 * Pretty-print the instructions of a block.
 */
void jit_pprint(struct JitIrBlock *block)
{
	printf("[*] IR Block at %p\n", (void*)block);

	for (size_t i = 0; true; ) {
		union JitIrInst *inst = &block->code[i];

		if (inst->op == END_OF_BLOCK) {
			break;
		}

		jit_pprint_inst(inst);
		i += jit_get_instruction_len(inst);
	}
}

/*------------------------------------------------------------------------------
 * IR Block Interpreter
 *----------------------------------------------------------------------------*/

/*
 * Interpret and execute the instructions of a block
 */
void jit_interpret(struct JitIrBlock *block)
{
	uint64_t regs[MAX_REGS];
	uint64_t labels[MAX_LABELS];
	uint64_t cmp_values[2];
	bool run = true;

	printf("[*] Interpreting IR Block at %p\n", (void*)block);

	memset(regs, 0, sizeof(regs));

	// Do a quick first pass to find labels
	for (size_t i = 0; true; ) {
		union JitIrInst *inst = &block->code[i];

		if (inst->op == END_OF_BLOCK) {
			break;
		}

		if (inst->op == OP_LABEL) {
			labels[jit_get_arg(inst, 0)] = i;
		}

		i += jit_get_instruction_len(inst);
	}

	for (size_t i = 0; run; ) {
		union JitIrInst *inst = &block->code[i];
		bool set_pc = false;

		if (inst->op == END_OF_BLOCK) {
			break;
		}
		
		// Pretty print the instruction
		printf("%04zx: ", i);
		jit_pprint_inst(inst);

		switch (inst->op) {
		case OP_MARK:
			break;

		case OP_LABEL:
			// Note: we already grabbed these in the first pass, so just ignore.
			break;

		case OP_BRANCH: {
			size_t target = labels[jit_get_arg(inst, 1)];
			switch (jit_get_arg(inst, 0)) {
			case BC_ALWAYS:
				i = target;
				set_pc = true;
				break;
			case BC_EQUAL:
				if (cmp_values[0] == cmp_values[1]) {
					i = target;
					set_pc = true;
				}
				break;
			case BC_NOTEQUAL:
				if (cmp_values[0] != cmp_values[1]) {
					i = target;
					set_pc = true;
				}
				break;
			default: assert(0);
			}}
			break;

		case OP_EXIT:
			run = false;
			break;

		case OP_CMP:
			cmp_values[0] = regs[jit_get_arg(inst, 0)];
			cmp_values[1] = regs[jit_get_arg(inst, 1)];
			break;

		case OP_LOADI:
			regs[jit_get_arg(inst, 0)] = jit_get_arg(inst, 1);
			break;

		case OP_LOAD:
			regs[jit_get_arg(inst, 0)] = *(uint64_t*)regs[jit_get_arg(inst, 1)];
			break;

		case OP_STORE:
			 *(uint64_t*)regs[jit_get_arg(inst, 0)] = regs[jit_get_arg(inst, 1)];
			break;

		case OP_ADD:
			regs[jit_get_arg(inst, 0)] += regs[jit_get_arg(inst, 1)];
			break;

		case OP_SUB:
			regs[jit_get_arg(inst, 0)] -= regs[jit_get_arg(inst, 1)];
			break;

		default:
			// Not supported yet!
			assert(0);
			break;
		}

		if (!set_pc) {
			i += jit_get_instruction_len(inst);
		}

		// Print regs for debugging
		for (size_t i = 0; i < MAX_REGS; i++) {
			printf("reg[%zd] = %lx\n", i, regs[i]);
		}
		printf("\n");
	}

	printf("[*] Done\n");
}

/*------------------------------------------------------------------------------
 * Very basic x86-64 code generation stuff
 *----------------------------------------------------------------------------*/

enum {
	X86_OP_ADD = 0x01,
	X86_OP_SUB = 0x29,
	X86_OP_CMP = 0x39,
};

enum {
	X86_REG_RAX = 0,
	X86_REG_RCX = 1,
	X86_REG_RDX = 2,
	X86_REG_RBX = 3,
	X86_REG_RSP = 4,
	X86_REG_RBP = 5,
	X86_REG_RSI = 6,
	X86_REG_RDI = 7,
};

/*
 * add dest, src (etc..)
 */
size_t x86_enc_alu(uint8_t *enc, int op, int dest, int src)
{
	enc[0] = 0x48;
	enc[1] = op;
	enc[2] = 0xC0 | (src & 3) << 3 | (dest & 3);
	return 3;
}

/*
 * push reg
 */
size_t x86_enc_push(uint8_t *enc, int reg)
{
	enc[0] = 0x50 + reg;
	return 1;
}

/*
 * pop reg
 */
size_t x86_enc_pop(uint8_t *enc, int reg)
{
	enc[0] = (0x58 + reg);
	return 1;
}

/*
 * Return
 */
size_t x86_enc_ret(uint8_t *enc)
{
	enc[0] = 0xC3;
	return 1;
}

/*
 * mov reg, imm
 */
size_t x86_enc_movri(uint8_t *enc, int reg, uint64_t val)
{
	enc[0] = 0x48;
	enc[1] = 0xB8 + reg;
	memcpy(&enc[2], &val, 8);
	return 10;
}

/*
 * mov [dest], src
 */
size_t x86_enc_movmr(uint8_t *enc, int dest, int src)
{
	enc[0] = 0x48;
	enc[1] = 0x89;
	enc[2] = (src & 3) << 3 | (dest & 3);
	return 3;
}

/*
 * mov dest, [src]
 */
size_t x86_enc_movrm(uint8_t *enc, int dest, int src)
{
	enc[0] = 0x48;
	enc[1] = 0x8B;
	enc[2] = (src & 3) << 3 | (dest & 3);
	return 3;
}

enum {
	X86_JMP = 0xEB,
	X86_JZ  = 0x74,
	X86_JNZ = 0x75,
};

/*
 * Encode a jmp/jcc with 1 byte displacement
 */
size_t x86_enc_jmp(uint8_t *enc, int cc, int disp)
{
	if (disp > 0) assert(disp < (125));
	else assert(disp > -126);
	enc[0] = cc;
	enc[1] = (-2 + disp);
	return 2;
}

/*------------------------------------------------------------------------------
 * Block Translator (IR to x86-64)
 *----------------------------------------------------------------------------*/

typedef void (*TbEntryPoint)(void);

/*
 * Translated block of instructions
 */
struct JitTranslatedBlock {
	struct JitIrBlock *ir;
	size_t             code_len;
	size_t             alloc_len;
	void              *code;
	TbEntryPoint       entry;
};

/*
 * Translate the IR block to x86-64
 */
struct JitTranslatedBlock *jit_translate(struct JitIrBlock *block)
{
	printf("[*] Translating IR Block at %p to native code\n", (void*)block);

	struct JitTranslatedBlock *tb = malloc(sizeof(struct JitTranslatedBlock));
	assert(tb != NULL);

    // Allocate guest memory aligned on a page boundary
    size_t pagesize = sysconf(_SC_PAGE_SIZE);
    assert(pagesize != -1);

    tb->alloc_len = pagesize;
    tb->code = memalign(pagesize, tb->alloc_len);
    assert(tb->code != NULL);

    uint8_t *b = tb->code;
	size_t n = 0;

	int labels[MAX_LABELS];

	// Save values of gpregs
	n += x86_enc_push(&b[n], X86_REG_RAX);
	n += x86_enc_push(&b[n], X86_REG_RBX);
	n += x86_enc_push(&b[n], X86_REG_RCX);
	n += x86_enc_push(&b[n], X86_REG_RDX);

	for (size_t i = 0; true; ) {
		union JitIrInst *inst = &block->code[i];

		if (inst->op == END_OF_BLOCK) {
			break;
		}
		
		// Pretty print the instruction
		jit_pprint_inst(inst);

		switch (inst->op) {
		case OP_MARK:
			break;

		case OP_LABEL:
			// FIXME: Check for overflow
			labels[jit_get_arg(inst, 0)] = n;
			break;

		case OP_BRANCH: {
	        // FIXME: Does not yet support forward jumps! Add fix-up table
			int target = labels[jit_get_arg(inst, 1)]-n;
			switch (jit_get_arg(inst, 0)) {
			case BC_ALWAYS:
				n += x86_enc_jmp(&b[n], X86_JMP, target);
				break;
			case BC_EQUAL:
				n += x86_enc_jmp(&b[n], X86_JZ, target);
				break;
			case BC_NOTEQUAL:
				n += x86_enc_jmp(&b[n], X86_JNZ, target);
				break;
			default: assert(0);
			}}
			break;

		case OP_EXIT:
			// FIXME: Replace with jmp to end of block
			n += x86_enc_pop(&b[n], X86_REG_RDX);
			n += x86_enc_pop(&b[n], X86_REG_RCX);
			n += x86_enc_pop(&b[n], X86_REG_RBX);
			n += x86_enc_pop(&b[n], X86_REG_RAX);
			n += x86_enc_ret(&b[n]);
			break;

		case OP_CMP: {
			int reg1 = jit_get_arg(inst, 0);
			int reg2 = jit_get_arg(inst, 1);
			assert(reg1 < 4 && reg2 < 4); // Don't support other regs yet!
			n += x86_enc_alu(&b[n], X86_OP_CMP, X86_REG_RAX+reg1, X86_REG_RAX+reg2);
			} break;

		case OP_LOADI: {
			int dest = jit_get_arg(inst, 0);
			uint64_t value = jit_get_arg(inst, 1);
			assert(dest < 4); // Don't support other regs yet!
			n += x86_enc_movri(&b[n], X86_REG_RAX+dest, value);
			} break;

		case OP_ADD: {
			int reg1 = jit_get_arg(inst, 0);
			int reg2 = jit_get_arg(inst, 1);
			assert(reg1 < 4 && reg2 < 4); // Don't support other regs yet!
			n += x86_enc_alu(&b[n], X86_OP_ADD, X86_REG_RAX+reg1, X86_REG_RAX+reg2);
			} break;

		case OP_LOAD: {
			int dest = jit_get_arg(inst, 0);
			int src = jit_get_arg(inst, 1);
			assert(dest < 4 && src < 4); // Don't support other regs yet!
			n += x86_enc_movrm(&b[n], X86_REG_RAX+dest, X86_REG_RAX+src);
			} break;

		case OP_STORE: {
			int dest = jit_get_arg(inst, 0);
			int src = jit_get_arg(inst, 1);
			assert(dest < 4 && src < 4); // Don't support other regs yet!
			n += x86_enc_movmr(&b[n], X86_REG_RAX+dest, X86_REG_RAX+src);
			} break;

		default:
			// Not supported yet!
			assert(0);
		}

		i += jit_get_instruction_len(inst);
	}

	printf("[*] Done\n");

	tb->code_len = n;
	tb->entry = (TbEntryPoint)tb->code;

	int status = mprotect(b, tb->alloc_len, PROT_EXEC | PROT_READ);
	assert(status != -1);

	return tb;
}


/*
 * Execute the translated block
 */
void jit_execute_block(struct JitTranslatedBlock *tb)
{
	printf("[*] Executing translated block at %p\n", (void*)tb);
	tb->entry();
	printf("[*] Done\n");
}

/*------------------------------------------------------------------------------
 * Test Code
 *----------------------------------------------------------------------------*/

#define EXT_ARG(x) (1<<(x))
#define RAW(x) { .raw = (uint64_t)x }

int magic_value = 0xCACACACA;

/*
 * This little program will load one register with a value from memory, loop a
 * number of times to increment that value, then write the value back into
 * memory at the same spot.
 */

#define ENC_LOADI(dst, v)       { .op = OP_LOADI,  .args_map = 0,          .args = { dst, v   }}
#define ENC_LOADI_LARGE(dst, v) { .op = OP_LOADI,  .args_map = EXT_ARG(1), .args = { dst      }}, RAW(v)
#define ENC_LOAD(dst, src)      { .op = OP_LOAD,   .args_map = 0,          .args = { dst, src }}
#define ENC_STORE(dst, src)     { .op = OP_STORE,  .args_map = 0,          .args = { dst, src }}
#define ENC_LABEL(x)            { .op = OP_LABEL,  .args_map = 0,          .args = { x        }}
#define ENC_ADD(dst, src)       { .op = OP_ADD,    .args_map = 0,          .args = { dst, src }}
#define ENC_CMP(r1, r2)         { .op = OP_CMP,    .args_map = 0,          .args = { r1,  r2  }}
#define ENC_BRANCH(c, l)        { .op = OP_BRANCH, .args_map = 0,          .args = { c,   l   }}
#define ENC_EXIT()              { .op = OP_EXIT                                                }
#define ENC_END_OF_BLOCK()      { .op = END_OF_BLOCK                                           }

union JitIrInst code[] = {
	ENC_LOADI(0, 1),                       // reg[0] = 1
	ENC_LOADI(1, 5),                       // reg[1] = 5
	ENC_LOADI_LARGE(3, &magic_value),      // reg[3] = &magic_value
	ENC_LOAD(3, 3),                        // reg[3] = mem[reg[3]]
	ENC_LABEL(0),                          // label0:
	ENC_ADD(3, 0),                         // reg[3] = reg[3] + reg[0]
	ENC_ADD(2, 0),                         // reg[2] = reg[2] + reg[0]
	ENC_CMP(1, 2),                         // if (reg[1] != reg[2])
	ENC_BRANCH(BC_NOTEQUAL, 0),            //     goto label0
	ENC_LOADI_LARGE(0, &magic_value),      // reg[0] = &magic_value
	ENC_STORE(0, 3),                       // mem[reg[0]] = reg[3] 
	ENC_EXIT(),                            // exit
	ENC_END_OF_BLOCK(),
};

struct JitIrBlock test_block = {
	.code = code,
};

#define ENABLE_PPRINT      0
#define ENABLE_IR_DUMP     0
#define ENABLE_INTERPRETER 0
#define ENABLE_JIT         1
#define ENABLE_TB_DUMP     0

int main(int argc, char const *argv[])
{
#if ENABLE_PPRINT
	jit_pprint(&test_block);
#endif

#if ENABLE_IR_DUMP
	size_t len = 0;
	for (len = 0; true; ) {
		union JitIrInst *inst = &test_block.code[len];
		len += jit_get_instruction_len(inst);
		if (inst->op == END_OF_BLOCK) {
			break;
		}
	}
	FILE *irf = fopen("ir.bin", "wb");
	fwrite(test_block.code, 1, len*8, irf);
	fclose(irf);
#endif

#if ENABLE_INTERPRETER
	magic_value = 0xDEADC0D9;
	printf("Magic value before is %x\n", magic_value);
	jit_interpret(&test_block);
	printf("Magic value after is %x\n", magic_value);
#endif

#if ENABLE_JIT
	// Translate the IR
	struct JitTranslatedBlock *tb = jit_translate(&test_block);

	// Enable if you want to dump the final code to a file!
#if ENABLE_TB_DUMP
	FILE *tbf = fopen("tb.bin", "wb");
	fwrite(tb->code, 1, tb->code_len, tbf);
	fclose(tbf);
#endif

	// Run it!
	magic_value = 0xDEADC0D9;
	printf("Magic value before is %x\n", magic_value);
	jit_execute_block(tb);
	printf("Magic value after is %x\n", magic_value);
#endif

	return 0;
}
