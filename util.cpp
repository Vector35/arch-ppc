#include "disassembler.h"

void printOperandVerbose(decomp_result *res, cs_ppc_op *op)
{
	if(op == NULL) {
		printf("NULL\n");
		return;
	}

 	switch(op->type) {
		case PPC_OP_INVALID:
			printf("invalid\n");
			break;
		case PPC_OP_REG:
			printf("reg: %s\n", cs_reg_name(res->handle, op->reg));
			break;
		case PPC_OP_IMM:
			printf("imm: 0x%X\n", op->imm);
			break;
		case PPC_OP_MEM:
			printf("mem (%s + %d)\n", cs_reg_name(res->handle, op->mem.base),
				op->mem.disp);
			break;
		case PPC_OP_CRX:
			printf("crx (scale:%d, reg:%s)\n", op->crx.scale, 
				cs_reg_name(res->handle, op->crx.reg));
			break;
		default:
			printf("unknown (%d)\n", op->type);
			break;
	}	
}

void printInstructionVerbose(decomp_result *res)
{
	struct cs_insn *insn = &(res->insn);
	struct cs_detail *detail = &(res->detail);
	struct cs_ppc *ppc = &(detail->ppc);

	/* LEVEL1: id, address, size, bytes, mnemonic, op_str */
	printf("instruction id: %d \"%s %s\"\n", insn->id, insn->mnemonic, 
	  insn->op_str);

	printf("  bytes: %02X %02X %02X %02X\n", insn->bytes[0], insn->bytes[1],
	  insn->bytes[2], insn->bytes[3]);

	/* LEVEL2: regs_read, regs_write, groups */
	printf("  regs read:");
	for(int j=0; j<detail->regs_read_count; ++j) {
		printf(" %s", cs_reg_name(res->handle, detail->regs_read[j]));
	}
	printf("\n");
	printf("  regs write:");
	for(int j=0; j<detail->regs_write_count; ++j) {
		printf(" %s", cs_reg_name(res->handle, detail->regs_write[j]));
	}
	printf("\n");
	printf("  groups:");
	for(int j=0; j<detail->groups_count; ++j) {
		int group = detail->groups[j];
		printf(" %d(%s)", group, cs_group_name(res->handle, group));
	}
	printf("\n");
	
	/* LEVEL3: branch code, branch hint, update_cr0, operands */
	if(1 /* branch instruction */) {
		printf("  branch code: %d\n", ppc->bc); // PPC_BC_LT, PPC_BC_LE, etc.
		printf("  branch hint: %d\n", ppc->bh); // PPC_BH_PLUS, PPC_BH_MINUS
	}

	printf("  update_cr0: %d\n", ppc->update_cr0);

	// .op_count is number of operands
	// .operands[] is array of cs_ppc_op
	for(int j=0; j<ppc->op_count; ++j) {
		printf("  operand%d: ", j);
		printOperandVerbose(res, &(ppc->operands[j]));
	}
}


