/******************************************************************************

See disassembler.h for more information about how this fits into the PPC
architecture plugin picture.

******************************************************************************/

#include <string.h> // strcpy, etc.

#define MYLOG(...) while(0);
//#define MYLOG printf
//#include <binaryninjaapi.h>
//#define MYLOG BinaryNinja::LogDebug

#include "disassembler.h"

/* have to do this... while options can be toggled after initialization (thru
	cs_option(), the modes cannot, and endianness is considered a mode) */
thread_local csh handle_lil = 0; /* for little endian */
thread_local csh handle_big = 0; /* for big endian */
thread_local csh handle_big_ps = 0; /* for big endian and paired singles */

/* single-threaded apps only need to call this once before other functions
 * for multi-threaded apps, each thread needs to call this */
extern "C" int
powerpc_init()
{
	int rc = -1;

	MYLOG("powerpc_init()\n");

	if(handle_lil && handle_big && handle_big_ps) {
		MYLOG("WARNING: already initialized!\n");
		rc = 0;
		goto cleanup;
	}

	/* initialize capstone handles */
	if(cs_open(CS_ARCH_PPC, CS_MODE_BIG_ENDIAN, &handle_big) != CS_ERR_OK) {
		MYLOG("ERROR: cs_open()\n");
		goto cleanup;
	}

	if(cs_open(CS_ARCH_PPC, (cs_mode)(CS_MODE_BIG_ENDIAN|CS_MODE_PS), &handle_big_ps) != CS_ERR_OK) {
		MYLOG("ERROR: cs_open()\n");
		goto cleanup;
	}

	if(cs_open(CS_ARCH_PPC, CS_MODE_LITTLE_ENDIAN, &handle_lil) != CS_ERR_OK) {
		MYLOG("ERROR: cs_open()\n");
		goto cleanup;
	}

	if(handle_lil == 0 || handle_big == 0 || handle_big_ps == 0) {
		MYLOG("ERROR: cs_open() created at least one NULL handle\n");
		goto cleanup;
	}

	cs_option(handle_big, CS_OPT_DETAIL, CS_OPT_ON);
	cs_option(handle_big_ps, CS_OPT_DETAIL, CS_OPT_ON);
	cs_option(handle_lil, CS_OPT_DETAIL, CS_OPT_ON);

	rc = 0;
	cleanup:
	return rc;
}

extern "C" void
powerpc_release(void)
{
	if(handle_lil) {
		cs_close(&handle_lil);
		handle_lil = 0;
	}

	if(handle_big) {
		cs_close(&handle_big);
		handle_big = 0;
	}

	if(handle_big_ps) {
		cs_close(&handle_big_ps);
		handle_big_ps = 0;
	}
}

static csh
disasm_mode_to_cs_handle(enum disasm_mode mode)
{
	switch (mode)
	{
		case DISASM_MODE_BIG:
			MYLOG("returning handle_big==0x%X\n", (unsigned int)handle_big);
			return handle_big;
		case DISASM_MODE_LITTLE:
			MYLOG("returning handle_little==0x%X\n", (unsigned int)handle_lil);
			return handle_lil;
		case DISASM_MODE_BIG_PAIRED_SINGLES:
			MYLOG("returning handle_big_ps==0x%X\n", (unsigned int)handle_big_ps);
			return handle_big_ps;
		default:
			MYLOG("ERROR: disasm_mode_to_cs_handle() cannot recognize mode 0x%X\n", mode);
			return (csh)0;
	}
}

extern "C" int
powerpc_decompose(const uint8_t *data, int size, uint32_t addr,
	struct decomp_result *res, enum disasm_mode mode)
{
	int rc = -1;
	res->status = STATUS_ERROR_UNSPEC;

	//typedef struct cs_insn {
	//	unsigned int id; /* see capstone/ppc.h for PPC_INS_ADD, etc. */
	//	uint64_t address;
	//	uint16_t size;
	//	uint8_t bytes[16];
	//	char mnemonic[32]; /* string */
	//	char op_str[160]; /* string */
	//	cs_detail *detail; /* need CS_OP_DETAIL ON and CS_OP_SKIPDATA is OFF */
	//} cs_insn;

	// where cs_detail is some details + architecture specific part
	// typedef struct cs_detail {
	//   uint8_t regs_read[12];
	//   uint8_t regs_read_count;
	//   uint8_t regs_write;
	//   uint8_t regs_write_count;
	//   uint8_t groups[8];
	//   uint8_t groups_count;
	//   cs_ppc *ppc;
	// }

	// and finally ppc is:
	// typedef struct cs_ppc {
	//   ppc_bc bc; /* branch code, see capstone/ppc.h for PPC_BC_LT, etc. */
	//   ppc_bh bh; /* branch hint, see capstone/ppc.h for PPC_BH_PLUS, etc. */
	//   bool update_cr0;
	//   uint8_t op_count;
	//   cs_ppc_op operands[8];
    // } cs_ppc;

	// and each operand is:
	// typedef struct cs_ppc_op {
	//   ppc_op_type type; /* see capstone/ppc.h for PPC_OP_REG, etc. */
	//   union {
	//	   unsigned int reg;	// register value for REG operand
	//	   int32_t imm;		// immediate value for IMM operand
	//	   ppc_op_mem mem;		// struct ppc_op_mem { uint base; int disp }
	//	   ppc_op_crx crx;		// struct ppc_op_crx { uint scale, uint reg }
	//   };
	// } cs_ppc_op;

	cs_insn *insn = 0; /* instruction information
					cs_disasm() will allocate array of cs_insn here */
	csh handle = 0;

	/* decide which capstone handle to use */
	handle = disasm_mode_to_cs_handle(mode);
	if (handle == (csh)0) {
		MYLOG("ERROR: disasm_mode_to_cs_handle() returned -1\n");
		goto cleanup;
	}

	/* call */
	if(cs_disasm(handle, data, size, addr, 1, &insn) != 1) {
		MYLOG("ERROR: cs_disasm() failed (cs_errno:%d)\n", cs_errno(handle));
		goto cleanup;
	}

	/* set the status */
	res->status = STATUS_SUCCESS;
	res->handle = handle;

	/* copy the instruction struct, and detail sub struct to result */
	memcpy(&(res->insn), insn, sizeof(cs_insn));
	memcpy(&(res->detail), insn->detail, sizeof(cs_detail));

	rc = 0;
	cleanup:
	if(insn) {
		cs_free(insn, 1);
		insn = 0;
	}
	return rc;
}

extern "C" int
powerpc_disassemble(struct decomp_result *res, char *buf, size_t len)
{
	/* ideally the "heavy" string disassemble result is derived from light data
		in the decomposition result, but capstone doesn't make this distinction */
	int rc = -1;

	if(len < strlen(res->insn.mnemonic)+strlen(res->insn.op_str) + 2) {
		MYLOG("ERROR: insufficient room\n");
		goto cleanup;
	}

	strcpy(buf, res->insn.mnemonic);
	strcat(buf, " ");
	strcat(buf, res->insn.op_str);

	rc = 0;
	cleanup:
	return rc;
}

extern "C" const char *
powerpc_reg_to_str(uint32_t rid, enum disasm_mode mode)
{
	MYLOG("%s(%d, %d)\n", __func__, rid, mode);

	csh handle = disasm_mode_to_cs_handle(mode);
	if (handle == (csh)0)
	{
		MYLOG("%s(): couldn't get handle\n", __func__);
		return "(ERROR)";
	}

	MYLOG("%s(%d, %d) returns %s\n", __func__, rid, mode, cs_reg_name(handle, rid));
	return cs_reg_name(handle, rid);
}
