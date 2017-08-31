#include <binaryninjaapi.h>

#include "disassembler.h"

using namespace BinaryNinja;

#include "il.h"
#include "util.h"

#define OTI_SEXT32_REGS 1
#define OTI_SEXT64_REGS 2
#define OTI_ZEXT32_REGS 4
#define OTI_ZEXT64_REGS 8
#define OTI_SEXT32_IMMS 16
#define OTI_SEXT64_IMMS 32
#define OTI_ZEXT32_IMMS 64
#define OTI_ZEXT64_IMMS 128
#define OTI_IMM_CPTR 256
#define OTI_IMM_REL_CPTR 512
#define OTI_IMM_BIAS 1024

//#define MYLOG(...) while(0);
#define MYLOG BinaryNinja::LogDebug

static ExprId operToIL(LowLevelILFunction &il, struct cs_ppc_op *op,
	int options=0, uint64_t extra=0)
{
	ExprId res;

	if(!op) {
		MYLOG("ERROR: operToIL() got NULL operand\n");
		return il.Unimplemented();
	}

	switch(op->type) {
		case PPC_OP_REG:
			//MYLOG("case PPC_OP_REG returning reg %d\n", op->reg);
			res = il.Register(4, op->reg);
			break;
		case PPC_OP_IMM:
			/* the immediate is a constant pointer (eg: absolute address) */
			if(options & OTI_IMM_CPTR) {
				res = il.ConstPointer(4, op->imm);
			}
			/* the immediate is a displacement (eg: relative addressing) */
			else if(options & OTI_IMM_REL_CPTR) {
				res = il.ConstPointer(4, op->imm + extra);
			}
			/* the immediate should be biased with given value */
			else if(options & OTI_IMM_BIAS) {
				res = il.Const(4, op->imm + extra);
			}
			/* the immediate is just a plain boring immediate */
			else {
				res = il.Const(4, op->imm);
			}
			break;

		case PPC_OP_MEM:
			//MYLOG("case PPC_OP_MEM returning regs (%d,%d)\n", op->mem.base, op->mem.disp);

			if(options & OTI_IMM_BIAS)
				res = il.Add(4, il.Register(4, op->mem.base), il.Const(4, op->mem.disp + extra));
			else
				res = il.Add(4, il.Register(4, op->mem.base), il.Const(4, op->mem.disp));
			break;

		case PPC_OP_CRX:
		case PPC_OP_INVALID:
		default:
			MYLOG("ERROR: don't know how to convert operand to IL\n");
			res = il.Unimplemented();
	}	

	switch(options) {
		case OTI_SEXT32_REGS:
			if(op->type == PPC_OP_REG)
				res = il.SignExtend(4, res);
			break;
		case OTI_SEXT64_REGS:
			if(op->type == PPC_OP_REG)
				res = il.SignExtend(8, res);
			break;
		case OTI_ZEXT32_REGS:
			if(op->type == PPC_OP_REG)
				res = il.ZeroExtend(4, res);
			break;
		case OTI_ZEXT64_REGS:
			if(op->type == PPC_OP_REG)
				res = il.ZeroExtend(8, res);
			break;
		case OTI_SEXT32_IMMS:
			if(op->type == PPC_OP_REG)
				res = il.SignExtend(4, res);
			break;
		case OTI_SEXT64_IMMS:
			if(op->type == PPC_OP_REG)
				res = il.SignExtend(8, res);
			break;
		case OTI_ZEXT32_IMMS:
			if(op->type == PPC_OP_REG)
				res = il.ZeroExtend(4, res);
			break;
		case OTI_ZEXT64_IMMS:
			if(op->type == PPC_OP_REG)
				res = il.ZeroExtend(8, res);
			break;
	}

	return res;
}

/* INPUT:
	- csBranchCode capstone branch code {PPC_BC_LT, PPC_BC_EQ, ...}

   OUTPUT:
	- BNLowLevelILFlagCondition {LLFC_E, LLFC_NE, ...}

   remember that the LLFC_XXX are names of sets in IL namespace, and
   architectures declare their architecture-specific flag names as
   members of these predefined sets by responding to
   GetFlagsRrequiredForFlagCondition()
*/
static BNLowLevelILFlagCondition bc2fc(int csBranchCode)
{
	MYLOG("switching on csBranchCode: %d\n", csBranchCode);
	switch(csBranchCode) {
		case PPC_BC_LT:
			return LLFC_ULT;
		case PPC_BC_LE: /* (a <= b) or not-greater-than "ng" */
			return LLFC_ULE;
		case PPC_BC_EQ:
			return LLFC_E;
		case PPC_BC_GE: /* (a >= b) or not-less-than "nl" */
			return LLFC_UGE;
		case PPC_BC_GT:
			return LLFC_UGT;
		case PPC_BC_NE:
			return LLFC_NE;
		case PPC_BC_SO: /* summary overflow */
		case PPC_BC_NS: /* not summary overflow */
		case PPC_BC_UN: /* unordered (after floating-point comparison) (AKA "uo") */
		case PPC_BC_NU: /* not unordered */
		default:
			MYLOG("%s() returning unimplemented!\n", __func__);
			return (BNLowLevelILFlagCondition)-1;
	}
}

/* INPUT:
	- csBranchCode capstone branch code {PPC_BC_LT, PPC_BC_EQ, ...}
	- addrSize {32, 64}
	- addrTrue ABSOLUTE
	- addrFalse ABSOLUTE
*/
static void ConditionalJump(Architecture* arch, LowLevelILFunction& il, 
  int csBranchCode, size_t addrSize, uint64_t addrTrue, uint64_t addrFalse)
{
	/* return early for unconditional jumps */
	if(csBranchCode == PPC_BC_INVALID) {
		il.AddInstruction(il.Jump(il.ConstPointer(addrSize, addrTrue)));
		return;
	}

	ExprId clause = il.FlagCondition(bc2fc(csBranchCode));

	BNLowLevelILLabel *trueLabel = il.GetLabelForAddress(arch, addrTrue);
	BNLowLevelILLabel *falseLabel = il.GetLabelForAddress(arch, addrFalse);

	if (trueLabel && falseLabel)
	{
		il.AddInstruction(il.If(clause, *trueLabel, *falseLabel));
		return;
	}

	LowLevelILLabel trueCode, falseCode;

	if (trueLabel)
	{
		il.AddInstruction(il.If(clause, *trueLabel, falseCode));
		il.MarkLabel(falseCode);
		il.AddInstruction(il.Jump(il.ConstPointer(addrSize, addrFalse)));
		return;
	}

	if (falseLabel)
	{
		il.AddInstruction(il.If(clause, trueCode, *falseLabel));
		il.MarkLabel(trueCode);
		il.AddInstruction(il.Jump(il.ConstPointer(addrSize, addrTrue)));
		return;
	}

	/* neither address had a label, create our own */
	il.AddInstruction(il.If(clause, trueCode, falseCode));
	il.MarkLabel(trueCode);
	il.AddInstruction(il.Jump(il.ConstPointer(addrSize, addrTrue)));
	il.MarkLabel(falseCode);
	il.AddInstruction(il.Jump(il.ConstPointer(addrSize, addrFalse)));
}

/* 
	ASSUME: 

	this should work for any conditional, even if the number of operands differ
	eg:
	beqlr <operand0>               where operand0 is what's tested for zero
	beq   <operand0>, <operand1>   where operand0 is what's tested for zero
										 operand1 is the branch destination

	in both cases, operand0 is what's tested for, so we consider it safe to
	generalize here
	
*/
static void conditionExecute(LowLevelILFunction &il, ExprId trueIL0,
  ExprId trueIL1, cs_ppc *ppc)
{
	/* unconditional case */
	if(ppc->bc == PPC_BC_INVALID) {
		il.AddInstruction(trueIL0);
		if(trueIL1 != (ExprId)-1) il.AddInstruction(trueIL1);
		return;
	}

	int lutFlags_cr0[4] = { IL_FLAG_LT,   IL_FLAG_GT,   IL_FLAG_EQ,   IL_FLAG_SO   };
	int lutFlags_cr1[4] = { IL_FLAG_LT_1, IL_FLAG_GT_1, IL_FLAG_EQ_1, IL_FLAG_SO_1 };
	int lutFlags_cr2[4] = { IL_FLAG_LT_2, IL_FLAG_GT_2, IL_FLAG_EQ_2, IL_FLAG_SO_2 };
	int lutFlags_cr3[4] = { IL_FLAG_LT_3, IL_FLAG_GT_3, IL_FLAG_EQ_3, IL_FLAG_SO_3 };
	int lutFlags_cr4[4] = { IL_FLAG_LT_4, IL_FLAG_GT_4, IL_FLAG_EQ_4, IL_FLAG_SO_4 };
	int lutFlags_cr5[4] = { IL_FLAG_LT_5, IL_FLAG_GT_5, IL_FLAG_EQ_5, IL_FLAG_SO_5 };
	int lutFlags_cr6[4] = { IL_FLAG_LT_6, IL_FLAG_GT_6, IL_FLAG_EQ_6, IL_FLAG_SO_6 };
	int lutFlags_cr7[4] = { IL_FLAG_LT_7, IL_FLAG_GT_7, IL_FLAG_EQ_7, IL_FLAG_SO_7 };

	/* we're conditional now - the question is just which of the cr0..cr7 do
		we read the flags from? */

	int *lutFlags = lutFlags_cr0;

	if(ppc->op_count >= 1 && ppc->operands[0].type == PPC_OP_REG) {
		switch(ppc->operands[0].reg) {
			case PPC_REG_CR1:
				lutFlags = lutFlags_cr1;
				break;
			case PPC_REG_CR2:
				lutFlags = lutFlags_cr2;
				break;
			case PPC_REG_CR3:
				lutFlags = lutFlags_cr3;
				break;
			case PPC_REG_CR4:
				lutFlags = lutFlags_cr4;
				break;
			case PPC_REG_CR5:
				lutFlags = lutFlags_cr5;
				break;
			case PPC_REG_CR6:
				lutFlags = lutFlags_cr6;
				break;
			case PPC_REG_CR7:
				lutFlags = lutFlags_cr7;
				break;
			default:
				MYLOG("ERROR: expected CRX register, got: %d\n", ppc->operands[0].reg);
				break;
		}
	}

	// TODO: get sign-sensitivity right
	// conditional branches simply look at the flags bits
	// cmp vs. cmpl does signed vs. unsigned
	/* if statement */
	LowLevelILLabel trueLabel, falseLabel;
	ExprId clause = il.FlagCondition(bc2fc(ppc->bc));
	il.AddInstruction(il.If(clause, trueLabel, falseLabel));
	/* true clause */
	il.MarkLabel(trueLabel);
	il.AddInstruction(trueIL0);
	if(trueIL1 != (ExprId)-1) il.AddInstruction(trueIL1);
	il.AddInstruction(il.Goto(falseLabel));
	/* false clause */
	il.MarkLabel(falseLabel);
	return;
}

/* map PPC_REG_CRX to an IL flagwrite type (a named set of written flags */
int crxToFlagWriteType(int crx)
{
	/* temporary: no matter what the crx, just pretend it writes a global
		gt, lt, eq flags */
	return IL_FLAGWRITE_SET4;	

	/* when we have more flags... */
	switch(crx)
	{
		case PPC_REG_CR0:
			return IL_FLAGWRITE_CR0;
		case PPC_REG_CR1:
			return IL_FLAGWRITE_CR1;
		case PPC_REG_CR2:
			return IL_FLAGWRITE_CR2;
		case PPC_REG_CR3:
			return IL_FLAGWRITE_CR3;
		case PPC_REG_CR4:
			return IL_FLAGWRITE_CR4;
		case PPC_REG_CR5:
			return IL_FLAGWRITE_CR5;
		case PPC_REG_CR6:
			return IL_FLAGWRITE_CR6;
		case PPC_REG_CR7:
			return IL_FLAGWRITE_CR7;
		default:
			return 0;
	}
}

/* returns	TRUE - if this IL continues
			FALSE - if this IL terminates a block */
bool GetLowLevelILForPPCInstruction(Architecture *arch, LowLevelILFunction &il,
  const uint8_t* data, uint64_t addr, decomp_result *res)
{
	int i;
	bool rc = true;

	struct cs_insn *insn = &(res->insn);
	struct cs_detail *detail = &(res->detail);
	struct cs_ppc *ppc = &(detail->ppc);

	/* create convenient access to instruction operands */
	int crx = PPC_REG_INVALID;
	cs_ppc_op *oper0=NULL, *oper1=NULL, *oper2=NULL, *oper3=NULL;

	switch(ppc->op_count) {
		default:
		case 4: oper3 = &(ppc->operands[3]);
		case 3: oper2 = &(ppc->operands[2]);
		case 2: oper1 = &(ppc->operands[1]);
		case 1: oper0 = &(ppc->operands[0]);
		case 0: while(0);
	}

	/* for conditionals that specify a crx, treat it special */
	if(ppc->bc != PPC_BC_INVALID) {
		if(oper0 && oper0->type == PPC_OP_REG && oper0->reg >= PPC_REG_CR0 && 
		  ppc->operands[0].reg <= PPC_REG_CR7) {
	
			crx = oper0->reg;
			oper0 = oper1;
			oper1 = oper2;
			oper2 = oper3;
			oper3 = NULL;
		}
	}

	if(0 && insn->id == PPC_INS_CMPLWI) {
		MYLOG("%s() %08llx: %02X %02X %02X %02X %s %s has %d operands\n",
			__func__, addr, data[0], data[1], data[2], data[3],
			insn->mnemonic, insn->op_str, ppc->op_count
		);
		
		//printInstructionVerbose(res);
		//MYLOG("oper0: %p\n", oper0);
		//MYLOG("oper1: %p\n", oper1);
		//MYLOG("oper2: %p\n", oper2);
		//MYLOG("oper3: %p\n", oper3);
	}

	int flagWriteType = crxToFlagWriteType(crx);

	ExprId ei0, ei1, ei2;	

	switch(insn->id) {
		/* add
			"add." also updates the CR0 bits */
		case PPC_INS_ADD: /* add */
		case PPC_INS_ADDI: /* add immediate, eg: addi rD, rA, <imm> */
			ei0 = il.Add(4, operToIL(il, oper1), operToIL(il, oper2));	//
			ei0 = il.SetRegister(4, oper0->reg, ei0);					//
			il.AddInstruction(ei0);
			break;
			
		case PPC_INS_ADDE: /* add, extended (+ carry flag) */
			ei0 = il.AddCarry(
			  4, 
			  operToIL(il, oper1), 
			  operToIL(il, oper2),
			  il.Flag(IL_FLAG_XER_CA),
			  0
			);
			ei0 = il.SetRegister(4, oper0->reg, ei0);
			il.AddInstruction(ei0);
			break;

		case PPC_INS_ADDC: /* add, carrying */
		case PPC_INS_ADDIC: /* add immediate, carrying */
			ei0 = il.AddCarry(
			  4, 
			  operToIL(il, oper1), 
			  operToIL(il, oper2),
			  il.Flag(IL_FLAG_XER_CA),
			  0
			);
			ei0 = il.SetRegister(4, oper0->reg, ei0);
			il.AddInstruction(ei0);
			break;
	
//		case PPC_INS_ADDIS: // add immediate, shifted
//			ei0 = il.Const(16, 0);								//                SIMM
//			ei0 = il.ShiftLeft(32, il.Const(4,oper2->imm), ei0, 0);			//                SIMM || 0x0000
//			ei0 = il.SignExtend(32, ei0, 0);					//           EXTS(SIMM || 0x0000)
//			ei0 = il.Add(4, il.Register(4, oper1->reg), ei0);	//      rA + EXTS(SIMM || 0x0000)
//			ei0 = il.SetRegister(4, oper0->reg, ei0);			// rD = rA + EXTS(SIMM || 0x0000)
//			il.AddInstruction(ei0);
//			break;	

		case PPC_INS_LIS: /* load immediate, shifted */
			ei0 = il.SetRegister(4, 
				oper0->reg, 
				il.Const(4, oper1->imm << 16));
			il.AddInstruction(ei0);
			break;

		case PPC_INS_LI: /* load immediate */
		case PPC_INS_LA: /* load displacement */
			il.AddInstruction(il.SetRegister(4, oper0->reg, operToIL(il, oper1)));
			break;

		/* WARNING! when address mode is relative, capstone will return an
			immediate whose value is NOT the actual operand, but the calculated
			absolute address (from the address that capstone was asked to
			disassemble plus the displacement) */
		case PPC_INS_B: /* or BEQ, BLT, BGT */
		case PPC_INS_BA:
			ConditionalJump(arch, il, ppc->bc, 4, oper0->imm, addr + 4);
			rc = false;
			break;

		/*
			branch [CTR conditional, to ctr [, and link]]

			these conditions are the CTR ones (decrement, then test, etc.)
			TODO
		*/
		case PPC_INS_BC:
		case PPC_INS_BCCTR:
			rc = false;
		case PPC_INS_BCCTRL:
			if(ppc->op_count == 1)
				ei0 = operToIL(il, oper0);		//            EffAddr
			else
				ei0 = operToIL(il, oper1);		//            EffAddr

			break;

		/*
			branch (unconditional) to ctr [and link]
		*/
		case PPC_INS_BCTR: /* branch to counter */
			rc = false;
		case PPC_INS_BCTRL: /* branch to counter, link */
			if(insn->id == PPC_INS_BCTRL)
				il.AddInstruction(il.SetRegister(4, PPC_REG_LR, il.ConstPointer(4, addr+4)));

			il.AddInstruction(il.Jump(il.Register(4, PPC_REG_CTR)));
			break;

		// KEY:
		// {BD}      = {"branch, decrement ctr"}
		// {NZ, Z}   = {"when not zero", "when zero"}
		// {T, F}    = {"and condition true", "and condition false"}
		// {, A, LR} = {"relative", "absolute", "link reg"}
		// {L}       = {"and link"}
		// condition codes NOT affected
//		case PPC_INS_BDNZ:
//		case PPC_INS_BDNZA:
//		case PPC_INS_BDNZL:
//		case PPC_INS_BDNZLA:
//		case PPC_INS_BDNZLR:
//		case PPC_INS_BDNZLRL:
//		case PPC_INS_BDZ:
//		case PPC_INS_BDZA:
//		case PPC_INS_BDZL:
//		case PPC_INS_BDZLA:
//		case PPC_INS_BDZLR:
//		case PPC_INS_BDZLRL:
//		{
//			LowLevelILLabel trueLabel, falseLabel;
//
//			/* everything decrements ctr */
//			ei0 = il.SetRegister(4, PPC_REG_CTR,
//				il.Sub(4,
//					il.Register(4, PPC_REG_CTR),
//					il.Const(4, 1)
//				)
//			);
//
//			il.AddInstruction(ei0);
//		
//			/* compare ctr to zero, or not zero */
//			switch(insn->id) {
//				case PPC_INS_BDNZ:
//				case PPC_INS_BDNZA:
//				case PPC_INS_BDNZL:
//				case PPC_INS_BDNZLA:
//				case PPC_INS_BDNZLR:
//				case PPC_INS_BDNZLRL:
//					ei0 = il.CompareNotEqual(4,
//						il.Register(4, PPC_REG_CTR), 
//						il.Const(4, 1),
//						trueLabel, falseLabel
//					);
//					break;
//
//				default:
//					ei0 = il.CompareEqual(4,
//						il.Register(4, PPC_REG_CTR), 
//						il.Const(4, 1),
//						trueLabel, falseLabel
//					);
//			}
//
//			/* if comparison true */
//			il.MarkLabel(trueLabel);
//
//			/* type of addressing*/
//			switch(insn->id) {
//				/* relative */
//				case PPC_INS_BDNZ:
//				case PPC_INS_BDZ:
//				case PPC_INS_BDNZL:
//				case PPC_INS_BDZL:
//
//				/* absolute */
//				case PPC_INS_BDNZA:
//				case PPC_INS_BDNZLA:
//				case PPC_INS_BDZA:
//				case PPC_INS_BDZLA:
//					il.AddInstruction(il.Jump(operToIL(il, oper0)));
//					break;
//
//				/* to LR */
//				case PPC_INS_BDNZLR:
//				case PPC_INS_BDNZLRL:
//				case PPC_INS_BDZLR:
//				case PPC_INS_BDZLRL:
//			
//					ei0 = il.CompareNotEqual(4,
//						il.Register(4, PPC_REG_CTR), 
//						il.Const(4, 1),
//						trueLabel, falseLabel
//					);
//					il.AddInstruction(ei0);
//					il.
//					break;
//
//				default:
//					ei0 = il.CompareEqual(4,
//						il.Register(4, PPC_REG_CTR), 
//						il.Const(4, 1),
//						trueLabel, falseLabel
//					);
//			}
//
//			/* false? skip down here */
//			il.MarkLabel(falseLabel);	
//		}

		/* capstone makes the oper0 into abs address, no need to add displacement */
		case PPC_INS_BLA: /* branch, link (absolute) */
		case PPC_INS_BL: /* branch, link */
			ei0 = il.Call(operToIL(il, oper0, OTI_IMM_CPTR));
			conditionExecute(il, ei0, -1, ppc);
			rc = false;
			break;

		case PPC_INS_BLRL: /* branch to LR, link */
			ei0 = il.Call(il.Register(4, PPC_REG_LR));
			conditionExecute(il, ei0, -1, ppc);
			rc = false;
			break;

		case PPC_INS_BLR: /* branch to LR */
			ei0 = il.Call(il.Register(4, PPC_REG_R31));
			conditionExecute(il, ei0, -1, ppc);
			rc = false;
			break;

		case PPC_INS_CMPW: /* compare (signed) word(32-bit) */
			ei0 = operToIL(il, oper0);
			ei1 = operToIL(il, oper1, OTI_SEXT32_REGS);
			ei2 = il.Sub(4, ei0, ei1, flagWriteType);	
			il.AddInstruction(ei2);
			break;

		case PPC_INS_CMPLW: /* compare logical(unsigned) word(32-bit) */
			ei0 = operToIL(il, oper0);
			ei1 = operToIL(il, oper1, OTI_ZEXT32_REGS);
			ei2 = il.Sub(4, ei0, ei1, flagWriteType);	
			il.AddInstruction(ei2);
			break;

		case PPC_INS_CMPD: /* compare (signed) d-word(64-bit) */
			ei0 = operToIL(il, oper0);
			ei1 = operToIL(il, oper1, OTI_SEXT64_REGS);
			ei2 = il.Sub(4, ei0, ei1, flagWriteType);	
			il.AddInstruction(ei2);
			break;

		case PPC_INS_CMPLD: /* compare logical(unsigned) d-word(64-bit) */
			ei0 = operToIL(il, oper0);
			ei1 = operToIL(il, oper1, OTI_ZEXT64_REGS);
			ei2 = il.Sub(4, ei0, ei1, flagWriteType);	
			il.AddInstruction(ei2);
			break;

		case PPC_INS_CMPWI: /* compare (signed) word(32-bit) immediate */
			ei0 = operToIL(il, oper0);
			ei1 = operToIL(il, oper1, OTI_SEXT32_IMMS);
			ei2 = il.Sub(4, ei0, ei1, flagWriteType);	
			il.AddInstruction(ei2);
			break;

		/* should we model this as a subtract that sets flags? (like x86 compare?)
			or like an assignment to a crX field in CR? */
		case PPC_INS_CMPLWI: /* compare logical(unsigned) word(32-bit) immediate */
			/* eg: cmplwi cr7, r9, 0x3c */
			ei0 = operToIL(il, oper1);
			ei1 = operToIL(il, oper2, OTI_ZEXT32_IMMS);
			ei2 = il.Sub(4, ei0, ei1, IL_FLAGWRITE_SET4);	
			il.AddInstruction(ei2);
			break;

		case PPC_INS_CMPDI: /* compare (signed) d-word(64-bit) immediate */
			ei0 = operToIL(il, oper0);
			ei1 = operToIL(il, oper1, OTI_SEXT64_IMMS);
			ei2 = il.Sub(4, ei0, ei1, flagWriteType);	
			il.AddInstruction(ei2);
			break;

		case PPC_INS_CMPLDI: /* compare logical(unsigned) d-word(64-bit) immediate */
			ei0 = operToIL(il, oper0);
			ei1 = operToIL(il, oper1, OTI_ZEXT64_IMMS);
			ei2 = il.Sub(4, ei0, ei1, flagWriteType);	
			il.AddInstruction(ei2);
			break;

		case PPC_INS_LMW:
			for(i=oper0->reg; i<=PPC_REG_R31; ++i) {
				ei0 = il.SetRegister(4,
					i,					// dest
					il.Load(4,			// source
						operToIL(il, oper1, OTI_IMM_BIAS, (i-(oper0->reg))*4)
					)
				);

				il.AddInstruction(ei0);
			}

			break;

		/*
			load word [and zero] [and update]
		*/
		case PPC_INS_LWZ:
		case PPC_INS_LWZU:
			ei0 = operToIL(il, oper1);						//       d(rA)
			ei0 = il.Load(4, ei0);							//      [d(rA)]
			ei0 = il.SetRegister(4, oper0->reg, ei0);		// rD = [d(rA)]
			il.AddInstruction(ei0);

			// if update, rA is set to effective address (d(rA))
			if(insn->id == PPC_INS_LWZU) {
				ei0 = il.SetRegister(4, oper1->mem.base, operToIL(il, oper1));
				il.AddInstruction(ei0);
			}

			break;

		case PPC_INS_MFLR: // move from link register
			il.AddInstruction(il.SetRegister(4, oper0->reg, il.Register(4, PPC_REG_LR)));
			break;

		case PPC_INS_MTCTR: // move to ctr
			il.AddInstruction(il.SetRegister(4, PPC_REG_CTR, operToIL(il, oper0)));
			break;

		case PPC_INS_MTLR: // move to link register
			il.AddInstruction(il.SetRegister(4, PPC_REG_LR, operToIL(il, oper0)));
			break;

		case PPC_INS_NOP:
			il.AddInstruction(il.Nop());
			break;

		case PPC_INS_ORI:
			ei0 = il.SetRegister(
				4, 
				oper0->reg,
				il.Or(4, 
					operToIL(il, oper1),
					operToIL(il, oper2)
				)
			);

			il.AddInstruction(ei0);
			break;

		case PPC_INS_STMW:
			for(i=oper0->reg; i<=PPC_REG_R31; ++i) {
				ei0 = il.Register(4, i); // source
				ei1 = operToIL(il, oper1, OTI_IMM_BIAS, (i-(oper0->reg))*4);
				il.AddInstruction(
					il.Store(4,
						ei1,
						ei0
					)
				);
			}

			break;

		/* store word with update */
		case PPC_INS_STW:
		case PPC_INS_STWU:
			/* store(size, addr, val) */
			ei0 = il.Store(4, 
				operToIL(il, oper1), 
				operToIL(il, oper0)
			);
			il.AddInstruction(ei0);

			// if update, then rA gets updated address 
			if(insn->id == PPC_INS_STWU) {
				ei0 = il.SetRegister(4, oper0->reg, operToIL(il, oper1));
				il.AddInstruction(ei0);
			}
			
			break;

		case PPC_INS_SLWI:
			if(ppc->op_count != 3) {
				MYLOG("ERROR: SLWI with op count %d\n", ppc->op_count);
				while(1);
			}
			ei0 = il.Const(4, oper2->imm);				// amt: shift amount
			ei1 = il.Register(4, oper1->reg);			//  rS: reg to be shifted
			ei0 = il.ShiftLeft(4, ei1, ei0);			// (rS << amt)
			ei0 = il.SetRegister(4, oper0->reg, ei0);	// rD = (rs << amt)
			il.AddInstruction(ei0);
			break;

		case PPC_INS_MR: /* move register */
			il.AddInstruction(il.SetRegister(4, oper0->reg, operToIL(il, oper1)));
			break;

		case PPC_INS_BCL:
		case PPC_INS_BCLR:
		case PPC_INS_BCLRL:
		case PPC_INS_ADDME:
		case PPC_INS_ADDZE:
		case PPC_INS_AND:
		case PPC_INS_ANDC:
		case PPC_INS_ANDIS:
		case PPC_INS_ANDI:
		case PPC_INS_CNTLZD:
		case PPC_INS_CNTLZW:
		case PPC_INS_CREQV:
		case PPC_INS_CRXOR:
		case PPC_INS_CRAND:
		case PPC_INS_CRANDC:
		case PPC_INS_CRNAND:
		case PPC_INS_CRNOR:
		case PPC_INS_CROR:
		case PPC_INS_CRORC:
		case PPC_INS_DCBA:
		case PPC_INS_DCBF:
		case PPC_INS_DCBI:
		case PPC_INS_DCBST:
		case PPC_INS_DCBT:
		case PPC_INS_DCBTST:
		case PPC_INS_DCBZ:
		case PPC_INS_DCBZL:
		case PPC_INS_DCCCI:
		case PPC_INS_DIVD:
		case PPC_INS_DIVDU:
		case PPC_INS_DIVW:
		case PPC_INS_DIVWU:
		case PPC_INS_DSS:
		case PPC_INS_DSSALL:
		case PPC_INS_DST:
		case PPC_INS_DSTST:
		case PPC_INS_DSTSTT:
		case PPC_INS_DSTT:
		case PPC_INS_EIEIO:
		case PPC_INS_EQV:
		case PPC_INS_EVABS:
		case PPC_INS_EVADDIW:
		case PPC_INS_EVADDSMIAAW:
		case PPC_INS_EVADDSSIAAW:
		case PPC_INS_EVADDUMIAAW:
		case PPC_INS_EVADDUSIAAW:
		case PPC_INS_EVADDW:
		case PPC_INS_EVAND:
		case PPC_INS_EVANDC:
		case PPC_INS_EVCMPEQ:
		case PPC_INS_EVCMPGTS:
		case PPC_INS_EVCMPGTU:
		case PPC_INS_EVCMPLTS:
		case PPC_INS_EVCMPLTU:
		case PPC_INS_EVCNTLSW:
		case PPC_INS_EVCNTLZW:
		case PPC_INS_EVDIVWS:
		case PPC_INS_EVDIVWU:
		case PPC_INS_EVEQV:
		case PPC_INS_EVEXTSB:
		case PPC_INS_EVEXTSH:
		case PPC_INS_EVLDD:
		case PPC_INS_EVLDDX:
		case PPC_INS_EVLDH:
		case PPC_INS_EVLDHX:
		case PPC_INS_EVLDW:
		case PPC_INS_EVLDWX:
		case PPC_INS_EVLHHESPLAT:
		case PPC_INS_EVLHHESPLATX:
		case PPC_INS_EVLHHOSSPLAT:
		case PPC_INS_EVLHHOSSPLATX:
		case PPC_INS_EVLHHOUSPLAT:
		case PPC_INS_EVLHHOUSPLATX:
		case PPC_INS_EVLWHE:
		case PPC_INS_EVLWHEX:
		case PPC_INS_EVLWHOS:
		case PPC_INS_EVLWHOSX:
		case PPC_INS_EVLWHOU:
		case PPC_INS_EVLWHOUX:
		case PPC_INS_EVLWHSPLAT:
		case PPC_INS_EVLWHSPLATX:
		case PPC_INS_EVLWWSPLAT:
		case PPC_INS_EVLWWSPLATX:
		case PPC_INS_EVMERGEHI:
		case PPC_INS_EVMERGEHILO:
		case PPC_INS_EVMERGELO:
		case PPC_INS_EVMERGELOHI:
		case PPC_INS_EVMHEGSMFAA:
		case PPC_INS_EVMHEGSMFAN:
		case PPC_INS_EVMHEGSMIAA:
		case PPC_INS_EVMHEGSMIAN:
		case PPC_INS_EVMHEGUMIAA:
		case PPC_INS_EVMHEGUMIAN:
		case PPC_INS_EVMHESMF:
		case PPC_INS_EVMHESMFA:
		case PPC_INS_EVMHESMFAAW:
		case PPC_INS_EVMHESMFANW:
		case PPC_INS_EVMHESMI:
		case PPC_INS_EVMHESMIA:
		case PPC_INS_EVMHESMIAAW:
		case PPC_INS_EVMHESMIANW:
		case PPC_INS_EVMHESSF:
		case PPC_INS_EVMHESSFA:
		case PPC_INS_EVMHESSFAAW:
		case PPC_INS_EVMHESSFANW:
		case PPC_INS_EVMHESSIAAW:
		case PPC_INS_EVMHESSIANW:
		case PPC_INS_EVMHEUMI:
		case PPC_INS_EVMHEUMIA:
		case PPC_INS_EVMHEUMIAAW:
		case PPC_INS_EVMHEUMIANW:
		case PPC_INS_EVMHEUSIAAW:
		case PPC_INS_EVMHEUSIANW:
		case PPC_INS_EVMHOGSMFAA:
		case PPC_INS_EVMHOGSMFAN:
		case PPC_INS_EVMHOGSMIAA:
		case PPC_INS_EVMHOGSMIAN:
		case PPC_INS_EVMHOGUMIAA:
		case PPC_INS_EVMHOGUMIAN:
		case PPC_INS_EVMHOSMF:
		case PPC_INS_EVMHOSMFA:
		case PPC_INS_EVMHOSMFAAW:
		case PPC_INS_EVMHOSMFANW:
		case PPC_INS_EVMHOSMI:
		case PPC_INS_EVMHOSMIA:
		case PPC_INS_EVMHOSMIAAW:
		case PPC_INS_EVMHOSMIANW:
		case PPC_INS_EVMHOSSF:
		case PPC_INS_EVMHOSSFA:
		case PPC_INS_EVMHOSSFAAW:
		case PPC_INS_EVMHOSSFANW:
		case PPC_INS_EVMHOSSIAAW:
		case PPC_INS_EVMHOSSIANW:
		case PPC_INS_EVMHOUMI:
		case PPC_INS_EVMHOUMIA:
		case PPC_INS_EVMHOUMIAAW:
		case PPC_INS_EVMHOUMIANW:
		case PPC_INS_EVMHOUSIAAW:
		case PPC_INS_EVMHOUSIANW:
		case PPC_INS_EVMRA:
		case PPC_INS_EVMWHSMF:
		case PPC_INS_EVMWHSMFA:
		case PPC_INS_EVMWHSMI:
		case PPC_INS_EVMWHSMIA:
		case PPC_INS_EVMWHSSF:
		case PPC_INS_EVMWHSSFA:
		case PPC_INS_EVMWHUMI:
		case PPC_INS_EVMWHUMIA:
		case PPC_INS_EVMWLSMIAAW:
		case PPC_INS_EVMWLSMIANW:
		case PPC_INS_EVMWLSSIAAW:
		case PPC_INS_EVMWLSSIANW:
		case PPC_INS_EVMWLUMI:
		case PPC_INS_EVMWLUMIA:
		case PPC_INS_EVMWLUMIAAW:
		case PPC_INS_EVMWLUMIANW:
		case PPC_INS_EVMWLUSIAAW:
		case PPC_INS_EVMWLUSIANW:
		case PPC_INS_EVMWSMF:
		case PPC_INS_EVMWSMFA:
		case PPC_INS_EVMWSMFAA:
		case PPC_INS_EVMWSMFAN:
		case PPC_INS_EVMWSMI:
		case PPC_INS_EVMWSMIA:
		case PPC_INS_EVMWSMIAA:
		case PPC_INS_EVMWSMIAN:
		case PPC_INS_EVMWSSF:
		case PPC_INS_EVMWSSFA:
		case PPC_INS_EVMWSSFAA:
		case PPC_INS_EVMWSSFAN:
		case PPC_INS_EVMWUMI:
		case PPC_INS_EVMWUMIA:
		case PPC_INS_EVMWUMIAA:
		case PPC_INS_EVMWUMIAN:
		case PPC_INS_EVNAND:
		case PPC_INS_EVNEG:
		case PPC_INS_EVNOR:
		case PPC_INS_EVOR:
		case PPC_INS_EVORC:
		case PPC_INS_EVRLW:
		case PPC_INS_EVRLWI:
		case PPC_INS_EVRNDW:
		case PPC_INS_EVSLW:
		case PPC_INS_EVSLWI:
		case PPC_INS_EVSPLATFI:
		case PPC_INS_EVSPLATI:
		case PPC_INS_EVSRWIS:
		case PPC_INS_EVSRWIU:
		case PPC_INS_EVSRWS:
		case PPC_INS_EVSRWU:
		case PPC_INS_EVSTDD:
		case PPC_INS_EVSTDDX:
		case PPC_INS_EVSTDH:
		case PPC_INS_EVSTDHX:
		case PPC_INS_EVSTDW:
		case PPC_INS_EVSTDWX:
		case PPC_INS_EVSTWHE:
		case PPC_INS_EVSTWHEX:
		case PPC_INS_EVSTWHO:
		case PPC_INS_EVSTWHOX:
		case PPC_INS_EVSTWWE:
		case PPC_INS_EVSTWWEX:
		case PPC_INS_EVSTWWO:
		case PPC_INS_EVSTWWOX:
		case PPC_INS_EVSUBFSMIAAW:
		case PPC_INS_EVSUBFSSIAAW:
		case PPC_INS_EVSUBFUMIAAW:
		case PPC_INS_EVSUBFUSIAAW:
		case PPC_INS_EVSUBFW:
		case PPC_INS_EVSUBIFW:
		case PPC_INS_EVXOR:
		case PPC_INS_EXTSB:
		case PPC_INS_EXTSH:
		case PPC_INS_EXTSW:
		case PPC_INS_FABS:
		case PPC_INS_FADD:
		case PPC_INS_FADDS:
		case PPC_INS_FCFID:
		case PPC_INS_FCFIDS:
		case PPC_INS_FCFIDU:
		case PPC_INS_FCFIDUS:
		case PPC_INS_FCMPU:
		case PPC_INS_FCPSGN:
		case PPC_INS_FCTID:
		case PPC_INS_FCTIDUZ:
		case PPC_INS_FCTIDZ:
		case PPC_INS_FCTIW:
		case PPC_INS_FCTIWUZ:
		case PPC_INS_FCTIWZ:
		case PPC_INS_FDIV:
		case PPC_INS_FDIVS:
		case PPC_INS_FMADD:
		case PPC_INS_FMADDS:
		case PPC_INS_FMR:
		case PPC_INS_FMSUB:
		case PPC_INS_FMSUBS:
		case PPC_INS_FMUL:
		case PPC_INS_FMULS:
		case PPC_INS_FNABS:
		case PPC_INS_FNEG:
		case PPC_INS_FNMADD:
		case PPC_INS_FNMADDS:
		case PPC_INS_FNMSUB:
		case PPC_INS_FNMSUBS:
		case PPC_INS_FRE:
		case PPC_INS_FRES:
		case PPC_INS_FRIM:
		case PPC_INS_FRIN:
		case PPC_INS_FRIP:
		case PPC_INS_FRIZ:
		case PPC_INS_FRSP:
		case PPC_INS_FRSQRTE:
		case PPC_INS_FRSQRTES:
		case PPC_INS_FSEL:
		case PPC_INS_FSQRT:
		case PPC_INS_FSQRTS:
		case PPC_INS_FSUB:
		case PPC_INS_FSUBS:
		case PPC_INS_ICBI:
		case PPC_INS_ICCCI:
		case PPC_INS_ISEL:
		case PPC_INS_ISYNC:
		case PPC_INS_LBZ:
		case PPC_INS_LBZU:
		case PPC_INS_LBZUX:
		case PPC_INS_LBZX:
		case PPC_INS_LD:
		case PPC_INS_LDARX:
		case PPC_INS_LDBRX:
		case PPC_INS_LDU:
		case PPC_INS_LDUX:
		case PPC_INS_LDX:
		case PPC_INS_LFD:
		case PPC_INS_LFDU:
		case PPC_INS_LFDUX:
		case PPC_INS_LFDX:
		case PPC_INS_LFIWAX:
		case PPC_INS_LFIWZX:
		case PPC_INS_LFS:
		case PPC_INS_LFSU:
		case PPC_INS_LFSUX:
		case PPC_INS_LFSX:
		case PPC_INS_LHA:
		case PPC_INS_LHAU:
		case PPC_INS_LHAUX:
		case PPC_INS_LHAX:
		case PPC_INS_LHBRX:
		case PPC_INS_LHZ:
		case PPC_INS_LHZU:
		case PPC_INS_LHZUX:
		case PPC_INS_LHZX:
		case PPC_INS_LSWI:
		case PPC_INS_LVEBX:
		case PPC_INS_LVEHX:
		case PPC_INS_LVEWX:
		case PPC_INS_LVSL:
		case PPC_INS_LVSR:
		case PPC_INS_LVX:
		case PPC_INS_LVXL:
		case PPC_INS_LWA:
		case PPC_INS_LWARX:
		case PPC_INS_LWAUX:
		case PPC_INS_LWAX:
		case PPC_INS_LWBRX:
		case PPC_INS_LWZUX:
		case PPC_INS_LWZX:
		case PPC_INS_LXSDX:
		case PPC_INS_LXVD2X:
		case PPC_INS_LXVDSX:
		case PPC_INS_LXVW4X:
		case PPC_INS_MBAR:
		case PPC_INS_MCRF:
		case PPC_INS_MFCR:
		case PPC_INS_MFCTR:
		case PPC_INS_MFDCR:
		case PPC_INS_MFFS:
		case PPC_INS_MFMSR:
		case PPC_INS_MFOCRF:
		case PPC_INS_MFSPR:
		case PPC_INS_MFSR:
		case PPC_INS_MFSRIN:
		case PPC_INS_MFTB:
		case PPC_INS_MFVSCR:
		case PPC_INS_MSYNC:
		case PPC_INS_MTCRF:
		case PPC_INS_MTDCR:
		case PPC_INS_MTFSB0:
		case PPC_INS_MTFSB1:
		case PPC_INS_MTFSF:
		case PPC_INS_MTMSR:
		case PPC_INS_MTMSRD:
		case PPC_INS_MTOCRF:
		case PPC_INS_MTSPR:
		case PPC_INS_MTSR:
		case PPC_INS_MTSRIN:
		case PPC_INS_MTVSCR:
		case PPC_INS_MULHD:
		case PPC_INS_MULHDU:
		case PPC_INS_MULHW:
		case PPC_INS_MULHWU:
		case PPC_INS_MULLD:
		case PPC_INS_MULLI:
		case PPC_INS_MULLW:
		case PPC_INS_NAND:
		case PPC_INS_NEG:
		case PPC_INS_NOR:
		case PPC_INS_OR:
		case PPC_INS_ORC:
		case PPC_INS_ORIS:
		case PPC_INS_POPCNTD:
		case PPC_INS_POPCNTW:
		case PPC_INS_RFCI:
		case PPC_INS_RFDI:
		case PPC_INS_RFI:
		case PPC_INS_RFID:
		case PPC_INS_RFMCI:
		case PPC_INS_RLDCL:
		case PPC_INS_RLDCR:
		case PPC_INS_RLDIC:
		case PPC_INS_RLDICL:
		case PPC_INS_RLDICR:
		case PPC_INS_RLDIMI:
		case PPC_INS_RLWIMI:
		case PPC_INS_RLWINM:
		case PPC_INS_RLWNM:
		case PPC_INS_SC:
		case PPC_INS_SLBIA:
		case PPC_INS_SLBIE:
		case PPC_INS_SLBMFEE:
		case PPC_INS_SLBMTE:
		case PPC_INS_SLD:
		case PPC_INS_SLW:
		case PPC_INS_SRAD:
		case PPC_INS_SRADI:
		case PPC_INS_SRAW:
		case PPC_INS_SRAWI:
		case PPC_INS_SRD:
		case PPC_INS_SRW:
		case PPC_INS_STB:
		case PPC_INS_STBU:
		case PPC_INS_STBUX:
		case PPC_INS_STBX:
		case PPC_INS_STD:
		case PPC_INS_STDBRX:
		case PPC_INS_STDCX:
		case PPC_INS_STDU:
		case PPC_INS_STDUX:
		case PPC_INS_STDX:
		case PPC_INS_STFD:
		case PPC_INS_STFDU:
		case PPC_INS_STFDUX:
		case PPC_INS_STFDX:
		case PPC_INS_STFIWX:
		case PPC_INS_STFS:
		case PPC_INS_STFSU:
		case PPC_INS_STFSUX:
		case PPC_INS_STFSX:
		case PPC_INS_STH:
		case PPC_INS_STHBRX:
		case PPC_INS_STHU:
		case PPC_INS_STHUX:
		case PPC_INS_STHX:
		case PPC_INS_STSWI:
		case PPC_INS_STVEBX:
		case PPC_INS_STVEHX:
		case PPC_INS_STVEWX:
		case PPC_INS_STVX:
		case PPC_INS_STVXL:
		case PPC_INS_STWBRX:
		case PPC_INS_STWCX:
		case PPC_INS_STWUX:
		case PPC_INS_STWX:
		case PPC_INS_STXSDX:
		case PPC_INS_STXVD2X:
		case PPC_INS_STXVW4X:
		case PPC_INS_SUBF:
		case PPC_INS_SUBFC:
		case PPC_INS_SUBFE:
		case PPC_INS_SUBFIC:
		case PPC_INS_SUBFME:
		case PPC_INS_SUBFZE:
		case PPC_INS_SYNC:
		case PPC_INS_TD:
		case PPC_INS_TDI:
		case PPC_INS_TLBIA:
		case PPC_INS_TLBIE:
		case PPC_INS_TLBIEL:
		case PPC_INS_TLBIVAX:
		case PPC_INS_TLBLD:
		case PPC_INS_TLBLI:
		case PPC_INS_TLBRE:
		case PPC_INS_TLBSX:
		case PPC_INS_TLBSYNC:
		case PPC_INS_TLBWE:
		case PPC_INS_TRAP:
		case PPC_INS_TW:
		case PPC_INS_TWI:
		case PPC_INS_VADDCUW:
		case PPC_INS_VADDFP:
		case PPC_INS_VADDSBS:
		case PPC_INS_VADDSHS:
		case PPC_INS_VADDSWS:
		case PPC_INS_VADDUBM:
		case PPC_INS_VADDUBS:
		case PPC_INS_VADDUHM:
		case PPC_INS_VADDUHS:
		case PPC_INS_VADDUWM:
		case PPC_INS_VADDUWS:
		case PPC_INS_VAND:
		case PPC_INS_VANDC:
		case PPC_INS_VAVGSB:
		case PPC_INS_VAVGSH:
		case PPC_INS_VAVGSW:
		case PPC_INS_VAVGUB:
		case PPC_INS_VAVGUH:
		case PPC_INS_VAVGUW:
		case PPC_INS_VCFSX:
		case PPC_INS_VCFUX:
		case PPC_INS_VCMPBFP:
		case PPC_INS_VCMPEQFP:
		case PPC_INS_VCMPEQUB:
		case PPC_INS_VCMPEQUH:
		case PPC_INS_VCMPEQUW:
		case PPC_INS_VCMPGEFP:
		case PPC_INS_VCMPGTFP:
		case PPC_INS_VCMPGTSB:
		case PPC_INS_VCMPGTSH:
		case PPC_INS_VCMPGTSW:
		case PPC_INS_VCMPGTUB:
		case PPC_INS_VCMPGTUH:
		case PPC_INS_VCMPGTUW:
		case PPC_INS_VCTSXS:
		case PPC_INS_VCTUXS:
		case PPC_INS_VEXPTEFP:
		case PPC_INS_VLOGEFP:
		case PPC_INS_VMADDFP:
		case PPC_INS_VMAXFP:
		case PPC_INS_VMAXSB:
		case PPC_INS_VMAXSH:
		case PPC_INS_VMAXSW:
		case PPC_INS_VMAXUB:
		case PPC_INS_VMAXUH:
		case PPC_INS_VMAXUW:
		case PPC_INS_VMHADDSHS:
		case PPC_INS_VMHRADDSHS:
		case PPC_INS_VMINFP:
		case PPC_INS_VMINSB:
		case PPC_INS_VMINSH:
		case PPC_INS_VMINSW:
		case PPC_INS_VMINUB:
		case PPC_INS_VMINUH:
		case PPC_INS_VMINUW:
		case PPC_INS_VMLADDUHM:
		case PPC_INS_VMRGHB:
		case PPC_INS_VMRGHH:
		case PPC_INS_VMRGHW:
		case PPC_INS_VMRGLB:
		case PPC_INS_VMRGLH:
		case PPC_INS_VMRGLW:
		case PPC_INS_VMSUMMBM:
		case PPC_INS_VMSUMSHM:
		case PPC_INS_VMSUMSHS:
		case PPC_INS_VMSUMUBM:
		case PPC_INS_VMSUMUHM:
		case PPC_INS_VMSUMUHS:
		case PPC_INS_VMULESB:
		case PPC_INS_VMULESH:
		case PPC_INS_VMULEUB:
		case PPC_INS_VMULEUH:
		case PPC_INS_VMULOSB:
		case PPC_INS_VMULOSH:
		case PPC_INS_VMULOUB:
		case PPC_INS_VMULOUH:
		case PPC_INS_VNMSUBFP:
		case PPC_INS_VNOR:
		case PPC_INS_VOR:
		case PPC_INS_VPERM:
		case PPC_INS_VPKPX:
		case PPC_INS_VPKSHSS:
		case PPC_INS_VPKSHUS:
		case PPC_INS_VPKSWSS:
		case PPC_INS_VPKSWUS:
		case PPC_INS_VPKUHUM:
		case PPC_INS_VPKUHUS:
		case PPC_INS_VPKUWUM:
		case PPC_INS_VPKUWUS:
		case PPC_INS_VREFP:
		case PPC_INS_VRFIM:
		case PPC_INS_VRFIN:
		case PPC_INS_VRFIP:
		case PPC_INS_VRFIZ:
		case PPC_INS_VRLB:
		case PPC_INS_VRLH:
		case PPC_INS_VRLW:
		case PPC_INS_VRSQRTEFP:
		case PPC_INS_VSEL:
		case PPC_INS_VSL:
		case PPC_INS_VSLB:
		case PPC_INS_VSLDOI:
		case PPC_INS_VSLH:
		case PPC_INS_VSLO:
		case PPC_INS_VSLW:
		case PPC_INS_VSPLTB:
		case PPC_INS_VSPLTH:
		case PPC_INS_VSPLTISB:
		case PPC_INS_VSPLTISH:
		case PPC_INS_VSPLTISW:
		case PPC_INS_VSPLTW:
		case PPC_INS_VSR:
		case PPC_INS_VSRAB:
		case PPC_INS_VSRAH:
		case PPC_INS_VSRAW:
		case PPC_INS_VSRB:
		case PPC_INS_VSRH:
		case PPC_INS_VSRO:
		case PPC_INS_VSRW:
		case PPC_INS_VSUBCUW:
		case PPC_INS_VSUBFP:
		case PPC_INS_VSUBSBS:
		case PPC_INS_VSUBSHS:
		case PPC_INS_VSUBSWS:
		case PPC_INS_VSUBUBM:
		case PPC_INS_VSUBUBS:
		case PPC_INS_VSUBUHM:
		case PPC_INS_VSUBUHS:
		case PPC_INS_VSUBUWM:
		case PPC_INS_VSUBUWS:
		case PPC_INS_VSUM2SWS:
		case PPC_INS_VSUM4SBS:
		case PPC_INS_VSUM4SHS:
		case PPC_INS_VSUM4UBS:
		case PPC_INS_VSUMSWS:
		case PPC_INS_VUPKHPX:
		case PPC_INS_VUPKHSB:
		case PPC_INS_VUPKHSH:
		case PPC_INS_VUPKLPX:
		case PPC_INS_VUPKLSB:
		case PPC_INS_VUPKLSH:
		case PPC_INS_VXOR:
		case PPC_INS_WAIT:
		case PPC_INS_WRTEE:
		case PPC_INS_WRTEEI:
		case PPC_INS_XOR:
		case PPC_INS_XORI:
		case PPC_INS_XORIS:
		case PPC_INS_XSABSDP:
		case PPC_INS_XSADDDP:
		case PPC_INS_XSCMPODP:
		case PPC_INS_XSCMPUDP:
		case PPC_INS_XSCPSGNDP:
		case PPC_INS_XSCVDPSP:
		case PPC_INS_XSCVDPSXDS:
		case PPC_INS_XSCVDPSXWS:
		case PPC_INS_XSCVDPUXDS:
		case PPC_INS_XSCVDPUXWS:
		case PPC_INS_XSCVSPDP:
		case PPC_INS_XSCVSXDDP:
		case PPC_INS_XSCVUXDDP:
		case PPC_INS_XSDIVDP:
		case PPC_INS_XSMADDADP:
		case PPC_INS_XSMADDMDP:
		case PPC_INS_XSMAXDP:
		case PPC_INS_XSMINDP:
		case PPC_INS_XSMSUBADP:
		case PPC_INS_XSMSUBMDP:
		case PPC_INS_XSMULDP:
		case PPC_INS_XSNABSDP:
		case PPC_INS_XSNEGDP:
		case PPC_INS_XSNMADDADP:
		case PPC_INS_XSNMADDMDP:
		case PPC_INS_XSNMSUBADP:
		case PPC_INS_XSNMSUBMDP:
		case PPC_INS_XSRDPI:
		case PPC_INS_XSRDPIC:
		case PPC_INS_XSRDPIM:
		case PPC_INS_XSRDPIP:
		case PPC_INS_XSRDPIZ:
		case PPC_INS_XSREDP:
		case PPC_INS_XSRSQRTEDP:
		case PPC_INS_XSSQRTDP:
		case PPC_INS_XSSUBDP:
		case PPC_INS_XSTDIVDP:
		case PPC_INS_XSTSQRTDP:
		case PPC_INS_XVABSDP:
		case PPC_INS_XVABSSP:
		case PPC_INS_XVADDDP:
		case PPC_INS_XVADDSP:
		case PPC_INS_XVCMPEQDP:
		case PPC_INS_XVCMPEQSP:
		case PPC_INS_XVCMPGEDP:
		case PPC_INS_XVCMPGESP:
		case PPC_INS_XVCMPGTDP:
		case PPC_INS_XVCMPGTSP:
		case PPC_INS_XVCPSGNDP:
		case PPC_INS_XVCPSGNSP:
		case PPC_INS_XVCVDPSP:
		case PPC_INS_XVCVDPSXDS:
		case PPC_INS_XVCVDPSXWS:
		case PPC_INS_XVCVDPUXDS:
		case PPC_INS_XVCVDPUXWS:
		case PPC_INS_XVCVSPDP:
		case PPC_INS_XVCVSPSXDS:
		case PPC_INS_XVCVSPSXWS:
		case PPC_INS_XVCVSPUXDS:
		case PPC_INS_XVCVSPUXWS:
		case PPC_INS_XVCVSXDDP:
		case PPC_INS_XVCVSXDSP:
		case PPC_INS_XVCVSXWDP:
		case PPC_INS_XVCVSXWSP:
		case PPC_INS_XVCVUXDDP:
		case PPC_INS_XVCVUXDSP:
		case PPC_INS_XVCVUXWDP:
		case PPC_INS_XVCVUXWSP:
		case PPC_INS_XVDIVDP:
		case PPC_INS_XVDIVSP:
		case PPC_INS_XVMADDADP:
		case PPC_INS_XVMADDASP:
		case PPC_INS_XVMADDMDP:
		case PPC_INS_XVMADDMSP:
		case PPC_INS_XVMAXDP:
		case PPC_INS_XVMAXSP:
		case PPC_INS_XVMINDP:
		case PPC_INS_XVMINSP:
		case PPC_INS_XVMSUBADP:
		case PPC_INS_XVMSUBASP:
		case PPC_INS_XVMSUBMDP:
		case PPC_INS_XVMSUBMSP:
		case PPC_INS_XVMULDP:
		case PPC_INS_XVMULSP:
		case PPC_INS_XVNABSDP:
		case PPC_INS_XVNABSSP:
		case PPC_INS_XVNEGDP:
		case PPC_INS_XVNEGSP:
		case PPC_INS_XVNMADDADP:
		case PPC_INS_XVNMADDASP:
		case PPC_INS_XVNMADDMDP:
		case PPC_INS_XVNMADDMSP:
		case PPC_INS_XVNMSUBADP:
		case PPC_INS_XVNMSUBASP:
		case PPC_INS_XVNMSUBMDP:
		case PPC_INS_XVNMSUBMSP:
		case PPC_INS_XVRDPI:
		case PPC_INS_XVRDPIC:
		case PPC_INS_XVRDPIM:
		case PPC_INS_XVRDPIP:
		case PPC_INS_XVRDPIZ:
		case PPC_INS_XVREDP:
		case PPC_INS_XVRESP:
		case PPC_INS_XVRSPI:
		case PPC_INS_XVRSPIC:
		case PPC_INS_XVRSPIM:
		case PPC_INS_XVRSPIP:
		case PPC_INS_XVRSPIZ:
		case PPC_INS_XVRSQRTEDP:
		case PPC_INS_XVRSQRTESP:
		case PPC_INS_XVSQRTDP:
		case PPC_INS_XVSQRTSP:
		case PPC_INS_XVSUBDP:
		case PPC_INS_XVSUBSP:
		case PPC_INS_XVTDIVDP:
		case PPC_INS_XVTDIVSP:
		case PPC_INS_XVTSQRTDP:
		case PPC_INS_XVTSQRTSP:
		case PPC_INS_XXLAND:
		case PPC_INS_XXLANDC:
		case PPC_INS_XXLNOR:
		case PPC_INS_XXLOR:
		case PPC_INS_XXLXOR:
		case PPC_INS_XXMRGHW:
		case PPC_INS_XXMRGLW:
		case PPC_INS_XXPERMDI:
		case PPC_INS_XXSEL:
		case PPC_INS_XXSLDWI:
		case PPC_INS_XXSPLTW:
		case PPC_INS_BCA:
		case PPC_INS_BCLA:
		case PPC_INS_SRWI:
		case PPC_INS_SLDI:
		case PPC_INS_BTA:
		case PPC_INS_CRSET:
		case PPC_INS_CRNOT:
		case PPC_INS_CRMOVE:
		case PPC_INS_CRCLR:
		case PPC_INS_MFBR0:
		case PPC_INS_MFBR1:
		case PPC_INS_MFBR2:
		case PPC_INS_MFBR3:
		case PPC_INS_MFBR4:
		case PPC_INS_MFBR5:
		case PPC_INS_MFBR6:
		case PPC_INS_MFBR7:
		case PPC_INS_MFXER:
		case PPC_INS_MFRTCU:
		case PPC_INS_MFRTCL:
		case PPC_INS_MFDSCR:
		case PPC_INS_MFDSISR:
		case PPC_INS_MFDAR:
		case PPC_INS_MFSRR2:
		case PPC_INS_MFSRR3:
		case PPC_INS_MFCFAR:
		case PPC_INS_MFAMR:
		case PPC_INS_MFPID:
		case PPC_INS_MFTBLO:
		case PPC_INS_MFTBHI:
		case PPC_INS_MFDBATU:
		case PPC_INS_MFDBATL:
		case PPC_INS_MFIBATU:
		case PPC_INS_MFIBATL:
		case PPC_INS_MFDCCR:
		case PPC_INS_MFICCR:
		case PPC_INS_MFDEAR:
		case PPC_INS_MFESR:
		case PPC_INS_MFSPEFSCR:
		case PPC_INS_MFTCR:
		case PPC_INS_MFASR:
		case PPC_INS_MFPVR:
		case PPC_INS_MFTBU:
		case PPC_INS_MTCR:
		case PPC_INS_MTBR0:
		case PPC_INS_MTBR1:
		case PPC_INS_MTBR2:
		case PPC_INS_MTBR3:
		case PPC_INS_MTBR4:
		case PPC_INS_MTBR5:
		case PPC_INS_MTBR6:
		case PPC_INS_MTBR7:
		case PPC_INS_MTXER:
		case PPC_INS_MTDSCR:
		case PPC_INS_MTDSISR:
		case PPC_INS_MTDAR:
		case PPC_INS_MTSRR2:
		case PPC_INS_MTSRR3:
		case PPC_INS_MTCFAR:
		case PPC_INS_MTAMR:
		case PPC_INS_MTPID:
		case PPC_INS_MTTBL:
		case PPC_INS_MTTBU:
		case PPC_INS_MTTBLO:
		case PPC_INS_MTTBHI:
		case PPC_INS_MTDBATU:
		case PPC_INS_MTDBATL:
		case PPC_INS_MTIBATU:
		case PPC_INS_MTIBATL:
		case PPC_INS_MTDCCR:
		case PPC_INS_MTICCR:
		case PPC_INS_MTDEAR:
		case PPC_INS_MTESR:
		case PPC_INS_MTSPEFSCR:
		case PPC_INS_MTTCR:
		case PPC_INS_NOT:
		case PPC_INS_ROTLD:
		case PPC_INS_ROTLDI:
		case PPC_INS_CLRLDI:
		case PPC_INS_ROTLWI:
		case PPC_INS_CLRLWI:
		case PPC_INS_ROTLW:
		case PPC_INS_SUB:
		case PPC_INS_SUBC:
		case PPC_INS_LWSYNC:
		case PPC_INS_PTESYNC:
		case PPC_INS_TDLT:
		case PPC_INS_TDEQ:
		case PPC_INS_TDGT:
		case PPC_INS_TDNE:
		case PPC_INS_TDLLT:
		case PPC_INS_TDLGT:
		case PPC_INS_TDU:
		case PPC_INS_TDLTI:
		case PPC_INS_TDEQI:
		case PPC_INS_TDGTI:
		case PPC_INS_TDNEI:
		case PPC_INS_TDLLTI:
		case PPC_INS_TDLGTI:
		case PPC_INS_TDUI:
		case PPC_INS_TLBREHI:
		case PPC_INS_TLBRELO:
		case PPC_INS_TLBWEHI:
		case PPC_INS_TLBWELO:
		case PPC_INS_TWLT:
		case PPC_INS_TWEQ:
		case PPC_INS_TWGT:
		case PPC_INS_TWNE:
		case PPC_INS_TWLLT:
		case PPC_INS_TWLGT:
		case PPC_INS_TWU:
		case PPC_INS_TWLTI:
		case PPC_INS_TWEQI:
		case PPC_INS_TWGTI:
		case PPC_INS_TWNEI:
		case PPC_INS_TWLLTI:
		case PPC_INS_TWLGTI:
		case PPC_INS_TWUI:
		case PPC_INS_WAITRSV:
		case PPC_INS_WAITIMPL:
		case PPC_INS_XNOP:
		case PPC_INS_XVMOVDP:
		case PPC_INS_XVMOVSP:
		case PPC_INS_XXSPLTD:
		case PPC_INS_XXMRGHD:
		case PPC_INS_XXMRGLD:
		case PPC_INS_XXSWAPD:
		case PPC_INS_BT:
		case PPC_INS_BF:
		case PPC_INS_BDNZT:
		case PPC_INS_BDNZF:
		case PPC_INS_BDZF:
		case PPC_INS_BDZT:
		case PPC_INS_BFA:
		case PPC_INS_BDNZTA:
		case PPC_INS_BDNZFA:
		case PPC_INS_BDZTA:
		case PPC_INS_BDZFA:
		case PPC_INS_BTCTR:
		case PPC_INS_BFCTR:
		case PPC_INS_BTCTRL:
		case PPC_INS_BFCTRL:
		case PPC_INS_BTL:
		case PPC_INS_BFL:
		case PPC_INS_BDNZTL:
		case PPC_INS_BDNZFL:
		case PPC_INS_BDZTL:
		case PPC_INS_BDZFL:
		case PPC_INS_BTLA:
		case PPC_INS_BFLA:
		case PPC_INS_BDNZTLA:
		case PPC_INS_BDNZFLA:
		case PPC_INS_BDZTLA:
		case PPC_INS_BDZFLA:
		case PPC_INS_BTLR:
		case PPC_INS_BFLR:
		case PPC_INS_BDNZTLR:
		case PPC_INS_BDZTLR:
		case PPC_INS_BDZFLR:
		case PPC_INS_BTLRL:
		case PPC_INS_BFLRL:
		case PPC_INS_BDNZTLRL:
		case PPC_INS_BDNZFLRL:
		case PPC_INS_BDZTLRL:
		case PPC_INS_BDZFLRL:
		case PPC_INS_BRINC:

		default:
			MYLOG("%s:%s() returning Unimplemented(...) on:\n", 
			  __FILE__, __func__);

			MYLOG("    %08llx: %02X %02X %02X %02X %s %s\n",
			  addr, data[0], data[1], data[2], data[3],  
			  res->insn.mnemonic, res->insn.op_str);

			il.AddInstruction(il.Unimplemented());
	}

	return rc;
}

