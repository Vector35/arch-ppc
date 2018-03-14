#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#include <vector>
using namespace std;

#include <binaryninjaapi.h>
#define MYLOG(...) while(0);
//#define MYLOG BinaryNinja::LogDebug
//#define MYLOG printf

#include "lowlevelilinstruction.h"
using namespace BinaryNinja; // for ::LogDebug, etc.

#include "disassembler.h"
#include "assembler.h"

#include "il.h"
#include "util.h"

/* class Architecture from binaryninjaapi.h */
class PowerpcArchitecture: public Architecture
{
	private:
	BNEndianness endian;

	/* this can maybe be moved to the API later */
	BNRegisterInfo RegisterInfo(uint32_t fullWidthReg, size_t offset, size_t size, bool zeroExtend = false)
	{
		BNRegisterInfo result;
		result.fullWidthRegister = fullWidthReg;
		result.offset = offset;
		result.size = size;
		result.extend = zeroExtend ? ZeroExtendToFullWidth : NoExtend;
		return result;
	}

	public:

	/* initialization list */
	PowerpcArchitecture(const char* name, BNEndianness endian_): Architecture(name)
	{
		endian = endian_;
	}

	/*************************************************************************/

	virtual BNEndianness GetEndianness() const override
	{
		//MYLOG("%s()\n", __func__);
		return endian;
	}

	virtual size_t GetAddressSize() const override
	{
		//MYLOG("%s()\n", __func__);
		return 4;
	}

	virtual size_t GetDefaultIntegerSize() const override
	{
		MYLOG("%s()\n", __func__);
		return 4;
	}

	virtual size_t GetInstructionAlignment() const override
	{
		return 4;
	}

	virtual size_t GetMaxInstructionLength() const override
	{
		return 4;
	}

	/* think "GetInstructionBranchBehavior()"

	   populates struct Instruction Info (api/binaryninjaapi.h)
	   which extends struct BNInstructionInfo (core/binaryninjacore.h)

	   tasks:
		1) set the length
		2) invoke AddBranch() for every non-sequential execution possibility

	   */
	virtual bool GetInstructionInfo(const uint8_t* data, uint64_t addr,
		size_t maxLen, InstructionInfo& result) override
	{
		struct decomp_result res;
		struct cs_insn *insn = &(res.insn);
		struct cs_detail *detail = &(res.detail);
		struct cs_ppc *ppc = &(detail->ppc);
		cs_ppc_op *oper0 = &(ppc->operands[0]);
		cs_ppc_op *oper1 = &(ppc->operands[1]);

		bool rc = false;

		//MYLOG("%s()\n", __func__);

		if (maxLen < 4) {
			MYLOG("ERROR: need at least 4 bytes\n");
			goto cleanup;
		}

		/* decompose the instruction to get branch info */
		if(powerpc_decompose(data, 4, addr, endian == LittleEndian, &res)) {
			MYLOG("ERROR: powerpc_decompose()\n");
			goto cleanup;
		}

		switch(insn->id) {
			case PPC_INS_B:
				/* if no branch code -> unconditional */
				if(ppc->bc == 0) {
					switch(oper0->type) {
						case PPC_OP_IMM:
							result.AddBranch(UnconditionalBranch, oper0->imm);
							break;
						default:
							result.AddBranch(UnresolvedBranch);
					}
				}
				else {
					//printInstructionVerbose(&res);

					result.AddBranch(FalseBranch, addr+4); /* fall-thru */

					if(oper0->type == PPC_OP_IMM) {
						result.AddBranch(TrueBranch, oper0->imm); /* branch taken */
					}
					if(oper1->type == PPC_OP_IMM) {
						result.AddBranch(TrueBranch, oper1->imm); /* branch taken */
					}
					else {
						result.AddBranch(UnresolvedBranch);
					}
				}

				break;
			case PPC_INS_BL:
				result.AddBranch(CallDestination, oper0->imm);
				break;
			case PPC_INS_BLR:
				if(ppc->bc == PPC_BC_INVALID) /* unconditional */
					result.AddBranch(FunctionReturn);

				break;
			case PPC_INS_BCTR:
			case PPC_INS_TRAP:
				result.AddBranch(UnresolvedBranch);
				break;
		}

		result.length = 4;

		rc = true;
		cleanup:
		return rc;
	}

	/* populate the vector result with InstructionTextToken

	*/
	virtual bool GetInstructionText(const uint8_t* data, uint64_t addr, size_t& len, vector<InstructionTextToken>& result) override
	{
		bool rc = false;
		bool capstoneWorkaround = false;
		char buf[32];
		int strlenMnem;
		struct decomp_result res;
		struct cs_insn *insn = &(res.insn);
		struct cs_detail *detail = &(res.detail);
		struct cs_ppc *ppc = &(detail->ppc);

		//MYLOG("%s()\n", __func__);

		if (len < 4) {
			MYLOG("ERROR: need at least 4 bytes\n");
			goto cleanup;
		}
		
		if(powerpc_decompose(data, 4, addr, endian == LittleEndian, &res)) {
			MYLOG("ERROR: powerpc_decompose()\n");
			goto cleanup;
		}

		switch (insn->id)
		{
			case PPC_INS_CRAND:
			case PPC_INS_CRANDC:
			case PPC_INS_CRNAND:
			case PPC_INS_CROR:
			case PPC_INS_CRORC:
			case PPC_INS_CRNOR:
			case PPC_INS_CREQV:
			case PPC_INS_CRXOR:
			case PPC_INS_CRSET:
			case PPC_INS_CRCLR:
			case PPC_INS_CRNOT:
			case PPC_INS_CRMOVE:
				capstoneWorkaround = true;
		}
		
		/* mnemonic */
		result.emplace_back(InstructionToken, insn->mnemonic);
		
		/* padding between mnemonic and operands */
		memset(buf, ' ', 8);
		strlenMnem = strlen(insn->mnemonic);
		if(strlenMnem < 8)
			buf[8-strlenMnem] = '\0';
		else
			buf[1] = '\0';
		result.emplace_back(TextToken, buf);

		/* operands */
		for(int i=0; i<ppc->op_count; ++i) {
			struct cs_ppc_op *op = &(ppc->operands[i]);

			switch(op->type) {
				case PPC_OP_REG:
					//MYLOG("pushing a register\n");
					if (capstoneWorkaround || (insn->id == PPC_INS_ISEL && i == 3))
						result.emplace_back(TextToken, GetFlagName(op->reg - PPC_REG_R0));
					else
						result.emplace_back(RegisterToken, GetRegisterName(op->reg));
					break;
				case PPC_OP_IMM:
					//MYLOG("pushing an integer\n");
					sprintf(buf, "0x%X", op->imm);

					switch(insn->id) {
						//case PPC_INS_B:
						//case PPC_INS_BA:
						//case PPC_INS_BC:
						//case PPC_INS_BCCTR:
						//case PPC_INS_BCCTRL:
						//case PPC_INS_BCL:
						//case PPC_INS_BCLR:
						//case PPC_INS_BCLRL:

						case PPC_INS_BL:
						case PPC_INS_BLA:
						case PPC_INS_BLR:
						case PPC_INS_BLRL:
							result.emplace_back(PossibleAddressToken, buf, op->imm, 4);
							break;
						default:
							result.emplace_back(IntegerToken, buf, op->imm, 4);
					}

					break;
				case PPC_OP_MEM:
					// eg: lwz r11, 8(r11)
					sprintf(buf, "%d", op->mem.disp);
					result.emplace_back(IntegerToken, buf, op->mem.disp, 4);

					result.emplace_back(TextToken, "(");
					result.emplace_back(RegisterToken, GetRegisterName(op->mem.base));
					result.emplace_back(TextToken, ")");
					break;
				case PPC_OP_CRX:
				case PPC_OP_INVALID:
				default:
					//MYLOG("pushing a ???\n");
					result.emplace_back(TextToken, "???");
			}
	
			if(i < ppc->op_count-1) {
				//MYLOG("pushing a comma\n");
				result.emplace_back(OperandSeparatorToken, ", ");
			}		
		}
		
		rc = true;
		len = 4;
		cleanup:
		return rc;
	}

	virtual bool GetInstructionLowLevelIL(const uint8_t* data, uint64_t addr, size_t& len, LowLevelILFunction& il) override
	{
		bool rc = false;

		//if(addr >= 0x10000300 && addr <= 0x10000320) {
		//	MYLOG("%s(data, 0x%llX, 0x%zX, il)\n", __func__, addr, len);
		//}

		struct decomp_result res;

		if(powerpc_decompose(data, 4, addr, endian == LittleEndian, &res)) {
			MYLOG("ERROR: powerpc_decompose()\n");
			il.AddInstruction(il.Unimplemented());
			goto cleanup;
		}

		rc = GetLowLevelILForPPCInstruction(this, il, data, addr, &res);
		len = 4;

		cleanup:
		return rc;
	}

	virtual size_t GetFlagWriteLowLevelIL(BNLowLevelILOperation op, size_t size, uint32_t flagWriteType,
		uint32_t flag, BNRegisterOrConstant* operands, size_t operandCount, LowLevelILFunction& il) override
	{
		MYLOG("%s()\n", __func__);

		bool signedWrite = true;
		ExprId left, right;

		switch (flagWriteType)
		{
			case IL_FLAGWRITE_CR0_U:
			case IL_FLAGWRITE_CR1_U:
			case IL_FLAGWRITE_CR2_U:
			case IL_FLAGWRITE_CR3_U:
			case IL_FLAGWRITE_CR4_U:
			case IL_FLAGWRITE_CR5_U:
			case IL_FLAGWRITE_CR6_U:
			case IL_FLAGWRITE_CR7_U:
				signedWrite = false;
		}

		auto liftOps = [&]() {
				if (op == LLIL_SUB)
				{
					left = il.GetExprForRegisterOrConstant(operands[0], size);
					right = il.GetExprForRegisterOrConstant(operands[1], size);
				}
				else
				{
					if (op == LLIL_SET_REG)
						left = il.GetExprForRegisterOrConstant(operands[0], size);
					else
						left = il.GetExprForRegisterOrConstantOperation(op, size, operands, operandCount);

					right = il.Const(size, 0);
				}
		};

		switch (flag)
		{
			case IL_FLAG_LT:
			case IL_FLAG_LT_1:
			case IL_FLAG_LT_2:
			case IL_FLAG_LT_3:
			case IL_FLAG_LT_4:
			case IL_FLAG_LT_5:
			case IL_FLAG_LT_6:
			case IL_FLAG_LT_7:
				liftOps();

				if (signedWrite)
					return il.CompareSignedLessThan(size, left, right);
				else
					return il.CompareUnsignedLessThan(size, left, right);

			case IL_FLAG_GT:
			case IL_FLAG_GT_1:
			case IL_FLAG_GT_2:
			case IL_FLAG_GT_3:
			case IL_FLAG_GT_4:
			case IL_FLAG_GT_5:
			case IL_FLAG_GT_6:
			case IL_FLAG_GT_7:
				liftOps();

				if (signedWrite)
					return il.CompareSignedGreaterThan(size, left, right);
				else
					return il.CompareUnsignedGreaterThan(size, left, right);

			case IL_FLAG_EQ:
			case IL_FLAG_EQ_1:
			case IL_FLAG_EQ_2:
			case IL_FLAG_EQ_3:
			case IL_FLAG_EQ_4:
			case IL_FLAG_EQ_5:
			case IL_FLAG_EQ_6:
			case IL_FLAG_EQ_7:
				liftOps();
				return il.CompareEqual(size, left, right);
		}

		BNFlagRole role = GetFlagRole(flag, GetSemanticClassForFlagWriteType(flagWriteType));
		return GetDefaultFlagWriteLowLevelIL(op, size, role, operands, operandCount, il);
	}


	/*
	virtual ExprId GetSemanticFlagGroupLowLevelIL(uint32_t semGroup, LowLevelILFunction& il) override
	{
		return il.Flag(semGroup);
	}
	*/

	virtual string GetRegisterName(uint32_t regId) override
	{
		const char *result = powerpc_reg_to_str(regId);

		if(result == NULL)
			result = "";

		//MYLOG("%s(%d) returns %s\n", __func__, regId, result);
		return result;
	}

	/*************************************************************************/
	/* FLAGS API 
		1) flag identifiers and names
		2) flag write types and names
		3) flag roles "which flags act like a carry flag?"
		4) map flag condition to set-of-flags
	*/
	/*************************************************************************/

	/*
		flag identifiers and names
	*/
	virtual vector<uint32_t> GetAllFlags() override
	{
		MYLOG("%s()\n", __func__);
		return vector<uint32_t> {
			IL_FLAG_LT, IL_FLAG_GT, IL_FLAG_EQ, IL_FLAG_SO,
			IL_FLAG_LT_1, IL_FLAG_GT_1, IL_FLAG_EQ_1, IL_FLAG_SO_1,
			IL_FLAG_LT_2, IL_FLAG_GT_2, IL_FLAG_EQ_2, IL_FLAG_SO_2,
			IL_FLAG_LT_3, IL_FLAG_GT_3, IL_FLAG_EQ_3, IL_FLAG_SO_3,
			IL_FLAG_LT_4, IL_FLAG_GT_4, IL_FLAG_EQ_4, IL_FLAG_SO_4,
			IL_FLAG_LT_5, IL_FLAG_GT_5, IL_FLAG_EQ_5, IL_FLAG_SO_5,
			IL_FLAG_LT_6, IL_FLAG_GT_6, IL_FLAG_EQ_6, IL_FLAG_SO_6,
			IL_FLAG_LT_7, IL_FLAG_GT_7, IL_FLAG_EQ_7, IL_FLAG_SO_7,
			IL_FLAG_XER_SO, IL_FLAG_XER_OV, IL_FLAG_XER_CA
		};
	}

	virtual string GetFlagName(uint32_t flag) override
	{
		MYLOG("%s(%d)\n", __func__, flag);

		switch(flag) {
			case IL_FLAG_LT: return "lt";
			case IL_FLAG_GT: return "gt";
			case IL_FLAG_EQ: return "eq";
			case IL_FLAG_SO: return "so";
			case IL_FLAG_LT_1: return "cr1_lt";
			case IL_FLAG_GT_1: return "cr1_gt";
			case IL_FLAG_EQ_1: return "cr1_eq";
			case IL_FLAG_SO_1: return "cr1_so";
			case IL_FLAG_LT_2: return "cr2_lt";
			case IL_FLAG_GT_2: return "cr2_gt";
			case IL_FLAG_EQ_2: return "cr2_eq";
			case IL_FLAG_SO_2: return "cr2_so";
			case IL_FLAG_LT_3: return "cr3_lt";
			case IL_FLAG_GT_3: return "cr3_gt";
			case IL_FLAG_EQ_3: return "cr3_eq";
			case IL_FLAG_SO_3: return "cr3_so";
			case IL_FLAG_LT_4: return "cr4_lt";
			case IL_FLAG_GT_4: return "cr4_gt";
			case IL_FLAG_EQ_4: return "cr4_eq";
			case IL_FLAG_SO_4: return "cr4_so";
			case IL_FLAG_LT_5: return "cr5_lt";
			case IL_FLAG_GT_5: return "cr5_gt";
			case IL_FLAG_EQ_5: return "cr5_eq";
			case IL_FLAG_SO_5: return "cr5_so";
			case IL_FLAG_LT_6: return "cr6_lt";
			case IL_FLAG_GT_6: return "cr6_gt";
			case IL_FLAG_EQ_6: return "cr6_eq";
			case IL_FLAG_SO_6: return "cr6_so";
			case IL_FLAG_LT_7: return "cr7_lt";
			case IL_FLAG_GT_7: return "cr7_gt";
			case IL_FLAG_EQ_7: return "cr7_eq";
			case IL_FLAG_SO_7: return "cr7_so";
			case IL_FLAG_XER_SO: return "xer_so";
			case IL_FLAG_XER_OV: return "xer_ov";
			case IL_FLAG_XER_CA: return "xer_ca";
			default: return "ERR_FLAG_NAME";
		}
	}

	/*
		flag write types 
	*/
	virtual vector<uint32_t> GetAllFlagWriteTypes() override
	{
		return vector<uint32_t> {
			IL_FLAGWRITE_NONE, 

			IL_FLAGWRITE_CR0_S, IL_FLAGWRITE_CR1_S, IL_FLAGWRITE_CR2_S, IL_FLAGWRITE_CR3_S,
			IL_FLAGWRITE_CR4_S, IL_FLAGWRITE_CR5_S, IL_FLAGWRITE_CR6_S, IL_FLAGWRITE_CR7_S,

			IL_FLAGWRITE_CR0_U, IL_FLAGWRITE_CR1_U, IL_FLAGWRITE_CR2_U, IL_FLAGWRITE_CR3_U,
			IL_FLAGWRITE_CR4_U, IL_FLAGWRITE_CR5_U, IL_FLAGWRITE_CR6_U, IL_FLAGWRITE_CR7_U,

			IL_FLAGWRITE_XER, IL_FLAGWRITE_XER_CA, IL_FLAGWRITE_XER_OV_SO
		};
	}

	virtual string GetFlagWriteTypeName(uint32_t writeType) override
	{
		MYLOG("%s(%d)\n", __func__, writeType);

		switch (writeType)
		{
			case IL_FLAGWRITE_CR0_S:
				return "cr0_signed";
			case IL_FLAGWRITE_CR1_S:
				return "cr1_signed";
			case IL_FLAGWRITE_CR2_S:
				return "cr2_signed";
			case IL_FLAGWRITE_CR3_S:
				return "cr3_signed";
			case IL_FLAGWRITE_CR4_S:
				return "cr4_signed";
			case IL_FLAGWRITE_CR5_S:
				return "cr5_signed";
			case IL_FLAGWRITE_CR6_S:
				return "cr6_signed";
			case IL_FLAGWRITE_CR7_S:
				return "cr7_signed";

			case IL_FLAGWRITE_CR0_U:
				return "cr0_unsigned";
			case IL_FLAGWRITE_CR1_U:
				return "cr1_unsigned";
			case IL_FLAGWRITE_CR2_U:
				return "cr2_unsigned";
			case IL_FLAGWRITE_CR3_U:
				return "cr3_unsigned";
			case IL_FLAGWRITE_CR4_U:
				return "cr4_unsigned";
			case IL_FLAGWRITE_CR5_U:
				return "cr5_unsigned";
			case IL_FLAGWRITE_CR6_U:
				return "cr6_unsigned";
			case IL_FLAGWRITE_CR7_U:
				return "cr7_unsigned";

			case IL_FLAGWRITE_XER:
				return "xer";
			case IL_FLAGWRITE_XER_CA:
				return "xer_ca";
			case IL_FLAGWRITE_XER_OV_SO:
				return "xer_ov_so";

			default:
				MYLOG("ERROR: unrecognized writeType\n");
				return "none";
		}
	}

	virtual vector<uint32_t> GetFlagsWrittenByFlagWriteType(uint32_t writeType) override
	{
		MYLOG("%s(%d)\n", __func__, writeType);

		switch (writeType)
		{
			case IL_FLAGWRITE_CR0_S:
			case IL_FLAGWRITE_CR0_U:
				return vector<uint32_t> {
					IL_FLAG_LT, IL_FLAG_GT, IL_FLAG_EQ, IL_FLAG_SO,
				};

			case IL_FLAGWRITE_CR1_S:
			case IL_FLAGWRITE_CR1_U:
				return vector<uint32_t> {
					IL_FLAG_LT_1, IL_FLAG_GT_1, IL_FLAG_EQ_1, IL_FLAG_SO_1,
				};

			case IL_FLAGWRITE_CR2_S:
			case IL_FLAGWRITE_CR2_U:
				return vector<uint32_t> {
					IL_FLAG_LT_2, IL_FLAG_GT_2, IL_FLAG_EQ_2, IL_FLAG_SO_2,
				};

			case IL_FLAGWRITE_CR3_S:
			case IL_FLAGWRITE_CR3_U:
				return vector<uint32_t> {
					IL_FLAG_LT_3, IL_FLAG_GT_3, IL_FLAG_EQ_3, IL_FLAG_SO_3,
				};

			case IL_FLAGWRITE_CR4_S:
			case IL_FLAGWRITE_CR4_U:
				return vector<uint32_t> {
					IL_FLAG_LT_4, IL_FLAG_GT_4, IL_FLAG_EQ_4, IL_FLAG_SO_4,
				};

			case IL_FLAGWRITE_CR5_S:
			case IL_FLAGWRITE_CR5_U:
				return vector<uint32_t> {
					IL_FLAG_LT_5, IL_FLAG_GT_5, IL_FLAG_EQ_5, IL_FLAG_SO_5,
				};

			case IL_FLAGWRITE_CR6_S:
			case IL_FLAGWRITE_CR6_U:
				return vector<uint32_t> {
					IL_FLAG_LT_6, IL_FLAG_GT_6, IL_FLAG_EQ_6, IL_FLAG_SO_6,
				};	
			
			case IL_FLAGWRITE_CR7_S:
			case IL_FLAGWRITE_CR7_U:
				return vector<uint32_t> {
					IL_FLAG_LT_7, IL_FLAG_GT_7, IL_FLAG_EQ_7, IL_FLAG_SO_7,
				};

			case IL_FLAGWRITE_XER:
				return vector<uint32_t> {
					IL_FLAG_XER_SO, IL_FLAG_XER_OV, IL_FLAG_XER_CA
				};

			case IL_FLAGWRITE_XER_CA:
				return vector<uint32_t> {
					IL_FLAG_XER_CA
				};

			case IL_FLAGWRITE_XER_OV_SO:
				return vector<uint32_t> {
					IL_FLAG_XER_SO, IL_FLAG_XER_OV
				};

			default:
				return vector<uint32_t>();
		}
	}
	virtual uint32_t GetSemanticClassForFlagWriteType(uint32_t writeType) override
	{
		switch (writeType)
		{
			case IL_FLAGWRITE_CR0_S: return IL_FLAGCLASS_CR0_S;
			case IL_FLAGWRITE_CR0_U: return IL_FLAGCLASS_CR0_U;
			case IL_FLAGWRITE_CR1_S: return IL_FLAGCLASS_CR1_S;
			case IL_FLAGWRITE_CR1_U: return IL_FLAGCLASS_CR1_U;
			case IL_FLAGWRITE_CR2_S: return IL_FLAGCLASS_CR2_S;
			case IL_FLAGWRITE_CR2_U: return IL_FLAGCLASS_CR2_U;
			case IL_FLAGWRITE_CR3_S: return IL_FLAGCLASS_CR3_S;
			case IL_FLAGWRITE_CR3_U: return IL_FLAGCLASS_CR3_U;
			case IL_FLAGWRITE_CR4_S: return IL_FLAGCLASS_CR4_S;
			case IL_FLAGWRITE_CR4_U: return IL_FLAGCLASS_CR4_U;
			case IL_FLAGWRITE_CR5_S: return IL_FLAGCLASS_CR5_S;
			case IL_FLAGWRITE_CR5_U: return IL_FLAGCLASS_CR5_U;
			case IL_FLAGWRITE_CR6_S: return IL_FLAGCLASS_CR6_S;
			case IL_FLAGWRITE_CR6_U: return IL_FLAGCLASS_CR6_U;
			case IL_FLAGWRITE_CR7_S: return IL_FLAGCLASS_CR7_S;
			case IL_FLAGWRITE_CR7_U: return IL_FLAGCLASS_CR7_U;
		}

		return IL_FLAGCLASS_NONE;
	}

	/*
		flag classes
	*/
	virtual vector<uint32_t> GetAllSemanticFlagClasses() override
	{
		return vector<uint32_t> {
			IL_FLAGCLASS_NONE, 

			IL_FLAGCLASS_CR0_S, IL_FLAGCLASS_CR1_S, IL_FLAGCLASS_CR2_S, IL_FLAGCLASS_CR3_S,
			IL_FLAGCLASS_CR4_S, IL_FLAGCLASS_CR5_S, IL_FLAGCLASS_CR6_S, IL_FLAGCLASS_CR7_S,

			IL_FLAGCLASS_CR0_U, IL_FLAGCLASS_CR1_U, IL_FLAGCLASS_CR2_U, IL_FLAGCLASS_CR3_U,
			IL_FLAGCLASS_CR4_U, IL_FLAGCLASS_CR5_U, IL_FLAGCLASS_CR6_U, IL_FLAGCLASS_CR7_U,
		};
	}

	virtual std::string GetSemanticFlagClassName(uint32_t semClass) override
	{
		return GetFlagWriteTypeName(semClass);
	}

	/*
	   semantic flag groups
	 */

	/*
	virtual vector<uint32_t> GetAllSemanticFlagGroups() override
	{
		return vector<uint32_t> {
			IL_FLAG_LT, IL_FLAG_GT, IL_FLAG_EQ, IL_FLAG_SO,
			IL_FLAG_LT_2, IL_FLAG_GT_2, IL_FLAG_EQ_2, IL_FLAG_SO_2,
			IL_FLAG_LT_3, IL_FLAG_GT_3, IL_FLAG_EQ_3, IL_FLAG_SO_3,
			IL_FLAG_LT_4, IL_FLAG_GT_4, IL_FLAG_EQ_4, IL_FLAG_SO_4,
			IL_FLAG_LT_5, IL_FLAG_GT_5, IL_FLAG_EQ_5, IL_FLAG_SO_5,
			IL_FLAG_LT_6, IL_FLAG_GT_6, IL_FLAG_EQ_6, IL_FLAG_SO_6,
			IL_FLAG_LT_7, IL_FLAG_GT_7, IL_FLAG_EQ_7, IL_FLAG_SO_7,
		};
	}

	virtual std::string GetSemanticFlagGroupName(uint32_t semGroup) override
	{
		// flag group ids kept identical to flag ids
		return GetFlagName(semGroup);
	}

	virtual std::vector<uint32_t> GetFlagsRequiredForSemanticFlagGroup(uint32_t semGroup) override
	{
		// flag group ids kept identical to flag ids
		return { semGroup };
	}

	//virtual std::map<uint32_t, BNLowLevelILFlagCondition> GetFlagConditionsForSemanticFlagGroup(uint32_t semGroup);
	*/

	/*
		flag roles
	*/

	virtual BNFlagRole GetFlagRole(uint32_t flag, uint32_t semClass) override
	{
		MYLOG("%s(%d)\n", __func__, flag);

		bool signedClass = true;

		switch (semClass)
		{
			case IL_FLAGCLASS_CR0_U:
			case IL_FLAGCLASS_CR1_U:
			case IL_FLAGCLASS_CR2_U:
			case IL_FLAGCLASS_CR3_U:
			case IL_FLAGCLASS_CR4_U:
			case IL_FLAGCLASS_CR5_U:
			case IL_FLAGCLASS_CR6_U:
			case IL_FLAGCLASS_CR7_U:
				signedClass = false;
		}

		switch (flag)
		{
			case IL_FLAG_LT:
			case IL_FLAG_LT_1:
			case IL_FLAG_LT_2:
			case IL_FLAG_LT_3:
			case IL_FLAG_LT_4:
			case IL_FLAG_LT_5:
			case IL_FLAG_LT_6:
			case IL_FLAG_LT_7:
				return signedClass ? NegativeSignFlagRole : SpecialFlagRole;
			case IL_FLAG_GT:
			case IL_FLAG_GT_1:
			case IL_FLAG_GT_2:
			case IL_FLAG_GT_3:
			case IL_FLAG_GT_4:
			case IL_FLAG_GT_5:
			case IL_FLAG_GT_6:
			case IL_FLAG_GT_7:
				return SpecialFlagRole; // PositiveSignFlag is >=, not >
			case IL_FLAG_EQ:
			case IL_FLAG_EQ_1:
			case IL_FLAG_EQ_2:
			case IL_FLAG_EQ_3:
			case IL_FLAG_EQ_4:
			case IL_FLAG_EQ_5:
			case IL_FLAG_EQ_6:
			case IL_FLAG_EQ_7:
				return ZeroFlagRole;
			// case IL_FLAG_SO:
			// case IL_FLAG_SO_1:
			// case IL_FLAG_SO_2:
			// case IL_FLAG_SO_3:
			// case IL_FLAG_SO_4:
			// case IL_FLAG_SO_5:
			// case IL_FLAG_SO_6:
			// case IL_FLAG_SO_7:
			// case IL_FLAG_XER_SO:
			case IL_FLAG_XER_OV:
				return OverflowFlagRole;
			case IL_FLAG_XER_CA:
				return CarryFlagRole;
			default: 
				return SpecialFlagRole;
		}
	}

	/*
		flag conditions -> set of flags
		LLFC is "low level flag condition"
	*/
	virtual vector<uint32_t> GetFlagsRequiredForFlagCondition(BNLowLevelILFlagCondition cond, uint32_t) override
	{
		MYLOG("%s(%d)\n", __func__, cond);

		switch (cond)
		{
			case LLFC_E: /* equal */
			case LLFC_NE: /* not equal */
				return vector<uint32_t>{ IL_FLAG_EQ };

			case LLFC_ULT: /* (unsigned) less than == LT */
			case LLFC_SLT: /* (signed) less than == LT */
			case LLFC_SGE: /* (signed) greater-or-equal == !LT */
			case LLFC_UGE: /* (unsigned) greater-or-equal == !LT */
				return vector<uint32_t>{ IL_FLAG_LT };

			case LLFC_SGT: /* (signed) greater-than == GT */
			case LLFC_UGT: /* (unsigned) greater-than == GT */
			case LLFC_ULE: /* (unsigned) less-or-equal == !GT */
			case LLFC_SLE: /* (signed) lesser-or-equal == !GT */
				return vector<uint32_t>{ IL_FLAG_GT };

			case LLFC_NEG: 
			case LLFC_POS:
				/* no ppc flags (that I'm aware of) indicate sign of result */
				return vector<uint32_t>();

			case LLFC_O:
			case LLFC_NO:
				/* difficult:
					crX: 8 signed sticky versions
					XER: 1 unsigned sticky, 1 unsigned traditional */
				return vector<uint32_t>{ 
					IL_FLAG_XER_OV
				};

			default:
				return vector<uint32_t>();
		}
	}


	/*************************************************************************/
	/* REGISTERS API
		1) registers' ids and names
		2) register info (size)
		3) special registers: stack pointer, link register
	*/
	/*************************************************************************/

	virtual vector<uint32_t> GetFullWidthRegisters() override
	{
		MYLOG("%s()\n", __func__);

		return vector<uint32_t>{
			PPC_REG_R0,   PPC_REG_R1,   PPC_REG_R2,   PPC_REG_R3,   PPC_REG_R4,   PPC_REG_R5,   PPC_REG_R6,   PPC_REG_R7,
			PPC_REG_R8,   PPC_REG_R9,   PPC_REG_R10,  PPC_REG_R11,  PPC_REG_R12,  PPC_REG_R13,  PPC_REG_R14,  PPC_REG_R15,
			PPC_REG_R16,  PPC_REG_R17,  PPC_REG_R18,  PPC_REG_R19,  PPC_REG_R20,  PPC_REG_R21,  PPC_REG_R22,  PPC_REG_R23,
			PPC_REG_R24,  PPC_REG_R25,  PPC_REG_R26,  PPC_REG_R27,  PPC_REG_R28,  PPC_REG_R29,  PPC_REG_R30,  PPC_REG_R31
		};
	}

	virtual vector<uint32_t> GetAllRegisters() override
	{
		vector<uint32_t> result = {
			PPC_REG_CARRY, PPC_REG_CC,
	
			PPC_REG_CR0, PPC_REG_CR1, PPC_REG_CR2, PPC_REG_CR3, PPC_REG_CR4, PPC_REG_CR5, PPC_REG_CR6, PPC_REG_CR7,

			PPC_REG_CTR, 

			PPC_REG_F0, PPC_REG_F1, PPC_REG_F2, PPC_REG_F3,  PPC_REG_F4, PPC_REG_F5, PPC_REG_F6, PPC_REG_F7,
			PPC_REG_F8, PPC_REG_F9, PPC_REG_F10, PPC_REG_F11, PPC_REG_F12, PPC_REG_F13, PPC_REG_F14, PPC_REG_F15,
			PPC_REG_F16, PPC_REG_F17, PPC_REG_F18, PPC_REG_F19, PPC_REG_F20, PPC_REG_F21, PPC_REG_F22, PPC_REG_F23,
			PPC_REG_F24, PPC_REG_F25, PPC_REG_F26, PPC_REG_F27, PPC_REG_F28, PPC_REG_F29, PPC_REG_F30, PPC_REG_F31,

			PPC_REG_LR, 

			PPC_REG_R0, PPC_REG_R1, PPC_REG_R2, PPC_REG_R3, PPC_REG_R4, PPC_REG_R5,  PPC_REG_R6, PPC_REG_R7,
			PPC_REG_R8, PPC_REG_R9, PPC_REG_R10, PPC_REG_R11, PPC_REG_R12, PPC_REG_R13, PPC_REG_R14, PPC_REG_R15,
			PPC_REG_R16, PPC_REG_R17, PPC_REG_R18, PPC_REG_R19,	PPC_REG_R20, PPC_REG_R21, PPC_REG_R22, PPC_REG_R23,
			PPC_REG_R24, PPC_REG_R25, PPC_REG_R26, PPC_REG_R27, PPC_REG_R28, PPC_REG_R29, PPC_REG_R30, PPC_REG_R31,

			PPC_REG_V0, PPC_REG_V1, PPC_REG_V2, PPC_REG_V3, PPC_REG_V4, PPC_REG_V5, PPC_REG_V6, PPC_REG_V7,
			PPC_REG_V8, PPC_REG_V9, PPC_REG_V10, PPC_REG_V11, PPC_REG_V12, PPC_REG_V13, PPC_REG_V14, PPC_REG_V15, 
			PPC_REG_V16, PPC_REG_V17, PPC_REG_V18, PPC_REG_V19, PPC_REG_V20, PPC_REG_V21, PPC_REG_V22, PPC_REG_V23,
			PPC_REG_V24, PPC_REG_V25, PPC_REG_V26, PPC_REG_V27, PPC_REG_V28, PPC_REG_V29, PPC_REG_V30, PPC_REG_V31,
			PPC_REG_VRSAVE,
			PPC_REG_VS0, PPC_REG_VS1, PPC_REG_VS2, PPC_REG_VS3, PPC_REG_VS4, PPC_REG_VS5, PPC_REG_VS6, PPC_REG_VS7,
			PPC_REG_VS8, PPC_REG_VS9, PPC_REG_VS10, PPC_REG_VS11, PPC_REG_VS12, PPC_REG_VS13, PPC_REG_VS14, PPC_REG_VS15,
			PPC_REG_VS16, PPC_REG_VS17, PPC_REG_VS18, PPC_REG_VS19, PPC_REG_VS20, PPC_REG_VS21, PPC_REG_VS22, PPC_REG_VS23,
			PPC_REG_VS24, PPC_REG_VS25, PPC_REG_VS26, PPC_REG_VS27, PPC_REG_VS28, PPC_REG_VS29, PPC_REG_VS30, PPC_REG_VS31,
			PPC_REG_VS32, PPC_REG_VS33, PPC_REG_VS34, PPC_REG_VS35, PPC_REG_VS36, PPC_REG_VS37, PPC_REG_VS38, PPC_REG_VS39,
			PPC_REG_VS40, PPC_REG_VS41, PPC_REG_VS42, PPC_REG_VS43, PPC_REG_VS44, PPC_REG_VS45, PPC_REG_VS46, PPC_REG_VS47,
			PPC_REG_VS48, PPC_REG_VS49, PPC_REG_VS50, PPC_REG_VS51, PPC_REG_VS52, PPC_REG_VS53, PPC_REG_VS54, PPC_REG_VS55,
			PPC_REG_VS56, PPC_REG_VS57, PPC_REG_VS58, PPC_REG_VS59, PPC_REG_VS60, PPC_REG_VS61, PPC_REG_VS62, PPC_REG_VS63
		};

		return result;
	}

	/* binja asks us about subregisters
		the full width reg is the enveloping register, if it exists,
		and also we report our offset within it (0 if we are not enveloped)
		and our size */
	virtual BNRegisterInfo GetRegisterInfo(uint32_t regId) override
	{
		//MYLOG("%s(%s)\n", __func__, powerpc_reg_to_str(regId));

		switch(regId) {
			// BNRegisterInfo RegisterInfo(uint32_t fullWidthReg, size_t offset, 
			//   size_t size, bool zeroExtend = false)

			case PPC_REG_CARRY: return RegisterInfo(PPC_REG_CARRY, 0, 4);
			case PPC_REG_CC: return RegisterInfo(PPC_REG_CC, 0, 4);
			case PPC_REG_CR0: return RegisterInfo(PPC_REG_CR0, 0, 4);
			case PPC_REG_CR1: return RegisterInfo(PPC_REG_CR1, 0, 4);
			case PPC_REG_CR2: return RegisterInfo(PPC_REG_CR2, 0, 4);
			case PPC_REG_CR3: return RegisterInfo(PPC_REG_CR3, 0, 4);
			case PPC_REG_CR4: return RegisterInfo(PPC_REG_CR4, 0, 4);
			case PPC_REG_CR5: return RegisterInfo(PPC_REG_CR5, 0, 4);
			case PPC_REG_CR6: return RegisterInfo(PPC_REG_CR6, 0, 4);
			case PPC_REG_CR7: return RegisterInfo(PPC_REG_CR7, 0, 4);
			case PPC_REG_CTR: return RegisterInfo(PPC_REG_CTR, 0, 4);
			case PPC_REG_F0: return RegisterInfo(PPC_REG_F0, 0, 4);
			case PPC_REG_F1: return RegisterInfo(PPC_REG_F1, 0, 4);
			case PPC_REG_F2: return RegisterInfo(PPC_REG_F2, 0, 4);
			case PPC_REG_F3: return RegisterInfo(PPC_REG_F3, 0, 4);
			case PPC_REG_F4: return RegisterInfo(PPC_REG_F4, 0, 4);
			case PPC_REG_F5: return RegisterInfo(PPC_REG_F5, 0, 4);
			case PPC_REG_F6: return RegisterInfo(PPC_REG_F6, 0, 4);
			case PPC_REG_F7: return RegisterInfo(PPC_REG_F7, 0, 4);
			case PPC_REG_F8: return RegisterInfo(PPC_REG_F8, 0, 4);
			case PPC_REG_F9: return RegisterInfo(PPC_REG_F9, 0, 4);
			case PPC_REG_F10: return RegisterInfo(PPC_REG_F10, 0, 4);
			case PPC_REG_F11: return RegisterInfo(PPC_REG_F11, 0, 4);
			case PPC_REG_F12: return RegisterInfo(PPC_REG_F12, 0, 4);
			case PPC_REG_F13: return RegisterInfo(PPC_REG_F13, 0, 4);
			case PPC_REG_F14: return RegisterInfo(PPC_REG_F14, 0, 4);
			case PPC_REG_F15: return RegisterInfo(PPC_REG_F15, 0, 4);
			case PPC_REG_F16: return RegisterInfo(PPC_REG_F16, 0, 4);
			case PPC_REG_F17: return RegisterInfo(PPC_REG_F17, 0, 4);
			case PPC_REG_F18: return RegisterInfo(PPC_REG_F18, 0, 4);
			case PPC_REG_F19: return RegisterInfo(PPC_REG_F19, 0, 4);
			case PPC_REG_F20: return RegisterInfo(PPC_REG_F20, 0, 4);
			case PPC_REG_F21: return RegisterInfo(PPC_REG_F21, 0, 4);
			case PPC_REG_F22: return RegisterInfo(PPC_REG_F22, 0, 4);
			case PPC_REG_F23: return RegisterInfo(PPC_REG_F23, 0, 4);
			case PPC_REG_F24: return RegisterInfo(PPC_REG_F24, 0, 4);
			case PPC_REG_F25: return RegisterInfo(PPC_REG_F25, 0, 4);
			case PPC_REG_F26: return RegisterInfo(PPC_REG_F26, 0, 4);
			case PPC_REG_F27: return RegisterInfo(PPC_REG_F27, 0, 4);
			case PPC_REG_F28: return RegisterInfo(PPC_REG_F28, 0, 4);
			case PPC_REG_F29: return RegisterInfo(PPC_REG_F29, 0, 4);
			case PPC_REG_F30: return RegisterInfo(PPC_REG_F30, 0, 4);
			case PPC_REG_F31: return RegisterInfo(PPC_REG_F31, 0, 4);
			case PPC_REG_LR: return RegisterInfo(PPC_REG_LR, 0, 4);
			case PPC_REG_R0: return RegisterInfo(PPC_REG_R0, 0, 4);
			case PPC_REG_R1: return RegisterInfo(PPC_REG_R1, 0, 4);
			case PPC_REG_R2: return RegisterInfo(PPC_REG_R2, 0, 4);
			case PPC_REG_R3: return RegisterInfo(PPC_REG_R3, 0, 4);
			case PPC_REG_R4: return RegisterInfo(PPC_REG_R4, 0, 4);
			case PPC_REG_R5: return RegisterInfo(PPC_REG_R5, 0, 4);
			case PPC_REG_R6: return RegisterInfo(PPC_REG_R6, 0, 4);
			case PPC_REG_R7: return RegisterInfo(PPC_REG_R7, 0, 4);
			case PPC_REG_R8: return RegisterInfo(PPC_REG_R8, 0, 4);
			case PPC_REG_R9: return RegisterInfo(PPC_REG_R9, 0, 4);
			case PPC_REG_R10: return RegisterInfo(PPC_REG_R10, 0, 4);
			case PPC_REG_R11: return RegisterInfo(PPC_REG_R11, 0, 4);
			case PPC_REG_R12: return RegisterInfo(PPC_REG_R12, 0, 4);
			case PPC_REG_R13: return RegisterInfo(PPC_REG_R13, 0, 4);
			case PPC_REG_R14: return RegisterInfo(PPC_REG_R14, 0, 4);
			case PPC_REG_R15: return RegisterInfo(PPC_REG_R15, 0, 4);
			case PPC_REG_R16: return RegisterInfo(PPC_REG_R16, 0, 4);
			case PPC_REG_R17: return RegisterInfo(PPC_REG_R17, 0, 4);
			case PPC_REG_R18: return RegisterInfo(PPC_REG_R18, 0, 4);
			case PPC_REG_R19: return RegisterInfo(PPC_REG_R19, 0, 4);
			case PPC_REG_R20: return RegisterInfo(PPC_REG_R20, 0, 4);
			case PPC_REG_R21: return RegisterInfo(PPC_REG_R21, 0, 4);
			case PPC_REG_R22: return RegisterInfo(PPC_REG_R22, 0, 4);
			case PPC_REG_R23: return RegisterInfo(PPC_REG_R23, 0, 4);
			case PPC_REG_R24: return RegisterInfo(PPC_REG_R24, 0, 4);
			case PPC_REG_R25: return RegisterInfo(PPC_REG_R25, 0, 4);
			case PPC_REG_R26: return RegisterInfo(PPC_REG_R26, 0, 4);
			case PPC_REG_R27: return RegisterInfo(PPC_REG_R27, 0, 4);
			case PPC_REG_R28: return RegisterInfo(PPC_REG_R28, 0, 4);
			case PPC_REG_R29: return RegisterInfo(PPC_REG_R29, 0, 4);
			case PPC_REG_R30: return RegisterInfo(PPC_REG_R30, 0, 4);
			case PPC_REG_R31: return RegisterInfo(PPC_REG_R31, 0, 4);
			case PPC_REG_V0: return RegisterInfo(PPC_REG_V0, 0, 4);
			case PPC_REG_V1: return RegisterInfo(PPC_REG_V1, 0, 4);
			case PPC_REG_V2: return RegisterInfo(PPC_REG_V2, 0, 4);
			case PPC_REG_V3: return RegisterInfo(PPC_REG_V3, 0, 4);
			case PPC_REG_V4: return RegisterInfo(PPC_REG_V4, 0, 4);
			case PPC_REG_V5: return RegisterInfo(PPC_REG_V5, 0, 4);
			case PPC_REG_V6: return RegisterInfo(PPC_REG_V6, 0, 4);
			case PPC_REG_V7: return RegisterInfo(PPC_REG_V7, 0, 4);
			case PPC_REG_V8: return RegisterInfo(PPC_REG_V8, 0, 4);
			case PPC_REG_V9: return RegisterInfo(PPC_REG_V9, 0, 4);
			case PPC_REG_V10: return RegisterInfo(PPC_REG_V10, 0, 4);
			case PPC_REG_V11: return RegisterInfo(PPC_REG_V11, 0, 4);
			case PPC_REG_V12: return RegisterInfo(PPC_REG_V12, 0, 4);
			case PPC_REG_V13: return RegisterInfo(PPC_REG_V13, 0, 4);
			case PPC_REG_V14: return RegisterInfo(PPC_REG_V14, 0, 4);
			case PPC_REG_V15: return RegisterInfo(PPC_REG_V15, 0, 4);
			case PPC_REG_V16: return RegisterInfo(PPC_REG_V16, 0, 4);
			case PPC_REG_V17: return RegisterInfo(PPC_REG_V17, 0, 4);
			case PPC_REG_V18: return RegisterInfo(PPC_REG_V18, 0, 4);
			case PPC_REG_V19: return RegisterInfo(PPC_REG_V19, 0, 4);
			case PPC_REG_V20: return RegisterInfo(PPC_REG_V20, 0, 4);
			case PPC_REG_V21: return RegisterInfo(PPC_REG_V21, 0, 4);
			case PPC_REG_V22: return RegisterInfo(PPC_REG_V22, 0, 4);
			case PPC_REG_V23: return RegisterInfo(PPC_REG_V23, 0, 4);
			case PPC_REG_V24: return RegisterInfo(PPC_REG_V24, 0, 4);
			case PPC_REG_V25: return RegisterInfo(PPC_REG_V25, 0, 4);
			case PPC_REG_V26: return RegisterInfo(PPC_REG_V26, 0, 4);
			case PPC_REG_V27: return RegisterInfo(PPC_REG_V27, 0, 4);
			case PPC_REG_V28: return RegisterInfo(PPC_REG_V28, 0, 4);
			case PPC_REG_V29: return RegisterInfo(PPC_REG_V29, 0, 4);
			case PPC_REG_V30: return RegisterInfo(PPC_REG_V30, 0, 4);
			case PPC_REG_V31: return RegisterInfo(PPC_REG_V31, 0, 4);
			case PPC_REG_VRSAVE: return RegisterInfo(PPC_REG_VRSAVE, 0, 4);
			case PPC_REG_VS0: return RegisterInfo(PPC_REG_VS0, 0, 4);
			case PPC_REG_VS1: return RegisterInfo(PPC_REG_VS1, 0, 4);
			case PPC_REG_VS2: return RegisterInfo(PPC_REG_VS2, 0, 4);
			case PPC_REG_VS3: return RegisterInfo(PPC_REG_VS3, 0, 4);
			case PPC_REG_VS4: return RegisterInfo(PPC_REG_VS4, 0, 4);
			case PPC_REG_VS5: return RegisterInfo(PPC_REG_VS5, 0, 4);
			case PPC_REG_VS6: return RegisterInfo(PPC_REG_VS6, 0, 4);
			case PPC_REG_VS7: return RegisterInfo(PPC_REG_VS7, 0, 4);
			case PPC_REG_VS8: return RegisterInfo(PPC_REG_VS8, 0, 4);
			case PPC_REG_VS9: return RegisterInfo(PPC_REG_VS9, 0, 4);
			case PPC_REG_VS10: return RegisterInfo(PPC_REG_VS10, 0, 4);
			case PPC_REG_VS11: return RegisterInfo(PPC_REG_VS11, 0, 4);
			case PPC_REG_VS12: return RegisterInfo(PPC_REG_VS12, 0, 4);
			case PPC_REG_VS13: return RegisterInfo(PPC_REG_VS13, 0, 4);
			case PPC_REG_VS14: return RegisterInfo(PPC_REG_VS14, 0, 4);
			case PPC_REG_VS15: return RegisterInfo(PPC_REG_VS15, 0, 4);
			case PPC_REG_VS16: return RegisterInfo(PPC_REG_VS16, 0, 4);
			case PPC_REG_VS17: return RegisterInfo(PPC_REG_VS17, 0, 4);
			case PPC_REG_VS18: return RegisterInfo(PPC_REG_VS18, 0, 4);
			case PPC_REG_VS19: return RegisterInfo(PPC_REG_VS19, 0, 4);
			case PPC_REG_VS20: return RegisterInfo(PPC_REG_VS20, 0, 4);
			case PPC_REG_VS21: return RegisterInfo(PPC_REG_VS21, 0, 4);
			case PPC_REG_VS22: return RegisterInfo(PPC_REG_VS22, 0, 4);
			case PPC_REG_VS23: return RegisterInfo(PPC_REG_VS23, 0, 4);
			case PPC_REG_VS24: return RegisterInfo(PPC_REG_VS24, 0, 4);
			case PPC_REG_VS25: return RegisterInfo(PPC_REG_VS25, 0, 4);
			case PPC_REG_VS26: return RegisterInfo(PPC_REG_VS26, 0, 4);
			case PPC_REG_VS27: return RegisterInfo(PPC_REG_VS27, 0, 4);
			case PPC_REG_VS28: return RegisterInfo(PPC_REG_VS28, 0, 4);
			case PPC_REG_VS29: return RegisterInfo(PPC_REG_VS29, 0, 4);
			case PPC_REG_VS30: return RegisterInfo(PPC_REG_VS30, 0, 4);
			case PPC_REG_VS31: return RegisterInfo(PPC_REG_VS31, 0, 4);
			case PPC_REG_VS32: return RegisterInfo(PPC_REG_VS32, 0, 4);
			case PPC_REG_VS33: return RegisterInfo(PPC_REG_VS33, 0, 4);
			case PPC_REG_VS34: return RegisterInfo(PPC_REG_VS34, 0, 4);
			case PPC_REG_VS35: return RegisterInfo(PPC_REG_VS35, 0, 4);
			case PPC_REG_VS36: return RegisterInfo(PPC_REG_VS36, 0, 4);
			case PPC_REG_VS37: return RegisterInfo(PPC_REG_VS37, 0, 4);
			case PPC_REG_VS38: return RegisterInfo(PPC_REG_VS38, 0, 4);
			case PPC_REG_VS39: return RegisterInfo(PPC_REG_VS39, 0, 4);
			case PPC_REG_VS40: return RegisterInfo(PPC_REG_VS40, 0, 4);
			case PPC_REG_VS41: return RegisterInfo(PPC_REG_VS41, 0, 4);
			case PPC_REG_VS42: return RegisterInfo(PPC_REG_VS42, 0, 4);
			case PPC_REG_VS43: return RegisterInfo(PPC_REG_VS43, 0, 4);
			case PPC_REG_VS44: return RegisterInfo(PPC_REG_VS44, 0, 4);
			case PPC_REG_VS45: return RegisterInfo(PPC_REG_VS45, 0, 4);
			case PPC_REG_VS46: return RegisterInfo(PPC_REG_VS46, 0, 4);
			case PPC_REG_VS47: return RegisterInfo(PPC_REG_VS47, 0, 4);
			case PPC_REG_VS48: return RegisterInfo(PPC_REG_VS48, 0, 4);
			case PPC_REG_VS49: return RegisterInfo(PPC_REG_VS49, 0, 4);
			case PPC_REG_VS50: return RegisterInfo(PPC_REG_VS50, 0, 4);
			case PPC_REG_VS51: return RegisterInfo(PPC_REG_VS51, 0, 4);
			case PPC_REG_VS52: return RegisterInfo(PPC_REG_VS52, 0, 4);
			case PPC_REG_VS53: return RegisterInfo(PPC_REG_VS53, 0, 4);
			case PPC_REG_VS54: return RegisterInfo(PPC_REG_VS54, 0, 4);
			case PPC_REG_VS55: return RegisterInfo(PPC_REG_VS55, 0, 4);
			case PPC_REG_VS56: return RegisterInfo(PPC_REG_VS56, 0, 4);
			case PPC_REG_VS57: return RegisterInfo(PPC_REG_VS57, 0, 4);
			case PPC_REG_VS58: return RegisterInfo(PPC_REG_VS58, 0, 4);
			case PPC_REG_VS59: return RegisterInfo(PPC_REG_VS59, 0, 4);
			case PPC_REG_VS60: return RegisterInfo(PPC_REG_VS60, 0, 4);
			case PPC_REG_VS61: return RegisterInfo(PPC_REG_VS61, 0, 4);
			case PPC_REG_VS62: return RegisterInfo(PPC_REG_VS62, 0, 4);
			case PPC_REG_VS63: return RegisterInfo(PPC_REG_VS63, 0, 4);
			default:
				LogError("%s(%d == \"%s\") invalid argument", __func__, 
				  regId, powerpc_reg_to_str(regId));
				return RegisterInfo(0,0,0);
		}
	}

	virtual uint32_t GetStackPointerRegister() override
	{
		//MYLOG("%s()\n", __func__);
		return PPC_REG_R1;
	}

	virtual uint32_t GetLinkRegister() override
	{
		//MYLOG("%s()\n", __func__);
		return PPC_REG_LR;
	}

	/*************************************************************************/

	bool Assemble(const string& code, uint64_t addr, DataBuffer& result, string& errors) override
	{
		MYLOG("%s()\n", __func__);

		/* prepend directives to command the assembler's origin and endianness */
		string src;
		char buf[1024];
		sprintf(buf, ".org %" PRIx64 "\n", addr);
		src += string(buf);
		sprintf(buf, ".endian %s\n", (endian==BigEndian) ? "big":"little");
		src += string(buf);
		src += code;

		/* assemble */	
		vector<uint8_t> byteEncoding;
		if(assemble_multiline(src, byteEncoding, errors)) {
			MYLOG("assemble_multiline() failed, errors contains: %s\n", errors.c_str());
			return false;
		}

		result.Clear();
		//for(int i=0; i<byteEncoding.size(); ++i)
		result.Append(&(byteEncoding[0]), byteEncoding.size());
		return true;
	}

	/*************************************************************************/

	virtual bool IsNeverBranchPatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override
	{
		(void)data;
		(void)addr;
		(void)len;
		MYLOG("%s()\n", __func__);
		return false;
	}

	virtual bool IsAlwaysBranchPatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override
	{
		(void)data;
		(void)addr;
		(void)len;

		MYLOG("%s()\n", __func__);

		if(len < 4) {
			MYLOG("data too small");
			return false;
		}

		uint32_t iw = *(uint32_t *)data;
		if(endian == BigEndian)
			iw = bswap32(iw);

		MYLOG("analyzing instruction word: 0x%08X\n", iw);

		if((iw & 0xfc000000) == 0x40000000) { /* BXX B-form */
			MYLOG("BXX B-form\n");
			return true;
		}

		if((iw & 0xfc0007fe) == 0x4c000020) { /* BXX to LR, XL-form */
			MYLOG("BXX to LR, XL-form\n");

			if((iw & 0x03E00000) != 0x02800000) /* is already unconditional? */
				return true;
		}

		if((iw & 0xfc0007fe) == 0x4c000420) { /* BXX to count reg, XL-form */
			MYLOG("BXX to count reg, XL-form\n");

			if((iw & 0x03E00000) != 0x02800000) /* is already unconditional? */
				return true;
		}

		return false;
	}

	virtual bool IsInvertBranchPatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override
	{
		(void)data;
		(void)addr;
		(void)len;
		MYLOG("%s()\n", __func__);

		if(len < 4) {
			MYLOG("data too small");
			return false;
		}

		uint32_t iw = *(uint32_t *)data;
		if(endian == BigEndian)
			iw = bswap32(iw);

		MYLOG("analyzing instruction word: 0x%08X\n", iw);

		if((iw & 0xfc000000) == 0x40000000) {
			MYLOG("BXX B-form\n");
		} else if((iw & 0xfc0007fe) == 0x4c000020) {
			MYLOG("BXX to LR, XL-form\n");
		} else if((iw & 0xfc0007fe) == 0x4c000420) {
			MYLOG("BXX to count reg, XL-form\n");
		} else {
			return false;
		}

		/* BO and BI exist in all 3 of the above forms */
		uint32_t bo = (iw >> 21) & 0x1F;
		if((bo & 0x1E) == 0) return true; // (--ctr)!=0 && cr_bi==0
		if((bo & 0x1E) == 2) return true; // (--ctr)==0 && cr_bi==0
		if((bo & 0x1C) == 4) return true; // cr_bi==0
		if((bo & 0x1E) == 8) return true; // (--ctr)!=0 && cr_bi==1
		if((bo & 0x1E) == 10) return true; // (--ctr)==0 && cr_bi==1
		if((bo & 0x1C) == 12) return true; // cr_bi==1
		return false;
	}

	virtual bool IsSkipAndReturnZeroPatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override
	{
		(void)data;
		(void)addr;
		(void)len;
		MYLOG("%s()\n", __func__);

		uint32_t iw = *(uint32_t *)data;
		if(endian == BigEndian)
			iw = bswap32(iw);

		MYLOG("analyzing instruction word: 0x%08X\n", iw);

		if((iw & 0xfc000001) == 0x48000001) {
			MYLOG("B I-form with LK==1\n");
			return true;
		} else if((iw & 0xfc000001) == 0x40000001) {
			MYLOG("BXX B-form with LK==1\n");
			return true;
		} else if((iw & 0xfc0007fe) == 0x4c000020) {
			MYLOG("BXX to LR, XL-form\n");
			return true;
		} else if((iw & 0xfc0007ff) == 0x4c000421) {
			MYLOG("BXX to count reg, XL-form with LK==1\n");
			return true;
		}

		return false;
	}

	virtual bool IsSkipAndReturnValuePatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override
	{
		(void)data;
		(void)addr;
		(void)len;
		MYLOG("%s()\n", __func__);
		return IsSkipAndReturnZeroPatchAvailable(data, addr, len);
	}

	/*************************************************************************/

	uint32_t bswap32(uint32_t x)
	{
		return ((x&0xFF)<<24) |
			((x&0xFF00)<<8) |
			((x&0xFF0000)>>8) |
			((x&0xFF000000)>>24);
	}

	virtual bool ConvertToNop(uint8_t* data, uint64_t, size_t len) override
	{
		(void)len;

		MYLOG("%s()\n", __func__);
		uint32_t nop;
		if(endian == LittleEndian)
			nop = 0x60000000;
		else
			nop = 0x00000060;
		if(len < 4)
			return false;
		for(size_t i=0; i<len/4; ++i)
			((uint32_t *)data)[i] = nop;
		return true;
	}

	virtual bool AlwaysBranch(uint8_t* data, uint64_t addr, size_t len) override
	{
		MYLOG("%s()\n", __func__);

		(void)len;
		(void)addr;

		uint32_t iwAfter = 0;
		uint32_t iwBefore = *(uint32_t *)data;
		if(endian == BigEndian)
			iwBefore = bswap32(iwBefore);

		if((iwBefore & 0xfc000000) == 0x40000000) { /* BXX B-form */
			MYLOG("BXX B-form\n");

			uint32_t li_aa_lk = iwBefore & 0xffff; /* grab BD,AA,LK */
			if(li_aa_lk & 0x8000) /* sign extend? */
				li_aa_lk |= 0x03FF0000;

			iwAfter = 0x48000000 | li_aa_lk;
		}
		else
		if((iwBefore & 0xfc0007fe) == 0x4c000020) { /* BXX to LR, XL-form */
			MYLOG("BXX to LR, XL-form\n");

			iwAfter = (iwBefore & 0xFC1FFFFF) | 0x02800000; /* set BO = 10100 */
		}
		else
		if((iwBefore & 0xfc0007fe) == 0x4c000420) { /* BXX to count reg, XL-form */
			MYLOG("BXX to count reg, XL-form\n");

			iwAfter = (iwBefore & 0xFC1FFFFF) | 0x02800000; /* set BO = 10100 */
		}
		else {
			return false;
		}
		
		if(endian == BigEndian)
			iwAfter = bswap32(iwAfter);
		*(uint32_t *)data = iwAfter;
		return true;	
	}

	virtual bool InvertBranch(uint8_t* data, uint64_t addr, size_t len) override
	{
		(void)data;
		(void)addr;
		(void)len;
		MYLOG("%s()\n", __func__);

		if(len < 4) {
			MYLOG("data too small");
			return false;
		}

		uint32_t iw = *(uint32_t *)data;
		if(endian == BigEndian)
			iw = bswap32(iw);

		MYLOG("analyzing instruction word: 0x%08X\n", iw);

		if((iw & 0xfc000000) == 0x40000000) {
			MYLOG("BXX B-form\n");
		} else if((iw & 0xfc0007fe) == 0x4c000020) {
			MYLOG("BXX to LR, XL-form\n");
		} else if((iw & 0xfc0007fe) == 0x4c000420) {
			MYLOG("BXX to count reg, XL-form\n");
		} else {
			return false;
		}

		iw ^= 0x1000000;

		/* success */
		if(endian == BigEndian)
			iw = bswap32(iw);
		*(uint32_t *)data = iw;
		return true;	
	}

	virtual bool SkipAndReturnValue(uint8_t* data, uint64_t addr, size_t len, uint64_t value) override
	{
		(void)data;
		(void)addr;
		(void)len;
		(void)value;
		MYLOG("%s()\n", __func__);

		if(value > 0x4000)
			return false;

		/* li (load immediate) is pseudo-op for addi rD,rA,SIMM with rA=0 */
		uint32_t iw = 0x38600000 | (value & 0xFFFF); // li (load immediate)

		/* success */
		if(endian == BigEndian)
			iw = bswap32(iw);
		*(uint32_t *)data = iw;
		return true;	
	}

	/*************************************************************************/

};

class PpcImportedFunctionRecognizer: public FunctionRecognizer
{
	private:
	bool RecognizeELFPLTEntries(BinaryView* data, Function* func, LowLevelILFunction* il)
	{
		MYLOG("%s()\n", __func__);
		LowLevelILInstruction lis, lwz, mtctr, tmp;
		int64_t entry, constGotBase;
		uint32_t regGotBase, regJump;

		// lis   r11, 0x1002     ; r11 -> base of GOT
		// lwz   r11, ???(r11)   ; get GOT[???]
		// mtctr r11             ; move to ctr
		// bctr                  ; branch to ctr
		if(il->GetInstructionCount() != 4)
			return false;

		//
		// LIS   r11, 0x1002
		//
		lis = il->GetInstruction(0);
		if(lis.operation != LLIL_SET_REG)
			return false;
		/* get the constant, address of GOT */
		tmp = lis.GetSourceExpr<LLIL_SET_REG>();
		if ((tmp.operation != LLIL_CONST) && (tmp.operation != LLIL_CONST_PTR))
			return false;
		constGotBase = tmp.GetConstant();
		/* get the destination register, is assigned the address of GOT */
		regGotBase = lis.GetDestRegister<LLIL_SET_REG>();
		
		//
		// LWZ   r11, ???(r11)
		//
		lwz = il->GetInstruction(1);
		if(lwz.operation != LLIL_SET_REG)
			return false;

		if(lwz.GetDestRegister<LLIL_SET_REG>() != regGotBase) // lwz must assign to same reg
			return false;

		tmp = lwz.GetSourceExpr<LLIL_SET_REG>(); // lwz must read from LOAD
		if(tmp.operation != LLIL_LOAD)
			return false;

		// "dereference" the load(...) to get either:
		tmp = tmp.GetSourceExpr<LLIL_LOAD>();
		// r11         (LLIL_REG)
		if(tmp.operation == LLIL_REG) {
			if(regGotBase != tmp.GetSourceRegister<LLIL_REG>()) // lwz must read from same reg
				return false;

			entry = constGotBase;
		}
		// r11 + ???   (LLIL_ADD)
		else if(tmp.operation == LLIL_ADD) {
			LowLevelILInstruction lhs, rhs;

			lhs = tmp.GetLeftExpr<LLIL_ADD>();
			rhs = tmp.GetRightExpr<LLIL_ADD>();

			if(lhs.operation != LLIL_REG)
				return false;
			if(lhs.GetSourceRegister<LLIL_REG>() != regGotBase)
				return false;

			if(rhs.operation != LLIL_CONST)
				return false;

			entry = constGotBase + rhs.GetConstant();
		}
		else {
			return false;
		}

		//
		// MTCTR
		//
		mtctr = il->GetInstruction(2);
		if(mtctr.operation != LLIL_SET_REG)
			return false;
		/* from regGotBase */
		tmp = mtctr.GetSourceExpr();
		if(tmp.operation != LLIL_REG)
			return false;
		if(tmp.GetSourceRegister<LLIL_REG>() != regGotBase)
			return false;
		/* to new register (probably CTR) */
		regJump = mtctr.GetDestRegister<LLIL_SET_REG>();

		//
		// JUMP
		//
		tmp = il->GetInstruction(3);
		if(tmp.operation != LLIL_JUMP)
			return false;
		tmp = tmp.GetDestExpr<LLIL_JUMP>();
		if(tmp.operation != LLIL_REG)
			return false;
		if(tmp.GetSourceRegister<LLIL_REG>() != regJump)
			return false;

		// done!
		Ref<Symbol> sym = data->GetSymbolByAddress(entry);
		if (!sym) {
			return false;
		}
		if (sym->GetType() != ImportAddressSymbol) {
			return false;
		}
		data->DefineImportedFunction(sym, func);

		return true;
	}

	bool RecognizeMachoPLTEntries(BinaryView* data, Function* func, LowLevelILFunction* il)
	{
		(void)data;
		(void)func;
		(void)il;

		MYLOG("%s()\n", __func__);

		return false;
	}

	public:
	virtual bool RecognizeLowLevelIL(BinaryView* data, Function* func, LowLevelILFunction* il) override
	{
		if (RecognizeELFPLTEntries(data, func, il))
			return true;
		else if (RecognizeMachoPLTEntries(data, func, il))
			return true;
		return false;
	}
};

class PpcSvr4CallingConvention: public CallingConvention
{
public:
	PpcSvr4CallingConvention(Architecture* arch): CallingConvention(arch, "svr4")
	{
	}


	virtual vector<uint32_t> GetIntegerArgumentRegisters() override
	{
		return vector<uint32_t>{
			PPC_REG_R3, PPC_REG_R4, PPC_REG_R5, PPC_REG_R6,
			PPC_REG_R7, PPC_REG_R8, PPC_REG_R9,	PPC_REG_R10
			/* remaining arguments onto stack */
		};
	}


	virtual vector<uint32_t> GetFloatArgumentRegisters() override
	{
		return vector<uint32_t>{ 
			PPC_REG_F1, PPC_REG_F2, PPC_REG_F3, PPC_REG_F4,
			PPC_REG_F5, PPC_REG_F6, PPC_REG_F7, PPC_REG_F8,
			PPC_REG_F9, PPC_REG_F10, PPC_REG_F11, PPC_REG_F12,
			PPC_REG_F13
		};
	}


	virtual vector<uint32_t> GetCallerSavedRegisters() override
	{
		return vector<uint32_t>{
			PPC_REG_R13, PPC_REG_R14, PPC_REG_R15, PPC_REG_R16,
			PPC_REG_R17, PPC_REG_R18, PPC_REG_R19, PPC_REG_R20,
			PPC_REG_R21, PPC_REG_R22, PPC_REG_R23, PPC_REG_R24,
			PPC_REG_R25, PPC_REG_R26, PPC_REG_R27, PPC_REG_R28,
			PPC_REG_R29, PPC_REG_R30, PPC_REG_R31
		};
	}


	virtual uint32_t GetIntegerReturnValueRegister() override
	{
		return PPC_REG_R3;
	}


	virtual uint32_t GetFloatReturnValueRegister() override
	{
		return PPC_REG_F1;
	}
};

class PpcLinuxSyscallCallingConvention: public CallingConvention
{
public:
	PpcLinuxSyscallCallingConvention(Architecture* arch): CallingConvention(arch, "linux-syscall")
	{
	}

	virtual vector<uint32_t> GetIntegerArgumentRegisters() override
	{
		return vector<uint32_t>{
			PPC_REG_R0,
			PPC_REG_R3, PPC_REG_R4, PPC_REG_R5, PPC_REG_R6,
			PPC_REG_R7, PPC_REG_R8, PPC_REG_R9,	PPC_REG_R10
		};
	}

	virtual vector<uint32_t> GetCallerSavedRegisters() override
	{
		return vector<uint32_t>{
			PPC_REG_R3
		};
	}

	virtual uint32_t GetIntegerReturnValueRegister() override
	{
		return PPC_REG_R3;
	}
};

extern "C"
{
	BINARYNINJAPLUGIN bool CorePluginInit()
	{
		MYLOG("ARCH POWERPC compiled at %s %s\n", __DATE__, __TIME__);

		/* create, register arch in global list of available architectures */
		Architecture* ppc = new PowerpcArchitecture("ppc", BigEndian);
		Architecture::Register(ppc);

		/* calling conventions */
		Ref<CallingConvention> conv;
		conv = new PpcSvr4CallingConvention(ppc);
		ppc->RegisterCallingConvention(conv);
		ppc->SetDefaultCallingConvention(conv);
		conv = new PpcLinuxSyscallCallingConvention(ppc);
		ppc->RegisterCallingConvention(conv);

		/* function recognizer */
		ppc->RegisterFunctionRecognizer(new PpcImportedFunctionRecognizer());
		ppc->SetBinaryViewTypeConstant("ELF", "R_COPY", 19);
		ppc->SetBinaryViewTypeConstant("ELF", "R_GLOBAL_DATA", 20);
		ppc->SetBinaryViewTypeConstant("ELF", "R_JUMP_SLOT", 21);

		/* call the STATIC RegisterArchitecture with "Mach-O"
			which invokes the "Mach-O" INSTANCE of RegisterArchitecture,
			supplied with CPU_TYPE_POWERPC from machoview.h */
		#define MACHO_CPU_TYPE_ARM 12
		#define MACHO_CPU_TYPE_POWERPC 18 /* from machostruct.h */
		BinaryViewType::RegisterArchitecture(
			"Mach-O", /* name of the binary view type */
			MACHO_CPU_TYPE_POWERPC, /* id (key in m_arch map) */
			BigEndian,
			ppc /* the architecture */
		);

		BinaryViewType::RegisterArchitecture(
			"Mach-O", /* name of the binary view type */
			MACHO_CPU_TYPE_POWERPC, /* id (key in m_arch map) */
			LittleEndian,
			ppc /* the architecture */
		);

		/* for e_machine field in Elf32_Ehdr */
		#define EM_386 3
		#define EM_PPC 20
		#define EM_PPC64 21
		#define EM_X86_64 62
		BinaryViewType::RegisterArchitecture(
			"ELF", /* name of the binary view type */
			EM_PPC, /* id (key in m_arch map) */
			BigEndian,
			ppc /* the architecture */
		);

		BinaryViewType::RegisterArchitecture(
			"ELF", /* name of the binary view type */
			EM_PPC, /* id (key in m_arch map) */
			LittleEndian,
			ppc /* the architecture */
		);

		return true;
	}
}
