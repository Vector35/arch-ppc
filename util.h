inline uint32_t bswap32(uint32_t x)
{
	return ((x&0xFF)<<24) |
		((x&0xFF00)<<8) |
		((x&0xFF0000)>>8) |
		((x&0xFF000000)>>24);
}

void printOperandVerbose(decomp_result *res, cs_ppc_op *opers);
void printInstructionVerbose(decomp_result *res);
