/* this is intended for use by BINJA */
int assemble_multiline(const string& code, vector<uint8_t>& result, string& err);

/* this is lower level API intended to be use by benchmarking tools (eg: test_asm.cpp) */
int assemble_single(string src, uint32_t addr, uint8_t *result, string& err, int& failures);
int disasm_capstone(uint8_t *data, uint32_t addr, string& result, string& err);
