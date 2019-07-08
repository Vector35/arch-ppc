# ppc-capstone
This is a PowerPC architecture plugin for Binary Ninja.

It demonstrates:

* use of an existing disassembler (capstone) in making an architecture
* use of the genetic algorithm for assembling (oracle: capstone)
* proper lifting

Note that assembler.cpp and test_asm.cpp are isolated, in that they do not include any binja headers or link against any binja libs. This allows quick command line compilation, debugging, and testing:

`g++ -std=c++11 -O0 -g test_asm.cpp assembler.cpp -o test_asm -lcapstone`

A similar situation exists for disassembler.cpp and test_disasm.cpp:

`g++ -std=c++11 -O0 -g test_disasm.cpp disassembler.cpp -o test_disasm -lcapstone`

## License

This code MIT licensed, see [LICENSE.txt](./license.txt).

It links against the [Capstone disassembly framework](https://github.com/aquynh/capstone) which is BSD licensed.