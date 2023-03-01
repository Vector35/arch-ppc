# ppc-capstone
This is a PowerPC architecture plugin for Binary Ninja.

## Issues

Issues for this repository have been disabled. Please file an issue for this repository at https://github.com/Vector35/binaryninja-api/issues. All previously existing issues for this repository have been transferred there as well.


## This Repo Demonstrates

* use of an existing disassembler (capstone) in making an architecture
* use of the genetic algorithm for assembling (oracle: capstone)
* proper lifting

Note that assembler.cpp and test_asm.cpp are isolated, in that they do not include any binja headers or link against any binja libs. This allows quick command line compilation, debugging, and testing:

`g++ -std=c++11 -O0 -g test_asm.cpp assembler.cpp -o test_asm -lcapstone`

A similar situation exists for disassembler.cpp and test_disasm.cpp:

`g++ -std=c++11 -O0 -g test_disasm.cpp disassembler.cpp -o test_disasm -lcapstone`

## Building

Building the architecture plugin requires `cmake` 3.13 or above. You will also need the
[Binary Ninja API source](https://github.com/Vector35/binaryninja-api) and
[capstone](https://github.com/aquynh/capstone).

First, set the `BN_API_PATH` environment variable to the path containing the
Binary Ninja API source tree.

Run `cmake`. This can be done either from a separate build directory or from the source
directory. Once that is complete, run `make` in the build directory to compile the plugin.

The plugin can be found in the root of the build directory as `libarch_ppc.so`,
`libarch_ppc.dylib` or `arch_ppc.dll` depending on your platform.

To install the plugin, first launch Binary Ninja and uncheck the "PowerPC architecture plugin"
option in the "Core Plugins" section. This will cause Binary Ninja to stop loading the
bundled plugin so that its replacement can be loaded. Once this is complete, you can copy
the plugin into the user plugins directory (you can locate this by using the "Open Plugin Folder"
option in the Binary Ninja UI).

**Do not replace the architecture plugin in the Binary Ninja install directory. This will
be overwritten every time there is a Binary Ninja update. Use the above process to ensure that
updates do not automatically uninstall your custom build.**

## License

This code MIT licensed, see [LICENSE.txt](./license.txt).

It links against the [Capstone disassembly framework](https://github.com/aquynh/capstone) which is BSD licensed.
