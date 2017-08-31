# binja_ppc
PowerPC Architecture Plugin for Binary Ninja

Capstone will temporarily be used as the disassembler. Along with the lifter, this will all be wrapped into an architecture plugin for Binary Ninja. Currently development is on MacOS.

# gotchas and catches
* "json/json.h" from binaryninjaapi.h doesn't exist yet in the api, so you'll roadblock just by including this file
* if you're internal, do `ln -s ~/repos/v35/binaryninja/core/json ./json`


