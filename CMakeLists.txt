cmake_minimum_required(VERSION 3.13 FATAL_ERROR)

project(arch_ppc)

if((NOT BN_API_PATH) AND (NOT BN_INTERNAL_BUILD))
	set(BN_API_PATH $ENV{BN_API_PATH})
	if(NOT BN_API_PATH)
		message(FATAL_ERROR "Provide path to Binary Ninja API source in BN_API_PATH")
	endif()
endif()
if(NOT BN_INTERNAL_BUILD)
	add_subdirectory(${BN_API_PATH} ${PROJECT_BINARY_DIR}/api)
endif()

file(GLOB SOURCES
	arch_ppc.cpp
	assembler.cpp
	disassembler.cpp
	il.cpp
	util.cpp
	*.h
)

if(DEMO)
	add_library(arch_ppc STATIC ${SOURCES})
else()
	add_library(arch_ppc SHARED ${SOURCES})
endif()

if(BN_INTERNAL_BUILD)
	if(MSVC)
		find_library(CAPSTONE_LIBRARY NAMES capstone_static
			PATHS ${PROJECT_SOURCE_DIR}/../../../capstone/windows
			REQUIRED NO_DEFAULT_PATH)
	elseif(APPLE)
		find_library(CAPSTONE_LIBRARY NAMES capstone
			PATHS ${PROJECT_SOURCE_DIR}/../../../capstone/mac
			REQUIRED NO_DEFAULT_PATH)
	else()
		find_library(CAPSTONE_LIBRARY NAMES capstone
			PATHS ${PROJECT_SOURCE_DIR}/../../../capstone/linux
			REQUIRED NO_DEFAULT_PATH)
	endif()
else()
	find_library(CAPSTONE_LIBRARY NAMES capstone REQUIRED)
endif()

add_library(capstone STATIC IMPORTED)
set_target_properties(capstone PROPERTIES
	IMPORTED_LOCATION ${CAPSTONE_LIBRARY})
	
target_link_libraries(arch_ppc binaryninjaapi capstone)

if(UNIX AND NOT APPLE)
	target_link_options(arch_ppc PRIVATE "LINKER:--exclude-libs,ALL")
endif()

set_target_properties(arch_ppc PROPERTIES
    CXX_STANDARD 17
	CXX_VISIBILITY_PRESET hidden
	CXX_STANDARD_REQUIRED ON
    VISIBILITY_INLINES_HIDDEN ON
	POSITION_INDEPENDENT_CODE ON)

if(BN_INTERNAL_BUILD)
	target_include_directories(arch_ppc PRIVATE ${PROJECT_SOURCE_DIR}/../../../capstone/include)
	plugin_rpath(arch_ppc)
	set_target_properties(arch_ppc PROPERTIES
		LIBRARY_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR}
		RUNTIME_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR})
endif()
