#pragma once
#include <string>
#include "pe_parser.h"
#include <vector>
#include <Windows.h>

EXTERN_C int syscall_num(unsigned long hash, PE_PARSER& parser, std::vector<uint8_t>& fileData);
EXTERN_C BYTE* syscall_address(PE_PARSER& parser, std::vector<uint8_t>& fileData);