#include <Windows.h>
#include <iostream>
#include <vector>
#include <cinttypes>
#include <fstream>
#include "syscall_retriever.h"
#include "pe_parser.h"
#include "hash.h"

int GetSyscallNumber(const std::vector<uint8_t>& fileData, DWORD startOffset) {
    if (startOffset >= fileData.size()) {
        return 0;
    }
    size_t currentOffset = startOffset;
    bool syscallFound = false;
    while (currentOffset < fileData.size() - 1) {
        uint8_t byte1 = fileData[currentOffset];
        uint8_t byte2 = fileData[currentOffset + 1];

        if (byte1 == 0x0F && byte2 == 0x05) {
            syscallFound = true;
            return fileData[currentOffset - 14];
        }
        currentOffset+=1;
    }
    return 0;
}

DWORD offset_to_rva(PE_PARSER& parser, DWORD offset) {
    DWORD RVA = 0;
    for (int i = 0; i < parser.NT_HEADERS64.FileHeader.NumberOfSections; i++) {
        if (parser.Section_Headers[i].VirtualAddress + parser.Section_Headers[i].PointerToRawData < offset && offset < (parser.Section_Headers[i].VirtualAddress + parser.Section_Headers[i].PointerToRawData + parser.Section_Headers[i].Misc.VirtualSize)) {
            RVA = offset + parser.Section_Headers[i].VirtualAddress - parser.Section_Headers[i].PointerToRawData;
            break;
        }
    }
    return RVA;
}


DWORD rva_to_offset(PE_PARSER& parser, DWORD RVA) {
    DWORD offset = 0;
    for (int i = 0; i < parser.NT_HEADERS64.FileHeader.NumberOfSections; i++) {
        if (parser.Section_Headers[i].VirtualAddress < RVA && RVA < parser.Section_Headers[i].VirtualAddress + parser.Section_Headers[i].Misc.VirtualSize) {
            offset = RVA - parser.Section_Headers[i].VirtualAddress + parser.Section_Headers[i].PointerToRawData;
            break;
        }
    }
    return offset;
}

DWORD RVAExportedFunctions(PE_PARSER* parser, std::vector<uint8_t>*fileData, unsigned long hash) {
    auto exportDirRVA = parser->NT_HEADERS64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!exportDirRVA) {
        exit(1);
    }

    DWORD exportDirOffset = rva_to_offset(*parser, exportDirRVA);

    if (exportDirOffset >= fileData->size()) {
        return 0;
    }

    auto exportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(fileData->data() + exportDirOffset);
    auto namesRVA = reinterpret_cast<DWORD*>(fileData->data() + rva_to_offset(*parser,exportDir->AddressOfNames));
    auto funcsRVA = reinterpret_cast<DWORD*>(fileData->data() + rva_to_offset(*parser,exportDir->AddressOfFunctions));
    auto ordinals = reinterpret_cast<WORD*>(fileData->data() + rva_to_offset(*parser,exportDir->AddressOfNameOrdinals));

    for (DWORD i = 0; i < exportDir->NumberOfNames; ++i) {
        DWORD nameOffset = rva_to_offset(*parser,namesRVA[i]);
        if (nameOffset >= fileData->size()) {
            std::cerr << "Invalid name offset: " << std::hex<<(DWORD)nameOffset << std::endl;
            return 0;
        }
        std::string funcName;
        funcName = reinterpret_cast<char*>(fileData->data() + nameOffset);
        
        if (calcHash(funcName) == hash) {
            auto funcAddress = funcsRVA[ordinals[i]];
            return (DWORD)funcAddress;
        }
    }
    return 0;
}


int syscall_num(unsigned long hash, PE_PARSER &parser, std::vector<uint8_t>&fileData) {
    DWORD RVA = RVAExportedFunctions(&parser, &fileData, hash);
    if (!RVA) {
        return 1;
    }
    DWORD offset = parser.rva_to_offset(RVA);
    int syscall_number_hex=GetSyscallNumber(fileData, offset);
    return syscall_number_hex;
}

BYTE* syscall_address(PE_PARSER& parser, std::vector<uint8_t>& fileData) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll"); 
    if (hNtdll == NULL) {
        exit(-1);
    }
    DWORD offset = rva_to_offset(parser, RVAExportedFunctions(&parser, &fileData, 1981666927));
    BYTE * func_base = &fileData[offset];

    BYTE* temp_base = 0x00;
    while (*func_base != 0xc3) {
        temp_base = func_base;
        if (*temp_base == 0x0f) {
            temp_base++;
            if (*temp_base == 0x05) {
                temp_base++;
                if (*temp_base == 0xc3) {
                    temp_base = func_base;
                    break;
                }
            }
        }
        else {
            func_base++;
            offset++;
            temp_base = 0x00;
        }
    }
    return (BYTE*)(offset_to_rva(parser,offset)+ (DWORD64)hNtdll);
}
