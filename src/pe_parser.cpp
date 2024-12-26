#include <Windows.h>
#include <string>
#include <vector>
#include <fstream>
#include <iostream>
#include <iomanip>
#include "pe_parser.h"

std::vector<unsigned char> PE_PARSER::populate_pe_bytes() {
	std::ifstream input(this->file_path, std::ios::binary);
	if (!input or !input.is_open()) {
		std::cerr << "Could not open file" << "\n";
		return {};
	}
	std::vector<unsigned char> magic_bytes = { 'M','Z' };
	std::vector<unsigned char> bytes = std::vector<unsigned char>(std::istreambuf_iterator<char>(input), {});
	if (memcmp(&bytes[0], &magic_bytes[0], 2) == 0) {
		return bytes;
	}
	else {
		return {};
	}
}

void PE_PARSER::populate_dos_header() {
	DOS_HEADER.e_magic = READ_WORD();
	DOS_HEADER.e_cblp = READ_WORD();
	DOS_HEADER.e_cp = READ_WORD();
	DOS_HEADER.e_crlc = READ_WORD();
	DOS_HEADER.e_cparhdr = READ_WORD();
	DOS_HEADER.e_minalloc = READ_WORD();
	DOS_HEADER.e_maxalloc = READ_WORD();
	DOS_HEADER.e_ss = READ_WORD();
	DOS_HEADER.e_sp = READ_WORD();
	DOS_HEADER.e_csum = READ_WORD();
	DOS_HEADER.e_ip = READ_WORD();
	DOS_HEADER.e_cs = READ_WORD();
	DOS_HEADER.e_lfarlc = READ_WORD();
	DOS_HEADER.e_ovno = READ_WORD();
	DOS_HEADER.e_res[0] = READ_WORD(); DOS_HEADER.e_res[1] = READ_WORD(); DOS_HEADER.e_res[2] = READ_WORD(); DOS_HEADER.e_res[3] = READ_WORD();
	DOS_HEADER.e_oemid = READ_WORD();
	DOS_HEADER.e_oeminfo = READ_WORD();
	for (int i = 0; i < 10; i++) {
		DOS_HEADER.e_res2[i] = READ_WORD();
	}
	DOS_HEADER.e_lfanew = READ_DWORD();
	this->offset = DOS_HEADER.e_lfanew;
}

void PE_PARSER::populate_nt_header() {
	if (!is32bit) {
		this->NT_HEADERS64.Signature = READ_DWORD();
		this->NT_HEADERS64.FileHeader = *(reinterpret_cast<IMAGE_FILE_HEADER*>(&pe_bytes[offset]));
		offset += sizeof(IMAGE_FILE_HEADER);
		this->NT_HEADERS64.OptionalHeader = *(reinterpret_cast<PIMAGE_OPTIONAL_HEADER64>(&pe_bytes[offset]));
		offset += sizeof(IMAGE_OPTIONAL_HEADER64);
	}
	else {
		this->NT_HEADERS32.Signature = READ_DWORD();
		this->NT_HEADERS32.FileHeader = *(reinterpret_cast<IMAGE_FILE_HEADER*>(&pe_bytes[offset]));
		offset += sizeof(IMAGE_FILE_HEADER);
		this->NT_HEADERS32.OptionalHeader = *(reinterpret_cast<IMAGE_OPTIONAL_HEADER32*>(&pe_bytes[offset]));
		offset += sizeof(IMAGE_OPTIONAL_HEADER32);
	}
}

void PE_PARSER::populate_section_headers32() {
	int number_sections = NT_HEADERS32.FileHeader.NumberOfSections;
	for (int i = 0; i < number_sections; i++) {
		IMAGE_SECTION_HEADER section_header = *(reinterpret_cast<IMAGE_SECTION_HEADER*>(&pe_bytes[offset]));
		Section_Headers.push_back(section_header);
		offset += sizeof(IMAGE_SECTION_HEADER);
	}

}

void PE_PARSER::populate_section_headers64() {
	int number_sections = NT_HEADERS64.FileHeader.NumberOfSections;
	for (int i = 0; i < number_sections; i++) {
		IMAGE_SECTION_HEADER section_header = *(reinterpret_cast<IMAGE_SECTION_HEADER*>(&pe_bytes[offset]));
		Section_Headers.push_back(section_header);
		offset += sizeof(IMAGE_SECTION_HEADER);
	}
}

bool PE_PARSER::get_bitness() {
	offset = DOS_HEADER.e_lfanew + 0x18;
	WORD optional_header_magic = READ_WORD();
	if (optional_header_magic == 0x10B) {
		offset = DOS_HEADER.e_lfanew;
		return 1;
	}
	else {
		offset = DOS_HEADER.e_lfanew;
		return 0;
	}
	return 0;
}

void PE_PARSER::Display_General_Info() {
	std::string base_filename = file_path.substr(file_path.find_last_of("/\\") + 1);
	std::cout << "General\n";
	std::cout << "--------------------------------------\n";
	std::cout << "File Name: " << base_filename << "\n";
	std::cout << "Size in bytes: " << pe_bytes.size() << "\n";
	if (is32bit) {
		std::cout << "Bitness: " << "x86" << "\n";
	}
	else {
		std::cout << "Bitness: " << "x64" << "\n";
	}
	std::cout << "----------------------------------------\n";
	std::cout << "\n\n";

}

void PE_PARSER::Display_Directories() {
	std::vector<std::string> data_directories_name = { "EXPORT","IMPORT","RESOURCE","EXCEPTION","SECURITY", "BASERELOC","DEBUG","COPYRIGHT",
		"ARCHITECTURE","GLOBALPTR","TLS","LOAD_CONFIG","BOUND_IMPORT","IAT","DELAY_IMPORT","COM_DESCRIPTOR" };
	std::cout << "Directory Name |  RVA   | SIZE" << "\n";
	std::cout << "--------------------------------" << "\n";
	for (int i = 0; i < 16; i++) {
		if (!is32bit) {
			std::cout << std::left << std::setw(14) << std::setfill(' ') << data_directories_name[i] << " | " << std::right << std::setw(6) << std::setfill('0') << std::hex << NT_HEADERS64.OptionalHeader.DataDirectory[i].VirtualAddress << " | " << NT_HEADERS64.OptionalHeader.DataDirectory[i].Size << "\n";
		}
		else {
			std::cout << std::left << std::setw(14) << std::setfill(' ') << data_directories_name[i] << " | " << std::right << std::setw(6) << std::setfill('0') << std::hex << NT_HEADERS32.OptionalHeader.DataDirectory[i].VirtualAddress << " | " << NT_HEADERS32.OptionalHeader.DataDirectory[i].Size << "\n";
		}
	}
	std::cout << "--------------------------------" << "\n";
	std::cout << "\n";
	std::cout << "\n";
}

void PE_PARSER::Display_Imports() {
	for (int i = 0; i < pe_imports.size(); i++) {
		IMAGE_IMPORT_DESCRIPTOR import = pe_imports[i];
		DWORD offset_name = rva_to_offset(import.Name);
		std::string name;

		unsigned char temp = *(reinterpret_cast<unsigned char*>(&pe_bytes[offset_name]));
		while (temp != 0x0) {
			name += temp;
			offset_name += sizeof(unsigned char);
			temp = *(reinterpret_cast<unsigned char*>(&pe_bytes[offset_name]));
		}
		std::cout << "Module Name : " << name << "\n";
		std::cout << "______________________________________________________________________________" << "\n";
		PE_PARSER::Display_Imported_Functions(rva_to_offset(import.FirstThunk));
	}
}

std::vector<IMAGE_IMPORT_DESCRIPTOR> PE_PARSER::get_imports() {
	std::vector<IMAGE_IMPORT_DESCRIPTOR> imports;
	std::vector<IMAGE_SECTION_HEADER>::iterator i;
	IMAGE_SECTION_HEADER* i_data = NULL;
	static const char zeroed_out[20];
	unsigned char name[] = ".idata";
	for (i = Section_Headers.begin(); i != Section_Headers.end(); i++) {
		if (memcmp(i->Name, &name, 7) == 0)
		{
			i_data = i._Ptr;
			offset = i_data->PointerToRawData;
		}
	}
	if (!i_data) {
		if (!is32bit) {
			offset = rva_to_offset(NT_HEADERS64.OptionalHeader.DataDirectory[1].VirtualAddress);
			int i = 0;
			while (memcmp(zeroed_out, &pe_bytes[offset], 20) != 0) {
				i++;
				IMAGE_IMPORT_DESCRIPTOR	import = *(reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(&pe_bytes[offset]));
				imports.emplace_back(import);
				offset += sizeof(IMAGE_IMPORT_DESCRIPTOR);
			}
		}
		else {
			offset = rva_to_offset(NT_HEADERS32.OptionalHeader.DataDirectory[1].VirtualAddress);
			int i = 0;
			while (memcmp(zeroed_out, &pe_bytes[offset], 20) != 0) {
				i++;
				IMAGE_IMPORT_DESCRIPTOR	import = *(reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(&pe_bytes[offset]));
				imports.emplace_back(import);
				offset += sizeof(IMAGE_IMPORT_DESCRIPTOR);
			}
		}
	}
	else {
		int i = 0;
		while (memcmp(zeroed_out, &pe_bytes[offset], 20) != 0) {
			i++;
			IMAGE_IMPORT_DESCRIPTOR	import = *(reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(&pe_bytes[offset]));
			imports.emplace_back(import);
			offset += sizeof(IMAGE_IMPORT_DESCRIPTOR);
		}
	}
	return imports;
}

DWORD PE_PARSER::rva_to_offset(DWORD RVA) {
	DWORD offset = 0;
	if (!is32bit) {
		for (int i = 0; i < NT_HEADERS64.FileHeader.NumberOfSections; i++) {
			if (Section_Headers[i].VirtualAddress < RVA && RVA < Section_Headers[i].VirtualAddress + Section_Headers[i].Misc.VirtualSize) {
				offset = RVA - Section_Headers[i].VirtualAddress + Section_Headers[i].PointerToRawData;
				break;
			}
		}
	}
	else {
		for (int i = 0; i < NT_HEADERS32.FileHeader.NumberOfSections; i++) {
			if (Section_Headers[i].VirtualAddress < RVA && RVA < Section_Headers[i].VirtualAddress + Section_Headers[i].Misc.VirtualSize) {
				offset = RVA - Section_Headers[i].VirtualAddress + Section_Headers[i].PointerToRawData;
				break;
			}
		}
	}
	return offset;
}

void PE_PARSER::Display_Imported_Functions(DWORD FirstThunkDLL) {
	static const char zeroed_out[8];
	offset = FirstThunkDLL;
	if (!is32bit) {
		while (memcmp(zeroed_out, &pe_bytes[offset], 8) != 0) {
			WORD hint = pe_bytes[rva_to_offset(PEEK_DWORD())] | (pe_bytes[rva_to_offset(PEEK_DWORD() + 1)] << 8);
			DWORD original_thunk = PEEK_DWORD() + sizeof(WORD);
			DWORD function_thunk = rva_to_offset(original_thunk);
			std::string name;
			unsigned char temp = pe_bytes[function_thunk];
			while (temp != 0x0) {
				name += temp;
				function_thunk += sizeof(unsigned char);
				temp = pe_bytes[function_thunk];
			}
			std::cout << "| Function Name : " << std::setw(30) << std::left << std::setfill(' ') << name << "  |  " << std::setw(6) << std::left << "Hint :" << std::setw(3) << (int)hint << "  |  " << "RVA : " << std::hex << (int)original_thunk - 2 << "| \n";
			offset += 8;
		}
	}
	else {
		while (memcmp(zeroed_out, &pe_bytes[offset], 4) != 0) {
			WORD hint = pe_bytes[rva_to_offset(PEEK_DWORD())] | (pe_bytes[rva_to_offset(PEEK_DWORD() + 1)] << 8);
			DWORD original_thunk = PEEK_DWORD() + sizeof(WORD);
			DWORD function_thunk = rva_to_offset(original_thunk);
			std::string name;
			unsigned char temp = pe_bytes[function_thunk];
			while (temp != 0x0) {
				name += temp;
				function_thunk += sizeof(unsigned char);
				temp = pe_bytes[function_thunk];
			}
			std::cout << "| Function Name : " << std::setw(30) << std::left << std::setfill(' ') << name << "  |  " << std::setw(6) << std::left << "Hint :" << std::setw(3) << (int)hint << "  |  " << "RVA : " << std::hex << (int)original_thunk - 2 << "| \n";
			offset += 4;
		}
	}
	std::cout << "------------------------------------------------------------------------------" << "\n";
	std::cout << "\n";
	std::cout << "\n";
}

void PE_PARSER::Display_Section_Headers() {
	for (int i = 0; i < Section_Headers.size(); i++) {
		std::cout << "Section name : " << Section_Headers[i].Name << "\n";
		std::cout << "-------------------------------------------\n";
		std::cout << "Raw Address : " << std::hex << (int)Section_Headers[i].PointerToRawData << "  |  " << "Raw Size : " << std::hex << (int)Section_Headers[i].SizeOfRawData << "\n";
		std::cout << "Virtual Address : " << std::hex << (int)Section_Headers[i].VirtualAddress << "  |  " << "Virtual Size : " << std::hex << (int)Section_Headers[i].Misc.VirtualSize << "\n";
		std::cout << "Characteristics : " << std::hex << (int)Section_Headers[i].Characteristics << "\n";
		std::cout << "---------------------------------------------\n";
		std::cout << "\n";
	}
	std::cout << "\n";
}

void PE_PARSER::Display_Dos_Header() {
	const int labelWidth = 40;
	std::cout << "DOS HEADER" << "\n";
	std::cout << "-----------------------------------------------------------\n";

	std::cout << std::left << std::setw(labelWidth) << "Magic bytes:" << std::hex << DOS_HEADER.e_magic << std::dec << std::endl;
	std::cout << std::left << std::setw(labelWidth) << "Bytes on last page of file:" << std::hex << (int)DOS_HEADER.e_cblp << std::endl;
	std::cout << std::left << std::setw(labelWidth) << "Pages in file:" << std::hex << (int)DOS_HEADER.e_cp << std::endl;
	std::cout << std::left << std::setw(labelWidth) << "Relocations:" << std::hex << (int)DOS_HEADER.e_crlc << std::endl;
	std::cout << std::left << std::setw(labelWidth) << "Size of header in paragraphs:" << std::hex << (int)DOS_HEADER.e_cparhdr << std::endl;
	std::cout << std::left << std::setw(labelWidth) << "Minimum extra paragraphs needed:" << std::hex << (int)DOS_HEADER.e_minalloc << std::endl;
	std::cout << std::left << std::setw(labelWidth) << "Maximum extra paragraphs needed:" << std::hex << (int)DOS_HEADER.e_maxalloc << std::endl;
	std::cout << std::left << std::setw(labelWidth) << "Initial (relative) SS value:" << std::hex << (int)DOS_HEADER.e_ss << std::endl;
	std::cout << std::left << std::setw(labelWidth) << "Initial SP value:" << std::hex << (int)DOS_HEADER.e_sp << std::endl;
	std::cout << std::left << std::setw(labelWidth) << "Checksum:" << std::hex << (int)DOS_HEADER.e_csum << std::endl;
	std::cout << std::left << std::setw(labelWidth) << "Initial IP value:" << std::hex << (int)DOS_HEADER.e_ip << std::endl;
	std::cout << std::left << std::setw(labelWidth) << "Initial (relative) CS value:" << std::hex << (int)DOS_HEADER.e_cs << std::endl;
	std::cout << std::left << std::setw(labelWidth) << "File address of relocation table:" << std::hex << (int)DOS_HEADER.e_lfarlc << std::endl;
	std::cout << std::left << std::setw(labelWidth) << "Overlay number:" << std::hex << (int)DOS_HEADER.e_ovno << std::endl;

	std::cout << std::left << std::setw(labelWidth) << "Reserved words[4]:";
	for (int i = 0; i < 4; ++i) {
		std::cout << std::hex << (int)DOS_HEADER.e_res[i] << " ";
	}
	std::cout << std::endl;

	std::cout << std::left << std::setw(labelWidth) << "OEM identifier (for OEM information):" << DOS_HEADER.e_oemid << std::endl;
	std::cout << std::left << std::setw(labelWidth) << "OEM identifier specific:" << DOS_HEADER.e_oeminfo << std::endl;

	std::cout << std::left << std::setw(labelWidth) << "Reserved words[10]:";
	for (int i = 0; i < 10; ++i) {
		std::cout << DOS_HEADER.e_res2[i] << " ";
	}
	std::cout << std::endl;

	std::cout << std::left << std::setw(labelWidth) << "File address of new exe header:" << DOS_HEADER.e_lfanew << std::endl;
	std::cout << "-----------------------------------------------------------\n";
	std::cout << "\n";
	std::cout << "\n";
}

void PE_PARSER::Display_File_Header() {
	if (!is32bit) {
		const int labelWidth = 30;
		IMAGE_FILE_HEADER fileHeader = NT_HEADERS64.FileHeader;
		std::cout << "\nFile Header Information:" << std::endl;
		std::cout << "-------------------------------------------\n";
		std::cout << std::left << std::setw(labelWidth) << "Machine:" << std::hex << (int)fileHeader.Machine << std::dec << std::endl;
		std::cout << std::left << std::setw(labelWidth) << "NumberOfSections:" << std::hex << (int)fileHeader.NumberOfSections << std::endl;
		std::cout << std::left << std::setw(labelWidth) << "TimeDateStamp:" << std::hex << (int)fileHeader.TimeDateStamp << std::endl;
		std::cout << std::left << std::setw(labelWidth) << "PointerToSymbolTable:" << std::hex << (int)fileHeader.PointerToSymbolTable << std::endl;
		std::cout << std::left << std::setw(labelWidth) << "NumberOfSymbols:" << std::hex << (int)fileHeader.NumberOfSymbols << std::endl;
		std::cout << std::left << std::setw(labelWidth) << "SizeOfOptionalHeader:" << std::hex << (int)fileHeader.SizeOfOptionalHeader << std::endl;
		std::cout << std::left << std::setw(labelWidth) << "Characteristics:" << std::hex << (int)fileHeader.Characteristics << std::dec << std::endl;
		std::cout << "-------------------------------------------\n";
		std::cout << "\n";
		std::cout << "\n";
	}
	else {
		const int labelWidth = 30;
		IMAGE_FILE_HEADER fileHeader = NT_HEADERS32.FileHeader;
		std::cout << "\nFile Header Information:" << std::endl;
		std::cout << "-------------------------------------------\n";
		std::cout << std::left << std::setw(labelWidth) << "Machine:" << "0x" << std::hex << fileHeader.Machine << std::dec << std::endl;
		std::cout << std::left << std::setw(labelWidth) << "NumberOfSections:" << fileHeader.NumberOfSections << std::endl;
		std::cout << std::left << std::setw(labelWidth) << "TimeDateStamp:" << fileHeader.TimeDateStamp << std::endl;
		std::cout << std::left << std::setw(labelWidth) << "PointerToSymbolTable:" << fileHeader.PointerToSymbolTable << std::endl;
		std::cout << std::left << std::setw(labelWidth) << "NumberOfSymbols:" << fileHeader.NumberOfSymbols << std::endl;
		std::cout << std::left << std::setw(labelWidth) << "SizeOfOptionalHeader:" << fileHeader.SizeOfOptionalHeader << std::endl;
		std::cout << std::left << std::setw(labelWidth) << "Characteristics:" << "0x" << std::hex << fileHeader.Characteristics << std::dec << std::endl;
		std::cout << "-------------------------------------------\n";
		std::cout << "\n";
		std::cout << "\n";
	}
}


void PE_PARSER::Display_Optional_Header() {
	const int labelWidth = 30;

	if (!is32bit) {
		IMAGE_OPTIONAL_HEADER64 optionalHeader = NT_HEADERS64.OptionalHeader;
		std::cout << "\nOptional Header Information:" << std::endl;
		std::cout << "-------------------------------------------\n";
		std::cout << std::left << std::setw(labelWidth) << "Magic:" << "0x" << std::hex << optionalHeader.Magic << std::dec << std::endl;
		std::cout << std::left << std::setw(labelWidth) << "MajorLinkerVersion:" << (int)optionalHeader.MajorLinkerVersion << std::endl;
		std::cout << std::left << std::setw(labelWidth) << "MinorLinkerVersion:" << (int)optionalHeader.MinorLinkerVersion << std::endl;
		std::cout << std::left << std::setw(labelWidth) << "SizeOfCode:" << optionalHeader.SizeOfCode << std::endl;
		std::cout << std::left << std::setw(labelWidth) << "SizeOfInitializedData:" << optionalHeader.SizeOfInitializedData << std::endl;
		std::cout << std::left << std::setw(labelWidth) << "SizeOfUninitializedData:" << optionalHeader.SizeOfUninitializedData << std::endl;
		std::cout << std::left << std::setw(labelWidth) << "AddressOfEntryPoint:" << optionalHeader.AddressOfEntryPoint << std::endl;
		std::cout << std::left << std::setw(labelWidth) << "BaseOfCode:" << optionalHeader.BaseOfCode << std::endl;
		std::cout << std::left << std::setw(labelWidth) << "ImageBase:" << optionalHeader.ImageBase << std::endl;
		std::cout << std::left << std::setw(labelWidth) << "SectionAlignment:" << optionalHeader.SectionAlignment << std::endl;
		std::cout << std::left << std::setw(labelWidth) << "FileAlignment:" << optionalHeader.FileAlignment << std::endl;
		std::cout << std::left << std::setw(labelWidth) << "MajorOperatingSystemVersion:" << optionalHeader.MajorOperatingSystemVersion << std::endl;
		std::cout << std::left << std::setw(labelWidth) << "MinorOperatingSystemVersion:" << optionalHeader.MinorOperatingSystemVersion << std::endl;
		std::cout << std::left << std::setw(labelWidth) << "MajorImageVersion:" << optionalHeader.MajorImageVersion << std::endl;
		std::cout << std::left << std::setw(labelWidth) << "MinorImageVersion:" << optionalHeader.MinorImageVersion << std::endl;
		std::cout << std::left << std::setw(labelWidth) << "MajorSubsystemVersion:" << optionalHeader.MajorSubsystemVersion << std::endl;
		std::cout << std::left << std::setw(labelWidth) << "MinorSubsystemVersion:" << optionalHeader.MinorSubsystemVersion << std::endl;
		std::cout << std::left << std::setw(labelWidth) << "Win32VersionValue:" << optionalHeader.Win32VersionValue << std::endl;
		std::cout << std::left << std::setw(labelWidth) << "SizeOfImage:" << optionalHeader.SizeOfImage << std::endl;
		std::cout << std::left << std::setw(labelWidth) << "SizeOfHeaders:" << optionalHeader.SizeOfHeaders << std::endl;
		std::cout << std::left << std::setw(labelWidth) << "CheckSum:" << optionalHeader.CheckSum << std::endl;
		std::cout << std::left << std::setw(labelWidth) << "Subsystem:" << optionalHeader.Subsystem << std::endl;
		std::cout << std::left << std::setw(labelWidth) << "DllCharacteristics:" << optionalHeader.DllCharacteristics << std::endl;
		std::cout << std::left << std::setw(labelWidth) << "SizeOfStackReserve:" << optionalHeader.SizeOfStackReserve << std::endl;
		std::cout << std::left << std::setw(labelWidth) << "SizeOfStackCommit:" << optionalHeader.SizeOfStackCommit << std::endl;
		std::cout << std::left << std::setw(labelWidth) << "SizeOfHeapReserve:" << optionalHeader.SizeOfHeapReserve << std::endl;
		std::cout << std::left << std::setw(labelWidth) << "SizeOfHeapCommit:" << optionalHeader.SizeOfHeapCommit << std::endl;
		std::cout << std::left << std::setw(labelWidth) << "LoaderFlags:" << optionalHeader.LoaderFlags << std::endl;
		std::cout << std::left << std::setw(labelWidth) << "NumberOfRvaAndSizes:" << optionalHeader.NumberOfRvaAndSizes << std::endl;
		std::cout << "-------------------------------------------\n";
		std::cout << "\n";
		std::cout << "\n";
	}
	else {
		IMAGE_OPTIONAL_HEADER32 optionalHeader = NT_HEADERS32.OptionalHeader;
		std::cout << "\nOptional Header Information:" << std::endl;
		std::cout << "-------------------------------------------\n";
		std::cout << std::left << std::setw(labelWidth) << "Magic:" << "0x" << std::hex << optionalHeader.Magic << std::dec << std::endl;
		std::cout << std::left << std::setw(labelWidth) << "MajorLinkerVersion:" << (int)optionalHeader.MajorLinkerVersion << std::endl;
		std::cout << std::left << std::setw(labelWidth) << "MinorLinkerVersion:" << (int)optionalHeader.MinorLinkerVersion << std::endl;
		std::cout << std::left << std::setw(labelWidth) << "SizeOfCode:" << optionalHeader.SizeOfCode << std::endl;
		std::cout << std::left << std::setw(labelWidth) << "SizeOfInitializedData:" << optionalHeader.SizeOfInitializedData << std::endl;
		std::cout << std::left << std::setw(labelWidth) << "SizeOfUninitializedData:" << optionalHeader.SizeOfUninitializedData << std::endl;
		std::cout << std::left << std::setw(labelWidth) << "AddressOfEntryPoint:" << optionalHeader.AddressOfEntryPoint << std::endl;
		std::cout << std::left << std::setw(labelWidth) << "BaseOfCode:" << optionalHeader.BaseOfCode << std::endl;
		std::cout << std::left << std::setw(labelWidth) << "ImageBase:" << optionalHeader.ImageBase << std::endl;
		std::cout << std::left << std::setw(labelWidth) << "SectionAlignment:" << optionalHeader.SectionAlignment << std::endl;
		std::cout << std::left << std::setw(labelWidth) << "FileAlignment:" << optionalHeader.FileAlignment << std::endl;
		std::cout << std::left << std::setw(labelWidth) << "MajorOperatingSystemVersion:" << optionalHeader.MajorOperatingSystemVersion << std::endl;
		std::cout << std::left << std::setw(labelWidth) << "MinorOperatingSystemVersion:" << optionalHeader.MinorOperatingSystemVersion << std::endl;
		std::cout << std::left << std::setw(labelWidth) << "MajorImageVersion:" << optionalHeader.MajorImageVersion << std::endl;
		std::cout << std::left << std::setw(labelWidth) << "MinorImageVersion:" << optionalHeader.MinorImageVersion << std::endl;
		std::cout << std::left << std::setw(labelWidth) << "MajorSubsystemVersion:" << optionalHeader.MajorSubsystemVersion << std::endl;
		std::cout << std::left << std::setw(labelWidth) << "MinorSubsystemVersion:" << optionalHeader.MinorSubsystemVersion << std::endl;
		std::cout << std::left << std::setw(labelWidth) << "Win32VersionValue:" << optionalHeader.Win32VersionValue << std::endl;
		std::cout << std::left << std::setw(labelWidth) << "SizeOfImage:" << optionalHeader.SizeOfImage << std::endl;
		std::cout << std::left << std::setw(labelWidth) << "SizeOfHeaders:" << optionalHeader.SizeOfHeaders << std::endl;
		std::cout << std::left << std::setw(labelWidth) << "CheckSum:" << optionalHeader.CheckSum << std::endl;
		std::cout << std::left << std::setw(labelWidth) << "Subsystem:" << optionalHeader.Subsystem << std::endl;
		std::cout << std::left << std::setw(labelWidth) << "DllCharacteristics:" << optionalHeader.DllCharacteristics << std::endl;
		std::cout << std::left << std::setw(labelWidth) << "SizeOfStackReserve:" << optionalHeader.SizeOfStackReserve << std::endl;
		std::cout << std::left << std::setw(labelWidth) << "SizeOfStackCommit:" << optionalHeader.SizeOfStackCommit << std::endl;
		std::cout << std::left << std::setw(labelWidth) << "SizeOfHeapReserve:" << optionalHeader.SizeOfHeapReserve << std::endl;
		std::cout << std::left << std::setw(labelWidth) << "SizeOfHeapCommit:" << optionalHeader.SizeOfHeapCommit << std::endl;
		std::cout << std::left << std::setw(labelWidth) << "LoaderFlags:" << optionalHeader.LoaderFlags << std::endl;
		std::cout << std::left << std::setw(labelWidth) << "NumberOfRvaAndSizes:" << optionalHeader.NumberOfRvaAndSizes << std::endl;
		std::cout << "-------------------------------------------\n";
		std::cout << "\n";
		std::cout << "\n";
	}

}

void PE_PARSER::Display_All_Information() {
	Display_General_Info();
	Display_Dos_Header();
	Display_File_Header();
	Display_Optional_Header();
	Display_Section_Headers();
	Display_Directories();
	Display_Imports();
}
