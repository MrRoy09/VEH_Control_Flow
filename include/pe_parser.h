#pragma once
#include <Windows.h>
#include <string>
#include <vector>
#include <fstream>
#include <iostream>
#include <iomanip>

#define cout_hex( x ) std::cout<<std::hex<<x<<"\n";
#define READ_BYTE() (int)pe_bytes[offset] ; this->offset+=1
#define READ_WORD() ((int)pe_bytes[offset] | (int)pe_bytes[(int)offset+1]<<8) ; this->offset+=2
#define READ_DWORD() (((int)pe_bytes[(int)offset]) | ((int)pe_bytes[(int)offset+1]<<8) | (int)pe_bytes[(int)offset+2]<<16 | (int)pe_bytes[(int)offset+3]<<24) ; this->offset+=4
#define READ_QWORD() (((int)pe_bytes[(int)offset]) | ((int)pe_bytes[(int)offset+1]<<8) | (int)pe_bytes[(int)offset+2]<<16 | (int)pe_bytes[(int)offset+3]<<24|(int)pe_bytes[(int)offset+3]<<32|(int)pe_bytes[(int)offset+3]<<40|(int)pe_bytes[(int)offset+3]<<48|(int)pe_bytes[(int)offset+3]<<56) ; this->offset+=8

#define PEEK_BYTE() (int)pe_bytes[offset]
#define PEEK_WORD() ((int)pe_bytes[offset] | (int)pe_bytes[(int)offset+1]<<8)
#define PEEK_DWORD() (((int)pe_bytes[(int)offset]) | ((int)pe_bytes[(int)offset+1]<<8) | (int)pe_bytes[(int)offset+2]<<16 | (int)pe_bytes[(int)offset+3]<<24)
#define PEEK_QWORD() (((int)pe_bytes[(int)offset]) | ((int)pe_bytes[(int)offset+1]<<8) | (int)pe_bytes[(int)offset+2]<<16 | (int)pe_bytes[(int)offset+3]<<24|(int)pe_bytes[(int)offset+3]<<32|(int)pe_bytes[(int)offset+3]<<40|(int)pe_bytes[(int)offset+3]<<48|(int)pe_bytes[(int)offset+3]<<56)


class PE_PARSER
{
public:
	std::string file_path;
	std::vector<unsigned char> pe_bytes;
	bool is32bit;
	int offset;
	friend class moonlit_disassembler;
	PE_PARSER(std::string file_path, bool *isElf) {
		this->is32bit = 0;
		this->offset = 0;
		this->file_path = file_path;
		this->pe_bytes = populate_pe_bytes();
		if (pe_bytes.size() == 0) {
			*isElf = 0;
		}
		else {
			populate_dos_header();
			is32bit = get_bitness();
			populate_nt_header();
			if (is32bit) {
				populate_section_headers32();
			}
			else {
				populate_section_headers64();
			}
			pe_imports = get_imports();
		}
	}

	std::vector<unsigned char> populate_pe_bytes();
	void populate_dos_header();
	void populate_nt_header();
	bool get_bitness();
	void populate_section_headers32();
	void populate_section_headers64();
	void Display_General_Info();
	void Display_Dos_Header();
	void Display_Optional_Header();
	void Display_Directories();
	void Display_Imports();
	void Display_Imported_Functions(DWORD FirstThunkDLL);
	void Display_Section_Headers();
	void Display_All_Information();
	void Display_File_Header();

	std::vector<IMAGE_IMPORT_DESCRIPTOR>get_imports();

	IMAGE_DOS_HEADER DOS_HEADER;
	IMAGE_NT_HEADERS64 NT_HEADERS64;
	IMAGE_NT_HEADERS32 NT_HEADERS32;
	std::vector<IMAGE_SECTION_HEADER> Section_Headers;
	std::vector<IMAGE_IMPORT_DESCRIPTOR> pe_imports;
	DWORD rva_to_offset(DWORD rva);

	
};