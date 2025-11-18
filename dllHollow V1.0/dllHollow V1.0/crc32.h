#pragma once
#include <Windows.h>

#define SEEDb								0xEDB88777
#define CreateFileW_CRC32b					0x8B13595B
#define GetFileSize_CRC32b					0x3188680C
#define ReadFile_CRC32b						0x22AD20D3
#define NtCreateSection_CRC32b				0x6D49CD50
#define NtMapViewOfSection_CRC32b			0x30743F8E
#define NtCreateTransaction_CRC32b			0xAF9D3A6D
#define NtClose_CRC32b						0x5F600790
#define NtProtectVirtualMemory_CRC32b		0x93B353AD
#define NtQueryVirtualMemory_CRC32b			0xCCC01A39
#define NtFreeVirtualMemory_CRC32b			0x786E6FE2
#define CreateFileTransactedW_CRC32b		0x723656F5
#define GetSystemDirectoryW_CRC32b			0xC0CB080B
#define FindFirstFileW_CRC32b				0xE05639A9
#define SetFilePointer_CRC32b				0xEC5A9632
#define FindNextFileW_CRC32b				0x5891EE95
#define FindClose_CRC32b					0x085F1C64
#define WriteFile_CRC32b					0xA38E6979
#define kernel32_CRC32b						0x47D9D149
#define ntdll_CRC32b						0xC48E2523

DWORD crc32b(unsigned char* str);

#define HASH(API)		(crc32b((unsigned char*)API))

VOID* ByGetProcAddress(PVOID dllAddress, DWORD funHash);

void* ByGetModuleHandle(DWORD dllNameHash);

void* ByPeModuleX(WCHAR* lpModuleName);

