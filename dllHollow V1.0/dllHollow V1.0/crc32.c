#include "crc32.h"
#include <Windows.h>
#include <winternl.h>
#include <stdio.h>

DWORD crc32b(unsigned char* str)
{
	unsigned int    byte, mask, crc = 0xFFFFFFFF;
	int             i = 0, j = 0;

	while (str[i] != 0) {
		byte = str[i];
		crc = crc ^ byte;

		for (j = 7; j >= 0; j--) {
			mask = -1 * (crc & 1);
			crc = (crc >> 1) ^ (SEEDb & mask);
		}

		i++;
	}
	return ~crc;
}

char* WcharToChar(WCHAR* wStr)
{
	int wcharLength = (int)(wcslen(wStr) + 1); // +1 for null terminator
	int charLength = WideCharToMultiByte(CP_ACP, 0, wStr, wcharLength, NULL, 0, NULL, NULL);
	char* charString = (char*)calloc(charLength * sizeof(char), 1);
	WideCharToMultiByte(CP_ACP, 0, wStr, wcharLength, charString, charLength, NULL, NULL);
	return charString;
}

VOID* ByGetProcAddress(PVOID dllAddress, DWORD funHash)//char* functionName)
{
	DWORD		j;
	uintptr_t rva = 0;

	const LPVOID BaseDLLAddr = (LPVOID)dllAddress;
	PIMAGE_DOS_HEADER pImgDOSHead = (PIMAGE_DOS_HEADER)BaseDLLAddr;
	PIMAGE_NT_HEADERS pImgNTHead = (PIMAGE_NT_HEADERS)((DWORD_PTR)BaseDLLAddr + pImgDOSHead->e_lfanew);

	PIMAGE_EXPORT_DIRECTORY pImgExpDir = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)BaseDLLAddr + pImgNTHead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	PDWORD Address = (PDWORD)((LPBYTE)BaseDLLAddr + pImgExpDir->AddressOfFunctions);

	PDWORD Name = (PDWORD)((LPBYTE)BaseDLLAddr + pImgExpDir->AddressOfNames);

	PWORD Ordinal = (PWORD)((LPBYTE)BaseDLLAddr + pImgExpDir->AddressOfNameOrdinals);

	for (j = 0; j < pImgExpDir->NumberOfNames; j++)
	{
		if (HASH((char*)BaseDLLAddr + Name[j]) == funHash)
		{
			rva = (uintptr_t)((LPBYTE)(uintptr_t)Address[Ordinal[j]]);
			break;
		}
	}

	if (rva)
	{
		uintptr_t moduleBase = (uintptr_t)BaseDLLAddr;
		uintptr_t* TrueAddress = (uintptr_t*)(moduleBase + rva);
		return (PVOID)TrueAddress;
	}
	else
	{
		return (PVOID)rva;
	}
}

void ExtractFilename(const wchar_t* fullPath, wchar_t* filename)
{
	const wchar_t* lastBackslash = wcsrchr(fullPath, L'\\');
	if (lastBackslash != NULL) {
		wcscpy_s(filename, MAX_PATH, lastBackslash + 1);
	}
	else {
		wcscpy_s(filename, MAX_PATH, fullPath);
	}
}

void* ByGetModuleHandle(DWORD dllNameHash)
{
	PPEB pPeb = 0;
	PLDR_DATA_TABLE_ENTRY pDataTableEntry = 0;
	PVOID DLLAddress = 0;

#ifdef _M_X64
	PPEB pPEB = (PPEB)__readgsqword(0x60); //ULONGLONG ProcessEnvironmentBlock;                                       //0x60 x64
#else
	//If 32 bits architecture
	PPEB pPEB = (PPEB)__readfsdword(0x30);
#endif

	PPEB_LDR_DATA pLdr = pPEB->Ldr;

	PLIST_ENTRY AddressFirstPLIST = &pLdr->InMemoryOrderModuleList;

	PLIST_ENTRY AddressFirstNode = AddressFirstPLIST->Flink;

	for (PLIST_ENTRY Node = AddressFirstNode; Node != AddressFirstPLIST; Node = Node->Flink)
	{
		Node = Node - 1;
		pDataTableEntry = (PLDR_DATA_TABLE_ENTRY)Node;

		wchar_t FullDLLName[MAX_PATH * 2] = { 0 };
		wcscpy_s(FullDLLName, MAX_PATH * 2, (wchar_t*)pDataTableEntry->FullDllName.Buffer);

		wchar_t filename[MAX_PATH * 2] = { 0 };
		ExtractFilename(FullDLLName, filename);

		char* dllName = WcharToChar(filename);
		if (HASH(dllName) == dllNameHash)
		{
			DLLAddress = (PVOID)pDataTableEntry->DllBase;
			free(dllName);
			return DLLAddress;
		}
		Node = Node + 1;
	}

	return DLLAddress;
}

void* ByPeModuleX(WCHAR* lpModuleName)
{
	PPEB pPeb = 0;
	PLDR_DATA_TABLE_ENTRY pDataTableEntry = 0;
	PVOID DLLAddress = 0;

#ifdef _M_X64
	PPEB pPEB = (PPEB)__readgsqword(0x60); //ULONGLONG ProcessEnvironmentBlock;                                       //0x60 x64
#else
	//If 32 bits architecture
	PPEB pPEB = (PPEB)__readfsdword(0x30);
#endif

	PPEB_LDR_DATA pLdr = pPEB->Ldr;

	PLIST_ENTRY AddressFirstPLIST = &pLdr->InMemoryOrderModuleList;

	PLIST_ENTRY AddressFirstNode = AddressFirstPLIST->Flink;

	for (PLIST_ENTRY Node = AddressFirstNode; Node != AddressFirstPLIST; Node = Node->Flink)
	{
		Node = Node - 1;
		pDataTableEntry = (PLDR_DATA_TABLE_ENTRY)Node;

		wchar_t FullDLLName[MAX_PATH * 2] = { 0 };
		wcscpy_s(FullDLLName, MAX_PATH * 2, (wchar_t*)pDataTableEntry->FullDllName.Buffer);

		wchar_t filename[MAX_PATH * 2] = { 0 };
		ExtractFilename(FullDLLName, filename);

		char* dllName	= WcharToChar(filename);
		CHAR* lpName	= WcharToChar(lpModuleName);
		if (dllName == lpName)
		{
			DLLAddress = (PVOID)pDataTableEntry->DllBase;
			free(dllName);
			return DLLAddress;
		}
		Node = Node + 1;
	}

	return DLLAddress;
}
