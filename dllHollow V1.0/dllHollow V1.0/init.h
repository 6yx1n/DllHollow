#pragma once
#include <Windows.h>
#include <stdint.h>

DWORD		wNtCreateSection;
UINT_PTR	sysAddrNtCreateSection;
DWORD		wNtMapViewOfSection;
UINT_PTR	sysAddrNtMapViewOfSection;
DWORD		wNtCreateTransaction;
UINT_PTR	sysAddrNtCreateTransaction;
DWORD		wNtProtectVirtualMemory;
UINT_PTR	sysAddrNtProtectVirtualMemory;
DWORD		wNtClose;
UINT_PTR	sysAddrNtClose;
DWORD       wNtNtQueryVirtualMemory;
UINT_PTR    sysAddrNtQueryVirtualMemory;
DWORD       wNtFreeVirtualMemory;
UINT_PTR    sysAddrNtFreeVirtualMemory;

typedef enum _MEMORY_INFORMATION_CLASS
{
    MemoryBasicInformation,                     // q: MEMORY_BASIC_INFORMATION
    MemoryWorkingSetInformation,                // q: MEMORY_WORKING_SET_INFORMATION
    MemoryMappedFilenameInformation,            // q: UNICODE_STRING
    MemoryRegionInformation,                    // q: MEMORY_REGION_INFORMATION
    MemoryWorkingSetExInformation,              // q: MEMORY_WORKING_SET_EX_INFORMATION // since VISTA
    MemorySharedCommitInformation,              // q: MEMORY_SHARED_COMMIT_INFORMATION // since WIN8
    MemoryImageInformation,                     // q: MEMORY_IMAGE_INFORMATION
    MemoryRegionInformationEx,                  // q: MEMORY_REGION_INFORMATION
    MemoryPrivilegedBasicInformation,           // q: MEMORY_BASIC_INFORMATION
    MemoryEnclaveImageInformation,              // q: MEMORY_ENCLAVE_IMAGE_INFORMATION // since REDSTONE3
    MemoryBasicInformationCapped,               // q: 10
    MemoryPhysicalContiguityInformation,        // q: MEMORY_PHYSICAL_CONTIGUITY_INFORMATION // since 20H1
    MemoryBadInformation,                       // q: since WIN11
    MemoryBadInformationAllProcesses,           // qs: not implemented // since 22H1
    MemoryImageExtensionInformation,            // q: MEMORY_IMAGE_EXTENSION_INFORMATION // since 24H2
    MaxMemoryInfoClass
} MEMORY_INFORMATION_CLASS;

typedef struct _UNICODE_STRING1
{
    USHORT Length;
    USHORT MaximumLength;
    _Field_size_bytes_part_opt_(MaximumLength, Length) PWCH Buffer;
} UNICODE_STRING1, * PUNICODE_STRING1;

typedef const UNICODE_STRING1* PCUNICODE_STRING1;

typedef struct _OBJECT_ATTRIBUTES1
{
    ULONG Length;
    HANDLE RootDirectory;
    PCUNICODE_STRING1 ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor; // PSECURITY_DESCRIPTOR;
    PVOID SecurityQualityOfService; // PSECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES1, * POBJECT_ATTRIBUTES1;

EXTERN_C LONG sysJmpNtCreateSection(HANDLE*, ULONG, void*, LARGE_INTEGER*, ULONG, ULONG, HANDLE);
EXTERN_C LONG sysJmpNtMapViewOfSection(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG);
EXTERN_C NTSTATUS sysJmpNtCreateTransaction(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES1, LPGUID, HANDLE, ULONG, ULONG, ULONG, PLARGE_INTEGER, PUNICODE_STRING1);

EXTERN_C NTSTATUS sysJmpNtClose(
    HANDLE Handle
    );

EXTERN_C NTSTATUS sysJmpNtProtectVirtualMemory(
    IN		HANDLE          ProcessHandle,
    IN OUT	PVOID*          BaseAddress,
    IN OUT	PULONG          NumberOfBytesToProtect,
    IN		ULONG           NewAccessProtection,
    OUT		PULONG          OldAccessProtection
);

EXTERN_C NTSTATUS sysJmpNtQueryVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _In_ MEMORY_INFORMATION_CLASS MemoryInformationClass,
    _Out_writes_bytes_(MemoryInformationLength) PVOID MemoryInformation,
    _In_ SIZE_T MemoryInformationLength,
    _Out_opt_ PSIZE_T ReturnLength
);

EXTERN_C NTSTATUS sysJmpNtFreeVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ __drv_freesMem(Mem) PVOID* BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG FreeType
    );

typedef HANDLE(WINAPI* bypass_CreateFileW)(
    _In_ LPCWSTR lpFileName,
    _In_ DWORD dwDesiredAccess,
    _In_ DWORD dwShareMode,
    _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    _In_ DWORD dwCreationDisposition,
    _In_ DWORD dwFlagsAndAttributes,
    _In_opt_ HANDLE hTemplateFile
    );

typedef DWORD(WINAPI* bypass_GetFileSize)(
    _In_ HANDLE hFile,
    _Out_opt_ LPDWORD lpFileSizeHigh
    );

typedef BOOL(WINAPI* bypass_ReadFile)(
    _In_ HANDLE hFile,
    _Out_writes_bytes_to_opt_(nNumberOfBytesToRead, *lpNumberOfBytesRead) __out_data_source(FILE) LPVOID lpBuffer,
    _In_ DWORD nNumberOfBytesToRead,
    _Out_opt_ LPDWORD lpNumberOfBytesRead,
    _Inout_opt_ LPOVERLAPPED lpOverlapped
    );

typedef HANDLE(WINAPI* bypass_CreateFileTransactedW)(
    _In_       LPCWSTR lpFileName,
    _In_       DWORD dwDesiredAccess,
    _In_       DWORD dwShareMode,
    _In_opt_   LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    _In_       DWORD dwCreationDisposition,
    _In_       DWORD dwFlagsAndAttributes,
    _In_opt_   HANDLE hTemplateFile,
    _In_       HANDLE hTransaction,
    _In_opt_   PUSHORT pusMiniVersion,
    _Reserved_ PVOID  lpExtendedParameter
);

typedef UINT(WINAPI* bypass_GetSystemDirectoryW)(
    _Out_writes_to_opt_(uSize, return +1) LPWSTR lpBuffer,
    _In_ UINT uSize
);

typedef HANDLE(WINAPI* bypass_FindFirstFileW)(
    _In_ LPCWSTR lpFileName,
    _Out_ LPWIN32_FIND_DATAW lpFindFileData
    );


typedef DWORD(WINAPI* bypass_SetFilePointer)(
    _In_ HANDLE hFile,
    _In_ LONG lDistanceToMove,
    _Inout_opt_ PLONG lpDistanceToMoveHigh,
    _In_ DWORD dwMoveMethod
    );

typedef BOOL(WINAPI* bypass_FindNextFileW)(
    _In_ HANDLE hFindFile,
    _Out_ LPWIN32_FIND_DATAW lpFindFileData
);

typedef BOOL(WINAPI* bypass_FindClose)(
    _Inout_ HANDLE hFindFile
);

typedef BOOL(WINAPI* bypass_WriteFile)(
    _In_ HANDLE hFile,
    _In_reads_bytes_opt_(nNumberOfBytesToWrite) LPCVOID lpBuffer,
    _In_ DWORD nNumberOfBytesToWrite,
    _Out_opt_ LPDWORD lpNumberOfBytesWritten,
    _Inout_opt_ LPOVERLAPPED lpOverlapped
);

typedef struct _K32FUN
{
    bypass_CreateFileW			    pCreateFileW;
    bypass_GetFileSize			    pGetFileSize;
    bypass_ReadFile				    pReadFile;
    bypass_CreateFileTransactedW    pCreateFileTransactedW;
    bypass_GetSystemDirectoryW      pGetSystemDirectoryW;
    bypass_FindFirstFileW           pFindFirstFileW;
    bypass_SetFilePointer           pSetFilePointer;
    bypass_FindNextFileW            pFindNextFileW;
    bypass_FindClose                pFindClose;
    bypass_WriteFile                pWriteFile;
}K32FUN, * PK32FUN;

K32FUN      k32Api;

BOOL GetFileLoad(uint8_t** buffer, PDWORD bufferSize);