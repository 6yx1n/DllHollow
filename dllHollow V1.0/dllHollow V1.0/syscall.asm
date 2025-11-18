EXTERN		wNtCreateSection:DWORD
EXTERN		sysAddrNtCreateSection:DWORD

EXTERN		wNtMapViewOfSection:DWORD
EXTERN		sysAddrNtMapViewOfSection:DWORD

EXTERN		wNtCreateTransaction:DWORD
EXTERN		sysAddrNtCreateTransaction:DWORD

EXTERN		wNtProtectVirtualMemory:DWORD
EXTERN		sysAddrNtProtectVirtualMemory:DWORD

EXTERN		wNtClose:DWORD
EXTERN		sysAddrNtClose:DWORD

EXTERN		wNtNtQueryVirtualMemory:DWORD
EXTERN		sysAddrNtQueryVirtualMemory:DWORD

EXTERN		wNtFreeVirtualMemory:DWORD
EXTERN		sysAddrNtFreeVirtualMemory:DWORD

.code
sysJmpNtCreateSection proc
	mov     r10, rcx        
	mov     eax, wNtCreateSection
	jmp QWORD PTR [sysAddrNtCreateSection]
sysJmpNtCreateSection endp

sysJmpNtMapViewOfSection proc
	mov     r10, rcx        
	mov     eax, wNtMapViewOfSection
	jmp QWORD PTR [sysAddrNtMapViewOfSection]
sysJmpNtMapViewOfSection endp

sysJmpNtCreateTransaction proc
	mov     r10, rcx        
	mov     eax, wNtCreateTransaction
	jmp QWORD PTR [sysAddrNtCreateTransaction]
sysJmpNtCreateTransaction endp

sysJmpNtProtectVirtualMemory proc
	mov     r10, rcx        
	mov     eax, wNtProtectVirtualMemory
	jmp QWORD PTR [sysAddrNtProtectVirtualMemory]
sysJmpNtProtectVirtualMemory endp

sysJmpNtClose proc
	mov     r10, rcx        
	mov     eax, wNtClose
	jmp QWORD PTR [sysAddrNtClose]
sysJmpNtClose endp

sysJmpNtQueryVirtualMemory proc
	mov     r10, rcx        
	mov     eax, wNtNtQueryVirtualMemory
	jmp QWORD PTR [sysAddrNtQueryVirtualMemory]
sysJmpNtQueryVirtualMemory endp

sysJmpNtFreeVirtualMemory proc
	mov     r10, rcx        
	mov     eax, wNtNtQueryVirtualMemory
	jmp QWORD PTR [sysAddrNtQueryVirtualMemory]
sysJmpNtFreeVirtualMemory endp

end