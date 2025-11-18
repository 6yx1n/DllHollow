#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>


void ShadowStackInit(void);

void ShadowStackCleanup(void);

void ShadowStackPush(void* returnAddress, void* framePointer, const char* functionName);

BOOL ShadowStackPop(void* expected_return_address, void* expected_frame_pointer);

#define PROTECTED_CALL(func_call) \
    (ShadowStackPush(_ReturnAddress(), _AddressOfReturnAddress(), #func_call), \
    (func_call), \
    (ShadowStackPop(_ReturnAddress(), _AddressOfReturnAddress()) ? 0 : (ExitProcess(0xDEAD), 0)))



