#include "shadowKiller.h"


#define SHADOW_STACK_SIZE 8192
#define MAX_FUNCTION_NAME_LENGTH 64
#define ENABLE_CALL_CHAIN_OBFUSCATION 1
#define ENABLE_STACK_PROTECTION 1
#define CANARY_VALUE_COUNT 16
#define ENABLE_STEALTH_MODE 1  

typedef struct {
    void* returnAddress;
    void* framePointer;
    char functionName[MAX_FUNCTION_NAME_LENGTH];
    uint32_t sequenceId;
    uint32_t checkSum;
    uint64_t timeStamp;
    uint8_t canary[8];
} ShadowStackFrame;

typedef struct {
    void* realAddress;
    void* obfuscatedAddress;
} AddressMapping;

static uint8_t*         gShadowStack = NULL;
static size_t           gShadowStackPtr = 0;
static BOOL             gShadowStackInitialized = FALSE;
static uint32_t         gSequenceCounter = 0;
static uint64_t         canaryValues[CANARY_VALUE_COUNT];
static AddressMapping* addressMappings = NULL;
static size_t           mappingCount = 0;
static size_t           mappingCapacity = 0;
static uint8_t          jitterSeed[16];
static CRITICAL_SECTION stackLock;

static void InitializeSecurityFeatures(void);
static uint32_t CalculateChecksum(const void* data, size_t size);
static uint64_t GetTimestamp(void);
static void GenerateCanary(uint8_t* out_canary);
static void* ObfuscateAddress(void* address);
static void* DeobfuscateAddress(void* obfuscatedAddress);
static void RecordAddressMapping(void* real, void* obfuscated);
static void _SecureZeroMemory(void* ptr, size_t size);


void ShadowStackInit(void) {
    if (gShadowStackInitialized) return;

    InitializeCriticalSection(&stackLock);
    EnterCriticalSection(&stackLock);

    gShadowStack = (uint8_t*)VirtualAlloc(NULL, SHADOW_STACK_SIZE,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);
    if (!gShadowStack) {
        //fprintf(stderr, "Failed to allocate shadow stack\n");
        ExitProcess(EXIT_FAILURE);
    }


    mappingCapacity = 128;
    addressMappings = (AddressMapping*)malloc(mappingCapacity * sizeof(AddressMapping));
    if (!addressMappings) {
        //fprintf(stderr, "Failed to allocate address mappings\n");
        ExitProcess(EXIT_FAILURE);
    }

    InitializeSecurityFeatures();

    gShadowStackInitialized = TRUE;
    gShadowStackPtr = 0;

    LeaveCriticalSection(&stackLock);
}

static void InitializeSecurityFeatures(void) {
    HCRYPTPROV hCryptProv;
    if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        srand((unsigned int)time(NULL) ^ (unsigned int)GetCurrentProcessId());
        for (int i = 0; i < 16; i++) {
            jitterSeed[i] = (uint8_t)rand();
        }
    }
    else {
        CryptGenRandom(hCryptProv, 16, jitterSeed);
        CryptReleaseContext(hCryptProv, 0);
    }

    for (int i = 0; i < CANARY_VALUE_COUNT; i++) {
        canaryValues[i] = ((uint64_t)jitterSeed[i % 8] << 56) |
            ((uint64_t)jitterSeed[(i + 1) % 8] << 48) |
            ((uint64_t)jitterSeed[(i + 2) % 8] << 40) |
            ((uint64_t)jitterSeed[(i + 3) % 8] << 32) |
            ((uint64_t)jitterSeed[(i + 4) % 8] << 24) |
            ((uint64_t)jitterSeed[(i + 5) % 8] << 16) |
            ((uint64_t)jitterSeed[(i + 6) % 8] << 8) |
            ((uint64_t)jitterSeed[(i + 7) % 8]);
    }
}

static uint32_t CalculateChecksum(const void* data, size_t size) {
    uint32_t checkSum = 0x12345678;
    const uint8_t* bytes = (const uint8_t*)data;

    for (size_t i = 0; i < size; i++) {
        checkSum = ((checkSum << 5) | (checkSum >> 27)) ^ bytes[i];
        checkSum += bytes[i] * 13;
    }

    return checkSum ^ 0xABCDEF90;
}

static uint64_t GetTimestamp(void) {
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    return ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
}

static void GenerateCanary(uint8_t* out_canary) {
    uint64_t value = canaryValues[gSequenceCounter % CANARY_VALUE_COUNT];
    value ^= GetTimestamp() & 0xFFFFFFFFFFFF0000ULL;
    memcpy(out_canary, &value, 8);
}

static void* ObfuscateAddress(void* address) {
    if (!ENABLE_CALL_CHAIN_OBFUSCATION)
        return address;

    for (size_t i = 0; i < mappingCount; i++) {
        if (addressMappings[i].realAddress == address) {
            return addressMappings[i].obfuscatedAddress;
        }
    }

    uint8_t* addrBytes = (uint8_t*)&address;
    uint64_t signature = 0;

    for (int i = 0; i < 8; i++) {
        signature = (signature << 8) | (addrBytes[i % sizeof(void*)] ^ jitterSeed[i]);
    }

    uintptr_t highBits = ((uintptr_t)address) & 0xFFFFFFFF00000000ULL;
    uintptr_t lowBits = (((uintptr_t)address) & 0xFFFFFFFFULL) ^ ((uintptr_t)signature & 0xFFFFFFFFULL);

    if (ENABLE_STEALTH_MODE) {
        const uint8_t sbox_mini[16] = { 0x07, 0x0C, 0x02, 0x08, 0x0A, 0x0D, 0x04, 0x0E,
                                       0x01, 0x05, 0x0F, 0x0B, 0x09, 0x06, 0x03, 0x00 };

        for (int i = 0; i < 8; i++) {
            uint8_t nibble = (lowBits >> (i * 4)) & 0x0F;
            lowBits &= ~(0x0FULL << (i * 4));
            lowBits |= ((uint64_t)sbox_mini[nibble]) << (i * 4);
        }
    }

    void* obfuscated = (void*)(highBits | lowBits);

    RecordAddressMapping(address, obfuscated);

    return obfuscated;
}

static void* DeobfuscateAddress(void* obfuscatedAddress) {
    if (!ENABLE_CALL_CHAIN_OBFUSCATION)
        return obfuscatedAddress;

    for (size_t i = 0; i < mappingCount; i++) {
        if (addressMappings[i].obfuscatedAddress == obfuscatedAddress) {
            return addressMappings[i].realAddress;
        }
    }

    return obfuscatedAddress;
}

static void RecordAddressMapping(void* real, void* obfuscated) {
    if (mappingCount >= mappingCapacity) {
        mappingCapacity *= 2;
        AddressMapping* new_mappings = (AddressMapping*)realloc(
            addressMappings, mappingCapacity * sizeof(AddressMapping));
        if (!new_mappings) {
            //fprintf(stderr, "Failed to resize address mapping table\n");
            return;
        }
        addressMappings = new_mappings;
    }

    addressMappings[mappingCount].realAddress = real;
    addressMappings[mappingCount].obfuscatedAddress = obfuscated;
    mappingCount++;
}

static void _SecureZeroMemory(void* ptr, size_t size) {
    volatile uint8_t* p = (volatile uint8_t*)ptr;
    while (size--) {
        *p++ = 0;
    }
}

void ShadowStackPush(void* returnAddress, void* framePointer, const char* functionName) {
    if (!gShadowStackInitialized) {
        ShadowStackInit();
    }

    EnterCriticalSection(&stackLock);

    if (gShadowStackPtr + sizeof(ShadowStackFrame) > SHADOW_STACK_SIZE) {
        LeaveCriticalSection(&stackLock);
        //fprintf(stderr, "Shadow stack overflow\n");
        ExitProcess(EXIT_FAILURE);
    }


    ShadowStackFrame* frame = (ShadowStackFrame*)(gShadowStack + gShadowStackPtr);

    void* obfuscated_return = ObfuscateAddress(returnAddress);

    frame->returnAddress = obfuscated_return;
    frame->framePointer = framePointer;
    frame->sequenceId = gSequenceCounter++;
    frame->timeStamp = GetTimestamp();

    strncpy_s(frame->functionName, MAX_FUNCTION_NAME_LENGTH,
        functionName, _TRUNCATE);

    GenerateCanary(frame->canary);

    frame->checkSum = CalculateChecksum(frame,
        offsetof(ShadowStackFrame, checkSum));

    gShadowStackPtr += sizeof(ShadowStackFrame);

    LeaveCriticalSection(&stackLock);
}

BOOL ShadowStackPop(void* expected_return_address, void* expected_frame_pointer) 
{
    if (!gShadowStackInitialized || gShadowStackPtr < sizeof(ShadowStackFrame)) {
        //fprintf(stderr, "Shadow stack underflow or not initialized\n");
        return FALSE;
    }

    EnterCriticalSection(&stackLock);

    gShadowStackPtr -= sizeof(ShadowStackFrame);
    ShadowStackFrame* frame = (ShadowStackFrame*)(gShadowStack + gShadowStackPtr);

    uint32_t calculated_checksum = CalculateChecksum(frame,
        offsetof(ShadowStackFrame, checkSum));

    void* real_return_address = DeobfuscateAddress(frame->returnAddress);


    BOOL valid = (calculated_checksum == frame->checkSum) &&
        (real_return_address == expected_return_address) &&
        (frame->framePointer == expected_frame_pointer);

    _SecureZeroMemory(frame, sizeof(ShadowStackFrame));

    LeaveCriticalSection(&stackLock);

    if (!valid) {
#ifdef _DEBUG
        fprintf(stderr, "Shadow stack validation failed!\n");
        fprintf(stderr, "Expected: return=%p, frame=%p\n",
            expected_return_address, expected_frame_pointer);
        fprintf(stderr, "Actual: return=%p, frame=%p\n",
            real_return_address, frame->framePointer);
#endif
    }

    return valid;
}

void ShadowStackCleanup(void) 
{
    if (!gShadowStackInitialized)
        return;

    EnterCriticalSection(&stackLock);

    if (gShadowStack) {
        _SecureZeroMemory(gShadowStack, SHADOW_STACK_SIZE);
        VirtualFree(gShadowStack, 0, MEM_RELEASE);
        gShadowStack = NULL;
    }

    if (addressMappings) {
        _SecureZeroMemory(addressMappings, mappingCapacity * sizeof(AddressMapping));
        free(addressMappings);
        addressMappings = NULL;
    }

    gShadowStackInitialized = FALSE;

    LeaveCriticalSection(&stackLock);
    DeleteCriticalSection(&stackLock);
}

