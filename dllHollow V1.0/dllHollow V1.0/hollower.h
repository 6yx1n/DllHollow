#pragma once
#include <Windows.h>
#include <stdint.h>

typedef void(*fnAddr)();

BOOL HollowDLLPro(
    uint8_t** ppMapBuf,
    uint64_t* pqwMapBufSize,
    const uint8_t* pCodeBuf,
    uint32_t dwReqBufSize,
    uint8_t** ppMappedCode,
    BOOL bTxF
);