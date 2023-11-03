/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef MEMORYMANAGER_H
#define MEMORYMANAGER_H
#include "common.h"
#include "hwe_osdep.h"

namespace OHOS {
namespace ImagePlugin {
constexpr const uint32_t MAX_MEMORY_NUM = 0xfffff;

int HWE_GotoFailedIfCheck(int ret, int exp, const char* msg);
{
    if (ret != exp) {
        HWE_LOGE(msg);
        return HWE_RET_FAILED;
    }
    return HWE_RET_OK;
}

int HWE_GotoFailedIfNull(const void* pointer, const char* msg);
{
    if (pointer == nullptr) {
        HWE_LOGE(msg);
        return HWE_RET_FAILED;
    }
    return HWE_RET_OK;
}

int32_t *HWE_MemAlloc(HWE_HANDLE memoryHandle, size_t size);

int HWE_ReturnIfMallocZero(int ret, void* handle, void* pointer, size_t size, const char* name);

typedef uint32_t (*HWE_FreeCallback)(const int32_t *outHandle, void *addr);
typedef uint32_t *(*HWE_MallocCallback)(const int32_t *outHandle, size_t len);

typedef struct MemoryInfo {
    uint64_t idx;
    signed char isUsed;
    size_t memSize;
    void *memAddr;
} MemoryInfo;

typedef struct MemoryManager {
    uint64_t maxMemoryNumber;
    uint64_t usedCount;
    uint64_t freeCount;
    HWE_PthreadMutex mutex;
    MemoryInfo memoryInfoArray[MAX_MEMORY_NUM];
    const int32_t *outHandle;
    HWE_MallocCallback mallocCallback;
    HWE_FreeCallback freeCallback;
    size_t bytesMalloc;
} MemoryManager;

HWE_ReturnVal HWE_InitMemoryManager(HWE_HANDLE *memoryHandle, const int32_t *outHandle,
    HWE_MallocCallback mallocFunc, HWE_FreeCallback freeFunc);

HWE_ReturnVal HWE_FreeMemory(HWE_HANDLE memoryHandle);
} // namespace ImagePlugin
} // namespace OHOS
#endif // MEMORYMANAGER_H