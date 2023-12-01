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

#include "hwe_memoryManager.h"

namespace OHOS {
namespace ImagePlugin {
HWE_ReturnVal HWE_InitMemoryManager(HWE_HANDLE *memoryHandle,
    const int32_t *outHandle, HWE_MallocCallback mallocFunc, HWE_FreeCallback freeFunc)
{
    int32_t ret;
    if (!memoryHandle) {
        HWE_LOGE("Init memoryInfoArray memoryHandle is nullptr.");
        return HWE_RET_FAILED;
    }
    MemoryManager *memoryManager = static_cast<MemoryManager *>(HWE_Malloc(sizeof(MemoryManager)));
    HWE_RETURN_IF_NULL(memoryManager, "memoryManager malloc failed!");
    *memoryHandle = memoryManager;

    ret = HWE_PthreadMutexInit(&memoryManager->mutex);
    if (ret) {
        HWE_Free(memoryManager);
        HWE_LOGE("Init mutex failed.");
        return HWE_RET_FAILED;
    }
    memoryManager->freeCount = 0;
    memoryManager->usedCount = 0;
    memoryManager->maxMemoryNumber = MAX_MEMORY_NUM;
    memoryManager->bytesMalloc = 0;
    if (outHandle && mallocFunc && freeFunc) {
        memoryManager->outHandle = outHandle;
        memoryManager->mallocCallback = mallocFunc;
        memoryManager->freeCallback = freeFunc;
    } else {
        memoryManager->outHandle = nullptr;
        memoryManager->mallocCallback = nullptr;
        memoryManager->freeCallback = nullptr;
    }

    return HWE_RET_OK;
}

HWE_ReturnVal HWE_FreeMemory(HWE_HANDLE memoryHandle)
{
    HWE_RETURN_IF_NULL(memoryHandle, "memoryHandle is nullptr!");
    MemoryManager *memoryManager = static_cast<MemoryManager *>(memoryHandle);
    uint64_t i;
    int32_t ret;
    for (i = 0; i < memoryManager->usedCount; i++) {
        if (memoryManager->memoryInfoArray[i].isUsed != TRUE) {
            continue;
        }

        if (memoryManager->memoryInfoArray[i].idx != i) {
            HWE_LOGE("Memory lack, idx is %d.", i);
            continue;
        }

        if (memoryManager->memoryInfoArray[i].memAddr == nullptr) {
            HWE_LOGE("Memory addr is nullptr.");
            continue;
        }

        if (memoryManager->outHandle && memoryManager->freeCallback) {
            memoryManager->freeCallback(memoryManager->outHandle, memoryManager->memoryInfoArray[i].memAddr);
        } else {
            HWE_Free(memoryManager->memoryInfoArray[i].memAddr);
        }

        memoryManager->freeCount++;
    }
    if (memoryManager->freeCount != memoryManager->usedCount) {
        HWE_LOGE("Memory leak[free:%d, used:%d]!", memoryManager->freeCount, memoryManager->usedCount);
        return HWE_RET_FAILED;
    }
    ret = HWE_PthreadMutexDestroy(&memoryManager->mutex);
    HWE_RETURN_IF_CHECK(ret, 0, "Destroy mutex failed.");
    HWE_Free(memoryManager);
    return HWE_RET_OK;
}

void* HWE_MemAlloc(HWE_HANDLE memoryHandle, size_t size)
{
    if (!memoryHandle) {
        HWE_LOGE("MemoryHandle is zero");
        return nullptr;
    }
    if (size == 0) {
        HWE_LOGE("Alloc size is zero");
        return nullptr;
    }
    MemoryManager *memoryManager = static_cast<MemoryManager *>(memoryHandle);
    HWE_PthreadMutexLock(&memoryManager->mutex);
    if (memoryManager->usedCount >= memoryManager->maxMemoryNumber) {
        HWE_LOGE("Don't enough memory[max:%d, used:%d]!", memoryManager->maxMemoryNumber, memoryManager->usedCount);
        HWE_PthreadMutexUnLock(&memoryManager->mutex);
        return nullptr;
    }
    void *p = nullptr;

    if (memoryManager->outHandle && memoryManager->mallocCallback) {
        p = memoryManager->mallocCallback(memoryManager->outHandle, size);
    } else {
        p = HWE_Malloc(size);
    }
    if (!p) {
        HWE_LOGE("HWE_Alloc failed.");
        return nullptr;
    }
    memoryManager->memoryInfoArray[memoryManager->usedCount].memAddr = p;
    memoryManager->memoryInfoArray[memoryManager->usedCount].memSize = size;
    memoryManager->memoryInfoArray[memoryManager->usedCount].isUsed = TRUE;
    memoryManager->memoryInfoArray[memoryManager->usedCount].idx = memoryManager->usedCount;
    memoryManager->bytesMalloc += size;
    memoryManager->usedCount++;
    HWE_PthreadMutexUnLock(&memoryManager->mutex);
    return p;
}

void* HWE_ReturnIfMallocZero(int& ret, int32_t* handle, size_t size, const char* name)
{
    void* pointer = nullptr;
    if (handle != nullptr) {
        pointer = HWE_MemAlloc(handle, size);
    } else {
        pointer = HWE_Malloc(size);
    }

    if (pointer == nullptr) {
        HWE_LOGE("malloc %s failed!", name);
        ret = HWE_RET_FAILED;
        return nullptr;
    }

    if (memset_s(pointer, size, 0, size) != 0) {
        if (handle == nullptr) {
            HWE_Free(pointer);
        }
        ret = HWE_RET_FAILED;
        HWE_LOGE("memset %s failed!", name);
        return nullptr;
    }

    ret = HWE_RET_OK;
    return pointer;
}
} // namespace ImagePlugin
} // namespace OHOS