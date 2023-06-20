/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "memory_manager.h"

#include <cerrno>
#include <unistd.h>
#include "hilog/log.h"
#include "log_tags.h"
#include "media_errors.h"
#include "securec.h"

#if !defined(_WIN32) && !defined(_APPLE) &&!defined(IOS_PLATFORM) &&!defined(A_PLATFORM)
#include <sys/mman.h>
#include "ashmem.h"
#define SUPPORT_SHARED_MEMORY
#endif

namespace OHOS {
namespace Media {
using namespace OHOS::HiviewDFX;
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_TAG_DOMAIN_ID_IMAGE, "MemoryManager" };
static const size_t SIZE_ZERO = 0;
static const int LINUX_SUCCESS = 0;
uint32_t HeapMemory::Create()
{
    HiLog::Debug(LABEL, "HeapMemory::Create IN");
    if (data.data != nullptr) {
        HiLog::Debug(LABEL, "HeapMemory::Create has created");
        return SUCCESS;
    }
    if (data.size == SIZE_ZERO) {
        HiLog::Error(LABEL, "HeapMemory::Create size is 0");
        return ERR_IMAGE_DATA_ABNORMAL;
    }
    auto dataPtr = std::make_unique<uint8_t[]>(data.size);
    if (dataPtr == nullptr) {
        HiLog::Error(LABEL, "HeapMemory::Create alloc failed");
        return ERR_IMAGE_DATA_ABNORMAL;
    }
    data.data = dataPtr.release();
    return SUCCESS;
}

uint32_t HeapMemory::Release()
{
    HiLog::Debug(LABEL, "HeapMemory::Release IN");
    if (data.data == nullptr) {
        HiLog::Error(LABEL, "HeapMemory::Release nullptr data");
        return ERR_IMAGE_DATA_ABNORMAL;
    }
    free(data.data);
    data.data = nullptr;
    return SUCCESS;
}

static inline void ReleaseSharedMemory(int* fdPtr, uint8_t* ptr = nullptr, size_t size = SIZE_ZERO)
{
    if (ptr != nullptr && ptr != MAP_FAILED) {
        ::munmap(ptr, size);
    }
    if (fdPtr != nullptr) {
        ::close(*fdPtr);
    }
}

uint32_t SharedMemory::Create()
{
#ifdef SUPPORT_SHARED_MEMORY
    HiLog::Debug(LABEL, "SharedMemory::Create IN tag %{public}s, data size %{public}zu",
        (data.tag == nullptr)?"nullptr":data.tag, data.size);

    if (data.tag == nullptr || data.size == SIZE_ZERO) {
        HiLog::Error(LABEL, "SharedMemory::Create tag is nullptr or data size %{public}zu", data.size);
        return ERR_IMAGE_DATA_ABNORMAL;
    }
    auto fdPtr = std::make_unique<int>();
    if (fdPtr == nullptr) {
        HiLog::Error(LABEL, "SharedMemory::Create fd alloc failed");
        return ERR_IMAGE_DATA_ABNORMAL;
    }
    *fdPtr = AshmemCreate(data.tag, data.size);
    if (*fdPtr < 0) {
        HiLog::Error(LABEL, "SharedMemory::Create AshmemCreate fd:[%{public}d].", *fdPtr);
        return ERR_IMAGE_DATA_ABNORMAL;
    }
    if (AshmemSetProt(*fdPtr, PROT_READ | PROT_WRITE) < LINUX_SUCCESS) {
        HiLog::Error(LABEL, "SharedMemory::Create AshmemSetProt errno %{public}d.", errno);
        ReleaseSharedMemory(fdPtr.get());
        return ERR_IMAGE_DATA_ABNORMAL;
    }
    data.data = ::mmap(nullptr, data.size, PROT_READ | PROT_WRITE, MAP_SHARED, *fdPtr, 0);
    if (data.data == MAP_FAILED) {
        HiLog::Error(LABEL, "SharedMemory::Create mmap failed, errno:%{public}d", errno);
        ReleaseSharedMemory(fdPtr.get(), static_cast<uint8_t*>(data.data), data.size);
        return ERR_IMAGE_DATA_ABNORMAL;
    }
    extend.size = sizeof(int);
    extend.data = fdPtr.release();
    return SUCCESS;
#else
    HiLog::Error(LABEL, "SharedMemory::Create unsupported");
    return ERR_IMAGE_DATA_UNSUPPORT;
#endif
}

uint32_t SharedMemory::Release()
{
#ifdef SUPPORT_SHARED_MEMORY
    HiLog::Debug(LABEL, "SharedMemory::Release IN");
    ReleaseSharedMemory(static_cast<int*>(extend.data), static_cast<uint8_t*>(data.data), data.size);
    data.data = nullptr;
    data.size = SIZE_ZERO;
    if (extend.data != nullptr) {
        free(extend.data);
        extend.data = nullptr;
        extend.size = SIZE_ZERO;
    }
    return SUCCESS;
#else
    HiLog::Error(LABEL, "SharedMemory::Release unsupported");
    return ERR_IMAGE_DATA_UNSUPPORT;
#endif
}

std::unique_ptr<AbsMemory> MemoryManager::CreateMemory(AllocatorType type, MemoryData &data)
{
    MemoryData extend;
    return CreateMemory(type, data, extend);
}

std::unique_ptr<AbsMemory> MemoryManager::CreateMemory(AllocatorType type, MemoryData &data, MemoryData &extend)
{
    std::unique_ptr<AbsMemory> res = nullptr;
    switch (type) {
        case AllocatorType::SHARE_MEM_ALLOC:
            res = std::make_unique<SharedMemory>();
            break;
        case AllocatorType::CUSTOM_ALLOC:
            HiLog::Error(LABEL, "MemoryManager::CreateMemory unsupported CUSTOM_ALLOC now");
            return nullptr;
        case AllocatorType::DEFAULT:
        case AllocatorType::HEAP_ALLOC:
        default:
            res = std::make_unique<HeapMemory>();
            break;
    }
    if (res == nullptr) {
        HiLog::Error(LABEL, "MemoryManager::CreateMemory unsupported %{public}d", type);
        return nullptr;
    }
    res->data.data = data.data;
    res->data.size = data.size;
    res->data.tag = data.tag;
    res->extend.data = extend.data;
    res->extend.size = extend.size;
    res->extend.tag = extend.tag;
    if (res->data.data == nullptr) {
        res->Create();
    }
    return res;
}

std::unique_ptr<AbsMemory> MemoryManager::TransMemoryType(const AbsMemory &source, AllocatorType target,
    std::string tag)
{
    MemoryData data = { nullptr, source.data.size, tag.c_str()};
    auto res = CreateMemory(target, data);
    if (res == nullptr) {
        return res;
    }
    memcpy_s(res->data.data, res->data.size, source.data.data, source.data.size);
    return res;
}
} // namespace Media
} // namespace OHOS