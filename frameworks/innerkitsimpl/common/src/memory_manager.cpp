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
#include "image_utils.h"
#include "log_tags.h"
#include "media_errors.h"
#include "securec.h"

#if !defined(_WIN32) && !defined(_APPLE) &&!defined(IOS_PLATFORM) &&!defined(A_PLATFORM)
#include <sys/mman.h>
#include "ashmem.h"
#include "surface_buffer.h"
#define SUPPORT_SHARED_MEMORY
#endif

namespace OHOS {
namespace Media {
using namespace OHOS::HiviewDFX;
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_TAG_DOMAIN_ID_IMAGE, "MemoryManager" };
static const size_t SIZE_ZERO = 0;
static const int LINUX_SUCCESS = 0;
// Define pixel map malloc max size 600MB
constexpr int32_t PIXEL_MAP_MAX_RAM_SIZE = 600 * 1024 * 1024;

uint32_t HeapMemory::Create()
{
    HiLog::Debug(LABEL, "HeapMemory::Create IN");
    if (data.data != nullptr) {
        HiLog::Debug(LABEL, "HeapMemory::Create has created");
        return SUCCESS;
    }
    if (data.size == 0 || data.size > PIXEL_MAP_MAX_RAM_SIZE) {
        HiLog::Error(LABEL, "HeapMemory::Create Invalid value of bufferSize");
        return ERR_IMAGE_DATA_ABNORMAL;
    }
    data.data = static_cast<uint8_t *>(malloc(data.size));
    if (data.data == nullptr) {
        HiLog::Error(LABEL, "HeapMemory::Create malloc buffer failed");
        return ERR_IMAGE_MALLOC_ABNORMAL;
    }
#if defined(IOS_PLATFORM) || defined(A_PLATFORM)
    memset_s(data.data, data.size, 0, data.size);
#endif
    return SUCCESS;
}

uint32_t HeapMemory::Release()
{
#if !defined(IOS_PLATFORM) &&!defined(A_PLATFORM)
    HiLog::Debug(LABEL, "HeapMemory::Release IN");
    if (data.data == nullptr) {
        HiLog::Error(LABEL, "HeapMemory::Release nullptr data");
        return ERR_IMAGE_DATA_ABNORMAL;
    }
    free(data.data);
    data.data = nullptr;
#endif
    return SUCCESS;
}

static inline void ReleaseSharedMemory(int* fdPtr, uint8_t* ptr = nullptr, size_t size = SIZE_ZERO)
{
#if !defined(IOS_PLATFORM) &&!defined(A_PLATFORM)
    if (ptr != nullptr && ptr != MAP_FAILED) {
        ::munmap(ptr, size);
    }
    if (fdPtr != nullptr) {
        ::close(*fdPtr);
    }
#endif
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

uint32_t DmaMemory::Create()
{
#if defined(_WIN32) || defined(_APPLE) || defined(A_PLATFORM) || defined(IOS_PLATFORM)
    HiLog::Error(LABEL, "Unsupport dma mem alloc");
    return ERR_IMAGE_DATA_UNSUPPORT;
#else
    sptr<SurfaceBuffer> sb = SurfaceBuffer::Create();
    BufferRequestConfig requestConfig = {
        .width = data.desiredSize.width,
        .height = data.desiredSize.height,
        .strideAlignment = 0x8, // set 0x8 as default value to alloc SurfaceBufferImpl
        .format = GRAPHIC_PIXEL_FMT_RGBA_8888, // PixelFormat
        .usage = BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE | BUFFER_USAGE_MEM_DMA,
        .timeout = 0,
        .colorGamut = GraphicColorGamut::GRAPHIC_COLOR_GAMUT_SRGB,
        .transform = GraphicTransformType::GRAPHIC_ROTATE_NONE,
    };
    GSError ret = sb->Alloc(requestConfig);
    if (ret != GSERROR_OK) {
        HiLog::Error(LABEL, "SurfaceBuffer Alloc failed, %{public}s", GSErrorStr(ret).c_str());
        return ERR_DMA_NOT_EXIST;
    }
    void* nativeBuffer = sb.GetRefPtr();
    int32_t err = ImageUtils::SurfaceBuffer_Reference(nativeBuffer);
    if (err != OHOS::GSERROR_OK) {
        HiLog::Error(LABEL, "NativeBufferReference failed");
        return ERR_DMA_DATA_ABNORMAL;
    }
    data.data = static_cast<uint8_t*>(sb->GetVirAddr());
    extend.size = data.size;
    extend.data = nativeBuffer;
    return SUCCESS;
#endif
}

uint32_t DmaMemory::Release()
{
#if defined(_WIN32) || defined(_APPLE) || defined(A_PLATFORM) || defined(IOS_PLATFORM)
    HiLog::Error(LABEL, "Unsupport dma mem release");
    return ERR_IMAGE_DATA_UNSUPPORT;
#else
    data.data = nullptr;
    data.size = SIZE_ZERO;
    if (extend.data != nullptr) {
        int32_t err = ImageUtils::SurfaceBuffer_Unreference(static_cast<SurfaceBuffer*>(extend.data));
        if (err != OHOS::GSERROR_OK) {
            HiLog::Error(LABEL, "NativeBufferReference failed");
            return ERR_DMA_DATA_ABNORMAL;
        }
        extend.data = nullptr;
        extend.size = SIZE_ZERO;
    }
    return SUCCESS;
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
        case AllocatorType::DMA_ALLOC:
            res = std::make_unique<DmaMemory>();
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
    res->data.desiredSize = data.desiredSize;
    res->extend.data = extend.data;
    res->extend.size = extend.size;
    res->extend.tag = extend.tag;
    res->extend.desiredSize = extend.desiredSize;
    if (res->data.data == nullptr) {
        if (res->Create() != SUCCESS) {
            return nullptr;
        }
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