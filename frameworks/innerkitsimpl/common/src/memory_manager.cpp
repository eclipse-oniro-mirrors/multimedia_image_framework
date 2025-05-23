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
#include "image_log.h"
#include "image_utils.h"
#include "media_errors.h"
#include "securec.h"

#if !defined(_WIN32) && !defined(_APPLE) &&!defined(IOS_PLATFORM) &&!defined(ANDROID_PLATFORM)
#include <sys/mman.h>
#include "ashmem.h"
#include "surface_buffer.h"
#define SUPPORT_SHARED_MEMORY
#endif

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "MemoryManager"

namespace OHOS {
namespace Media {
static const size_t SIZE_ZERO = 0;
static const int LINUX_SUCCESS = 0;
// Define pixel map malloc max size 600MB
constexpr int32_t PIXEL_MAP_MAX_RAM_SIZE = 600 * 1024 * 1024;

uint32_t HeapMemory::Create()
{
    IMAGE_LOGD("HeapMemory::Create IN");
    if (data.data != nullptr) {
        IMAGE_LOGD("HeapMemory::Create has created");
        return SUCCESS;
    }
    if (data.size == 0 || data.size > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("HeapMemory::Create Invalid value of bufferSize");
        return ERR_IMAGE_DATA_ABNORMAL;
    }
    data.data = static_cast<uint8_t *>(malloc(data.size));
    if (data.data == nullptr) {
        IMAGE_LOGE("HeapMemory::Create malloc buffer failed");
        return ERR_IMAGE_MALLOC_ABNORMAL;
    }
#if defined(IOS_PLATFORM) || defined(ANDROID_PLATFORM)
    memset_s(data.data, data.size, 0, data.size);
#endif
    return SUCCESS;
}

uint32_t HeapMemory::Release()
{
#if !defined(IOS_PLATFORM) &&!defined(ANDROID_PLATFORM)
    IMAGE_LOGD("HeapMemory::Release IN");
    if (data.data == nullptr) {
        IMAGE_LOGI("HeapMemory::Release nullptr data");
        return ERR_IMAGE_DATA_ABNORMAL;
    }
    free(data.data);
    data.data = nullptr;
#endif
    return SUCCESS;
}

static inline void ReleaseSharedMemory(int* fdPtr, uint8_t* ptr = nullptr, size_t size = SIZE_ZERO)
{
#if !defined(IOS_PLATFORM) &&!defined(ANDROID_PLATFORM)
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
    IMAGE_LOGD("SharedMemory::Create IN tag %{public}s, data size %{public}zu",
        data.tag == nullptr ? "nullptr" : data.tag, data.size);

    if (data.tag == nullptr || data.size == SIZE_ZERO) {
        IMAGE_LOGE("SharedMemory::Create tag is nullptr or data size %{public}zu", data.size);
        return ERR_IMAGE_DATA_ABNORMAL;
    }
    auto fdPtr = std::make_unique<int>();
    *fdPtr = AshmemCreate(data.tag, data.size);
    if (*fdPtr < 0) {
        IMAGE_LOGE("SharedMemory::Create AshmemCreate fd:[%{public}d].", *fdPtr);
        return ERR_IMAGE_DATA_ABNORMAL;
    }
    if (AshmemSetProt(*fdPtr, PROT_READ | PROT_WRITE) < LINUX_SUCCESS) {
        IMAGE_LOGE("SharedMemory::Create AshmemSetProt errno %{public}d.", errno);
        ReleaseSharedMemory(fdPtr.get());
        return ERR_IMAGE_DATA_ABNORMAL;
    }
    data.data = ::mmap(nullptr, data.size, PROT_READ | PROT_WRITE, MAP_SHARED, *fdPtr, 0);
    if (data.data == MAP_FAILED) {
        IMAGE_LOGE("SharedMemory::Create mmap failed, errno:%{public}d", errno);
        ReleaseSharedMemory(fdPtr.get(), static_cast<uint8_t*>(data.data), data.size);
        return ERR_IMAGE_DATA_ABNORMAL;
    }
    extend.size = sizeof(int);
    extend.data = fdPtr.release();
    return SUCCESS;
#else
    IMAGE_LOGE("SharedMemory::Create unsupported");
    return ERR_IMAGE_DATA_UNSUPPORT;
#endif
}

uint32_t SharedMemory::Release()
{
#ifdef SUPPORT_SHARED_MEMORY
    IMAGE_LOGD("SharedMemory::Release IN");
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
    IMAGE_LOGE("SharedMemory::Release unsupported");
    return ERR_IMAGE_DATA_UNSUPPORT;
#endif
}

#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
GraphicPixelFormat GetRequestBufferFormatWithPixelFormat(const PixelFormat format)
{
    switch (format) {
        case PixelFormat::RGBA_1010102:
            return GRAPHIC_PIXEL_FMT_RGBA_1010102;
        case PixelFormat::ASTC_4x4:
        case PixelFormat::ASTC_6x6:
        case PixelFormat::ASTC_8x8:
            return GRAPHIC_PIXEL_FMT_BLOB;
        case PixelFormat::NV12:
            return GRAPHIC_PIXEL_FMT_YCBCR_420_SP;
        case PixelFormat::NV21:
            return GRAPHIC_PIXEL_FMT_YCRCB_420_SP;
        case PixelFormat::BGRA_8888:
            return GRAPHIC_PIXEL_FMT_BGRA_8888;
        case PixelFormat::YCRCB_P010:
            return GRAPHIC_PIXEL_FMT_YCRCB_P010;
        case PixelFormat::YCBCR_P010:
            return GRAPHIC_PIXEL_FMT_YCBCR_P010;
        case PixelFormat::RGBA_F16:
            return GRAPHIC_PIXEL_FMT_RGBA16_FLOAT;
        case PixelFormat::RGB_565:
            return GRAPHIC_PIXEL_FMT_RGB_565;
        default:
            return GRAPHIC_PIXEL_FMT_RGBA_8888;
    }
}
#endif

uint32_t DmaMemory::Create()
{
#if defined(_WIN32) || defined(_APPLE) || defined(ANDROID_PLATFORM) || defined(IOS_PLATFORM)
    IMAGE_LOGE("Unsupport dma mem alloc");
    return ERR_IMAGE_DATA_UNSUPPORT;
#else
    sptr<SurfaceBuffer> sb = SurfaceBuffer::Create();
    if (sb == nullptr) {
        IMAGE_LOGE("SurfaceBuffer failed to be created");
        return ERR_DMA_DATA_ABNORMAL;
    }
    GraphicPixelFormat format = GetRequestBufferFormatWithPixelFormat(data.format);
    BufferRequestConfig requestConfig = {
        .width = data.desiredSize.width,
        .height = data.desiredSize.height,
        .strideAlignment = 0x8, // set 0x8 as default value to alloc SurfaceBufferImpl
        .format = format, // PixelFormat
        .usage = BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE | BUFFER_USAGE_MEM_DMA | BUFFER_USAGE_MEM_MMZ_CACHE,
        .timeout = 0,
    };
    GSError ret = sb->Alloc(requestConfig);
    if (ret != GSERROR_OK) {
        IMAGE_LOGE("SurfaceBuffer Alloc failed, %{public}s", GSErrorStr(ret).c_str());
        return ERR_DMA_NOT_EXIST;
    }
    void* nativeBuffer = sb.GetRefPtr();
    int32_t err = ImageUtils::SurfaceBuffer_Reference(nativeBuffer);
    if (err != OHOS::GSERROR_OK) {
        IMAGE_LOGE("NativeBufferReference failed");
        return ERR_DMA_DATA_ABNORMAL;
    }
    data.data = static_cast<uint8_t*>(sb->GetVirAddr());
    if (data.data == nullptr) {
        IMAGE_LOGE("SurfaceBuffer failed to  GetVirAddr");
        return ERR_DMA_DATA_ABNORMAL;
    }
    extend.size = data.size;
    extend.data = nativeBuffer;
    return SUCCESS;
#endif
}

uint32_t DmaMemory::Release()
{
#if defined(_WIN32) || defined(_APPLE) || defined(ANDROID_PLATFORM) || defined(IOS_PLATFORM)
    IMAGE_LOGE("Unsupport dma mem release");
    return ERR_IMAGE_DATA_UNSUPPORT;
#else
    data.data = nullptr;
    data.size = SIZE_ZERO;
    if (extend.data != nullptr) {
        int32_t err = ImageUtils::SurfaceBuffer_Unreference(static_cast<SurfaceBuffer*>(extend.data));
        if (err != OHOS::GSERROR_OK) {
            IMAGE_LOGE("NativeBufferReference failed");
            extend.data = nullptr;
            extend.size = SIZE_ZERO;
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
    MemoryData extend{};
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
            IMAGE_LOGE("MemoryManager::CreateMemory unsupported CUSTOM_ALLOC now");
            return nullptr;
        case AllocatorType::DEFAULT:
        case AllocatorType::HEAP_ALLOC:
        default:
            res = std::make_unique<HeapMemory>();
            break;
    }
    if (res == nullptr) {
        IMAGE_LOGE("MemoryManager::CreateMemory unsupported %{public}d", type);
        return nullptr;
    }
    res->data.data = data.data;
    res->data.size = data.size;
    res->data.tag = data.tag;
    res->data.desiredSize = data.desiredSize;
    res->data.format = data.format;
    res->extend.data = extend.data;
    res->extend.size = extend.size;
    res->extend.tag = extend.tag;
    res->extend.desiredSize = extend.desiredSize;
    res->extend.format = data.format;
    if (res->data.data == nullptr) {
        if (res->Create() != SUCCESS) {
            return nullptr;
        }
    }
    return res;
}
} // namespace Media
} // namespace OHOS