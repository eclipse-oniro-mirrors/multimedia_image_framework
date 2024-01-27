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

#include "pixel_map_parcel.h"
#include <unistd.h>
#include "image_log.h"
#include "media_errors.h"
#ifndef _WIN32
#include "securec.h"
#else
#include "memory.h"
#endif

#if !defined(_WIN32) && !defined(_APPLE)
#include <sys/mman.h>
#include "ashmem.h"
#endif

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "PixelMapParcel"

namespace OHOS {
namespace Media {
using namespace std;

constexpr int32_t PIXEL_MAP_INFO_MAX_LENGTH = 128;

void PixelMapParcel::ReleaseMemory(AllocatorType allocType, void *addr, void *context, uint32_t size)
{
    if (allocType == AllocatorType::SHARE_MEM_ALLOC) {
#if !defined(_WIN32) && !defined(_APPLE)
        int *fd = static_cast<int *>(context);
        if (addr != nullptr) {
            ::munmap(addr, size);
        }
        if (fd != nullptr) {
            ::close(*fd);
            delete fd;
        }
#endif
    } else if (allocType == AllocatorType::HEAP_ALLOC) {
        if (addr != nullptr) {
            free(addr);
            addr = nullptr;
        }
    }
}

uint8_t *PixelMapParcel::ReadAshmemDataFromParcel(OHOS::MessageParcel& data, int32_t bufferSize, int32_t*& context)
{
    uint8_t *base = nullptr;
    int fd = data.ReadFileDescriptor();
    if (fd < 0) {
        IMAGE_LOGE("read fileDescriptor failed, fd < 0");
        return nullptr;
    }
    void* ptr = ::mmap(nullptr, bufferSize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (ptr == MAP_FAILED) {
        ::close(fd);
        IMAGE_LOGE("mmap shared memory failed");
        return nullptr;
    }
    context = new int32_t();
    if (context == nullptr) {
        IMAGE_LOGE("alloc context failed.");
        ::munmap(ptr, bufferSize);
        ::close(fd);
        return nullptr;
    }
    *static_cast<int32_t *>(context) = fd;
    base = static_cast<uint8_t *>(ptr);
    return base;
}

uint8_t *PixelMapParcel::ReadHeapDataFromParcel(OHOS::MessageParcel& data, int32_t bufferSize)
{
    const uint8_t *addr = data.ReadBuffer(bufferSize);
    uint8_t *base = nullptr;
    if (addr == nullptr) {
        IMAGE_LOGE("read buffer from parcel failed, read buffer addr is null");
        return nullptr;
    }
    if (bufferSize <= 0 || bufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("read bufferSize failed, invalid bufferSize.");
        return nullptr;
    }
    base = static_cast<uint8_t *>(malloc(bufferSize));
    if (base == nullptr) {
        IMAGE_LOGE("alloc new pixel memory size:[%{public}d] failed.", bufferSize);
        return nullptr;
    }
    if (memcpy_s(base, bufferSize, addr, bufferSize) != 0) {
        free(base);
        base = nullptr;
        IMAGE_LOGE("memcpy pixel data size:[%{public}d] error.", bufferSize);
        return nullptr;
    }
    return base;
}

std::unique_ptr<PixelMap> PixelMapParcel::CreateFromParcel(OHOS::MessageParcel& data)
{
    unique_ptr<PixelMap> pixelMap = make_unique<PixelMap>();
    if (pixelMap == nullptr) {
        IMAGE_LOGE("create pixelmap pointer fail");
        return nullptr;
    }

    ImageInfo imgInfo;
    imgInfo.size.width = data.ReadInt32();
    imgInfo.size.height = data.ReadInt32();
    imgInfo.pixelFormat = static_cast<PixelFormat>(data.ReadInt32());
    imgInfo.colorSpace = static_cast<ColorSpace>(data.ReadInt32());
    imgInfo.alphaType = static_cast<AlphaType>(data.ReadInt32());
    imgInfo.baseDensity = data.ReadInt32();
    int32_t bufferSize = data.ReadInt32();
    AllocatorType allocType = static_cast<AllocatorType>(data.ReadInt32());
    uint8_t *base = nullptr;
    int32_t *context = nullptr;
    if (allocType == AllocatorType::SHARE_MEM_ALLOC) {
#if !defined(_WIN32) && !defined(_APPLE)
        base = ReadAshmemDataFromParcel(data, bufferSize, context);
#endif
    } else {
        base = ReadHeapDataFromParcel(data, bufferSize);
    }

    uint32_t ret = pixelMap->SetImageInfo(imgInfo);
    if (ret != SUCCESS) {
        ReleaseMemory(allocType, base, reinterpret_cast<void *>(context), bufferSize);
        IMAGE_LOGE("create pixel map from parcel failed, set image info error.");
        return nullptr;
    }
    pixelMap->SetPixelsAddr(base, reinterpret_cast<void *>(context), bufferSize, allocType, nullptr);
    return pixelMap;
}

bool PixelMapParcel::WriteImageInfo(PixelMap* pixelMap, OHOS::MessageParcel& data)
{
    int32_t bufferSize = pixelMap->GetByteCount();
    if (static_cast<size_t>(bufferSize + PIXEL_MAP_INFO_MAX_LENGTH) > data.GetDataCapacity() &&
        !data.SetDataCapacity(bufferSize + PIXEL_MAP_INFO_MAX_LENGTH)) {
        IMAGE_LOGE("set parcel max capacity:[%{public}d] failed.", bufferSize + PIXEL_MAP_INFO_MAX_LENGTH);
        return false;
    }
    if (!data.WriteInt32(pixelMap->GetWidth())) {
        IMAGE_LOGE("write pixel map width:[%{public}d] to parcel failed.", pixelMap->GetWidth());
        return false;
    }
    if (!data.WriteInt32(pixelMap->GetHeight())) {
        IMAGE_LOGE("write pixel map height:[%{public}d] to parcel failed.", pixelMap->GetHeight());
        return false;
    }
    if (!data.WriteInt32(static_cast<int32_t>(pixelMap->GetPixelFormat()))) {
        IMAGE_LOGE("write pixel map pixel format:[%{public}d] to parcel failed.", pixelMap->GetPixelFormat());
        return false;
    }
    if (!data.WriteInt32(static_cast<int32_t>(pixelMap->GetColorSpace()))) {
        IMAGE_LOGE("write pixel map color space:[%{public}d] to parcel failed.", pixelMap->GetColorSpace());
        return false;
    }
    if (!data.WriteInt32(static_cast<int32_t>(pixelMap->GetAlphaType()))) {
        IMAGE_LOGE("write pixel map alpha type:[%{public}d] to parcel failed.", pixelMap->GetAlphaType());
        return false;
    }
    if (!data.WriteInt32(pixelMap->GetBaseDensity())) {
        IMAGE_LOGE("write pixel map base density:[%{public}d] to parcel failed.", pixelMap->GetBaseDensity());
        return false;
    }
    if (!data.WriteInt32(bufferSize)) {
        IMAGE_LOGE("write pixel map buffer size:[%{public}d] to parcel failed.", bufferSize);
        return false;
    }
    if (!data.WriteInt32(static_cast<int32_t>(pixelMap->GetAllocatorType()))) {
        IMAGE_LOGE("write pixel map allocator type:[%{public}d] to parcel failed.",
            pixelMap->GetAllocatorType());
        return false;
    }
    return true;
}

bool PixelMapParcel::WriteToParcel(PixelMap* pixelMap, OHOS::MessageParcel& data)
{
    if (pixelMap == nullptr) {
        return false;
    }
    int32_t bufferSize = pixelMap->GetByteCount();
    if (!WriteImageInfo(pixelMap, data)) {
        IMAGE_LOGE("write pixel map info failed.");
        return false;
    }
    if (pixelMap->GetAllocatorType() == AllocatorType::SHARE_MEM_ALLOC) {
#if !defined(_WIN32) && !defined(_APPLE)
        int *fd = static_cast<int *>(pixelMap->GetFd());
        if (*fd < 0) {
            IMAGE_LOGE("write pixel map failed, fd < 0.");
            return false;
        }
        if (!data.WriteFileDescriptor(*fd)) {
            IMAGE_LOGE("write pixel map fd:[%{public}d] to parcel failed.", *fd);
            return false;
        }
#endif
    } else {
        const uint8_t *addr = pixelMap->GetPixels();
        if (addr == nullptr) {
            IMAGE_LOGE("write to parcel failed, pixel memory is null.");
            return false;
        }
        if (!data.WriteBuffer(addr, bufferSize)) {
            IMAGE_LOGE("write pixel map buffer to parcel failed.");
            return false;
        }
    }
    return true;
}
}  // namespace Media
}  // namespace OHOS
