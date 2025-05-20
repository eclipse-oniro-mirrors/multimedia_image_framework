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
#include "pixel_map_utils.h"
#include "pixel_map.h"
#include "pixel_yuv.h"
#include "pixel_astc.h"
#include "image_system_properties.h"
#include "image_trace.h"
#include "image_utils.h"
#ifndef _WIN32
#include "securec.h"
#else
#include "memory.h"
#endif

#if !defined(_WIN32) && !defined(_APPLE)
#include <sys/mman.h>
#include "ashmem.h"
#endif

#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
#include "buffer_handle_parcel.h"
#include "ipc_file_descriptor.h"
#include "surface_buffer.h"
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
    if (!CheckAshmemSize(fd, bufferSize)) {
        IMAGE_LOGE("bufferSize does not match the fileDescriptor");
        return nullptr;
    }
    void* ptr = ::mmap(nullptr, bufferSize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (ptr == MAP_FAILED) {
        ::close(fd);
        IMAGE_LOGE("mmap shared memory failed");
        return nullptr;
    }
    context = new(std::nothrow) int32_t();
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
    if (bufferSize <= 0 || bufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("read bufferSize failed, invalid bufferSize.");
        return nullptr;
    }
    const uint8_t *addr = data.ReadBuffer(bufferSize);
    uint8_t *base = nullptr;
    if (addr == nullptr) {
        IMAGE_LOGE("read buffer from parcel failed, read buffer addr is null");
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

bool PixelMapRecordParcel::WriteImageInfo(Parcel &parcel)
{
    ImageInfo& imageInfo_ = parcelInfo_.imageInfo_;
    if (imageInfo_.size.width <= 0 || !parcel.WriteInt32(imageInfo_.size.width)) {
        IMAGE_LOGE("write image info width:[%{public}d] to parcel failed.", imageInfo_.size.width);
        return false;
    }
    if (imageInfo_.size.height <= 0 || !parcel.WriteInt32(imageInfo_.size.height)) {
        IMAGE_LOGE("write image info height:[%{public}d] to parcel failed.", imageInfo_.size.height);
        return false;
    }
    if (!parcel.WriteInt32(static_cast<int32_t>(imageInfo_.pixelFormat))) {
        IMAGE_LOGE("write image info pixel format:[%{public}d] to parcel failed.", imageInfo_.pixelFormat);
        return false;
    }
    if (!parcel.WriteInt32(static_cast<int32_t>(imageInfo_.colorSpace))) {
        IMAGE_LOGE("write image info color space:[%{public}d] to parcel failed.", imageInfo_.colorSpace);
        return false;
    }
    if (!parcel.WriteInt32(static_cast<int32_t>(imageInfo_.alphaType))) {
        IMAGE_LOGE("write image info alpha type:[%{public}d] to parcel failed.", imageInfo_.alphaType);
        return false;
    }
    if (!parcel.WriteInt32(imageInfo_.baseDensity)) {
        IMAGE_LOGE("write image info base density:[%{public}d] to parcel failed.", imageInfo_.baseDensity);
        return false;
    }
    if (!parcel.WriteString(imageInfo_.encodedFormat)) {
        IMAGE_LOGE("write image info encoded format:[%{public}s] to parcel failed.", imageInfo_.encodedFormat.c_str());
        return false;
    }
    return true;
}

bool PixelMapRecordParcel::WriteAstcRealSizeToParcel(Parcel &parcel)
{
    if (parcelInfo_.isAstc_) {
        if (!parcel.WriteInt32(static_cast<int32_t>(parcelInfo_.astcrealSize_.width))) {
            IMAGE_LOGE("write astcrealSize_.width:[%{public}d] to parcel failed.", parcelInfo_.astcrealSize_.width);
            return false;
        }
        if (!parcel.WriteInt32(static_cast<int32_t>(parcelInfo_.astcrealSize_.height))) {
            IMAGE_LOGE("write astcrealSize_.height:[%{public}d] to parcel failed.", parcelInfo_.astcrealSize_.height);
            return false;
        }
    }
    return true;
}

bool PixelMapRecordParcel::WritePropertiesToParcel(Parcel &parcel)
{
    if (!WriteImageInfo(parcel)) {
        IMAGE_LOGE("write image info to parcel failed.");
        return false;
    }

    if (!parcel.WriteBool(parcelInfo_.editable_)) {
        IMAGE_LOGE("write pixel map editable to parcel failed.");
        return false;
    }

    if (!parcel.WriteBool(parcelInfo_.isAstc_)) {
        IMAGE_LOGE("write pixel map isAstc_ to parcel failed.");
        return false;
    }

    if (!parcel.WriteBool(parcelInfo_.displayOnly_)) {
        IMAGE_LOGE("write pixel map displayOnly_ to parcel failed.");
        return false;
    }

    if (!parcel.WriteInt32(static_cast<int32_t>(parcelInfo_.allocatorType_))) {
        IMAGE_LOGE("write pixel map allocator type:[%{public}d] to parcel failed.", parcelInfo_.allocatorType_);
        return false;
    }

    if (!parcel.WriteInt32(static_cast<int32_t>(parcelInfo_.grColorSpace_ ?
        parcelInfo_.grColorSpace_->GetColorSpaceName() : ERR_MEDIA_INVALID_VALUE))) {
        IMAGE_LOGE("write pixel map grColorSpace to parcel failed.");
        return false;
    }

    if (!parcel.WriteUint32(parcelInfo_.versionId_)) {
        IMAGE_LOGE("write image info versionId_:[%{public}d] to parcel failed.", parcelInfo_.versionId_);
        return false;
    }

    if (!WriteAstcRealSizeToParcel(parcel)) {
        IMAGE_LOGE("write ASTC real size to parcel failed.");
        return false;
    }

    return true;
}

bool PixelMapRecordParcel::WriteFileDescriptor(Parcel &parcel, int fd)
{
#if !defined(IOS_PLATFORM) &&!defined(ANDROID_PLATFORM)
    if (fd < 0) {
        IMAGE_LOGE("WriteFileDescriptor get fd failed, fd:[%{public}d].", fd);
        return false;
    }
    int dupFd = dup(fd);
    if (dupFd < 0) {
        IMAGE_LOGE("WriteFileDescriptor dup fd failed, dupFd:[%{public}d].", dupFd);
        return false;
    }
    sptr<IPCFileDescriptor> descriptor = new IPCFileDescriptor(dupFd);
    return parcel.WriteObject<IPCFileDescriptor>(descriptor);
#else
    IMAGE_LOGE("[Pixemap] Not support Cross-Platform");
    return false;
#endif
}

bool PixelMapRecordParcel::WriteAshmemDataToParcel(Parcel &parcel, size_t size)
{
#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) &&!defined(ANDROID_PLATFORM)
    const uint8_t *data = parcelInfo_.data_;
    uint32_t id = parcelInfo_.uniqueId_;
    std::string name = "Parcel ImageData, uniqueId: " + std::to_string(getpid()) + '_' + std::to_string(id);
    int fd = AshmemCreate(name.c_str(), size);
    IMAGE_LOGI("AshmemCreate:[%{public}d].", fd);
    if (fd < 0) {
        return false;
    }

    int result = AshmemSetProt(fd, PROT_READ | PROT_WRITE);
    IMAGE_LOGD("AshmemSetProt:[%{public}d].", result);
    if (result < 0) {
        ::close(fd);
        return false;
    }
    void *ptr = ::mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (ptr == MAP_FAILED) {
        ::close(fd);
        IMAGE_LOGE("WriteAshmemData map failed, errno:%{public}d", errno);
        return false;
    }
    IMAGE_LOGD("mmap success");

    if (memcpy_s(ptr, size, data, size) != EOK) {
        ::munmap(ptr, size);
        ::close(fd);
        IMAGE_LOGE("WriteAshmemData memcpy_s error");
        return false;
    }

    if (!WriteFileDescriptor(parcel, fd)) {
        ::munmap(ptr, size);
        ::close(fd);
        IMAGE_LOGE("WriteAshmemData WriteFileDescriptor error");
        return false;
    }
    IMAGE_LOGD("WriteAshmemData WriteFileDescriptor success");
    ::munmap(ptr, size);
    ::close(fd);
    return true;
#endif
    IMAGE_LOGE("WriteAshmemData not support crossplatform");
    return false;
}

bool PixelMapRecordParcel::WriteImageData(Parcel &parcel, size_t size)
{
    const uint8_t *data = parcelInfo_.data_;
    if (parcelInfo_.isUnMap_ || data == nullptr || size > PixelMapRecordParcel::MAX_IMAGEDATA_SIZE) {
        IMAGE_LOGE("WriteImageData failed, data is null or size bigger than 128M, isUnMap %{public}d.", parcelInfo_.isUnMap_);
        return false;
    }

    if (!parcel.WriteInt32(size)) {
        IMAGE_LOGE("WriteImageData size failed.");
        return false;
    }
    if (size <= PixelMapRecordParcel::MIN_IMAGEDATA_SIZE) {
        return parcel.WriteUnpadBuffer(data, size);
    }
    return WriteAshmemDataToParcel(parcel, size);
}

bool PixelMapRecordParcel::WriteMemInfoToParcel(Parcel &parcel, const int32_t &bufferSize)
{
    if (parcelInfo_.allocatorType_ == AllocatorType::SHARE_MEM_ALLOC) {
        if (!parcel.WriteInt32(bufferSize)) {
            return false;
        }

        int *fd = static_cast<int *>(parcelInfo_.context_);
        if (fd == nullptr || *fd < 0) {
            IMAGE_LOGE("write pixel map failed, fd is [%{public}d] or fd < 0.", fd == nullptr ? 1 : 0);
            return false;
        }
        if (!CheckAshmemSize(*fd, bufferSize, parcelInfo_.isAstc_)) {
            IMAGE_LOGE("write pixel map check ashmem size failed, fd:[%{public}d].", *fd);
            return false;
        }
        if (!WriteFileDescriptor(parcel, *fd)) {
            IMAGE_LOGE("write pixel map fd:[%{public}d] to parcel failed.", *fd);
            ::close(*fd);
            return false;
        }
    } else if (parcelInfo_.allocatorType_ == AllocatorType::DMA_ALLOC) {
        if (!parcel.WriteInt32(bufferSize)) {
            return false;
        }
        SurfaceBuffer* sbBuffer = static_cast<SurfaceBuffer*>(parcelInfo_.context_);
        if (sbBuffer == nullptr) {
            IMAGE_LOGE("write pixel map failed, surface buffer is null");
            return false;
        }
        GSError ret = sbBuffer->WriteToMessageParcel(static_cast<MessageParcel&>(parcel));
        if (ret != GSError::GSERROR_OK) {
            IMAGE_LOGE("write pixel map to message parcel failed: %{public}s.", GSErrorStr(ret).c_str());
            return false;
        }
    } else {
        if (!WriteImageData(parcel, bufferSize)) {
            IMAGE_LOGE("write pixel map buffer to parcel failed.");
            return false;
        }
    }
    return true;
}

thread_local TransformData gTransformData = {1, 1, 0, 0, 0, 0, 0, 0, 0, false, false};
bool PixelMapRecordParcel::MarshallingPixelMapForRecord(Parcel& parcel, PixelMap& pixelmap)
{
    ImageInfo imageInfo;
    pixelmap.GetImageInfo(imageInfo);
    PixelMapRecordParcel instance;
    ParcelInfo parcelInfo_ = instance.GetParcelInfo();
    parcelInfo_.imageInfo_ = imageInfo;
    parcelInfo_.rowDataSize_ = pixelmap.rowDataSize_;
    parcelInfo_.isAstc_ = pixelmap.isAstc_;
    parcelInfo_.pixelsSize_ = pixelmap.pixelsSize_;
    parcelInfo_.context_ = pixelmap.context_;
    parcelInfo_.displayOnly_ = pixelmap.displayOnly_;
    parcelInfo_.rowStride_ = pixelmap.rowStride_;
    parcelInfo_.astcrealSize_ = pixelmap.astcrealSize_;
    parcelInfo_.isUnMap_ = pixelmap.isUnMap_;
    parcelInfo_.uniqueId_ = pixelmap.uniqueId_;
    gTransformData = pixelmap.transformData_;
    parcelInfo_.yuvDataInfo_ = pixelmap.yuvDataInfo_;
    parcelInfo_.isMemoryDirty_ = pixelmap.isMemoryDirty_;
    parcelInfo_.data_ = pixelmap.data_;
    parcelInfo_.allocatorType_ = pixelmap.allocatorType_;
    parcelInfo_.editable_ = pixelmap.editable_;
    parcelInfo_.pixelBytes_ = pixelmap.pixelBytes_;
#ifdef IMAGE_COLORSPACE_FLAG
    parcelInfo_.grColorSpace_ = pixelmap.grColorSpace_;
#endif
    parcelInfo_.versionId_ = pixelmap.versionId_;
    return instance.Marshalling(parcel, pixelmap);
}

bool PixelMapRecordParcel::IsYUV(const PixelFormat &format)
{
    return format == PixelFormat::NV12 || format == PixelFormat::NV21 ||
        format == PixelFormat::YCBCR_P010 || format == PixelFormat::YCRCB_P010;
}

bool PixelMapRecordParcel::WriteTransformDataToParcel(Parcel &parcel) const
{
    TransformData &transformData_ = gTransformData;
    if (parcelInfo_.isAstc_) {
        if (!parcel.WriteFloat(static_cast<float>(transformData_.scaleX))) {
            IMAGE_LOGE("write scaleX:[%{public}f] to parcel failed.", transformData_.scaleX);
            return false;
        }
        if (!parcel.WriteFloat(static_cast<float>(transformData_.scaleY))) {
            IMAGE_LOGE("write scaleY:[%{public}f] to parcel failed.", transformData_.scaleY);
            return false;
        }
        if (!parcel.WriteFloat(static_cast<float>(transformData_.rotateD))) {
            IMAGE_LOGE("write rotateD:[%{public}f] to parcel failed.", transformData_.rotateD);
            return false;
        }
        if (!parcel.WriteFloat(static_cast<float>(transformData_.cropLeft))) {
            IMAGE_LOGE("write cropLeft:[%{public}f] to parcel failed.", transformData_.cropLeft);
            return false;
        }
        if (!parcel.WriteFloat(static_cast<float>(transformData_.cropTop))) {
            IMAGE_LOGE("write cropTop:[%{public}f] to parcel failed.", transformData_.cropTop);
            return false;
        }
        if (!parcel.WriteFloat(static_cast<float>(transformData_.cropWidth))) {
            IMAGE_LOGE("write cropWidth:[%{public}f] to parcel failed.", transformData_.cropWidth);
            return false;
        }
        if (!parcel.WriteFloat(static_cast<float>(transformData_.cropHeight))) {
            IMAGE_LOGE("write cropHeight:[%{public}f] to parcel failed.", transformData_.cropHeight);
            return false;
        }
        if (!parcel.WriteFloat(static_cast<float>(transformData_.translateX))) {
            IMAGE_LOGE("write translateX:[%{public}f] to parcel failed.", transformData_.translateX);
            return false;
        }
        if (!parcel.WriteFloat(static_cast<float>(transformData_.translateY))) {
            IMAGE_LOGE("write translateY:[%{public}f] to parcel failed.", transformData_.translateY);
            return false;
        }
        if (!parcel.WriteBool(static_cast<bool>(transformData_.flipX))) {
            IMAGE_LOGE("write astc transformData_.flipX to parcel failed.");
            return false;
        }
        if (!parcel.WriteBool(static_cast<bool>(transformData_.flipY))) {
            IMAGE_LOGE("write astc transformData_.flipY to parcel failed.");
            return false;
        }
    }
    return true;
}

bool PixelMapRecordParcel::IsYuvFormat(PixelFormat format) const
{
    return format == PixelFormat::NV21 || format == PixelFormat::NV12 ||
        format == PixelFormat::YCBCR_P010 || format == PixelFormat::YCRCB_P010;
}

bool PixelMapRecordParcel::WriteYuvDataInfoToParcel(Parcel &parcel) const
{

    if (IsYuvFormat(parcelInfo_.imageInfo_.pixelFormat)) {
        if (!parcel.WriteInt32(static_cast<int32_t>(parcelInfo_.yuvDataInfo_.imageSize.width))) {
            return false;
        }
        if (!parcel.WriteInt32(static_cast<int32_t>(parcelInfo_.yuvDataInfo_.imageSize.height))) {
            return false;
        }
        if (!parcel.WriteInt32(static_cast<int32_t>(parcelInfo_.yuvDataInfo_.yWidth))) {
            return false;
        }
        if (!parcel.WriteInt32(static_cast<int32_t>(parcelInfo_.yuvDataInfo_.yHeight))) {
            return false;
        }
        if (!parcel.WriteInt32(static_cast<int32_t>(parcelInfo_.yuvDataInfo_.uvWidth))) {
            return false;
        }
        if (!parcel.WriteInt32(static_cast<int32_t>(parcelInfo_.yuvDataInfo_.uvHeight))) {
            return false;
        }
        if (!parcel.WriteInt32(static_cast<int32_t>(parcelInfo_.yuvDataInfo_.yStride))) {
            return false;
        }
        if (!parcel.WriteInt32(static_cast<int32_t>(parcelInfo_.yuvDataInfo_.uStride))) {
            return false;
        }
        if (!parcel.WriteInt32(static_cast<int32_t>(parcelInfo_.yuvDataInfo_.vStride))) {
            return false;
        }
        if (!parcel.WriteInt32(static_cast<int32_t>(parcelInfo_.yuvDataInfo_.uvStride))) {
            return false;
        }
        if (!parcel.WriteInt32(static_cast<int32_t>(parcelInfo_.yuvDataInfo_.yOffset))) {
            return false;
        }
        if (!parcel.WriteInt32(static_cast<int32_t>(parcelInfo_.yuvDataInfo_.uOffset))) {
            return false;
        }
        if (!parcel.WriteInt32(static_cast<int32_t>(parcelInfo_.yuvDataInfo_.vOffset))) {
            return false;
        }
        if (!parcel.WriteInt32(static_cast<int32_t>(parcelInfo_.yuvDataInfo_.uvOffset))) {
            return false;
        }
    }
    return true;
}

bool PixelMapRecordParcel::Marshalling(Parcel &parcel, PixelMap& pixelmap)
{
    int32_t PIXEL_MAP_INFO_MAX_LENGTH = 128;
    if (ImageUtils::CheckMulOverflow(parcelInfo_.imageInfo_.size.height, parcelInfo_.rowDataSize_)) {
        IMAGE_LOGE("pixelmap invalid params, height:%{public}d, rowDataSize:%{public}d.",
            parcelInfo_.imageInfo_.size.height, parcelInfo_.rowDataSize_);
        return false;
    }
    int32_t bufferSize = parcelInfo_.rowDataSize_ * parcelInfo_.imageInfo_.size.height;
    if (parcelInfo_.isAstc_ || IsYUV(parcelInfo_.imageInfo_.pixelFormat) || parcelInfo_.imageInfo_.pixelFormat == PixelFormat::RGBA_F16) {
        bufferSize = parcelInfo_.pixelsSize_;
    }
    size_t capacityLength =
        static_cast<size_t>(bufferSize) + static_cast<size_t>(PIXEL_MAP_INFO_MAX_LENGTH);
    if (static_cast<size_t>(bufferSize) <= MIN_IMAGEDATA_SIZE &&
        capacityLength > parcel.GetDataCapacity() &&
        !parcel.SetDataCapacity(bufferSize + PIXEL_MAP_INFO_MAX_LENGTH)) {
        IMAGE_LOGE("set parcel max capacity:[%{public}zu] failed.", capacityLength);
        return false;
    }
    if (!parcel.WriteInt32(static_cast<int32_t>(-PIXELMAP_VERSION_LATEST))) {
        IMAGE_LOGE("write image info pixelmap version to parcel failed.");
        return false;
    }
    if (!WritePropertiesToParcel(parcel)) {
        IMAGE_LOGE("write info to parcel failed.");
        return false;
    }
    if (!WriteMemInfoToParcel(parcel, bufferSize)) {
        IMAGE_LOGE("write memory info to parcel failed.");
        return false;
    }

    if (!WriteTransformDataToParcel(parcel)) {
        IMAGE_LOGE("write transformData to parcel failed.");
        return false;
    }

    if (!WriteYuvDataInfoToParcel(parcel)) {
        IMAGE_LOGE("write WriteYuvDataInfoToParcel to parcel failed.");
        return false;
    }

    if (parcelInfo_.isMemoryDirty_) {
        ImageUtils::FlushSurfaceBuffer(const_cast<PixelMap*>(&pixelmap));
        parcelInfo_.isMemoryDirty_ = false;
    }
    return true;
}

static bool ReadImageInfo(Parcel &parcel, ImageInfo &imgInfo)
{
    imgInfo.size.width = parcel.ReadInt32();
    IMAGE_LOGD("read pixel map width:[%{public}d] to parcel.", imgInfo.size.width);
    imgInfo.size.height = parcel.ReadInt32();
    IMAGE_LOGD("read pixel map height:[%{public}d] to parcel.", imgInfo.size.height);
    if (imgInfo.size.width <= 0 || imgInfo.size.height <= 0) {
        IMAGE_LOGE("invalid width:[%{public}d] or height:[%{public}d]", imgInfo.size.width, imgInfo.size.height);
        return false;
    }
    imgInfo.pixelFormat = static_cast<PixelFormat>(parcel.ReadInt32());
    IMAGE_LOGD("read pixel map pixelFormat:[%{public}d] to parcel.", imgInfo.pixelFormat);
    if (ImageUtils::GetPixelBytes(imgInfo.pixelFormat) == 0) {
        IMAGE_LOGE("invalid pixelFormat:[%{public}d]", imgInfo.pixelFormat);
        return false;
    }
    imgInfo.colorSpace = static_cast<ColorSpace>(parcel.ReadInt32());
    IMAGE_LOGD("read pixel map colorSpace:[%{public}d] to parcel.", imgInfo.colorSpace);
    imgInfo.alphaType = static_cast<AlphaType>(parcel.ReadInt32());
    IMAGE_LOGD("read pixel map alphaType:[%{public}d] to parcel.", imgInfo.alphaType);
    imgInfo.baseDensity = parcel.ReadInt32();
    imgInfo.encodedFormat = parcel.ReadString();
    return true;
}

static bool ReadTransformData(Parcel &parcel, PixelMap *pixelMap)
{
    if (pixelMap == nullptr) {
        IMAGE_LOGE("ReadTransformData invalid input parameter: pixelMap is null");
        return false;
    }

    if (pixelMap->IsAstc()) {
        TransformData transformData;
        transformData.scaleX = parcel.ReadFloat();
        transformData.scaleY = parcel.ReadFloat();
        transformData.rotateD = parcel.ReadFloat();
        transformData.cropLeft = parcel.ReadFloat();
        transformData.cropTop = parcel.ReadFloat();
        transformData.cropWidth = parcel.ReadFloat();
        transformData.cropHeight = parcel.ReadFloat();
        transformData.translateX = parcel.ReadFloat();
        transformData.translateY = parcel.ReadFloat();
        transformData.flipX = parcel.ReadBool();
        transformData.flipY = parcel.ReadBool();
        pixelMap->SetTransformData(transformData);
    }
    return true;
}

static bool ReadAstcRealSize(Parcel &parcel, PixelMap *pixelMap)
{
    if (pixelMap == nullptr) {
        IMAGE_LOGE("ReadAstcRealSize invalid input parameter: pixelMap is null");
        return false;
    }

    if (pixelMap->IsAstc()) {
        Size realSize;
        realSize.width = parcel.ReadInt32();
        realSize.height = parcel.ReadInt32();
        pixelMap->SetAstcRealSize(realSize);
    }
    return true;
}

bool PixelMapRecordParcel::ReadPropertiesFromParcel(Parcel& parcel, PixelMap*& pixelMap, ImageInfo& imgInfo, PixelMemInfo& memInfo)
{
    int32_t readVersion = PIXELMAP_VERSION_START;
    const size_t startReadPosition = parcel.GetReadPosition();

    int32_t firstInt32 = parcel.ReadInt32();
    if (firstInt32 <= -PIXELMAP_VERSION_START) {
        // version present in parcel (consider width < -2^16 is not possible), read it first
        readVersion = -firstInt32;
    } else {
        // old way: no version let's consider it's oldest
        parcel.RewindRead(startReadPosition);
    }
    if (!ReadImageInfo(parcel, imgInfo)) {
        IMAGE_LOGE("ReadPropertiesFromParcel: read image info failed");
        return false;
    }

    if (pixelMap != nullptr) {
        pixelMap->FreePixelMap();
        pixelMap = nullptr;
    }

    if (IsYUV(imgInfo.pixelFormat)) {
#ifdef EXT_PIXEL
        pixelMap = new(std::nothrow) PixelYuvExt();
#else
        pixelMap = new(std::nothrow) PixelYuv();
#endif
    } else if (ImageUtils::IsAstc(imgInfo.pixelFormat)) {
#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
        pixelMap = new(std::nothrow) PixelAstc();
#else
        pixelMap = new(std::nothrow) PixelMap();
#endif
    } else {
        pixelMap = new(std::nothrow) PixelMap();
    }

    if (pixelMap == nullptr) {
        IMAGE_LOGE("ReadPropertiesFromParcel: create PixelMap failed");
        return false;
    }

    pixelMap->SetReadVersion(readVersion);
    pixelMap->SetEditable(parcel.ReadBool());
    memInfo.isAstc = parcel.ReadBool();
    pixelMap->SetAstc(memInfo.isAstc);
    if (pixelMap->GetReadVersion() >= PIXELMAP_VERSION_DISPLAY_ONLY) {
        bool displayOnly = parcel.ReadBool();
        pixelMap->SetDisplayOnly(displayOnly);
    } else {
        pixelMap->SetDisplayOnly(false);
    }
    int32_t readAllocatorValue = parcel.ReadInt32();
    if (readAllocatorValue < static_cast<int32_t>(AllocatorType::DEFAULT) ||
        readAllocatorValue > static_cast<int32_t>(AllocatorType::DMA_ALLOC)) {
        IMAGE_LOGE("ReadPropertiesFromParcel invalid allocatorType");
        return false;
    }
    memInfo.allocatorType = static_cast<AllocatorType>(readAllocatorValue);
    if (memInfo.allocatorType == AllocatorType::DEFAULT || memInfo.allocatorType == AllocatorType::CUSTOM_ALLOC) {
        memInfo.allocatorType = AllocatorType::HEAP_ALLOC;
    }
    // PixelMap's allocator type should not be set before SetImageInfo()

    int32_t csm = parcel.ReadInt32();
    if (csm != ERR_MEDIA_INVALID_VALUE) {
        OHOS::ColorManager::ColorSpaceName colorSpaceName = static_cast<OHOS::ColorManager::ColorSpaceName>(csm);
        OHOS::ColorManager::ColorSpace grColorSpace = OHOS::ColorManager::ColorSpace(colorSpaceName);
        pixelMap->InnerSetColorSpace(grColorSpace);
    }

    pixelMap->SetVersionId(parcel.ReadUint32());

    if (!pixelMap->ReadAstcRealSize(parcel, pixelMap)) {
        IMAGE_LOGE("ReadPropertiesFromParcel: read ASTC real size failed");
        return false;
    }

    return true;
}

PixelMap *PixelMapRecordParcel::StartUnmarshalling(Parcel &parcel, ImageInfo &imgInfo,
    PixelMemInfo& pixelMemInfo, PIXEL_MAP_ERR &error)
{
    PixelMap* pixelMap = nullptr;
    if (!ReadPropertiesFromParcel(parcel, pixelMap, imgInfo, pixelMemInfo)) {
        if (pixelMap == nullptr) {
            PixelMap::ConstructPixelMapError(error, ERR_IMAGE_PIXELMAP_CREATE_FAILED, "PixelMap creation failed");
        } else {
            PixelMap::ConstructPixelMapError(error, ERR_IMAGE_PIXELMAP_CREATE_FAILED, "Read properties failed");
            delete pixelMap;
        }
        IMAGE_LOGE("Unmarshalling: read properties failed");
        return nullptr;
    }

    if (!pixelMap->ReadBufferSizeFromParcel(parcel, imgInfo, pixelMemInfo, error)) {
        IMAGE_LOGE("Unmarshalling: read buffer size failed");
        delete pixelMap;
        return nullptr;
    }
    pixelMemInfo.displayOnly = pixelMap->IsDisplayOnly();
    return pixelMap;
}

void PixelMapRecordParcel::ReleaseMemory(AllocatorType allocType, void *addr, void *context, uint32_t size)
{
#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) &&!defined(ANDROID_PLATFORM)
    if (allocType == AllocatorType::SHARE_MEM_ALLOC) {
        if (context != nullptr) {
            int *fd = static_cast<int *>(context);
            if (addr != nullptr) {
                ::munmap(addr, size);
            }
            if (fd != nullptr) {
                ::close(*fd);
            }
            context = nullptr;
            addr = nullptr;
        }
    } else if (allocType == AllocatorType::HEAP_ALLOC) {
        if (addr != nullptr) {
            free(addr);
            addr = nullptr;
        }
    } else if (allocType == AllocatorType::DMA_ALLOC) {
        if (context != nullptr) {
            ImageUtils::SurfaceBuffer_Unreference(static_cast<SurfaceBuffer*>(context));
        }
        context = nullptr;
        addr = nullptr;
    }
#else
    if (addr != nullptr) {
        free(addr);
        addr = nullptr;
    }
#endif
}

bool PixelMapRecordParcel::UpdatePixelMapMemInfo(PixelMap *pixelMap, ImageInfo &imgInfo, PixelMemInfo &pixelMemInfo)
{
    if (pixelMap == nullptr) {
        IMAGE_LOGE("UpdatePixelMapMemInfo invalid input parameter: pixelMap is null");
        return false;
    }

    uint32_t ret = pixelMap->SetImageInfo(imgInfo);
    if (ret != SUCCESS) {
        if (pixelMap->freePixelMapProc_ != nullptr) {
            pixelMap->freePixelMapProc_(pixelMemInfo.base, pixelMemInfo.context, pixelMemInfo.bufferSize);
        }
        ReleaseMemory(pixelMemInfo.allocatorType, pixelMemInfo.base, pixelMemInfo.context, pixelMemInfo.bufferSize);
        if (pixelMemInfo.allocatorType == AllocatorType::SHARE_MEM_ALLOC && pixelMemInfo.context != nullptr) {
            delete static_cast<int32_t *>(pixelMemInfo.context);
            pixelMemInfo.context = nullptr;
        }
        IMAGE_LOGE("create pixel map from parcel failed, set image info error.");
        return false;
    }
    pixelMap->SetPixelsAddr(pixelMemInfo.base, pixelMemInfo.context,
        pixelMemInfo.bufferSize, pixelMemInfo.allocatorType, nullptr);
    return true;
}

PixelMap *PixelMapRecordParcel::FinishUnmarshalling(PixelMap *pixelMap, Parcel &parcel,
    ImageInfo &imgInfo, PixelMemInfo &pixelMemInfo, PIXEL_MAP_ERR &error)
{
    if (!pixelMap) {
        return nullptr;
    }
    if (!UpdatePixelMapMemInfo(pixelMap, imgInfo, pixelMemInfo)) {
        IMAGE_LOGE("Unmarshalling: update pixelMap memInfo failed");
        delete pixelMap;
        return nullptr;
    }
    if (!pixelMap->ReadTransformData(parcel, pixelMap)) {
        IMAGE_LOGE("Unmarshalling: read transformData failed");
        delete pixelMap;
        return nullptr;
    }
    if (!pixelMap->ReadYuvDataInfoFromParcel(parcel, pixelMap)) {
        IMAGE_LOGE("Unmarshalling: ReadYuvDataInfoFromParcel failed");
        delete pixelMap;
        return nullptr;
    }
    return pixelMap;
}

bool PixelMapRecordParcel::ReadDmaMemInfoFromParcel(Parcel &parcel, PixelMemInfo &pixelMemInfo,
    std::function<int(Parcel &parcel, std::function<int(Parcel&)> readFdDefaultFunc)> readSafeFdFunc)
{
    sptr<SurfaceBuffer> surfaceBuffer = SurfaceBuffer::Create();
    if (surfaceBuffer == nullptr) {
        IMAGE_LOGE("SurfaceBuffer failed to be created");
        return false;
    }
    GSError ret = surfaceBuffer->ReadFromMessageParcel(static_cast<MessageParcel&>(parcel), readSafeFdFunc);
    if (ret != GSError::GSERROR_OK) {
        IMAGE_LOGE("SurfaceBuffer read from message parcel failed: %{public}s", GSErrorStr(ret).c_str());
        return false;
    }

    void* nativeBuffer = surfaceBuffer.GetRefPtr();
    ImageUtils::SurfaceBuffer_Reference(nativeBuffer);
    if (!pixelMemInfo.displayOnly) {
        pixelMemInfo.base = static_cast<uint8_t*>(surfaceBuffer->GetVirAddr());
    }
    pixelMemInfo.context = nativeBuffer;
    return true;
}

uint8_t *PixelMapRecordParcel::ReadHeapDataFromParcel(Parcel &parcel, int32_t bufferSize)
{
    uint8_t *base = nullptr;
    if (bufferSize <= 0) {
        IMAGE_LOGE("malloc parameter bufferSize:[%{public}d] error.", bufferSize);
        return nullptr;
    }

    const uint8_t *ptr = parcel.ReadUnpadBuffer(bufferSize);
    if (ptr == nullptr) {
        IMAGE_LOGE("read buffer from parcel failed, read buffer addr is null");
        return nullptr;
    }

    base = static_cast<uint8_t *>(malloc(bufferSize));
    if (base == nullptr) {
        IMAGE_LOGE("alloc output pixel memory size:[%{public}d] error.", bufferSize);
        return nullptr;
    }
    if (memcpy_s(base, bufferSize, ptr, bufferSize) != 0) {
        free(base);
        base = nullptr;
        IMAGE_LOGE("memcpy pixel data size:[%{public}d] error.", bufferSize);
        return nullptr;
    }
    return base;
}

int PixelMapRecordParcel::ReadFileDescriptor(Parcel &parcel)
{
#if !defined(IOS_PLATFORM) &&!defined(ANDROID_PLATFORM)
    sptr<IPCFileDescriptor> descriptor = parcel.ReadObject<IPCFileDescriptor>();
    if (descriptor == nullptr) {
        IMAGE_LOGE("ReadFileDescriptor get descriptor failed");
        return -1;
    }
    int fd = descriptor->GetFd();
    if (fd < 0) {
        IMAGE_LOGE("ReadFileDescriptor get fd failed, fd:[%{public}d].", fd);
        return -1;
    }
    int dupFd = dup(fd);
    if (dupFd < 0) {
        IMAGE_LOGE("ReadFileDescriptor dup fd failed, dupFd:[%{public}d].", dupFd);
        return -1;
    }
    return dupFd;
#else
    IMAGE_LOGE("[Pixemap] Not support Cross-Platform");
    return -1;
#endif
}

uint8_t *PixelMapRecordParcel::ReadAshmemDataFromParcel(Parcel &parcel, int32_t bufferSize,
    std::function<int(Parcel &parcel, std::function<int(Parcel&)> readFdDefaultFunc)> readSafeFdFunc)
{
    uint8_t *base = nullptr;
#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    auto readFdDefaultFunc = [](Parcel &parcel) -> int { return ReadFileDescriptor(parcel); };
    int fd = ((readSafeFdFunc != nullptr) ? readSafeFdFunc(parcel, readFdDefaultFunc) : readFdDefaultFunc(parcel));
    if (!CheckAshmemSize(fd, bufferSize)) {
        IMAGE_LOGE("ReadAshmemDataFromParcel check ashmem size failed, fd:[%{public}d].", fd);
        return nullptr;
    }
    if (bufferSize <= 0 || bufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("malloc parameter bufferSize:[%{public}d] error.", bufferSize);
        return nullptr;
    }

    void *ptr = ::mmap(nullptr, bufferSize, PROT_READ, MAP_SHARED, fd, 0);
    if (ptr == MAP_FAILED) {
        // do not close fd here. fd will be closed in FileDescriptor, ::close(fd)
        IMAGE_LOGE("ReadImageData map failed, errno:%{public}d", errno);
        return nullptr;
    }

    base = static_cast<uint8_t *>(malloc(bufferSize));
    if (base == nullptr) {
        ::munmap(ptr, bufferSize);
        IMAGE_LOGE("alloc output pixel memory size:[%{public}d] error.", bufferSize);
        return nullptr;
    }
    if (memcpy_s(base, bufferSize, ptr, bufferSize) != 0) {
        ::munmap(ptr, bufferSize);
        free(base);
        base = nullptr;
        IMAGE_LOGE("memcpy pixel data size:[%{public}d] error.", bufferSize);
        return nullptr;
    }

    ReleaseMemory(AllocatorType::SHARE_MEM_ALLOC, ptr, &fd, bufferSize);
#endif
    return base;
}

uint8_t *PixelMapRecordParcel::ReadImageData(Parcel &parcel, int32_t bufferSize,
    std::function<int(Parcel &parcel, std::function<int(Parcel&)> readFdDefaultFunc)> readSafeFdFunc)
{
#if !defined(_WIN32) && !defined(_APPLE) &&!defined(IOS_PLATFORM) &&!defined(ANDROID_PLATFORM)
    if (static_cast<unsigned int>(bufferSize) <= MIN_IMAGEDATA_SIZE) {
        return ReadHeapDataFromParcel(parcel, bufferSize);
    } else {
        return ReadAshmemDataFromParcel(parcel, bufferSize, readSafeFdFunc);
    }
#else
    return ReadHeapDataFromParcel(parcel, bufferSize);
#endif
}

bool PixelMapRecordParcel::ReadMemInfoFromParcel(Parcel &parcel, PixelMemInfo &pixelMemInfo, PIXEL_MAP_ERR &error,
    std::function<int(Parcel &parcel, std::function<int(Parcel&)> readFdDefaultFunc)> readSafeFdFunc)
{
#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    if (pixelMemInfo.allocatorType == AllocatorType::SHARE_MEM_ALLOC) {
        auto readFdDefaultFunc = [](Parcel &parcel) -> int { return ReadFileDescriptor(parcel); };
        int fd = ((readSafeFdFunc != nullptr) ? readSafeFdFunc(parcel, readFdDefaultFunc) : readFdDefaultFunc(parcel));
        if (!CheckAshmemSize(fd, pixelMemInfo.bufferSize, pixelMemInfo.isAstc)) {
            PixelMap::ConstructPixelMapError(error, ERR_IMAGE_GET_FD_BAD, "fd acquisition failed");
            ::close(fd);
            return false;
        }
        void* ptr = ::mmap(nullptr, pixelMemInfo.bufferSize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (ptr == MAP_FAILED) {
            ptr = ::mmap(nullptr, pixelMemInfo.bufferSize, PROT_READ, MAP_SHARED, fd, 0);
            if (ptr == MAP_FAILED) {
                ::close(fd);
                IMAGE_LOGE("shared memory map in memalloc failed, errno:%{public}d", errno);
                PixelMap::ConstructPixelMapError(error, ERR_IMAGE_GET_FD_BAD, "shared memory map in memalloc failed");
                return false;
            }
        }
        pixelMemInfo.context = new(std::nothrow) int32_t();
        if (pixelMemInfo.context == nullptr) {
            ::munmap(ptr, pixelMemInfo.bufferSize);
            ::close(fd);
            return false;
        }
        *static_cast<int32_t *>(pixelMemInfo.context) = fd;
        pixelMemInfo.base = static_cast<uint8_t *>(ptr);
    } else if (pixelMemInfo.allocatorType == AllocatorType::DMA_ALLOC) {
        if (!ReadDmaMemInfoFromParcel(parcel, pixelMemInfo, readSafeFdFunc)) {
            PixelMap::ConstructPixelMapError(error, ERR_IMAGE_GET_DATA_ABNORMAL, "ReadFromMessageParcel failed");
            return false;
        }
    } else { // Any other allocator types will malloc HEAP memory
        pixelMemInfo.base = ReadImageData(parcel, pixelMemInfo.bufferSize, readSafeFdFunc);
        if (pixelMemInfo.base == nullptr) {
            PixelMap::ConstructPixelMapError(error, ERR_IMAGE_GET_DATA_ABNORMAL, "ReadImageData failed");
            return false;
        }
    }
#else
    pixelMemInfo.base = ReadImageData(parcel, pixelMemInfo.bufferSize);
    if (pixelMemInfo.base == nullptr) {
        IMAGE_LOGE("get pixel memory size:[%{public}d] error.", pixelMemInfo.bufferSize);
        return false;
    }
#endif
    return true;
}

PixelMap *PixelMapRecordParcel::Unmarshalling(Parcel &parcel, PIXEL_MAP_ERR &error,
    std::function<int(Parcel &parcel, std::function<int(Parcel&)> readFdDefaultFunc)> readSafeFdFunc)
{
    ImageInfo imgInfo;
    PixelMemInfo pixelMemInfo;
    PixelMap* pixelMap = StartUnmarshalling(parcel, imgInfo, pixelMemInfo, error);
    if (!pixelMap) {
        IMAGE_LOGE("StartUnmarshalling: get pixelmap failed");
        return nullptr;
    }
    if (!ReadMemInfoFromParcel(parcel, pixelMemInfo, error, readSafeFdFunc)) {
        IMAGE_LOGE("Unmarshalling: read memInfo failed");
        delete pixelMap;
        return nullptr;
    }
    return FinishUnmarshalling(pixelMap, parcel, imgInfo, pixelMemInfo, error);
}

PixelMap *PixelMapRecordParcel::UnmarshallingPixelMapForRecord(Parcel &parcel,
    std::function<int(Parcel &parcel, std::function<int(Parcel&)> readFdDefaultFunc)> readSafeFdFunc)
{
    PIXEL_MAP_ERR error;
    PixelMap* dstPixelMap = Unmarshalling(parcel, error, readSafeFdFunc);
    if (dstPixelMap == nullptr || error.errorCode != SUCCESS) {
        IMAGE_LOGE("unmarshalling failed errorCode:%{public}d, errorInfo:%{public}s",
            error.errorCode, error.errorInfo.c_str());
    }
    return dstPixelMap;
}
}  // namespace Media
}  // namespace OHOS
