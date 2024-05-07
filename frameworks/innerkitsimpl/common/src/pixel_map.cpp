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

#include "pixel_map.h"
#include <charconv>
#include <iostream>
#include <unistd.h>

#include "image_log.h"
#include "image_system_properties.h"
#include "image_trace.h"
#include "image_type_converter.h"
#include "image_utils.h"
#include "memory_manager.h"
#include "include/core/SkBitmap.h"
#include "include/core/SkCanvas.h"
#include "include/core/SkImage.h"
#include "hitrace_meter.h"
#include "media_errors.h"
#include "pixel_convert_adapter.h"
#include "pixel_map_utils.h"
#include "post_proc.h"
#include "parcel.h"
#include "pubdef.h"
#include "exif_metadata.h"
#include "image_mdk_common.h"

#ifndef _WIN32
#include "securec.h"
#else
#include "memory.h"
#endif

#ifdef IMAGE_PURGEABLE_PIXELMAP
#include "purgeable_resource_manager.h"
#endif

#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
#include <sys/mman.h>
#include "ashmem.h"
#include "buffer_handle_parcel.h"
#include "ipc_file_descriptor.h"
#include "surface_buffer.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif
#include "libswscale/swscale.h"
#include "libavutil/opt.h"
#include "libavutil/imgutils.h"
#include "libavcodec/avcodec.h"
#ifdef __cplusplus
}
#endif

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "PixelMap"

namespace OHOS {
namespace Media {
using namespace std;
constexpr int32_t MAX_DIMENSION = INT32_MAX >> 2;
constexpr int8_t INVALID_ALPHA_INDEX = -1;
constexpr uint8_t ARGB_ALPHA_INDEX = 0;
constexpr uint8_t BGRA_ALPHA_INDEX = 3;
constexpr uint8_t ALPHA_BYTES = 1;
constexpr uint8_t BGRA_BYTES = 4;
constexpr uint8_t RGBA_F16_BYTES = 8;
constexpr uint8_t PER_PIXEL_LEN = 1;
constexpr uint32_t MAX_READ_COUNT = 2048;

constexpr uint8_t FILL_NUMBER = 3;
constexpr uint8_t ALIGN_NUMBER = 4;

static const uint8_t NUM_2 = 2;
static const uint8_t NUM_3 = 3;
static const uint8_t NUM_5 = 5;
static const uint8_t NUM_6 = 6;
static const uint8_t NUM_7 = 7;

constexpr int32_t ANTIALIASING_SIZE = 350;

std::atomic<uint32_t> PixelMap::currentId = 0;

PixelMap::~PixelMap()
{
    IMAGE_LOGD("PixelMap::~PixelMap_id:%{public}d width:%{public}d height:%{public}d",
        GetUniqueId(), imageInfo_.size.width, imageInfo_.size.height);
    FreePixelMap();
}

void PixelMap::FreePixelMap() __attribute__((no_sanitize("cfi")))
{
    // remove PixelMap from purgeable LRU if it is purgeable PixelMap
#ifdef IMAGE_PURGEABLE_PIXELMAP
    if (purgeableMemPtr_) {
        PurgeableMem::PurgeableResourceManager::GetInstance().RemoveResource(purgeableMemPtr_);
        purgeableMemPtr_.reset();
        purgeableMemPtr_ = nullptr;
    }
#endif

    if (data_ == nullptr) {
        return;
    }

    if (freePixelMapProc_ != nullptr) {
        freePixelMapProc_(data_, context_, pixelsSize_);
    }
    
    switch (allocatorType_) {
        case AllocatorType::HEAP_ALLOC: {
            free(data_);
            data_ = nullptr;
            break;
        }
        case AllocatorType::CUSTOM_ALLOC: {
            if (custFreePixelMap_ != nullptr) {
                custFreePixelMap_(data_, context_, pixelsSize_);
            }
            data_ = nullptr;
            context_ = nullptr;
            break;
        }
        case AllocatorType::SHARE_MEM_ALLOC: {
            ReleaseSharedMemory(data_, context_, pixelsSize_);
            data_ = nullptr;
            context_ = nullptr;
            break;
        }
        case AllocatorType::DMA_ALLOC: {
#if !defined(IOS_PLATFORM) &&!defined(ANDROID_PLATFORM)
            ImageUtils::SurfaceBuffer_Unreference(static_cast<SurfaceBuffer*>(context_));
            data_ = nullptr;
            context_ = nullptr;
#endif
            break;
        }
        default: {
            IMAGE_LOGE("unknown allocator type:[%{public}d].", allocatorType_);
            return;
        }
    }
}

void PixelMap::ReleaseSharedMemory(void *addr, void *context, uint32_t size)
{
#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) &&!defined(ANDROID_PLATFORM)
    int *fd = static_cast<int *>(context);
    if (addr != nullptr) {
        ::munmap(addr, size);
    }
    if (fd != nullptr) {
        ::close(*fd);
        delete fd;
    }
#endif
}

void PixelMap::SetFreePixelMapProc(CustomFreePixelMap func)
{
    freePixelMapProc_ = func;
}

void PixelMap::SetTransformered(bool isTransformered)
{
    std::unique_lock<std::mutex> lock(*transformMutex_);
    isTransformered_ = isTransformered;
}

void PixelMap::SetPixelsAddr(void *addr, void *context, uint32_t size, AllocatorType type, CustomFreePixelMap func)
{
    if (data_ != nullptr) {
        IMAGE_LOGD("SetPixelsAddr release the existed data first");
        FreePixelMap();
    }
    if (type == AllocatorType::SHARE_MEM_ALLOC && context == nullptr) {
        IMAGE_LOGE("SetPixelsAddr error type %{public}d ", type);
    }
    data_ = static_cast<uint8_t *>(addr);
    context_ = context;
    pixelsSize_ = size;
    allocatorType_ = type;
    custFreePixelMap_ = func;
    if (type == AllocatorType::DMA_ALLOC && rowDataSize_ != 0) {
        UpdateImageInfo();
    }
}

bool CheckPixelmap(std::unique_ptr<PixelMap> &pixelMap, ImageInfo &imageInfo)
{
    if (pixelMap->SetImageInfo(imageInfo) != SUCCESS) {
        IMAGE_LOGE("set image info fail");
        return false;
    }
    uint32_t bufferSize = pixelMap->GetByteCount();
    if (bufferSize == 0 || (pixelMap->GetAllocatorType() == AllocatorType::HEAP_ALLOC &&
        bufferSize > PIXEL_MAP_MAX_RAM_SIZE)) {
        IMAGE_LOGE("AllocSharedMemory parameter is zero");
        return false;
    }
    return true;
}

unique_ptr<PixelMap> PixelMap::Create(const uint32_t *colors, uint32_t colorLength, const InitializationOptions &opts)
{
    IMAGE_LOGD("PixelMap::Create1 enter");
    return Create(colors, colorLength, 0, opts.size.width, opts);
}

unique_ptr<PixelMap> PixelMap::Create(const uint32_t *colors, uint32_t colorLength, int32_t offset, int32_t width,
                                      const InitializationOptions &opts)
{
    IMAGE_LOGD("PixelMap::Create2 enter");
    return Create(colors, colorLength, 0, opts.size.width, opts, true);
}

unique_ptr<PixelMap> PixelMap::Create(const uint32_t *colors, uint32_t colorLength, int32_t offset, int32_t width,
                                      const InitializationOptions &opts, bool useCustomFormat)
{
    int errorCode;
    BUILD_PARAM info;
    info.offset_ = offset;
    info.width_ = width;
    info.flag_ = useCustomFormat;
    return Create(colors, colorLength, info, opts, errorCode);
}

static void MakePixelMap(void *dstPixels, int fd, std::unique_ptr<PixelMap> &dstPixelMap)
{
    void *fdBuffer = new int32_t();
    *static_cast<int32_t *>(fdBuffer) = fd;
    uint32_t bufferSize = dstPixelMap->GetByteCount();
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    dstPixelMap->SetPixelsAddr(dstPixels, fdBuffer, bufferSize, AllocatorType::SHARE_MEM_ALLOC, nullptr);
#else
    dstPixelMap->SetPixelsAddr(dstPixels, fdBuffer, bufferSize, AllocatorType::HEAP_ALLOC, nullptr);
#endif
}

static const map<PixelFormat, AVPixelFormat> FFMPEG_PIXEL_FORMAT_MAP = {
    { PixelFormat::UNKNOWN, AVPixelFormat::AV_PIX_FMT_NONE },
    { PixelFormat::ARGB_8888, AVPixelFormat::AV_PIX_FMT_ARGB },
    { PixelFormat::RGB_565, AVPixelFormat::AV_PIX_FMT_RGB565 },
    { PixelFormat::RGBA_8888, AVPixelFormat::AV_PIX_FMT_RGBA },
    { PixelFormat::BGRA_8888, AVPixelFormat::AV_PIX_FMT_BGRA },
    { PixelFormat::RGB_888, AVPixelFormat::AV_PIX_FMT_RGB24 },
    { PixelFormat::NV21, AVPixelFormat::AV_PIX_FMT_NV21 },
    { PixelFormat::NV12, AVPixelFormat::AV_PIX_FMT_NV12 },
    { PixelFormat::CMYK, AVPixelFormat::AV_PIX_FMT_GBRP },
};

static AVPixelFormat PixelFormatToAVPixelFormat(const PixelFormat &pixelFormat)
{
    auto formatSearch = FFMPEG_PIXEL_FORMAT_MAP.find(pixelFormat);
    return (formatSearch != FFMPEG_PIXEL_FORMAT_MAP.end()) ? formatSearch->second : AVPixelFormat::AV_PIX_FMT_NONE;
}

int32_t PixelMap::GetRGBxRowDataSize(const ImageInfo& info)
{
    if (info.pixelFormat <= PixelFormat::UNKNOWN || info.pixelFormat >= PixelFormat::NV21) {
        IMAGE_LOGE("[ImageUtil]unsupport pixel format");
        return -1;
    }
    int32_t pixelBytes = ImageUtils::GetPixelBytes(info.pixelFormat);
    if (pixelBytes < 0) {
        IMAGE_LOGE("[ImageUtil]get rgbx pixel bytes failed");
        return -1;
    }
    return pixelBytes * info.size.width;
}

int32_t PixelMap::GetRGBxByteCount(const ImageInfo& info)
{
    if (info.pixelFormat == PixelFormat::NV21 || info.pixelFormat == PixelFormat::NV12) {
        IMAGE_LOGE("[ImageUtil]unsupport pixel format");
        return -1;
    }
    int32_t rowDataSize = GetRGBxRowDataSize(info);
    if (rowDataSize < 0) {
        IMAGE_LOGE("[ImageUtil]get rgbx row data size failed");
        return -1;
    }
    return rowDataSize * info.size.height;
}

int32_t PixelMap::GetYUVByteCount(const ImageInfo& info)
{
    if (info.pixelFormat != PixelFormat::NV21 && info.pixelFormat != PixelFormat::NV12) {
        IMAGE_LOGE("[ImageUtil]unsupport pixel format");
        return -1;
    }
    if (info.size.width <= 0 || info.size.height <= 0) {
        IMAGE_LOGE("[ImageUtil]image size error");
        return -1;
    }
    AVPixelFormat avPixelFormat = PixelFormatToAVPixelFormat(info.pixelFormat);
    if (avPixelFormat == AVPixelFormat::AV_PIX_FMT_NONE) {
        IMAGE_LOGE("[ImageUtil]pixel format to ffmpeg pixel format failed");
        return -1;
    }
    return av_image_get_buffer_size(avPixelFormat, info.size.width, info.size.height, 1);
}

int32_t PixelMap::GetAllocatedByteCount(const ImageInfo& info)
{
    if (info.pixelFormat == PixelFormat::NV21 || info.pixelFormat == PixelFormat::NV12) {
        return GetYUVByteCount(info);
    } else {
        return GetRGBxByteCount(info);
    }
}

unique_ptr<PixelMap> PixelMap::Create(const uint32_t *colors, uint32_t colorLength, BUILD_PARAM &info,
    const InitializationOptions &opts, int &errorCode)
{
    int offset = info.offset_;
    if (!CheckParams(colors, colorLength, offset, info.width_, opts)) {
        return nullptr;
    }

    unique_ptr<PixelMap> dstPixelMap = make_unique<PixelMap>();
    if (dstPixelMap == nullptr) {
        IMAGE_LOGE("[image]Create: make pixelmap failed!");
        errorCode = IMAGE_RESULT_PLUGIN_REGISTER_FAILED;
        return nullptr;
    }
    PixelFormat format = PixelFormat::BGRA_8888;
    if (info.flag_) {
        format = ((opts.srcPixelFormat == PixelFormat::UNKNOWN) ? PixelFormat::BGRA_8888 : opts.srcPixelFormat);
    }
    ImageInfo srcImageInfo =
        MakeImageInfo(info.width_, opts.size.height, format, AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL);
    PixelFormat dstPixelFormat = (opts.pixelFormat == PixelFormat::UNKNOWN ? PixelFormat::RGBA_8888 : opts.pixelFormat);
    AlphaType dstAlphaType =
        (opts.alphaType == AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN) ? AlphaType::IMAGE_ALPHA_TYPE_PREMUL : opts.alphaType;
    dstAlphaType = ImageUtils::GetValidAlphaTypeByFormat(dstAlphaType, dstPixelFormat);
    ImageInfo dstImageInfo = MakeImageInfo(opts.size.width, opts.size.height, dstPixelFormat, dstAlphaType);
    if (!CheckPixelmap(dstPixelMap, dstImageInfo)) {
        IMAGE_LOGE("[PixelMap]Create: check pixelmap failed!");
        errorCode = IMAGE_RESULT_DATA_ABNORMAL;
        return nullptr;
    }

    int fd = 0;
    uint32_t bufferSize = dstPixelMap->GetByteCount();
    void *dstPixels = AllocSharedMemory(bufferSize, fd, dstPixelMap->GetUniqueId());
    if (dstPixels == nullptr) {
        IMAGE_LOGE("[PixelMap]Create: allocate memory size %{public}u fail", bufferSize);
        errorCode = IMAGE_RESULT_ERR_SHAMEM_NOT_EXIST;
        return nullptr;
    }
    int32_t dstLength = PixelConvert::PixelsConvert(reinterpret_cast<const void *>(colors + offset),
                                                    colorLength, srcImageInfo, dstPixels, dstImageInfo);
    if (dstLength < 0) {
        IMAGE_LOGE("[PixelMap]Create: pixel convert failed.");
        ReleaseBuffer(AllocatorType::SHARE_MEM_ALLOC, fd, bufferSize, &dstPixels);
        dstPixels = nullptr;
        errorCode = IMAGE_RESULT_THIRDPART_SKIA_ERROR;
        return nullptr;
    }

    dstPixelMap->SetEditable(opts.editable);
    MakePixelMap(dstPixels, fd, dstPixelMap);
    ImageUtils::DumpPixelMapIfDumpEnabled(dstPixelMap);
    return dstPixelMap;
}

void PixelMap::ReleaseBuffer(AllocatorType allocatorType, int fd, uint64_t dataSize, void **buffer)
{
#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    if (allocatorType == AllocatorType::SHARE_MEM_ALLOC) {
        if (*buffer != nullptr) {
            ::munmap(*buffer, dataSize);
            ::close(fd);
        }
        return;
    }
#endif

    if (allocatorType == AllocatorType::HEAP_ALLOC) {
        if (*buffer != nullptr) {
            free(*buffer);
            *buffer = nullptr;
        }
        return;
    }
}

void *PixelMap::AllocSharedMemory(const uint64_t bufferSize, int &fd, uint32_t uniqueId)
{
#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    std::string name = "PixelMap RawData, uniqueId: " + std::to_string(getpid()) + '_' + std::to_string(uniqueId);
    fd = AshmemCreate(name.c_str(), bufferSize);
    if (fd < 0) {
        IMAGE_LOGE("AllocSharedMemory fd error");
        return nullptr;
    }
    int result = AshmemSetProt(fd, PROT_READ | PROT_WRITE);
    if (result < 0) {
        IMAGE_LOGE("AshmemSetProt error");
        ::close(fd);
        return nullptr;
    }
    void* ptr = ::mmap(nullptr, bufferSize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (ptr == MAP_FAILED) {
        IMAGE_LOGE("mmap error, errno: %{public}s, fd %{public}d, bufferSize %{public}lld",
            strerror(errno), fd, (long long)bufferSize);
        ::close(fd);
        return nullptr;
    }
    return ptr;
#else
    return malloc(bufferSize);
#endif
}

bool PixelMap::CheckParams(const uint32_t *colors, uint32_t colorLength, int32_t offset, int32_t width,
    const InitializationOptions &opts)
{
    if (colors == nullptr || colorLength <= 0) {
        IMAGE_LOGE("colors invalid");
        return false;
    }
    int32_t dstWidth = opts.size.width;
    int32_t dstHeight = opts.size.height;
    if (dstWidth <= 0 || dstHeight <= 0) {
        IMAGE_LOGE("initial options size invalid");
        return false;
    }
    if (width < dstWidth) {
        IMAGE_LOGE("width: %{public}d must >= width: %{public}d", width, dstWidth);
        return false;
    }
    if (width > MAX_DIMENSION) {
        IMAGE_LOGE("stride %{public}d is out of range", width);
        return false;
    }
    int64_t lastLine = static_cast<int64_t>(dstHeight - 1) * width + offset;
    if (offset < 0 || static_cast<int64_t>(offset) + dstWidth > colorLength || lastLine + dstWidth > colorLength) {
        IMAGE_LOGE("colors length: %{public}u, offset: %{public}d, width: %{public}d  is invalid",
            colorLength, offset, width);
        return false;
    }
    return true;
}

unique_ptr<PixelMap> PixelMap::Create(const InitializationOptions &opts)
{
    IMAGE_LOGD("PixelMap::Create3 enter");
    unique_ptr<PixelMap> dstPixelMap = make_unique<PixelMap>();
    if (dstPixelMap == nullptr) {
        IMAGE_LOGE("create pixelMap pointer fail");
        return nullptr;
    }
    PixelFormat dstPixelFormat = (opts.pixelFormat == PixelFormat::UNKNOWN ? PixelFormat::RGBA_8888 : opts.pixelFormat);
    AlphaType dstAlphaType =
        (opts.alphaType == AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN) ? AlphaType::IMAGE_ALPHA_TYPE_PREMUL : opts.alphaType;
    dstAlphaType = ImageUtils::GetValidAlphaTypeByFormat(dstAlphaType, dstPixelFormat);
    ImageInfo dstImageInfo = MakeImageInfo(opts.size.width, opts.size.height, dstPixelFormat, dstAlphaType);
    if (dstPixelMap->SetImageInfo(dstImageInfo) != SUCCESS) {
        IMAGE_LOGE("set image info fail");
        return nullptr;
    }
    uint32_t bufferSize = dstPixelMap->GetByteCount();
    if (bufferSize == 0) {
        IMAGE_LOGE("calloc parameter bufferSize:[%{public}d] error.", bufferSize);
        return nullptr;
    }
    int fd = 0;
    void *dstPixels = AllocSharedMemory(bufferSize, fd, dstPixelMap->GetUniqueId());
    if (dstPixels == nullptr) {
        IMAGE_LOGE("allocate memory size %{public}u fail", bufferSize);
        return nullptr;
    }
    // update alpha opaque
    UpdatePixelsAlpha(dstImageInfo.alphaType, dstImageInfo.pixelFormat,
                      static_cast<uint8_t *>(dstPixels), *dstPixelMap.get());
    void *fdBuffer = new int32_t();
    *static_cast<int32_t *>(fdBuffer) = fd;
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    dstPixelMap->SetPixelsAddr(dstPixels, fdBuffer, bufferSize, AllocatorType::SHARE_MEM_ALLOC, nullptr);
#else
    dstPixelMap->SetPixelsAddr(dstPixels, fdBuffer, bufferSize, AllocatorType::HEAP_ALLOC, nullptr);
#endif
    dstPixelMap->SetEditable(opts.editable);
    return dstPixelMap;
}

void PixelMap::UpdatePixelsAlpha(const AlphaType &alphaType, const PixelFormat &pixelFormat, uint8_t *dstPixels,
                                 PixelMap dstPixelMap)
{
    if (alphaType == AlphaType::IMAGE_ALPHA_TYPE_OPAQUE) {
        int8_t alphaIndex = -1;
        if (pixelFormat == PixelFormat::RGBA_8888 || pixelFormat == PixelFormat::BGRA_8888) {
            alphaIndex = BGRA_ALPHA_INDEX;
        } else if (pixelFormat == PixelFormat::ARGB_8888) {
            alphaIndex = 0;
        }
        if (alphaIndex != -1) {
            uint8_t pixelBytes = dstPixelMap.GetPixelBytes();
            uint32_t bufferSize = dstPixelMap.GetByteCount();
            uint32_t i = alphaIndex;
            while (i < bufferSize) {
                dstPixels[i] = ALPHA_OPAQUE;
                i += pixelBytes;
            }
        }
    }
}

static int32_t BuildPixelMap(unique_ptr<PixelMap> &dstPixelMap, const CropValue &cropType,
    ImageInfo &dstImageInfo, const Rect &sRect, const ImageInfo &srcImageInfo)
{
    dstPixelMap = make_unique<PixelMap>();
    if (dstPixelMap == nullptr) {
        IMAGE_LOGE("create pixelmap pointer fail");
        return IMAGE_RESULT_PLUGIN_REGISTER_FAILED;
    }

    if (cropType == CropValue::VALID) {
        dstImageInfo.size.width = sRect.width;
        dstImageInfo.size.height = sRect.height;
    } else {
        dstImageInfo.size = srcImageInfo.size;
    }
    if (dstPixelMap->SetImageInfo(dstImageInfo) != SUCCESS) {
        return IMAGE_RESULT_DATA_ABNORMAL;
    }
    return SUCCESS;
}

unique_ptr<PixelMap> PixelMap::Create(PixelMap &source, const InitializationOptions &opts)
{
    IMAGE_LOGD("PixelMap::Create4 enter");
    Rect rect;
    return Create(source, rect, opts);
}

unique_ptr<PixelMap> PixelMap::Create(PixelMap &source, const Rect &srcRect, const InitializationOptions &opts)
{
    int error;
    return Create(source, srcRect, opts, error);
}

unique_ptr<PixelMap> PixelMap::Create(PixelMap &source, const Rect &srcRect, const InitializationOptions &opts,
    int32_t &errorCode)
{
    IMAGE_LOGD("PixelMap::Create5 enter");
    ImageInfo srcImageInfo;
    source.GetImageInfo(srcImageInfo);
    PostProc postProc;
    Rect sRect = srcRect;
    CropValue cropType = PostProc::ValidCropValue(sRect, srcImageInfo.size);
    if (cropType == CropValue::INVALID) {
        IMAGE_LOGE("src crop range is invalid");
        errorCode = IMAGE_RESULT_DECODE_FAILED;
        return nullptr;
    }
    ImageInfo dstImageInfo;
    InitDstImageInfo(opts, srcImageInfo, dstImageInfo);
    Size targetSize = dstImageInfo.size;
    // use source if match
    bool isHasConvert = postProc.HasPixelConvert(srcImageInfo, dstImageInfo);
    if (opts.useSourceIfMatch && !source.IsEditable() && !opts.editable && (cropType == CropValue::NOCROP) &&
        !isHasConvert && IsSameSize(srcImageInfo.size, dstImageInfo.size)) {
        source.useSourceAsResponse_ = true;
        return unique_ptr<PixelMap>(&source);
    }
    unique_ptr<PixelMap> dstPixelMap = nullptr;
    if ((errorCode = BuildPixelMap(dstPixelMap, cropType, dstImageInfo, sRect, srcImageInfo)) != SUCCESS) {
        return nullptr;
    }
    // dst pixelmap is source crop and convert pixelmap
    if ((cropType == CropValue::VALID) || isHasConvert) {
        if (!SourceCropAndConvert(source, srcImageInfo, dstImageInfo, sRect, *dstPixelMap.get())) {
            return nullptr;
        }
    } else {
        // only maybe size changed, copy source as scale operation
        if (!CopyPixelMap(source, *dstPixelMap.get(), errorCode)) {
            return nullptr;
        }
    }
    if (!ScalePixelMap(targetSize, dstImageInfo.size, opts.scaleMode, *dstPixelMap.get())) {
        return nullptr;
    }
    dstPixelMap->SetEditable(opts.editable);
    ImageUtils::DumpPixelMapIfDumpEnabled(dstPixelMap);
    return dstPixelMap;
}

bool PixelMap::SourceCropAndConvert(PixelMap &source, const ImageInfo &srcImageInfo, const ImageInfo &dstImageInfo,
    const Rect &srcRect, PixelMap &dstPixelMap)
{
    uint32_t bufferSize = dstPixelMap.GetByteCount();
    if (bufferSize == 0 || (source.GetAllocatorType() == AllocatorType::HEAP_ALLOC &&
        bufferSize > PIXEL_MAP_MAX_RAM_SIZE)) {
        IMAGE_LOGE("SourceCropAndConvert  parameter bufferSize:[%{public}d] error.", bufferSize);
        return false;
    }
    int fd = 0;
    void *dstPixels = nullptr;
    if (source.GetAllocatorType() == AllocatorType::SHARE_MEM_ALLOC) {
        dstPixels = AllocSharedMemory(bufferSize, fd, dstPixelMap.GetUniqueId());
    } else {
        dstPixels = malloc(bufferSize);
    }
    if (dstPixels == nullptr) {
        IMAGE_LOGE("source crop allocate memory fail allocatetype: %{public}d ", source.GetAllocatorType());
        return false;
    }
    if (memset_s(dstPixels, bufferSize, 0, bufferSize) != EOK) {
        IMAGE_LOGE("dstPixels memset_s failed.");
    }
    Position srcPosition { srcRect.left, srcRect.top };
    if (!PixelConvertAdapter::ReadPixelsConvert(source.GetPixels(), srcPosition, source.GetRowStride(), srcImageInfo,
        dstPixels, dstPixelMap.GetRowStride(), dstImageInfo)) {
        IMAGE_LOGE("pixel convert in adapter failed.");
        ReleaseBuffer(fd > 0 ? AllocatorType::SHARE_MEM_ALLOC : AllocatorType::HEAP_ALLOC, fd, bufferSize, &dstPixels);
        return false;
    }

    if (fd <= 0) {
        dstPixelMap.SetPixelsAddr(dstPixels, nullptr, bufferSize, AllocatorType::HEAP_ALLOC, nullptr);
        return true;
    }
    void *fdBuffer = new int32_t();
    *static_cast<int32_t *>(fdBuffer) = fd;
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    dstPixelMap.SetPixelsAddr(dstPixels, fdBuffer, bufferSize, AllocatorType::SHARE_MEM_ALLOC, nullptr);
#else
    dstPixelMap.SetPixelsAddr(dstPixels, fdBuffer, bufferSize, AllocatorType::HEAP_ALLOC, nullptr);
#endif
    return true;
}

bool PixelMap::ScalePixelMap(const Size &targetSize, const Size &dstSize, const ScaleMode &scaleMode,
                             PixelMap &dstPixelMap)
{
    if (dstSize.width == targetSize.width && dstSize.height == targetSize.height) {
        return true;
    }
    PostProc postProc;
    if (scaleMode == ScaleMode::FIT_TARGET_SIZE) {
        if (!postProc.ScalePixelMap(targetSize, dstPixelMap)) {
            IMAGE_LOGE("scale FIT_TARGET_SIZE fail");
            return false;
        }
    }
    if (scaleMode == ScaleMode::CENTER_CROP) {
        if (!postProc.CenterScale(targetSize, dstPixelMap)) {
            IMAGE_LOGE("scale CENTER_CROP fail");
            return false;
        }
    }
    return true;
}

void PixelMap::InitDstImageInfo(const InitializationOptions &opts, const ImageInfo &srcImageInfo,
                                ImageInfo &dstImageInfo)
{
    dstImageInfo.size = opts.size;
    if (dstImageInfo.size.width == 0 && dstImageInfo.size.height == 0) {
        dstImageInfo.size = srcImageInfo.size;
    }
    dstImageInfo.pixelFormat = opts.pixelFormat;
    if (dstImageInfo.pixelFormat == PixelFormat::UNKNOWN) {
        dstImageInfo.pixelFormat = srcImageInfo.pixelFormat;
    }
    dstImageInfo.alphaType = opts.alphaType;
    if (dstImageInfo.alphaType == AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN) {
        dstImageInfo.alphaType = srcImageInfo.alphaType;
    }
}

bool PixelMap::CopyPixMapToDst(PixelMap &source, void* &dstPixels, int &fd, uint32_t bufferSize)
{
    if (source.GetAllocatorType() == AllocatorType::DMA_ALLOC) {
        ImageInfo imageInfo;
        source.GetImageInfo(imageInfo);
        for (int i = 0; i < imageInfo.size.height; ++i) {
            errno_t ret = memcpy_s(dstPixels, source.GetRowBytes(),
                                   source.GetPixels() + i * source.GetRowStride(), source.GetRowBytes());
            if (ret != 0) {
                IMAGE_LOGE("copy source memory size %{public}u fail", bufferSize);
                ReleaseBuffer(AllocatorType::DMA_ALLOC, fd, bufferSize, &dstPixels);
                return false;
            }
            // Move the destination buffer pointer to the next row
            dstPixels = reinterpret_cast<uint8_t *>(dstPixels) + source.GetRowBytes();
        }
    } else {
        if (memcpy_s(dstPixels, bufferSize, source.GetPixels(), bufferSize) != 0) {
            IMAGE_LOGE("copy source memory size %{public}u fail", bufferSize);
            ReleaseBuffer(fd > 0 ? AllocatorType::SHARE_MEM_ALLOC : AllocatorType::HEAP_ALLOC,
                          fd, bufferSize, &dstPixels);
            return false;
        }
    }
    return true;
}

bool PixelMap::CopyPixelMap(PixelMap &source, PixelMap &dstPixelMap)
{
    int32_t error;
    return CopyPixelMap(source, dstPixelMap, error);
}
bool PixelMap::CopyPixelMap(PixelMap &source, PixelMap &dstPixelMap, int32_t &error)
{
    uint32_t bufferSize = source.GetByteCount();
    if (source.GetPixels() == nullptr) {
        IMAGE_LOGE("source pixelMap data invalid");
        error = IMAGE_RESULT_GET_DATA_ABNORMAL;
        return false;
    }
    if (bufferSize == 0 || (source.GetAllocatorType() == AllocatorType::HEAP_ALLOC &&
        bufferSize > PIXEL_MAP_MAX_RAM_SIZE)) {
        IMAGE_LOGE("AllocSharedMemory parameter bufferSize:[%{public}d] error.", bufferSize);
        error = IMAGE_RESULT_DATA_ABNORMAL;
        return false;
    }
    int fd = -1;
    void *dstPixels = nullptr;
    if (source.GetAllocatorType() == AllocatorType::SHARE_MEM_ALLOC) {
        dstPixels = AllocSharedMemory(bufferSize, fd, dstPixelMap.GetUniqueId());
    } else {
        dstPixels = malloc(bufferSize);
    }
    if (dstPixels == nullptr) {
        IMAGE_LOGE("source crop allocate memory fail allocatetype: %{public}d ", source.GetAllocatorType());
        error = IMAGE_RESULT_MALLOC_ABNORMAL;
        return false;
    }
    void *tmpDstPixels = dstPixels;
    if (!CopyPixMapToDst(source, tmpDstPixels, fd, bufferSize)) {
        error = IMAGE_RESULT_ERR_SHAMEM_DATA_ABNORMAL;
        return false;
    }
    if (fd < 0) {
        dstPixelMap.SetPixelsAddr(dstPixels, nullptr, bufferSize, AllocatorType::HEAP_ALLOC, nullptr);
        return true;
    }
    void *fdBuffer = new int32_t();
    *static_cast<int32_t *>(fdBuffer) = fd;
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    dstPixelMap.SetPixelsAddr(dstPixels, fdBuffer, bufferSize, AllocatorType::SHARE_MEM_ALLOC, nullptr);
#else
    dstPixelMap.SetPixelsAddr(dstPixels, fdBuffer, bufferSize, AllocatorType::HEAP_ALLOC, nullptr);
#endif
    return true;
}

bool PixelMap::IsSameSize(const Size &src, const Size &dst)
{
    return (src.width == dst.width) && (src.height == dst.height);
}

bool PixelMap::GetPixelFormatDetail(const PixelFormat format)
{
    switch (format) {
        case PixelFormat::RGBA_8888: {
            pixelBytes_ = ARGB_8888_BYTES;
            colorProc_ = RGBA8888ToARGB;
            break;
        }
        case PixelFormat::RGBA_1010102: {
            pixelBytes_ = ARGB_8888_BYTES;
            break;
        }
        case PixelFormat::BGRA_8888: {
            pixelBytes_ = ARGB_8888_BYTES;
            colorProc_ = BGRA8888ToARGB;
            break;
        }
        case PixelFormat::ARGB_8888: {
            pixelBytes_ = ARGB_8888_BYTES;
            colorProc_ = ARGB8888ToARGB;
            break;
        }
        case PixelFormat::ALPHA_8: {
            pixelBytes_ = ALPHA_8_BYTES;
            colorProc_ = ALPHA8ToARGB;
            break;
        }
        case PixelFormat::RGB_565: {
            pixelBytes_ = RGB_565_BYTES;
            colorProc_ = RGB565ToARGB;
            break;
        }
        case PixelFormat::RGB_888: {
            pixelBytes_ = RGB_888_BYTES;
            colorProc_ = RGB888ToARGB;
            break;
        }
        case PixelFormat::NV12:
        case PixelFormat::NV21: {
            pixelBytes_ = YUV420_BYTES;
            break;
        }
        case PixelFormat::CMYK:
            pixelBytes_ = ARGB_8888_BYTES;
            break;
        case PixelFormat::RGBA_F16:
            pixelBytes_ = BGRA_F16_BYTES;
            break;
        case PixelFormat::ASTC_4x4:
        case PixelFormat::ASTC_6x6:
        case PixelFormat::ASTC_8x8:
            pixelBytes_ = ASTC_4x4_BYTES;
            break;
        default: {
            IMAGE_LOGE("pixel format:[%{public}d] not supported.", format);
            return false;
        }
    }
    return true;
}

void PixelMap::SetRowStride(uint32_t stride)
{
    rowStride_ = stride;
}

void PixelMap::UpdateImageInfo()
{
    SetImageInfo(imageInfo_, true);
}

uint32_t PixelMap::SetImageInfo(ImageInfo &info)
{
    return SetImageInfo(info, false);
}

uint32_t PixelMap::SetRowDataSizeForImageInfo(ImageInfo info)
{
    if (info.pixelFormat == PixelFormat::ALPHA_8) {
        rowDataSize_ = pixelBytes_ * ((info.size.width + FILL_NUMBER) / ALIGN_NUMBER * ALIGN_NUMBER);
        SetRowStride(rowDataSize_);
        IMAGE_LOGI("ALPHA_8 rowDataSize_ %{public}d.", rowDataSize_);
    } else if (info.pixelFormat == PixelFormat::ASTC_4x4) {
        rowDataSize_ = pixelBytes_ * (((info.size.width + NUM_3) >> NUM_2) << NUM_2);
    } else if (info.pixelFormat == PixelFormat::ASTC_6x6) {
        rowDataSize_ = pixelBytes_ * (((info.size.width + NUM_5) / NUM_6) * NUM_6);
    } else if (info.pixelFormat == PixelFormat::ASTC_8x8) {
        rowDataSize_ = pixelBytes_ * (((info.size.width + NUM_7) >> NUM_3) << NUM_3);
    } else {
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
        if (allocatorType_ == AllocatorType::DMA_ALLOC) {
            if (context_ == nullptr) {
                IMAGE_LOGE("set imageInfo failed, context_ is null");
                return ERR_IMAGE_DATA_ABNORMAL;
            }
            SurfaceBuffer* sbBuffer = reinterpret_cast<SurfaceBuffer*>(context_);
            SetRowStride(sbBuffer->GetStride());
        } else {
            SetRowStride(pixelBytes_ * info.size.width);
        }
#else
        SetRowStride(pixelBytes_ * info.size.width);
#endif
        rowDataSize_ = pixelBytes_ * info.size.width;
    }
    return SUCCESS;
}

uint32_t PixelMap::SetImageInfo(ImageInfo &info, bool isReused)
{
    if (info.size.width <= 0 || info.size.height <= 0) {
        IMAGE_LOGE("pixel map image info invalid.");
        return ERR_IMAGE_DATA_ABNORMAL;
    }
    if (!GetPixelFormatDetail(info.pixelFormat)) {
        return ERR_IMAGE_DATA_UNSUPPORT;
    }

    if (pixelBytes_ <= 0) {
        ResetPixelMap();
        IMAGE_LOGE("pixel map bytes is invalid.");
        return ERR_IMAGE_DATA_ABNORMAL;
    }

    if (allocatorType_ == AllocatorType::HEAP_ALLOC &&
        ((static_cast<uint64_t>(pixelBytes_) * info.size.width * info.size.height) > PIXEL_MAP_MAX_RAM_SIZE)) {
        ResetPixelMap();
        IMAGE_LOGE("image size is out of range.");
        return ERR_IMAGE_TOO_LARGE;
    }

    if (SetRowDataSizeForImageInfo(info) != SUCCESS) {
        IMAGE_LOGE("pixel map set rowDataSize error.");
        return ERR_IMAGE_DATA_ABNORMAL;
    }

    if (rowDataSize_ != 0 && allocatorType_ == AllocatorType::HEAP_ALLOC &&
        info.size.height > (PIXEL_MAP_MAX_RAM_SIZE / rowDataSize_)) {
        ResetPixelMap();
        IMAGE_LOGE("pixel map byte count out of range.");
        return ERR_IMAGE_TOO_LARGE;
    }
    if (!isReused) {
        FreePixelMap();
    }
    imageInfo_ = info;
    return SUCCESS;
}

const uint8_t *PixelMap::GetPixel8(int32_t x, int32_t y)
{
    if (!CheckValidParam(x, y) || (pixelBytes_ != ALPHA_8_BYTES)) {
        IMAGE_LOGE("get addr8 pixel position:(%{public}d, %{public}d) pixel bytes:%{public}d invalid.", x, y,
            pixelBytes_);
        return nullptr;
    }
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    return (data_ + y * rowStride_ + x);
#else
    return (data_ + y * rowDataSize_  + x);
#endif
}

const uint16_t *PixelMap::GetPixel16(int32_t x, int32_t y)
{
    if (!CheckValidParam(x, y) || (pixelBytes_ != RGB_565_BYTES)) {
        IMAGE_LOGE("get addr16 pixel position:(%{public}d, %{public}d) pixel bytes:%{public}d invalid.", x, y,
            pixelBytes_);
        return nullptr;
    }
    // convert uint8_t* to uint16_t*
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    return reinterpret_cast<uint16_t *>(data_ + y * rowStride_ + (static_cast<uint32_t>(x) << RGB_565_SHIFT));
#else
    return reinterpret_cast<uint16_t *>(data_ + y * rowDataSize_ + (static_cast<uint32_t>(x) << RGB_565_SHIFT));
#endif
}

const uint32_t *PixelMap::GetPixel32(int32_t x, int32_t y)
{
    if (!CheckValidParam(x, y) || (pixelBytes_ != ARGB_8888_BYTES)) {
        IMAGE_LOGE("get addr32 pixel position:(%{public}d, %{public}d) pixel bytes:%{public}d invalid.", x, y,
            pixelBytes_);
        return nullptr;
    }
    // convert uint8_t* to uint32_t*
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    return reinterpret_cast<uint32_t *>(data_ + y * rowStride_ + (static_cast<uint32_t>(x) << ARGB_8888_SHIFT));
#else
    return reinterpret_cast<uint32_t *>(data_ + y * rowDataSize_ + (static_cast<uint32_t>(x) << ARGB_8888_SHIFT));
#endif
}

const uint8_t *PixelMap::GetPixel(int32_t x, int32_t y)
{
    if (!CheckValidParam(x, y)) {
        IMAGE_LOGE("input pixel position:(%{public}d, %{public}d) invalid.", x, y);
        return nullptr;
    }
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    return (data_ + y * rowStride_ + (static_cast<uint32_t>(x) * pixelBytes_));
#else
    return (data_ + y * rowDataSize_ + (static_cast<uint32_t>(x) * pixelBytes_));
#endif
}

bool PixelMap::GetARGB32Color(int32_t x, int32_t y, uint32_t &color)
{
    if (colorProc_ == nullptr) {
        IMAGE_LOGE("pixel format not supported.");
        return false;
    }
    const uint8_t *src = GetPixel(x, y);
    if (src == nullptr) {
        IMAGE_LOGE("get pixel color error.");
        return false;
    }
    // use founction point for frequently called interface
    return colorProc_(src, ONE_PIXEL_SIZE * pixelBytes_, &color, ONE_PIXEL_SIZE);
}

uint32_t PixelMap::ModifyImageProperty(const std::string &key, const std::string &value)
{
    if (exifMetadata_ == nullptr) {
        return ERR_IMAGE_DECODE_EXIF_UNSUPPORT;
    }

    if (!exifMetadata_->SetValue(key, value)) {
        return ERR_MEDIA_VALUE_INVALID;
    }

    return SUCCESS;
}

uint32_t PixelMap::GetImagePropertyInt(const std::string &key, int32_t &value)
{
    if (exifMetadata_ == nullptr) {
        return ERR_MEDIA_NO_EXIF_DATA;
    }

    std::string strValue;
    int  ret = exifMetadata_->GetValue(key, strValue);
    if (ret != SUCCESS) {
        return ret;
    }

    std::from_chars_result res = std::from_chars(strValue.data(), strValue.data() + strValue.size(), value);
    if (res.ec != std::errc()) {
        return ERR_IMAGE_SOURCE_DATA;
    }

    return SUCCESS;
}

uint32_t PixelMap::GetImagePropertyString(const std::string &key, std::string &value)
{
    if (exifMetadata_ == nullptr) {
        return ERR_MEDIA_NO_EXIF_DATA;
    }

    return exifMetadata_->GetValue(key, value);
}

bool PixelMap::ALPHA8ToARGB(const uint8_t *in, uint32_t inCount, uint32_t *out, uint32_t outCount)
{
    if (inCount != outCount) {
        IMAGE_LOGE("input count:%{public}u is not match to output count:%{public}u.", inCount, outCount);
        return false;
    }
    const uint8_t *src = in;
    for (uint32_t i = 0; i < outCount; i++) {
        *out++ = GetColorARGB(*src++, BYTE_ZERO, BYTE_ZERO, BYTE_ZERO);
    }
    return true;
}

bool PixelMap::RGB565ToARGB(const uint8_t *in, uint32_t inCount, uint32_t *out, uint32_t outCount)
{
    if (((inCount / RGB_565_BYTES) != outCount) && ((inCount % RGB_565_BYTES) != 0)) {
        IMAGE_LOGE("input count:%{public}u is not match to output count:%{public}u.", inCount, outCount);
        return false;
    }
    const uint16_t *src = reinterpret_cast<const uint16_t *>(in);
    for (uint32_t i = 0; i < outCount; i++) {
        uint16_t color = *src++;
        *out++ = GetColorARGB(BYTE_FULL, RGB565ToR32(color), RGB565ToG32(color), RGB565ToB32(color));
    }
    return true;
}

bool PixelMap::ARGB8888ToARGB(const uint8_t *in, uint32_t inCount, uint32_t *out, uint32_t outCount)
{
    if (((inCount / ARGB_8888_BYTES) != outCount) && ((inCount % ARGB_8888_BYTES) != 0)) {
        IMAGE_LOGE("input count:%{public}u is not match to output count:%{public}u.", inCount, outCount);
        return false;
    }
    const uint32_t *src = reinterpret_cast<const uint32_t *>(in);
    for (uint32_t i = 0; i < outCount; i++) {
        uint32_t color = *src++;
        *out++ = GetColorARGB(GetColorComp(color, ARGB32_A_SHIFT), GetColorComp(color, ARGB32_R_SHIFT),
                              GetColorComp(color, ARGB32_G_SHIFT), GetColorComp(color, ARGB32_B_SHIFT));
    }
    return true;
}

bool PixelMap::RGBA8888ToARGB(const uint8_t *in, uint32_t inCount, uint32_t *out, uint32_t outCount)
{
    if (((inCount / ARGB_8888_BYTES) != outCount) && ((inCount % ARGB_8888_BYTES) != 0)) {
        IMAGE_LOGE("input count:%{public}u is not match to output count:%{public}u.", inCount, outCount);
        return false;
    }
    const uint32_t *src = reinterpret_cast<const uint32_t *>(in);
    for (uint32_t i = 0; i < outCount; i++) {
        uint32_t color = *src++;
        *out++ = GetColorARGB(GetColorComp(color, RGBA32_A_SHIFT), GetColorComp(color, RGBA32_R_SHIFT),
                              GetColorComp(color, RGBA32_G_SHIFT), GetColorComp(color, RGBA32_B_SHIFT));
    }
    return true;
}

bool PixelMap::BGRA8888ToARGB(const uint8_t *in, uint32_t inCount, uint32_t *out, uint32_t outCount)
{
    if (((inCount / ARGB_8888_BYTES) != outCount) && ((inCount % ARGB_8888_BYTES) != 0)) {
        IMAGE_LOGE("input count:%{public}u is not match to output count:%{public}u.", inCount, outCount);
        return false;
    }
    const uint32_t *src = reinterpret_cast<const uint32_t *>(in);
    for (uint32_t i = 0; i < outCount; i++) {
        uint32_t color = *src++;
        *out++ = GetColorARGB(GetColorComp(color, BGRA32_A_SHIFT), GetColorComp(color, BGRA32_R_SHIFT),
                              GetColorComp(color, BGRA32_G_SHIFT), GetColorComp(color, BGRA32_B_SHIFT));
    }
    return true;
}

bool PixelMap::RGB888ToARGB(const uint8_t *in, uint32_t inCount, uint32_t *out, uint32_t outCount)
{
    if (((inCount / RGB_888_BYTES) != outCount) && ((inCount % RGB_888_BYTES) != 0)) {
        IMAGE_LOGE("input count:%{public}u is not match to output count:%{public}u.", inCount, outCount);
        return false;
    }
    const uint8_t *src = in;
    for (uint32_t i = 0; i < outCount; i++) {
        uint8_t colorR = *src++;
        uint8_t colorG = *src++;
        uint8_t colorB = *src++;
        *out++ = GetColorARGB(BYTE_FULL, colorR, colorG, colorB);
    }
    return true;
}

int32_t PixelMap::GetPixelBytes()
{
    return pixelBytes_;
}

int32_t PixelMap::GetRowBytes()
{
    return rowDataSize_;
}

int32_t PixelMap::GetByteCount()
{
    IMAGE_LOGD("GetByteCount");
    if (imageInfo_.pixelFormat == PixelFormat::NV12 || imageInfo_.pixelFormat == PixelFormat::NV21) {
        return GetYUVByteCount(imageInfo_);
    } else {
        return rowDataSize_ * imageInfo_.size.height;
    }
}

int32_t PixelMap::GetWidth()
{
    return imageInfo_.size.width;
}

int32_t PixelMap::GetHeight()
{
    return imageInfo_.size.height;
}

void PixelMap::GetTransformData(TransformData &transformData)
{
    transformData = transformData_;
}

void PixelMap::SetTransformData(TransformData transformData)
{
    transformData_ = transformData;
}

int32_t PixelMap::GetBaseDensity()
{
    return imageInfo_.baseDensity;
}

void PixelMap::GetImageInfo(ImageInfo &imageInfo)
{
    imageInfo = imageInfo_;
}

PixelFormat PixelMap::GetPixelFormat()
{
    return imageInfo_.pixelFormat;
}

ColorSpace PixelMap::GetColorSpace()
{
    return imageInfo_.colorSpace;
}

AlphaType PixelMap::GetAlphaType()
{
    return imageInfo_.alphaType;
}

const uint8_t *PixelMap::GetPixels()
{
    return data_;
}

bool PixelMap::IsHdr()
{
    if (imageInfo_.pixelFormat != PixelFormat::RGBA_1010102) {
        return false;
    }
#ifdef IMAGE_COLORSPACE_FLAG
    OHOS::ColorManager::ColorSpace colorSpace = InnerGetGrColorSpace();
    if (colorSpace.GetColorSpaceName() != ColorManager::BT2020_HLG &&
        colorSpace.GetColorSpaceName() != ColorManager::BT2020_PQ &&
        colorSpace.GetColorSpaceName() != ColorManager::BT2020_HLG_LIMIT &&
        colorSpace.GetColorSpaceName() != ColorManager::BT2020_PQ_LIMIT) {
        return false;
    }
#endif
    return true;
}

uint8_t PixelMap::GetARGB32ColorA(uint32_t color)
{
    return (color >> ARGB_A_SHIFT) & ARGB_MASK;
}

uint8_t PixelMap::GetARGB32ColorR(uint32_t color)
{
    return (color >> ARGB_R_SHIFT) & ARGB_MASK;
}

uint8_t PixelMap::GetARGB32ColorG(uint32_t color)
{
    return (color >> ARGB_G_SHIFT) & ARGB_MASK;
}

uint8_t PixelMap::GetARGB32ColorB(uint32_t color)
{
    return (color >> ARGB_B_SHIFT) & ARGB_MASK;
}

bool PixelMap::IsSameImage(const PixelMap &other)
{
    if (data_ == nullptr || other.data_ == nullptr) {
        IMAGE_LOGE("IsSameImage data_ is nullptr.");
        return false;
    }
    if (imageInfo_.size.width != other.imageInfo_.size.width ||
        imageInfo_.size.height != other.imageInfo_.size.height ||
        imageInfo_.pixelFormat != other.imageInfo_.pixelFormat || imageInfo_.alphaType != other.imageInfo_.alphaType) {
        IMAGE_LOGI("IsSameImage imageInfo is not same");
        return false;
    }
    uint64_t size = static_cast<uint64_t>(rowDataSize_) * imageInfo_.size.height;
    if (memcmp(data_, other.data_, size) != 0) {
        IMAGE_LOGI("IsSameImage memcmp is not same");
        return false;
    }
    return true;
}

uint32_t PixelMap::ReadPixels(const uint64_t &bufferSize, uint8_t *dst)
{
    ImageTrace imageTrace("ReadPixels by bufferSize");
    if (dst == nullptr) {
        IMAGE_LOGE("read pixels by buffer input dst address is null.");
        return ERR_IMAGE_READ_PIXELMAP_FAILED;
    }
    if (data_ == nullptr) {
        IMAGE_LOGE("read pixels by buffer current PixelMap data is null.");
        return ERR_IMAGE_READ_PIXELMAP_FAILED;
    }
    if (bufferSize < static_cast<uint64_t>(pixelsSize_)) {
        IMAGE_LOGE("read pixels by buffer input dst buffer(%{public}llu) < current pixelmap size(%{public}u).",
            static_cast<unsigned long long>(bufferSize), pixelsSize_);
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    if (imageInfo_.pixelFormat == PixelFormat::NV12 || imageInfo_.pixelFormat == PixelFormat::NV21) {
        uint64_t tmpSize = 0;
        int readSize = MAX_READ_COUNT;
        while (tmpSize < bufferSize) {
            if (tmpSize + MAX_READ_COUNT > bufferSize) {
                readSize = (int)(bufferSize - tmpSize);
            }
            errno_t ret = memcpy_s(dst + tmpSize, readSize, data_ + tmpSize, readSize);
            if (ret != 0) {
                IMAGE_LOGE("read pixels by buffer memcpy the pixelmap data to dst fail, error:%{public}d", ret);
                return ERR_IMAGE_READ_PIXELMAP_FAILED;
            }
            tmpSize += static_cast<uint64_t>(readSize);
        }
    } else {
        // Copy the actual pixel data without padding bytes
        for (int i = 0; i < imageInfo_.size.height; ++i) {
            errno_t ret = memcpy_s(dst, rowDataSize_, data_ + i * rowStride_, rowDataSize_);
            if (ret != 0) {
                IMAGE_LOGE("read pixels by buffer memcpy the pixelmap data to dst fail, error:%{public}d", ret);
                return ERR_IMAGE_READ_PIXELMAP_FAILED;
            }
            dst += rowDataSize_; // Move the destination buffer pointer to the next row
        }
    }
    return SUCCESS;
}

bool PixelMap::CheckPixelsInput(const uint8_t *dst, const uint64_t &bufferSize, const uint32_t &offset,
                                const uint32_t &stride, const Rect &region)
{
    if (dst == nullptr) {
        IMAGE_LOGE("CheckPixelsInput input dst address is null.");
        return false;
    }

    if (bufferSize == 0) {
        IMAGE_LOGE("CheckPixelsInput input buffer size is 0.");
        return false;
    }

    if (region.left < 0 || region.top < 0 || stride > numeric_limits<int32_t>::max() ||
        static_cast<uint64_t>(offset) > bufferSize) {
        IMAGE_LOGE(
            "CheckPixelsInput left(%{public}d) or top(%{public}d) or stride(%{public}u) or offset(%{public}u) < 0.",
            region.left, region.top, stride, offset);
        return false;
    }
    if (region.width <= 0 || region.height <= 0 || region.width > MAX_DIMENSION || region.height > MAX_DIMENSION) {
        IMAGE_LOGE("CheckPixelsInput width(%{public}d) or height(%{public}d) is < 0.", region.width, region.height);
        return false;
    }
    if (region.left > GetWidth() - region.width) {
        IMAGE_LOGE("CheckPixelsInput left(%{public}d) + width(%{public}d) is > pixelmap width(%{public}d).",
            region.left, region.width, GetWidth());
        return false;
    }
    if (region.top > GetHeight() - region.height) {
        IMAGE_LOGE("CheckPixelsInput top(%{public}d) + height(%{public}d) is > pixelmap height(%{public}d).",
            region.top, region.height, GetHeight());
        return false;
    }
    uint32_t regionStride = static_cast<uint32_t>(region.width) * 4;  // bytes count, need multiply by 4
    if (stride < regionStride) {
        IMAGE_LOGE("CheckPixelsInput stride(%{public}d) < width*4 (%{public}d).", stride, regionStride);
        return false;
    }

    if (bufferSize < regionStride) {
        IMAGE_LOGE("CheckPixelsInput input buffer size is < width * 4.");
        return false;
    }
    uint64_t lastLinePos = offset + static_cast<uint64_t>(region.height - 1) * stride;  // "1" is except the last line.
    if (static_cast<uint64_t>(offset) > (bufferSize - regionStride) || lastLinePos > (bufferSize - regionStride)) {
        IMAGE_LOGE(
            "CheckPixelsInput fail, height(%{public}d), width(%{public}d), lastLine(%{public}llu), "
            "offset(%{public}u), bufferSize:%{public}llu.", region.height, region.width,
            static_cast<unsigned long long>(lastLinePos), offset, static_cast<unsigned long long>(bufferSize));
        return false;
    }
    return true;
}

uint32_t PixelMap::ReadPixels(const uint64_t &bufferSize, const uint32_t &offset, const uint32_t &stride,
                              const Rect &region, uint8_t *dst)
{
    if (!CheckPixelsInput(dst, bufferSize, offset, stride, region)) {
        IMAGE_LOGE("read pixels by rect input parameter fail.");
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    if (data_ == nullptr) {
        IMAGE_LOGE("read pixels by rect this pixel data is null.");
        return ERR_IMAGE_READ_PIXELMAP_FAILED;
    }
    ImageInfo dstImageInfo =
        MakeImageInfo(region.width, region.height, PixelFormat::BGRA_8888, AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL);
    Position srcPosition { region.left, region.top };
    if (!PixelConvertAdapter::ReadPixelsConvert(data_, srcPosition, rowStride_, imageInfo_, dst + offset, stride,
        dstImageInfo)) {
        IMAGE_LOGE("read pixels by rect call ReadPixelsConvert fail.");
        return ERR_IMAGE_READ_PIXELMAP_FAILED;
    }
    return SUCCESS;
}

uint32_t PixelMap::ReadPixel(const Position &pos, uint32_t &dst)
{
    if (pos.x < 0 || pos.y < 0 || pos.x >= GetWidth() || pos.y >= GetHeight()) {
        IMAGE_LOGE("read pixel by pos input invalid exception. [x(%{public}d), y(%{public}d)]", pos.x, pos.y);
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    if (data_ == nullptr) {
        IMAGE_LOGE("read pixel by pos source data is null.");
        return ERR_IMAGE_READ_PIXELMAP_FAILED;
    }
    ImageInfo dstImageInfo =
        MakeImageInfo(PER_PIXEL_LEN, PER_PIXEL_LEN, PixelFormat::BGRA_8888, AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL);
    uint32_t dstRowBytes = BGRA_BYTES;
    Position srcPosition { pos.x, pos.y };
    if (!PixelConvertAdapter::ReadPixelsConvert(data_, srcPosition, rowStride_, imageInfo_, &dst, dstRowBytes,
        dstImageInfo)) {
        IMAGE_LOGE("read pixel by pos call ReadPixelsConvert fail.");
        return ERR_IMAGE_READ_PIXELMAP_FAILED;
    }
    return SUCCESS;
}

uint32_t PixelMap::ResetConfig(const Size &size, const PixelFormat &format)
{
    if (size.width <= 0 || size.height <= 0) {
        IMAGE_LOGE("ResetConfig reset input width(%{public}d) or height(%{public}d) is < 0.", size.width,
            size.height);
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    uint32_t bytesPerPixel = ImageUtils::GetPixelBytes(format);
    if (bytesPerPixel == 0) {
        IMAGE_LOGE("ResetConfig get bytes by per pixel fail.");
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    uint64_t dstSize = static_cast<uint64_t>(size.width) * size.height * bytesPerPixel;
    if (dstSize > static_cast<uint64_t>(pixelsSize_)) {
        IMAGE_LOGE("ResetConfig reset dstSize(%{public}llu) > current(%{public}u).",
            static_cast<unsigned long long>(dstSize), pixelsSize_);
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    AlphaType dstAlphaType = ImageUtils::GetValidAlphaTypeByFormat(GetAlphaType(), format);
    if (dstAlphaType == AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN) {
        IMAGE_LOGE("ResetConfig Failed to get validate alpha type.");
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    ImageInfo dstInfo = MakeImageInfo(size.width, size.height, format, dstAlphaType);
    uint32_t ret = SetImageInfo(dstInfo, true);
    if (ret != SUCCESS) {
        IMAGE_LOGE("ResetConfig call SetImageInfo Failed. ret:%{public}u", ret);
        return ERR_IMAGE_CONFIG_FAILED;
    }
    return SUCCESS;
}

bool PixelMap::SetAlphaType(const AlphaType &alphaType)
{
    AlphaType type = ImageUtils::GetValidAlphaTypeByFormat(alphaType, imageInfo_.pixelFormat);
    if (type == AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN) {
        IMAGE_LOGE("SetAlphaType Failed to get validate alpha type.");
        return false;
    }
    ImageInfo dstInfo = imageInfo_;
    dstInfo.alphaType = type;
    uint32_t ret = SetImageInfo(dstInfo, true);
    if (ret != SUCCESS) {
        IMAGE_LOGE("SetAlphaType call SetImageInfo Failed. ret:%{public}u", ret);
        return false;
    }
    return true;
}

uint32_t PixelMap::WritePixel(const Position &pos, const uint32_t &color)
{
    if (pos.x < 0 || pos.y < 0 || pos.x >= GetWidth() || pos.y >= GetHeight()) {
        IMAGE_LOGE(
            "write pixel by pos but input position is invalid. [x(%{public}d), y(%{public}d)]"\
            "Width() %{public}d,  Height() %{public}d, ", pos.x, pos.y, GetWidth(), GetHeight());
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    if (!IsEditable()) {
        IMAGE_LOGE("write pixel by pos pixelmap is not editable.");
        return ERR_IMAGE_PIXELMAP_NOT_ALLOW_MODIFY;
    }
    if (!ImageUtils::IsValidImageInfo(imageInfo_)) {
        IMAGE_LOGE("write pixel by pos current pixelmap image info is invalid.");
        return ERR_IMAGE_WRITE_PIXELMAP_FAILED;
    }
    if (data_ == nullptr) {
        IMAGE_LOGE("write pixel by pos but current pixelmap data is nullptr.");
        return ERR_IMAGE_WRITE_PIXELMAP_FAILED;
    }
    ImageInfo srcImageInfo =
        MakeImageInfo(PER_PIXEL_LEN, PER_PIXEL_LEN, PixelFormat::BGRA_8888, AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL);
    uint32_t srcRowBytes = BGRA_BYTES;
    Position dstPosition { pos.x, pos.y };  // source is per pixel.
    if (!PixelConvertAdapter::WritePixelsConvert(&color, srcRowBytes, srcImageInfo, data_, dstPosition, rowStride_,
        imageInfo_)) {
        IMAGE_LOGE("write pixel by pos call WritePixelsConvert fail.");
        return ERR_IMAGE_WRITE_PIXELMAP_FAILED;
    }
    return SUCCESS;
}

uint32_t PixelMap::WritePixels(const uint8_t *source, const uint64_t &bufferSize, const uint32_t &offset,
                               const uint32_t &stride, const Rect &region)
{
    if (!CheckPixelsInput(source, bufferSize, offset, stride, region)) {
        IMAGE_LOGE("write pixel by rect input parameter fail.");
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    if (!IsEditable()) {
        IMAGE_LOGE("write pixel by rect pixelmap data is not editable.");
        return ERR_IMAGE_PIXELMAP_NOT_ALLOW_MODIFY;
    }
    if (!ImageUtils::IsValidImageInfo(imageInfo_)) {
        IMAGE_LOGE("write pixel by rect current pixelmap image info is invalid.");
        return ERR_IMAGE_WRITE_PIXELMAP_FAILED;
    }
    if (data_ == nullptr) {
        IMAGE_LOGE("write pixel by rect current pixel map data is null.");
        return ERR_IMAGE_WRITE_PIXELMAP_FAILED;
    }
    uint32_t bytesPerPixel = ImageUtils::GetPixelBytes(imageInfo_.pixelFormat);
    if (bytesPerPixel == 0) {
        IMAGE_LOGE("write pixel by rect get bytes by per pixel fail.");
        return ERR_IMAGE_WRITE_PIXELMAP_FAILED;
    }
    Position dstPosition { region.left, region.top };
    ImageInfo srcInfo =
        MakeImageInfo(region.width, region.height, PixelFormat::BGRA_8888, AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL);
    if (!PixelConvertAdapter::WritePixelsConvert(source + offset, stride, srcInfo, data_, dstPosition, rowStride_,
        imageInfo_)) {
        IMAGE_LOGE("write pixel by rect call WritePixelsConvert fail.");
        return ERR_IMAGE_WRITE_PIXELMAP_FAILED;
    }
    return SUCCESS;
}

uint32_t PixelMap::WritePixels(const uint8_t *source, const uint64_t &bufferSize)
{
    ImageTrace imageTrace("WritePixels");
    if (source == nullptr || bufferSize < static_cast<uint64_t>(pixelsSize_)) {
        IMAGE_LOGE("write pixels by buffer source is nullptr or size(%{public}llu) < pixelSize(%{public}u).",
            static_cast<unsigned long long>(bufferSize), pixelsSize_);
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    if (!IsEditable()) {
        IMAGE_LOGE("write pixels by buffer pixelmap data is not editable.");
        return ERR_IMAGE_PIXELMAP_NOT_ALLOW_MODIFY;
    }
    if (!ImageUtils::IsValidImageInfo(imageInfo_)) {
        IMAGE_LOGE("write pixels by buffer current pixelmap image info is invalid.");
        return ERR_IMAGE_WRITE_PIXELMAP_FAILED;
    }
    if (data_ == nullptr) {
        IMAGE_LOGE("write pixels by buffer current pixelmap data is nullptr.");
        return ERR_IMAGE_WRITE_PIXELMAP_FAILED;
    }

    if (imageInfo_.pixelFormat == PixelFormat::NV12 || imageInfo_.pixelFormat == PixelFormat::NV21) {
        uint64_t tmpSize = 0;
        int readSize = MAX_READ_COUNT;
        while (tmpSize < bufferSize) {
            if (tmpSize + MAX_READ_COUNT > bufferSize) {
                readSize = (int)(bufferSize - tmpSize);
            }
            errno_t ret = memcpy_s(data_ + tmpSize, readSize, source + tmpSize, readSize);
            if (ret != 0) {
                IMAGE_LOGE("write pixels by buffer memcpy the pixelmap data to dst fail, error:%{public}d", ret);
                return ERR_IMAGE_READ_PIXELMAP_FAILED;
            }
            tmpSize += static_cast<uint64_t>(readSize);
        }
    } else {
        for (int i = 0; i < imageInfo_.size.height; ++i) {
            const uint8_t* sourceRow = source + i * rowDataSize_;
            errno_t ret = memcpy_s(data_ + i * rowStride_, rowDataSize_, sourceRow, rowDataSize_);
            if (ret != 0) {
                IMAGE_LOGE("write pixels by buffer memcpy the pixelmap data to dst fail, error:%{public}d", ret);
                return ERR_IMAGE_WRITE_PIXELMAP_FAILED;
            }
        }
    }
    return SUCCESS;
}

bool PixelMap::WritePixels(const uint32_t &color)
{
    if (!IsEditable()) {
        IMAGE_LOGE("erase pixels by color pixelmap data is not editable.");
        return false;
    }
    if (!ImageUtils::IsValidImageInfo(imageInfo_)) {
        IMAGE_LOGE("erase pixels by color current pixelmap image info is invalid.");
        return false;
    }
    if (data_ == nullptr) {
        IMAGE_LOGE("erase pixels by color current pixel map data is null.");
        return false;
    }
    ImageInfo srcInfo =
        MakeImageInfo(imageInfo_.size.width, imageInfo_.size.height, imageInfo_.pixelFormat, imageInfo_.alphaType);
    if (!PixelConvertAdapter::EraseBitmap(data_, rowStride_, srcInfo, color)) {
        IMAGE_LOGE("erase pixels by color call EraseBitmap fail.");
        return false;
    }
    return true;
}

bool PixelMap::IsStrideAlignment()
{
    IMAGE_LOGE("IsStrideAlignment error ");
    if (allocatorType_ == AllocatorType::DMA_ALLOC) {
        IMAGE_LOGE("SetPixelsAddr error allocatorType_ %{public}d ", allocatorType_);
        return true;
    }
    IMAGE_LOGE("IsStrideAlignment error ");
    return false;
}

AllocatorType PixelMap::GetAllocatorType()
{
    return allocatorType_;
}

void *PixelMap::GetFd() const
{
    return context_;
}

void PixelMap::ReleaseMemory(AllocatorType allocType, void *addr, void *context, uint32_t size)
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

bool PixelMap::WriteAshmemDataToParcel(Parcel &parcel, size_t size) const
{
#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) &&!defined(ANDROID_PLATFORM)
    const uint8_t *data = data_;
    uint32_t id = GetUniqueId();
    std::string name = "Parcel ImageData, uniqueId: " + std::to_string(getpid()) + '_' + std::to_string(id);
    int fd = AshmemCreate(name.c_str(), size);
    IMAGE_LOGI("AshmemCreate:[%{public}d].", fd);
    if (fd < 0) {
        return false;
    }

    int result = AshmemSetProt(fd, PROT_READ | PROT_WRITE);
    IMAGE_LOGI("AshmemSetProt:[%{public}d].", result);
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
    IMAGE_LOGI("mmap success");

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

bool PixelMap::WriteImageData(Parcel &parcel, size_t size) const
{
    const uint8_t *data = data_;
    if (data == nullptr || size > MAX_IMAGEDATA_SIZE) {
        IMAGE_LOGE("WriteImageData failed, data is null or size bigger than 128M.");
        return false;
    }

    if (!parcel.WriteInt32(size)) {
        IMAGE_LOGE("WriteImageData size failed.");
        return false;
    }
    if (size <= MIN_IMAGEDATA_SIZE) {
        return parcel.WriteUnpadBuffer(data, size);
    }
    return WriteAshmemDataToParcel(parcel, size);
}

uint8_t *PixelMap::ReadHeapDataFromParcel(Parcel &parcel, int32_t bufferSize)
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

uint8_t *PixelMap::ReadAshmemDataFromParcel(Parcel &parcel, int32_t bufferSize)
{
    uint8_t *base = nullptr;
#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(A_PLATFORM)
    int fd = ReadFileDescriptor(parcel);
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

uint8_t *PixelMap::ReadImageData(Parcel &parcel, int32_t bufferSize)
{
#if !defined(_WIN32) && !defined(_APPLE) &&!defined(IOS_PLATFORM) &&!defined(ANDROID_PLATFORM)
    if (static_cast<unsigned int>(bufferSize) <= MIN_IMAGEDATA_SIZE) {
        return ReadHeapDataFromParcel(parcel, bufferSize);
    } else {
        return ReadAshmemDataFromParcel(parcel, bufferSize);
    }
#else
    return ReadHeapDataFromParcel(parcel, bufferSize);
#endif
}

bool PixelMap::WriteFileDescriptor(Parcel &parcel, int fd)
{
#if !defined(IOS_PLATFORM) &&!defined(ANDROID_PLATFORM)
    if (fd < 0) {
        return false;
    }
    int dupFd = dup(fd);
    if (dupFd < 0) {
        return false;
    }
    sptr<IPCFileDescriptor> descriptor = new IPCFileDescriptor(dupFd);
    return parcel.WriteObject<IPCFileDescriptor>(descriptor);
#else
    return false;
#endif
}

int PixelMap::ReadFileDescriptor(Parcel &parcel)
{
#if !defined(IOS_PLATFORM) &&!defined(ANDROID_PLATFORM)
    sptr<IPCFileDescriptor> descriptor = parcel.ReadObject<IPCFileDescriptor>();
    if (descriptor == nullptr) {
        return -1;
    }
    int fd = descriptor->GetFd();
    if (fd < 0) {
        return -1;
    }
    return dup(fd);
#else
    return -1;
#endif
}

bool PixelMap::WriteImageInfo(Parcel &parcel) const
{
    if (!parcel.WriteInt32(imageInfo_.size.width)) {
        IMAGE_LOGE("write image info width:[%{public}d] to parcel failed.", imageInfo_.size.width);
        return false;
    }
    if (!parcel.WriteInt32(imageInfo_.size.height)) {
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
    return true;
}

bool PixelMap::WritePropertiesToParcel(Parcel &parcel) const
{
    if (!WriteImageInfo(parcel)) {
        IMAGE_LOGE("write image info to parcel failed.");
        return false;
    }

    if (!parcel.WriteBool(editable_)) {
        IMAGE_LOGE("write pixel map editable to parcel failed.");
        return false;
    }

    if (!parcel.WriteBool(isAstc_)) {
        IMAGE_LOGE("write pixel map isAstc_ to parcel failed.");
        return false;
    }

    if (!parcel.WriteInt32(static_cast<int32_t>(allocatorType_))) {
        IMAGE_LOGE("write pixel map allocator type:[%{public}d] to parcel failed.", allocatorType_);
        return false;
    }

    if (!parcel.WriteInt32(static_cast<int32_t>(grColorSpace_ ?
            grColorSpace_->GetColorSpaceName() : ERR_MEDIA_INVALID_VALUE))) {
        IMAGE_LOGE("write pixel map grColorSpace to parcel failed.");
        return false;
    }

    if (!parcel.WriteInt32(static_cast<int32_t>(rowDataSize_))) {
        IMAGE_LOGE("write image info rowStride_:[%{public}d] to parcel failed.", rowDataSize_);
        return false;
    }
    return true;
}

bool PixelMap::WriteMemInfoToParcel(Parcel &parcel, const int32_t &bufferSize) const
{
#if !defined(_WIN32) && !defined(_APPLE) &&!defined(IOS_PLATFORM) &&!defined(ANDROID_PLATFORM)
    if (allocatorType_ == AllocatorType::SHARE_MEM_ALLOC) {
        if (!parcel.WriteInt32(bufferSize)) {
            return false;
        }

        int *fd = static_cast<int *>(context_);
        if (fd == nullptr || *fd <= 0) {
            IMAGE_LOGE("write pixel map failed, fd is [%{public}d] or fd <= 0.", fd == nullptr ? 1 : 0);
            return false;
        }
        if (!CheckAshmemSize(*fd, bufferSize, isAstc_)) {
            IMAGE_LOGE("write pixel map check ashmem size failed, fd:[%{public}d].", *fd);
            return false;
        }
        if (!WriteFileDescriptor(parcel, *fd)) {
            IMAGE_LOGE("write pixel map fd:[%{public}d] to parcel failed.", *fd);
            return false;
        }
    } else if (allocatorType_ == AllocatorType::DMA_ALLOC) {
        if (!parcel.WriteInt32(bufferSize)) {
            return false;
        }
        SurfaceBuffer* sbBuffer = reinterpret_cast<SurfaceBuffer*> (context_);
        sbBuffer->WriteToMessageParcel(static_cast<MessageParcel&>(parcel));
    } else {
        if (!WriteImageData(parcel, bufferSize)) {
            IMAGE_LOGE("write pixel map buffer to parcel failed.");
            return false;
        }
    }
#else
    if (!WriteImageData(parcel, bufferSize)) {
        IMAGE_LOGE("write pixel map buffer to parcel failed.");
        return false;
    }
#endif
    return true;
}

bool PixelMap::WriteTransformDataToParcel(Parcel &parcel) const
{
    if (isAstc_) {
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

bool PixelMap::WriteAstcRealSizeToParcel(Parcel &parcel) const
{
    if (isAstc_) {
        if (!parcel.WriteInt32(static_cast<int32_t>(astcrealSize_.width))) {
            IMAGE_LOGE("write astcrealSize_.width:[%{public}d] to parcel failed.", astcrealSize_.width);
            return false;
        }
        if (!parcel.WriteInt32(static_cast<int32_t>(astcrealSize_.height))) {
            IMAGE_LOGE("write astcrealSize_.height:[%{public}d] to parcel failed.", astcrealSize_.height);
            return false;
        }
    }
    return true;
}

bool isYUV(const PixelFormat &format)
{
    return format == PixelFormat::NV12 || format == PixelFormat::NV21;
}

bool PixelMap::Marshalling(Parcel &parcel) const
{
    int32_t PIXEL_MAP_INFO_MAX_LENGTH = 128;
    int32_t bufferSize = rowDataSize_ * imageInfo_.size.height;
    if (isAstc_ || isYUV(imageInfo_.pixelFormat)) {
        bufferSize = pixelsSize_;
    }
    if (static_cast<size_t>(bufferSize) <= MIN_IMAGEDATA_SIZE &&
        static_cast<size_t>(bufferSize + PIXEL_MAP_INFO_MAX_LENGTH) > parcel.GetDataCapacity() &&
        !parcel.SetDataCapacity(bufferSize + PIXEL_MAP_INFO_MAX_LENGTH)) {
        IMAGE_LOGE("set parcel max capacity:[%{public}d] failed.", bufferSize + PIXEL_MAP_INFO_MAX_LENGTH);
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
    if (!WriteAstcRealSizeToParcel(parcel)) {
        IMAGE_LOGE("write astcrealSize to parcel failed.");
        return false;
    }
    return true;
}

bool PixelMap::ReadImageInfo(Parcel &parcel, ImageInfo &imgInfo)
{
    imgInfo.size.width = parcel.ReadInt32();
    IMAGE_LOGD("read pixel map width:[%{public}d] to parcel.", imgInfo.size.width);
    imgInfo.size.height = parcel.ReadInt32();
    IMAGE_LOGD("read pixel map height:[%{public}d] to parcel.", imgInfo.size.height);
    imgInfo.pixelFormat = static_cast<PixelFormat>(parcel.ReadInt32());
    IMAGE_LOGD("read pixel map pixelFormat:[%{public}d] to parcel.", imgInfo.pixelFormat);
    imgInfo.colorSpace = static_cast<ColorSpace>(parcel.ReadInt32());
    IMAGE_LOGD("read pixel map colorSpace:[%{public}d] to parcel.", imgInfo.colorSpace);
    imgInfo.alphaType = static_cast<AlphaType>(parcel.ReadInt32());
    IMAGE_LOGD("read pixel map alphaType:[%{public}d] to parcel.", imgInfo.alphaType);
    imgInfo.baseDensity = parcel.ReadInt32();
    return true;
}

bool PixelMap::ReadTransformData(Parcel &parcel, PixelMap *pixelMap)
{
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

bool PixelMap::ReadAstcRealSize(Parcel &parcel, PixelMap *pixelMap)
{
    if (pixelMap->IsAstc()) {
        Size realSize;
        realSize.width = parcel.ReadInt32();
        realSize.height = parcel.ReadInt32();
        pixelMap->SetAstcRealSize(realSize);
    }
    return true;
}

bool PixelMap::ReadPropertiesFromParcel(Parcel &parcel, ImageInfo &imgInfo,
    AllocatorType &allocatorType, int32_t &bufferSize, PIXEL_MAP_ERR &error)
{
    if (!ReadImageInfo(parcel, imgInfo)) {
        IMAGE_LOGE("read imageInfo fail");
        PixelMap::ConstructPixelMapError(error, ERR_IMAGE_PIXELMAP_CREATE_FAILED, "read imageInfo fail");
        return false;
    }
    bool isEditable = parcel.ReadBool();
    SetEditable(isEditable);
    bool isAstc = parcel.ReadBool();
    SetAstc(isAstc);

    allocatorType = static_cast<AllocatorType>(parcel.ReadInt32());

    int32_t csm = parcel.ReadInt32();
    if (csm != ERR_MEDIA_INVALID_VALUE) {
        OHOS::ColorManager::ColorSpaceName colorSpaceName = static_cast<OHOS::ColorManager::ColorSpaceName>(csm);
        OHOS::ColorManager::ColorSpace grColorSpace = OHOS::ColorManager::ColorSpace(colorSpaceName);
        InnerSetColorSpace(grColorSpace);
    }

    int32_t rowDataSize = parcel.ReadInt32();
    bufferSize = parcel.ReadInt32();
    int32_t bytesPerPixel = ImageUtils::GetPixelBytes(imgInfo.pixelFormat);
    if (bytesPerPixel == 0) {
        IMAGE_LOGE("ReadPropertiesFromParcel bytesPerPixel fail");
        return false;
    }
    if ((!isAstc) && (!isYUV(imgInfo.pixelFormat)) && bufferSize != rowDataSize * imgInfo.size.height) {
        IMAGE_LOGE("ReadPropertiesFromParcel bufferSize invalid");
        PixelMap::ConstructPixelMapError(error, ERR_IMAGE_PIXELMAP_CREATE_FAILED, "bufferSize invalid");
        return false;
    }
    return true;
}

bool PixelMap::ReadMemInfoFromParcel(Parcel &parcel, PixelMemInfo &pixelMemInfo, PIXEL_MAP_ERR &error)
{
#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) &&!defined(ANDROID_PLATFORM)
    if (pixelMemInfo.allocatorType == AllocatorType::SHARE_MEM_ALLOC) {
        int fd = ReadFileDescriptor(parcel);
        if (!CheckAshmemSize(fd, pixelMemInfo.bufferSize, pixelMemInfo.isAstc)) {
            PixelMap::ConstructPixelMapError(error, ERR_IMAGE_GET_FD_BAD, "fd acquisition failed");
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
        pixelMemInfo.context = new int32_t();
        if (pixelMemInfo.context == nullptr) {
            ::munmap(ptr, pixelMemInfo.bufferSize);
            ::close(fd);
            return false;
        }
        *static_cast<int32_t *>(pixelMemInfo.context) = fd;
        pixelMemInfo.base = static_cast<uint8_t *>(ptr);
    } else if (pixelMemInfo.allocatorType == AllocatorType::DMA_ALLOC) {
        sptr<SurfaceBuffer> surfaceBuffer = SurfaceBuffer::Create();
        surfaceBuffer->ReadFromMessageParcel(static_cast<MessageParcel&>(parcel));
        void* nativeBuffer = surfaceBuffer.GetRefPtr();
        ImageUtils::SurfaceBuffer_Reference(nativeBuffer);
        pixelMemInfo.base = static_cast<uint8_t*>(surfaceBuffer->GetVirAddr());
        pixelMemInfo.context = nativeBuffer;
    } else {
        pixelMemInfo.base = ReadImageData(parcel, pixelMemInfo.bufferSize);
        if (pixelMemInfo.base == nullptr) {
            IMAGE_LOGE("get pixel memory size:[%{public}d] error.", pixelMemInfo.bufferSize);
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

bool PixelMap::UpdatePixelMapMemInfo(PixelMap *pixelMap, ImageInfo &imgInfo, PixelMemInfo &pixelMemInfo)
{
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

PixelMap *PixelMap::Unmarshalling(Parcel &parcel)
{
    PIXEL_MAP_ERR error;
    PixelMap* dstPixelMap = PixelMap::Unmarshalling(parcel, error);
    if (dstPixelMap == nullptr || error.errorCode != SUCCESS) {
        IMAGE_LOGE("unmarshalling failed errorCode:%{public}d, errorInfo:%{public}s",
            error.errorCode, error.errorInfo.c_str());
    }
    return dstPixelMap;
}

PixelMap *PixelMap::Unmarshalling(Parcel &parcel, PIXEL_MAP_ERR &error)
{
    PixelMap *pixelMap = new PixelMap();
    if (pixelMap == nullptr) {
        PixelMap::ConstructPixelMapError(error, ERR_IMAGE_PIXELMAP_CREATE_FAILED, "pixelmap create failed");
        return nullptr;
    }

    ImageInfo imgInfo;
    PixelMemInfo pixelMemInfo;
    if (!pixelMap->ReadPropertiesFromParcel(parcel, imgInfo, pixelMemInfo.allocatorType,
        pixelMemInfo.bufferSize, error)) {
        IMAGE_LOGE("read properties fail");
        delete pixelMap;
        return nullptr;
    }
    pixelMemInfo.isAstc = pixelMap->IsAstc();
    if (!ReadMemInfoFromParcel(parcel, pixelMemInfo, error)) {
        IMAGE_LOGE("read memInfo fail");
        delete pixelMap;
        return nullptr;
    }
    if (!UpdatePixelMapMemInfo(pixelMap, imgInfo, pixelMemInfo)) {
        IMAGE_LOGE("update pixelMap memInfo fail");
        delete pixelMap;
        return nullptr;
    }
    if (!pixelMap->ReadTransformData(parcel, pixelMap)) {
        IMAGE_LOGE("read transformData fail");
        delete pixelMap;
        return nullptr;
    }
    if (!pixelMap->ReadAstcRealSize(parcel, pixelMap)) {
        IMAGE_LOGE("read astcrealSize fail");
        delete pixelMap;
        return nullptr;
    }
    return pixelMap;
}

void PixelMap::WriteUint8(std::vector<uint8_t> &buff, uint8_t value) const
{
    buff.push_back(value);
}

uint8_t PixelMap::ReadUint8(std::vector<uint8_t> &buff, int32_t &cursor)
{
    if (static_cast<size_t>(cursor + 1) > buff.size()) {
        IMAGE_LOGE("ReadUint8 out of range");
        return TLV_END;
    }
    return buff[cursor++];
}

uint8_t PixelMap::GetVarintLen(int32_t value) const
{
    uint8_t len = 1;
    while (value > TLV_VARINT_MASK) {
        len++;
        value >>= TLV_VARINT_BITS;
    }
    return len;
}

void PixelMap::WriteVarint(std::vector<uint8_t> &buff, int32_t value) const
{
    while (value > TLV_VARINT_MASK) {
        buff.push_back(TLV_VARINT_MORE | uint8_t(value & TLV_VARINT_MASK));
        value >>= TLV_VARINT_BITS;
    }
    buff.push_back(uint8_t(value));
}

int32_t PixelMap::ReadVarint(std::vector<uint8_t> &buff, int32_t &cursor)
{
    int32_t value = 0;
    uint8_t shift = 0;
    int32_t item = 0;
    do {
        if (static_cast<size_t>(cursor + 1) > buff.size()) {
            IMAGE_LOGE("ReadVarint out of range");
            return static_cast<int32_t>(TLV_END);
        }
        item = int32_t(buff[cursor++]);
        value |= (item & TLV_VARINT_MASK) << shift;
        shift += TLV_VARINT_BITS;
    } while ((item & TLV_VARINT_MORE) != 0);
    return value;
}

void PixelMap::WriteData(std::vector<uint8_t> &buff, const uint8_t *data,
    const int32_t &height, const int32_t &rowDataSize, const int32_t &rowStride) const
{
    if (allocatorType_ == AllocatorType::DMA_ALLOC) {
        for (int row = 0; row < height; row++) {
            for (int col = 0; col < rowDataSize; col++) {
                buff.push_back(*(data + row * rowStride + col));
            }
        }
    } else {
        int32_t size = pixelsSize_;
        for (int32_t offset = 0; offset < size; offset++) {
            buff.push_back(*(data + offset));
        }
    }
}

uint8_t *PixelMap::ReadData(std::vector<uint8_t> &buff, int32_t size, int32_t &cursor)
{
    if (size <= 0) {
        IMAGE_LOGE("pixel map tlv read data fail: invalid size[%{public}d]", size);
        return nullptr;
    }
    if (static_cast<size_t>(cursor + size) > buff.size()) {
        IMAGE_LOGE("ReadData out of range");
        return nullptr;
    }
    uint8_t *data = static_cast<uint8_t *>(malloc(size));
    if (data == nullptr) {
        IMAGE_LOGE("pixel map tlv read data fail: malloc memory size[%{public}d]", size);
        return nullptr;
    }
    for (int32_t offset = 0; offset < size; offset++) {
        *(data + offset) = buff[cursor++];
    }
    return data;
}

bool PixelMap::EncodeTlv(std::vector<uint8_t> &buff) const
{
    WriteUint8(buff, TLV_IMAGE_WIDTH);
    WriteVarint(buff, GetVarintLen(imageInfo_.size.width));
    WriteVarint(buff, imageInfo_.size.width);
    WriteUint8(buff, TLV_IMAGE_HEIGHT);
    WriteVarint(buff, GetVarintLen(imageInfo_.size.height));
    WriteVarint(buff, imageInfo_.size.height);
    WriteUint8(buff, TLV_IMAGE_PIXELFORMAT);
    WriteVarint(buff, GetVarintLen(static_cast<int32_t>(imageInfo_.pixelFormat)));
    WriteVarint(buff, static_cast<int32_t>(imageInfo_.pixelFormat));
    WriteUint8(buff, TLV_IMAGE_COLORSPACE);
    WriteVarint(buff, GetVarintLen(static_cast<int32_t>(imageInfo_.colorSpace)));
    WriteVarint(buff, static_cast<int32_t>(imageInfo_.colorSpace));
    WriteUint8(buff, TLV_IMAGE_ALPHATYPE);
    WriteVarint(buff, GetVarintLen(static_cast<int32_t>(imageInfo_.alphaType)));
    WriteVarint(buff, static_cast<int32_t>(imageInfo_.alphaType));
    WriteUint8(buff, TLV_IMAGE_BASEDENSITY);
    WriteVarint(buff, GetVarintLen(imageInfo_.baseDensity));
    WriteVarint(buff, imageInfo_.baseDensity);
    WriteUint8(buff, TLV_IMAGE_ALLOCATORTYPE);
    AllocatorType tmpAllocatorType = AllocatorType::HEAP_ALLOC;
    WriteVarint(buff, GetVarintLen(static_cast<int32_t>(tmpAllocatorType)));
    WriteVarint(buff, static_cast<int32_t>(tmpAllocatorType));
    WriteUint8(buff, TLV_IMAGE_DATA);
    const uint8_t *data = data_;
    int32_t dataSize = rowDataSize_ * imageInfo_.size.height;
    if (data == nullptr || size_t(dataSize) > MAX_IMAGEDATA_SIZE || dataSize <= 0) {
        WriteVarint(buff, 0); // L is zero and no value
        WriteUint8(buff, TLV_END); // end tag
        IMAGE_LOGE("pixel map tlv encode fail: no data");
        return false;
    }
    WriteVarint(buff, dataSize);
    WriteData(buff, data, imageInfo_.size.height, rowDataSize_, rowStride_);
    WriteUint8(buff, TLV_END); // end tag
    return true;
}

void PixelMap::ReadTlvAttr(std::vector<uint8_t> &buff, ImageInfo &info, int32_t &type, int32_t &size, uint8_t **data)
{
    int cursor = 0;
    for (uint8_t tag = ReadUint8(buff, cursor); tag != TLV_END; tag = ReadUint8(buff, cursor)) {
        int32_t len = ReadVarint(buff, cursor);
        if (len <= 0 || static_cast<size_t>(cursor + len) > buff.size()) {
            IMAGE_LOGE("ReadTlvAttr out of range");
            return;
        }
        switch (tag) {
            case TLV_IMAGE_WIDTH:
                info.size.width = ReadVarint(buff, cursor);
                break;
            case TLV_IMAGE_HEIGHT:
                info.size.height = ReadVarint(buff, cursor);
                break;
            case TLV_IMAGE_PIXELFORMAT:
                info.pixelFormat = static_cast<PixelFormat>(ReadVarint(buff, cursor));
                break;
            case TLV_IMAGE_COLORSPACE:
                info.colorSpace = static_cast<ColorSpace>(ReadVarint(buff, cursor));
                break;
            case TLV_IMAGE_ALPHATYPE:
                info.alphaType = static_cast<AlphaType>(ReadVarint(buff, cursor));
                break;
            case TLV_IMAGE_BASEDENSITY:
                info.baseDensity = ReadVarint(buff, cursor);
                break;
            case TLV_IMAGE_ALLOCATORTYPE:
                type = ReadVarint(buff, cursor);
                IMAGE_LOGI("pixel alloctype: %{public}d", type);
                break;
            case TLV_IMAGE_DATA:
                size = len;
                *data = ReadData(buff, size, cursor);
                break;
            default:
                cursor += len; // skip unknown tag
                IMAGE_LOGW("pixel map tlv decode warn: unknown tag[%{public}d]", tag);
                break;
        }
    }
}

PixelMap *PixelMap::DecodeTlv(std::vector<uint8_t> &buff)
{
    PixelMap *pixelMap = new PixelMap();
    if (pixelMap == nullptr) {
        IMAGE_LOGE("pixel map tlv decode fail: new PixelMap error");
        return nullptr;
    }
    ImageInfo imageInfo;
    int32_t dataSize = 0;
    uint8_t *data = nullptr;
    int32_t allocType = static_cast<int32_t>(AllocatorType::DEFAULT);
    ReadTlvAttr(buff, imageInfo, allocType, dataSize, &data);
    if (data == nullptr) {
        delete pixelMap;
        IMAGE_LOGE("pixel map tlv decode fail: no data");
        return nullptr;
    }
    uint32_t ret = pixelMap->SetImageInfo(imageInfo);
    if (ret != SUCCESS) {
        free(data);
        delete pixelMap;
        IMAGE_LOGE("pixel map tlv decode fail: set image info error[%{public}d]", ret);
        return nullptr;
    }
    if (dataSize != pixelMap->GetByteCount()) {
        delete pixelMap;
        IMAGE_LOGE("pixel map tlv decode fail: dataSize not match");
        return nullptr;
    }
    pixelMap->SetPixelsAddr(data, nullptr, dataSize, static_cast<AllocatorType>(allocType), nullptr);
    return pixelMap;
}

static const string GetNamedAlphaType(const AlphaType alphaType)
{
    switch (alphaType) {
        case AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN:
            return "Alpha Type Unknown";
        case AlphaType::IMAGE_ALPHA_TYPE_OPAQUE:
            return "Alpha Type Opaque";
        case AlphaType::IMAGE_ALPHA_TYPE_PREMUL:
            return "Alpha Type Premul";
        case AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL:
            return "Alpha Type Unpremul";
        default:
            return "Alpha Type Unknown";
    }
    return "Alpha Type Unknown";
}

static const string GetNamedPixelFormat(const PixelFormat pixelFormat)
{
    switch (pixelFormat) {
        case PixelFormat::UNKNOWN:
            return "Pixel Format UNKNOWN";
        case PixelFormat::RGB_565:
            return "Pixel Format RGB_565";
        case PixelFormat::RGB_888:
            return "Pixel Format RGB_888";
        case PixelFormat::NV21:
            return "Pixel Format NV21";
        case PixelFormat::NV12:
            return "Pixel Format NV12";
        case PixelFormat::CMYK:
            return "Pixel Format CMYK";
        case PixelFormat::ARGB_8888:
            return "Pixel Format ARGB_8888";
        case PixelFormat::ALPHA_8:
            return "Pixel Format ALPHA_8";
        case PixelFormat::RGBA_8888:
            return "Pixel Format RGBA_8888";
        case PixelFormat::BGRA_8888:
            return "Pixel Format BGRA_8888";
        case PixelFormat::RGBA_F16:
            return "Pixel Format RGBA_F16";
        case PixelFormat::ASTC_4x4:
            return "Pixel Format ASTC_4x4";
        case PixelFormat::ASTC_6x6:
            return "Pixel Format ASTC_6x6";
        case PixelFormat::ASTC_8x8:
            return "Pixel Format ASTC_8x8";
        case PixelFormat::RGBA_1010102:
            return "Pixel Format RGBA_1010102";
        default:
            return "Pixel Format UNKNOWN";
    }
    return "Pixel Format UNKNOWN";
}

constexpr uint8_t HALF_LOW_BYTE = 0;
constexpr uint8_t HALF_HIGH_BYTE = 1;

static float HalfTranslate(const uint8_t* ui)
{
    return HalfToFloat(U8ToU16(ui[HALF_HIGH_BYTE], ui[HALF_LOW_BYTE]));
}

static void HalfTranslate(const float pixel, uint8_t* ui)
{
    uint16_t val = FloatToHalf(pixel);
    ui[HALF_LOW_BYTE] = static_cast<uint8_t>((val >> SHIFT_8_BIT) & UINT8_MAX);
    ui[HALF_HIGH_BYTE] = static_cast<uint8_t>(val & UINT8_MAX);
}
constexpr uint8_t RGBA_F16_R_OFFSET = 0;
constexpr uint8_t RGBA_F16_G_OFFSET = 2;
constexpr uint8_t RGBA_F16_B_OFFSET = 4;
constexpr uint8_t RGBA_F16_A_OFFSET = 6;

static constexpr float FLOAT_NUMBER_NEAR_ZERO = 0.000001;
static constexpr float FLOAT_ZERO = 0.0f;
static float ProcessPremulF16Pixel(float mulPixel, float alpha, const float percent)
{
    if (alpha < FLOAT_NUMBER_NEAR_ZERO && alpha > -FLOAT_NUMBER_NEAR_ZERO) {
        return FLOAT_ZERO;
    }
    float res = mulPixel * percent / alpha;
    return res > MAX_HALF ? MAX_HALF : res;
}

static void SetF16PixelAlpha(uint8_t *pixel, const float percent, bool isPixelPremul)
{
    float a = HalfTranslate(pixel + RGBA_F16_A_OFFSET);
    if (isPixelPremul) {
        float r = HalfTranslate(pixel + RGBA_F16_R_OFFSET);
        float g = HalfTranslate(pixel + RGBA_F16_G_OFFSET);
        float b = HalfTranslate(pixel + RGBA_F16_B_OFFSET);
        r = ProcessPremulF16Pixel(r, a, percent);
        g = ProcessPremulF16Pixel(g, a, percent);
        b = ProcessPremulF16Pixel(b, a, percent);
        HalfTranslate(r, pixel + RGBA_F16_R_OFFSET);
        HalfTranslate(g, pixel + RGBA_F16_G_OFFSET);
        HalfTranslate(b, pixel + RGBA_F16_B_OFFSET);
    }
    a = percent * MAX_HALF;
    HalfTranslate(a, pixel + RGBA_F16_A_OFFSET);
}

static constexpr uint8_t U_ZERO = 0;
static uint8_t ProcessPremulPixel(uint8_t mulPixel, uint8_t alpha, const float percent)
{
    // mP = oP * oAlpha / UINT8_MAX
    // => oP = mP * UINT8_MAX / oAlpha
    // nP = oP * percent
    // => nP = mP * UINT8_MAX * percent / oAlpha
    if (alpha == 0) {
        return U_ZERO;
    }
    float nPixel = mulPixel * percent * UINT8_MAX / alpha;
    if ((nPixel + HALF_ONE) >= UINT8_MAX) {
        return UINT8_MAX;
    }
    return static_cast<uint8_t>(nPixel + HALF_ONE);
}

static void SetUintPixelAlpha(uint8_t *pixel, const float percent,
    uint8_t pixelByte, int8_t alphaIndex, bool isPixelPremul)
{
    if (isPixelPremul) {
        for (int32_t pixelIndex = 0; pixelIndex < pixelByte; pixelIndex++) {
            if (pixelIndex != alphaIndex) {
                pixel[pixelIndex] = ProcessPremulPixel(pixel[pixelIndex],
                    pixel[alphaIndex], percent);
            }
        }
    }
    pixel[alphaIndex] = static_cast<uint8_t>(UINT8_MAX * percent + HALF_ONE);
}

static int8_t GetAlphaIndex(const PixelFormat& pixelFormat)
{
    switch (pixelFormat) {
        case PixelFormat::ARGB_8888:
        case PixelFormat::ALPHA_8:
            return ARGB_ALPHA_INDEX;
        case PixelFormat::RGBA_8888:
        case PixelFormat::BGRA_8888:
        case PixelFormat::RGBA_F16:
            return BGRA_ALPHA_INDEX;
        default:
            return INVALID_ALPHA_INDEX;
    }
}

static void ConvertUintPixelAlpha(uint8_t *rpixel,
    uint8_t pixelByte, int8_t alphaIndex, bool isPremul, uint8_t *wpixel)
{
    float alphaValue = static_cast<float>(rpixel[alphaIndex]) / UINT8_MAX;
    for (int32_t pixelIndex = 0; pixelIndex < pixelByte; pixelIndex++) {
        float pixelValue = static_cast<float>(rpixel[pixelIndex]);
        if (pixelIndex != alphaIndex) {
            float nPixel;
            if (isPremul) {
                nPixel = pixelValue * alphaValue;
            } else {
                nPixel = (alphaValue > 0) ? pixelValue / alphaValue : 0;
            }
            wpixel[pixelIndex] = static_cast<uint8_t>(nPixel + HALF_ONE);
        } else {
            wpixel[pixelIndex] = rpixel[pixelIndex];
        }
    }
}

uint32_t PixelMap::CheckAlphaFormatInput(PixelMap &wPixelMap, const bool isPremul)
{
    ImageInfo dstImageInfo;
    wPixelMap.GetImageInfo(dstImageInfo);
    uint32_t dstPixelSize = wPixelMap.GetCapacity();
    int32_t dstPixelBytes = wPixelMap.GetPixelBytes();
    void* dstData = wPixelMap.GetWritablePixels();
    int32_t stride = wPixelMap.GetRowStride();

    if (dstData == nullptr || data_ == nullptr) {
        IMAGE_LOGE("read pixels by dstPixelMap or srcPixelMap data is null.");
        return ERR_IMAGE_READ_PIXELMAP_FAILED;
    }
    if (!((GetAlphaType() == AlphaType::IMAGE_ALPHA_TYPE_PREMUL && !isPremul) ||
        (GetAlphaType() == AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL && isPremul))) {
        IMAGE_LOGE("alpha type error");
        return COMMON_ERR_INVALID_PARAMETER;
    }
    if (imageInfo_.size.height != dstImageInfo.size.height || imageInfo_.size.width != dstImageInfo.size.width) {
        IMAGE_LOGE("dstPixelMap size mismtach srcPixelMap");
        return COMMON_ERR_INVALID_PARAMETER;
    }
    if (stride != GetRowStride() || dstPixelSize < pixelsSize_) {
        IMAGE_LOGE("stride or pixelsSize from dstPixelMap mismtach srcPixelMap");
        return COMMON_ERR_INVALID_PARAMETER;
    }

    PixelFormat srcPixelFormat = GetPixelFormat();
    PixelFormat dstPixelFormat = dstImageInfo.pixelFormat;
    int8_t srcAlphaIndex = GetAlphaIndex(srcPixelFormat);
    int8_t dstAlphaIndex = GetAlphaIndex(dstPixelFormat);
    if (srcPixelFormat != dstPixelFormat || srcAlphaIndex == INVALID_ALPHA_INDEX ||
        dstAlphaIndex == INVALID_ALPHA_INDEX || srcPixelFormat == PixelFormat::RGBA_F16 ||
        dstPixelFormat == PixelFormat::RGBA_F16) {
        IMAGE_LOGE("Could not perform premultiply or nonpremultiply from %{public}s to %{public}s",
            GetNamedPixelFormat(srcPixelFormat).c_str(), GetNamedPixelFormat(dstPixelFormat).c_str());
        return ERR_IMAGE_DATA_UNSUPPORT;
    }

    if ((srcPixelFormat == PixelFormat::ALPHA_8 && pixelBytes_ != ALPHA_BYTES) ||
        (dstPixelFormat == PixelFormat::ALPHA_8 && dstPixelBytes != ALPHA_BYTES)) {
        IMAGE_LOGE("Pixel format %{public}s and %{public}s mismatch pixelByte %{public}d and %{public}d",
            GetNamedPixelFormat(srcPixelFormat).c_str(), GetNamedPixelFormat(dstPixelFormat).c_str(), pixelBytes_,
            dstPixelBytes);
        return COMMON_ERR_INVALID_PARAMETER;
    }
    return SUCCESS;
}

uint32_t PixelMap::ConvertAlphaFormat(PixelMap &wPixelMap, const bool isPremul)
{
    uint32_t res = CheckAlphaFormatInput(wPixelMap, isPremul);
    if (res != SUCCESS) {
        return res;
    }

    ImageInfo dstImageInfo;
    wPixelMap.GetImageInfo(dstImageInfo);
    void* dstData = wPixelMap.GetWritablePixels();
    int32_t stride = wPixelMap.GetRowStride();

    PixelFormat srcPixelFormat = GetPixelFormat();
    int8_t srcAlphaIndex = GetAlphaIndex(srcPixelFormat);
    int32_t index = 0;
    for (int32_t i = 0; i < imageInfo_.size.height; ++i) {
        for (int32_t j = 0; j < stride; j+=pixelBytes_) {
            index = i * stride + j;
            ConvertUintPixelAlpha(data_ + index, pixelBytes_, srcAlphaIndex, isPremul,
                static_cast<uint8_t*>(dstData) + index);
        }
    }
    if (isPremul == true) {
        wPixelMap.SetAlphaType(AlphaType::IMAGE_ALPHA_TYPE_PREMUL);
    } else {
        wPixelMap.SetAlphaType(AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL);
    }
    return SUCCESS;
}

uint32_t PixelMap::SetAlpha(const float percent)
{
    auto alphaType = GetAlphaType();
    if (alphaType == AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN ||
        alphaType == AlphaType::IMAGE_ALPHA_TYPE_OPAQUE) {
        IMAGE_LOGE(
            "Could not set alpha on %{public}s",
            GetNamedAlphaType(alphaType).c_str());
        return ERR_IMAGE_DATA_UNSUPPORT;
    }

    if (percent <= 0 || percent > 1) {
        IMAGE_LOGE(
            "Set alpha input should (0 < input <= 1). Current input %{public}f",
            percent);
        return ERR_IMAGE_INVALID_PARAMETER;
    }

    bool isPixelPremul = alphaType == AlphaType::IMAGE_ALPHA_TYPE_PREMUL;
    auto pixelFormat = GetPixelFormat();
    uint32_t pixelsSize = GetByteCount();
    int8_t alphaIndex = GetAlphaIndex(pixelFormat);
    if (alphaIndex == INVALID_ALPHA_INDEX) {
        IMAGE_LOGE("Could not set alpha on %{public}s",
            GetNamedPixelFormat(pixelFormat).c_str());
        return ERR_IMAGE_DATA_UNSUPPORT;
    }

    if ((pixelFormat == PixelFormat::ALPHA_8 && pixelBytes_ != ALPHA_BYTES) ||
        (pixelFormat == PixelFormat::RGBA_F16 && pixelBytes_ != RGBA_F16_BYTES)) {
        IMAGE_LOGE("Pixel format %{public}s mismatch pixelByte %{public}d",
            GetNamedPixelFormat(pixelFormat).c_str(), pixelBytes_);
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    for (uint32_t i = 0; i < pixelsSize;) {
        uint8_t* pixel = data_ + i;
        if (pixelFormat == PixelFormat::RGBA_F16) {
            SetF16PixelAlpha(pixel, percent, isPixelPremul);
        } else {
            SetUintPixelAlpha(pixel, percent, pixelBytes_, alphaIndex, isPixelPremul);
        }
        i += pixelBytes_;
    }
    return SUCCESS;
}

static sk_sp<SkColorSpace> ToSkColorSpace(PixelMap *pixelmap)
{
#ifdef IMAGE_COLORSPACE_FLAG
    if (pixelmap->InnerGetGrColorSpacePtr() == nullptr) {
        return nullptr;
    }
    return pixelmap->InnerGetGrColorSpacePtr()->ToSkColorSpace();
#else
    return nullptr;
#endif
}

static SkImageInfo ToSkImageInfo(ImageInfo &info, sk_sp<SkColorSpace> colorSpace)
{
    SkColorType colorType = ImageTypeConverter::ToSkColorType(info.pixelFormat);
    SkAlphaType alphaType = ImageTypeConverter::ToSkAlphaType(info.alphaType);
    IMAGE_LOGD("ToSkImageInfo w %{public}d, h %{public}d", info.size.width, info.size.height);
    IMAGE_LOGD(
        "ToSkImageInfo pf %{public}s, at %{public}s, skpf %{public}s, skat %{public}s",
        ImageTypeConverter::ToName(info.pixelFormat).c_str(),
        ImageTypeConverter::ToName(info.alphaType).c_str(),
        ImageTypeConverter::ToName(colorType).c_str(),
        ImageTypeConverter::ToName(alphaType).c_str()
    );
    return SkImageInfo::Make(info.size.width, info.size.height, colorType, alphaType, colorSpace);
}

static void ToImageInfo(ImageInfo &info, SkImageInfo &skInfo, bool sizeOnly = true)
{
    info.size.width = skInfo.width();
    info.size.height = skInfo.height();
    if (!sizeOnly) {
        info.alphaType = ImageTypeConverter::ToAlphaType(skInfo.alphaType());
        info.pixelFormat = ImageTypeConverter::ToPixelFormat(skInfo.colorType());
    }
}

struct SkTransInfo {
    SkRect r;
    SkImageInfo info;
    SkBitmap bitmap;
};

struct TransMemoryInfo {
    AllocatorType allocType;
    std::unique_ptr<AbsMemory> memory = nullptr;
};

constexpr float HALF = 0.5f;

static inline int FloatToInt(float a)
{
    return static_cast<int>(a + HALF);
}

#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
static void GenSrcTransInfo(SkTransInfo &srcInfo, ImageInfo &imageInfo, PixelMap* pixelmap,
    sk_sp<SkColorSpace> colorSpace)
{
    srcInfo.r = SkRect::MakeIWH(imageInfo.size.width, imageInfo.size.height);
    srcInfo.info = ToSkImageInfo(imageInfo, colorSpace);
    uint64_t rowStride = srcInfo.info.minRowBytes();
    if (pixelmap->GetAllocatorType() == AllocatorType::DMA_ALLOC) {
        if (pixelmap->GetFd() == nullptr) {
            IMAGE_LOGE("GenSrcTransInfo get surfacebuffer failed");
        }
        SurfaceBuffer* sbBuffer = reinterpret_cast<SurfaceBuffer*>(pixelmap->GetFd());
        rowStride = sbBuffer->GetStride();
    }
    srcInfo.bitmap.installPixels(srcInfo.info, static_cast<uint8_t *>(pixelmap->GetWritablePixels()), rowStride);
}
#else
static void GenSrcTransInfo(SkTransInfo &srcInfo, ImageInfo &imageInfo, uint8_t* pixels,
    sk_sp<SkColorSpace> colorSpace)
{
    srcInfo.r = SkRect::MakeIWH(imageInfo.size.width, imageInfo.size.height);
    srcInfo.info = ToSkImageInfo(imageInfo, colorSpace);
    srcInfo.bitmap.installPixels(srcInfo.info, pixels, srcInfo.info.minRowBytes());
}
#endif

static bool GendstTransInfo(SkTransInfo &srcInfo, SkTransInfo &dstInfo, SkMatrix &matrix,
    TransMemoryInfo &memoryInfo)
{
    dstInfo.r = matrix.mapRect(srcInfo.r);
    int width = FloatToInt(dstInfo.r.width());
    int height = FloatToInt(dstInfo.r.height());
    if (matrix.isTranslate()) {
        width += dstInfo.r.fLeft;
        height += dstInfo.r.fTop;
    }
    dstInfo.info = srcInfo.info.makeWH(width, height);
    PixelFormat format = ImageTypeConverter::ToPixelFormat(srcInfo.info.colorType());
#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    Size desiredSize = {dstInfo.info.width(), dstInfo.info.height()};
    MemoryData memoryData = {nullptr, dstInfo.info.computeMinByteSize(), "Trans ImageData", desiredSize, format};
#else
    MemoryData memoryData = {nullptr, dstInfo.info.computeMinByteSize(), "Trans ImageData"};
    memoryData.format = format;
#endif
    std::unique_ptr<AbsMemory> dstMemory = MemoryManager::CreateMemory(memoryInfo.allocType, memoryData);
    if (dstMemory == nullptr) {
        IMAGE_LOGE("CreateMemory falied");
        return false;
    }
    memoryInfo.memory = std::move(dstMemory);
#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    uint64_t rowStride = dstInfo.info.minRowBytes();
    if (memoryInfo.allocType == AllocatorType::DMA_ALLOC) {
        if (memoryInfo.memory->extend.data == nullptr) {
            IMAGE_LOGE("GendstTransInfo get surfacebuffer failed");
        }
        SurfaceBuffer* sbBuffer = reinterpret_cast<SurfaceBuffer*>(memoryInfo.memory->extend.data);
        rowStride = sbBuffer->GetStride();
    }
    dstInfo.bitmap.installPixels(dstInfo.info, memoryInfo.memory->data.data, rowStride);
#else
    dstInfo.bitmap.installPixels(dstInfo.info, memoryInfo.memory->data.data, dstInfo.info.minRowBytes());
#endif
    return true;
}

struct TransInfos {
    SkMatrix matrix;
};

bool IsSupportAntiAliasing(const ImageInfo& imageInfo, const AntiAliasingOption &option)
{
    return option != AntiAliasingOption::NONE && imageInfo.size.width <= ANTIALIASING_SIZE &&
            imageInfo.size.height <= ANTIALIASING_SIZE;
}

SkSamplingOptions ToSkSamplingOption(const AntiAliasingOption &option)
{
    switch (option) {
        case AntiAliasingOption::NONE: return SkSamplingOptions(SkFilterMode::kNearest, SkMipmapMode::kNone);
        case AntiAliasingOption::LOW: return SkSamplingOptions(SkFilterMode::kLinear, SkMipmapMode::kNone);
        case AntiAliasingOption::MEDIUM: return SkSamplingOptions(SkFilterMode::kLinear, SkMipmapMode::kLinear);
        case AntiAliasingOption::HIGH: return SkSamplingOptions(SkCubicResampler { 1 / 3.0f, 1 / 3.0f });
        default: return SkSamplingOptions(SkFilterMode::kNearest, SkMipmapMode::kNone);
    }
}

bool PixelMap::DoTranslation(TransInfos &infos, const AntiAliasingOption &option)
{
    ImageInfo imageInfo;
    GetImageInfo(imageInfo);

    TransMemoryInfo dstMemory;
    if (allocatorType_ == AllocatorType::CUSTOM_ALLOC) {
        // We dont know how custom alloc memory
        dstMemory.allocType = AllocatorType::DEFAULT;
    } else {
        dstMemory.allocType = allocatorType_;
    }

    SkTransInfo src;
#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    GenSrcTransInfo(src, imageInfo, this, ToSkColorSpace(this));
#else
    GenSrcTransInfo(src, imageInfo, data_, ToSkColorSpace(this));
#endif

    SkTransInfo dst;
    if (!GendstTransInfo(src, dst, infos.matrix, dstMemory)) {
        IMAGE_LOGE("GendstTransInfo dstMemory falied");
        this->errorCode = IMAGE_RESULT_DECODE_FAILED;
        return false;
    }

    SkCanvas canvas(dst.bitmap);
    if (!infos.matrix.isTranslate()) {
        if (!EQUAL_TO_ZERO(dst.r.fLeft) || !EQUAL_TO_ZERO(dst.r.fTop)) {
            canvas.translate(-dst.r.fLeft, -dst.r.fTop);
        }
    }
    canvas.concat(infos.matrix);
    auto skimage = SkImage::MakeFromBitmap(src.bitmap);
    if (infos.matrix.rectStaysRect()) {
        SkRect skrect = SkRect::MakeXYWH(0, 0, skimage->width(), skimage->height());
        SkPaint paint;
        paint.setAntiAlias(true);
        canvas.drawImageRect(skimage, skrect, ToSkSamplingOption(option), &paint);
    } else {
        canvas.drawImage(skimage, FLOAT_ZERO, FLOAT_ZERO, ToSkSamplingOption(option));
    }

    ToImageInfo(imageInfo, dst.info);
    auto m = dstMemory.memory.get();
    SetPixelsAddr(m->data.data, m->extend.data, m->data.size, m->GetType(), nullptr);
    SetImageInfo(imageInfo, true);
    return true;
}

void PixelMap::scale(float xAxis, float yAxis)
{
    ImageTrace imageTrace("PixelMap scale xAxis = %f, yAxis = %f", xAxis, yAxis);
    TransInfos infos;
    infos.matrix.setScale(xAxis, yAxis);
    if (!DoTranslation(infos)) {
        IMAGE_LOGE("scale falied");
    }
}

void PixelMap::scale(float xAxis, float yAxis, const AntiAliasingOption &option)
{
    ImageTrace imageTrace("PixelMap scale with option");
    TransInfos infos;
    infos.matrix.setScale(xAxis, yAxis);
    if (!DoTranslation(infos, option)) {
        IMAGE_LOGE("scale falied");
    }
}

bool PixelMap::resize(float xAxis, float yAxis)
{
    if (imageInfo_.pixelFormat == PixelFormat::NV12 || imageInfo_.pixelFormat == PixelFormat::NV21) {
        IMAGE_LOGE("resize temp disabled for YUV data");
        return true;
    }
    ImageTrace imageTrace("PixelMap resize");
    TransInfos infos;
    infos.matrix.setScale(xAxis, yAxis);
    if (!DoTranslation(infos)) {
        IMAGE_LOGE("resize falied");
        return false;
    }
    return true;
}

void PixelMap::translate(float xAxis, float yAxis)
{
    ImageTrace imageTrace("PixelMap translate");
    TransInfos infos;
    infos.matrix.setTranslate(xAxis, yAxis);
    if (!DoTranslation(infos)) {
        IMAGE_LOGE("translate falied");
    }
}

void PixelMap::rotate(float degrees)
{
    ImageTrace imageTrace("PixelMap rotate");
    TransInfos infos;
    infos.matrix.setRotate(degrees);
    if (!DoTranslation(infos)) {
        IMAGE_LOGE("rotate falied");
    }
}

void PixelMap::flip(bool xAxis, bool yAxis)
{
    ImageTrace imageTrace("PixelMap flip");
    if (xAxis == false && yAxis == false) {
        return;
    }
    scale(xAxis ? -1 : 1, yAxis ? -1 : 1);
}

uint32_t PixelMap::crop(const Rect &rect)
{
    ImageTrace imageTrace("PixelMap crop");
    ImageInfo imageInfo;
    GetImageInfo(imageInfo);

    SkTransInfo src;
#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    GenSrcTransInfo(src, imageInfo, this, ToSkColorSpace(this));
#else
    GenSrcTransInfo(src, imageInfo, data_, ToSkColorSpace(this));
#endif
    SkTransInfo dst;
    SkIRect dstIRect = SkIRect::MakeXYWH(rect.left, rect.top, rect.width, rect.height);
    dst.r = SkRect::Make(dstIRect);
    if (dst.r == src.r) {
        return SUCCESS;
    }

    if (!src.r.contains(dst.r)) {
        IMAGE_LOGE("Invalid crop rect");
        return ERR_IMAGE_CROP;
    }
    dst.info = src.info.makeWH(dstIRect.width(), dstIRect.height());
    Size desiredSize = {dst.info.width(), dst.info.height()};
    MemoryData memoryData = {nullptr, dst.info.computeMinByteSize(), "Trans ImageData", desiredSize,
                             imageInfo.pixelFormat};
    auto m = MemoryManager::CreateMemory(allocatorType_, memoryData);
    if (m == nullptr) {
        return ERR_IMAGE_CROP;
    }
    uint64_t rowStride = dst.info.minRowBytes();
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    if (allocatorType_ == AllocatorType::DMA_ALLOC) {
        if (m->extend.data == nullptr) {
            IMAGE_LOGE("GendstTransInfo get surfacebuffer failed");
            return ERR_IMAGE_CROP;
        }
        rowStride = reinterpret_cast<SurfaceBuffer*>(m->extend.data)->GetStride();
    }
#endif
    if (!src.bitmap.readPixels(dst.info, m->data.data, rowStride, dstIRect.fLeft, dstIRect.fTop)) {
        IMAGE_LOGE("ReadPixels failed");
        return ERR_IMAGE_CROP;
    }
    ToImageInfo(imageInfo, dst.info);
    SetPixelsAddr(m->data.data, m->extend.data, m->data.size, m->GetType(), nullptr);
    SetImageInfo(imageInfo, true);
    return SUCCESS;
}

#ifdef IMAGE_COLORSPACE_FLAG
void PixelMap::InnerSetColorSpace(const OHOS::ColorManager::ColorSpace &grColorSpace)
{
    grColorSpace_ = std::make_shared<OHOS::ColorManager::ColorSpace>(grColorSpace.ToSkColorSpace(),
        grColorSpace.GetColorSpaceName());
}

OHOS::ColorManager::ColorSpace PixelMap::InnerGetGrColorSpace()
{
    if (grColorSpace_ == nullptr) {
        grColorSpace_ =
            std::make_shared<OHOS::ColorManager::ColorSpace>(OHOS::ColorManager::ColorSpaceName::SRGB);
    }
    return *grColorSpace_;
}

static bool isSameColorSpace(const OHOS::ColorManager::ColorSpace &src,
    const OHOS::ColorManager::ColorSpace &dst)
{
    auto skSrc = src.ToSkColorSpace();
    auto skDst = dst.ToSkColorSpace();
    return SkColorSpace::Equals(skSrc.get(), skDst.get());
}

uint32_t PixelMap::ApplyColorSpace(const OHOS::ColorManager::ColorSpace &grColorSpace)
{
    auto grName = grColorSpace.GetColorSpaceName();
    if (grColorSpace_ != nullptr && isSameColorSpace(*grColorSpace_, grColorSpace)) {
        if (grColorSpace_->GetColorSpaceName() != grName) {
            InnerSetColorSpace(grColorSpace);
        }
        return SUCCESS;
    }
    ImageInfo imageInfo;
    GetImageInfo(imageInfo);
    // Build sk source infomation
    SkTransInfo src;
    src.info = ToSkImageInfo(imageInfo, ToSkColorSpace(this));
    uint64_t rowStride = src.info.minRowBytes();
    uint8_t* srcData = data_;
#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    if (GetAllocatorType() == AllocatorType::DMA_ALLOC && GetFd() != nullptr) {
        SurfaceBuffer* sbBuffer = reinterpret_cast<SurfaceBuffer*>(GetFd());
        rowStride = sbBuffer->GetStride();
    }
    srcData = static_cast<uint8_t *>(GetWritablePixels());
#endif
    src.bitmap.installPixels(src.info, srcData, rowStride);
    // Build sk target infomation
    SkTransInfo dst;
    dst.info = ToSkImageInfo(imageInfo, grColorSpace.ToSkColorSpace());
    MemoryData memoryData = {nullptr, dst.info.computeMinByteSize(),
        "Trans ImageData", {dst.info.width(), dst.info.height()}, imageInfo.pixelFormat};
    auto m = MemoryManager::CreateMemory(allocatorType_, memoryData);
    if (m == nullptr) {
        IMAGE_LOGE("applyColorSpace CreateMemory failed");
        return ERR_IMAGE_COLOR_CONVERT;
    }
    // Transfor pixels by readPixels
    if (!src.bitmap.readPixels(dst.info, m->data.data, rowStride, 0, 0)) {
        m->Release();
        IMAGE_LOGE("ReadPixels failed");
        return ERR_IMAGE_COLOR_CONVERT;
    }
    // Restore target infomation into pixelmap
    ToImageInfo(imageInfo, dst.info);
    grColorSpace_ = std::make_shared<OHOS::ColorManager::ColorSpace>(dst.info.refColorSpace(), grName);
    SetPixelsAddr(m->data.data, m->extend.data, m->data.size, m->GetType(), nullptr);
    SetImageInfo(imageInfo, true);
    return SUCCESS;
}
#endif
} // namespace Media
} // namespace OHOS
