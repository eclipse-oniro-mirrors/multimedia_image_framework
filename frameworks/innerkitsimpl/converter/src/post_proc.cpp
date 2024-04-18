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

#include "post_proc.h"

#include <unistd.h>

#include "basic_transformer.h"
#include "image_log.h"
#include "image_trace.h"
#include "image_utils.h"
#include "media_errors.h"
#include "memory_manager.h"
#include "pixel_convert_adapter.h"
#ifndef _WIN32
#include "securec.h"
#else
#include "memory.h"
#endif

#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
#include <sys/mman.h>
#include "ashmem.h"
#include "surface_buffer.h"

#ifdef __cplusplus
extern "C" {
#endif
#include "libswscale/swscale.h"
#ifdef __cplusplus
};
#endif
#endif

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "PostProc"

namespace OHOS {
namespace Media {
using namespace std;
constexpr uint32_t NEED_NEXT = 1;
constexpr float EPSILON = 1e-6;
constexpr uint8_t HALF = 2;
constexpr float HALF_F = 2;
constexpr int FFMPEG_NUM = 8;

#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(A_PLATFORM)
static const map<PixelFormat, AVPixelFormat> PIXEL_FORMAT_MAP = {
    { PixelFormat::ALPHA_8, AVPixelFormat::AV_PIX_FMT_GRAY8 },
    { PixelFormat::RGB_565, AVPixelFormat::AV_PIX_FMT_RGB565BE },
    { PixelFormat::RGB_888, AVPixelFormat::AV_PIX_FMT_RGB24 },
    { PixelFormat::RGBA_8888, AVPixelFormat::AV_PIX_FMT_RGBA },
    { PixelFormat::ARGB_8888, AVPixelFormat::AV_PIX_FMT_ARGB },
    { PixelFormat::BGRA_8888, AVPixelFormat::AV_PIX_FMT_BGRA },
    { PixelFormat::RGBA_F16, AVPixelFormat::AV_PIX_FMT_RGBA64BE },
};
#endif

uint32_t PostProc::DecodePostProc(const DecodeOptions &opts, PixelMap &pixelMap, FinalOutputStep finalOutputStep)
{
    ImageInfo srcImageInfo;
    pixelMap.GetImageInfo(srcImageInfo);
    ImageInfo dstImageInfo;
    GetDstImageInfo(opts, pixelMap, srcImageInfo, dstImageInfo);
    uint32_t errorCode = ConvertProc(opts.CropRect, dstImageInfo, pixelMap, srcImageInfo);
    if (errorCode != SUCCESS) {
        IMAGE_LOGE("[PostProc]crop pixel map failed, errcode:%{public}u", errorCode);
        return errorCode;
    }
    decodeOpts_.allocatorType = opts.allocatorType;
    bool isNeedRotate = !ImageUtils::FloatCompareZero(opts.rotateDegrees);
    if (isNeedRotate) {
        if (!RotatePixelMap(opts.rotateDegrees, pixelMap)) {
            IMAGE_LOGE("[PostProc]rotate:transform pixel map failed");
            return ERR_IMAGE_TRANSFORM;
        }
    }
    decodeOpts_.allocatorType = opts.allocatorType;
    if (opts.desiredSize.height > 0 && opts.desiredSize.width > 0) {
        if (!ScalePixelMap(opts.desiredSize, pixelMap)) {
            IMAGE_LOGE("[PostProc]scale:transform pixel map failed");
            return ERR_IMAGE_TRANSFORM;
        }
    } else {
        ImageInfo info;
        pixelMap.GetImageInfo(info);
        if ((finalOutputStep == FinalOutputStep::DENSITY_CHANGE) && (info.baseDensity != 0)) {
            int targetWidth = (pixelMap.GetWidth() * opts.fitDensity + (info.baseDensity >> 1)) / info.baseDensity;
            int targetHeight = (pixelMap.GetHeight() * opts.fitDensity + (info.baseDensity >> 1)) / info.baseDensity;
            Size size;
            size.height = targetHeight;
            size.width = targetWidth;
            if (!ScalePixelMap(size, pixelMap)) {
                IMAGE_LOGE("[PostProc]density scale:transform pixel map failed");
                return ERR_IMAGE_TRANSFORM;
            }
            info.baseDensity = opts.fitDensity;
            pixelMap.SetImageInfo(info, true);
        }
    }
    return SUCCESS;
}

void PostProc::GetDstImageInfo(const DecodeOptions &opts, PixelMap &pixelMap,
                               ImageInfo srcImageInfo, ImageInfo &dstImageInfo)
{
    dstImageInfo.size = opts.desiredSize;
    dstImageInfo.pixelFormat = opts.desiredPixelFormat;
    dstImageInfo.baseDensity = srcImageInfo.baseDensity;
    decodeOpts_ = opts;
    if (opts.desiredPixelFormat == PixelFormat::UNKNOWN) {
        if (opts.preference == MemoryUsagePreference::LOW_RAM &&
            srcImageInfo.alphaType == AlphaType::IMAGE_ALPHA_TYPE_OPAQUE) {
            dstImageInfo.pixelFormat = PixelFormat::RGB_565;
        } else {
            dstImageInfo.pixelFormat = PixelFormat::RGBA_8888;
        }
    }
    // decode use, this value may be changed by real pixelFormat
    if (pixelMap.GetAlphaType() == AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL) {
        dstImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_PREMUL;
    } else {
        dstImageInfo.alphaType = pixelMap.GetAlphaType();
    }
}

bool PostProc::CenterScale(const Size &size, PixelMap &pixelMap)
{
    int32_t srcWidth = pixelMap.GetWidth();
    int32_t srcHeight = pixelMap.GetHeight();
    int32_t targetWidth = size.width;
    int32_t targetHeight = size.height;
    if (targetWidth <= 0 || targetHeight <= 0 || srcWidth <= 0 || srcHeight <= 0) {
        IMAGE_LOGE("[PostProc]params invalid, targetWidth:%{public}d, targetHeight:%{public}d, "
            "srcWidth:%{public}d, srcHeight:%{public}d", targetWidth, targetHeight, srcWidth, srcHeight);
        return false;
    }
    float widthScale = static_cast<float>(targetWidth) / static_cast<float>(srcWidth);
    float heightScale = static_cast<float>(targetHeight) / static_cast<float>(srcHeight);
    float scale = max(widthScale, heightScale);
    if (pixelMap.IsAstc() && scale > 0) {
        TransformData transformData;
        pixelMap.GetTransformData(transformData);
        transformData.scaleX *= scale;
        transformData.scaleY *= scale;
        transformData.cropLeft = (srcWidth - targetWidth / scale) / HALF_F;
        transformData.cropTop = (srcHeight - targetHeight / scale) / HALF_F;
        transformData.cropWidth = targetWidth / scale;
        transformData.cropHeight = targetHeight / scale;
        pixelMap.SetTransformData(transformData);
        ImageInfo imageInfo;
        pixelMap.GetImageInfo(imageInfo);
        imageInfo.size.width = targetWidth;
        imageInfo.size.height = targetHeight;
        pixelMap.SetImageInfo(imageInfo, true);
        return true;
    }
    if (!ScalePixelMap(scale, scale, pixelMap)) {
        IMAGE_LOGE("[PostProc]center scale pixelmap %{public}f fail", scale);
        return false;
    }
    srcWidth = pixelMap.GetWidth();
    srcHeight = pixelMap.GetHeight();
    if (srcWidth == targetWidth && srcHeight == targetHeight) {
        return true;
    }
    if (srcWidth < targetWidth || srcHeight < targetHeight) {
        IMAGE_LOGE("[PostProc]src size [%{public}d, %{public}d] must less than dst size [%{public}d,"
            "%{public}d]", srcWidth, srcHeight, targetWidth, targetHeight);
        return false;
    }

    return CenterDisplay(pixelMap, srcWidth, srcHeight, targetWidth, targetHeight);
}

bool PostProc::CopyPixels(PixelMap& pixelMap, uint8_t* dstPixels, const Size& dstSize,
                          const int32_t srcWidth, const int32_t srcHeight,
                          int32_t srcRowStride, int32_t targetRowStride)
{
    int32_t targetWidth = dstSize.width;
    int32_t targetHeight = dstSize.height;
    int32_t left = max(0, srcWidth - targetWidth) / HALF;
    int32_t top = max(0, srcHeight - targetHeight) / HALF;
    int32_t pixelBytes = pixelMap.GetPixelBytes();
    uint8_t *srcPixels = const_cast<uint8_t *>(pixelMap.GetPixels()) + (top * srcWidth + left) * pixelBytes;
    uint8_t *dstStartPixel = nullptr;
    uint8_t *srcStartPixel = nullptr;
    uint32_t targetRowBytes = targetWidth * pixelBytes;
    if (targetRowStride <= 0) {
        targetRowStride = targetRowBytes;
    }
    uint32_t srcRowBytes = srcWidth * pixelBytes;
    if (srcRowStride <= 0) {
        srcRowStride = srcRowBytes;
    }
    uint32_t copyRowBytes = std::min(srcWidth, targetWidth) * pixelBytes;
    for (int32_t scanLine = 0; scanLine < std::min(srcHeight, targetHeight); scanLine++) {
        dstStartPixel = dstPixels + scanLine * targetRowStride;
        srcStartPixel = srcPixels + scanLine * srcRowStride;
        errno_t errRet = memcpy_s(dstStartPixel, targetRowBytes, srcStartPixel, copyRowBytes);
        if (errRet != EOK) {
            IMAGE_LOGE("[PostProc]memcpy scanline %{public}d fail, errorCode = %{public}d", scanLine, errRet);
            return false;
        }
    }
    return true;
}

bool PostProc::CenterDisplay(PixelMap &pixelMap, int32_t srcWidth, int32_t srcHeight, int32_t targetWidth,
                             int32_t targetHeight)
{
    ImageInfo dstImageInfo;
    pixelMap.GetImageInfo(dstImageInfo);
    int32_t srcRowStride = pixelMap.GetAllocatorType() == AllocatorType::DMA_ALLOC ? pixelMap.GetRowStride() : 0;
    dstImageInfo.size.width = targetWidth;
    dstImageInfo.size.height = targetHeight;
    if (pixelMap.SetImageInfo(dstImageInfo, true) != SUCCESS) {
        IMAGE_LOGE("update ImageInfo failed");
        return false;
    }
    int32_t bufferSize = pixelMap.GetByteCount();
    uint8_t *dstPixels = nullptr;
    void *nativeBuffer = nullptr;
    int fd = 0;
    int targetRowStride = 0;
    if (pixelMap.GetAllocatorType() == AllocatorType::HEAP_ALLOC) {
        if (!AllocHeapBuffer(bufferSize, &dstPixels)) {
            return false;
        }
    } else if (pixelMap.GetAllocatorType() == AllocatorType::DMA_ALLOC) {
        dstPixels = AllocDmaMemory(dstImageInfo.size, bufferSize, &nativeBuffer, targetRowStride);
        if (dstPixels == nullptr) {
            IMAGE_LOGE("[PostProc]CenterDisplay AllocDmaMemory failed");
            return false;
        }
    } else {
        dstPixels = AllocSharedMemory(dstImageInfo.size, bufferSize, fd, pixelMap.GetUniqueId());
        if (dstPixels == nullptr) {
            IMAGE_LOGE("[PostProc]CenterDisplay AllocSharedMemory failed");
            return false;
        }
    }
    if (!CopyPixels(pixelMap, dstPixels, dstImageInfo.size, srcWidth, srcHeight, srcRowStride, targetRowStride)) {
        IMAGE_LOGE("[PostProc]CopyPixels failed");
        ReleaseBuffer(pixelMap.GetAllocatorType(), fd, bufferSize, &dstPixels, nativeBuffer);
        return false;
    }
    void *fdBuffer = nullptr;
    if (pixelMap.GetAllocatorType() == AllocatorType::HEAP_ALLOC) {
        pixelMap.SetPixelsAddr(dstPixels, nullptr, bufferSize, AllocatorType::HEAP_ALLOC, nullptr);
    } else if (pixelMap.GetAllocatorType() == AllocatorType::DMA_ALLOC) {
        pixelMap.SetPixelsAddr(dstPixels, nativeBuffer, bufferSize, AllocatorType::DMA_ALLOC, nullptr);
    } else {
        fdBuffer = new int32_t();
        *static_cast<int32_t *>(fdBuffer) = fd;
        pixelMap.SetPixelsAddr(dstPixels, fdBuffer, bufferSize, AllocatorType::SHARE_MEM_ALLOC, nullptr);
    }
    return true;
}

bool PostProc::ProcessScanlineFilter(ScanlineFilter &scanlineFilter, const Rect &cropRect, PixelMap &pixelMap,
                                     uint8_t *resultData, uint32_t rowBytes)
{
    auto srcData = pixelMap.GetPixels();
    int32_t scanLine = 0;
    while (scanLine < pixelMap.GetHeight()) {
        FilterRowType filterRow = scanlineFilter.GetFilterRowType(scanLine);
        if (filterRow == FilterRowType::NON_REFERENCE_ROW) {
            scanLine++;
            continue;
        }
        if (filterRow == FilterRowType::LAST_REFERENCE_ROW) {
            break;
        }
        uint32_t ret = scanlineFilter.FilterLine(resultData + ((scanLine - cropRect.top) * rowBytes), rowBytes,
                                                 srcData + (scanLine * pixelMap.GetRowBytes()));
        if (ret != SUCCESS) {
            IMAGE_LOGE("[PostProc]scan line failed, ret:%{public}u", ret);
            return false;
        }
        scanLine++;
    }
    return true;
}

uint32_t PostProc::CheckScanlineFilter(const Rect &cropRect, ImageInfo &dstImageInfo, PixelMap &pixelMap,
                                       int32_t pixelBytes, ScanlineFilter &scanlineFilter)
{
    uint64_t bufferSize = static_cast<uint64_t>(dstImageInfo.size.width) * dstImageInfo.size.height * pixelBytes;
    uint8_t *resultData = nullptr;
    int fd = 0;
    if (decodeOpts_.allocatorType == AllocatorType::SHARE_MEM_ALLOC) {
        resultData = AllocSharedMemory(dstImageInfo.size, bufferSize, fd, pixelMap.GetUniqueId());
        if (resultData == nullptr) {
            IMAGE_LOGE("[PostProc]AllocSharedMemory failed");
            return ERR_IMAGE_CROP;
        }
    } else {
        if (!AllocHeapBuffer(bufferSize, &resultData)) {
            return ERR_IMAGE_CROP;
        }
    }
    if (ImageUtils::CheckMulOverflow(dstImageInfo.size.width, pixelBytes)) {
        IMAGE_LOGE("[PostProc]size.width:%{public}d, is too large",
            dstImageInfo.size.width);
        ReleaseBuffer(decodeOpts_.allocatorType, fd, bufferSize, &resultData);
        return ERR_IMAGE_CROP;
    }
    uint32_t rowBytes = pixelBytes * dstImageInfo.size.width;
    if (!ProcessScanlineFilter(scanlineFilter, cropRect, pixelMap, resultData, rowBytes)) {
        IMAGE_LOGE("[PostProc]ProcessScanlineFilter failed");
        ReleaseBuffer(decodeOpts_.allocatorType, fd, bufferSize, &resultData);
        return ERR_IMAGE_CROP;
    }
    uint32_t result = pixelMap.SetImageInfo(dstImageInfo);
    if (result != SUCCESS) {
        ReleaseBuffer(decodeOpts_.allocatorType, fd, bufferSize, &resultData);
        return result;
    }

    if (decodeOpts_.allocatorType == AllocatorType::HEAP_ALLOC) {
        pixelMap.SetPixelsAddr(resultData, nullptr, bufferSize, decodeOpts_.allocatorType, nullptr);
        return result;
    }
    void *fdBuffer = new int32_t();
    *static_cast<int32_t *>(fdBuffer) = fd;
    pixelMap.SetPixelsAddr(resultData, fdBuffer, bufferSize, decodeOpts_.allocatorType, nullptr);
    return result;
}

uint32_t PostProc::ConvertProc(const Rect &cropRect, ImageInfo &dstImageInfo, PixelMap &pixelMap,
                               ImageInfo &srcImageInfo)
{
    bool hasPixelConvert = HasPixelConvert(srcImageInfo, dstImageInfo);
    uint32_t ret = NeedScanlineFilter(cropRect, srcImageInfo.size, hasPixelConvert);
    if (ret != NEED_NEXT) {
        return ret;
    }

    // we suppose a quick method to scanline in mostly seen cases: NO CROP && hasPixelConvert
    if (GetCropValue(cropRect, srcImageInfo.size) == CropValue::NOCROP &&
        dstImageInfo.pixelFormat == PixelFormat::ARGB_8888 && hasPixelConvert) {
        IMAGE_LOGI("[PostProc]no need crop, only pixel convert.");
        return PixelConvertProc(dstImageInfo, pixelMap, srcImageInfo);
    }

    ScanlineFilter scanlineFilter(srcImageInfo.pixelFormat);
    // this method maybe update dst image size to crop size
    SetScanlineCropAndConvert(cropRect, dstImageInfo, srcImageInfo, scanlineFilter, hasPixelConvert);

    int32_t pixelBytes = ImageUtils::GetPixelBytes(dstImageInfo.pixelFormat);
    if (pixelBytes == 0) {
        return ERR_IMAGE_CROP;
    }
    if (ImageUtils::CheckMulOverflow(dstImageInfo.size.width, dstImageInfo.size.height, pixelBytes)) {
        IMAGE_LOGE("[PostProc]size.width:%{public}d, size.height:%{public}d is too large",
            dstImageInfo.size.width, dstImageInfo.size.height);
        return ERR_IMAGE_CROP;
    }
    return CheckScanlineFilter(cropRect, dstImageInfo, pixelMap, pixelBytes, scanlineFilter);
}

uint32_t PostProc::PixelConvertProc(ImageInfo &dstImageInfo, PixelMap &pixelMap,
                                    ImageInfo &srcImageInfo)
{
    uint32_t ret;
    int fd = 0;
    uint64_t bufferSize = 0;
    uint8_t *resultData = nullptr;

    // as no crop, the size is same as src
    dstImageInfo.size = srcImageInfo.size;
    if (AllocBuffer(dstImageInfo, &resultData, bufferSize, fd, pixelMap.GetUniqueId()) != SUCCESS) {
        ReleaseBuffer(decodeOpts_.allocatorType, fd, bufferSize, &resultData);
        return ERR_IMAGE_CROP;
    }

    int32_t pixelBytes = ImageUtils::GetPixelBytes(srcImageInfo.pixelFormat);
    if (pixelBytes == 0) {
        return ERR_IMAGE_CROP;
    }

    ret = pixelMap.SetImageInfo(dstImageInfo);
    if (ret != SUCCESS) {
        ReleaseBuffer(decodeOpts_.allocatorType, fd, bufferSize, &resultData);
        return ret;
    }

    if (decodeOpts_.allocatorType == AllocatorType::HEAP_ALLOC) {
        pixelMap.SetPixelsAddr(resultData, nullptr, bufferSize, decodeOpts_.allocatorType, nullptr);
        return ret;
    }

    void *fdBuffer = new int32_t();
    *static_cast<int32_t *>(fdBuffer) = fd;
    pixelMap.SetPixelsAddr(resultData, fdBuffer, bufferSize, decodeOpts_.allocatorType, nullptr);
    return ret;
}

uint32_t PostProc::AllocBuffer(ImageInfo imageInfo, uint8_t **resultData, uint64_t &bufferSize, int &fd, uint32_t id)
{
    int32_t pixelBytes = ImageUtils::GetPixelBytes(imageInfo.pixelFormat);
    if (pixelBytes == 0) {
        return ERR_IMAGE_CROP;
    }
    if (ImageUtils::CheckMulOverflow(imageInfo.size.width, imageInfo.size.height, pixelBytes)) {
        IMAGE_LOGE("[PostProc]size.width:%{public}d, size.height:%{public}d is too large",
            imageInfo.size.width, imageInfo.size.height);
        return ERR_IMAGE_CROP;
    }
    bufferSize = static_cast<uint64_t>(imageInfo.size.width) * imageInfo.size.height * pixelBytes;
    IMAGE_LOGD("[PostProc]size.width:%{public}d, size.height:%{public}d, bufferSize:%{public}lld",
        imageInfo.size.width, imageInfo.size.height, static_cast<long long>(bufferSize));
    if (decodeOpts_.allocatorType == AllocatorType::SHARE_MEM_ALLOC) {
        *resultData = AllocSharedMemory(imageInfo.size, bufferSize, fd, id);
        if (*resultData == nullptr) {
            IMAGE_LOGE("[PostProc]AllocSharedMemory failed");
            return ERR_IMAGE_CROP;
        }
    } else {
        if (!AllocHeapBuffer(bufferSize, resultData)) {
            return ERR_IMAGE_CROP;
        }
    }
    return SUCCESS;
}

bool PostProc::AllocHeapBuffer(uint64_t bufferSize, uint8_t **buffer)
{
    if (bufferSize == 0 || bufferSize > MALLOC_MAX_LENTH) {
        IMAGE_LOGE("[PostProc]Invalid value of bufferSize");
        return false;
    }
    *buffer = static_cast<uint8_t *>(malloc(bufferSize));
    if (*buffer == nullptr) {
        IMAGE_LOGE("[PostProc]alloc covert color buffersize[%{public}llu] failed.",
            static_cast<unsigned long long>(bufferSize));
        return false;
    }
#ifdef _WIN32
    errno_t backRet = memset_s(*buffer, 0, bufferSize);
    if (backRet != EOK) {
        IMAGE_LOGE("[PostProc]memset convertData fail, errorCode = %{public}d", backRet);
        ReleaseBuffer(AllocatorType::HEAP_ALLOC, 0, 0, buffer);
        return false;
    }
    return true;
#else
    errno_t errRet = memset_s(*buffer, bufferSize, 0, bufferSize);
    if (errRet != EOK) {
        IMAGE_LOGE("[PostProc]memset convertData fail, errorCode = %{public}d", errRet);
        ReleaseBuffer(AllocatorType::HEAP_ALLOC, 0, 0, buffer);
        return false;
    }
    return true;
#endif
}

uint8_t *PostProc::AllocSharedMemory(const Size &size, const uint64_t bufferSize, int &fd, uint32_t uniqueId)
{
#if defined(_WIN32) || defined(_APPLE) || defined(IOS_PLATFORM) || defined(ANDROID_PLATFORM)
        return nullptr;
#else
    std::string name = "Parcel RawData, uniqueId: " + std::to_string(getpid()) + '_' + std::to_string(uniqueId);
    fd = AshmemCreate(name.c_str(), bufferSize);
    if (fd < 0) {
        IMAGE_LOGE("[PostProc]AllocSharedMemory fd error, bufferSize %{public}lld",
            static_cast<long long>(bufferSize));
        return nullptr;
    }
    int result = AshmemSetProt(fd, PROT_READ | PROT_WRITE);
    if (result < 0) {
        IMAGE_LOGE("[PostProc]AshmemSetProt error");
        ::close(fd);
        return nullptr;
    }
    void* ptr = ::mmap(nullptr, bufferSize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (ptr == MAP_FAILED) {
        IMAGE_LOGE("[PostProc]mmap error, errno: %{public}s, fd %{public}d, bufferSize %{public}lld",
            strerror(errno), fd, (long long)bufferSize);
        ::close(fd);
        return nullptr;
    }
    return reinterpret_cast<uint8_t *>(ptr);
#endif
}

uint8_t *PostProc::AllocDmaMemory(const Size &size, const uint64_t bufferSize,
                                  void **nativeBuffer, int &targetRowStride)
{
#if defined(_WIN32) || defined(_APPLE) || defined(IOS_PLATFORM) || defined(ANDROID_PLATFORM)
    return nullptr;
#else
    MemoryData memoryData = {nullptr, (uint32_t)bufferSize, "PostProc", {size.width, size.height}};
    auto dstMemory = MemoryManager::CreateMemory(AllocatorType::DMA_ALLOC, memoryData);
    if (dstMemory == nullptr) {
        return nullptr;
    }
    *nativeBuffer = dstMemory->extend.data;
    auto sbBuffer = reinterpret_cast<SurfaceBuffer *>(dstMemory->extend.data);
    targetRowStride = sbBuffer->GetStride();
    return (uint8_t *)dstMemory->data.data;
#endif
}

void PostProc::ReleaseBuffer(AllocatorType allocatorType, int fd,
                             uint64_t dataSize, uint8_t **buffer, void *nativeBuffer)
{
#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    if (allocatorType == AllocatorType::SHARE_MEM_ALLOC) {
        if (*buffer != nullptr) {
            ::munmap(*buffer, dataSize);
            ::close(fd);
        }
        return;
    }
    if (allocatorType == AllocatorType::DMA_ALLOC) {
        if (nativeBuffer != nullptr) {
            int32_t err = ImageUtils::SurfaceBuffer_Unreference(static_cast<SurfaceBuffer*>(nativeBuffer));
            if (err != OHOS::GSERROR_OK) {
                IMAGE_LOGE("PostProc NativeBufferReference failed");
            }
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

uint32_t PostProc::NeedScanlineFilter(const Rect &cropRect, const Size &srcSize, const bool &hasPixelConvert)
{
    CropValue value = GetCropValue(cropRect, srcSize);
    if (value == CropValue::NOCROP && !hasPixelConvert) {
        IMAGE_LOGI("[PostProc]no need crop and pixel convert.");
        return SUCCESS;
    } else if (value == CropValue::INVALID) {
        IMAGE_LOGE("[PostProc]invalid corp region, top:%{public}d, left:%{public}d, "
            "width:%{public}d, height:%{public}d", cropRect.top, cropRect.left, cropRect.width, cropRect.height);
        return ERR_IMAGE_CROP;
    }
    return NEED_NEXT;
}

void PostProc::ConvertPixelMapToPixmapInfo(PixelMap &pixelMap, PixmapInfo &pixmapInfo)
{
    pixmapInfo.imageInfo.size.width = pixelMap.GetWidth();
    pixmapInfo.imageInfo.size.height = pixelMap.GetHeight();
    pixmapInfo.imageInfo.pixelFormat = pixelMap.GetPixelFormat();
    pixmapInfo.imageInfo.colorSpace = pixelMap.GetColorSpace();
    pixmapInfo.imageInfo.alphaType = pixelMap.GetAlphaType();
    pixmapInfo.imageInfo.baseDensity = pixelMap.GetBaseDensity();
    pixmapInfo.data = const_cast<uint8_t *>(pixelMap.GetPixels());
    pixmapInfo.bufferSize = pixelMap.GetByteCount();
}

bool PostProc::RotatePixelMap(float rotateDegrees, PixelMap &pixelMap)
{
    BasicTransformer trans;
    PixmapInfo input(false);
    ConvertPixelMapToPixmapInfo(pixelMap, input);
    // Default rotation at the center of the image, so divide 2
    trans.SetRotateParam(rotateDegrees, static_cast<float>(input.imageInfo.size.width) * FHALF,
                         static_cast<float>(input.imageInfo.size.height) * FHALF);
    return Transform(trans, input, pixelMap);
}

bool PostProc::ScalePixelMap(const Size &size, PixelMap &pixelMap)
{
    int32_t srcWidth = pixelMap.GetWidth();
    int32_t srcHeight = pixelMap.GetHeight();
    if (srcWidth <= 0 || srcHeight <= 0) {
        IMAGE_LOGE("[PostProc]src width:%{public}d, height:%{public}d is invalid.", srcWidth, srcHeight);
        return false;
    }
    float scaleX = static_cast<float>(size.width) / static_cast<float>(srcWidth);
    float scaleY = static_cast<float>(size.height) / static_cast<float>(srcHeight);
    return ScalePixelMap(scaleX, scaleY, pixelMap);
}

bool PostProc::ScalePixelMap(float scaleX, float scaleY, PixelMap &pixelMap)
{
    // returns directly with a scale of 1.0
    if ((fabs(scaleX - 1.0f) < EPSILON) && (fabs(scaleY - 1.0f) < EPSILON)) {
        return true;
    }
    return pixelMap.resize(scaleX, scaleY);
}
bool PostProc::TranslatePixelMap(float tX, float tY, PixelMap &pixelMap)
{
    BasicTransformer trans;
    PixmapInfo input(false);
    ConvertPixelMapToPixmapInfo(pixelMap, input);

    trans.SetTranslateParam(tX, tY);
    return Transform(trans, input, pixelMap);
}

bool PostProc::Transform(BasicTransformer &trans, const PixmapInfo &input, PixelMap &pixelMap)
{
    if (pixelMap.IsTransformered()) {
        IMAGE_LOGE("[PostProc]Transform pixelmap is transforming");
        return false;
    }
    pixelMap.SetTransformered(true);
    PixmapInfo output(false);
    output.uniqueId = pixelMap.GetUniqueId();
    uint32_t ret;
    if (decodeOpts_.allocatorType == AllocatorType::SHARE_MEM_ALLOC) {
        typedef uint8_t *(*AllocMemory)(const Size &size, const uint64_t bufferSize, int &fd, uint32_t uniqueId);
        AllocMemory allcFunc = AllocSharedMemory;
        ret = trans.TransformPixmap(input, output, allcFunc);
    } else {
        ret = trans.TransformPixmap(input, output);
    }
    if (ret != IMAGE_SUCCESS) {
        output.Destroy();
        return false;
    }

    if (pixelMap.SetImageInfo(output.imageInfo) != SUCCESS) {
        output.Destroy();
        return false;
    }
    pixelMap.SetPixelsAddr(output.data, output.context, output.bufferSize, decodeOpts_.allocatorType, nullptr);
    pixelMap.SetTransformered(false);
    return true;
}

CropValue PostProc::GetCropValue(const Rect &rect, const Size &size)
{
    bool isSameSize = (rect.top == 0 && rect.left == 0 && rect.height == size.height && rect.width == size.width);
    if (!IsHasCrop(rect) || isSameSize) {
        return CropValue::NOCROP;
    }
    bool isValid = ((rect.top >= 0 && rect.width > 0 && rect.left >= 0 && rect.height > 0) &&
                    (rect.top + rect.height <= size.height) && (rect.left + rect.width <= size.width));
    if (!isValid) {
        return CropValue::INVALID;
    }
    return CropValue::VALID;
}

CropValue PostProc::ValidCropValue(Rect &rect, const Size &size)
{
    CropValue res = GetCropValue(rect, size);
    if (res == CropValue::INVALID) {
        if (rect.top + rect.height > size.height) {
            rect.height = size.height - rect.top;
        }
        if (rect.left + rect.width > size.width) {
            rect.width = size.width - rect.left;
        }
        res = GetCropValue(rect, size);
    }
    return res;
}

bool PostProc::IsHasCrop(const Rect &rect)
{
    return (rect.top != 0 || rect.left != 0 || rect.width != 0 || rect.height != 0);
}

bool PostProc::HasPixelConvert(const ImageInfo &srcImageInfo, ImageInfo &dstImageInfo)
{
    dstImageInfo.alphaType = ImageUtils::GetValidAlphaTypeByFormat(dstImageInfo.alphaType, dstImageInfo.pixelFormat);
    return (dstImageInfo.pixelFormat != srcImageInfo.pixelFormat || dstImageInfo.alphaType != srcImageInfo.alphaType);
}

void PostProc::SetScanlineCropAndConvert(const Rect &cropRect, ImageInfo &dstImageInfo, ImageInfo &srcImageInfo,
                                         ScanlineFilter &scanlineFilter, bool hasPixelConvert)
{
    if (hasPixelConvert) {
        scanlineFilter.SetPixelConvert(srcImageInfo, dstImageInfo);
    }

    Rect srcRect = cropRect;
    if (IsHasCrop(cropRect)) {
        dstImageInfo.size.width = cropRect.width;
        dstImageInfo.size.height = cropRect.height;
    } else {
        srcRect = { 0, 0, srcImageInfo.size.width, srcImageInfo.size.height };
        dstImageInfo.size = srcImageInfo.size;
    }
    scanlineFilter.SetSrcRegion(srcRect);
}

#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(A_PLATFORM)
bool GetScaleFormat(const PixelFormat &format, AVPixelFormat &pixelFormat)
{
    if (format != PixelFormat::UNKNOWN) {
        auto formatPair = PIXEL_FORMAT_MAP.find(format);
        if (formatPair != PIXEL_FORMAT_MAP.end() && formatPair->second != 0) {
            pixelFormat = formatPair->second;
            return true;
        }
    }
    return false;
}

int GetInterpolation(const AntiAliasingOption &option)
{
    switch (option) {
        case AntiAliasingOption::NONE:
            return SWS_POINT;
        case AntiAliasingOption::LOW:
            return SWS_BILINEAR;
        case AntiAliasingOption::MEDIUM:
            return SWS_BICUBIC;
        case AntiAliasingOption::HIGH:
            return SWS_AREA;
        case AntiAliasingOption::FAST_BILINEAER:
            return SWS_FAST_BILINEAR;
        case AntiAliasingOption::BICUBLIN:
            return SWS_BICUBLIN;
        case AntiAliasingOption::GAUSS:
            return SWS_GAUSS;
        case AntiAliasingOption::SINC:
            return SWS_SINC;
        case AntiAliasingOption::LANCZOS:
            return SWS_LANCZOS;
        case AntiAliasingOption::SPLINE:
            return SWS_SPLINE;
        default:
            return SWS_POINT;
    }
}

bool PostProc::ScalePixelMapEx(const Size &desiredSize, PixelMap &pixelMap, const AntiAliasingOption &option)
{
    ImageTrace imageTrace("PixelMap ScalePixelMapEx");
    ImageInfo imgInfo;
    pixelMap.GetImageInfo(imgInfo);
    int32_t srcWidth = pixelMap.GetWidth();
    int32_t srcHeight = pixelMap.GetHeight();
    if (srcWidth <= 0 || srcHeight <= 0 || !pixelMap.GetWritablePixels()) {
        IMAGE_LOGE("pixelMap param is invalid, src width:%{public}d, height:%{public}d", srcWidth, srcHeight);
        return false;
    }
    AVPixelFormat pixelFormat;
    if (!GetScaleFormat(imgInfo.pixelFormat, pixelFormat)) {
        IMAGE_LOGE("pixelMap format is invalid, format: %{public}d", imgInfo.pixelFormat);
        return false;
    }
    uint32_t dstBufferSize = desiredSize.height * desiredSize.width * ImageUtils::GetPixelBytes(imgInfo.pixelFormat);
    MemoryData memoryData = {nullptr, dstBufferSize, "ScalePixelMapEx ImageData", desiredSize};
    
    auto mem = MemoryManager::CreateMemory(pixelMap.GetAllocatorType() == AllocatorType::CUSTOM_ALLOC ?
        AllocatorType::DEFAULT : pixelMap.GetAllocatorType(), memoryData);
    if (mem == nullptr) {
        IMAGE_LOGE("ScalePixelMapEx CreateMemory failed");
        return false;
    }

    const uint8_t *srcPixels[FFMPEG_NUM] = {};
    uint8_t *dstPixels[FFMPEG_NUM] = {};
    srcPixels[0] = pixelMap.GetPixels();
    dstPixels[0] = reinterpret_cast<uint8_t *>(mem->data.data);
    int srcRowStride[FFMPEG_NUM] = {};
    int dstRowStride[FFMPEG_NUM] = {};
    srcRowStride[0] = pixelMap.GetRowStride();
    if (mem->GetType() == AllocatorType::DMA_ALLOC) {
        dstRowStride[0] = reinterpret_cast<SurfaceBuffer*>(mem->extend.data)->GetStride();
    } else {
        dstRowStride[0] = desiredSize.width * ImageUtils::GetPixelBytes(imgInfo.pixelFormat);
    }
    SwsContext *swsContext = sws_getContext(srcWidth, srcHeight, pixelFormat, desiredSize.width, desiredSize.height,
        pixelFormat, GetInterpolation(option), nullptr, nullptr, nullptr);
    auto res = sws_scale(swsContext, srcPixels, srcRowStride, 0, srcHeight, dstPixels, dstRowStride);
    if (!res) {
        sws_freeContext(swsContext);
        mem->Release();
        IMAGE_LOGE("sws_scale failed");
        return false;
    }
    pixelMap.SetPixelsAddr(mem->data.data, mem->extend.data, dstBufferSize, mem->GetType(), nullptr);
    imgInfo.size = desiredSize;
    pixelMap.SetImageInfo(imgInfo, true);
    sws_freeContext(swsContext);
    return true;
}
#endif
} // namespace Media
} // namespace OHOS
