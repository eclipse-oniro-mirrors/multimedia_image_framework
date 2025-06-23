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

#include <memory>
#include <unistd.h>

#include "basic_transformer.h"
#include "image_log.h"
#include "image_system_properties.h"
#include "image_trace.h"
#include "image_type.h"
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
#include "vpe_utils.h"
#include "pixel_map_program_manager.h"
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
constexpr int SLR_CACHE_CAPACITY = 256;

#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
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
    if (opts.cropAndScaleStrategy == CropAndScaleStrategy::SCALE_FIRST && opts.desiredSize.height > 0 &&
        opts.desiredSize.width > 0) {
        CHECK_ERROR_RETURN_RET_LOG(!ScalePixelMap(opts.desiredSize, pixelMap), ERR_IMAGE_TRANSFORM,
            "[PostProc]scale:transform pixelMap failed");
        CHECK_ERROR_RETURN_RET_LOG(pixelMap.crop(opts.CropRect) != SUCCESS, ERR_IMAGE_TRANSFORM,
            "[PostProc]crop:transform pixelMap failed");
    } else {
        ImageInfo srcImageInfo;
        pixelMap.GetImageInfo(srcImageInfo);
        ImageInfo dstImageInfo;
        GetDstImageInfo(opts, pixelMap, srcImageInfo, dstImageInfo);
        uint32_t errorCode = ConvertProc(opts.CropRect, dstImageInfo, pixelMap, srcImageInfo);
        if (errorCode != SUCCESS) {
            IMAGE_LOGE("[PostProc]crop pixel map failed, errcode:%{public}u", errorCode);
            return errorCode;
        }
    }
    bool cond = false;
    decodeOpts_.allocatorType = opts.allocatorType;
    bool isNeedRotate = !ImageUtils::FloatCompareZero(opts.rotateDegrees);
    if (isNeedRotate) {
        cond = !RotatePixelMap(opts.rotateDegrees, pixelMap);
        CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_TRANSFORM, "[PostProc]rotate:transform pixel map failed");
    }
    decodeOpts_.allocatorType = opts.allocatorType;
    if (opts.desiredSize.height > 0 && opts.desiredSize.width > 0 &&
        opts.cropAndScaleStrategy != CropAndScaleStrategy::SCALE_FIRST) {
        cond = !ScalePixelMap(opts.desiredSize, pixelMap);
        CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_TRANSFORM, "[PostProc]scale:transform pixel map failed");
    } else if (opts.cropAndScaleStrategy != CropAndScaleStrategy::SCALE_FIRST) {
        ImageInfo info;
        pixelMap.GetImageInfo(info);
        if ((finalOutputStep == FinalOutputStep::DENSITY_CHANGE) && (info.baseDensity != 0)) {
            int targetWidth = (pixelMap.GetWidth() * opts.fitDensity + (info.baseDensity >> 1)) / info.baseDensity;
            int targetHeight = (pixelMap.GetHeight() * opts.fitDensity + (info.baseDensity >> 1)) / info.baseDensity;
            Size size;
            size.height = targetHeight;
            size.width = targetWidth;
            cond = !ScalePixelMap(size, pixelMap);
            CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_TRANSFORM,
                                       "[PostProc]density scale:transform pixel map failed");
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
    bool cond = !ScalePixelMap(scale, scale, pixelMap);
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "[PostProc]center scale pixelmap %{public}f fail", scale);
    srcWidth = pixelMap.GetWidth();
    srcHeight = pixelMap.GetHeight();
    if (srcWidth == targetWidth && srcHeight == targetHeight) {
        return true;
    }
    cond = srcWidth < targetWidth || srcHeight < targetHeight;
    CHECK_ERROR_RETURN_RET_LOG(cond, false,
        "[PostProc]src size [%{public}d, %{public}d] must less than dst size [%{public}d, %{public}d]",
        srcWidth, srcHeight, targetWidth, targetHeight);

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
    uint8_t *dstStartPixel = nullptr;
    uint8_t *srcStartPixel = nullptr;
    int32_t targetRowBytes = targetWidth * pixelBytes;
    if (targetRowStride <= 0) {
        targetRowStride = targetRowBytes;
    }
    int32_t srcRowBytes = srcWidth * pixelBytes;
    if (srcRowStride <= 0) {
        srcRowStride = srcRowBytes;
    }
    uint8_t *srcPixels = const_cast<uint8_t *>(pixelMap.GetPixels()) + top * srcRowStride + left * pixelBytes;
    bool cond = std::min(srcWidth, targetWidth) != 0 &&
        ImageUtils::CheckMulOverflow(std::min(srcWidth, targetWidth), pixelBytes);
    CHECK_ERROR_RETURN_RET_LOG(cond, false,
        "[PostProc]invalid params, srcWidth:%{public}d, targetWidth:%{public}d, pixelBytes:%{public}d",
        srcWidth, targetWidth, pixelBytes);
    uint32_t copyRowBytes = static_cast<uint32_t>(std::min(srcWidth, targetWidth) * pixelBytes);
    for (int32_t scanLine = 0; scanLine < std::min(srcHeight, targetHeight); scanLine++) {
        dstStartPixel = dstPixels + scanLine * targetRowStride;
        srcStartPixel = srcPixels + scanLine * srcRowStride;
        errno_t errRet = memcpy_s(dstStartPixel, static_cast<size_t>(targetRowBytes), srcStartPixel, copyRowBytes);
        CHECK_ERROR_RETURN_RET_LOG(errRet != EOK, false,
            "[PostProc]memcpy scanline %{public}d fail, errorCode = %{public}d", scanLine, errRet);
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
    bool cond = false;
    CHECK_ERROR_RETURN_RET_LOG(pixelMap.SetImageInfo(dstImageInfo, true) != SUCCESS, false, "update ImageInfo failed");
    int32_t bufferSize = pixelMap.GetByteCount();
    uint8_t *dstPixels = nullptr;
    void *nativeBuffer = nullptr;
    int fd = 0;
    int targetRowStride = 0;
    if (pixelMap.GetAllocatorType() == AllocatorType::HEAP_ALLOC) {
        cond = !AllocHeapBuffer(bufferSize, &dstPixels);
        CHECK_ERROR_RETURN_RET(cond, false);
    } else if (pixelMap.GetAllocatorType() == AllocatorType::DMA_ALLOC) {
        dstPixels = AllocDmaMemory(dstImageInfo, bufferSize, &nativeBuffer, targetRowStride);
    } else {
        dstPixels = AllocSharedMemory(dstImageInfo.size, bufferSize, fd, pixelMap.GetUniqueId());
    }
    cond = dstPixels == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, false,
                               "[PostProc]CenterDisplay AllocMemory[%{public}d] failed",
                               pixelMap.GetAllocatorType());
    if (!CopyPixels(pixelMap, dstPixels, dstImageInfo.size, srcWidth, srcHeight, srcRowStride, targetRowStride)) {
        IMAGE_LOGE("[PostProc]CopyPixels failed");
        ReleaseBuffer(pixelMap.GetAllocatorType(), fd, bufferSize, &dstPixels, nativeBuffer);
        return false;
    }
    void *fdBuffer = nullptr;
    if (pixelMap.GetAllocatorType() == AllocatorType::HEAP_ALLOC) {
        pixelMap.SetPixelsAddr(dstPixels, nullptr, bufferSize, AllocatorType::HEAP_ALLOC, nullptr);
    } else if (pixelMap.GetAllocatorType() == AllocatorType::DMA_ALLOC) {
#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
        sptr<SurfaceBuffer> sourceSurfaceBuffer(reinterpret_cast<SurfaceBuffer*> (pixelMap.GetFd()));
        sptr<SurfaceBuffer> dstSurfaceBuffer(reinterpret_cast<SurfaceBuffer*> (nativeBuffer));
        VpeUtils::CopySurfaceBufferInfo(sourceSurfaceBuffer, dstSurfaceBuffer);
#endif
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
        bool cond = ret != SUCCESS;
        CHECK_ERROR_RETURN_RET_LOG(cond, false, "[PostProc]scan line failed, ret:%{public}u", ret);
        scanLine++;
    }
    return true;
}

uint32_t PostProc::CheckScanlineFilter(const Rect &cropRect, ImageInfo &dstImageInfo, PixelMap &pixelMap,
                                       int32_t pixelBytes, ScanlineFilter &scanlineFilter)
{
    if (ImageUtils::CheckMulOverflow(dstImageInfo.size.width, dstImageInfo.size.height, pixelBytes)) {
        IMAGE_LOGE("[PostProc]size is too large, width:%{public}d, height:%{public}d",
                   dstImageInfo.size.width,  dstImageInfo.size.height);
        return ERR_IMAGE_CROP;
    }
    uint64_t bufferSize = static_cast<uint64_t>(dstImageInfo.size.width) *
            static_cast<uint64_t>(dstImageInfo.size.height) *
            static_cast<uint64_t>(pixelBytes);
    uint8_t *resultData = nullptr;
    int fd = 0;
    if (decodeOpts_.allocatorType == AllocatorType::SHARE_MEM_ALLOC) {
        resultData = AllocSharedMemory(dstImageInfo.size, bufferSize, fd, pixelMap.GetUniqueId());
        bool cond = resultData == nullptr;
        CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_CROP, "[PostProc]AllocSharedMemory failed");
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
    bool cond = ImageUtils::CheckMulOverflow(dstImageInfo.size.width, dstImageInfo.size.height, pixelBytes);
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_CROP,
        "[PostProc]size.width:%{public}d, size.height:%{public}d is too large",
        dstImageInfo.size.width, dstImageInfo.size.height);
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
        ReleaseBuffer(decodeOpts_.allocatorType, fd, bufferSize, &resultData);
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
    bool cond = false;
    if (pixelBytes == 0) {
        return ERR_IMAGE_CROP;
    }
    if (ImageUtils::CheckMulOverflow(imageInfo.size.width, imageInfo.size.height, pixelBytes)) {
        IMAGE_LOGE("[PostProc]size.width:%{public}d, size.height:%{public}d is too large",
            imageInfo.size.width, imageInfo.size.height);
        return ERR_IMAGE_CROP;
    }
    bufferSize = static_cast<uint64_t>(imageInfo.size.width) *
            static_cast<uint64_t>(imageInfo.size.height) *
            static_cast<uint64_t>(pixelBytes);
    IMAGE_LOGD("[PostProc]size.width:%{public}d, size.height:%{public}d, bufferSize:%{public}lld",
        imageInfo.size.width, imageInfo.size.height, static_cast<long long>(bufferSize));
    if (decodeOpts_.allocatorType == AllocatorType::SHARE_MEM_ALLOC) {
        *resultData = AllocSharedMemory(imageInfo.size, bufferSize, fd, id);
        cond = *resultData == nullptr;
        CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_CROP, "[PostProc]AllocSharedMemory failed");
    } else {
        cond = !AllocHeapBuffer(bufferSize, resultData);
        CHECK_ERROR_RETURN_RET(cond, ERR_IMAGE_CROP);
    }
    return SUCCESS;
}

bool PostProc::AllocHeapBuffer(uint64_t bufferSize, uint8_t **buffer)
{
    bool cond = bufferSize == 0 || bufferSize > MALLOC_MAX_LENTH;
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "[PostProc]Invalid value of bufferSize");
    *buffer = static_cast<uint8_t *>(malloc(bufferSize));
    CHECK_ERROR_RETURN_RET_LOG(*buffer == nullptr, false,
        "[PostProc]alloc covert color buffersize[%{public}llu] failed.", static_cast<unsigned long long>(bufferSize));
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
    CHECK_ERROR_RETURN_RET_LOG(fd < 0, nullptr, "[PostProc]AllocSharedMemory fd error, bufferSize %{public}lld",
        static_cast<long long>(bufferSize));
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

uint8_t *PostProc::AllocDmaMemory(ImageInfo info, const uint64_t bufferSize,
                                  void **nativeBuffer, int &targetRowStride)
{
#if defined(_WIN32) || defined(_APPLE) || defined(IOS_PLATFORM) || defined(ANDROID_PLATFORM)
    return nullptr;
#else
    MemoryData memoryData = {nullptr, (uint32_t)bufferSize, "PostProc", {info.size.width, info.size.height}};
    memoryData.format = info.pixelFormat;
    auto dstMemory = MemoryManager::CreateMemory(AllocatorType::DMA_ALLOC, memoryData);
    bool cond = dstMemory == nullptr;
    CHECK_ERROR_RETURN_RET(cond, nullptr);
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
            CHECK_ERROR_PRINT_LOG(err != OHOS::GSERROR_OK, "PostProc NativeBufferReference failed");
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
    bool cond = srcWidth <= 0 || srcHeight <= 0;
    CHECK_ERROR_RETURN_RET_LOG(cond, false,
        "[PostProc]src width:%{public}d, height:%{public}d is invalid.", srcWidth, srcHeight);
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

#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
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

static SkSLRCacheMgr GetNewSkSLRCacheMgr()
{
    static SkMutex slrMutex;
    static SLRLRUCache slrCache(SLR_CACHE_CAPACITY);
    return SkSLRCacheMgr(slrCache, slrMutex);
}

std::shared_ptr<SLRWeightTuple> initSLRFactor(Size srcSize, Size dstSize)
{
    bool cond = srcSize.width == 0 || srcSize.height == 0 || dstSize.width == 0 || dstSize.height == 0;
    CHECK_ERROR_RETURN_RET_LOG(cond, nullptr,
        "initSLRFactor invalid size, %{public}d, %{public}d, %{public}d, %{public}d",
        srcSize.width, srcSize.height, dstSize.width, dstSize.height);
    SkSLRCacheMgr cacheMgr = GetNewSkSLRCacheMgr();
    SLRWeightKey key(srcSize, dstSize);
    std::shared_ptr<SLRWeightTuple> weightTuplePtr = cacheMgr.find(key.fKey);
    if (weightTuplePtr == nullptr) {
        SLRWeightMat slrWeightX = SLRProc::GetWeights(static_cast<float>(dstSize.width) / srcSize.width,
            static_cast<int>(dstSize.width));
        SLRWeightMat slrWeightY = SLRProc::GetWeights(static_cast<float>(dstSize.height) / srcSize.height,
            static_cast<int>(dstSize.height));
        SLRWeightTuple value{slrWeightX, slrWeightY, key};
        std::shared_ptr<SLRWeightTuple> weightPtr = std::make_shared<SLRWeightTuple>(value);
        cacheMgr.insert(key.fKey, weightPtr);
        IMAGE_LOGI("initSLRFactor insert:%{public}d", key.fKey);
        return weightPtr;
    }
    return weightTuplePtr;
}

bool CheckPixelMapSLR(const Size &desiredSize, PixelMap &pixelMap)
{
    ImageInfo imgInfo;
    pixelMap.GetImageInfo(imgInfo);
    bool cond = imgInfo.pixelFormat != PixelFormat::RGBA_8888;
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "CheckPixelMapSLR only support RGBA_8888 format");
    int32_t srcWidth = pixelMap.GetWidth();
    int32_t srcHeight = pixelMap.GetHeight();
    cond = srcWidth <= 0 || srcHeight <= 0 || !pixelMap.GetWritablePixels();
    CHECK_ERROR_RETURN_RET_LOG(cond, false,
        "CheckPixelMapSLR invalid src size, %{public}d, %{public}d", srcWidth, srcHeight);

    cond = desiredSize.width <= 0 || desiredSize.height <= 0;
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "CheckPixelMapSLR invalid desired size, %{public}d, %{public}d",
        desiredSize.width, desiredSize.height);

    cond = desiredSize.width == srcWidth && desiredSize.height == srcHeight;
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "CheckPixelMapSLR same source and desired size, %{public}d, %{public}d",
        desiredSize.width, desiredSize.height);

    cond = static_cast<float>(desiredSize.width) / srcWidth < EPSILON ||
        static_cast<float>(desiredSize.height) / srcHeight < EPSILON;
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "CheckPixelMapSLR scaling factor overflow");

    int32_t pixelBytes = pixelMap.GetPixelBytes();
    CHECK_ERROR_RETURN_RET_LOG(pixelBytes <= 0, false, "CheckPixelMapSLR invalid pixel bytes, %{public}d", pixelBytes);

    uint64_t dstSizeOverflow =
        static_cast<uint64_t>(desiredSize.width) * static_cast<uint64_t>(desiredSize.height) *
        static_cast<uint64_t>(pixelBytes);
    CHECK_ERROR_RETURN_RET_LOG(dstSizeOverflow > UINT_MAX, false, "ScalePixelMapWithSLR desired size overflow");
    return true;
}

#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
static int g_minSize = 512;
static constexpr int g_maxTextureSize = 8192;
static bool CheckPixelMapSLR(PixelMap &pixelMap, const Size &desiredSize, GPUTransformData &trans)
{
    ImageInfo imgInfo;
    pixelMap.GetImageInfo(imgInfo);
    if (imgInfo.pixelFormat != PixelFormat::RGBA_8888) {
        IMAGE_LOGE("slr_gpu CheckPixelMapSLR only support RGBA_8888 format  %{public}d", imgInfo.pixelFormat);
        return false;
    }
    int32_t srcWidth = pixelMap.GetWidth();
    int32_t srcHeight = pixelMap.GetHeight();
    if (srcWidth <= 0 || srcHeight <= 0 || !pixelMap.GetWritablePixels()) {
        IMAGE_LOGE("slr_gpu CheckPixelMapSLR invalid src size, %{public}d, %{public}d", srcWidth, srcHeight);
        return false;
    }
    if (desiredSize.width <= 0 || desiredSize.height <= 0) {
        IMAGE_LOGE("slr_gpu CheckPixelMapSLR invalid desired size, %{public}d, %{public}d",
            desiredSize.width, desiredSize.height);
        return false;
    }
    int32_t pixelBytes = pixelMap.GetPixelBytes();
    if (pixelBytes <= 0) {
        IMAGE_LOGE("slr_gpu CheckPixelMapSLR invalid pixel bytes, %{public}d", pixelBytes);
        return false;
    }
    if (srcWidth > g_maxTextureSize || srcHeight > g_maxTextureSize) {
        IMAGE_LOGI("slr_gpu CheckPixelMapSLR The maximum width and height cannot exceed:%{public}d.", g_maxTextureSize);
        return false;
    }
    uint64_t dstSizeOverflow = static_cast<uint64_t>(desiredSize.width) * static_cast<uint64_t>(desiredSize.height) *
        static_cast<uint64_t>(pixelBytes);
    if (dstSizeOverflow > UINT_MAX) {
        IMAGE_LOGE("slr_gpu ScalePixelMapWithSLR desired size overflow");
        return false;
    }
    if (trans.transformationType == TransformationType::SCALE &&
        (srcWidth <= desiredSize.width || srcHeight <= desiredSize.height)) {
        IMAGE_LOGI("slr_gpu  CheckPixelMapSLR  failed. Only zoom-out is supported.");
        return false;
    }
    if (trans.transformationType == TransformationType::SCALE &&
        (srcWidth * srcHeight < g_minSize * g_minSize)) {
        IMAGE_LOGI("slr_gpu  CheckPixelMapSLR  failed. srcWidth * srcHeight < minSize * minSize.");
        return false;
    }
    if (trans.transformationType == TransformationType::ROTATE &&
        !(std::fabs(std::fmod(trans.rotateDegreeZ, 90.f)) < 1e-6)) {
        IMAGE_LOGI("slr_gpu  CheckPixelMapSLR  failed. Only 90* is supported.");
        return false;
    }
    return true;
}

static void GetPixelMapInfo(PixelMap &source, Size &size, GLenum &glFormat, int &perPixelSize)
{
    size = {
        .width = source.GetWidth(),
        .height = source.GetHeight(),
    };
    glFormat = GL_RGBA;
    perPixelSize = ImageUtils::GetPixelBytes(PixelFormat::RGBA_8888);
    PixelFormat originFormat = source.GetPixelFormat();
    switch (originFormat) {
        case PixelFormat::RGBA_8888:
            glFormat = GL_RGBA;
            break;
        case PixelFormat::RGB_565:
            glFormat = GL_RGB565;
            perPixelSize = ImageUtils::GetPixelBytes(PixelFormat::RGB_565);
            break;
        case PixelFormat::RGB_888:
            glFormat = GL_RGB;
            perPixelSize = ImageUtils::GetPixelBytes(PixelFormat::RGB_888);
            break;
        case PixelFormat::BGRA_8888:
            glFormat = GL_BGRA_EXT;
            break;
        case PixelFormat::ALPHA_8:
            glFormat = GL_ALPHA8_EXT;
            perPixelSize = ImageUtils::GetPixelBytes(PixelFormat::ALPHA_8);
            break;
        default:
            IMAGE_LOGE("slr_gpu %{public}s format %{public}d is not support! ", __func__, originFormat);
            break;
    }
}

static bool PixelMapPostProcWithGL(PixelMap &sourcePixelMap, GPUTransformData &trans, bool needHighQuality)
{
    Size &desiredSize = trans.targetInfo_.size;
    if (!CheckPixelMapSLR(sourcePixelMap, trans.targetInfo_.size, trans)) {
        return false;
    }
    Size sourceSize;
    GLenum glFormat = GL_RGBA;
    int perPixelSize = ImageUtils::GetPixelBytes(sourcePixelMap.GetPixelFormat());
    GetPixelMapInfo(sourcePixelMap, sourceSize, glFormat, perPixelSize);
    ImageTrace imageTrace("PixelMapPostProcWithGL (%d, %d)=>(%d, %d) stride %d type %d transtype:%d",
        sourceSize.width, sourceSize.height, desiredSize.width, desiredSize.height,
        sourcePixelMap.GetRowStride(), (int)sourcePixelMap.GetAllocatorType(), (int)trans.transformationType);
    IMAGE_LOGI("slr_gpu PixelMapPostProcWithGL uniqueId:%{public}d AllocatorType:%{public}d "
        "size (%{public}d, %{public}d)=>(%{public}d, %{public}d) stride %{public}d transtype:%{public}d",
        sourcePixelMap.GetUniqueId(), (int)sourcePixelMap.GetAllocatorType(), sourceSize.width, sourceSize.height,
        desiredSize.width, desiredSize.height, sourcePixelMap.GetRowStride(), (int)trans.transformationType);
    AllocatorType allocType = sourcePixelMap.GetAllocatorType();
    size_t buffersize = static_cast<size_t>(4 * desiredSize.width * desiredSize.height); // 4: 4 bytes per pixel
    MemoryData memoryData = {nullptr, buffersize, "PixelMapPostProcWithGL", desiredSize};
    std::unique_ptr<AbsMemory> dstMemory = MemoryManager::CreateMemory(allocType, memoryData);
    if (dstMemory == nullptr || dstMemory->data.data == nullptr) {
        IMAGE_LOGE("slr_gpu PixelMapPostProcWithGL dstMemory is null");
        return false;
    }
    int outputStride = 4 * desiredSize.width;
    if (allocType == AllocatorType::DMA_ALLOC) {
        SurfaceBuffer* sbBuffer = reinterpret_cast<SurfaceBuffer*>(dstMemory->extend.data);
        outputStride = sbBuffer->GetStride();
        buffersize = static_cast<uint32_t>(sbBuffer->GetStride() * desiredSize.height);
    }
    PixelMapProgramManager::BuildShader();
    bool ret = true;
    auto program = PixelMapProgramManager::GetInstance().GetProgram();
    if (program == nullptr) {
        IMAGE_LOGE("slr_gpu PixelMapPostProcWithGL %{public}s create gl context failed", __func__);
        ret = false;
    } else {
        trans.targetInfo_.stride = outputStride;
        trans.targetInfo_.pixelBytes = perPixelSize;
        trans.targetInfo_.outdata = dstMemory->data.data;
        trans.targetInfo_.context = dstMemory->extend.data;
        trans.glFormat = glFormat;
        trans.isDma = allocType == AllocatorType::DMA_ALLOC ? true : false;
        program->SetGPUTransformData(trans);
        ret = PixelMapProgramManager::GetInstance().ExecutProgram(program);
    }
    if (!ret) {
        dstMemory->Release();
        IMAGE_LOGE("slr_gpu PixelMapPostProcWithGL Resize failed");
        return false;
    }
    sourcePixelMap.SetPixelsAddr(dstMemory->data.data, dstMemory->extend.data,
        desiredSize.height * outputStride, allocType, nullptr);
    ImageInfo info;
    info.size = desiredSize;
    info.pixelFormat = PixelFormat::RGBA_8888;
    info.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    sourcePixelMap.SetImageInfo(info, true);
    return true;
}
#endif

bool PostProc::RotateInRectangularSteps(PixelMap &pixelMap, float degrees, bool useGpu)
{
#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    float oldDegrees = degrees;
    if (useGpu && ImageSystemProperties::GetGenThumbWithGpu() &&
        ImageSystemProperties::UseGPUScalingCapabilities() &&
        std::fabs(std::fmod(degrees, 90.f)) < 1e-6) { // degrees 90
        ImageTrace imageTrace("RotateInRectangularSteps:%f", degrees);
        IMAGE_LOGI("slr_gpu RotateInRectangularSteps in :%{public}f", degrees);
        GPUTransformData gpuTransform;
        ImageInfo imageInfo;
        pixelMap.GetImageInfo(imageInfo);
        GlCommon::Mat4 tmpMat4;
        std::array<float, 3> axis = { 0.0f, 0.0f, 1.0f }; // capacity 3
        float angle = degrees * M_PI / 180.f; // degrees 180
        gpuTransform.targetInfo_.size = {
            std::abs(imageInfo.size.width * std::cos(angle)) + std::abs(imageInfo.size.height * std::sin(angle)),
            std::abs(imageInfo.size.height * std::cos(angle)) + std::abs(imageInfo.size.width * std::sin(angle))
        };
        degrees = std::fmod(degrees, 360.f); // degrees 360
        degrees = std::fmod(360.f - degrees, 360.f); // degrees 360
        gpuTransform.rotateTrans = GlCommon::Mat4(tmpMat4, degrees, axis);
        gpuTransform.rotateDegreeZ = degrees;
        gpuTransform.sourceInfo_ = {
            .size = imageInfo.size,
            .stride = pixelMap.GetRowStride(),
            .pixelBytes = ImageUtils::GetPixelBytes(pixelMap.GetPixelFormat()),
            .addr = pixelMap.GetPixels(),
            .context = pixelMap.GetFd(),
        };
        gpuTransform.transformationType = TransformationType::ROTATE;
        if (PixelMapPostProcWithGL(pixelMap, gpuTransform, true)) {
            IMAGE_LOGI("slr_gpu RotateInRectangularSteps success");
            return true;
        }
        IMAGE_LOGI("slr_gpu RotateInRectangularSteps rotate with cpu");
    }
#endif
    pixelMap.rotate(oldDegrees);
    return true;
}

bool PostProc::ScalePixelMapWithGPU(PixelMap &pixelMap, const Size &desiredSize,
    const AntiAliasingOption &option, bool useGpu)
{
#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    if (useGpu && ImageSystemProperties::GetGenThumbWithGpu() &&
        ImageSystemProperties::UseGPUScalingCapabilities() &&
        option == AntiAliasingOption::HIGH) {
        ImageTrace imageTrace("ScalePixelMapWithGPU:wh(%d,%d)->(%d,%d)",
            pixelMap.GetWidth(), pixelMap.GetHeight(), desiredSize.width, desiredSize.height);
        IMAGE_LOGI("slr_gpu ScalePixelMapWithGPU:wh(%{public}d,%{public}d)->(%{public}d,%{public}d)",
            pixelMap.GetWidth(), pixelMap.GetHeight(), desiredSize.width, desiredSize.height);
        GPUTransformData gpuTransform;
        gpuTransform.targetInfo_.size = desiredSize;
        ImageInfo imageInfo;
        pixelMap.GetImageInfo(imageInfo);
        gpuTransform.sourceInfo_ = {
            .size = imageInfo.size,
            .stride = pixelMap.GetRowStride(),
            .pixelBytes = ImageUtils::GetPixelBytes(pixelMap.GetPixelFormat()),
            .addr = pixelMap.GetPixels(),
            .context = pixelMap.GetFd(),
        };
        gpuTransform.transformationType = TransformationType::SCALE;
        if (PixelMapPostProcWithGL(pixelMap, gpuTransform, true)) {
            IMAGE_LOGI("slr_gpu ScalePixelMapWithGPU success");
            return true;
        }
        IMAGE_LOGI("slr_gpu ScalePixelMapWithGPU failed scale with cpu");
    }
#endif
    PostProc postProc;
    return postProc.ScalePixelMapEx(desiredSize, pixelMap, option);
}

static std::unique_ptr<AbsMemory> CreateSLRMemory(PixelMap &pixelMap, uint32_t dstBufferSize, const Size &desiredSize,
    std::unique_ptr<AbsMemory> &dstMemory, bool useLap)
{
    AllocatorType allocatorType = pixelMap.GetAllocatorType();
    if (useLap && allocatorType == AllocatorType::DMA_ALLOC) {
        allocatorType = AllocatorType::SHARE_MEM_ALLOC;
    }
    MemoryData memoryData = {nullptr, dstBufferSize, "ScalePixelMapWithSLR ImageData", desiredSize,
        pixelMap.GetPixelFormat()};
    dstMemory = MemoryManager::CreateMemory(allocatorType, memoryData);
    CHECK_ERROR_RETURN_RET_LOG(dstMemory == nullptr, nullptr, "ScalePixelMapWithSLR create dstMemory failed");
    std::unique_ptr<AbsMemory> lapMemory = nullptr;
    if (useLap) {
        MemoryData lapMemoryData = {nullptr, dstBufferSize, "ScalePixelMapWithSLR ImageData Lap", desiredSize,
            pixelMap.GetPixelFormat()};
        lapMemory = MemoryManager::CreateMemory(pixelMap.GetAllocatorType(), lapMemoryData);
        if (lapMemory == nullptr) {
            IMAGE_LOGE("ScalePixelMapWithSLR create lapMemory failed");
            dstMemory->Release();
            return nullptr;
        }
    }
    return lapMemory;
}

float getLapFactor(const ImageInfo& imgInfo, const Size &desiredSize)
{
    float coeff = ((float)desiredSize.width) / imgInfo.size.width;
    if (coeff > 0.8f) {
        return .0f;
    }
    if (coeff > 0.6f) {
        return 0.06f;
    }
    if (coeff > 0.5f) {
        return 0.1f;
    }
    return 0.15f;
}

struct SLRContext {
    void *data;
    bool useLap;
};

bool ExecuteSLR(PixelMap& pixelMap, const Size& desiredSize, SLRMat &src, SLRMat &dst,
    SLRContext scalingContext)
{
    ImageInfo imgInfo;
    pixelMap.GetImageInfo(imgInfo);
    std::shared_ptr<SLRWeightTuple> weightTuplePtr = initSLRFactor(imgInfo.size, desiredSize);
    CHECK_ERROR_RETURN_RET_LOG(weightTuplePtr == nullptr, false, "PostProcExecuteSLR init failed");
    SLRWeightMat slrWeightX = std::get<0>(*weightTuplePtr);
    SLRWeightMat slrWeightY = std::get<1>(*weightTuplePtr);
    if (ImageSystemProperties::GetSLRParallelEnabled()) {
        SLRProc::Parallel(src, dst, slrWeightX, slrWeightY);
    } else {
        SLRProc::Serial(src, dst, slrWeightX, slrWeightY);
    }
    if (scalingContext.useLap) {
        float factor = getLapFactor(imgInfo, desiredSize);
        SLRProc::Laplacian(dst, scalingContext.data, factor);
    }
    return true;
}

bool PostProc::ScalePixelMapWithSLR(const Size &desiredSize, PixelMap &pixelMap, bool useLap)
{
    ImageInfo imgInfo;
    pixelMap.GetImageInfo(imgInfo);
    bool cond = !CheckPixelMapSLR(desiredSize, pixelMap);
    CHECK_ERROR_RETURN_RET(cond, false);
    useLap = useLap && ImageSystemProperties::GetSLRLaplacianEnabled();
    ImageTrace imageTrace("ScalePixelMapWithSLR");
    int32_t pixelBytes = pixelMap.GetPixelBytes();
    SLRMat src(imgInfo.size, imgInfo.pixelFormat, pixelMap.GetWritablePixels(), pixelMap.GetRowStride() / pixelBytes);
    uint32_t dstBufferSize = desiredSize.height * desiredSize.width * pixelBytes;
    std::unique_ptr<AbsMemory> m = nullptr;
    auto lapMemory = CreateSLRMemory(pixelMap, dstBufferSize, desiredSize, m, useLap);
    cond = m == nullptr || (useLap && (lapMemory == nullptr));
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "pixelMap scale slr memory nullptr");
    size_t rowStride;
    if (m->GetType() == AllocatorType::DMA_ALLOC) {
#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
        rowStride = reinterpret_cast<SurfaceBuffer*>(m->extend.data)->GetStride();
#endif
    } else {
        rowStride = desiredSize.width * pixelBytes;
    }
    void *data = useLap ? lapMemory->data.data : m->data.data;
    SLRMat dst({desiredSize.width, desiredSize.height}, imgInfo.pixelFormat, data, rowStride / pixelBytes);
    if (!ExecuteSLR(pixelMap, desiredSize, src, dst, {m->data.data, useLap})) {
        m->Release();
        if (useLap && lapMemory) {
            lapMemory->Release();
        }
        return false;
    }
    pixelMap.SetPixelsAddr(m->data.data, m->extend.data, dstBufferSize, m->GetType(), nullptr);
    imgInfo.size = desiredSize;
    pixelMap.SetImageInfo(imgInfo, true);
    if (m->GetType() == AllocatorType::DMA_ALLOC) {
        ImageUtils::FlushSurfaceBuffer(&pixelMap);
    }
    if (lapMemory) {
        lapMemory->Release();
    }
    return true;
}

bool PostProc::ScalePixelMapEx(const Size &desiredSize, PixelMap &pixelMap, const AntiAliasingOption &option)
{
    ImageTrace imageTrace("PixelMap ScalePixelMapEx, srcSize[%d, %d], dstSize[%d, %d] ",
        pixelMap.GetWidth(), pixelMap.GetHeight(), desiredSize.width, desiredSize.height);
    IMAGE_LOGI("slr_gpu ScalePixelMapEx pixelMap: width = %{public}d, height = %{public}d, pixelFormat = %{public}d, "
        "allocatorType = %{public}d; desiredSize: width = %{public}d, height = %{public}d",
        pixelMap.GetWidth(), pixelMap.GetHeight(), pixelMap.GetPixelFormat(),
        pixelMap.GetAllocatorType(), desiredSize.width, desiredSize.height);
    ImageInfo imgInfo;
    pixelMap.GetImageInfo(imgInfo);
    int32_t srcWidth = pixelMap.GetWidth();
    int32_t srcHeight = pixelMap.GetHeight();
    bool cond = srcWidth <= 0 || srcHeight <= 0 || !pixelMap.GetWritablePixels();
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "pixelMap param is invalid, src width:%{public}d, height:%{public}d",
        srcWidth, srcHeight);
    AVPixelFormat pixelFormat;
    cond = !GetScaleFormat(imgInfo.pixelFormat, pixelFormat);
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "pixelMap format is invalid, format: %{public}d", imgInfo.pixelFormat);
    uint64_t dstBufferSizeOverflow =
        static_cast<uint64_t>(desiredSize.width) * static_cast<uint64_t>(desiredSize.height) *
        static_cast<uint64_t>(ImageUtils::GetPixelBytes(imgInfo.pixelFormat));
    CHECK_ERROR_RETURN_RET_LOG(dstBufferSizeOverflow > UINT_MAX, false, "ScalePixelMapEx target size too large");
    uint32_t dstBufferSize = static_cast<uint32_t>(dstBufferSizeOverflow);
    MemoryData memoryData = {nullptr, dstBufferSize, "ScalePixelMapEx ImageData", desiredSize};

    auto mem = MemoryManager::CreateMemory(pixelMap.GetAllocatorType() == AllocatorType::CUSTOM_ALLOC ?
        AllocatorType::DEFAULT : pixelMap.GetAllocatorType(), memoryData);
    CHECK_ERROR_RETURN_RET_LOG(mem == nullptr, false, "ScalePixelMapEx CreateMemory failed");

    const uint8_t *srcPixels[FFMPEG_NUM] = {};
    uint8_t *dstPixels[FFMPEG_NUM] = {};
    srcPixels[0] = pixelMap.GetPixels();
    dstPixels[0] = reinterpret_cast<uint8_t *>(mem->data.data);
    int srcRowStride[FFMPEG_NUM] = {};
    int dstRowStride[FFMPEG_NUM] = {};
    srcRowStride[0] = pixelMap.GetRowStride();
    dstRowStride[0] = (mem->GetType() == AllocatorType::DMA_ALLOC) ?
        reinterpret_cast<SurfaceBuffer*>(mem->extend.data)->GetStride() :
        desiredSize.width * ImageUtils::GetPixelBytes(imgInfo.pixelFormat);

    void *inBuf = nullptr;
    if (srcWidth % HALF != 0 && pixelMap.GetAllocatorType() == AllocatorType::SHARE_MEM_ALLOC) {
        // Workaround for crash on odd number width, caused by FFmpeg 5.0 upgrade
        uint64_t byteCount = static_cast<uint64_t>(srcRowStride[0]) * static_cast<uint64_t>(srcHeight);
        uint64_t allocSize = static_cast<uint64_t>(srcWidth + 1) * static_cast<uint64_t>(srcHeight) *
            static_cast<uint64_t>(ImageUtils::GetPixelBytes(imgInfo.pixelFormat));
        if (srcRowStride[0] <= 0 || byteCount > UINT_MAX || allocSize < byteCount || allocSize > UINT_MAX) {
            mem->Release();
            IMAGE_LOGE("ScalePixelMapEx invalid srcRowStride or pixelMap size too large");
            return false;
        }
        inBuf = malloc(allocSize);
        srcPixels[0] = reinterpret_cast<uint8_t*>(inBuf);
        errno_t errRet = memcpy_s(inBuf, allocSize, pixelMap.GetWritablePixels(), byteCount);
        if (errRet != EOK) {
            if (inBuf != nullptr) {
                free(inBuf);
            }
            mem->Release();
            IMAGE_LOGE("ScalePixelMapEx memcpy_s failed with error code: %{public}d", errRet);
            return false;
        }
    }

    SwsContext *swsContext = sws_getContext(srcWidth, srcHeight, pixelFormat, desiredSize.width, desiredSize.height,
        pixelFormat, GetInterpolation(option), nullptr, nullptr, nullptr);
    if (swsContext == nullptr) {
        if (inBuf != nullptr) {
            free(inBuf);
        }
        mem->Release();
        IMAGE_LOGE("sws_getContext failed");
        return false;
    }
    auto res = sws_scale(swsContext, srcPixels, srcRowStride, 0, srcHeight, dstPixels, dstRowStride);

    sws_freeContext(swsContext);
    if (inBuf != nullptr) {
        free(inBuf);
    }
    if (!res) {
        mem->Release();
        IMAGE_LOGE("sws_scale failed");
        return false;
    }
    pixelMap.SetPixelsAddr(mem->data.data, mem->extend.data, dstBufferSize, mem->GetType(), nullptr);
    imgInfo.size = desiredSize;
    pixelMap.SetImageInfo(imgInfo, true);
    return true;
}
#endif
} // namespace Media
} // namespace OHOS
