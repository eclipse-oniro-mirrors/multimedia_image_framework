/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "hispeed_image_manager.h"

#ifdef USE_M133_SKIA
#include "src/encode/SkImageEncoderFns.h"
#include "include/core/SkStream.h"
#else
#include "include/core/SkImageEncoder.h"
#include "src/images/SkImageEncoderFns.h"
#endif

#include <dlfcn.h>
#include <string>
#include "image_log.h"
#include "image_func_timer.h"
#include "pixel_map.h"
#include "image/abs_image_encoder.h"
#include "media_errors.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "HispeedImageManager"
namespace {
constexpr uint32_t TWO_SLICES = 2;
constexpr uint32_t BYTES_PER_PIXEL_RGBA = 4;
constexpr int PIXEL_FORMAT_NV12 = 0;
constexpr int PIXEL_FORMAT_NV21 = 1;
}  // namespace
static const std::string HISPEED_IMAGE_SO = "libhispeed_image.so";

namespace OHOS {
namespace Media {

HispeedImageManager::HispeedImageManager()
{
#if !defined(CROSS_PLATFORM)
    hispeedImageSoHandle_ = nullptr;
    jpegEncoderCreateFunc_ = nullptr;
    jpegEncoderSetQualityFunc_ = nullptr;
    jpegEncoderSetSubsamplingFunc_ = nullptr;
    jpegEncoderSetICCMetadataFunc_ = nullptr;
    jpegEncoderEncodeFunc_ = nullptr;
    jpegEncoderDestroyFunc_ = nullptr;
    yuv10ToRgb10Func_ = nullptr;
    yuv10ToRgb8888Func_ = nullptr;
    isHispeedImageSoOpened_ = false;
    LoadHispeedImageSo();
#endif
}

HispeedImageManager::~HispeedImageManager()
{
#if !defined(CROSS_PLATFORM)
    UnloadHispeedImageSo();
#endif
}

bool HispeedImageManager::LoadYuvJpegEncoderSym()
{
#if !defined(CROSS_PLATFORM)
    jpegEncoderCreateFunc_ =
        reinterpret_cast<YuvJpegEncoderCreateFunc>(dlsym(hispeedImageSoHandle_, "HSD_Image_JpegEncoderCreate"));
    jpegEncoderSetQualityFunc_ =
        reinterpret_cast<YuvJpegEncoderSetQualityFunc>(dlsym(hispeedImageSoHandle_, "HSD_Image_JpegEncoderSetQuality"));
    jpegEncoderSetSubsamplingFunc_ = reinterpret_cast<YuvJpegEncoderSetSubsamplingFunc>(
        dlsym(hispeedImageSoHandle_, "HSD_Image_JpegEncoderSetSubsampling"));
    jpegEncoderSetICCMetadataFunc_ = reinterpret_cast<YuvJpegEncoderSetIccMetadataFunc>(
        dlsym(hispeedImageSoHandle_, "HSD_Image_JpegEncoderSetIccMetadata"));
    jpegEncoderEncodeFunc_ =
        reinterpret_cast<YuvJpegEncoderEncodeFunc>(dlsym(hispeedImageSoHandle_, "HSD_Image_JpegEncoderEncode"));
    jpegEncoderDestroyFunc_ =
        reinterpret_cast<YuvJpegEncoderDestroyFunc>(dlsym(hispeedImageSoHandle_, "HSD_Image_JpegEncoderDestroy"));
    if (jpegEncoderCreateFunc_ == nullptr || jpegEncoderSetQualityFunc_ == nullptr ||
        jpegEncoderSetSubsamplingFunc_ == nullptr || jpegEncoderSetICCMetadataFunc_ == nullptr ||
        jpegEncoderEncodeFunc_ == nullptr || jpegEncoderDestroyFunc_ == nullptr) {
        IMAGE_LOGE("HispeedImageManager LoadYuvJpegEncoderSym failed");
        return false;
    }
    IMAGE_LOGI("HispeedImageManager LoadYuvJpegEncoderSym success");
    return true;
#else
    return false;
#endif
}

bool HispeedImageManager::LoadYuvConvertSym()
{
#if !defined(CROSS_PLATFORM)
    yuv10ToRgb10Func_ = reinterpret_cast<Yuv10ToRgb10Func>(dlsym(hispeedImageSoHandle_, "HSD_Image_P010ToAR30"));
    if (yuv10ToRgb10Func_ == nullptr) {
        IMAGE_LOGE("yuv10ToRgb10Func_ dlsym failed");
        return false;
    }
    yuv10ToRgb8888Func_ = reinterpret_cast<Yuv10ToRgb8888Func>(dlsym(hispeedImageSoHandle_, "HSD_Image_P010ToARGB"));
    if (yuv10ToRgb8888Func_ == nullptr) {
        IMAGE_LOGE("yuv10ToRgb8888Func_ dlsym failed");
        return false;
    }
    yuvConstants[HSD_BT601_LIMIT] = reinterpret_cast<int*>(dlsym(hispeedImageSoHandle_, "HSD_IMAGE_YUV_I601"));
    yuvConstants[HSD_BT601_FULL] = reinterpret_cast<int*>(dlsym(hispeedImageSoHandle_, "HSD_IMAGE_YUV_JPEG"));
    yuvConstants[HSD_BT709_LIMIT] = reinterpret_cast<int*>(dlsym(hispeedImageSoHandle_, "HSD_IMAGE_YUV_H709"));
    yuvConstants[HSD_BT709_FULL] = reinterpret_cast<int*>(dlsym(hispeedImageSoHandle_, "HSD_IMAGE_YUV_F709"));
    yuvConstants[HSD_BT2020_LIMIT] = reinterpret_cast<int*>(dlsym(hispeedImageSoHandle_, "HSD_IMAGE_YUV_2020"));
    yuvConstants[HSD_BT2020_FULL] = reinterpret_cast<int*>(dlsym(hispeedImageSoHandle_, "HSD_IMAGE_YUV_V2020"));
    for (int i = 0; i < NUM_OF_YUV_CONSTANTS; i++) {
        if (yuvConstants[i] == nullptr) {
            IMAGE_LOGE("yuvConstants[%d] dlsym failed", i);
            return false;
        }
    }
    return true;
#else
    return false;
#endif
}

bool HispeedImageManager::LoadHispeedImageSo()
{
#if !defined(CROSS_PLATFORM)
    ImageFuncTimer imageFuncTimer(__func__);
    if (!isHispeedImageSoOpened_) {
        hispeedImageSoHandle_ = dlopen(HISPEED_IMAGE_SO.c_str(), RTLD_LAZY);
        if (hispeedImageSoHandle_ == nullptr) {
            IMAGE_LOGE("%{public}s dlopen failed", HISPEED_IMAGE_SO.c_str());
            return false;
        }
        if (LoadYuvJpegEncoderSym() == false) {
            UnloadHispeedImageSo();
            return false;
        }
        if (LoadYuvConvertSym() == false) {
            UnloadHispeedImageSo();
            return false;
        }
        isHispeedImageSoOpened_ = true;
    }
    return true;
#else
    return false;
#endif
}

void HispeedImageManager::UnloadHispeedImageSo()
{
#if !defined(CROSS_PLATFORM)
    if (hispeedImageSoHandle_ != nullptr) {
        if (dlclose(hispeedImageSoHandle_)) {
            IMAGE_LOGD("hispeedImageSoHandle dlclose failed: %{public}s", HISPEED_IMAGE_SO.c_str());
        } else {
            IMAGE_LOGD("hispeedImageSoHandle dlclose success: %{public}s", HISPEED_IMAGE_SO.c_str());
        }
    }

    hispeedImageSoHandle_ = nullptr;
    jpegEncoderCreateFunc_ = nullptr;
    jpegEncoderSetQualityFunc_ = nullptr;
    jpegEncoderSetSubsamplingFunc_ = nullptr;
    jpegEncoderSetICCMetadataFunc_ = nullptr;
    jpegEncoderEncodeFunc_ = nullptr;
    jpegEncoderDestroyFunc_ = nullptr;
    yuv10ToRgb10Func_ = nullptr;
    yuv10ToRgb8888Func_ = nullptr;
    isHispeedImageSoOpened_ = false;
#endif
}

YuvJpegEncoder HispeedImageManager::InitJpegEncoder(uint8_t quality)
{
#if !defined(CROSS_PLATFORM)
    if (isHispeedImageSoOpened_ == false && LoadHispeedImageSo() == false) {
        IMAGE_LOGE("hispeed image so not opened");
        return nullptr;
    }

    YuvJpegEncoder encoder = jpegEncoderCreateFunc_();
    if (encoder == nullptr) {
        IMAGE_LOGE("create jpeg encoder failed");
        return nullptr;
    }

    int result = jpegEncoderSetQualityFunc_(encoder, quality);
    if (result != 0) {
        jpegEncoderDestroyFunc_(encoder);
        return nullptr;
    }

    return encoder;
#else
    return nullptr;
#endif
}

void HispeedImageManager::JpegEncoderAppendICC(YuvJpegEncoder encoder, SkImageInfo info)
{
#if !defined(CROSS_PLATFORM)
    if (isHispeedImageSoOpened_ == false || jpegEncoderSetICCMetadataFunc_ == nullptr) {
        IMAGE_LOGE("open hispeed image so occurs error");
        return;
    }
#ifdef USE_M133_SKIA
    sk_sp<SkData> iccProfile = icc_from_color_space(info, nullptr, nullptr);
#else
    sk_sp<SkData> iccProfile = icc_from_color_space(info);
#endif
    if (iccProfile == nullptr) {
        IMAGE_LOGE("JpegEncoderAppendICC: iccProfile is null");
        return;
    }

    static constexpr uint8_t kICCSig[] = {
        'I', 'C', 'C', '_', 'P', 'R', 'O', 'F', 'I', 'L', 'E', '\0',
    };
    SkDynamicMemoryWStream s;
    s.write(kICCSig, sizeof(kICCSig));
    s.write8(1);  // 1:This is the first marker.
    s.write8(1);  // 1:Out of one total markers.
    s.write(iccProfile->data(), iccProfile->size());
    sk_sp<SkData> iccData = s.detachAsData();
    jpegEncoderSetICCMetadataFunc_(encoder, iccData->bytes(), iccData->size());
#endif
}

uint32_t HispeedImageManager::DoEncodeJpeg(
    void *skStream, OHOS::Media::PixelMap* pixelMap, uint8_t quality, SkImageInfo info)
{
#if !defined(CROSS_PLATFORM)
    bool cond = pixelMap == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_ENCODE_FAILED, "pixelMap is nullptr");
    cond = skStream == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_ENCODE_FAILED, "HispeedImageManager::DoEncodeJpeg: skStream is null");
    ImageFuncTimer imageFuncTimer("HispeedImageManager::%s:(%d, %d)", __func__,
        pixelMap->GetWidth(), pixelMap->GetHeight());

    uint8_t* srcData = static_cast<uint8_t*>(pixelMap->GetWritablePixels());
    cond = srcData == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_ENCODE_FAILED, "cannot get writable pixels from pixelMap");

    ImageInfo imageInfo;
    pixelMap->GetImageInfo(imageInfo);
    cond = imageInfo.size.width != pixelMap->GetRowStride();
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_ENCODE_FAILED, "hispeed invalid width mismatch stride");
    if (imageInfo.pixelFormat != PixelFormat::NV12 && imageInfo.pixelFormat != PixelFormat::NV21) {
        IMAGE_LOGE("unsupported pixel format: %{public}d", imageInfo.pixelFormat);
        return ERR_IMAGE_ENCODE_FAILED;
    }

    YuvJpegEncoder encoder = InitJpegEncoder(quality);
    if (encoder == nullptr) {
        IMAGE_LOGE("hispeed init jpeg encoder failed");
        return ERR_IMAGE_ENCODE_FAILED;
    }
    JpegEncoderAppendICC(encoder, info);

    auto writeDef = [](void *opaque, const void* buffer, size_t size) -> bool {
        if (opaque == NULL) { return false; }
        return ((SkWStream *)opaque)->write(buffer, size);
    };
    auto flushDef = [](void *opaque) {
        if (opaque == NULL) { return; }
        ((SkWStream *)opaque)->flush();
    };
    int format = (imageInfo.pixelFormat == PixelFormat::NV12) ? PIXEL_FORMAT_NV12 : PIXEL_FORMAT_NV21;
    int result = jpegEncoderEncodeFunc_(
        encoder, srcData, imageInfo.size.width, imageInfo.size.height, format, writeDef, flushDef, skStream);
    if (result != SUCCESS) {
        IMAGE_LOGE("jpeg encode failed, result: %{public}d", result);
        DestroyJpegEncoder(encoder);
        return ERR_IMAGE_ENCODE_FAILED;
    }

    return SUCCESS;
#else
    return ERR_IMAGE_ENCODE_FAILED;
#endif
}

void HispeedImageManager::DestroyJpegEncoder(YuvJpegEncoder encoder)
{
#if !defined(CROSS_PLATFORM)
    if (isHispeedImageSoOpened_ == false ||
        jpegEncoderDestroyFunc_ == nullptr) {
        IMAGE_LOGE("open hispeed image so occurs error");
        return;
    }

    jpegEncoderDestroyFunc_(encoder);
#endif
}

void HispeedImageManager::YuvConvertPara(
    const YUVDataInfo& yDInfo, SrcConvertParam& srcParam, DestConvertParam& destParam, DestConvertInfo& destInfo)
{
#if !defined(CROSS_PLATFORM)
    srcParam.slice[0] = srcParam.buffer + yDInfo.yOffset;
    srcParam.slice[1] = srcParam.buffer + yDInfo.uvOffset * TWO_SLICES;
    srcParam.stride[0] = static_cast<int>(yDInfo.yStride);
    srcParam.stride[1] = static_cast<int>(yDInfo.uvStride);
    int dstStride = 0;
    if (destInfo.allocType == AllocatorType::DMA_ALLOC) {
        dstStride = static_cast<int>(destInfo.yStride);
        destParam.slice[0] = destInfo.buffer + destInfo.yOffset;
    } else {
        dstStride = static_cast<int>(destParam.width * BYTES_PER_PIXEL_RGBA);
        destParam.slice[0] = destInfo.buffer;
    }
    destParam.stride[0] = dstStride;
    destParam.yuvConvertCSDetails = destInfo.yuvConvertCSDetails;
#endif
}
const int* HispeedImageManager::GetYuvCoeffFromDest(const DestConvertParam &destParam)
{
#if !defined(CROSS_PLATFORM)
    bool isFullRange = destParam.yuvConvertCSDetails.srcRange != 0; // 0: limit range, 1: full range
    const int* yuvConstantGet = nullptr;
    switch (destParam.yuvConvertCSDetails.srcYuvConversion) {
        case YuvConversion::BT601:
            yuvConstantGet = isFullRange ?
                yuvConstants[HSD_BT601_FULL]  // BT.601 full
                : yuvConstants[HSD_BT601_LIMIT]; // BT.601 limit
            break;
        case YuvConversion::BT709:
            yuvConstantGet = isFullRange ?
                yuvConstants[HSD_BT709_FULL]  // BT.709 full
                : yuvConstants[HSD_BT709_LIMIT]; // BT.709 limit
            break;
        case YuvConversion::BT2020:
            yuvConstantGet = isFullRange ?
                yuvConstants[HSD_BT2020_FULL]  // BT.2020 full
                : yuvConstants[HSD_BT2020_LIMIT]; // BT.2020 limit
            break;
        default:
            if (destParam.format == PixelFormat::RGBA_1010102) {
                yuvConstantGet = isFullRange ?
                    yuvConstants[HSD_BT2020_FULL]  // BT.2020 full
                    : yuvConstants[HSD_BT2020_LIMIT]; // BT.2020 limit
            } else {
                yuvConstantGet = isFullRange ?
                    yuvConstants[HSD_BT601_FULL]  // BT.601 full
                    : yuvConstants[HSD_BT601_LIMIT]; // BT.601 limit
            }
    }
    return yuvConstantGet;
#else
    return nullptr;
#endif
}

bool HispeedImageManager::P010ToARGB(const uint8_t* srcBuffer, const YUVDataInfo& yDInfo, DestConvertInfo& destInfo)
{
#if !defined(CROSS_PLATFORM)
    if (isHispeedImageSoOpened_ == false && LoadHispeedImageSo() == false) {
        IMAGE_LOGE("hispeed image so not opened");
        return false;
    }
    SrcConvertParam srcParam = {yDInfo.yWidth, yDInfo.yHeight};
    srcParam.buffer = srcBuffer;
    DestConvertParam destParam = {yDInfo.yWidth, yDInfo.yHeight};
    YuvConvertPara(yDInfo, srcParam, destParam, destInfo);
    int ret = yuv10ToRgb8888Func_(reinterpret_cast<const uint16_t*>(srcParam.slice[0]),
        srcParam.stride[0],
        reinterpret_cast<const uint16_t*>(srcParam.slice[1]),
        srcParam.stride[1],
        destParam.slice[0],
        destParam.stride[0],
        destParam.width,
        destParam.height,
        nullptr);
    if (ret != SUCCESS) {
        IMAGE_LOGE("hispeed image so yuv10ToRgb8888 failed");
        return false;
    }
    return true;
#else
    return false;
#endif
}

bool HispeedImageManager::P010ToAR30(const uint8_t* srcBuffer, const YUVDataInfo& yDInfo, DestConvertInfo& destInfo)
{
#if !defined(CROSS_PLATFORM)
    if (isHispeedImageSoOpened_ == false && LoadHispeedImageSo() == false) {
        IMAGE_LOGE("hispeed image so not opened");
        return false;
    }
    SrcConvertParam srcParam = {yDInfo.yWidth, yDInfo.yHeight};
    srcParam.buffer = srcBuffer;
    DestConvertParam destParam = {yDInfo.yWidth, yDInfo.yHeight};
    YuvConvertPara(yDInfo, srcParam, destParam, destInfo);
    const int* yuvConstantGet = GetYuvCoeffFromDest(destParam);
    int ret = yuv10ToRgb10Func_(reinterpret_cast<const uint16_t*>(srcParam.slice[0]),
        srcParam.stride[0],
        reinterpret_cast<const uint16_t*>(srcParam.slice[1]),
        srcParam.stride[1],
        destParam.slice[0],
        destParam.stride[0],
        destParam.width,
        destParam.height,
        yuvConstantGet);
    if (ret != SUCCESS) {
        IMAGE_LOGE("hispeed image so yuv10ToRgb10 failed");
        return false;
    }
    return true;
#else
    return false;
#endif
}
}  // namespace Media
}  // namespace OHOS