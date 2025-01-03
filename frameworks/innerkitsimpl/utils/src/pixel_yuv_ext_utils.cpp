/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "pixel_yuv_ext_utils.h"

#include "image_log.h"
#include "ios"
#include "istream"
#include "image_trace.h"
#include "image_system_properties.h"
#include "media_errors.h"
#include "securec.h"
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
#include "surface_buffer.h"
#endif

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "PixelYuvExtUtils"

namespace OHOS {
namespace Media {

static const uint8_t NUM_2 = 2;
static const uint8_t NUM_4 = 4;
static const uint32_t BYTE_PER_PIXEL = 2;
static const float ROUND_FLOAT_NUMBER = 0.5f;

static const std::map<PixelFormat, AVPixelFormat> FFMPEG_PIXEL_FORMAT_MAP = {
    {PixelFormat::UNKNOWN, AVPixelFormat::AV_PIX_FMT_NONE},
    {PixelFormat::NV21, AVPixelFormat::AV_PIX_FMT_NV21},
    {PixelFormat::NV12, AVPixelFormat::AV_PIX_FMT_NV12},
    {PixelFormat::ARGB_8888, AVPixelFormat::AV_PIX_FMT_ARGB},
    {PixelFormat::BGRA_8888, AVPixelFormat::AV_PIX_FMT_BGRA},
};

static int32_t GetYSize(int32_t width, int32_t height)
{
    return width * height;
}

static int32_t GetVOffset(int32_t width, int32_t height)
{
    return width * height + ((width + 1) / NUM_2) * ((height + 1) / NUM_2);
}

static int32_t GetUStride(int32_t width)
{
    return (width + 1) / NUM_2;
}

static int32_t GetUVHeight(int32_t height)
{
    return (height + 1) / NUM_2;
}

// Yuv420SP, u、 v blend planer
static int32_t GetUVStride(int32_t width)
{
    return (width + 1) / NUM_2 * NUM_2;
}

static uint32_t GetImageSize(int32_t width, int32_t height)
{
    return width * height + ((width + 1) / NUM_2) * ((height + 1) / NUM_2) * NUM_2;
}

bool PixelYuvExtUtils::BGRAToYuv420(const uint8_t *src, uint8_t *dst, int srcW, int srcH,
    PixelFormat pixelFormat, YUVDataInfo &info)
{
    auto converter = ConverterHandle::GetInstance().GetHandle();
    int32_t r = 0;
    if (pixelFormat == PixelFormat::NV12) {
        r = converter.ARGBToNV12(src, srcW * NUM_4,
                                 dst, info.yStride,
                                 dst + info.uvOffset,
                                 info.uvStride, srcW, srcH);
    } else if (pixelFormat == PixelFormat::NV21) {
        r = converter.ARGBToNV21(src, srcW * NUM_4,
                                 dst, info.yStride,
                                 dst + info.uvOffset,
                                 info.uvStride, srcW, srcH);
    }
    return r == 0;
}

bool PixelYuvExtUtils::Yuv420ToBGRA(const uint8_t *sample, uint8_t *dstArgb,
    Size &size, PixelFormat pixelFormat, YUVDataInfo &info)
{
    info.uvStride = (info.uvStride +1) & ~1;
    const uint8_t *srcY = sample + info.yOffset;
    const uint8_t *srcUV = sample + info.uvOffset;
    const uint32_t dstStrideARGB = static_cast<uint32_t>(size.width) * NUM_4;
    auto converter = ConverterHandle::GetInstance().GetHandle();
    if (pixelFormat == PixelFormat::NV12) {
        converter.NV12ToARGB(srcY, info.yStride, srcUV, info.uvStride,
            dstArgb, dstStrideARGB, size.width, size.height);
    } else if (pixelFormat == PixelFormat::NV21) {
        converter.NV21ToARGB(srcY, info.yStride, srcUV, info.uvStride,
            dstArgb, dstStrideARGB, size.width, size.height);
    }
    return true;
}

bool PixelYuvExtUtils::Yuv420ToARGB(const uint8_t *sample, uint8_t *dstArgb,
    Size &size, PixelFormat pixelFormat, YUVDataInfo &info)
{
    std::unique_ptr<uint8_t[]> temp = std::make_unique<uint8_t[]>(size.width * size.height * NUM_4);
    if (!Yuv420ToBGRA(sample, temp.get(), size, pixelFormat, info)) {
        IMAGE_LOGE("Yuv420ToBGRA failed");
        return false;
    }
    auto converter = ConverterHandle::GetInstance().GetHandle();
    bool cond = converter.ARGBToBGRA(temp.get(), size.width * NUM_4, dstArgb,
                size.width * NUM_4, size.width, size.height) != SUCCESS;
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "ARGBToBGRA failed");
    return true;
}


bool PixelYuvExtUtils::NV12Rotate(uint8_t *src, PixelSize &size, YUVDataInfo &info,
    OpenSourceLibyuv::RotationMode &rotateNum, uint8_t* dst, YUVStrideInfo &dstStrides)
{
    std::unique_ptr<uint8_t[]> tmpPixels = std::make_unique<uint8_t[]>(GetImageSize(size.dstW, size.dstH));
    uint8_t *srcY = src + info.yOffset;
    uint8_t *srcUV = src + info.uvOffset;
    uint8_t *tmpY = tmpPixels.get();
    uint8_t *tmpU = tmpPixels.get()+ GetYSize(size.dstW, size.dstH);
    uint8_t *tmpV = tmpPixels.get()+ GetVOffset(size.dstW, size.dstH);

    auto converter = ConverterHandle::GetInstance().GetHandle();

    int srcYStride = static_cast<int>(info.yStride);
    int srcUVStride = static_cast<int>(info.uvStride);
    int tmpYStride = size.dstW;
    int tmpUStride = GetUStride(size.dstW);
    int tmpVStride =  GetUStride(size.dstW);
    if (converter.NV12ToI420Rotate(srcY, srcYStride, srcUV, srcUVStride,
        tmpY, tmpYStride,
        tmpU, tmpUStride,
        tmpV, tmpVStride,
        size.srcW, size.srcH, rotateNum) == -1) {
        return false;
    }

    int dstYStride = static_cast<int>(dstStrides.yStride);
    int dstUVStride = static_cast<int>(dstStrides.uvStride);
    int dstWidth = size.dstW;
    int dstHeight = size.dstH;
    auto dstY = dst + dstStrides.yOffset;
    auto dstUV = dst + dstStrides.uvOffset;
    if (converter.I420ToNV12(tmpY, tmpYStride, tmpU, tmpUStride, tmpV, tmpVStride,
        dstY, dstYStride, dstUV, dstUVStride, dstWidth, dstHeight) == -1) {
        return false;
    }

    return true;
}

static bool NV12P010Rotate(YuvPixels yuvPixels, PixelSize& size, YUVDataInfo& info,
    OpenSourceLibyuv::RotationMode& rotateNum, YUVStrideInfo& dstStrides)
{
    std::unique_ptr<uint16_t[]> dstPixels = std::make_unique<uint16_t[]>(GetImageSize(info.yStride, size.srcH));
    uint16_t* srcbuffer = reinterpret_cast<uint16_t *>(yuvPixels.srcPixels);
    uint16_t* srcY = srcbuffer + info.yOffset;
    uint16_t* srcUV = srcbuffer + info.uvOffset;

    uint16_t* dstY = dstPixels.get();
    uint16_t* dstU = dstPixels.get() + GetYSize(info.yStride, size.srcH);
    uint16_t* dstV = dstPixels.get() + GetVOffset(info.yStride, size.srcH);
    auto converter = ConverterHandle::GetInstance().GetHandle();
    if (converter.P010ToI010(srcY, info.yStride, srcUV, GetUVStride(info.yStride),
        dstY, info.yStride, dstU, GetUStride(info.yStride),
        dstV, GetUStride(info.yStride), size.srcW, size.srcH) == -1) {
        IMAGE_LOGE("NV12P010ToI010 failed");
        return false;
    }

    std::unique_ptr<uint16_t[]> rotatePixels = std::make_unique<uint16_t[]>(GetImageSize(size.srcW, size.srcH));
    uint16_t* rotateY = rotatePixels.get();
    uint16_t* rotateU = rotatePixels.get() + GetYSize(size.dstW, size.dstH);
    uint16_t* rotateV = rotatePixels.get() + GetVOffset(size.dstW, size.dstH);

    if (converter.I010Rotate(dstY, info.yStride, dstU, GetUStride(info.yStride),
        dstV, GetUStride(info.yStride), rotateY, size.dstW, rotateU, GetUStride(size.dstW),
        rotateV, GetUStride(size.dstW), size.srcW, size.srcH, rotateNum) == -1) {
        IMAGE_LOGE("I010Rotate failed");
        return false;
    }

    uint16_t* dstbuffer = reinterpret_cast<uint16_t *>(yuvPixels.dstPixels);
    int32_t dstYStride = static_cast<int32_t>(dstStrides.yStride);
    int32_t dstUVStride = static_cast<int32_t>(dstStrides.uvStride);
    uint16_t* dstbufferY = dstbuffer + dstStrides.yOffset;
    uint16_t* dstbufferUV = dstbuffer + dstStrides.uvOffset;
    if (converter.I010ToP010(rotateY, size.dstW, rotateU, GetUStride(size.dstW), rotateV, GetUStride(size.dstW),
        dstbufferY, dstYStride, dstbufferUV, dstUVStride, size.dstW, size.dstH) == -1) {
        IMAGE_LOGE("I010ToP010 failed");
        return false;
    }
    return true;
}

bool PixelYuvExtUtils::YuvRotate(uint8_t* srcPixels, const PixelFormat& format, YUVDataInfo& info,
    Size& dstSize, uint8_t* dstPixels, YUVStrideInfo& dstStrides, OpenSourceLibyuv::RotationMode &rotateNum)
{
    int32_t dstWidth = dstSize.width;
    int32_t dstHeight = dstSize.height;
    PixelSize pixelSize = {info.imageSize.width, info.imageSize.height, dstWidth, dstHeight};
    if (format == PixelFormat::YCBCR_P010 || format == PixelFormat::YCRCB_P010) {
        IMAGE_LOGD("YuvRotate P010Rotate enter");
        YuvPixels yuvPixels = {srcPixels, dstPixels, 0, 0};
        if (!NV12P010Rotate(yuvPixels, pixelSize, info, rotateNum, dstStrides)) {
            IMAGE_LOGE("YuvRotate P010Rotate fail");
            return false;
        }
        return true;
    }
    if (!NV12Rotate(srcPixels, pixelSize, info, rotateNum, dstPixels, dstStrides)) {
        return false;
    }

    return true;
}

void PixelYuvExtUtils::ConvertYuvMode(OpenSourceLibyuv::FilterMode &filterMode, const AntiAliasingOption &option)
{
    switch (option) {
        case AntiAliasingOption::NONE:
            filterMode = OpenSourceLibyuv::FilterMode::kFilterNone;
            break;
        case AntiAliasingOption::LOW:
            filterMode = OpenSourceLibyuv::FilterMode::kFilterLinear;
            break;
        case AntiAliasingOption::MEDIUM:
            filterMode = OpenSourceLibyuv::FilterMode::kFilterBilinear;
            break;
        case AntiAliasingOption::HIGH:
            filterMode = OpenSourceLibyuv::FilterMode::kFilterBox;
            break;
        default:
            break;
    }
}

static void ScaleUVPlane(const uint8_t *src, uint8_t*dst, OpenSourceLibyuv::FilterMode filterMode,
    YuvImageInfo &yuvInfo, uint32_t dstYStride, uint32_t dstYHeight, uint32_t dstYWidth)
{
    uint32_t srcUWidth = static_cast<uint32_t>(GetUStride(yuvInfo.width));
    uint32_t srcUHeight = static_cast<uint32_t>(GetUVHeight(yuvInfo.height));
    uint32_t dstUWidth = static_cast<uint32_t>(GetUStride(dstYWidth));
    uint32_t dstUHeight = static_cast<uint32_t>(GetUVHeight(dstYHeight));
    // Split VUplane
    std::unique_ptr<uint8_t[]> uvData = std::make_unique<uint8_t[]>(NUM_2 * srcUWidth * srcUHeight);
    if (uvData == nullptr) {
        IMAGE_LOGE("ScaleUVPlane make unique ptr for uvData failed.");
        return;
    }
    uint8_t *uData = nullptr;
    uint8_t *vData = nullptr;
    uint32_t dstSplitStride = srcUWidth;
    const uint8_t *srcUV = src + yuvInfo.yuvDataInfo.uvOffset;
    uint32_t uvStride = yuvInfo.yuvDataInfo.uvStride;
    auto converter = ConverterHandle::GetInstance().GetHandle();
    if (yuvInfo.yuvFormat == PixelFormat::NV12) {
        uData = uvData.get();
        vData = uvData.get() + srcUWidth * srcUHeight;
        converter.SplitUVPlane(srcUV, uvStride, uData, dstSplitStride, vData, dstSplitStride, srcUWidth, srcUHeight);
    } else if (yuvInfo.yuvFormat == PixelFormat::NV21) {
        vData = uvData.get();
        uData = uvData.get() + srcUWidth * srcUHeight;
        converter.SplitUVPlane(srcUV, uvStride, vData, dstSplitStride, uData, dstSplitStride, srcUWidth, srcUHeight);
    }
    // malloc memory to store temp u v
    std::unique_ptr<uint8_t[]> tempUVData = std::make_unique<uint8_t[]>(NUM_2 * dstUWidth * dstUHeight);
    if (tempUVData == nullptr) {
        IMAGE_LOGE("ScaleUVPlane make unique ptr for tempUVData failed.");
        return;
    }
    uint8_t *tempUData = nullptr;
    uint8_t *tempVData = nullptr;
    if (yuvInfo.yuvFormat == PixelFormat::NV12) {
        tempUData = tempUVData.get();
        tempVData = tempUVData.get() + dstUWidth * dstUHeight;
    } else if (yuvInfo.yuvFormat == PixelFormat::NV21) {
        tempVData = tempUVData.get();
        tempUData = tempUVData.get() + dstUWidth * dstUHeight;
    }

    // resize u* and v
    converter.ScalePlane(uData, dstSplitStride, srcUWidth, srcUHeight,
                         tempUData, dstUWidth, dstUWidth, dstUHeight, filterMode);

    converter.ScalePlane(vData, dstSplitStride, srcUWidth, srcUHeight,
                         tempVData, dstUWidth, dstUWidth, dstUHeight, filterMode);
    // Merge  the UV
    uint8_t *dstUV = dst + GetYSize(dstYStride, dstYHeight);

    int32_t dstUVStride = static_cast<int32_t>(dstUWidth * NUM_2);
    //AllocatorType DMA_ALLOC
    if (dstYStride != dstYWidth) {
        dstUVStride = static_cast<int32_t>(dstYStride);
    }
    if (yuvInfo.yuvFormat == PixelFormat::NV12) {
        converter.MergeUVPlane(tempUData, dstUWidth, tempVData, dstUWidth, dstUV, dstUVStride, dstUWidth, dstUHeight);
    } else if (yuvInfo.yuvFormat == PixelFormat::NV21) {
        converter.MergeUVPlane(tempVData, dstUWidth, tempUData, dstUWidth, dstUV, dstUVStride, dstUWidth, dstUHeight);
    }

    uData = vData = nullptr;
    tempUData = tempVData = nullptr;
}

static bool CopyP010Pixels(
    uint16_t *src, YUVStrideInfo &srcStrides, uint16_t *dst, YUVStrideInfo &dstStrides, uint32_t yHeight)
{
    uint16_t* srcY = src + srcStrides.yOffset;
    uint16_t* srcUV = srcY + srcStrides.uvOffset;
    uint16_t* dstY = dst + dstStrides.yOffset;
    uint16_t* dstUV = dstY + dstStrides.uvOffset;
    uint32_t stride = std::min(srcStrides.yStride, dstStrides.yStride);
    for (uint32_t y = 0; y < yHeight; y++) {
        errno_t ret = memcpy_s(dstY, stride * BYTE_PER_PIXEL, srcY, stride * BYTE_PER_PIXEL);
        if (ret != EOK) {
            IMAGE_LOGE("CopyP010Pixels memcpy dstY failed.");
            return false;
        }
        dstY += dstStrides.yStride;
        srcY += srcStrides.yStride;
    }
    uint32_t uvStride = std::min(srcStrides.uvStride, dstStrides.uvStride);
    for (uint32_t y = 0; y < static_cast<uint32_t>(GetUVHeight(yHeight)); y++) {
        errno_t ret = memcpy_s(dstUV, uvStride * BYTE_PER_PIXEL, srcUV, uvStride * BYTE_PER_PIXEL);
        if (ret != EOK) {
            IMAGE_LOGE("CopyP010Pixels memcpy dstY failed.");
            return false;
        }
        dstUV += dstStrides.uvStride;
        srcUV += srcStrides.uvStride;
    }
    return true;
}

static void ScaleP010(YuvPixels yuvPixels, OpenSourceLibyuv::ImageYuvConverter &converter,
    OpenSourceLibyuv::FilterMode &filterMode, YuvImageInfo &yuvInfo, YUVStrideInfo &dstStrides)
{
    uint32_t height = yuvInfo.yuvDataInfo.yHeight;
    std::unique_ptr<uint16_t[]> srcPixels = std::make_unique<uint16_t[]>(GetImageSize(yuvInfo.width, height));
    if (srcPixels == nullptr) {
        IMAGE_LOGE("ScaleP010 srcPixels make unique ptr failed");
        return;
    }
    uint16_t *srcBuffer = reinterpret_cast<uint16_t *>(yuvPixels.srcPixels);
    YUVStrideInfo srcStrides = {yuvInfo.yuvDataInfo.yStride, yuvInfo.yuvDataInfo.uvStride,
        yuvInfo.yuvDataInfo.yOffset, yuvInfo.yuvDataInfo.uvOffset};
    YUVStrideInfo dstStride = {yuvInfo.width, GetUVStride(yuvInfo.width), 0, GetYSize(yuvInfo.width, yuvInfo.height)};
    if (!CopyP010Pixels(srcBuffer, srcStrides, srcPixels.get(), dstStride, yuvInfo.yuvDataInfo.yHeight)) {
        return;
    }
    uint16_t* srcY = srcPixels.get();
    uint16_t* srcUV = srcPixels.get() + GetYSize(yuvInfo.width, yuvInfo.yuvDataInfo.yHeight);
    int32_t srcWidth = yuvInfo.width;
    int32_t srcHeight = yuvInfo.height;
    uint16_t *dstBuffer = reinterpret_cast<uint16_t *>(yuvPixels.dstPixels);
    int32_t dst_width = yuvInfo.width * yuvPixels.xAxis + ROUND_FLOAT_NUMBER;
    int32_t dst_height = yuvInfo.height * yuvPixels.yAxis + ROUND_FLOAT_NUMBER;
    std::unique_ptr<uint16_t[]> dstPixels = std::make_unique<uint16_t[]>(GetImageSize(srcWidth, srcHeight));
    if (dstPixels == nullptr) {
        IMAGE_LOGE("ScaleP010 dstPixels make unique ptr failed");
        return;
    }

    uint16_t* dstY = dstPixels.get();
    uint16_t* dstU = dstPixels.get() + GetYSize(srcWidth, srcHeight);
    uint16_t* dstV = dstPixels.get() + GetVOffset(srcWidth, srcHeight);
    if (converter.P010ToI010(srcY, srcWidth, srcUV,
        GetUVStride(srcWidth), dstY, srcWidth, dstU, GetUStride(srcWidth), dstV,
        GetUStride(srcWidth), srcWidth, srcHeight) == -1) {
        IMAGE_LOGE("NV12P010ToI010 failed");
        return;
    }
    std::unique_ptr<uint16_t[]> scalePixels = std::make_unique<uint16_t[]>(GetImageSize(dst_width, dst_height));
    if (scalePixels == nullptr) {
        IMAGE_LOGE("ScaleP010 scalePixels make unique ptr failed");
        return;
    }
    uint16_t* scaleY = scalePixels.get();
    uint16_t* scaleU = scalePixels.get() + GetYSize(dst_width, dst_height);
    uint16_t* scaleV = scalePixels.get() + GetVOffset(dst_width, dst_height);
    if (converter.I420Scale_16(dstY, srcWidth, dstU, GetUStride(srcWidth), dstV,
        GetUStride(srcWidth), srcWidth, srcHeight, scaleY, dst_width, scaleU,
        GetUStride(dst_width), scaleV, GetUStride(dst_width), dst_width, dst_height, filterMode) == -1) {
        IMAGE_LOGE("I420Scale_16 failed");
        return;
    }

    std::unique_ptr<uint16_t[]> dstPixel = std::make_unique<uint16_t[]>(GetImageSize(dst_width, dst_height));
    if (dstPixel == nullptr) {
        IMAGE_LOGE("ScaleP010 dstPixel make unique ptr failed");
        return;
    }
    uint16_t* dstPixelY = dstPixel.get();
    uint16_t* dstPixelUV = dstPixel.get() + GetYSize(dst_width, dst_height);
    if (converter.I010ToP010(scaleY, dst_width, scaleU, GetUStride(dst_width),
        scaleV, GetUStride(dst_width), dstPixelY, dst_width, dstPixelUV, GetUVStride(dst_width),
        dst_width, dst_height) == -1) {
        IMAGE_LOGE("I010ToP010 failed");
        return;
    }
    YUVStrideInfo dstPixelStrides = {dst_width, GetUVStride(dst_width), 0, GetYSize(dst_width, dst_height)};
    if (!CopyP010Pixels(dstPixelY, dstPixelStrides, dstBuffer, dstStrides, dst_height)) {
        return;
    }
}

void PixelYuvExtUtils::ScaleYuv420(float xAxis, float yAxis, const AntiAliasingOption &option,
    YuvImageInfo &yuvInfo, uint8_t *src, uint8_t *dst, YUVStrideInfo &dstStrides)
{
    OpenSourceLibyuv::FilterMode filterMode = OpenSourceLibyuv ::FilterMode::kFilterLinear;
    ConvertYuvMode(filterMode, option);

    uint8_t* srcY = src + yuvInfo.yuvDataInfo.yOffset;
    int srcYStride = static_cast<int>(yuvInfo.yuvDataInfo.yStride)
    uint8_t* srcUV = srcY + yuvInfo.yuvDataInfo.uvOffset;
    int srcUVStride = static_cast<int>(yuvInfo.yuvDataInfo.uvStride);
    int srcWidth = yuvInfo.width;
    int srcHeight = yuvInfo.height;

    int32_t dst_width = (yuvInfo.width * xAxis + ROUND_FLOAT_NUMBER);
    int32_t dst_height = (yuvInfo.height * yAxis + ROUND_FLOAT_NUMBER);
    uint8_t* dstY = dst + dstStrides.yOffset;
    int dstYStride = static_cast<int>(dstStrides.yStride);
    uint8_t* dstUV = dst + dstStrides.uvOffset;
    int dstUVStride = static_cast<int>(dstStrides.uvStride);
    auto converter = ConverterHandle::GetInstance().GetHandle();
    YuvPixels yuvPixels = {src, dst, xAxis, yAxis};
    if (yuvInfo.yuvFormat == PixelFormat::YCBCR_P010 || yuvInfo.yuvFormat == PixelFormat::YCRCB_P010) {
        ScaleP010(yuvPixels, converter, filterMode, yuvInfo, dstStrides);
    } else {
        converter.NV12Scale(srcY, srcYStride, srcUV, srcUVStride, srcWidth, srcHeight,
            dstY, dstYStride, dstUV, dstUVStride, dst_width, dst_height, filterMode);
    }
}

void PixelYuvExtUtils::ScaleYuv420(int32_t dst_width, int32_t dst_height, const AntiAliasingOption &option,
    YuvImageInfo &yuvInfo, uint8_t *src, uint8_t *dst, YUVStrideInfo &dstStrides)
{
    OpenSourceLibyuv::FilterMode filterMode = OpenSourceLibyuv ::FilterMode::kFilterLinear;
    ConvertYuvMode(filterMode, option);

    uint8_t* srcY = src + yuvInfo.yuvDataInfo.yOffset;
    int srcYStride = static_cast<int>(yuvInfo.yuvDataInfo.yStride);
    uint8_t* srcUV = srcY + yuvInfo.yuvDataInfo.uvOffset;
    int srcUVStride = static_cast<int>(yuvInfo.yuvDataInfo.uvStride);
    int srcWidth = yuvInfo.width;
    int srcHeight = yuvInfo.height;

    uint8_t* dstY = dst + dstStrides.yOffset;
    int dstYStride = static_cast<int>(dstStrides.yStride);
    uint8_t* dstUV = dst + dstStrides.uvOffset;
    int dstUVStride = static_cast<int>(dstStrides.uvStride);
    auto converter = ConverterHandle::GetInstance().GetHandle();

    PixelSize pixelSize = {srcWidth, srcHeight, dst_width, dst_height};
    if (yuvInfo.yuvFormat != PixelFormat::YCBCR_P010 && yuvInfo.yuvFormat != PixelFormat::YCRCB_P010) {
        converter.NV12Scale(srcY, srcYStride, srcUV, srcUVStride, srcWidth, srcHeight,
            dstY, dstYStride, dstUV, dstUVStride, dst_width, dst_height, filterMode);
    }
}

bool PixelYuvExtUtils::FlipXaxis(uint8_t *src, uint8_t *dst, Size &size, PixelFormat format,
    YUVDataInfo &info, YUVStrideInfo &dstStrides)
{
    IMAGE_LOGE("PixelYuvExtUtils FlipXaxis");
    uint8_t *srcY = src + info.yOffset;
    uint8_t *srcUV = src + info.uvOffset;
    int srcYStride = static_cast<int>(info.yStride);
    int srcUVStride = static_cast<int>(info.uvStride);
    int32_t width = size.width;
    int32_t height = size.height;

    uint8_t* dstY = dst + dstStrides.yOffset;
    uint8_t* dstUV = dst + dstStrides.uvOffset;
    int dstYStride = static_cast<int>(dstStrides.yStride);
    int dstUVStride = static_cast<int>(dstStrides.uvStride);

    auto converter = ConverterHandle::GetInstance().GetHandle();
    converter.NV12Copy(srcY, srcYStride, srcUV, srcUVStride, dstY, dstYStride, dstUV, dstUVStride, width, -height);
    return true;
}

bool PixelYuvExtUtils::Mirror(uint8_t *src, uint8_t *dst, Size &size, PixelFormat format, YUVDataInfo &info,
    YUVStrideInfo &dstStrides, bool isReversed)
{
    auto converter = ConverterHandle::GetInstance().GetHandle();
    uint8_t *srcY = src + info.yOffset;
    uint8_t *srcUV = src + info.uvOffset;
    int32_t width = size.width;
    int32_t height = size.height;
    int srcYStride = static_cast<int>(info.yStride);
    int srcUVStride = static_cast<int>(info.uvStride);

    uint8_t *dstY = dst + dstStrides.yOffset;
    uint8_t *dstUV = dst +  dstStrides.uvOffset;
    int dstYStride = static_cast<int>(dstStrides.yStride);
    int dstUVStride = static_cast<int>(dstStrides.uvStride);
    height = isReversed? -height : height;

    int iret = converter.NV12Mirror(srcY, srcYStride, srcUV, srcUVStride, dstY, dstYStride,
        dstUV, dstUVStride, width, height);
    if (iret == -1) {
        return false;
    }
    return true;
}
} // namespace Media
} // namespace OHOS