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

static const int32_t degrees90 = 90;
static const int32_t degrees180 = 180;
static const int32_t degrees270 = 270;
static const int32_t degrees360 = 360;

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

bool PixelYuvExtUtils::BGRAToYuv420(const uint8_t *src, uint8_t *dst, int srcW, int srcH, PixelFormat pixelFormat)
{
    auto converter = ConverterHandle::GetInstance().GetHandle();
    int32_t r = 0;
    if (pixelFormat == PixelFormat::NV12) {
        r = converter.ARGBToNV12(src, srcW * NUM_4, dst, srcW,
                                 dst + srcW * srcH,
                                 ((srcW + 1) / NUM_2) * NUM_2, srcW, srcH);
    } else if (pixelFormat == PixelFormat::NV21) {
        r = converter.ARGBToNV21(src, srcW * NUM_4, dst, srcW,
                                 dst + srcW * srcH,
                                 ((srcW + 1) / NUM_2) * NUM_2, srcW, srcH);
    }
    return r == 0;
}

bool PixelYuvExtUtils::Yuv420ToBGRA(const uint8_t *sample, uint8_t *dstArgb,
    Size &size, PixelFormat pixelFormat, YUVDataInfo &info)
{
    info.uvStride = (info.uvStride +1) & ~1;
    const uint8_t *srcY = sample + info.yOffset;
    const uint8_t *srcUV = sample + info.uvOffset;
    const uint32_t dstStrideARGB = static_cast<uint32_t>(size.width * NUM_4);
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
    if (converter.ARGBToBGRA(temp.get(), size.width * NUM_4, dstArgb,
        size.width * NUM_4, size.width, size.height) != SUCCESS) {
        IMAGE_LOGE("ARGBToBGRA failed");
        return false;
    }
    return true;
}

static bool YuvRotateConvert(Size &size, int32_t degrees, int32_t &dstWidth, int32_t &dstHeight,
    OpenSourceLibyuv::RotationMode &rotateNum)
{
    switch (degrees) {
        case degrees90:
            dstWidth = size.height;
            dstHeight = size.width;
            rotateNum = OpenSourceLibyuv::RotationMode::kRotate90;
            return true;
        case degrees180:
            rotateNum = OpenSourceLibyuv::RotationMode::kRotate180;
            return true;
        case degrees270:
            dstWidth = size.height;
            dstHeight = size.width;
            rotateNum = OpenSourceLibyuv::RotationMode::kRotate270;
            return true;
        default:
            return false;
    }
}

static bool NV12Rotate(uint8_t *src, PixelSize &size, YUVDataInfo &info, OpenSourceLibyuv::RotationMode &rotateNum)
{
    std::unique_ptr<uint8_t[]> dstPixels = std::make_unique<uint8_t[]>(GetImageSize(size.srcW, size.srcH));
    uint8_t *srcY = src + info.yOffset;
    uint8_t *srcUV = src + info.uvOffset;
    uint8_t *dstY = dstPixels.get();
    uint8_t *dstU = dstPixels.get()+ GetYSize(size.dstW, size.dstH);
    uint8_t *dstV = dstPixels.get()+ GetVOffset(size.dstW, size.dstH);
    auto converter = ConverterHandle::GetInstance().GetHandle();
    if (converter.NV12ToI420Rotate(srcY, info.yStride, srcUV, info.uvStride, dstY, size.dstW,
        dstU, GetUStride(size.dstW), dstV, GetUStride(size.dstW),
        size.srcW, size.srcH, rotateNum) == -1) {
        return false;
    }
    if (converter.I420ToNV12(dstY, size.dstW, dstU,
        GetUStride(size.dstW), dstV,
        GetUStride(size.dstW), src, size.dstW, src + GetYSize(size.dstW, size.dstH),
        GetUVStride(size.dstW), size.dstW, size.dstH) == -1) {
        return false;
    }
    return true;
}

static bool NV21Rotate(uint8_t* src, PixelSize& size, YUVDataInfo& info, OpenSourceLibyuv::RotationMode & rotateNum)
{
    std::unique_ptr<uint8_t[]> dstPixels = std::make_unique<uint8_t[]>(GetImageSize(size.srcW, size.srcH));
    uint8_t* srcY = src + info.yOffset;
    uint8_t* srcUV = src + info.uvOffset;
    uint8_t* dstY = dstPixels.get();
    uint8_t* dstU = dstPixels.get() + GetYSize(size.dstW, size.dstH);
    uint8_t* dstV = dstPixels.get() + GetVOffset(size.dstW, size.dstH);
    auto converter = ConverterHandle::GetInstance().GetHandle();
    if (converter.NV12ToI420Rotate(srcY, info.yStride, srcUV, info.uvStride, dstY, size.dstW,
        dstU, GetUStride(size.dstW), dstV, GetUStride(size.dstW),
        size.srcW, size.srcH, rotateNum) == -1) {
        IMAGE_LOGE("NV12ToI420Rotate failed");
        return false;
    }
    if (converter.I420ToNV12(dstY, size.dstW, dstU,
        GetUStride(size.dstW), dstV,
        GetUStride(size.dstW), src, size.dstW, src + GetYSize(size.dstW, size.dstH),
        GetUVStride(size.dstW), size.dstW, size.dstH) == -1) {
        IMAGE_LOGE("I420ToNV12 failed");
        return false;
    }
    return true;
}

static bool NV12P010Rotate(uint8_t* src, PixelSize& size, YUVDataInfo& info, OpenSourceLibyuv::RotationMode& rotateNum)
{
    std::unique_ptr<uint16_t[]> dstPixels = std::make_unique<uint16_t[]>(GetImageSize(size.srcW, size.srcH));
    uint16_t* srcbuffer = reinterpret_cast<uint16_t *>(src);
    uint16_t* srcY = srcbuffer + info.yOffset;
    uint16_t* srcUV = srcbuffer + info.uvOffset;

    uint16_t* dstY = dstPixels.get();
    uint16_t* dstU = dstPixels.get() + GetYSize(size.dstW, size.dstH);
    uint16_t* dstV = dstPixels.get() + GetVOffset(size.dstW, size.dstH);
    auto converter = ConverterHandle::GetInstance().GetHandle();
    if (converter.P010ToI010(srcY, info.yWidth, srcUV, info.uvWidth * NUM_2, dstY, info.yWidth, dstU, info.uvWidth,
        dstV, info.uvWidth, info.yWidth, info.yHeight) == -1) {
        IMAGE_LOGE("NV12P010ToI010 failed");
        return false;
    }

    std::unique_ptr<uint16_t[]> rotatePixels = std::make_unique<uint16_t[]>(GetImageSize(size.srcW, size.srcH));
    uint16_t* rotateY = rotatePixels.get();
    uint16_t* rotateU = rotatePixels.get() + GetYSize(size.dstW, size.dstH);
    uint16_t* rotateV = rotatePixels.get() + GetVOffset(size.dstW, size.dstH);

    if (converter.I010Rotate(dstY, info.yWidth, dstU, info.uvWidth, dstV, info.uvWidth, rotateY, info.yWidth, rotateU,
        info.uvWidth, rotateV, info.uvWidth, info.yWidth, info.yHeight, rotateNum) == -1) {
        IMAGE_LOGE("I010Rotate failed");
        return false;
    }

    if (converter.I010ToP010(rotateY, info.yWidth, rotateU, info.uvWidth, rotateV, info.uvWidth, srcbuffer,
        info.yWidth, srcbuffer + GetYSize(size.dstW, size.dstH), GetUVStride(info.yWidth), size.dstW,
        size.dstH) == -1) {
        IMAGE_LOGE("I010ToP010 failed");
        return false;
    }
    return true;
}

bool PixelYuvExtUtils::YuvRotate(uint8_t* srcPixels, Size& size, int32_t degrees,
    const PixelFormat& format, YUVDataInfo& info)
{
    if (degrees < 0) {
        degrees += degrees360;
    }
    OpenSourceLibyuv::RotationMode rotateNum = OpenSourceLibyuv::RotationMode::kRotate0;
    int32_t dstWidth = size.width;
    int32_t dstHeight = size.height;
    if (!YuvRotateConvert(size, degrees, dstWidth, dstHeight, rotateNum)) {
        IMAGE_LOGI("Rotate degress is invalid, don't need rotate");
        return false;
    }
    PixelSize pixelSize = {size.width, size.height, dstWidth, dstHeight};
    if (format == PixelFormat::NV12) {
        IMAGE_LOGE("YuvRotate NV12Rotate enter");
        if (!NV12Rotate(srcPixels, pixelSize, info, rotateNum)) {
            return false;
        }
    } else if (format == PixelFormat::NV21) {
        IMAGE_LOGE("YuvRotate NV21Rotate enter");
        if (!NV21Rotate(srcPixels, pixelSize, info, rotateNum)) {
            return false;
        }
    } else if (format == PixelFormat::YCBCR_P010 || format == PixelFormat::YCRCB_P010) {
        IMAGE_LOGD("YuvRotate P010Rotate enter");
        if (!NV12P010Rotate(srcPixels, pixelSize, info, rotateNum)) {
            IMAGE_LOGE("YuvRotate P010Rotate fail");
            return false;
        }
    }

    size.width = dstWidth;
    size.height = dstHeight;
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
    YuvImageInfo &yuvInfo, uint32_t dstYStride, uint32_t dstYHeight)
{
    uint32_t srcUWidth = static_cast<uint32_t>(GetUStride(yuvInfo.width));
    uint32_t srcUHeight = static_cast<uint32_t>(GetUVHeight(yuvInfo.height));
    uint32_t dstUWidth = static_cast<uint32_t>(GetUStride(dstYStride));
    uint32_t dstUHeight = static_cast<uint32_t>(GetUVHeight(dstYHeight));
    // Split VUplane
    std::unique_ptr<uint8_t[]> uvData = std::make_unique<uint8_t[]>(NUM_2 * srcUWidth * srcUHeight);
    uint8_t *uData = nullptr;
    uint8_t *vData = nullptr;
    if (yuvInfo.yuvFormat == PixelFormat::NV12) {
        uData = uvData.get();
        vData = uvData.get() + srcUWidth * srcUHeight;
    } else if (yuvInfo.yuvFormat == PixelFormat::NV21) {
        vData = uvData.get();
        uData = uvData.get() + srcUWidth * srcUHeight;
    }
    uint32_t dstSplitStride = srcUWidth;
    const uint8_t *srcUV = src + yuvInfo.yuvDataInfo.uvOffset;
    uint32_t uvStride = yuvInfo.yuvDataInfo.uvStride;
    auto converter = ConverterHandle::GetInstance().GetHandle();
    if (yuvInfo.yuvFormat == PixelFormat::NV12) {
        converter.SplitUVPlane(srcUV, uvStride, uData, dstSplitStride, vData, dstSplitStride,
                               srcUWidth, srcUHeight);
    } else if (yuvInfo.yuvFormat == PixelFormat::NV21) {
        converter.SplitUVPlane(srcUV, uvStride, vData, dstSplitStride, uData, dstSplitStride,
                               srcUWidth, srcUHeight);
    }
    // malloc memory to store temp u v
    std::unique_ptr<uint8_t[]> tempUVData = std::make_unique<uint8_t[]>(NUM_2 * dstUWidth * dstUHeight);
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
    if (yuvInfo.yuvFormat == PixelFormat::NV12) {
        converter.MergeUVPlane(tempUData, dstUWidth, tempVData, dstUWidth, dstUV, dstUVStride, dstUWidth, dstUHeight);
    } else if (yuvInfo.yuvFormat == PixelFormat::NV21) {
        converter.MergeUVPlane(tempVData, dstUWidth, tempUData, dstUWidth, dstUV, dstUVStride, dstUWidth, dstUHeight);
    }

    uData = vData = nullptr;
    tempUData = tempVData = nullptr;
}

static void ScaleP010(PixelSize pixelSize, uint8_t *src, uint8_t *dst, OpenSourceLibyuv::ImageYuvConverter &converter,
    OpenSourceLibyuv::FilterMode &filterMode)
{
    uint16_t *srcBuffer = reinterpret_cast<uint16_t *>(src);
    uint16_t *dstBuffer = reinterpret_cast<uint16_t *>(dst);
    std::unique_ptr<uint16_t[]> dstPixels = std::make_unique<uint16_t[]>(GetImageSize(pixelSize.srcW, pixelSize.srcH));
    uint16_t* dstY = dstPixels.get();
    uint16_t* dstU = dstPixels.get() + GetYSize(pixelSize.srcW, pixelSize.srcH);
    uint16_t* dstV = dstPixels.get() + GetVOffset(pixelSize.srcW, pixelSize.srcH);
    if (converter.P010ToI010(srcBuffer, pixelSize.srcW, srcBuffer + GetYSize(pixelSize.srcW, pixelSize.srcH),
        GetUVStride(pixelSize.srcW), dstY, pixelSize.srcW, dstU, GetUStride(pixelSize.srcW), dstV,
        GetUStride(pixelSize.srcW), pixelSize.srcW, pixelSize.srcH) == -1) {
        IMAGE_LOGE("NV12P010ToI010 failed");
        return;
    }
    std::unique_ptr<uint16_t[]> scalePixels = std::make_unique<uint16_t[]>(GetImageSize(pixelSize.dstW,
        pixelSize.dstH));
    uint16_t* scaleY = scalePixels.get();
    uint16_t* scaleU = scalePixels.get() + GetYSize(pixelSize.dstW, pixelSize.dstH);
    uint16_t* scaleV = scalePixels.get() + GetVOffset(pixelSize.dstW, pixelSize.dstH);
    if (converter.I420Scale_16(dstY, pixelSize.srcW, dstU, GetUStride(pixelSize.srcW), dstV,
        GetUStride(pixelSize.srcW), pixelSize.srcW, pixelSize.srcH, scaleY, pixelSize.dstW, scaleU,
        GetUStride(pixelSize.dstW), scaleV, GetUStride(pixelSize.dstW), pixelSize.dstW, pixelSize.dstH,
        filterMode) == -1) {
        IMAGE_LOGE("I420Scale_16 failed");
        return;
    }
    if (converter.I010ToP010(scaleY, pixelSize.dstW, scaleU, GetUStride(pixelSize.dstW),
        scaleV, GetUStride(pixelSize.dstW), dstBuffer, pixelSize.dstW, dstBuffer +
        GetYSize(pixelSize.dstW, pixelSize.dstH), GetUVStride(pixelSize.dstW),
        pixelSize.dstW, pixelSize.dstH) == -1) {
        IMAGE_LOGE("I010ToP010 failed");
        return;
    }
}

void PixelYuvExtUtils::ScaleYuv420(float xAxis, float yAxis, const AntiAliasingOption &option,
    YuvImageInfo &yuvInfo, uint8_t *src, uint8_t *dst)
{
    OpenSourceLibyuv::FilterMode filterMode = OpenSourceLibyuv ::FilterMode::kFilterNone;
    ConvertYuvMode(filterMode, option);
    uint32_t srcYStride = yuvInfo.yuvDataInfo.yStride;
    uint32_t srcYWidth = static_cast<uint32_t>(yuvInfo.width);
    uint32_t srcYHeight = static_cast<uint32_t>(yuvInfo.height);

    int32_t dstYStride = srcYWidth * xAxis;
    int32_t dstYWidth = dstYStride;
    int32_t dstYHeight = srcYHeight * yAxis;
    PixelSize pixelSize = {srcYWidth, srcYHeight, dstYWidth, dstYHeight};
    auto converter = ConverterHandle::GetInstance().GetHandle();
    if (yuvInfo.yuvFormat == PixelFormat::YCBCR_P010 || yuvInfo.yuvFormat == PixelFormat::YCRCB_P010) {
        ScaleP010(pixelSize, src, dst, converter, filterMode);
    } else {
        // setupY stride width height infomation
        uint8_t *srcY = src + yuvInfo.yuvDataInfo.yOffset;
        // resize'y plane
        converter.ScalePlane(srcY,
                             srcYStride,
                             srcYWidth,
                             srcYHeight,
                             dst,
                             dstYStride,
                             dstYWidth,
                             dstYHeight,
                             filterMode);
        ScaleUVPlane(src, dst, filterMode, yuvInfo, dstYStride, dstYHeight);
    }
}

static bool FlipXaxis(uint8_t *src, uint8_t *dst, Size &size, PixelFormat format, YUVDataInfo &info)
{
    uint8_t *srcY = src + info.yOffset;
    uint8_t *srcUV = src + info.uvOffset;
    int32_t width = size.width;
    int32_t height = size.height;
    auto converter = ConverterHandle::GetInstance().GetHandle();
    if (format == PixelFormat::NV12) {
        converter.NV12ToI420(srcY, info.yStride, srcUV, info.uvStride, dst, width,
            dst + GetYSize(width, height), GetUStride(width), dst + GetVOffset(width, height), GetUStride(width),
            width, height);
        if (SUCCESS != converter.I420Copy(dst, width, dst + GetYSize(width, height), GetUStride(width),
            dst + GetVOffset(width, height), GetUStride(width), const_cast<uint8_t *>(src), width,
            const_cast<uint8_t *>(src) + GetYSize(width, height), GetUStride(width),
            const_cast<uint8_t *>(src) + GetVOffset(width, height), GetUStride(width), width, -height)) {
            IMAGE_LOGE("Flip YUV420SP,YUV420SP Copy failed");
            return false;
        }
        converter.I420ToNV12(src, width, src + GetYSize(width, height), GetUStride(width),
            src + GetVOffset(width, height), GetUStride(width), dst, width,
            dst + GetYSize(width, height), GetUVStride(width), width, height);
    } else if (format == PixelFormat::NV21) {
        converter.NV21ToI420(srcY, info.yStride, srcUV, info.uvStride, dst, width,
            dst + GetYSize(width, height), GetUStride(width), dst + GetVOffset(width, height), GetUStride(width),
            width, height);
        if (SUCCESS != converter.I420Copy(dst, width, dst + GetYSize(width, height), GetUStride(width),
            dst + GetVOffset(width, height), GetUStride(width), const_cast<uint8_t *>(src), width,
            const_cast<uint8_t *>(src) + GetYSize(width, height), GetUStride(width),
            const_cast<uint8_t *>(src) + GetVOffset(width, height), GetUStride(width), width, -height)) {
            IMAGE_LOGE("Flip YUV420SP, YUV420SP Copy failed");
            return false;
        }
        converter.I420ToNV21(src, width, src + GetYSize(width, height), GetUStride(width),
            src + GetVOffset(width, height), GetUStride(width), dst, width,
            dst + GetYSize(width, height), GetUVStride(width), width, height);
    }
    return true;
}

static bool FlipYaxis(uint8_t *src, uint8_t *dst, Size &size, PixelFormat format, YUVDataInfo &info)
{
    uint8_t *srcY = src + info.yOffset;
    uint8_t *srcUV = src + info.uvOffset;
    int32_t width = size.width;
    int32_t height = size.height;
    auto converter = ConverterHandle::GetInstance().GetHandle();
    if (format == PixelFormat::NV12) {
        converter.NV12ToI420(srcY, info.yStride, srcUV, info.uvStride, dst, width,
            dst + GetYSize(width, height), GetUStride(width), dst + GetVOffset(width, height), GetUStride(width),
            width, height);
        if (SUCCESS != converter.I420Mirror(dst, width, dst + GetYSize(width, height), GetUStride(width),
            dst + GetVOffset(width, height), GetUStride(width), const_cast<uint8_t *>(src),
            width, const_cast<uint8_t *>(src) + GetYSize(width, height), GetUStride(width),
            const_cast<uint8_t *>(src) + GetVOffset(width, height), GetUStride(width), width, height)) {
            IMAGE_LOGE("Flip YUV420SP, YUV420SP Mirror failed");
            return false;
        }
        converter.I420ToNV12(
            src, width, src + GetYSize(width, height), GetUStride(width),
            src + GetVOffset(width, height), GetUStride(width), dst, width,
            dst + GetYSize(width, height), GetUVStride(width), width, height);
    } else if (format == PixelFormat::NV21) {
        converter.NV21ToI420(srcY, info.yStride, srcUV, info.uvStride, dst, width,
            dst + GetYSize(width, height), GetUStride(width), dst + GetVOffset(width, height), GetUStride(width),
            width, height);
        if (SUCCESS != converter.I420Mirror(dst, width, dst + GetYSize(width, height), GetUStride(width),
            dst + GetVOffset(width, height), GetUStride(width), const_cast<uint8_t *>(src),
            width, const_cast<uint8_t *>(src) + GetYSize(width, height), GetUStride(width),
            const_cast<uint8_t *>(src) + GetVOffset(width, height), GetUStride(width), width, height)) {
            IMAGE_LOGE("Flip YUV420SP,YUV420SP Mirror failed");
            return false;
        }
        converter.I420ToNV21(src, width, src + GetYSize(width, height), GetUStride(width),
            src + GetVOffset(width, height), GetUStride(width), dst, width,
            dst + GetYSize(width, height), GetUVStride(width), width, height);
    }
    return true;
}

static void AssignYuvDataOnType(PixelFormat format, int32_t width, int32_t height, YUVDataInfo &info)
{
    if (format == PixelFormat::NV12 || format == PixelFormat::NV21) {
        info.yWidth = static_cast<uint32_t>(width);
        info.yHeight = static_cast<uint32_t>(height);
        info.yStride = static_cast<uint32_t>(width);
        info.uvWidth = static_cast<uint32_t>(GetUStride(width));
        info.uvHeight = static_cast<uint32_t>(GetUVHeight(height));
        info.uvStride = static_cast<uint32_t>(GetUVStride(width));
        info.yOffset = 0;
        info.uvOffset =  info.yHeight * info.yStride;
    }
}

bool PixelYuvExtUtils::ReversalYuv(uint8_t *src, uint8_t *dst, Size &size, PixelFormat format, YUVDataInfo &info)
{
    uint32_t cout = GetImageSize(size.width, size.height);
    std::unique_ptr<uint8_t[]> tmpData = std::make_unique<uint8_t[]>(cout);
    if (!FlipXaxis(src, tmpData.get(), size, format, info)) {
        IMAGE_LOGE("FlipXaxis failed");
        return false;
    }
    AssignYuvDataOnType(format, size.width, size.height, info);
    if (!FlipYaxis(tmpData.get(), dst, size, format, info)) {
        IMAGE_LOGE("FlipYaxis failed");
        return false;
    }
    return true;
}

bool PixelYuvExtUtils::FlipYuv(uint8_t*src, uint8_t *dst, ImageInfo &imageinfo, bool isXaxis, YUVDataInfo &info)
{
    if (isXaxis) {
        if (!FlipXaxis(src, dst, imageinfo.size, imageinfo.pixelFormat, info)) {
            IMAGE_LOGE("NewFlipXaxis failed");
            return false;
        }
    } else {
        if (!FlipYaxis(src, dst, imageinfo.size, imageinfo.pixelFormat, info)) {
            IMAGE_LOGE("FlipYaxis failed");
            return false;
        }
    }
    return true;
}

} // namespace Media
} // namespace OHOS