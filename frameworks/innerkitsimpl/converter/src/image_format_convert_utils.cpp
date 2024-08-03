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

#include "image_format_convert_utils.h"

#include <cmath>
#include <cstring>
#include <map>
#include "hilog/log.h"
#include "image_log.h"
#include "log_tags.h"
#include "securec.h"
#include "pixel_convert_adapter.h"

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

namespace {
    constexpr uint32_t SRCSLICEY = 0;
    constexpr uint32_t EVEN_ODD_DIVISOR = 2;
    constexpr uint32_t TWO_SLICES = 2;
    constexpr uint32_t BYTES_PER_PIXEL_RGB565 = 2;
    constexpr uint32_t BYTES_PER_PIXEL_RGB = 3;
    constexpr uint32_t BYTES_PER_PIXEL_RGBA = 4;
    constexpr uint32_t BYTES_PER_PIXEL_BGRA = 4;
    constexpr uint32_t STRIDES_PER_PLANE = 8;
    constexpr int32_t PIXEL_MAP_MAX_RAM_SIZE = 600 * 1024 * 1024;
}

#undef LOG_TAG
#define LOG_TAG "ImageFormatConvert"
namespace OHOS {
namespace Media {
static AVPixelFormat findPixelFormat(PixelFormat format)
{
    auto formatSearch = PixelConvertAdapter::FFMPEG_PIXEL_FORMAT_MAP.find(format);
    if (formatSearch != PixelConvertAdapter::FFMPEG_PIXEL_FORMAT_MAP.end()) {
        return formatSearch->second;
    } else {
        return AV_PIX_FMT_NONE;
    }
}

static bool CalcRGBStride(PixelFormat format, uint32_t width, int &stride)
{
    if (format == PixelFormat::RGBA_1010102) {
        stride = static_cast<int>(width * BYTES_PER_PIXEL_RGBA);
        return true;
    }
    auto avFormat = findPixelFormat(format);
    switch (avFormat) {
        case AV_PIX_FMT_RGB565:
            stride = static_cast<int>(width * BYTES_PER_PIXEL_RGB565);
            break;
        case AV_PIX_FMT_RGBA:
            stride = static_cast<int>(width * BYTES_PER_PIXEL_RGBA);
            break;
        case AV_PIX_FMT_RGBA64:
            stride = static_cast<int>(width * STRIDES_PER_PLANE);
            break;
        case AV_PIX_FMT_BGRA:
            stride = static_cast<int>(width * BYTES_PER_PIXEL_BGRA);
            break;
        case AV_PIX_FMT_RGB24:
            stride = static_cast<int>(width * BYTES_PER_PIXEL_RGB);
            break;
        default:
            return false;
    }
    return true;
}

static bool YuvToRGBParam(const YUVDataInfo &yDInfo, SrcConvertParam &srcParam, DestConvertParam &destParam,
                          DestConvertInfo &destInfo)
{
    srcParam.slice[0] = srcParam.buffer + yDInfo.yOffset;
    srcParam.slice[1] = srcParam.buffer + yDInfo.uvOffset;
    srcParam.stride[0] = static_cast<int>(yDInfo.yStride);
    srcParam.stride[1] = static_cast<int>(yDInfo.uvStride);
    int dstStride = 0;
    if (destInfo.allocType == AllocatorType::DMA_ALLOC) {
        dstStride = destInfo.yStride;
        destParam.slice[0] = destInfo.buffer + destInfo.yOffset;
    } else {
        auto bRet = CalcRGBStride(destParam.format, destParam.width, dstStride);
        if (!bRet) {
            return false;
        }
        destParam.slice[0] = destInfo.buffer;
    }
    destParam.stride[0] = dstStride;
    return true;
}

static bool RGBToYuvParam(const RGBDataInfo &rgbInfo, SrcConvertParam &srcParam, DestConvertParam &destParam,
                          DestConvertInfo &destInfo)
{
    srcParam.slice[0] = srcParam.buffer;
    srcParam.stride[0] = static_cast<int>(rgbInfo.stride);

    if (destInfo.allocType == AllocatorType::DMA_ALLOC) {
        destParam.stride[0] = static_cast<int>(destInfo.yStride);
        destParam.stride[1] = static_cast<int>(destInfo.uvStride);
        destParam.slice[0] = destInfo.buffer + destInfo.yOffset;
        destParam.slice[1] = destInfo.buffer + destInfo.uvOffset;
    } else {
        int uvStride = (destParam.width % EVEN_ODD_DIVISOR == 0) ? (destParam.width) : (destParam.width + 1);
        destParam.stride[0] = static_cast<int>(destParam.width);
        destParam.stride[1] = static_cast<int>(uvStride);
        destParam.slice[0] = destInfo.buffer;
        destParam.slice[1] = destInfo.buffer + destParam.width * destParam.height;
    }
    return true;
}

static bool SoftDecode(const SrcConvertParam &srcParam, const DestConvertParam &destParam)
{
    auto srcformat = findPixelFormat(srcParam.format);
    auto dstformat = findPixelFormat(destParam.format);

    SwsContext *swsContext = sws_getContext(srcParam.width, srcParam.height, srcformat, destParam.width,
        destParam.height, dstformat, SWS_BILINEAR, nullptr, nullptr, nullptr);
    if (swsContext == nullptr) {
        IMAGE_LOGE("Error to create SwsContext.");
        return false;
    }
    int height = 0;
    const uint8_t *srcSlice[] = {srcParam.slice[0], srcParam.slice[1]};
    int srcStride[] = {static_cast<int>(srcParam.stride[0]), static_cast<int>(srcParam.stride[1])};
    uint8_t *dstSlice[] = {destParam.slice[0], destParam.slice[1]};
    int dstStride[] = {static_cast<int>(destParam.stride[0]), static_cast<int>(destParam.stride[1])};

    height = sws_scale(swsContext, srcSlice, srcStride, SRCSLICEY, destParam.height, dstSlice, dstStride);

    sws_freeContext(swsContext);
    if (height == 0) {
        IMAGE_LOGE("Image pixel format conversion failed");
        return false;
    }
    return true;
}

static bool NV12P010ToNV21P010SoftDecode(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo, uint8_t *destBuffer)
{
    const uint16_t *src = reinterpret_cast<const uint16_t *>(srcBuffer);
    uint16_t *dst = reinterpret_cast<uint16_t *>(destBuffer);
    const uint16_t *src_uv = src + yDInfo.uvOffset;
    uint16_t *dst_vu = dst + yDInfo.uvOffset;
    uint32_t size_uv = yDInfo.uvOffset / TWO_SLICES;
    for (uint32_t i = 0; i < yDInfo.uvOffset; i++) {
        dst[i] = src[i];
    }
    for (uint32_t i = 0; i < size_uv; i += TWO_SLICES) {
        dst_vu[i] = src_uv[i + 1];
        dst_vu[i + 1] = src_uv[i];
    }
    return true;
}

static bool RGBAConvert(const RGBDataInfo &rgbInfo, const uint8_t *srcBuffer, uint8_t *dstBuffer,
                        Convert10bitInfo convertInfo)
{
    ImageInfo srcInfo;
    ImageInfo destInfo;
    srcInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_PREMUL;
    destInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_PREMUL;
    srcInfo.pixelFormat = convertInfo.srcPixelFormat;
    destInfo.pixelFormat = convertInfo.dstPixelFormat;
    srcInfo.size.width = rgbInfo.width;
    srcInfo.size.height = rgbInfo.height;
    destInfo.size.width = rgbInfo.width;
    destInfo.size.height = rgbInfo.height;

    Position pos;
    if (!PixelConvertAdapter::WritePixelsConvert(srcBuffer, convertInfo.srcBytes, srcInfo,
        dstBuffer, pos, convertInfo.dstBytes, destInfo)) {
        IMAGE_LOGE("RGBAConvert: pixel convert in adapter failed.");
        return false;
    }
    return true;
}

static bool P010ToRGBA10101012SoftDecode(const YUVDataInfo &yDInfo, SrcConvertParam &srcParam,
                                         DestConvertParam &destParam)
{
    size_t midBufferSize = static_cast<size_t>(yDInfo.yWidth * yDInfo.yHeight * STRIDES_PER_PLANE);
    if (midBufferSize == 0 || midBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size is 0!");
        return false;
    }
    uint8_t *midBuffer = nullptr;
    midBuffer = new(std::nothrow) uint8_t[midBufferSize]();
    if (midBuffer == nullptr) {
        IMAGE_LOGE("Apply space for dest buffer failed!");
        return false;
    }
    DestConvertParam midParam = {yDInfo.yWidth, yDInfo.yHeight};
    midParam.format = PixelFormat::RGBA_F16;
    midParam.buffer = midBuffer;
    midParam.slice[0] = midParam.buffer;
    midParam.stride[0] = static_cast<int>(yDInfo.yWidth * STRIDES_PER_PLANE);
    if (!SoftDecode(srcParam, midParam)) {
        IMAGE_LOGE("RGB manual conversion to YUV failed!");
        delete[] midBuffer;
        return false;
    }
    RGBDataInfo rgbInfo;
    rgbInfo.width = yDInfo.yWidth;
    rgbInfo.height = yDInfo.yHeight;
    Convert10bitInfo convertInfo;
    convertInfo.srcPixelFormat = PixelFormat::RGBA_U16;
    convertInfo.srcBytes = midParam.stride[0];
    convertInfo.dstPixelFormat = PixelFormat::RGBA_1010102;
    convertInfo.dstBytes = destParam.stride[0];
    if (!RGBAConvert(rgbInfo, midParam.slice[0], destParam.slice[0], convertInfo)) {
        IMAGE_LOGE("RGB888ToRGBA1010102: pixel convert in adapter failed.");
        delete[] midBuffer;
        return false;
    }
    delete[] midBuffer;
    return true;
}

static bool YuvP010ToRGBParam(const YUVDataInfo &yDInfo, SrcConvertParam &srcParam, DestConvertParam &destParam,
                              DestConvertInfo &destInfo)
{
    srcParam.slice[0] = srcParam.buffer + yDInfo.yOffset;
    srcParam.slice[1] = srcParam.buffer + yDInfo.uvOffset * TWO_SLICES;
    srcParam.stride[0] = static_cast<int>(yDInfo.yStride * TWO_SLICES);
    srcParam.stride[1] = static_cast<int>(yDInfo.uvStride * TWO_SLICES);
    int dstStride = 0;
    if (destInfo.allocType == AllocatorType::DMA_ALLOC) {
        dstStride = destInfo.yStride;
        destParam.slice[0] = destInfo.buffer + destInfo.yOffset;
    } else {
        auto bRet = CalcRGBStride(destParam.format, destParam.width, dstStride);
        if (!bRet) {
            return false;
        }
        destParam.slice[0] = destInfo.buffer;
    }
    destParam.stride[0] = dstStride;
    return true;
}

static bool YuvP010ToRGB10(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo, PixelFormat srcFormat,
    DestConvertInfo &destInfo, PixelFormat dstFormat)
{
    if (srcBuffer == nullptr || destInfo.buffer == nullptr || yDInfo.yWidth == 0 || yDInfo.yHeight == 0 ||
        yDInfo.uvWidth == 0 || yDInfo.uvHeight == 0) {
        return false;
    }
    SrcConvertParam srcParam = {yDInfo.yWidth, yDInfo.yHeight};
    srcParam.format = srcFormat;
    srcParam.buffer = srcBuffer;
    DestConvertParam destParam = {yDInfo.yWidth, yDInfo.yHeight};
    destParam.format = dstFormat;
    if (!YuvP010ToRGBParam(yDInfo, srcParam, destParam, destInfo)) {
        IMAGE_LOGE("yuv conversion to yuv failed!");
        return false;
    }
    if (srcParam.format == PixelFormat::YCRCB_P010) {
        size_t midBufferSize =
            static_cast<size_t>((yDInfo.uvOffset + yDInfo.uvWidth * yDInfo.uvWidth * TWO_SLICES) * TWO_SLICES);
        if (midBufferSize == 0 || midBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
            IMAGE_LOGE("Invalid destination buffer size is 0!");
            return false;
        }
        uint8_t *midBuffer = nullptr;
        midBuffer = new(std::nothrow) uint8_t[midBufferSize]();
        if (midBuffer == nullptr) {
            IMAGE_LOGE("Apply space for dest buffer failed!");
            return false;
        }
        NV12P010ToNV21P010SoftDecode(srcParam.slice[0], yDInfo, midBuffer);
        SrcConvertParam midParam = {yDInfo.yWidth, yDInfo.yHeight};
        midParam.format = srcFormat;
        midParam.buffer = midBuffer;
        midParam.slice[0] = midParam.buffer + yDInfo.yOffset;
        midParam.slice[1] = midParam.buffer + yDInfo.uvOffset * TWO_SLICES;
        midParam.stride[0] = static_cast<int>(yDInfo.yStride) * TWO_SLICES;
        midParam.stride[1] = static_cast<int>(yDInfo.uvStride) * TWO_SLICES;
        if (!P010ToRGBA10101012SoftDecode(yDInfo, midParam, destParam)) {
            IMAGE_LOGE("P010ToRGBA1010102: pixel convert in adapter failed!");
            delete[] midBuffer;
            return false;
        }
        delete[] midBuffer;
        return true;
    }
    if (!P010ToRGBA10101012SoftDecode(yDInfo, srcParam, destParam)) {
        IMAGE_LOGE("P010ToRGBA1010102: pixel convert in adapter failed!");
        return false;
    }
    return true;
}

static bool RGBToYuvP010Param(const RGBDataInfo &rgbInfo, SrcConvertParam &srcParam, DestConvertParam &destParam,
                              DestConvertInfo &destInfo)
{
    srcParam.slice[0] = srcParam.buffer;
    srcParam.stride[0] = static_cast<int>(rgbInfo.stride);

    if (destInfo.allocType == AllocatorType::DMA_ALLOC) {
        destParam.stride[0] = static_cast<int>(destInfo.yStride) * TWO_SLICES;
        destParam.stride[1] = static_cast<int>(destInfo.uvStride) * TWO_SLICES;
        destParam.slice[0] = destInfo.buffer + destInfo.yOffset;
        destParam.slice[1] = destInfo.buffer + destInfo.uvOffset * TWO_SLICES;
    } else {
        int uvStride = (destParam.width % EVEN_ODD_DIVISOR == 0) ? (destParam.width) : (destParam.width + 1);
        destParam.stride[0] = static_cast<int>(destParam.width) * TWO_SLICES;
        destParam.stride[1] = static_cast<int>(uvStride) * TWO_SLICES;
        destParam.slice[0] = destInfo.buffer;
        destParam.slice[1] = destInfo.buffer + destParam.width * destParam.height * TWO_SLICES;
    }
    return true;
}

static bool SwapNV21P010(DestConvertInfo &destInfo)
{
    int32_t frameSize = destInfo.width * destInfo.height;
    size_t midBufferSize = (frameSize +
        (((destInfo.width + 1) / TWO_SLICES) * ((destInfo.height + 1) / TWO_SLICES) * TWO_SLICES)) * TWO_SLICES;
    if (midBufferSize == 0 || midBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size calculation!");
        return false;
    }
    uint8_t *midBuffer = nullptr;
    midBuffer = new(std::nothrow) uint8_t[midBufferSize]();
    if (midBuffer == nullptr) {
        IMAGE_LOGE("apply space for dest buffer failed!");
        return false;
    }

    if (memcpy_s(midBuffer, midBufferSize, destInfo.buffer, midBufferSize) != 0) {
        IMAGE_LOGE("Failed to copy memory for YCRCB!");
        delete[] midBuffer;
        return false;
    }
    YUVDataInfo yDInfo;
    yDInfo.uvOffset = destInfo.width * destInfo.height;
    bool result = NV12P010ToNV21P010SoftDecode(midBuffer, yDInfo, destInfo.buffer);
    if (!result) {
        IMAGE_LOGE("NV12P010ToNV21P010 failed!");
        delete[] midBuffer;
        return false;
    }
    delete[] midBuffer;
    return true;
}

static bool RGBToYuvP010(const uint8_t *srcBuffer, const RGBDataInfo &rgbInfo, PixelFormat srcFormat,
                         DestConvertInfo &destInfo, PixelFormat dstFormat)
{
    if (srcBuffer == nullptr || destInfo.buffer == nullptr || rgbInfo.width == 0 || rgbInfo.height == 0) {
        return false;
    }
    SrcConvertParam srcParam = {rgbInfo.width, rgbInfo.height};
    srcParam.format = srcFormat;
    srcParam.buffer = srcBuffer;

    DestConvertParam destParam = {rgbInfo.width, rgbInfo.height};
    destParam.format = dstFormat;

    if (!RGBToYuvP010Param(rgbInfo, srcParam, destParam, destInfo)) {
        IMAGE_LOGE("RGB conversion to YUVP010 failed!");
        return false;
    }

    if (!SoftDecode(srcParam, destParam)) {
        IMAGE_LOGE("RGB manual conversion to YUV failed!");
        return false;
    }

    if (destInfo.format == PixelFormat::YCRCB_P010) {
        if (!SwapNV21P010(destInfo)) {
            IMAGE_LOGE("SwapNV21P010 failed!");
            return false;
        }
    }
    return true;
}

static bool RGB10ToYuv(const uint8_t *srcBuffer, const RGBDataInfo &rgbInfo, PixelFormat srcFormat,
                       DestConvertInfo &destInfo, PixelFormat dstFormat)
{
    if (srcBuffer == nullptr || destInfo.buffer == nullptr || rgbInfo.width == 0 || rgbInfo.height == 0) {
        return false;
    }
    SrcConvertParam srcParam = {rgbInfo.width, rgbInfo.height};
    srcParam.format = srcFormat;
    srcParam.buffer = srcBuffer;
    DestConvertParam destParam = {rgbInfo.width, rgbInfo.height};
    destParam.format = dstFormat;
    if (!RGBToYuvParam(rgbInfo, srcParam, destParam, destInfo)) {
        IMAGE_LOGE("RGB conversion to YUV failed!");
        return false;
    }
    size_t midBufferSize = static_cast<size_t>(rgbInfo.width * rgbInfo.height * STRIDES_PER_PLANE);
    if (midBufferSize == 0 || midBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size is 0!");
        return false;
    }
    uint8_t *midBuffer = nullptr;
    midBuffer = new(std::nothrow) uint8_t[midBufferSize]();
    if (midBuffer == nullptr) {
        IMAGE_LOGE("Apply space for dest buffer failed!");
        return false;
    }
    Convert10bitInfo convertInfo;
    convertInfo.srcPixelFormat = PixelFormat::RGBA_1010102;
    convertInfo.srcBytes = srcParam.stride[0];
    convertInfo.dstPixelFormat = PixelFormat::RGB_888;
    convertInfo.dstBytes = rgbInfo.width * BYTES_PER_PIXEL_RGB;
    if (!RGBAConvert(rgbInfo, srcParam.slice[0], midBuffer, convertInfo)) {
        IMAGE_LOGE("RGBA1010102ToRGB888: pixel convert in adapter failed.");
        delete[] midBuffer;
        return false;
    }
    SrcConvertParam midParam = {rgbInfo.width, rgbInfo.height};
    midParam.format = PixelFormat::RGB_888;
    midParam.buffer = midBuffer;
    midParam.slice[0] = midParam.buffer;
    midParam.stride[0] = static_cast<int>(rgbInfo.width * BYTES_PER_PIXEL_RGB);
    if (!SoftDecode(midParam, destParam)) {
        IMAGE_LOGE("RGB manual conversion to YUV failed!");
        delete[] midBuffer;
        return false;
    }
    delete[] midBuffer;
    return true;
}

static bool RGBA1010102ToP010SoftDecode(const RGBDataInfo &rgbInfo, SrcConvertParam &srcParam,
                                        DestConvertParam &destParam, DestConvertInfo &destInfo)
{
    size_t midBufferSize = static_cast<size_t>(rgbInfo.width * rgbInfo.height * STRIDES_PER_PLANE);
    if (midBufferSize == 0 || midBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size is 0!");
        return false;
    }
    uint8_t *midBuffer = nullptr;
    midBuffer = new(std::nothrow) uint8_t[midBufferSize]();
    if (midBuffer == nullptr) {
        IMAGE_LOGE("Apply space for dest buffer failed!");
        return false;
    }
    Convert10bitInfo convertInfo;
    convertInfo.srcPixelFormat = PixelFormat::RGBA_1010102;
    convertInfo.srcBytes = srcParam.stride[0];
    convertInfo.dstPixelFormat = PixelFormat::RGBA_U16;
    convertInfo.dstBytes = rgbInfo.width * STRIDES_PER_PLANE;
    if (!RGBAConvert(rgbInfo, srcParam.slice[0], midBuffer, convertInfo)) {
        IMAGE_LOGE("RGBA1010102ToRGB888: pixel convert in adapter failed.");
        delete[] midBuffer;
        return false;
    }
    SrcConvertParam midParam = {rgbInfo.width, rgbInfo.height};
    midParam.format = PixelFormat::RGBA_F16;
    midParam.buffer = midBuffer;
    midParam.slice[0] = midParam.buffer;
    midParam.stride[0] = static_cast<int>(rgbInfo.width * STRIDES_PER_PLANE);
    if (!SoftDecode(midParam, destParam)) {
        IMAGE_LOGE("RGB manual conversion to YUV failed!");
        delete[] midBuffer;
        return false;
    }
    if (destInfo.format == PixelFormat::YCRCB_P010) {
        if (!SwapNV21P010(destInfo)) {
            IMAGE_LOGE("SwapNV21P010 failed!");
            delete[] midBuffer;
            return false;
        }
    }
    delete[] midBuffer;
    return true;
}

static bool RGB10ToYuvP010(const uint8_t *srcBuffer, const RGBDataInfo &rgbInfo, PixelFormat srcFormat,
                           DestConvertInfo &destInfo, PixelFormat dstFormat)
{
    if (srcBuffer == nullptr || destInfo.buffer == nullptr || rgbInfo.width == 0 || rgbInfo.height == 0) {
        return false;
    }
    SrcConvertParam srcParam = {rgbInfo.width, rgbInfo.height};
    srcParam.format = srcFormat;
    srcParam.buffer = srcBuffer;
    DestConvertParam destParam = {rgbInfo.width, rgbInfo.height};
    destParam.format = dstFormat;
    if (!RGBToYuvP010Param(rgbInfo, srcParam, destParam, destInfo)) {
        IMAGE_LOGE("RGB conversion to YUV failed!");
        return false;
    }
    if (!RGBA1010102ToP010SoftDecode(rgbInfo, srcParam, destParam, destInfo)) {
        IMAGE_LOGE("RGB10bit manual conversion to YUVP010 failed!");
        return false;
    }
    return true;
}

static bool YUVToRGBA1010102SoftDecode(const YUVDataInfo &yDInfo, SrcConvertParam &srcParam,
                                       DestConvertParam &destParam)
{
    size_t midBufferSize = static_cast<size_t>(yDInfo.yWidth * yDInfo.yHeight * BYTES_PER_PIXEL_RGB);
    if (midBufferSize == 0 || midBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size is 0!");
        return false;
    }
    uint8_t *midBuffer = nullptr;
    midBuffer = new(std::nothrow) uint8_t[midBufferSize]();
    if (midBuffer == nullptr) {
        IMAGE_LOGE("Apply space for dest buffer failed!");
        return false;
    }
    DestConvertParam midParam = {yDInfo.yWidth, yDInfo.yHeight};
    midParam.format = PixelFormat::RGB_888;
    midParam.buffer = midBuffer;
    midParam.slice[0] = midParam.buffer;
    midParam.stride[0] = static_cast<int>(yDInfo.yWidth * BYTES_PER_PIXEL_RGB);
    if (!SoftDecode(srcParam, midParam)) {
        IMAGE_LOGE("RGB manual conversion to YUV failed!");
        delete[] midBuffer;
        return false;
    }
    RGBDataInfo rgbInfo;
    rgbInfo.width = yDInfo.yWidth;
    rgbInfo.height = yDInfo.yHeight;
    Convert10bitInfo convertInfo;
    convertInfo.srcPixelFormat = PixelFormat::RGB_888;
    convertInfo.srcBytes = midParam.stride[0];
    convertInfo.dstPixelFormat = PixelFormat::RGBA_1010102;
    convertInfo.dstBytes = destParam.stride[0];
    if (!RGBAConvert(rgbInfo, midParam.slice[0], destParam.slice[0], convertInfo)) {
        IMAGE_LOGE("RGB888ToRGBA1010102: pixel convert in adapter failed.");
        delete[] midBuffer;
        return false;
    }
    delete[] midBuffer;
    return true;
}

static bool YUVToRGB10(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo, PixelFormat srcFormat,
    DestConvertInfo &destInfo, PixelFormat dstFormat)
{
    if (srcBuffer == nullptr || destInfo.buffer == nullptr || yDInfo.yWidth == 0 || yDInfo.yHeight == 0 ||
        yDInfo.uvWidth == 0 || yDInfo.uvHeight == 0) {
        return false;
    }
    SrcConvertParam srcParam = {yDInfo.yWidth, yDInfo.yHeight};
    srcParam.format = srcFormat;
    srcParam.buffer = srcBuffer;

    DestConvertParam destParam = {yDInfo.yWidth, yDInfo.yHeight};
    destParam.format = dstFormat;
    if (!YuvToRGBParam(yDInfo, srcParam, destParam, destInfo)) {
        IMAGE_LOGE("yuv conversion to RGB failed!");
        return false;
    }
    if (!YUVToRGBA1010102SoftDecode(yDInfo, srcParam, destParam)) {
        IMAGE_LOGE("YUVToRGBA1010102: pixel convert in adapter failed!");
        return false;
    }
    return true;
}

static bool YuvToYuvP010Param(const YUVDataInfo &yDInfo, SrcConvertParam &srcParam, DestConvertParam &destParam,
                              DestConvertInfo &destInfo)
{
    srcParam.slice[0] = srcParam.buffer + yDInfo.yOffset;
    srcParam.slice[1] = srcParam.buffer + yDInfo.uvOffset;

    srcParam.stride[0] = static_cast<int>(yDInfo.yStride);
    srcParam.stride[1] = static_cast<int>(yDInfo.uvStride);

    int dstyStride = 0;
    int dstuvStride = 0;
    if (destInfo.allocType == AllocatorType::DMA_ALLOC) {
        dstyStride = destInfo.yStride;
        dstuvStride = destInfo.uvStride;
        destParam.slice[0] = destInfo.buffer + destInfo.yOffset;
        destParam.slice[1] = destInfo.buffer + destInfo.uvOffset * TWO_SLICES;
    } else {
        dstyStride = static_cast<int>(destParam.width);
        dstuvStride = (destParam.width % EVEN_ODD_DIVISOR == 0) ? (destParam.width) : (destParam.width + 1);
        destParam.slice[0] = destInfo.buffer;
        destParam.slice[1] = destInfo.buffer + dstyStride * destParam.height * TWO_SLICES;
    }

    destParam.stride[0] = dstyStride * TWO_SLICES;
    destParam.stride[1] = dstuvStride * TWO_SLICES;
    return true;
}

static bool YuvToYuvP010(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo, PixelFormat srcFormat,
    DestConvertInfo &destInfo, PixelFormat dstFormat)
{
    if (srcBuffer == nullptr || destInfo.buffer == nullptr || yDInfo.yWidth == 0 || yDInfo.yHeight == 0 ||
        yDInfo.uvWidth == 0 || yDInfo.uvHeight == 0) {
        return false;
    }
    SrcConvertParam srcParam = {yDInfo.yWidth, yDInfo.yHeight};
    srcParam.format = srcFormat;
    srcParam.buffer = srcBuffer;
    DestConvertParam destParam = {yDInfo.yWidth, yDInfo.yHeight};
    destParam.format = dstFormat;
    if (!YuvToYuvP010Param(yDInfo, srcParam, destParam, destInfo)) {
        IMAGE_LOGE("yuv conversion to yuv failed!");
        return false;
    }
    if (!SoftDecode(srcParam, destParam)) {
        IMAGE_LOGE("yuv manual conversion to yuv failed!");
        return false;
    }
    if (destInfo.format == PixelFormat::YCRCB_P010) {
        if (!SwapNV21P010(destInfo)) {
            IMAGE_LOGE("SwapNV21P010 failed!");
            return false;
        }
    }
    return true;
}

static bool YuvP010ToYuvParam(const YUVDataInfo &yDInfo, SrcConvertParam &srcParam, DestConvertParam &destParam,
                              DestConvertInfo &destInfo)
{
    srcParam.slice[0] = srcParam.buffer + yDInfo.yOffset;
    srcParam.slice[1] = srcParam.buffer + yDInfo.uvOffset * TWO_SLICES;

    srcParam.stride[0] = static_cast<int>(yDInfo.yStride * TWO_SLICES);
    srcParam.stride[1] = static_cast<int>(yDInfo.uvStride * TWO_SLICES);

    int dstyStride = 0;
    int dstuvStride = 0;
    if (destInfo.allocType == AllocatorType::DMA_ALLOC) {
        dstyStride = destInfo.yStride;
        dstuvStride = destInfo.uvStride;
        destParam.slice[0] = destInfo.buffer + destInfo.yOffset;
        destParam.slice[1] = destInfo.buffer + destInfo.uvOffset;
    } else {
        dstyStride = static_cast<int>(destParam.width);
        dstuvStride = (destParam.width % EVEN_ODD_DIVISOR == 0) ? (destParam.width) : (destParam.width + 1);
        destParam.slice[0] = destInfo.buffer;
        destParam.slice[1] = destInfo.buffer + dstyStride * destParam.height;
    }

    destParam.stride[0] = dstyStride;
    destParam.stride[1] = dstuvStride;
    return true;
}

static bool YuvP010ToYuv(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo, PixelFormat srcFormat,
    DestConvertInfo &destInfo, PixelFormat dstFormat)
{
    if (srcBuffer == nullptr || destInfo.buffer == nullptr || yDInfo.yWidth == 0 || yDInfo.yHeight == 0 ||
        yDInfo.uvWidth == 0 || yDInfo.uvHeight == 0) {
        return false;
    }
    SrcConvertParam srcParam = {yDInfo.yWidth, yDInfo.yHeight};
    srcParam.format = srcFormat;
    srcParam.buffer = srcBuffer;
    DestConvertParam destParam = {yDInfo.yWidth, yDInfo.yHeight};
    destParam.format = dstFormat;
    if (!YuvP010ToYuvParam(yDInfo, srcParam, destParam, destInfo)) {
        IMAGE_LOGE("yuv conversion to yuv failed!");
        return false;
    }
    if (srcParam.format == PixelFormat::YCRCB_P010) {
        size_t midBufferSize =
            static_cast<size_t>((yDInfo.uvOffset + yDInfo.uvWidth * yDInfo.uvWidth * TWO_SLICES) * TWO_SLICES);
        if (midBufferSize == 0 || midBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
            IMAGE_LOGE("Invalid destination buffer size is 0!");
            return false;
        }
        uint8_t *midBuffer = nullptr;
        midBuffer = new(std::nothrow) uint8_t[midBufferSize]();
        if (midBuffer == nullptr) {
            IMAGE_LOGE("Apply space for dest buffer failed!");
            return false;
        }
        NV12P010ToNV21P010SoftDecode(srcParam.slice[0], yDInfo, midBuffer);
        SrcConvertParam midParam = {yDInfo.yWidth, yDInfo.yHeight};
        midParam.format = srcFormat;
        midParam.buffer = midBuffer;
        midParam.slice[0] = midParam.buffer + yDInfo.yOffset;
        midParam.slice[1] = midParam.buffer + yDInfo.uvOffset * TWO_SLICES;
        midParam.stride[0] = static_cast<int>(yDInfo.yStride) * TWO_SLICES;
        midParam.stride[1] = static_cast<int>(yDInfo.uvStride) * TWO_SLICES;
        if (!SoftDecode(midParam, destParam)) {
            IMAGE_LOGE("yuv manual conversion to yuv failed!");
            delete[] midBuffer;
            return false;
        }
        delete[] midBuffer;
        return true;
    }
    if (!SoftDecode(srcParam, destParam)) {
        IMAGE_LOGE("yuv manual conversion to yuv failed!");
        return false;
    }
    return true;
}

static bool YuvP010ToYuvP010Param(const YUVDataInfo &yDInfo, SrcConvertParam &srcParam, DestConvertParam &destParam,
                                  DestConvertInfo &destInfo)
{
    srcParam.slice[0] = srcParam.buffer + yDInfo.yOffset;
    srcParam.slice[1] = srcParam.buffer + yDInfo.uvOffset * TWO_SLICES;

    srcParam.stride[0] = static_cast<int>(yDInfo.yStride) * TWO_SLICES;
    srcParam.stride[1] = static_cast<int>(yDInfo.uvStride) * TWO_SLICES;

    int dstyStride = 0;
    int dstuvStride = 0;
    if (destInfo.allocType == AllocatorType::DMA_ALLOC) {
        dstyStride = destInfo.yStride;
        dstuvStride = destInfo.uvStride;
        destParam.slice[0] = destInfo.buffer + destInfo.yOffset;
        destParam.slice[1] = destInfo.buffer + destInfo.uvOffset * TWO_SLICES;
    } else {
        dstyStride = static_cast<int>(destParam.width);
        dstuvStride = (destParam.width % EVEN_ODD_DIVISOR == 0) ? (destParam.width) : (destParam.width + 1);
        destParam.slice[0] = destInfo.buffer;
        destParam.slice[1] = destInfo.buffer + dstyStride * destParam.height * TWO_SLICES;
    }

    destParam.stride[0] = dstyStride * TWO_SLICES;
    destParam.stride[1] = dstuvStride * TWO_SLICES;
    return true;
}

bool ImageFormatConvertUtils::NV12P010ToNV21P010(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                                 DestConvertInfo &destInfo, [[maybe_unused]]ColorSpace colorSpace)
{
    if (srcBuffer == nullptr || destInfo.buffer == nullptr || yDInfo.yWidth == 0 || yDInfo.yHeight == 0 ||
        yDInfo.uvWidth == 0 || yDInfo.uvHeight == 0) {
        return false;
    }
    SrcConvertParam srcParam = {yDInfo.yWidth, yDInfo.yHeight};
    srcParam.format = PixelFormat::YCBCR_P010;
    srcParam.buffer = srcBuffer;
    DestConvertParam destParam = {yDInfo.yWidth, yDInfo.yHeight};
    destParam.format = PixelFormat::YCRCB_P010;

    if (!YuvP010ToYuvP010Param(yDInfo, srcParam, destParam, destInfo)) {
        IMAGE_LOGE("yuvP010 conversion to yuv failed!");
        return false;
    }

    bool result = false;
    result = NV12P010ToNV21P010SoftDecode(srcParam.slice[0], yDInfo, destParam.slice[0]);
    if (!result) {
        IMAGE_LOGE("NV12P010ToNV21P010 failed!");
        return result;
    }
    return result;
}

static bool YuvP010ToRGB(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo, PixelFormat srcFormat,
    DestConvertInfo &destInfo, PixelFormat dstFormat)
{
    if (srcBuffer == nullptr || destInfo.buffer == nullptr || yDInfo.yWidth == 0 || yDInfo.yHeight == 0 ||
        yDInfo.uvWidth == 0 || yDInfo.uvHeight == 0) {
        return false;
    }
    SrcConvertParam srcParam = {yDInfo.yWidth, yDInfo.yHeight};
    srcParam.format = srcFormat;
    srcParam.buffer = srcBuffer;
    DestConvertParam destParam = {yDInfo.yWidth, yDInfo.yHeight};
    destParam.format = dstFormat;
    if (!YuvP010ToRGBParam(yDInfo, srcParam, destParam, destInfo)) {
        IMAGE_LOGE("yuv conversion to yuv failed!");
        return false;
    }
    if (srcParam.format == PixelFormat::YCRCB_P010) {
        size_t midBufferSize =
            static_cast<size_t>((yDInfo.uvOffset + yDInfo.uvWidth * yDInfo.uvWidth * TWO_SLICES) * TWO_SLICES);
        if (midBufferSize == 0 || midBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
            IMAGE_LOGE("Invalid destination buffer size is 0!");
            return false;
        }
        uint8_t *midBuffer = nullptr;
        midBuffer = new(std::nothrow) uint8_t[midBufferSize]();
        if (midBuffer == nullptr) {
            IMAGE_LOGE("Apply space for dest buffer failed!");
            return false;
        }
        NV12P010ToNV21P010SoftDecode(srcParam.slice[0], yDInfo, midBuffer);
        SrcConvertParam midParam = {yDInfo.yWidth, yDInfo.yHeight};
        midParam.format = srcFormat;
        midParam.buffer = midBuffer;
        midParam.slice[0] = midParam.buffer + yDInfo.yOffset;
        midParam.slice[1] = midParam.buffer + yDInfo.uvOffset * TWO_SLICES;
        midParam.stride[0] = static_cast<int>(yDInfo.yStride) * TWO_SLICES;
        midParam.stride[1] = static_cast<int>(yDInfo.uvStride) * TWO_SLICES;
        if (!SoftDecode(midParam, destParam)) {
            IMAGE_LOGE("yuv manual conversion to yuv failed!");
            delete[] midBuffer;
            return false;
        }
        delete[] midBuffer;
        return true;
    }
    if (!SoftDecode(srcParam, destParam)) {
        IMAGE_LOGE("yuv manual conversion to yuv failed!");
        return false;
    }
    return true;
}

bool ImageFormatConvertUtils::NV12P010ToRGB565(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                               DestConvertInfo &destInfo, [[maybe_unused]]ColorSpace colorSpace)
{
    return YuvP010ToRGB(srcBuffer, yDInfo, PixelFormat::YCBCR_P010, destInfo, PixelFormat::RGB_565);
}

bool ImageFormatConvertUtils::NV12P010ToRGBA8888(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                                 DestConvertInfo &destInfo, [[maybe_unused]]ColorSpace colorSpace)
{
    return YuvP010ToRGB(srcBuffer, yDInfo, PixelFormat::YCBCR_P010, destInfo, PixelFormat::RGBA_8888);
}

bool ImageFormatConvertUtils::NV12P010ToBGRA8888(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                                 DestConvertInfo &destInfo, [[maybe_unused]]ColorSpace colorSpace)
{
    return YuvP010ToRGB(srcBuffer, yDInfo, PixelFormat::YCBCR_P010, destInfo, PixelFormat::BGRA_8888);
}

bool ImageFormatConvertUtils::NV12P010ToRGB888(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                               DestConvertInfo &destInfo, [[maybe_unused]]ColorSpace colorSpace)
{
    return YuvP010ToRGB(srcBuffer, yDInfo, PixelFormat::YCBCR_P010, destInfo, PixelFormat::RGB_888);
}

bool ImageFormatConvertUtils::NV12P010ToRGBAF16(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                                DestConvertInfo &destInfo, [[maybe_unused]]ColorSpace colorSpace)
{
    return YuvP010ToRGB(srcBuffer, yDInfo, PixelFormat::YCBCR_P010, destInfo, PixelFormat::RGBA_F16);
}

bool ImageFormatConvertUtils::NV21P010ToNV12(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                             DestConvertInfo &destInfo, [[maybe_unused]]ColorSpace colorSpace)
{
    return YuvP010ToYuv(srcBuffer, yDInfo, PixelFormat::YCRCB_P010, destInfo, PixelFormat::NV12);
}

bool ImageFormatConvertUtils::NV21P010ToNV21(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                             DestConvertInfo &destInfo, [[maybe_unused]]ColorSpace colorSpace)
{
    return YuvP010ToYuv(srcBuffer, yDInfo, PixelFormat::YCRCB_P010, destInfo, PixelFormat::NV21);
}

bool ImageFormatConvertUtils::NV21P010ToNV12P010(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                                 DestConvertInfo &destInfo, [[maybe_unused]]ColorSpace colorSpace)
{
    if (srcBuffer == nullptr || destInfo.buffer == nullptr || yDInfo.yWidth == 0 || yDInfo.yHeight == 0 ||
        yDInfo.uvWidth == 0 || yDInfo.uvHeight == 0) {
        return false;
    }

    SrcConvertParam srcParam = {yDInfo.yWidth, yDInfo.yHeight};
    srcParam.format = PixelFormat::YCRCB_P010;
    srcParam.buffer = srcBuffer;
    DestConvertParam destParam = {yDInfo.yWidth, yDInfo.yHeight};
    destParam.format = PixelFormat::YCBCR_P010;

    if (!YuvP010ToYuvP010Param(yDInfo, srcParam, destParam, destInfo)) {
        IMAGE_LOGE("yuvP010 conversion to yuv failed!");
        return false;
    }

    bool result = false;
    result = NV12P010ToNV21P010SoftDecode(srcParam.slice[0], yDInfo, destParam.slice[0]);
    if (!result) {
        IMAGE_LOGE("NV12P010ToNV21P010 failed!");
        return result;
    }
    return result;
}

bool ImageFormatConvertUtils::NV21P010ToRGB565(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                               DestConvertInfo &destInfo, [[maybe_unused]]ColorSpace colorSpace)
{
    return YuvP010ToRGB(srcBuffer, yDInfo, PixelFormat::YCRCB_P010, destInfo, PixelFormat::RGB_565);
}

bool ImageFormatConvertUtils::NV21P010ToRGBA8888(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                                 DestConvertInfo &destInfo, [[maybe_unused]]ColorSpace colorSpace)
{
    return YuvP010ToRGB(srcBuffer, yDInfo, PixelFormat::YCRCB_P010, destInfo, PixelFormat::RGBA_8888);
}

bool ImageFormatConvertUtils::NV21P010ToBGRA8888(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                                 DestConvertInfo &destInfo, [[maybe_unused]]ColorSpace colorSpace)
{
    return YuvP010ToRGB(srcBuffer, yDInfo, PixelFormat::YCRCB_P010, destInfo, PixelFormat::BGRA_8888);
}

bool ImageFormatConvertUtils::NV21P010ToRGB888(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                               DestConvertInfo &destInfo, [[maybe_unused]]ColorSpace colorSpace)
{
    return YuvP010ToRGB(srcBuffer, yDInfo, PixelFormat::YCRCB_P010, destInfo, PixelFormat::RGB_888);
}

bool ImageFormatConvertUtils::NV21P010ToRGBAF16(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                                DestConvertInfo &destInfo, [[maybe_unused]]ColorSpace colorSpace)
{
    return YuvP010ToRGB(srcBuffer, yDInfo, PixelFormat::YCRCB_P010, destInfo, PixelFormat::RGBA_F16);
}

bool ImageFormatConvertUtils::NV12P010ToNV12(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                             DestConvertInfo &destInfo, [[maybe_unused]]ColorSpace colorSpace)
{
    return YuvP010ToYuv(srcBuffer, yDInfo, PixelFormat::YCBCR_P010, destInfo, PixelFormat::NV12);
}

bool ImageFormatConvertUtils::NV12P010ToNV21(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                             DestConvertInfo &destInfo, [[maybe_unused]]ColorSpace colorSpace)
{
    return YuvP010ToYuv(srcBuffer, yDInfo, PixelFormat::YCBCR_P010, destInfo, PixelFormat::NV21);
}

bool ImageFormatConvertUtils::NV12ToNV12P010(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                             DestConvertInfo &destInfo, [[maybe_unused]]ColorSpace colorSpace)
{
    return YuvToYuvP010(srcBuffer, yDInfo, PixelFormat::NV12, destInfo, PixelFormat::YCBCR_P010);
}

bool ImageFormatConvertUtils::NV12ToNV21P010(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                             DestConvertInfo &destInfo, [[maybe_unused]]ColorSpace colorSpace)
{
    return YuvToYuvP010(srcBuffer, yDInfo, PixelFormat::NV12, destInfo, PixelFormat::YCRCB_P010);
}
bool ImageFormatConvertUtils::NV21ToNV12P010(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                             DestConvertInfo &destInfo, [[maybe_unused]]ColorSpace colorSpace)
{
    return YuvToYuvP010(srcBuffer, yDInfo, PixelFormat::NV21, destInfo, PixelFormat::YCBCR_P010);
}
bool ImageFormatConvertUtils::NV21ToNV21P010(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                             DestConvertInfo &destInfo, [[maybe_unused]]ColorSpace colorSpace)
{
    return YuvToYuvP010(srcBuffer, yDInfo, PixelFormat::NV21, destInfo, PixelFormat::YCRCB_P010);
}

bool ImageFormatConvertUtils::NV12ToRGBA1010102(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                                DestConvertInfo &destInfo, [[maybe_unused]]ColorSpace colorSpace)
{
    return YUVToRGB10(srcBuffer, yDInfo, PixelFormat::NV12, destInfo, PixelFormat::RGBA_1010102);
}

bool ImageFormatConvertUtils::NV21ToRGBA1010102(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                                DestConvertInfo &destInfo, [[maybe_unused]]ColorSpace colorSpace)
{
    return YUVToRGB10(srcBuffer, yDInfo, PixelFormat::NV21, destInfo, PixelFormat::RGBA_1010102);
}

bool ImageFormatConvertUtils::NV12P010ToRGBA1010102(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                                    DestConvertInfo &destInfo, [[maybe_unused]]ColorSpace colorSpace)
{
    return YuvP010ToRGB10(srcBuffer, yDInfo, PixelFormat::YCBCR_P010, destInfo, PixelFormat::RGBA_1010102);
}

bool ImageFormatConvertUtils::NV21P010ToRGBA1010102(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                                    DestConvertInfo &destInfo, [[maybe_unused]]ColorSpace colorSpace)
{
    return YuvP010ToRGB10(srcBuffer, yDInfo, PixelFormat::YCRCB_P010, destInfo, PixelFormat::RGBA_1010102);
}

bool ImageFormatConvertUtils::RGB565ToNV12P010(const uint8_t *srcBuffer, const RGBDataInfo &rgbInfo,
                                               DestConvertInfo &destInfo, [[maybe_unused]]ColorSpace colorSpace)
{
    return RGBToYuvP010(srcBuffer, rgbInfo, PixelFormat::RGB_565, destInfo, PixelFormat::YCBCR_P010);
}

bool ImageFormatConvertUtils::RGB565ToNV21P010(const uint8_t *srcBuffer, const RGBDataInfo &rgbInfo,
                                               DestConvertInfo &destInfo, [[maybe_unused]]ColorSpace colorSpace)
{
    return RGBToYuvP010(srcBuffer, rgbInfo, PixelFormat::RGB_565, destInfo, PixelFormat::YCRCB_P010);
}

bool ImageFormatConvertUtils::RGBAToNV12P010(const uint8_t *srcBuffer, const RGBDataInfo &rgbInfo,
                                             DestConvertInfo &destInfo, [[maybe_unused]]ColorSpace colorSpace)
{
    return RGBToYuvP010(srcBuffer, rgbInfo, PixelFormat::RGBA_8888, destInfo, PixelFormat::YCBCR_P010);
}

bool ImageFormatConvertUtils::RGBAToNV21P010(const uint8_t *srcBuffer, const RGBDataInfo &rgbInfo,
                                             DestConvertInfo &destInfo, [[maybe_unused]]ColorSpace colorSpace)
{
    return RGBToYuvP010(srcBuffer, rgbInfo, PixelFormat::RGBA_8888, destInfo, PixelFormat::YCRCB_P010);
}

bool ImageFormatConvertUtils::BGRAToNV12P010(const uint8_t *srcBuffer, const RGBDataInfo &rgbInfo,
                                             DestConvertInfo &destInfo, [[maybe_unused]]ColorSpace colorSpace)
{
    return RGBToYuvP010(srcBuffer, rgbInfo, PixelFormat::BGRA_8888, destInfo, PixelFormat::YCBCR_P010);
}

bool ImageFormatConvertUtils::BGRAToNV21P010(const uint8_t *srcBuffer, const RGBDataInfo &rgbInfo,
                                             DestConvertInfo &destInfo, [[maybe_unused]]ColorSpace colorSpace)
{
    return RGBToYuvP010(srcBuffer, rgbInfo, PixelFormat::BGRA_8888, destInfo, PixelFormat::YCRCB_P010);
}

bool ImageFormatConvertUtils::RGBToNV12P010(const uint8_t *srcBuffer, const RGBDataInfo &rgbInfo,
                                            DestConvertInfo &destInfo, [[maybe_unused]]ColorSpace colorSpace)
{
    return RGBToYuvP010(srcBuffer, rgbInfo, PixelFormat::RGB_888, destInfo, PixelFormat::YCBCR_P010);
}

bool ImageFormatConvertUtils::RGBToNV21P010(const uint8_t *srcBuffer, const RGBDataInfo &rgbInfo,
                                            DestConvertInfo &destInfo, [[maybe_unused]]ColorSpace colorSpace)
{
    return RGBToYuvP010(srcBuffer, rgbInfo, PixelFormat::RGB_888, destInfo, PixelFormat::YCRCB_P010);
}

bool ImageFormatConvertUtils::RGBAF16ToNV12P010(const uint8_t *srcBuffer, const RGBDataInfo &rgbInfo,
                                                DestConvertInfo &destInfo, [[maybe_unused]]ColorSpace colorSpace)
{
    return RGBToYuvP010(srcBuffer, rgbInfo, PixelFormat::RGBA_F16, destInfo, PixelFormat::YCBCR_P010);
}

bool ImageFormatConvertUtils::RGBAF16ToNV21P010(const uint8_t *srcBuffer, const RGBDataInfo &rgbInfo,
                                                DestConvertInfo &destInfo, [[maybe_unused]]ColorSpace colorSpace)
{
    return RGBToYuvP010(srcBuffer, rgbInfo, PixelFormat::RGBA_F16, destInfo, PixelFormat::YCRCB_P010);
}

bool ImageFormatConvertUtils::RGBA1010102ToNV12(const uint8_t *srcBuffer, const RGBDataInfo &rgbInfo,
                                                DestConvertInfo &destInfo, [[maybe_unused]]ColorSpace colorSpace)
{
    return RGB10ToYuv(srcBuffer, rgbInfo, PixelFormat::RGBA_1010102, destInfo, PixelFormat::NV12);
}

bool ImageFormatConvertUtils::RGBA1010102ToNV21(const uint8_t *srcBuffer, const RGBDataInfo &rgbInfo,
                                                DestConvertInfo &destInfo, [[maybe_unused]]ColorSpace colorSpace)
{
    return RGB10ToYuv(srcBuffer, rgbInfo, PixelFormat::RGBA_1010102, destInfo, PixelFormat::NV21);
}

bool ImageFormatConvertUtils::RGBA1010102ToNV12P010(const uint8_t *srcBuffer, const RGBDataInfo &rgbInfo,
                                                    DestConvertInfo &destInfo, [[maybe_unused]]ColorSpace colorSpace)
{
    return RGB10ToYuvP010(srcBuffer, rgbInfo, PixelFormat::RGBA_1010102, destInfo, PixelFormat::YCBCR_P010);
}

bool ImageFormatConvertUtils::RGBA1010102ToNV21P010(const uint8_t *srcBuffer, const RGBDataInfo &rgbInfo,
                                                    DestConvertInfo &destInfo, [[maybe_unused]]ColorSpace colorSpace)
{
    return RGB10ToYuvP010(srcBuffer, rgbInfo, PixelFormat::RGBA_1010102, destInfo, PixelFormat::YCRCB_P010);
}

static bool YuvToYuvParam(const YUVDataInfo &yDInfo, SrcConvertParam &srcParam, DestConvertParam &destParam,
                          DestConvertInfo &destInfo)
{
    srcParam.slice[0] = srcParam.buffer + yDInfo.yOffset;
    srcParam.slice[1] = srcParam.buffer + yDInfo.uvOffset;

    srcParam.stride[0] = static_cast<int>(yDInfo.yStride);
    srcParam.stride[1] = static_cast<int>(yDInfo.uvStride);

    int dstyStride = 0;
    int dstuvStride = 0;
    if (destInfo.allocType == AllocatorType::DMA_ALLOC) {
        dstyStride = destInfo.yStride;
        dstuvStride = destInfo.uvStride;
        destParam.slice[0] = destInfo.buffer + destInfo.yOffset;
        destParam.slice[1] = destInfo.buffer + destInfo.uvOffset;
    } else {
        dstyStride = static_cast<int>(destParam.width);
        dstuvStride = (destParam.width % EVEN_ODD_DIVISOR == 0) ? (destParam.width) : (destParam.width + 1);
        destParam.slice[0] = destInfo.buffer;
        destParam.slice[1] = destInfo.buffer + dstyStride * destParam.height;
    }

    destParam.stride[0] = dstyStride;
    destParam.stride[1] = dstuvStride;
    return true;
}

static bool YuvToYuv(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo, PixelFormat srcFormat,
                     DestConvertInfo &destInfo, PixelFormat destFormat)
{
    if (srcBuffer == nullptr || destInfo.buffer == nullptr || yDInfo.yWidth == 0 || yDInfo.yHeight == 0 ||
        yDInfo.uvWidth == 0 || yDInfo.uvHeight == 0 || destInfo.bufferSize == 0) {
        return false;
    }
    SrcConvertParam srcParam = {yDInfo.yWidth, yDInfo.yHeight};
    srcParam.format = srcFormat;
    srcParam.buffer = srcBuffer;

    DestConvertParam destParam = {destInfo.width, destInfo.height};
    destParam.format = destFormat;

    if (!YuvToYuvParam(yDInfo, srcParam, destParam, destInfo)) {
        IMAGE_LOGE("yuv conversion to yuv failed!");
        return false;
    }
    if (!SoftDecode(srcParam, destParam)) {
        IMAGE_LOGE("yuv manual conversion to yuv failed!");
        return false;
    }
    return true;
}

static bool YuvToRGB(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo, PixelFormat srcFormat,
                     DestConvertInfo &destInfo, PixelFormat destFormat)
{
    if (srcBuffer == nullptr || destInfo.buffer == nullptr || yDInfo.yWidth == 0 || yDInfo.yHeight == 0 ||
        yDInfo.uvWidth == 0 || yDInfo.uvHeight == 0 || destInfo.bufferSize == 0) {
        return false;
    }
    SrcConvertParam srcParam = {yDInfo.yWidth, yDInfo.yHeight};
    srcParam.format = srcFormat;
    srcParam.buffer = srcBuffer;

    DestConvertParam destParam = {destInfo.width, destInfo.height};
    destParam.format = destFormat;

    if (!YuvToRGBParam(yDInfo, srcParam, destParam, destInfo)) {
        IMAGE_LOGE("yuv conversion to RGB failed!");
        return false;
    }
    if (!SoftDecode(srcParam, destParam)) {
        IMAGE_LOGE("yuv manual conversion to RGB failed!");
        return false;
    }
    return true;
}

static bool RGBToYuv(const uint8_t *srcBuffer, const RGBDataInfo &rgbInfo, PixelFormat srcFormat,
                     DestConvertInfo &destInfo, PixelFormat destFormat)
{
    if (srcBuffer == nullptr || destInfo.buffer == nullptr || rgbInfo.width == 0 || rgbInfo.height == 0 ||
        destInfo.bufferSize == 0) {
        return false;
    }
    SrcConvertParam srcParam = {rgbInfo.width, rgbInfo.height};
    srcParam.format = srcFormat;
    srcParam.buffer = srcBuffer;

    DestConvertParam destParam = {destInfo.width, destInfo.height};
    destParam.format = destFormat;

    if (!RGBToYuvParam(rgbInfo, srcParam, destParam, destInfo)) {
        IMAGE_LOGE("RGB conversion to YUV failed!");
        return false;
    }
    if (!SoftDecode(srcParam, destParam)) {
        IMAGE_LOGE("RGB manual conversion to YUV failed!");
        return false;
    }
    return true;
}

bool ImageFormatConvertUtils::NV12ToRGB565(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                           DestConvertInfo &destInfo,
                                           [[maybe_unused]]ColorSpace colorSpace)
{
    return YuvToRGB(srcBuffer, yDInfo, PixelFormat::NV12, destInfo, PixelFormat::RGB_565);
}

bool ImageFormatConvertUtils::NV21ToRGB565(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                           DestConvertInfo &destInfo,
                                           [[maybe_unused]]ColorSpace colorSpace)
{
    return YuvToRGB(srcBuffer, yDInfo, PixelFormat::NV21, destInfo, PixelFormat::RGB_565);
}

bool ImageFormatConvertUtils::NV21ToRGB(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                        DestConvertInfo &destInfo,
                                        [[maybe_unused]]ColorSpace colorSpace)
{
    return YuvToRGB(srcBuffer, yDInfo, PixelFormat::NV21, destInfo, PixelFormat::RGB_888);
}

bool ImageFormatConvertUtils::NV12ToRGB(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                        DestConvertInfo &destInfo,
                                        [[maybe_unused]]ColorSpace colorSpace)
{
    return YuvToRGB(srcBuffer, yDInfo, PixelFormat::NV12, destInfo, PixelFormat::RGB_888);
}

bool ImageFormatConvertUtils::NV21ToRGBA(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                         DestConvertInfo &destInfo,
                                         [[maybe_unused]]ColorSpace colorSpace)
{
    return YuvToRGB(srcBuffer, yDInfo, PixelFormat::NV21, destInfo, PixelFormat::RGBA_8888);
}

bool ImageFormatConvertUtils::NV12ToRGBA(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                         DestConvertInfo &destInfo,
                                         [[maybe_unused]]ColorSpace colorSpace)
{
    return YuvToRGB(srcBuffer, yDInfo, PixelFormat::NV12, destInfo, PixelFormat::RGBA_8888);
}

bool ImageFormatConvertUtils::NV21ToBGRA(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                         DestConvertInfo &destInfo,
                                         [[maybe_unused]]ColorSpace colorSpace)
{
    return YuvToRGB(srcBuffer, yDInfo, PixelFormat::NV21, destInfo, PixelFormat::BGRA_8888);
}

bool ImageFormatConvertUtils::NV12ToBGRA(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                         DestConvertInfo &destInfo,
                                         [[maybe_unused]]ColorSpace colorSpace)
{
    return YuvToRGB(srcBuffer, yDInfo, PixelFormat::NV12, destInfo, PixelFormat::BGRA_8888);
}

bool ImageFormatConvertUtils::NV21ToRGBAF16(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                            DestConvertInfo &destInfo,
                                            [[maybe_unused]]ColorSpace colorSpace)
{
    return YuvToRGB(srcBuffer, yDInfo, PixelFormat::NV12, destInfo, PixelFormat::RGBA_F16);
}

bool ImageFormatConvertUtils::NV12ToRGBAF16(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                            DestConvertInfo &destInfo,
                                            [[maybe_unused]]ColorSpace colorSpace)
{
    return YuvToRGB(srcBuffer, yDInfo, PixelFormat::NV12, destInfo, PixelFormat::RGBA_F16);
}

bool ImageFormatConvertUtils::NV12ToNV21(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                         DestConvertInfo &destInfo,
                                         [[maybe_unused]]ColorSpace colorSpace)
{
    return YuvToYuv(srcBuffer, yDInfo, PixelFormat::NV12, destInfo, PixelFormat::NV21);
}

bool ImageFormatConvertUtils::NV21ToNV12(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                         DestConvertInfo &destInfo,
                                         [[maybe_unused]]ColorSpace colorSpace)
{
    return YuvToYuv(srcBuffer, yDInfo, PixelFormat::NV21, destInfo, PixelFormat::NV12);
}

bool ImageFormatConvertUtils::RGBToNV21(const uint8_t *srcBuffer, const RGBDataInfo &rgbInfo,
                                        DestConvertInfo &destInfo,
                                        [[maybe_unused]]ColorSpace colorSpace)
{
    return RGBToYuv(srcBuffer, rgbInfo, PixelFormat::RGB_888, destInfo, PixelFormat::NV21);
}

bool ImageFormatConvertUtils::RGBToNV12(const uint8_t *srcBuffer, const RGBDataInfo &rgbInfo,
                                        DestConvertInfo &destInfo,
                                        [[maybe_unused]]ColorSpace colorSpace)
{
    return RGBToYuv(srcBuffer, rgbInfo, PixelFormat::RGB_888, destInfo, PixelFormat::NV12);
}

bool ImageFormatConvertUtils::RGB565ToNV21(const uint8_t *srcBuffer, const RGBDataInfo &rgbInfo,
                                           DestConvertInfo &destInfo,
                                           [[maybe_unused]]ColorSpace colorSpace)
{
    return RGBToYuv(srcBuffer, rgbInfo, PixelFormat::RGB_565, destInfo, PixelFormat::NV21);
}

bool ImageFormatConvertUtils::RGB565ToNV12(const uint8_t *srcBuffer, const RGBDataInfo &rgbInfo,
                                           DestConvertInfo &destInfo,
                                           [[maybe_unused]]ColorSpace colorSpace)
{
    return RGBToYuv(srcBuffer, rgbInfo, PixelFormat::RGB_565, destInfo, PixelFormat::NV12);
}

bool ImageFormatConvertUtils::RGBAToNV21(const uint8_t *srcBuffer, const RGBDataInfo &rgbInfo,
                                         DestConvertInfo &destInfo,
                                         [[maybe_unused]]ColorSpace colorSpace)
{
    return RGBToYuv(srcBuffer, rgbInfo, PixelFormat::RGBA_8888, destInfo, PixelFormat::NV21);
}

bool ImageFormatConvertUtils::RGBAToNV12(const uint8_t *srcBuffer, const RGBDataInfo &rgbInfo,
                                         DestConvertInfo &destInfo,
                                         [[maybe_unused]]ColorSpace colorSpace)
{
    return RGBToYuv(srcBuffer, rgbInfo, PixelFormat::RGBA_8888, destInfo, PixelFormat::NV12);
}

bool ImageFormatConvertUtils::BGRAToNV21(const uint8_t *srcBuffer, const RGBDataInfo &rgbInfo,
                                         DestConvertInfo &destInfo,
                                         [[maybe_unused]]ColorSpace colorSpace)
{
    return RGBToYuv(srcBuffer, rgbInfo, PixelFormat::BGRA_8888, destInfo, PixelFormat::NV21);
}

bool ImageFormatConvertUtils::BGRAToNV12(const uint8_t *srcBuffer, const RGBDataInfo &rgbInfo,
                                         DestConvertInfo &destInfo,
                                         [[maybe_unused]]ColorSpace colorSpace)
{
    return RGBToYuv(srcBuffer, rgbInfo, PixelFormat::BGRA_8888, destInfo, PixelFormat::NV12);
}

bool ImageFormatConvertUtils::RGBAF16ToNV21(const uint8_t *srcBuffer, const RGBDataInfo &rgbInfo,
                                            DestConvertInfo &destInfo,
                                            [[maybe_unused]]ColorSpace colorSpace)
{
    return RGBToYuv(srcBuffer, rgbInfo, PixelFormat::RGBA_F16, destInfo, PixelFormat::NV21);
}

bool ImageFormatConvertUtils::RGBAF16ToNV12(const uint8_t *srcBuffer, const RGBDataInfo &rgbInfo,
                                            DestConvertInfo &destInfo,
                                            [[maybe_unused]]ColorSpace colorSpace)
{
    return RGBToYuv(srcBuffer, rgbInfo, PixelFormat::RGBA_F16, destInfo, PixelFormat::NV12);
}
} // namespace Media
} // namespace OHOS