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

static bool YUVToP010SoftDecode(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo, uint8_t **destBuffer,
    PixelFormat srcPixelFormat, PixelFormat dstPixelFormat)
{
    AVPixelFormat srcFormat = findPixelFormat(srcPixelFormat);
    AVPixelFormat dstFormat = findPixelFormat(dstPixelFormat);
    SwsContext *swsContext = sws_getContext(yDInfo.yWidth, yDInfo.yHeight, srcFormat, yDInfo.yWidth,
        yDInfo.yHeight, dstFormat, SWS_BILINEAR, nullptr, nullptr, nullptr);
    if (swsContext == nullptr) {
        IMAGE_LOGE("Error to create SwsContext.");
        return false;
    }

    int widthEven = (yDInfo.yWidth % EVEN_ODD_DIVISOR == 0) ? (yDInfo.yWidth) : (yDInfo.yWidth + 1);
    const uint8_t *srcSlice[] = {srcBuffer + yDInfo.yOffset, srcBuffer + yDInfo.uvOffset};
    const int srcStride[] = {static_cast<int>(yDInfo.yStride), static_cast<int>(yDInfo.uvStride)};
    uint8_t *dstSlice[] = {*destBuffer, *destBuffer + yDInfo.yWidth * yDInfo.yHeight * TWO_SLICES};
    const int dstStride[] = {static_cast<int>(yDInfo.yWidth) * TWO_SLICES,
        static_cast<int>(widthEven) * TWO_SLICES};

    int height = sws_scale(swsContext, srcSlice, srcStride, SRCSLICEY, yDInfo.yHeight, dstSlice, dstStride);
    sws_freeContext(swsContext);
    if (height == 0) {
        IMAGE_LOGE("Image pixel format conversion failed");
        return false;
    }
    return true;
}

static bool P010ToYUVSoftDecode(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo, uint8_t **destBuffer,
    PixelFormat srcPixelFormat, PixelFormat dstPixelFormat)
{
    AVPixelFormat srcFormat = findPixelFormat(srcPixelFormat);
    AVPixelFormat dstFormat = findPixelFormat(dstPixelFormat);
    SwsContext *swsContext = sws_getContext(yDInfo.yWidth, yDInfo.yHeight, srcFormat, yDInfo.yWidth,
        yDInfo.yHeight, dstFormat, SWS_BILINEAR, nullptr, nullptr, nullptr);
    if (swsContext == nullptr) {
        IMAGE_LOGE("Error to create SwsContext.");
        return false;
    }

    int widthEven = (yDInfo.yWidth % EVEN_ODD_DIVISOR == 0) ? (yDInfo.yWidth) : (yDInfo.yWidth + 1);
    const uint8_t *srcSlice[] = {srcBuffer, srcBuffer + yDInfo.uvOffset * TWO_SLICES};
    const int srcStride[] = {static_cast<int>(yDInfo.yStride) * TWO_SLICES,
        static_cast<int>(yDInfo.yStride) * TWO_SLICES};
    uint8_t *dstSlice[] = {*destBuffer, *destBuffer + widthEven * yDInfo.yHeight};
    const int dstStride[] = {static_cast<int>(yDInfo.yWidth), static_cast<int>(widthEven)};

    int height = sws_scale(swsContext, srcSlice, srcStride, SRCSLICEY, yDInfo.yHeight, dstSlice, dstStride);
    sws_freeContext(swsContext);
    if (height == 0) {
        IMAGE_LOGE("Image pixel format conversion failed");
        return false;
    }
    return true;
}

static bool NV12P010ToNV21P010SoftDecode(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo, uint8_t **destBuffer)
{
    const uint16_t *src = reinterpret_cast<const uint16_t *>(srcBuffer);
    uint16_t *dst = reinterpret_cast<uint16_t *>(*destBuffer);
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

static bool P010ToRGBASoftDecode(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo, uint8_t **destBuffer,
    Convert10bitInfo convertInfo)
{
    AVPixelFormat srcFormat = findPixelFormat(convertInfo.srcPixelFormat);
    AVPixelFormat dstFormat = findPixelFormat(convertInfo.dstPixelFormat);
    SwsContext *swsContext = sws_getContext(yDInfo.yWidth, yDInfo.yHeight, srcFormat, yDInfo.yWidth,
        yDInfo.yHeight, dstFormat, SWS_BILINEAR, nullptr, nullptr, nullptr);
    if (swsContext == nullptr) {
        IMAGE_LOGD("Error to create SwsContext.");
        return false;
    }
    const uint8_t *srcSlice[] = {srcBuffer, srcBuffer + yDInfo.uvOffset * TWO_SLICES};
    const int srcStride[] = {static_cast<int>(yDInfo.yStride) * TWO_SLICES,
        static_cast<int>(yDInfo.yStride) * TWO_SLICES};
    const int dstStride[] = {static_cast<int>(yDInfo.yStride * convertInfo.dstBytes)};
    int height = sws_scale(swsContext, srcSlice, srcStride, SRCSLICEY, yDInfo.yHeight, destBuffer, dstStride);
    sws_freeContext(swsContext);
    if (height == 0) {
        IMAGE_LOGE("Image pixel format conversion failed");
        return false;
    }
    return true;
}

static bool RGBAConvert(const YUVDataInfo &yDInfo, const uint8_t *srcBuffer, uint8_t *dstBuffer,
                        Convert10bitInfo convertInfo)
{
    ImageInfo srcInfo;
    ImageInfo dstInfo;
    srcInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_PREMUL;
    dstInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_PREMUL;
    srcInfo.pixelFormat = convertInfo.srcPixelFormat;
    dstInfo.pixelFormat = convertInfo.dstPixelFormat;
    srcInfo.size.width = yDInfo.yWidth;
    srcInfo.size.height = yDInfo.yHeight;
    dstInfo.size.width = yDInfo.yWidth;
    dstInfo.size.height = yDInfo.yHeight;

    Position pos;
    if (!PixelConvertAdapter::WritePixelsConvert(srcBuffer, yDInfo.yWidth * convertInfo.srcBytes, srcInfo,
        dstBuffer, pos, yDInfo.yWidth * convertInfo.dstBytes, dstInfo)) {
        IMAGE_LOGE("RGBAConvert: pixel convert in adapter failed.");
        return false;
    }
    return true;
}

static bool P010ToRGBA1010102SoftDecode(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo, uint8_t **destBuffer)
{
    uint8_t *midBuffer = nullptr;
    size_t midBufferSize = static_cast<size_t>(yDInfo.uvOffset * STRIDES_PER_PLANE);
    if (midBufferSize == 0 || midBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size is 0!");
        return false;
    }
    midBuffer = new(std::nothrow) uint8_t[midBufferSize]();
    if (midBuffer == nullptr) {
        IMAGE_LOGE("apply space for dest buffer failed!");
        return false;
    }
    Convert10bitInfo yuvToRgba;
    yuvToRgba.srcPixelFormat = PixelFormat::YCBCR_P010;
    yuvToRgba.dstPixelFormat = PixelFormat::RGBA_F16;
    yuvToRgba.dstBytes = STRIDES_PER_PLANE;
    bool result = P010ToRGBASoftDecode(srcBuffer, yDInfo, &midBuffer, yuvToRgba);
    if (!result) {
        IMAGE_LOGE("NV12P010ToRGBAF16 failed!");
        delete[] midBuffer;
        return result;
    }
    Convert10bitInfo rgbaToRgba;
    rgbaToRgba.srcPixelFormat = PixelFormat::RGBA_U16;
    rgbaToRgba.srcBytes = STRIDES_PER_PLANE;
    rgbaToRgba.dstPixelFormat = PixelFormat::RGBA_1010102;
    rgbaToRgba.dstBytes = BYTES_PER_PIXEL_RGBA;
    if (!RGBAConvert(yDInfo, midBuffer, *destBuffer, rgbaToRgba)) {
        IMAGE_LOGE("RGBAF16ToRGBA1010102: pixel convert in adapter failed.");
        delete[] midBuffer;
        return false;
    }
    delete[] midBuffer;
    return true;
}

bool ImageFormatConvertUtils::NV12P010ToRGBA1010102(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                                    uint8_t **destBuffer, size_t &destBufferSize,
                                                    [[maybe_unused]]ColorSpace colorSpace)
{
    if (srcBuffer == nullptr || destBuffer == nullptr || yDInfo.yWidth == 0 || yDInfo.yHeight == 0 ||
        yDInfo.uvWidth == 0 || yDInfo.uvHeight == 0) {
        return false;
    }
    destBufferSize = static_cast<size_t>(yDInfo.uvOffset * BYTES_PER_PIXEL_RGBA);
    if (destBufferSize == 0 || destBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size calculation!");
        return false;
    }
    *destBuffer = new(std::nothrow) uint8_t[destBufferSize]();
    if (*destBuffer == nullptr) {
        IMAGE_LOGE("apply space for dest buffer failed!");
        return false;
    }
    bool result = P010ToRGBA1010102SoftDecode(srcBuffer, yDInfo, destBuffer);
    if (!result) {
        IMAGE_LOGE("NV12P010ToRGBA1010102 failed!");
        delete[] (*destBuffer);
        *destBuffer = nullptr;
        return false;
    }
    return true;
}

bool ImageFormatConvertUtils::NV21P010ToRGBA1010102(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                                    uint8_t **destBuffer, size_t &destBufferSize,
                                                    [[maybe_unused]]ColorSpace colorSpace)
{
    if (srcBuffer == nullptr || destBuffer == nullptr || yDInfo.yWidth == 0 || yDInfo.yHeight == 0 ||
        yDInfo.uvWidth == 0 || yDInfo.uvHeight == 0) {
        return false;
    }
    size_t midBufferSize = yDInfo.yWidth * yDInfo.yHeight + yDInfo.uvWidth * EVEN_ODD_DIVISOR * yDInfo.uvHeight;
    if (midBufferSize == 0 || midBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size calculation!");
        return false;
    }
    uint8_t *midBuffer = nullptr;
    midBuffer = new(std::nothrow) uint8_t[midBufferSize * TWO_SLICES]();
    if (midBuffer == nullptr) {
        IMAGE_LOGE("apply space for dest buffer failed!");
        return false;
    }
    bool result = false;
    result = NV12P010ToNV21P010SoftDecode(srcBuffer, yDInfo, &midBuffer);
    if (!result) {
        IMAGE_LOGE("NV12P010ToNV21P010 failed!");
        delete[] midBuffer;
        return false;
    }
    destBufferSize = static_cast<size_t>(yDInfo.uvOffset * BYTES_PER_PIXEL_RGBA);
    if (destBufferSize == 0 || destBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size calculation!");
        return false;
    }
    *destBuffer = new(std::nothrow) uint8_t[destBufferSize]();
    if (*destBuffer == nullptr) {
        IMAGE_LOGE("apply space for dest buffer failed!");
        delete[] midBuffer;
        return false;
    }
    result = P010ToRGBA1010102SoftDecode(midBuffer, yDInfo, destBuffer);
    if (!result) {
        IMAGE_LOGE("NV12P010ToRGBA1010102 failed!");
        delete[] midBuffer;
        delete[] (*destBuffer);
        *destBuffer = nullptr;
        return false;
    }
    delete[] midBuffer;
    return true;
}

static bool RGBAToP010SoftDecode(const uint8_t *srcBuffer, const RGBDataInfo &imageSize, uint8_t **destBuffer,
                                 Convert10bitInfo convertInfo)
{
    AVPixelFormat srcFormat = findPixelFormat(convertInfo.srcPixelFormat);
    AVPixelFormat dstFormat = findPixelFormat(convertInfo.dstPixelFormat);
    SwsContext *swsContext = sws_getContext(imageSize.width, imageSize.height, srcFormat, imageSize.width,
        imageSize.height, dstFormat, SWS_BILINEAR, nullptr, nullptr, nullptr);
    if (swsContext == nullptr) {
        IMAGE_LOGE("Error to create SwsContext.");
        return false;
    }
    int widthEven = (imageSize.width % EVEN_ODD_DIVISOR == 0) ? (imageSize.width) : (imageSize.width + 1);
    const uint8_t *srcSlice[] = {srcBuffer};
    const int srcStride[] = {static_cast<int>(imageSize.width * convertInfo.srcBytes)};
    uint8_t *dstSlice[] = {*destBuffer, *destBuffer + imageSize.width * imageSize.height * TWO_SLICES};
    const int dstStride[] = {static_cast<int>(imageSize.width) * TWO_SLICES,
        static_cast<int>(widthEven) * TWO_SLICES};
    int height = sws_scale(swsContext, srcSlice, srcStride, SRCSLICEY, imageSize.height, dstSlice, dstStride);
    sws_freeContext(swsContext);
    if (height == 0) {
        IMAGE_LOGE("Image pixel format conversion failed");
        return false;
    }
    return true;
}

bool ImageFormatConvertUtils::RGB565ToNV12P010(const uint8_t *srcBuffer, const RGBDataInfo &imageSize,
    uint8_t **destBuffer, size_t &destBufferSize, [[maybe_unused]]ColorSpace colorSpace)
{
    if (srcBuffer == nullptr || destBuffer == nullptr || imageSize.width < 0 || imageSize.height < 0) {
        return false;
    }
    uint32_t frameSize = imageSize.width * imageSize.height;
    destBufferSize = (frameSize +
        (((imageSize.width + 1) / TWO_SLICES) * ((imageSize.height + 1) / TWO_SLICES) * TWO_SLICES)) * TWO_SLICES;
    if (destBufferSize == 0 || destBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size calculation!");
        return false;
    }
    *destBuffer = new(std::nothrow) uint8_t[destBufferSize]();
    if (*destBuffer == nullptr) {
        IMAGE_LOGE("apply space for dest buffer failed!");
        return false;
    }
    Convert10bitInfo convertInfo;
    convertInfo.srcPixelFormat = PixelFormat::RGB_565;
    convertInfo.srcBytes = BYTES_PER_PIXEL_RGB565;
    convertInfo.dstPixelFormat = PixelFormat::YCBCR_P010;
    bool result = RGBAToP010SoftDecode(srcBuffer, imageSize, destBuffer, convertInfo);
    if (!result) {
        IMAGE_LOGE("RGB565ToNV12P010 failed!");
        delete[] (*destBuffer);
        *destBuffer = nullptr;
        return false;
    }
    return true;
}

bool ImageFormatConvertUtils::RGB565ToNV21P010(const uint8_t *srcBuffer, const RGBDataInfo &imageSize,
    uint8_t **destBuffer, size_t &destBufferSize, [[maybe_unused]]ColorSpace colorSpace)
{
    if (srcBuffer == nullptr || destBuffer == nullptr || imageSize.width < 0 || imageSize.height < 0) {
        return false;
    }
    uint32_t frameSize = imageSize.width * imageSize.height;
    destBufferSize = (frameSize +
        (((imageSize.width + 1) / TWO_SLICES) * ((imageSize.height + 1) / TWO_SLICES) * TWO_SLICES)) * TWO_SLICES;
    if (destBufferSize == 0 || destBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size calculation!");
        return false;
    }
    uint8_t *midBuffer = nullptr;
    midBuffer = new(std::nothrow) uint8_t[destBufferSize]();
    if (midBuffer == nullptr) {
        IMAGE_LOGE("apply space for dest buffer failed!");
        return false;
    }
    Convert10bitInfo convertInfo;
    convertInfo.srcPixelFormat = PixelFormat::RGB_565;
    convertInfo.srcBytes = BYTES_PER_PIXEL_RGB565;
    convertInfo.dstPixelFormat = PixelFormat::YCBCR_P010;
    bool result = RGBAToP010SoftDecode(srcBuffer, imageSize, &midBuffer, convertInfo);
    if (!result) {
        IMAGE_LOGE("RGB565ToNV12P010 failed!");
        delete[] midBuffer;
        return false;
    }
    YUVDataInfo yDInfo;
    yDInfo.uvOffset = imageSize.width * imageSize.height;
    *destBuffer = new(std::nothrow) uint8_t[destBufferSize]();
    if (*destBuffer == nullptr) {
        IMAGE_LOGE("apply space for dest buffer failed!");
        delete[] midBuffer;
        return false;
    }
    result = NV12P010ToNV21P010SoftDecode(midBuffer, yDInfo, destBuffer);
    if (!result) {
        IMAGE_LOGE("NV12P010ToNV21P010 failed!");
        delete[] midBuffer;
        delete[] (*destBuffer);
        *destBuffer = nullptr;
        return false;
    }
    delete[] midBuffer;
    return true;
}

bool ImageFormatConvertUtils::RGBAToNV12P010(const uint8_t *srcBuffer, const RGBDataInfo &imageSize,
    uint8_t **destBuffer, size_t &destBufferSize, [[maybe_unused]]ColorSpace colorSpace)
{
    if (srcBuffer == nullptr || destBuffer == nullptr || imageSize.width < 0 || imageSize.height < 0) {
        return false;
    }
    size_t destPlaneSizeY = imageSize.width * imageSize.height;
    size_t destPlaneSizeUV = ((imageSize.width + 1) / TWO_SLICES) * ((imageSize.height + 1) / TWO_SLICES);
    destBufferSize = (destPlaneSizeY + destPlaneSizeUV * TWO_SLICES) * TWO_SLICES;
    if (destBufferSize == 0 || destBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size calculation!");
        return false;
    }
    *destBuffer = new(std::nothrow) uint8_t[destBufferSize]();
    if (*destBuffer == nullptr) {
        IMAGE_LOGE("apply space for dest buffer failed!");
        return false;
    }
    Convert10bitInfo convertInfo;
    convertInfo.srcPixelFormat = PixelFormat::RGBA_8888;
    convertInfo.srcBytes = BYTES_PER_PIXEL_RGBA;
    convertInfo.dstPixelFormat = PixelFormat::YCBCR_P010;
    bool result = RGBAToP010SoftDecode(srcBuffer, imageSize, destBuffer, convertInfo);
    if (!result) {
        IMAGE_LOGE("RGBAToNV12P010 failed!");
        delete[] (*destBuffer);
        *destBuffer = nullptr;
        return false;
    }
    return true;
}

bool ImageFormatConvertUtils::RGBAToNV21P010(const uint8_t *srcBuffer, const RGBDataInfo &imageSize,
    uint8_t **destBuffer, size_t &destBufferSize, [[maybe_unused]]ColorSpace colorSpace)
{
    if (srcBuffer == nullptr || destBuffer == nullptr || imageSize.width < 0 || imageSize.height < 0) {
        return false;
    }
    size_t destPlaneSizeY = imageSize.width * imageSize.height;
    size_t destPlaneSizeUV = ((imageSize.width + 1) / TWO_SLICES) * ((imageSize.height + 1) / TWO_SLICES);
    destBufferSize = (destPlaneSizeY + destPlaneSizeUV * TWO_SLICES) * TWO_SLICES;
    if (destBufferSize == 0 || destBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size calculation!");
        return false;
    }
    uint8_t *midBuffer = nullptr;
    midBuffer = new(std::nothrow) uint8_t[destBufferSize]();
    if (midBuffer == nullptr) {
        IMAGE_LOGE("apply space for dest buffer failed!");
        return false;
    }
    Convert10bitInfo convertInfo;
    convertInfo.srcPixelFormat = PixelFormat::RGBA_8888;
    convertInfo.srcBytes = BYTES_PER_PIXEL_RGBA;
    convertInfo.dstPixelFormat = PixelFormat::YCBCR_P010;
    bool result = RGBAToP010SoftDecode(srcBuffer, imageSize, &midBuffer, convertInfo);
    if (!result) {
        IMAGE_LOGE("RGBAToNV12P010 failed!");
        delete[] midBuffer;
        return false;
    }
    YUVDataInfo yDInfo;
    yDInfo.uvOffset = imageSize.width * imageSize.height;
    *destBuffer = new(std::nothrow) uint8_t[destBufferSize]();
    if (*destBuffer == nullptr) {
        IMAGE_LOGE("apply space for dest buffer failed!");
        delete[] midBuffer;
        return false;
    }
    result = NV12P010ToNV21P010SoftDecode(midBuffer, yDInfo, destBuffer);
    if (!result) {
        IMAGE_LOGE("NV12P010ToNV21P010 failed!");
        delete[] midBuffer;
        delete[] (*destBuffer);
        *destBuffer = nullptr;
        return false;
    }
    delete[] midBuffer;
    return true;
}

bool ImageFormatConvertUtils::BGRAToNV12P010(const uint8_t *srcBuffer, const RGBDataInfo &imageSize,
    uint8_t **destBuffer, size_t &destBufferSize, [[maybe_unused]]ColorSpace colorSpace)
{
    if (srcBuffer == nullptr || destBuffer == nullptr || imageSize.width < 0 || imageSize.height < 0) {
        return false;
    }
    size_t destPlaneSizeY = imageSize.width * imageSize.height;
    size_t srcPlaneSizeUV = ((imageSize.width + 1) / TWO_SLICES) * ((imageSize.height + 1) / TWO_SLICES);
    destBufferSize = static_cast<size_t>((destPlaneSizeY + srcPlaneSizeUV * TWO_SLICES) * TWO_SLICES);
    if (destBufferSize == 0 || destBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size calculation!");
        return false;
    }
    *destBuffer = new(std::nothrow) uint8_t[destBufferSize]();
    if (*destBuffer == nullptr) {
        IMAGE_LOGE("apply space for dest buffer failed!");
        return false;
    }
    Convert10bitInfo convertInfo;
    convertInfo.srcPixelFormat = PixelFormat::BGRA_8888;
    convertInfo.srcBytes = BYTES_PER_PIXEL_BGRA;
    convertInfo.dstPixelFormat = PixelFormat::YCBCR_P010;
    bool result = RGBAToP010SoftDecode(srcBuffer, imageSize, destBuffer, convertInfo);
    if (!result) {
        IMAGE_LOGE("BGRAToNV12P010 failed!");
        delete[] (*destBuffer);
        *destBuffer = nullptr;
        return false;
    }
    return true;
}

bool ImageFormatConvertUtils::BGRAToNV21P010(const uint8_t *srcBuffer, const RGBDataInfo &imageSize,
    uint8_t **destBuffer, size_t &destBufferSize, [[maybe_unused]]ColorSpace colorSpace)
{
    if (srcBuffer == nullptr || destBuffer == nullptr || imageSize.width < 0 || imageSize.height < 0) {
        return false;
    }
    size_t destPlaneSizeY = imageSize.width * imageSize.height;
    size_t srcPlaneSizeUV = ((imageSize.width + 1) / TWO_SLICES) * ((imageSize.height + 1) / TWO_SLICES);
    destBufferSize = static_cast<size_t>((destPlaneSizeY + srcPlaneSizeUV * TWO_SLICES) * TWO_SLICES);
    if (destBufferSize == 0 || destBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size calculation!");
        return false;
    }
    uint8_t *midBuffer = nullptr;
    midBuffer = new(std::nothrow) uint8_t[destBufferSize]();
    if (midBuffer == nullptr) {
        IMAGE_LOGE("apply space for dest buffer failed!");
        return false;
    }
    Convert10bitInfo convertInfo;
    convertInfo.srcPixelFormat = PixelFormat::BGRA_8888;
    convertInfo.srcBytes = BYTES_PER_PIXEL_BGRA;
    convertInfo.dstPixelFormat = PixelFormat::YCBCR_P010;
    bool result = RGBAToP010SoftDecode(srcBuffer, imageSize, &midBuffer, convertInfo);
    if (!result) {
        IMAGE_LOGE("BGRAToNV12P010 failed!");
        delete[] midBuffer;
        return false;
    }
    YUVDataInfo yDInfo;
    yDInfo.uvOffset = imageSize.width * imageSize.height;
    *destBuffer = new(std::nothrow) uint8_t[destBufferSize]();
    if (*destBuffer == nullptr) {
        IMAGE_LOGE("apply space for dest buffer failed!");
        delete[] midBuffer;
        return false;
    }
    result = NV12P010ToNV21P010SoftDecode(midBuffer, yDInfo, destBuffer);
    if (!result) {
        IMAGE_LOGE("NV12P010ToNV21P010 failed!");
        delete[] midBuffer;
        delete[] (*destBuffer);
        *destBuffer = nullptr;
        return false;
    }
    delete[] midBuffer;
    return true;
}

bool ImageFormatConvertUtils::RGBToNV12P010(const uint8_t *srcBuffer, const RGBDataInfo &imageSize,
    uint8_t **destBuffer, size_t &destBufferSize, [[maybe_unused]]ColorSpace colorSpace)
{
    if (srcBuffer == nullptr || destBuffer == nullptr || imageSize.width < 0 || imageSize.height < 0) {
        return false;
    }
    destBufferSize = static_cast<size_t>((imageSize.width * imageSize.height + ((imageSize.width + 1) / TWO_SLICES) *
        ((imageSize.height + 1) / TWO_SLICES) * TWO_SLICES) * TWO_SLICES);
    if (destBufferSize == 0 || destBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size calculation!");
        return false;
    }
    (*destBuffer) = new(std::nothrow) uint8_t[destBufferSize]();
    if (*destBuffer == nullptr) {
        IMAGE_LOGE("apply space for dest buffer failed!");
        return false;
    }
    Convert10bitInfo convertInfo;
    convertInfo.srcPixelFormat = PixelFormat::RGB_888;
    convertInfo.srcBytes = BYTES_PER_PIXEL_RGB;
    convertInfo.dstPixelFormat = PixelFormat::YCBCR_P010;
    bool result = RGBAToP010SoftDecode(srcBuffer, imageSize, destBuffer, convertInfo);
    if (!result) {
        IMAGE_LOGE("RGBToNV12P010 failed!");
        delete[] (*destBuffer);
        *destBuffer = nullptr;
        return result;
    }
    return true;
}

bool ImageFormatConvertUtils::RGBToNV21P010(const uint8_t *srcBuffer, const RGBDataInfo &imageSize,
    uint8_t **destBuffer, size_t &destBufferSize, [[maybe_unused]]ColorSpace colorSpace)
{
    if (srcBuffer == nullptr || destBuffer == nullptr || imageSize.width < 0 || imageSize.height < 0) {
        return false;
    }
    destBufferSize = static_cast<size_t>((imageSize.width * imageSize.height + ((imageSize.width + 1) / TWO_SLICES) *
        ((imageSize.height + 1) / TWO_SLICES) * TWO_SLICES) * TWO_SLICES);
    if (destBufferSize == 0 || destBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size calculation!");
        return false;
    }
    uint8_t *midBuffer = nullptr;
    midBuffer = new(std::nothrow) uint8_t[destBufferSize]();
    if (midBuffer == nullptr) {
        IMAGE_LOGE("apply space for dest buffer failed!");
        return false;
    }
    Convert10bitInfo convertInfo;
    convertInfo.srcPixelFormat = PixelFormat::RGB_888;
    convertInfo.srcBytes = BYTES_PER_PIXEL_RGB;
    convertInfo.dstPixelFormat = PixelFormat::YCBCR_P010;
    bool result = RGBAToP010SoftDecode(srcBuffer, imageSize, &midBuffer, convertInfo);
    if (!result) {
        IMAGE_LOGE("RGBToNV12P010 failed!");
        delete[] midBuffer;
        return result;
    }
    YUVDataInfo yDInfo;
    yDInfo.uvOffset = imageSize.width * imageSize.height;
    *destBuffer = new(std::nothrow) uint8_t[destBufferSize]();
    if (*destBuffer == nullptr) {
        IMAGE_LOGE("apply space for dest buffer failed!");
        delete[] midBuffer;
        return false;
    }
    result = NV12P010ToNV21P010SoftDecode(midBuffer, yDInfo, destBuffer);
    if (!result) {
        IMAGE_LOGE("NV12P010ToNV21P010 failed!");
        delete[] midBuffer;
        delete[] (*destBuffer);
        *destBuffer = nullptr;
        return false;
    }
    delete[] midBuffer;
    return true;
}

bool ImageFormatConvertUtils::RGBAF16ToNV12P010(const uint8_t *srcBuffer, const RGBDataInfo &imageSize,
    uint8_t **destBuffer, size_t &destBufferSize, [[maybe_unused]]ColorSpace colorSpace)
{
    if (srcBuffer == nullptr || destBuffer == nullptr || imageSize.width < 0 || imageSize.height < 0) {
        return false;
    }
    uint32_t frameSize = imageSize.width * imageSize.height;
    destBufferSize = ((frameSize +
        ((imageSize.width + 1) / TWO_SLICES) * ((imageSize.height + 1) / TWO_SLICES) * TWO_SLICES) * TWO_SLICES);
    if (destBufferSize == 0 || destBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size calculation!");
        return false;
    }
    *destBuffer = new(std::nothrow) uint8_t[destBufferSize]();
    if (*destBuffer == nullptr) {
        IMAGE_LOGE("apply space for dest buffer failed!");
        return false;
    }
    Convert10bitInfo convertInfo;
    convertInfo.srcPixelFormat = PixelFormat::RGBA_F16;
    convertInfo.srcBytes = STRIDES_PER_PLANE;
    convertInfo.dstPixelFormat = PixelFormat::YCBCR_P010;
    bool result = RGBAToP010SoftDecode(srcBuffer, imageSize, destBuffer, convertInfo);
    if (!result) {
        IMAGE_LOGE("RGBAF16ToNV12P010 failed!");
        delete[] (*destBuffer);
        *destBuffer = nullptr;
        return result;
    }
    return true;
}

bool ImageFormatConvertUtils::RGBAF16ToNV21P010(const uint8_t *srcBuffer, const RGBDataInfo &imageSize,
    uint8_t **destBuffer, size_t &destBufferSize, [[maybe_unused]]ColorSpace colorSpace)
{
    if (srcBuffer == nullptr || destBuffer == nullptr || imageSize.width < 0 || imageSize.height < 0) {
        return false;
    }
    uint32_t frameSize = imageSize.width * imageSize.height;
    destBufferSize = (frameSize +
        ((imageSize.width + 1) / TWO_SLICES) * ((imageSize.height + 1) / TWO_SLICES) * TWO_SLICES) * TWO_SLICES;
    if (destBufferSize == 0 || destBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size calculation!");
        return false;
    }
    uint8_t *midBuffer = nullptr;
    midBuffer = new(std::nothrow) uint8_t[destBufferSize]();
    if (midBuffer == nullptr) {
        IMAGE_LOGE("apply space for dest buffer failed!");
        return false;
    }
    Convert10bitInfo convertInfo;
    convertInfo.srcPixelFormat = PixelFormat::RGBA_F16;
    convertInfo.srcBytes = STRIDES_PER_PLANE;
    convertInfo.dstPixelFormat = PixelFormat::YCBCR_P010;
    bool result = RGBAToP010SoftDecode(srcBuffer, imageSize, &midBuffer, convertInfo);
    if (!result) {
        IMAGE_LOGE("RGBAF16ToNV12P010 failed!");
        delete[] midBuffer;
        return result;
    }
    YUVDataInfo yDInfo;
    yDInfo.uvOffset = imageSize.width * imageSize.height;
    *destBuffer = new(std::nothrow) uint8_t[destBufferSize]();
    if (*destBuffer == nullptr) {
        IMAGE_LOGE("apply space for dest buffer failed!");
        delete[] midBuffer;
        return false;
    }
    result = NV12P010ToNV21P010SoftDecode(midBuffer, yDInfo, destBuffer);
    if (!result) {
        IMAGE_LOGE("NV12P010ToNV21P010 failed!");
        delete[] midBuffer;
        delete[] (*destBuffer);
        *destBuffer = nullptr;
        return false;
    }
    delete[] midBuffer;
    return true;
}

static bool RGBA1010102ToNV12SoftDecode(const uint8_t *srcBuffer, const RGBDataInfo &imageSize, uint8_t **destBuffer)
{
    size_t midBufferSize = static_cast<size_t>(imageSize.width * imageSize.height * STRIDES_PER_PLANE);
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
    YUVDataInfo yDInfo;
    yDInfo.yWidth = imageSize.width;
    yDInfo.yHeight = imageSize.height;
    Convert10bitInfo convertInfo;
    convertInfo.srcPixelFormat = PixelFormat::RGBA_1010102;
    convertInfo.srcBytes = BYTES_PER_PIXEL_RGBA;
    convertInfo.dstPixelFormat = PixelFormat::RGB_888;
    convertInfo.dstBytes = BYTES_PER_PIXEL_RGB;
    if (!RGBAConvert(yDInfo, srcBuffer, midBuffer, convertInfo)) {
        IMAGE_LOGE("RGBA1010102ToRGB888: pixel convert in adapter failed.");
        delete[] midBuffer;
        return false;
    }
    AVPixelFormat srcFormat = findPixelFormat(PixelFormat::RGB_888);
    AVPixelFormat dstFormat = findPixelFormat(PixelFormat::NV12);
    SwsContext *swsContext = sws_getContext(imageSize.width, imageSize.height, srcFormat, imageSize.width,
        imageSize.height, dstFormat, SWS_BILINEAR, nullptr, nullptr, nullptr);
    if (swsContext == nullptr) {
        IMAGE_LOGE("Error to create SwsContext.");
        delete[] midBuffer;
        return false;
    }
    int widthEven = (imageSize.width % EVEN_ODD_DIVISOR == 0) ? (imageSize.width) : (imageSize.width + 1);
    const uint8_t *srcSlice[] = {midBuffer};
    const int srcStride[] = {static_cast<int>(imageSize.width * BYTES_PER_PIXEL_RGB)};
    uint8_t *dstSlice[] = {*destBuffer, *destBuffer + imageSize.width * imageSize.height};
    const int dstStride[] = {static_cast<int>(imageSize.width), static_cast<int>(widthEven)};
    int height = sws_scale(swsContext, srcSlice, srcStride, SRCSLICEY, imageSize.height, dstSlice, dstStride);
    sws_freeContext(swsContext);
    if (height == 0) {
        IMAGE_LOGE("RGB888ToNV12 format conversion failed");
        delete[] midBuffer;
        return false;
    }
    delete[] midBuffer;
    return true;
}

bool ImageFormatConvertUtils::RGBA1010102ToNV12(const uint8_t *srcBuffer, const RGBDataInfo &imageSize,
    uint8_t **destBuffer, size_t &destBufferSize, [[maybe_unused]]ColorSpace colorSpace)
{
    if (srcBuffer == nullptr || destBuffer == nullptr || imageSize.width < 0 || imageSize.height < 0) {
        return false;
    }
    uint32_t frameSize = imageSize.width * imageSize.height;
    destBufferSize = frameSize +
        ((imageSize.width + 1) / TWO_SLICES) * ((imageSize.height + 1) / TWO_SLICES) * TWO_SLICES;
    if (destBufferSize == 0 || destBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size calculation!");
        return false;
    }
    *destBuffer = new(std::nothrow) uint8_t[destBufferSize]();
    if (*destBuffer == nullptr) {
        IMAGE_LOGE("Apply space for dest buffer failed!");
        return false;
    }
    bool result = RGBA1010102ToNV12SoftDecode(srcBuffer, imageSize, destBuffer);
    if (!result) {
        IMAGE_LOGE("RGBA1010102ToNV12 failed!");
        delete[] (*destBuffer);
        *destBuffer = nullptr;
        return false;
    }
    return true;
}

static bool RGBA1010102ToNV21SoftDecode(const uint8_t *srcBuffer, const RGBDataInfo &imageSize, uint8_t **destBuffer)
{
    size_t midBufferSize = static_cast<size_t>(imageSize.width * imageSize.height * STRIDES_PER_PLANE);
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
    YUVDataInfo yDInfo;
    yDInfo.yWidth = imageSize.width;
    yDInfo.yHeight = imageSize.height;
    Convert10bitInfo convertInfo;
    convertInfo.srcPixelFormat = PixelFormat::RGBA_1010102;
    convertInfo.srcBytes = BYTES_PER_PIXEL_RGBA;
    convertInfo.dstPixelFormat = PixelFormat::RGB_888;
    convertInfo.dstBytes = BYTES_PER_PIXEL_RGB;
    if (!RGBAConvert(yDInfo, srcBuffer, midBuffer, convertInfo)) {
        IMAGE_LOGE("RGBA1010102ToRGB888: pixel convert in adapter failed.");
        delete[] midBuffer;
        return false;
    }
    AVPixelFormat srcFormat = findPixelFormat(PixelFormat::RGB_888);
    AVPixelFormat dstFormat = findPixelFormat(PixelFormat::NV21);
    SwsContext *swsContext = sws_getContext(imageSize.width, imageSize.height, srcFormat, imageSize.width,
        imageSize.height, dstFormat, SWS_BILINEAR, nullptr, nullptr, nullptr);
    if (swsContext == nullptr) {
        IMAGE_LOGE("Error to create SwsContext.");
        delete[] midBuffer;
        return false;
    }
    int widthEven = (imageSize.width % EVEN_ODD_DIVISOR == 0) ? (imageSize.width) : (imageSize.width + 1);
    const uint8_t *srcSlice[] = {midBuffer};
    const int srcStride[] = {static_cast<int>(imageSize.width * BYTES_PER_PIXEL_RGB)};
    uint8_t *dstSlice[] = {*destBuffer, *destBuffer + imageSize.width * imageSize.height};
    const int dstStride[] = {static_cast<int>(imageSize.width), static_cast<int>(widthEven)};
    int height = sws_scale(swsContext, srcSlice, srcStride, SRCSLICEY, imageSize.height, dstSlice, dstStride);
    sws_freeContext(swsContext);
    if (height == 0) {
        IMAGE_LOGE("RGBAF16ToNV12 format conversion failed");
        delete[] midBuffer;
        return false;
    }
    delete[] midBuffer;
    return true;
}

bool ImageFormatConvertUtils::RGBA1010102ToNV21(const uint8_t *srcBuffer, const RGBDataInfo &imageSize,
    uint8_t **destBuffer, size_t &destBufferSize, [[maybe_unused]]ColorSpace colorSpace)
{
    if (srcBuffer == nullptr || destBuffer == nullptr || imageSize.width < 0 || imageSize.height < 0) {
        return false;
    }
    uint32_t frameSize = imageSize.width * imageSize.height;
    destBufferSize = frameSize +
        ((imageSize.width + 1) / TWO_SLICES) * ((imageSize.height + 1) / TWO_SLICES) * TWO_SLICES;
    if (destBufferSize == 0 || destBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size calculation!");
        return false;
    }
    *destBuffer = new(std::nothrow) uint8_t[destBufferSize]();
    if (*destBuffer == nullptr) {
        IMAGE_LOGE("Apply space for dest buffer failed!");
        return false;
    }
    bool result = RGBA1010102ToNV21SoftDecode(srcBuffer, imageSize, destBuffer);
    if (!result) {
        IMAGE_LOGE("RGBA1010102ToNV21 failed!");
        delete[] (*destBuffer);
        *destBuffer = nullptr;
        return false;
    }
    return true;
}

static bool RGBA1010102ToP010SoftDecode(const uint8_t *srcBuffer, const RGBDataInfo &imageSize, uint8_t **destBuffer)
{
    size_t midBufferSize = static_cast<size_t>(imageSize.width * imageSize.height * STRIDES_PER_PLANE);
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
    YUVDataInfo yDInfo;
    yDInfo.yWidth = imageSize.width;
    yDInfo.yHeight = imageSize.height;
    Convert10bitInfo rgbaToRgba;
    rgbaToRgba.srcPixelFormat = PixelFormat::RGBA_1010102;
    rgbaToRgba.srcBytes = BYTES_PER_PIXEL_RGBA;
    rgbaToRgba.dstPixelFormat = PixelFormat::RGBA_U16;
    rgbaToRgba.dstBytes = STRIDES_PER_PLANE;
    if (!RGBAConvert(yDInfo, srcBuffer, midBuffer, rgbaToRgba)) {
        IMAGE_LOGE("RGBA1010102ToRGBAF16: pixel convert in adapter failed.");
        delete[] midBuffer;
        return false;
    }
    Convert10bitInfo rgbaToYuv;
    rgbaToYuv.srcPixelFormat = PixelFormat::RGBA_F16;
    rgbaToYuv.srcBytes = STRIDES_PER_PLANE;
    rgbaToYuv.dstPixelFormat = PixelFormat::YCBCR_P010;
    bool result = RGBAToP010SoftDecode(midBuffer, imageSize, destBuffer, rgbaToYuv);
    if (!result) {
        IMAGE_LOGE("RGBAF16ToNV12P010 failed!");
        delete[] midBuffer;
        return result;
    }
    delete[] midBuffer;
    return true;
}

bool ImageFormatConvertUtils::RGBA1010102ToNV12P010(const uint8_t *srcBuffer, const RGBDataInfo &imageSize,
                                                    uint8_t **destBuffer, size_t &destBufferSize,
                                                    [[maybe_unused]]ColorSpace colorSpace)
{
    if (srcBuffer == nullptr || destBuffer == nullptr || imageSize.width < 0 || imageSize.height < 0) {
        return false;
    }
    uint32_t frameSize = imageSize.width * imageSize.height;
    destBufferSize = (frameSize +
        ((imageSize.width + 1) / TWO_SLICES) * ((imageSize.height + 1) / TWO_SLICES) * TWO_SLICES) * TWO_SLICES;
    if (destBufferSize == 0 || destBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size calculation!");
        return false;
    }
    *destBuffer = new(std::nothrow) uint8_t[destBufferSize]();
    if (*destBuffer == nullptr) {
        IMAGE_LOGE("Apply space for dest buffer failed!");
        return false;
    }
    bool result = RGBA1010102ToP010SoftDecode(srcBuffer, imageSize, destBuffer);
    if (!result) {
        IMAGE_LOGE("RGBAF16ToNV12P010 failed!");
        delete[] (*destBuffer);
        *destBuffer = nullptr;
        return result;
    }
    return true;
}

bool ImageFormatConvertUtils::RGBA1010102ToNV21P010(const uint8_t *srcBuffer, const RGBDataInfo &imageSize,
                                                    uint8_t **destBuffer, size_t &destBufferSize,
                                                    [[maybe_unused]]ColorSpace colorSpace)
{
    if (srcBuffer == nullptr || destBuffer == nullptr || imageSize.width < 0 || imageSize.height < 0) {
        return false;
    }
    uint32_t frameSize = imageSize.width * imageSize.height;
    destBufferSize = (frameSize +
        ((imageSize.width + 1) / TWO_SLICES) * ((imageSize.height + 1) / TWO_SLICES) * TWO_SLICES) * TWO_SLICES;
    if (destBufferSize == 0 || destBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size calculation!");
        return false;
    }
    uint8_t *midBuffer = nullptr;
    midBuffer = new(std::nothrow) uint8_t[destBufferSize]();
    if (midBuffer == nullptr) {
        IMAGE_LOGE("Apply space for dest buffer failed!");
        return false;
    }
    bool result = RGBA1010102ToP010SoftDecode(srcBuffer, imageSize, &midBuffer);
    if (!result) {
        IMAGE_LOGE("RGBAF16ToNV12P010 failed!");
        delete[] midBuffer;
        return result;
    }
    *destBuffer = new(std::nothrow) uint8_t[destBufferSize]();
    if (*destBuffer == nullptr) {
        IMAGE_LOGE("Apply space for dest buffer failed!");
        delete[] midBuffer;
        return false;
    }
    YUVDataInfo yDInfo;
    yDInfo.uvOffset = imageSize.width * imageSize.height;
    result = NV12P010ToNV21P010SoftDecode(midBuffer, yDInfo, destBuffer);
    if (!result) {
        IMAGE_LOGE("NV12P010ToNV21P010 failed!");
        delete[] midBuffer;
        delete[] (*destBuffer);
        *destBuffer = nullptr;
        return result;
    }
    delete[] midBuffer;
    return result;
}

static bool NV12ToRGBManual(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo, uint8_t **destBuffer)
{
    AVPixelFormat srcFormat = findPixelFormat(PixelFormat::NV12);
    AVPixelFormat dstFormat = findPixelFormat(PixelFormat::RGB_888);
    struct SwsContext *ctx = sws_getContext(yDInfo.yWidth, yDInfo.yHeight, srcFormat,
                                            yDInfo.yWidth, yDInfo.yHeight, dstFormat,
                                            SWS_BILINEAR, nullptr, nullptr, nullptr);
    if (ctx == nullptr) {
        IMAGE_LOGE("sws_getContext: result is null!");
        return false;
    }

    const uint8_t *srcSlice[] = { srcBuffer + yDInfo.yOffset, srcBuffer + yDInfo.uvOffset };
    const int srcStride[] = { static_cast<int>(yDInfo.yStride), static_cast<int>(yDInfo.uvStride) };
    const int dstStride[] = { static_cast<int>(yDInfo.yWidth * BYTES_PER_PIXEL_RGB) };
    int height = sws_scale(ctx, srcSlice, srcStride, SRCSLICEY, yDInfo.yHeight, destBuffer, dstStride);
    sws_freeContext(ctx);

    if (height == 0) {
        IMAGE_LOGE("Image pixel format conversion failed");
        return false;
    }
    return true;
}

bool ImageFormatConvertUtils::NV12ToRGBA1010102(const uint8_t *data, const YUVDataInfo &yDInfo, uint8_t **destBuffer,
                                                size_t &destBufferSize, [[maybe_unused]]ColorSpace colorSpace)
{
    if (data == nullptr || destBuffer == nullptr) {
        IMAGE_LOGE("Input buffer pointer data or destBuffer is null!");
        return false;
    }
    uint32_t frameSize = yDInfo.yWidth * yDInfo.yHeight;
    size_t midBufferSize = static_cast<size_t>(frameSize * BYTES_PER_PIXEL_RGB);
    if (midBufferSize == 0 || midBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size is 0!");
        return false;
    }
    uint8_t *midBuffer = nullptr;
    midBuffer = new(std::nothrow) uint8_t[midBufferSize]();
    if (midBuffer == nullptr) {
        IMAGE_LOGE("apply space for dest buffer failed!");
        return false;
    }
    if (!NV12ToRGBManual(data, yDInfo, &midBuffer)) {
        IMAGE_LOGE("NV12ToRGB888 failed!");
        delete[] midBuffer;
        midBuffer = nullptr;
        return false;
    }
    destBufferSize = frameSize * BYTES_PER_PIXEL_RGBA;
    if (destBufferSize == 0 || destBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size is 0!");
        delete[] midBuffer;
        return false;
    }
    *destBuffer = new(std::nothrow) uint8_t[destBufferSize]();
    if (*destBuffer == nullptr) {
        IMAGE_LOGE("Dynamically allocating memory for destination buffer failed!");
        delete[] midBuffer;
        return false;
    }
    Convert10bitInfo convertInfo;
    convertInfo.srcPixelFormat = PixelFormat::RGB_888;
    convertInfo.srcBytes = BYTES_PER_PIXEL_RGB;
    convertInfo.dstPixelFormat = PixelFormat::RGBA_1010102;
    convertInfo.dstBytes = BYTES_PER_PIXEL_RGBA;
    if (!RGBAConvert(yDInfo, midBuffer, *destBuffer, convertInfo)) {
        IMAGE_LOGE("RGB888ToRGBA1010102: pixel convert in adapter failed.");
        delete[] midBuffer;
        delete[] (*destBuffer);
        *destBuffer = nullptr;
        return false;
    }
    delete[] midBuffer;
    return true;
}

static bool ConvertNV21ToRGB(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo, uint8_t *midBuffer)
{
    AVPixelFormat srcFormat = findPixelFormat(PixelFormat::NV21);
    AVPixelFormat dstFormat = findPixelFormat(PixelFormat::RGB_888);
    SwsContext *swsContext = sws_getContext(yDInfo.yWidth, yDInfo.yHeight, srcFormat, yDInfo.yWidth,
        yDInfo.yHeight, dstFormat, SWS_BILINEAR, nullptr, nullptr, nullptr);
    if (swsContext == nullptr) {
        IMAGE_LOGE("Error to create SwsContext.");
        return false;
    }
    const uint8_t *srcSlice[] = {srcBuffer + yDInfo.yOffset, srcBuffer + yDInfo.uvOffset};
    const int srcStride[] = {static_cast<int>(yDInfo.yStride), static_cast<int>(yDInfo.uvStride)};
    uint8_t *dstSlice[] = {midBuffer};
    const int dstStride[] = {static_cast<int>(yDInfo.yWidth * BYTES_PER_PIXEL_RGB)};
    int height = sws_scale(swsContext, srcSlice, srcStride, SRCSLICEY, yDInfo.yHeight, dstSlice, dstStride);
    sws_freeContext(swsContext);
    if (height == 0) {
        IMAGE_LOGE("Image pixel format conversion failed");
        return false;
    }
    return true;
}

bool ImageFormatConvertUtils::NV21ToRGBA1010102(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                                uint8_t **destBuffer, size_t &destBufferSize,
                                                [[maybe_unused]]ColorSpace colorSpace)
{
    if (srcBuffer == nullptr || destBuffer == nullptr || yDInfo.yWidth == 0 || yDInfo.yHeight == 0 ||
        yDInfo.uvWidth == 0 || yDInfo.uvHeight == 0) {
        return false;
    }
    uint8_t *midBuffer = nullptr;
    size_t midBufferSize = static_cast<size_t>(yDInfo.yWidth * yDInfo.yHeight * BYTES_PER_PIXEL_RGB);
    if (midBufferSize == 0 || midBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size is 0!");
        return false;
    }
    midBuffer = new(std::nothrow) uint8_t[midBufferSize]();
    if (midBuffer == nullptr) {
        IMAGE_LOGE("apply space for dest buffer failed!");
        return false;
    }
    if (!ConvertNV21ToRGB(srcBuffer, yDInfo, midBuffer)) {
        delete[] midBuffer;
        return false;
    }
    destBufferSize = yDInfo.yWidth * yDInfo.yHeight * BYTES_PER_PIXEL_RGBA;
    if (destBufferSize == 0 || destBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size is 0!");
        delete[] midBuffer;
        return false;
    }
    *destBuffer = new(std::nothrow) uint8_t[destBufferSize]();
    if (*destBuffer == nullptr) {
        IMAGE_LOGE("apply space for dest buffer failed!");
        delete[] midBuffer;
        return false;
    }
    Convert10bitInfo convertInfo;
    convertInfo.srcPixelFormat = PixelFormat::RGB_888;
    convertInfo.srcBytes = BYTES_PER_PIXEL_RGB;
    convertInfo.dstPixelFormat = PixelFormat::RGBA_1010102;
    convertInfo.dstBytes = BYTES_PER_PIXEL_RGBA;
    if (!RGBAConvert(yDInfo, midBuffer, *destBuffer, convertInfo)) {
        IMAGE_LOGE("RGB888ToRGBA1010102: pixel convert in adapter failed.");
        delete[] midBuffer;
        delete[] (*destBuffer);
        *destBuffer = nullptr;
        return false;
    }
    delete[] midBuffer;
    return true;
}

bool ImageFormatConvertUtils::NV12ToNV12P010(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo, uint8_t **destBuffer,
                                             size_t &destBufferSize, [[maybe_unused]]ColorSpace colorSpace)
{
    if (srcBuffer == nullptr || destBuffer == nullptr || yDInfo.yWidth == 0 || yDInfo.yHeight == 0 ||
        yDInfo.uvWidth == 0 || yDInfo.uvHeight == 0) {
        return false;
    }
    destBufferSize =
        (yDInfo.yWidth * yDInfo.yHeight + yDInfo.uvWidth * EVEN_ODD_DIVISOR * yDInfo.uvHeight) * TWO_SLICES;
    if (destBufferSize == 0 || destBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size is 0!");
        return false;
    }
    *destBuffer = new(std::nothrow) uint8_t[destBufferSize]();
    if (*destBuffer == nullptr) {
        IMAGE_LOGE("apply space for dest buffer failed!");
        return false;
    }
    bool result = YUVToP010SoftDecode(srcBuffer, yDInfo, destBuffer, PixelFormat::NV12, PixelFormat::YCBCR_P010);
    if (!result) {
        IMAGE_LOGE("NV12ToNV12P010 failed!");
        delete[] (*destBuffer);
        *destBuffer = nullptr;
        return false;
    }
    return result;
}

bool ImageFormatConvertUtils::NV12ToNV21P010(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo, uint8_t **destBuffer,
                                             size_t &destBufferSize, [[maybe_unused]]ColorSpace colorSpace)
{
    if (srcBuffer == nullptr || destBuffer == nullptr || yDInfo.yWidth == 0 || yDInfo.yHeight == 0 ||
        yDInfo.uvWidth == 0 || yDInfo.uvHeight == 0) {
        return false;
    }
    destBufferSize =
        (yDInfo.yWidth * yDInfo.yHeight + yDInfo.uvWidth * EVEN_ODD_DIVISOR * yDInfo.uvHeight) * TWO_SLICES;
    if (destBufferSize == 0 || destBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size is 0!");
        return false;
    }
    *destBuffer = new(std::nothrow) uint8_t[destBufferSize]();
    if (*destBuffer == nullptr) {
        IMAGE_LOGE("apply space for dest buffer failed!");
        return false;
    }
    bool result = YUVToP010SoftDecode(srcBuffer, yDInfo, destBuffer, PixelFormat::NV21, PixelFormat::YCBCR_P010);
    if (!result) {
        IMAGE_LOGE("NV12ToNV21P010 failed!");
        delete[] (*destBuffer);
        *destBuffer = nullptr;
        return false;
    }
    return result;
}
bool ImageFormatConvertUtils::NV21ToNV12P010(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo, uint8_t **destBuffer,
                                             size_t &destBufferSize, [[maybe_unused]]ColorSpace colorSpace)
{
    if (srcBuffer == nullptr || destBuffer == nullptr || yDInfo.yWidth == 0 || yDInfo.yHeight == 0 ||
        yDInfo.uvWidth == 0 || yDInfo.uvHeight == 0) {
        return false;
    }
    destBufferSize =
        (yDInfo.yWidth * yDInfo.yHeight + yDInfo.uvWidth * EVEN_ODD_DIVISOR * yDInfo.uvHeight) * TWO_SLICES;
    if (destBufferSize == 0 || destBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size is 0!");
        return false;
    }
    *destBuffer = new(std::nothrow) uint8_t[destBufferSize]();
    if (*destBuffer == nullptr) {
        IMAGE_LOGE("apply space for dest buffer failed!");
        return false;
    }
    bool result = YUVToP010SoftDecode(srcBuffer, yDInfo, destBuffer, PixelFormat::NV21, PixelFormat::YCBCR_P010);
    if (!result) {
        IMAGE_LOGE("NV21ToNV12P010 failed!");
        delete[] (*destBuffer);
        *destBuffer = nullptr;
        return false;
    }
    return result;
}
bool ImageFormatConvertUtils::NV21ToNV21P010(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo, uint8_t **destBuffer,
                                             size_t &destBufferSize, [[maybe_unused]]ColorSpace colorSpace)
{
    if (srcBuffer == nullptr || destBuffer == nullptr || yDInfo.yWidth == 0 || yDInfo.yHeight == 0 ||
        yDInfo.uvWidth == 0 || yDInfo.uvHeight == 0) {
        return false;
    }
    destBufferSize =
        (yDInfo.yWidth * yDInfo.yHeight + yDInfo.uvWidth * EVEN_ODD_DIVISOR * yDInfo.uvHeight) * TWO_SLICES;
    if (destBufferSize == 0 || destBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size is 0!");
        return false;
    }
    *destBuffer = new(std::nothrow) uint8_t[destBufferSize]();
    if (*destBuffer == nullptr) {
        IMAGE_LOGE("apply space for dest buffer failed!");
        return false;
    }
    bool result = YUVToP010SoftDecode(srcBuffer, yDInfo, destBuffer, PixelFormat::NV12, PixelFormat::YCBCR_P010);
    if (!result) {
        IMAGE_LOGE("NV21ToNV21P010 failed!");
        delete[] (*destBuffer);
        *destBuffer = nullptr;
        return false;
    }
    return result;
}

bool ImageFormatConvertUtils::NV12P010ToNV12(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo, uint8_t **destBuffer,
                                             size_t &destBufferSize, [[maybe_unused]]ColorSpace colorSpace)
{
    if (srcBuffer == nullptr || destBuffer == nullptr || yDInfo.yWidth == 0 || yDInfo.yHeight == 0 ||
        yDInfo.uvWidth == 0 || yDInfo.uvHeight == 0) {
        return false;
    }

    destBufferSize = yDInfo.uvOffset +
        ((yDInfo.yWidth + 1) / TWO_SLICES) * ((yDInfo.yHeight + 1) / TWO_SLICES) * TWO_SLICES;
    if (destBufferSize == 0 || destBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size calculation!");
        return false;
    }
    *destBuffer = new(std::nothrow) uint8_t[destBufferSize]();
    if (*destBuffer == nullptr) {
        IMAGE_LOGE("apply space for dest buffer failed!");
        return false;
    }

    bool result = P010ToYUVSoftDecode(srcBuffer, yDInfo, destBuffer, PixelFormat::YCBCR_P010, PixelFormat::NV12);
    if (!result) {
        IMAGE_LOGE("NV12P010ToNV12 failed!");
        delete[] (*destBuffer);
        *destBuffer = nullptr;
        return result;
    }
    return true;
}

bool ImageFormatConvertUtils::NV12P010ToNV21(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo, uint8_t **destBuffer,
                                             size_t &destBufferSize, [[maybe_unused]]ColorSpace colorSpace)
{
    if (srcBuffer == nullptr || destBuffer == nullptr || yDInfo.yWidth == 0 || yDInfo.yHeight == 0 ||
        yDInfo.uvWidth == 0 || yDInfo.uvHeight == 0) {
        return false;
    }
    destBufferSize = yDInfo.uvOffset +
        ((yDInfo.yWidth + 1) / TWO_SLICES) * ((yDInfo.yHeight + 1) / TWO_SLICES) * TWO_SLICES;
    if (destBufferSize == 0 || destBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size calculation!");
        return false;
    }
    *destBuffer = new(std::nothrow) uint8_t[destBufferSize]();
    if (*destBuffer == nullptr) {
        IMAGE_LOGE("apply space for dest buffer failed!");
        return false;
    }
    bool result = P010ToYUVSoftDecode(srcBuffer, yDInfo, destBuffer, PixelFormat::YCBCR_P010, PixelFormat::NV21);
    if (!result) {
        IMAGE_LOGE("NV12P010ToNV21 failed!");
        delete[] (*destBuffer);
        *destBuffer = nullptr;
        return result;
    }
    return result;
}

bool ImageFormatConvertUtils::NV12P010ToNV21P010(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                                 uint8_t **destBuffer, size_t &destBufferSize,
                                                 [[maybe_unused]]ColorSpace colorSpace)
{
    if (srcBuffer == nullptr || destBuffer == nullptr || yDInfo.yWidth == 0 || yDInfo.yHeight == 0 ||
        yDInfo.uvWidth == 0 || yDInfo.uvHeight == 0) {
        return false;
    }
    destBufferSize =
        (yDInfo.yWidth * yDInfo.yHeight + yDInfo.uvWidth * EVEN_ODD_DIVISOR * yDInfo.uvHeight) * TWO_SLICES;
    if (destBufferSize == 0 || destBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size calculation!");
        return false;
    }
    *destBuffer = new(std::nothrow) uint8_t[destBufferSize]();
    if (*destBuffer == nullptr) {
        IMAGE_LOGE("apply space for dest buffer failed!");
        return false;
    }
    bool result = false;
    result = NV12P010ToNV21P010SoftDecode(srcBuffer, yDInfo, destBuffer);
    if (!result) {
        IMAGE_LOGE("NV12P010ToNV21P010 failed!");
        delete[] (*destBuffer);
        *destBuffer = nullptr;
        return result;
    }
    return result;
}

bool ImageFormatConvertUtils::NV12P010ToRGB565(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                               uint8_t **destBuffer, size_t &destBufferSize,
                                               [[maybe_unused]]ColorSpace colorSpace)
{
    if (srcBuffer == nullptr || destBuffer == nullptr || yDInfo.yWidth == 0 || yDInfo.yHeight == 0 ||
        yDInfo.uvWidth == 0 || yDInfo.uvHeight == 0) {
        return false;
    }

    destBufferSize = static_cast<size_t>(yDInfo.uvOffset * BYTES_PER_PIXEL_RGB565);
    if (destBufferSize == 0 || destBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size calculation!");
        return false;
    }
    *destBuffer = new(std::nothrow) uint8_t[destBufferSize]();
    if (*destBuffer == nullptr) {
        IMAGE_LOGE("apply space for dest buffer failed!");
        return false;
    }
    Convert10bitInfo convertInfo;
    convertInfo.srcPixelFormat = PixelFormat::YCBCR_P010;
    convertInfo.dstPixelFormat = PixelFormat::RGB_565;
    convertInfo.dstBytes = BYTES_PER_PIXEL_RGB565;
    bool result = P010ToRGBASoftDecode(srcBuffer, yDInfo, destBuffer, convertInfo);
    if (!result) {
        IMAGE_LOGE("NV12P010ToRGB565 failed!");
        delete[] (*destBuffer);
        *destBuffer = nullptr;
        return result;
    }
    return true;
}

bool ImageFormatConvertUtils::NV12P010ToRGBA8888(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                                 uint8_t **destBuffer, size_t &destBufferSize,
                                                 [[maybe_unused]]ColorSpace colorSpace)
{
    if (srcBuffer == nullptr || destBuffer == nullptr || yDInfo.yWidth == 0 || yDInfo.yHeight == 0 ||
        yDInfo.uvWidth == 0 || yDInfo.uvHeight == 0) {
        return false;
    }

    destBufferSize = static_cast<size_t>(yDInfo.uvOffset * BYTES_PER_PIXEL_RGBA);
    if (destBufferSize == 0 || destBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size calculation!");
        return false;
    }
    *destBuffer = new(std::nothrow) uint8_t[destBufferSize]();
    if (*destBuffer == nullptr) {
        IMAGE_LOGE("apply space for dest buffer failed!");
        return false;
    }
    Convert10bitInfo convertInfo;
    convertInfo.srcPixelFormat = PixelFormat::YCBCR_P010;
    convertInfo.dstPixelFormat = PixelFormat::RGBA_8888;
    convertInfo.dstBytes = BYTES_PER_PIXEL_RGBA;
    bool result = P010ToRGBASoftDecode(srcBuffer, yDInfo, destBuffer, convertInfo);
    if (!result) {
        IMAGE_LOGE("NV12P010ToRGBA8888 failed!");
        delete[] (*destBuffer);
        *destBuffer = nullptr;
        return result;
    }
    return true;
}

bool ImageFormatConvertUtils::NV12P010ToBGRA8888(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                                 uint8_t **destBuffer, size_t &destBufferSize,
                                                 [[maybe_unused]]ColorSpace colorSpace)
{
    if (srcBuffer == nullptr || destBuffer == nullptr || yDInfo.yWidth == 0 || yDInfo.yHeight == 0 ||
        yDInfo.uvWidth == 0 || yDInfo.uvHeight == 0) {
        return false;
    }

    destBufferSize = static_cast<size_t>(yDInfo.uvOffset * BYTES_PER_PIXEL_BGRA);
    if (destBufferSize == 0 || destBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size calculation!");
        return false;
    }
    *destBuffer = new(std::nothrow) uint8_t[destBufferSize]();
    if (*destBuffer == nullptr) {
        IMAGE_LOGE("apply space for dest buffer failed!");
        return false;
    }
    Convert10bitInfo convertInfo;
    convertInfo.srcPixelFormat = PixelFormat::YCBCR_P010;
    convertInfo.dstPixelFormat = PixelFormat::BGRA_8888;
    convertInfo.dstBytes = BYTES_PER_PIXEL_BGRA;
    bool result = P010ToRGBASoftDecode(srcBuffer, yDInfo, destBuffer, convertInfo);
    if (!result) {
        IMAGE_LOGE("NV12P010ToBGRA8888 failed!");
        delete[] (*destBuffer);
        *destBuffer = nullptr;
        return result;
    }
    return true;
}

bool ImageFormatConvertUtils::NV12P010ToRGB888(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                               uint8_t **destBuffer, size_t &destBufferSize,
                                               [[maybe_unused]]ColorSpace colorSpace)
{
    if (srcBuffer == nullptr || destBuffer == nullptr || yDInfo.yWidth == 0 || yDInfo.yHeight == 0 ||
        yDInfo.uvWidth == 0 || yDInfo.uvHeight == 0) {
        return false;
    }

    destBufferSize = static_cast<size_t>(yDInfo.uvOffset * BYTES_PER_PIXEL_RGB);
    if (destBufferSize == 0 || destBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size calculation!");
        return false;
    }
    *destBuffer = new(std::nothrow) uint8_t[destBufferSize]();
    if (*destBuffer == nullptr) {
        IMAGE_LOGE("apply space for dest buffer failed!");
        return false;
    }
    Convert10bitInfo convertInfo;
    convertInfo.srcPixelFormat = PixelFormat::YCBCR_P010;
    convertInfo.dstPixelFormat = PixelFormat::RGB_888;
    convertInfo.dstBytes = BYTES_PER_PIXEL_RGB;
    bool result = P010ToRGBASoftDecode(srcBuffer, yDInfo, destBuffer, convertInfo);
    if (!result) {
        IMAGE_LOGE("NV12P010ToRGB888 failed!");
        delete[] (*destBuffer);
        *destBuffer = nullptr;
        return result;
    }
    return true;
}


bool ImageFormatConvertUtils::NV12P010ToRGBAF16(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                                uint8_t **destBuffer, size_t &destBufferSize,
                                                [[maybe_unused]]ColorSpace colorSpace)
{
    if (srcBuffer == nullptr || destBuffer == nullptr || yDInfo.yWidth == 0 || yDInfo.yHeight == 0 ||
        yDInfo.uvWidth == 0 || yDInfo.uvHeight == 0) {
        return false;
    }

    destBufferSize = static_cast<size_t>(yDInfo.uvOffset * STRIDES_PER_PLANE);
    if (destBufferSize == 0 || destBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size calculation!");
        return false;
    }
    *destBuffer = new(std::nothrow) uint8_t[destBufferSize]();
    if (*destBuffer == nullptr) {
        IMAGE_LOGE("apply space for dest buffer failed!");
        return false;
    }
    Convert10bitInfo convertInfo;
    convertInfo.srcPixelFormat = PixelFormat::YCBCR_P010;
    convertInfo.dstPixelFormat = PixelFormat::RGBA_F16;
    convertInfo.dstBytes = STRIDES_PER_PLANE;
    bool result = P010ToRGBASoftDecode(srcBuffer, yDInfo, destBuffer, convertInfo);
    if (!result) {
        IMAGE_LOGE("NV12P010ToRGBAF16 failed!");
        delete[] (*destBuffer);
        *destBuffer = nullptr;
        return result;
    }
    return true;
}

bool ImageFormatConvertUtils::NV21P010ToNV12(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo, uint8_t **destBuffer,
                                             size_t &destBufferSize, [[maybe_unused]]ColorSpace colorSpace)
{
    if (srcBuffer == nullptr || destBuffer == nullptr || yDInfo.yWidth == 0 || yDInfo.yHeight == 0 ||
        yDInfo.uvWidth == 0 || yDInfo.uvHeight == 0) {
        return false;
    }
    destBufferSize = yDInfo.uvOffset +
        ((yDInfo.yWidth + 1) / TWO_SLICES) * ((yDInfo.yHeight + 1) / TWO_SLICES) * TWO_SLICES;
    if (destBufferSize == 0 || destBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size calculation!");
        return false;
    }
    *destBuffer = new(std::nothrow) uint8_t[destBufferSize]();
    if (*destBuffer == nullptr) {
        IMAGE_LOGE("apply space for dest buffer failed!");
        return false;
    }
    bool result = P010ToYUVSoftDecode(srcBuffer, yDInfo, destBuffer, PixelFormat::YCBCR_P010, PixelFormat::NV21);
    if (!result) {
        IMAGE_LOGE("NV21P010ToNV12 failed!");
        delete[] (*destBuffer);
        *destBuffer = nullptr;
        return result;
    }
    return result;
}

bool ImageFormatConvertUtils::NV21P010ToNV21(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo, uint8_t **destBuffer,
                                             size_t &destBufferSize, [[maybe_unused]]ColorSpace colorSpace)
{
    if (srcBuffer == nullptr || destBuffer == nullptr || yDInfo.yWidth == 0 || yDInfo.yHeight == 0 ||
        yDInfo.uvWidth == 0 || yDInfo.uvHeight == 0) {
        return false;
    }
    destBufferSize = yDInfo.uvOffset +
        ((yDInfo.yWidth + 1) / TWO_SLICES) * ((yDInfo.yHeight + 1) / TWO_SLICES) * TWO_SLICES;
    if (destBufferSize == 0 || destBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size calculation!");
        return false;
    }
    *destBuffer = new(std::nothrow) uint8_t[destBufferSize]();
    if (*destBuffer == nullptr) {
        IMAGE_LOGE("apply space for dest buffer failed!");
        return false;
    }
    bool result = P010ToYUVSoftDecode(srcBuffer, yDInfo, destBuffer, PixelFormat::YCBCR_P010, PixelFormat::NV12);
    if (!result) {
        IMAGE_LOGE("NV21P010ToNV21 failed!");
        delete[] (*destBuffer);
        *destBuffer = nullptr;
        return result;
    }
    return result;
}

bool ImageFormatConvertUtils::NV21P010ToNV12P010(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                                 uint8_t **destBuffer, size_t &destBufferSize,
                                                 [[maybe_unused]]ColorSpace colorSpace)
{
    if (srcBuffer == nullptr || destBuffer == nullptr || yDInfo.yWidth == 0 || yDInfo.yHeight == 0 ||
        yDInfo.uvWidth == 0 || yDInfo.uvHeight == 0) {
        return false;
    }
    destBufferSize =
        (yDInfo.yWidth * yDInfo.yHeight + yDInfo.uvWidth * EVEN_ODD_DIVISOR * yDInfo.uvHeight) * TWO_SLICES;
    if (destBufferSize == 0 || destBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size calculation!");
        return false;
    }
    *destBuffer = new(std::nothrow) uint8_t[destBufferSize]();
    if (*destBuffer == nullptr) {
        IMAGE_LOGE("apply space for dest buffer failed!");
        return false;
    }
    bool result = false;
    result = NV12P010ToNV21P010SoftDecode(srcBuffer, yDInfo, destBuffer);
    if (!result) {
        IMAGE_LOGE("NV21P010ToNV12P010 failed!");
        delete[] (*destBuffer);
        *destBuffer = nullptr;
        return result;
    }
    return result;
}

bool ImageFormatConvertUtils::NV21P010ToRGB565(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                               uint8_t **destBuffer, size_t &destBufferSize,
                                               [[maybe_unused]]ColorSpace colorSpace)
{
    if (srcBuffer == nullptr || destBuffer == nullptr || yDInfo.yWidth == 0 || yDInfo.yHeight == 0 ||
        yDInfo.uvWidth == 0 || yDInfo.uvHeight == 0) {
        return false;
    }
    uint8_t *midBuffer = nullptr;
    midBuffer = new(std::nothrow) uint8_t[(yDInfo.yWidth * yDInfo.yHeight + yDInfo.uvWidth *
        EVEN_ODD_DIVISOR * yDInfo.uvHeight) * TWO_SLICES]();
    if (midBuffer == nullptr) {
        IMAGE_LOGE("apply space for dest buffer failed!");
        return false;
    }
    bool result = false;
    result = NV12P010ToNV21P010SoftDecode(srcBuffer, yDInfo, &midBuffer);
    if (!result) {
        IMAGE_LOGE("NV21P010ToNV12P010 failed!");
        delete[] midBuffer;
        return false;
    }
    destBufferSize = static_cast<size_t>(yDInfo.uvOffset * BYTES_PER_PIXEL_RGB565);
    if (destBufferSize == 0 || destBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size calculation!");
        return false;
    }
    *destBuffer = new(std::nothrow) uint8_t[destBufferSize]();
    if (*destBuffer == nullptr) {
        IMAGE_LOGE("apply space for dest buffer failed!");
        delete[] midBuffer;
        return false;
    }
    Convert10bitInfo convertInfo;
    convertInfo.srcPixelFormat = PixelFormat::YCBCR_P010;
    convertInfo.dstPixelFormat = PixelFormat::RGB_565;
    convertInfo.dstBytes = BYTES_PER_PIXEL_RGB565;
    result = P010ToRGBASoftDecode(midBuffer, yDInfo, destBuffer, convertInfo);
    if (!result) {
        IMAGE_LOGE("NV21P010ToRGB565 failed!");
        delete[] midBuffer;
        delete[] (*destBuffer);
        *destBuffer = nullptr;
        return result;
    }
    delete[] midBuffer;
    return true;
}

bool ImageFormatConvertUtils::NV21P010ToRGBA8888(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                                 uint8_t **destBuffer, size_t &destBufferSize,
                                                 [[maybe_unused]]ColorSpace colorSpace)
{
    if (srcBuffer == nullptr || destBuffer == nullptr || yDInfo.yWidth == 0 || yDInfo.yHeight == 0 ||
        yDInfo.uvWidth == 0 || yDInfo.uvHeight == 0) {
        return false;
    }
    uint8_t *midBuffer = nullptr;
    midBuffer = new(std::nothrow) uint8_t[(yDInfo.yWidth * yDInfo.yHeight + yDInfo.uvWidth * EVEN_ODD_DIVISOR *
        yDInfo.uvHeight) * TWO_SLICES]();
    if (midBuffer == nullptr) {
        IMAGE_LOGE("apply space for dest buffer failed!");
        return false;
    }
    bool result = NV12P010ToNV21P010SoftDecode(srcBuffer, yDInfo, &midBuffer);
    if (!result) {
        IMAGE_LOGE("NV21P010ToNV12P010 failed!");
        delete[] midBuffer;
        return false;
    }
    destBufferSize = static_cast<size_t>(yDInfo.uvOffset * BYTES_PER_PIXEL_RGBA);
    if (destBufferSize == 0 || destBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size calculation!");
        return false;
    }
    *destBuffer = new(std::nothrow) uint8_t[destBufferSize]();
    if (*destBuffer == nullptr) {
        IMAGE_LOGE("apply space for dest buffer failed!");
        delete[] midBuffer;
        return false;
    }
    Convert10bitInfo convertInfo;
    convertInfo.srcPixelFormat = PixelFormat::YCBCR_P010;
    convertInfo.dstPixelFormat = PixelFormat::RGBA_8888;
    convertInfo.dstBytes = BYTES_PER_PIXEL_RGBA;
    result = P010ToRGBASoftDecode(midBuffer, yDInfo, destBuffer, convertInfo);
    if (!result) {
        IMAGE_LOGE("NV21P010ToRGBA8888 failed!");
        delete[] midBuffer;
        delete[] (*destBuffer);
        *destBuffer = nullptr;
        return result;
    }
    delete[] midBuffer;
    return true;
}

bool ImageFormatConvertUtils::NV21P010ToBGRA8888(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                                 uint8_t **destBuffer, size_t &destBufferSize,
                                                 [[maybe_unused]]ColorSpace colorSpace)
{
    if (srcBuffer == nullptr || destBuffer == nullptr || yDInfo.yWidth == 0 || yDInfo.yHeight == 0 ||
        yDInfo.uvWidth == 0 || yDInfo.uvHeight == 0) {
        return false;
    }
    size_t midBufferSize =
        (yDInfo.yWidth * yDInfo.yHeight + yDInfo.uvWidth * EVEN_ODD_DIVISOR * yDInfo.uvHeight) * TWO_SLICES;
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
    bool result = NV12P010ToNV21P010SoftDecode(srcBuffer, yDInfo, &midBuffer);
    if (!result) {
        IMAGE_LOGE("NV21P010ToNV12P010 failed!");
        delete[] midBuffer;
        return false;
    }
    destBufferSize = static_cast<size_t>(yDInfo.uvOffset * BYTES_PER_PIXEL_BGRA);
    if (destBufferSize == 0 || destBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size calculation!");
        return false;
    }
    *destBuffer = new(std::nothrow) uint8_t[destBufferSize]();
    if (*destBuffer == nullptr) {
        IMAGE_LOGE("apply space for dest buffer failed!");
        delete[] midBuffer;
        return false;
    }
    Convert10bitInfo convertInfo;
    convertInfo.srcPixelFormat = PixelFormat::YCBCR_P010;
    convertInfo.dstPixelFormat = PixelFormat::BGRA_8888;
    convertInfo.dstBytes = BYTES_PER_PIXEL_BGRA;
    result = P010ToRGBASoftDecode(midBuffer, yDInfo, destBuffer, convertInfo);
    if (!result) {
        IMAGE_LOGE("NV21P010ToBGRA8888 failed!");
        delete[] midBuffer;
        delete[] (*destBuffer);
        *destBuffer = nullptr;
        return result;
    }
    delete[] midBuffer;
    return true;
}

bool ImageFormatConvertUtils::NV21P010ToRGB888(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                               uint8_t **destBuffer, size_t &destBufferSize,
                                               [[maybe_unused]]ColorSpace colorSpace)
{
    if (srcBuffer == nullptr || destBuffer == nullptr || yDInfo.yWidth == 0 || yDInfo.yHeight == 0 ||
        yDInfo.uvWidth == 0 || yDInfo.uvHeight == 0) {
        return false;
    }
    size_t midBufferSize = (yDInfo.uvOffset + yDInfo.uvWidth * EVEN_ODD_DIVISOR * yDInfo.uvHeight) * TWO_SLICES;
    if (midBufferSize == 0 || midBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size calculation!");
        return false;
    }
    destBufferSize = static_cast<size_t>(yDInfo.uvOffset * BYTES_PER_PIXEL_RGB);
    if (destBufferSize == 0 || destBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size calculation!");
        return false;
    }
    uint8_t *midBuffer = nullptr;
    midBuffer = new(std::nothrow) uint8_t[midBufferSize]();
    if (midBuffer == nullptr) {
        IMAGE_LOGE("apply space for dest buffer failed!");
        return false;
    }
    bool result = false;
    result = NV12P010ToNV21P010SoftDecode(srcBuffer, yDInfo, &midBuffer);
    if (!result) {
        IMAGE_LOGE("NV21P010ToNV12P010 failed!");
        delete[] midBuffer;
        return false;
    }
    *destBuffer = new(std::nothrow) uint8_t[destBufferSize]();
    if (*destBuffer == nullptr) {
        IMAGE_LOGE("apply space for dest buffer failed!");
        delete[] midBuffer;
        return false;
    }
    Convert10bitInfo convertInfo;
    convertInfo.srcPixelFormat = PixelFormat::YCBCR_P010;
    convertInfo.dstPixelFormat = PixelFormat::RGB_888;
    convertInfo.dstBytes = BYTES_PER_PIXEL_RGB;
    result = P010ToRGBASoftDecode(midBuffer, yDInfo, destBuffer, convertInfo);
    if (!result) {
        IMAGE_LOGE("NV21P010ToRGB888 failed!");
        delete[] midBuffer;
        delete[] (*destBuffer);
        *destBuffer = nullptr;
        return result;
    }
    delete[] midBuffer;
    return true;
}

bool ImageFormatConvertUtils::NV21P010ToRGBAF16(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                                uint8_t **destBuffer, size_t &destBufferSize,
                                                [[maybe_unused]]ColorSpace colorSpace)
{
    if (srcBuffer == nullptr || destBuffer == nullptr || yDInfo.yWidth == 0 || yDInfo.yHeight == 0 ||
        yDInfo.uvWidth == 0 || yDInfo.uvHeight == 0) {
        return false;
    }
    size_t midBufferSize = (yDInfo.uvOffset + yDInfo.uvWidth * EVEN_ODD_DIVISOR * yDInfo.uvHeight) * TWO_SLICES;
    if (midBufferSize == 0 || midBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size calculation!");
        return false;
    }
    destBufferSize = static_cast<size_t>(yDInfo.uvOffset * STRIDES_PER_PLANE);
    if (destBufferSize == 0 || destBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size calculation!");
        return false;
    }
    uint8_t *midBuffer = nullptr;
    midBuffer = new(std::nothrow) uint8_t[midBufferSize]();
    if (midBuffer == nullptr) {
        IMAGE_LOGE("apply space for dest buffer failed!");
        return false;
    }
    bool result = false;
    result = NV12P010ToNV21P010SoftDecode(srcBuffer, yDInfo, &midBuffer);
    if (!result) {
        IMAGE_LOGE("NV21P010ToNV12P010 failed!");
        delete[] midBuffer;
        return false;
    }
    *destBuffer = new(std::nothrow) uint8_t[destBufferSize]();
    if (*destBuffer == nullptr) {
        IMAGE_LOGE("apply space for dest buffer failed!");
        delete[] midBuffer;
        return false;
    }
    Convert10bitInfo convertInfo;
    convertInfo.srcPixelFormat = PixelFormat::YCBCR_P010;
    convertInfo.dstPixelFormat = PixelFormat::RGBA_F16;
    convertInfo.dstBytes = STRIDES_PER_PLANE;
    result = P010ToRGBASoftDecode(midBuffer, yDInfo, destBuffer, convertInfo);
    if (!result) {
        IMAGE_LOGE("NV21P010ToRGBAF16 failed!");
        delete[] midBuffer;
        delete[] (*destBuffer);
        *destBuffer = nullptr;
        return result;
    }
    delete[] midBuffer;
    return true;
}

static bool CalcRGBStride(PixelFormat format, uint32_t width, int &stride)
{
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