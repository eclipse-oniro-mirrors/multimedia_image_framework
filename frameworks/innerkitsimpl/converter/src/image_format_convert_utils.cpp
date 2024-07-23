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

static bool NV12ToRGB565SoftDecode(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo, uint8_t **destBuffer)
{
    AVPixelFormat srcFormat = findPixelFormat(PixelFormat::NV12);
    AVPixelFormat dstFormat = findPixelFormat(PixelFormat::RGB_565);
    SwsContext *swsContext = sws_getContext(yDInfo.yWidth, yDInfo.yHeight, srcFormat, yDInfo.yWidth,
        yDInfo.yHeight, dstFormat, SWS_BILINEAR, nullptr, nullptr, nullptr);
    if (swsContext == nullptr) {
        IMAGE_LOGE("Error to create SwsContext.");
        return false;
    }

    const uint8_t *srcSlice[] = {srcBuffer + yDInfo.yOffset, srcBuffer + yDInfo.uvOffset};
    const int srcStride[] = {static_cast<int>(yDInfo.yStride), static_cast<int>(yDInfo.uvStride)};
    uint8_t *dstSlice[] = {*destBuffer};
    const int dstStride[] = {static_cast<int>(yDInfo.yWidth * BYTES_PER_PIXEL_RGB565)};
    int height = sws_scale(swsContext, srcSlice, srcStride, SRCSLICEY, yDInfo.yHeight, dstSlice, dstStride);
    sws_freeContext(swsContext);
    if (height == 0) {
        IMAGE_LOGE("Image pixel format conversion failed");
        return false;
    }
    return true;
}

static bool NV21ToNV12SoftDecode(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo, uint8_t **destBuffer)
{
    AVPixelFormat srcFormat = findPixelFormat(PixelFormat::NV21);
    AVPixelFormat dstFormat = findPixelFormat(PixelFormat::NV12);
    SwsContext *swsContext = sws_getContext(yDInfo.yWidth, yDInfo.yHeight, srcFormat, yDInfo.yWidth,
        yDInfo.yHeight, dstFormat, SWS_BILINEAR, nullptr, nullptr, nullptr);
    if (swsContext == nullptr) {
        IMAGE_LOGE("Error to create SwsContext.");
        return false;
    }

    int widthEven = (yDInfo.yWidth % EVEN_ODD_DIVISOR == 0) ? (yDInfo.yWidth) : (yDInfo.yWidth + 1);
    const uint8_t *srcSlice[] = {srcBuffer + yDInfo.yOffset, srcBuffer + yDInfo.uvOffset};
    const int srcStride[] = {static_cast<int>(yDInfo.yStride), static_cast<int>(yDInfo.uvStride)};
    uint8_t *dstSlice[] = {*destBuffer, *destBuffer + yDInfo.yWidth * yDInfo.yHeight};
    const int dstStride[] = {static_cast<int>(yDInfo.yWidth), static_cast<int>(widthEven)};

    int height = sws_scale(swsContext, srcSlice, srcStride, SRCSLICEY, yDInfo.yHeight, dstSlice, dstStride);
    sws_freeContext(swsContext);
    if (height == 0) {
        IMAGE_LOGE("Image pixel format conversion failed");
        return false;
    }
    return true;
}

static bool NV12ToNV21SoftDecode(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo, uint8_t **destBuffer)
{
    AVPixelFormat srcFormat = findPixelFormat(PixelFormat::NV12);
    AVPixelFormat dstFormat = findPixelFormat(PixelFormat::NV21);
    SwsContext *swsContext = sws_getContext(yDInfo.yWidth, yDInfo.yHeight, srcFormat, yDInfo.yWidth,
        yDInfo.yHeight, dstFormat, SWS_BILINEAR, nullptr, nullptr, nullptr);
    if (swsContext == nullptr) {
        IMAGE_LOGE("Error to create SwsContext.");
        return false;
    }

    int widthEven = (yDInfo.yWidth % EVEN_ODD_DIVISOR == 0) ? (yDInfo.yWidth) : (yDInfo.yWidth + 1);
    const uint8_t *srcSlice[] = {srcBuffer + yDInfo.yOffset, srcBuffer + yDInfo.uvOffset};
    const int srcStride[] = {static_cast<int>(yDInfo.yStride), static_cast<int>(yDInfo.uvStride)};
    uint8_t *dstSlice[] = {*destBuffer, *destBuffer + yDInfo.yWidth * yDInfo.yHeight};
    const int dstStride[] = {static_cast<int>(yDInfo.yWidth), static_cast<int>(widthEven)};

    int height = sws_scale(swsContext, srcSlice, srcStride, SRCSLICEY, yDInfo.yHeight, dstSlice, dstStride);
    sws_freeContext(swsContext);
    if (height == 0) {
        IMAGE_LOGE("Image pixel format conversion failed");
        return false;
    }
    return true;
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

static bool RGB565ToNV12SoftDecode(const uint8_t *srcBuffer, const Size &imageSize, uint8_t **destBuffer)
{
    AVPixelFormat srcFormat = findPixelFormat(PixelFormat::RGB_565);
    AVPixelFormat dstFormat = findPixelFormat(PixelFormat::NV12);
    SwsContext *swsContext = sws_getContext(imageSize.width, imageSize.height, srcFormat, imageSize.width,
        imageSize.height, dstFormat, SWS_BILINEAR, nullptr, nullptr, nullptr);
    if (swsContext == nullptr) {
        IMAGE_LOGE("Error to create SwsContext.");
        return false;
    }

    int widthEven = (imageSize.width % EVEN_ODD_DIVISOR == 0) ? (imageSize.width) : (imageSize.width + 1);
    const uint8_t *srcSlice[] = {srcBuffer};
    const int srcStride[] = {static_cast<int>(imageSize.width * BYTES_PER_PIXEL_RGB565)};
    uint8_t *dstSlice[] = {*destBuffer, *destBuffer + imageSize.width * imageSize.height};
    const int dstStride[] = {static_cast<int>(imageSize.width), static_cast<int>(widthEven)};
    int height = sws_scale(swsContext, srcSlice, srcStride, SRCSLICEY, imageSize.height, dstSlice, dstStride);
    sws_freeContext(swsContext);
    if (height == 0) {
        IMAGE_LOGE("Image pixel format conversion failed");
        return false;
    }
    return true;
}

static bool RGB565ToNV21SoftDecode(const uint8_t *srcBuffer, const Size &imageSize, uint8_t **destBuffer)
{
    AVPixelFormat srcFormat = findPixelFormat(PixelFormat::RGB_565);
    AVPixelFormat dstFormat = findPixelFormat(PixelFormat::NV21);
    SwsContext *swsContext = sws_getContext(imageSize.width, imageSize.height, srcFormat, imageSize.width,
        imageSize.height, dstFormat, SWS_BILINEAR, nullptr, nullptr, nullptr);
    if (swsContext == nullptr) {
        IMAGE_LOGE("Error to create SwsContext.");
        return false;
    }

    int widthEven = (imageSize.width % EVEN_ODD_DIVISOR == 0) ? (imageSize.width) : (imageSize.width + 1);
    const uint8_t *srcSlice[] = {srcBuffer};
    const int srcStride[] = {static_cast<int>(imageSize.width * BYTES_PER_PIXEL_RGB565)};
    uint8_t *dstSlice[] = {*destBuffer, *destBuffer + imageSize.width * imageSize.height};
    const int dstStride[] = {static_cast<int>(imageSize.width), static_cast<int>(widthEven)};
    int height = sws_scale(swsContext, srcSlice, srcStride, SRCSLICEY, imageSize.height, dstSlice, dstStride);
    sws_freeContext(swsContext);
    if (height == 0) {
        IMAGE_LOGE("Image pixel format conversion failed");
        return false;
    }
    return true;
}

static bool NV12ToRGBAF16SoftDecode(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo, uint8_t **destBuffer)
{
    AVPixelFormat srcFormat = findPixelFormat(PixelFormat::NV12);
    AVPixelFormat dstFormat = findPixelFormat(PixelFormat::RGBA_F16);
    struct SwsContext *ctx = sws_getContext(yDInfo.yWidth, yDInfo.yHeight, srcFormat,
                                            yDInfo.yWidth, yDInfo.yHeight, dstFormat,
                                            SWS_BILINEAR, nullptr, nullptr, nullptr);
    if (ctx == nullptr) {
        IMAGE_LOGE("sws_getContext: result is null!");
        return false;
    }

    const uint8_t *srcSlice[] = { srcBuffer + yDInfo.yOffset, srcBuffer + yDInfo.uvOffset };
    const int srcStride[] = { static_cast<int>(yDInfo.yStride), static_cast<int>(yDInfo.uvStride) };
    const int dstStride[] = { static_cast<int>(yDInfo.yWidth * STRIDES_PER_PLANE) };
    int height = sws_scale(ctx, srcSlice, srcStride, SRCSLICEY, yDInfo.yHeight, destBuffer, dstStride);
    sws_freeContext(ctx);
    if (height == 0) {
        IMAGE_LOGE("Image pixel format conversion failed");
        return false;
    }
    return true;
}

static bool BGRAToNV21SoftDecode(const uint8_t *srcBuffer, const Size &imageSize, uint8_t **destBuffer)
{
    AVPixelFormat srcFormat = findPixelFormat(PixelFormat::BGRA_8888);
    AVPixelFormat dstFormat = findPixelFormat(PixelFormat::NV21);
    SwsContext *swsContext = sws_getContext(imageSize.width, imageSize.height, srcFormat, imageSize.width,
        imageSize.height, dstFormat, SWS_BILINEAR, nullptr, nullptr, nullptr);
    if (swsContext == nullptr) {
        IMAGE_LOGE("Error to create SwsContext.");
        return false;
    }

    int widthEven = (imageSize.width % EVEN_ODD_DIVISOR == 0) ? (imageSize.width) : (imageSize.width + 1);
    const uint8_t *srcSlice[] = {srcBuffer};
    const int srcStride[] = {static_cast<int>(imageSize.width * BYTES_PER_PIXEL_BGRA)};
    uint8_t *dstSlice[] = {*destBuffer, *destBuffer + imageSize.width * imageSize.height};
    const int dstStride[] = {static_cast<int>(imageSize.width), static_cast<int>(widthEven)};
    int height = sws_scale(swsContext, srcSlice, srcStride, SRCSLICEY, imageSize.height, dstSlice, dstStride);
    sws_freeContext(swsContext);
    if (height == 0) {
        IMAGE_LOGE("Image pixel format conversion failed");
        return false;
    }
    return true;
}

static bool NV12ToRGBASoftDecode(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo, uint8_t **destBuffer)
{
    AVPixelFormat srcFormat = findPixelFormat(PixelFormat::NV12);
    AVPixelFormat dstFormat = findPixelFormat(PixelFormat::RGBA_8888);
    struct SwsContext *ctx = sws_getContext(yDInfo.yWidth, yDInfo.yHeight, srcFormat,
                                            yDInfo.yWidth, yDInfo.yHeight, dstFormat,
                                            SWS_BILINEAR, nullptr, nullptr, nullptr);
    if (ctx == nullptr) {
        IMAGE_LOGE("sws_getContext: result is null!");
        return false;
    }

    const uint8_t *srcSlice[] = { srcBuffer + yDInfo.yOffset, srcBuffer + yDInfo.uvOffset };
    const int srcStride[] = { static_cast<int>(yDInfo.yStride), static_cast<int>(yDInfo.uvStride) };
    const int dstStride[] = { static_cast<int>(yDInfo.yWidth * BYTES_PER_PIXEL_RGBA) };
    int height = sws_scale(ctx, srcSlice, srcStride, SRCSLICEY, yDInfo.yHeight, destBuffer, dstStride);
    sws_freeContext(ctx);

    if (height == 0) {
        IMAGE_LOGE("Image pixel format conversion failed");
        return false;
    }
    return true;
}

static bool NV12ToBGRASoftDecode(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo, uint8_t **destBuffer)
{
    AVPixelFormat srcFormat = findPixelFormat(PixelFormat::NV12);
    AVPixelFormat dstFormat = findPixelFormat(PixelFormat::BGRA_8888);
    struct SwsContext *ctx = sws_getContext(yDInfo.yWidth, yDInfo.yHeight, srcFormat,
                                            yDInfo.yWidth, yDInfo.yHeight, dstFormat,
                                            SWS_BILINEAR, nullptr, nullptr, nullptr);
    if (ctx == nullptr) {
        IMAGE_LOGE("sws_getContext: result is null!");
        return false;
    }

    const uint8_t *srcSlice[] = { srcBuffer + yDInfo.yOffset, srcBuffer + yDInfo.uvOffset };
    const int srcStride[] = {static_cast<int>(yDInfo.yStride), static_cast<int>(yDInfo.uvStride)};
    const int dstStride[] = { static_cast<int>(yDInfo.yWidth * BYTES_PER_PIXEL_BGRA) };
    int height = sws_scale(ctx, srcSlice, srcStride, SRCSLICEY, yDInfo.yHeight, destBuffer, dstStride);
    sws_freeContext(ctx);

    if (height == 0) {
        IMAGE_LOGE("Image pixel format conversion failed");
        return false;
    }
    return true;
}

static bool RGBAToNV12SoftDecode(const uint8_t *srcBuffer, const Size &imageSize, uint8_t **destBuffer)
{
    AVPixelFormat srcFormat = findPixelFormat(PixelFormat::RGBA_8888);
    AVPixelFormat dstFormat = findPixelFormat(PixelFormat::NV12);
    SwsContext *swsContext = sws_getContext(imageSize.width, imageSize.height, srcFormat, imageSize.width,
        imageSize.height, dstFormat, SWS_BILINEAR, nullptr, nullptr, nullptr);
    if (swsContext == nullptr) {
        IMAGE_LOGE("Error to create SwsContext.");
        return false;
    }

    int widthEven = (imageSize.width % EVEN_ODD_DIVISOR == 0) ? (imageSize.width) : (imageSize.width + 1);
    const uint8_t *srcSlice[] = {srcBuffer};
    const int srcStride[] = {static_cast<int>(imageSize.width * BYTES_PER_PIXEL_RGBA)};
    uint8_t *dstSlice[] = {*destBuffer, *destBuffer + imageSize.width * imageSize.height};
    const int dstStride[] = {static_cast<int>(imageSize.width), static_cast<int>(widthEven)};
    int height = sws_scale(swsContext, srcSlice, srcStride, SRCSLICEY, imageSize.height, dstSlice, dstStride);
    sws_freeContext(swsContext);
    if (height == 0) {
        IMAGE_LOGE("Image pixel format conversion failed");
        return false;
    }
    return true;
}

static bool RGBAToNV21SoftDecode(const uint8_t *srcBuffer, const Size &imageSize, uint8_t **destBuffer)
{
    AVPixelFormat srcFormat = findPixelFormat(PixelFormat::RGBA_8888);
    AVPixelFormat dstFormat = findPixelFormat(PixelFormat::NV21);
    SwsContext *swsContext = sws_getContext(imageSize.width, imageSize.height, srcFormat, imageSize.width,
        imageSize.height, dstFormat, SWS_BILINEAR, nullptr, nullptr, nullptr);
    if (swsContext == nullptr) {
        IMAGE_LOGE("Error to create SwsContext.");
        return false;
    }

    int widthEven = (imageSize.width % EVEN_ODD_DIVISOR == 0) ? (imageSize.width) : (imageSize.width + 1);
    const uint8_t *srcSlice[] = {srcBuffer};
    const int srcStride[] = {static_cast<int>(imageSize.width * BYTES_PER_PIXEL_RGBA)};
    uint8_t *dstSlice[] = {*destBuffer, *destBuffer + imageSize.width * imageSize.height};
    const int dstStride[] = {static_cast<int>(imageSize.width), static_cast<int>(widthEven)};
    int height = sws_scale(swsContext, srcSlice, srcStride, SRCSLICEY, imageSize.height, dstSlice, dstStride);
    sws_freeContext(swsContext);
    if (height == 0) {
        IMAGE_LOGE("Image pixel format conversion failed");
        return false;
    }
    return true;
}

static bool RGBToNV21SoftDecode(const uint8_t *srcBuffer, const Size &imageSize, uint8_t **destBuffer)
{
    AVPixelFormat srcFormat = findPixelFormat(PixelFormat::RGB_888);
    AVPixelFormat dstFormat = findPixelFormat(PixelFormat::NV21);
    SwsContext *swsContext = sws_getContext(imageSize.width, imageSize.height, srcFormat, imageSize.width,
        imageSize.height, dstFormat, SWS_BILINEAR, nullptr, nullptr, nullptr);
    if (swsContext == nullptr) {
        IMAGE_LOGE("Error to create SwsContext.");
        return false;
    }

    int widthEven = (imageSize.width % EVEN_ODD_DIVISOR == 0) ? (imageSize.width) : (imageSize.width + 1);
    const uint8_t *srcSlice[] = {srcBuffer};
    const int srcStride[] = {static_cast<int>(imageSize.width * BYTES_PER_PIXEL_RGB)};
    uint8_t *dstSlice[] = {*destBuffer, *destBuffer + imageSize.width * imageSize.height};
    const int dstStride[] = {static_cast<int>(imageSize.width), static_cast<int>(widthEven)};
    int height = sws_scale(swsContext, srcSlice, srcStride, SRCSLICEY, imageSize.height, dstSlice, dstStride);
    sws_freeContext(swsContext);
    if (height == 0) {
        IMAGE_LOGE("Image pixel format conversion failed");
        return false;
    }
    return true;
}

static bool NV21ToRGBASoftDecode(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo, uint8_t **destBuffer)
{
    AVPixelFormat srcFormat = findPixelFormat(PixelFormat::NV21);
    AVPixelFormat dstFormat = findPixelFormat(PixelFormat::RGBA_8888);
    SwsContext *swsContext = sws_getContext(yDInfo.yWidth, yDInfo.yHeight, srcFormat, yDInfo.yWidth,
        yDInfo.yHeight, dstFormat, SWS_BILINEAR, nullptr, nullptr, nullptr);
    if (swsContext == nullptr) {
        IMAGE_LOGE("Error to create SwsContext.");
        return false;
    }

    const uint8_t *srcSlice[] = {srcBuffer + yDInfo.yOffset, srcBuffer + yDInfo.uvOffset};
    const int srcStride[] = {static_cast<int>(yDInfo.yStride), static_cast<int>(yDInfo.uvStride)};
    uint8_t *dstSlice[] = {*destBuffer};
    const int dstStride[] = {static_cast<int>(yDInfo.yWidth * BYTES_PER_PIXEL_RGBA)};
    int height = sws_scale(swsContext, srcSlice, srcStride, SRCSLICEY, yDInfo.yHeight, dstSlice, dstStride);
    sws_freeContext(swsContext);
    if (height == 0) {
        IMAGE_LOGE("Image pixel format conversion failed");
        return false;
    }
    return true;
}

static bool NV21ToRGB565SoftDecode(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo, uint8_t **destBuffer)
{
    AVPixelFormat srcFormat = findPixelFormat(PixelFormat::NV21);
    AVPixelFormat dstFormat = findPixelFormat(PixelFormat::RGB_565);
    SwsContext *swsContext = sws_getContext(yDInfo.yWidth, yDInfo.yHeight, srcFormat, yDInfo.yWidth,
        yDInfo.yHeight, dstFormat, SWS_BILINEAR, nullptr, nullptr, nullptr);
    if (swsContext == nullptr) {
        IMAGE_LOGE("Error to create SwsContext.");
        return false;
    }

    const uint8_t *srcSlice[] = {srcBuffer + yDInfo.yOffset, srcBuffer + yDInfo.uvOffset};
    const int srcStride[] = {static_cast<int>(yDInfo.yStride), static_cast<int>(yDInfo.uvStride)};
    uint8_t *dstSlice[] = {*destBuffer};
    const int dstStride[] = {static_cast<int>(yDInfo.yWidth * BYTES_PER_PIXEL_RGB565)};
    int height = sws_scale(swsContext, srcSlice, srcStride, SRCSLICEY, yDInfo.yHeight, dstSlice, dstStride);

    sws_freeContext(swsContext);
    if (height == 0) {
        IMAGE_LOGE("Image pixel format conversion failed");
        return false;
    }
    return true;
}

static bool NV21ToBGRASoftDecode(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo, uint8_t **destBuffer)
{
    AVPixelFormat srcFormat = findPixelFormat(PixelFormat::NV21);
    AVPixelFormat dstFormat = findPixelFormat(PixelFormat::BGRA_8888);
    SwsContext *swsContext = sws_getContext(yDInfo.yWidth, yDInfo.yHeight, srcFormat, yDInfo.yWidth,
        yDInfo.yHeight, dstFormat, SWS_BILINEAR, nullptr, nullptr, nullptr);
    if (swsContext == nullptr) {
        IMAGE_LOGE("Error to create SwsContext.");
        return false;
    }

    const uint8_t *srcSlice[] = {srcBuffer + yDInfo.yOffset, srcBuffer + yDInfo.uvOffset};
    const int srcStride[] = {static_cast<int>(yDInfo.yStride), static_cast<int>(yDInfo.uvStride)};
    uint8_t *dstSlice[] = {*destBuffer};
    const int dstStride[] = {static_cast<int>(yDInfo.yWidth * BYTES_PER_PIXEL_RGBA)};
    int height = sws_scale(swsContext, srcSlice, srcStride, SRCSLICEY, yDInfo.yHeight, dstSlice, dstStride);
    sws_freeContext(swsContext);
    if (height == 0) {
        IMAGE_LOGE("Image pixel format conversion failed");
        return false;
    }
    return true;
}

static bool RGBToNV12SoftDecode(const uint8_t *srcBuffer, const Size &imageSize, uint8_t **destBuffer)
{
    AVPixelFormat srcFormat = findPixelFormat(PixelFormat::RGB_888);
    AVPixelFormat dstFormat = findPixelFormat(PixelFormat::NV12);
    SwsContext *swsContext = sws_getContext(imageSize.width, imageSize.height, srcFormat, imageSize.width,
        imageSize.height, dstFormat, SWS_BILINEAR, nullptr, nullptr, nullptr);
    if (swsContext == nullptr) {
        IMAGE_LOGE("Error to create SwsContext.");
        return false;
    }

    int widthEven = (imageSize.width % EVEN_ODD_DIVISOR == 0) ? (imageSize.width) : (imageSize.width + 1);
    const uint8_t *srcSlice[] = {srcBuffer};
    const int srcStride[] = {static_cast<int>(imageSize.width * BYTES_PER_PIXEL_RGB)};
    uint8_t *dstSlice[] = {*destBuffer, *destBuffer + imageSize.width * imageSize.height};
    const int dstStride[] = {static_cast<int>(imageSize.width), static_cast<int>(widthEven)};
    int height = sws_scale(swsContext, srcSlice, srcStride, SRCSLICEY, imageSize.height, dstSlice, dstStride);
    sws_freeContext(swsContext);
    if (height == 0) {
        IMAGE_LOGE("Image pixel format conversion failed");
        return false;
    }
    return true;
}

static bool BGRAToNV12SoftDecode(const uint8_t *srcBuffer, const Size &imageSize, uint8_t **destBuffer)
{
    AVPixelFormat srcFormat = findPixelFormat(PixelFormat::BGRA_8888);
    AVPixelFormat dstFormat = findPixelFormat(PixelFormat::NV12);
    SwsContext *swsContext = sws_getContext(imageSize.width, imageSize.height, srcFormat, imageSize.width,
        imageSize.height, dstFormat, SWS_BILINEAR, nullptr, nullptr, nullptr);
    if (swsContext == nullptr) {
        IMAGE_LOGE("Error to create SwsContext.");
        return false;
    }

    int widthEven = (imageSize.width % EVEN_ODD_DIVISOR == 0) ? (imageSize.width) : (imageSize.width + 1);
    const uint8_t *srcSlice[] = {srcBuffer};
    const int srcStride[] = {static_cast<int>(imageSize.width * BYTES_PER_PIXEL_BGRA)};
    uint8_t *dstSlice[] = {*destBuffer, *destBuffer + imageSize.width * imageSize.height};
    const int dstStride[] = {static_cast<int>(imageSize.width), static_cast<int>(widthEven)};
    int height = sws_scale(swsContext, srcSlice, srcStride, SRCSLICEY, imageSize.height, dstSlice, dstStride);
    sws_freeContext(swsContext);
    if (height == 0) {
        IMAGE_LOGE("Image pixel format conversion failed");
        return false;
    }
    return true;
}

bool ImageFormatConvertUtils::NV12ToRGB565(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo, uint8_t **destBuffer,
                                           size_t &destBufferSize, [[maybe_unused]]ColorSpace colorSpace)
{
    if (srcBuffer == nullptr || destBuffer == nullptr || yDInfo.yWidth == 0 || yDInfo.yHeight == 0 ||
        yDInfo.uvWidth == 0 || yDInfo.uvHeight == 0) {
        return false;
    }

    destBufferSize = static_cast<size_t>(yDInfo.yWidth * yDInfo.yHeight * BYTES_PER_PIXEL_RGB565);
    if (destBufferSize == 0 || destBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size calculation!");
        return false;
    }
    *destBuffer = new(std::nothrow) uint8_t[destBufferSize]();
    if (*destBuffer == nullptr) {
        IMAGE_LOGE("apply space for dest buffer failed!");
        return false;
    }
    if (!NV12ToRGB565SoftDecode(srcBuffer, yDInfo, destBuffer)) {
        delete[] (*destBuffer);
        IMAGE_LOGE("NV12 manual conversion to RGB565 failed!");
        return false;
    }
    return true;
}

bool ImageFormatConvertUtils::RGBAF16ToNV21(const uint8_t *srcBuffer, const Size &imageSize, uint8_t **destBuffer,
                                            size_t &destBufferSize, [[maybe_unused]]ColorSpace colorSpace)
{
    if (srcBuffer == nullptr || destBuffer == nullptr || imageSize.width < 0 || imageSize.height < 0) {
        return false;
    }
    uint32_t frameSize = imageSize.width * imageSize.height;
    destBufferSize = frameSize +
        (((imageSize.width + 1) / TWO_SLICES * (imageSize.height + 1) / TWO_SLICES) * TWO_SLICES);
    if (destBufferSize == 0 || destBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size calculation!");
        return false;
    }
    *destBuffer = new(std::nothrow) uint8_t[destBufferSize]();
    if (*destBuffer == nullptr) {
        IMAGE_LOGE("apply space for dest buffer failed!");
        return false;
    }

    AVPixelFormat srcFormat = findPixelFormat(PixelFormat::RGBA_F16);
    AVPixelFormat dstFormat = findPixelFormat(PixelFormat::NV21);
    SwsContext *swsContext = sws_getContext(imageSize.width, imageSize.height, srcFormat, imageSize.width,
        imageSize.height, dstFormat, SWS_BILINEAR, nullptr, nullptr, nullptr);
    if (swsContext == nullptr) {
        IMAGE_LOGE("Error to create SwsContext.");
        delete[] destBuffer;
        return false;
    }

    int widthEven = (imageSize.width % EVEN_ODD_DIVISOR == 0) ? (imageSize.width) : (imageSize.width + 1);
    const uint8_t *srcSlice[] = {srcBuffer};
    const int srcStride[] = {static_cast<int>(imageSize.width * STRIDES_PER_PLANE)};
    uint8_t *dstSlice[] = {*destBuffer, *destBuffer + imageSize.width * imageSize.height};
    const int dstStride[] = {static_cast<int>(imageSize.width), static_cast<int>(widthEven)};
    int height = sws_scale(swsContext, srcSlice, srcStride, SRCSLICEY, imageSize.height, dstSlice, dstStride);
    sws_freeContext(swsContext);
    if (height == 0) {
        IMAGE_LOGE("RGBAF16ToNV21 format conversion failed");
        delete[] destBuffer;
        return false;
    }
    return true;
}

bool ImageFormatConvertUtils::NV21ToNV12(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo, uint8_t **destBuffer,
                                         size_t &destBufferSize, [[maybe_unused]]ColorSpace colorSpace)
{
    if (srcBuffer == nullptr || destBuffer == nullptr || yDInfo.yWidth == 0 || yDInfo.yHeight == 0 ||
        yDInfo.uvWidth == 0 || yDInfo.uvHeight == 0) {
        return false;
    }
    destBufferSize = yDInfo.yWidth * yDInfo.yHeight + yDInfo.uvWidth * TWO_SLICES * yDInfo.uvHeight;
    if (destBufferSize == 0 || destBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size is 0!");
        return false;
    }
    *destBuffer = new(std::nothrow) uint8_t[destBufferSize];
    if (*destBuffer == nullptr) {
        IMAGE_LOGE("apply space for dest buffer failed!");
        return false;
    }
    bool result = NV21ToNV12SoftDecode(srcBuffer, yDInfo, destBuffer);
    if (!result) {
        delete[] (*destBuffer);
        IMAGE_LOGE("NV21 conversion to NV12 failed!");
    }
    return result;
}

bool ImageFormatConvertUtils::NV21ToRGBAF16(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo, uint8_t **destBuffer,
                                            size_t &destBufferSize, [[maybe_unused]]ColorSpace colorSpace)
{
    if (srcBuffer == nullptr || destBuffer == nullptr || yDInfo.yWidth == 0 || yDInfo.yHeight == 0 ||
        yDInfo.uvWidth == 0 || yDInfo.uvHeight == 0) {
        return false;
    }
    destBufferSize = yDInfo.yWidth * yDInfo.yHeight * STRIDES_PER_PLANE;
    if (destBufferSize == 0 || destBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size is 0!");
        return false;
    }
    *destBuffer = new(std::nothrow) uint8_t[destBufferSize]();
    if (*destBuffer == nullptr) {
        IMAGE_LOGE("apply space for dest buffer failed!");
        return false;
    }
    AVPixelFormat srcFormat = findPixelFormat(PixelFormat::NV21);
    AVPixelFormat dstFormat = findPixelFormat(PixelFormat::RGBA_F16);
    SwsContext *swsContext = sws_getContext(yDInfo.yWidth, yDInfo.yHeight, srcFormat, yDInfo.yWidth,
        yDInfo.yHeight, dstFormat, SWS_BILINEAR, nullptr, nullptr, nullptr);
    if (swsContext == nullptr) {
        IMAGE_LOGE("Error to create SwsContext.");
        return false;
    }
    
    const uint8_t *srcSlice[] = {srcBuffer + yDInfo.yOffset, srcBuffer + yDInfo.uvOffset};
    const int srcStride[] = {static_cast<int>(yDInfo.yStride), static_cast<int>(yDInfo.uvStride)};
    uint8_t *dstSlice[] = {*destBuffer};
    const int dstStride[] = {static_cast<int>(yDInfo.yWidth * STRIDES_PER_PLANE)};
    int height = sws_scale(swsContext, srcSlice, srcStride, SRCSLICEY, yDInfo.yHeight, dstSlice, dstStride);
    sws_freeContext(swsContext);
    if (height == 0) {
        IMAGE_LOGE("Image pixel format conversion failed");
        delete[] (*destBuffer);
        return false;
    }
    return true;
}

bool ImageFormatConvertUtils::NV12ToNV21(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo, uint8_t **destBuffer,
                                         size_t &destBufferSize, [[maybe_unused]]ColorSpace colorSpace)
{
    if (srcBuffer == nullptr || destBuffer == nullptr || yDInfo.yWidth == 0 || yDInfo.yHeight == 0 ||
        yDInfo.uvWidth == 0 || yDInfo.uvHeight == 0) {
        return false;
    }
    destBufferSize = yDInfo.yWidth * yDInfo.yHeight + yDInfo.uvWidth * EVEN_ODD_DIVISOR * yDInfo.uvHeight;
    if (destBufferSize == 0 || destBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size calculation!");
        return false;
    }

    *destBuffer = new(std::nothrow) uint8_t[destBufferSize]();
    if (*destBuffer == nullptr) {
        IMAGE_LOGE("apply space for dest buffer failed!");
        return false;
    }
    bool result = NV12ToNV21SoftDecode(srcBuffer, yDInfo, destBuffer);
    if (!result) {
        delete[] (*destBuffer);
        IMAGE_LOGE("NV12 conversion to NV21 failed!");
    }
    return result;
}

bool ImageFormatConvertUtils::BGRAToNV12(const uint8_t *srcBuffer, const Size &imageSize, uint8_t **destBuffer,
                                         size_t &destBufferSize, [[maybe_unused]]ColorSpace colorSpace)
{
    if (srcBuffer == nullptr || destBuffer == nullptr || imageSize.width < 0 || imageSize.height < 0) {
        return false;
    }
    size_t destPlaneSizeY = imageSize.width * imageSize.height;
    size_t srcPlaneSizeUV = ((imageSize.width + 1) / TWO_SLICES) * ((imageSize.height + 1) / TWO_SLICES);
    destBufferSize = static_cast<size_t>(destPlaneSizeY + srcPlaneSizeUV * TWO_SLICES);
    if (destBufferSize == 0 || destBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size calculation!");
        return false;
    }
    *destBuffer = new(std::nothrow) uint8_t[destBufferSize]();
    if (*destBuffer == nullptr) {
        IMAGE_LOGE("apply space for dest buffer failed!");
        return false;
    }
    bool bRet = BGRAToNV12SoftDecode(srcBuffer, imageSize, destBuffer);
    if (!bRet) {
        IMAGE_LOGE("BGRAToNV12 failed!");
        delete[] (*destBuffer);
        *destBuffer = nullptr;
        return false;
    }
    return true;
}

bool ImageFormatConvertUtils::RGB565ToNV12(const uint8_t *srcBuffer, const Size &imageSize, uint8_t **destBuffer,
                                           size_t &destBufferSize, [[maybe_unused]]ColorSpace colorSpace)
{
    if (srcBuffer == nullptr || destBuffer == nullptr || imageSize.width < 0 || imageSize.height < 0) {
        return false;
    }
    destBufferSize = static_cast<size_t>(imageSize.width * imageSize.height +
        ((imageSize.width + 1) / TWO_SLICES) * ((imageSize.height + 1) / TWO_SLICES) * TWO_SLICES);
    if (destBufferSize == 0 || destBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size calculation!");
        return false;
    }

    *destBuffer = new(std::nothrow) uint8_t[destBufferSize]();
    if (*destBuffer == nullptr) {
        IMAGE_LOGE("apply space for dest buffer failed!");
        return false;
    }
    bool bRet = RGB565ToNV12SoftDecode(srcBuffer, imageSize, destBuffer);
    if (!bRet) {
        IMAGE_LOGE("RGB565ToNV12 failed!");
        delete[] (*destBuffer);
        *destBuffer = nullptr;
        return false;
    }
    return true;
}

bool ImageFormatConvertUtils::RGB565ToNV21(const uint8_t *srcBuffer, const Size &imageSize, uint8_t **destBuffer,
                                           size_t &destBufferSize, [[maybe_unused]]ColorSpace colorSpace)
{
    if (srcBuffer == nullptr || destBuffer == nullptr || imageSize.width < 0 || imageSize.height < 0) {
        return false;
    }
    destBufferSize = static_cast<size_t>(imageSize.width * imageSize.height + ((imageSize.width + 1) / TWO_SLICES) *
        ((imageSize.height + 1) / TWO_SLICES) * TWO_SLICES);
    if (destBufferSize == 0 || destBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size calculation!");
        return false;
    }
    *destBuffer = new(std::nothrow) uint8_t[destBufferSize]();
    if (*destBuffer == nullptr) {
        IMAGE_LOGE("apply space for dest buffer failed!");
        return false;
    }
    bool bRet = RGB565ToNV21SoftDecode(srcBuffer, imageSize, destBuffer);
    if (!bRet) {
        IMAGE_LOGE("RGB565ToNV21 failed!");
        delete[] (*destBuffer);
        *destBuffer = nullptr;
        return false;
    }
    return true;
}

bool ImageFormatConvertUtils::NV12ToRGBAF16(const uint8_t *data, const YUVDataInfo &yDInfo, uint8_t **destBuffer,
                                            size_t &destBufferSize, [[maybe_unused]]ColorSpace colorSpace)
{
    if (data == nullptr || destBuffer == nullptr) {
        IMAGE_LOGE("Input buffer pointer data or destBuffer is null!");
        return false;
    }

    uint32_t frameSize = yDInfo.yWidth * yDInfo.yHeight;
    destBufferSize = frameSize * sizeof(uint64_t);
    if (destBufferSize == 0 || destBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size is 0!");
        return false;
    }
    *destBuffer = new(std::nothrow) uint8_t[destBufferSize]();
    if (*destBuffer == nullptr) {
        IMAGE_LOGE("Dynamically allocating memory for destination buffer failed!");
        return false;
    }

    if (!NV12ToRGBAF16SoftDecode(data, yDInfo, destBuffer)) {
        IMAGE_LOGE("NV12ToRGBAF16 failed!");
        delete[] (*destBuffer);
        *destBuffer = nullptr;
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

bool ImageFormatConvertUtils::BGRAToNV21(const uint8_t *srcBuffer, const Size &imageSize, uint8_t **destBuffer,
                                         size_t &destBufferSize, [[maybe_unused]]ColorSpace colorSpace)
{
    if (srcBuffer == nullptr || destBuffer == nullptr || imageSize.width < 0 || imageSize.height < 0) {
        return false;
    }
    const int32_t destPlaneSizeY = imageSize.width * imageSize.height;
    const int32_t destPlaneSizeVU = ((imageSize.width + 1) / TWO_SLICES) * ((imageSize.height + 1) / TWO_SLICES);
    destBufferSize = static_cast<size_t>(destPlaneSizeY + destPlaneSizeVU * TWO_SLICES);
    if (destBufferSize == 0 || destBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size calculation!");
        return false;
    }
    *destBuffer = new(std::nothrow) uint8_t[destBufferSize]();
    if (*destBuffer == nullptr) {
        IMAGE_LOGE("apply space for dest buffer failed!");
        return false;
    }
    bool bRet = BGRAToNV21SoftDecode(srcBuffer, imageSize, destBuffer);
    if ((!bRet)) {
        IMAGE_LOGE("BGRAToNV21 failed!");
        delete[] (*destBuffer);
        *destBuffer = nullptr;
        return false;
    }
    return true;
}

bool ImageFormatConvertUtils::NV12ToRGBA(const uint8_t *data, const YUVDataInfo &yDInfo, uint8_t **destBuffer,
                                         size_t &destBufferSize, [[maybe_unused]]ColorSpace colorSpace)
{
    if (data == nullptr || destBuffer == nullptr) {
        IMAGE_LOGE("Input buffer pointer data or destBuffer is null!");
        return false;
    }

    destBufferSize = static_cast<size_t>(yDInfo.yWidth * yDInfo.yHeight * BYTES_PER_PIXEL_RGBA);
    if (destBufferSize == 0 || destBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size is 0!");
        return false;
    }

    *destBuffer = new(std::nothrow) uint8_t[destBufferSize]();
    if (*destBuffer == nullptr) {
        IMAGE_LOGE("Dynamically allocating memory for destination buffer failed!");
        return false;
    }

    bool bRet = NV12ToRGBASoftDecode(data, yDInfo, destBuffer);
    if (!bRet) {
        IMAGE_LOGE("NV12ToRGBA failed!");
        delete[] (*destBuffer);
        *destBuffer = nullptr;
        return false;
    }
    return true;
}

bool ImageFormatConvertUtils::NV12ToBGRA(const uint8_t *data, const YUVDataInfo &yDInfo, uint8_t **destBuffer,
                                         size_t &destBufferSize, [[maybe_unused]]ColorSpace colorSpace)
{
    if (data == nullptr || destBuffer == nullptr) {
        IMAGE_LOGE("Input buffer pointer data or destBuffer is null!");
        return false;
    }

    destBufferSize = static_cast<size_t>(yDInfo.yWidth * yDInfo.yHeight * BYTES_PER_PIXEL_BGRA);
    if (destBufferSize == 0 || destBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size is 0!");
        return false;
    }

    *destBuffer = new(std::nothrow) uint8_t[destBufferSize]();
    if (*destBuffer == nullptr) {
        IMAGE_LOGE("Dynamically allocating memory for destination buffer failed!");
        return false;
    }

    bool bRet = NV12ToBGRASoftDecode(data, yDInfo, destBuffer);
    if (!bRet) {
        IMAGE_LOGE("NV12ToBGRA failed!");
        delete[] (*destBuffer);
        *destBuffer = nullptr;
        return false;
    }
    return true;
}

bool ImageFormatConvertUtils::RGBAF16ToNV12(const uint8_t *srcBuffer, const Size &imageSize, uint8_t **destBuffer,
                                            size_t &destBufferSize, [[maybe_unused]]ColorSpace colorSpace)
{
    if (srcBuffer == nullptr || destBuffer == nullptr || imageSize.width < 0 || imageSize.height < 0) {
        return false;
    }
    uint32_t frameSize = imageSize.width * imageSize.height;
    destBufferSize = frameSize +
        (((imageSize.width + 1) / TWO_SLICES * (imageSize.height + 1) / TWO_SLICES) * TWO_SLICES);
    if (destBufferSize == 0 || destBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size calculation!");
        return false;
    }
    *destBuffer = new(std::nothrow) uint8_t[destBufferSize]();
    if (*destBuffer == nullptr) {
        IMAGE_LOGE("apply space for dest buffer failed!");
        return false;
    }

    AVPixelFormat srcFormat = findPixelFormat(PixelFormat::RGBA_F16);
    AVPixelFormat dstFormat = findPixelFormat(PixelFormat::NV12);
    SwsContext *swsContext = sws_getContext(imageSize.width, imageSize.height, srcFormat, imageSize.width,
        imageSize.height, dstFormat, SWS_BILINEAR, nullptr, nullptr, nullptr);
    if (swsContext == nullptr) {
        IMAGE_LOGE("Error to create SwsContext.");
        delete[] destBuffer;
        return false;
    }

    int widthEven = (imageSize.width % EVEN_ODD_DIVISOR == 0) ? (imageSize.width) : (imageSize.width + 1);
    const uint8_t *srcSlice[] = {srcBuffer};
    const int srcStride[] = {static_cast<int>(imageSize.width * STRIDES_PER_PLANE)};
    uint8_t *dstSlice[] = {*destBuffer, *destBuffer + imageSize.width * imageSize.height};
    const int dstStride[] = {static_cast<int>(imageSize.width), static_cast<int>(widthEven)};
    int height = sws_scale(swsContext, srcSlice, srcStride, SRCSLICEY, imageSize.height, dstSlice, dstStride);
    sws_freeContext(swsContext);
    if (height == 0) {
        IMAGE_LOGE("RGBAF16ToNV12 format conversion failed");
        delete[] destBuffer;
        return false;
    }
    return true;
}

static bool RGBAToP010SoftDecode(const uint8_t *srcBuffer, const Size &imageSize, uint8_t **destBuffer,
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

bool ImageFormatConvertUtils::RGB565ToNV12P010(const uint8_t *srcBuffer, const Size &imageSize, uint8_t **destBuffer,
                                               size_t &destBufferSize, [[maybe_unused]]ColorSpace colorSpace)
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

bool ImageFormatConvertUtils::RGB565ToNV21P010(const uint8_t *srcBuffer, const Size &imageSize, uint8_t **destBuffer,
                                               size_t &destBufferSize, [[maybe_unused]]ColorSpace colorSpace)
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

bool ImageFormatConvertUtils::RGBAToNV12P010(const uint8_t *srcBuffer, const Size &imageSize, uint8_t **destBuffer,
                                             size_t &destBufferSize, [[maybe_unused]]ColorSpace colorSpace)
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

bool ImageFormatConvertUtils::RGBAToNV21P010(const uint8_t *srcBuffer, const Size &imageSize, uint8_t **destBuffer,
                                             size_t &destBufferSize, [[maybe_unused]]ColorSpace colorSpace)
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

bool ImageFormatConvertUtils::BGRAToNV12P010(const uint8_t *srcBuffer, const Size &imageSize, uint8_t **destBuffer,
                                             size_t &destBufferSize, [[maybe_unused]]ColorSpace colorSpace)
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

bool ImageFormatConvertUtils::BGRAToNV21P010(const uint8_t *srcBuffer, const Size &imageSize, uint8_t **destBuffer,
                                             size_t &destBufferSize, [[maybe_unused]]ColorSpace colorSpace)
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

bool ImageFormatConvertUtils::RGBToNV12P010(const uint8_t *srcBuffer, const Size &imageSize, uint8_t **destBuffer,
                                            size_t &destBufferSize, [[maybe_unused]]ColorSpace colorSpace)
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

bool ImageFormatConvertUtils::RGBToNV21P010(const uint8_t *srcBuffer, const Size &imageSize, uint8_t **destBuffer,
                                            size_t &destBufferSize, [[maybe_unused]]ColorSpace colorSpace)
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

bool ImageFormatConvertUtils::RGBAF16ToNV12P010(const uint8_t *srcBuffer, const Size &imageSize, uint8_t **destBuffer,
                                                size_t &destBufferSize, [[maybe_unused]]ColorSpace colorSpace)
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

bool ImageFormatConvertUtils::RGBAF16ToNV21P010(const uint8_t *srcBuffer, const Size &imageSize, uint8_t **destBuffer,
                                                size_t &destBufferSize, [[maybe_unused]]ColorSpace colorSpace)
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

static bool RGBA1010102ToNV12SoftDecode(const uint8_t *srcBuffer, const Size &imageSize, uint8_t **destBuffer)
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

bool ImageFormatConvertUtils::RGBA1010102ToNV12(const uint8_t *srcBuffer, const Size &imageSize, uint8_t **destBuffer,
                                                size_t &destBufferSize, [[maybe_unused]]ColorSpace colorSpace)
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

static bool RGBA1010102ToNV21SoftDecode(const uint8_t *srcBuffer, const Size &imageSize, uint8_t **destBuffer)
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

bool ImageFormatConvertUtils::RGBA1010102ToNV21(const uint8_t *srcBuffer, const Size &imageSize, uint8_t **destBuffer,
                                                size_t &destBufferSize, [[maybe_unused]]ColorSpace colorSpace)
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

static bool RGBA1010102ToP010SoftDecode(const uint8_t *srcBuffer, const Size &imageSize, uint8_t **destBuffer)
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

bool ImageFormatConvertUtils::RGBA1010102ToNV12P010(const uint8_t *srcBuffer, const Size &imageSize,
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

bool ImageFormatConvertUtils::RGBA1010102ToNV21P010(const uint8_t *srcBuffer, const Size &imageSize,
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

bool ImageFormatConvertUtils::RGBAToNV12(const uint8_t *srcBuffer, const Size &imageSize, uint8_t **destBuffer,
                                         size_t &destBufferSize, [[maybe_unused]]ColorSpace colorSpace)
{
    if (srcBuffer == nullptr || destBuffer == nullptr || imageSize.width < 0 || imageSize.height < 0) {
        return false;
    }
    size_t destPlaneSizeY = imageSize.width * imageSize.height;
    size_t destPlaneSizeUV = ((imageSize.width + 1) / TWO_SLICES) * ((imageSize.height + 1) / TWO_SLICES);
    destBufferSize = destPlaneSizeY + destPlaneSizeUV * TWO_SLICES;
    if (destBufferSize == 0 || destBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size calculation!");
        return false;
    }
    *destBuffer = new(std::nothrow) uint8_t[destBufferSize]();
    if (*destBuffer == nullptr) {
        IMAGE_LOGE("apply space for dest buffer failed!");
        return false;
    }
    bool bRet = RGBAToNV12SoftDecode(srcBuffer, imageSize, destBuffer);
    if (!bRet) {
        IMAGE_LOGE("RGBAToNV12 failed!");
        delete[] (*destBuffer);
        *destBuffer = nullptr;
        return false;
    }
    return true;
}

bool ImageFormatConvertUtils::RGBAToNV21(const uint8_t *srcBuffer, const Size &imageSize, uint8_t **destBuffer,
                                         size_t &destBufferSize, [[maybe_unused]]ColorSpace colorSpace)
{
    if (srcBuffer == nullptr || destBuffer == nullptr || imageSize.width < 0 || imageSize.height < 0) {
        return false;
    }
    size_t destPlaneSizeY = imageSize.width * imageSize.height;
    size_t destPlaneSizeVU = ((imageSize.width + 1) / TWO_SLICES) * ((imageSize.height + 1) / TWO_SLICES);
    destBufferSize = static_cast<size_t>(destPlaneSizeY + destPlaneSizeVU * TWO_SLICES);
    if (destBufferSize == 0 || destBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size calculation!");
        return false;
    }
    *destBuffer = new(std::nothrow) uint8_t[destBufferSize]();
    if (*destBuffer == nullptr) {
        IMAGE_LOGE("apply space for dest buffer failed!");
        return false;
    }

    bool bRet = RGBAToNV21SoftDecode(srcBuffer, imageSize, destBuffer);
    if (!bRet) {
        IMAGE_LOGE("RGBAToNV21 failed!");
        delete[] (*destBuffer);
        *destBuffer = nullptr;
        return false;
    }
    return true;
}

bool ImageFormatConvertUtils::RGBToNV21(const uint8_t *srcBuffer, const Size &imageSize, uint8_t **destBuffer,
                                        size_t &destBufferSize, [[maybe_unused]]ColorSpace colorSpace)
{
    if (srcBuffer == nullptr || destBuffer == nullptr || imageSize.width < 0 || imageSize.height < 0) {
        return false;
    }
    destBufferSize = static_cast<size_t>
        (imageSize.width * imageSize.height + ((imageSize.width + 1) / TWO_SLICES *
        ((imageSize.height + 1) / TWO_SLICES) * TWO_SLICES));
    if (destBufferSize == 0 || destBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size calculation!");
        return false;
    }
    *destBuffer = new(std::nothrow) uint8_t[destBufferSize]();
    if (*destBuffer == nullptr) {
        IMAGE_LOGE("apply space for dest buffer failed!");
        return false;
    }
    bool bRet = RGBToNV21SoftDecode(srcBuffer, imageSize, destBuffer);
    if (!bRet) {
        IMAGE_LOGE("RGBToNV21 failed!");
        delete[] (*destBuffer);
        *destBuffer = nullptr;
        return false;
    }
    return true;
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

bool ImageFormatConvertUtils::NV12ToRGB(const uint8_t *data, const YUVDataInfo &yDInfo, uint8_t **destBuffer,
                                        size_t &destBufferSize, [[maybe_unused]]ColorSpace colorSpace)
{
    if (data == nullptr || destBuffer == nullptr) {
        IMAGE_LOGE("Input buffer pointer data or destBuffer is null!");
        return false;
    }

    destBufferSize = static_cast<size_t>(yDInfo.yWidth * yDInfo.yHeight * BYTES_PER_PIXEL_RGB);
    if (destBufferSize == 0 || destBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size is 0!");
        return false;
    }

    (*destBuffer) = new(std::nothrow) uint8_t[destBufferSize]();
    if (*destBuffer == nullptr) {
        IMAGE_LOGE("Dynamically allocating memory for destination buffer failed!");
        return false;
    }

    bool bRet = NV12ToRGBManual(data, yDInfo, destBuffer);
    if (!bRet) {
        IMAGE_LOGE("NV12ToRGB failed!");
        delete[] (*destBuffer);
        *destBuffer = nullptr;
        return false;
    }

    return true;
}

bool ImageFormatConvertUtils::NV21ToRGB(const uint8_t *data, const YUVDataInfo &yDInfo, uint8_t **destBuffer,
                                        size_t &destBufferSize, [[maybe_unused]]ColorSpace colorSpace)
{
    if (data == nullptr || destBuffer == nullptr || yDInfo.yWidth == 0 || yDInfo.yHeight == 0 ||
        yDInfo.uvWidth == 0 || yDInfo.uvHeight == 0) {
        return false;
    }

    destBufferSize = static_cast<size_t>(yDInfo.yWidth * yDInfo.yHeight * BYTES_PER_PIXEL_RGB);
    if (destBufferSize == 0 || destBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size is 0!");
        return false;
    }
    *destBuffer = new(std::nothrow) uint8_t[destBufferSize]();
    if (*destBuffer == nullptr) {
        IMAGE_LOGE("apply space for dest buffer failed!");
        return false;
    }

    AVPixelFormat srcFormat = findPixelFormat(PixelFormat::NV21);
    AVPixelFormat dstFormat = findPixelFormat(PixelFormat::RGB_888);
    SwsContext *swsContext = sws_getContext(yDInfo.yWidth, yDInfo.yHeight, srcFormat, yDInfo.yWidth,
                                             yDInfo.yHeight, dstFormat, SWS_BILINEAR, nullptr, nullptr, nullptr);
    if (swsContext == nullptr) {
        delete[] destBuffer;
        IMAGE_LOGE("Error to create SwsContext.");
        return false;
    }

    const uint8_t *srcSlice[] = { data + yDInfo.yOffset, data + yDInfo.uvOffset };
    const int srcStride[] = { static_cast<int>(yDInfo.yStride), static_cast<int>(yDInfo.uvStride) };
    const int dstStride[] = {static_cast<int>(yDInfo.yWidth * BYTES_PER_PIXEL_RGB)};
    int height = sws_scale(swsContext, srcSlice, srcStride, SRCSLICEY, yDInfo.yHeight, destBuffer, dstStride);
    sws_freeContext(swsContext);
    if (height == 0) {
        IMAGE_LOGE("Image pixel format conversion failed");
        delete[] destBuffer;
        return false;
    }
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

bool ImageFormatConvertUtils::NV21ToRGBA(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo, uint8_t **destBuffer,
                                         size_t &destBufferSize, ColorSpace colorSpace)
{
    if (srcBuffer == nullptr || destBuffer == nullptr || yDInfo.yWidth == 0 || yDInfo.yHeight == 0 ||
        yDInfo.uvWidth == 0 || yDInfo.uvHeight == 0) {
        return false;
    }

    destBufferSize = static_cast<size_t>(yDInfo.yWidth * yDInfo.yHeight * BYTES_PER_PIXEL_RGBA);
    if (destBufferSize == 0 || destBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size is 0!");
        return false;
    }
    *destBuffer = new(std::nothrow) uint8_t[destBufferSize]();
    if (*destBuffer == nullptr) {
        IMAGE_LOGE("Apply space for dest buffer failed!");
        return false;
    }
    bool bRet = NV21ToRGBASoftDecode(srcBuffer, yDInfo, destBuffer);
    if (!bRet) {
        IMAGE_LOGE("NV21ToRGBA failed!");
        delete[] destBuffer;
        return bRet;
    }
    return true;
}

bool ImageFormatConvertUtils::NV21ToBGRA(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo, uint8_t **destBuffer,
                                         size_t &destBufferSize, [[maybe_unused]]ColorSpace colorSpace)
{
    if (srcBuffer == nullptr || destBuffer == nullptr || yDInfo.yWidth == 0 || yDInfo.yHeight == 0 ||
        yDInfo.uvWidth == 0 || yDInfo.uvHeight == 0) {
        return false;
    }

    destBufferSize = static_cast<size_t>(yDInfo.yWidth * yDInfo.yHeight * BYTES_PER_PIXEL_BGRA);
    if (destBufferSize == 0 || destBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size is 0!");
        return false;
    }
    *destBuffer = new(std::nothrow) uint8_t[destBufferSize]();
    if (*destBuffer == nullptr) {
        IMAGE_LOGE("apply space for dest buffer failed!");
        return false;
    }

    bool bRet = NV21ToBGRASoftDecode(srcBuffer, yDInfo, destBuffer);
    if (!bRet) {
        IMAGE_LOGE("NV21ToBGRA failed!");
        delete[] destBuffer;
        return bRet;
    }
    return true;
}

bool ImageFormatConvertUtils::NV21ToRGB565(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo, uint8_t **destBuffer,
                                           size_t &destBufferSize, ColorSpace colorSpace)
{
    if (srcBuffer == nullptr || destBuffer == nullptr || yDInfo.yWidth == 0 || yDInfo.yHeight == 0 ||
        yDInfo.uvWidth == 0 || yDInfo.uvHeight == 0) {
        return false;
    }

    destBufferSize = static_cast<size_t>(yDInfo.yWidth * yDInfo.yHeight * BYTES_PER_PIXEL_RGB565);
    if (destBufferSize == 0 || destBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size is 0!");
        return false;
    }
    *destBuffer = new(std::nothrow) uint8_t[destBufferSize]();
    if (*destBuffer == nullptr) {
        IMAGE_LOGE("apply space for dest buffer failed!");
        return false;
    }

    bool bRet = NV21ToRGB565SoftDecode(srcBuffer, yDInfo, destBuffer);
    if (!bRet) {
        IMAGE_LOGE("NV21ToRGB565 failed!");
        delete[] destBuffer;
        return bRet;
    }
    return true;
}

bool ImageFormatConvertUtils::RGBToNV12(const uint8_t *srcBuffer, const Size &imageSize, uint8_t **destBuffer,
                                        size_t &destBufferSize, [[maybe_unused]]ColorSpace colorSpace)
{
    if (srcBuffer == nullptr || destBuffer == nullptr || imageSize.width < 0 || imageSize.height < 0) {
        return false;
    }
    destBufferSize = static_cast<size_t>(imageSize.width * imageSize.height + (imageSize.width + 1) / TWO_SLICES *
        (imageSize.height + 1) / TWO_SLICES * TWO_SLICES);
    if (destBufferSize == 0 || destBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size calculation!");
        return false;
    }
    (*destBuffer) = new(std::nothrow) uint8_t[destBufferSize]();
    if (*destBuffer == nullptr) {
        IMAGE_LOGE("apply space for dest buffer failed!");
        return false;
    }
    bool bRet = RGBToNV12SoftDecode(srcBuffer, imageSize, destBuffer);
    if (!bRet) {
        IMAGE_LOGE("RGBToNV12 failed!");
        delete[] destBuffer;
        return bRet;
    }
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
} // namespace Media
} // namespace OHOS