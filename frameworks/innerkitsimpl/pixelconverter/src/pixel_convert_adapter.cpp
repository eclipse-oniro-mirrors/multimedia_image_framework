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

#include <map>
#include "include/core/SkBitmap.h"
#include "include/core/SkCanvas.h"
#include "include/core/SkColor.h"
#include "include/core/SkColorSpace.h"
#include "include/core/SkImageInfo.h"
#include "include/core/SkPaint.h"
#include "include/core/SkPixmap.h"
#include "pixel_convert_adapter.h"
#ifdef _WIN32
#include <iomanip>
#endif

namespace OHOS {
namespace Media {
using namespace OHOS::HiviewDFX;
using namespace std;

static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_TAG_DOMAIN_ID_IMAGE, "PixelConvertAdapter" };
static const uint8_t NUM_0 = 0;
static const uint8_t NUM_1 = 1;
static const uint8_t NUM_2 = 2;
static const uint8_t NUM_3 = 3;
static const uint8_t NUM_4 = 4;

static const map<PixelFormat, SkColorType> PIXEL_FORMAT_MAP = {
    { PixelFormat::UNKNOWN, SkColorType::kUnknown_SkColorType},
    { PixelFormat::ARGB_8888, SkColorType::kRGBA_8888_SkColorType},
    { PixelFormat::ALPHA_8, SkColorType::kAlpha_8_SkColorType},
    { PixelFormat::RGB_565, SkColorType::kRGB_565_SkColorType},
    { PixelFormat::RGBA_F16, SkColorType::kRGBA_F16_SkColorType},
    { PixelFormat::RGBA_8888, SkColorType::kRGBA_8888_SkColorType},
    { PixelFormat::BGRA_8888, SkColorType::kBGRA_8888_SkColorType},
    { PixelFormat::RGB_888, SkColorType::kRGB_888x_SkColorType},
};

static SkColorType PixelFormatConvert(const PixelFormat &pixelFormat)
{
    auto formatSearch = PIXEL_FORMAT_MAP.find(pixelFormat);
    return (formatSearch != PIXEL_FORMAT_MAP.end()) ? formatSearch->second : SkColorType::kUnknown_SkColorType;
}

static void ARGBToRGBA(uint8_t* srcPixels, uint8_t* dstPixels, uint32_t byteCount)
{
    if (byteCount % NUM_4 != NUM_0) {
        HiLog::Error(LABEL, "Pixel count must multiple of 4.");
        return;
    }
    uint8_t *src = srcPixels;
    uint8_t *dst = dstPixels;
    for (uint32_t i = NUM_0 ; i < byteCount; i += NUM_4) {
        // 0-R 1-G 2-B 3-A
        dst[NUM_0] = src[NUM_1];
        dst[NUM_1] = src[NUM_2];
        dst[NUM_2] = src[NUM_3];
        dst[NUM_3] = src[NUM_0];
        src += NUM_4;
        dst += NUM_4;
    }
}

static void RGBAToARGB(uint8_t* srcPixels, uint8_t* dstPixels, uint32_t byteCount)
{
    if (byteCount % NUM_4 != NUM_0) {
        HiLog::Error(LABEL, "Pixel count must multiple of 4.");
        return;
    }
    uint8_t *src = srcPixels;
    uint8_t *dst = dstPixels;
    for (uint32_t i = NUM_0 ; i < byteCount; i += NUM_4) {
        // 0-A 1-R 2-G 3-B
        dst[NUM_0] = src[NUM_3];
        dst[NUM_1] = src[NUM_0];
        dst[NUM_2] = src[NUM_1];
        dst[NUM_3] = src[NUM_2];
        src += NUM_4;
        dst += NUM_4;
    }
}

static void RGBxToRGB(const uint8_t* srcPixels, uint8_t* dstPixels, uint32_t byteCount)
{
    if (byteCount % NUM_4 != NUM_0) {
        HiLog::Error(LABEL, "Pixel count must multiple of 4.");
        return;
    }
    const uint8_t *src = srcPixels;
    uint8_t *dst = dstPixels;
    for (uint32_t i = NUM_0 ; i < byteCount; i += NUM_4) {
        // 0-R 1-G 2-B
        dst[NUM_0] = src[NUM_0];
        dst[NUM_1] = src[NUM_1];
        dst[NUM_2] = src[NUM_2];
        src += NUM_4;
        dst += NUM_3;
    }
}

static void RGBToRGBx(const uint8_t* srcPixels, uint8_t* dstPixels, uint32_t byteCount)
{
    if (byteCount % NUM_3 != NUM_0) {
        HiLog::Error(LABEL, "Pixel count must multiple of 3.");
        return;
    }
    const uint8_t *src = srcPixels;
    uint8_t *dst = dstPixels;
    for (uint32_t i = NUM_0 ; i < byteCount; i += NUM_3) {
        // 0-R 1-G 2-B
        dst[NUM_0] = src[NUM_0];
        dst[NUM_1] = src[NUM_1];
        dst[NUM_2] = src[NUM_2];
        dst[NUM_3] = 0;
        src += NUM_3;
        dst += NUM_4;
    }
}

static int32_t GetRGBxRowBytes(const ImageInfo &imgInfo)
{
    return imgInfo.size.width * NUM_4;
}

static int32_t GetRGBxSize(const ImageInfo &imgInfo)
{
    return imgInfo.size.height * GetRGBxRowBytes(imgInfo);
}

bool PixelConvertAdapter::WritePixelsConvert(const void *srcPixels, uint32_t srcRowBytes, const ImageInfo &srcInfo,
                                             void *dstPixels, const Position &dstPos, uint32_t dstRowBytes,
                                             const ImageInfo &dstInfo)
{
    // basic valid check, other parameters valid check in writePixels method
    if (srcPixels == nullptr || dstPixels == nullptr) {
        HiLog::Error(LABEL, "src or dst pixels invalid.");
        return false;
    }

    SkAlphaType srcAlphaType = static_cast<SkAlphaType>(srcInfo.alphaType);
    SkAlphaType dstAlphaType = static_cast<SkAlphaType>(dstInfo.alphaType);
    SkColorType srcColorType = PixelFormatConvert(srcInfo.pixelFormat);
    SkColorType dstColorType = PixelFormatConvert(dstInfo.pixelFormat);
    SkImageInfo srcImageInfo = SkImageInfo::Make(srcInfo.size.width, srcInfo.size.height, srcColorType, srcAlphaType);
    SkImageInfo dstImageInfo = SkImageInfo::Make(dstInfo.size.width, dstInfo.size.height, dstColorType, dstAlphaType);

    int32_t dstRGBxSize = (dstInfo.pixelFormat == PixelFormat::RGB_888) ? GetRGBxSize(dstInfo) : NUM_1;
    auto dstRGBxPixels = std::make_unique<uint8_t[]>(dstRGBxSize);
    auto keepDstPixels = dstPixels;
    dstPixels = (dstInfo.pixelFormat == PixelFormat::RGB_888) ? &dstRGBxPixels[0] : dstPixels;
    dstRowBytes = (dstInfo.pixelFormat == PixelFormat::RGB_888) ? GetRGBxRowBytes(dstInfo) : dstRowBytes;

    int32_t srcRGBxSize = (srcInfo.pixelFormat == PixelFormat::RGB_888) ? GetRGBxSize(srcInfo) : NUM_1;
    auto srcRGBxPixels = std::make_unique<uint8_t[]>(srcRGBxSize);
    if (srcInfo.pixelFormat == PixelFormat::RGB_888) {
        RGBToRGBx(static_cast<const uint8_t*>(srcPixels), &srcRGBxPixels[0], srcRowBytes * srcInfo.size.height);
        srcPixels = &srcRGBxPixels[0];
        srcRowBytes = GetRGBxRowBytes(srcInfo);
    }
    SkPixmap srcPixmap(srcImageInfo, srcPixels, srcRowBytes);
    if (srcInfo.pixelFormat == PixelFormat::ARGB_8888) {
        uint8_t* src = static_cast<uint8_t*>(srcPixmap.writable_addr());
        ARGBToRGBA(src, src, srcRowBytes * srcInfo.size.height);
    }

    SkBitmap dstBitmap;
    if (!dstBitmap.installPixels(dstImageInfo, dstPixels, dstRowBytes)) {
        HiLog::Error(LABEL, "WritePixelsConvert dst bitmap install pixels failed.");
        return false;
    }
    if (!dstBitmap.writePixels(srcPixmap, dstPos.x, dstPos.y)) {
        HiLog::Error(LABEL, "WritePixelsConvert dst bitmap write pixels by source failed.");
        return false;
    }

    if (dstInfo.pixelFormat == PixelFormat::ARGB_8888) {
        uint32_t dstSize = dstRowBytes * dstInfo.size.height;
        RGBAToARGB(static_cast<uint8_t*>(dstPixels), static_cast<uint8_t*>(dstPixels), dstSize);
    } else if (dstInfo.pixelFormat == PixelFormat::RGB_888) {
        RGBxToRGB(&dstRGBxPixels[0], static_cast<uint8_t*>(keepDstPixels), dstRGBxSize);
    }

    return true;
}

bool PixelConvertAdapter::ReadPixelsConvert(const void *srcPixels, const Position &srcPos, uint32_t srcRowBytes,
                                            const ImageInfo &srcInfo, void *dstPixels, uint32_t dstRowBytes,
                                            const ImageInfo &dstInfo)
{
    // basic valid check, other parameters valid check in readPixels method
    if (srcPixels == nullptr || dstPixels == nullptr) {
        HiLog::Error(LABEL, "src or dst pixels invalid.");
        return false;
    }
    SkAlphaType srcAlphaType = static_cast<SkAlphaType>(srcInfo.alphaType);
    SkAlphaType dstAlphaType = static_cast<SkAlphaType>(dstInfo.alphaType);
    SkColorType srcColorType = PixelFormatConvert(srcInfo.pixelFormat);
    SkColorType dstColorType = PixelFormatConvert(dstInfo.pixelFormat);
    SkImageInfo srcImageInfo = SkImageInfo::Make(srcInfo.size.width, srcInfo.size.height, srcColorType, srcAlphaType);
    SkImageInfo dstImageInfo = SkImageInfo::Make(dstInfo.size.width, dstInfo.size.height, dstColorType, dstAlphaType);

    SkBitmap srcBitmap;
    if (!srcBitmap.installPixels(srcImageInfo, const_cast<void *>(srcPixels), srcRowBytes)) {
        HiLog::Error(LABEL, "ReadPixelsConvert src bitmap install pixels failed.");
        return false;
    }
    if (!srcBitmap.readPixels(dstImageInfo, dstPixels, dstRowBytes, srcPos.x, srcPos.y)) {
        HiLog::Error(LABEL, "ReadPixelsConvert read dst pixels from source failed.");
        return false;
    }
    return true;
}

bool PixelConvertAdapter::EraseBitmap(const void *srcPixels, uint32_t srcRowBytes, const ImageInfo &srcInfo,
                                      uint32_t color)
{
    if (srcPixels == nullptr) {
        HiLog::Error(LABEL, "srcPixels is null.");
        return false;
    }
    SkAlphaType srcAlphaType = static_cast<SkAlphaType>(srcInfo.alphaType);
    SkColorType srcColorType = PixelFormatConvert(srcInfo.pixelFormat);
    SkImageInfo srcImageInfo = SkImageInfo::Make(srcInfo.size.width, srcInfo.size.height, srcColorType, srcAlphaType);
    SkBitmap srcBitmap;
    if (!srcBitmap.installPixels(srcImageInfo, const_cast<void *>(srcPixels), srcRowBytes)) {
        HiLog::Error(LABEL, "ReadPixelsConvert src bitmap install pixels failed.");
        return false;
    }
    const SkColor4f skColor = SkColor4f::FromColor(color);
    SkPaint paint;
    paint.setColor4f(skColor, SkColorSpace::MakeSRGB().get());
    paint.setBlendMode(SkBlendMode::kSrc);
    SkCanvas canvas(srcBitmap);
    canvas.drawPaint(paint);
    return true;
}
} // namespace Media
} // namespace OHOS
