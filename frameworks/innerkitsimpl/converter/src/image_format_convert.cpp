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

#include "image_format_convert.h"

#include <map>
#include <memory>
#include "hilog/log.h"
#include "image_format_convert_ext_utils.h"
#include "image_log.h"
#include "image_source.h"
#include "log_tags.h"
#include "media_errors.h"
#include "pixel_yuv.h"

namespace {
    constexpr uint8_t NUM_0 = 0;
    constexpr uint8_t NUM_1 = 1;
    constexpr uint8_t NUM_2 = 2;
    constexpr uint8_t NUM_3 = 3;
    constexpr uint8_t NUM_4 = 4;
    constexpr uint8_t NUM_8 = 8;
}

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "ImageFormatConvert"

namespace OHOS {
namespace Media {

static const std::map<std::pair<PixelFormat, PixelFormat>, ConvertFunction> g_cvtFuncMap = []() {
#ifndef EXT_PIXEL
    static const std::map<std::pair<PixelFormat, PixelFormat>, ConvertFunction> cvtFuncMap = {
        {std::make_pair(PixelFormat::RGB_565, PixelFormat::NV21), ImageFormatConvertUtils::RGB565ToNV21},
        {std::make_pair(PixelFormat::RGB_565, PixelFormat::NV12), ImageFormatConvertUtils::RGB565ToNV12},
        {std::make_pair(PixelFormat::RGBA_8888, PixelFormat::NV21), ImageFormatConvertUtils::RGBAToNV21},
        {std::make_pair(PixelFormat::RGBA_8888, PixelFormat::NV12), ImageFormatConvertUtils::RGBAToNV12},
        {std::make_pair(PixelFormat::BGRA_8888, PixelFormat::NV21), ImageFormatConvertUtils::BGRAToNV21},
        {std::make_pair(PixelFormat::BGRA_8888, PixelFormat::NV12), ImageFormatConvertUtils::BGRAToNV12},
        {std::make_pair(PixelFormat::RGB_888, PixelFormat::NV21), ImageFormatConvertUtils::RGBToNV21},
        {std::make_pair(PixelFormat::RGB_888, PixelFormat::NV12), ImageFormatConvertUtils::RGBToNV12},
        {std::make_pair(PixelFormat::RGBA_F16, PixelFormat::NV21), ImageFormatConvertUtils::RGBAF16ToNV21},
        {std::make_pair(PixelFormat::RGBA_F16, PixelFormat::NV12), ImageFormatConvertUtils::RGBAF16ToNV12},
    };
#else
    static const std::map<std::pair<PixelFormat, PixelFormat>, ConvertFunction> cvtFuncMap = {
        {std::make_pair(PixelFormat::RGB_565, PixelFormat::NV21), ImageFormatConvertExtUtils::RGB565ToNV21},
        {std::make_pair(PixelFormat::RGB_565, PixelFormat::NV12), ImageFormatConvertExtUtils::RGB565ToNV12},
        {std::make_pair(PixelFormat::RGBA_8888, PixelFormat::NV21), ImageFormatConvertExtUtils::RGBAToNV21},
        {std::make_pair(PixelFormat::RGBA_8888, PixelFormat::NV12), ImageFormatConvertExtUtils::RGBAToNV12},
        {std::make_pair(PixelFormat::BGRA_8888, PixelFormat::NV21), ImageFormatConvertExtUtils::BGRAToNV21},
        {std::make_pair(PixelFormat::BGRA_8888, PixelFormat::NV12), ImageFormatConvertExtUtils::BGRAToNV12},
        {std::make_pair(PixelFormat::RGB_888, PixelFormat::NV21), ImageFormatConvertExtUtils::RGBToNV21},
        {std::make_pair(PixelFormat::RGB_888, PixelFormat::NV12), ImageFormatConvertExtUtils::RGBToNV12},
        {std::make_pair(PixelFormat::RGBA_F16, PixelFormat::NV21), ImageFormatConvertUtils::RGBAF16ToNV21},
        {std::make_pair(PixelFormat::RGBA_F16, PixelFormat::NV12), ImageFormatConvertUtils::RGBAF16ToNV12},
    };
#endif
    return cvtFuncMap;
}();

static const std::map<std::pair<PixelFormat, PixelFormat>, YUVConvertFunction> g_yuvCvtFuncMap = []() {
#ifndef EXT_PIXEL
    std::map<std::pair<PixelFormat, PixelFormat>, YUVConvertFunction> yuvCvtFuncMap = {
        {std::make_pair(PixelFormat::NV12, PixelFormat::NV21), ImageFormatConvertUtils::NV12ToNV21},
        {std::make_pair(PixelFormat::NV12, PixelFormat::RGB_888), ImageFormatConvertUtils::NV12ToRGB},
        {std::make_pair(PixelFormat::NV12, PixelFormat::RGB_565), ImageFormatConvertUtils::NV12ToRGB565},
        {std::make_pair(PixelFormat::NV12, PixelFormat::RGBA_F16), ImageFormatConvertUtils::NV12ToRGBAF16},
        {std::make_pair(PixelFormat::NV12, PixelFormat::RGBA_8888), ImageFormatConvertUtils::NV12ToRGBA},
        {std::make_pair(PixelFormat::NV12, PixelFormat::BGRA_8888), ImageFormatConvertUtils::NV12ToBGRA},
        {std::make_pair(PixelFormat::NV21, PixelFormat::NV12), ImageFormatConvertUtils::NV21ToNV12},
        {std::make_pair(PixelFormat::NV21, PixelFormat::RGB_888), ImageFormatConvertUtils::NV21ToRGB},
        {std::make_pair(PixelFormat::NV21, PixelFormat::RGB_565), ImageFormatConvertUtils::NV21ToRGB565},
        {std::make_pair(PixelFormat::NV21, PixelFormat::RGBA_F16), ImageFormatConvertUtils::NV21ToRGBAF16},
        {std::make_pair(PixelFormat::NV21, PixelFormat::RGBA_8888), ImageFormatConvertUtils::NV21ToRGBA},
        {std::make_pair(PixelFormat::NV21, PixelFormat::BGRA_8888), ImageFormatConvertUtils::NV21ToBGRA},
    };
#else
    std::map<std::pair<PixelFormat, PixelFormat>, YUVConvertFunction> yuvCvtFuncMap = {
        {std::make_pair(PixelFormat::NV21, PixelFormat::RGB_888), ImageFormatConvertExtUtils::NV21ToRGB},
        {std::make_pair(PixelFormat::NV21, PixelFormat::RGBA_8888), ImageFormatConvertExtUtils::NV21ToRGBA},
        {std::make_pair(PixelFormat::NV21, PixelFormat::BGRA_8888), ImageFormatConvertExtUtils::NV21ToBGRA},
        {std::make_pair(PixelFormat::NV21, PixelFormat::RGB_565), ImageFormatConvertExtUtils::NV21ToRGB565},
        {std::make_pair(PixelFormat::NV12, PixelFormat::RGB_565), ImageFormatConvertExtUtils::NV12ToRGB565},
        {std::make_pair(PixelFormat::NV21, PixelFormat::NV12), ImageFormatConvertExtUtils::NV21ToNV12},
        {std::make_pair(PixelFormat::NV21, PixelFormat::RGBA_F16), ImageFormatConvertUtils::NV21ToRGBAF16},
        {std::make_pair(PixelFormat::NV12, PixelFormat::NV21), ImageFormatConvertExtUtils::NV12ToNV21},
        {std::make_pair(PixelFormat::NV12, PixelFormat::RGBA_F16), ImageFormatConvertUtils::NV12ToRGBAF16},
        {std::make_pair(PixelFormat::NV12, PixelFormat::RGBA_8888), ImageFormatConvertExtUtils::NV12ToRGBA},
        {std::make_pair(PixelFormat::NV12, PixelFormat::BGRA_8888), ImageFormatConvertExtUtils::NV12ToBGRA},
        {std::make_pair(PixelFormat::NV12, PixelFormat::RGB_888), ImageFormatConvertExtUtils::NV12ToRGB},
    };
#endif
    return yuvCvtFuncMap;
}();

uint32_t ImageFormatConvert::ConvertImageFormat(const ConvertDataInfo &srcDataInfo, ConvertDataInfo &destDataInfo)
{
    if (!CheckConvertDataInfo(srcDataInfo)) {
        IMAGE_LOGE("source convert data info is invalid");
        return ERR_IMAGE_INVALID_PARAMETER;
    }

    if (!IsSupport(destDataInfo.pixelFormat)) {
        IMAGE_LOGE("destination format is not support or invalid");
        return ERR_IMAGE_INVALID_PARAMETER;
    }

    ConvertFunction cvtFunc = GetConvertFuncByFormat(srcDataInfo.pixelFormat, destDataInfo.pixelFormat);
    if (cvtFunc == nullptr) {
        IMAGE_LOGE("get convert function by format failed!");
        return ERR_IMAGE_INVALID_PARAMETER;
    }

    if (!cvtFunc(srcDataInfo.buffer, srcDataInfo.imageSize, &destDataInfo.buffer,
                 destDataInfo.bufferSize, srcDataInfo.colorSpace)) {
        IMAGE_LOGE("format convert failed!");
        return IMAGE_RESULT_FORMAT_CONVERT_FAILED;
    }
    destDataInfo.imageSize = srcDataInfo.imageSize;
    destDataInfo.colorSpace = srcDataInfo.colorSpace;

    return SUCCESS;
}

uint32_t ImageFormatConvert::ConvertImageFormat(std::shared_ptr<PixelMap> &srcPiexlMap, PixelFormat destFormat)
{
    if (srcPiexlMap == nullptr) {
        IMAGE_LOGE("source pixel map is null");
        return ERR_IMAGE_INVALID_PARAMETER;
    }

    if (!IsSupport(destFormat)) {
        IMAGE_LOGE("destination format not support");
        return ERR_MEDIA_FORMAT_UNSUPPORT;
    }

    PixelFormat srcFormat = srcPiexlMap->GetPixelFormat();
    if ((srcFormat == PixelFormat::NV21) || (srcFormat == PixelFormat::NV12)) {
        uint32_t ret = YUVConvertImageFormatOption(srcPiexlMap, srcFormat, destFormat);
        if (ret != SUCCESS) {
            IMAGE_LOGE("convert yuv format failed!");
            return ret;
        }
        return SUCCESS;
    }

    ConvertFunction cvtFunc = GetConvertFuncByFormat(srcFormat, destFormat);
    if (cvtFunc == nullptr) {
        IMAGE_LOGE("get convert function by format failed!");
        return ERR_IMAGE_INVALID_PARAMETER;
    }

    const_uint8_buffer_type srcBuffer = srcPiexlMap->GetPixels();
    Size size = {srcPiexlMap->GetWidth(), srcPiexlMap->GetHeight()};
    uint8_buffer_type destBuffer = nullptr;
    size_t destBufferSize = 0;
    if (!cvtFunc(srcBuffer, size, &destBuffer, destBufferSize, srcPiexlMap->GetColorSpace())) {
        IMAGE_LOGE("format convert failed!");
        return IMAGE_RESULT_FORMAT_CONVERT_FAILED;
    }

    ImageInfo srcInfo;
    srcPiexlMap->GetImageInfo(srcInfo);
    ImageInfo destInfo;
    destInfo.alphaType = srcInfo.alphaType;
    destInfo.baseDensity = srcInfo.baseDensity;
    destInfo.colorSpace = srcInfo.colorSpace;
    destInfo.pixelFormat = destFormat;
    destInfo.size = srcInfo.size;
    if (!MakeDestPixelMap(srcPiexlMap, destBuffer, destBufferSize, destInfo, srcPiexlMap->GetAllocatorType())) {
        IMAGE_LOGE("create pixel map failed");
        return ERR_IMAGE_PIXELMAP_CREATE_FAILED;
    }
    return SUCCESS;
}

bool ImageFormatConvert::IsValidSize(const Size &size)
{
    return size.width > 0 && size.height > 0;
}

bool ImageFormatConvert::CheckConvertDataInfo(const ConvertDataInfo &convertDataInfo)
{
    if (convertDataInfo.buffer == nullptr) {
        IMAGE_LOGE("buffer is null");
        return false;
    }

    if (!IsSupport(convertDataInfo.pixelFormat)) {
        IMAGE_LOGE("format is not support or invalid");
        return false;
    }

    if (!IsValidSize(convertDataInfo.imageSize)) {
        IMAGE_LOGE("image size is invalid");
        return false;
    }

    if (GetBufferSizeByFormat(convertDataInfo.pixelFormat, convertDataInfo.imageSize) != convertDataInfo.bufferSize) {
        IMAGE_LOGE("buffer size is wrong");
        return false;
    }

    return true;
}

uint32_t ImageFormatConvert::YUVConvertImageFormatOption(std::shared_ptr<PixelMap> &srcPiexlMap,
                                                         const PixelFormat &srcFormat, PixelFormat destFormat)
{
    YUVConvertFunction yuvCvtFunc = YUVGetConvertFuncByFormat(srcFormat, destFormat);
    if (yuvCvtFunc == nullptr) {
        IMAGE_LOGE("get convert function by format failed!");
        return ERR_IMAGE_INVALID_PARAMETER;
    }

    const_uint8_buffer_type data = srcPiexlMap->GetPixels();
    YUVDataInfo yDInfo;
    srcPiexlMap->GetImageYUVInfo(yDInfo);
    ImageInfo srcInfo;
    srcPiexlMap->GetImageInfo(srcInfo);
    if (srcFormat == PixelFormat::NV21 && yDInfo.yWidth == 0) {
        IMAGE_LOGE("info is invalid");
        yDInfo.yWidth = static_cast<uint32_t>(srcInfo.size.width);
        yDInfo.yHeight = static_cast<uint32_t>(srcInfo.size.height);
        yDInfo.uvWidth = static_cast<uint32_t>((srcInfo.size.width + 1) / NUM_2);
        yDInfo.uvHeight = static_cast<uint32_t>((srcInfo.size.height + 1) / NUM_2);
    }
    uint8_buffer_type destBuffer = nullptr;
    size_t destBufferSize = 0;
    if (!yuvCvtFunc(data, yDInfo, &destBuffer, destBufferSize, srcPiexlMap->GetColorSpace())) {
        IMAGE_LOGE("format convert failed!");
        return IMAGE_RESULT_FORMAT_CONVERT_FAILED;
    }

    ImageInfo destInfo;
    destInfo.alphaType = srcInfo.alphaType;
    destInfo.baseDensity = srcInfo.baseDensity;
    destInfo.colorSpace = srcInfo.colorSpace;
    destInfo.pixelFormat = destFormat;
    destInfo.size = srcInfo.size;
    if (!MakeDestPixelMap(srcPiexlMap, destBuffer, destBufferSize, destInfo, srcPiexlMap->GetAllocatorType())) {
        IMAGE_LOGE("create pixel map failed");
        return ERR_IMAGE_PIXELMAP_CREATE_FAILED;
    }

    return SUCCESS;
}

size_t ImageFormatConvert::GetBufferSizeByFormat(PixelFormat format, const Size &size)
{
    switch (format) {
        case PixelFormat::RGB_565:{
            return size.width * size.height * NUM_2;
        }
        case PixelFormat::RGB_888:{
            return size.width * size.height * NUM_3;
        }
        case PixelFormat::ARGB_8888:
        case PixelFormat::RGBA_8888:
        case PixelFormat::BGRA_8888:{
            return size.width * size.height * NUM_4;
        }
        case PixelFormat::RGBA_F16:{
            return size.width * size.height * NUM_8;
        }
        case PixelFormat::NV21:
        case PixelFormat::NV12:{
            return size.width * size.height + ((size.width + NUM_1) / NUM_2) *
                ((size.height + NUM_1) / NUM_2) * NUM_2;
        }
        default:{
            return NUM_0;
        }
    }
}

ConvertFunction ImageFormatConvert::GetConvertFuncByFormat(PixelFormat srcFormat, PixelFormat destFormat)
{
    auto iter = g_cvtFuncMap.find(std::make_pair(srcFormat, destFormat));
    if (iter == g_cvtFuncMap.end()) {
        IMAGE_LOGE("current format is not supported or format is wrong");
        return nullptr;
    }
    return iter->second;
}

YUVConvertFunction ImageFormatConvert::YUVGetConvertFuncByFormat(PixelFormat srcFormat, PixelFormat destFormat)
{
    auto iter = g_yuvCvtFuncMap.find(std::make_pair(srcFormat, destFormat));
    if (iter == g_yuvCvtFuncMap.end()) {
        IMAGE_LOGE("current format is not supported or format is wrong");
        return nullptr;
    }
    return iter->second;
}

bool ImageFormatConvert::MakeDestPixelMap(std::shared_ptr<PixelMap> &destPixelMap, uint8_buffer_type destBuffer,
                                          const size_t destBufferSize, ImageInfo &info, AllocatorType allcatorType)
{
    std::unique_ptr<PixelMap> pixelMap;
    if (info.pixelFormat == PixelFormat::NV21 || info.pixelFormat == PixelFormat::NV12) {
        pixelMap = std::make_unique<PixelYuv>();
    } else {
        pixelMap = std::make_unique<PixelMap>();
    }
    if (pixelMap->SetImageInfo(info) != SUCCESS) {
        IMAGE_LOGE("set imageInfo failed");
        return false;
    }
    pixelMap->SetPixelsAddr(destBuffer, nullptr, destBufferSize, allcatorType, nullptr);
    destPixelMap = std::move(pixelMap);
    return true;
}

bool ImageFormatConvert::IsSupport(PixelFormat format)
{
    switch (format) {
        case PixelFormat::ARGB_8888:
        case PixelFormat::RGB_565:
        case PixelFormat::RGBA_8888:
        case PixelFormat::BGRA_8888:
        case PixelFormat::RGB_888:
        case PixelFormat::RGBA_F16:
        case PixelFormat::NV21:
        case PixelFormat::NV12:{
            return true;
        }
        default:{
            return false;
        }
    }
}
} // namespace Media
} // namespace OHOS