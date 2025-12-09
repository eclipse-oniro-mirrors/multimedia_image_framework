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
#ifdef EXT_PIXEL
#include "pixel_yuv_ext.h"
#endif

#include <map>
#include <memory>
#include "hilog/log.h"
#include "image_format_convert_ext_utils.h"
#include "image_log.h"
#include "image_trace.h"
#include "image_source.h"
#include "log_tags.h"
#include "media_errors.h"
#include "pixel_yuv.h"
#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
#include "v1_0/buffer_handle_meta_key_type.h"
#include "v1_0/cm_color_space.h"
#include "v2_1/cm_color_space.h"
#include "v1_0/hdr_static_metadata.h"
#include "surface_buffer.h"
#endif
#include "vpe_utils.h"
#include "image_utils.h"

namespace {
    constexpr uint8_t NUM_0 = 0;
    constexpr uint8_t NUM_1 = 1;
    constexpr uint8_t NUM_2 = 2;
    constexpr uint8_t NUM_3 = 3;
    constexpr uint8_t NUM_4 = 4;
    constexpr uint8_t NUM_8 = 8;
    constexpr uint8_t PLANE_Y = 0;
    constexpr uint8_t PLANE_U = 1;
    constexpr uint8_t PLANE_V = 2;
    constexpr uint32_t BYTES_PER_PIXEL_RGB565 = 2;
    constexpr uint32_t BYTES_PER_PIXEL_RGB = 3;
    constexpr uint32_t BYTES_PER_PIXEL_RGBA = 4;
    constexpr uint32_t BYTES_PER_PIXEL_BGRA = 4;
    constexpr uint32_t STRIDES_PER_PLANE = 8;
}

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "ImageFormatConvert"

namespace OHOS {
namespace Media {
#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
using namespace HDI::Display::Graphic::Common::V1_0;
using CM_ColorSpaceType_V2_1 = OHOS::HDI::Display::Graphic::Common::V2_1::CM_ColorSpaceType;
#endif

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
        {std::make_pair(PixelFormat::RGB_565, PixelFormat::YCBCR_P010), ImageFormatConvertUtils::RGB565ToNV12P010},
        {std::make_pair(PixelFormat::RGB_565, PixelFormat::YCRCB_P010), ImageFormatConvertUtils::RGB565ToNV21P010},
        {std::make_pair(PixelFormat::RGBA_8888, PixelFormat::YCBCR_P010), ImageFormatConvertUtils::RGBAToNV12P010},
        {std::make_pair(PixelFormat::RGBA_8888, PixelFormat::YCRCB_P010), ImageFormatConvertUtils::RGBAToNV21P010},
        {std::make_pair(PixelFormat::BGRA_8888, PixelFormat::YCBCR_P010), ImageFormatConvertUtils::BGRAToNV12P010},
        {std::make_pair(PixelFormat::BGRA_8888, PixelFormat::YCRCB_P010), ImageFormatConvertUtils::BGRAToNV21P010},
        {std::make_pair(PixelFormat::RGB_888, PixelFormat::YCBCR_P010), ImageFormatConvertUtils::RGBToNV12P010},
        {std::make_pair(PixelFormat::RGB_888, PixelFormat::YCRCB_P010), ImageFormatConvertUtils::RGBToNV21P010},
        {std::make_pair(PixelFormat::RGBA_F16, PixelFormat::YCBCR_P010), ImageFormatConvertUtils::RGBAF16ToNV12P010},
        {std::make_pair(PixelFormat::RGBA_F16, PixelFormat::YCRCB_P010), ImageFormatConvertUtils::RGBAF16ToNV21P010},
        {std::make_pair(PixelFormat::RGBA_1010102, PixelFormat::NV12), ImageFormatConvertUtils::RGBA1010102ToNV12},
        {std::make_pair(PixelFormat::RGBA_1010102, PixelFormat::NV21), ImageFormatConvertUtils::RGBA1010102ToNV21},
        {std::make_pair(PixelFormat::RGBA_1010102, PixelFormat::YCBCR_P010),
            ImageFormatConvertUtils::RGBA1010102ToNV12P010},
        {std::make_pair(PixelFormat::RGBA_1010102, PixelFormat::YCRCB_P010),
            ImageFormatConvertUtils::RGBA1010102ToNV21P010},
    };
#else
    static const std::map<std::pair<PixelFormat, PixelFormat>, ConvertFunction> cvtFuncMap = {
        {std::make_pair(PixelFormat::RGB_565, PixelFormat::NV21), ImageFormatConvertExtUtils::RGB565ToNV21},
        {std::make_pair(PixelFormat::RGB_565, PixelFormat::NV12), ImageFormatConvertExtUtils::RGB565ToNV12},
        {std::make_pair(PixelFormat::RGBA_8888, PixelFormat::NV21), ImageFormatConvertExtUtils::RGBAToNV21},
        {std::make_pair(PixelFormat::RGBA_8888, PixelFormat::NV12), ImageFormatConvertExtUtils::RGBAToNV12},
        {std::make_pair(PixelFormat::BGRA_8888, PixelFormat::NV21), ImageFormatConvertExtUtils::BGRAToNV21},
        {std::make_pair(PixelFormat::BGRA_8888, PixelFormat::NV12), ImageFormatConvertExtUtils::BGRAToNV12},
        {std::make_pair(PixelFormat::RGB_888, PixelFormat::NV21), ImageFormatConvertUtils::RGBToNV21},
        {std::make_pair(PixelFormat::RGB_888, PixelFormat::NV12), ImageFormatConvertUtils::RGBToNV12},
        {std::make_pair(PixelFormat::RGBA_F16, PixelFormat::NV21), ImageFormatConvertUtils::RGBAF16ToNV21},
        {std::make_pair(PixelFormat::RGBA_F16, PixelFormat::NV12), ImageFormatConvertUtils::RGBAF16ToNV12},
        {std::make_pair(PixelFormat::RGB_565, PixelFormat::YCBCR_P010), ImageFormatConvertExtUtils::RGB565ToNV12P010},
        {std::make_pair(PixelFormat::RGB_565, PixelFormat::YCRCB_P010), ImageFormatConvertExtUtils::RGB565ToNV21P010},
        {std::make_pair(PixelFormat::RGBA_8888, PixelFormat::YCBCR_P010), ImageFormatConvertExtUtils::RGBAToNV12P010},
        {std::make_pair(PixelFormat::RGBA_8888, PixelFormat::YCRCB_P010), ImageFormatConvertExtUtils::RGBAToNV21P010},
        {std::make_pair(PixelFormat::BGRA_8888, PixelFormat::YCBCR_P010), ImageFormatConvertExtUtils::BGRAToNV12P010},
        {std::make_pair(PixelFormat::BGRA_8888, PixelFormat::YCRCB_P010), ImageFormatConvertExtUtils::BGRAToNV21P010},
        {std::make_pair(PixelFormat::RGB_888, PixelFormat::YCBCR_P010), ImageFormatConvertExtUtils::RGBToNV12P010},
        {std::make_pair(PixelFormat::RGB_888, PixelFormat::YCRCB_P010), ImageFormatConvertExtUtils::RGBToNV21P010},
        {std::make_pair(PixelFormat::RGBA_1010102, PixelFormat::NV12), ImageFormatConvertExtUtils::RGBA1010102ToNV12},
        {std::make_pair(PixelFormat::RGBA_1010102, PixelFormat::NV21), ImageFormatConvertExtUtils::RGBA1010102ToNV21},
        {std::make_pair(PixelFormat::RGBA_1010102, PixelFormat::YCBCR_P010),
            ImageFormatConvertUtils::RGBA1010102ToNV12P010},
        {std::make_pair(PixelFormat::RGBA_1010102, PixelFormat::YCRCB_P010),
            ImageFormatConvertUtils::RGBA1010102ToNV21P010},
        {std::make_pair(PixelFormat::RGBA_F16, PixelFormat::YCBCR_P010), ImageFormatConvertUtils::RGBAF16ToNV12P010},
        {std::make_pair(PixelFormat::RGBA_F16, PixelFormat::YCRCB_P010), ImageFormatConvertUtils::RGBAF16ToNV21P010},
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
        {std::make_pair(PixelFormat::NV12, PixelFormat::YCBCR_P010), ImageFormatConvertUtils::NV12ToNV12P010},
        {std::make_pair(PixelFormat::NV12, PixelFormat::YCRCB_P010), ImageFormatConvertUtils::NV12ToNV21P010},
        {std::make_pair(PixelFormat::NV21, PixelFormat::YCBCR_P010), ImageFormatConvertUtils::NV21ToNV12P010},
        {std::make_pair(PixelFormat::NV21, PixelFormat::YCRCB_P010), ImageFormatConvertUtils::NV21ToNV21P010},
        {std::make_pair(PixelFormat::NV12, PixelFormat::RGBA_1010102), ImageFormatConvertUtils::NV12ToRGBA1010102},
        {std::make_pair(PixelFormat::NV21, PixelFormat::RGBA_1010102), ImageFormatConvertUtils::NV21ToRGBA1010102},
        {std::make_pair(PixelFormat::YCBCR_P010, PixelFormat::NV12), ImageFormatConvertUtils::NV12P010ToNV12},
        {std::make_pair(PixelFormat::YCBCR_P010, PixelFormat::NV21), ImageFormatConvertUtils::NV12P010ToNV21},
        {std::make_pair(PixelFormat::YCBCR_P010, PixelFormat::YCRCB_P010),
            ImageFormatConvertUtils::NV12P010ToNV21P010},
        {std::make_pair(PixelFormat::YCBCR_P010, PixelFormat::RGB_565), ImageFormatConvertUtils::NV12P010ToRGB565},
        {std::make_pair(PixelFormat::YCBCR_P010, PixelFormat::RGBA_8888), ImageFormatConvertUtils::NV12P010ToRGBA8888},
        {std::make_pair(PixelFormat::YCBCR_P010, PixelFormat::BGRA_8888), ImageFormatConvertUtils::NV12P010ToBGRA8888},
        {std::make_pair(PixelFormat::YCBCR_P010, PixelFormat::RGB_888), ImageFormatConvertUtils::NV12P010ToRGB888},
        {std::make_pair(PixelFormat::YCBCR_P010, PixelFormat::RGBA_F16), ImageFormatConvertUtils::NV12P010ToRGBAF16},
        {std::make_pair(PixelFormat::YCRCB_P010, PixelFormat::NV12), ImageFormatConvertUtils::NV21P010ToNV12},
        {std::make_pair(PixelFormat::YCRCB_P010, PixelFormat::NV21), ImageFormatConvertUtils::NV21P010ToNV21},
        {std::make_pair(PixelFormat::YCRCB_P010, PixelFormat::YCBCR_P010),
            ImageFormatConvertUtils::NV21P010ToNV12P010},
        {std::make_pair(PixelFormat::YCBCR_P010, PixelFormat::RGBA_1010102),
            ImageFormatConvertUtils::NV12P010ToRGBA1010102},
        {std::make_pair(PixelFormat::YCRCB_P010, PixelFormat::RGB_565), ImageFormatConvertUtils::NV21P010ToRGB565},
        {std::make_pair(PixelFormat::YCRCB_P010, PixelFormat::RGBA_8888), ImageFormatConvertUtils::NV21P010ToRGBA8888},
        {std::make_pair(PixelFormat::YCRCB_P010, PixelFormat::BGRA_8888), ImageFormatConvertUtils::NV21P010ToBGRA8888},
        {std::make_pair(PixelFormat::YCRCB_P010, PixelFormat::RGB_888), ImageFormatConvertUtils::NV21P010ToRGB888},
        {std::make_pair(PixelFormat::YCRCB_P010, PixelFormat::RGBA_F16), ImageFormatConvertUtils::NV21P010ToRGBAF16},
        {std::make_pair(PixelFormat::YCRCB_P010, PixelFormat::RGBA_1010102),
            ImageFormatConvertUtils::NV21P010ToRGBA1010102},
    };
#else
    std::map<std::pair<PixelFormat, PixelFormat>, YUVConvertFunction> yuvCvtFuncMap = {
        {std::make_pair(PixelFormat::NV21, PixelFormat::RGB_888), ImageFormatConvertExtUtils::NV21ToRGB},
        {std::make_pair(PixelFormat::NV21, PixelFormat::RGBA_8888), ImageFormatConvertExtUtils::NV21ToRGBA},
        {std::make_pair(PixelFormat::NV21, PixelFormat::BGRA_8888), ImageFormatConvertExtUtils::NV21ToBGRA},
        {std::make_pair(PixelFormat::NV21, PixelFormat::RGB_565), ImageFormatConvertExtUtils::NV21ToRGB565},
        {std::make_pair(PixelFormat::NV12, PixelFormat::RGB_565), ImageFormatConvertExtUtils::NV12ToRGB565},
        {std::make_pair(PixelFormat::NV21, PixelFormat::NV12), ImageFormatConvertUtils::NV21ToNV12},
        {std::make_pair(PixelFormat::NV21, PixelFormat::RGBA_F16), ImageFormatConvertUtils::NV21ToRGBAF16},
        {std::make_pair(PixelFormat::NV12, PixelFormat::NV21), ImageFormatConvertUtils::NV12ToNV21},
        {std::make_pair(PixelFormat::NV12, PixelFormat::RGBA_F16), ImageFormatConvertUtils::NV12ToRGBAF16},
        {std::make_pair(PixelFormat::NV12, PixelFormat::RGBA_8888), ImageFormatConvertExtUtils::NV12ToRGBA},
        {std::make_pair(PixelFormat::NV12, PixelFormat::BGRA_8888), ImageFormatConvertExtUtils::NV12ToBGRA},
        {std::make_pair(PixelFormat::NV12, PixelFormat::RGB_888), ImageFormatConvertExtUtils::NV12ToRGB},
        {std::make_pair(PixelFormat::NV12, PixelFormat::RGBA_1010102), ImageFormatConvertExtUtils::NV12ToRGBA1010102},
        {std::make_pair(PixelFormat::NV21, PixelFormat::RGBA_1010102), ImageFormatConvertExtUtils::NV21ToRGBA1010102},
        {std::make_pair(PixelFormat::NV12, PixelFormat::YCBCR_P010), ImageFormatConvertExtUtils::NV12ToNV12P010},
        {std::make_pair(PixelFormat::NV12, PixelFormat::YCRCB_P010), ImageFormatConvertExtUtils::NV12ToNV21P010},
        {std::make_pair(PixelFormat::NV21, PixelFormat::YCBCR_P010), ImageFormatConvertExtUtils::NV21ToNV12P010},
        {std::make_pair(PixelFormat::NV21, PixelFormat::YCRCB_P010), ImageFormatConvertExtUtils::NV21ToNV21P010},
        {std::make_pair(PixelFormat::YCBCR_P010, PixelFormat::NV12), ImageFormatConvertExtUtils::NV12P010ToNV12},
        {std::make_pair(PixelFormat::YCBCR_P010, PixelFormat::NV21), ImageFormatConvertExtUtils::NV12P010ToNV21},
        {std::make_pair(PixelFormat::YCBCR_P010, PixelFormat::YCRCB_P010),
            ImageFormatConvertUtils::NV12P010ToNV21P010},
        {std::make_pair(PixelFormat::YCBCR_P010, PixelFormat::RGB_565), ImageFormatConvertExtUtils::NV12P010ToRGB565},
        {std::make_pair(PixelFormat::YCBCR_P010, PixelFormat::RGBA_8888),
            ImageFormatConvertExtUtils::NV12P010ToRGBA8888},
        {std::make_pair(PixelFormat::YCBCR_P010, PixelFormat::BGRA_8888),
            ImageFormatConvertExtUtils::NV12P010ToBGRA8888},
        {std::make_pair(PixelFormat::YCBCR_P010, PixelFormat::RGB_888), ImageFormatConvertExtUtils::NV12P010ToRGB888},
        {std::make_pair(PixelFormat::YCBCR_P010, PixelFormat::RGBA_F16), ImageFormatConvertUtils::NV12P010ToRGBAF16},
        {std::make_pair(PixelFormat::YCRCB_P010, PixelFormat::NV12), ImageFormatConvertExtUtils::NV21P010ToNV12},
        {std::make_pair(PixelFormat::YCRCB_P010, PixelFormat::NV21), ImageFormatConvertExtUtils::NV21P010ToNV21},
        {std::make_pair(PixelFormat::YCRCB_P010, PixelFormat::YCBCR_P010),
            ImageFormatConvertUtils::NV21P010ToNV12P010},
        {std::make_pair(PixelFormat::YCBCR_P010, PixelFormat::RGBA_1010102),
            ImageFormatConvertExtUtils::NV12P010ToRGBA1010102},
        {std::make_pair(PixelFormat::YCRCB_P010, PixelFormat::RGB_565), ImageFormatConvertExtUtils::NV21P010ToRGB565},
        {std::make_pair(PixelFormat::YCRCB_P010, PixelFormat::RGBA_8888),
            ImageFormatConvertExtUtils::NV21P010ToRGBA8888},
        {std::make_pair(PixelFormat::YCRCB_P010, PixelFormat::BGRA_8888),
            ImageFormatConvertExtUtils::NV21P010ToBGRA8888},
        {std::make_pair(PixelFormat::YCRCB_P010, PixelFormat::RGB_888), ImageFormatConvertExtUtils::NV21P010ToRGB888},
        {std::make_pair(PixelFormat::YCRCB_P010, PixelFormat::RGBA_F16), ImageFormatConvertUtils::NV21P010ToRGBAF16},
        {std::make_pair(PixelFormat::YCRCB_P010, PixelFormat::RGBA_1010102),
            ImageFormatConvertExtUtils::NV21P010ToRGBA1010102},
    };
#endif
    return yuvCvtFuncMap;
}();

static const std::set<std::pair<PixelFormat, PixelFormat>> conversions = {
    {PixelFormat::NV12, PixelFormat::RGBA_1010102},
    {PixelFormat::NV21, PixelFormat::RGBA_1010102},
    {PixelFormat::RGB_565, PixelFormat::YCBCR_P010},
    {PixelFormat::RGBA_8888, PixelFormat::YCBCR_P010},
    {PixelFormat::BGRA_8888, PixelFormat::YCBCR_P010},
    {PixelFormat::RGB_888, PixelFormat::YCBCR_P010},
    {PixelFormat::RGBA_F16, PixelFormat::YCBCR_P010},
    {PixelFormat::RGB_565, PixelFormat::YCRCB_P010},
    {PixelFormat::RGBA_8888, PixelFormat::YCRCB_P010},
    {PixelFormat::BGRA_8888, PixelFormat::YCRCB_P010},
    {PixelFormat::RGB_888, PixelFormat::YCRCB_P010},
    {PixelFormat::RGBA_F16, PixelFormat::YCRCB_P010}
};

static void CalcRGBStride(PixelFormat format, uint32_t width, uint32_t &stride)
{
    switch (format) {
        case PixelFormat::RGB_565:
            stride = static_cast<uint32_t>(width * BYTES_PER_PIXEL_RGB565);
            break;
        case PixelFormat::RGBA_8888:
            stride = static_cast<uint32_t>(width * BYTES_PER_PIXEL_RGBA);
            break;
        case PixelFormat::BGRA_8888:
            stride = static_cast<uint32_t>(width * BYTES_PER_PIXEL_BGRA);
            break;
        case PixelFormat::RGB_888:
            stride = static_cast<uint32_t>(width * BYTES_PER_PIXEL_RGB);
            break;
        case PixelFormat::RGBA_F16:
            stride = static_cast<uint32_t>(width * STRIDES_PER_PLANE);
            break;
        default:
            stride = static_cast<uint32_t>(width * BYTES_PER_PIXEL_RGBA);
    }
}

static bool IsYUVConvert(PixelFormat srcFormat)
{
    bool ret = srcFormat == PixelFormat::NV21 || srcFormat == PixelFormat::NV12 ||
               srcFormat == PixelFormat::YCBCR_P010 || srcFormat == PixelFormat::YCRCB_P010;
    return ret;
}

uint32_t ImageFormatConvert::YUVConvert(const OHOS::Media::ConvertDataInfo &srcDataInfo,
                                        OHOS::Media::DestConvertInfo &destInfo)
{
    YUVConvertFunction yuvConvertFunction = YUVGetConvertFuncByFormat(srcDataInfo.pixelFormat, destInfo.format);
    CHECK_ERROR_RETURN_RET_LOG(yuvConvertFunction == nullptr, ERR_IMAGE_INVALID_PARAMETER,
        "YUVConvert get convert function by format failed!");
    YUVDataInfo yuvDataInfo = srcDataInfo.yuvDataInfo;
    int32_t width = srcDataInfo.imageSize.width;
    int32_t height = srcDataInfo.imageSize.height;
    if (destInfo.width == 0 || destInfo.height == 0) {
        destInfo.width = static_cast<uint32_t>(width);
        destInfo.height = static_cast<uint32_t>(height);
    }
    if (yuvDataInfo.yWidth == 0 || yuvDataInfo.yHeight == 0 || yuvDataInfo.uvWidth == 0 || yuvDataInfo.uvHeight == 0) {
        yuvDataInfo.yWidth = static_cast<uint32_t>(width);
        yuvDataInfo.yHeight = static_cast<uint32_t>(height);
        yuvDataInfo.uvWidth = static_cast<uint32_t>((width + 1) / NUM_2);
        yuvDataInfo.uvHeight = static_cast<uint32_t>((height + 1) / NUM_2);
    }
    YUVStrideInfo dstStrides;
    auto m = CreateMemory(destInfo.format, destInfo.allocType, {destInfo.width, destInfo.height}, dstStrides);
    CHECK_ERROR_RETURN_RET_LOG(m == nullptr, ERR_IMAGE_INVALID_PARAMETER, "YUVConvert create memory failed!");
    destInfo.context = m->extend.data;
    destInfo.yStride = dstStrides.yStride;
    destInfo.uvStride = dstStrides.uvStride;
    destInfo.yOffset = dstStrides.yOffset;
    destInfo.uvOffset = dstStrides.uvOffset;
    destInfo.buffer = reinterpret_cast<uint8_t *>(m->data.data);
    destInfo.bufferSize = GetBufferSizeByFormat(destInfo.format, {destInfo.width, destInfo.height});

    if (!yuvConvertFunction(srcDataInfo.buffer, yuvDataInfo, destInfo, srcDataInfo.colorSpace)) {
        IMAGE_LOGE("YUVConvert format convert failed!");
        m->Release();
        return IMAGE_RESULT_FORMAT_CONVERT_FAILED;
    }
    return SUCCESS;
}

uint32_t ImageFormatConvert::RGBConvert(const OHOS::Media::ConvertDataInfo &srcDataInfo,
                                        OHOS::Media::DestConvertInfo &destInfo)
{
    ConvertFunction cvtFunc = GetConvertFuncByFormat(srcDataInfo.pixelFormat, destInfo.format);
    CHECK_ERROR_RETURN_RET_LOG(cvtFunc == nullptr, ERR_IMAGE_INVALID_PARAMETER,
        "RGBConvert get convert function by format failed!");
    YUVStrideInfo dstStrides;
    auto m = CreateMemory(destInfo.format, destInfo.allocType, {destInfo.width, destInfo.height}, dstStrides);
    CHECK_ERROR_RETURN_RET_LOG(m == nullptr, ERR_IMAGE_INVALID_PARAMETER, "RGBConvert create memory failed!");
    destInfo.context = m->extend.data;
    destInfo.yStride = dstStrides.yStride;
    destInfo.uvStride = dstStrides.uvStride;
    destInfo.yOffset = dstStrides.yOffset;
    destInfo.uvOffset = dstStrides.uvOffset;
    destInfo.buffer = reinterpret_cast<uint8_t *>(m->data.data);
    destInfo.bufferSize = GetBufferSizeByFormat(destInfo.format, {destInfo.width, destInfo.height});
    uint32_t srcStride = 0;
    if (srcDataInfo.stride != 0) {
        srcStride = srcDataInfo.stride;
    } else {
        CalcRGBStride(srcDataInfo.pixelFormat, srcDataInfo.imageSize.width, srcStride);
    }
    RGBDataInfo rgbDataInfo = {srcDataInfo.imageSize.width, srcDataInfo.imageSize.height, srcStride};
    if (!cvtFunc(srcDataInfo.buffer, rgbDataInfo, destInfo, srcDataInfo.colorSpace)) {
        IMAGE_LOGE("RGBConvert format convert failed!");
        m->Release();
        return IMAGE_RESULT_FORMAT_CONVERT_FAILED;
    }
    return SUCCESS;
}

uint32_t ImageFormatConvert::ConvertImageFormat(const ConvertDataInfo &srcDataInfo, DestConvertInfo &destInfo)
{
    if (!CheckConvertDataInfo(srcDataInfo)) {
        IMAGE_LOGE("source convert data info is invalid");
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    if (!IsSupport(destInfo.format)) {
        IMAGE_LOGE("destination format is not support or invalid");
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    if (IsYUVConvert(srcDataInfo.pixelFormat)) {
        return YUVConvert(srcDataInfo, destInfo);
    }
    return RGBConvert(srcDataInfo, destInfo);
}

uint32_t ImageFormatConvert::ConvertImageFormat(std::shared_ptr<PixelMap> &srcPixelMap, PixelFormat destFormat)
{
    if (srcPixelMap == nullptr) {
        IMAGE_LOGE("source pixel map is null");
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    ImageTrace imageTrace("ImageFormatConvert::ConvertImageFormat srcFmt %u, dstFmt %u",
        static_cast<uint32_t>(srcPixelMap->GetPixelFormat(), static_cast<uint32_t>(destFormat)));
    if (!IsSupport(destFormat)) {
        IMAGE_LOGE("destination format not support");
        return ERR_MEDIA_FORMAT_UNSUPPORT;
    }
    PixelFormat srcFormat = srcPixelMap->GetPixelFormat();
    if (IsYUVConvert(srcFormat)) {
        uint32_t ret = 0;
        ret = YUVConvertImageFormatOption(srcPixelMap, srcFormat, destFormat);
        if (ret != SUCCESS) {
            IMAGE_LOGE("convert yuv format failed!");
        }
        return ret;
    }
    if (srcPixelMap->IsAstc()) {
        uint32_t ret = 0;
        std::unique_ptr<PixelMap> resultPixelMap = PixelMap::ConvertFromAstc(srcPixelMap.get(), ret,
            destFormat);
        srcPixelMap = std::move(resultPixelMap);
        if (ret != SUCCESS) {
            IMAGE_LOGE("convert astc format failed!");
        }
        return ret;
    }
    uint32_t ret = RGBConvertImageFormatOption(srcPixelMap, srcFormat, destFormat);
    if (ret != SUCCESS) {
        IMAGE_LOGE("convert rgb format failed!");
        return ret;
    }
    ImageUtils::DumpPixelMapIfDumpEnabled(*srcPixelMap, __func__);
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
        case PixelFormat::BGRA_8888:
        case PixelFormat::RGBA_1010102:{
            return size.width * size.height * NUM_4;
        }
        case PixelFormat::RGBA_F16:{
            return (((size.width + NUM_1) / NUM_2) * NUM_2) * size.height * NUM_8;
        }
        case PixelFormat::NV21:
        case PixelFormat::NV12:{
            return size.width * size.height + ((size.width + NUM_1) / NUM_2) *
                ((size.height + NUM_1) / NUM_2) * NUM_2;
        }
        case PixelFormat::YCBCR_P010:
        case PixelFormat::YCRCB_P010: {
            return (size.width * size.height + ((size.width + NUM_1) / NUM_2) *
                ((size.height + NUM_1) / NUM_2) * NUM_2) * NUM_2;
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

bool ImageFormatConvert::IsSupport(PixelFormat format)
{
    switch (format) {
        case PixelFormat::ARGB_8888:
        case PixelFormat::RGB_565:
        case PixelFormat::RGBA_8888:
        case PixelFormat::BGRA_8888:
        case PixelFormat::RGB_888:
        case PixelFormat::RGBA_F16:
        case PixelFormat::RGBA_1010102:
        case PixelFormat::YCBCR_P010:
        case PixelFormat::YCRCB_P010:
        case PixelFormat::NV21:
        case PixelFormat::NV12:{
            return true;
        }
        default:{
            return false;
        }
    }
}

#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
static void GetYUVStrideInfo(int32_t pixelFmt, OH_NativeBuffer_Planes *planes, YUVStrideInfo &dstStrides)
{
    if (pixelFmt == GRAPHIC_PIXEL_FMT_YCBCR_420_SP) {
        auto yStride = planes->planes[PLANE_Y].columnStride;
        auto uvStride = planes->planes[PLANE_U].columnStride;
        auto yOffset = planes->planes[PLANE_Y].offset;
        auto uvOffset = planes->planes[PLANE_U].offset;
        dstStrides = {yStride, uvStride, yOffset, uvOffset};
    } else if (pixelFmt == GRAPHIC_PIXEL_FMT_YCRCB_420_SP) {
        auto yStride = planes->planes[PLANE_Y].columnStride;
        auto uvStride = planes->planes[PLANE_V].columnStride;
        auto yOffset = planes->planes[PLANE_Y].offset;
        auto uvOffset = planes->planes[PLANE_V].offset;
        dstStrides = {yStride, uvStride, yOffset, uvOffset};
    } else if (pixelFmt == GRAPHIC_PIXEL_FMT_YCBCR_P010) {
        auto yStride = planes->planes[PLANE_Y].columnStride / 2;
        auto uvStride = planes->planes[PLANE_U].columnStride / 2;
        auto yOffset = planes->planes[PLANE_Y].offset / 2;
        auto uvOffset = planes->planes[PLANE_U].offset / 2;
        dstStrides = {yStride, uvStride, yOffset, uvOffset};
    } else if (pixelFmt == GRAPHIC_PIXEL_FMT_YCRCB_P010) {
        auto yStride = planes->planes[PLANE_Y].columnStride / 2;
        auto uvStride = planes->planes[PLANE_V].columnStride / 2;
        auto yOffset = planes->planes[PLANE_Y].offset / 2;
        auto uvOffset = planes->planes[PLANE_V].offset / 2;
        dstStrides = {yStride, uvStride, yOffset, uvOffset};
    }
}
#endif

std::unique_ptr<AbsMemory> ImageFormatConvert::CreateMemory(PixelFormat pixelFormat, AllocatorType allocatorType,
    Size size, YUVStrideInfo &strides, uint64_t usage)
{
    if (size.width == 0 || size.height == 0 || pixelFormat == PixelFormat::UNKNOWN) {
        IMAGE_LOGE("CreateMemory err ERR_IMAGE_INVALID_PARAMETER!");
        return nullptr;
    }
    uint32_t pictureSize = GetBufferSizeByFormat(pixelFormat, size);
    if (IsYUVConvert(pixelFormat)) {
        strides = {size.width, (size.width + 1) / NUM_2 * NUM_2, 0, size.width * size.height};
    } else {
        uint32_t stride = 0;
        CalcRGBStride(pixelFormat, size.width, stride);
        strides = {stride, 0, 0, 0};
    }
    MemoryData memoryData = {nullptr, pictureSize, "PixelConvert", size, pixelFormat};
    memoryData.usage = usage;
    auto m = MemoryManager::CreateMemory(allocatorType, memoryData);
    CHECK_ERROR_RETURN_RET_LOG(m == nullptr, m, "CreateMemory failed");
#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    if (allocatorType != AllocatorType::DMA_ALLOC) {
        return m;
    }
    CHECK_ERROR_RETURN_RET_LOG(m->extend.data == nullptr, m, "CreateMemory get surfacebuffer failed");
    auto sb = reinterpret_cast<SurfaceBuffer*>(m->extend.data);
    OH_NativeBuffer_Planes *planes = nullptr;
    GSError retVal = sb->GetPlanesInfo(reinterpret_cast<void**>(&planes));
    auto stride = sb->GetStride();
    strides = {stride, 0, 0, 0};
    if (retVal != OHOS::GSERROR_OK || planes == nullptr) {
        IMAGE_LOGE("CreateMemory Get planesInfo failed, retVal:%{public}d", retVal);
    } else if (planes->planeCount >= NUM_2) {
        int32_t pixelFmt = sb->GetFormat();
        GetYUVStrideInfo(pixelFmt, planes, strides);
    }
#endif
    return m;
}

std::unique_ptr<AbsMemory> Truncate10BitMemory(std::shared_ptr<PixelMap> &srcPixelmap,
    ImageInfo &imageInfo, PixelFormat destFormat, AllocatorType dstType, uint32_t &errorCode)
{
#if !defined(CROSS_PLATFORM)
    ImageTrace imageTrace("ImageFormatConvert::Truncate10BitMemory");
    IMAGE_LOGD("%{public}s srcPixelMap get format %{public}d", __func__, destFormat);
    bool cond = srcPixelmap == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, nullptr, "Truncate function error by src null");

    // hdr and sdr has same byte size.
    size_t byteSize = static_cast<size_t>(srcPixelmap->GetByteCount());
    MemoryData sdrData = {nullptr, byteSize, "Trans ImageData", imageInfo.size, destFormat};
    auto sdrMemory = MemoryManager::CreateMemory(dstType, sdrData);
    if (sdrMemory == nullptr) {
        IMAGE_LOGE("sdr memory alloc failed.");
        errorCode = IMAGE_RESULT_GET_SURFAC_FAILED;
        return nullptr;
    }

    VpeSurfaceBuffers buffers;
    buffers.sdr = sptr<SurfaceBuffer>(reinterpret_cast<SurfaceBuffer*>(sdrMemory->extend.data));
    buffers.hdr = sptr<SurfaceBuffer>(reinterpret_cast<SurfaceBuffer*>(srcPixelmap->GetFd()));
    std::unique_ptr<VpeUtils> utils = std::make_unique<VpeUtils>();
    int32_t res = utils->TruncateBuffer(buffers, false);
    if (res != SUCCESS) {
        sdrMemory->Release();
        IMAGE_LOGE("HDR-IMAGE Truncate10BitMemory failed");
        errorCode = IMAGE_RESULT_GET_SURFAC_FAILED;
        return nullptr;
    }
    errorCode = SUCCESS;
    return sdrMemory;
#else
    errorCode = ERR_MEDIA_INVALID_OPERATION;
    return nullptr;
#endif
}

uint32_t CheckIfConvertRGB1010102ToRGBA8888(std::shared_ptr<PixelMap> &srcPixelMap, PixelFormat destFormat)
{
    IMAGE_LOGI("do %{public}s", __func__);
    if (srcPixelMap == nullptr) {
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    PixelFormat srcFormat = srcPixelMap->GetPixelFormat();
    if (srcFormat != PixelFormat::RGBA_1010102 || destFormat != PixelFormat::RGBA_8888) {
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    auto allocateType = srcPixelMap->GetAllocatorType();
    if (allocateType != AllocatorType::DMA_ALLOC) {
        IMAGE_LOGE("do %{public}s allocatorType error", __func__);
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    AllocatorType dstType = AllocatorType::DMA_ALLOC;
    ImageInfo imageInfo;
    srcPixelMap->GetImageInfo(imageInfo);
    uint32_t ret = SUCCESS;
    auto sdrMemory = Truncate10BitMemory(srcPixelMap, imageInfo, destFormat, dstType, ret);
    if (sdrMemory == nullptr) {
        return IMAGE_RESULT_FORMAT_CONVERT_FAILED;
    }
    srcPixelMap->SetPixelsAddr(sdrMemory->data.data, sdrMemory->extend.data, sdrMemory->data.size, dstType, nullptr);
    imageInfo.pixelFormat = sdrMemory->data.format;
    srcPixelMap->SetImageInfo(imageInfo, true);
    return SUCCESS;
}

uint32_t ImageFormatConvert::RGBConvertImageFormatOption(std::shared_ptr<PixelMap> &srcPixelMap,
                                                         const PixelFormat &srcFormat, PixelFormat destFormat)
{
    ConvertFunction cvtFunc = GetConvertFuncByFormat(srcFormat, destFormat);
    if (cvtFunc == nullptr) {
        IMAGE_LOGE("get convert function by format failed!");
        return CheckIfConvertRGB1010102ToRGBA8888(srcPixelMap, destFormat);
    }
    const_uint8_buffer_type srcBuffer = srcPixelMap->GetPixels();
    ImageInfo imageInfo;
    srcPixelMap->GetImageInfo(imageInfo);

    int32_t width = imageInfo.size.width;
    int32_t height = imageInfo.size.height;
    YUVStrideInfo dstStrides;
    auto allocType = srcPixelMap->GetAllocatorType();
    auto m = CreateMemory(destFormat, allocType, imageInfo.size, dstStrides, srcPixelMap->GetNoPaddingUsage());
    if (m == nullptr) {
        IMAGE_LOGE("CreateMemory failed");
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    int32_t stride = srcPixelMap->GetRowStride();
    #if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    if (allocType == AllocatorType::DMA_ALLOC) {
        auto sb = reinterpret_cast<SurfaceBuffer*>(srcPixelMap->GetFd());
        stride = sb->GetStride();
        sptr<SurfaceBuffer> sourceSurfaceBuffer(sb);
        sptr<SurfaceBuffer> dstSurfaceBuffer(reinterpret_cast<SurfaceBuffer*>(m->extend.data));
        VpeUtils::CopySurfaceBufferInfo(sourceSurfaceBuffer, dstSurfaceBuffer);
    }
    #endif
    RGBDataInfo rgbDataInfo = {width, height, static_cast<uint32_t>(stride)};
    DestConvertInfo destInfo = {width, height, destFormat, allocType};
    destInfo.buffer = reinterpret_cast<uint8_t *>(m->data.data);
    destInfo.bufferSize = GetBufferSizeByFormat(destFormat, {destInfo.width, destInfo.height});
    destInfo.yStride = dstStrides.yStride;
    destInfo.uvStride = dstStrides.uvStride;
    destInfo.yOffset = dstStrides.yOffset;
    destInfo.uvOffset = dstStrides.uvOffset;
    if (!cvtFunc(srcBuffer, rgbDataInfo, destInfo, srcPixelMap->GetColorSpace())) {
        IMAGE_LOGE("format convert failed!");
        m->Release();
        return IMAGE_RESULT_FORMAT_CONVERT_FAILED;
    }
    auto ret = MakeDestPixelMap(srcPixelMap, imageInfo, destInfo, m->extend.data);
    if (ret == ERR_IMAGE_PIXELMAP_CREATE_FAILED) {
        m->Release();
    }
    return ret;
}

uint32_t ImageFormatConvert::RGBConvertImageFormatOptionUnique(
    std::unique_ptr<PixelMap> &srcPixelMap, const PixelFormat &srcFormat, PixelFormat destFormat)
{
    ConvertFunction cvtFunc = GetConvertFuncByFormat(srcFormat, destFormat);
    bool cond = cvtFunc == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_INVALID_PARAMETER, "get convert function by format failed!");
    const_uint8_buffer_type srcBuffer = srcPixelMap->GetPixels();
    ImageInfo imageInfo;
    srcPixelMap->GetImageInfo(imageInfo);

    int32_t width = imageInfo.size.width;
    int32_t height = imageInfo.size.height;
    YUVStrideInfo dstStrides;
    auto allocType = srcPixelMap->GetAllocatorType();
    auto memory = CreateMemory(destFormat, allocType, imageInfo.size, dstStrides, srcPixelMap->GetNoPaddingUsage());
    cond = memory == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_INVALID_PARAMETER, "CreateMemory failed");
    int32_t stride = srcPixelMap->GetRowStride();
    #if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    if (allocType == AllocatorType::DMA_ALLOC) {
        auto sb = reinterpret_cast<SurfaceBuffer*>(srcPixelMap->GetFd());
        stride = sb->GetStride();
        sptr<SurfaceBuffer> sourceSurfaceBuffer(sb);
        sptr<SurfaceBuffer> dstSurfaceBuffer(reinterpret_cast<SurfaceBuffer*>(memory->extend.data));
        VpeUtils::CopySurfaceBufferInfo(sourceSurfaceBuffer, dstSurfaceBuffer);
    }
    #endif
    RGBDataInfo rgbDataInfo = {width, height, static_cast<uint32_t>(stride)};
    DestConvertInfo destInfo = {width, height, destFormat, allocType};
    destInfo.buffer = reinterpret_cast<uint8_t *>(memory->data.data);
    destInfo.bufferSize = GetBufferSizeByFormat(destFormat, {destInfo.width, destInfo.height});
    destInfo.yStride = dstStrides.yStride;
    destInfo.uvStride = dstStrides.uvStride;
    destInfo.yOffset = dstStrides.yOffset;
    destInfo.uvOffset = dstStrides.uvOffset;
    if (!cvtFunc(srcBuffer, rgbDataInfo, destInfo, srcPixelMap->GetColorSpace())) {
        IMAGE_LOGE("format convert failed!");
        memory->Release();
        return IMAGE_RESULT_FORMAT_CONVERT_FAILED;
    }
    auto ret = MakeDestPixelMapUnique(srcPixelMap, imageInfo, destInfo, memory->extend.data);
    if (ret == ERR_IMAGE_PIXELMAP_CREATE_FAILED) {
        memory->Release();
    }
    return ret;
}

bool ImageFormatConvert::SetConvertImageMetaData(std::unique_ptr<PixelMap> &srcPixelMap,
                                                 std::unique_ptr<PixelMap> &dstPixelMap)
{
    CHECK_ERROR_RETURN_RET(srcPixelMap == nullptr || dstPixelMap == nullptr, false);
    auto HdrMetadata = srcPixelMap->GetHdrMetadata();
    if (HdrMetadata != nullptr) {
        dstPixelMap->SetHdrMetadata(HdrMetadata);
    }
    auto exifData = srcPixelMap->GetExifMetadata();
    if (exifData != nullptr) {
        dstPixelMap->SetExifMetadata(exifData);
    }
    return true;
}

bool ImageFormatConvert::SetConvertImageMetaData(std::shared_ptr<PixelMap> &srcPixelMap,
                                                 std::unique_ptr<PixelMap> &dstPixelMap)
{
    if (srcPixelMap == nullptr || dstPixelMap == nullptr) {
        return false;
    }
    auto HdrMetadata = srcPixelMap->GetHdrMetadata();
    if (HdrMetadata != nullptr) {
        dstPixelMap->SetHdrMetadata(HdrMetadata);
    }
    auto exifData = srcPixelMap->GetExifMetadata();
    if (exifData != nullptr) {
        dstPixelMap->SetExifMetadata(exifData);
    }
    return true;
}

static AllocatorType GetAllocatorType(std::shared_ptr<PixelMap> &srcPixelMap, PixelFormat destFormat)
{
    auto allocType = srcPixelMap->GetAllocatorType();
    if (destFormat == PixelFormat::RGB_888 || destFormat == PixelFormat::RGB_565 ||
        destFormat == PixelFormat::RGBA_F16) {
        allocType = AllocatorType::SHARE_MEM_ALLOC;
    }
    return allocType;
}

#ifndef CROSS_PLATFORM
bool GetYuvSbConvertDetails(sptr<SurfaceBuffer> sourceSurfaceBuffer, DestConvertInfo &destInfo)
{
    if (sourceSurfaceBuffer == nullptr) {
        return false;
    }
    CM_ColorSpaceInfo colorSpaceInfo;
    if (!VpeUtils::GetColorSpaceInfo(sourceSurfaceBuffer, colorSpaceInfo)) {
        return false;
    }
    if (colorSpaceInfo.primaries == CM_ColorPrimaries::COLORPRIMARIES_BT709) {
        destInfo.yuvConvertCSDetails.srcYuvConversion = YuvConversion::BT709;
    } else if (colorSpaceInfo.primaries == CM_ColorPrimaries::COLORPRIMARIES_BT2020) {
        destInfo.yuvConvertCSDetails.srcYuvConversion = YuvConversion::BT2020;
    } else {
        destInfo.yuvConvertCSDetails.srcYuvConversion = YuvConversion::BT601;
    }
    destInfo.yuvConvertCSDetails.srcRange = colorSpaceInfo.range == CM_Range::RANGE_FULL ? 1 : 0;
    IMAGE_LOGD("GetYuvSbConvertDetails srcYuvConversion: %{public}d, srcRange: %{public}d",
        destInfo.yuvConvertCSDetails.srcYuvConversion, destInfo.yuvConvertCSDetails.srcRange);
    return true;
}
#endif

uint32_t ImageFormatConvert::YUVConvertImageFormatOption(std::shared_ptr<PixelMap> &srcPixelMap,
                                                         const PixelFormat &srcFormat, PixelFormat destFormat)
{
    YUVConvertFunction yuvCvtFunc = YUVGetConvertFuncByFormat(srcFormat, destFormat);
    bool cond = yuvCvtFunc == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_INVALID_PARAMETER, "get convert function by format failed!");
    const_uint8_buffer_type data = srcPixelMap->GetPixels();
    YUVDataInfo yDInfo;
    srcPixelMap->GetImageYUVInfo(yDInfo);
    ImageInfo imageInfo;
    srcPixelMap->GetImageInfo(imageInfo);
    if ((srcFormat == PixelFormat::NV21 || srcFormat == PixelFormat::YCBCR_P010 ||
        srcFormat == PixelFormat::YCRCB_P010) &&
        (yDInfo.yWidth == 0 || yDInfo.yHeight == 0 || yDInfo.uvWidth == 0 || yDInfo.uvHeight == 0)) {
        yDInfo.yWidth = static_cast<uint32_t>(imageInfo.size.width);
        yDInfo.yHeight = static_cast<uint32_t>(imageInfo.size.height);
        yDInfo.uvWidth = static_cast<uint32_t>((imageInfo.size.width + 1) / NUM_2);
        yDInfo.uvHeight = static_cast<uint32_t>((imageInfo.size.height + 1) / NUM_2);
    }
    YUVStrideInfo dstStrides;
    auto allocType = GetAllocatorType(srcPixelMap, destFormat);
    DestConvertInfo destInfo = {imageInfo.size.width, imageInfo.size.height, destFormat, allocType};
    auto m = CreateMemory(destFormat, allocType, imageInfo.size, dstStrides,
        srcPixelMap->GetNoPaddingUsage());
    cond = m == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_INVALID_PARAMETER, "CreateMemory failed");
#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    if (allocType == AllocatorType::DMA_ALLOC) {
        sptr<SurfaceBuffer> sourceSurfaceBuffer(reinterpret_cast<SurfaceBuffer*>(srcPixelMap->GetFd()));
        sptr<SurfaceBuffer> dstSurfaceBuffer(reinterpret_cast<SurfaceBuffer*>(m->extend.data));
        VpeUtils::CopySurfaceBufferInfo(sourceSurfaceBuffer, dstSurfaceBuffer);
        cond = !GetYuvSbConvertDetails(sourceSurfaceBuffer, destInfo);
        CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_INVALID_PARAMETER, "GetYuvSbConvertDetails failed");
    }
#endif
    destInfo.buffer = reinterpret_cast<uint8_t *>(m->data.data);
    destInfo.bufferSize = GetBufferSizeByFormat(destFormat, {destInfo.width, destInfo.height});
    destInfo.yStride = dstStrides.yStride;
    destInfo.uvStride = dstStrides.uvStride;
    destInfo.yOffset = dstStrides.yOffset;
    destInfo.uvOffset = dstStrides.uvOffset;
    if (!yuvCvtFunc(data, yDInfo, destInfo, srcPixelMap->GetColorSpace())) {
        m->Release();
        return IMAGE_RESULT_FORMAT_CONVERT_FAILED;
    }
    auto ret = MakeDestPixelMap(srcPixelMap, imageInfo, destInfo, m->extend.data);
    if (ret == ERR_IMAGE_PIXELMAP_CREATE_FAILED) {
        m->Release();
    }
    return ret;
}

bool NeedProtectionConversion(const PixelFormat inputFormat, const PixelFormat outputFormat)
{
    if (conversions.find({inputFormat, outputFormat}) != conversions.end()) {
        return true;
    }
    return false;
}

ImageInfo SetImageInfo(ImageInfo &srcImageinfo, DestConvertInfo &destInfo)
{
    ImageInfo info;
    info.alphaType = srcImageinfo.alphaType;
    info.baseDensity = srcImageinfo.baseDensity;
    info.colorSpace = srcImageinfo.colorSpace;
    info.pixelFormat = destInfo.format;
    info.size = {destInfo.width, destInfo.height};
    info.encodedFormat = srcImageinfo.encodedFormat;
    return info;
}

uint32_t ImageFormatConvert::MakeDestPixelMap(std::shared_ptr<PixelMap> &destPixelMap, ImageInfo &srcImageinfo,
                                              DestConvertInfo &destInfo, void *context)
{
    if (srcImageinfo.size.width == 0 || srcImageinfo.size.height == 0 || destInfo.width == 0
        || destInfo.height == 0 || destInfo.format == PixelFormat::UNKNOWN) {
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    ImageInfo info = SetImageInfo(srcImageinfo, destInfo);
    auto allcatorType = destInfo.allocType;
    std::unique_ptr<PixelMap> pixelMap;
    if (info.pixelFormat == PixelFormat::NV21 || info.pixelFormat == PixelFormat::NV12 ||
        info.pixelFormat == PixelFormat::YCBCR_P010 || info.pixelFormat == PixelFormat::YCRCB_P010) {
#ifdef EXT_PIXEL
        pixelMap = std::make_unique<PixelYuvExt>();
#else
        pixelMap = std::make_unique<PixelYuv>();
#endif
        CHECK_ERROR_RETURN_RET(pixelMap == nullptr, ERR_IMAGE_PIXELMAP_CREATE_FAILED);
        if (allcatorType != AllocatorType::DMA_ALLOC) {
            pixelMap->AssignYuvDataOnType(info.pixelFormat, info.size.width, info.size.height);
        } else {
            YUVStrideInfo strides = {destInfo.yStride, destInfo.uvStride, destInfo.yOffset, destInfo.uvOffset};
            pixelMap->UpdateYUVDataInfo(info.pixelFormat, info.size.width, info.size.height, strides);
        }
    } else {
        pixelMap = std::make_unique<PixelMap>();
        CHECK_ERROR_RETURN_RET(pixelMap == nullptr, ERR_IMAGE_PIXELMAP_CREATE_FAILED);
    }
    pixelMap->SetPixelsAddr(destInfo.buffer, context, destInfo.bufferSize, allcatorType, nullptr);
    auto ret = pixelMap->SetImageInfo(info, true);
    bool isSetMetaData = SetConvertImageMetaData(destPixelMap, pixelMap);
    CHECK_ERROR_RETURN_RET_LOG(ret != SUCCESS || isSetMetaData == false, ret, "set imageInfo failed");
#ifdef IMAGE_COLORSPACE_FLAG
    if (NeedProtectionConversion(srcImageinfo.pixelFormat, info.pixelFormat)) {
        pixelMap->InnerSetColorSpace(OHOS::ColorManager::ColorSpace(ColorManager::ColorSpaceName::BT2020_HLG));
    } else {
        pixelMap->InnerSetColorSpace(destPixelMap->InnerGetGrColorSpace());
    }
#endif
    destPixelMap = std::move(pixelMap);
    return SUCCESS;
}

uint32_t ImageFormatConvert::MakeDestPixelMapUnique(std::unique_ptr<PixelMap> &destPixelMap, ImageInfo &srcImageinfo,
    DestConvertInfo &destInfo, void *context)
{
    bool cond = srcImageinfo.size.width == 0 || srcImageinfo.size.height == 0 || destInfo.width == 0 ||
                destInfo.height == 0 || destInfo.format == PixelFormat::UNKNOWN;
    CHECK_ERROR_RETURN_RET(cond, ERR_IMAGE_INVALID_PARAMETER);
    ImageInfo info = SetImageInfo(srcImageinfo, destInfo);
    auto allcatorType = destInfo.allocType;
    std::unique_ptr<PixelMap> pixelMap;
    if (info.pixelFormat == PixelFormat::NV21 || info.pixelFormat == PixelFormat::NV12 ||
        info.pixelFormat == PixelFormat::YCBCR_P010 || info.pixelFormat == PixelFormat::YCRCB_P010) {
#ifdef EXT_PIXEL
        pixelMap = std::make_unique<PixelYuvExt>();
#else
        pixelMap = std::make_unique<PixelYuv>();
#endif
        CHECK_ERROR_RETURN_RET(pixelMap == nullptr, ERR_IMAGE_PIXELMAP_CREATE_FAILED);
        if (allcatorType != AllocatorType::DMA_ALLOC) {
            pixelMap->AssignYuvDataOnType(info.pixelFormat, info.size.width, info.size.height);
        } else {
            YUVStrideInfo strides = {destInfo.yStride, destInfo.uvStride, destInfo.yOffset, destInfo.uvOffset};
            pixelMap->UpdateYUVDataInfo(info.pixelFormat, info.size.width, info.size.height, strides);
        }
    } else {
        pixelMap = std::make_unique<PixelMap>();
        CHECK_ERROR_RETURN_RET(pixelMap == nullptr, ERR_IMAGE_PIXELMAP_CREATE_FAILED);
    }
    pixelMap->SetPixelsAddr(destInfo.buffer, context, destInfo.bufferSize, allcatorType, nullptr);
    auto ret = pixelMap->SetImageInfo(info, true);
    bool isSetMetaData = SetConvertImageMetaData(destPixelMap, pixelMap);
    cond = ret != SUCCESS || isSetMetaData == false;
    CHECK_ERROR_RETURN_RET_LOG(cond, ret, "set imageInfo failed");
#ifdef IMAGE_COLORSPACE_FLAG
    if (NeedProtectionConversion(srcImageinfo.pixelFormat, info.pixelFormat)) {
        pixelMap->InnerSetColorSpace(OHOS::ColorManager::ColorSpace(ColorManager::ColorSpaceName::BT2020_HLG));
    } else {
        pixelMap->InnerSetColorSpace(destPixelMap->InnerGetGrColorSpace());
    }
#endif
    destPixelMap = std::move(pixelMap);
    return SUCCESS;
}
} // namespace Media
} // namespace OHOS