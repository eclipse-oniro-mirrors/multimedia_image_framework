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
#include "image_source.h"
#include "log_tags.h"
#include "media_errors.h"
#include "pixel_yuv.h"
#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
#include "v1_0/buffer_handle_meta_key_type.h"
#include "v1_0/cm_color_space.h"
#include "v1_0/hdr_static_metadata.h"
#include "surface_buffer.h"
#endif
#include "vpe_utils.h"

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
    ConvertFunction cvtFunc = GetConvertFuncByFormat(srcDataInfo.pixelFormat, destInfo.format);
    if (cvtFunc == nullptr) {
        IMAGE_LOGE("get convert function by format failed!");
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    YUVStrideInfo dstStrides;
    auto m = CreateMemory(destInfo.format, destInfo.allocType, destInfo.width,
                          destInfo.height, dstStrides);
    if (m == nullptr) {
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    destInfo.context = m->extend.data;
    destInfo.yStride = dstStrides.yStride;
    destInfo.uvStride = dstStrides.uvStride;
    destInfo.yOffset = dstStrides.yOffset;
    destInfo.uvOffset = dstStrides.uvOffset;
    destInfo.buffer = reinterpret_cast<uint8_t *>(m->data.data);
    destInfo.bufferSize = GetBufferSizeByFormat(destInfo.format, {destInfo.width, destInfo.height});
    uint32_t srcStride = 0;
    CalcRGBStride(srcDataInfo.pixelFormat, srcDataInfo.imageSize.width, srcStride);
    RGBDataInfo rgbDataInfo = {srcDataInfo.imageSize.width, srcDataInfo.imageSize.height, srcStride};
    if (!cvtFunc(srcDataInfo.buffer, rgbDataInfo, destInfo, srcDataInfo.colorSpace)) {
        IMAGE_LOGE("format convert failed!");
        m->Release();
        return IMAGE_RESULT_FORMAT_CONVERT_FAILED;
    }
    return SUCCESS;
}

static bool IsYUVConvert(PixelFormat srcFormat)
{
    bool ret = srcFormat == PixelFormat::NV21 || srcFormat == PixelFormat::NV12 ||
        srcFormat == PixelFormat::YCBCR_P010 || srcFormat == PixelFormat::YCRCB_P010;
    return ret;
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
    if (IsYUVConvert(srcFormat)) {
        uint32_t ret = 0;
        ret = YUVConvertImageFormatOption(srcPiexlMap, srcFormat, destFormat);
        if (ret != SUCCESS) {
            IMAGE_LOGE("convert yuv format failed!");
        }
        return ret;
    }
    if (srcPiexlMap->IsAstc()) {
        uint32_t ret = 0;
        std::unique_ptr<PixelMap> resultPixelMap = PixelMap::ConvertFromAstc(srcPiexlMap.get(), ret,
            destFormat);
        srcPiexlMap = std::move(resultPixelMap);
        if (ret != SUCCESS) {
            IMAGE_LOGE("convert astc format failed!");
        }
        return ret;
    }
    uint32_t ret = RGBConvertImageFormatOption(srcPiexlMap, srcFormat, destFormat);
    if (ret != SUCCESS) {
        IMAGE_LOGE("convert rgb format failed!");
        return ret;
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
                                                            int32_t width, int32_t height, YUVStrideInfo &strides)
{
    if (width == 0 || height == 0 || pixelFormat == PixelFormat::UNKNOWN) {
        IMAGE_LOGE("CreateMemory err ERR_IMAGE_INVALID_PARAMETER!");
        return nullptr;
    }
    uint32_t pictureSize = GetBufferSizeByFormat(pixelFormat, {width, height});
    if (IsYUVConvert(pixelFormat)) {
        strides = {width, (width + 1) / NUM_2 * NUM_2, 0, width * height};
    } else {
        uint32_t stride = 0;
        CalcRGBStride(pixelFormat, width, stride);
        strides = {stride, 0, 0, 0};
    }
    MemoryData memoryData = {nullptr, pictureSize, "PixelConvert", {width, height}, pixelFormat};
    auto m = MemoryManager::CreateMemory(allocatorType, memoryData);
    if (m == nullptr) {
        IMAGE_LOGE("CreateMemory failed");
        return m;
    }
#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    if (allocatorType != AllocatorType::DMA_ALLOC) {
        return m;
    }
    if (m->extend.data == nullptr) {
        IMAGE_LOGE("CreateMemory get surfacebuffer failed");
        return m;
    }
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

uint32_t ImageFormatConvert::RGBConvertImageFormatOption(std::shared_ptr<PixelMap> &srcPiexlMap,
                                                         const PixelFormat &srcFormat, PixelFormat destFormat)
{
    ConvertFunction cvtFunc = GetConvertFuncByFormat(srcFormat, destFormat);
    if (cvtFunc == nullptr) {
        IMAGE_LOGE("get convert function by format failed!");
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    const_uint8_buffer_type srcBuffer = srcPiexlMap->GetPixels();
    ImageInfo imageInfo;
    srcPiexlMap->GetImageInfo(imageInfo);

    int32_t width = imageInfo.size.width;
    int32_t height = imageInfo.size.height;
    YUVStrideInfo dstStrides;
    auto allocType = srcPiexlMap->GetAllocatorType();
    auto m = CreateMemory(destFormat, allocType, width, height, dstStrides);
    if (m == nullptr) {
        IMAGE_LOGE("CreateMemory failed");
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    int32_t stride = srcPiexlMap->GetRowStride();
    #if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    if (allocType == AllocatorType::DMA_ALLOC) {
        auto sb = reinterpret_cast<SurfaceBuffer*>(srcPiexlMap->GetFd());
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
    if (!cvtFunc(srcBuffer, rgbDataInfo, destInfo, srcPiexlMap->GetColorSpace())) {
        IMAGE_LOGE("format convert failed!");
        m->Release();
        return IMAGE_RESULT_FORMAT_CONVERT_FAILED;
    }
    auto ret = MakeDestPixelMap(srcPiexlMap, imageInfo, destInfo, m->extend.data);
    if (ret == ERR_IMAGE_PIXELMAP_CREATE_FAILED) {
        m->Release();
    }
    return ret;
}

uint32_t ImageFormatConvert::RGBConvertImageFormatOptionUnique(
    std::unique_ptr<PixelMap> &srcPiexlMap, const PixelFormat &srcFormat, PixelFormat destFormat)
{
    ConvertFunction cvtFunc = GetConvertFuncByFormat(srcFormat, destFormat);
    bool cond = cvtFunc == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_INVALID_PARAMETER, "get convert function by format failed!");
    const_uint8_buffer_type srcBuffer = srcPiexlMap->GetPixels();
    ImageInfo imageInfo;
    srcPiexlMap->GetImageInfo(imageInfo);

    int32_t width = imageInfo.size.width;
    int32_t height = imageInfo.size.height;
    YUVStrideInfo dstStrides;
    auto allocType = srcPiexlMap->GetAllocatorType();
    auto memory = CreateMemory(destFormat, allocType, width, height, dstStrides);
    cond = memory == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_INVALID_PARAMETER, "CreateMemory failed");
    int32_t stride = srcPiexlMap->GetRowStride();
    #if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    if (allocType == AllocatorType::DMA_ALLOC) {
        auto sb = reinterpret_cast<SurfaceBuffer*>(srcPiexlMap->GetFd());
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
    if (!cvtFunc(srcBuffer, rgbDataInfo, destInfo, srcPiexlMap->GetColorSpace())) {
        IMAGE_LOGE("format convert failed!");
        memory->Release();
        return IMAGE_RESULT_FORMAT_CONVERT_FAILED;
    }
    auto ret = MakeDestPixelMapUnique(srcPiexlMap, imageInfo, destInfo, memory->extend.data);
    if (ret == ERR_IMAGE_PIXELMAP_CREATE_FAILED) {
        memory->Release();
    }
    return ret;
}

bool ImageFormatConvert::SetConvertImageMetaData(std::unique_ptr<PixelMap> &srcPixelMap,
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

static AllocatorType GetAllocatorType(std::shared_ptr<PixelMap> &srcPiexlMap, PixelFormat destFormat)
{
    auto allocType = srcPiexlMap->GetAllocatorType();
    if (destFormat == PixelFormat::RGB_888 || destFormat == PixelFormat::RGB_565 ||
        destFormat == PixelFormat::RGBA_F16) {
        allocType = AllocatorType::SHARE_MEM_ALLOC;
    }
    return allocType;
}

uint32_t ImageFormatConvert::YUVConvertImageFormatOption(std::shared_ptr<PixelMap> &srcPiexlMap,
                                                         const PixelFormat &srcFormat, PixelFormat destFormat)
{
    YUVConvertFunction yuvCvtFunc = YUVGetConvertFuncByFormat(srcFormat, destFormat);
    if (yuvCvtFunc == nullptr) {
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    const_uint8_buffer_type data = srcPiexlMap->GetPixels();
    YUVDataInfo yDInfo;
    srcPiexlMap->GetImageYUVInfo(yDInfo);
    ImageInfo imageInfo;
    srcPiexlMap->GetImageInfo(imageInfo);
    if ((srcFormat == PixelFormat::NV21 || srcFormat == PixelFormat::YCBCR_P010 ||
        srcFormat == PixelFormat::YCRCB_P010) &&
        (yDInfo.yWidth == 0 || yDInfo.yHeight == 0 || yDInfo.uvWidth == 0 || yDInfo.uvHeight == 0)) {
        yDInfo.yWidth = static_cast<uint32_t>(imageInfo.size.width);
        yDInfo.yHeight = static_cast<uint32_t>(imageInfo.size.height);
        yDInfo.uvWidth = static_cast<uint32_t>((imageInfo.size.width + 1) / NUM_2);
        yDInfo.uvHeight = static_cast<uint32_t>((imageInfo.size.height + 1) / NUM_2);
    }
    YUVStrideInfo dstStrides;
    auto allocType = GetAllocatorType(srcPiexlMap, destFormat);
    DestConvertInfo destInfo = {imageInfo.size.width, imageInfo.size.height, destFormat, allocType};
    auto m = CreateMemory(destFormat, allocType, destInfo.width, destInfo.height, dstStrides);
    if (m == nullptr) {
        return ERR_IMAGE_INVALID_PARAMETER;
    }
#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    if (allocType == AllocatorType::DMA_ALLOC) {
        sptr<SurfaceBuffer> sourceSurfaceBuffer(reinterpret_cast<SurfaceBuffer*>(srcPiexlMap->GetFd()));
        sptr<SurfaceBuffer> dstSurfaceBuffer(reinterpret_cast<SurfaceBuffer*>(m->extend.data));
        VpeUtils::CopySurfaceBufferInfo(sourceSurfaceBuffer, dstSurfaceBuffer);
    }
#endif
    destInfo.buffer = reinterpret_cast<uint8_t *>(m->data.data);
    destInfo.bufferSize = GetBufferSizeByFormat(destFormat, {destInfo.width, destInfo.height});
    destInfo.yStride = dstStrides.yStride;
    destInfo.uvStride = dstStrides.uvStride;
    destInfo.yOffset = dstStrides.yOffset;
    destInfo.uvOffset = dstStrides.uvOffset;
    if (!yuvCvtFunc(data, yDInfo, destInfo, srcPiexlMap->GetColorSpace())) {
        m->Release();
        return IMAGE_RESULT_FORMAT_CONVERT_FAILED;
    }
    auto ret = MakeDestPixelMap(srcPiexlMap, imageInfo, destInfo, m->extend.data);
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
        if (pixelMap == nullptr) {
            return ERR_IMAGE_PIXELMAP_CREATE_FAILED;
        }
        if (allcatorType != AllocatorType::DMA_ALLOC) {
            pixelMap->AssignYuvDataOnType(info.pixelFormat, info.size.width, info.size.height);
        } else {
            YUVStrideInfo strides = {destInfo.yStride, destInfo.uvStride, destInfo.yOffset, destInfo.uvOffset};
            pixelMap->UpdateYUVDataInfo(info.pixelFormat, info.size.width, info.size.height, strides);
        }
    } else {
        pixelMap = std::make_unique<PixelMap>();
        if (pixelMap == nullptr) {
            return ERR_IMAGE_PIXELMAP_CREATE_FAILED;
        }
    }
    pixelMap->SetPixelsAddr(destInfo.buffer, context, destInfo.bufferSize, allcatorType, nullptr);
    auto ret = pixelMap->SetImageInfo(info, true);
    bool isSetMetaData = SetConvertImageMetaData(destPixelMap, pixelMap);
    if (ret != SUCCESS || isSetMetaData == false) {
        IMAGE_LOGE("set imageInfo failed");
        return ret;
    }
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
        if (pixelMap == nullptr) {
            return ERR_IMAGE_PIXELMAP_CREATE_FAILED;
        }
        if (allcatorType != AllocatorType::DMA_ALLOC) {
            pixelMap->AssignYuvDataOnType(info.pixelFormat, info.size.width, info.size.height);
        } else {
            YUVStrideInfo strides = {destInfo.yStride, destInfo.uvStride, destInfo.yOffset, destInfo.uvOffset};
            pixelMap->UpdateYUVDataInfo(info.pixelFormat, info.size.width, info.size.height, strides);
        }
    } else {
        pixelMap = std::make_unique<PixelMap>();
        if (pixelMap == nullptr) {
            return ERR_IMAGE_PIXELMAP_CREATE_FAILED;
        }
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