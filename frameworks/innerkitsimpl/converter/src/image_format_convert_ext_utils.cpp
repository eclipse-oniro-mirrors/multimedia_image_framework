/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "image_format_convert_ext_utils.h"

#include <cmath>
#include <cstring>
#include <iostream>
#include <map>
#include "hilog/log.h"
#include "image_convert_tools.h"
#include "image_log.h"
#include "log_tags.h"
#include "securec.h"

namespace {
constexpr uint32_t NUM_0 = 0;
constexpr uint32_t NUM_1 = 1;
constexpr uint32_t NUM_2 = 2;
constexpr uint32_t NUM_3 = 3;
constexpr uint32_t NUM_4 = 4;

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
#define LOG_TAG "ImageFormatConvertExt"
namespace OHOS {
namespace Media {
static bool I010ToP010(I010Info &i010, DestConvertParam &destParam)
{
    auto &converter = ConverterHandle::GetInstance().GetHandle();
    switch (destParam.format) {
        case PixelFormat::YCBCR_P010:
            converter.I010ToP010(i010.I010Y, i010.yStride, i010.I010U, i010.uStride, i010.I010V, i010.vStride,
                reinterpret_cast<uint16_t *>(destParam.slice[0]), destParam.stride[0],
                reinterpret_cast<uint16_t *>(destParam.slice[1]), destParam.stride[1],
                destParam.width, destParam.height);
            break;
        case PixelFormat::YCRCB_P010:
            converter.I010ToP010(i010.I010Y, i010.yStride, i010.I010V, i010.vStride, i010.I010U, i010.uStride,
                reinterpret_cast<uint16_t *>(destParam.slice[0]), destParam.stride[0],
                reinterpret_cast<uint16_t *>(destParam.slice[1]), destParam.stride[1],
                destParam.width, destParam.height);
            break;
        default:
            return false;
    }
    return true;
}

static bool I420ToI010(I420Info &i420, I010Info &i010)
{
    auto &converter = ConverterHandle::GetInstance().GetHandle();
    converter.I420ToI010(i420.I420Y, i420.yStride, i420.I420U, i420.uStride, i420.I420V, i420.vStride,
        i010.I010Y, i010.yStride, i010.I010U, i010.uStride, i010.I010V, i010.vStride,
        i420.width, i420.height);
    return true;
}

static bool RGBToI420(SrcConvertParam &srcParam, I420Info &i420)
{
    auto &converter = ConverterHandle::GetInstance().GetHandle();
    switch (srcParam.format) {
        case PixelFormat::RGB_888:
            converter.RGB24ToI420(srcParam.slice[0], srcParam.stride[0], i420.I420Y, i420.yStride, i420.I420U,
                i420.uStride, i420.I420V, i420.vStride, srcParam.width, srcParam.height);
            break;
        case PixelFormat::RGB_565:
            converter.RGB565ToI420(srcParam.slice[0], srcParam.stride[0], i420.I420Y, i420.yStride, i420.I420U,
                i420.uStride, i420.I420V, i420.vStride, srcParam.width, srcParam.height);
            break;
        case PixelFormat::RGBA_8888:
            converter.ABGRToI420(srcParam.slice[0], srcParam.stride[0], i420.I420Y, i420.yStride, i420.I420U,
                i420.uStride, i420.I420V, i420.vStride, srcParam.width, srcParam.height);
            break;
        case PixelFormat::BGRA_8888:
            converter.ARGBToI420(srcParam.slice[0], srcParam.stride[0], i420.I420Y, i420.yStride, i420.I420U,
                i420.uStride, i420.I420V, i420.vStride, srcParam.width, srcParam.height);
            break;
        default:
            return false;
    }
    return true;
}

static bool I420ToYuv(I420Info &i420, DestConvertParam &destParam)
{
    auto &converter = ConverterHandle::GetInstance().GetHandle();
    switch (destParam.format) {
        case PixelFormat::NV12:
            converter.I420ToNV12(i420.I420Y, i420.yStride, i420.I420U, i420.uStride, i420.I420V, i420.vStride,
                destParam.slice[0], destParam.stride[0], destParam.slice[1], destParam.stride[1],
                destParam.width, destParam.height);
            break;
        case PixelFormat::NV21:
            converter.I420ToNV21(i420.I420Y, i420.yStride, i420.I420U, i420.uStride, i420.I420V, i420.vStride,
                destParam.slice[0], destParam.stride[0], destParam.slice[1], destParam.stride[1],
                destParam.width, destParam.height);
            break;
        default:
            return false;
    }
    return true;
}

static void RGBToYuvParam(const RGBDataInfo &rgbInfo, SrcConvertParam &srcParam, DestConvertParam &destParam,
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
        int uvStride = (rgbInfo.width + NUM_1) / NUM_2 * NUM_2;
        destParam.stride[0] = static_cast<int>(destParam.width);
        destParam.stride[1] = static_cast<int>(uvStride);
        destParam.slice[0] = destInfo.buffer;
        destParam.slice[1] = destInfo.buffer + destParam.width * destParam.height;
    }
}

static bool YuvToI420(SrcConvertParam &srcParam, I420Info &i420)
{
    auto &converter = ConverterHandle::GetInstance().GetHandle();
    switch (srcParam.format) {
        case PixelFormat::NV12:
            converter.NV12ToI420(srcParam.slice[0], srcParam.stride[0], srcParam.slice[1], srcParam.stride[1],
                i420.I420Y, i420.yStride, i420.I420U, i420.uStride, i420.I420V, i420.vStride,
                i420.width, i420.height);
            break;
        case PixelFormat::NV21:
            converter.NV21ToI420(srcParam.slice[0], srcParam.stride[0], srcParam.slice[1], srcParam.stride[1],
                i420.I420Y, i420.yStride, i420.I420U, i420.uStride, i420.I420V, i420.vStride,
                i420.width, i420.height);
            break;
        default:
            return false;
    }
    return true;
}

static bool I420ToRGB(I420Info &i420, DestConvertParam &destParam, [[maybe_unused]]ColorSpace colorSpace)
{
    auto &converter = ConverterHandle::GetInstance().GetHandle();
    switch (destParam.format) {
        case PixelFormat::RGBA_8888:
            converter.I420ToABGR(i420.I420Y, i420.yStride, i420.I420U, i420.uStride, i420.I420V, i420.vStride,
                destParam.slice[0], destParam.stride[0], destParam.width, destParam.height);
            break;
        case PixelFormat::RGB_565:
            converter.I420ToRGB565Matrix(i420.I420Y, i420.yStride, i420.I420U, i420.uStride, i420.I420V, i420.vStride,
                destParam.slice[0], destParam.stride[0], static_cast<OHOS::OpenSourceLibyuv::ColorSpace>(colorSpace),
                destParam.width, destParam.height);
            break;
        case PixelFormat::BGRA_8888:
            converter.I420ToARGB(i420.I420Y, i420.yStride, i420.I420U, i420.uStride, i420.I420V, i420.vStride,
                destParam.slice[0], destParam.stride[0], destParam.width, destParam.height);
            break;
        case PixelFormat::RGB_888:
            converter.I420ToRAW(i420.I420Y, i420.yStride, i420.I420U, i420.uStride, i420.I420V, i420.vStride,
                destParam.slice[0], destParam.stride[0], destParam.width, destParam.height);
            break;
        default:
            return false;
    }
    return true;
}

static bool CalcRGBStride(PixelFormat format, uint32_t width, int &stride)
{
    switch (format) {
        case PixelFormat::RGB_565:
            stride = static_cast<int>(width * BYTES_PER_PIXEL_RGB565);
            break;
        case PixelFormat::RGBA_8888:
            stride = static_cast<int>(width * BYTES_PER_PIXEL_RGBA);
            break;
        case PixelFormat::RGBA_1010102:
            stride = static_cast<int>(width * BYTES_PER_PIXEL_RGBA);
            break;
        case PixelFormat::RGBA_F16:
            stride = static_cast<int>(width * STRIDES_PER_PLANE);
            break;
        case PixelFormat::BGRA_8888:
            stride = static_cast<int>(width * BYTES_PER_PIXEL_BGRA);
            break;
        case PixelFormat::RGB_888:
            stride = static_cast<int>(width * BYTES_PER_PIXEL_RGB);
            break;
        default:
            return false;
    }
    return true;
}

static void YuvToRGBParam(const YUVDataInfo &yuvInfo, SrcConvertParam &srcParam,
                          DestConvertParam &destParam, DestConvertInfo &destInfo)
{
    srcParam.slice[0] = srcParam.buffer + yuvInfo.yOffset;
    srcParam.slice[1] = srcParam.buffer + yuvInfo.uvOffset;
    srcParam.stride[0] = static_cast<int>(yuvInfo.yStride);
    srcParam.stride[1] = static_cast<int>(yuvInfo.uvStride);
    int dstStride = 0;
    if (destInfo.allocType == AllocatorType::DMA_ALLOC) {
        dstStride = static_cast<int>(destInfo.yStride);
        destParam.slice[0] = destInfo.buffer + destInfo.yOffset;
    } else {
        auto bRet = CalcRGBStride(destParam.format, destParam.width, dstStride);
        if (!bRet) {
            return ;
        }
        destParam.slice[0] = destInfo.buffer;
    }
    destParam.stride[0] = dstStride;
}

static bool I420Param(uint32_t width, uint32_t height, I420Info &i420Info)
{
    i420Info.yStride = width;
    i420Info.uStride = (width + NUM_1) / NUM_2;
    i420Info.vStride = (width + NUM_1) / NUM_2;
    i420Info.uHeight = (height + NUM_1) / NUM_2;

    const uint32_t i420BufferSize = static_cast<size_t>(i420Info.yStride * i420Info.height +
        i420Info.uStride * i420Info.uHeight * NUM_2);
    if (i420BufferSize <= NUM_0 || i420BufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size calculation!");
        return false;
    }
    uint8_t *i420Buffer = new (std::nothrow) uint8_t[i420BufferSize];
    if (i420Buffer == nullptr) {
        IMAGE_LOGE("apply space for I420 buffer failed!");
        return false;
    }
    auto i420UOffset = height * i420Info.yStride;
    auto i420VOffset = i420UOffset + i420Info.uStride * ((height + NUM_1) / NUM_2);
    i420Info.I420Y = i420Buffer;
    i420Info.I420U = i420Buffer + i420UOffset;
    i420Info.I420V = i420Buffer + i420VOffset;
    return true;
}

static bool YuvToI420ToRGBParam(const YUVDataInfo &yuvInfo, SrcConvertParam &srcParam, I420Info &i420Info,
                                DestConvertParam &destParam, DestConvertInfo &destInfo)
{
    YuvToRGBParam(yuvInfo, srcParam, destParam, destInfo);

    return I420Param(yuvInfo.yWidth, yuvInfo.yHeight, i420Info);
}

static bool YuvTo420ToRGB(const uint8_t *srcBuffer, const YUVDataInfo &yuvInfo, PixelFormat srcFormat,
                          DestConvertInfo &destInfo, [[maybe_unused]]ColorSpace colorSpace)
{
    if (srcBuffer == nullptr || destInfo.buffer == nullptr || yuvInfo.yWidth == 0 || yuvInfo.yHeight == 0 ||
        destInfo.bufferSize == 0) {
        return false;
    }
    SrcConvertParam srcParam = {yuvInfo.yWidth, yuvInfo.yHeight};
    srcParam.buffer = srcBuffer;
    srcParam.format = srcFormat;

    DestConvertParam destParam = {destInfo.width, destInfo.height};
    destParam.format = destInfo.format;

    I420Info i420Info = {yuvInfo.yWidth, yuvInfo.yHeight};

    YuvToI420ToRGBParam(yuvInfo, srcParam, i420Info, destParam, destInfo);
    auto bRet = YuvToI420(srcParam, i420Info);
    if (!bRet) {
        delete[] i420Info.I420Y;
        return false;
    }
    bRet = I420ToRGB(i420Info, destParam, colorSpace);
    delete[] i420Info.I420Y;
    return bRet;
}

static bool YuvToRGBConverter(SrcConvertParam &srcParam, DestConvertParam &destParam)
{
    auto &converter = ConverterHandle::GetInstance().GetHandle();
    if (srcParam.format == PixelFormat::NV21) {
        switch (destParam.format) {
            case PixelFormat::RGB_888:
                converter.NV21ToRAW(srcParam.slice[0], srcParam.stride[0], srcParam.slice[1], srcParam.stride[1],
                    destParam.slice[0], destParam.stride[0], destParam.width, destParam.height);
                break;
            case PixelFormat::BGRA_8888:
                converter.NV21ToARGB(srcParam.slice[0], srcParam.stride[0], srcParam.slice[1], srcParam.stride[1],
                    destParam.slice[0], destParam.stride[0], destParam.width, destParam.height);
                break;
            default:
                return false;
        }
    } else if (srcParam.format == PixelFormat::NV12) {
        switch (destParam.format) {
            case PixelFormat::RGB_888:
                converter.NV12ToRAW(srcParam.slice[0], srcParam.stride[0], srcParam.slice[1], srcParam.stride[1],
                    destParam.slice[0], destParam.stride[0], destParam.width, destParam.height);
                break;
            case PixelFormat::BGRA_8888:
                converter.NV12ToARGB(srcParam.slice[0], srcParam.stride[0], srcParam.slice[1], srcParam.stride[1],
                    destParam.slice[0], destParam.stride[0], destParam.width, destParam.height);
                break;
            default:
                return false;
        }
    }
    return true;
}

static bool YuvToRGB(const uint8_t *srcBuffer, const YUVDataInfo &yuvInfo, PixelFormat srcFormat,
                     DestConvertInfo &destInfo, PixelFormat destFormat)
{
    if (srcBuffer == nullptr || destInfo.buffer == nullptr || yuvInfo.yWidth == 0 || yuvInfo.yHeight == 0 ||
        destInfo.bufferSize == 0) {
        return false;
    }
    SrcConvertParam srcParam = {yuvInfo.yWidth, yuvInfo.yHeight};
    srcParam.buffer = srcBuffer;
    srcParam.format = srcFormat;

    DestConvertParam destParam = {destInfo.width, destInfo.height};
    destParam.format = destFormat;

    YuvToRGBParam(yuvInfo, srcParam, destParam, destInfo);
    return YuvToRGBConverter(srcParam, destParam);
}

static bool I010Param(I010Info &i010Info)
{
    i010Info.yStride = i010Info.width;
    i010Info.uStride = (i010Info.width + NUM_1) / NUM_2;
    i010Info.vStride = (i010Info.width + NUM_1) / NUM_2;
    i010Info.uvHeight = ((i010Info.height + NUM_1) / NUM_2);
    const uint32_t i010BufferSize = static_cast<size_t>(i010Info.yStride * i010Info.height +
        i010Info.uStride * i010Info.uvHeight * NUM_2);
    if (i010BufferSize <= NUM_0 || i010BufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size calculation!");
        return false;
    }
    uint16_t *i010Buffer = new (std::nothrow) uint16_t[i010BufferSize];
    if (i010Buffer == nullptr) {
        IMAGE_LOGE("apply space for I420 buffer failed!");
        return false;
    }
    i010Info.I010Y = i010Buffer;
    i010Info.I010U = i010Info.I010Y + i010Info.height * i010Info.yStride;
    i010Info.I010V = i010Info.I010U + i010Info.uStride * ((i010Info.height + NUM_1) / NUM_2);
    return true;
}

static void RGBToYuvP010Param(const RGBDataInfo &rgbInfo, SrcConvertParam &srcParam, DestConvertParam &destParam,
                              DestConvertInfo &destInfo)
{
    srcParam.slice[0] = srcParam.buffer;
    srcParam.stride[0] = static_cast<int>(rgbInfo.stride);
    if (destInfo.allocType == AllocatorType::DMA_ALLOC) {
        destParam.stride[0] = static_cast<int>(destInfo.yStride);
        destParam.stride[1] = static_cast<int>(destInfo.uvStride);
        destParam.slice[0] = destInfo.buffer + destInfo.yOffset;
        destParam.slice[1] = destInfo.buffer + destInfo.uvOffset * TWO_SLICES;
    } else {
        int uvStride = (destParam.width % EVEN_ODD_DIVISOR == 0) ? (destParam.width) : (destParam.width + 1);
        destParam.stride[0] = static_cast<int>(destParam.width);
        destParam.stride[1] = static_cast<int>(uvStride);
        destParam.slice[0] = destInfo.buffer;
        destParam.slice[1] = destInfo.buffer + destParam.width * destParam.height * TWO_SLICES;
    }
}

static bool RGBToI420ToYuvP010Param(const RGBDataInfo &rgbInfo, SrcConvertParam &srcParam, I420Info &i420Info,
                                    DestConvertParam &destParam, DestConvertInfo &destInfo)
{
    RGBToYuvP010Param(rgbInfo, srcParam, destParam, destInfo);

    i420Info.yStride = rgbInfo.width;
    i420Info.uStride = (rgbInfo.width + NUM_1) / NUM_2;
    i420Info.vStride = (rgbInfo.width + NUM_1) / NUM_2;
    i420Info.uvHeight = ((i420Info.height + NUM_1) / NUM_2);
    const uint32_t i420BufferSize = static_cast<size_t>(i420Info.yStride * i420Info.height +
        i420Info.uStride * i420Info.uvHeight * NUM_2);
    if (i420BufferSize <= NUM_0 || i420BufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size calculation!");
        return false;
    }
    uint8_t *i420Buffer = new (std::nothrow) uint8_t[i420BufferSize];
    if (i420Buffer == nullptr) {
        IMAGE_LOGE("apply space for I420 buffer failed!");
        return false;
    }
    i420Info.I420Y = i420Buffer;
    i420Info.I420U = i420Info.I420Y + rgbInfo.height * i420Info.yStride;
    i420Info.I420V = i420Info.I420U + i420Info.uStride * ((rgbInfo.height + NUM_1) / NUM_2);
    return true;
}

static bool RGBToI420ToI010ToP010(const uint8_t *srcBuffer, const RGBDataInfo &rgbInfo, PixelFormat srcFormat,
                                  DestConvertInfo &destInfo, PixelFormat dstFormat)
{
    SrcConvertParam srcParam = {rgbInfo.width, rgbInfo.height};
    srcParam.buffer = srcBuffer;
    srcParam.format = srcFormat;

    DestConvertParam destParam = {rgbInfo.width, rgbInfo.height};
    destParam.format = dstFormat;
    I420Info i420Info = {rgbInfo.width, rgbInfo.height};

    if (!RGBToI420ToYuvP010Param(rgbInfo, srcParam, i420Info, destParam, destInfo)) {
        IMAGE_LOGE("RGB conversion to YUV failed!");
        return false;
    }
    I010Info i010Info = {rgbInfo.width, rgbInfo.height};
    if (!I010Param(i010Info)) {
        IMAGE_LOGE("I010 Param failed!");
        delete[] i420Info.I420Y;
        return false;
    }
    auto bRet = RGBToI420(srcParam, i420Info);
    if (!bRet) {
        IMAGE_LOGE("RGB conversion to I420 failed!");
        delete[] i420Info.I420Y;
        delete[] i010Info.I010Y;
        return false;
    }
    bRet = I420ToI010(i420Info, i010Info);
    if (!bRet) {
        IMAGE_LOGE("I420 conversion to I010 failed!");
        delete[] i420Info.I420Y;
        delete[] i010Info.I010Y;
        return false;
    }
    bRet = I010ToP010(i010Info, destParam);
    if (!bRet) {
        IMAGE_LOGE("I010 conversion to P010 failed!");
        delete[] i420Info.I420Y;
        delete[] i010Info.I010Y;
        return false;
    }
    delete[] i420Info.I420Y;
    delete[] i010Info.I010Y;
    return bRet;
}

static bool RGB10ToI420ToYuv(SrcConvertParam &srcParam, DestConvertParam &midParam,
                             I420Info &i420, DestConvertParam &destParam)
{
    auto &converter = ConverterHandle::GetInstance().GetHandle();
    switch (destParam.format) {
        case PixelFormat::NV12:
            converter.AR30ToARGB(srcParam.slice[0], srcParam.stride[0], midParam.slice[0], midParam.stride[0],
                srcParam.width, srcParam.height);
            converter.ABGRToI420(midParam.slice[0], midParam.stride[0], i420.I420Y, i420.yStride, i420.I420U,
                i420.uStride, i420.I420V, i420.vStride, midParam.width, midParam.height);
            converter.I420ToNV12(i420.I420Y, i420.yStride, i420.I420U, i420.uStride, i420.I420V, i420.vStride,
                destParam.slice[0], destParam.stride[0], destParam.slice[1], destParam.stride[1],
                destParam.width, destParam.height);
            break;
        case PixelFormat::NV21:
            converter.AR30ToARGB(srcParam.slice[0], srcParam.stride[0], midParam.slice[0], midParam.stride[0],
                srcParam.width, srcParam.height);
            converter.ABGRToI420(midParam.slice[0], midParam.stride[0], i420.I420Y, i420.yStride, i420.I420U,
                i420.uStride, i420.I420V, i420.vStride, midParam.width, midParam.height);
            converter.I420ToNV21(i420.I420Y, i420.yStride, i420.I420U, i420.uStride, i420.I420V, i420.vStride,
                destParam.slice[0], destParam.stride[0], destParam.slice[1], destParam.stride[1],
                destParam.width, destParam.height);
            break;
        default:
            return false;
    }
    return true;
}

static bool RGBAParam(DestConvertParam &srcParam)
{
    const uint32_t midBufferSize = static_cast<size_t>(srcParam.width * srcParam.height * BYTES_PER_PIXEL_RGBA);
    if (midBufferSize <= NUM_0 || midBufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size calculation!");
        return false;
    }
    uint8_t *midBuffer = new (std::nothrow) uint8_t[midBufferSize];
    if (midBuffer == nullptr) {
        IMAGE_LOGE("apply space for I420 buffer failed!");
        return false;
    }
    srcParam.buffer = midBuffer;
    srcParam.slice[0] = srcParam.buffer;
    srcParam.stride[0] = static_cast<int>(srcParam.width * BYTES_PER_PIXEL_RGBA);
    return true;
}

static bool RGB10ToRGBToI420Param(const RGBDataInfo &rgbInfo, SrcConvertParam &srcParam, I420Info &i420Info,
                                  DestConvertParam &destParam, DestConvertInfo &destInfo)
{
    RGBToYuvParam(rgbInfo, srcParam, destParam, destInfo);

    i420Info.yStride = rgbInfo.width;
    i420Info.uStride = (rgbInfo.width + NUM_1) / NUM_2;
    i420Info.vStride = (rgbInfo.width + NUM_1) / NUM_2;
    i420Info.uvHeight = ((i420Info.height + NUM_1) / NUM_2);
    const uint32_t i420BufferSize = static_cast<size_t>(i420Info.yStride * i420Info.height +
        i420Info.uStride * i420Info.uvHeight * NUM_2);
    if (i420BufferSize <= NUM_0 || i420BufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size calculation!");
        return false;
    }
    uint8_t *i420Buffer = new (std::nothrow) uint8_t[i420BufferSize];
    if (i420Buffer == nullptr) {
        IMAGE_LOGE("apply space for I420 buffer failed!");
        return false;
    }
    i420Info.I420Y = i420Buffer;
    i420Info.I420U = i420Info.I420Y + rgbInfo.height * i420Info.yStride;
    i420Info.I420V = i420Info.I420U + i420Info.uStride * ((rgbInfo.height + NUM_1) / NUM_2);
    return true;
}

static bool RGB10ToRGBToI420ToYuv(const uint8_t *srcBuffer, const RGBDataInfo &rgbInfo, PixelFormat srcFormat,
                                  DestConvertInfo &destInfo, PixelFormat dstFormat)
{
    SrcConvertParam srcParam = {rgbInfo.width, rgbInfo.height};
    srcParam.buffer = srcBuffer;
    srcParam.format = srcFormat;

    DestConvertParam destParam = {rgbInfo.width, rgbInfo.height};
    destParam.format = dstFormat;

    I420Info i420Info = {rgbInfo.width, rgbInfo.height};

    if (!RGB10ToRGBToI420Param(rgbInfo, srcParam, i420Info, destParam, destInfo)) {
        IMAGE_LOGE("RGB conversion to YUV failed!");
        return false;
    }

    DestConvertParam midParam = {rgbInfo.width, rgbInfo.height};
    if (!RGBAParam(midParam)) {
        IMAGE_LOGE("I010 Param failed!");
        delete[] i420Info.I420Y;
        return false;
    }

    auto bRet = RGB10ToI420ToYuv(srcParam, midParam, i420Info, destParam);
    if (!bRet) {
        IMAGE_LOGE("RGB10 conversion to YUV failed!");
        delete[] i420Info.I420Y;
        delete[] midParam.buffer;
        return false;
    }
    delete[] i420Info.I420Y;
    delete[] midParam.buffer;
    return bRet;
}

static bool I010ToRGB10(I010Info &i010, DestConvertParam &destParam)
{
    auto &converter = ConverterHandle::GetInstance().GetHandle();
    bool ret = converter.I010ToAB30(i010.I010Y, i010.yStride, i010.I010U, i010.uStride, i010.I010V, i010.vStride,
                                    destParam.slice[0], destParam.stride[0], destParam.width, destParam.height);
    if (ret != 0) {
        IMAGE_LOGE("I010ToAB30 failed, ret = %{public}d!", ret);
        return false;
    }
    return true;
}

static bool YuvToI420ToI010ToRGB10(const uint8_t *srcBuffer, const YUVDataInfo &yuvInfo, PixelFormat srcFormat,
                                   DestConvertInfo &destInfo, [[maybe_unused]]ColorSpace colorSpace)
{
    SrcConvertParam srcParam = {yuvInfo.yWidth, yuvInfo.yHeight};
    srcParam.buffer = srcBuffer;
    srcParam.format = srcFormat;

    DestConvertParam destParam = {yuvInfo.yWidth, yuvInfo.yHeight};
    destParam.format = destInfo.format;

    I420Info i420Info = {yuvInfo.yWidth, yuvInfo.yHeight};

    YuvToI420ToRGBParam(yuvInfo, srcParam, i420Info, destParam, destInfo);

    I010Info i010Info = {yuvInfo.yWidth, yuvInfo.yHeight};

    if (!I010Param(i010Info)) {
        IMAGE_LOGE("I010 Param failed!");
        delete[] i420Info.I420Y;
        return false;
    }

    auto bRet = YuvToI420(srcParam, i420Info);
    if (!bRet) {
        IMAGE_LOGE("Yuv conversion to I420 failed!");
        delete[] i420Info.I420Y;
        delete[] i010Info.I010Y;
        return false;
    }

    bRet = I420ToI010(i420Info, i010Info);
    if (!bRet) {
        IMAGE_LOGE("I420 conversion to I010 failed!");
        delete[] i420Info.I420Y;
        delete[] i010Info.I010Y;
        return false;
    }

    bRet = I010ToRGB10(i010Info, destParam);
    if (!bRet) {
        IMAGE_LOGE("I010 conversion to RGB10 failed!");
        delete[] i420Info.I420Y;
        delete[] i010Info.I010Y;
        return false;
    }
    delete[] i420Info.I420Y;
    delete[] i010Info.I010Y;
    return bRet;
}

static bool YuvToP010Param(const YUVDataInfo &yDInfo, SrcConvertParam &srcParam, DestConvertParam &destParam,
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
        destParam.slice[1] = destInfo.buffer + dstyStride * destParam.height  * TWO_SLICES;
    }
    destParam.stride[0] = dstyStride;
    destParam.stride[1] = dstuvStride;
    return true;
}

static bool YuvToI420ToP010Param(const YUVDataInfo &yuvInfo, SrcConvertParam &srcParam, I420Info &i420Info,
                                 DestConvertParam &destParam, DestConvertInfo &destInfo)
{
    YuvToP010Param(yuvInfo, srcParam, destParam, destInfo);
    i420Info.yStride = yuvInfo.yWidth;
    i420Info.uStride = (yuvInfo.yWidth + NUM_1) / NUM_2;
    i420Info.vStride = (yuvInfo.yWidth + NUM_1) / NUM_2;
    i420Info.uvHeight = ((i420Info.height + NUM_1) / NUM_2);
    const uint32_t i420BufferSize = static_cast<size_t>(i420Info.yStride * i420Info.height +
        i420Info.uStride * i420Info.uvHeight * NUM_2);
    if (i420BufferSize <= NUM_0 || i420BufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size calculation!");
        return false;
    }
    uint8_t *i420Buffer = new (std::nothrow) uint8_t[i420BufferSize];
    if (i420Buffer == nullptr) {
        IMAGE_LOGE("apply space for I420 buffer failed!");
        return false;
    }
    i420Info.I420Y = i420Buffer;
    i420Info.I420U = i420Info.I420Y + yuvInfo.yHeight * i420Info.yStride;
    i420Info.I420V = i420Info.I420U + i420Info.uStride * ((yuvInfo.yHeight + NUM_1) / NUM_2);
    return true;
}

static bool YuvToI420ToI010ToP010(const uint8_t *srcBuffer, const YUVDataInfo &yuvInfo, PixelFormat srcFormat,
                                  DestConvertInfo &destInfo, [[maybe_unused]]ColorSpace colorSpace)
{
    SrcConvertParam srcParam = {yuvInfo.yWidth, yuvInfo.yHeight};
    srcParam.buffer = srcBuffer;
    srcParam.format = srcFormat;

    DestConvertParam destParam = {yuvInfo.yWidth, yuvInfo.yHeight};
    destParam.format = destInfo.format;

    I420Info i420Info = {yuvInfo.yWidth, yuvInfo.yHeight};

    YuvToI420ToP010Param(yuvInfo, srcParam, i420Info, destParam, destInfo);

    I010Info i010Info = {yuvInfo.yWidth, yuvInfo.yHeight};

    if (!I010Param(i010Info)) {
        IMAGE_LOGE("I010 Param failed!");
        delete[] i420Info.I420Y;
        return false;
    }

    auto bRet = YuvToI420(srcParam, i420Info);
    if (!bRet) {
        IMAGE_LOGE("Yuv conversion to I420 failed!");
        delete[] i420Info.I420Y;
        delete[] i010Info.I010Y;
        return false;
    }

    bRet = I420ToI010(i420Info, i010Info);
    if (!bRet) {
        IMAGE_LOGE("I420 conversion to I010 failed!");
        delete[] i420Info.I420Y;
        delete[] i010Info.I010Y;
        return false;
    }

    bRet = I010ToP010(i010Info, destParam);
    if (!bRet) {
        IMAGE_LOGE("I010 conversion to P010 failed!");
        delete[] i420Info.I420Y;
        delete[] i010Info.I010Y;
        return false;
    }
    delete[] i420Info.I420Y;
    delete[] i010Info.I010Y;
    return bRet;
}

static bool P010ToI010(SrcConvertParam &srcParam, I010Info &i010)
{
    auto &converter = ConverterHandle::GetInstance().GetHandle();
    switch (srcParam.format) {
        case PixelFormat::YCBCR_P010:
            converter.P010ToI010(reinterpret_cast<const uint16_t *>(srcParam.slice[0]), srcParam.stride[0],
                reinterpret_cast<const uint16_t *>(srcParam.slice[1]), srcParam.stride[1],
                i010.I010Y, i010.yStride, i010.I010U, i010.uStride, i010.I010V, i010.vStride,
                srcParam.width, srcParam.height);
            break;
        case PixelFormat::YCRCB_P010:
            converter.P010ToI010(reinterpret_cast<const uint16_t *>(srcParam.slice[0]), srcParam.stride[0],
                reinterpret_cast<const uint16_t *>(srcParam.slice[1]), srcParam.stride[1],
                i010.I010Y, i010.yStride, i010.I010V, i010.vStride, i010.I010U, i010.uStride,
                srcParam.width, srcParam.height);
            break;
        default:
            return false;
    }
    return true;
}

static bool YuvP010ToYuvParam(const YUVDataInfo &yDInfo, SrcConvertParam &srcParam, DestConvertParam &destParam,
                              DestConvertInfo &destInfo)
{
    srcParam.slice[0] = srcParam.buffer + yDInfo.yOffset;
    srcParam.slice[1] = srcParam.buffer + yDInfo.uvOffset * TWO_SLICES;

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

static bool YuvP010ToI420ToYuvParam(const YUVDataInfo &yuvInfo, SrcConvertParam &srcParam, I420Info &i420Info,
                                    DestConvertParam &destParam, DestConvertInfo &destInfo)
{
    YuvP010ToYuvParam(yuvInfo, srcParam, destParam, destInfo);
    i420Info.yStride = yuvInfo.yWidth;
    i420Info.uStride = (yuvInfo.yWidth + NUM_1) / NUM_2;
    i420Info.vStride = (yuvInfo.yWidth + NUM_1) / NUM_2;
    i420Info.uvHeight = ((i420Info.height + NUM_1) / NUM_2);
    const uint32_t i420BufferSize = static_cast<size_t>(i420Info.yStride * i420Info.height +
        i420Info.uStride * i420Info.uvHeight * NUM_2);
    if (i420BufferSize <= NUM_0 || i420BufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size calculation!");
        return false;
    }
    uint8_t *i420Buffer = new (std::nothrow) uint8_t[i420BufferSize];
    if (i420Buffer == nullptr) {
        IMAGE_LOGE("apply space for I420 buffer failed!");
        return false;
    }
    i420Info.I420Y = i420Buffer;
    i420Info.I420U = i420Info.I420Y + yuvInfo.yHeight * i420Info.yStride;
    i420Info.I420V = i420Info.I420U + i420Info.uStride * ((yuvInfo.yHeight + NUM_1) / NUM_2);
    return true;
}

static bool I010ToI420(I010Info &i010, I420Info &i420)
{
    auto &converter = ConverterHandle::GetInstance().GetHandle();
    converter.I010ToI420(i010.I010Y, i010.yStride, i010.I010U, i010.uStride, i010.I010V, i010.vStride,
        i420.I420Y, i420.yStride, i420.I420U, i420.uStride, i420.I420V, i420.vStride,
        i010.width, i010.height);
    return true;
}

static bool P010ToI010ToI420ToYuv(const uint8_t *srcBuffer, const YUVDataInfo &yuvInfo, PixelFormat srcFormat,
                                  DestConvertInfo &destInfo, [[maybe_unused]]ColorSpace colorSpace)
{
    SrcConvertParam srcParam = {yuvInfo.yWidth, yuvInfo.yHeight};
    srcParam.buffer = srcBuffer;
    srcParam.format = srcFormat;

    DestConvertParam destParam = {yuvInfo.yWidth, yuvInfo.yHeight};
    destParam.format = destInfo.format;

    I420Info i420Info = {yuvInfo.yWidth, yuvInfo.yHeight};

    YuvP010ToI420ToYuvParam(yuvInfo, srcParam, i420Info, destParam, destInfo);

    I010Info i010Info = {yuvInfo.yWidth, yuvInfo.yHeight};

    if (!I010Param(i010Info)) {
        IMAGE_LOGE("I010 Param failed!");
        delete[] i420Info.I420Y;
        return false;
    }

    auto bRet = P010ToI010(srcParam, i010Info);
    if (!bRet) {
        IMAGE_LOGE("P010 conversion to I010 failed!");
        delete[] i420Info.I420Y;
        delete[] i010Info.I010Y;
        return false;
    }

    bRet = I010ToI420(i010Info, i420Info);
    if (!bRet) {
        IMAGE_LOGE("I010 conversion to I420 failed!");
        delete[] i420Info.I420Y;
        delete[] i010Info.I010Y;
        return false;
    }
    bRet = I420ToYuv(i420Info, destParam);
    if (!bRet) {
        IMAGE_LOGE("I420 conversion to Yuv failed!");
        delete[] i420Info.I420Y;
        delete[] i010Info.I010Y;
        return false;
    }
    delete[] i420Info.I420Y;
    delete[] i010Info.I010Y;
    return bRet;
}

static void YuvP010ToRGBParam(const YUVDataInfo &yuvInfo, SrcConvertParam &srcParam,
                              DestConvertParam &destParam, DestConvertInfo &destInfo)
{
    srcParam.slice[0] = srcParam.buffer + yuvInfo.yOffset;
    srcParam.slice[1] = srcParam.buffer + yuvInfo.uvOffset * TWO_SLICES;
    srcParam.stride[0] = static_cast<int>(yuvInfo.yStride);
    srcParam.stride[1] = static_cast<int>(yuvInfo.uvStride);
    int dstStride = 0;
    if (destInfo.allocType == AllocatorType::DMA_ALLOC) {
        dstStride = static_cast<int>(destInfo.yStride);
        destParam.slice[0] = destInfo.buffer + destInfo.yOffset;
    } else {
        auto bRet = CalcRGBStride(destParam.format, destParam.width, dstStride);
        if (!bRet) {
            return;
        }
        destParam.slice[0] = destInfo.buffer;
    }
    destParam.stride[0] = dstStride;
}

static bool YuvP010ToI420ToRGBParam(const YUVDataInfo &yuvInfo, SrcConvertParam &srcParam, I420Info &i420Info,
                                    DestConvertParam &destParam, DestConvertInfo &destInfo)
{
    YuvP010ToRGBParam(yuvInfo, srcParam, destParam, destInfo);
    i420Info.yStride = yuvInfo.yWidth;
    i420Info.uStride = (yuvInfo.yWidth + NUM_1) / NUM_2;
    i420Info.vStride = (yuvInfo.yWidth + NUM_1) / NUM_2;
    i420Info.uvHeight = ((i420Info.height + NUM_1) / NUM_2);
    const uint32_t i420BufferSize = static_cast<size_t>(i420Info.yStride * i420Info.height +
        i420Info.uStride * i420Info.uvHeight * NUM_2);
    if (i420BufferSize <= NUM_0 || i420BufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size calculation!");
        return false;
    }
    uint8_t *i420Buffer = new (std::nothrow) uint8_t[i420BufferSize];
    if (i420Buffer == nullptr) {
        IMAGE_LOGE("apply space for I420 buffer failed!");
        return false;
    }
    i420Info.I420Y = i420Buffer;
    i420Info.I420U = i420Info.I420Y + yuvInfo.yHeight * i420Info.yStride;
    i420Info.I420V = i420Info.I420U + i420Info.uStride * ((yuvInfo.yHeight + NUM_1) / NUM_2);
    return true;
}

static bool P010ToI010ToI420ToRGB(const uint8_t *srcBuffer, const YUVDataInfo &yuvInfo, PixelFormat srcFormat,
                                  DestConvertInfo &destInfo, [[maybe_unused]]ColorSpace colorSpace)
{
    SrcConvertParam srcParam = {yuvInfo.yWidth, yuvInfo.yHeight};
    srcParam.buffer = srcBuffer;
    srcParam.format = srcFormat;

    DestConvertParam destParam = {yuvInfo.yWidth, yuvInfo.yHeight};
    destParam.format = destInfo.format;

    I420Info i420Info = {yuvInfo.yWidth, yuvInfo.yHeight};

    YuvP010ToI420ToRGBParam(yuvInfo, srcParam, i420Info, destParam, destInfo);

    I010Info i010Info = {yuvInfo.yWidth, yuvInfo.yHeight};

    if (!I010Param(i010Info)) {
        IMAGE_LOGE("I010 Param failed!");
        delete[] i420Info.I420Y;
        return false;
    }

    auto bRet = P010ToI010(srcParam, i010Info);
    if (!bRet) {
        IMAGE_LOGE("P010 conversion to I010 failed!");
        delete[] i420Info.I420Y;
        delete[] i010Info.I010Y;
        return false;
    }

    bRet = I010ToI420(i010Info, i420Info);
    if (!bRet) {
        IMAGE_LOGE("I010 conversion to I420 failed!");
        delete[] i420Info.I420Y;
        delete[] i010Info.I010Y;
        return false;
    }
    bRet = I420ToRGB(i420Info, destParam, colorSpace);
    if (!bRet) {
        IMAGE_LOGE("I420 conversion to RGB failed!");
        delete[] i420Info.I420Y;
        delete[] i010Info.I010Y;
        return false;
    }
    delete[] i420Info.I420Y;
    delete[] i010Info.I010Y;
    return bRet;
}

static bool P010ToI010ToRGB10Param(const YUVDataInfo &yuvInfo, SrcConvertParam &srcParam, I010Info &i010Info,
                                   DestConvertParam &destParam, DestConvertInfo &destInfo)
{
    YuvP010ToRGBParam(yuvInfo, srcParam, destParam, destInfo);
    i010Info.yStride = yuvInfo.yWidth;
    i010Info.uStride = (yuvInfo.yWidth + NUM_1) / NUM_2;
    i010Info.vStride = (yuvInfo.yWidth + NUM_1) / NUM_2;
    i010Info.uvHeight = ((i010Info.height + NUM_1) / NUM_2);
    const uint32_t i010BufferSize = static_cast<size_t>(i010Info.yStride * i010Info.height +
        i010Info.uStride * i010Info.uvHeight * NUM_2);
    if (i010BufferSize <= NUM_0 || i010BufferSize > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("Invalid destination buffer size calculation!");
        return false;
    }
    uint16_t *i010Buffer = new (std::nothrow) uint16_t[i010BufferSize];
    if (i010Buffer == nullptr) {
        IMAGE_LOGE("apply space for I420 buffer failed!");
        return false;
    }
    i010Info.I010Y = i010Buffer;
    i010Info.I010U = i010Info.I010Y + yuvInfo.yHeight * i010Info.yStride;
    i010Info.I010V = i010Info.I010U + i010Info.uStride * ((yuvInfo.yHeight + NUM_1) / NUM_2);
    return true;
}

static bool P010ToI010ToRGB10(const uint8_t *srcBuffer, const YUVDataInfo &yuvInfo, PixelFormat srcFormat,
                              DestConvertInfo &destInfo, [[maybe_unused]]ColorSpace colorSpace)
{
    SrcConvertParam srcParam = {yuvInfo.yWidth, yuvInfo.yHeight};
    srcParam.buffer = srcBuffer;
    srcParam.format = srcFormat;

    DestConvertParam destParam = {yuvInfo.yWidth, yuvInfo.yHeight};
    destParam.format = destInfo.format;

    I010Info i010Info = {yuvInfo.yWidth, yuvInfo.yHeight};

    P010ToI010ToRGB10Param(yuvInfo, srcParam, i010Info, destParam, destInfo);

    auto bRet = P010ToI010(srcParam, i010Info);
    if (!bRet) {
        IMAGE_LOGE("P010 conversion to I010 failed!");
        delete[] i010Info.I010Y;
        return false;
    }

    bRet = I010ToRGB10(i010Info, destParam);
    if (!bRet) {
        IMAGE_LOGE("I010 conversion to RGB10 failed!");
        delete[] i010Info.I010Y;
        return false;
    }
    delete[] i010Info.I010Y;
    return bRet;
}

bool ImageFormatConvertExtUtils::RGB565ToNV12P010(const uint8_t *srcBuffer, const RGBDataInfo &rgbInfo,
                                                  DestConvertInfo &destInfo, [[maybe_unused]]ColorSpace colorSpace)
{
    return RGBToI420ToI010ToP010(srcBuffer, rgbInfo, PixelFormat::RGB_565, destInfo, PixelFormat::YCBCR_P010);
}

bool ImageFormatConvertExtUtils::RGB565ToNV21P010(const uint8_t *srcBuffer, const RGBDataInfo &rgbInfo,
                                                  DestConvertInfo &destInfo, [[maybe_unused]]ColorSpace colorSpace)
{
    return RGBToI420ToI010ToP010(srcBuffer, rgbInfo, PixelFormat::RGB_565, destInfo, PixelFormat::YCRCB_P010);
}

bool ImageFormatConvertExtUtils::RGBAToNV12P010(const uint8_t *srcBuffer, const RGBDataInfo &rgbInfo,
                                                DestConvertInfo &destInfo, [[maybe_unused]]ColorSpace colorSpace)
{
    return RGBToI420ToI010ToP010(srcBuffer, rgbInfo, PixelFormat::RGBA_8888, destInfo, PixelFormat::YCBCR_P010);
}

bool ImageFormatConvertExtUtils::RGBAToNV21P010(const uint8_t *srcBuffer, const RGBDataInfo &rgbInfo,
                                                DestConvertInfo &destInfo, [[maybe_unused]]ColorSpace colorSpace)
{
    return RGBToI420ToI010ToP010(srcBuffer, rgbInfo, PixelFormat::RGBA_8888, destInfo, PixelFormat::YCRCB_P010);
}

bool ImageFormatConvertExtUtils::BGRAToNV12P010(const uint8_t *srcBuffer, const RGBDataInfo &rgbInfo,
                                                DestConvertInfo &destInfo, [[maybe_unused]]ColorSpace colorSpace)
{
    return RGBToI420ToI010ToP010(srcBuffer, rgbInfo, PixelFormat::RGBA_8888, destInfo, PixelFormat::YCBCR_P010);
}

bool ImageFormatConvertExtUtils::BGRAToNV21P010(const uint8_t *srcBuffer, const RGBDataInfo &rgbInfo,
                                                DestConvertInfo &destInfo, [[maybe_unused]]ColorSpace colorSpace)
{
    return RGBToI420ToI010ToP010(srcBuffer, rgbInfo, PixelFormat::RGBA_8888, destInfo, PixelFormat::YCRCB_P010);
}

bool ImageFormatConvertExtUtils::RGBToNV12P010(const uint8_t *srcBuffer, const RGBDataInfo &rgbInfo,
                                               DestConvertInfo &destInfo, [[maybe_unused]]ColorSpace colorSpace)
{
    return RGBToI420ToI010ToP010(srcBuffer, rgbInfo, PixelFormat::RGB_888, destInfo, PixelFormat::YCBCR_P010);
}

bool ImageFormatConvertExtUtils::RGBToNV21P010(const uint8_t *srcBuffer, const RGBDataInfo &rgbInfo,
                                               DestConvertInfo &destInfo, [[maybe_unused]]ColorSpace colorSpace)
{
    return RGBToI420ToI010ToP010(srcBuffer, rgbInfo, PixelFormat::RGB_888, destInfo, PixelFormat::YCRCB_P010);
}

bool ImageFormatConvertExtUtils::RGBA1010102ToNV12(const uint8_t *srcBuffer, const RGBDataInfo &rgbInfo,
                                                   DestConvertInfo &destInfo, [[maybe_unused]]ColorSpace colorSpace)
{
    return RGB10ToRGBToI420ToYuv(srcBuffer, rgbInfo, PixelFormat::RGBA_1010102, destInfo, PixelFormat::NV12);
}

bool ImageFormatConvertExtUtils::RGBA1010102ToNV21(const uint8_t *srcBuffer, const RGBDataInfo &rgbInfo,
                                                   DestConvertInfo &destInfo, [[maybe_unused]]ColorSpace colorSpace)
{
    return RGB10ToRGBToI420ToYuv(srcBuffer, rgbInfo, PixelFormat::RGBA_1010102, destInfo, PixelFormat::NV21);
}

bool ImageFormatConvertExtUtils::NV12ToRGBA1010102(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                                   DestConvertInfo &destInfo, [[maybe_unused]]ColorSpace colorSpace)
{
    return YuvToI420ToI010ToRGB10(srcBuffer, yDInfo, PixelFormat::NV12, destInfo, colorSpace);
}

bool ImageFormatConvertExtUtils::NV21ToRGBA1010102(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                                   DestConvertInfo &destInfo, [[maybe_unused]]ColorSpace colorSpace)
{
    return YuvToI420ToI010ToRGB10(srcBuffer, yDInfo, PixelFormat::NV12, destInfo, colorSpace);
}

bool ImageFormatConvertExtUtils::NV12ToNV12P010(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                                DestConvertInfo &destInfo, [[maybe_unused]]ColorSpace colorSpace)
{
    return YuvToI420ToI010ToP010(srcBuffer, yDInfo, PixelFormat::NV12, destInfo, colorSpace);
}

bool ImageFormatConvertExtUtils::NV12ToNV21P010(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                                DestConvertInfo &destInfo, [[maybe_unused]]ColorSpace colorSpace)
{
    return YuvToI420ToI010ToP010(srcBuffer, yDInfo, PixelFormat::NV12, destInfo, colorSpace);
}

bool ImageFormatConvertExtUtils::NV21ToNV12P010(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                                DestConvertInfo &destInfo, [[maybe_unused]]ColorSpace colorSpace)
{
    return YuvToI420ToI010ToP010(srcBuffer, yDInfo, PixelFormat::NV21, destInfo, colorSpace);
}

bool ImageFormatConvertExtUtils::NV21ToNV21P010(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                                DestConvertInfo &destInfo, [[maybe_unused]]ColorSpace colorSpace)
{
    return YuvToI420ToI010ToP010(srcBuffer, yDInfo, PixelFormat::NV21, destInfo, colorSpace);
}

bool ImageFormatConvertExtUtils::NV12P010ToNV12(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                                DestConvertInfo &destInfo, [[maybe_unused]]ColorSpace colorSpace)
{
    return P010ToI010ToI420ToYuv(srcBuffer, yDInfo, PixelFormat::YCBCR_P010, destInfo, colorSpace);
}

bool ImageFormatConvertExtUtils::NV12P010ToNV21(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                                DestConvertInfo &destInfo, [[maybe_unused]]ColorSpace colorSpace)
{
    return P010ToI010ToI420ToYuv(srcBuffer, yDInfo, PixelFormat::YCBCR_P010, destInfo, colorSpace);
}

bool ImageFormatConvertExtUtils::NV12P010ToRGB565(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                                  DestConvertInfo &destInfo, [[maybe_unused]]ColorSpace colorSpace)
{
    return P010ToI010ToI420ToRGB(srcBuffer, yDInfo, PixelFormat::YCBCR_P010, destInfo, colorSpace);
}

bool ImageFormatConvertExtUtils::NV12P010ToRGBA8888(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                                    DestConvertInfo &destInfo, [[maybe_unused]]ColorSpace colorSpace)
{
    return P010ToI010ToI420ToRGB(srcBuffer, yDInfo, PixelFormat::YCBCR_P010, destInfo, colorSpace);
}

bool ImageFormatConvertExtUtils::NV12P010ToBGRA8888(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                                    DestConvertInfo &destInfo, [[maybe_unused]]ColorSpace colorSpace)
{
    return P010ToI010ToI420ToRGB(srcBuffer, yDInfo, PixelFormat::YCBCR_P010, destInfo, colorSpace);
}

bool ImageFormatConvertExtUtils::NV12P010ToRGB888(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                                  DestConvertInfo &destInfo, [[maybe_unused]]ColorSpace colorSpace)
{
    return P010ToI010ToI420ToRGB(srcBuffer, yDInfo, PixelFormat::YCBCR_P010, destInfo, colorSpace);
}

bool ImageFormatConvertExtUtils::NV21P010ToNV12(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                                DestConvertInfo &destInfo, [[maybe_unused]]ColorSpace colorSpace)
{
    return P010ToI010ToI420ToYuv(srcBuffer, yDInfo, PixelFormat::YCRCB_P010, destInfo, colorSpace);
}

bool ImageFormatConvertExtUtils::NV21P010ToNV21(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                                DestConvertInfo &destInfo, [[maybe_unused]]ColorSpace colorSpace)
{
    return P010ToI010ToI420ToYuv(srcBuffer, yDInfo, PixelFormat::YCRCB_P010, destInfo, colorSpace);
}

bool ImageFormatConvertExtUtils::NV12P010ToRGBA1010102(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                                       DestConvertInfo &destInfo,
                                                       [[maybe_unused]]ColorSpace colorSpace)
{
    return P010ToI010ToRGB10(srcBuffer, yDInfo, PixelFormat::YCBCR_P010, destInfo, colorSpace);
}

bool ImageFormatConvertExtUtils::NV21P010ToRGB565(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                                  DestConvertInfo &destInfo, [[maybe_unused]]ColorSpace colorSpace)
{
    return P010ToI010ToI420ToRGB(srcBuffer, yDInfo, PixelFormat::YCRCB_P010, destInfo, colorSpace);
}

bool ImageFormatConvertExtUtils::NV21P010ToRGBA8888(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                                    DestConvertInfo &destInfo, [[maybe_unused]]ColorSpace colorSpace)
{
    return P010ToI010ToI420ToRGB(srcBuffer, yDInfo, PixelFormat::YCRCB_P010, destInfo, colorSpace);
}

bool ImageFormatConvertExtUtils::NV21P010ToBGRA8888(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                                    DestConvertInfo &destInfo, [[maybe_unused]]ColorSpace colorSpace)
{
    return P010ToI010ToI420ToRGB(srcBuffer, yDInfo, PixelFormat::YCRCB_P010, destInfo, colorSpace);
}

bool ImageFormatConvertExtUtils::NV21P010ToRGB888(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                                  DestConvertInfo &destInfo, [[maybe_unused]]ColorSpace colorSpace)
{
    return P010ToI010ToI420ToRGB(srcBuffer, yDInfo, PixelFormat::YCRCB_P010, destInfo, colorSpace);
}

bool ImageFormatConvertExtUtils::NV21P010ToRGBA1010102(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                                       DestConvertInfo &destInfo,
                                                       [[maybe_unused]]ColorSpace colorSpace)
{
    return P010ToI010ToRGB10(srcBuffer, yDInfo, PixelFormat::YCRCB_P010, destInfo, colorSpace);
}

static bool RGBToI420ToYuv(const uint8_t *srcBuffer, const RGBDataInfo &rgbInfo, PixelFormat srcFormat,
                           DestConvertInfo &destInfo, PixelFormat destFormat)
{
    if (srcBuffer == nullptr || destInfo.buffer == nullptr || rgbInfo.width == 0 || rgbInfo.height == 0 ||
        destInfo.bufferSize == 0) {
        return false;
    }
    SrcConvertParam srcParam = {rgbInfo.width, rgbInfo.height};
    srcParam.buffer = srcBuffer;
    srcParam.format = srcFormat;

    DestConvertParam destParam = {destInfo.width, destInfo.height};
    destParam.format = destFormat;

    I420Info i420Info = {rgbInfo.width, rgbInfo.height};
    if (!RGBToI420ToYuvParam(rgbInfo, srcParam, i420Info, destParam, destInfo)) {
        IMAGE_LOGE("RGB conversion to YUV failed!");
        return false;
    }
    auto bRet = RGBToI420(srcParam, i420Info);
    if (!bRet) {
        delete[] i420Info.I420Y;
        return false;
    }
    bRet = I420ToYuv(i420Info, destParam);
    delete[] i420Info.I420Y;
    return bRet;
}

static bool RGBToYuvConverter(SrcConvertParam &srcParam, DestConvertParam &destParam)
{
    if (srcParam.format != PixelFormat::BGRA_8888) {
        return false;
    }
    auto &converter = ConverterHandle::GetInstance().GetHandle();
    switch (destParam.format) {
        case PixelFormat::NV12:
            converter.ARGBToNV12(srcParam.slice[0], srcParam.stride[0],
                destParam.slice[0], destParam.stride[0], destParam.slice[1], destParam.stride[1],
                destParam.width, destParam.height);
            break;
        case PixelFormat::NV21:
            converter.ARGBToNV21(srcParam.slice[0], srcParam.stride[0],
                destParam.slice[0], destParam.stride[0], destParam.slice[1], destParam.stride[1],
                destParam.width, destParam.height);
            break;
        default:
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
    srcParam.buffer = srcBuffer;
    srcParam.format = srcFormat;

    DestConvertParam destParam = {destInfo.width, destInfo.height};
    destParam.format = destFormat;

    RGBToYuvParam(rgbInfo, srcParam, destParam, destInfo);
    return RGBToYuvConverter(srcParam, destParam);
}

bool ImageFormatConvertExtUtils::BGRAToNV21(const uint8_t *srcBuffer, const RGBDataInfo &rgbInfo,
                                            DestConvertInfo &destInfo,
                                            [[maybe_unused]] ColorSpace colorSpace)
{
    return RGBToYuv(srcBuffer, rgbInfo, PixelFormat::BGRA_8888, destInfo, PixelFormat::NV21);
}

bool ImageFormatConvertExtUtils::BGRAToNV12(const uint8_t *srcBuffer, const RGBDataInfo &rgbInfo,
                                            DestConvertInfo &destInfo,
                                            [[maybe_unused]] ColorSpace colorSpace)
{
    return RGBToYuv(srcBuffer, rgbInfo, PixelFormat::BGRA_8888, destInfo, PixelFormat::NV12);
}

bool ImageFormatConvertExtUtils::RGB565ToNV21(const uint8_t *srcBuffer, const RGBDataInfo &rgbInfo,
                                              DestConvertInfo &destInfo,
                                              [[maybe_unused]] ColorSpace colorSpace)
{
    return RGBToI420ToYuv(srcBuffer, rgbInfo, PixelFormat::RGB_565, destInfo, PixelFormat::NV21);
}

bool ImageFormatConvertExtUtils::RGB565ToNV12(const uint8_t *srcBuffer, const RGBDataInfo &rgbInfo,
                                              DestConvertInfo &destInfo,
                                              [[maybe_unused]] ColorSpace colorSpace)
{
    return RGBToI420ToYuv(srcBuffer, rgbInfo, PixelFormat::RGB_565, destInfo, PixelFormat::NV12);
}

bool ImageFormatConvertExtUtils::RGBToNV21(const uint8_t *srcBuffer, const RGBDataInfo &rgbInfo,
                                           DestConvertInfo &destInfo,
                                           [[maybe_unused]] ColorSpace colorSpace)
{
    return RGBToI420ToYuv(srcBuffer, rgbInfo, PixelFormat::RGB_888, destInfo, PixelFormat::NV21);
}

bool ImageFormatConvertExtUtils::RGBToNV12(const uint8_t *srcBuffer, const RGBDataInfo &rgbInfo,
                                           DestConvertInfo &destInfo,
                                           [[maybe_unused]] ColorSpace colorSpace)
{
    return RGBToI420ToYuv(srcBuffer, rgbInfo, PixelFormat::RGB_888, destInfo, PixelFormat::NV12);
}

bool ImageFormatConvertExtUtils::RGBAToNV21(const uint8_t *srcBuffer, const RGBDataInfo &rgbInfo,
                                            DestConvertInfo &destInfo,
                                            [[maybe_unused]] ColorSpace colorSpace)
{
    return RGBToI420ToYuv(srcBuffer, rgbInfo, PixelFormat::RGBA_8888, destInfo, PixelFormat::NV21);
}

bool ImageFormatConvertExtUtils::RGBAToNV12(const uint8_t *srcBuffer, const RGBDataInfo &rgbInfo,
                                            DestConvertInfo &destInfo,
                                            [[maybe_unused]] ColorSpace colorSpace)
{
    return RGBToI420ToYuv(srcBuffer, rgbInfo, PixelFormat::RGBA_8888, destInfo, PixelFormat::NV12);
}

bool ImageFormatConvertExtUtils::NV21ToRGB(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                           DestConvertInfo &destInfo,
                                           [[maybe_unused]]ColorSpace colorSpace)
{
    return YuvToRGB(srcBuffer, yDInfo, PixelFormat::NV21, destInfo, PixelFormat::RGB_888);
}

bool ImageFormatConvertExtUtils::NV12ToRGB(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                           DestConvertInfo &destInfo,
                                           [[maybe_unused]]ColorSpace colorSpace)
{
    return YuvToRGB(srcBuffer, yDInfo, PixelFormat::NV12, destInfo, PixelFormat::RGB_888);
}

bool ImageFormatConvertExtUtils::NV21ToRGBA(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                            DestConvertInfo &destInfo,
                                            [[maybe_unused]]ColorSpace colorSpace)
{
    destInfo.format = PixelFormat::RGBA_8888;
    return YuvTo420ToRGB(srcBuffer, yDInfo, PixelFormat::NV21, destInfo, colorSpace);
}

bool ImageFormatConvertExtUtils::NV12ToRGBA(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                            DestConvertInfo &destInfo,
                                            [[maybe_unused]]ColorSpace colorSpace)
{
    destInfo.format = PixelFormat::RGBA_8888;
    return YuvTo420ToRGB(srcBuffer, yDInfo, PixelFormat::NV12, destInfo, colorSpace);
}

bool ImageFormatConvertExtUtils::NV21ToBGRA(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                            DestConvertInfo &destInfo,
                                            [[maybe_unused]]ColorSpace colorSpace)
{
    return YuvToRGB(srcBuffer, yDInfo, PixelFormat::NV21, destInfo, PixelFormat::BGRA_8888);
}

bool ImageFormatConvertExtUtils::NV12ToBGRA(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                            DestConvertInfo &destInfo,
                                            [[maybe_unused]]ColorSpace colorSpace)
{
    return YuvToRGB(srcBuffer, yDInfo, PixelFormat::NV12, destInfo, PixelFormat::BGRA_8888);
}

bool ImageFormatConvertExtUtils::NV21ToRGB565(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                              DestConvertInfo &destInfo,
                                              [[maybe_unused]]ColorSpace colorSpace)
{
    destInfo.format = PixelFormat::RGB_565;
    return YuvTo420ToRGB(srcBuffer, yDInfo, PixelFormat::NV21, destInfo, colorSpace);
}

bool ImageFormatConvertExtUtils::NV12ToRGB565(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo,
                                              DestConvertInfo &destInfo,
                                              [[maybe_unused]]ColorSpace colorSpace)
{
    destInfo.format = PixelFormat::RGB_565;
    return YuvTo420ToRGB(srcBuffer, yDInfo, PixelFormat::NV12, destInfo, colorSpace);
}
} // namespace Media
} // namespace OHOS