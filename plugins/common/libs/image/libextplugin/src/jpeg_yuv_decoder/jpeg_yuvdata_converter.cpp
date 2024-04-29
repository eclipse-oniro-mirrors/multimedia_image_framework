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

#include "jpeg_yuvdata_converter.h"

#include <algorithm>

#include "jpeg_decoder_yuv.h"
#include "securec.h"

namespace OHOS {
namespace ImagePlugin {

#define EVEN_MASK 1
#define AVERAGE_FACTOR 2

#define SAMPLE_FACTOR420 2
#define MAXUVSCALE_JPEG 4

#define SCALE_444_X 1
#define SCALE_444_Y 1
#define SCALE_422_X 2
#define SCALE_422_Y 1
#define SCALE_420_X 2
#define SCALE_420_Y 2
#define SCALE_440_X 1
#define SCALE_440_Y 2
#define SCALE_411_X 4
#define SCALE_411_Y 1

static bool IsValidYuvData(const YuvPlaneInfo &data)
{
    if (data.planes[YCOM] == nullptr || data.planes[UCOM] == nullptr || data.planes[VCOM] == nullptr ||
        data.strides[YCOM] == 0 || data.strides[UCOM] == 0 || data.strides[VCOM] == 0) {
        return false;
    } else {
        return true;
    }
}

static bool IsValidYuvNVData(const YuvPlaneInfo &data)
{
    if (data.planes[YCOM] == nullptr || data.planes[UVCOM] == nullptr ||
        data.strides[YCOM] == 0 || data.strides[UVCOM] == 0) {
        return false;
    } else {
        return true;
    }
}

static bool IsValidYuvGrayData(const YuvPlaneInfo &data)
{
    if (data.planes[YCOM] == nullptr || data.strides[YCOM] == 0) {
        return false;
    } else {
        return true;
    }
}

static bool IsValidSize(uint32_t width, uint32_t height)
{
    if (width == 0 || height == 0) {
        return false;
    } else {
        return true;
    }
}

static bool IsValidScaleFactor(uint8_t factor)
{
    if (factor > MAXUVSCALE_JPEG || factor == 0) {
        return false;
    } else {
        return true;
    }
}

static bool CopyLineData(uint8_t *dest, uint32_t destStride, const uint8_t *src, uint32_t srcStride)
{
    if (srcStride == 0 || destStride == 0) {
        return false;
    }
    errno_t ret = memcpy_s(dest, destStride, src, std::min(srcStride, destStride));
    if (ret != EOK) {
        return false;
    }
    if (destStride > srcStride) {
        int count = destStride - srcStride;
        uint8_t lastValueinCurrentSrcLine = *(src + srcStride - 1);
        ret = memset_s(dest + srcStride, count, lastValueinCurrentSrcLine, count);
        if (ret != EOK) {
            return false;
        }
    }
    return true;
}

static uint8_t SampleUV(const uint8_t* srcUV, int stride, bool canUseNextRow, bool canUseNextColumn)
{
    const uint8_t* srcUVNextLine = nullptr;
    if (canUseNextRow) {
        srcUVNextLine = srcUV + stride;
    }
    if (srcUVNextLine != nullptr) {
        return (*srcUV + *srcUVNextLine) / AVERAGE_FACTOR;
    }
    if (canUseNextColumn) {
        return (*srcUV + *(srcUV + 1)) / AVERAGE_FACTOR;
    }
    return *srcUV;
}

static bool VerifyParameter(const YuvPlaneInfo &src, const YuvPlaneInfo &dest,
                            uint8_t srcXScale, uint8_t srcYScale, bool outYU12)
{
    uint32_t width = src.imageWidth;
    uint32_t height = src.imageHeight;
    if (!IsValidYuvData(src) || !IsValidSize(width, height) ||
        !IsValidScaleFactor(srcXScale) || !IsValidScaleFactor(srcYScale)) {
        return false;
    }
    if (outYU12 && !IsValidYuvData(dest)) {
        return false;
    } else if (!outYU12 && !IsValidYuvNVData(dest)) {
        return false;
    }
    return true;
}

static bool CopyYData(const YuvPlaneInfo &src, const YuvPlaneInfo &dest)
{
    uint32_t height = src.imageHeight;
    const uint8_t* srcY = nullptr;
    for (uint32_t k = 0; k < height; k++) {
        srcY = src.planes[YCOM] + k * src.strides[YCOM];
        uint8_t* outY = dest.planes[YCOM] + k * dest.strides[YCOM];
        bool ret = CopyLineData(outY, dest.strides[YCOM], srcY, src.strides[YCOM]);
        if (!ret) {
            return false;
        }
    }
    if (dest.planeHeight[YCOM] > height && srcY) {
        uint8_t* outY = dest.planes[YCOM] + height * dest.strides[YCOM];
        bool ret = CopyLineData(outY, dest.strides[YCOM], srcY, src.strides[YCOM]);
        if (!ret) {
            return false;
        }
    }
    return true;
}

int I4xxToI420_c(const YuvPlaneInfo &src, const YuvPlaneInfo &dest,
                 uint8_t srcXScale, uint8_t srcYScale, bool outfmtIsYU12)
{
    if (!VerifyParameter(src, dest, srcXScale, srcYScale, outfmtIsYU12)) {
        return -1;
    }
    if (!CopyYData(src, dest)) {
        return -1;
    }
    if (srcYScale == 0) {
        return -1;
    }
    for (uint32_t k = 0; k < src.imageHeight; k += SAMPLE_FACTOR420) {
        const uint8_t* srcU = src.planes[UCOM] + k / srcYScale * src.strides[UCOM];
        const uint8_t* srcV = src.planes[VCOM] + k / srcYScale * src.strides[VCOM];
        uint8_t* outU = nullptr;
        uint8_t* outV = nullptr;
        uint8_t* outVU = nullptr;
        if (outfmtIsYU12) {
            outU = dest.planes[UCOM] + k / SAMPLE_FACTOR420 * dest.strides[UCOM];
            outV = dest.planes[VCOM] + k / SAMPLE_FACTOR420 * dest.strides[VCOM];
            if (srcXScale == SAMPLE_FACTOR420 && srcYScale >= SAMPLE_FACTOR420) {
                CopyLineData(outU, dest.strides[UCOM], srcU, src.strides[UCOM]);
                CopyLineData(outV, dest.strides[VCOM], srcV, src.strides[VCOM]);
                continue;
            }
        } else {
            outVU = dest.planes[UVCOM] + k / SAMPLE_FACTOR420 * dest.strides[UVCOM];
        }
        bool canUseNextRow = false;
        if (srcYScale < SAMPLE_FACTOR420 && k != src.planeHeight[UCOM] - 1) {
            canUseNextRow = true;
        }
        for (uint32_t j = 0; j < src.imageWidth; j++) {
            if ((j & EVEN_MASK) == 0 && outfmtIsYU12) {
                bool canUseNextColumn = ((j != src.imageWidth - 1) && (srcXScale < SAMPLE_FACTOR420));
                *outU++ = SampleUV(srcU, src.strides[UCOM], canUseNextRow, canUseNextColumn);
                *outV++ = SampleUV(srcV, src.strides[VCOM], canUseNextRow, canUseNextColumn);
            } else if ((j & EVEN_MASK) == 0) {
                bool canUseNextColumn = ((j != src.imageWidth - 1) && (srcXScale < SAMPLE_FACTOR420));
                *outVU++ = SampleUV(srcV, src.strides[VCOM], canUseNextRow, canUseNextColumn);
                *outVU++ = SampleUV(srcU, src.strides[UCOM], canUseNextRow, canUseNextColumn);
            }
            if (((j + 1) % srcXScale) == 0) {
                srcU++;
                srcV++;
            }
        }
    }
    return 0;
}

int I444ToI420_wrapper(const YuvPlaneInfo &src, const YuvPlaneInfo &dest)
{
    if (JpegDecoderYuv::GetLibyuvConverter().I444ToI420) {
        uint32_t width = src.imageWidth;
        uint32_t height = src.imageHeight;
        if (!IsValidYuvData(src) || !IsValidYuvData(dest) || !IsValidSize(width, height)) {
            return -1;
        }
        return JpegDecoderYuv::GetLibyuvConverter().I444ToI420(src.planes[YCOM], src.strides[YCOM], src.planes[UCOM],
            src.strides[UCOM], src.planes[VCOM], src.strides[VCOM], dest.planes[YCOM], dest.strides[YCOM],
            dest.planes[UCOM], dest.strides[UCOM], dest.planes[VCOM], dest.strides[VCOM], width, height);
    } else {
        return I4xxToI420_c(src, dest, SCALE_444_X, SCALE_444_Y, true);
    }
}

int I444ToNV21_wrapper(const YuvPlaneInfo &src, const YuvPlaneInfo &dest)
{
    if (JpegDecoderYuv::GetLibyuvConverter().I444ToNV21) {
        uint32_t width = src.imageWidth;
        uint32_t height = src.imageHeight;
        if (!IsValidYuvData(src) || !IsValidYuvNVData(dest) || !IsValidSize(width, height)) {
            return -1;
        }
        return JpegDecoderYuv::GetLibyuvConverter().I444ToNV21(src.planes[YCOM], src.strides[YCOM], src.planes[UCOM],
            src.strides[UCOM], src.planes[VCOM], src.strides[VCOM], dest.planes[YCOM], dest.strides[YCOM],
            dest.planes[UVCOM], dest.strides[UVCOM], width, height);
    } else {
        return I4xxToI420_c(src, dest, SCALE_444_X, SCALE_444_Y, false);
    }
}

int I422ToI420_wrapper(const YuvPlaneInfo &src, const YuvPlaneInfo &dest)
{
    if (JpegDecoderYuv::GetLibyuvConverter().I422ToI420) {
        uint32_t width = src.imageWidth;
        uint32_t height = src.imageHeight;
        if (!IsValidYuvData(src) || !IsValidYuvData(dest) || !IsValidSize(width, height)) {
            return -1;
        }
        return JpegDecoderYuv::GetLibyuvConverter().I422ToI420(src.planes[YCOM], src.strides[YCOM], src.planes[UCOM],
            src.strides[UCOM], src.planes[VCOM], src.strides[VCOM], dest.planes[YCOM], dest.strides[YCOM],
            dest.planes[UCOM], dest.strides[UCOM], dest.planes[VCOM], dest.strides[VCOM], width, height);
    } else {
        return I4xxToI420_c(src, dest, SCALE_422_X, SCALE_422_Y, true);
    }
}

int I422ToNV21_wrapper(const YuvPlaneInfo &src, const YuvPlaneInfo &dest)
{
    if (JpegDecoderYuv::GetLibyuvConverter().I422ToNV21) {
        uint32_t width = src.imageWidth;
        uint32_t height = src.imageHeight;
        if (!IsValidYuvData(src) || !IsValidYuvNVData(dest) || !IsValidSize(width, height)) {
            return -1;
        }
        return JpegDecoderYuv::GetLibyuvConverter().I422ToNV21(src.planes[YCOM], src.strides[YCOM], src.planes[UCOM],
            src.strides[UCOM], src.planes[VCOM], src.strides[VCOM], dest.planes[YCOM], dest.strides[YCOM],
            dest.planes[UVCOM], dest.strides[UVCOM], width, height);
    } else {
        return I4xxToI420_c(src, dest, SCALE_422_X, SCALE_422_Y, false);
    }
}

int I420ToI420_wrapper(const YuvPlaneInfo &src, const YuvPlaneInfo &dest)
{
    return I4xxToI420_c(src, dest, SCALE_420_X, SCALE_420_Y, true);
}

int I420ToNV21_wrapper(const YuvPlaneInfo &src, const YuvPlaneInfo &dest)
{
    if (JpegDecoderYuv::GetLibyuvConverter().I420ToNV21) {
        uint32_t width = src.imageWidth;
        uint32_t height = src.imageHeight;
        if (!IsValidYuvData(src) || !IsValidYuvNVData(dest) || !IsValidSize(width, height)) {
            return -1;
        }
        return JpegDecoderYuv::GetLibyuvConverter().I420ToNV21(src.planes[YCOM], src.strides[YCOM], src.planes[UCOM],
            src.strides[UCOM], src.planes[VCOM], src.strides[VCOM], dest.planes[YCOM], dest.strides[YCOM],
            dest.planes[UVCOM], dest.strides[UVCOM], width, height);
    } else {
        return I4xxToI420_c(src, dest, SCALE_420_X, SCALE_420_Y, false);
    }
}

int I440ToI420_wrapper(const YuvPlaneInfo &src, const YuvPlaneInfo &dest)
{
    return I4xxToI420_c(src, dest, SCALE_440_X, SCALE_440_Y, true);
}

int I440ToNV21_wrapper(const YuvPlaneInfo &src, const YuvPlaneInfo &dest)
{
    return I4xxToI420_c(src, dest, SCALE_440_X, SCALE_440_Y, false);
}

int I411ToI420_wrapper(const YuvPlaneInfo &src, const YuvPlaneInfo &dest)
{
    return I4xxToI420_c(src, dest, SCALE_411_X, SCALE_411_Y, true);
}

int I411ToNV21_wrapper(const YuvPlaneInfo &src, const YuvPlaneInfo &dest)
{
    return I4xxToI420_c(src, dest, SCALE_411_X, SCALE_411_Y, false);
}

int I400ToI420_wrapper(const YuvPlaneInfo &src, const YuvPlaneInfo &dest)
{
    uint32_t width = src.imageWidth;
    uint32_t height = src.imageHeight;
    if (!IsValidYuvGrayData(src) || !IsValidYuvData(dest) || !IsValidSize(width, height)) {
        return -1;
    }
    if (JpegDecoderYuv::GetLibyuvConverter().I400ToI420) {
        return JpegDecoderYuv::GetLibyuvConverter().I400ToI420(src.planes[YCOM], src.strides[YCOM], dest.planes[YCOM],
            dest.strides[YCOM], dest.planes[UCOM], dest.strides[UCOM], dest.planes[VCOM], dest.strides[VCOM],
            width, height);
    } else {
        const uint8_t* srcY = nullptr;
        for (uint32_t k = 0; k < height; k++) {
            srcY = src.planes[YCOM] + k * src.strides[YCOM];
            uint8_t* outY = dest.planes[YCOM] + k * dest.strides[YCOM];
            CopyLineData(outY, dest.strides[YCOM], srcY, std::min(src.strides[YCOM], dest.strides[YCOM]));
        }
        if (dest.planeHeight[YCOM] > height && srcY) {
            uint8_t* outY = dest.planes[YCOM] + height * dest.strides[YCOM];
            CopyLineData(outY, dest.strides[YCOM], srcY, src.strides[YCOM]);
        }
        const uint8_t chromaValueForGray = 0x80;
        uint32_t UVCOMSize = dest.planeWidth[UCOM] * dest.planeHeight[UCOM];
        UVCOMSize += dest.planeWidth[VCOM] * dest.planeHeight[VCOM];
        errno_t ret = memset_s(dest.planes[UCOM], UVCOMSize, chromaValueForGray, UVCOMSize);
        if (ret != EOK) {
            return -1;
        }
        return 0;
    }
}

}
}