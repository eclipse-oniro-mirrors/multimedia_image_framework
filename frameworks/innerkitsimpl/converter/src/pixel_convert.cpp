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

#include "pixel_convert.h"

#include <map>
#include <mutex>
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
#include "astcenc.h"
#endif
#ifndef _WIN32
#include "securec.h"
#else
#include "memory.h"
#endif
#include "pixel_convert_adapter.h"
#include "image_utils.h"
#include "pixel_map.h"

#include "image_log.h"
#include "media_errors.h"
#include "memory_manager.h"
#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
#include "surface_buffer.h"
#endif

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

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "PixelConvert"

namespace OHOS {
namespace Media {
using namespace std;
#if __BYTE_ORDER == __LITTLE_ENDIAN
constexpr bool IS_LITTLE_ENDIAN = true;
#else
constexpr bool IS_LITTLE_ENDIAN = false;
#endif
constexpr int32_t DMA_LINE_SIZE = 256;
static const uint8_t NUM_2 = 2;
constexpr uint8_t YUV420_P010_BYTES = 2;

constexpr uint8_t BYTE_POS_0 = 0;
constexpr uint8_t BYTE_POS_1 = 1;
constexpr uint8_t BYTE_POS_2 = 2;
constexpr uint8_t BYTE_POS_3 = 3;
constexpr uint8_t BYTE_POS_4 = 4;
constexpr uint8_t BYTE_POS_5 = 5;
constexpr uint8_t BYTE_POS_6 = 6;
constexpr uint8_t BYTE_POS_7 = 7;
constexpr uint8_t BYTE_POS_8 = 8;
constexpr uint8_t BYTE_POS_9 = 9;
constexpr uint8_t BYTE_POS_10 = 10;
constexpr uint8_t BYTE_POS_11 = 11;
constexpr uint8_t BYTE_POS_12 = 12;
constexpr uint8_t BYTE_POS_13 = 13;
constexpr uint8_t BYTE_POS_14 = 14;
constexpr uint8_t BYTE_POS_15 = 15;
constexpr uint32_t ASTC_BLOCK_SIZE_4 = 4;
constexpr uint32_t ASTC_MAGIC_ID = 0x5CA1AB13;
constexpr uint32_t UNPACK_SHIFT_1 = 8;
constexpr uint32_t UNPACK_SHIFT_2 = 16;
constexpr uint32_t UNPACK_SHIFT_3 = 24;
constexpr uint32_t ASTC_UNIT_BYTES = 16;
constexpr uint32_t ASTC_DIM_MAX = 8192;
constexpr uint32_t BYTES_PER_PIXEL = 4;
constexpr uint32_t BIT_SHIFT_16BITS = 16;
constexpr uint32_t EVEN_ALIGNMENT = 2;
constexpr int32_t CONVERT_ERROR = -1;
constexpr uint32_t UV_PLANES_COUNT = 2;
constexpr uint8_t RGB565_EXTRA_BYTES = 2;

static const std::map<YuvConversion, const int> SWS_CS_COEFFICIENT = {
    {YuvConversion::BT601, SWS_CS_DEFAULT},
    {YuvConversion::BT709, SWS_CS_ITU709},
    {YuvConversion::BT2020, SWS_CS_BT2020},
    {YuvConversion::BT240, SWS_CS_SMPTE240M},
    {YuvConversion::BTFCC, SWS_CS_FCC}
};

struct AstcInfo {
    uint32_t astcBufSize;
    uint8_t *astcBuf;
    PixelFormat format;
    Size astcSize;
    unsigned int dimX;
    unsigned int dimY;
};

static void AlphaTypeConvertOnRGB(uint32_t &A, uint32_t &R, uint32_t &G, uint32_t &B,
                                  const ProcFuncExtension &extension)
{
    switch (extension.alphaConvertType) {
        case AlphaConvertType::PREMUL_CONVERT_UNPREMUL:
            R = Unpremul255(R, A);
            G = Unpremul255(G, A);
            B = Unpremul255(B, A);
            break;
        case AlphaConvertType::PREMUL_CONVERT_OPAQUE:
            R = Unpremul255(R, A);
            G = Unpremul255(G, A);
            B = Unpremul255(B, A);
            A = ALPHA_OPAQUE;
            break;
        case AlphaConvertType::UNPREMUL_CONVERT_PREMUL:
            R = Premul255(R, A);
            G = Premul255(G, A);
            B = Premul255(B, A);
            break;
        case AlphaConvertType::UNPREMUL_CONVERT_OPAQUE:
            A = ALPHA_OPAQUE;
            break;
        default:
            break;
    }
}

static uint32_t FillARGB8888(uint32_t A, uint32_t R, uint32_t G, uint32_t B)
{
    if (IS_LITTLE_ENDIAN) {
        return ((B << SHIFT_24_BIT) | (G << SHIFT_16_BIT) | (R << SHIFT_8_BIT) | A);
    }
    return ((A << SHIFT_24_BIT) | (R << SHIFT_16_BIT) | (G << SHIFT_8_BIT) | B);
}

static uint32_t FillABGR8888(uint32_t A, uint32_t B, uint32_t G, uint32_t R)
{
    if (IS_LITTLE_ENDIAN) {
        return ((R << SHIFT_24_BIT) | (G << SHIFT_16_BIT) | (B << SHIFT_8_BIT) | A);
    }
    return ((A << SHIFT_24_BIT) | (B << SHIFT_16_BIT) | (G << SHIFT_8_BIT) | R);
}

static uint32_t FillRGBA8888(uint32_t R, uint32_t G, uint32_t B, uint32_t A)
{
    if (IS_LITTLE_ENDIAN) {
        return ((A << SHIFT_24_BIT) | (B << SHIFT_16_BIT) | (G << SHIFT_8_BIT) | R);
    }
    return ((R << SHIFT_24_BIT) | (G << SHIFT_16_BIT) | (B << SHIFT_8_BIT) | A);
}

static uint32_t FillBGRA8888(uint32_t B, uint32_t G, uint32_t R, uint32_t A)
{
    if (IS_LITTLE_ENDIAN) {
        return ((A << SHIFT_24_BIT) | (R << SHIFT_16_BIT) | (G << SHIFT_8_BIT) | B);
    }
    return ((B << SHIFT_24_BIT) | (G << SHIFT_16_BIT) | (R << SHIFT_8_BIT) | A);
}

static uint16_t FillRGB565(uint32_t R, uint32_t G, uint32_t B)
{
    if (IS_LITTLE_ENDIAN) {
        return ((B << SHIFT_11_BIT) | (G << SHIFT_5_BIT) | R);
    }
    return ((R << SHIFT_11_BIT) | (G << SHIFT_5_BIT) | B);
}

static uint64_t FillRGBAF16(float R, float G, float B, float A)
{
    uint64_t R16 = FloatToHalf(R);
    uint64_t G16 = FloatToHalf(G);
    uint64_t B16 = FloatToHalf(B);
    uint64_t A16 = FloatToHalf(A);
    if (IS_LITTLE_ENDIAN) {
        return ((A16 << SHIFT_48_BIT) | (R16 << SHIFT_32_BIT) | (G16 << SHIFT_16_BIT) | B16);
    }
    return ((B16 << SHIFT_48_BIT) | (G16 << SHIFT_32_BIT) | (R16 << SHIFT_16_BIT) | A16);
}

constexpr uint8_t BYTE_BITS = 8;
constexpr uint8_t BYTE_BITS_MAX_INDEX = 7;
template<typename T>
static void BitConvert(T *destinationRow, const uint8_t *sourceRow, uint32_t sourceWidth, uint32_t white,
                       uint32_t black)
{
    destinationRow[0] = (*sourceRow & GET_8_BIT) ? white : black;
    uint32_t bitIndex = 0;
    uint8_t currentSource = 0;
    /*
     * 1 byte = 8 bit
     * 7: 8 bit index
     */
    for (uint32_t i = 1; i < sourceWidth; i++) {
        bitIndex = i % BYTE_BITS;
        currentSource = *(sourceRow + i / BYTE_BITS);
        if (bitIndex > BYTE_BITS_MAX_INDEX) {
            continue;
        }
        destinationRow[i] = ((currentSource >> (BYTE_BITS_MAX_INDEX - bitIndex)) & GET_1_BIT) ? white : black;
    }
}

static void BitConvertGray(void *destinationRow, const uint8_t *sourceRow, uint32_t sourceWidth,
                           const ProcFuncExtension &extension)
{
    uint8_t *newDestinationRow = static_cast<uint8_t *>(destinationRow);
    BitConvert(newDestinationRow, sourceRow, sourceWidth, GRAYSCALE_WHITE, GRAYSCALE_BLACK);
}

static void BitConvertARGB8888(void *destinationRow, const uint8_t *sourceRow, uint32_t sourceWidth,
                               const ProcFuncExtension &extension)
{
    uint32_t *newDestinationRow = static_cast<uint32_t *>(destinationRow);
    BitConvert(newDestinationRow, sourceRow, sourceWidth, ARGB_WHITE, ARGB_BLACK);
}

static void BitConvertRGB565(void *destinationRow, const uint8_t *sourceRow, uint32_t sourceWidth,
                             const ProcFuncExtension &extension)
{
    uint16_t *newDestinationRow = static_cast<uint16_t *>(destinationRow);
    BitConvert(newDestinationRow, sourceRow, sourceWidth, RGB_WHITE, RGB_BLACK);
}

constexpr uint32_t BRANCH_GRAY_TO_ARGB8888 = 0x00000001;
constexpr uint32_t BRANCH_GRAY_TO_RGB565 = 0x00000002;
template<typename T>
static void GrayConvert(T *destinationRow, const uint8_t *sourceRow, uint32_t sourceWidth, uint32_t branch)
{
    for (uint32_t i = 0; i < sourceWidth; i++) {
        uint32_t R = sourceRow[i];
        uint32_t G = sourceRow[i];
        uint32_t B = sourceRow[i];
        if (branch == BRANCH_GRAY_TO_ARGB8888) {
            uint32_t A = ALPHA_OPAQUE;
            destinationRow[i] = ((A << SHIFT_24_BIT) | (R << SHIFT_16_BIT) | (G << SHIFT_8_BIT) | B);
        } else if (branch == BRANCH_GRAY_TO_RGB565) {
            R = R >> SHIFT_3_BIT;
            G = G >> SHIFT_2_BIT;
            B = B >> SHIFT_3_BIT;
            destinationRow[i] = ((R << SHIFT_11_BIT) | (G << SHIFT_5_BIT) | B);
        } else {
            break;
        }
    }
}

static void GrayConvertARGB8888(void *destinationRow, const uint8_t *sourceRow, uint32_t sourceWidth,
                                const ProcFuncExtension &extension)
{
    uint32_t *newDestinationRow = static_cast<uint32_t *>(destinationRow);
    GrayConvert(newDestinationRow, sourceRow, sourceWidth, BRANCH_GRAY_TO_ARGB8888);
}

static void GrayConvertRGB565(void *destinationRow, const uint8_t *sourceRow, uint32_t sourceWidth,
                              const ProcFuncExtension &extension)
{
    uint16_t *newDestinationRow = static_cast<uint16_t *>(destinationRow);
    GrayConvert(newDestinationRow, sourceRow, sourceWidth, BRANCH_GRAY_TO_RGB565);
}

constexpr uint32_t BRANCH_ARGB8888 = 0x10000001;
constexpr uint32_t BRANCH_ALPHA = 0x10000002;
template<typename T>
static void GrayAlphaConvert(T *destinationRow, const uint8_t *sourceRow, uint32_t sourceWidth, uint32_t branch,
                             const ProcFuncExtension &extension)
{
    for (uint32_t i = 0; i < sourceWidth; i++) {
        uint32_t A = sourceRow[1];
        uint32_t R = sourceRow[0];
        uint32_t G = sourceRow[0];
        uint32_t B = sourceRow[0];
        AlphaTypeConvertOnRGB(A, R, G, B, extension);
        if (branch == BRANCH_ARGB8888) {
            destinationRow[i] = FillARGB8888(A, R, G, B);
        } else if (branch == BRANCH_ALPHA) {
            destinationRow[i] = A;
        } else {
            break;
        }
        sourceRow += SIZE_2_BYTE;
    }
}

static void GrayAlphaConvertARGB8888(void *destinationRow, const uint8_t *sourceRow, uint32_t sourceWidth,
                                     const ProcFuncExtension &extension)
{
    uint32_t *newDestinationRow = static_cast<uint32_t *>(destinationRow);
    GrayAlphaConvert(newDestinationRow, sourceRow, sourceWidth, BRANCH_ARGB8888, extension);
}

static void GrayAlphaConvertAlpha(void *destinationRow, const uint8_t *sourceRow, uint32_t sourceWidth,
                                  const ProcFuncExtension &extension)
{
    uint8_t *newDestinationRow = static_cast<uint8_t *>(destinationRow);
    GrayAlphaConvert(newDestinationRow, sourceRow, sourceWidth, BRANCH_ALPHA, extension);
}

constexpr uint32_t BRANCH_BGR888_TO_ARGB8888 = 0x20000001;
constexpr uint32_t BRANCH_BGR888_TO_RGBA8888 = 0x20000002;
constexpr uint32_t BRANCH_BGR888_TO_BGRA8888 = 0x20000003;
constexpr uint32_t BRANCH_BGR888_TO_RGB565 = 0x20000004;
constexpr uint32_t BRANCH_BGR888_TO_RGBAF16 = 0x20000005;
template<typename T>
static void BGR888Convert(T *destinationRow, const uint8_t *sourceRow, uint32_t sourceWidth, uint32_t branch)
{
    for (uint32_t i = 0; i < sourceWidth; i++) {
        uint32_t R = sourceRow[2];
        uint32_t G = sourceRow[1];
        uint32_t B = sourceRow[0];
        uint32_t A = ALPHA_OPAQUE;
        if (branch == BRANCH_BGR888_TO_ARGB8888) {
            destinationRow[i] = FillARGB8888(A, R, G, B);
        } else if (branch == BRANCH_BGR888_TO_RGBA8888) {
            destinationRow[i] = FillRGBA8888(R, G, B, A);
        } else if (branch == BRANCH_BGR888_TO_BGRA8888) {
            destinationRow[i] = FillBGRA8888(B, G, R, A);
        } else if (branch == BRANCH_BGR888_TO_RGB565) {
            R = R >> SHIFT_3_BIT;
            G = G >> SHIFT_2_BIT;
            B = B >> SHIFT_3_BIT;
            destinationRow[i] = ((B << SHIFT_11_BIT) | (G << SHIFT_5_BIT) | R);
        } else if (branch == BRANCH_BGR888_TO_RGBAF16) {
            destinationRow[i] = FillRGBAF16(R, G, B, A);
        } else {
            break;
        }
        sourceRow += SIZE_3_BYTE;
    }
}

static void BGR888ConvertARGB8888(void *destinationRow, const uint8_t *sourceRow, uint32_t sourceWidth,
                                  const ProcFuncExtension &extension)
{
    uint32_t *newDestinationRow = static_cast<uint32_t *>(destinationRow);
    BGR888Convert(newDestinationRow, sourceRow, sourceWidth, BRANCH_BGR888_TO_ARGB8888);
}

static void BGR888ConvertRGBA8888(void *destinationRow, const uint8_t *sourceRow, uint32_t sourceWidth,
                                  const ProcFuncExtension &extension)
{
    uint32_t *newDestinationRow = static_cast<uint32_t *>(destinationRow);
    BGR888Convert(newDestinationRow, sourceRow, sourceWidth, BRANCH_BGR888_TO_RGBA8888);
}

static void BGR888ConvertBGRA8888(void *destinationRow, const uint8_t *sourceRow, uint32_t sourceWidth,
                                  const ProcFuncExtension &extension)
{
    uint32_t *newDestinationRow = static_cast<uint32_t *>(destinationRow);
    BGR888Convert(newDestinationRow, sourceRow, sourceWidth, BRANCH_BGR888_TO_BGRA8888);
}

static void BGR888ConvertRGB565(void *destinationRow, const uint8_t *sourceRow, uint32_t sourceWidth,
                                const ProcFuncExtension &extension)
{
    uint16_t *newDestinationRow = static_cast<uint16_t *>(destinationRow);
    BGR888Convert(newDestinationRow, sourceRow, sourceWidth, BRANCH_BGR888_TO_RGB565);
}

static void BGR888ConvertRGBAF16(uint8_t *destinationRow, const uint8_t *sourceRow, uint32_t sourceWidth,
    const ProcFuncExtension &extension)
{
    void* tmp = static_cast<void *>(destinationRow);
    uint64_t *newDestinationRow = static_cast<uint64_t *>(tmp);
    BGR888Convert(newDestinationRow, sourceRow, sourceWidth, BRANCH_BGR888_TO_RGBAF16);
}

constexpr uint32_t BRANCH_RGB888_TO_ARGB8888 = 0x30000001;
constexpr uint32_t BRANCH_RGB888_TO_RGBA8888 = 0x30000002;
constexpr uint32_t BRANCH_RGB888_TO_BGRA8888 = 0x30000003;
constexpr uint32_t BRANCH_RGB888_TO_RGB565 = 0x30000004;
constexpr uint32_t BRANCH_RGB888_TO_RGBAF16 = 0x30000005;
template<typename T>
static void RGB888Convert(T *destinationRow, const uint8_t *sourceRow, uint32_t sourceWidth, uint32_t branch)
{
    for (uint32_t i = 0; i < sourceWidth; i++) {
        uint32_t R = sourceRow[0];
        uint32_t G = sourceRow[1];
        uint32_t B = sourceRow[2];
        uint32_t A = ALPHA_OPAQUE;
        if (branch == BRANCH_RGB888_TO_ARGB8888) {
            destinationRow[i] = FillARGB8888(A, R, G, B);
        } else if (branch == BRANCH_RGB888_TO_RGBA8888) {
            destinationRow[i] = FillRGBA8888(R, G, B, A);
        } else if (branch == BRANCH_RGB888_TO_BGRA8888) {
            destinationRow[i] = FillBGRA8888(B, G, R, A);
        } else if (branch == BRANCH_RGB888_TO_RGB565) {
            R = R >> SHIFT_3_BIT;
            G = G >> SHIFT_2_BIT;
            B = B >> SHIFT_3_BIT;
            destinationRow[i] = FillRGB565(R, G, B);
        } else if (branch == BRANCH_RGB888_TO_RGBAF16) {
            destinationRow[i] = FillRGBAF16(R, G, B, A);
        } else {
            break;
        }
        sourceRow += SIZE_3_BYTE;
    }
}
static void RGB888ConvertARGB8888(void *destinationRow, const uint8_t *sourceRow, uint32_t sourceWidth,
                                  const ProcFuncExtension &extension)
{
    uint32_t *newDestinationRow = static_cast<uint32_t *>(destinationRow);
    RGB888Convert(newDestinationRow, sourceRow, sourceWidth, BRANCH_RGB888_TO_ARGB8888);
}

static void RGB888ConvertRGBA8888(void *destinationRow, const uint8_t *sourceRow, uint32_t sourceWidth,
                                  const ProcFuncExtension &extension)
{
    uint32_t *newDestinationRow = static_cast<uint32_t *>(destinationRow);
    RGB888Convert(newDestinationRow, sourceRow, sourceWidth, BRANCH_RGB888_TO_RGBA8888);
}

static void RGB888ConvertBGRA8888(void *destinationRow, const uint8_t *sourceRow, uint32_t sourceWidth,
                                  const ProcFuncExtension &extension)
{
    uint32_t *newDestinationRow = static_cast<uint32_t *>(destinationRow);
    RGB888Convert(newDestinationRow, sourceRow, sourceWidth, BRANCH_RGB888_TO_BGRA8888);
}

static void RGB888ConvertRGB565(void *destinationRow, const uint8_t *sourceRow, uint32_t sourceWidth,
                                const ProcFuncExtension &extension)
{
    uint16_t *newDestinationRow = static_cast<uint16_t *>(destinationRow);
    RGB888Convert(newDestinationRow, sourceRow, sourceWidth, BRANCH_RGB888_TO_RGB565);
}

static void RGB888ConvertRGBAF16(uint8_t *destinationRow, const uint8_t *sourceRow, uint32_t sourceWidth,
    const ProcFuncExtension &extension)
{
    void* tmp = static_cast<void *>(destinationRow);
    uint64_t *newDestinationRow = static_cast<uint64_t *>(tmp);
    RGB888Convert(newDestinationRow, sourceRow, sourceWidth, BRANCH_RGB888_TO_RGBAF16);
}
constexpr uint32_t BRANCH_RGBA8888_TO_RGBA8888_ALPHA = 0x40000001;
constexpr uint32_t BRANCH_RGBA8888_TO_ARGB8888 = 0x40000002;
constexpr uint32_t BRANCH_RGBA8888_TO_BGRA8888 = 0x40000003;
constexpr uint32_t BRANCH_RGBA8888_TO_RGB565 = 0x40000004;
constexpr uint32_t BRANCH_RGBA8888_TO_RGBAF16 = 0x40000005;
template<typename T>
static void RGBA8888Convert(T *destinationRow, const uint8_t *sourceRow, uint32_t sourceWidth, uint32_t branch,
                            const ProcFuncExtension &extension)
{
    for (uint32_t i = 0; i < sourceWidth; i++) {
        uint32_t R = sourceRow[0];
        uint32_t G = sourceRow[1];
        uint32_t B = sourceRow[2];
        uint32_t A = sourceRow[3];
        AlphaTypeConvertOnRGB(A, R, G, B, extension);
        if (branch == BRANCH_RGBA8888_TO_RGBA8888_ALPHA) {
            destinationRow[i] = FillRGBA8888(R, G, B, A);
        } else if (branch == BRANCH_RGBA8888_TO_ARGB8888) {
            destinationRow[i] = FillARGB8888(A, R, G, B);
        } else if (branch == BRANCH_RGBA8888_TO_BGRA8888) {
            destinationRow[i] = FillBGRA8888(B, G, R, A);
        } else if (branch == BRANCH_RGBA8888_TO_RGB565) {
            R = R >> SHIFT_3_BIT;
            G = G >> SHIFT_2_BIT;
            B = B >> SHIFT_3_BIT;
            destinationRow[i] = FillRGB565(R, G, B);
        } else if (branch == BRANCH_RGBA8888_TO_RGBAF16) {
            destinationRow[i] = FillRGBAF16(R, G, B, A);
        } else {
            break;
        }
        sourceRow += SIZE_4_BYTE;
    }
}

static void RGBA8888ConvertRGBA8888Alpha(void *destinationRow, const uint8_t *sourceRow, uint32_t sourceWidth,
                                         const ProcFuncExtension &extension)
{
    uint32_t *newDestinationRow = static_cast<uint32_t *>(destinationRow);
    RGBA8888Convert(newDestinationRow, sourceRow, sourceWidth, BRANCH_RGBA8888_TO_RGBA8888_ALPHA, extension);
}

static void RGBA8888ConvertARGB8888(void *destinationRow, const uint8_t *sourceRow, uint32_t sourceWidth,
                                    const ProcFuncExtension &extension)
{
    uint32_t *newDestinationRow = static_cast<uint32_t *>(destinationRow);
    RGBA8888Convert(newDestinationRow, sourceRow, sourceWidth, BRANCH_RGBA8888_TO_ARGB8888, extension);
}
static void RGBA8888ConvertBGRA8888(void *destinationRow, const uint8_t *sourceRow, uint32_t sourceWidth,
                                    const ProcFuncExtension &extension)
{
    uint32_t *newDestinationRow = static_cast<uint32_t *>(destinationRow);
    RGBA8888Convert(newDestinationRow, sourceRow, sourceWidth, BRANCH_RGBA8888_TO_BGRA8888, extension);
}

static void RGBA8888ConvertRGB565(void *destinationRow, const uint8_t *sourceRow, uint32_t sourceWidth,
                                  const ProcFuncExtension &extension)
{
    uint16_t *newDestinationRow = static_cast<uint16_t *>(destinationRow);
    RGBA8888Convert(newDestinationRow, sourceRow, sourceWidth, BRANCH_RGBA8888_TO_RGB565, extension);
}

static void RGBA8888ConvertRGBAF16(uint8_t *destinationRow, const uint8_t *sourceRow, uint32_t sourceWidth,
    const ProcFuncExtension &extension)
{
    void* tmp = static_cast<void *>(destinationRow);
    uint64_t *newDestinationRow = static_cast<uint64_t *>(tmp);
    RGBA8888Convert(newDestinationRow, sourceRow, sourceWidth, BRANCH_RGBA8888_TO_RGBAF16, extension);
}
constexpr uint32_t BRANCH_BGRA8888_TO_BGRA8888_ALPHA = 0x80000001;
constexpr uint32_t BRANCH_BGRA8888_TO_ARGB8888 = 0x80000002;
constexpr uint32_t BRANCH_BGRA8888_TO_RGBA8888 = 0x80000003;
constexpr uint32_t BRANCH_BGRA8888_TO_RGB565 = 0x80000004;
constexpr uint32_t BRANCH_BGRA8888_TO_RGBAF16 = 0x80000005;
template<typename T>
static void BGRA8888Convert(T *destinationRow, const uint8_t *sourceRow, uint32_t sourceWidth, uint32_t branch,
                            const ProcFuncExtension &extension)
{
    for (uint32_t i = 0; i < sourceWidth; i++) {
        uint32_t B = sourceRow[0];
        uint32_t G = sourceRow[1];
        uint32_t R = sourceRow[2];
        uint32_t A = sourceRow[3];
        AlphaTypeConvertOnRGB(A, R, G, B, extension);
        if (branch == BRANCH_BGRA8888_TO_BGRA8888_ALPHA) {
            destinationRow[i] = FillBGRA8888(B, G, R, A);
        } else if (branch == BRANCH_BGRA8888_TO_ARGB8888) {
            destinationRow[i] = FillARGB8888(A, R, G, B);
        } else if (branch == BRANCH_BGRA8888_TO_RGBA8888) {
            destinationRow[i] = FillRGBA8888(R, G, B, A);
        } else if (branch == BRANCH_BGRA8888_TO_RGB565) {
            R = R >> SHIFT_3_BIT;
            G = G >> SHIFT_2_BIT;
            B = B >> SHIFT_3_BIT;
            destinationRow[i] = FillRGB565(R, G, B);
        } else if (branch == BRANCH_BGRA8888_TO_RGBAF16) {
            destinationRow[i] = FillRGBAF16(R, G, B, A);
        } else {
            break;
        }
        sourceRow += SIZE_4_BYTE;
    }
}

static void BGRA8888ConvertBGRA8888Alpha(void *destinationRow, const uint8_t *sourceRow, uint32_t sourceWidth,
                                         const ProcFuncExtension &extension)
{
    uint32_t *newDestinationRow = static_cast<uint32_t *>(destinationRow);
    BGRA8888Convert(newDestinationRow, sourceRow, sourceWidth, BRANCH_BGRA8888_TO_BGRA8888_ALPHA, extension);
}

static void BGRA8888ConvertARGB8888(void *destinationRow, const uint8_t *sourceRow, uint32_t sourceWidth,
                                    const ProcFuncExtension &extension)
{
    uint32_t *newDestinationRow = static_cast<uint32_t *>(destinationRow);
    BGRA8888Convert(newDestinationRow, sourceRow, sourceWidth, BRANCH_BGRA8888_TO_ARGB8888, extension);
}

static void BGRA8888ConvertRGBA8888(void *destinationRow, const uint8_t *sourceRow, uint32_t sourceWidth,
                                    const ProcFuncExtension &extension)
{
    uint32_t *newDestinationRow = static_cast<uint32_t *>(destinationRow);
    BGRA8888Convert(newDestinationRow, sourceRow, sourceWidth, BRANCH_BGRA8888_TO_RGBA8888, extension);
}

static void BGRA8888ConvertRGB565(void *destinationRow, const uint8_t *sourceRow, uint32_t sourceWidth,
                                  const ProcFuncExtension &extension)
{
    uint16_t *newDestinationRow = static_cast<uint16_t *>(destinationRow);
    BGRA8888Convert(newDestinationRow, sourceRow, sourceWidth, BRANCH_BGRA8888_TO_RGB565, extension);
}

static void BGRA8888ConvertRGBAF16(uint8_t *destinationRow, const uint8_t *sourceRow, uint32_t sourceWidth,
    const ProcFuncExtension &extension)
{
    void* tmp = static_cast<void *>(destinationRow);
    uint64_t *newDestinationRow = static_cast<uint64_t *>(tmp);
    BGRA8888Convert(newDestinationRow, sourceRow, sourceWidth, BRANCH_BGRA8888_TO_RGBAF16, extension);
}

constexpr uint32_t BRANCH_ARGB8888_TO_ARGB8888_ALPHA = 0x90000001;
constexpr uint32_t BRANCH_ARGB8888_TO_RGBA8888 = 0x90000002;
constexpr uint32_t BRANCH_ARGB8888_TO_BGRA8888 = 0x90000003;
constexpr uint32_t BRANCH_ARGB8888_TO_RGB565 = 0x90000004;
constexpr uint32_t BRANCH_ARGB8888_TO_RGBAF16 = 0x90000005;
template<typename T>
static void ARGB8888Convert(T *destinationRow, const uint8_t *sourceRow, uint32_t sourceWidth, uint32_t branch,
                            const ProcFuncExtension &extension)
{
    for (uint32_t i = 0; i < sourceWidth; i++) {
        uint32_t A = sourceRow[0];
        uint32_t R = sourceRow[1];
        uint32_t G = sourceRow[2];
        uint32_t B = sourceRow[3];
        AlphaTypeConvertOnRGB(A, R, G, B, extension);
        if (branch == BRANCH_ARGB8888_TO_ARGB8888_ALPHA) {
            destinationRow[i] = FillARGB8888(A, R, G, B);
        } else if (branch == BRANCH_ARGB8888_TO_RGBA8888) {
            destinationRow[i] = FillRGBA8888(R, G, B, A);
        } else if (branch == BRANCH_ARGB8888_TO_BGRA8888) {
            destinationRow[i] = FillBGRA8888(B, G, R, A);
        } else if (branch == BRANCH_ARGB8888_TO_RGB565) {
            R = R >> SHIFT_3_BIT;
            G = G >> SHIFT_2_BIT;
            B = B >> SHIFT_3_BIT;
            destinationRow[i] = FillRGB565(R, G, B);
        } else if (branch == BRANCH_ARGB8888_TO_RGBAF16) {
            destinationRow[i] = FillRGBAF16(R, G, B, A);
        } else {
            break;
        }
        sourceRow += SIZE_4_BYTE;
    }
}

static void ARGB8888ConvertARGB8888Alpha(void *destinationRow, const uint8_t *sourceRow, uint32_t sourceWidth,
                                         const ProcFuncExtension &extension)
{
    uint32_t *newDestinationRow = static_cast<uint32_t *>(destinationRow);
    ARGB8888Convert(newDestinationRow, sourceRow, sourceWidth, BRANCH_ARGB8888_TO_ARGB8888_ALPHA, extension);
}

static void ARGB8888ConvertRGBA8888(void *destinationRow, const uint8_t *sourceRow, uint32_t sourceWidth,
                                    const ProcFuncExtension &extension)
{
    uint32_t *newDestinationRow = static_cast<uint32_t *>(destinationRow);
    ARGB8888Convert(newDestinationRow, sourceRow, sourceWidth, BRANCH_ARGB8888_TO_RGBA8888, extension);
}

static void ARGB8888ConvertBGRA8888(void *destinationRow, const uint8_t *sourceRow, uint32_t sourceWidth,
                                    const ProcFuncExtension &extension)
{
    uint32_t *newDestinationRow = static_cast<uint32_t *>(destinationRow);
    ARGB8888Convert(newDestinationRow, sourceRow, sourceWidth, BRANCH_ARGB8888_TO_BGRA8888, extension);
}

static void ARGB8888ConvertRGB565(void *destinationRow, const uint8_t *sourceRow, uint32_t sourceWidth,
                                  const ProcFuncExtension &extension)
{
    uint16_t *newDestinationRow = static_cast<uint16_t *>(destinationRow);
    ARGB8888Convert(newDestinationRow, sourceRow, sourceWidth, BRANCH_ARGB8888_TO_RGB565, extension);
}

static void ARGB8888ConvertRGBAF16(uint8_t *destinationRow, const uint8_t *sourceRow, uint32_t sourceWidth,
    const ProcFuncExtension &extension)
{
    void* tmp = static_cast<void *>(destinationRow);
    uint64_t *newDestinationRow = static_cast<uint64_t *>(tmp);
    ARGB8888Convert(newDestinationRow, sourceRow, sourceWidth, BRANCH_ARGB8888_TO_RGBAF16, extension);
}

constexpr uint32_t BRANCH_RGB161616_TO_ARGB8888 = 0x50000001;
constexpr uint32_t BRANCH_RGB161616_TO_ABGR8888 = 0x50000002;
constexpr uint32_t BRANCH_RGB161616_TO_RGBA8888 = 0x50000003;
constexpr uint32_t BRANCH_RGB161616_TO_BGRA8888 = 0x50000004;
constexpr uint32_t BRANCH_RGB161616_TO_RGB565 = 0x50000005;
constexpr uint32_t BRANCH_RGB161616_TO_RGBAF16 = 0x50000006;
template<typename T>
static void RGB161616Convert(T *destinationRow, const uint8_t *sourceRow, uint32_t sourceWidth, uint32_t branch)
{
    for (uint32_t i = 0; i < sourceWidth; i++) {
        uint32_t R = sourceRow[0];
        uint32_t G = sourceRow[2];
        uint32_t B = sourceRow[4];
        uint32_t A = ALPHA_OPAQUE;
        if (branch == BRANCH_RGB161616_TO_ARGB8888) {
            destinationRow[i] = FillARGB8888(A, R, G, B);
        } else if (branch == BRANCH_RGB161616_TO_ABGR8888) {
            destinationRow[i] = FillABGR8888(A, B, G, R);
        } else if (branch == BRANCH_RGB161616_TO_RGBA8888) {
            destinationRow[i] = FillRGBA8888(R, G, B, A);
        } else if (branch == BRANCH_RGB161616_TO_BGRA8888) {
            destinationRow[i] = FillBGRA8888(B, G, R, A);
        } else if (branch == BRANCH_RGB161616_TO_RGB565) {
            R = R >> SHIFT_3_BIT;
            G = G >> SHIFT_2_BIT;
            B = B >> SHIFT_3_BIT;
            destinationRow[i] = FillRGB565(R, G, B);
        } else if (branch == BRANCH_RGB161616_TO_RGBAF16) {
            destinationRow[i] = FillRGBAF16(R, G, B, A);
        } else {
            break;
        }
        sourceRow += SIZE_6_BYTE;
    }
}

static void RGB161616ConvertARGB8888(void *destinationRow, const uint8_t *sourceRow, uint32_t sourceWidth,
                                     const ProcFuncExtension &extension)
{
    uint32_t *newDestinationRow = static_cast<uint32_t *>(destinationRow);
    RGB161616Convert(newDestinationRow, sourceRow, sourceWidth, BRANCH_RGB161616_TO_ARGB8888);
}

static void RGB161616ConvertABGR8888(void *destinationRow, const uint8_t *sourceRow, uint32_t sourceWidth,
                                     const ProcFuncExtension &extension)
{
    uint32_t *newDestinationRow = static_cast<uint32_t *>(destinationRow);
    RGB161616Convert(newDestinationRow, sourceRow, sourceWidth, BRANCH_RGB161616_TO_ABGR8888);
}

static void RGB161616ConvertRGBA8888(void *destinationRow, const uint8_t *sourceRow, uint32_t sourceWidth,
                                     const ProcFuncExtension &extension)
{
    uint32_t *newDestinationRow = static_cast<uint32_t *>(destinationRow);
    RGB161616Convert(newDestinationRow, sourceRow, sourceWidth, BRANCH_RGB161616_TO_RGBA8888);
}

static void RGB161616ConvertBGRA8888(void *destinationRow, const uint8_t *sourceRow, uint32_t sourceWidth,
                                     const ProcFuncExtension &extension)
{
    uint32_t *newDestinationRow = static_cast<uint32_t *>(destinationRow);
    RGB161616Convert(newDestinationRow, sourceRow, sourceWidth, BRANCH_RGB161616_TO_BGRA8888);
}

static void RGB161616ConvertRGB565(void *destinationRow, const uint8_t *sourceRow, uint32_t sourceWidth,
                                   const ProcFuncExtension &extension)
{
    uint16_t *newDestinationRow = static_cast<uint16_t *>(destinationRow);
    RGB161616Convert(newDestinationRow, sourceRow, sourceWidth, BRANCH_RGB161616_TO_RGB565);
}

static void RGB161616ConvertRGBAF16(uint8_t *destinationRow, const uint8_t *sourceRow, uint32_t sourceWidth,
    const ProcFuncExtension &extension)
{
    void* tmp = static_cast<void *>(destinationRow);
    uint64_t *newDestinationRow = static_cast<uint64_t *>(tmp);
    RGB161616Convert(newDestinationRow, sourceRow, sourceWidth, BRANCH_RGB161616_TO_RGBAF16);
}

constexpr uint32_t BRANCH_RGBA16161616_TO_ARGB8888 = 0x60000001;
constexpr uint32_t BRANCH_RGBA16161616_TO_ABGR8888 = 0x60000002;
constexpr uint32_t BRANCH_RGBA16161616_TO_RGBA8888 = 0x60000003;
constexpr uint32_t BRANCH_RGBA16161616_TO_BGRA8888 = 0x60000004;
constexpr uint32_t BRANCH_RGBA16161616_TO_RGBAF16 = 0x60000005;
template<typename T>
static void RGBA16161616Convert(T *destinationRow, const uint8_t *sourceRow, uint32_t sourceWidth, uint32_t branch,
                                const ProcFuncExtension &extension)
{
    for (uint32_t i = 0; i < sourceWidth; i++) {
        uint32_t R = sourceRow[0];
        uint32_t G = sourceRow[2];
        uint32_t B = sourceRow[4];
        uint32_t A = sourceRow[6];
        AlphaTypeConvertOnRGB(A, R, G, B, extension);
        if (branch == BRANCH_RGBA16161616_TO_ARGB8888) {
            destinationRow[i] = FillARGB8888(A, R, G, B);
        } else if (branch == BRANCH_RGBA16161616_TO_ABGR8888) {
            destinationRow[i] = FillABGR8888(A, B, G, R);
        } else if (branch == BRANCH_RGBA16161616_TO_RGBA8888) {
            destinationRow[i] = FillRGBA8888(A, B, G, R);
        } else if (branch == BRANCH_RGBA16161616_TO_BGRA8888) {
            destinationRow[i] = FillBGRA8888(A, B, G, R);
        } else if (branch == BRANCH_RGBA16161616_TO_RGBAF16) {
            destinationRow[i] = FillRGBAF16(R, G, B, A);
        } else {
            break;
        }
        sourceRow += SIZE_8_BYTE;
    }
}

static void RGBA16161616ConvertARGB8888(void *destinationRow, const uint8_t *sourceRow, uint32_t sourceWidth,
                                        const ProcFuncExtension &extension)
{
    uint32_t *newDestinationRow = static_cast<uint32_t *>(destinationRow);
    RGBA16161616Convert(newDestinationRow, sourceRow, sourceWidth, BRANCH_RGBA16161616_TO_ARGB8888, extension);
}

static void RGBA16161616ConvertABGR8888(void *destinationRow, const uint8_t *sourceRow, uint32_t sourceWidth,
                                        const ProcFuncExtension &extension)
{
    uint32_t *newDestinationRow = static_cast<uint32_t *>(destinationRow);
    RGBA16161616Convert(newDestinationRow, sourceRow, sourceWidth, BRANCH_RGBA16161616_TO_ABGR8888, extension);
}

static void RGBA16161616ConvertRGBA8888(void *destinationRow, const uint8_t *sourceRow, uint32_t sourceWidth,
                                        const ProcFuncExtension &extension)
{
    uint32_t *newDestinationRow = static_cast<uint32_t *>(destinationRow);
    RGBA16161616Convert(newDestinationRow, sourceRow, sourceWidth, BRANCH_RGBA16161616_TO_RGBA8888, extension);
}

static void RGBA16161616ConvertBGRA8888(void *destinationRow, const uint8_t *sourceRow, uint32_t sourceWidth,
                                        const ProcFuncExtension &extension)
{
    uint32_t *newDestinationRow = static_cast<uint32_t *>(destinationRow);
    RGBA16161616Convert(newDestinationRow, sourceRow, sourceWidth, BRANCH_RGBA16161616_TO_BGRA8888, extension);
}

static void RGBA16161616ConvertRGBAF16(uint8_t *destinationRow, const uint8_t *sourceRow, uint32_t sourceWidth,
    const ProcFuncExtension &extension)
{
    void* tmp = static_cast<void *>(destinationRow);
    uint64_t *newDestinationRow = static_cast<uint64_t *>(tmp);
    RGBA16161616Convert(newDestinationRow, sourceRow, sourceWidth, BRANCH_RGBA16161616_TO_RGBAF16, extension);
}

constexpr uint32_t BRANCH_CMYK_TO_ARGB8888 = 0x70000001;
constexpr uint32_t BRANCH_CMYK_TO_ABGR8888 = 0x70000002;
constexpr uint32_t BRANCH_CMYK_TO_RGBA8888 = 0x70000003;
constexpr uint32_t BRANCH_CMYK_TO_BGRA8888 = 0x70000004;
constexpr uint32_t BRANCH_CMYK_TO_RGB565 = 0x70000005;
template<typename T>
static void CMYKConvert(T *destinationRow, const uint8_t *sourceRow, uint32_t sourceWidth, uint32_t branch)
{
    for (uint32_t i = 0; i < sourceWidth; i++) {
        uint8_t C = sourceRow[0];
        uint8_t M = sourceRow[1];
        uint8_t Y = sourceRow[2];
        uint8_t K = sourceRow[3];
        uint32_t R = Premul255(C, K);
        uint32_t G = Premul255(M, K);
        uint32_t B = Premul255(Y, K);
        uint32_t A = ALPHA_OPAQUE;
        if (branch == BRANCH_CMYK_TO_ARGB8888) {
            destinationRow[i] = FillARGB8888(A, R, G, B);
        } else if (branch == BRANCH_CMYK_TO_ABGR8888) {
            destinationRow[i] = FillABGR8888(A, B, G, R);
        } else if (branch == BRANCH_CMYK_TO_RGBA8888) {
            destinationRow[i] = FillRGBA8888(R, G, B, A);
        } else if (branch == BRANCH_CMYK_TO_BGRA8888) {
            destinationRow[i] = FillBGRA8888(B, G, R, A);
        } else if (branch == BRANCH_CMYK_TO_RGB565) {
            R = R >> SHIFT_3_BIT;
            G = R >> SHIFT_2_BIT;
            B = B >> SHIFT_3_BIT;
            destinationRow[i] = FillRGB565(R, G, B);
        } else {
            break;
        }
        sourceRow += SIZE_4_BYTE;
    }
}

static void CMYKConvertARGB8888(void *destinationRow, const uint8_t *sourceRow, uint32_t sourceWidth,
                                const ProcFuncExtension &extension)
{
    uint32_t *newDestinationRow = static_cast<uint32_t *>(destinationRow);
    CMYKConvert(newDestinationRow, sourceRow, sourceWidth, BRANCH_CMYK_TO_ARGB8888);
}

static void CMYKConvertABGR8888(void *destinationRow, const uint8_t *sourceRow, uint32_t sourceWidth,
                                const ProcFuncExtension &extension)
{
    uint32_t *newDestinationRow = static_cast<uint32_t *>(destinationRow);
    CMYKConvert(newDestinationRow, sourceRow, sourceWidth, BRANCH_CMYK_TO_ABGR8888);
}

static void CMYKConvertRGBA8888(void *destinationRow, const uint8_t *sourceRow, uint32_t sourceWidth,
                                const ProcFuncExtension &extension)
{
    uint32_t *newDestinationRow = static_cast<uint32_t *>(destinationRow);
    CMYKConvert(newDestinationRow, sourceRow, sourceWidth, BRANCH_CMYK_TO_RGBA8888);
}

static void CMYKConvertBGRA8888(void *destinationRow, const uint8_t *sourceRow, uint32_t sourceWidth,
                                const ProcFuncExtension &extension)
{
    uint32_t *newDestinationRow = static_cast<uint32_t *>(destinationRow);
    CMYKConvert(newDestinationRow, sourceRow, sourceWidth, BRANCH_CMYK_TO_BGRA8888);
}

static void CMYKConvertRGB565(void *destinationRow, const uint8_t *sourceRow, uint32_t sourceWidth,
                              const ProcFuncExtension &extension)
{
    uint32_t *newDestinationRow = static_cast<uint32_t *>(destinationRow);
    CMYKConvert(newDestinationRow, sourceRow, sourceWidth, BRANCH_CMYK_TO_RGB565);
}

constexpr uint32_t BRANCH_RGB565_TO_ARGB8888 = 0x11000001;
constexpr uint32_t BRANCH_RGB565_TO_RGBA8888 = 0x11000002;
constexpr uint32_t BRANCH_RGB565_TO_BGRA8888 = 0x11000003;
constexpr uint32_t BRANCH_RGB565_TO_RGBAF16 = 0x11000004;
template<typename T>
static void RGB565Convert(T *destinationRow, const uint8_t *sourceRow, uint32_t sourceWidth, uint32_t branch)
{
    for (uint32_t i = 0; i < sourceWidth; i++) {
        uint32_t R = (sourceRow[0] >> SHIFT_3_BIT) & SHIFT_5_MASK;
        uint32_t G = ((sourceRow[0] & SHIFT_3_MASK) << SHIFT_3_BIT) | ((sourceRow[1] >> SHIFT_5_BIT) & SHIFT_3_MASK);
        uint32_t B = sourceRow[1] & SHIFT_5_MASK;
        uint32_t A = ALPHA_OPAQUE;
        if (branch == BRANCH_RGB565_TO_ARGB8888) {
            destinationRow[i] = FillARGB8888(A, R, G, B);
        } else if (branch == BRANCH_RGB565_TO_RGBA8888) {
            destinationRow[i] = FillRGBA8888(R, G, B, A);
        } else if (branch == BRANCH_RGB565_TO_BGRA8888) {
            destinationRow[i] = FillBGRA8888(B, G, R, A);
        } else if (branch == BRANCH_RGB565_TO_RGBAF16) {
            destinationRow[i] = FillRGBAF16(R, G, B, A);
        } else {
            break;
        }
        sourceRow += SIZE_2_BYTE;
    }
}

static void RGB565ConvertARGB8888(void *destinationRow, const uint8_t *sourceRow, uint32_t sourceWidth,
                                  const ProcFuncExtension &extension)
{
    uint32_t *newDestinationRow = static_cast<uint32_t *>(destinationRow);
    RGB565Convert(newDestinationRow, sourceRow, sourceWidth, BRANCH_RGB565_TO_ARGB8888);
}

static void RGB565ConvertRGBA8888(void *destinationRow, const uint8_t *sourceRow, uint32_t sourceWidth,
                                  const ProcFuncExtension &extension)
{
    uint32_t *newDestinationRow = static_cast<uint32_t *>(destinationRow);
    RGB565Convert(newDestinationRow, sourceRow, sourceWidth, BRANCH_RGB565_TO_RGBA8888);
}

static void RGB565ConvertBGRA8888(void *destinationRow, const uint8_t *sourceRow, uint32_t sourceWidth,
                                  const ProcFuncExtension &extension)
{
    uint32_t *newDestinationRow = static_cast<uint32_t *>(destinationRow);
    RGB565Convert(newDestinationRow, sourceRow, sourceWidth, BRANCH_RGB565_TO_BGRA8888);
}

static void RGB565ConvertRGBAF16(uint8_t *destinationRow, const uint8_t *sourceRow, uint32_t sourceWidth,
    const ProcFuncExtension &extension)
{
    void* tmp = static_cast<void *>(destinationRow);
    uint64_t *newDestinationRow = static_cast<uint64_t *>(tmp);
    RGB565Convert(newDestinationRow, sourceRow, sourceWidth, BRANCH_RGB565_TO_RGBAF16);
}

constexpr uint32_t BRANCH_RGBAF16_TO_ARGB8888 = 0x13000001;
constexpr uint32_t BRANCH_RGBAF16_TO_RGBA8888 = 0x13000002;
constexpr uint32_t BRANCH_RGBAF16_TO_BGRA8888 = 0x13000003;
constexpr uint32_t BRANCH_RGBAF16_TO_ABGR8888 = 0x13000004;
constexpr uint32_t BRANCH_RGBAF16_TO_RGB565 = 0x13000005;
template<typename T>
static void RGBAF16Convert(T *destinationRow, const uint8_t *sourceRow, uint32_t sourceWidth, uint32_t branch,
                           const ProcFuncExtension &extension)
{
    for (uint32_t i = 0; i < sourceWidth; i++) {
        uint32_t R = HalfToUint32(sourceRow, IS_LITTLE_ENDIAN);
        uint32_t G = HalfToUint32(sourceRow + 2, IS_LITTLE_ENDIAN);
        uint32_t B = HalfToUint32(sourceRow + 4, IS_LITTLE_ENDIAN);
        uint32_t A = HalfToUint32(sourceRow + 6, IS_LITTLE_ENDIAN);
        AlphaTypeConvertOnRGB(A, R, G, B, extension);
        if (branch == BRANCH_RGBAF16_TO_ARGB8888) {
            destinationRow[i] = FillARGB8888(A, R, G, B);
        } else if (branch == BRANCH_RGBAF16_TO_RGBA8888) {
            destinationRow[i] = FillRGBA8888(R, G, B, A);
        } else if (branch == BRANCH_RGBAF16_TO_BGRA8888) {
            destinationRow[i] = FillBGRA8888(B, G, R, A);
        } else if (branch == BRANCH_RGBAF16_TO_ABGR8888) {
            destinationRow[i] = FillABGR8888(A, B, G, R);
        } else if (branch == BRANCH_RGBAF16_TO_RGB565) {
            R = R >> SHIFT_3_BIT;
            G = G >> SHIFT_2_BIT;
            B = B >> SHIFT_3_BIT;
            destinationRow[i] = FillRGB565(R, G, B);
        } else {
            break;
        }
        sourceRow += SIZE_8_BYTE;
    }
}

static void RGBAF16ConvertARGB8888(uint8_t *destinationRow, const uint8_t *sourceRow, uint32_t sourceWidth,
    const ProcFuncExtension &extension)
{
    void* tmp = static_cast<void *>(destinationRow);
    uint32_t *newDestinationRow = static_cast<uint32_t *>(tmp);
    RGBAF16Convert(newDestinationRow, sourceRow, sourceWidth, BRANCH_RGBAF16_TO_ARGB8888, extension);
}

static void RGBAF16ConvertRGBA8888(uint8_t *destinationRow, const uint8_t *sourceRow, uint32_t sourceWidth,
    const ProcFuncExtension &extension)
{
    void* tmp = static_cast<void *>(destinationRow);
    uint32_t *newDestinationRow = static_cast<uint32_t *>(tmp);
    RGBAF16Convert(newDestinationRow, sourceRow, sourceWidth, BRANCH_RGBAF16_TO_RGBA8888, extension);
}

static void RGBAF16ConvertBGRA8888(uint8_t *destinationRow, const uint8_t *sourceRow, uint32_t sourceWidth,
    const ProcFuncExtension &extension)
{
    void* tmp = static_cast<void *>(destinationRow);
    uint32_t *newDestinationRow = static_cast<uint32_t *>(tmp);
    RGBAF16Convert(newDestinationRow, sourceRow, sourceWidth, BRANCH_RGBAF16_TO_BGRA8888, extension);
}

static void RGBAF16ConvertABGR8888(uint8_t *destinationRow, const uint8_t *sourceRow, uint32_t sourceWidth,
    const ProcFuncExtension &extension)
{
    void* tmp = static_cast<void *>(destinationRow);
    uint32_t *newDestinationRow = static_cast<uint32_t *>(tmp);
    RGBAF16Convert(newDestinationRow, sourceRow, sourceWidth, BRANCH_RGBAF16_TO_ABGR8888, extension);
}

static void RGBAF16ConvertRGB565(uint8_t *destinationRow, const uint8_t *sourceRow, uint32_t sourceWidth,
    const ProcFuncExtension &extension)
{
    void* tmp = static_cast<void *>(destinationRow);
    uint16_t *newDestinationRow = static_cast<uint16_t *>(tmp);
    RGBAF16Convert(newDestinationRow, sourceRow, sourceWidth, BRANCH_RGBAF16_TO_RGB565, extension);
}

static map<string, ProcFuncType> g_procMapping;
static mutex g_procMutex;

static string MakeKey(uint32_t srcFormat, uint32_t dstFormat)
{
    return to_string(srcFormat) + ("_") + to_string(dstFormat);
}

static void InitGrayProc()
{
    g_procMapping.emplace(MakeKey(GRAY_BIT, ARGB_8888), &BitConvertARGB8888);
    g_procMapping.emplace(MakeKey(GRAY_BIT, RGB_565), &BitConvertRGB565);
    g_procMapping.emplace(MakeKey(GRAY_BIT, ALPHA_8), &BitConvertGray);

    g_procMapping.emplace(MakeKey(ALPHA_8, ARGB_8888), &GrayConvertARGB8888);
    g_procMapping.emplace(MakeKey(ALPHA_8, RGB_565), &GrayConvertRGB565);

    g_procMapping.emplace(MakeKey(GRAY_ALPHA, ARGB_8888), &GrayAlphaConvertARGB8888);
    g_procMapping.emplace(MakeKey(GRAY_ALPHA, ALPHA_8), &GrayAlphaConvertAlpha);
}

static void InitRGBProc()
{
    g_procMapping.emplace(MakeKey(RGB_888, ARGB_8888), &RGB888ConvertARGB8888);
    g_procMapping.emplace(MakeKey(RGB_888, RGBA_8888), &RGB888ConvertRGBA8888);
    g_procMapping.emplace(MakeKey(RGB_888, BGRA_8888), &RGB888ConvertBGRA8888);
    g_procMapping.emplace(MakeKey(RGB_888, RGB_565), &RGB888ConvertRGB565);

    g_procMapping.emplace(MakeKey(BGR_888, ARGB_8888), &BGR888ConvertARGB8888);
    g_procMapping.emplace(MakeKey(BGR_888, RGBA_8888), &BGR888ConvertRGBA8888);
    g_procMapping.emplace(MakeKey(BGR_888, BGRA_8888), &BGR888ConvertBGRA8888);
    g_procMapping.emplace(MakeKey(BGR_888, RGB_565), &BGR888ConvertRGB565);

    g_procMapping.emplace(MakeKey(RGB_161616, ARGB_8888), &RGB161616ConvertARGB8888);
    g_procMapping.emplace(MakeKey(RGB_161616, ABGR_8888), &RGB161616ConvertABGR8888);
    g_procMapping.emplace(MakeKey(RGB_161616, RGBA_8888), &RGB161616ConvertRGBA8888);
    g_procMapping.emplace(MakeKey(RGB_161616, BGRA_8888), &RGB161616ConvertBGRA8888);
    g_procMapping.emplace(MakeKey(RGB_161616, RGB_565), &RGB161616ConvertRGB565);

    g_procMapping.emplace(MakeKey(RGB_565, ARGB_8888), &RGB565ConvertARGB8888);
    g_procMapping.emplace(MakeKey(RGB_565, RGBA_8888), &RGB565ConvertRGBA8888);
    g_procMapping.emplace(MakeKey(RGB_565, BGRA_8888), &RGB565ConvertBGRA8888);
}

static void InitRGBAProc()
{
    g_procMapping.emplace(MakeKey(RGBA_8888, RGBA_8888), &RGBA8888ConvertRGBA8888Alpha);
    g_procMapping.emplace(MakeKey(RGBA_8888, ARGB_8888), &RGBA8888ConvertARGB8888);
    g_procMapping.emplace(MakeKey(RGBA_8888, BGRA_8888), &RGBA8888ConvertBGRA8888);
    g_procMapping.emplace(MakeKey(RGBA_8888, RGB_565), &RGBA8888ConvertRGB565);

    g_procMapping.emplace(MakeKey(BGRA_8888, RGBA_8888), &BGRA8888ConvertRGBA8888);
    g_procMapping.emplace(MakeKey(BGRA_8888, ARGB_8888), &BGRA8888ConvertARGB8888);
    g_procMapping.emplace(MakeKey(BGRA_8888, BGRA_8888), &BGRA8888ConvertBGRA8888Alpha);
    g_procMapping.emplace(MakeKey(BGRA_8888, RGB_565), &BGRA8888ConvertRGB565);

    g_procMapping.emplace(MakeKey(ARGB_8888, RGBA_8888), &ARGB8888ConvertRGBA8888);
    g_procMapping.emplace(MakeKey(ARGB_8888, ARGB_8888), &ARGB8888ConvertARGB8888Alpha);
    g_procMapping.emplace(MakeKey(ARGB_8888, BGRA_8888), &ARGB8888ConvertBGRA8888);
    g_procMapping.emplace(MakeKey(ARGB_8888, RGB_565), &ARGB8888ConvertRGB565);

    g_procMapping.emplace(MakeKey(RGBA_16161616, ARGB_8888), &RGBA16161616ConvertARGB8888);
    g_procMapping.emplace(MakeKey(RGBA_16161616, RGBA_8888), &RGBA16161616ConvertRGBA8888);
    g_procMapping.emplace(MakeKey(RGBA_16161616, BGRA_8888), &RGBA16161616ConvertBGRA8888);
    g_procMapping.emplace(MakeKey(RGBA_16161616, ABGR_8888), &RGBA16161616ConvertABGR8888);
}

static void InitCMYKProc()
{
    g_procMapping.emplace(MakeKey(CMKY, ARGB_8888), &CMYKConvertARGB8888);
    g_procMapping.emplace(MakeKey(CMKY, RGBA_8888), &CMYKConvertRGBA8888);
    g_procMapping.emplace(MakeKey(CMKY, BGRA_8888), &CMYKConvertBGRA8888);
    g_procMapping.emplace(MakeKey(CMKY, ABGR_8888), &CMYKConvertABGR8888);
    g_procMapping.emplace(MakeKey(CMKY, RGB_565), &CMYKConvertRGB565);
}

static void InitF16Proc()
{
    g_procMapping.emplace(MakeKey(RGBA_F16, ARGB_8888),
        reinterpret_cast<ProcFuncType>(&RGBAF16ConvertARGB8888));
    g_procMapping.emplace(MakeKey(RGBA_F16, RGBA_8888),
        reinterpret_cast<ProcFuncType>(&RGBAF16ConvertRGBA8888));
    g_procMapping.emplace(MakeKey(RGBA_F16, BGRA_8888),
        reinterpret_cast<ProcFuncType>(&RGBAF16ConvertBGRA8888));
    g_procMapping.emplace(MakeKey(RGBA_F16, ABGR_8888),
        reinterpret_cast<ProcFuncType>(&RGBAF16ConvertABGR8888));
    g_procMapping.emplace(MakeKey(RGBA_F16, RGB_565),
        reinterpret_cast<ProcFuncType>(&RGBAF16ConvertRGB565));

    g_procMapping.emplace(MakeKey(BGR_888, RGBA_F16),
        reinterpret_cast<ProcFuncType>(&BGR888ConvertRGBAF16));
    g_procMapping.emplace(MakeKey(RGB_888, RGBA_F16),
        reinterpret_cast<ProcFuncType>(&RGB888ConvertRGBAF16));
    g_procMapping.emplace(MakeKey(RGB_161616, RGBA_F16),
        reinterpret_cast<ProcFuncType>(&RGB161616ConvertRGBAF16));
    g_procMapping.emplace(MakeKey(ARGB_8888, RGBA_F16),
        reinterpret_cast<ProcFuncType>(&ARGB8888ConvertRGBAF16));
    g_procMapping.emplace(MakeKey(RGBA_8888, RGBA_F16),
        reinterpret_cast<ProcFuncType>(&RGBA8888ConvertRGBAF16));
    g_procMapping.emplace(MakeKey(BGRA_8888, RGBA_F16),
        reinterpret_cast<ProcFuncType>(&BGRA8888ConvertRGBAF16));
    g_procMapping.emplace(MakeKey(RGB_565, RGBA_F16),
        reinterpret_cast<ProcFuncType>(&RGB565ConvertRGBAF16));
    g_procMapping.emplace(MakeKey(RGBA_16161616, RGBA_F16),
        reinterpret_cast<ProcFuncType>(&RGBA16161616ConvertRGBAF16));
}

static ProcFuncType GetProcFuncType(uint32_t srcPixelFormat, uint32_t dstPixelFormat)
{
    unique_lock<mutex> guard(g_procMutex);
    if (g_procMapping.empty()) {
        InitGrayProc();
        InitRGBProc();
        InitRGBAProc();
        InitCMYKProc();
        InitF16Proc();
    }
    guard.unlock();
    string procKey = MakeKey(srcPixelFormat, dstPixelFormat);
    map<string, ProcFuncType>::iterator iter = g_procMapping.find(procKey);
    if (iter != g_procMapping.end()) {
        return iter->second;
    }
    return nullptr;
}

static AVPixelFormat PixelFormatToAVPixelFormat(const PixelFormat &pixelFormat)
{
    auto formatSearch = PixelConvertAdapter::FFMPEG_PIXEL_FORMAT_MAP.find(pixelFormat);
    return (formatSearch != PixelConvertAdapter::FFMPEG_PIXEL_FORMAT_MAP.end()) ?
        formatSearch->second : AVPixelFormat::AV_PIX_FMT_NONE;
}

typedef struct FFMpegConvertInfo {
    AVPixelFormat format = AVPixelFormat::AV_PIX_FMT_NONE;
    int32_t width = 0;
    int32_t height = 0;
    int32_t alignSize = 1;
} FFMPEG_CONVERT_INFO;

static bool FFMpegConvert(const void *srcPixels, const FFMPEG_CONVERT_INFO& srcInfo,
    void *dstPixels, const FFMPEG_CONVERT_INFO& dstInfo, YUVConvertColorSpaceDetails &colorSpaceDetails)
{
    bool ret = true;
    AVFrame *inputFrame = nullptr;
    AVFrame *outputFrame = nullptr;

    CHECK_ERROR_RETURN_RET_LOG(srcInfo.format == AVPixelFormat::AV_PIX_FMT_NONE ||
        dstInfo.format == AVPixelFormat::AV_PIX_FMT_NONE, false, "unsupport src/dst pixel format!");
    CHECK_ERROR_RETURN_RET_LOG((srcInfo.width <= 0 || srcInfo.height <= 0 ||
        dstInfo.width <= 0 || dstInfo.height <= 0 ||
        (SWS_CS_COEFFICIENT.find(colorSpaceDetails.srcYuvConversion) == SWS_CS_COEFFICIENT.end()) ||
        (SWS_CS_COEFFICIENT.find(colorSpaceDetails.dstYuvConversion) == SWS_CS_COEFFICIENT.end())),
        false, "src/dst width/height colorTableCoefficients error!");

    inputFrame = av_frame_alloc();
    outputFrame = av_frame_alloc();
    if (inputFrame != nullptr && outputFrame != nullptr) {
        struct SwsContext *ctx = sws_getContext(srcInfo.width, srcInfo.height, srcInfo.format,
            dstInfo.width, dstInfo.height, dstInfo.format, SWS_POINT, nullptr, nullptr, nullptr);
        IMAGE_LOGE("srcInfo.width:%{public}d, srcInfo.height:%{public}d", srcInfo.width, srcInfo.height);
        if (ctx != nullptr) {
            //if need applu colorspace in scale, change defult table;
            auto srcColorTable = sws_getCoefficients(SWS_CS_COEFFICIENT.at(colorSpaceDetails.srcYuvConversion));
            auto dstColorTable = sws_getCoefficients(SWS_CS_COEFFICIENT.at(colorSpaceDetails.dstYuvConversion));
            sws_setColorspaceDetails(ctx,
                // src convert matrix(YUV2RGB), Range: 0 means limit range, 1 means full range.
                srcColorTable, colorSpaceDetails.srcRange,
                // dst convert matrix(RGB2YUV, not used here).
                dstColorTable, colorSpaceDetails.dstRange,
                // brightness, contrast, saturation not adjusted.
                0, 1 << BIT_SHIFT_16BITS, 1 << BIT_SHIFT_16BITS);

            av_image_fill_arrays(inputFrame->data, inputFrame->linesize, (uint8_t *)srcPixels,
                srcInfo.format, srcInfo.width, srcInfo.height, srcInfo.alignSize);
            av_image_fill_arrays(outputFrame->data, outputFrame->linesize, (uint8_t *)dstPixels,
                dstInfo.format, dstInfo.width, dstInfo.height, dstInfo.alignSize);

            sws_scale(ctx, (uint8_t const **)inputFrame->data, inputFrame->linesize, 0, srcInfo.height,
                outputFrame->data, outputFrame->linesize);
            sws_freeContext(ctx);
        } else {
            IMAGE_LOGE("FFMpeg: sws_getContext failed!");
            ret = false;
        }
    } else {
        IMAGE_LOGE("FFMpeg: av_frame_alloc failed!");
        ret = false;
    }
    av_frame_free(&inputFrame);
    av_frame_free(&outputFrame);
    return ret;
}

static bool FFMpegConvert(const void *srcPixels, const FFMPEG_CONVERT_INFO& srcInfo,
    void *dstPixels, const FFMPEG_CONVERT_INFO& dstInfo)
{
    YUVConvertColorSpaceDetails colorSpaceDetails = { 0, 0 };
    return FFMpegConvert(srcPixels, srcInfo, dstPixels, dstInfo, colorSpaceDetails);
}

static bool NV12P010ToNV21P010(const uint16_t *srcBuffer, const ImageInfo &info, uint16_t *destBuffer)
{
    if (info.size.width <= 0 || info.size.height <= 0) {
        IMAGE_LOGE("Invalid Pixelmap size: width = %{public}d, height = %{public}d", info.size.width, info.size.height);
        return false;
    }
    uint32_t width = static_cast<uint32_t>(info.size.width);
    uint32_t height = static_cast<uint32_t>(info.size.height);
    if (width > UINT32_MAX / height) {
        IMAGE_LOGE("Image size too large: width = %{public}u, height = %{public}u", width, height);
        return false;
    }
    uint32_t ysize = width * height;
    uint32_t sizeUV = ysize / NUM_2;
    const uint16_t *srcUV = srcBuffer + ysize;
    uint16_t *dstVU = destBuffer + ysize;
    for (uint32_t i = 0; i < ysize; i++) {
        destBuffer[i] = srcBuffer[i];
    }
    for (uint32_t i = 0; i < sizeUV / UV_PLANES_COUNT; i++) {
        dstVU[UV_PLANES_COUNT * i] = srcUV[UV_PLANES_COUNT * i + 1];
        dstVU[UV_PLANES_COUNT * i + 1] = srcUV[UV_PLANES_COUNT * i];
    }
    return true;
}

bool IsYUVP010Format(PixelFormat format)
{
    return (format == PixelFormat::YCBCR_P010) || (format == PixelFormat::YCRCB_P010);
}

static bool ConvertForFFMPEG(const void *srcPixels, PixelFormat srcpixelmap, ImageInfo srcInfo,
    void *dstPixels, PixelFormat dstpixelmap)
{
    FFMPEG_CONVERT_INFO srcFFmpegInfo = {PixelFormatToAVPixelFormat(srcpixelmap),
        srcInfo.size.width, srcInfo.size.height, 1};
    FFMPEG_CONVERT_INFO dstFFmpegInfo = {PixelFormatToAVPixelFormat(dstpixelmap),
        srcInfo.size.width, srcInfo.size.height, 1};

    CHECK_ERROR_RETURN_RET_LOG((!FFMpegConvert(srcPixels, srcFFmpegInfo, dstPixels, dstFFmpegInfo)),
        false, "[PixelMap]Convert: ffmpeg convert failed!");

    return true;
}

static int64_t GetValidBufferSize(const ImageInfo &dstInfo)
{
    int64_t rowDataSize = ImageUtils::GetRowDataSizeByPixelFormat(dstInfo.size.width, dstInfo.pixelFormat);
    CHECK_ERROR_RETURN_RET_LOG(rowDataSize <= 0, CONVERT_ERROR,
        "[PixelMap] AllocPixelMapMemory: get row data size failed");

    int64_t bufferSize = rowDataSize * dstInfo.size.height;
    CHECK_ERROR_RETURN_RET_LOG(bufferSize > UINT32_MAX, CONVERT_ERROR,
        "[PixelMap]Create: Pixelmap size too large: width = %{public}d, height = %{public}d",
        dstInfo.size.width, dstInfo.size.height);
    return bufferSize;
}

static bool IsRGBFormat(PixelFormat format)
{
    return (format == PixelFormat::RGB_888) || (format == PixelFormat::RGB_565);
}

// Convert and collapse pixels by removing line paddings if any
static bool ConvertAndCollapseByFFMpeg(const void *srcPixels, const ImageInfo &srcInfo, void *dstPixels,
    const ImageInfo &dstInfo, bool useDMA)
{
    FFMPEG_CONVERT_INFO srcFFMpegInfo = {PixelFormatToAVPixelFormat(srcInfo.pixelFormat),
        srcInfo.size.width, srcInfo.size.height, useDMA ? DMA_LINE_SIZE : 1};
    FFMPEG_CONVERT_INFO dstFFMpegInfo = {PixelFormatToAVPixelFormat(dstInfo.pixelFormat),
        dstInfo.size.width, dstInfo.size.height, 1};

    std::unique_ptr<uint8_t[]> tmpBuffer = nullptr;
    bool needTmpBuffer = false;
    int64_t bufferSize = 0;
    if (IsRGBFormat(srcInfo.pixelFormat) && dstInfo.pixelFormat == PixelFormat::ARGB_8888) {
        bufferSize = GetValidBufferSize(dstInfo);
        CHECK_ERROR_RETURN_RET(bufferSize <= 0, false);

        tmpBuffer = std::make_unique<uint8_t[]>(bufferSize + 1); // avoid ffmpeg out-bounds-write
        CHECK_ERROR_RETURN_RET_LOG(tmpBuffer == nullptr, false,
            "[PixelMap] ConvertAndCollapseByFFMpeg: alloc memory failed!");
        needTmpBuffer = true;
    }
    void* conversionTarget = needTmpBuffer ? static_cast<void*>(tmpBuffer.get()) : dstPixels;
    bool cond = FFMpegConvert(srcPixels, srcFFMpegInfo, conversionTarget, dstFFMpegInfo);
    CHECK_ERROR_RETURN_RET_LOG(!cond, false, "[PixelMap] ConvertAndCollapseByFFMpeg: FFMpeg convert failed!");
    if (needTmpBuffer) {
        CHECK_ERROR_RETURN_RET_LOG(memcpy_s(dstPixels, bufferSize, conversionTarget, bufferSize) != 0, false,
            "[PixelMap] ConvertAndCollapseByFFMpeg: memcpy_s failed!");
    }
    return true;
}

static bool P010ConvertRGBA1010102(const void *srcPixels, ImageInfo srcInfo,
    void *dstPixels, ImageInfo dstInfo)
{
    FFMPEG_CONVERT_INFO srcFFmpegInfo = {PixelFormatToAVPixelFormat(srcInfo.pixelFormat),
        srcInfo.size.width, srcInfo.size.height, 1};
    FFMPEG_CONVERT_INFO tmpFFmpegInfo = {PixelFormatToAVPixelFormat(PixelFormat::RGBA_F16),
        srcInfo.size.width, srcInfo.size.height, 1};
    int tmpPixelsLen = av_image_get_buffer_size(tmpFFmpegInfo.format, tmpFFmpegInfo.width, tmpFFmpegInfo.height,
        tmpFFmpegInfo.alignSize);
   
    CHECK_ERROR_RETURN_RET_LOG((tmpPixelsLen <= 0), false, "[PixelMap]Convert: Get tmp pixels length failed!");

    uint8_t* tmpPixels = new(std::nothrow) uint8_t[tmpPixelsLen];
    CHECK_ERROR_RETURN_RET_LOG(tmpPixels == nullptr, false, "[PixelMap]Convert: alloc memory failed!");
    memset_s(tmpPixels, tmpPixelsLen, 0, tmpPixelsLen);
    if (!FFMpegConvert(srcPixels, srcFFmpegInfo, tmpPixels, tmpFFmpegInfo)) {
        IMAGE_LOGE("[PixelMap]Convert: ffmpeg convert failed!");
        delete[] tmpPixels;
        tmpPixels = nullptr;
        return false;
    }
    ImageInfo tmpInfo = srcInfo;
    tmpInfo.pixelFormat = PixelFormat::RGBA_U16;
    tmpInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_PREMUL;
    Position pos;
    if (!PixelConvertAdapter::WritePixelsConvert(tmpPixels, PixelMap::GetRGBxRowDataSize(tmpInfo), tmpInfo,
        dstPixels, pos, PixelMap::GetRGBxRowDataSize(dstInfo), dstInfo)) {
        IMAGE_LOGE("[PixelMap]Convert: ConvertFromYUV: pixel convert in adapter failed.");
        delete[] tmpPixels;
        tmpPixels = nullptr;
        return false;
    }
    delete[] tmpPixels;
    tmpPixels = nullptr;
    return true;
}

static bool P010ConvertRGB565(const uint8_t* srcP010, const ImageInfo& srcInfo,
    void* dstPixels, const ImageInfo& dstInfo)
{
    int64_t bufferSize = GetValidBufferSize(dstInfo);
    if (bufferSize <= 0) {
        return false;
    }

    std::unique_ptr<uint8_t[]> tmpBuffer =
        std::make_unique<uint8_t[]>(bufferSize + RGB565_EXTRA_BYTES); // avoid ffmpeg out-bounds-write
    if (tmpBuffer == nullptr) {
        IMAGE_LOGE("P010ConvertRGB565: alloc temp buffer failed");
        return false;
    }
    if (!ConvertForFFMPEG(srcP010, srcInfo.pixelFormat, srcInfo, tmpBuffer.get(), dstInfo.pixelFormat)) {
        IMAGE_LOGE("P010ConvertRGB565: FFMpeg convert failed");
        return false;
    }
    if (memcpy_s(dstPixels, bufferSize, tmpBuffer.get(), bufferSize) != 0) {
        IMAGE_LOGE("P010ConvertRGB565: memcpy_s dstPixels failed!");
        return false;
    }
    return true;
}

static bool ConvertRGBA1010102ToYUV(const void *srcPixels, ImageInfo srcInfo,
    void *dstPixels, ImageInfo dstInfo)
{
    ImageInfo copySrcInfo = srcInfo;
    copySrcInfo.pixelFormat = PixelFormat::RGBA_U16;
    bool cond = ImageUtils::GetAlignedNumber(copySrcInfo.size.width, EVEN_ALIGNMENT) &&
        ImageUtils::GetAlignedNumber(copySrcInfo.size.height, EVEN_ALIGNMENT);
    CHECK_ERROR_RETURN_RET(!cond, false);

    int copySrcLen = PixelMap::GetRGBxByteCount(copySrcInfo);
    CHECK_ERROR_RETURN_RET_LOG(copySrcLen <= 0, false, "[PixelMap]Convert: Get copySrc pixels length failed!");
    std::unique_ptr<uint8_t[]> copySrcBuffer = std::make_unique<uint8_t[]>(copySrcLen);
    CHECK_ERROR_RETURN_RET_LOG(copySrcBuffer == nullptr, false, "[PixelMap]Convert: alloc memory failed!");
    uint8_t* copySrcPixels = copySrcBuffer.get();
    memset_s(copySrcPixels, copySrcLen, 0, copySrcLen);

    Position pos;
    cond = PixelConvertAdapter::WritePixelsConvert(srcPixels, PixelMap::GetRGBxRowDataSize(srcInfo), srcInfo,
        copySrcPixels, pos, PixelMap::GetRGBxRowDataSize(copySrcInfo), copySrcInfo);
    CHECK_ERROR_RETURN_RET_LOG(!cond, false, "[PixelMap]Convert: ConvertToYUV: pixel convert in adapter failed.");

    FFMPEG_CONVERT_INFO srcFFmpegInfo = {PixelFormatToAVPixelFormat(PixelFormat::RGBA_F16),
        copySrcInfo.size.width, copySrcInfo.size.height, 1};
    FFMPEG_CONVERT_INFO dstFFmpegInfo = {PixelFormatToAVPixelFormat(dstInfo.pixelFormat),
        dstInfo.size.width, dstInfo.size.height, 1};
    cond = FFMpegConvert(copySrcPixels, srcFFmpegInfo, dstPixels, dstFFmpegInfo);
    CHECK_ERROR_RETURN_RET_LOG(!cond, false, "[PixelMap]Convert: ffmpeg convert failed!");
    return true;
}

static int32_t YUVConvertRGB(const void *srcPixels, const ImageInfo &srcInfo,
    void *dstPixels, const ImageInfo &dstInfo, YUVConvertColorSpaceDetails &colorSpaceDetails)
{
    FFMPEG_CONVERT_INFO srcFFmpegInfo = {PixelFormatToAVPixelFormat(srcInfo.pixelFormat),
        srcInfo.size.width, srcInfo.size.height, 1};
    FFMPEG_CONVERT_INFO tmpFFmpegInfo = {PixelFormatToAVPixelFormat(PixelFormat::RGB_888),
        srcInfo.size.width, srcInfo.size.height, 1};
    int tmpPixelsLen = av_image_get_buffer_size(tmpFFmpegInfo.format, tmpFFmpegInfo.width, tmpFFmpegInfo.height,
        tmpFFmpegInfo.alignSize);

    CHECK_ERROR_RETURN_RET_LOG((tmpPixelsLen <= 0), -1, "[PixelMap]Convert: Get tmp pixels length failed!");

    uint8_t* tmpPixels = new(std::nothrow) uint8_t[tmpPixelsLen];
    CHECK_ERROR_RETURN_RET_LOG(tmpPixels == nullptr, -1, "[PixelMap]Convert: alloc memory failed!");

    memset_s(tmpPixels, tmpPixelsLen, 0, tmpPixelsLen);
    if (!FFMpegConvert(srcPixels, srcFFmpegInfo, (void *)tmpPixels, tmpFFmpegInfo, colorSpaceDetails)) {
        IMAGE_LOGE("[PixelMap]Convert: ffmpeg convert failed!");
        delete[] tmpPixels;
        tmpPixels = nullptr;
        return -1;
    }

    ImageInfo tmpInfo = srcInfo;
    tmpInfo.pixelFormat = PixelFormat::RGB_888;
    Position pos;
    if (!PixelConvertAdapter::WritePixelsConvert(tmpPixels, PixelMap::GetRGBxRowDataSize(tmpInfo), tmpInfo,
        dstPixels, pos, PixelMap::GetRGBxRowDataSize(dstInfo), dstInfo)) {
        IMAGE_LOGE("[PixelMap]Convert: ConvertFromYUV: pixel convert in adapter failed.");
        delete[] tmpPixels;
        tmpPixels = nullptr;
        return -1;
    }

    delete[] tmpPixels;
    tmpPixels = nullptr;
    return PixelMap::GetRGBxByteCount(dstInfo);
}

static int32_t ConvertFromYUV(const BufferInfo &srcBufferInfo, const int32_t srcLength, BufferInfo &dstBufferInfo)
{
    bool cond = srcBufferInfo.pixels == nullptr || dstBufferInfo.pixels == nullptr || srcLength <= 0;
    CHECK_ERROR_RETURN_RET_LOG(cond, CONVERT_ERROR,
        "[PixelMap]Convert: src pixels or dst pixels or src pixels length invalid.");

    const ImageInfo &srcInfo = srcBufferInfo.imageInfo;
    const ImageInfo &dstInfo = dstBufferInfo.imageInfo;
    YUVConvertColorSpaceDetails colorSpaceDetails = {
        srcBufferInfo.range,
        dstBufferInfo.range,
        srcBufferInfo.yuvConversion,
        dstBufferInfo.yuvConversion
    };

    cond = (srcInfo.pixelFormat != PixelFormat::NV21 && srcInfo.pixelFormat != PixelFormat::NV12) ||
        (dstInfo.pixelFormat == PixelFormat::NV21 || dstInfo.pixelFormat == PixelFormat::NV12);
    CHECK_ERROR_RETURN_RET_LOG(cond, CONVERT_ERROR, "[PixelMap]Convert: src or dst pixel format invalid.");

    ImageInfo copySrcInfo = srcInfo;
    cond = ImageUtils::GetAlignedNumber(copySrcInfo.size.width, EVEN_ALIGNMENT) &&
        ImageUtils::GetAlignedNumber(copySrcInfo.size.height, EVEN_ALIGNMENT);
    CHECK_ERROR_RETURN_RET(!cond, CONVERT_ERROR);

    int32_t copySrcLen = PixelMap::GetAllocatedByteCount(copySrcInfo);
    CHECK_ERROR_RETURN_RET_LOG((copySrcLen <= 0), -1, "[PixelMap]Convert: Get copySrcLen pixels length failed!");
    std::unique_ptr<uint8_t[]> copySrcBuffer = std::make_unique<uint8_t[]>(copySrcLen);
    CHECK_ERROR_RETURN_RET_LOG((copySrcBuffer == nullptr), -1, "[PixelMap]Convert: alloc memory failed!");
    uint8_t* copySrcPixels = copySrcBuffer.get();
    memset_s(copySrcPixels, copySrcLen, 0, copySrcLen);
    cond = memcpy_s(copySrcPixels, copySrcLen, srcBufferInfo.pixels, std::min(srcLength, copySrcLen)) != EOK;
    CHECK_ERROR_RETURN_RET(cond, -1);
    if ((srcInfo.pixelFormat == PixelFormat::NV12 && dstInfo.pixelFormat == PixelFormat::YCBCR_P010) ||
        (srcInfo.pixelFormat == PixelFormat::NV21 && dstInfo.pixelFormat == PixelFormat::YCRCB_P010)) {
        return ConvertForFFMPEG(copySrcPixels, PixelFormat::NV12, srcInfo, dstBufferInfo.pixels,
            PixelFormat::YCBCR_P010) == true ? PixelMap::GetYUVByteCount(dstInfo) : -1;
    }
    if ((srcInfo.pixelFormat == PixelFormat::NV12 && dstInfo.pixelFormat == PixelFormat::YCRCB_P010) ||
        (srcInfo.pixelFormat == PixelFormat::NV21 && dstInfo.pixelFormat == PixelFormat::YCBCR_P010)) {
        return ConvertForFFMPEG(copySrcPixels, PixelFormat::NV21, srcInfo, dstBufferInfo.pixels,
            PixelFormat::YCBCR_P010) == true ? PixelMap::GetYUVByteCount(dstInfo) : -1;
    }

    return YUVConvertRGB(copySrcPixels, srcInfo, dstBufferInfo.pixels, dstInfo, colorSpaceDetails);
}

static int32_t ConvertFromP010(const void *srcPixels, const int32_t srcLength, const ImageInfo &srcInfo,
    void *dstPixels, const ImageInfo &dstInfo)
{
    bool cond = srcPixels == nullptr || dstPixels == nullptr || srcLength <= 0;
    CHECK_ERROR_RETURN_RET_LOG(cond, CONVERT_ERROR,
        "[PixelMap]Convert: src pixels or dst pixels or src pixels length invalid.");

    cond = (srcInfo.pixelFormat != PixelFormat::YCRCB_P010 && srcInfo.pixelFormat != PixelFormat::YCBCR_P010) ||
        IsYUVP010Format(dstInfo.pixelFormat);
    CHECK_ERROR_RETURN_RET_LOG(cond, CONVERT_ERROR, "[PixelMap]Convert: src or dst pixel format invalid.");

    ImageInfo copySrcInfo = srcInfo;
    cond = ImageUtils::GetAlignedNumber(copySrcInfo.size.width, EVEN_ALIGNMENT) &&
        ImageUtils::GetAlignedNumber(copySrcInfo.size.height, EVEN_ALIGNMENT);
    CHECK_ERROR_RETURN_RET(!cond, CONVERT_ERROR);

    int32_t srcP010Length = PixelMap::GetAllocatedByteCount(copySrcInfo);
    std::unique_ptr<uint8_t[]> srcP010Buffer = std::make_unique<uint8_t[]>(srcP010Length);
    CHECK_ERROR_RETURN_RET_LOG(srcP010Buffer == nullptr, CONVERT_ERROR, "[PixelMap]Convert: alloc memory failed!");

    uint8_t* srcP010 = srcP010Buffer.get();
    memset_s(srcP010, srcP010Length, 0, srcP010Length);
    if (srcInfo.pixelFormat == PixelFormat::YCRCB_P010) {
        NV12P010ToNV21P010((uint16_t *)srcPixels, srcInfo, (uint16_t *)srcP010);
    } else {
        CHECK_ERROR_RETURN_RET(memcpy_s(srcP010, srcP010Length, srcPixels, srcLength) != 0, CONVERT_ERROR);
    }
    if (dstInfo.pixelFormat == PixelFormat::RGBA_1010102) {
        if (P010ConvertRGBA1010102(srcP010, srcInfo, dstPixels, dstInfo)) {
            return PixelMap::GetRGBxByteCount(dstInfo);
        }
        return -1;
    } else if (dstInfo.pixelFormat == PixelFormat::RGB_565) {
        if (P010ConvertRGB565(srcP010, srcInfo, dstPixels, dstInfo)) {
            return PixelMap::GetRGBxByteCount(dstInfo);
        }
        return -1;
    } else {
        if (ConvertForFFMPEG(srcP010, srcInfo.pixelFormat, srcInfo, dstPixels, dstInfo.pixelFormat)) {
            return PixelMap::GetRGBxByteCount(dstInfo);
        }
        return -1;
    }
}

static int32_t RGBConvertYUV(const void *srcPixels, const ImageInfo &srcInfo,
    void *dstPixels, const ImageInfo &dstInfo)
{
    ImageInfo tmpInfo = srcInfo;
    tmpInfo.pixelFormat = PixelFormat::RGB_888;
    uint32_t tmpWidth = (static_cast<uint32_t>(tmpInfo.size.width) & 1) == 1 ?
        static_cast<uint32_t>(tmpInfo.size.width) + 1 : static_cast<uint32_t>(tmpInfo.size.width);
    size_t tmpPixelsLen = static_cast<size_t>(tmpWidth) * static_cast<size_t>(tmpInfo.size.height) *
        static_cast<size_t>(ImageUtils::GetPixelBytes(tmpInfo.pixelFormat));
    CHECK_ERROR_RETURN_RET_LOG(tmpPixelsLen == 0 || tmpPixelsLen > INT32_MAX, CONVERT_ERROR,
        "[PixelMap]Convert: Get tmp pixels length failed!");
    uint8_t* tmpPixels = new(std::nothrow) uint8_t[tmpPixelsLen];

    CHECK_ERROR_RETURN_RET_LOG((tmpPixels == nullptr), -1, "[PixelMap]Convert: alloc memory failed!");

    memset_s(tmpPixels, tmpPixelsLen, 0, tmpPixelsLen);
    Position pos;
    if (!PixelConvertAdapter::WritePixelsConvert(srcPixels, PixelMap::GetRGBxRowDataSize(srcInfo), srcInfo,
        tmpPixels, pos, PixelMap::GetRGBxRowDataSize(tmpInfo), tmpInfo)) {
        IMAGE_LOGE("[PixelMap]Convert: ConvertToYUV: pixel convert in adapter failed.");
        delete[] tmpPixels;
        tmpPixels = nullptr;
        return -1;
    }
    FFMPEG_CONVERT_INFO srcFFmpegInfo = {PixelFormatToAVPixelFormat(PixelFormat::RGB_888),
        tmpInfo.size.width, tmpInfo.size.height, 1};
    FFMPEG_CONVERT_INFO dstFFmpegInfo = {PixelFormatToAVPixelFormat(dstInfo.pixelFormat),
        dstInfo.size.width, dstInfo.size.height, 1};
    if (!FFMpegConvert(tmpPixels, srcFFmpegInfo, (void *)dstPixels, dstFFmpegInfo)) {
        IMAGE_LOGE("[PixelMap]Convert: ffmpeg convert failed!");
        delete[] tmpPixels;
        tmpPixels = nullptr;
        return -1;
    }
    delete[] tmpPixels;
    tmpPixels = nullptr;
    return av_image_get_buffer_size(dstFFmpegInfo.format, dstFFmpegInfo.width, dstFFmpegInfo.height,
        dstFFmpegInfo.alignSize);
}

static int32_t ConvertToYUV(const void *srcPixels, const int32_t srcLength, const ImageInfo &srcInfo,
    void *dstPixels, const ImageInfo &dstInfo)
{
    bool cond = srcPixels == nullptr || dstPixels == nullptr || srcLength <= 0;
    CHECK_ERROR_RETURN_RET_LOG(cond, CONVERT_ERROR,
        "[PixelMap]Convert: src pixels or dst pixels or src pixel length invalid");

    cond = (srcInfo.pixelFormat == PixelFormat::NV21 || srcInfo.pixelFormat == PixelFormat::NV12) ||
        (dstInfo.pixelFormat != PixelFormat::NV21 && dstInfo.pixelFormat != PixelFormat::NV12);
    CHECK_ERROR_RETURN_RET_LOG(cond, CONVERT_ERROR, "[PixelMap]Convert: src or dst pixel format invalid.");

    ImageInfo copySrcInfo = srcInfo;
    cond = ImageUtils::GetAlignedNumber(copySrcInfo.size.width, EVEN_ALIGNMENT) &&
        ImageUtils::GetAlignedNumber(copySrcInfo.size.height, EVEN_ALIGNMENT);
    CHECK_ERROR_RETURN_RET(!cond, CONVERT_ERROR);

    int32_t copySrcLen = PixelMap::GetAllocatedByteCount(copySrcInfo);
    CHECK_ERROR_RETURN_RET_LOG((copySrcLen <= 0), -1, "[PixelMap]Convert: Get copySrcLen pixels length failed!");
    std::unique_ptr<uint8_t[]> copySrcBuffer = std::make_unique<uint8_t[]>(copySrcLen);
    CHECK_ERROR_RETURN_RET_LOG((copySrcBuffer == nullptr), -1, "[PixelMap]Convert: alloc memory failed!");
    uint8_t* copySrcPixels = copySrcBuffer.get();
    memset_s(copySrcPixels, copySrcLen, 0, copySrcLen);
    cond = memcpy_s(copySrcPixels, copySrcLen, srcPixels, std::min(srcLength, copySrcLen)) != EOK;
    CHECK_ERROR_RETURN_RET(cond, -1);
    if ((srcInfo.pixelFormat == PixelFormat::YCBCR_P010 && dstInfo.pixelFormat == PixelFormat::NV12) ||
        (srcInfo.pixelFormat == PixelFormat::YCRCB_P010 && dstInfo.pixelFormat == PixelFormat::NV21)) {
        return ConvertForFFMPEG(copySrcPixels, PixelFormat::YCBCR_P010, srcInfo, dstPixels,
            PixelFormat::NV12) == true ? PixelMap::GetYUVByteCount(dstInfo) : -1;
    }
    if ((srcInfo.pixelFormat == PixelFormat::YCBCR_P010 && dstInfo.pixelFormat == PixelFormat::NV21) ||
        (srcInfo.pixelFormat == PixelFormat::YCRCB_P010 && dstInfo.pixelFormat == PixelFormat::NV12)) {
        return ConvertForFFMPEG(copySrcPixels, PixelFormat::YCBCR_P010, srcInfo, dstPixels,
            PixelFormat::NV21) == true ? PixelMap::GetYUVByteCount(dstInfo) : -1;
    }
    return RGBConvertYUV(copySrcPixels, srcInfo, dstPixels, dstInfo);
}

static int32_t ConvertToP010(const BufferInfo &src, BufferInfo &dst)
{
    const void *srcPixels = src.pixels;
    const int32_t srcLength = src.length;
    const ImageInfo &srcInfo = src.imageInfo;
    void *dstPixels = dst.pixels;
    const ImageInfo &dstInfo = dst.imageInfo;

    CHECK_ERROR_RETURN_RET_LOG((srcPixels == nullptr || dstPixels == nullptr || srcLength <= 0), -1,
        "[PixelMap]Convert: src pixels or dst pixels or src pixel length invalid");
    CHECK_ERROR_RETURN_RET_LOG((IsYUVP010Format(srcInfo.pixelFormat) ||
        (dstInfo.pixelFormat != PixelFormat::YCRCB_P010 && dstInfo.pixelFormat != PixelFormat::YCBCR_P010)),
        -1, "[PixelMap]Convert: src or dst pixel format invalid.");
    int32_t dstLength = PixelMap::GetYUVByteCount(dstInfo);

    CHECK_ERROR_RETURN_RET_LOG(dstLength <= 0, -1, "[PixelMap]Convert: Get dstP010 length failed!");

    std::unique_ptr<uint8_t[]> dstP010Buffer = std::make_unique<uint8_t[]>(dstLength);
    CHECK_ERROR_RETURN_RET_LOG(dstP010Buffer == nullptr, CONVERT_ERROR, "[PixelMap]Convert: alloc memory failed!");
    uint8_t* dstP010 = dstP010Buffer.get();
    memset_s(dstP010, dstLength, 0, dstLength);

    bool cond = false;
    if (srcInfo.pixelFormat == PixelFormat::RGBA_1010102) {
        cond = ConvertRGBA1010102ToYUV(srcPixels, srcInfo, dstP010, dstInfo);
        CHECK_ERROR_RETURN_RET(!cond, CONVERT_ERROR);
    } else {
        ImageInfo copySrcInfo = srcInfo;
        cond = ImageUtils::GetAlignedNumber(copySrcInfo.size.width, EVEN_ALIGNMENT) &&
            ImageUtils::GetAlignedNumber(copySrcInfo.size.height, EVEN_ALIGNMENT);
        CHECK_ERROR_RETURN_RET(!cond, CONVERT_ERROR);
        int32_t copySrcLength = PixelMap::GetAllocatedByteCount(copySrcInfo);
        std::unique_ptr<uint8_t[]> copySrcBuffer = std::make_unique<uint8_t[]>(copySrcLength);
        cond = copySrcBuffer == nullptr || EOK != memcpy_s(copySrcBuffer.get(), copySrcLength, srcPixels, srcLength);
        CHECK_ERROR_RETURN_RET_LOG(cond, CONVERT_ERROR, "alloc memory or memcpy_s failed!");
        cond = ConvertForFFMPEG(copySrcBuffer.get(), srcInfo.pixelFormat, srcInfo, dstP010, dstInfo.pixelFormat);
        CHECK_ERROR_RETURN_RET(!cond, CONVERT_ERROR);
    }
    if (dstInfo.pixelFormat == PixelFormat::YCRCB_P010) {
        NV12P010ToNV21P010((uint16_t *)dstP010, dstInfo, (uint16_t *)dstPixels);
    } else {
        CHECK_ERROR_RETURN_RET(memcpy_s(dstPixels, dst.length, dstP010, dstLength) != 0, CONVERT_ERROR);
    }
    return dstLength;
}

static int32_t YUVConvert(const BufferInfo &src, const int32_t srcLength, BufferInfo &dst)
{
    ImageInfo srcInfo = src.imageInfo;
    ImageInfo dstInfo = dst.imageInfo;
    const void *srcPixels = src.pixels;
    void* dstPixels = dst.pixels;
    if (srcInfo.pixelFormat == dstInfo.pixelFormat &&
        srcInfo.size.width == dstInfo.size.width && srcInfo.size.height == dstInfo.size.height) {
            IMAGE_LOGD("src pixel format is equal dst pixel format. no need to convert.");
            int32_t minLength = static_cast<int32_t>(dst.length) < srcLength ?
                static_cast<int32_t>(dst.length) : srcLength;
            auto result = memcpy_s(dstPixels, dst.length, srcPixels, minLength);
            return result == 0 ? minLength : -1;
    }
    if (IsYUVP010Format(srcInfo.pixelFormat) && IsYUVP010Format(dstInfo.pixelFormat)) {
        if (srcInfo.size.width == dstInfo.size.width && srcInfo.size.height == dstInfo.size.height) {
            return NV12P010ToNV21P010((uint16_t *)srcPixels, dstInfo, (uint16_t *)dstPixels) == true ?
                srcLength : -1;
        }
    }
    ImageInfo copySrcInfo = srcInfo;
    bool cond = ImageUtils::GetAlignedNumber(copySrcInfo.size.width, EVEN_ALIGNMENT) &&
        ImageUtils::GetAlignedNumber(copySrcInfo.size.height, EVEN_ALIGNMENT);
    CHECK_ERROR_RETURN_RET(!cond, CONVERT_ERROR);

    int32_t copySrcLen = PixelMap::GetAllocatedByteCount(copySrcInfo);
    CHECK_ERROR_RETURN_RET_LOG((copySrcLen <= 0), -1, "[PixelMap]Convert: Get copySrcLen pixels length failed!");
    std::unique_ptr<uint8_t[]> copySrcBuffer = std::make_unique<uint8_t[]>(copySrcLen);
    CHECK_ERROR_RETURN_RET_LOG((copySrcBuffer == nullptr), -1, "[PixelMap]Convert: alloc memory failed!");
    uint8_t* copySrcPixels = copySrcBuffer.get();
    memset_s(copySrcPixels, copySrcLen, 0, copySrcLen);
    cond = memcpy_s(copySrcPixels, copySrcLen, srcPixels, std::min(srcLength, copySrcLen)) != EOK;
    CHECK_ERROR_RETURN_RET(cond, -1);
    FFMPEG_CONVERT_INFO srcFFmpegInfo = {PixelFormatToAVPixelFormat(srcInfo.pixelFormat), srcInfo.size.width,
        srcInfo.size.height, 1};
    FFMPEG_CONVERT_INFO dstFFmpegInfo = {PixelFormatToAVPixelFormat(dstInfo.pixelFormat), dstInfo.size.width,
        dstInfo.size.height, 1};

    CHECK_ERROR_RETURN_RET_LOG(!FFMpegConvert(copySrcPixels, srcFFmpegInfo, dstPixels, dstFFmpegInfo),
        -1, "[PixelMap]Convert: ffmpeg convert failed!");
    
    return av_image_get_buffer_size(dstFFmpegInfo.format, dstFFmpegInfo.width, dstFFmpegInfo.height,
        dstFFmpegInfo.alignSize);
}

static bool IsInterYUVConvert(PixelFormat srcPixelFormat, PixelFormat dstPixelFormat)
{
    return (srcPixelFormat == PixelFormat::NV12 || srcPixelFormat == PixelFormat::NV21) &&
        (dstPixelFormat == PixelFormat::NV12 || dstPixelFormat == PixelFormat::NV21);
}

int32_t PixelConvert::PixelsConvert(const BufferInfo &src, BufferInfo &dst, bool useDMA)
{
    CHECK_ERROR_RETURN_RET_LOG(!(IsValidBufferInfo(src) && IsValidBufferInfo(dst)), CONVERT_ERROR,
        "[PixelMap]Convert: pixels or image info or row stride or src pixels length invalid.");
    return ConvertAndCollapseByFFMpeg(src.pixels, src.imageInfo, dst.pixels, dst.imageInfo, useDMA) ?
        PixelMap::GetRGBxByteCount(dst.imageInfo) : -1;
}

int32_t PixelConvert::CopySrcBufferAndConvert(const BufferInfo &src, BufferInfo &dst, int32_t srcLength, bool useDMA)
{
    bool cond = src.pixels == nullptr || dst.pixels == nullptr || srcLength <= 0;
    CHECK_ERROR_RETURN_RET_LOG(cond, CONVERT_ERROR,
        "[PixelMap]Convert: src pixels or dst pixels or src pixels length invalid.");

    ImageInfo copySrcInfo = src.imageInfo;
    cond = ImageUtils::GetAlignedNumber(copySrcInfo.size.width, EVEN_ALIGNMENT) &&
        ImageUtils::GetAlignedNumber(copySrcInfo.size.height, EVEN_ALIGNMENT);
    CHECK_ERROR_RETURN_RET(!cond, CONVERT_ERROR);
    int32_t copySrcLen = PixelMap::GetAllocatedByteCount(copySrcInfo);
    std::unique_ptr<uint8_t[]> copySrcBuffer = std::make_unique<uint8_t[]>(copySrcLen);
    CHECK_ERROR_RETURN_RET_LOG(copySrcBuffer == nullptr, CONVERT_ERROR, "[PixelMap]Convert: alloc memory failed!");

    uint8_t* copySrcPixels = copySrcBuffer.get();
    memset_s(copySrcPixels, copySrcLen, 0, copySrcLen);
    CHECK_ERROR_RETURN_RET(memcpy_s(copySrcPixels, copySrcLen, src.pixels, srcLength) != 0, CONVERT_ERROR);
    return ConvertAndCollapseByFFMpeg(copySrcPixels, src.imageInfo, dst.pixels, dst.imageInfo, useDMA) ?
        PixelMap::GetRGBxByteCount(dst.imageInfo) : CONVERT_ERROR;
}

int32_t PixelConvert::PixelsConvert(const BufferInfo &src, BufferInfo &dst, int32_t srcLength, bool useDMA)
{
    bool cond = IsValidBufferInfo(src) && IsValidBufferInfo(dst) && srcLength > 0;
    CHECK_ERROR_RETURN_RET_LOG(!cond, CONVERT_ERROR,
        "[PixelMap]Convert: pixels or image info or row stride or src pixels length invalid.");

    if (dst.imageInfo.pixelFormat == PixelFormat::ARGB_8888) {
        if (useDMA || (src.imageInfo.size.width % EVEN_ALIGNMENT == 0 &&
            src.imageInfo.size.height % EVEN_ALIGNMENT == 0)) {
            return ConvertAndCollapseByFFMpeg(src.pixels, src.imageInfo, dst.pixels, dst.imageInfo, useDMA) ?
                PixelMap::GetRGBxByteCount(dst.imageInfo) : CONVERT_ERROR;
        } else {
            return CopySrcBufferAndConvert(src, dst, srcLength, useDMA);
        }
    }
    if (IsInterYUVConvert(src.imageInfo.pixelFormat, dst.imageInfo.pixelFormat) ||
        (IsYUVP010Format(src.imageInfo.pixelFormat) && IsYUVP010Format(dst.imageInfo.pixelFormat))) {
        return YUVConvert(src, srcLength, dst);
    }
    if (src.imageInfo.pixelFormat == PixelFormat::NV12 || src.imageInfo.pixelFormat == PixelFormat::NV21) {
        return ConvertFromYUV(src, srcLength, dst);
    } else if (dst.imageInfo.pixelFormat == PixelFormat::NV12 || dst.imageInfo.pixelFormat == PixelFormat::NV21) {
        return ConvertToYUV(src.pixels, srcLength, src.imageInfo, dst.pixels, dst.imageInfo);
    } else if (IsYUVP010Format(src.imageInfo.pixelFormat)) {
        return ConvertFromP010(src.pixels, srcLength, src.imageInfo, dst.pixels, dst.imageInfo);
    } else if (IsYUVP010Format(dst.imageInfo.pixelFormat)) {
        return ConvertToP010(src, dst);
    }

    Position pos;
    cond = srcLength < src.imageInfo.size.width * src.imageInfo.size.height *
        ImageUtils::GetPixelBytes(src.imageInfo.pixelFormat);
    CHECK_ERROR_PRINT_LOG(cond, "srcLength = %{public}d, size:(%{public}d, %{public}d)", srcLength,
        src.imageInfo.size.width, src.imageInfo.size.height);
    IMAGE_LOGD("srcLength = %{public}d, size:(%{public}d, %{public}d)", srcLength,
        src.imageInfo.size.width, src.imageInfo.size.height);

    cond = PixelConvertAdapter::WritePixelsConvert(src.pixels,
        src.rowStride == 0 ? PixelMap::GetRGBxRowDataSize(src.imageInfo) : src.rowStride, src.imageInfo,
        dst.pixels, pos, useDMA ? dst.rowStride : PixelMap::GetRGBxRowDataSize(dst.imageInfo), dst.imageInfo);
    CHECK_ERROR_RETURN_RET_LOG(!cond, CONVERT_ERROR,
        "[PixelMap]Convert: PixelsConvert: pixel convert in adapter failed.");

    return PixelMap::GetRGBxByteCount(dst.imageInfo);
}

PixelConvert::PixelConvert(ProcFuncType funcPtr, ProcFuncExtension extension, bool isNeedConvert)
    : procFunc_(funcPtr), procFuncExtension_(extension), isNeedConvert_(isNeedConvert)
{}

// caller need setting the correct pixelFormat and alphaType
std::unique_ptr<PixelConvert> PixelConvert::Create(const ImageInfo &srcInfo, const ImageInfo &dstInfo)
{
    if (srcInfo.pixelFormat == PixelFormat::UNKNOWN || dstInfo.pixelFormat == PixelFormat::UNKNOWN) {
        IMAGE_LOGE("source or destination pixel format unknown");
        return nullptr;
    }
    uint32_t srcFormat = static_cast<uint32_t>(srcInfo.pixelFormat);
    uint32_t dstFormat = static_cast<uint32_t>(dstInfo.pixelFormat);
    ProcFuncType funcPtr = GetProcFuncType(srcFormat, dstFormat);
    if (funcPtr == nullptr) {
        IMAGE_LOGE("not found convert function. pixelFormat %{public}u -> %{public}u", srcFormat, dstFormat);
        return nullptr;
    }
    ProcFuncExtension extension;
    extension.alphaConvertType = GetAlphaConvertType(srcInfo.alphaType, dstInfo.alphaType);
    bool isNeedConvert = true;
    if ((srcInfo.pixelFormat == dstInfo.pixelFormat) && (extension.alphaConvertType == AlphaConvertType::NO_CONVERT)) {
        isNeedConvert = false;
    }
    return make_unique<PixelConvert>(funcPtr, extension, isNeedConvert);
}

AlphaConvertType PixelConvert::GetAlphaConvertType(const AlphaType &srcType, const AlphaType &dstType)
{
    if (srcType == AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN || dstType == AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN) {
        IMAGE_LOGD("source or destination alpha type unknown");
        return AlphaConvertType::NO_CONVERT;
    }
    if ((srcType == AlphaType::IMAGE_ALPHA_TYPE_PREMUL) && (dstType == AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL)) {
        return AlphaConvertType::PREMUL_CONVERT_UNPREMUL;
    }
    if ((srcType == AlphaType::IMAGE_ALPHA_TYPE_PREMUL) && (dstType == AlphaType::IMAGE_ALPHA_TYPE_OPAQUE)) {
        return AlphaConvertType::PREMUL_CONVERT_OPAQUE;
    }
    if ((srcType == AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL) && (dstType == AlphaType::IMAGE_ALPHA_TYPE_PREMUL)) {
        return AlphaConvertType::UNPREMUL_CONVERT_PREMUL;
    }
    if ((srcType == AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL) && (dstType == AlphaType::IMAGE_ALPHA_TYPE_OPAQUE)) {
        return AlphaConvertType::UNPREMUL_CONVERT_OPAQUE;
    }
    return AlphaConvertType::NO_CONVERT;
}

bool PixelConvert::IsValidRowStride(int32_t rowStride, const ImageInfo &imageInfo)
{
    if (imageInfo.pixelFormat == PixelFormat::YCBCR_P010 ||
        imageInfo.pixelFormat == PixelFormat::YCRCB_P010) {
        return rowStride == 0 || rowStride >= imageInfo.size.width * YUV420_P010_BYTES;
    }
    return rowStride == 0 || rowStride >= imageInfo.size.width * ImageUtils::GetPixelBytes(imageInfo.pixelFormat);
}

bool PixelConvert::IsValidBufferInfo(const BufferInfo &bufferInfo)
{
    return bufferInfo.pixels != nullptr && IsValidRowStride(bufferInfo.rowStride, bufferInfo.imageInfo);
}

void PixelConvert::Convert(void *destinationPixels, const uint8_t *sourcePixels, uint32_t sourcePixelsNum)
{
    if ((destinationPixels == nullptr) || (sourcePixels == nullptr)) {
        IMAGE_LOGE("destinationPixel or sourcePixel is null");
        return;
    }
    if (!isNeedConvert_) {
        IMAGE_LOGD("no need convert");
        return;
    }
    procFunc_(destinationPixels, sourcePixels, sourcePixelsNum, procFuncExtension_);
}

#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
static unsigned int UnpackBytes(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
    return static_cast<unsigned int>(a) +
        (static_cast<unsigned int>(b) << UNPACK_SHIFT_1) +
        (static_cast<unsigned int>(c) << UNPACK_SHIFT_2) +
        (static_cast<unsigned int>(d) << UNPACK_SHIFT_3);
}

static bool CheckAstcHead(uint8_t *astcBuf, unsigned int &blockX, unsigned int &blockY, uint32_t astcBufSize)
{
    CHECK_ERROR_RETURN_RET_LOG(astcBufSize < ASTC_UNIT_BYTES + ASTC_UNIT_BYTES, false,
        "DecAstc astcBufSize: %{public}d is invalid", astcBufSize);

    unsigned int magicVal = UnpackBytes(astcBuf[BYTE_POS_0], astcBuf[BYTE_POS_1], astcBuf[BYTE_POS_2],
        astcBuf[BYTE_POS_3]);
    CHECK_ERROR_RETURN_RET_LOG(magicVal != ASTC_MAGIC_ID, false, "DecAstc magicVal: %{public}d is invalid", magicVal);
    blockX = static_cast<unsigned int>(astcBuf[BYTE_POS_4]);
    blockY = static_cast<unsigned int>(astcBuf[BYTE_POS_5]);
    CHECK_ERROR_RETURN_RET_LOG(blockX != ASTC_BLOCK_SIZE_4 || blockY != blockX, false,
        "DecAstc blockX: %{public}d blockY: %{public}d not 4x4 or w!=h", blockX, blockY);
    CHECK_ERROR_RETURN_RET_LOG(astcBuf[BYTE_POS_6] != 1, false, "DecAstc astc buffer is not 1d");

    // dimZ = 1
    bool cond = UnpackBytes(astcBuf[BYTE_POS_13], astcBuf[BYTE_POS_14], astcBuf[BYTE_POS_15], 0) != 1;
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "DecAstc astc buffer is not 1d");

    CHECK_ERROR_RETURN_RET(blockX == 0 || blockY == 0, false);
    return true;
}

static bool InitAstcOutImage(astcenc_image &outImage, uint8_t *astcBuf, uint8_t *recRgba, uint32_t stride)
{
    outImage.dim_x = UnpackBytes(astcBuf[BYTE_POS_7], astcBuf[BYTE_POS_8], astcBuf[BYTE_POS_9], 0);
    outImage.dim_y = UnpackBytes(astcBuf[BYTE_POS_10], astcBuf[BYTE_POS_11], astcBuf[BYTE_POS_12], 0);
    outImage.dim_z = 1;
    outImage.dim_stride = stride;
    outImage.data_type = ASTCENC_TYPE_U8;
    outImage.data = new void* [1];
    CHECK_ERROR_RETURN_RET_LOG(outImage.data == nullptr, false, "DecAstc outImage.data is null");
    outImage.data[0] = recRgba;
    return true;
}

static void FreeAstcMem(astcenc_image &outImage, astcenc_context *codec_context)
{
    if (outImage.data != nullptr) {
        delete[] outImage.data;
    }
    if (codec_context != nullptr) {
        astcenc_context_free(codec_context);
    }
}

static bool DecAstc(uint8_t *recRgba, uint32_t stride, AstcInfo astcInfo)
{
    unsigned int blockX = 0;
    unsigned int blockY = 0;

    bool cond = CheckAstcHead(astcInfo.astcBuf, blockX, blockY, astcInfo.astcBufSize);
    CHECK_ERROR_RETURN_RET(!cond, false);

    unsigned int xblocks = (astcInfo.dimX + blockX - 1) / blockX;
    unsigned int yblocks = (astcInfo.dimY + blockY - 1) / blockY;
    size_t dataSize = xblocks * yblocks * ASTC_UNIT_BYTES;
    CHECK_ERROR_RETURN_RET_LOG(dataSize + ASTC_UNIT_BYTES > astcInfo.astcBufSize, false,
        "DecAstc astc buffer is invalid, dataSize: %{public}zu, astcBufSize: %{public}d",
        dataSize, astcInfo.astcBufSize);

    astcenc_config config = {};
    astcenc_error status = astcenc_config_init(ASTCENC_PRF_LDR_SRGB, blockX, blockY, 1, 0, 0x10, &config);
    CHECK_ERROR_RETURN_RET_LOG(status != ASTCENC_SUCCESS, false,
        "DecAstc init config failed with %{public}s", astcenc_get_error_string(status));
    config.flags = 0x12;
    astcenc_context *codec_context = nullptr;
    status = astcenc_context_alloc(&config, 1, &codec_context);

    CHECK_ERROR_RETURN_RET_LOG(status != ASTCENC_SUCCESS, false,
        "DecAstc codec context alloc failed: %{public}s", astcenc_get_error_string(status));
    astcenc_image outImage;
    if (!InitAstcOutImage(outImage, astcInfo.astcBuf, recRgba, stride)) {
        FreeAstcMem(outImage, codec_context);
        return false;
    }

    astcenc_swizzle swz_decode {ASTCENC_SWZ_R, ASTCENC_SWZ_G, ASTCENC_SWZ_B, ASTCENC_SWZ_A};
    status = astcenc_decompress_image(codec_context, astcInfo.astcBuf + ASTC_UNIT_BYTES, dataSize, &outImage,
        &swz_decode, 0);
    if (status != ASTCENC_SUCCESS) {
        IMAGE_LOGE("DecAstc codec decompress failed: %{public}s", astcenc_get_error_string(status));
        FreeAstcMem(outImage, codec_context);
        return false;
    }
    FreeAstcMem(outImage, codec_context);
    return true;
}

static bool CheckInputValid(AstcInfo &astcInfo, PixelFormat destFormat)
{
    bool isInvalidInput = (astcInfo.astcBufSize < ASTC_UNIT_BYTES || astcInfo.astcBuf == nullptr ||
        astcInfo.format != PixelFormat::ASTC_4x4 || destFormat != PixelFormat::RGBA_8888);
    if (isInvalidInput) {
        IMAGE_LOGE("DecAstc input astcBuf is null or src is not astc_4x4 or dst is not rgba_8888");
        return false;
    }
    unsigned int dimX = UnpackBytes(astcInfo.astcBuf[BYTE_POS_7], astcInfo.astcBuf[BYTE_POS_8],
        astcInfo.astcBuf[BYTE_POS_9], 0);
    unsigned int dimY = UnpackBytes(astcInfo.astcBuf[BYTE_POS_10], astcInfo.astcBuf[BYTE_POS_11],
        astcInfo.astcBuf[BYTE_POS_12], 0);
    bool cond = dimX > ASTC_DIM_MAX || dimY > ASTC_DIM_MAX ||
        dimX != static_cast<unsigned int>(astcInfo.astcSize.width) ||
        dimY != static_cast<unsigned int>(astcInfo.astcSize.height);
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "DecAstc dimX: %{public}d dimY: %{public}d overflow", dimX, dimY);
    astcInfo.dimX = dimX;
    astcInfo.dimY = dimY;
    return true;
}

static void GetStride(AllocatorType allocatorType, void *data, uint32_t &stride, Size astcSize)
{
    if (allocatorType == AllocatorType::DMA_ALLOC) {
        SurfaceBuffer *surfaceBuffer = reinterpret_cast<SurfaceBuffer *>(data);
        stride = static_cast<uint32_t>(surfaceBuffer->GetStride()) >> NUM_2;
    } else {
        stride = static_cast<uint32_t>(astcSize.width);
    }
}

static void InitAstcInfo(AstcInfo &astcInfo, PixelMap *source)
{
    astcInfo.astcBufSize = source->GetCapacity();
    astcInfo.astcBuf = const_cast<uint8_t *>(source->GetPixels());
    astcInfo.format = source->GetPixelFormat();
    source->GetAstcRealSize(astcInfo.astcSize);
}
#endif

std::unique_ptr<PixelMap> PixelConvert::AstcToRgba(PixelMap *source, uint32_t &errorCode, PixelFormat destFormat)
{
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    auto colorSpace = source->InnerGetGrColorSpace();
    AstcInfo astcInfo;
    if (memset_s(&astcInfo, sizeof(AstcInfo), 0, sizeof(AstcInfo)) != 0) {
        IMAGE_LOGE("DecAstc memset failed");
        errorCode = ERR_IMAGE_INIT_ABNORMAL;
        return nullptr;
    }
    InitAstcInfo(astcInfo, source);
    if (!CheckInputValid(astcInfo, destFormat)) {
        errorCode = ERR_IMAGE_INVALID_PARAMETER;
        return nullptr;
    }
    uint32_t byteCount = static_cast<uint32_t>(astcInfo.astcSize.width * astcInfo.astcSize.height * BYTES_PER_PIXEL);
    MemoryData memoryData = {nullptr, byteCount, "Create PixelMap", astcInfo.astcSize, PixelFormat::RGBA_8888};
    memoryData.usage = source->GetNoPaddingUsage();
    AllocatorType allocatorType = ImageUtils::GetPixelMapAllocatorType(astcInfo.astcSize, PixelFormat::RGBA_8888, true);
    std::unique_ptr<AbsMemory> dstMemory = MemoryManager::CreateMemory(allocatorType, memoryData);
    if (dstMemory == nullptr) {
        IMAGE_LOGE("DecAstc malloc failed");
        errorCode = ERR_IMAGE_MALLOC_ABNORMAL;
        return nullptr;
    }
    uint8_t *recRgba = static_cast<uint8_t *>(dstMemory->data.data);
    uint32_t stride = 0;
    GetStride(allocatorType, dstMemory->extend.data, stride, astcInfo.astcSize);
    if (!DecAstc(recRgba, stride, astcInfo)) {
        IMAGE_LOGE("DecAstc failed");
        dstMemory->Release();
        errorCode = ERR_IMAGE_DECODE_FAILED;
        return nullptr;
    }

    InitializationOptions opts = { astcInfo.astcSize, PixelFormat::RGBA_8888 };
    std::unique_ptr<PixelMap> result = PixelMap::Create(opts);
    if (result == nullptr) {
        IMAGE_LOGE("DecAstc create pixelmap failed");
        dstMemory->Release();
        errorCode = ERR_IMAGE_DECODE_FAILED;
        return nullptr;
    }
    result->SetPixelsAddr(static_cast<void *>(recRgba), dstMemory->extend.data, byteCount, allocatorType, nullptr);
    result->InnerSetColorSpace(colorSpace);
    return result;
#else
    errorCode = ERR_IMAGE_DECODE_FAILED;
    return nullptr;
#endif
}
} // namespace Media
} // namespace OHOS
