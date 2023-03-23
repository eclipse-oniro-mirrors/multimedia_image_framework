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

#ifndef FRAMEWORKS_INNERKITSIMPL_CONVERTER_INCLUDE_PIXEL_CONVERT_H_
#define FRAMEWORKS_INNERKITSIMPL_CONVERTER_INCLUDE_PIXEL_CONVERT_H_

#include <cstdint>
#include <cmath>
#include <memory>
#include "hilog/log.h"
#include "image_type.h"
#include "log_tags.h"

namespace OHOS {
namespace Media {
enum class AlphaConvertType : uint32_t {
    NO_CONVERT = 0,
    PREMUL_CONVERT_UNPREMUL = 1,
    PREMUL_CONVERT_OPAQUE = 2,
    UNPREMUL_CONVERT_PREMUL = 3,
    UNPREMUL_CONVERT_OPAQUE = 4,
};

// now support AlphaConvertType
struct ProcFuncExtension {
    AlphaConvertType alphaConvertType;
};

// These values SHOULD be sync with image_type.h PixelFormat
constexpr uint32_t GRAY_BIT = 0x80000001; /* Tow value image, just white or black. */
constexpr uint32_t GRAY_ALPHA = 0x80000002;
constexpr uint32_t ARGB_8888 = 0x00000001;
constexpr uint32_t RGB_565 = 0x00000002;
constexpr uint32_t RGBA_8888 = 0x00000003;
constexpr uint32_t BGRA_8888 = 0x00000004;
constexpr uint32_t RGB_888 = 0x00000005;
constexpr uint32_t ALPHA_8 = 0x00000006; /* Gray image, 8 bit = 255 color. */
constexpr uint32_t RGBA_F16 = 0x00000007;
constexpr uint32_t ABGR_8888 = 0x00000008;
constexpr uint32_t BGR_888 = 0x40000002;
constexpr uint32_t RGB_161616 = 0x40000007;
constexpr uint32_t RGBA_16161616 = 0x40000008;

constexpr uint32_t CMKY = 0x0000000A;

constexpr uint32_t SIZE_1_BYTE = 0x00000001; /* a pixel has 8 bit = 1 byte */
constexpr uint32_t SIZE_2_BYTE = 0x00000002; /* a pixel has 16 bit = 2 byte */
constexpr uint32_t SIZE_3_BYTE = 0x00000003;
constexpr uint32_t SIZE_4_BYTE = 0x00000004;
constexpr uint32_t SIZE_6_BYTE = 0x00000006;
constexpr uint32_t SIZE_8_BYTE = 0x00000008;

constexpr uint8_t GRAYSCALE_WHITE = 0xFF;
constexpr uint8_t GRAYSCALE_BLACK = 0x00;
constexpr uint32_t ARGB_WHITE = 0xFFFFFFFF;
constexpr uint32_t ARGB_BLACK = 0xFF000000;
constexpr uint16_t RGB_WHITE = 0xFFFF;
constexpr uint16_t RGB_BLACK = 0x0000;

constexpr uint8_t ALPHA_OPAQUE = 0xFF;
constexpr uint8_t ALPHA_TRANSPARENT = 0x00;

constexpr uint32_t GET_8_BIT = 0x80;
constexpr uint32_t GET_1_BIT = 0x01;

constexpr uint32_t SHIFT_48_BIT = 0x30;
constexpr uint32_t SHIFT_32_BIT = 0x20;
constexpr uint32_t SHIFT_24_BIT = 0x18;
constexpr uint32_t SHIFT_16_BIT = 0x10;
constexpr uint32_t SHIFT_8_BIT = 0x08;
constexpr uint32_t SHIFT_11_BIT = 0x0B;
constexpr uint32_t SHIFT_5_BIT = 0x05;
constexpr uint32_t SHIFT_3_BIT = 0x03;
constexpr uint32_t SHIFT_2_BIT = 0x02;

constexpr uint32_t SHIFT_32_MASK = 0x80000000;
constexpr uint32_t SHIFT_16_MASK = 0x8000;
constexpr uint32_t SHIFT_7_MASK = 0x1C000;
constexpr uint8_t SHIFT_5_MASK = 0x1F;
constexpr uint8_t SHIFT_3_MASK = 0x07;

constexpr uint8_t SHIFT_HALF_BIT = 0x0D;
constexpr uint32_t SHIFT_HALF_MASK = 0x38000000;

constexpr uint16_t MAX_15_BIT_VALUE = 0x7FFF;
constexpr uint16_t MAX_16_BIT_VALUE = 0xFFFF;
constexpr uint32_t MAX_31_BIT_VALUE = 0x7FFFFFFF;
constexpr float HALF_ONE = 0.5F;
constexpr float MAX_HALF = 65504;
constexpr float MIN_EPSILON = 1e-6;

static inline bool FloatCompareTo(float val, float compare)
{
    return fabs(val - compare) < MIN_EPSILON;
}

static inline uint32_t Premul255(uint32_t colorComponent, uint32_t alpha)
{
    if (colorComponent == 0 || colorComponent > MAX_15_BIT_VALUE || alpha > MAX_15_BIT_VALUE) {
        return 0;
    }
    uint32_t product = colorComponent * alpha + GET_8_BIT;
    if (colorComponent * alpha / colorComponent != alpha) {
        return 0;
    }
    return ((product + (product >> SHIFT_8_BIT)) >> SHIFT_8_BIT);
}

static inline uint32_t Unpremul255(uint32_t colorComponent, uint32_t alpha)
{
    if (colorComponent > ALPHA_OPAQUE || alpha > ALPHA_OPAQUE) {
        return 0;
    }
    if (alpha == ALPHA_TRANSPARENT) {
        return ALPHA_TRANSPARENT;
    }
    if (alpha == ALPHA_OPAQUE) {
        return colorComponent;
    }
    uint32_t result = static_cast<float>(colorComponent) * ALPHA_OPAQUE / alpha + HALF_ONE;
    return (result > ALPHA_OPAQUE) ? ALPHA_OPAQUE : result;
}

static inline uint32_t FloatToUint(float f)
{
    uint32_t *p = reinterpret_cast<uint32_t*>(&f);
    return *p;
}

static inline float UintToFloat(uint32_t ui)
{
    float *pf = reinterpret_cast<float*>(&ui);
    return *pf;
}

static inline uint16_t FloatToHalf(float f)
{
    uint32_t u32 = FloatToUint(f);
    uint16_t u16 = static_cast<uint16_t>(
        (((u32 & MAX_31_BIT_VALUE) >> SHIFT_HALF_BIT) - SHIFT_7_MASK) & MAX_16_BIT_VALUE);
    u16 |= static_cast<uint16_t>(
        ((u32 & SHIFT_32_MASK) >> SHIFT_16_BIT) & MAX_16_BIT_VALUE);
    return u16;
}

static inline float HalfToFloat(uint16_t ui)
{
    uint32_t u32 = ((ui & MAX_15_BIT_VALUE) << SHIFT_HALF_BIT) + SHIFT_HALF_MASK;
    u32 |= ((ui & SHIFT_16_MASK) << SHIFT_16_BIT);
    return UintToFloat(u32);
}

static inline uint16_t U8ToU16(uint8_t val1, uint8_t val2)
{
    uint16_t ret = val1;
    return ((ret << SHIFT_8_BIT) | val2);
}

static inline uint32_t HalfToUint32(const uint8_t* ui, bool isLittleEndian)
{
    uint16_t val = isLittleEndian?U8ToU16(*ui, *(ui + 1)):U8ToU16(*(ui + 1), *ui);
    float fRet = HalfToFloat(val);
    return static_cast<uint32_t> (fRet);
}

using ProcFuncType = void (*)(void *destinationRow, const uint8_t *sourceRow, uint32_t sourceWidth,
                              const ProcFuncExtension &extension);
class PixelConvert {
public:
    ~PixelConvert() = default;
    static std::unique_ptr<PixelConvert> Create(const ImageInfo &srcInfo, const ImageInfo &dstInfo);
    void Convert(void *destinationPixels, const uint8_t *sourcePixels, uint32_t sourcePixelsNum);

private:
    PixelConvert(ProcFuncType funcPtr, ProcFuncExtension extension, bool isNeedConvert);
    static AlphaConvertType GetAlphaConvertType(const AlphaType &srcType, const AlphaType &dstType);

    ProcFuncType procFunc_;
    ProcFuncExtension procFuncExtension_;
    bool isNeedConvert_ = true;
};
} // namespace Media
} // namespace OHOS

#endif // FRAMEWORKS_INNERKITSIMPL_CONVERTER_INCLUDE_PIXEL_CONVERT_H_
