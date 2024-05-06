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

#ifndef INTERFACES_INNERKITS_INCLUDE_IMAGE_TYPE_H_
#define INTERFACES_INNERKITS_INCLUDE_IMAGE_TYPE_H_

#include <cinttypes>
#include <string>
#include "color_space.h"

namespace OHOS {
namespace Media {
#ifdef _WIN32
#define NATIVEEXPORT __declspec(dllexport)
#else
#define NATIVEEXPORT
#endif

enum class AllocatorType : int32_t {
    // keep same with java AllocatorType
    DEFAULT = 0,
    HEAP_ALLOC = 1,
    SHARE_MEM_ALLOC = 2,
    CUSTOM_ALLOC = 3,  // external
    DMA_ALLOC = 4, // SurfaceBuffer
};

enum class ColorSpace : int32_t {
    // unknown color space.
    UNKNOWN = 0,

    // based on SMPTE RP 431-2-2007 & IEC 61966-2.1:1999.
    DISPLAY_P3 = 1,

    // standard Red Green Blue based on IEC 61966-2.1:1999.
    SRGB = 2,

    // SRGB with a linear transfer function based on IEC 61966-2.1:1999.
    LINEAR_SRGB = 3,

    // based on IEC 61966-2-2:2003.
    EXTENDED_SRGB = 4,

    // based on IEC 61966-2-2:2003.
    LINEAR_EXTENDED_SRGB = 5,

    // based on standard illuminant D50 as the white point.
    GENERIC_XYZ = 6,

    // based on CIE XYZ D50 as the profile conversion space.
    GENERIC_LAB = 7,

    // based on SMPTE ST 2065-1:2012.
    ACES = 8,

    // based on Academy S-2014-004.
    ACES_CG = 9,

    // based on Adobe RGB (1998).
    ADOBE_RGB_1998 = 10,

    // based on SMPTE RP 431-2-2007.
    DCI_P3 = 11,

    // based on Rec. ITU-R BT.709-5.
    ITU_709 = 12,

    // based on Rec. ITU-R BT.2020-1.
    ITU_2020 = 13,

    // based on ROMM RGB ISO 22028-2:2013.
    ROMM_RGB = 14,

    // based on 1953 standard.
    NTSC_1953 = 15,

    // based on SMPTE C.
    SMPTE_C = 16,
};

enum class EncodedFormat : int32_t {
    UNKNOWN = 0,
    JPEG = 1,
    PNG = 2,
    GIF = 3,
    HEIF = 4,
    WEBP = 5,
    DNG = 6
};

enum class PixelFormat : int32_t {
    UNKNOWN = 0,
    ARGB_8888 = 1,  // Each pixel is stored on 4 bytes.
    RGB_565 = 2,    // Each pixel is stored on 2 bytes
    RGBA_8888 = 3,
    BGRA_8888 = 4,
    RGB_888 = 5,
    ALPHA_8 = 6,
    RGBA_F16 = 7,
    NV21 = 8,  // Each pixel is sorted on 3/2 bytes.
    NV12 = 9,
    CMYK = 10,
    ASTC_4x4 = 11,
    ASTC_6x6 = 12,
    ASTC_8x8 = 13,
    RGBA_1010102 = 14,
};

enum class DecodeDynamicRange : int32_t {
    AUTO = 0,
    SDR = 1,
    HDR = 2,
};

enum class EncodeDynamicRange : int32_t {
    AUTO = 0, //10bit jpeg will be encode as HDR_VIVID_DUAL, others will be encode as SDR
    SDR,
    HDR_VIVID_DUAL,
    HDR_VIVID_SINGLE,
};

enum class AlphaType : int32_t {
    IMAGE_ALPHA_TYPE_UNKNOWN = 0,
    IMAGE_ALPHA_TYPE_OPAQUE = 1,   // image pixels are stored as opaque.
    IMAGE_ALPHA_TYPE_PREMUL = 2,   // image have alpha component, and all pixels have premultiplied by alpha value.
    IMAGE_ALPHA_TYPE_UNPREMUL = 3, // image have alpha component, and all pixels stored without premultiply alpha value.
};

enum class MemoryUsagePreference : int32_t {
    DEFAULT = 0,
    LOW_RAM = 1,  // low memory
};

enum class FinalOutputStep : int32_t {
    NO_CHANGE = 0,
    CONVERT_CHANGE = 1,
    ROTATE_CHANGE = 2,
    SIZE_CHANGE = 3,
    DENSITY_CHANGE = 4
};

enum class ResolutionQuality : int32_t {
    LOW = 1,
    MEDIUM,
    HIGH
};

struct Position {
    int32_t x = 0;
    int32_t y = 0;
};

struct Rect {
    int32_t left = 0;
    int32_t top = 0;
    int32_t width = 0;
    int32_t height = 0;
};

struct Size {
    int32_t width = 0;
    int32_t height = 0;
};

struct ImageInfo {
    Size size;
    PixelFormat pixelFormat = PixelFormat::UNKNOWN;
    ColorSpace colorSpace = ColorSpace::SRGB;
    AlphaType alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN;
    int32_t baseDensity = 0;
    std::string encodedFormat;
};

struct YUVDataInfo {
    uint32_t y_width = 0;
    uint32_t y_height = 0;
    uint32_t uv_width = 0;
    uint32_t uv_height = 0;
    uint32_t y_stride = 0;
    uint32_t u_stride = 0;
    uint32_t v_stride = 0;
    uint32_t uv_stride = 0;
};

struct FillColor {
    bool isValidColor = false;
    uint32_t color = 0;
};

struct SVGResize {
    bool isValidPercentage = false;
    uint32_t resizePercentage = 100;
};

struct SVGDecodeOptions {
    FillColor fillColor;
    FillColor strokeColor;
    SVGResize SVGResize;
};

struct DecodeOptions {
    int32_t fitDensity = 0;
    Rect CropRect;
    Size desiredSize;
    Rect desiredRegion;
    float rotateDegrees = 0;
    uint32_t rotateNewDegrees = 0;
    static constexpr uint32_t DEFAULT_SAMPLE_SIZE = 1;
    uint32_t sampleSize = DEFAULT_SAMPLE_SIZE;
    PixelFormat desiredPixelFormat = PixelFormat::UNKNOWN;
#if defined(ANDROID_PLATFORM) || defined(IOS_PLATFORM)
    AllocatorType allocatorType = AllocatorType::HEAP_ALLOC;
#else
    AllocatorType allocatorType = AllocatorType::DEFAULT;
#endif
    ColorSpace desiredColorSpace = ColorSpace::SRGB;
    bool allowPartialImage = true;
    bool editable = false;
    MemoryUsagePreference preference = MemoryUsagePreference::DEFAULT;
    SVGDecodeOptions SVGOpts;
    std::shared_ptr<OHOS::ColorManager::ColorSpace> desiredColorSpaceInfo = nullptr;
    bool preferDma = false;
    bool fastAstc = false;
    uint16_t invokeType = 0;
    DecodeDynamicRange desiredDynamicRange = DecodeDynamicRange::SDR;
    ResolutionQuality resolutionQuality = ResolutionQuality::LOW;
    bool isAisr = false;
};

enum class ScaleMode : int32_t {
    FIT_TARGET_SIZE = 0,
    CENTER_CROP = 1,
};

enum class IncrementalMode { FULL_DATA = 0, INCREMENTAL_DATA = 1 };

// used in ScalePixelMapEx
enum class AntiAliasingOption : int32_t {
    NONE = 0, // SWS_POINT_NEAREST
    LOW = 1, // SWS_BILINEAR
    MEDIUM = 2, // SWS_BICUBIC
    HIGH = 3, // SWS_AREA
    FAST_BILINEAER = 4, // SWS_FAST_BILINEAER
    BICUBLIN = 5, // SWS_AREA
    GAUSS = 6, // SWS_GAUSS
    SINC = 7, // SWS_SINC
    LANCZOS = 8, // SWS_LANCZOS
    SPLINE = 9, // SWS_SPLINE
};
} // namespace Media
} // namespace OHOS

#endif // INTERFACES_INNERKITS_INCLUDE_IMAGE_TYPE_H_
