/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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
#ifndef FAST_MANAGER_TEST_H
#define FAST_MANAGER_TEST_H

#include <dlfcn.h>
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace fast::image {
enum class FastErrCode {
    OK,
    INVALID_PTR,
    ILLEGAL_INPUT,
    DECODE_ERROR,
    OOM,
};

enum class IMAGE_ErrorCode {
    SUCCESS,
    SUCCESS_PARTIAL,
    ILLEGAL_INPUT,
    INVALID_PTR,
    UNSUPPORTED,
    DECODE_ERROR,
    OOM,
};

enum class YUVFormat {
    NV12,
    NV21,
};

enum class RGBFormat {
    RGB888,
    RGBA8888,
    BGRA8888,
    RGB565,
};

enum class AlphaType {
    UNKNOWN,
    OPAQUE,
    PREMUL,
    UNPREMUL,
};

struct TransferFunction {
    float g;
    float a;
    float b;
    float c;
    float d;
    float e;
    float f;
};

struct Matrix3x3 {
    float vals[3][3];
};

struct ColorSpace {
    TransferFunction fTransferFn;
    Matrix3x3 fToXYZD50;
};

struct ColorInfo {
    ColorSpace colorSpace;
    RGBFormat formatType;
    AlphaType fAlphaType = AlphaType::UNKNOWN;
};

// Region-decode mirror of fast::image::bandjpeg in libfast_image.so:
// DecodeImageRegion and its types live in the nested `bandjpeg` namespace on the
// fast side (namespace refactor), so the mirror must follow the same nesting.
namespace bandjpeg {

// Native reduced-IDCT scale used by region decode. Enum values are IDCT output
// block sizes, NOT sampling denominators: FULL/HALF/QUARTER/EIGHTH map to the
// denominators 1/2/4/8 when deriving region output geometry. Must match the
// fast::image::bandjpeg::DecodeScale in libfast_image.so (ABI).
enum class DecodeScale : uint8_t {
    EIGHTH = 1,
    QUARTER = 2,
    HALF = 4,
    FULL = 8,
};

// Mirror of fast::image::bandjpeg::RegionDecodeParams in libfast_image.so.
// Layout and field order are ABI-critical for the dlsym'ed DecodeImageRegion
// call; do not reorder, and keep the exact underlying types (DecodeScale:
// uint8_t, RGBFormat: default int from the outer fast::image namespace).
struct RegionDecodeParams {
    const uint8_t* jpegData = nullptr;   ///< Complete JPEG data, read-only.
    size_t jpegSize = 0;                 ///< Declared readable bytes; non-zero.
    uint32_t regionX = 0;                ///< Region left edge in the original image.
    uint32_t regionY = 0;                ///< Region top edge in the original image.
    uint32_t regionWidth = 0;            ///< Region width in pixels.
    uint32_t regionHeight = 0;           ///< Region height in pixels.
    DecodeScale scale = DecodeScale::FULL;  ///< Native decode scale.
    uint8_t* dst = nullptr;              ///< Writable storage base address.
    uint32_t dstWidth = 0;               ///< Exact output width; must equal W.
    uint32_t dstHeight = 0;              ///< Exact output height; must equal H.
    size_t stride = 0;                   ///< Byte span between adjacent output rows.
    RGBFormat rgbFormat = RGBFormat::RGBA8888;  ///< Packed output format.
    size_t capacityBytes = 0;            ///< Declared writable bytes from dst.
};
}  // namespace bandjpeg
}

namespace OHOS {
namespace ImagePlugin {

class FASTManager {
public:
    static FASTManager& GetInstance();

    bool IsInitialized() const { return isInitialized_; }

    bool IsGamutAvailable() const { return isInitialized_ && ColorSpaceConvert != nullptr; }

    fast::image::FastErrCode (*DecodeImage)(const uint8_t*, size_t, uint8_t*, uint32_t,
        uint32_t, size_t, fast::image::RGBFormat) = nullptr;
    fast::image::FastErrCode (*DecodeImageYUV)(const uint8_t*, size_t, uint8_t*, uint8_t*, uint32_t,
        uint32_t, size_t, size_t, fast::image::YUVFormat) = nullptr;
    fast::image::IMAGE_ErrorCode (*ColorSpaceConvert)(uint8_t*, uint32_t, fast::image::ColorInfo,
        uint8_t*, uint32_t, fast::image::ColorInfo, uint32_t, uint32_t) = nullptr;
    fast::image::IMAGE_ErrorCode (*DecodeImageRegion)(const fast::image::bandjpeg::RegionDecodeParams&) = nullptr;

private:
    FASTManager();
    ~FASTManager();
    FASTManager(const FASTManager&) = delete;
    FASTManager(const FASTManager&&) = delete;
    FASTManager& operator=(const FASTManager&) = delete;
    FASTManager& operator=(const FASTManager&&) = delete;

    void* FASTHandle_ = nullptr;
    bool isInitialized_ = false; // initialization flag
};
}
}
#endif
