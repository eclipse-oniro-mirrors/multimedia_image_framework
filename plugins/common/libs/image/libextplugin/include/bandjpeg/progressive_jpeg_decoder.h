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

#ifndef PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_PROGRESSIVE_JPEG_DECODER_H
#define PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_PROGRESSIVE_JPEG_DECODER_H

#include <cstdint>
#include <cstddef>
#include <functional>
#include <memory>

#include "abs_image_decoder.h"
#include "bandjpeg/fast_manager.h"
#include "include/codec/SkCodec.h"
#include "include/core/SkImageInfo.h"

namespace OHOS {
namespace ImagePlugin {
class InputDataStream;

class ProgressiveJpegDecoder {
public:
    struct JpegInputData {
        uint8_t *buffer = nullptr;
        uint32_t bufferSize = 0;
        std::unique_ptr<uint8_t[]> ownedBuffer = nullptr;
    };
    using ReadJpegDataFunc = std::function<uint32_t(uint8_t *, uint32_t)>;

    struct RgbDecodeOptions {
        SkCodec *codec = nullptr;
        SkImageInfo srcInfo;
        SkImageInfo dstInfo;
        OHOS::Media::Size desiredSize = {0, 0};
        OHOS::Media::PixelFormat pixelFormat = OHOS::Media::PixelFormat::UNKNOWN;
        OHOS::Media::AllocatorType allocatorType = OHOS::Media::AllocatorType::DEFAULT;
        bool ifSourceCompleted = false;
        bool supportRegion = false;
        bool hasOutputBuffer = false;
        bool hasReusePixelmap = false;
        bool hasSubset = false;
        uint32_t sampleSize = 1;
        int softSampleSize = 1;
    };

    struct RgbDecodePlan {
        SkImageInfo dstInfo;
        uint64_t byteCount = 0;
        OHOS::Media::PixelFormat pixelFormat = OHOS::Media::PixelFormat::UNKNOWN;
        bool useDesiredSize = false;
        bool isRgb888Output = false;
    };

    struct YuvDecodeOptions {
        SkCodec *codec = nullptr;
        OHOS::Media::Size sourceSize = {0, 0};
        OHOS::Media::Size desiredSize = {0, 0};
        OHOS::Media::PixelFormat pixelFormat = OHOS::Media::PixelFormat::UNKNOWN;
        bool ifSourceCompleted = false;
        bool supportRegion = false;
        bool hasSubset = false;
        uint32_t sampleSize = 1;
        int softSampleSize = 1;
    };

    struct YuvDecodePlan {
        OHOS::Media::Size size = {0, 0};
        uint64_t bufferSize = 0;
    };

    static uint32_t GetJpegInputData(InputDataStream *stream, const ReadJpegDataFunc &readJpegData,
        JpegInputData &jpegData);

    // Region decode (fast::image::bandjpeg::DecodeImageRegion via FASTManager).
    // Region coordinates are in the unrotated original image and are never clipped here.
    // A desired size of {0, 0} selects FULL; otherwise both dimensions must be positive.
    static bool IsProgressiveJpeg(SkCodec *codec);

    struct RgbRegionOptions {
        int32_t sourceWidth = 0;
        int32_t sourceHeight = 0;
        int32_t regionX = 0;
        int32_t regionY = 0;
        int32_t regionWidth = 0;
        int32_t regionHeight = 0;
        int32_t desiredWidth = 0;
        int32_t desiredHeight = 0;
    };

    // Pure geometry/scale/output-size builder (no Skia/OHOS dependency, host-testable).
    // Fills regionX/Y/Width/Height, scale and dstWidth/dstHeight of params only;
    // input/output storage fields (jpegData/dst/stride/capacityBytes/rgbFormat) stay
    // caller-owned and can be filled after a successful build. Returns false for
    // invalid geometry or sizes; leaves params untouched on failure.
    static bool BuildRgbRegionParams(const RgbRegionOptions &options,
        fast::image::bandjpeg::RegionDecodeParams &params);

    // Runs fast::image::bandjpeg::DecodeImageRegion through FASTManager and maps
    // the native IMAGE_ErrorCode to the framework error code. Never falls back to
    // software decode.
    static uint32_t DecodeRegion(const fast::image::bandjpeg::RegionDecodeParams &params);
    static bool BuildRgbDecodePlan(const RgbDecodeOptions &options, RgbDecodePlan &plan);
    static uint32_t DecodeRgb(const JpegInputData &jpegData, const RgbDecodePlan &plan,
        uint8_t *dstPixels, size_t dstStride);
    static bool BuildYuvDecodePlan(const YuvDecodeOptions &options, YuvDecodePlan &plan);
    static uint32_t DecodeYuv(const JpegInputData &jpegData, const YuvDecodePlan &plan, DecodeContext &context);
    static uint64_t GetRgbOutputByteCount(const SkImageInfo &imageInfo, bool isRgb888Format);
    static uint64_t GetOutputRowStride(const SkImageInfo &imageInfo, const DecodeContext &context,
        const uint8_t *bufferForDecode);
    static void ResetDecodeContextPixelsBuffer(DecodeContext &context);
};
} // namespace ImagePlugin
} // namespace OHOS

#endif // PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_PROGRESSIVE_JPEG_DECODER_H
