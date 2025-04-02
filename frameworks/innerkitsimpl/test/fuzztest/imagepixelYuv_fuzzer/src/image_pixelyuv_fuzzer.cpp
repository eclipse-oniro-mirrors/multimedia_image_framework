/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "image_pixelyuv_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <securec.h>

#include "pixel_map.h"

#include "image_log.h"
#include "image_source.h"

constexpr int32_t ODDTREE_ORIGINAL_WIDTH = 951;
constexpr int32_t ODDTREE_ORIGINAL_HEIGHT = 595;
constexpr int32_t ODDTREE_DEST_WIDTH = 361;
constexpr int32_t ODDTREE_DEST_HEIGHT = 200;

struct ImageSize {
    int32_t width = 0;
    int32_t height = 0;
    float dstWidth = 0;
    float dstHeight = 0;
};

namespace OHOS {
namespace Media {

void PixelMapYuvRotateTest(const uint8_t* data, size_t size, PixelFormat outfmt, ImageSize &imageSize, float degrees)
{
    if (data == nullptr) {
        return;
    }
    SourceOptions opts;
    uint32_t errorCode;
    std::shared_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(data, size, opts, errorCode);
    if (imageSource == nullptr) {
        return;
    }
    DecodeOptions decodeOpts;
    decodeOpts.desiredPixelFormat = outfmt;
    decodeOpts.desiredSize.width = imageSize.width;
    decodeOpts.desiredSize.height = imageSize.height;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    if (pixelMap == nullptr) {
        return;
    }
    pixelMap->rotate(degrees);
}

void PixelMapYuvP010RotateTest(const uint8_t* data, size_t size, PixelFormat outfmt, ImageSize &imageSize,
    float degrees)
{
    if (data == nullptr) {
        return;
    }
    SourceOptions opts;
    uint32_t errorCode;
    std::shared_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(data, size, opts, errorCode);
    if (imageSource == nullptr) {
        return;
    }
    DecodeOptions decodeOpts;
    decodeOpts.desiredPixelFormat = outfmt;
    decodeOpts.desiredSize.width = imageSize.width;
    decodeOpts.desiredSize.height = imageSize.height;
    decodeOpts.desiredDynamicRange = DecodeDynamicRange::HDR;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    if (pixelMap == nullptr) {
        return;
    }
    pixelMap->rotate(degrees);
}

void PixelMapYuvRotate(const uint8_t* data, size_t size)
{
    PixelFormat outfmt[] = {PixelFormat::NV12, PixelFormat::NV21};
    float degrees[] = {90, 180, 270};
    for (int i = 0; i < sizeof(outfmt) / sizeof(PixelFormat); ++i) {
        for (int j = 0; j < sizeof(degrees) / sizeof(float); ++j) {
            ImageSize imageSize = {ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT, 0, 0};
            PixelMapYuvRotateTest(data, size, outfmt[i], imageSize, degrees[j]);
        }
    }
    PixelFormat outfmtP010[] = {PixelFormat::YCBCR_P010, PixelFormat::YCRCB_P010};
    for (int i = 0; i < sizeof(outfmtP010) / sizeof(PixelFormat); ++i) {
        for (int j = 0; j < sizeof(degrees) / sizeof(float); ++j) {
            ImageSize imageSize = {ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT, 0, 0};
            PixelMapYuvP010RotateTest(data, size, outfmtP010[i], imageSize, degrees[j]);
        }
    }
}

void PixelMapYuvScaleTest(const uint8_t* data, size_t size, PixelFormat outfmt, ImageSize &imageSize,
    AntiAliasingOption option)
{
    if (data == nullptr) {
        return;
    }
    SourceOptions opts;
    uint32_t errorCode;
    std::shared_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(data, size, opts, errorCode);
    if (imageSource == nullptr) {
        return;
    }
    DecodeOptions decodeOpts;
    decodeOpts.desiredPixelFormat = outfmt;
    decodeOpts.desiredSize.width = imageSize.width;
    decodeOpts.desiredSize.height = imageSize.height;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    if (pixelMap == nullptr) {
        return;
    }
    pixelMap->scale(imageSize.dstWidth, imageSize.dstHeight, option);
}

void PixelMapYuvP010ScaleTest(const uint8_t* data, size_t size, PixelFormat outfmt, ImageSize &imageSize,
    AntiAliasingOption option)
{
    if (data == nullptr) {
        return;
    }
    SourceOptions opts;
    uint32_t errorCode;
    std::shared_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(data, size, opts, errorCode);
    if (imageSource == nullptr) {
        return;
    }
    DecodeOptions decodeOpts;
    decodeOpts.desiredPixelFormat = outfmt;
    decodeOpts.desiredSize.width = imageSize.width;
    decodeOpts.desiredSize.height = imageSize.height;
    decodeOpts.desiredDynamicRange = DecodeDynamicRange::HDR;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    if (pixelMap == nullptr) {
        return;
    }
    pixelMap->scale(imageSize.dstWidth, imageSize.dstHeight, option);
}

void PixelMapYuvScale(const uint8_t* data, size_t size)
{
    PixelFormat outfmt[] = {PixelFormat::NV12, PixelFormat::NV21};
    AntiAliasingOption options[] = {AntiAliasingOption::NONE, AntiAliasingOption::LOW,
                                    AntiAliasingOption::MEDIUM, AntiAliasingOption::HIGH};
    for (size_t j = 0; j < sizeof(outfmt) / sizeof(PixelFormat); j++) {
        for (size_t i = 0; i < sizeof(options) / sizeof(AntiAliasingOption); i++) {
            ImageSize imageSize = {ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT, ODDTREE_DEST_WIDTH,
                ODDTREE_DEST_HEIGHT};
            PixelMapYuvScaleTest(data, size, outfmt[j], imageSize, options[i]);
        }
    }
    PixelFormat outfmtP010[] = {PixelFormat::YCBCR_P010, PixelFormat::YCRCB_P010};
    for (size_t j = 0; j < sizeof(outfmtP010) / sizeof(PixelFormat); j++) {
        for (size_t i = 0; i < sizeof(options) / sizeof(AntiAliasingOption); i++) {
            ImageSize imageSize = {ODDTREE_ORIGINAL_WIDTH, ODDTREE_ORIGINAL_HEIGHT, ODDTREE_DEST_WIDTH,
                ODDTREE_DEST_HEIGHT};
            PixelMapYuvP010ScaleTest(data, size, outfmtP010[j], imageSize, options[i]);
        }
    }
}

} // namespace Media
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::Media::PixelMapYuvRotate(data, size);
    OHOS::Media::PixelMapYuvScale(data, size);
    return 0;
}