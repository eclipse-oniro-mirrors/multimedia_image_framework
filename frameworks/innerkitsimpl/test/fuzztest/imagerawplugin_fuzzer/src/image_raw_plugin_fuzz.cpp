/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include <fuzzer/FuzzedDataProvider.h>
#include "image_raw_plugin_fuzz.h"

#include <cstdint>
#include <string>
#include <unistd.h>
#include <fcntl.h>

#include "buffer_source_stream.h"
#include "common_fuzztest_function.h"
#include "image_source.h"
#include "raw_decoder.h"
#include "image_log.h"
#include "data_buf.h"

namespace OHOS {
namespace Media {
using namespace OHOS::ImagePlugin;
FuzzedDataProvider *FDP;

namespace {
    static constexpr uint32_t RAW_DECODING_STATE_MODULE = 8;
    static constexpr uint32_t NUM_ZERO = 0;
    static constexpr uint32_t NUM_ONE = 1;
    static constexpr uint32_t ALLOCATOR_TYPE_MODULE = 5;
    static constexpr uint32_t COLOR_SPACE_MODULE = 17;
    static constexpr uint32_t IMAGE_HDR_TYPE_MODULE = 8;
    static constexpr uint32_t ALPHA_TYPE_MODULE = 4;
    static constexpr uint32_t RESOLUTION_QUALITY_MODULE = 4;
    static constexpr uint32_t PIXEL_FORMAT_MODULE = 105;

    std::unique_ptr<BufferSourceStream> bufferSourceStream;
}

std::shared_ptr<RawDecoder> ConstructRawDecoder(const uint8_t *data, size_t size)
{
    std::shared_ptr<RawDecoder> rawDecoder = std::make_shared<RawDecoder>();
    if (!rawDecoder) {
        return nullptr;
    }
    if (!bufferSourceStream) {
        bufferSourceStream = BufferSourceStream::CreateSourceStream(data, size);
        if (!bufferSourceStream) {
            return nullptr;
        }
    }
    rawDecoder->SetSource(*bufferSourceStream.get());
    return rawDecoder;
}

Size ConstructSize()
{
    return Size {
        .width = FDP->ConsumeIntegral<int32_t>(),
        .height = FDP->ConsumeIntegral<int32_t>() };
}

YUVDataInfo ConstructYUVDataInfo()
{
    return YUVDataInfo {
        .imageSize = ConstructSize(),
        .yWidth = FDP->ConsumeIntegral<uint32_t>(),
        .yHeight = FDP->ConsumeIntegral<uint32_t>(),
        .uvWidth = FDP->ConsumeIntegral<uint32_t>(),
        .uvHeight = FDP->ConsumeIntegral<uint32_t>(),
        .yStride = FDP->ConsumeIntegral<uint32_t>(),
        .uStride = FDP->ConsumeIntegral<uint32_t>(),
        .vStride = FDP->ConsumeIntegral<uint32_t>(),
        .uvStride = FDP->ConsumeIntegral<uint32_t>(),
        .yOffset = FDP->ConsumeIntegral<uint32_t>(),
        .uOffset = FDP->ConsumeIntegral<uint32_t>(),
        .vOffset = FDP->ConsumeIntegral<uint32_t>(),
        .uvOffset = FDP->ConsumeIntegral<uint32_t>() };
}

PlImageInfo ConstructPlImageInfo()
{
    return PlImageInfo {
        .size = ConstructSize(),
        .pixelFormat = static_cast<PixelFormat>(FDP->ConsumeIntegral<uint32_t>() % PIXEL_FORMAT_MODULE),
        .colorSpace = static_cast<ColorSpace>(FDP->ConsumeIntegral<uint32_t>() % COLOR_SPACE_MODULE),
        .alphaType = static_cast<AlphaType>(FDP->ConsumeIntegral<uint32_t>() % ALPHA_TYPE_MODULE),
        .yuvDataInfo = ConstructYUVDataInfo() };
}

DecodeContext ConstructDecodeContext()
{
    return DecodeContext {
        .info = ConstructPlImageInfo(),
        .pixelmapUniqueId_ = FDP->ConsumeIntegral<uint32_t>(),
        .ifSourceCompleted = FDP->ConsumeBool(),
        .pixelFormat = static_cast<PixelFormat>(FDP->ConsumeIntegral<uint32_t>() % PIXEL_FORMAT_MODULE),
        .photoDesiredPixelFormat = static_cast<PixelFormat>(FDP->ConsumeIntegral<uint32_t>() % PIXEL_FORMAT_MODULE),
        .colorSpace = static_cast<ColorSpace>(FDP->ConsumeIntegral<uint32_t>() % COLOR_SPACE_MODULE),
        .ifPartialOutput = FDP->ConsumeBool(),
        .allocatorType = static_cast<AllocatorType>(FDP->ConsumeIntegral<uint32_t>() % ALLOCATOR_TYPE_MODULE),
        .yuvInfo = ConstructYUVDataInfo(),
        .isHardDecode = FDP->ConsumeBool(),
        .hdrType = static_cast<ImageHdrType>(FDP->ConsumeIntegral<uint32_t>() % IMAGE_HDR_TYPE_MODULE),
        .resolutionQuality =
            static_cast<ResolutionQuality>(FDP->ConsumeIntegral<uint32_t>() % RESOLUTION_QUALITY_MODULE),
        .isAisr = FDP->ConsumeBool(),
        .isAppUseAllocator = FDP->ConsumeBool(),
        .isCreateWideGamutSdrPixelMap = FDP->ConsumeBool() };
}

void PromoteIncrementalDecodeFuzzTest(std::shared_ptr<RawDecoder> rawDecoder)
{
    if (!rawDecoder) {
        return;
    }
    ProgDecodeContext context;
    rawDecoder->PromoteIncrementalDecode(FDP->ConsumeIntegral<uint32_t>(), context);
}

void SetDecodeOptionsFuzzTest(std::shared_ptr<RawDecoder> rawDecoder)
{
    if (!rawDecoder) {
        return;
    }
    PlImageInfo plInfo;
    PixelDecodeOptions plOpts;
    SetFdpPixelDecodeOptions(FDP, plOpts);
    uint32_t index = FDP->ConsumeIntegralInRange<uint32_t>(NUM_ZERO, NUM_ONE);
    rawDecoder->state_ =
        static_cast<RawDecoder::RawDecodingState>(FDP->ConsumeIntegral<uint32_t>() % RAW_DECODING_STATE_MODULE);
    rawDecoder->SetDecodeOptions(index, plOpts, plInfo);
}

void GetImageSizeFuzzTest(std::shared_ptr<RawDecoder> rawDecoder)
{
    if (!rawDecoder) {
        return;
    }
    Size size;
    uint32_t index = FDP->ConsumeIntegralInRange<uint32_t>(NUM_ZERO, NUM_ONE);
    rawDecoder->state_ =
        static_cast<RawDecoder::RawDecodingState>(FDP->ConsumeIntegral<uint32_t>() % RAW_DECODING_STATE_MODULE);
    rawDecoder->GetImageSize(index, size);
}

void DecodeFuzzTest(std::shared_ptr<RawDecoder> rawDecoder)
{
    if (!rawDecoder) {
        return;
    }
    DecodeContext decodeContext = ConstructDecodeContext();
    uint32_t index = FDP->ConsumeIntegralInRange<uint32_t>(NUM_ZERO, NUM_ONE);
    rawDecoder->state_ =
        static_cast<RawDecoder::RawDecodingState>(FDP->ConsumeIntegral<uint32_t>() % RAW_DECODING_STATE_MODULE);
    rawDecoder->Decode(index, decodeContext);
}

void RawDecoderFuzzTest001(const uint8_t *data, size_t size)
{
    if (data == nullptr) {
        return;
    }
    std::shared_ptr<RawDecoder> rawDecoder = ConstructRawDecoder(data, size);
    if (!rawDecoder) {
        return;
    }
    PromoteIncrementalDecodeFuzzTest(rawDecoder);
    SetDecodeOptionsFuzzTest(rawDecoder);
    GetImageSizeFuzzTest(rawDecoder);
    DecodeFuzzTest(rawDecoder);
}

}  // namespace Media
}  // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::Media::FDP = &fdp;
    /* Run your code on data */
    OHOS::Media::RawDecoderFuzzTest001(data, size);
    return 0;
}
