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
#include <fuzzer/FuzzedDataProvider.h>
#include "image_fwk_decode_svg_fuzzer.h"

#define private public
#define protected public
#include <cstdint>
#include <string>
#include <vector>
#include <unistd.h>
#include <fcntl.h>

#include "common_fuzztest_function.h"
#include "image_source.h"
#include "svg_decoder.h"
#include "image_log.h"
#include "pixel_yuv.h"
#include "file_source_stream.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "IMAGE_FWK_DECODE_SVG_FUZZ"

constexpr uint32_t PIXELFORMAT_MODULO = 105;
constexpr uint32_t COLORSPACE_MODULO = 17;
constexpr uint32_t DYNAMICRANGE_MODULO = 3;
constexpr uint32_t RESOLUTION_MODULO = 4;
constexpr uint32_t ALPHATYPE_MODULO = 4;
constexpr uint32_t OPT_SIZE = 110;

namespace OHOS {
namespace Media {
FuzzedDataProvider* FDP;

using namespace OHOS::ImagePlugin;
void SvgDecoderFuncTest001(const std::string& pathName)
{
    SourceOptions srcOpts;
    uint32_t errorCode;
    auto imageSource = ImageSource::CreateImageSource(pathName, srcOpts, errorCode);
    if (imageSource == nullptr) {
        IMAGE_LOGE("%{public}s CreateImageSource failed", __func__);
        return;
    }
    
    DecodeOptions dstOpts;
    dstOpts.fitDensity = FDP->ConsumeIntegral<int32_t>();
    dstOpts.CropRect.left = FDP->ConsumeIntegral<int32_t>();
    dstOpts.CropRect.top = FDP->ConsumeIntegral<int32_t>();
    dstOpts.CropRect.width = FDP->ConsumeIntegral<int32_t>();
    dstOpts.CropRect.height = FDP->ConsumeIntegral<int32_t>();
    dstOpts.desiredSize.width = FDP->ConsumeIntegralInRange<uint16_t>(0, 0xfff);
    dstOpts.desiredSize.height = FDP->ConsumeIntegralInRange<uint16_t>(0, 0xfff);
    dstOpts.desiredRegion.left = FDP->ConsumeIntegral<int32_t>();
    dstOpts.desiredRegion.top = FDP->ConsumeIntegral<int32_t>();
    dstOpts.desiredRegion.width = FDP->ConsumeIntegral<int32_t>();
    dstOpts.desiredRegion.height = FDP->ConsumeIntegral<int32_t>();
    dstOpts.rotateDegrees = FDP->ConsumeFloatingPoint<float>();
    dstOpts.rotateNewDegrees = FDP->ConsumeIntegral<uint32_t>();
    dstOpts.sampleSize = FDP->ConsumeIntegral<uint32_t>();
    dstOpts.desiredPixelFormat = static_cast<Media::PixelFormat>(FDP->ConsumeIntegral<uint8_t>() % PIXELFORMAT_MODULO);
    dstOpts.photoDesiredPixelFormat = static_cast<Media::PixelFormat>(FDP->ConsumeIntegral<uint8_t>() % PIXELFORMAT_MODULO);
    dstOpts.desiredColorSpace = static_cast<Media::ColorSpace>(FDP->ConsumeIntegral<uint8_t>() % COLORSPACE_MODULO);
    dstOpts.allowPartialImage = FDP->ConsumeBool();
    dstOpts.editable = FDP->ConsumeBool();
    dstOpts.preference = static_cast<Media::MemoryUsagePreference>(FDP->ConsumeBool());
    dstOpts.fastAstc = FDP->ConsumeBool();
    dstOpts.invokeType = FDP->ConsumeIntegral<uint16_t>();
    dstOpts.desiredDynamicRange = static_cast<Media::DecodeDynamicRange>(FDP->ConsumeIntegral<uint8_t>() % DYNAMICRANGE_MODULO);
    dstOpts.resolutionQuality = static_cast<Media::ResolutionQuality>(FDP->ConsumeIntegral<uint8_t>() % RESOLUTION_MODULO);
    dstOpts.isAisr = FDP->ConsumeBool();
    dstOpts.isAppUseAllocator = FDP->ConsumeBool();
    
    imageSource->CreatePixelMap(0, dstOpts, errorCode);
    
    std::shared_ptr<SvgDecoder> svgDecoder = std::make_shared<SvgDecoder>();
    SourceStream* sourceStreamPtr = (imageSource->sourceStreamPtr_).get();
    svgDecoder->SetSource(*sourceStreamPtr);
    svgDecoder->DoDecodeHeader();
    
    PixelDecodeOptions plOpts;
    plOpts.CropRect.left = FDP->ConsumeIntegral<int32_t>();
    plOpts.CropRect.top = FDP->ConsumeIntegral<int32_t>();
    plOpts.CropRect.width = FDP->ConsumeIntegral<int32_t>();
    plOpts.CropRect.height = FDP->ConsumeIntegral<int32_t>();
    plOpts.desiredSize.width = FDP->ConsumeIntegralInRange<uint16_t>(0, 0xfff);
    plOpts.desiredSize.height = FDP->ConsumeIntegralInRange<uint16_t>(0, 0xfff);
    plOpts.rotateDegrees = FDP->ConsumeFloatingPoint<float>();
    plOpts.sampleSize = FDP->ConsumeIntegral<uint32_t>();
    plOpts.desiredPixelFormat = static_cast<Media::PixelFormat>(FDP->ConsumeIntegral<uint8_t>() % PIXELFORMAT_MODULO);
    plOpts.desiredColorSpace = static_cast<Media::ColorSpace>(FDP->ConsumeIntegral<uint8_t>() % COLORSPACE_MODULO);
    plOpts.desireAlphaType = static_cast<Media::AlphaType>(FDP->ConsumeIntegral<uint8_t>() % ALPHATYPE_MODULO);
    plOpts.allowPartialImage = FDP->ConsumeBool();
    plOpts.editable = FDP->ConsumeBool();
    
    PlImageInfo plInfo;
    svgDecoder->SetDecodeOptions(0, plOpts, plInfo);
    DecodeContext context;
    svgDecoder->Decode(0, context);
    uint32_t num;
    svgDecoder->GetTopLevelImageNum(num);
    context.allocatorType = AllocatorType::SHARE_MEM_ALLOC;
    svgDecoder->AllocBuffer(context);
    context.allocatorType = AllocatorType::DMA_ALLOC;
    svgDecoder->AllocBuffer(context);
    context.allocatorType = AllocatorType::HEAP_ALLOC;
    svgDecoder->AllocBuffer(context);

    Size plSize;
    svgDecoder->DoGetImageSize(0, plSize);
    
    imageSource->Reset();
}
} // namespace Media
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    if(size < OPT_SIZE) return -1;
    FuzzedDataProvider fdp(data + size - OPT_SIZE, OPT_SIZE);
    OHOS::Media::FDP = &fdp;
    static const std::string pathName = "/data/local/tmp/test_decode_svg.svg";
    WriteDataToFile(data, size - OPT_SIZE, pathName);
    OHOS::Media::SvgDecoderFuncTest001(pathName);
    return 0;
}
