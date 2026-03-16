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
#include "image_fwk_decode_heif_fuzzer.h"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>
#include <unistd.h>
#include <fcntl.h>

#include "common_fuzztest_function.h"
#define private public
#define protected public
#include "HeifDecoder.h"
#include "HeifDecoderImpl.h"
#include "heif_parser.h"
#include "heif_image.h"
#include "heif_stream.h"
#include "box/item_info_box.h"
#include "box/heif_box.h"
#include "box/basic_box.h"
#include "box/item_data_box.h"
#include "box/item_ref_box.h"
#include "box/item_property_box.h"
#include "box/item_property_basic_box.h"
#include "box/item_property_aux_box.h"
#include "box/item_property_color_box.h"
#include "box/item_property_display_box.h"
#include "box/item_property_hvcc_box.h"
#include "box/item_property_transform_box.h"
#include "include/core/SkStream.h"
#include "buffer_source_stream.h"
#include "ext_stream.h"
#include "image_log.h"
#include "image_source.h"
#include "include/codec/SkCodec.h"

constexpr uint32_t PIXELFORMAT_MODULO = 105;
constexpr uint32_t COLORSPACE_MODULO = 17;
constexpr uint32_t DYNAMICRANGE_MODULO = 3;
constexpr uint32_t RESOLUTION_MODULO = 4;
constexpr uint32_t METADATATYPE_MODULO = 8;
constexpr uint32_t OPT_SIZE = 80;

namespace OHOS {
namespace Media {
using namespace OHOS::ImagePlugin;
FuzzedDataProvider* FDP;

void HeifDecodeFuzzTest001(const std::string& pathName)
{

    SourceOptions srcOpts;
    uint32_t errorCode;
    auto imageSource = ImageSource::CreateImageSource(pathName, srcOpts, errorCode);
    if (imageSource == nullptr) {
        return ;
    }
	DecodeOptions decodeOpts;
	decodeOpts.fitDensity = FDP->ConsumeIntegral<int32_t>();
	decodeOpts.CropRect.left = FDP->ConsumeIntegral<int32_t>();
	decodeOpts.CropRect.top = FDP->ConsumeIntegral<int32_t>();
	decodeOpts.CropRect.width = FDP->ConsumeIntegral<int32_t>();
	decodeOpts.CropRect.height = FDP->ConsumeIntegral<int32_t>();
	decodeOpts.desiredSize.width = FDP->ConsumeIntegralInRange<uint16_t>(0, 0xfff);
	decodeOpts.desiredSize.height = FDP->ConsumeIntegralInRange<uint16_t>(0, 0xfff);
	decodeOpts.desiredRegion.left = FDP->ConsumeIntegral<int32_t>();
	decodeOpts.desiredRegion.top = FDP->ConsumeIntegral<int32_t>();
	decodeOpts.desiredRegion.width = FDP->ConsumeIntegral<int32_t>();
	decodeOpts.desiredRegion.height = FDP->ConsumeIntegral<int32_t>();
	decodeOpts.rotateDegrees = FDP->ConsumeFloatingPoint<float>();
	decodeOpts.rotateNewDegrees = FDP->ConsumeIntegral<uint32_t>();
	decodeOpts.sampleSize = FDP->ConsumeIntegral<uint32_t>();
	decodeOpts.desiredPixelFormat = static_cast<Media::PixelFormat>(FDP->ConsumeIntegral<uint8_t>() % PIXELFORMAT_MODULO);
	decodeOpts.photoDesiredPixelFormat = static_cast<Media::PixelFormat>(FDP->ConsumeIntegral<uint8_t>() % PIXELFORMAT_MODULO);
	decodeOpts.desiredColorSpace = static_cast<Media::ColorSpace>(FDP->ConsumeIntegral<uint8_t>() % COLORSPACE_MODULO);
	decodeOpts.allowPartialImage = FDP->ConsumeBool();
	decodeOpts.editable = FDP->ConsumeBool();
	decodeOpts.preference = static_cast<Media::MemoryUsagePreference>(FDP->ConsumeBool());
	decodeOpts.fastAstc = FDP->ConsumeBool();
	decodeOpts.invokeType = FDP->ConsumeIntegral<uint16_t>();
	decodeOpts.desiredDynamicRange = static_cast<Media::DecodeDynamicRange>(FDP->ConsumeIntegral<uint8_t>() % DYNAMICRANGE_MODULO);
	decodeOpts.resolutionQuality = static_cast<Media::ResolutionQuality>(FDP->ConsumeIntegral<uint8_t>() % RESOLUTION_MODULO);
	decodeOpts.isAisr = FDP->ConsumeBool();
	decodeOpts.isAppUseAllocator = FDP->ConsumeBool();
    for (uint32_t index = 0; index < imageSource->GetFrameCount(errorCode); ++index) {
        auto pixelMap = imageSource->CreatePixelMapEx(index, decodeOpts, errorCode);
        IMAGE_LOGI("%{public}s heif decode SUCCESS", __func__);
    }
	
}

std::unique_ptr<SkCodec> CreateCodec(const std::string& pathName)
{
#ifdef HEIF_HW_DECODE_ENABLE
    SourceOptions opts;
    uint32_t errorCode;
    std::shared_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(pathName, opts, errorCode);
    if (imageSource == nullptr) {
        return nullptr;
    }
    std::unique_ptr<ImagePlugin::ExtStream> extStream = std::make_unique<ImagePlugin::ExtStream>();
    if (extStream == nullptr) {
        return nullptr;
    }
    extStream->stream_ = imageSource->sourceStreamPtr_.get();
    return SkCodec::MakeFromStream(std::make_unique<ImagePlugin::ExtStream>(extStream->stream_));
#endif
}

void HeifDecodeFuzzTest002(const std::string& pathName)
{
#ifdef HEIF_HW_DECODE_ENABLE
    std::unique_ptr<SkCodec> codec = CreateCodec(pathName);
    if (codec == nullptr) {
        return;
    }
    auto heifContext = reinterpret_cast<ImagePlugin::HeifDecoderImpl*>(codec->getHeifContext());
    if (heifContext == nullptr) {
        return;
    }
    std::string errorMessage = "";
    heifContext->getErrMsg(errorMessage);
    HeifFrameInfo frameInfo;
    heifContext->getImageInfo(&frameInfo);
    heifContext->getTmapInfo(&frameInfo);
    heifContext->getHdrType();
    std::vector<uint8_t> uwaInfo;
    std::vector<uint8_t> displayInfo;
    std::vector<uint8_t> lightInfo;
    heifContext->getVividMetadata(uwaInfo, displayInfo, lightInfo);
    std::vector<uint8_t> isoMetadata;
    heifContext->getISOMetadata(isoMetadata);
    heifContext->getColorDepth();
    heifContext->getAuxiliaryMapInfo(&frameInfo);
    Media::Rect fragmentMetadata;
    heifContext->getFragmentMetadata(fragmentMetadata);
    std::vector<uint8_t> metadata;
    Media::MetadataType type = static_cast<Media::MetadataType>(FDP->ConsumeIntegral<uint8_t>() % METADATATYPE_MODULO);
    heifContext->GetMetadataBlob(metadata, type);
    heifContext->IsHeifHasAlphaImage();
    int32_t widthPadding = FDP->ConsumeIntegral<int32_t>();
    int32_t heightPadding = FDP->ConsumeIntegral<int32_t>();
    heifContext->SetPadding(widthPadding, heightPadding);
    int32_t primaryDisplayWidth = FDP->ConsumeIntegral<int32_t>();
    int32_t primaryDisplayHeight = FDP->ConsumeIntegral<int32_t>();
    heifContext->IsHeifGainmapDivisibility(primaryDisplayWidth, primaryDisplayHeight);
    heifContext->IsHeifGainmapYuv400();
    heifContext->IsHeifAlphaYuv400();
    uint32_t sampleSize = FDP->ConsumeIntegral<uint32_t>();
    heifContext->GetPrimaryLumaBitNum();
    heifContext->IsGainmapDivisibleBySampleSize(sampleSize);
#endif
}
} // namespace Media
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
	if(size < OPT_SIZE) return -1;
	FuzzedDataProvider fdp(data, OPT_SIZE);
    OHOS::Media::FDP = &fdp;
    static const std::string pathName = "/data/local/tmp/test1.heic";
    WriteDataToFile(data, size - OPT_SIZE, pathName);
	uint8_t action = fdp.ConsumeIntegral<uint8_t>();
	switch(action){
        case 0:
            OHOS::Media::HeifDecodeFuzzTest001(pathName);
            break;
        default:
            OHOS::Media::HeifDecodeFuzzTest002(pathName);
            break;
    }
    return 0;
}
