/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "image_heifs_decode2_fuzzer.h"

#include <cstdint>
#include <memory>
#include <string>
#include <fuzzer/FuzzedDataProvider.h>

#include "box/item_info_box.h"
#include "box/heif_box.h"
#include "buffer_source_stream.h"
#include "common_fuzztest_function.h"
#include "ext_stream.h"
#include "ext_decoder.h"
#include "HeifDecoder.h"
#include "HeifDecoderImpl.h"
#include "heif_parser.h"
#include "heif_image.h"
#include "heif_stream.h"
#include "image_source.h"

namespace OHOS {
namespace Media {
using namespace OHOS::ImagePlugin;
FuzzedDataProvider* FDP;

namespace {
    static constexpr uint32_t NUM_0 = 0;
    static constexpr uint32_t NUM_2 = 2;
    static constexpr uint32_t NUM_10 = 10;
    static constexpr uint32_t ALLOCATOR_TYPE_MODULO = 5;
    static constexpr uint32_t PIXELFORMAT_MODULO = 105;
    static constexpr uint32_t SOURCEOPTIONS_MIMETYPE_MODULO = 3;
    static constexpr uint32_t OPT_SIZE = 80;
}

std::unique_ptr<ImageSource> ConstructImageSourceByBuffer(const uint8_t *data, size_t size)
{
    SourceOptions opts;
    std::string mimeType[] = {"image/jpeg", "image/heic", "image/heif"};
    opts.formatHint = mimeType[FDP->ConsumeIntegral<uint8_t>() % SOURCEOPTIONS_MIMETYPE_MODULO];
    opts.pixelFormat = static_cast<PixelFormat>(FDP->ConsumeIntegral<uint8_t>() % PIXELFORMAT_MODULO);
    size_t power = FDP->ConsumeIntegralInRange<size_t>(NUM_0, NUM_10);
    int32_t height = std::pow(NUM_2, power);
    if (static_cast<size_t>(height) > size) {
        return nullptr;
    }
    int32_t width = static_cast<int32_t>(size / static_cast<size_t>(height));
    if (static_cast<size_t>(width * height) != size) {
        return nullptr;
    }
    opts.size.height = height;
    opts.size.width = width;
    uint32_t errorCode { NUM_0 };
    return ImageSource::CreateImageSource(data, size, opts, errorCode);
}

void CreatePictureAtIndexFuzzTest001(const uint8_t *data, size_t size)
{
    if (!data) {
        return;
    }
    uint32_t errorCode = 0;
    auto imageSource = ConstructImageSourceByBuffer(data, size);
    if (!imageSource) {
        return;
    }
    uint32_t frameCount = imageSource->GetFrameCount(errorCode);
    if (errorCode != SUCCESS) {
        return;
    }
    uint32_t index = FDP->ConsumeIntegralInRange<uint32_t>(NUM_0, frameCount);
    imageSource->opts_.allocatorType =
        static_cast<AllocatorType>(FDP->ConsumeIntegral<uint32_t>() % ALLOCATOR_TYPE_MODULO);
    imageSource->CreatePictureAtIndex(index, errorCode);
}

void SetHeifsMetadataForPictureTest001(const uint8_t *data, size_t size)
{
    if (!data) {
        return;
    }
    auto imageSource = ConstructImageSourceByBuffer(data, size);
    if (!imageSource) {
        return;
    }
    if (imageSource->InitMainDecoder() != SUCCESS) {
        return;
    }
    std::shared_ptr<PixelMap> pixelMap = std::make_shared<PixelMap>();
    std::unique_ptr<Picture> picture = Picture::Create(pixelMap);
    uint32_t index = FDP->ConsumeIntegralInRange<uint32_t>(NUM_0, NUM_10);
    imageSource->SetHeifsMetadataForPicture(picture, index);
}

void GetHeifsFrameCountTest001()
{
#ifdef HEIF_HW_DECODE_ENABLE
    HeifDecoderImpl heifDecoderImpl;
    uint32_t sampleCount = FDP->ConsumeIntegral<uint32_t>();
    heifDecoderImpl.GetHeifsFrameCount(sampleCount);
#endif
}

} // namespace Media
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size <  OHOS::Media::OPT_SIZE) {
        return 0;
    }
    FuzzedDataProvider fdp(data + size - OHOS::Media::OPT_SIZE, OHOS::Media::OPT_SIZE);
    OHOS::Media::FDP = &fdp;
    uint8_t action = fdp.ConsumeIntegral<uint8_t>() % 3;
    switch (action) {
        case 0:
            OHOS::Media::CreatePictureAtIndexFuzzTest001(data, size - OHOS::Media::OPT_SIZE);
            break;
        case 1:
            OHOS::Media::SetHeifsMetadataForPictureTest001(data, size - OHOS::Media::OPT_SIZE);
            break;
        case 2:
            OHOS::Media::GetHeifsFrameCountTest001();
            break;
        default:
            break;
    }
    return 0;
}