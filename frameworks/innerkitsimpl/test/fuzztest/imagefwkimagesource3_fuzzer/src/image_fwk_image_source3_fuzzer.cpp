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

#include "image_fwk_image_source3_fuzzer.h"

#include <cstdint>
#include <string>
#include <unistd.h>
#include <fcntl.h>
#include <fstream>
#include "common_fuzztest_function.h"

#include "image_dfx.h"
#include "image_log.h"
#include "image_packer.h"
#include "image_source.h"
#include "image_utils.h"
#include "media_errors.h"

namespace OHOS {
namespace Media {
FuzzedDataProvider *FDP;

namespace {
    static constexpr uint32_t MAX_SIZE = 1024;
    static constexpr uint32_t NUM_0 = 0;
    static constexpr uint32_t NUM_1 = 1;
    static constexpr uint32_t NUM_2 = 2;
    static constexpr uint32_t NUM_4 = 4;
    static constexpr uint32_t NUM_10 = 10;
    static constexpr uint32_t MAX_SOURCE_SIZE = 300 * MAX_SIZE * MAX_SIZE;
    static constexpr uint32_t PIXELFORMAT_MODULO = 105;
    static constexpr uint32_t SOURCEOPTIONS_MIMETYPE_MODULO = 3;
    static constexpr uint32_t ALLOCATOR_TYPE_MODULO = 5;
    static constexpr uint32_t DECODE_DYNAMIC_RANGE_MODULO = 3;
    static constexpr uint32_t INCREMENTAL_MODE_MODULO = 2;
    static constexpr uint32_t INCREMENTAL_DECODING_STATE_MODULO = 7;
    static constexpr uint32_t SOURCE_DECODING_STATE_MODULO = 9;
    static constexpr uint32_t AUXILIARY_PICTURE_TYPE_MODULO = 6;
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

std::unique_ptr<ImageSource> ConstructImageSourceByFd(const uint8_t *data, size_t size)
{
    std::string pathName = "/data/local/tmp/test_create_imagesource_pathname.png";
    if (!WriteDataToFile(data, size, pathName)) {
        return nullptr;
    }
    int fd = open(pathName.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (fd < NUM_0) {
        return nullptr;
    }
    SourceOptions opts;
    std::string mimeType[] = {"image/jpeg", "image/heic", "image/heif"};
    opts.formatHint = mimeType[FDP->ConsumeIntegral<uint8_t>() % SOURCEOPTIONS_MIMETYPE_MODULO];
    opts.pixelFormat = static_cast<PixelFormat>(FDP->ConsumeIntegral<uint8_t>() % PIXELFORMAT_MODULO);
    size_t power = FDP->ConsumeIntegralInRange<size_t>(NUM_0, NUM_10);
    int32_t height = std::pow(NUM_2, power);
    if (static_cast<size_t>(height) > size) {
        close(fd);
        return nullptr;
    }
    int32_t width = static_cast<int32_t>(size / static_cast<size_t>(height));
    if (static_cast<size_t>(width * height) != size) {
        close(fd);
        return nullptr;
    }
    opts.size.height = height;
    opts.size.width = width;
    uint32_t errorCode { NUM_0 };

    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(fd, opts, errorCode);
    close(fd);
    return imageSource;
}

std::unique_ptr<ImageSource> ConstructImageSourceByPath(const uint8_t *data, size_t size)
{
    std::string pathName = "/data/local/tmp/test_create_imagesource_pathname.png";
    if (!WriteDataToFile(data, size, pathName)) {
        return nullptr;
    }
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
    return ImageSource::CreateImageSource(pathName, opts, errorCode);
}

std::unique_ptr<ImageSource> ConstructIncrementalImageSource(const uint8_t *data, size_t size)
{
    IncrementalSourceOptions incOpts;
    std::string mimeType[] = {"image/jpeg", "image/heic", "image/heif"};
    incOpts.sourceOptions.formatHint = mimeType[FDP->ConsumeIntegral<uint8_t>() % SOURCEOPTIONS_MIMETYPE_MODULO];
    incOpts.sourceOptions.pixelFormat = static_cast<PixelFormat>(FDP->ConsumeIntegral<uint8_t>() % PIXELFORMAT_MODULO);
    size_t power = FDP->ConsumeIntegralInRange<size_t>(NUM_0, NUM_10);
    int32_t height = std::pow(NUM_2, power);
    if (static_cast<size_t>(height) > size) {
        return nullptr;
    }
    int32_t width = static_cast<int32_t>(size / static_cast<size_t>(height));
    if (static_cast<size_t>(width * height) != size) {
        return nullptr;
    }
    incOpts.sourceOptions.size.height = height;
    incOpts.sourceOptions.size.width = width;
    uint32_t errorCode { NUM_0 };
    incOpts.incrementalMode = static_cast<IncrementalMode>(FDP->ConsumeIntegral<uint8_t>() % INCREMENTAL_MODE_MODULO);
    auto incrementalImageSource = ImageSource::CreateIncrementalImageSource(incOpts, errorCode);
    if (!incrementalImageSource || errorCode != SUCCESS) {
        return nullptr;
    }
    if (incrementalImageSource->UpdateData(data, size, FDP->ConsumeBool()) != SUCCESS) {
        return nullptr;
    }
    return incrementalImageSource;
}

void CreateImageSourceFuzzTest()
{
    size_t dataSize = FDP->ConsumeIntegralInRange<size_t>(NUM_0, MAX_SOURCE_SIZE + MAX_SIZE);
    uint8_t *data { nullptr };
    std::vector<uint8_t> dataVec;
    if (dataSize != NUM_0) {
        dataVec = FDP->ConsumeBytes<uint8_t>(dataSize);
    }
    SourceOptions opts;
    std::string mimeType[] = {"image/jpeg", "image/heic", "image/heif"};
    opts.formatHint = mimeType[FDP->ConsumeIntegral<uint8_t>() % SOURCEOPTIONS_MIMETYPE_MODULO];
    uint32_t errorCode { NUM_0 };
    ImageSource::CreateImageSource(data, dataSize, opts, errorCode);
}

void CreatePixelMapExFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr) {
        return;
    }

    auto imageSource = ConstructImageSourceByBuffer(data, size);
    if (!imageSource) {
        return;
    }

    uint32_t index = FDP->ConsumeIntegral<uint32_t>();
    uint32_t errorCode { NUM_0 };
    DecodeOptions decodeOpts;
    SetFdpDecodeOptions(FDP, decodeOpts);
    decodeOpts.desiredSize.width = FDP->ConsumeIntegralInRange<int16_t>(-0xfff, 0xfff);
    decodeOpts.desiredSize.height = FDP->ConsumeIntegralInRange<int16_t>(-0xfff, 0xfff);
    imageSource->CreatePixelMapEx(index, decodeOpts, errorCode);
}

void TransformSizeWithDensityFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr) {
        return;
    }

    auto imageSource = ConstructImageSourceByBuffer(data, size);
    if (!imageSource) {
        return;
    }

    ImageInfo info;
    imageSource->GetImageInfo(info);
    Size wantSize;
    int32_t srcDensity = FDP->ConsumeIntegralInRange<int32_t>(NUM_1, NUM_2);
    int32_t wantDensity = FDP->ConsumeIntegralInRange<int32_t>(NUM_1, NUM_2);
    Size dstSize;
    imageSource->TransformSizeWithDensity(info.size, srcDensity, wantSize, wantDensity, dstSize);
}

void IsSupportAllocatorTypeFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr) {
        return;
    }

    auto imageSource = ConstructImageSourceByBuffer(data, size);
    if (!imageSource) {
        return;
    }

    DecodeOptions decOpts;
    decOpts.allocatorType = static_cast<AllocatorType>(FDP->ConsumeIntegral<uint32_t>() % ALLOCATOR_TYPE_MODULO);
    decOpts.desiredDynamicRange =
        static_cast<DecodeDynamicRange>(FDP->ConsumeIntegral<uint32_t>() % DECODE_DYNAMIC_RANGE_MODULO);
    int32_t allocatorType = FDP->ConsumeIntegralInRange<int32_t>(NUM_1, NUM_4);
    imageSource->IsSupportAllocatorType(decOpts, allocatorType);
}

void SetImageEventHeifParserErrFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr) {
        return;
    }

    auto imageSource = ConstructImageSourceByBuffer(data, size);
    if (!imageSource) {
        return;
    }
    imageSource->heifParseErr_ = FDP->ConsumeIntegral<uint32_t>();
    ImageEvent imageEvent;
    imageSource->SetImageEventHeifParseErr(imageEvent);
}

void PromoteDecodingFuzzTest(const uint8_t *data, size_t size)
{
    auto incrementalImageSource = ConstructIncrementalImageSource(data, size);
    if (!incrementalImageSource) {
        return;
    }
    if (incrementalImageSource->InitMainDecoder() != SUCCESS) {
        return;
    }
    DecodeOptions decodeOpts;
    SetFdpDecodeOptions(FDP, decodeOpts);
    uint32_t errorCode { NUM_0 };
    std::unique_ptr<IncrementalPixelMap> incPixelMap =
        incrementalImageSource->CreateIncrementalPixelMap(NUM_0, decodeOpts, errorCode);
    if (!incPixelMap || errorCode != SUCCESS) {
        return;
    }
    uint8_t decodeProgress { NUM_0 };
    incPixelMap->decodingStatus_.state =
        static_cast<IncrementalDecodingState>(FDP->ConsumeIntegral<uint32_t>() % INCREMENTAL_DECODING_STATE_MODULO);
    incPixelMap->PromoteDecoding(decodeProgress);
    incPixelMap->DetachFromDecoding();
}

void ModifyImagePropertyExFuzzTest(const uint8_t *data, size_t size)
{
    std::vector<std::unique_ptr<ImageSource>> imageSources;
    imageSources.emplace_back(ConstructImageSourceByBuffer(data, size));
    imageSources.emplace_back(ConstructImageSourceByFd(data, size));
    imageSources.emplace_back(ConstructImageSourceByPath(data, size));
    for (const auto& imageSource : imageSources) {
        if (imageSource) {
            std::string key = FDP->ConsumeRandomLengthString();
            std::string value = FDP->ConsumeRandomLengthString();
            imageSource->ModifyImagePropertyEx(NUM_0, key, value);
        }
    }
}

void ModifyImagePropertiesExFuzzTest(const uint8_t *data, size_t size)
{
    std::vector<std::unique_ptr<ImageSource>> imageSources;
    imageSources.emplace_back(ConstructImageSourceByBuffer(data, size));
    imageSources.emplace_back(ConstructImageSourceByFd(data, size));
    imageSources.emplace_back(ConstructImageSourceByPath(data, size));

    std::vector<std::pair<std::string, std::string>> properties;
    int32_t propertiesNum = FDP->ConsumeIntegralInRange<int32_t>(NUM_1, NUM_10);
    while (propertiesNum) {
        std::string key = FDP->ConsumeRandomLengthString();
        std::string value = FDP->ConsumeRandomLengthString();
        properties.emplace_back(key, value);
        propertiesNum--;
    }

    for (const auto& imageSource : imageSources) {
        if (imageSource) {
            imageSource->ModifyImagePropertiesEx(NUM_0, properties);
        }
    }
}

void GetImagePropertyFuzzTest(const uint8_t *data, size_t size)
{
    auto imageSource = ConstructImageSourceByBuffer(data, size);
    if (!imageSource) {
        return;
    }
    if (imageSource->InitMainDecoder() != SUCCESS) {
        return;
    }
    std::vector<std::string> IMAGE_KEYS = { "DelayTime", "DisposalType", "GIFLoopCount" };
    for (const auto &key : IMAGE_KEYS) {
        int32_t value { NUM_0 };
        imageSource->GetImagePropertyInt(NUM_0, key, value);
        std::string strValue = "";
        imageSource->GetImagePropertyString(NUM_0, key, strValue);
        imageSource->GetImagePropertyStringBySync(NUM_0, key, strValue);
    }
}

void DecodeSourceInfoFuzzTest(const uint8_t *data, size_t size)
{
    auto imageSource = ConstructImageSourceByBuffer(data, size);
    if (!imageSource) {
        return;
    }
    imageSource->decodeState_ =
        static_cast<SourceDecodingState>(FDP->ConsumeIntegral<uint32_t>() % SOURCE_DECODING_STATE_MODULO);
    imageSource->DecodeSourceInfo(FDP->ConsumeBool());
}

void CreatePictureAtIndexFuzzTest(const uint8_t *data, size_t size)
{
    auto imageSource = ConstructImageSourceByBuffer(data, size);
    if (!imageSource) {
        return;
    }
    uint32_t errorCode { NUM_0 };
    imageSource->CreatePictureAtIndex(NUM_0, errorCode);
}

void CreatePictureFuzzTest(const uint8_t *data, size_t size)
{
    auto imageSource = ConstructImageSourceByBuffer(data, size);
    if (!imageSource) {
        return;
    }
    DecodingOptionsForPicture opts;
    opts.allocatorType = static_cast<AllocatorType>(FDP->ConsumeIntegral<uint32_t>() % ALLOCATOR_TYPE_MODULO);
    opts.desiredPixelFormat = static_cast<PixelFormat>(FDP->ConsumeIntegral<uint32_t>() % PIXELFORMAT_MODULO);
    for (uint32_t i = 0; i < AUXILIARY_PICTURE_TYPE_MODULO; i++) {
        AuxiliaryPictureType tmpType =
            static_cast<AuxiliaryPictureType>(FDP->ConsumeIntegral<uint32_t>() % AUXILIARY_PICTURE_TYPE_MODULO);
        opts.desireAuxiliaryPictures.insert(tmpType);
    }
    uint32_t errorCode { NUM_0 };
    imageSource->CreatePicture(opts, errorCode);
}

}  // namespace Media
}  // namespace OHOS


/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::Media::FDP = &fdp;

    /* Run your code on data */
    OHOS::Media::CreateImageSourceFuzzTest();
    OHOS::Media::CreatePixelMapExFuzzTest(data, size);
    OHOS::Media::TransformSizeWithDensityFuzzTest(data, size);
    OHOS::Media::IsSupportAllocatorTypeFuzzTest(data, size);
    OHOS::Media::SetImageEventHeifParserErrFuzzTest(data, size);
    OHOS::Media::PromoteDecodingFuzzTest(data, size);
    OHOS::Media::ModifyImagePropertyExFuzzTest(data, size);
    OHOS::Media::ModifyImagePropertiesExFuzzTest(data, size);
    OHOS::Media::GetImagePropertyFuzzTest(data, size);
    OHOS::Media::DecodeSourceInfoFuzzTest(data, size);
    OHOS::Media::CreatePictureFuzzTest(data, size);
    return 0;
}
