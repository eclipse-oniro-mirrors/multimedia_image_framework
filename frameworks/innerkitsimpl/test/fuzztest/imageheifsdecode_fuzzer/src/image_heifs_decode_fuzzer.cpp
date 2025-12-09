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

#include "image_heifs_decode_fuzzer.h"

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
    static const std::string IMAGE_INPUT_HEIFS_PATH = "/data/local/tmp/image/starfield_animation.heic";
    static constexpr uint32_t NUM_0 = 0;
    static constexpr uint32_t NUM_2 = 2;
    static constexpr uint32_t NUM_4 = 4;
    static constexpr uint32_t NUM_10 = 10;
    static constexpr uint32_t ALLOCATOR_TYPE_MODULO = 5;
    static constexpr uint32_t PIXELFORMAT_MODULO = 105;
    static constexpr uint32_t SOURCEOPTIONS_MIMETYPE_MODULO = 3;
    static constexpr uint32_t MOCK_MAX_INDEX = 15;
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

std::vector<HeifBox> ConstructParseContentChildrenBox()
{
    std::vector<HeifBox> boxList;
    boxList.emplace_back(HeifMoovBox());
    boxList.emplace_back(HeifTrakBox());
    boxList.emplace_back(HeifMdiaBox());
    boxList.emplace_back(HeifMinfBox());
    boxList.emplace_back(HeifDinfBox());
    boxList.emplace_back(HeifStblBox());
    return boxList;
}

std::vector<HeifFullBox> ConstructParseContentFullBox()
{
    std::vector<HeifFullBox> boxList;
    boxList.emplace_back(HeifMvhdBox());
    boxList.emplace_back(HeifTkhdBox());
    boxList.emplace_back(HeifMdhdBox());
    boxList.emplace_back(HeifVmhdBox());
    boxList.emplace_back(HeifDrefBox());
    boxList.emplace_back(HeifStsdBox());
    boxList.emplace_back(HeifSttsBox());
    boxList.emplace_back(HeifStscBox());
    boxList.emplace_back(HeifStcoBox());
    boxList.emplace_back(HeifStszBox());
    boxList.emplace_back(HeifStssBox());
    return boxList;
}

void ConstructHeifStsdBox(HeifStsdBox &stsdBox)
{
    std::vector<HeifFullBox> boxList = ConstructParseContentFullBox();
    for (const auto &box : boxList) {
        stsdBox.entries_.emplace_back(std::make_shared<HeifFullBox>(box));
    }
    stsdBox.entries_.emplace_back(std::make_shared<HeifHvc1Box>());
}

void ConstructHeifStcoBox(HeifStcoBox &stcoBox)
{
    stcoBox.entryCount_ = FDP->ConsumeIntegralInRange<uint32_t>(0, MOCK_MAX_INDEX);
    for (uint32_t i = 0; i < stcoBox.entryCount_; i++) {
        stcoBox.chunkOffsets_.emplace_back(FDP->ConsumeIntegral<uint32_t>());
    }
}

void ConstructHeifStszBox(HeifStszBox &stszBox)
{
    stszBox.sampleCount_ = FDP->ConsumeIntegralInRange<uint32_t>(0, MOCK_MAX_INDEX);
    for (uint32_t i = 0; i < stszBox.sampleCount_; i++) {
        stszBox.entrySizes_.emplace_back(FDP->ConsumeIntegral<uint32_t>());
    }
}

void ConstructHeifSttsBox(HeifSttsBox &sttsBox)
{
    sttsBox.entryCount_ = FDP->ConsumeIntegralInRange<uint32_t>(0, NUM_10);
    for (uint32_t i = 0; i < sttsBox.entryCount_; i++) {
        HeifSttsBox::TimeToSampleEntry entry;
        entry.sampleCount = FDP->ConsumeIntegralInRange<uint32_t>(0, NUM_10);
        entry.sampleDelta = FDP->ConsumeIntegralInRange<uint32_t>(0, NUM_10);
        sttsBox.entries_.emplace_back(entry);
    }
}

void ConstructHeifStssBox(HeifStssBox &stssBox)
{
    stssBox.entryCount_ = FDP->ConsumeIntegralInRange<uint32_t>(0, MOCK_MAX_INDEX);
    for (uint32_t i = 0; i < stssBox.entryCount_; i++) {
        uint32_t mockData = FDP->ConsumeIntegral<uint32_t>();
        stssBox.sampleNumbers_.emplace_back(mockData);
    }
}

uint32_t GetRandomCode()
{
    return fourcc_to_code(FDP->ConsumeBytesAsString(NUM_4).c_str());
}

void ConstructHeifParser(HeifParser &parser, const uint8_t *data, size_t size)
{
    parser.ftypBox_ = FDP->ConsumeBool() ? std::make_shared<HeifFtypBox>() : nullptr;
    if (parser.ftypBox_) {
        parser.ftypBox_->majorBrand_ = GetRandomCode();
    }
    parser.hdlrBox_ = FDP->ConsumeBool() ? std::make_shared<HeifHdlrBox>() : nullptr;
    if (parser.hdlrBox_) {
        parser.hdlrBox_->handlerType_ = GetRandomCode();
    }
    parser.stsdBox_ = FDP->ConsumeBool() ? std::make_shared<HeifStsdBox>() : nullptr;
    if (parser.stsdBox_) {
        ConstructHeifStsdBox(*(parser.stsdBox_));
    }
    parser.stcoBox_ = FDP->ConsumeBool() ? std::make_shared<HeifStcoBox>() : nullptr;
    if (parser.stcoBox_) {
        ConstructHeifStcoBox(*(parser.stcoBox_));
    }
    parser.stszBox_ = FDP->ConsumeBool() ? std::make_shared<HeifStszBox>() : nullptr;
    if (parser.stszBox_) {
        ConstructHeifStszBox(*(parser.stszBox_));
    }
    parser.sttsBox_ = FDP->ConsumeBool() ? std::make_shared<HeifSttsBox>() : nullptr;
    if (parser.sttsBox_) {
        ConstructHeifSttsBox(*(parser.sttsBox_));
    }
    parser.stssBox_ = FDP->ConsumeBool() ? std::make_shared<HeifStssBox>() : nullptr;
    if (parser.stssBox_) {
        ConstructHeifStssBox(*(parser.stssBox_));
    }
    if (!data) {
        return;
    }
    parser.inputStream_ = FDP->ConsumeBool() ? std::make_shared<HeifBufferInputStream>(data, size, true) : nullptr;
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

void ParseContentChildrenTest001(const uint8_t *data, size_t size)
{
    if (!data) {
        return;
    }
    std::vector<HeifBox> boxList = ConstructParseContentChildrenBox();
    std::shared_ptr<HeifBufferInputStream> inputStream = std::make_shared<HeifBufferInputStream>(data, size, true);
    if (!inputStream) {
        return;
    }
    for (auto &box : boxList) {
        HeifStreamReader reader(inputStream, 0, size);
        uint32_t recursionCount = FDP->ConsumeIntegral<uint32_t>();
        box.ParseContentChildrenByReadChildren(reader, recursionCount);
    }
}

void HeifFullBoxParseContentAndWriteTest001(const uint8_t *data, size_t size)
{
    if (!data) {
        return;
    }
    std::vector<HeifFullBox> boxList = ConstructParseContentFullBox();
    std::shared_ptr<HeifBufferInputStream> inputStream = std::make_shared<HeifBufferInputStream>(data, size, true);
    if (!inputStream) {
        return;
    }
    for (auto& box : boxList) {
        HeifStreamReader reader(inputStream, 0, size);
        box.ParseContent(reader);
        HeifStreamWriter writer;
        box.Write(writer);
    }
}

void GetSampleEntryWidthHeightTest001()
{
    HeifStsdBox stsdBox;
    ConstructHeifStsdBox(stsdBox);
    uint32_t index = FDP->ConsumeIntegralInRange<uint32_t>(0, MOCK_MAX_INDEX);
    uint32_t width = FDP->ConsumeIntegral<uint32_t>();
    uint32_t height = FDP->ConsumeIntegral<uint32_t>();
    stsdBox.GetSampleEntryWidthHeight(index, width, height);
}

void GetHvccBoxTest001()
{
    HeifStsdBox stsdBox;
    ConstructHeifStsdBox(stsdBox);
    uint32_t index = FDP->ConsumeIntegralInRange<uint32_t>(0, MOCK_MAX_INDEX);
    stsdBox.GetHvccBox(index);
}

void GetDelayTimeTest001()
{
    HeifSttsBox sttsBox;
    ConstructHeifSttsBox(sttsBox);
    uint32_t index = FDP->ConsumeIntegral<uint32_t>();
    int32_t value = FDP->ConsumeIntegral<int32_t>();
    sttsBox.GetDelayTime(index, value);
}

void GetChunkOffsetTest001()
{
    HeifStcoBox stcoBox;
    stcoBox.entryCount_ = FDP->ConsumeIntegralInRange<uint32_t>(0, NUM_10);
    for (uint32_t i = 0; i < stcoBox.entryCount_; i++) {
        stcoBox.chunkOffsets_.emplace_back(FDP->ConsumeIntegral<uint32_t>());
    }
    uint32_t index = FDP->ConsumeIntegral<uint32_t>();
    uint32_t value = FDP->ConsumeIntegral<uint32_t>();
    stcoBox.GetChunkOffset(index, value);
}

void GetSampleSizeTest001()
{
    HeifStszBox stszBox;
    stszBox.sampleCount_ = FDP->ConsumeIntegralInRange<uint32_t>(0, NUM_10);
    for (uint32_t i = 0; i < stszBox.sampleCount_; i++) {
        stszBox.entrySizes_.emplace_back(FDP->ConsumeIntegral<uint32_t>());
    }
    uint32_t index = FDP->ConsumeIntegral<uint32_t>();
    uint32_t value = FDP->ConsumeIntegral<uint32_t>();
    stszBox.GetSampleSize(index, value);
}

void GetSampleNumbersTest001()
{
    HeifStssBox stssBox;
    stssBox.entryCount_ = FDP->ConsumeIntegralInRange<uint32_t>(0, NUM_10);
    for (uint32_t i = 0; i < stssBox.entryCount_; i++) {
        stssBox.sampleNumbers_.emplace_back(FDP->ConsumeIntegral<uint32_t>());
    }
    std::vector<uint32_t> samples;
    stssBox.GetSampleNumbers(samples);
}

void IsHeifsImageTest001(const uint8_t *data, size_t size)
{
    HeifParser parser;
    ConstructHeifParser(parser, data, size);
    bool isHeifs = false;
    parser.IsHeifsImage(isHeifs);
}

void GetHeifsMovieFrameDataTest001(const uint8_t *data, size_t size)
{
    HeifParser parser;
    ConstructHeifParser(parser, data, size);
    uint32_t index = FDP->ConsumeIntegral<uint32_t>();
    std::vector<uint8_t> dest;
    parser.GetHeifsMovieFrameData(index, dest);
}

void GetHeifsFrameDataTest001(const uint8_t *data, size_t size)
{
    HeifParser parser;
    ConstructHeifParser(parser, data, size);
    uint32_t index = FDP->ConsumeIntegral<uint32_t>();
    std::vector<uint8_t> dest;
    parser.GetHeifsFrameData(index, dest);
}

void GetHeifsDelayTimeTest001(const uint8_t *data, size_t size)
{
    HeifParser parser;
    ConstructHeifParser(parser, data, size);
    uint32_t index = FDP->ConsumeIntegral<uint32_t>();
    int32_t value = 0;
    parser.GetHeifsDelayTime(index, value);
}

void GetPreSampleSizeTest001(const uint8_t *data, size_t size)
{
    HeifParser parser;
    ConstructHeifParser(parser, data, size);
    uint32_t index = FDP->ConsumeIntegral<uint32_t>();
    uint32_t preSampleSize = FDP->ConsumeIntegral<uint32_t>();
    parser.GetPreSampleSize(index, preSampleSize);
}

void GetHeifsGroupFrameInfoTest001(const uint8_t *data, size_t size)
{
    HeifParser parser;
    ConstructHeifParser(parser, data, size);
    HeifsFrameGroup frameGroup;
    uint32_t index = FDP->ConsumeIntegral<uint32_t>();
    parser.GetHeifsGroupFrameInfo(index, frameGroup);
}
} // namespace Media
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::Media::FDP = &fdp;
    /* Run your code on data */
    OHOS::Media::CreatePictureAtIndexFuzzTest001(data, size);
    OHOS::Media::SetHeifsMetadataForPictureTest001(data, size);
    OHOS::Media::GetHeifsFrameCountTest001();
    OHOS::Media::ParseContentChildrenTest001(data, size);
    OHOS::Media::HeifFullBoxParseContentAndWriteTest001(data, size);
    OHOS::Media::GetSampleEntryWidthHeightTest001();
    OHOS::Media::GetHvccBoxTest001();
    OHOS::Media::GetDelayTimeTest001();
    OHOS::Media::GetChunkOffsetTest001();
    OHOS::Media::GetSampleSizeTest001();
    OHOS::Media::GetSampleNumbersTest001();
    OHOS::Media::IsHeifsImageTest001(data, size);
    OHOS::Media::GetHeifsMovieFrameDataTest001(data, size);
    OHOS::Media::GetHeifsFrameDataTest001(data, size);
    OHOS::Media::GetHeifsDelayTimeTest001(data, size);
    OHOS::Media::GetPreSampleSizeTest001(data, size);
    return 0;
}