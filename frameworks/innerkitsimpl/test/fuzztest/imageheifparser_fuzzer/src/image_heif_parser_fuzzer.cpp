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

#include "image_heif_parser_fuzzer.h"

#include <cstdint>
#include <memory>
#include <string>
#include <fuzzer/FuzzedDataProvider.h>

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
#include "buffer_source_stream.h"
#include "common_fuzztest_function.h"
#include "ext_stream.h"
#include "HeifDecoder.h"
#include "HeifDecoderImpl.h"
#include "heif_parser.h"
#include "heif_image.h"
#include "heif_stream.h"
#include "include/core/SkStream.h"

namespace OHOS {
namespace Media {
using namespace OHOS::ImagePlugin;
FuzzedDataProvider* FDP;

namespace {
    static constexpr uint32_t MOCK_ITEM_ID = 0;
    static constexpr uint32_t MOCK_ITEM_ID2 = 1;
    static constexpr uint32_t MOCK_ITEM_GRID = 2;
    static constexpr uint32_t MOCK_IMAGE_ID = 3;
    static constexpr uint32_t BOX_TYPE_DIMG = fourcc_to_code("dimg");
    static constexpr uint32_t HEIF_MAX_EXIF_SIZE = 128 * 1024;
    static constexpr size_t MOCKLEN = 3;

    static constexpr const char *GRID_STR = "grid";
    enum class BoxType : uint8_t {
        ILOC = 0,
        IDAT,
        IINF,
        INFE,
        PTIM,
        META,
        FTYP,
        TOPB,
        CLLI,
        IREF,
        IPCO,
        IPMA,
    };
}

std::shared_ptr<HeifParser> ConstructHeifParser(const uint8_t *data, size_t size)
{
    if (data == nullptr) {
        return nullptr;
    }
    std::shared_ptr<HeifParser> heifParser;
    std::shared_ptr<HeifBufferInputStream> inputStream = std::make_shared<HeifBufferInputStream>(data, size, false);
    if (!inputStream) {
        return nullptr;
    }
    if (heif_error_ok != HeifParser::MakeFromStream(inputStream, &heifParser)) {
        return std::make_shared<HeifParser>(inputStream);
    }
    return heifParser;
}

HvccConfig ConstructHvccConfig()
{
    return HvccConfig {
        .version = FDP->ConsumeIntegral<uint8_t>(),
        .generalProfileSpace = FDP->ConsumeIntegral<uint8_t>(),
        .generalTierFlag = FDP->ConsumeIntegral<uint8_t>(),
        .generalProfileIdc = FDP->ConsumeIntegral<uint8_t>(),
        .generalProfileCompatibilityFlags = FDP->ConsumeIntegral<uint32_t>(),
        .generalConstraintIndicatorFlags = FDP->ConsumeIntegral<uint64_t>(),
        .generalLevelIdc = FDP->ConsumeIntegral<uint8_t>(),
        .minSpatialSegmentationIdc = FDP->ConsumeIntegral<uint16_t>(),
        .parallelismType = FDP->ConsumeIntegral<uint8_t>(),
        .chromaFormat = FDP->ConsumeIntegral<uint8_t>(),
        .bitDepthLuma = FDP->ConsumeIntegral<uint8_t>(),
        .bitDepthChroma = FDP->ConsumeIntegral<uint8_t>(),
        .avgFrameRate = FDP->ConsumeIntegral<uint16_t>(),
        .constFrameRate = FDP->ConsumeIntegral<uint8_t>(),
        .numTemporalLayers = FDP->ConsumeIntegral<uint8_t>(),
        .temporalIdNested = FDP->ConsumeIntegral<uint8_t>(),
    };
}

std::shared_ptr<HeifRawColorProfile> ConstructHeifColorProfile()
{
    std::vector<uint8_t> colorData {
        FDP->ConsumeIntegral<uint8_t>(),
        FDP->ConsumeIntegral<uint8_t>(),
        FDP->ConsumeIntegral<uint8_t>()
    };
    return std::make_shared<HeifRawColorProfile>(
        FDP->ConsumeIntegral<uint32_t>(),
        colorData);
}

bool ConstructHeifIlocBox(std::shared_ptr<HeifParser> heifParser)
{
    if (heifParser->ilocBox_) {
        return true;
    }
    heifParser->ilocBox_ = std::make_shared<HeifIlocBox>();
    if (!heifParser->ilocBox_) {
        return false;
    }

    std::vector<uint32_t> itemIds {
        FDP->ConsumeIntegral<uint32_t>(),
        FDP->ConsumeIntegral<uint32_t>(),
        FDP->ConsumeIntegral<uint32_t>(),
        MOCK_ITEM_ID
    };

    for (const auto &id : itemIds) {
        std::vector<uint8_t> mockData(MOCKLEN);
        for (auto &data : mockData) {
            data = FDP->ConsumeIntegral<uint8_t>();
        }
        heifParser->AppendIlocData(id, mockData);
    }
    return true;
}

bool ConstructHeifIdatBox(std::shared_ptr<HeifParser> heifParser)
{
    if (heifParser->idatBox_) {
        return true;
    }

    heifParser->idatBox_ = std::make_shared<HeifIdatBox>();
    if (!heifParser->idatBox_) {
        return false;
    }
    return true;
}

bool ConstructHeifIinfBox(std::shared_ptr<HeifParser> heifParser)
{
    if (heifParser->iinfBox_) {
        return true;
    }

    heifParser->iinfBox_ = std::make_shared<HeifIinfBox>();
    if (!heifParser->iinfBox_) {
        return false;
    }
    return true;
}

bool ConstructHeifInfeBox(std::shared_ptr<HeifParser> heifParser)
{
    if (heifParser->infeBoxes_.count(MOCK_ITEM_ID) && heifParser->infeBoxes_[MOCK_ITEM_ID]) {
        return true;
    }
    if (!ConstructHeifIlocBox(heifParser)) {
        return false;
    }

    for (size_t i = 0; i < MOCKLEN; i++) {
        uint32_t tItemId = i == MOCKLEN - 1 ? MOCK_ITEM_ID2 : FDP->ConsumeIntegral<uint32_t>();
        heifParser->infeBoxes_[tItemId] = std::make_shared<HeifInfeBox>();
    }
    heifParser->infeBoxes_[MOCK_ITEM_ID] = std::make_shared<HeifInfeBox>();
    if (!heifParser->infeBoxes_.count(MOCK_ITEM_ID) || !heifParser->infeBoxes_[MOCK_ITEM_ID]) {
        return false;
    }
    heifParser->infeBoxes_[MOCK_ITEM_GRID] = std::make_shared<HeifInfeBox>(MOCK_ITEM_GRID, GRID_STR, false);
    if (!heifParser->infeBoxes_.count(MOCK_ITEM_GRID) || !heifParser->infeBoxes_[MOCK_ITEM_GRID]) {
        return false;
    }
    return true;
}

bool ConstructHeifPtimBox(std::shared_ptr<HeifParser> heifParser)
{
    if (heifParser->pitmBox_) {
        return true;
    }

    heifParser->pitmBox_ = std::make_shared<HeifPtimBox>();
    if (!heifParser->pitmBox_) {
        return false;
    }
    return true;
}

bool ConstructHeifTopBoxes(std::shared_ptr<HeifParser> heifParser)
{
    if (!heifParser->topBoxes_.empty()) {
        return true;
    }
    std::vector<BoxType> boxes { BoxType::FTYP, BoxType::META, BoxType::CLLI };
    for (uint32_t i = 0; i < MOCKLEN; i++) {
        BoxType tType = boxes[FDP->ConsumeIntegral<uint8_t>() % MOCKLEN];
        switch (tType) {
            case BoxType::FTYP:
                heifParser->topBoxes_.emplace_back(std::make_shared<HeifFtypBox>());
                break;
            case BoxType::META:
                heifParser->topBoxes_.emplace_back(std::make_shared<HeifMetaBox>());
                break;
            case BoxType::CLLI:
                heifParser->topBoxes_.emplace_back(std::make_shared<HeifClliBox>());
                break;
            default:
                break;
        }
    }

    if (heifParser->topBoxes_.empty()) {
        return false;
    }
    return true;
}

bool ConstructHeifIrefBox(std::shared_ptr<HeifParser> heifParser)
{
    if (heifParser->irefBox_) {
        return true;
    }

    heifParser->irefBox_ = std::make_shared<HeifIrefBox>();
    if (!heifParser->irefBox_) {
        return false;
    }
    std::vector<heif_item_id> ids;
    ids.emplace_back(MOCK_IMAGE_ID);
    heifParser->irefBox_->AddReferences(MOCK_ITEM_GRID, BOX_TYPE_DIMG, ids);
    std::shared_ptr<HeifImage> gridImage = std::make_shared<HeifImage>(MOCK_IMAGE_ID);
    if (!gridImage) {
        return false;
    }
    heifParser->images_.insert(std::make_pair(MOCK_IMAGE_ID, gridImage));
    if (!heifParser->images_.count(MOCK_IMAGE_ID) || !heifParser->images_[MOCK_IMAGE_ID]) {
        return false;
    }
    return true;
}

bool ConstructHeifIpcoBox(std::shared_ptr<HeifParser> heifParser)
{
    if (heifParser->ipcoBox_) {
        return true;
    }

    heifParser->ipcoBox_ = std::make_shared<HeifIpcoBox>();
    if (!heifParser->ipcoBox_) {
        return false;
    }
    return true;
}

bool ConstructHeifIpmaBox(std::shared_ptr<HeifParser> heifParser)
{
    if (heifParser->ipmaBox_) {
        return true;
    }

    heifParser->ipmaBox_ = std::make_shared<HeifIpmaBox>();
    if (!heifParser->ipmaBox_) {
        return false;
    }
    return true;
}

bool ConstructHeifMetaBox(std::shared_ptr<HeifParser> heifParser)
{
    if (heifParser->metaBox_) {
        return true;
    }

    heifParser->metaBox_ = std::make_shared<HeifMetaBox>();
    if (!heifParser->metaBox_) {
        return false;
    }
    return true;
}

bool ConstructHeifBox(std::shared_ptr<HeifParser> heifParser, BoxType boxType)
{
    if (!heifParser) {
        return false;
    }

    switch (boxType) {
        case BoxType::ILOC:
            return ConstructHeifIlocBox(heifParser);
        case BoxType::IDAT:
            return ConstructHeifIdatBox(heifParser);
        case BoxType::IINF:
            return ConstructHeifIinfBox(heifParser);
        case BoxType::INFE:
            return ConstructHeifInfeBox(heifParser);
        case BoxType::PTIM:
            return ConstructHeifPtimBox(heifParser);
        case BoxType::IREF:
            return ConstructHeifIrefBox(heifParser);
        case BoxType::IPCO:
            return ConstructHeifIpcoBox(heifParser);
        case BoxType::IPMA:
            return ConstructHeifIpmaBox(heifParser);
        case BoxType::META:
            return ConstructHeifMetaBox(heifParser);
        default:
            break;
    }

    return false;
}

void WriteFuzzTest(std::shared_ptr<HeifParser> heifParser)
{
    if (!heifParser) {
        return;
    }
    if (!ConstructHeifTopBoxes(heifParser) || !ConstructHeifBox(heifParser, BoxType::ILOC)) {
        return;
    }
    HeifStreamWriter writer;
    heifParser->Write(writer);
}

void GetGridLengthFuzzTest(std::shared_ptr<HeifParser> heifParser)
{
    if (!heifParser) {
        return;
    }
    if (!ConstructHeifBox(heifParser, BoxType::INFE)) {
        return;
    }
    std::vector<uint32_t> itemIds {
        MOCK_ITEM_ID,
        MOCK_ITEM_ID2,
        FDP->ConsumeIntegral<uint32_t>(),
        FDP->ConsumeIntegral<uint32_t>()
    };
    for (const auto &id : itemIds) {
        size_t length { 0 };
        heifParser->GetGridLength(id, length);
    }
}

void GetIdenImageFuzzTest(std::shared_ptr<HeifParser> heifParser)
{
    if (!heifParser) {
        return;
    }
    if (!ConstructHeifBox(heifParser, BoxType::INFE) || !ConstructHeifBox(heifParser, BoxType::IREF)) {
        return;
    }
    std::vector<uint32_t> itemIds {
        MOCK_ITEM_GRID,
        FDP->ConsumeIntegral<uint32_t>(),
        FDP->ConsumeIntegral<uint32_t>()
    };
    for (const auto &id : itemIds) {
        std::shared_ptr<HeifImage> out;
        heifParser->GetIdenImage(id, out);
    }
}

void AddPropertyFuzzTest(std::shared_ptr<HeifParser> heifParser)
{
    if (!heifParser) {
        return;
    }
    if (!ConstructHeifBox(heifParser, BoxType::IPCO) || !ConstructHeifBox(heifParser, BoxType::IPMA)) {
        return;
    }
    heifParser->AddIspeProperty(
        FDP->ConsumeIntegral<uint32_t>(),
        FDP->ConsumeIntegral<uint32_t>(),
        FDP->ConsumeIntegral<uint32_t>());
    heifParser->AddPixiProperty(
        FDP->ConsumeIntegral<uint32_t>(),
        FDP->ConsumeIntegral<uint8_t>());
    heifParser->AddHvccProperty(FDP->ConsumeIntegral<uint32_t>());
    heifParser->SetAuxcProperty(
        FDP->ConsumeIntegral<uint32_t>(),
        FDP->ConsumeRandomLengthString(MOCKLEN));
    auto colorProfile = ConstructHeifColorProfile();
    heifParser->SetColorProfile(
        FDP->ConsumeIntegral<uint32_t>(),
        colorProfile);
}

void HeifHvccFuzzTest(std::shared_ptr<HeifParser> heifParser)
{
    if (!heifParser) {
        return;
    }
    if (!ConstructHeifBox(heifParser, BoxType::IPCO) || !ConstructHeifBox(heifParser, BoxType::IPMA)) {
        return;
    }
    uint32_t hvccId = FDP->ConsumeIntegral<uint32_t>();
    std::vector<uint8_t> hvccData {
        FDP->ConsumeIntegral<uint8_t>(),
        FDP->ConsumeIntegral<uint8_t>(),
        FDP->ConsumeIntegral<uint8_t>()
    };
    HvccConfig hvccConfig { ConstructHvccConfig() };
    heifParser->AddHvccProperty(hvccId);
    heifParser->AppendHvccNalData(hvccId, hvccData);
    heifParser->SetHvccConfig(hvccId, hvccConfig);
}

void AddReferenceFuzzTest(std::shared_ptr<HeifParser> heifParser)
{
    if (!heifParser) {
        return;
    }

    if (!ConstructHeifBox(heifParser, BoxType::META)) {
        return;
    }

    heifParser->irefBox_.reset();
    std::vector<uint32_t> toItemIds {
        FDP->ConsumeIntegral<uint32_t>(),
        FDP->ConsumeIntegral<uint32_t>(),
        FDP->ConsumeIntegral<uint32_t>()
    };
    heifParser->AddReference(
        FDP->ConsumeIntegral<uint32_t>(),
        FDP->ConsumeIntegral<uint32_t>(),
        toItemIds);
}

void SetPrimaryImageFuzzTest(std::shared_ptr<HeifParser> heifParser)
{
    if (!heifParser) {
        return;
    }
    if (!ConstructHeifBox(heifParser, BoxType::PTIM)) {
        return;
    }
    std::shared_ptr<HeifImage> heifImage = std::make_shared<HeifImage>(FDP->ConsumeIntegral<uint32_t>());
    if (!heifImage) {
        return;
    }
    heifParser->SetPrimaryImage(heifImage);
    heifParser->SetPrimaryImage(heifImage);
    std::shared_ptr<HeifImage> heifImageAnother = std::make_shared<HeifImage>(FDP->ConsumeIntegral<uint32_t>());
    if (!heifImageAnother) {
        return;
    }
    heifParser->SetPrimaryImage(heifImageAnother);
}

void SetExifMetaDataFuzzTest(std::shared_ptr<HeifParser> heifParser)
{
    if (!heifParser) {
        return;
    }
    if (!ConstructHeifBox(heifParser, BoxType::IINF) ||
        !ConstructHeifBox(heifParser, BoxType::META) ||
        !ConstructHeifBox(heifParser, BoxType::ILOC)) {
        return;
    }
    std::shared_ptr<HeifImage> heifImage = std::make_shared<HeifImage>(FDP->ConsumeIntegral<uint32_t>());
    if (!heifImage) {
        return;
    }
    size_t numBytes = FDP->ConsumeIntegralInRange<size_t>(0, HEIF_MAX_EXIF_SIZE + MOCKLEN);
    std::vector<uint8_t> metaDataVec = FDP->ConsumeBytes<uint8_t>(numBytes);
    heifParser->SetExifMetadata(heifImage, metaDataVec.data(), metaDataVec.size());
}

void UpdateExifMetaDataFuzzTest(std::shared_ptr<HeifParser> heifParser)
{
    if (!heifParser) {
        return;
    }
    if (!ConstructHeifBox(heifParser, BoxType::ILOC)) {
        return;
    }
    uint32_t itemId = FDP->ConsumeIntegral<uint32_t>();
    std::shared_ptr<HeifImage> heifImage = std::make_shared<HeifImage>(itemId);
    if (!heifImage) {
        return;
    }
    size_t numBytes = FDP->ConsumeIntegralInRange<size_t>(0, HEIF_MAX_EXIF_SIZE + MOCKLEN);
    std::vector<uint8_t> metaDataVec = FDP->ConsumeBytes<uint8_t>(numBytes);
    heifParser->UpdateExifMetadata(heifImage, metaDataVec.data(), metaDataVec.size(), itemId);
}

void HeifParserFuzzTest001(const uint8_t *data, size_t size)
{
    if (data == nullptr) {
        return;
    }

    auto heifParser = ConstructHeifParser(data, size);
    if (!heifParser) {
        return;
    }

    WriteFuzzTest(heifParser);
    GetGridLengthFuzzTest(heifParser);
    GetIdenImageFuzzTest(heifParser);
    AddPropertyFuzzTest(heifParser);
    HeifHvccFuzzTest(heifParser);
    AddReferenceFuzzTest(heifParser);
    SetPrimaryImageFuzzTest(heifParser);
    SetExifMetaDataFuzzTest(heifParser);
    UpdateExifMetaDataFuzzTest(heifParser);
}

} // namespace Media
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::Media::FDP = &fdp;
    /* Run your code on data */
    OHOS::Media::HeifParserFuzzTest001(data, size);
    return 0;
}