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

#include "image_heif_impl_fuzzer.h"

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

static constexpr uint32_t MOCK_ITEM_ID = 0;
static constexpr size_t MOCKLEN = 3;
static constexpr uint8_t CONSTRUCTION_METHOD_IDAT_OFFSET = 1;
namespace {
    enum class BoxType : uint8_t {
        ILOC,
        IDAT,
        IINF,
        INFE,
        PTIM,
        HEIF,
        FULL,
    };
}

std::shared_ptr<HeifParser> ConstructHeifParser(const uint8_t *data, size_t size)
{
    if (data == nullptr) {
        return nullptr;
    }
    auto inputStream = std::make_shared<HeifBufferInputStream>(data, size, false);
    if (!inputStream) {
        return nullptr;
    }
    std::shared_ptr<HeifParser> heifParser = std::make_shared<HeifParser>(inputStream);
    if (!heifParser) {
        return nullptr;
    }
    return heifParser;
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

    std::vector<uint8_t> mockData(MOCKLEN);
    for (auto &data : mockData) {
        data = FDP->ConsumeIntegral<uint8_t>();
    }
    heifParser->AppendIlocData(MOCK_ITEM_ID, mockData);
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

    heifParser->infeBoxes_[MOCK_ITEM_ID] = std::make_shared<HeifInfeBox>();
    if (!heifParser->infeBoxes_.count(MOCK_ITEM_ID) || !heifParser->infeBoxes_[MOCK_ITEM_ID]) {
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

bool ConstructHeifHeifBox(std::shared_ptr<HeifParser> heifParser)
{
    if (!heifParser->topBoxes_.empty()) {
        decltype(heifParser->topBoxes_) temp;
        heifParser->topBoxes_.swap(temp);
    }
    heifParser->topBoxes_.push_back(std::make_shared<HeifBox>());
    if (heifParser->topBoxes_.empty() || heifParser->topBoxes_[0]->boxType_ != 0) {
        return false;
    }
    return true;
}

bool ConstructHeifFullBox(std::shared_ptr<HeifParser> heifParser)
{
    if (!heifParser->topBoxes_.empty()) {
        decltype(heifParser->topBoxes_) temp;
        heifParser->topBoxes_.swap(temp);
    }
    heifParser->topBoxes_.push_back(std::make_shared<HeifFullBox>());
    if (heifParser->topBoxes_.empty() || heifParser->topBoxes_[0]->boxType_ != 0) {
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
        case BoxType::HEIF:
            return ConstructHeifHeifBox(heifParser);
        case BoxType::FULL:
            return ConstructHeifFullBox(heifParser);
    }

    return false;
}

void GridLengthFuzzTest001(std::shared_ptr<HeifParser> heifParser)
{
    if (!heifParser) {
        return;
    }

    if (ConstructHeifBox(heifParser, BoxType::ILOC)) {
        return;
    }

    size_t length { 0 };
    heifParser->GetGridLength(MOCK_ITEM_ID, length);
}

void UpdateDataFuzzTest001(std::shared_ptr<HeifParser> heifParser)
{
    if (!heifParser) {
        return;
    }

    if (ConstructHeifBox(heifParser, BoxType::ILOC)) {
        return;
    }

    std::shared_ptr<HeifImage> heifImage = std::make_shared<HeifImage>(MOCK_ITEM_ID);
    if (!heifImage) {
        return;
    }

    std::vector<uint8_t> mockData(MOCKLEN);
    for (auto &data : mockData) {
        data = FDP->ConsumeIntegral<uint8_t>();
    }
    heifParser->UpdateExifMetadata(heifImage, mockData.data(), MOCKLEN, MOCK_ITEM_ID);
}

void InferFullBoxVersionIlocFuzzTest(std::shared_ptr<HeifParser> heifParser)
{
    if (!heifParser || !ConstructHeifBox(heifParser, BoxType::ILOC)) {
        return;
    }

    heifParser->ilocBox_->InferFullBoxVersion();
}

void WriteIlocFuzzTest(std::shared_ptr<HeifParser> heifParser)
{
    if (!heifParser || !ConstructHeifBox(heifParser, BoxType::ILOC)) {
        return;
    }

    HeifStreamWriter writer;
    heifParser->Write(writer);
    heifParser->ilocBox_->Write(writer);
}

void ReadToExtentDataIdatFuzzTest001(std::shared_ptr<HeifParser> heifParser)
{
    if (!heifParser) {
        return;
    }

    if (!ConstructHeifBox(heifParser, BoxType::ILOC) || !ConstructHeifBox(heifParser, BoxType::IDAT)) {
        return;
    }

    std::vector<uint8_t> mockData(MOCKLEN);
    for (auto &data : mockData) {
        data = FDP->ConsumeIntegral<uint8_t>();
    }
    heifParser->AppendIlocData(MOCK_ITEM_ID, mockData, CONSTRUCTION_METHOD_IDAT_OFFSET);
    heifParser->CheckExtentData();
}

void WriteIdatFuzzTest(std::shared_ptr<HeifParser> heifParser)
{
    if (!heifParser) {
        return;
    }

    if (!ConstructHeifBox(heifParser, BoxType::ILOC) || !ConstructHeifBox(heifParser, BoxType::IDAT)) {
        return;
    }

    HeifStreamWriter writer;
    heifParser->idatBox_->Write(writer);
}

void HeifImplFuzzTest001(const uint8_t *data, size_t size)
{
    if (data == nullptr) {
        return;
    }
    auto heifParser = ConstructHeifParser(data, size);
    if (!heifParser) {
        return;
    }

    GridLengthFuzzTest001(heifParser);
    UpdateDataFuzzTest001(heifParser);
    InferFullBoxVersionIlocFuzzTest(heifParser);
    WriteIlocFuzzTest(heifParser);
    ReadToExtentDataIdatFuzzTest001(heifParser);
    WriteIdatFuzzTest(heifParser);
}

void InferFullBoxVersionIinfFuzzTest(std::shared_ptr<HeifParser> heifParser)
{
    if (!heifParser) {
        return;
    }
    if (!ConstructHeifBox(heifParser, BoxType::IINF)) {
        return;
    }
    heifParser->iinfBox_->InferFullBoxVersion();
}

void WriteIinfFuzzTest(std::shared_ptr<HeifParser> heifParser)
{
    if (!heifParser) {
        return;
    }
    if (!ConstructHeifBox(heifParser, BoxType::IINF)) {
        return;
    }
    HeifStreamWriter writer;
    heifParser->iinfBox_->Write(writer);
}

void InferFullBoxVersionInfeFuzzTest(std::shared_ptr<HeifParser> heifParser)
{
    if (!heifParser) {
        return;
    }
    if (!ConstructHeifBox(heifParser, BoxType::INFE)) {
        return;
    }
    heifParser->infeBoxes_[MOCK_ITEM_ID]->InferFullBoxVersion();
}

void WriteInfeFuzzTest(std::shared_ptr<HeifParser> heifParser)
{
    if (!heifParser) {
        return;
    }
    if (!ConstructHeifBox(heifParser, BoxType::INFE)) {
        return;
    }
    HeifStreamWriter writer;
    heifParser->infeBoxes_[MOCK_ITEM_ID]->Write(writer);
}

void InferFullBoxVersionPtimFuzzTest(std::shared_ptr<HeifParser> heifParser)
{
    if (!heifParser) {
        return;
    }
    if (!ConstructHeifBox(heifParser, BoxType::PTIM)) {
        return;
    }
    heifParser->pitmBox_->InferFullBoxVersion();
}

void WritePtimFuzzTest(std::shared_ptr<HeifParser> heifParser)
{
    if (!heifParser) {
        return;
    }
    if (!ConstructHeifBox(heifParser, BoxType::PTIM)) {
        return;
    }
    HeifStreamWriter writer;
    heifParser->pitmBox_->Write(writer);
}

void HeifImplFuzzTest002(const uint8_t *data, size_t size)
{
    if (data == nullptr) {
        return;
    }

    auto heifParser = ConstructHeifParser(data, size);
    if (!heifParser) {
        return;
    }

    InferFullBoxVersionIinfFuzzTest(heifParser);
    WriteIinfFuzzTest(heifParser);
    InferFullBoxVersionInfeFuzzTest(heifParser);
    WriteInfeFuzzTest(heifParser);
    InferFullBoxVersionPtimFuzzTest(heifParser);
    WritePtimFuzzTest(heifParser);
}

void WriteHeifFuzzTest(std::shared_ptr<HeifParser> heifParser)
{
    if (!heifParser) {
        return;
    }
    if (!ConstructHeifBox(heifParser, BoxType::HEIF)) {
        return;
    }
    HeifStreamWriter writer;
    heifParser->topBoxes_[0]->Write(writer);
}

void WriteFullFuzzTest(std::shared_ptr<HeifParser> heifParser)
{
    if (!heifParser) {
        return;
    }
    if (!ConstructHeifBox(heifParser, BoxType::FULL)) {
        return;
    }
    HeifStreamWriter writer;
    heifParser->topBoxes_[0]->Write(writer);
}

void HeifImplFuzzTest003(const uint8_t *data, size_t size)
{
    if (data == nullptr) {
        return;
    }

    auto heifParser = ConstructHeifParser(data, size);
    if (!heifParser) {
        return;
    }

    WriteHeifFuzzTest(heifParser);
    WriteFullFuzzTest(heifParser);
}
} // namespace Media
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::Media::FDP = &fdp;
    /* Run your code on data */
    OHOS::Media::HeifImplFuzzTest001(data, size);
    OHOS::Media::HeifImplFuzzTest002(data, size);
    OHOS::Media::HeifImplFuzzTest003(data, size);
    return 0;
}