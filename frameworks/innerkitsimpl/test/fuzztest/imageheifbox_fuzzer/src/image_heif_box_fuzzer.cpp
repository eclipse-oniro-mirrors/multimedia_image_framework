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

#include "image_heif_box_fuzzer.h"

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
    static constexpr uint32_t DIRECTION_MODULO = 3;
    static constexpr uint32_t NUM_0 = 0;
    static constexpr uint32_t NUM_1 = 1;
    static constexpr uint32_t NUM_10 = 10;
    enum class BOX_TYPE {
        IMIR,
        IROT,
        CLLI,
        FTYP,
        HDLR,
        AUXC,
        ISPE,
        IREF,
        COLR,
        MDCV,
        PIXI,
        RLOC,
        IPMA,
        IPCO,
    };
}

std::shared_ptr<HeifBox> ConstructIMIRBox()
{
    std::shared_ptr<HeifImirBox> res = std::make_shared<HeifImirBox>();
    if (!res) {
        return nullptr;
    }
    res->direction_ = static_cast<HeifTransformMirrorDirection>(FDP->ConsumeIntegral<uint32_t>() % DIRECTION_MODULO);
    return res;
}

std::shared_ptr<HeifBox> ConstructIROTBox()
{
    std::shared_ptr<HeifIrotBox> res = std::make_shared<HeifIrotBox>();
    if (!res) {
        return nullptr;
    }
    res->rotDegree_ = FDP->ConsumeIntegral<int>();
    return res;
}

std::shared_ptr<HeifBox> ConstructCLLIBox()
{
    std::shared_ptr<HeifClliBox> res = std::make_shared<HeifClliBox>();
    if (!res) {
        return nullptr;
    }
    ContentLightLevelInfo levelInfo {
        .maxContentLightLevel = FDP->ConsumeIntegral<uint16_t>(),
        .maxPicAverageLightLevel = FDP->ConsumeIntegral<uint16_t>()};
    res->lightLevel_ = levelInfo;
    return res;
}

std::shared_ptr<HeifBox> ConstructFTYPBox()
{
    std::shared_ptr<HeifFtypBox> res = std::make_shared<HeifFtypBox>();
    if (!res) {
        return nullptr;
    }
    res->majorBrand_ = FDP->ConsumeIntegral<uint32_t>();
    res->minorVersion_ = FDP->ConsumeIntegral<uint32_t>();
    size_t randomSize = FDP->ConsumeIntegralInRange<size_t>(NUM_1, NUM_10);
    for (size_t i = 0; i < randomSize; i++) {
        res->compatibleBrands_.emplace_back(FDP->ConsumeIntegral<uint32_t>());
    }
    return res;
}

std::shared_ptr<HeifBox> ConstructHDLRBox()
{
    std::shared_ptr<HeifHdlrBox> res = std::make_shared<HeifHdlrBox>();
    if (!res) {
        return nullptr;
    }
    res->isPreDefined_ = FDP->ConsumeIntegral<uint32_t>();
    res->handlerType_ = FDP->ConsumeIntegral<uint32_t>();
    for (size_t i = 0; i < HeifHdlrBox::HDLR_BOX_RESERVED_SIZE; i++) {
        res->reserved_[i] = FDP->ConsumeIntegral<uint32_t>();
    }
    res->name_ = FDP->ConsumeRandomLengthString(NUM_10);
    return res;
}

std::shared_ptr<HeifBox> ConstructAUXCBox()
{
    std::shared_ptr<HeifAuxcBox> res = std::make_shared<HeifAuxcBox>();
    if (!res) {
        return nullptr;
    }
    res->auxType_ = FDP->ConsumeRandomLengthString(NUM_10);
    size_t randomSize = FDP->ConsumeIntegralInRange<size_t>(NUM_1, NUM_10);
    res->auxSubtypes_ = FDP->ConsumeBytes<uint8_t>(randomSize);
    return res;
}

std::shared_ptr<HeifBox> ConstructISPEBox()
{
    std::shared_ptr<HeifIspeBox> res = std::make_shared<HeifIspeBox>();
    if (!res) {
        return nullptr;
    }
    res->width_ = FDP->ConsumeIntegral<uint32_t>();
    res->height_ = FDP->ConsumeIntegral<uint32_t>();
    return res;
}

std::shared_ptr<HeifBox> ConstructIREFBox()
{
    std::shared_ptr<HeifIrefBox> res = std::make_shared<HeifIrefBox>();
    if (!res) {
        return nullptr;
    }
    res->version_ = FDP->ConsumeIntegralInRange<uint8_t>(NUM_1, NUM_10);
    size_t randomSize = FDP->ConsumeIntegralInRange<size_t>(NUM_1, NUM_10);
    std::vector<heif_item_id> toItemIds;
    for (size_t i = 0; i < randomSize; i++) {
        toItemIds.emplace_back(FDP->ConsumeIntegral<uint32_t>());
    }
    uint32_t fromId = FDP->ConsumeIntegral<uint32_t>();
    uint32_t type = FDP->ConsumeIntegral<uint32_t>();
    res->AddReferences(fromId, type, toItemIds);
    if (!res->HasReferences(fromId)) {
        return nullptr;
    }
    return res;
}

std::shared_ptr<HeifBox> ConstructCOLRBox()
{
    std::shared_ptr<HeifColrBox> res = std::make_shared<HeifColrBox>();
    if (!res) {
        return nullptr;
    }
    if (FDP->ConsumeBool()) {
        uint32_t type = FDP->ConsumeIntegral<uint32_t>();
        size_t randomSize = FDP->ConsumeIntegralInRange<size_t>(NUM_1, NUM_10);
        std::vector<uint8_t> data = FDP->ConsumeBytes<uint8_t>(randomSize);
        std::shared_ptr<const HeifColorProfile> profile = std::make_shared<const HeifRawColorProfile>(type, data);
        if (!profile) {
            return nullptr;
        }
        res->SetColorProfile(profile);
    } else {
        uint16_t color = FDP->ConsumeIntegral<uint16_t>();
        uint16_t transfer = FDP->ConsumeIntegral<uint16_t>();
        uint16_t matrix = FDP->ConsumeIntegral<uint16_t>();
        uint8_t flag = FDP->ConsumeIntegral<uint8_t>();
        std::shared_ptr<const HeifColorProfile> profile =
            std::make_shared<const HeifNclxColorProfile>(color, transfer, matrix, flag);
        if (!profile) {
            return nullptr;
        }
        res->SetColorProfile(profile);
    }
    return res;
}

std::shared_ptr<HeifBox> ConstructMDCVBox()
{
    std::shared_ptr<HeifMdcvBox> res = std::make_shared<HeifMdcvBox>();
    if (!res) {
        return nullptr;
    }
    DisplayColourVolume volume;
    volume.red.x = FDP->ConsumeIntegral<uint16_t>();
    volume.red.y = FDP->ConsumeIntegral<uint16_t>();
    volume.green.x = FDP->ConsumeIntegral<uint16_t>();
    volume.green.y = FDP->ConsumeIntegral<uint16_t>();
    volume.blue.x = FDP->ConsumeIntegral<uint16_t>();
    volume.blue.y = FDP->ConsumeIntegral<uint16_t>();
    volume.whitePoint.x = FDP->ConsumeIntegral<uint16_t>();
    volume.whitePoint.y = FDP->ConsumeIntegral<uint16_t>();
    volume.luminanceMax = FDP->ConsumeIntegralInRange<uint32_t>(NUM_1, NUM_10);
    volume.luminanceMin = FDP->ConsumeIntegralInRange<uint32_t>(NUM_0, volume.luminanceMax);
    res->colourVolume_ = volume;
    return res;
}

std::shared_ptr<HeifBox> ConstructPIXIBox()
{
    std::shared_ptr<HeifPixiBox> res = std::make_shared<HeifPixiBox>();
    if (!res) {
        return nullptr;
    }
    size_t randomSize = FDP->ConsumeIntegralInRange<size_t>(NUM_1, NUM_10);
    std::vector<uint8_t> data = FDP->ConsumeBytes<uint8_t>(randomSize);
    res->bitNums_ = data;
    return res;
}

std::shared_ptr<HeifBox> ConstructRLOCBox()
{
    std::shared_ptr<HeifRlocBox> res = std::make_shared<HeifRlocBox>();
    if (!res) {
        return nullptr;
    }
    res->horizontalOffset_ = FDP->ConsumeIntegral<uint32_t>();
    res->verticalOffset_ = FDP->ConsumeIntegral<uint32_t>();
    return res;
}

std::shared_ptr<HeifBox> ConstructIPMABox()
{
    std::shared_ptr<HeifIpmaBox> res = std::make_shared<HeifIpmaBox>();
    if (!res) {
        return nullptr;
    }
    PropertyAssociation property;
    property.essential = FDP->ConsumeBool();
    property.propertyIndex = FDP->ConsumeIntegralInRange<uint16_t>(NUM_1, NUM_10);
    uint32_t itemId = FDP->ConsumeIntegral<uint32_t>();
    res->AddProperty(itemId, property);
    return res;
}

std::shared_ptr<HeifBox> ConstructIPCOBox()
{
    std::shared_ptr<HeifIpcoBox> res = std::make_shared<HeifIpcoBox>();
    if (!res) {
        return nullptr;
    }
    uint32_t type = FDP->ConsumeIntegral<uint32_t>();
    size_t randomSize = FDP->ConsumeIntegralInRange<size_t>(NUM_1, NUM_10);
    for (size_t i = 0; i < randomSize; i++) {
        std::shared_ptr<HeifBox> childBox = std::make_shared<HeifBox>(type);
        if (!childBox) {
            return nullptr;
        }
        res->AddChild(childBox);
    }
    return res;
}

std::shared_ptr<HeifBox> ConstructHeifBox(BOX_TYPE type)
{
    switch (type) {
        case BOX_TYPE::IMIR:
            return ConstructIMIRBox();
        case BOX_TYPE::IROT:
            return ConstructIROTBox();
        case BOX_TYPE::CLLI:
            return ConstructCLLIBox();
        case BOX_TYPE::FTYP:
            return ConstructFTYPBox();
        case BOX_TYPE::HDLR:
            return ConstructHDLRBox();
        case BOX_TYPE::AUXC:
            return ConstructAUXCBox();
        case BOX_TYPE::ISPE:
            return ConstructISPEBox();
        case BOX_TYPE::IREF:
            return ConstructIREFBox();
        case BOX_TYPE::COLR:
            return ConstructCOLRBox();
        case BOX_TYPE::MDCV:
            return ConstructMDCVBox();
        case BOX_TYPE::PIXI:
            return ConstructPIXIBox();
        case BOX_TYPE::RLOC:
            return ConstructRLOCBox();
        case BOX_TYPE::IPMA:
            return ConstructIPMABox();
        case BOX_TYPE::IPCO:
            return ConstructIPCOBox();
        default:
            break;
    }
    return nullptr;
}

std::vector<std::shared_ptr<HeifBox>> ConstructWriteHeifBoxes()
{
    std::vector<BOX_TYPE> boxTypes {
        BOX_TYPE::IMIR,
        BOX_TYPE::IROT,
        BOX_TYPE::CLLI,
        BOX_TYPE::FTYP,
        BOX_TYPE::HDLR,
        BOX_TYPE::AUXC,
        BOX_TYPE::ISPE,
        BOX_TYPE::COLR,
        BOX_TYPE::MDCV,
        BOX_TYPE::PIXI,
        BOX_TYPE::RLOC,
        BOX_TYPE::IPMA,
        BOX_TYPE::IREF
    };
    std::vector<std::shared_ptr<HeifBox>> res;
    for (const auto &type : boxTypes) {
        res.emplace_back(ConstructHeifBox(type));
    }
    return res;
}

std::vector<std::shared_ptr<HeifBox>> ConstructParseContentBoxes()
{
    std::vector<BOX_TYPE> boxTypes {
        BOX_TYPE::IMIR,
        BOX_TYPE::MDCV
    };
    std::vector<std::shared_ptr<HeifBox>> res;
    for (const auto &type : boxTypes) {
        res.emplace_back(ConstructHeifBox(type));
    }
    return res;
}

void HeifBoxWriteFuzzTest()
{
    auto boxes = ConstructWriteHeifBoxes();

    for (auto box : boxes) {
        if (box) {
            HeifStreamWriter writer;
            box->Write(writer);
        }
    }
}

void HeifBoxGetPropertyFuzzTest()
{
    std::shared_ptr<HeifIpcoBox> ipco = std::static_pointer_cast<HeifIpcoBox>(ConstructHeifBox(BOX_TYPE::IPCO));
    if (!ipco || ipco->children_.empty()) {
        return;
    }
    std::shared_ptr<HeifIpmaBox> ipma = std::static_pointer_cast<HeifIpmaBox>(ConstructHeifBox(BOX_TYPE::IPMA));
    if (!ipma || ipma->entries_.empty()) {
        return;
    }
    uint32_t itemId = ipma->entries_[0].itemId;
    uint32_t type = ipco->children_[0]->GetBoxType();
    ipco->GetProperty(itemId, ipma, type);
}

void HeifBoxParseContentFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr) {
        return;
    }
    auto boxes = ConstructParseContentBoxes();
    for (auto box : boxes) {
        if (box) {
            std::shared_ptr<HeifBufferInputStream> inputStream =
                std::make_shared<HeifBufferInputStream>(data, size, false);
            if (!inputStream) {
                return;
            }
            HeifStreamReader reader(inputStream, NUM_0, size);
            box->ParseContent(reader);
        }
    }
}

} // namespace Media
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::Media::FDP = &fdp;
    /* Run your code on data */
    OHOS::Media::HeifBoxWriteFuzzTest();
    OHOS::Media::HeifBoxGetPropertyFuzzTest();
    OHOS::Media::HeifBoxParseContentFuzzTest(data, size);
    return 0;
}