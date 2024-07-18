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

#include "image_heif_impl_fuzzer.h"

#include <cstdint>
#include <memory>
#include <string>

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

namespace OHOS {
namespace Media {
using namespace OHOS::ImagePlugin;

void ItemPropertyBoxTest001(HeifIprpBox *heifiprpbox, HeifIpcoBox *heifipcobox,
    HeifIpmaBox *heifipmabox, HeifStreamReader &reader, HeifStreamWriter &writer)
{
    heif_item_id itemId = 0xffff;
    const std::shared_ptr<HeifIpmaBox> const_box_ptr = nullptr;
    std::vector<std::shared_ptr<HeifBox>> v1(1, nullptr);
    uint32_t uint32data = 0;
    PropertyAssociation assoc;
    const HeifIpmaBox const_box;

    if (heifiprpbox == nullptr) {
        return;
    }
    heifiprpbox->ParseContent(reader);

    if (heifipcobox == nullptr) {
        return;
    }
    heifipcobox->GetProperties(itemId, const_box_ptr, v1);
    heifipcobox->GetProperty(itemId, const_box_ptr, uint32data);
    heifipcobox->ParseContent(reader);

    if (heifipmabox == nullptr) {
        return;
    }
    heifipmabox->GetProperties(itemId);
    heifipmabox->AddProperty(itemId, assoc);
    heifipmabox->InferFullBoxVersion();
    heifipmabox->Write(writer);
    heifipmabox->MergeImpaBoxes(const_box);
    heifipmabox->ParseContent(reader);
}

void ItemPropertyBasicBoxTest001(HeifIspeBox *heifispebox, HeifPixiBox *heifpixibox,
    HeifStreamReader &reader, HeifStreamWriter &writer)
{
    uint32_t uint32data = 0;
    int channel = 0;
    uint8_t uint8data = 0;

    if (heifispebox == nullptr) {
        return;
    }
    heifispebox->GetWidth();
    heifispebox->GetHeight();
    heifispebox->SetDimension(uint32data, uint32data);
    heifispebox->Write(writer);
    heifispebox->ParseContent(reader);

    if (heifpixibox == nullptr) {
        return;
    }
    heifpixibox->GetChannelNum();
    heifpixibox->GetBitNum(channel);
    heifpixibox->AddBitNum(uint8data);
    heifpixibox->Write(writer);
    heifpixibox->ParseContent(reader);
}

void ItemPropertyAuxBoxTest001(HeifAuxcBox *heifauxcbox, HeifStreamReader &reader,
    HeifStreamWriter &writer)
{
    const std::string const_type = "abc";

    if (heifauxcbox == nullptr) {
        return;
    }
    heifauxcbox->GetAuxType();
    heifauxcbox->SetAuxType(const_type);
    heifauxcbox->GetAuxSubtypes();
    heifauxcbox->ParseContent(reader);
    heifauxcbox->Write(writer);
}

void ItemPropertyColorBoxTest001(const std::shared_ptr<const HeifRawColorProfile> &heifrawcolorprofile,
    const std::shared_ptr<const HeifNclxColorProfile> &heifnclxcolorprofile,
    HeifColrBox *heifcolrbox, HeifStreamReader &reader, HeifStreamWriter &writer)
{
    const std::shared_ptr<const HeifColorProfile> const_prof = nullptr;

    if (heifrawcolorprofile == nullptr) {
        return;
    }
    heifrawcolorprofile->GetProfileType();
    heifrawcolorprofile->GetData();
    heifrawcolorprofile->Write(writer);

    if (heifnclxcolorprofile == nullptr) {
        return;
    }
    heifnclxcolorprofile->GetProfileType();
    heifnclxcolorprofile->Write(writer);
    heifnclxcolorprofile->GetColorPrimaries();
    heifnclxcolorprofile->GetTransferCharacteristics();
    heifnclxcolorprofile->GetMatrixCoefficients();
    heifnclxcolorprofile->GetFullRangeFlag();

    if (heifcolrbox == nullptr) {
        return;
    }
    heifcolrbox->GetColorProfileType();
    heifcolrbox->GetColorProfile();
    heifcolrbox->SetColorProfile(const_prof);
    heifcolrbox->Write(writer);
    heifcolrbox->ParseContent(reader);
}

void ItemPropertyDisplayBoxTest001(HeifMdcvBox *heifmdcvbox, HeifClliBox *heifcllibox,
    HeifStreamReader &reader,  HeifStreamWriter &writer)
{
    DisplayColourVolume colourVolume;
    ContentLightLevelInfo lightLevel;

    if (heifmdcvbox == nullptr) {
        return;
    }
    heifmdcvbox->GetColourVolume();
    heifmdcvbox->SetColourVolume(colourVolume);
    heifmdcvbox->ParseContent(reader);
    heifmdcvbox->Write(writer);

    if (heifcllibox == nullptr) {
        return;
    }
    heifcllibox->GetLightLevel();
    heifcllibox->SetLightLevel(lightLevel);
    heifcllibox->ParseContent(reader);
    heifcllibox->Write(writer);
}

void ItemPropertyHvccBoxTest001(HeifHvccBox *heifhvccbox, HeifStreamReader &reader,
    HeifStreamWriter &writer)
{
    std::vector<uint8_t> v1(1, 1);
    const HvccConfig config = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    const std::vector<uint8_t> v2(1, 1);
    std::vector<std::vector<uint8_t>> v3(1, v1);

    if (heifhvccbox == nullptr) {
        return;
    }
    heifhvccbox->GetHeaders(&v1);
    heifhvccbox->SetConfig(config);
    heifhvccbox->GetConfig();
    heifhvccbox->AppendNalData(v2);
    heifhvccbox->Write(writer);
    heifhvccbox->ParseContent(reader);
    heifhvccbox->ParseNalUnitArray(reader, v3);
}

void ItemPropertyTransformBoxTest001(HeifIrotBox *heifirotbox,
    HeifImirBox *heifimirbox, HeifStreamReader &reader, HeifStreamWriter &writer)
{
    int rot = 0;
    HeifTransformMirrorDirection dir = HeifTransformMirrorDirection::VERTICAL;

    if (heifirotbox == nullptr) {
        return;
    }
    heifirotbox->GetRotDegree();
    heifirotbox->SetRotDegree(rot);
    heifirotbox->ParseContent(reader);
    heifirotbox->Write(writer);

    if (heifimirbox == nullptr) {
        return;
    }
    heifimirbox->GetDirection();
    heifimirbox->SetDirection(dir);
    heifimirbox->ParseContent(reader);
    heifimirbox->Write(writer);
}

void HeifImplFuzzTest001(const uint8_t *data, size_t size)
{
    bool flag;
    const char *itemType = "abc";
    int64_t start = 0;
    auto heifbuffstream = std::make_shared<HeifBufferInputStream>(data, size, flag);
    auto heifparse = HeifParser(heifbuffstream);
    std::shared_ptr<HeifInfeBox> heifinfebox = heifparse.AddItem(itemType, flag);
    std::shared_ptr<HeifFullBox> heiffullbox = heifinfebox;
    std::shared_ptr<HeifBox> heifbox = heiffullbox;
    HeifBox *temp_heifbox = heifbox.get();
    void *objHeifbox = dynamic_cast<void*>(temp_heifbox);
    HeifFullBox *temp_heiffullbox = heiffullbox.get();
    void *objHeiffullbox = dynamic_cast<void*>(temp_heiffullbox);
    auto heifstreamreader = HeifStreamReader(heifbuffstream, start, size);
    auto heifstreamwriter = HeifStreamWriter();

    // item_property_box.cpp create/init/fuzztest
    auto heifiprpbox = static_cast<HeifIprpBox*>(objHeifbox);
    auto heifipcobox = static_cast<HeifIpcoBox*>(objHeifbox);
    auto heifipmabox = static_cast<HeifIpmaBox*>(objHeiffullbox);
    ItemPropertyBoxTest001(heifiprpbox, heifipcobox, heifipmabox, heifstreamreader, heifstreamwriter);

    // item_property_basic_box.cpp create/init/fuzztest
    auto heifispebox = static_cast<HeifIspeBox*>(objHeiffullbox);
    auto heifpixibox = static_cast<HeifPixiBox*>(objHeiffullbox);
    ItemPropertyBasicBoxTest001(heifispebox, heifpixibox, heifstreamreader, heifstreamwriter);

    // item_property_aux_box.cpp create/init/fuzztest
    auto heifauxcbox = static_cast<HeifAuxcBox*>(objHeiffullbox);
    ItemPropertyAuxBoxTest001(heifauxcbox, heifstreamreader, heifstreamwriter);

    // item_property_color_box.cpp create/init/fuzztest
    std::shared_ptr<HeifImage> heifimage = heifparse.GetGainmapImage();
    if (heifimage != nullptr) {
        auto heifrawcolorprofile = heifimage->GetRawColorProfile();
        auto heifnclxcolorprofile = heifimage->GetNclxColorProfile();
        auto heifcolrbox = static_cast<HeifColrBox*>(objHeifbox);
        ItemPropertyColorBoxTest001(heifrawcolorprofile, heifnclxcolorprofile, heifcolrbox,
            heifstreamreader, heifstreamwriter);
    }

    // item_property_display_box.cpp create/init/fuzztest
    auto heifmdcvbox = static_cast<HeifMdcvBox*>(objHeifbox);
    auto heifcllibox = static_cast<HeifClliBox*>(objHeifbox);
    ItemPropertyDisplayBoxTest001(heifmdcvbox, heifcllibox, heifstreamreader, heifstreamwriter);

    // item_property_hvcc_box.cpp create/init/fuzztest
    auto heifhvccbox = static_cast<HeifHvccBox*>(objHeifbox);
    ItemPropertyHvccBoxTest001(heifhvccbox, heifstreamreader, heifstreamwriter);

    // item_property_transform_box.cpp create/init/fuzztest
    auto heifirotbox = static_cast<HeifIrotBox*>(objHeifbox);
    auto heifimirbox = static_cast<HeifImirBox*>(objHeifbox);
    ItemPropertyTransformBoxTest001(heifirotbox, heifimirbox, heifstreamreader, heifstreamwriter);
}

} // namespace Media
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::Media::HeifImplFuzzTest001(data, size);
    return 0;
}