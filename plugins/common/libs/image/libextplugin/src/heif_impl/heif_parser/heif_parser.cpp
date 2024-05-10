/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "heif_parser.h"
#include "box/item_property_aux_box.h"
#include "box/item_property_basic_box.h"
#include "box/item_property_display_box.h"
#include "box/item_property_transform_box.h"
#include "securec.h"

#include <limits>
#include <cstring>

namespace OHOS {
namespace ImagePlugin {

HeifParser::HeifParser() = default;

HeifParser::~HeifParser() = default;

heif_error HeifParser::MakeFromMemory(const void *data, size_t size, bool isNeedCopy, std::shared_ptr<HeifParser> *out)
{
    auto input_stream = std::make_shared<HeifBufferInputStream>((const uint8_t *) data, size, isNeedCopy);
    return MakeFromStream(input_stream, out);
}

heif_error HeifParser::MakeFromStream(const std::shared_ptr<HeifInputStream> &stream, std::shared_ptr<HeifParser> *out)
{
    std::shared_ptr<HeifParser> file = std::make_shared<HeifParser>(stream);

    auto maxSize = static_cast<uint64_t>(std::numeric_limits<int64_t>::max());
    HeifStreamReader reader(stream, 0, maxSize);

    heif_error errorBox = file->AssembleBoxes(reader);
    if (errorBox != heif_error_ok) {
        return errorBox;
    }

    heif_error errorImage = file->AssembleImages();
    if (errorImage != heif_error_ok) {
        return errorImage;
    }

    *out = std::move(file);
    return errorBox;
}

void HeifParser::Write(HeifStreamWriter &writer)
{
    CheckExtentData();
    for (auto &box: topBoxes_) {
        box->InferAllFullBoxVersion();
        box->Write(writer);
    }

    ilocBox_->WriteMdatBox(writer);
}

heif_item_id HeifParser::GetPrimaryItemId() const
{
    return pitmBox_->GetItemId();
}

void HeifParser::GetAllItemId(std::vector<heif_item_id> &itemIdList) const
{
    for (const auto &infeBox: infeBoxes_) {
        itemIdList.push_back(infeBox.second->GetItemId());
    }
}

heif_error HeifParser::AssembleBoxes(HeifStreamReader &reader)
{
    while (true) {
        std::shared_ptr<HeifBox> box;
        heif_error error = HeifBox::MakeFromReader(reader, &box);
        if (reader.IsAtEnd() || error == heif_error_eof) {
            break;
        }
        if (error != heif_error_ok) {
            return error;
        }
        topBoxes_.push_back(box);
        if (box->GetBoxType() == BOX_TYPE_META) {
            metaBox_ = std::dynamic_pointer_cast<HeifMetaBox>(box);
        }
        if (box->GetBoxType() == BOX_TYPE_FTYP) {
            ftypBox_ = std::dynamic_pointer_cast<HeifFtypBox>(box);
        }
    }

    if (!ftypBox_) {
        return heif_error_no_ftyp;
    }

    if (!metaBox_) {
        return heif_error_no_meta;
    }

    hdlrBox_ = metaBox_->GetChild<HeifHdlrBox>(BOX_TYPE_HDLR);
    if (!hdlrBox_ || (hdlrBox_ && hdlrBox_->GetHandlerType() != HANDLER_TYPE_PICT)) {
        return heif_error_invalid_handler;
    }

    pitmBox_ = metaBox_->GetChild<HeifPtimBox>(BOX_TYPE_PITM);
    if (!pitmBox_) {
        return heif_error_no_pitm;
    }

    iinfBox_ = metaBox_->GetChild<HeifIinfBox>(BOX_TYPE_IINF);
    if (!iinfBox_) {
        return heif_error_no_iinf;
    }
    std::vector<std::shared_ptr<HeifInfeBox>> infes = iinfBox_->GetChildren<HeifInfeBox>(BOX_TYPE_INFE);
    for (auto &infe: infes) {
        infeBoxes_.insert(std::make_pair(infe->GetItemId(), infe));
    }

    irefBox_ = metaBox_->GetChild<HeifIrefBox>(BOX_TYPE_IREF);

    iprpBox_ = metaBox_->GetChild<HeifIprpBox>(BOX_TYPE_IPRP);
    if (!iprpBox_) {
        return heif_error_no_iprp;
    }

    ipcoBox_ = iprpBox_->GetChild<HeifIpcoBox>(BOX_TYPE_IPCO);
    if (!ipcoBox_) {
        return heif_error_no_ipco;
    }

    std::vector<std::shared_ptr<HeifIpmaBox>> ipmas = iprpBox_->GetChildren<HeifIpmaBox>(BOX_TYPE_IPMA);
    if (ipmas.empty()) {
        return heif_error_no_ipma;
    }
    ipmaBox_ = std::make_shared<HeifIpmaBox>();
    for (auto &ipma : ipmas) {
        ipmaBox_->MergeImpaBoxes(*ipma);
    }
    idatBox_ = metaBox_->GetChild<HeifIdatBox>(BOX_TYPE_IDAT);

    ilocBox_ = metaBox_->GetChild<HeifIlocBox>(BOX_TYPE_ILOC);
    if (!ilocBox_) {
        return heif_error_no_iloc;
    }
    return heif_error_ok;
}

bool HeifParser::HasItemId(heif_item_id itemId) const
{
    return infeBoxes_.find(itemId) != infeBoxes_.end();
}

std::string HeifParser::GetItemType(heif_item_id itemId) const
{
    auto infe_box = GetInfeBox(itemId);
    if (!infe_box) {
        return "";
    }
    return infe_box->GetItemType();
}

std::string HeifParser::GetItemContentType(heif_item_id itemId) const
{
    auto infe_box = GetInfeBox(itemId);
    if (!infe_box) {
        return "";
    }
    return infe_box->GetContentType();
}

std::string HeifParser::GetItemUriType(heif_item_id itemId) const
{
    auto infe_box = GetInfeBox(itemId);
    if (!infe_box) {
        return "";
    }
    return infe_box->GetItemUriType();
}


heif_error HeifParser::GetAllProperties(heif_item_id itemId, std::vector<std::shared_ptr<HeifBox>> &properties) const
{
    if (!ipcoBox_) {
        return heif_error_no_ipco;
    }
    if (!ipmaBox_) {
        return heif_error_no_ipma;
    }
    return ipcoBox_->GetProperties(itemId, ipmaBox_, properties);
}

heif_error HeifParser::GetItemData(heif_item_id itemId, std::vector<uint8_t> *out, heif_header_option option) const
{
    if (!HasItemId(itemId)) {
        return heif_error_item_not_found;
    }

    auto infe_box = GetInfeBox(itemId);
    if (!infe_box) {
        return heif_error_item_not_found;
    }

    std::string item_type = infe_box->GetItemType();
    auto items = ilocBox_->GetItems();
    const HeifIlocBox::Item *ilocItem = nullptr;
    for (const auto &item: items) {
        if (item.itemId == itemId) {
            ilocItem = &item;
            break;
        }
    }
    if (!ilocItem) {
        return heif_error_item_data_not_found;
    }

    heif_error error;
    if (item_type == "hvc1") {
        auto hvcc = GetProperty<HeifHvccBox>(itemId);
        if (!hvcc) {
            return heif_error_no_hvcc;
        }
        if (option != heif_no_header && !hvcc->GetHeaders(out)) {
            return heif_error_item_data_not_found;
        }
        if (option != heif_only_header) {
            error = ilocBox_->ReadData(*ilocItem, inputStream_, idatBox_, out);
        } else {
            error = heif_error_ok;
        }
    } else {
        error = ilocBox_->ReadData(*ilocItem, inputStream_, idatBox_, out);
    }

    return error;
}

void HeifParser::GetTileImages(heif_item_id gridItemId, std::vector<std::shared_ptr<HeifImage>> &out)
{
    auto infe = GetInfeBox(gridItemId);
    if (!infe || infe->GetItemType() != "grid") {
        return;
    }
    auto toItemIds = irefBox_->GetReferences(gridItemId, BOX_TYPE_DIMG);
    for (heif_item_id toItemId: toItemIds) {
        auto tileImage = GetImage(toItemId);
        if (tileImage) {
            out.push_back(tileImage);
        }
    }
}

std::shared_ptr<HeifInfeBox> HeifParser::GetInfeBox(heif_item_id itemId) const
{
    auto iter = infeBoxes_.find(itemId);
    if (iter == infeBoxes_.end()) {
        return nullptr;
    }
    return iter->second;
}

heif_error HeifParser::AssembleImages()
{
    images_.clear();
    primaryImage_.reset();

    std::vector<heif_item_id> allItemIds;
    GetAllItemId(allItemIds);

    for (heif_item_id itemId: allItemIds) {
        // extract Image Item
        auto infe = GetInfeBox(itemId);
        if (!infe) {
            continue;
        }
        const std::string& itemType = infe->GetItemType();
        if (itemType != "hvc1" && itemType != "grid" && itemType != "tmap") {
            continue;
        }
        auto image = std::make_shared<HeifImage>(itemId);
        if (itemType == "tmap") {
            tmapImage_ = image;
            ExtractImageProperties(tmapImage_);
            continue;
        }
        images_.insert(std::make_pair(itemId, image));
        if (!infe->IsHidden() && itemId == GetPrimaryItemId()) {
            image->SetPrimaryImage(true);
            primaryImage_ = image;
        }

        ExtractImageProperties(image);
    }

    if (!primaryImage_) {
        return heif_error_primary_item_not_found;
    }

    ExtractGainmap(allItemIds);
    ExtractGridImageProperties();
    ExtractNonMasterImages();
    ExtractMetadata(allItemIds);
    return heif_error_ok;
}

void HeifParser::ExtractIT35Metadata(const heif_item_id& metadataItemId)
{
    if (GetItemType(metadataItemId) != "it35") {
        return;
    }
    std::vector<uint8_t> extendInfo;
    heif_error err = GetItemData(metadataItemId, &(extendInfo));
    if (err != heif_error_ok || extendInfo.empty()) {
        return;
    }
    primaryImage_->SetUWAInfo(extendInfo);
}

void HeifParser::ExtractISOMetadata(const heif_item_id& itemId)
{
    if (GetItemType(itemId) != "tmap") {
        return;
    }
    std::vector<uint8_t> extendInfo;
    heif_error err = GetItemData(itemId, &extendInfo);
    if (err != heif_error_ok || extendInfo.empty()) {
        return ;
    }
    primaryImage_->SetISOMetadata(extendInfo);
}

void HeifParser::ExtractDisplayData(std::shared_ptr<HeifImage>& image, heif_item_id& itemId)
{
    auto mdcv = GetProperty<HeifMdcvBox>(itemId);
    auto clli = GetProperty<HeifClliBox>(itemId);
    if (mdcv == nullptr && clli == nullptr) {
        return;
    }
    DisplayColourVolume displayColourVolume{};
    ContentLightLevelInfo lightInfo{};
    uint32_t displaySize = sizeof(DisplayColourVolume);
    std::vector<uint8_t> displayVec(displaySize);
    if (mdcv) {
        displayColourVolume = mdcv->GetColourVolume();
        if (memcpy_s(displayVec.data(), displaySize, &displayColourVolume, displaySize) != EOK) {
            displayVec.resize(0);
        }
    }

    uint32_t lightInfoSize = sizeof(ContentLightLevelInfo);
    std::vector<uint8_t> lightInfoVec(lightInfoSize);
    if (clli) {
        lightInfo = clli->GetLightLevel();
        if (memcpy_s(lightInfoVec.data(), lightInfoSize, &lightInfo, lightInfoSize) != EOK) {
            lightInfoVec.resize(0);
        }
    }

    image->SetStaticMetadata(displayVec, lightInfoVec);
}

void HeifParser::ExtractGainmap(const std::vector<heif_item_id>& allItemIds)
{
    for (heif_item_id itemId: allItemIds) {
        // extract Image Item
        auto infe = GetInfeBox(itemId);
        if (!infe) {
            continue;
        }
        const std::string& itemType = infe->GetItemType();
        if (itemType == "it35") {
            ExtractIT35Metadata(itemId);
        }
        if (itemType == "tmap") {
            ExtractISOMetadata(itemId);
            ExtractGainmapImage(itemId);
        }
    }
}

void HeifParser::ExtractImageProperties(std::shared_ptr<HeifImage> &image)
{
    heif_item_id itemId = image->GetItemId();

    auto ispe = GetProperty<HeifIspeBox>(itemId);
    if (ispe) {
        uint32_t width = ispe->GetWidth();
        uint32_t height = ispe->GetHeight();
        image->SetOriginalSize(width, height);
    }

    auto irot = GetProperty<HeifIrotBox>(itemId);
    if (irot) {
        image->SetRotateDegrees(irot->GetRotDegree());
    }

    auto imir = GetProperty<HeifImirBox>(itemId);
    if (imir) {
        image->SetMirrorDirection(imir->GetDirection());
    }

    auto colr = GetProperty<HeifColrBox>(itemId);
    if (colr) {
        auto profile = colr->GetColorProfile();
        image->SetColorProfile(profile);
    }

    auto pixi = GetProperty<HeifPixiBox>(itemId);
    if (pixi && pixi->GetChannelNum() == 1) {
        image->SetDefaultColorFormat(HeifColorFormat::MONOCHROME);
        image->SetDefaultPixelFormat(HeifPixelFormat::MONOCHROME);
    } else {
        image->SetDefaultColorFormat(HeifColorFormat::YCBCR);
        image->SetDefaultPixelFormat(HeifPixelFormat::UNDEFINED);
    }

    auto hvcc = GetProperty<HeifHvccBox>(itemId);
    if (hvcc) {
        auto hvccConfig = hvcc->GetConfig();
        image->SetLumaBitNum(hvccConfig.bitDepthLuma);
        image->SetChromaBitNum(hvccConfig.bitDepthChroma);
        image->SetDefaultPixelFormat((HeifPixelFormat) hvccConfig.chromaFormat);
    }
    ExtractDisplayData(image, itemId);
}

void HeifParser::ExtractGridImageProperties()
{
    for (auto &pair: images_) {
        heif_item_id itemId = pair.first;
        auto infe = GetInfeBox(itemId);
        if (!infe || infe->GetItemType() != "grid") {
            continue;
        }
        auto &image = pair.second;
        auto tileItemIds = irefBox_->GetReferences(itemId, BOX_TYPE_DIMG);
        if (tileItemIds.empty()) {
            continue;
        }
        auto tileImage = GetImage(tileItemIds[0]);
        if (image->GetLumaBitNum() < 0) {
            image->SetLumaBitNum(tileImage->GetLumaBitNum());
        }
        if (image->GetChromaBitNum() < 0) {
            image->SetChromaBitNum(tileImage->GetChromaBitNum());
        }
        if (image->GetDefaultPixelFormat() == HeifPixelFormat::UNDEFINED) {
            image->SetDefaultPixelFormat(tileImage->GetDefaultPixelFormat());
        }
        if (image->GetDefaultColorFormat() == HeifColorFormat::UNDEDEFINED) {
            image->SetDefaultColorFormat(tileImage->GetDefaultColorFormat());
        }
    }
}

void HeifParser::ExtractThumbnailImage(std::shared_ptr<HeifImage> &thumbnailImage, const HeifIrefBox::Reference &ref)
{
    std::vector<heif_item_id> toItemIds = ref.toItemIds;
    if (toItemIds.empty()) {
        return;
    }
    heif_item_id masterItemId = toItemIds[0];
    if (masterItemId == thumbnailImage->GetItemId()) {
        return;
    }
    auto masterImage = GetImage(masterItemId);
    if (!masterImage) {
        return;
    }

    thumbnailImage->SetThumbnailImage(masterItemId);
    masterImage->AddThumbnailImage(thumbnailImage);
}

void HeifParser::ExtractAuxImage(std::shared_ptr<HeifImage> &auxImage, const HeifIrefBox::Reference &ref)
{
    std::vector<heif_item_id> toItemIds = ref.toItemIds;
    if (toItemIds.empty()) {
        return;
    }
    heif_item_id masterItemId = toItemIds[0];
    heif_item_id auxItemId = auxImage->GetItemId();
    if (masterItemId == auxItemId) {
        return;
    }
    auto masterImage = GetImage(masterItemId);
    if (!masterImage) {
        return;
    }
    std::shared_ptr<HeifAuxcBox> auxc = GetProperty<HeifAuxcBox>(auxItemId);
    if (!auxc) {
        return;
    }

    auxImage->SetAuxImage(masterItemId, auxc->GetAuxType());
    masterImage->AddAuxImage(auxImage);
}

void HeifParser::ExtractGainmapImage(const heif_item_id& tmapId)
{
    std::vector<HeifIrefBox::Reference> references = irefBox_->GetReferencesFrom(tmapId);
    for (const HeifIrefBox::Reference &ref : references) {
        uint32_t type = ref.box.GetBoxType();
        if (type != BOX_TYPE_DIMG) {
            continue;
        }
        heif_item_id fromItemId = ref.fromItemId;
        auto fromItemInfeBox = GetInfeBox(fromItemId);
        if (fromItemInfeBox->GetItemType() != "tmap") {
            return;
        }
        std::vector<heif_item_id> toItemIds = ref.toItemIds;
        const size_t tmapToItemSize = 2;
        if (toItemIds.size() != tmapToItemSize) {
            return;
        }
        const uint8_t baseIndex = 0;
        const uint8_t gainmapIndex = 1;
        heif_item_id baseId = toItemIds[baseIndex];
        if (baseId != primaryImage_->GetItemId()) {
            return;
        }
        heif_item_id gainmapId = toItemIds[gainmapIndex];
        auto gainmapImage = GetImage(gainmapId);
        if (gainmapImage == nullptr) {
            return;
        }
        gainmapImage->SetGainmapMasterImage(baseId);
        gainmapImage->SetTmapBoxId(tmapId);
        primaryImage_->AddGainmapImage(gainmapImage);
        primaryImage_->SetTmapBoxId(tmapId);
    }
}

void HeifParser::ExtractNonMasterImages()
{
    if (!irefBox_) {
        return;
    }
    for (auto &pair: images_) {
        auto &image = pair.second;
        std::vector<HeifIrefBox::Reference> references = irefBox_->GetReferencesFrom(image->GetItemId());
        for (const HeifIrefBox::Reference &ref: references) {
            uint32_t type = ref.box.GetBoxType();
            if (type == BOX_TYPE_THMB) {
                ExtractThumbnailImage(image, ref);
            } else if (type == BOX_TYPE_AUXL) {
                ExtractAuxImage(image, ref);
            }
        }
    }
}

void HeifParser::ExtractMetadata(const std::vector<heif_item_id> &allItemIds)
{
    if (!irefBox_) {
        return;
    }

    for (heif_item_id metadataItemId: allItemIds) {
        std::vector<heif_item_id> toItemIds = irefBox_->GetReferences(metadataItemId, BOX_TYPE_CDSC);
        if (toItemIds.empty()) {
            continue;
        }
        heif_item_id masterImageId = toItemIds[0];
        if (masterImageId == metadataItemId) {
            continue;
        }
        auto masterImage = GetImage(masterImageId);
        if (!masterImage) {
            continue;
        }

        std::shared_ptr<HeifMetadata> metadata = std::make_shared<HeifMetadata>();
        metadata->itemId = metadataItemId;
        metadata->itemType = GetItemType(metadataItemId);
        metadata->contentType = GetItemContentType(metadataItemId);
        metadata->itemUriType = GetItemUriType(metadataItemId);
        heif_error err = GetItemData(metadataItemId, &(metadata->mData));
        if (err != heif_error_ok) {
            metadata.reset();
            continue;
        }
        masterImage->AddMetadata(metadata);
    }
}

std::shared_ptr<HeifImage> HeifParser::GetImage(heif_item_id itemId)
{
    auto iter = images_.find(itemId);
    if (iter == images_.end()) {
        return nullptr;
    }
    return iter->second;
}

std::shared_ptr<HeifImage> HeifParser::GetPrimaryImage()
{
    return primaryImage_;
}

std::shared_ptr<HeifImage> HeifParser::GetGainmapImage()
{
    return primaryImage_->GetGainmapImage();
}

std::shared_ptr<HeifImage> HeifParser::GetTmapImage()
{
    return tmapImage_;
}

heif_item_id HeifParser::GetNextItemId() const
{
    heif_item_id max_id = 0;
    for (const auto& infe: infeBoxes_) {
        max_id = std::max(max_id, infe.second->GetItemId());
    }
    return max_id + 1;
}

std::shared_ptr<HeifInfeBox> HeifParser::AddItem(const char *itemType, bool hidden)
{
    heif_item_id newItemId = GetNextItemId();
    auto newInfe = std::make_shared<HeifInfeBox>(newItemId, itemType, false);
    newInfe->SetHidden(hidden);
    infeBoxes_[newItemId] = newInfe;
    iinfBox_->AddChild(newInfe);
    return newInfe;
}

void HeifParser::AddIspeProperty(heif_item_id itemId, uint32_t width, uint32_t height)
{
    auto ispe = std::make_shared<HeifIspeBox>();
    ispe->SetDimension(width, height);
    AddProperty(itemId, ispe, false);
}

heif_property_id HeifParser::AddProperty(heif_item_id itemId, const std::shared_ptr<HeifBox>& property, bool essential)
{
    int index = ipcoBox_->AddChild(property);
    ipmaBox_->AddProperty(itemId, PropertyAssociation{essential, uint16_t(index + 1)});
    return index + 1;
}

void HeifParser::AddPixiProperty(heif_item_id itemId, uint8_t c1, uint8_t c2, uint8_t c3)
{
    auto pixi = std::make_shared<HeifPixiBox>();
    pixi->AddBitNum(c1);
    pixi->AddBitNum(c2);
    pixi->AddBitNum(c3);
    AddProperty(itemId, pixi, false);
}


void HeifParser::AddHvccProperty(heif_item_id itemId)
{
    auto hvcC = std::make_shared<HeifHvccBox>();
    AddProperty(itemId, hvcC, true);
}

heif_error HeifParser::AppendHvccNalData(heif_item_id itemId, const std::vector<uint8_t> &data)
{
    auto hvcc = GetProperty<HeifHvccBox>(itemId);
    if (!hvcc) {
        return heif_error_no_hvcc;
    }
    hvcc->AppendNalData(data);
    return heif_error_ok;
}

heif_error HeifParser::SetHvccConfig(heif_item_id itemId, const HvccConfig &config)
{
    auto hvcc = GetProperty<HeifHvccBox>(itemId);
    if (!hvcc) {
        return heif_error_no_hvcc;
    }
    hvcc->SetConfig(config);
    return heif_error_ok;
}

void HeifParser::AppendIlocData(heif_item_id itemId, const std::vector<uint8_t> &data, uint8_t construction_method)
{
    if (!ilocBox_) {
        return;
    }
    ilocBox_->AppendData(itemId, data, construction_method);
}

void HeifParser::SetPrimaryItemId(heif_item_id itemId)
{
    if (!pitmBox_) {
        return;
    }
    pitmBox_->SetItemId(itemId);
}

void HeifParser::AddReference(heif_item_id fromItemId, uint32_t type, const std::vector<heif_item_id> &toItemIds)
{
    if (!irefBox_) {
        irefBox_ = std::make_shared<HeifIrefBox>();
        metaBox_->AddChild(irefBox_);
    }
    irefBox_->AddReferences(fromItemId, type, toItemIds);
}

void HeifParser::SetAuxcProperty(heif_item_id itemId, const std::string &type)
{
    auto auxC = std::make_shared<HeifAuxcBox>();
    auxC->SetAuxType(type);
    AddProperty(itemId, auxC, true);
}

void HeifParser::SetColorProfile(heif_item_id itemId, const std::shared_ptr<const HeifColorProfile> &profile)
{
    auto colr = std::make_shared<HeifColrBox>();
    colr->SetColorProfile(profile);
    AddProperty(itemId, colr, false);
}

void HeifParser::CheckExtentData()
{
    const std::vector<HeifIlocBox::Item>& items = ilocBox_->GetItems();
    for (const HeifIlocBox::Item& item: items) {
        ilocBox_->ReadToExtentData(const_cast<HeifIlocBox::Item &>(item), inputStream_, idatBox_);
    }
}

void HeifParser::SetPrimaryImage(const std::shared_ptr<HeifImage> &image)
{
    if (primaryImage_) {
        if (primaryImage_->GetItemId() == image->GetItemId()) {
            return;
        }
        primaryImage_->SetPrimaryImage(false);
    }
    primaryImage_ = image;
    image->SetPrimaryImage(true);
    SetPrimaryItemId(image->GetItemId());
}

uint32_t HeifParser::GetExifHeaderOffset(const uint8_t *data, uint32_t size)
{
    uint32_t offset = 0;
    const int endianSize = 4;
    while (offset + endianSize < (unsigned int) size) {
        if (!memcmp(data + offset, "MM\0*", endianSize) || !memcmp(data + offset, "II*\0", endianSize)) {
            return offset;
        }
        offset++;
    }
    return offset;
}

heif_error HeifParser::SetExifMetadata(const std::shared_ptr<HeifImage> &image, const uint8_t *data, uint32_t size)
{
    uint32_t offset = GetExifHeaderOffset(data, size);
    if (offset >= size) {
        return heif_invalid_exif_data;
    }

    std::vector<uint8_t> content;
    content.resize(size + UINT32_BYTES_NUM);
    std::string offsetFourcc = code_to_fourcc(offset);
    for (int index = 0; index < UINT32_BYTES_NUM; ++index) {
        content[index] = (uint8_t)offsetFourcc[index];
    }
    memcpy_s(content.data() + UINT32_BYTES_NUM, size, data, size);
    return SetMetadata(image, content, "Exif", nullptr);
}

heif_error HeifParser::UpdateExifMetadata(const std::shared_ptr<HeifImage> &master_image, const uint8_t *data,
                                          uint32_t size, heif_item_id itemId)
{
    uint32_t offset = GetExifHeaderOffset(data, size);
    if (offset >= (unsigned int) size) {
        return heif_invalid_exif_data;
    }

    std::vector<uint8_t> content;
    content.resize(size + UINT32_BYTES_NUM);
    std::string offsetFourcc = code_to_fourcc(offset);
    for (int index = 0; index < UINT32_BYTES_NUM; ++index) {
        content[index] = (uint8_t)offsetFourcc[index];
    }

    if (memcpy_s(content.data() + UINT32_BYTES_NUM, size, data, size) != 0) {
        return heif_invalid_exif_data;
    }

    uint8_t construction_method = GetConstructMethod(itemId);

    return ilocBox_->UpdateData(itemId, content, construction_method);
}

heif_error HeifParser::SetMetadata(const std::shared_ptr<HeifImage> &image, const std::vector<uint8_t> &data,
                                   const char *item_type, const char *content_type)
{
    auto metadataInfe = AddItem(item_type, true);
    if (content_type != nullptr) {
        metadataInfe->SetContentType(content_type);
    }

    heif_item_id metadataItemId = metadataInfe->GetItemId();
    heif_item_id imageItemId = image->GetItemId();
    AddReference(metadataItemId, BOX_TYPE_CDSC, {imageItemId});

    // store metadata in mdat
    AppendIlocData(metadataItemId, data, 0);
    return heif_error_ok;
}

uint8_t HeifParser::GetConstructMethod(const heif_item_id &id)
{
    auto items = ilocBox_->GetItems();
    for (const auto &item: items) {
        if (item.itemId == id) {
            return item.constructionMethod;
        }
    }

    // CONSTRUCTION_METHOD_FILE_OFFSET 0
    return 0;
}
} // namespace ImagePlugin
} // namespace OHOS
