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

#ifndef PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_HEIF_PARSER_H
#define PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_HEIF_PARSER_H

#include "box/heif_box.h"
#include "box/basic_box.h"
#include "box/item_data_box.h"
#include "box/item_info_box.h"
#include "box/item_property_box.h"
#include "box/item_property_color_box.h"
#include "box/item_property_hvcc_box.h"
#include "box/item_ref_box.h"
#include "heif_image.h"

#include <map>

namespace OHOS {
namespace ImagePlugin {
enum heif_header_option {
    heif_header_data,
    heif_no_header,
    heif_only_header
};

class HeifParser {
public:
    HeifParser();

    explicit HeifParser(const std::shared_ptr<HeifInputStream> &inputStream) : inputStream_(inputStream) {};

    ~HeifParser();

    static heif_error MakeFromStream(const std::shared_ptr<HeifInputStream> &stream, std::shared_ptr<HeifParser> *out);

    static heif_error MakeFromMemory(const void *data, size_t size, bool isNeedCopy, std::shared_ptr<HeifParser> *out);

    void Write(HeifStreamWriter &writer);

    std::shared_ptr<HeifImage> GetImage(heif_item_id itemId);

    std::shared_ptr<HeifImage> GetPrimaryImage();

    std::shared_ptr<HeifImage> GetGainmapImage();

    std::shared_ptr<HeifImage> GetTmapImage();

    std::string GetItemType(heif_item_id itemId) const;

    heif_error GetItemData(heif_item_id itemId, std::vector<uint8_t> *out,
                           heif_header_option option = heif_no_header) const;

    void GetTileImages(heif_item_id gridItemId, std::vector<std::shared_ptr<HeifImage>> &out);

    void GetAllItemId(std::vector<heif_item_id> &itemIdList) const;

    heif_error SetExifMetadata(const std::shared_ptr<HeifImage> &master_image, const uint8_t *data, uint32_t size);

    heif_error UpdateExifMetadata(const std::shared_ptr<HeifImage> &master_image, const uint8_t *data,
                                  uint32_t size, heif_item_id itemId);

private:
    // stream
    std::shared_ptr<HeifInputStream> inputStream_;

    // boxes
    std::shared_ptr<HeifFtypBox> ftypBox_;
    std::shared_ptr<HeifMetaBox> metaBox_;
    std::shared_ptr<HeifHdlrBox> hdlrBox_;
    std::shared_ptr<HeifPtimBox> pitmBox_;
    std::shared_ptr<HeifIinfBox> iinfBox_;
    std::map<heif_item_id, std::shared_ptr<HeifInfeBox> > infeBoxes_;
    std::shared_ptr<HeifIrefBox> irefBox_;
    std::shared_ptr<HeifIprpBox> iprpBox_;
    std::shared_ptr<HeifIpcoBox> ipcoBox_;
    std::shared_ptr<HeifIpmaBox> ipmaBox_;
    std::shared_ptr<HeifIdatBox> idatBox_;
    std::shared_ptr<HeifIlocBox> ilocBox_;
    std::vector<std::shared_ptr<HeifBox> > topBoxes_;

    // images
    std::map<heif_item_id, std::shared_ptr<HeifImage>> images_;
    std::shared_ptr<HeifImage> primaryImage_; // shortcut to primary image
    std::shared_ptr<HeifImage> tmapImage_;

    // reading functions for boxes
    heif_error AssembleBoxes(HeifStreamReader &reader);

    heif_item_id GetPrimaryItemId() const;

    bool HasItemId(heif_item_id itemId) const;

    std::string GetItemContentType(heif_item_id itemId) const;

    std::string GetItemUriType(heif_item_id itemId) const;

    std::shared_ptr<HeifInfeBox> GetInfeBox(heif_item_id itemId) const;

    heif_error GetAllProperties(heif_item_id itemId, std::vector<std::shared_ptr<HeifBox>> &properties) const;

    template<class BoxType>
    std::shared_ptr<BoxType> GetProperty(heif_item_id itemId) const
    {
        std::vector<std::shared_ptr<HeifBox>> properties;
        heif_error err = GetAllProperties(itemId, properties);
        if (err) {
            return nullptr;
        }

        for (auto &property: properties) {
            if (auto box = std::dynamic_pointer_cast<BoxType>(property)) {
                return box;
            }
        }
        return nullptr;
    }

    // reading functions for images
    heif_error AssembleImages();

    void ExtractImageProperties(std::shared_ptr<HeifImage> &image);

    void ExtractGridImageProperties();

    void ExtractThumbnailImage(std::shared_ptr<HeifImage> &thumbnailImage, const HeifIrefBox::Reference &ref);

    void ExtractAuxImage(std::shared_ptr<HeifImage> &auxImage, const HeifIrefBox::Reference &ref);

    void ExtractNonMasterImages();

    void ExtractMetadata(const std::vector<heif_item_id> &allItemIds);

    // writing fuctions for boxes
    heif_item_id GetNextItemId() const;

    std::shared_ptr<HeifInfeBox> AddItem(const char *itemType, bool hidden = false);

    void AddHvccProperty(heif_item_id itemId);

    heif_error AppendHvccNalData(heif_item_id itemId, const std::vector<uint8_t> &data);

    heif_error SetHvccConfig(heif_item_id itemId, const HvccConfig &config);

    void AddIspeProperty(heif_item_id itemId, uint32_t width, uint32_t height);

    void AddPixiProperty(heif_item_id itemId, uint8_t c1, uint8_t c2 = 0, uint8_t c3 = 0);

    heif_property_id AddProperty(heif_item_id itemId, const std::shared_ptr<HeifBox>& property, bool essential);

    void AppendIlocData(heif_item_id itemId, const std::vector<uint8_t> &data, uint8_t constructionMethod = 0);

    void SetPrimaryItemId(heif_item_id itemId);

    void AddReference(heif_item_id fromItemId, uint32_t type, const std::vector<heif_item_id> &toItemIds);

    void SetAuxcProperty(heif_item_id itemId, const std::string &type);

    void SetColorProfile(heif_item_id itemId, const std::shared_ptr<const HeifColorProfile> &profile);

    void CheckExtentData();

    // writing functions for images
    void SetPrimaryImage(const std::shared_ptr<HeifImage> &image);

    uint32_t GetExifHeaderOffset(const uint8_t *data, uint32_t size);

    heif_error SetMetadata(const std::shared_ptr<HeifImage> &image, const std::vector<uint8_t> &data,
                      const char *item_type, const char *content_type);

    uint8_t GetConstructMethod(const heif_item_id& id);

    void ExtractGainmap(const std::vector<heif_item_id>& allItemIds);

    void ExtractDisplayData(std::shared_ptr<HeifImage>& image, heif_item_id& itemId);

    void ExtractIT35Metadata(const heif_item_id& metadataItemId);

    void ExtractISOMetadata(const heif_item_id& itemId);

    void ExtractGainmapImage(const heif_item_id& tmapId);
};
} // namespace ImagePlugin
} // namespace OHOS

#endif // PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_HEIF_PARSER_H
