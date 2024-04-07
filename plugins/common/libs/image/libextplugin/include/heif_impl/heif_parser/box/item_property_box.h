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

#ifndef PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_ITEM_PROPERTY_BOX_H
#define PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_ITEM_PROPERTY_BOX_H

#include "box/heif_box.h"

namespace OHOS {
namespace ImagePlugin {
struct PropertyAssociation {
    bool essential;
    uint16_t propertyIndex;
};

struct PropertyEntry {
    heif_item_id itemId;
    std::vector<PropertyAssociation> associations;
};

class HeifIprpBox : public HeifBox {
public:
    HeifIprpBox() : HeifBox(BOX_TYPE_IPRP) {}

protected:
    heif_error ParseContent(HeifStreamReader &reader) override;
};

class HeifIpcoBox : public HeifBox {
public:
    HeifIpcoBox() : HeifBox(BOX_TYPE_IPCO) {}

    heif_error GetProperties(heif_item_id itemId,
                        const std::shared_ptr<class HeifIpmaBox> &,
                        std::vector<std::shared_ptr<HeifBox>> &outProperties) const;

    std::shared_ptr<HeifBox> GetProperty(heif_item_id itemId,
                                         const std::shared_ptr<class HeifIpmaBox> &,
                                         uint32_t boxType) const;

protected:
    heif_error ParseContent(HeifStreamReader &reader) override;
};

class HeifIpmaBox : public HeifFullBox {
public:
    HeifIpmaBox() : HeifFullBox(BOX_TYPE_IPMA) {}

    const std::vector<PropertyAssociation> *GetProperties(heif_item_id itemId) const;

    void AddProperty(heif_item_id itemId,
                     PropertyAssociation assoc);

    void InferFullBoxVersion() override;

    heif_error Write(HeifStreamWriter &writer) const override;

    void MergeImpaBoxes(const HeifIpmaBox &b);

protected:
    heif_error ParseContent(HeifStreamReader &reader) override;

    std::vector<PropertyEntry> entries_;
};
} // namespace ImagePlugin
} // namespace OHOS

#endif // PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_ITEM_PROPERTY_BOX_H
