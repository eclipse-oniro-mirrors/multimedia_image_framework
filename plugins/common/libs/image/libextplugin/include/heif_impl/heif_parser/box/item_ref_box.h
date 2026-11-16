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

#ifndef PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_ITEM_REF_BOX_H
#define PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_ITEM_REF_BOX_H

#include "heif_box.h"

namespace OHOS {
namespace ImagePlugin {
class HeifIrefBox : public HeifFullBox {
public:
    HeifIrefBox() : HeifFullBox(BOX_TYPE_IREF) {}

    struct Reference {
        HeifBox box;
        heif_item_id fromItemId;
        std::vector<heif_item_id> toItemIds;
    };

    bool HasReferences(heif_item_id itemId) const;

    std::vector<heif_item_id> GetReferences(heif_item_id itemId, uint32_t ref_type) const;

    // Returns the matching references without copying them. The pointers stay valid as long as the
    // parsed box is alive, which is the case for every parser side query.
    std::vector<const Reference *> GetReferencesFrom(heif_item_id itemId) const;

    void AddReferences(heif_item_id from_id, uint32_t type, const std::vector<heif_item_id> &to_ids);

protected:
    heif_error ParseContent(HeifStreamReader &reader) override;

    heif_error Write(HeifStreamWriter &writer) const override;

    void InferFullBoxVersion() override;

private:
    void ParseItemRef(HeifStreamReader &reader, Reference& ref);

    std::vector<Reference> references_;
};

// Entity group list (ISO/IEC 14496-12 'grpl'), holding EntityToGroupBox children such as 'altr'
// and 'ster'. HEIF uses it to describe alternative representations (for example SDR/HDR versions
// of the same image), so it has to survive a rewrite.
class HeifGrplBox : public HeifBox {
public:
    // Upper bound of structurally parsed entity groups. Bytes beyond the bound are kept verbatim,
    // so a crafted grpl with a huge number of groups cannot grow the parsed object list without bound.
    static constexpr uint32_t MAX_GROUP_COUNT = 1024;

    struct EntityGroup {
        uint32_t groupType = 0;
        uint8_t version = 0;
        uint32_t flags = 0;
        uint32_t groupId = 0;
        std::vector<uint32_t> entityIds;
        std::vector<uint8_t> extra;
    };

    HeifGrplBox() : HeifBox(BOX_TYPE_GRPL) {}

    const std::vector<EntityGroup> &GetGroups() const { return groups_; }

    // Convenience accessors for one grouping type, for example BOX_TYPE_ALTR.
    bool HasGroup(uint32_t groupType) const;

    std::vector<uint32_t> GetEntityIds(uint32_t groupType) const;

    heif_error Write(HeifStreamWriter &writer) const override;

protected:
    heif_error ParseContent(HeifStreamReader &reader) override;

private:
    heif_error ParseEntityGroup(HeifStreamReader &reader, EntityGroup &group);

    void ReadTrailingBytes(HeifStreamReader &reader, size_t size);

    std::vector<EntityGroup> groups_;
    std::vector<uint8_t> trailingBytes_;
};
} // namespace ImagePlugin
} // namespace OHOS

#endif // PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_ITEM_REF_BOX_H
