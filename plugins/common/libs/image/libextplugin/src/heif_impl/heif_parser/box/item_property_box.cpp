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

#include "box/item_property_box.h"

namespace {
    const uint8_t LARGE_PROPERTY_INDEX_FLAG = 1;
}

namespace OHOS {
namespace ImagePlugin {
heif_error HeifIprpBox::ParseContent(HeifStreamReader &reader)
{
    return ReadChildren(reader);
}

heif_error HeifIpcoBox::ParseContent(HeifStreamReader &reader)
{
    return ReadChildren(reader);
}

heif_error HeifIpcoBox::GetProperties(uint32_t itemId, const std::shared_ptr<class HeifIpmaBox> &ipma,
                                      std::vector<std::shared_ptr<HeifBox>> &outProperties) const
{
    const std::vector<PropertyAssociation> *propertyAssocs = ipma->GetProperties(itemId);
    if (propertyAssocs == nullptr) {
        return heif_error_property_not_found;
    }

    const auto &allProperties = GetChildren();
    for (const PropertyAssociation &assoc: *propertyAssocs) {
        if (assoc.propertyIndex > allProperties.size()) {
            return heif_error_invalid_property_index;
        }

        if (assoc.propertyIndex > 0) {
            outProperties.push_back(allProperties[assoc.propertyIndex - 1]);
        }
    }

    return heif_error_ok;
}

std::shared_ptr<HeifBox> HeifIpcoBox::GetProperty(heif_item_id itemId,
    const std::shared_ptr<class HeifIpmaBox> &ipma, uint32_t boxType) const
{
    const std::vector<PropertyAssociation> *propertyAssocs = ipma->GetProperties(itemId);
    if (propertyAssocs == nullptr) {
        return nullptr;
    }

    const auto &allProperties = GetChildren();
    for (const PropertyAssociation &assoc: *propertyAssocs) {
        if (assoc.propertyIndex > allProperties.size() ||
            assoc.propertyIndex == 0) {
            return nullptr;
        }

        const auto &property = allProperties[assoc.propertyIndex - 1];
        if (property->GetBoxType() == boxType) {
            return property;
        }
    }

    return nullptr;
}

heif_error HeifIpmaBox::ParseContent(HeifStreamReader &reader)
{
    ParseFullHeader(reader);

    uint32_t entryNum = reader.Read32();
    for (uint32_t i = 0; i < entryNum && !reader.HasError() && !reader.IsAtEnd(); i++) {
        PropertyEntry entry;
        if (GetVersion() < HEIF_BOX_VERSION_ONE) {
            entry.itemId = reader.Read16();
        } else {
            entry.itemId = reader.Read32();
        }

        int assocNum = reader.Read8();
        for (int k = 0; k < assocNum; k++) {
            PropertyAssociation association;
            uint16_t index;
            if (GetFlags() & LARGE_PROPERTY_INDEX_FLAG) {
                index = reader.Read16();
                association.essential = !!(index & 0x8000);
                association.propertyIndex = (index & 0x7fff);
            } else {
                index = reader.Read8();
                association.essential = !!(index & 0x80);
                association.propertyIndex = (index & 0x7f);
            }
            entry.associations.push_back(association);
        }
        entries_.push_back(entry);
    }
    return reader.GetError();
}

const std::vector<PropertyAssociation> *HeifIpmaBox::GetProperties(uint32_t itemId) const
{
    for (const auto &entry: entries_) {
        if (entry.itemId == itemId) {
            return &entry.associations;
        }
    }
    return nullptr;
}

void HeifIpmaBox::AddProperty(heif_item_id itemId, PropertyAssociation assoc)
{
    size_t idx;
    for (idx = 0; idx < entries_.size(); idx++) {
        if (entries_[idx].itemId == itemId) {
            break;
        }
    }

    if (idx == entries_.size()) {
        PropertyEntry entry;
        entry.itemId = itemId;
        entries_.push_back(entry);
    }

    entries_[idx].associations.push_back(assoc);
}

void HeifIpmaBox::InferFullBoxVersion()
{
    int version = HEIF_BOX_VERSION_ZERO;
    bool largeIndices = false;

    for (const PropertyEntry &entry: entries_) {
        if (entry.itemId > 0xFFFF) {
            version = HEIF_BOX_VERSION_ONE;
        }

        for (const auto &assoc: entry.associations) {
            if (assoc.propertyIndex > 0x7F) {
                largeIndices = true;
            }
        }
    }

    SetVersion((uint8_t) version);
    SetFlags(largeIndices ? LARGE_PROPERTY_INDEX_FLAG : 0);
}

heif_error HeifIpmaBox::Write(HeifStreamWriter &writer) const
{
    size_t boxStart = ReserveHeader(writer);

    size_t entryNum = entries_.size();
    writer.Write32((uint32_t) entryNum);

    for (const PropertyEntry &entry: entries_) {
        if (GetVersion() < HEIF_BOX_VERSION_ONE) {
            writer.Write16((uint16_t) entry.itemId);
        } else {
            writer.Write32(entry.itemId);
        }
        size_t assocNum = entry.associations.size();
        writer.Write8((uint8_t) assocNum);
        for (const PropertyAssociation &association: entry.associations) {
            if (GetFlags() & LARGE_PROPERTY_INDEX_FLAG) {
                writer.Write16((uint16_t) ((association.essential ? 0x8000 : 0) |
                                           (association.propertyIndex & 0x7FFF)));
            } else {
                writer.Write8((uint8_t) ((association.essential ? 0x80 : 0) |
                                         (association.propertyIndex & 0x7F)));
            }
        }
    }

    WriteCalculatedHeader(writer, boxStart);
    return heif_error_ok;
}

void HeifIpmaBox::MergeImpaBoxes(const HeifIpmaBox &b)
{
    entries_.insert(entries_.end(), b.entries_.begin(), b.entries_.end());
}
} // namespace ImagePlugin
} // namespace OHOS
