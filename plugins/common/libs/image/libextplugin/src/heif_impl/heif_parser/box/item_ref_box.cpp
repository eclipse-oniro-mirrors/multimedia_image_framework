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

#include "box/item_ref_box.h"

namespace OHOS {
namespace ImagePlugin {
void HeifIrefBox::ParseItemRef(HeifStreamReader &reader, Reference& ref)
{
    if (GetVersion() == HEIF_BOX_VERSION_ZERO) {
        ref.fromItemId = reader.Read16();
        int nRefs = reader.Read16();
        for (int i = 0; i < nRefs; i++) {
            ref.toItemIds.push_back(reader.Read16());
            if (reader.IsAtEnd()) {
                break;
            }
        }
    } else {
        ref.fromItemId = reader.Read32();
        int nRefs = reader.Read16();
        for (int i = 0; i < nRefs; i++) {
            ref.toItemIds.push_back(reader.Read32());
            if (reader.IsAtEnd()) {
                break;
            }
        }
    }
}

heif_error HeifIrefBox::ParseContent(HeifStreamReader &reader)
{
    ParseFullHeader(reader);
    while (!reader.IsAtEnd()) {
        Reference ref;
        heif_error err = ref.box.ParseHeader(reader);
        if (err != heif_error_ok) {
            return err;
        }
        ParseItemRef(reader, ref);
        references_.push_back(ref);
    }

    return reader.GetError();
}

void HeifIrefBox::InferFullBoxVersion()
{
    uint8_t version = 0;
    for (auto &ref: references_) {
        if ((ref.fromItemId >> TWO_BYTES_SHIFT) > 0) {
            version = HEIF_BOX_VERSION_ONE;
            SetVersion(version);
            return;
        }

        for (auto id: ref.toItemIds) {
            if ((id >> TWO_BYTES_SHIFT) > 0) {
                version = HEIF_BOX_VERSION_ONE;
                SetVersion(version);
                return;
            }
        }
    }
    SetVersion(version);
}


heif_error HeifIrefBox::Write(HeifStreamWriter &writer) const
{
    size_t boxStart = ReserveHeader(writer);

    int idSize = ((GetVersion() == HEIF_BOX_VERSION_ZERO) ? UINT16_BYTES_NUM : UINT32_BYTES_NUM);

    for (const auto &ref: references_) {
        auto box_size = uint32_t(UINT32_BYTES_NUM + UINT32_BYTES_NUM + UINT16_BYTES_NUM +
                                 static_cast<size_t>(idSize) * (UINT8_BYTES_NUM + ref.toItemIds.size()));

        writer.Write32(box_size);
        writer.Write32(ref.box.GetBoxType());

        writer.Write(idSize, ref.fromItemId);
        writer.Write16((uint16_t) ref.toItemIds.size());

        for (uint32_t r: ref.toItemIds) {
            writer.Write(idSize, r);
        }
    }
    WriteCalculatedHeader(writer, boxStart);

    return heif_error_ok;
}

bool HeifIrefBox::HasReferences(heif_item_id itemId) const
{
    for (const Reference &ref: references_) {
        if (ref.fromItemId == itemId) {
            return true;
        }
    }
    return false;
}


std::vector<HeifIrefBox::Reference> HeifIrefBox::GetReferencesFrom(heif_item_id itemId) const
{
    std::vector<Reference> references;
    for (const Reference &ref: references_) {
        if (ref.fromItemId == itemId) {
            references.push_back(ref);
        }
    }
    return references;
}


std::vector<uint32_t> HeifIrefBox::GetReferences(heif_item_id itemId, uint32_t ref_type) const
{
    for (const Reference &ref: references_) {
        if (ref.fromItemId == itemId &&
            ref.box.GetBoxType() == ref_type) {
            return ref.toItemIds;
        }
    }
    return {};
}


void HeifIrefBox::AddReferences(heif_item_id from_id, uint32_t type, const std::vector<heif_item_id> &to_ids)
{
    Reference ref;
    ref.box.SetBoxType(type);
    ref.fromItemId = from_id;
    ref.toItemIds = to_ids;
    references_.push_back(ref);
}
} // namespace ImagePlugin
} // namespace OHOS