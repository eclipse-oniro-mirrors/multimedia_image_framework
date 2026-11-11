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

#include <algorithm>

const uint16_t MAX_REFS_PER_ITEM = 1024;
const uint32_t MAX_GRPL_ENTITY_COUNT = 4096;

namespace OHOS {
namespace ImagePlugin {
void HeifIrefBox::ParseItemRef(HeifStreamReader &reader, Reference& ref)
{
    if (GetVersion() == HEIF_BOX_VERSION_ZERO) {
        ref.fromItemId = reader.Read16();
        int nRefs = reader.Read16();
        if (nRefs > MAX_REFS_PER_ITEM) {
            reader.SetError(true);
            return;
        }
        for (int i = 0; i < nRefs; i++) {
            ref.toItemIds.push_back(reader.Read16());
            if (reader.IsAtEnd()) {
                break;
            }
        }
    } else {
        ref.fromItemId = reader.Read32();
        int nRefs = reader.Read16();
        if (nRefs > MAX_REFS_PER_ITEM) {
            reader.SetError(true);
            return;
        }
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
        if (ref.box.GetBoxSize() < ref.box.GetHeaderSize()) {
            return heif_error_invalid_box_size;
        }
        uint64_t contentSize = ref.box.GetBoxSize() - ref.box.GetHeaderSize();
        if (!reader.CheckSize(contentSize)) {
            return heif_error_eof;
        }
        HeifStreamReader contentReader(reader.GetStream(), reader.GetStream()->Tell(), contentSize);
        ParseItemRef(contentReader, ref);
        contentReader.SkipEnd();
        if (contentReader.HasError()) {
            return contentReader.GetError();
        }
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
        uint32_t tmpValue;
        if (__builtin_mul_overflow(idSize, (UINT8_BYTES_NUM + ref.toItemIds.size()), &tmpValue)) {
            return heif_error_add_overflow;
        }
        auto box_size = uint32_t(UINT32_BYTES_NUM + UINT32_BYTES_NUM + UINT16_BYTES_NUM + tmpValue);

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
    return std::any_of(references_.begin(), references_.end(), [&itemId](const auto& ref) {
        return ref.fromItemId == itemId;
    });
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
    std::vector<uint32_t> res{};
    auto iter = std::find_if(references_.begin(), references_.end(), [&itemId, &ref_type](const auto& ref) {
        return ref.fromItemId == itemId && ref.box.GetBoxType() == ref_type;
    });
    return iter == references_.end() ? res : iter->toItemIds;
}


void HeifIrefBox::AddReferences(heif_item_id from_id, uint32_t type, const std::vector<heif_item_id> &to_ids)
{
    Reference ref;
    ref.box.SetBoxType(type);
    ref.fromItemId = from_id;
    ref.toItemIds = to_ids;
    references_.push_back(ref);
}

heif_error HeifGrplBox::ParseContent(HeifStreamReader &reader)
{
    while (!reader.IsAtEnd() && !reader.HasError()) {
        int64_t groupStart = reader.GetStream()->Tell();
        size_t remainSize = reader.GetRemainSize();
        if (remainSize < UINT64_BYTES_NUM) {
            ReadTrailingBytes(reader, remainSize);
            break;
        }

        HeifBox headerBox;
        heif_error err = headerBox.ParseHeader(reader);
        uint64_t groupSize = headerBox.GetBoxSize();
        uint64_t headerSize = headerBox.GetHeaderSize();
        if (err != heif_error_ok || groupSize < headerSize ||
            groupSize - headerSize > reader.GetRemainSize()) {
            // Keep whatever cannot be parsed as an entity group verbatim instead of rejecting the file,
            // so unknown or vendor specific group payloads still survive a rewrite.
            reader.GetStream()->Seek(groupStart);
            reader.SetError(false);
            ReadTrailingBytes(reader, remainSize);
            break;
        }

        EntityGroup group;
        group.groupType = headerBox.GetBoxType();
        HeifStreamReader contentReader(reader.GetStream(), reader.GetStream()->Tell(),
            static_cast<size_t>(groupSize - headerSize));
        err = ParseEntityGroup(contentReader, group);
        contentReader.SkipEnd();
        if (err != heif_error_ok) {
            reader.GetStream()->Seek(groupStart);
            reader.SetError(false);
            ReadTrailingBytes(reader, remainSize);
            break;
        }
        groups_.push_back(group);
    }
    return reader.GetError();
}

heif_error HeifGrplBox::ParseEntityGroup(HeifStreamReader &reader, EntityGroup &group)
{
    uint32_t versionAndFlags = reader.Read32();
    group.version = static_cast<uint8_t>(versionAndFlags >> THREE_BYTES_SHIFT);
    group.flags = versionAndFlags & 0x00FFFFFF;
    group.groupId = reader.Read32();
    uint32_t entityCount = reader.Read32();
    if (entityCount > MAX_GRPL_ENTITY_COUNT ||
        static_cast<uint64_t>(entityCount) * UINT32_BYTES_NUM > reader.GetRemainSize()) {
        return heif_error_invalid_data;
    }
    group.entityIds.reserve(entityCount);
    for (uint32_t index = 0; index < entityCount; ++index) {
        group.entityIds.push_back(reader.Read32());
    }
    size_t extraSize = reader.GetRemainSize();
    if (extraSize > 0) {
        group.extra.resize(extraSize);
        if (!reader.ReadData(group.extra.data(), extraSize)) {
            return reader.GetError();
        }
    }
    return reader.GetError();
}

void HeifGrplBox::ReadTrailingBytes(HeifStreamReader &reader, size_t size)
{
    if (size == 0) {
        return;
    }
    trailingBytes_.resize(size);
    if (!reader.ReadData(trailingBytes_.data(), size)) {
        trailingBytes_.clear();
    }
}

heif_error HeifGrplBox::Write(HeifStreamWriter &writer) const
{
    size_t boxStart = ReserveHeader(writer);

    for (const auto &group: groups_) {
        size_t groupStart = writer.GetPos();
        writer.Write32(0); // placeholder, overwritten with the calculated size below
        writer.Write32(group.groupType);
        writer.Write32((static_cast<uint32_t>(group.version) << THREE_BYTES_SHIFT) |
            (group.flags & 0x00FFFFFF));
        writer.Write32(group.groupId);
        writer.Write32(static_cast<uint32_t>(group.entityIds.size()));
        for (uint32_t entityId: group.entityIds) {
            writer.Write32(entityId);
        }
        if (!group.extra.empty()) {
            writer.Write(group.extra);
        }
        size_t groupEnd = writer.GetPos();
        writer.SetPos(groupStart);
        writer.Write32(static_cast<uint32_t>(groupEnd - groupStart));
        writer.SetPos(groupEnd);
    }
    if (!trailingBytes_.empty()) {
        writer.Write(trailingBytes_);
    }

    WriteCalculatedHeader(writer, boxStart);
    return heif_error_ok;
}
} // namespace ImagePlugin
} // namespace OHOS