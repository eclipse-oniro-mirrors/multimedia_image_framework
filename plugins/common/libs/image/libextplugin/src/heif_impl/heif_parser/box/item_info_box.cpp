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

#include "box/item_info_box.h"

namespace OHOS {
namespace ImagePlugin {
heif_error HeifIinfBox::ParseContent(HeifStreamReader &reader)
{
    ParseFullHeader(reader);
    uint8_t boxVersion = GetVersion();
    uint32_t entryCount = (boxVersion == HEIF_BOX_VERSION_ZERO) ? reader.Read16() : reader.Read32();
    if (entryCount == 0) {
        return heif_error_ok;
    }
    return ReadChildren(reader);
}

void HeifIinfBox::InferFullBoxVersion()
{
    SetVersion(children_.size() > 0xFFFF ? HEIF_BOX_VERSION_ONE : HEIF_BOX_VERSION_ZERO);
}

heif_error HeifIinfBox::Write(HeifStreamWriter &writer) const
{
    size_t boxStart = ReserveHeader(writer);
    uint8_t boxVersion = GetVersion();
    writer.Write(boxVersion > HEIF_BOX_VERSION_ZERO ? UINT32_BYTES_NUM : UINT16_BYTES_NUM, children_.size());
    heif_error err = WriteChildren(writer);
    WriteCalculatedHeader(writer, boxStart);
    return err;
}

heif_error HeifInfeBox::ParseContent(HeifStreamReader &reader)
{
    ParseFullHeader(reader);

    uint8_t boxVersion = GetVersion();
    if (boxVersion <= HEIF_BOX_VERSION_ONE) {
        itemId_ = reader.Read16();
        itemProtectionIndex_ = reader.Read16();
        itemName_ = reader.ReadString();
        contentType_ = reader.ReadString();
        contentEncoding_ = reader.ReadString();
    } else if (boxVersion >= HEIF_BOX_VERSION_TWO) {
        isHidden_ = (GetFlags() & 0x01);
        itemId_ = boxVersion == HEIF_BOX_VERSION_TWO ? reader.Read16() : reader.Read32();
        itemProtectionIndex_ = reader.Read16();
        uint32_t itemType = reader.Read32();
        if (itemType != 0) {
            itemType_ = code_to_fourcc(itemType);
        }
        itemName_ = reader.ReadString();
        if (itemType == ITEM_TYPE_MIME) {
            contentType_ = reader.ReadString();
            contentEncoding_ = reader.ReadString();
        } else if (itemType == ITEM_TYPE_URI) {
            itemUriType_ = reader.ReadString();
        }
    }

    return reader.GetError();
}

void HeifInfeBox::InferFullBoxVersion()
{
    uint8_t version = GetVersion();
    if (isHidden_ || !itemType_.empty()) {
        version = std::max(version, (uint8_t)HEIF_BOX_VERSION_TWO);
    }
    if (itemId_ > 0xFFFF) {
        version = std::max(version, (uint8_t)HEIF_BOX_VERSION_THREE);
    }
    SetVersion(version);
}

void HeifInfeBox::SetHidden(bool hidden)
{
    isHidden_ = hidden;
    SetFlags(isHidden_ ? (GetFlags() | 0x01) : (GetFlags() & ~(0x00000001)));
}

heif_error HeifInfeBox::Write(HeifStreamWriter &writer) const
{
    size_t boxStart = ReserveHeader(writer);

    uint8_t boxVersion = GetVersion();
    if (boxVersion <= HEIF_BOX_VERSION_ONE) {
        writer.Write16(itemId_);
        writer.Write16(itemProtectionIndex_);

        writer.Write(itemName_);
        writer.Write(contentType_);
        writer.Write(contentEncoding_);
    }

    if (boxVersion >= HEIF_BOX_VERSION_TWO) {
        if (boxVersion == HEIF_BOX_VERSION_TWO) {
            writer.Write16(itemId_);
        } else if (boxVersion == HEIF_BOX_VERSION_THREE) {
            writer.Write32(itemId_);
        }

        writer.Write16(itemProtectionIndex_);

        if (itemType_.empty()) {
            writer.Write32(0);
        } else {
            writer.Write32(fourcc_to_code(itemType_.c_str()));
        }

        writer.Write(itemName_);
        if (itemType_ == "mime") {
            writer.Write(contentType_);
            writer.Write(contentEncoding_);
        } else if (itemType_ == "uri ") {
            writer.Write(itemUriType_);
        }
    }

    WriteCalculatedHeader(writer, boxStart);
    return heif_error_ok;
}

heif_error HeifPtimBox::ParseContent(HeifStreamReader &reader)
{
    ParseFullHeader(reader);
    uint8_t boxVersion = GetVersion();
    itemId_ = boxVersion == HEIF_BOX_VERSION_ZERO ? reader.Read16() : reader.Read32();
    return reader.GetError();
}

void HeifPtimBox::InferFullBoxVersion()
{
    SetVersion(itemId_ <= 0xFFFF ? HEIF_BOX_VERSION_ZERO : HEIF_BOX_VERSION_ONE);
}

heif_error HeifPtimBox::Write(HeifStreamWriter &writer) const
{
    size_t boxStart = ReserveHeader(writer);

    if (GetVersion() == HEIF_BOX_VERSION_ZERO) {
        writer.Write16(itemId_);
    } else {
        writer.Write32(itemId_);
    }

    WriteCalculatedHeader(writer, boxStart);
    return heif_error_ok;
}
} // namespace ImagePlugin
} // namespace OHOS
