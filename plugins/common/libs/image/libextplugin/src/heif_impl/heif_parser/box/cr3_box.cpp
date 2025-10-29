/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "box/cr3_box.h"

#include <map>
#include "heif_utils.h"
#include "image_log.h"

namespace OHOS {
namespace ImagePlugin {

static const std::string CR3_UUID_CANON = "\x85\xc0\xb6\x87\x82\x0f\x11\xe0\x81\x11\xf4\xce\x46\x2b\x6a\x48";
static const std::string CR3_UUID_PREVIEW = "\xea\xf4\x2b\x5e\x1c\x98\x4b\x88\xb9\xfb\xb7\xdc\x40\x6e\x4d\x16";
static const std::string CR3_UUID_XMP = "\xbe\x7a\xcf\xcb\x97\xa9\x42\xe8\x9c\x71\x99\x94\x91\xe3\xaf\xac";

static const std::map<std::string, Cr3UuidBox::Cr3UuidType> CR3_UUID_STRING_TYPE_MAP = {
    {CR3_UUID_CANON, Cr3UuidBox::Cr3UuidType::CANON},
    {CR3_UUID_PREVIEW, Cr3UuidBox::Cr3UuidType::PREVIEW},
    {CR3_UUID_XMP, Cr3UuidBox::Cr3UuidType::XMP},
};

std::shared_ptr<Cr3Box> Cr3Box::MakeCr3Box(uint32_t boxType)
{
    std::shared_ptr<Cr3Box> box;
    switch (boxType) {
        case BOX_TYPE_FTYP:
            box = std::make_shared<Cr3FtypBox>();
            break;
        case BOX_TYPE_UUID:
            box = std::make_shared<Cr3UuidBox>();
            break;
        case CR3_BOX_TYPE_MOOV:
            box = std::make_shared<Cr3MoovBox>();
            break;
        case CR3_BOX_TYPE_PRVW:
            box = std::make_shared<Cr3PrvwBox>();
            break;
        default:
            box = std::make_shared<Cr3Box>(boxType);
            break;
    }
    return box;
}

static bool Cr3BoxContentChildren(uint32_t boxType)
{
    return boxType == BOX_TYPE_UUID || boxType == CR3_BOX_TYPE_MOOV;
}

heif_error Cr3Box::MakeCr3FromReader(HeifStreamReader &reader,
    std::shared_ptr<Cr3Box> &result, uint32_t &recursionCount)
{
    HeifBox headerBox;
    heif_error err = headerBox.ParseHeader(reader);
    if (err != heif_error_ok) {
        return err;
    }
    if (reader.HasError()) {
        return reader.GetError();
    }
    std::shared_ptr<Cr3Box> box = Cr3Box::MakeCr3Box(headerBox.GetBoxType());
    if (box == nullptr) {
        return heif_error_no_data;
    }
    box->SetHeaderInfo(headerBox);
    if (box->GetBoxSize() < box->GetHeaderSize()) {
        return heif_error_invalid_box_size;
    }
    uint64_t boxContentSize = box->GetBoxSize() - box->GetHeaderSize();
    if (!reader.CheckSize(boxContentSize)) {
        return heif_error_eof;
    }
    HeifStreamReader contentReader(reader.GetStream(), reader.GetStream()->Tell(), boxContentSize);
    if (Cr3BoxContentChildren(box->GetBoxType())) {
        err = box->ParseContentChildren(contentReader, recursionCount);
    } else {
        err = box->ParseContent(contentReader);
    }
    if (err == heif_error_ok) {
        result = std::move(box);
    }
    contentReader.SkipEnd();
    return err;
}

heif_error Cr3Box::ReadData(const std::shared_ptr<HeifInputStream> &stream,
    uint64_t start, uint64_t length, std::vector<uint8_t> &outData) const
{
    if (stream == nullptr) {
        return heif_error_no_data;
    }
    uint64_t boxStartPos = static_cast<uint64_t>(startPos_);
    if (start > GetBoxSize() || length > GetBoxSize() || start + length > GetBoxSize()) {
        return heif_error_eof;
    }

    stream->Seek(boxStartPos + start);
    if (length > 0) {
        outData.resize(static_cast<size_t>(length));
        uint8_t *data = &outData[0];
        stream->Read(reinterpret_cast<char*>(data), static_cast<size_t>(length));
    }
    return heif_error_ok;
}

heif_error Cr3Box::ParseContent(HeifStreamReader &reader)
{
    startPos_ = reader.GetStream()->Tell();
    return reader.GetError();
}

heif_error Cr3Box::ReadCr3Children(HeifStreamReader &reader, uint32_t &recursionCount)
{
    while (!reader.IsAtEnd() && !reader.HasError()) {
        std::shared_ptr<Cr3Box> box = nullptr;
        heif_error error = Cr3Box::MakeCr3FromReader(reader, box, recursionCount);
        if (error != heif_error_ok) {
            return error;
        }
        if (box != nullptr) {
            auto parent = code_to_fourcc(GetBoxType());
            auto child = code_to_fourcc(box->GetBoxType());
            IMAGE_LOGD("%{public}s parent[%{public}s] add child[%{public}s]", __func__, parent.c_str(), child.c_str());
            children_.emplace_back(box);
        }
    }
    return reader.GetError();
}

heif_error Cr3FtypBox::ParseContent(HeifStreamReader &reader)
{
    startPos_ = reader.GetStream()->Tell();
    majorBrand_ = reader.Read32();
    minorVersion_ = reader.Read32();

    // (box size - headersize - majorbrand bytes - minorversion bytes) / (compatibleBrand bytes)
    uint64_t compatibleBrandNum =
        (GetBoxSize() - GetHeaderSize() - UINT32_BYTES_NUM - UINT32_BYTES_NUM) / UINT32_BYTES_NUM;
    for (uint64_t i = 0; i < compatibleBrandNum && !reader.HasError(); i++) {
        compatibleBrands_.push_back(reader.Read32());
    }
    return reader.GetError();
}

Cr3UuidBox::Cr3UuidType Cr3UuidBox::GetCr3UuidType()
{
    if (cr3UuidType_ == Cr3UuidBox::Cr3UuidType::UNKNOWN) {
        auto boxUuidType = GetBoxUuidType();
        std::string boxUuidString(boxUuidType.begin(), boxUuidType.end());
        auto item = CR3_UUID_STRING_TYPE_MAP.find(boxUuidString);
        if (item != CR3_UUID_STRING_TYPE_MAP.end()) {
            cr3UuidType_ = item->second;
        }
    }
    return cr3UuidType_;
}

heif_error Cr3UuidBox::ParseContentChildren(HeifStreamReader &reader, uint32_t &recursionCount)
{
    startPos_ = reader.GetStream()->Tell();
    recursionCount++;
    if (recursionCount > MAX_RECURSION_COUNT) {
        return heif_error_too_many_recursion;
    }

    auto boxUuidType = GetBoxUuidType();
    Cr3UuidBox::Cr3UuidType cr3Uuid = GetCr3UuidType();
    if (cr3Uuid == Cr3UuidBox::Cr3UuidType::CANON) {
        return ReadCr3Children(reader, recursionCount);
    } else if (cr3Uuid == Cr3UuidBox::Cr3UuidType::PREVIEW) {
        // Skip 8 bytes
        reader.Read64();
        return ReadCr3Children(reader, recursionCount);
    } else {
        IMAGE_LOGD("%{public}s unsupport uuid type: %{public}d", __func__, cr3Uuid);
    }
    return heif_error_ok;
}

heif_error Cr3MoovBox::ParseContentChildren(HeifStreamReader &reader, uint32_t &recursionCount)
{
    startPos_ = reader.GetStream()->Tell();
    recursionCount++;
    if (recursionCount > MAX_RECURSION_COUNT) {
        return heif_error_too_many_recursion;
    }
    return ReadCr3Children(reader, recursionCount);
}

heif_error Cr3PrvwBox::ParseContent(HeifStreamReader &reader)
{
    startPos_ = reader.GetStream()->Tell();
    // Skip 6 bytes
    reader.Read32();
    reader.Read16();
    width_ = reader.Read16();
    height_ = reader.Read16();
    // Skip 2 bytes
    reader.Read16();
    jpegSize_ = reader.Read32();
    jpegFileOffset_ = static_cast<uint64_t>(reader.GetStream()->Tell());
    return reader.GetError();
}
} // namespace ImagePlugin
} // namespace OHOS
