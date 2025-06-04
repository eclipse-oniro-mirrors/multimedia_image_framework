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

#include "box/heif_box.h"
#include "box/basic_box.h"
#include "box/item_data_box.h"
#include "box/item_info_box.h"
#include "box/item_property_box.h"
#include "box/item_property_aux_box.h"
#include "box/item_property_basic_box.h"
#include "box/item_property_color_box.h"
#include "box/item_property_hvcc_box.h"
#include "box/item_property_transform_box.h"
#include "box/item_ref_box.h"
#include "box/item_property_display_box.h"
#include "box/item_movie_box.h"

#define MAKE_BOX_CASE(box_type, box_class_type)    \
case fourcc_to_code(box_type):                     \
    box = std::make_shared<box_class_type>();      \
    break

namespace {
    const uint8_t UUID_TYPE_BYTE_NUM = 16;
    const uint8_t LARGE_BOX_SIZE_TAG = 1;
}

namespace OHOS {
namespace ImagePlugin {
heif_error HeifBox::ParseHeader(HeifStreamReader &reader)
{
    // box size bytes + box type bytes
    if (!reader.CheckSize(UINT64_BYTES_NUM)) {
        return heif_error_eof;
    }

    boxSize_ = reader.Read32();
    boxType_ = reader.Read32();

    headerSize_ = UINT64_BYTES_NUM;

    if (boxSize_ == LARGE_BOX_SIZE_TAG) {
        if (!reader.CheckSize(UINT64_BYTES_NUM)) {
            return heif_error_eof;
        }
        boxSize_ = reader.Read64();
        headerSize_ += UINT64_BYTES_NUM;
    }

    if (boxType_ == BOX_TYPE_UUID) {
        if (!reader.CheckSize(UUID_TYPE_BYTE_NUM)) {
            return heif_error_eof;
        }

        boxUuidType_.resize(UUID_TYPE_BYTE_NUM);
        reader.GetStream()->Read(reinterpret_cast<char*>(boxUuidType_.data()), UUID_TYPE_BYTE_NUM);
        headerSize_ += UUID_TYPE_BYTE_NUM;
    }

    return reader.GetError();
}

int HeifBox::InferHeaderSize() const
{
    int headerSize = UINT64_BYTES_NUM;
    if (GetBoxType() == BOX_TYPE_UUID) {
        headerSize += UUID_TYPE_BYTE_NUM;
    }
    return headerSize;
}


size_t HeifBox::ReserveHeader(HeifStreamWriter &writer) const
{
    size_t startPos = writer.GetPos();
    int header_size = InferHeaderSize();
    writer.Skip(header_size);
    return startPos;
}


size_t HeifFullBox::ReserveHeader(HeifStreamWriter &writer) const
{
    size_t startPos = HeifBox::ReserveHeader(writer);
    writer.Skip(UINT32_BYTES_NUM);
    return startPos;
}


heif_error HeifFullBox::WriteHeader(HeifStreamWriter &writer, size_t boxSize) const
{
    auto err = HeifBox::WriteHeader(writer, boxSize);
    if (err) {
        return err;
    }
    writer.Write32((GetVersion() << THREE_BYTES_SHIFT) | GetFlags());
    return heif_error_ok;
}


heif_error HeifBox::WriteCalculatedHeader(HeifStreamWriter &writer, size_t startPos) const
{
    size_t boxSize = writer.GetDataSize() - startPos;
    writer.SetPos(startPos);
    auto err = WriteHeader(writer, boxSize);
    writer.SetPositionToEnd();
    return err;
}


heif_error HeifBox::WriteHeader(HeifStreamWriter &writer, size_t boxSize) const
{
    bool isSizeNeed64Bit = (boxSize > 0xFFFFFFFF);
    if (isSizeNeed64Bit) {
        // set largeSize need insert (boxSize bytes + boxType bytes).
        writer.Insert(UINT64_BYTES_NUM);
        writer.Write32(LARGE_BOX_SIZE_TAG);
    } else {
        writer.Write32((uint32_t) boxSize);
    }

    writer.Write32(GetBoxType());

    if (isSizeNeed64Bit) {
        writer.Write64(boxSize);
    }

    if (GetBoxType() == BOX_TYPE_UUID) {
        writer.Write(GetBoxUuidType());
    }

    return heif_error_ok;
}

heif_error HeifBox::ParseContent(HeifStreamReader &reader)
{
    uint64_t contentSize = GetBoxSize() - GetHeaderSize();
    if (reader.CheckSize(contentSize)) {
        reader.GetStream()->Seek(reader.GetStream()->Tell() + GetBoxSize() - GetHeaderSize());
    }

    return reader.GetError();
}

heif_error HeifBox::ParseContentChildren(HeifStreamReader &reader, uint32_t &recursionCount)
{
    uint64_t contentSize = GetBoxSize() - GetHeaderSize();
    if (reader.CheckSize(contentSize)) {
        reader.GetStream()->Seek(reader.GetStream()->Tell() + GetBoxSize() - GetHeaderSize());
    }

    return reader.GetError();
}

heif_error HeifFullBox::ParseFullHeader(HeifStreamReader &reader)
{
    uint32_t data = reader.Read32();
    version_ = static_cast<uint8_t>(data >> THREE_BYTES_SHIFT);
    flags_ = data & 0x00FFFFFF;
    headerSize_ += UINT32_BYTES_NUM;
    return reader.GetError();
}

std::shared_ptr<HeifBox> HeifBox::MakeBox(uint32_t boxType)
{
    std::shared_ptr<HeifBox> box;
    switch (boxType) {
        MAKE_BOX_CASE("ftyp", HeifFtypBox);
        MAKE_BOX_CASE("meta", HeifMetaBox);
        MAKE_BOX_CASE("hdlr", HeifHdlrBox);
        MAKE_BOX_CASE("pitm", HeifPtimBox);
        MAKE_BOX_CASE("iinf", HeifIinfBox);
        MAKE_BOX_CASE("infe", HeifInfeBox);
        MAKE_BOX_CASE("iref", HeifIrefBox);
        MAKE_BOX_CASE("iprp", HeifIprpBox);
        MAKE_BOX_CASE("ipco", HeifIpcoBox);
        MAKE_BOX_CASE("ipma", HeifIpmaBox);
        MAKE_BOX_CASE("colr", HeifColrBox);
        MAKE_BOX_CASE("hvcC", HeifHvccBox);
        MAKE_BOX_CASE("ispe", HeifIspeBox);
        MAKE_BOX_CASE("irot", HeifIrotBox);
        MAKE_BOX_CASE("imir", HeifImirBox);
        MAKE_BOX_CASE("pixi", HeifPixiBox);
        MAKE_BOX_CASE("auxC", HeifAuxcBox);
        MAKE_BOX_CASE("idat", HeifIdatBox);
        MAKE_BOX_CASE("iloc", HeifIlocBox);
        MAKE_BOX_CASE("rloc", HeifRlocBox);
        MAKE_BOX_CASE("clli", HeifClliBox);
        MAKE_BOX_CASE("moov", HeifMoovBox);
        MAKE_BOX_CASE("mvhd", HeifMvhdBox);
        MAKE_BOX_CASE("trak", HeifTrakBox);
        MAKE_BOX_CASE("tkhd", HeifTkhdBox);
        MAKE_BOX_CASE("mdia", HeifMdiaBox);
        MAKE_BOX_CASE("mdhd", HeifMdhdBox);
        MAKE_BOX_CASE("minf", HeifMinfBox);
        MAKE_BOX_CASE("vmhd", HeifVmhdBox);
        MAKE_BOX_CASE("dinf", HeifDinfBox);
        MAKE_BOX_CASE("dref", HeifDrefBox);
        MAKE_BOX_CASE("stbl", HeifStblBox);
        MAKE_BOX_CASE("stsd", HeifStsdBox);
        MAKE_BOX_CASE("hvc1", HeifHvc1Box);
        MAKE_BOX_CASE("stts", HeifSttsBox);
        MAKE_BOX_CASE("stsc", HeifStscBox);
        MAKE_BOX_CASE("stco", HeifStcoBox);
        MAKE_BOX_CASE("stsz", HeifStszBox);
        default:
            box = std::make_shared<HeifBox>();
            break;
    }
    return box;
}

bool BoxContentChildren(std::shared_ptr<HeifBox> box)
{
    return box->GetBoxType() == BOX_TYPE_IPRP || box->GetBoxType() == BOX_TYPE_IPCO ||
        box->GetBoxType() == BOX_TYPE_META || box->GetBoxType() == BOX_TYPE_IINF ||
        box->GetBoxType() == BOX_TYPE_MOOV || box->GetBoxType() == BOX_TYPE_TRAK ||
        box->GetBoxType() == BOX_TYPE_MDIA || box->GetBoxType() == BOX_TYPE_DINF ||
        box->GetBoxType() == BOX_TYPE_STBL || box->GetBoxType() == BOX_TYPE_MINF;
}

heif_error HeifBox::MakeFromReader(HeifStreamReader &reader,
    std::shared_ptr<HeifBox> *result, uint32_t &recursionCount)
{
    HeifBox headerBox;
    heif_error err = headerBox.ParseHeader(reader);
    if (err) {
        return err;
    }
    if (reader.HasError()) {
        return reader.GetError();
    }
    std::shared_ptr<HeifBox> box = HeifBox::MakeBox(headerBox.GetBoxType());
    box->SetHeaderInfo(headerBox);
    if (box->GetBoxSize() < box->GetHeaderSize()) {
        return heif_error_invalid_box_size;
    }
    uint64_t boxContentSize = box->GetBoxSize() - box->GetHeaderSize();
    if (!reader.CheckSize(boxContentSize)) {
        return heif_error_eof;
    }
    HeifStreamReader contentReader(reader.GetStream(), reader.GetStream()->Tell(), boxContentSize);
    if (BoxContentChildren(box)) {
        err = box->ParseContentChildren(contentReader, recursionCount);
    } else {
        err = box->ParseContent(contentReader);
    }
    if (!err) {
        *result = std::move(box);
    }
    if (err && box->GetBoxType() == BOX_TYPE_CLLI) {
        err = heif_error_ok;
    }
    contentReader.SkipEnd();
    return err;
}

heif_error HeifBox::Write(HeifStreamWriter &writer) const
{
    if (boxType_ == BOX_TYPE_MDAT || boxType_ == BOX_TYPE_IDAT) {
        return heif_error_ok;
    }

    size_t boxStart = ReserveHeader(writer);

    heif_error err = WriteChildren(writer);

    WriteCalculatedHeader(writer, boxStart);

    return err;
}

heif_error HeifBox::ReadChildren(HeifStreamReader &reader, uint32_t &recursionCount)
{
    while (!reader.IsAtEnd() && !reader.HasError()) {
        std::shared_ptr<HeifBox> box;
        heif_error error = HeifBox::MakeFromReader(reader, &box, recursionCount);
        if (error != heif_error_ok) {
            return error;
        }
        children_.push_back(std::move(box));
    }
    return reader.GetError();
}

heif_error HeifBox::WriteChildren(HeifStreamWriter &writer) const
{
    for (const auto &child: children_) {
        if (child->GetBoxType() == BOX_TYPE_GRPL) {
            continue;
        }
        heif_error err = child->Write(writer);
        if (err) {
            return err;
        }
    }
    return heif_error_ok;
}

void HeifBox::SetHeaderInfo(const HeifBox &box)
{
    boxSize_ = box.boxSize_;
    boxType_ = box.boxType_;
    boxUuidType_ = box.boxUuidType_;
    headerSize_ = box.headerSize_;
}

void HeifBox::InferAllFullBoxVersion()
{
    InferFullBoxVersion();

    for (auto &child: children_) {
        child->InferAllFullBoxVersion();
    }
}

heif_error HeifBox::ParseContentChildrenByReadChildren(HeifStreamReader &reader, uint32_t &recursionCount)
{
    recursionCount++;
    if (recursionCount > MAX_RECURSION_COUNT) {
        return heif_error_too_many_recursion;
    }
    return ReadChildren(reader, recursionCount);
}
} // namespace ImagePlugin
} // namespace OHOS
