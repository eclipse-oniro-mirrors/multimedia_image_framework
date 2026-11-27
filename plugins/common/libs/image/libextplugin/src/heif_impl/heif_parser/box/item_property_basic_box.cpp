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

#include "box/item_property_basic_box.h"

#include "image_log.h"

namespace OHOS {
namespace ImagePlugin {
namespace {
    // all_ref_pics_intra + intra_pred_used + max_ref_per_pic + reserved, 32 bits in total.
    const size_t CCST_CONTENT_SIZE = UINT32_BYTES_NUM;
}
heif_error HeifIspeBox::ParseContent(HeifStreamReader &reader)
{
    ParseFullHeader(reader);
    width_ = reader.Read32();
    height_ = reader.Read32();
    return reader.GetError();
}

heif_error HeifIspeBox::Write(HeifStreamWriter &writer) const
{
    size_t boxStart = ReserveHeader(writer);

    writer.Write32(width_);
    writer.Write32(height_);

    WriteCalculatedHeader(writer, boxStart);
    return heif_error_ok;
}

heif_error HeifPixiBox::ParseContent(HeifStreamReader &reader)
{
    ParseFullHeader(reader);
    uint8_t channelNum = reader.Read8();
    if (!reader.CheckSize(channelNum)) {
        return heif_error_eof;
    }
    bitNums_.resize(channelNum);
    for (int i = 0; i < channelNum; i++) {
        bitNums_[i] = reader.Read8();
    }
    return reader.GetError();
}

heif_error HeifPixiBox::Write(HeifStreamWriter &writer) const
{
    size_t boxStart = ReserveHeader(writer);

    writer.Write8((uint8_t) (bitNums_.size()));
    for (uint8_t bitNum : bitNums_) {
        writer.Write8(bitNum);
    }

    WriteCalculatedHeader(writer, boxStart);
    return heif_error_ok;
}

heif_error HeifRlocBox::ParseContent(HeifStreamReader &reader)
{
    ParseFullHeader(reader);
    horizontalOffset_ = reader.Read32();
    verticalOffset_ = reader.Read32();
    return reader.GetError();
}

heif_error HeifRlocBox::Write(HeifStreamWriter &writer) const
{
    size_t boxStart = ReserveHeader(writer);

    writer.Write32(horizontalOffset_);
    writer.Write32(verticalOffset_);

    WriteCalculatedHeader(writer, boxStart);
    return heif_error_ok;
}

void HeifCcstBox::SetCodingConstraints(bool allRefPicsIntra, bool intraPredUsed, uint8_t maxRefPerPic)
{
    // max_ref_per_pic is a 4 bit field, so a larger input is clamped instead of overflowing into
    // the reserved bits.
    const uint32_t maxRef = (maxRefPerPic > MAX_REF_PER_PIC_LIMIT) ? MAX_REF_PER_PIC_LIMIT : maxRefPerPic;
    codingConstraints_ = (allRefPicsIntra ? ALL_REF_PICS_INTRA_FLAG : 0) |
        (intraPredUsed ? INTRA_PRED_USED_FLAG : 0) |
        ((maxRef & MAX_REF_PER_PIC_MASK) << MAX_REF_PER_PIC_SHIFT);
}

heif_error HeifCcstBox::ParseContent(HeifStreamReader &reader)
{
    ParseFullHeader(reader);
    // Keep the property slot for a truncated box instead of rejecting the whole file.
    if (reader.GetRemainSize() < CCST_CONTENT_SIZE) {
        IMAGE_LOGW("Truncated ccst box, remain size: %{public}zu, expected: %{public}zu",
            reader.GetRemainSize(), CCST_CONTENT_SIZE);
        return heif_error_ok;
    }
    codingConstraints_ = reader.Read32();
    return reader.GetError();
}

heif_error HeifCcstBox::Write(HeifStreamWriter &writer) const
{
    size_t boxStart = ReserveHeader(writer);

    writer.Write32(codingConstraints_);

    WriteCalculatedHeader(writer, boxStart);
    return heif_error_ok;
}
} // namespace ImagePlugin
} // namespace OHOS
