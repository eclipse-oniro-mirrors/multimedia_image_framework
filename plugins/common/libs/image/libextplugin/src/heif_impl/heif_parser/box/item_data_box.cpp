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

#include "box/item_data_box.h"
#include <climits>

namespace {
    const uint8_t CONSTRUCTION_METHOD_FILE_OFFSET = 0;
    const uint8_t CONSTRUCTION_METHOD_IDAT_OFFSET = 1;
    const uint32_t MAX_HEIF_IMAGE_GRID_SIZE = 128 * 1024 * 1024;
    const uint32_t MAX_HEIF_ITEM_COUNT = 2000;
    const uint32_t MAX_HEIF_EXTENT_NUM = 1024;
}

namespace OHOS {
namespace ImagePlugin {
static bool HasOverflowed64(uint64_t num1, uint64_t num2)
{
    return num1 > std::numeric_limits<uint64_t>::max() - num2;
}

static bool HasOverflowed64(uint64_t num1, uint64_t num2, uint64_t num3)
{
    if (HasOverflowed64(num1, num2)) {
        return true;
    }
    uint64_t tmp = num1 + num2;
    return HasOverflowed64(tmp, num3);
}

heif_error HeifIlocBox::ParseExtents(Item& item, HeifStreamReader &reader,
    int indexSize, int offsetSize, int lengthSize)
{
    uint16_t extentNum = reader.Read16();
    if (extentNum > MAX_HEIF_EXTENT_NUM) {
        return heif_error_extent_num_too_large;
    }
    item.extents.resize(extentNum);
    for (int extentIndex = 0; extentIndex < extentNum; extentIndex++) {
        // indexSize is taken from the set {0, 4, 8} and indicates the length in bytes of 'index'
        if (GetVersion() >= HEIF_BOX_VERSION_ONE) {
            item.extents[extentIndex].index = 0;
            if (indexSize == UINT32_BYTES_NUM) {
                item.extents[extentIndex].index = reader.Read32();
            } else if (indexSize == UINT64_BYTES_NUM) {
                item.extents[extentIndex].index = reader.Read64();
            }
        }

        // offsetSize is taken from the set {0, 4, 8} and indicates the length in bytes of 'offset'
        item.extents[extentIndex].offset = 0;
        if (offsetSize == UINT32_BYTES_NUM) {
            item.extents[extentIndex].offset = reader.Read32();
        } else if (offsetSize == UINT64_BYTES_NUM) {
            item.extents[extentIndex].offset = reader.Read64();
        }

        // lengthSize is taken from the set {0, 4, 8} and indicates the length in bytes of 'length'
        item.extents[extentIndex].length = 0;
        if (lengthSize == UINT32_BYTES_NUM) {
            item.extents[extentIndex].length = reader.Read32();
        } else if (lengthSize == UINT64_BYTES_NUM) {
            item.extents[extentIndex].length = reader.Read64();
        }
    }
    return heif_error_ok;
}

heif_error HeifIlocBox::ParseContent(HeifStreamReader &reader)
{
    ParseFullHeader(reader);

    const uint8_t offsetSizeShift = 12;
    const uint8_t baseOffsetSizeShift = 4;
    uint16_t values4 = reader.Read16();
    int offsetSize = (values4 >> offsetSizeShift) & 0xF;
    int lengthSize = (values4 >> ONE_BYTE_SHIFT) & 0xF;
    int baseOffsetSize = (values4 >> baseOffsetSizeShift) & 0xF;
    int indexSize = (GetVersion() >= HEIF_BOX_VERSION_ONE) ? (values4 & 0xF) : 0;
    uint32_t itemCount = GetVersion() < HEIF_BOX_VERSION_TWO ? reader.Read16() : reader.Read32();
    if (itemCount > MAX_HEIF_ITEM_COUNT) {
        return heif_error_too_many_item;
    }
    for (uint32_t itemIndex = 0; itemIndex < itemCount; ++itemIndex) {
        Item item;
        item.itemId = GetVersion() < HEIF_BOX_VERSION_TWO ? reader.Read16() : reader.Read32();

        if (GetVersion() >= HEIF_BOX_VERSION_ONE) {
            values4 = reader.Read16();
            item.constructionMethod = (values4 & 0xF);
        }
        item.dataReferenceIndex = reader.Read16();

         // baseOffsetSize is taken from the set {0, 4, 8} and indicates the length in bytes of 'baseOffset'
        item.baseOffset = 0;
        if (baseOffsetSize == UINT32_BYTES_NUM) {
            item.baseOffset = reader.Read32();
        } else if (baseOffsetSize == UINT64_BYTES_NUM) {
            item.baseOffset = reader.Read64();
        }
        if (ParseExtents(item, reader, indexSize, offsetSize, lengthSize)) {
            return heif_error_extent_num_too_large;
        }
        if (!reader.HasError()) {
            items_.push_back(item);
        }
    }
    return reader.GetError();
}

heif_error HeifIlocBox::GetIlocDataLength(const Item &item, size_t &length)
{
    for (const auto &extent: item.extents) {
        if (extent.length > MAX_HEIF_IMAGE_GRID_SIZE) {
            return heif_error_grid_too_large;
        }
        length = extent.length;
    }
    return heif_error_ok;
}

heif_error HeifIlocBox::ReadData(const Item &item, const std::shared_ptr<HeifInputStream> &stream,
    const std::shared_ptr<HeifIdatBox> &idat, std::vector<uint8_t> *dest) const
{
    for (const auto &extent: item.extents) {
        if (item.constructionMethod == CONSTRUCTION_METHOD_FILE_OFFSET) {
            stream->Seek(extent.offset + item.baseOffset);

            size_t oldSize = dest->size();
            if (extent.length > MAX_HEIF_IMAGE_GRID_SIZE) {
                return heif_error_grid_too_large;
            }
            dest->resize(static_cast<size_t>(oldSize + extent.length));
            stream->Read(reinterpret_cast<char*>(dest->data()) + oldSize, static_cast<size_t>(extent.length));
        } else if (item.constructionMethod == CONSTRUCTION_METHOD_IDAT_OFFSET) {
            if (!idat) {
                return heif_error_no_idat;
            }
            uint64_t start = extent.offset + item.baseOffset;
            idat->ReadData(stream, start, extent.length, *dest);
        } else {
            return heif_error_no_idat;
        }
    }

    return heif_error_ok;
}

heif_error HeifIlocBox::AppendData(heif_item_id itemId, const std::vector<uint8_t> &data, uint8_t constructionMethod)
{
    size_t idx;
    for (idx = 0; idx < items_.size(); idx++) {
        if (items_[idx].itemId == itemId) {
            break;
        }
    }
    if (idx == items_.size()) {
        Item item;
        item.itemId = itemId;
        item.constructionMethod = constructionMethod;

        items_.push_back(item);
    }
    Extent extent;
    extent.data = data;
    if (constructionMethod == CONSTRUCTION_METHOD_IDAT_OFFSET) {
        extent.offset = idatOffset_;
        extent.length = data.size();

        idatOffset_ += data.size();
    }
    items_[idx].extents.push_back(std::move(extent));
    return heif_error_ok;
}

heif_error HeifIlocBox::UpdateData(heif_item_id itemID, const std::vector<uint8_t> &data, uint8_t constructionMethod)
{
    if (0 != constructionMethod) {
        return heif_invalid_exif_data;
    }

    // check whether this item ID already exists
    size_t idx;
    for (idx = 0; idx < items_.size(); idx++) {
        if (items_[idx].itemId == itemID) {
            break;
        }
    }

    // No item existing return
    if (idx == items_.size()) {
        return heif_error_item_not_found;
    }

    Extent extent;
    extent.data = data;
    extent.length = data.size();

    // clean any old extends
    items_[idx].extents.clear();

    // push the new extend in
    items_[idx].extents.push_back(std::move(extent));
    return heif_error_ok;
}

void HeifIlocBox::InferFullBoxVersion()
{
    int minVersion = items_.size() < 0xFFFF ? HEIF_BOX_VERSION_ONE : HEIF_BOX_VERSION_TWO;
    offsetSize_ = 0;
    lengthSize_ = 0;
    baseOffsetSize_ = 0;
    indexSize_ = 0;

    for (const auto &item: items_) {
        minVersion = (item.itemId < 0xFFFF) ? minVersion : std::max(minVersion, (int)HEIF_BOX_VERSION_TWO);
        minVersion = (item.constructionMethod == CONSTRUCTION_METHOD_FILE_OFFSET) ?
            minVersion : std::max(minVersion, (int)HEIF_BOX_VERSION_ONE);
    }

    offsetSize_ = UINT32_BYTES_NUM;
    lengthSize_ = UINT32_BYTES_NUM;
    baseOffsetSize_ = 0;
    indexSize_ = 0;

    SetVersion((uint8_t)minVersion);
}

heif_error HeifIlocBox::Write(HeifStreamWriter &writer) const
{
    size_t idatTotalSize = 0;
    for (const auto &item: items_) {
        idatTotalSize += (item.constructionMethod == CONSTRUCTION_METHOD_IDAT_OFFSET) ? item.GetExtentsTotalSize() : 0;
    }
    if (idatTotalSize > 0) {
        // need add header bytes size
        writer.Write32((uint32_t) (idatTotalSize + UINT64_BYTES_NUM));
        writer.Write32(BOX_TYPE_IDAT);

        for (auto &item: items_) {
            if (item.constructionMethod != CONSTRUCTION_METHOD_IDAT_OFFSET) {
                continue;
            }
            for (auto &extent: item.extents) {
                writer.Write(extent.data);
            }
        }
    }

    size_t boxStart = ReserveHeader(writer);
    startPos_ = writer.GetPos();
    int nSkip = 0;
    nSkip += UINT16_BYTES_NUM;
    nSkip += (GetVersion() < HEIF_BOX_VERSION_TWO) ? UINT16_BYTES_NUM : UINT32_BYTES_NUM;
    for (const auto &item: items_) {
        nSkip += (GetVersion() < HEIF_BOX_VERSION_TWO) ? UINT16_BYTES_NUM : UINT32_BYTES_NUM;
        nSkip += (GetVersion() >= HEIF_BOX_VERSION_ONE) ? UINT16_BYTES_NUM : 0;
        nSkip += UINT32_BYTES_NUM + baseOffsetSize_;
        for (const auto &extent: item.extents) {
            (void) extent;
            if (GetVersion() >= HEIF_BOX_VERSION_ONE) {
                nSkip += indexSize_;
            }
            nSkip += offsetSize_ + lengthSize_;
        }
    }
    writer.Skip(nSkip);
    WriteCalculatedHeader(writer, boxStart);
    return heif_error_ok;
}

heif_error HeifIlocBox::WriteMdatBox(HeifStreamWriter &writer)
{
    // all mdat data size
    size_t mdatTotalSize = 0;

    for (const auto &item: items_) {
        mdatTotalSize += (item.constructionMethod != CONSTRUCTION_METHOD_FILE_OFFSET) ?
            0 : item.GetExtentsTotalSize();
    }

    // need add header bytes
    writer.Write32((uint32_t) (mdatTotalSize + UINT64_BYTES_NUM));
    writer.Write32(BOX_TYPE_MDAT);

    for (auto &item: items_) {
        if (item.constructionMethod != CONSTRUCTION_METHOD_FILE_OFFSET) {
            continue;
        }
        for (auto &extent: item.extents) {
            extent.offset = writer.GetPos();
            extent.length = extent.data.size();

            writer.Write(extent.data);
        }
    }

    PackIlocHeader(writer);
    return heif_error_ok;
}

heif_error HeifIlocBox::ReadToExtentData(Item &item, const std::shared_ptr<HeifInputStream> &stream,
    const std::shared_ptr<HeifIdatBox> &idatBox)
{
    for (auto &extent: item.extents) {
        if (!extent.data.empty()) {
            continue;
        }
        if (item.constructionMethod == CONSTRUCTION_METHOD_FILE_OFFSET) {
            bool ret = stream->Seek(extent.offset + item.baseOffset);
            if (!ret) {
                return heif_error_eof;
            }
            ret = stream->CheckSize(extent.length, -1);
            if (!ret) {
                return heif_error_eof;
            }
            extent.data.resize(extent.length);
            ret = stream->Read(extent.data.data(), static_cast<size_t>(extent.length));
            if (!ret) {
                return heif_error_eof;
            }
        } else if (item.constructionMethod == CONSTRUCTION_METHOD_IDAT_OFFSET) {
            if (!idatBox) {
                return heif_error_no_idat;
            }
            idatBox->ReadData(stream, extent.offset + item.baseOffset, extent.length, extent.data);
        }
    }

    return heif_error_ok;
}

void HeifIlocBox::PackIlocHeader(HeifStreamWriter &writer) const
{
    size_t oldPos = writer.GetPos();
    writer.SetPos(startPos_);
    const uint8_t offsetSizeShift = 4;
    writer.Write8((uint8_t) ((offsetSize_ << offsetSizeShift) | (lengthSize_)));
    writer.Write8((uint8_t) ((baseOffsetSize_ << offsetSizeShift) | (indexSize_)));

    if (GetVersion() < HEIF_BOX_VERSION_TWO) {
        writer.Write16((uint16_t) items_.size());
    } else {
        writer.Write32((uint32_t) items_.size());
    }

    for (const auto &item: items_) {
        if (GetVersion() < HEIF_BOX_VERSION_TWO) {
            writer.Write16((uint16_t) item.itemId);
        } else {
            writer.Write32((uint32_t) item.itemId);
        }

        if (GetVersion() >= HEIF_BOX_VERSION_ONE) {
            writer.Write16(item.constructionMethod);
        }

        writer.Write16(item.dataReferenceIndex);
        writer.Write(baseOffsetSize_, item.baseOffset);
        writer.Write16((uint16_t) item.extents.size());

        for (const auto &extent: item.extents) {
            if (GetVersion() >= HEIF_BOX_VERSION_ONE && indexSize_ > 0) {
                writer.Write(indexSize_, extent.index);
            }

            writer.Write(offsetSize_, extent.offset);
            writer.Write(lengthSize_, extent.length);
        }
    }

    writer.SetPos(oldPos);
}

heif_error HeifIlocBox::GetPrimaryImageFileOffset(heif_item_id itemId, uint64_t &offset,
    const std::shared_ptr<HeifIdatBox> &idat) const
{
    const std::vector<Item> items = GetItems();
    for (const auto &item : items) {
        if (item.itemId != itemId) {
            continue;
        }
        if (item.extents.empty()) {
            return heif_error_item_data_not_found;
        }
        const auto &extent = item.extents[0];
        if (item.constructionMethod == CONSTRUCTION_METHOD_FILE_OFFSET) {
            if (HasOverflowed64(extent.offset, item.baseOffset)) {
                return heif_error_eof;
            }
            offset = extent.offset + item.baseOffset;
        } else if (item.constructionMethod == CONSTRUCTION_METHOD_IDAT_OFFSET) {
            if (!idat) {
                return heif_error_no_idat;
            }
            if (HasOverflowed64(idat->GetStartPos(), extent.offset, item.baseOffset)) {
                return heif_error_eof;
            }
            offset = idat->GetStartPos() + extent.offset + item.baseOffset;
        } else {
            return heif_error_item_data_not_found;
        }
        return heif_error_ok;
    }
    return heif_error_primary_item_not_found;
}

heif_error HeifIdatBox::ParseContent(HeifStreamReader &reader)
{
    startPos_ = reader.GetStream()->Tell();

    return reader.GetError();
}

heif_error HeifIdatBox::Write(HeifStreamWriter &writer) const
{
    if (dataForWriting_.empty()) {
        return heif_error_ok;
    }

    size_t boxStart = ReserveHeader(writer);

    writer.Write(dataForWriting_);

    WriteCalculatedHeader(writer, boxStart);

    return heif_error_ok;
}

heif_error HeifIdatBox::ReadData(const std::shared_ptr<HeifInputStream> &stream,
    uint64_t start, uint64_t length, std::vector<uint8_t> &outData) const
{
    auto currSize = outData.size();
    if (start > (uint64_t) startPos_ + GetBoxSize()) {
        return heif_error_eof;
    } else if (length > GetBoxSize() || start + length > GetBoxSize()) {
        return heif_error_eof;
    }

    stream->Seek(startPos_ + (std::streampos) start);

    if (length > 0) {
        outData.resize(static_cast<size_t>(currSize + length));
        uint8_t *data = &outData[currSize];

        stream->Read(reinterpret_cast<char*>(data), static_cast<size_t>(length));
    }

    return heif_error_ok;
}
} // namespace ImagePlugin
} // namespace OHOS
