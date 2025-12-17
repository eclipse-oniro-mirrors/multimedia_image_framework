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

#include "box/item_movie_box.h"

#include <algorithm>
#include <numeric>

namespace {
    const uint32_t MVHD_MATRIX_OFFSET = 9;
    const uint32_t MVHD_PREDEFINED_OFFSET = 6;
    const uint32_t TKHD_MATRIX_OFFSET = 9;
    const uint32_t VMHD_OPCOLOR_OFFSET = 3;
    const uint32_t HVC1_RESERVED_OFFSET = 6;
    const uint32_t HVC1_PREDEFINE_OFFSET = 16;
    const uint32_t HVC1_SKIP_OFFSET = 50;
    const uint32_t RESERVERED_INDEX_ZERO = 0;
    const uint32_t RESERVERED_INDEX_ONE = 1;
    const uint32_t MAX_DREF_ENTRYCOUNT = static_cast<uint32_t>(std::numeric_limits<int32_t>::max());
    const uint32_t MAX_STSD_ENTRYCOUNT = 1024;
    const uint32_t MAX_STTS_ENTRYCOUNT = 1024 * 1024 * 512;
    const uint32_t MAX_STSC_ENTRYCOUNT = 1024 * 1024 * 256;
    const uint32_t MAX_STCO_ENTRYCOUNT = 1024 * 1024 * 1024;
    const uint32_t MAX_STSS_ENTRYCOUNT = 1024 * 1024 * 1024;
}

namespace OHOS {
namespace ImagePlugin {

static bool isStrictlyIncreasing(const std::vector<uint32_t>& vec)
{
    return std::is_sorted(vec.begin(), vec.end(), [](uint32_t a, uint32_t b) {
        return a < b;
    });
}

heif_error HeifMoovBox::ParseContentChildren(HeifStreamReader &reader, uint32_t &recursionCount)
{
    return ParseContentChildrenByReadChildren(reader, recursionCount);
}

heif_error HeifMvhdBox::ParseContent(HeifStreamReader &reader)
{
    ParseFullHeader(reader);
    if (GetVersion() == HEIF_BOX_VERSION_ONE) {
        creationTime_ = reader.Read64();
        modificationTime_ = reader.Read64();
        timescale_ = reader.Read32();
        duration_ = reader.Read32();
    } else {
        creationTime_ = reader.Read32();
        modificationTime_ = reader.Read32();
        timescale_ = reader.Read32();
        duration_ = reader.Read32();
    }
    rate_ = reader.Read32();
    volume_ = reader.Read16();
    reserved_ = reader.Read16();
    reserved2_[RESERVERED_INDEX_ZERO] = reader.Read32();
    reserved2_[RESERVERED_INDEX_ONE] = reader.Read32();
    for (uint32_t i = 0; i < MVHD_MATRIX_OFFSET; i++) {
        matrix_[i] = reader.Read32();
    }
    for (uint32_t i = 0; i < MVHD_PREDEFINED_OFFSET; i++) {
        preDefined_[i] = reader.Read32();
    }
    nextTrackId_ = reader.Read32();
    return reader.GetError();
}

heif_error HeifMvhdBox::Write(HeifStreamWriter &writer) const
{
    size_t boxStart = ReserveHeader(writer);
    if (GetVersion() == HEIF_BOX_VERSION_ONE) {
        writer.Write64(creationTime_);
        writer.Write64(modificationTime_);
        writer.Write32(timescale_);
        writer.Write64(duration_);
    } else {
        writer.Write32(creationTime_);
        writer.Write32(modificationTime_);
        writer.Write32(timescale_);
        writer.Write32(duration_);
    }
    writer.Write32(rate_);
    writer.Write16(volume_);
    writer.Write16(reserved_);
    writer.Write32(reserved2_[RESERVERED_INDEX_ZERO]);
    writer.Write32(reserved2_[RESERVERED_INDEX_ONE]);
    for (uint32_t i = 0; i < MVHD_MATRIX_OFFSET; i++) {
        writer.Write32(matrix_[i]);
    }
    for (uint32_t i = 0; i < MVHD_PREDEFINED_OFFSET; i++) {
        writer.Write32(preDefined_[i]);
    }
    writer.Write32(nextTrackId_);
    WriteCalculatedHeader(writer, boxStart);
    return heif_error_ok;
}

heif_error HeifTrakBox::ParseContentChildren(HeifStreamReader &reader, uint32_t &recursionCount)
{
    return ParseContentChildrenByReadChildren(reader, recursionCount);
}

heif_error HeifTkhdBox::ParseContent(HeifStreamReader &reader)
{
    ParseFullHeader(reader);
    if (GetVersion() == HEIF_BOX_VERSION_ONE) {
        creationTime_ = reader.Read64();
        modificationTime_ = reader.Read64();
        trackId_ = reader.Read32();
        reserved1_ = reader.Read32();
        duration_ = reader.Read64();
    } else {
        creationTime_ = reader.Read32();
        modificationTime_ = reader.Read32();
        trackId_ = reader.Read32();
        reserved1_ = reader.Read32();
        duration_ = reader.Read32();
    }
    reserved2_[RESERVERED_INDEX_ZERO] = reader.Read32();
    reserved2_[RESERVERED_INDEX_ONE] = reader.Read32();
    layer_ = reader.Read16();
    alternateGroup_ = reader.Read16();
    volume_ = reader.Read16();
    reserved3_ = reader.Read16();
    for (uint32_t i = 0; i < TKHD_MATRIX_OFFSET; i++) {
        matrix_[i] = reader.Read32();
    }
    width_ = reader.Read32();
    height_ = reader.Read32();
    return reader.GetError();
}

heif_error HeifTkhdBox::Write(HeifStreamWriter &writer) const
{
    size_t boxStart = ReserveHeader(writer);
    if (GetVersion() == HEIF_BOX_VERSION_ONE) {
        writer.Write64(creationTime_);
        writer.Write64(modificationTime_);
        writer.Write32(trackId_);
        writer.Write32(reserved1_);
        writer.Write64(duration_);
    } else {
        writer.Write32(creationTime_);
        writer.Write32(modificationTime_);
        writer.Write32(trackId_);
        writer.Write32(reserved1_);
        writer.Write32(duration_);
    }
    writer.Write32(reserved2_[RESERVERED_INDEX_ZERO]);
    writer.Write32(reserved2_[RESERVERED_INDEX_ONE]);
    writer.Write16(layer_);
    writer.Write16(alternateGroup_);
    writer.Write16(volume_);
    writer.Write16(reserved3_);
    for (uint32_t i = 0; i < TKHD_MATRIX_OFFSET; i++) {
        writer.Write32(matrix_[i]);
    }
    writer.Write32(width_);
    writer.Write32(height_);

    WriteCalculatedHeader(writer, boxStart);
    return heif_error_ok;
}

heif_error HeifMdiaBox::ParseContentChildren(HeifStreamReader &reader, uint32_t &recursionCount)
{
    return ParseContentChildrenByReadChildren(reader, recursionCount);
}

heif_error HeifMdhdBox::ParseContent(HeifStreamReader &reader)
{
    ParseFullHeader(reader);
    if (GetVersion() == HEIF_BOX_VERSION_ONE) {
        creationTime_ = reader.Read64();
        modificationTime_ = reader.Read64();
        timescale_ = reader.Read32();
        duration_ = reader.Read64();
    } else {
        creationTime_ = reader.Read32();
        modificationTime_ = reader.Read32();
        timescale_ = reader.Read32();
        duration_ = reader.Read32();
    }
    language_ = reader.Read16();
    preDefined_ = reader.Read16();
    return reader.GetError();
}

heif_error HeifMdhdBox::Write(HeifStreamWriter &writer) const
{
    size_t boxStart = ReserveHeader(writer);
    if (GetVersion() == HEIF_BOX_VERSION_ONE) {
        writer.Write64(creationTime_);
        writer.Write64(modificationTime_);
        writer.Write32(timescale_);
        writer.Write64(duration_);
    } else {
        writer.Write32(creationTime_);
        writer.Write32(modificationTime_);
        writer.Write32(timescale_);
        writer.Write32(duration_);
    }
    writer.Write16(language_);
    writer.Write16(preDefined_);
    WriteCalculatedHeader(writer, boxStart);
    return heif_error_ok;
}

heif_error HeifMinfBox::ParseContentChildren(HeifStreamReader &reader, uint32_t &recursionCount)
{
    return ParseContentChildrenByReadChildren(reader, recursionCount);
}

heif_error HeifVmhdBox::ParseContent(HeifStreamReader &reader)
{
    ParseFullHeader(reader);
    graphicsMode_ = reader.Read16();
    for (uint32_t i = 0; i < VMHD_OPCOLOR_OFFSET; i++) {
        opColor_[i] = reader.Read16();
    }
    return reader.GetError();
}

heif_error HeifVmhdBox::Write(HeifStreamWriter &writer) const
{
    size_t boxStart = ReserveHeader(writer);
    writer.Write16(graphicsMode_);
    for (uint32_t  i = 0; i < VMHD_OPCOLOR_OFFSET; i++) {
        writer.Write16(opColor_[i]);
    }
    WriteCalculatedHeader(writer, boxStart);
    return heif_error_ok;
}

heif_error HeifDinfBox::ParseContentChildren(HeifStreamReader &reader, uint32_t &recursionCount)
{
    return ParseContentChildrenByReadChildren(reader, recursionCount);
}

heif_error HeifDrefBox::ParseContent(HeifStreamReader &reader)
{
    ParseFullHeader(reader);
    entryCount_ = reader.Read32();
    if (entryCount_ > MAX_DREF_ENTRYCOUNT) {
        return heif_error_invalid_dref;
    }
    for (uint32_t i = 0; i < entryCount_; i++) {
        uint32_t recursionCount = 0;
        std::shared_ptr<HeifBox> entry;
        heif_error error = HeifBox::MakeFromReader(reader, &entry, recursionCount);
        if (error != heif_error_ok) {
            return error;
        }
        entries_.push_back(entry);
    }
    return reader.GetError();
}

heif_error HeifDrefBox::Write(HeifStreamWriter &writer) const
{
    size_t boxStart = ReserveHeader(writer);
    writer.Write32(entryCount_);
    for (const auto& entry : entries_) {
        entry->Write(writer);
    }
    WriteCalculatedHeader(writer, boxStart);
    return heif_error_ok;
}

heif_error HeifStblBox::ParseContentChildren(HeifStreamReader &reader, uint32_t &recursionCount)
{
    return ParseContentChildrenByReadChildren(reader, recursionCount);
}

heif_error HeifStsdBox::ParseContent(HeifStreamReader &reader)
{
    ParseFullHeader(reader);
    entryCount_ = reader.Read32();
    if (entryCount_ > MAX_STSD_ENTRYCOUNT) {
        return heif_error_invalid_stsd;
    }
    for (uint32_t i = 0; i < entryCount_; i++) {
        uint32_t recursionCount = 0;
        std::shared_ptr<HeifBox> entry;
        heif_error error = HeifBox::MakeFromReader(reader, &entry, recursionCount);
        if (error != heif_error_ok) {
            return error;
        }
        entries_.push_back(entry);
    }
    return reader.GetError();
}

heif_error HeifStsdBox::GetSampleEntryWidthHeight(uint32_t index, uint32_t &width, uint32_t &height)
{
    if (index >= entries_.size()) {
        return heif_error_invalid_index;
    }
    if (entries_[index] && entries_[index]->GetBoxType() == BOX_TYPE_HVC1) {
        auto hvc1Entry = std::dynamic_pointer_cast<HeifHvc1Box>(entries_[index]);
        width = hvc1Entry->GetWidth();
        height = hvc1Entry->GetHeight();
    }
    return heif_error_ok;
}

std::shared_ptr<HeifBox> HeifStsdBox::GetHvccBox(uint32_t index)
{
    if (index >= entries_.size()) {
        return nullptr;
    }
    if (entries_[index] && entries_[index]->GetBoxType() == BOX_TYPE_HVC1) {
        auto hvc1Entry = std::dynamic_pointer_cast<HeifHvc1Box>(entries_[index]);
        return hvc1Entry->GetHvccBox();
    }
    return nullptr;
}

heif_error HeifStsdBox::Write(HeifStreamWriter &writer) const
{
    size_t boxStart = ReserveHeader(writer);
    writer.Write32(entryCount_);
    for (const auto& entry : entries_) {
        entry->Write(writer);
    }
    WriteCalculatedHeader(writer, boxStart);
    return heif_error_ok;
}

heif_error HeifSttsBox::ParseContent(HeifStreamReader &reader)
{
    ParseFullHeader(reader);
    entryCount_ = reader.Read32();
    if (entryCount_ > MAX_STTS_ENTRYCOUNT) {
        return heif_error_invalid_stts;
    }
    for (uint32_t i = 0; i < entryCount_; i++) {
        TimeToSampleEntry entry;
        entry.sampleCount = reader.Read32();
        entry.sampleDelta = reader.Read32();
        entries_.push_back(entry);
    }
    return reader.GetError();
}

heif_error HeifSttsBox::Write(HeifStreamWriter &writer) const
{
    size_t boxStart = ReserveHeader(writer);
    writer.Write32(entryCount_);
    for (const auto& entry : entries_) {
        writer.Write32(entry.sampleCount);
        writer.Write32(entry.sampleDelta);
    }
    WriteCalculatedHeader(writer, boxStart);
    return heif_error_ok;
}

heif_error HeifSttsBox::GetDelayTime(uint32_t index, int32_t &value) const
{
    if (entries_.empty()) {
        return heif_error_invalid_stts;
    }
    uint32_t preCount = 0;
    for (const auto &entry : entries_) {
        preCount += entry.sampleCount;
        if (index < preCount) {
            value = entry.sampleDelta;
            return heif_error_ok;
        }
    }
    return heif_error_invalid_stts;
}

heif_error HeifStscBox::ParseContent(HeifStreamReader &reader)
{
    ParseFullHeader(reader);
    entryCount_ = reader.Read32();
    if (entryCount_ > MAX_STSC_ENTRYCOUNT) {
        return heif_error_invalid_stsc;
    }
    for (uint32_t i = 0; i < entryCount_; i++) {
        SampleToChunkEntry entry;
        entry.firstChunk = reader.Read32();
        entry.samplesPerChunk = reader.Read32();
        entry.sampleDescriptionIndex = reader.Read32();
        entries_.push_back(entry);
    }
    return reader.GetError();
}

heif_error HeifStscBox::Write(HeifStreamWriter &writer) const
{
    size_t boxStart = ReserveHeader(writer);
    writer.Write32(entryCount_);
    for (const auto& entry : entries_) {
        writer.Write32(entry.firstChunk);
        writer.Write32(entry.samplesPerChunk);
        writer.Write32(entry.sampleDescriptionIndex);
    }
    WriteCalculatedHeader(writer, boxStart);
    return heif_error_ok;
}

heif_error HeifStcoBox::ParseContent(HeifStreamReader &reader)
{
    ParseFullHeader(reader);
    entryCount_ = reader.Read32();
    if (entryCount_ > MAX_STCO_ENTRYCOUNT) {
        return heif_error_invalid_stco;
    }
    for (uint32_t i = 0; i < entryCount_; i++) {
        chunkOffsets_.push_back(reader.Read32());
    }
    return reader.GetError();
}

heif_error HeifStcoBox::GetChunkOffset(uint32_t chunkIndex, uint32_t &chunkOffset)
{
    if (chunkIndex >= chunkOffsets_.size()) {
        return heif_error_invalid_index;
    }
    chunkOffset = chunkOffsets_[chunkIndex];
    return heif_error_ok;
}

heif_error HeifStcoBox::Write(HeifStreamWriter &writer) const
{
    size_t boxStart = ReserveHeader(writer);
    writer.Write32(entryCount_);
    for (uint32_t offset : chunkOffsets_) {
        writer.Write32(offset);
    }
    WriteCalculatedHeader(writer, boxStart);
    return heif_error_ok;
}

heif_error HeifStszBox::ParseContent(HeifStreamReader &reader)
{
    ParseFullHeader(reader);
    sampleSize_ = reader.Read32();
    sampleCount_ = reader.Read32();
    if (sampleSize_ == 0) {
        for (uint32_t i = 0; i < sampleCount_; i++) {
            entrySizes_.push_back(reader.Read32());
        }
    }
    return reader.GetError();
}

uint32_t HeifStszBox::GetSampleCount()
{
    return sampleCount_;
}

heif_error HeifStszBox::GetSampleSize(uint32_t sampleIndex, uint32_t &sampleSize)
{
    if (sampleIndex >= entrySizes_.size()) {
        return heif_error_invalid_index;
    }
    sampleSize = entrySizes_[sampleIndex];
    return heif_error_ok;
}

heif_error HeifStszBox::Write(HeifStreamWriter &writer) const
{
    size_t boxStart = ReserveHeader(writer);
    writer.Write32(sampleSize_);
    writer.Write32(sampleCount_);
    if (sampleSize_ == 0) {
        for (uint32_t size : entrySizes_) {
            writer.Write32(size);
        }
    }
    WriteCalculatedHeader(writer, boxStart);
    return heif_error_ok;
}

heif_error HeifStssBox::GetSampleNumbers(std::vector<uint32_t> &sampleNumbers)
{
    if (sampleNumbers_.empty()) {
        return heif_error_invalid_stss;
    }
    if (!isStrictlyIncreasing(sampleNumbers_)) {
        sampleNumbers_.clear();
        sampleNumbers_.shrink_to_fit();
        return heif_error_invalid_stss;
    }
    sampleNumbers = sampleNumbers_;
    return heif_error_ok;
}

heif_error HeifStssBox::Write(HeifStreamWriter &writer) const
{
    size_t boxStart = ReserveHeader(writer);
    writer.Write32(entryCount_);
    for (uint32_t number : sampleNumbers_) {
        writer.Write32(number);
    }
    WriteCalculatedHeader(writer, boxStart);
    return heif_error_ok;
}

heif_error HeifStssBox::ParseContent(HeifStreamReader &reader)
{
    ParseFullHeader(reader);
    entryCount_ = reader.Read32();
    if (entryCount_ > MAX_STSS_ENTRYCOUNT) {
        return heif_error_invalid_stss;
    }
    for (uint32_t i = 0; i < entryCount_; i++) {
        sampleNumbers_.push_back(reader.Read32());
    }
    return reader.GetError();
}

heif_error HeifHvc1Box::ParseContent(HeifStreamReader &reader)
{
    for (uint32_t i = 0; i < HVC1_RESERVED_OFFSET; i++) {
        reserved_[i] = reader.Read8();
    }
    dataRefIndex_ = reader.Read16();
    for (uint32_t i = 0; i < HVC1_PREDEFINE_OFFSET; i++) {
        reader.Read8();
    }
    width_ = reader.Read16();
    height_ = reader.Read16();
    for (uint32_t i = 0; i < HVC1_SKIP_OFFSET; i++) {
        reader.Read8();
    }
    uint32_t recursionCount = 0;
    heif_error error = HeifBox::MakeFromReader(reader, &hvccBox_, recursionCount);
    if (error != heif_error_ok) {
        return error;
    }
    return reader.GetError();
}
} // namespace ImagePlugin
} // namespace OHOS
