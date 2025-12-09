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

#ifndef PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_ITEM_MOVIE_BOX_H
#define PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_ITEM_MOVIE_BOX_H

#include "box/heif_box.h"

namespace OHOS {
namespace ImagePlugin {
class HeifMoovBox : public HeifBox {
public:
    HeifMoovBox() : HeifBox(BOX_TYPE_MOOV) {}

protected:
    heif_error ParseContentChildren(HeifStreamReader &reader, uint32_t &recursionCount) override;
};

class HeifMvhdBox : public HeifFullBox {
public:
    HeifMvhdBox() : HeifFullBox(BOX_TYPE_MVHD) {}

    uint64_t GetDuration() const { return duration_; }
    uint32_t GetTimescale() const { return timescale_; }

    heif_error Write(HeifStreamWriter &writer) const override;
protected:
    heif_error ParseContent(HeifStreamReader &reader) override;
private:
    static constexpr uint32_t RESERVED_SIZE = 2;
    static constexpr uint32_t MATRIX_SIZE = 9;
    static constexpr uint32_t PREDEFINED_SIZE = 6;
    uint64_t creationTime_ = 0;
    uint64_t modificationTime_ = 0;
    uint32_t timescale_ = 0;
    uint64_t duration_ = 0;
    uint32_t rate_ = 0;
    uint16_t volume_ = 0;
    uint16_t reserved_ = 0;
    uint32_t reserved2_[RESERVED_SIZE] = {0};
    uint32_t matrix_[MATRIX_SIZE] = {0};
    uint32_t preDefined_[PREDEFINED_SIZE] = {0};
    uint32_t nextTrackId_ = 0;
};

class HeifTrakBox : public HeifBox {
public:
    HeifTrakBox() : HeifBox(BOX_TYPE_TRAK) {}

protected:
    heif_error ParseContentChildren(HeifStreamReader &reader, uint32_t &recursionCount) override;
};

class HeifTkhdBox : public HeifFullBox {
public:
    HeifTkhdBox() : HeifFullBox(BOX_TYPE_TKHD) {}

    heif_error Write(HeifStreamWriter &writer) const override;
protected:
    heif_error ParseContent(HeifStreamReader &reader) override;
private:
    static constexpr uint32_t RESERVED_SIZE = 2;
    static constexpr uint32_t MATRIX_SIZE = 9;
    uint64_t creationTime_ = 0;
    uint64_t modificationTime_ = 0;
    uint32_t trackId_ = 0;
    uint32_t reserved1_ = 0;
    uint64_t duration_ = 0;
    uint32_t reserved2_[RESERVED_SIZE] = {0};
    uint16_t layer_ = 0;
    uint16_t alternateGroup_ = 0;
    uint16_t volume_ = 0;
    uint16_t reserved3_ = 0;
    uint32_t matrix_[MATRIX_SIZE] = {0};
    uint32_t width_ = 0;
    uint32_t height_ = 0;
};

class HeifMdiaBox : public HeifBox {
public:
    HeifMdiaBox() : HeifBox(BOX_TYPE_MDIA) {}
protected:
    heif_error ParseContentChildren(HeifStreamReader &reader, uint32_t &recursionCount) override;
};

class HeifMdhdBox : public HeifFullBox {
public:
    HeifMdhdBox() : HeifFullBox(BOX_TYPE_MDHD) {}

    heif_error Write(HeifStreamWriter &writer) const override;
protected:
    heif_error ParseContent(HeifStreamReader &reader) override;
private:
    uint64_t creationTime_ = 0;
    uint64_t modificationTime_ = 0;
    uint32_t timescale_ = 0;
    uint64_t duration_ = 0;
    uint16_t language_ = 0;
    uint16_t preDefined_ = 0;
};

class HeifMinfBox : public HeifBox {
public:
    HeifMinfBox() : HeifBox(BOX_TYPE_MINF) {}
protected:
    heif_error ParseContentChildren(HeifStreamReader &reader, uint32_t &recursionCount) override;
};

class HeifVmhdBox : public HeifFullBox {
public:
    HeifVmhdBox() : HeifFullBox(BOX_TYPE_VMHD) {}

    heif_error Write(HeifStreamWriter &writer) const override;
protected:
    heif_error ParseContent(HeifStreamReader &reader) override;
private:
    static constexpr uint32_t OPCOLOR_SIZE = 3;
    uint16_t graphicsMode_ = 0;
    uint16_t opColor_[OPCOLOR_SIZE] = {0, 0, 0};
};

class HeifDinfBox : public HeifBox {
public:
    HeifDinfBox() : HeifBox(BOX_TYPE_DINF) {}
protected:
    heif_error ParseContentChildren(HeifStreamReader &reader, uint32_t &recursionCount) override;
};

class HeifDrefBox : public HeifFullBox {
public:
    HeifDrefBox() : HeifFullBox(BOX_TYPE_DREF) {}

    heif_error Write(HeifStreamWriter &writer) const override;
protected:
    heif_error ParseContent(HeifStreamReader &reader) override;
private:
    uint32_t entryCount_ = 0;
    std::vector<std::shared_ptr<HeifBox>> entries_;
};

class HeifStblBox : public HeifBox {
public:
    HeifStblBox() : HeifBox(BOX_TYPE_STBL) {}
protected:
    heif_error ParseContentChildren(HeifStreamReader &reader, uint32_t &recursionCount) override;
};

class HeifStsdBox : public HeifFullBox {
public:
    HeifStsdBox() : HeifFullBox(BOX_TYPE_STSD) {}

    heif_error Write(HeifStreamWriter &writer) const override;
    heif_error GetSampleEntryWidthHeight(uint32_t index, uint32_t &width, uint32_t &height);
    std::shared_ptr<HeifBox> GetHvccBox(uint32_t index);
protected:
    heif_error ParseContent(HeifStreamReader &reader) override;
private:
    uint32_t entryCount_ = 0;
    std::vector<std::shared_ptr<HeifBox>> entries_;
};

class HeifSttsBox : public HeifFullBox {
public:
    HeifSttsBox() : HeifFullBox(BOX_TYPE_STTS) {}

    heif_error Write(HeifStreamWriter &writer) const override;

    heif_error GetDelayTime(uint32_t index, int32_t &value) const;
protected:
    heif_error ParseContent(HeifStreamReader &reader) override;
private:
    struct TimeToSampleEntry {
        uint32_t sampleCount;
        uint32_t sampleDelta;
    };

    uint32_t entryCount_ = 0;
    std::vector<TimeToSampleEntry> entries_;
};

class HeifStscBox : public HeifFullBox {
public:
    HeifStscBox() : HeifFullBox(BOX_TYPE_STSC) {}

    heif_error Write(HeifStreamWriter &writer) const override;
protected:
    heif_error ParseContent(HeifStreamReader &reader) override;
private:
    struct SampleToChunkEntry {
        uint32_t firstChunk;
        uint32_t samplesPerChunk;
        uint32_t sampleDescriptionIndex;
    };

    uint32_t entryCount_ = 0;
    std::vector<SampleToChunkEntry> entries_;
};

class HeifStcoBox : public HeifFullBox {
public:
    HeifStcoBox() : HeifFullBox(BOX_TYPE_STCO) {}

    heif_error GetChunkOffset(uint32_t chunkIndex, uint32_t &chunkOffset);
    heif_error Write(HeifStreamWriter &writer) const override;
protected:
    heif_error ParseContent(HeifStreamReader &reader) override;
private:
    uint32_t entryCount_ = 0;
    std::vector<uint32_t> chunkOffsets_;
};

class HeifStszBox : public HeifFullBox {
public:
    HeifStszBox() : HeifFullBox(BOX_TYPE_STSZ) {}

    heif_error GetSampleSize(uint32_t sampleIndex, uint32_t &sampleSize);
    uint32_t GetSampleCount();
    heif_error Write(HeifStreamWriter &writer) const override;
protected:
    heif_error ParseContent(HeifStreamReader &reader) override;
private:
    uint32_t sampleSize_ = 0;
    uint32_t sampleCount_ = 0;
    std::vector<uint32_t> entrySizes_;
};

class HeifStssBox : public HeifFullBox {
public:
    HeifStssBox() : HeifFullBox(BOX_TYPE_STSS) {}

    heif_error GetSampleNumbers(std::vector<uint32_t> &sampleNumber);
    heif_error Write(HeifStreamWriter &writer) const override;
protected:
    heif_error ParseContent(HeifStreamReader &reader) override;
private:
    uint32_t entryCount_ = 0;
    std::vector<uint32_t> sampleNumbers_;
};

class HeifHvc1Box : public HeifBox {
public:
    HeifHvc1Box() : HeifBox(BOX_TYPE_HVC1) {}

    uint32_t GetWidth() { return width_; }
    uint32_t GetHeight() { return height_; }
    std::shared_ptr<HeifBox> GetHvccBox() { return hvccBox_; }
protected:
    heif_error ParseContent(HeifStreamReader &reader) override;
private:
    static constexpr uint32_t RESERVED_SIZE = 6;
    uint8_t reserved_[RESERVED_SIZE];
    uint32_t width_ = 0;
    uint32_t height_ = 0;
    std::shared_ptr<HeifBox> hvccBox_;
};
} // namespace ImagePlugin
} // namespace OHOS

#endif // PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_ITEM_MOVIE_BOX_H
