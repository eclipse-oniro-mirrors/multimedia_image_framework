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

#ifndef PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_ITEM_PROPERTY_BASIC_BOX_H
#define PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_ITEM_PROPERTY_BASIC_BOX_H

#include "box/heif_box.h"

namespace OHOS {
namespace ImagePlugin {
class HeifIspeBox : public HeifFullBox {
public:
    HeifIspeBox() : HeifFullBox(BOX_TYPE_ISPE) {}

    uint32_t GetWidth() const { return width_; }

    uint32_t GetHeight() const { return height_; }

    void SetDimension(uint32_t width, uint32_t height)
    {
        width_ = width;
        height_ = height;
    }

    heif_error Write(HeifStreamWriter &writer) const override;

protected:
    heif_error ParseContent(HeifStreamReader &reader) override;

private:
    uint32_t width_ = 0;
    uint32_t height_ = 0;
};

class HeifPixiBox : public HeifFullBox {
public:
    HeifPixiBox() : HeifFullBox(BOX_TYPE_PIXI) {}

    int GetChannelNum() const { return (int) bitNums_.size(); }

    int GetBitNum(int channel) const { return bitNums_[channel]; }

    void AddBitNum(uint8_t c)
    {
        bitNums_.push_back(c);
    }

    heif_error Write(HeifStreamWriter &writer) const override;

protected:
    heif_error ParseContent(HeifStreamReader &reader) override;

private:
    std::vector<uint8_t> bitNums_;
};

class HeifRlocBox : public HeifFullBox {
public:
    HeifRlocBox() : HeifFullBox(BOX_TYPE_RLOC) {}

    uint32_t GetX() const { return horizontalOffset_; }

    uint32_t GetY() const { return verticalOffset_; }

    void SetLocation(const uint32_t horizontalOffset, const uint32_t verticalOffset)
    {
        horizontalOffset_ = horizontalOffset;
        verticalOffset_ = verticalOffset;
    }

    heif_error Write(HeifStreamWriter &writer) const override;

protected:
    heif_error ParseContent(HeifStreamReader &reader) override;

private:
    uint32_t horizontalOffset_ = 0;
    uint32_t verticalOffset_ = 0;
};

// ISO/IEC 23000-22 CodingConstraintsBox. The three fields share a single 32 bit word, so the raw
// value is kept as well and the reserved bits are written back untouched.
class HeifCcstBox : public HeifFullBox {
public:
    HeifCcstBox() : HeifFullBox(BOX_TYPE_CCST) {}

    bool GetAllRefPicsIntra() const { return (codingConstraints_ & ALL_REF_PICS_INTRA_FLAG) != 0; }

    bool GetIntraPredUsed() const { return (codingConstraints_ & INTRA_PRED_USED_FLAG) != 0; }

    uint8_t GetMaxRefPerPic() const
    {
        return static_cast<uint8_t>((codingConstraints_ >> MAX_REF_PER_PIC_SHIFT) & MAX_REF_PER_PIC_MASK);
    }

    uint32_t GetCodingConstraints() const { return codingConstraints_; }

    void SetCodingConstraints(uint32_t codingConstraints) { codingConstraints_ = codingConstraints; }

    void SetCodingConstraints(bool allRefPicsIntra, bool intraPredUsed, uint8_t maxRefPerPic);

    heif_error Write(HeifStreamWriter &writer) const override;

protected:
    heif_error ParseContent(HeifStreamReader &reader) override;

private:
    static constexpr uint32_t ALL_REF_PICS_INTRA_FLAG = 0x80000000;
    static constexpr uint32_t INTRA_PRED_USED_FLAG = 0x40000000;
    static constexpr uint8_t MAX_REF_PER_PIC_SHIFT = 2;
    static constexpr uint32_t MAX_REF_PER_PIC_MASK = 0x0F;
    static constexpr uint8_t MAX_REF_PER_PIC_LIMIT = 15;

    uint32_t codingConstraints_ = 0;
};
} // namespace ImagePlugin
} // namespace OHOS

#endif // PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_ITEM_PROPERTY_BASIC_BOX_H
