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
} // namespace ImagePlugin
} // namespace OHOS

#endif // PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_ITEM_PROPERTY_BASIC_BOX_H
