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

#ifndef PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_ITEM_DATA_BOX_H
#define PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_ITEM_DATA_BOX_H

#include "box/heif_box.h"

namespace OHOS {
namespace ImagePlugin {
class HeifIlocBox : public HeifFullBox {
public:
    HeifIlocBox() : HeifFullBox(BOX_TYPE_ILOC) {}

    struct Extent {
        uint64_t index = 0;
        uint64_t length = 0;
        uint64_t offset = 0;
        std::vector<uint8_t> data;
    };

    struct Item {
        heif_item_id itemId = 0;
        uint8_t constructionMethod = 0;
        uint16_t dataReferenceIndex = 0;
        uint64_t baseOffset = 0;
        std::vector<Extent> extents;

        size_t GetExtentsTotalSize() const
        {
            size_t total = 0;
            for (auto &extent: extents) {
                total += extent.data.size();
            }
            return total;
        };
    };

    const std::vector<Item> &GetItems() const { return items_; }

    heif_error ReadData(const Item &item,
                    const std::shared_ptr<HeifInputStream> &stream,
                    const std::shared_ptr<class HeifIdatBox> &idat,
                    std::vector<uint8_t> *dest) const;

    heif_error AppendData(heif_item_id itemId,
                     const std::vector<uint8_t> &data,
                     uint8_t constructionMethod = 0);

    heif_error UpdateData(heif_item_id itemID, const std::vector<uint8_t> &data, uint8_t constructionMethod);

    void InferFullBoxVersion() override;

    heif_error Write(HeifStreamWriter &writer) const override;

    heif_error WriteMdatBox(HeifStreamWriter &writer);

    heif_error ReadToExtentData(Item &item, const std::shared_ptr<HeifInputStream> &stream,
                                const std::shared_ptr<HeifIdatBox> &idatBox);

protected:
    heif_error ParseContent(HeifStreamReader &reader) override;

private:
    std::vector<Item> items_;

    mutable size_t startPos_ = 0;
    uint8_t offsetSize_ = 0;
    uint8_t lengthSize_ = 0;
    uint8_t baseOffsetSize_ = 0;
    uint8_t indexSize_ = 0;
    void ParseExtents(Item& item, HeifStreamReader &reader, int indexSize, int offsetSize, int lengthSize);
    void PackIlocHeader(HeifStreamWriter &writer) const;

    uint64_t idatOffset_ = 0;
};

class HeifIdatBox : public HeifBox {
public:
    heif_error ReadData(const std::shared_ptr<HeifInputStream> &stream,
                    uint64_t start, uint64_t length,
                    std::vector<uint8_t> &outData) const;

    int AppendData(const std::vector<uint8_t> &data)
    {
        auto pos = dataForWriting_.size();

        dataForWriting_.insert(dataForWriting_.end(),
                               data.begin(),
                               data.end());

        return (int) pos;
    }

    heif_error Write(HeifStreamWriter &writer) const override;

protected:
    heif_error ParseContent(HeifStreamReader &reader) override;

    std::streampos startPos_;

    std::vector<uint8_t> dataForWriting_;
};
} // namespace ImagePlugin
} // namespace OHOS

#endif // PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_ITEM_DATA_BOX_H
