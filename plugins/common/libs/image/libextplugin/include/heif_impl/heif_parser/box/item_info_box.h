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

#ifndef PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_ITEM_INFO_BOX_H
#define PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_ITEM_INFO_BOX_H

#include "box/heif_box.h"

namespace OHOS {
namespace ImagePlugin {
class HeifIinfBox : public HeifFullBox {
public:
    HeifIinfBox() : HeifFullBox(BOX_TYPE_IINF) {}

    void InferFullBoxVersion() override;

    heif_error Write(HeifStreamWriter &writer) const override;
protected:
    heif_error ParseContent(HeifStreamReader &reader) override;
};

class HeifInfeBox : public HeifFullBox {
public:
    HeifInfeBox() : HeifFullBox(BOX_TYPE_INFE) {}

    HeifInfeBox(heif_item_id id, const char *itemType, bool isHidden) : HeifFullBox(BOX_TYPE_INFE),
                                                                        itemId_(id), itemType_(itemType),
                                                                        isHidden_(isHidden) {};

    bool IsHidden() const { return isHidden_; }

    void SetHidden(bool hidden);

    heif_item_id GetItemId() const { return itemId_; }

    void SetItemId(heif_item_id id) { itemId_ = id; }

    const std::string &GetItemType() const { return itemType_; }

    void SetItemType(const std::string &type) { itemType_ = type; }

    void SetItemName(const std::string &name) { itemName_ = name; }

    const std::string &GetContentType() const { return contentType_; }

    const std::string &GetContentEncoding() const { return contentEncoding_; }

    void SetContentType(const std::string &content_type) { contentType_ = content_type; }

    void SetContentEncoding(const std::string &content_encoding) { contentEncoding_ = content_encoding; }

    void InferFullBoxVersion() override;

    heif_error Write(HeifStreamWriter &writer) const override;

    const std::string &GetItemUriType() const { return itemUriType_; }
protected:
    heif_error ParseContent(HeifStreamReader &reader) override;

private:
    heif_item_id itemId_ = 0;
    uint16_t itemProtectionIndex_ = 0;

    std::string itemType_;
    std::string itemName_;
    std::string contentType_;
    std::string contentEncoding_;
    std::string itemUriType_;

    bool isHidden_ = false;
};

class HeifPtimBox : public HeifFullBox {
public:
    HeifPtimBox() : HeifFullBox(BOX_TYPE_PTIM) {}

    heif_item_id GetItemId() const { return itemId_; }

    void SetItemId(heif_item_id id) { itemId_ = id; }

    void InferFullBoxVersion() override;

    heif_error Write(HeifStreamWriter &writer) const override;

protected:
    heif_error ParseContent(HeifStreamReader &reader) override;

private:
    heif_item_id itemId_ = 0;
};
} // namespace ImagePlugin
} // namespace OHOS

#endif // PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_ITEM_INFO_BOX_H
