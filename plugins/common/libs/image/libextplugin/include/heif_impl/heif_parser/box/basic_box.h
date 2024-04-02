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

#ifndef PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_BASIC_BOX_H
#define PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_BASIC_BOX_H

#include "box/heif_box.h"

namespace OHOS {
namespace ImagePlugin {
class HeifFtypBox : public HeifBox {
public:
    HeifFtypBox() : HeifBox(BOX_TYPE_FTYP) {}

    heif_error Write(HeifStreamWriter &writer) const override;
protected:
    heif_error ParseContent(HeifStreamReader &reader) override;

private:
    uint32_t majorBrand_ = 0;
    uint32_t minorVersion_ = 0;
    std::vector<heif_brand> compatibleBrands_;
};

class HeifMetaBox : public HeifFullBox {
public:
    HeifMetaBox() : HeifFullBox(BOX_TYPE_META) {}

protected:
    heif_error ParseContent(HeifStreamReader &reader) override;
};

class HeifHdlrBox : public HeifFullBox {
public:
    HeifHdlrBox() : HeifFullBox(BOX_TYPE_HDLR) {}

    uint32_t GetHandlerType() const { return handlerType_; }

    heif_error Write(HeifStreamWriter &writer) const override;

protected:
    heif_error ParseContent(HeifStreamReader &reader) override;

private:
    uint32_t isPreDefined_ = 0;
    uint32_t handlerType_ = HANDLER_TYPE_PICT;
    static const uint8_t HDLR_BOX_RESERVED_SIZE = 3;
    uint32_t reserved_[HDLR_BOX_RESERVED_SIZE] = {0};
    std::string name_;
};
} // namespace ImagePlugin
} // namespace OHOS

#endif // PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_BASIC_BOX_H
