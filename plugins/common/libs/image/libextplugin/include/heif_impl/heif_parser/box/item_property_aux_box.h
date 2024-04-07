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

#ifndef PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_ITEM_AUX_BOX_H
#define PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_ITEM_AUX_BOX_H

#include "box/heif_box.h"

namespace OHOS {
namespace ImagePlugin {
class HeifAuxcBox : public HeifFullBox {
public:
    HeifAuxcBox() : HeifFullBox(BOX_TYPE_AUXC) {}

    const std::string &GetAuxType() const { return auxType_; }

    void SetAuxType(const std::string &type) { auxType_ = type; }

    const std::vector<uint8_t> &GetAuxSubtypes() const { return auxSubtypes_; }

protected:
    heif_error ParseContent(HeifStreamReader &reader) override;

    heif_error Write(HeifStreamWriter &writer) const override;

private:
    std::string auxType_;
    std::vector<uint8_t> auxSubtypes_;
};
} // namespace ImagePlugin
} // namespace OHOS

#endif // PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_ITEM_AUX_BOX_H
