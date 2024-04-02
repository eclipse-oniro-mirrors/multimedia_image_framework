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

#ifndef PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_ITEM_PROPERTY_TRANSFORM_BOX_H
#define PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_ITEM_PROPERTY_TRANSFORM_BOX_H

#include "box/heif_box.h"

namespace OHOS {
namespace ImagePlugin {
class HeifIrotBox : public HeifBox {
public:
    HeifIrotBox() : HeifBox(BOX_TYPE_IROT) {}

    int GetRotDegree() const { return rotDegree_; }

    void SetRotDegree(int rot) { rotDegree_ = rot; }

protected:
    heif_error ParseContent(HeifStreamReader &reader) override;

    heif_error Write(HeifStreamWriter &writer) const override;

private:
    int rotDegree_ = 0;
};

class HeifImirBox : public HeifBox {
public:
    HeifImirBox() : HeifBox(BOX_TYPE_IMIR) {}

    HeifTransformMirrorDirection GetDirection() const { return direction_; }

    void SetDirection(HeifTransformMirrorDirection dir) { direction_ = dir; }

protected:
    heif_error ParseContent(HeifStreamReader &reader) override;

    heif_error Write(HeifStreamWriter &writer) const override;

private:
    HeifTransformMirrorDirection direction_ = HeifTransformMirrorDirection::VERTICAL;
};
} // namespace ImagePlugin
} // namespace OHOS

#endif // PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_ITEM_PROPERTY_TRANSFORM_BOX_H
