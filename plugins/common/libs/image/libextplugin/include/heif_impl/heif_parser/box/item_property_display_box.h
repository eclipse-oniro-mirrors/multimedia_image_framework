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

#ifndef PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_ITEM_PROPERTY_DISPLAY_BOX_H
#define PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_ITEM_PROPERTY_DISPLAY_BOX_H

#include "box/heif_box.h"

namespace OHOS {
namespace ImagePlugin {

typedef struct {
    uint16_t x;
    uint16_t y;
} DisplayPrimariesXY;

typedef struct {
    DisplayPrimariesXY red;
    DisplayPrimariesXY green;
    DisplayPrimariesXY blue;
    DisplayPrimariesXY whitePoint;
    uint32_t luminanceMax;
    uint32_t luminanceMin;
} DisplayColourVolume;

typedef struct {
    uint16_t maxContentLightLevel;
    uint16_t maxPicAverageLightLevel;
} ContentLightLevelInfo;


class HeifMdcvBox : public HeifBox {
public:
    HeifMdcvBox() : HeifBox(BOX_TYPE_MDCV) {}

    DisplayColourVolume GetColourVolume() const { return colourVolume_; };

    void SetColourVolume(DisplayColourVolume colourVolume) { colourVolume_ = colourVolume; };
protected:
    heif_error ParseContent(HeifStreamReader &reader) override;

    heif_error Write(HeifStreamWriter &writer) const override;

private:
    DisplayColourVolume colourVolume_{};
};

class HeifClliBox : public HeifBox {
public:
    HeifClliBox() : HeifBox(BOX_TYPE_CLLI) {}

    ContentLightLevelInfo GetLightLevel() const { return lightLevel_; };
    void SetLightLevel(ContentLightLevelInfo lightLevel) { lightLevel_ = lightLevel; };
protected:
    heif_error ParseContent(HeifStreamReader &reader) override;

    heif_error Write(HeifStreamWriter &writer) const override;

private:
    ContentLightLevelInfo lightLevel_;
};
}
}
#endif //PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_ITEM_PROPERTY_DISPLAY_BOX_H