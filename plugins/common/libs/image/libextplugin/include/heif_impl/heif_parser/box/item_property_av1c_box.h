/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#ifndef PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_ITEM_PROPERTY_AV1C_BOX_H
#define PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_ITEM_PROPERTY_AV1C_BOX_H

#include "box/heif_box.h"

namespace OHOS {
namespace ImagePlugin {

enum class AvifBitDepth : int32_t {
    UNKNOWN = 0,
    Bit_8 = 8,
    Bit_10 = 10,
    Bit_12 = 12,
};

struct Av1CConfiguration {
    uint8_t version = 0;
    uint8_t seqProfile = 0;
    uint8_t seqLevelIdx0 = 0;
    uint8_t seqTier0 = 0;
    uint8_t highBitDepth = 0;
    uint8_t twelveBit = 0;
    uint8_t monochrome = 0;
    uint8_t chromaSubsamplingX = 0;
    uint8_t chromaSubsamplingY = 0;
    uint8_t chromaSamplePosition = 0;
    uint8_t initialPresentationDelayPresent = 0;
    uint8_t initialPresentationDelayMinusOne = 0;
};

class HeifAv1CBox : public HeifBox {
public:
    HeifAv1CBox() : HeifBox(BOX_TYPE_AV1C) {}
    bool HaveConfigOBUS() const
    {
        return !configOBUs_.empty();
    }
    const std::vector<uint8_t> &GetHeaders()
    {
        return configOBUs_;
    }
    const Av1CConfiguration &GetConfig()
    {
        return config_;
    }
    HeifPixelFormat GetAVIFPixelFormat();
    AvifBitDepth GetBitDepth();
protected:
    heif_error ParseContent(HeifStreamReader &reader) override;
private:
    heif_error ParseConfiguration(HeifStreamReader &reader);
    heif_error ParseConfigOBUS(HeifStreamReader &reader);

    Av1CConfiguration config_{};
    std::vector<uint8_t> configOBUs_;
};
} // namespace ImagePlugin
} // namespace OHOS

#endif // PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_ITEM_PROPERTY_AV1C_BOX_H
