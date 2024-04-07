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

#ifndef PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_ITEM_PROPERTY_HVCC_BOX_H
#define PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_ITEM_PROPERTY_HVCC_BOX_H

#include "box/heif_box.h"

namespace OHOS {
namespace ImagePlugin {
// defined in ISO/IEC 14496-15
struct HvccConfig {
    uint8_t version;
    uint8_t generalProfileSpace;
    uint8_t generalTierFlag;
    uint8_t generalProfileIdc;
    uint32_t generalProfileCompatibilityFlags;
    uint64_t generalConstraintIndicatorFlags;
    uint8_t generalLevelIdc;
    uint16_t minSpatialSegmentationIdc;
    uint8_t parallelismType;
    uint8_t chromaFormat;
    uint8_t bitDepthLuma;
    uint8_t bitDepthChroma;
    uint16_t avgFrameRate;
    uint8_t constFrameRate;
    uint8_t numTemporalLayers;
    uint8_t temporalIdNested;
};

struct HvccNalArray {
    uint8_t arrayCompleteness;
    uint8_t nalUnitType;
    std::vector<std::vector<uint8_t>> nalUnits;
};

class HeifHvccBox : public HeifBox {
public:
    HeifHvccBox() : HeifBox(BOX_TYPE_HVCC) {}

    bool GetHeaders(std::vector<uint8_t>* outData) const;

    void SetConfig(const HvccConfig& config) { config_ = config; }

    const HvccConfig& GetConfig() const { return config_; }

    void AppendNalData(const std::vector<uint8_t>& nalData);

    heif_error Write(HeifStreamWriter& writer) const override;

protected:
    heif_error ParseContent(HeifStreamReader& reader) override;
    heif_error ParseNalUnitArray(HeifStreamReader& reader, std::vector<std::vector<uint8_t>>& nalUnits);

private:
    HvccConfig config_{};
    uint8_t nalUnitLengthSize_ = 4;
    std::vector<HvccNalArray> nalArrays_;
};
} // namespace ImagePlugin
} // namespace OHOS

#endif // PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_ITEM_PROPERTY_HVCC_BOX_H
