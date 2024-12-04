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

struct HvccSpsConfig {
    uint8_t forbiddenZeroBit;
    uint8_t nalUnitType;
    uint8_t nuhLayerId;
    uint8_t nuhTemporalIdPlus1;
    uint8_t spsVideoParameterSetId;
    uint8_t spsMaxSubLayersMinus1;
    uint8_t spsTemporalIdNestingFlag;
    uint32_t spsSeqParameterSetId;
    uint32_t chromaFormatIdc;
    uint8_t separateColourPlaneFlag;
    uint32_t picWidthInLumaSamples;
    uint32_t picHeightInLumaSamples;
    uint8_t conformanceWindowFlag;
    uint32_t confWinLefOffset;
    uint32_t confWinRightOffset;
    uint32_t confWinTopOffset;
    uint32_t confWinBottomOffset;
    uint32_t bitDepthLumaMinus8;
    uint32_t bitDepthChromaMinus8;
    uint32_t log2MaxPicOrderCntLsbMinus4;
    uint8_t spsSubLayerOrderingInfoPresentFlag;
    uint8_t scalingListEnabeldFlag;
    uint8_t pcmEnabledFlag;
    uint32_t numShortTermRefPicSets;
    uint8_t longTermRefPicsPresentFlag;
    uint8_t vuiParameterPresentFlag;
    uint8_t videoRangeFlag;
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

    const HvccSpsConfig& GetSpsConfig() const { return spsConfig_; }

    uint32_t GetWord(const std::vector<uint8_t>& nalu, int length);

    uint32_t GetGolombCode(const std::vector<uint8_t> &nalu);

    int32_t GetNaluTypeId(std::vector<uint8_t>& nalu);

    void ParserHvccColorRangeFlag(const std::vector<HvccNalArray> &nalArrays);

    std::vector<HvccNalArray> GetNalArrays() const { return nalArrays_; };

    std::vector<uint8_t> GetNaluData(const std::vector<HvccNalArray>& nalArrays, int8_t naluId);

    void ProcessBoxData(std::vector<uint8_t>& nalu);

    void ProfileTierLevel(std::vector<uint8_t>& SPSBox, int32_t profilePresentFlag, int32_t maxNumSubLayersMinus1);

    bool ParseNalUnitAnalysisSps(std::vector<uint8_t>& nalUnits);

    bool ParseSpsSyntax(std::vector<uint8_t> &nalUnits);

    bool ParseSpsSyntaxScalingList(std::vector<uint8_t>& nalUnits);

    void ParseSpsScallListData(std::vector<uint8_t> &nalUnits);

    bool ParseSpsVuiParameter(std::vector<uint8_t> &nalUnits);

    void ReadGolombCodesForSizeId(std::vector<uint8_t> &nalUnits, int sizeId);

protected:
    heif_error ParseContent(HeifStreamReader& reader) override;
    heif_error ParseNalUnitArray(HeifStreamReader& reader, std::vector<std::vector<uint8_t>>& nalUnits);

private:
    HvccConfig config_{};
    HvccSpsConfig spsConfig_{};
    uint8_t nalUnitLengthSize_ = 4;
    std::vector<HvccNalArray> nalArrays_;
    uint32_t boxBitLength_ = 0;
    uint32_t pos_ = 0;
};
} // namespace ImagePlugin
} // namespace OHOS

#endif // PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_ITEM_PROPERTY_HVCC_BOX_H
