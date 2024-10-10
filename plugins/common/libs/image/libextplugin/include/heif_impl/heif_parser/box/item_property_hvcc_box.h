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
    uint8_t forbidden_zero_bit;
    uint8_t nal_unit_type;
    uint8_t nuh_layer_id;
    uint8_t nuh_temporal_id_plus1;
    uint8_t sps_video_parameter_set_id;
    uint8_t sps_max_sub_layers_minus1;
    uint8_t sps_temporal_id_nesting_flag;
    uint32_t sps_seq_parameter_set_id;
    uint32_t chroma_format_idc;
    uint8_t separate_colour_plane_flag;
    uint32_t pic_width_in_luma_samples;
    uint32_t pic_height_in_luma_samples;
    uint8_t conformance_window_flag;
    uint32_t conf_win_lef_offset;
    uint32_t conf_win_right_offset;
    uint32_t conf_win_top_offset;
    uint32_t conf_win_bottom_offset;
    uint32_t bit_depth_luma_minus8;
    uint32_t bit_depth_chroma_minus8;
    uint32_t log2_max_pic_order_cnt_lsb_minus4;
    uint8_t sps_sub_layer_ordering_info_present_flag;
    uint8_t scaling_list_enabeld_flag;
    uint8_t pcm_enabled_flag;
    uint32_t num_short_term_ref_pic_sets;
    uint8_t long_term_ref_pics_present_flag;
    uint8_t vui_parameter_present_flag;
    uint8_t video_range_flag;
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

    int32_t GetWord(const std::vector<uint8_t>& nalu, int m_len);

    int32_t GetGolombCode(const std::vector<uint8_t> &nalu);

    int32_t GetNaluTypeId(std::vector<uint8_t>& nalu);

    void ParserHvccColorRangeFlag(const std::vector<HvccNalArray> &nalArrays);

    std::vector<HvccNalArray> GetNalArrays() const { return nalArrays_; };

    std::vector<uint8_t> GetNaluData(const std::vector<HvccNalArray>& nalArrays, int8_t NaluId);

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
