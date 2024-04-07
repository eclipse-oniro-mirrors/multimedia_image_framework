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

#include "box/item_property_hvcc_box.h"

static const uint8_t GENGERAL_PROFILE_SPACE_SHIFT = 6;
static const uint8_t GENERAL_TIER_FLAG_SHIFT = 5;
static const uint8_t CONST_FRMAE_RATE_SHIFT = 6;
static const uint8_t NUM_TEMPORAL_LAYERS_SHIFT = 3;
static const uint8_t TEMPORAL_ID_NESTED_SHIFT = 2;
static const uint8_t ARRAY_COMPLETENESS_SHIFT = 6;
static const uint8_t BIT_DEPTH_DIFF = 8;
static const uint8_t NAL_UNIT_LENGTH_SIZE_DIFF = 1;

namespace OHOS {
namespace ImagePlugin {
heif_error HeifHvccBox::ParseNalUnitArray(HeifStreamReader& reader, std::vector<std::vector<uint8_t>>& nalUnits)
{
    int nalUnitNum = reader.Read16();
    for (int unitIndex = 0; unitIndex < nalUnitNum && !reader.HasError(); ++unitIndex) {
        int nalUnitSize = reader.Read16();
        if (!nalUnitSize || !reader.CheckSize(nalUnitSize)) {
            continue;
        }
        std::vector<uint8_t> nalUnit(nalUnitSize);
        bool res = reader.ReadData(nalUnit.data(), nalUnitSize);
        if (!res) {
            return heif_error_eof;
        }
        nalUnits.push_back(nalUnit);
    }
    return reader.GetError();
}

heif_error HeifHvccBox::ParseContent(HeifStreamReader& reader)
{
    config_.version = reader.Read8();
    uint8_t tempByte = reader.Read8();
    config_.generalProfileSpace = (tempByte >> GENGERAL_PROFILE_SPACE_SHIFT) & 0x03;
    config_.generalTierFlag = (tempByte >> GENERAL_TIER_FLAG_SHIFT) & 0x01;
    config_.generalProfileIdc = (tempByte & 0x1F);
    config_.generalProfileCompatibilityFlags = reader.Read32();
    uint32_t indicatorFlagsPre = reader.Read32();
    uint16_t indicatorFlagsLast = reader.Read16();
    config_.generalConstraintIndicatorFlags = uint64_t((indicatorFlagsPre << TWO_BYTES_SHIFT) | indicatorFlagsLast);
    config_.generalLevelIdc = reader.Read8();
    config_.minSpatialSegmentationIdc = reader.Read16() & 0x0FFF;
    config_.parallelismType = reader.Read8() & 0x03;
    config_.chromaFormat = reader.Read8() & 0x03;

    // box store content is bitDepthLumaMinus8
    config_.bitDepthLuma = (reader.Read8() & 0x07) + BIT_DEPTH_DIFF;
    config_.bitDepthChroma = (reader.Read8() & 0x07) + BIT_DEPTH_DIFF;
    config_.avgFrameRate = reader.Read16();

    tempByte = reader.Read8();
    config_.constFrameRate = (tempByte >> CONST_FRMAE_RATE_SHIFT) & 0x03;
    config_.numTemporalLayers = (tempByte >> NUM_TEMPORAL_LAYERS_SHIFT) & 0x07;
    config_.temporalIdNested = (tempByte >> TEMPORAL_ID_NESTED_SHIFT) & 0x01;

    // box store content is lengthSizeMinus1
    nalUnitLengthSize_ = static_cast<uint8_t>((tempByte & 0x03) + NAL_UNIT_LENGTH_SIZE_DIFF);
    int nalArrayNum = reader.Read8();
    for (int arrayIndex = 0; arrayIndex < nalArrayNum && !reader.HasError(); ++arrayIndex) {
        tempByte = reader.Read8();
        HvccNalArray array;
        array.arrayCompleteness = (tempByte >> ARRAY_COMPLETENESS_SHIFT) & 0x01;
        array.nalUnitType = (tempByte & 0x3F);
        heif_error error = ParseNalUnitArray(reader, array.nalUnits);
        if (error) {
            return error;
        }
        nalArrays_.push_back(std::move(array));
    }
    return reader.GetError();
}

bool HeifHvccBox::GetHeaders(std::vector<uint8_t>* outData) const
{
    for (const auto& array : nalArrays_) {
        for (const auto& unit : array.nalUnits) {
            outData->push_back((unit.size() >> THREE_BYTES_SHIFT) & 0xFF);
            outData->push_back((unit.size() >> TWO_BYTES_SHIFT) & 0xFF);
            outData->push_back((unit.size() >> ONE_BYTE_SHIFT) & 0xFF);
            outData->push_back((unit.size()) & 0xFF);
            outData->insert(outData->end(), unit.begin(), unit.end());
        }
    }

    return true;
}

void HeifHvccBox::AppendNalData(const std::vector<uint8_t>& nalData)
{
    HvccNalArray array;
    array.arrayCompleteness = 0;
    array.nalUnitType = uint8_t(nalData[0] >> 1);
    array.nalUnits.push_back(nalData);
    nalArrays_.push_back(array);
}

heif_error HeifHvccBox::Write(HeifStreamWriter& writer) const
{
    size_t boxStart = ReserveHeader(writer);

    const HvccConfig& config = config_;
    writer.Write8(config.version);
    writer.Write8((uint8_t) (((config.generalProfileSpace & 0x03) << GENGERAL_PROFILE_SPACE_SHIFT) |
                             ((config.generalTierFlag & 0x01) << GENERAL_TIER_FLAG_SHIFT) |
                             (config.generalProfileIdc & 0x1F)));
    writer.Write32(config.generalProfileCompatibilityFlags);
    writer.Write32((config.generalConstraintIndicatorFlags >> TWO_BYTES_SHIFT) & 0xFFFFFFFF);
    writer.Write16((config.generalConstraintIndicatorFlags) & 0xFFFF);
    writer.Write8(config.generalLevelIdc);
    writer.Write16((config.minSpatialSegmentationIdc & 0x0FFF) | 0xF000);
    writer.Write8((config.parallelismType & 0x03) | 0xFC);
    writer.Write8((config.chromaFormat & 0x03) | 0xFC);
    writer.Write8(((config.bitDepthLuma - BIT_DEPTH_DIFF) & 0x07) | 0xF8);
    writer.Write8(((config.bitDepthChroma - BIT_DEPTH_DIFF) & 0x07) | 0xF8);
    writer.Write16(config.avgFrameRate);
    writer.Write8((uint8_t) (((config.constFrameRate & 0x03) << CONST_FRMAE_RATE_SHIFT) |
                             ((config.numTemporalLayers & 0x07) << NUM_TEMPORAL_LAYERS_SHIFT) |
                             ((config.temporalIdNested & 0x01) << TEMPORAL_ID_NESTED_SHIFT) |
                             ((nalUnitLengthSize_ - NAL_UNIT_LENGTH_SIZE_DIFF) & 0x03)));

    size_t nArrays = nalArrays_.size();
    writer.Write8((uint8_t) nArrays);
    for (const HvccNalArray& array : nalArrays_) {
        writer.Write8((uint8_t) (((array.arrayCompleteness & 0x01) << ARRAY_COMPLETENESS_SHIFT) |
                                 (array.nalUnitType & 0x3F)));
        size_t nUnits = array.nalUnits.size();
        writer.Write16((uint16_t) nUnits);
        for (const std::vector<uint8_t>& nalUnit : array.nalUnits) {
            writer.Write16((uint16_t) nalUnit.size());
            writer.Write(nalUnit);
        }
    }

    WriteCalculatedHeader(writer, boxStart);
    return heif_error_ok;
}
} // namespace ImagePlugin
} // namespace OHOS
