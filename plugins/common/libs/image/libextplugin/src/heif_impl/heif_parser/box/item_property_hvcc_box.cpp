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
#include "image_log.h"

static const uint8_t GENGERAL_PROFILE_SPACE_SHIFT = 6;
static const uint8_t GENERAL_TIER_FLAG_SHIFT = 5;
static const uint8_t CONST_FRMAE_RATE_SHIFT = 6;
static const uint8_t NUM_TEMPORAL_LAYERS_SHIFT = 3;
static const uint8_t TEMPORAL_ID_NESTED_SHIFT = 2;
static const uint8_t ARRAY_COMPLETENESS_SHIFT = 6;
static const uint8_t BIT_DEPTH_DIFF = 8;
static const uint8_t NAL_UNIT_LENGTH_SIZE_DIFF = 1;

static const uint8_t SKIP_DOUBLE_DATA_PROCESS_BYTE = 2;
static const uint8_t READ_BIT_NUM_FLAG = 1;
static const uint8_t READ_BYTE_NUM_FLAG = 8;
static const uint8_t READ_GENERAL_PROFILE_IDC_NUM = 32;
static const uint8_t READ_SUB_LAYER_PROFILE_IDCS = 48;

static const uint8_t SPS_BOX_TYPE = 33;
static const uint8_t EXTENDED_SAR = 255;
static const uint8_t NALU_TYPE_ID_SIZE = 6;
static const uint8_t SUB_LAYER_MINUS = 3;
static const uint8_t GENERAL_PROFILE_SIZE = 4;
static const uint8_t SUB_LAYER_PRESENT_PROFILE_SIZE = 3;
static const uint8_t SUB_LAYER_PROFILE_IDC_SIZE = 5;
static const uint8_t PCM_ENABLED_FLAG = 4;
static const uint8_t NUM_TEMPORAL_ID_SIZE = 6;
static const uint8_t MAX_COEF_NUM = 64;
static uint32_t HEIF_MAX_IMAGE_DPB_SIZE = 32;
static uint32_t HEIF_MAX_LONG_TERM_REF_PRESENT_FLAG_SIZE = 32;
static uint32_t HEIF_NUM_DELTA_POCS = 1;
static uint32_t HEIF_BASE_DELTA_FlAG = 1;

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

uint32_t HeifHvccBox::GetWord(const std::vector<uint8_t>& nalu, uint32_t length)
{
    uint32_t res = 0;
    for (uint32_t i = 0; i < length && pos_ < boxBitLength_; ++i, ++pos_) {
        uint32_t bit = ((nalu[pos_ / BIT_DEPTH_DIFF] >>
                        (BIT_DEPTH_DIFF - BIT_SHIFT - (pos_ % BIT_DEPTH_DIFF)))
                        & 0x01);
        res <<= BIT_SHIFT;
        res |= bit;
    }
    return res;
}

uint32_t HeifHvccBox::GetGolombCode(const std::vector<uint8_t> &nalu)
{
    uint32_t zeros = 0;
    while (pos_ < boxBitLength_ && ((nalu[pos_ / ONE_BYTE_SHIFT] >>
           (ONE_BYTE_SHIFT - BIT_SHIFT - (pos_ % ONE_BYTE_SHIFT))) &
           0x01) == 0x00) {
        zeros++;
        pos_++;
    }
    pos_++;
    return GetWord(nalu, zeros) + ((BIT_SHIFT << zeros) - BIT_SHIFT);
}

uint32_t HeifHvccBox::GetNaluTypeId(std::vector<uint8_t> &nalUnits)
{
    if (nalUnits.empty()) {
        return -1;
    }
    GetWord(nalUnits, READ_BIT_NUM_FLAG);
    return GetWord(nalUnits, NALU_TYPE_ID_SIZE);
}

std::vector<uint8_t> HeifHvccBox::GetNaluData(const std::vector<HvccNalArray> &nalArrays,
                                              uint8_t naluId)
{
    for (auto HvccNalunit : nalArrays) {
        if (HvccNalunit.nalUnitType == naluId && (!HvccNalunit.nalUnits.empty())) {
            return HvccNalunit.nalUnits[0];
        }
    }
    return std::vector<uint8_t>();
}

void HeifHvccBox::ProcessBoxData(std::vector<uint8_t> &nalu)
{
    uint32_t naluSize = nalu.size();
    std::vector<uint32_t> indicesToDelete;
    for (uint32_t i = UINT16_BYTES_NUM; i < naluSize; ++i) {
        if (nalu[i - UINT8_BYTES_NUM] == 0x00 &&
            nalu[i - SKIP_DOUBLE_DATA_PROCESS_BYTE] == 0x00 && nalu[i] == 0x03) {
            indicesToDelete.push_back(i);
        }
    }
    for (auto it = indicesToDelete.rbegin(); it != indicesToDelete.rend(); ++it) {
        nalu.erase(nalu.begin() + *it);
    }
}

bool HeifHvccBox::ParserHvccColorRangeFlag(const std::vector<HvccNalArray> &nalArrays)
{
    auto spsBox = GetNaluData(nalArrays, SPS_BOX_TYPE);
    if (spsBox.empty()) {
        return false;
    }
    ProcessBoxData(spsBox);
    if (!ParseNalUnitAnalysisSps(spsBox)) {
        IMAGE_LOGD("Sps does not return a range flag");
        return false;
    }
    return true;
}

void HeifHvccBox::ProfileTierLevel(std::vector<uint8_t> &nalUnits, uint32_t profilePresentFlag,
                                   uint32_t maxNumSubLayerMinus1)
{
    std::vector<uint32_t> generalProfileCompatibilityFlags;
    std::vector<uint32_t> subLayerProfilePresentFlag;
    std::vector<uint32_t> subLayerLevelPresentFlags;
    std::vector<uint32_t> subLayerProfileIdcs;
    std::vector<std::vector<uint32_t>> subLayerProfileCompatibilityFlags;
    if (profilePresentFlag) {
        GetWord(nalUnits, TEMPORAL_ID_NESTED_SHIFT);
        GetWord(nalUnits, READ_BIT_NUM_FLAG);
        GetWord(nalUnits, SUB_LAYER_PROFILE_IDC_SIZE); // general_profile_idc

        for (uint32_t j = 0; j < READ_GENERAL_PROFILE_IDC_NUM; ++j) {
            uint32_t flag = GetWord(nalUnits, READ_BIT_NUM_FLAG);
            generalProfileCompatibilityFlags.push_back(flag);
        }
        GetWord(nalUnits, READ_BYTE_NUM_FLAG);
        GetWord(nalUnits, READ_BYTE_NUM_FLAG);
        GetWord(nalUnits, READ_GENERAL_PROFILE_IDC_NUM);
    }
    GetWord(nalUnits, READ_BYTE_NUM_FLAG);
    subLayerProfilePresentFlag.resize(maxNumSubLayerMinus1);
    for (uint32_t i = 0; i < maxNumSubLayerMinus1; ++i) {
        subLayerProfilePresentFlag[i] = GetWord(nalUnits, READ_BIT_NUM_FLAG);
        subLayerLevelPresentFlags.push_back(GetWord(nalUnits, READ_BIT_NUM_FLAG));
    }

    if (maxNumSubLayerMinus1 > 0) {
        for (uint32_t i = maxNumSubLayerMinus1; i < READ_BYTE_NUM_FLAG; ++i) {
            GetWord(nalUnits, READ_BIT_NUM_FLAG);
            GetWord(nalUnits, READ_BIT_NUM_FLAG);
        }
    }

    subLayerProfileIdcs.resize(maxNumSubLayerMinus1);
    subLayerProfileCompatibilityFlags.resize(maxNumSubLayerMinus1,
                                             std::vector<uint32_t>(GENERAL_PROFILE_SIZE));
    for (uint32_t i = 0; i < maxNumSubLayerMinus1; i++) {
        if (subLayerProfilePresentFlag[i]) {
            GetWord(nalUnits, SUB_LAYER_PRESENT_PROFILE_SIZE);
            subLayerProfileIdcs[i] = GetWord(nalUnits, SUB_LAYER_PROFILE_IDC_SIZE);
            for (uint32_t j = 0; j < GENERAL_PROFILE_SIZE; ++j) {
                subLayerProfileCompatibilityFlags[i][j] = GetWord(nalUnits, READ_BIT_NUM_FLAG);
            }

            // skip sub_layer_profile_idcs judge;
            GetWord(nalUnits, READ_SUB_LAYER_PROFILE_IDCS);
        }
        if (subLayerLevelPresentFlags[i]) {
            GetWord(nalUnits, READ_BYTE_NUM_FLAG);
        }
    }
}

bool HeifHvccBox::ParseNalUnitAnalysisSps(std::vector<uint8_t> &nalUnits)
{
    boxBitLength_ = nalUnits.size() * BIT_DEPTH_DIFF;
    spsConfig_.forbiddenZeroBit = GetWord(nalUnits, READ_BIT_NUM_FLAG);
    spsConfig_.nalUnitType = GetWord(nalUnits, NALU_TYPE_ID_SIZE);
    if (spsConfig_.nalUnitType != SPS_BOX_TYPE) {
        return false;
    }
    spsConfig_.nuhLayerId = GetWord(nalUnits, NUM_TEMPORAL_ID_SIZE);
    GetWord(nalUnits, SUB_LAYER_MINUS);
    return ParseSpsSyntax(nalUnits);
}

bool HeifHvccBox::ParseSpsSyntax(std::vector<uint8_t> &nalUnits)
{
    //General sequence parameter set RBSP syntax
    spsConfig_.spsVideoParameterSetId = GetWord(nalUnits, GENERAL_PROFILE_SIZE);
    spsConfig_.spsMaxSubLayersMinus1 = GetWord(nalUnits, SUB_LAYER_MINUS);
    spsConfig_.spsTemporalIdNestingFlag = GetWord(nalUnits, READ_BIT_NUM_FLAG);

    //go to profile_tier_level parser
    ProfileTierLevel(nalUnits,
                     spsConfig_.spsTemporalIdNestingFlag,
                     spsConfig_.spsMaxSubLayersMinus1);

    spsConfig_.spsVideoParameterSetId = GetGolombCode(nalUnits);
    spsConfig_.chromaFormatIdc = GetGolombCode(nalUnits);
    IMAGE_LOGD("HeifParser::SPS chromaFormatIdc is %{public}d", spsConfig_.chromaFormatIdc);
    if (spsConfig_.chromaFormatIdc == SUB_LAYER_MINUS) {
        spsConfig_.separateColourPlaneFlag = GetWord(nalUnits, READ_BIT_NUM_FLAG);
    }
    spsConfig_.picWidthInLumaSamples = GetGolombCode(nalUnits);
    spsConfig_.picHeightInLumaSamples = GetGolombCode(nalUnits);
    IMAGE_LOGD("HeifParser::SPS picWidthInLumaSamples : %{public}d", spsConfig_.picWidthInLumaSamples);
    IMAGE_LOGD("HeifParser::SPS picHeightInLumaSamples : %{public}d", spsConfig_.picHeightInLumaSamples);
    spsConfig_.conformanceWindowFlag = GetWord(nalUnits, READ_BIT_NUM_FLAG);
    if (spsConfig_.conformanceWindowFlag == READ_BIT_NUM_FLAG) {
        spsConfig_.confWinLefOffset = GetGolombCode(nalUnits);
        spsConfig_.confWinRightOffset = GetGolombCode(nalUnits);
        spsConfig_.confWinTopOffset = GetGolombCode(nalUnits);
        spsConfig_.confWinBottomOffset = GetGolombCode(nalUnits);
    }
    spsConfig_.bitDepthLumaMinus8 = GetGolombCode(nalUnits);
    spsConfig_.bitDepthChromaMinus8 = GetGolombCode(nalUnits);
    IMAGE_LOGD("HeifParser::SPS bitDepthLumaMinus8 : %{public}d", spsConfig_.bitDepthLumaMinus8);
    IMAGE_LOGD("HeifParser::SPS bitDepthChromaMinus8 : %{public}d", spsConfig_.bitDepthChromaMinus8);
    spsConfig_.log2MaxPicOrderCntLsbMinus4 = GetGolombCode(nalUnits);
    spsConfig_.spsSubLayerOrderingInfoPresentFlag = GetWord(nalUnits, READ_BIT_NUM_FLAG);
    uint32_t i = spsConfig_.spsSubLayerOrderingInfoPresentFlag ? 0 : spsConfig_.spsMaxSubLayersMinus1;
    for (; i <= spsConfig_.spsMaxSubLayersMinus1; i++) {
        GetGolombCode(nalUnits);
        GetGolombCode(nalUnits);
        GetGolombCode(nalUnits);
    }
    GetGolombCode(nalUnits);
    GetGolombCode(nalUnits);
    GetGolombCode(nalUnits);
    GetGolombCode(nalUnits);
    GetGolombCode(nalUnits);
    GetGolombCode(nalUnits);
    return ParseSpsSyntaxScalingList(nalUnits);
}

void HeifHvccBox::ReadGolombCodesForSizeId(std::vector<uint8_t> &nalUnits, uint32_t sizeId)
{
    uint8_t minCoefNum = READ_BIT_NUM_FLAG << (GENERAL_PROFILE_SIZE + (static_cast<uint8_t>(sizeId)
                         << READ_BIT_NUM_FLAG));
    uint32_t coefNum = MAX_COEF_NUM < minCoefNum ? MAX_COEF_NUM : minCoefNum;
    if (sizeId > READ_BIT_NUM_FLAG) {
        GetGolombCode(nalUnits);
    }
    for (uint32_t i = 0; i < coefNum; i++) {
        GetGolombCode(nalUnits);
    }
}

void HeifHvccBox::ParseSpsScallListData(std::vector<uint8_t> &nalUnits)
{
    for (uint32_t sizeId = 0; sizeId < GENERAL_PROFILE_SIZE; ++sizeId) {
        for (uint32_t matrixId = 0; matrixId < NUM_TEMPORAL_ID_SIZE;
            matrixId += ((sizeId == SUB_LAYER_MINUS) ? SUB_LAYER_MINUS : READ_BIT_NUM_FLAG)) {
            uint32_t tmpFlag = GetWord(nalUnits, READ_BIT_NUM_FLAG);
            if (!tmpFlag) {
                GetGolombCode(nalUnits);
            } else {
                ReadGolombCodesForSizeId(nalUnits, sizeId);
            }
        }
    }
}

bool HeifHvccBox::ParseSpsVuiParameter(std::vector<uint8_t> &nalUnits)
{
    uint8_t aspectRatioInfoPresentFlag = GetWord(nalUnits, READ_BIT_NUM_FLAG);
    if (aspectRatioInfoPresentFlag) {
        uint32_t aspectRatioIdc = GetWord(nalUnits, READ_BYTE_NUM_FLAG);
        if (aspectRatioIdc == EXTENDED_SAR) {
            GetWord(nalUnits, READ_BIT_NUM_FLAG);
        }
    }
    uint32_t overscanInfoPresentFlag = GetWord(nalUnits, READ_BIT_NUM_FLAG);
    if (overscanInfoPresentFlag) {
        GetWord(nalUnits, GENERAL_PROFILE_SIZE);
    }
    uint32_t videoSignalTypePresentFlag = GetWord(nalUnits, READ_BIT_NUM_FLAG);
    if (videoSignalTypePresentFlag) {
        GetWord(nalUnits, SUB_LAYER_MINUS);
        spsConfig_.videoRangeFlag = GetWord(nalUnits, READ_BIT_NUM_FLAG);
        IMAGE_LOGD("HeifParser::SPS videoRangeFlag : %{public}d", spsConfig_.videoRangeFlag);
    }
    return true;
}

void HeifHvccBox::ParseStRefPicSet(std::vector<uint8_t> &nalUnits, uint32_t stRpsIdx, uint32_t numShortTermRefPicSets)
{
    RefPicSet rps;
    if (stRpsIdx != 0) {
        rps.interRefPicSetPredictionFlag = GetWord(nalUnits, READ_BIT_NUM_FLAG);
    } else {
        rps.interRefPicSetPredictionFlag = 0;
    }
    if (rps.interRefPicSetPredictionFlag) {
        if (stRpsIdx == numShortTermRefPicSets) {
            rps.deltaIdxMinus1 = GetGolombCode(nalUnits);
        } else {
            rps.deltaIdxMinus1 = 0;
        }
        rps.deltaRpsSign = GetWord(nalUnits, READ_BIT_NUM_FLAG);
        rps.absDeltaRpsMinus1 = GetGolombCode(nalUnits);

        uint32_t refRpsIdx = stRpsIdx - (rps.deltaIdxMinus1 + 1);
        IMAGE_LOGD("HeifParser::SPS refRpsIdx : %{public}d", refRpsIdx);

        rps.usedByCurrPicFlag.resize(HEIF_NUM_DELTA_POCS);
        rps.usedDeltaFlag.resize(HEIF_NUM_DELTA_POCS);

        for (uint32_t i = 0; i < HEIF_NUM_DELTA_POCS; i++) {
            rps.usedDeltaFlag[i] = GetWord(nalUnits, READ_BIT_NUM_FLAG);
            if (!rps.usedByCurrPicFlag[i]) {
                rps.usedDeltaFlag[i] = GetWord(nalUnits, READ_BIT_NUM_FLAG);
            } else {
                rps.usedDeltaFlag[i] = HEIF_BASE_DELTA_FlAG;
            }
        }
    } else {
        rps.numNegativePics = GetGolombCode(nalUnits);
        rps.numPositivePics = GetGolombCode(nalUnits);

        if (rps.numNegativePics > HEIF_MAX_IMAGE_DPB_SIZE || rps.numPositivePics > HEIF_MAX_IMAGE_DPB_SIZE) {
            IMAGE_LOGE("HeifParser:: RPS pics-Buffering more than max");
            return;
        }
        rps.deltaPocS0Minus1.resize(rps.numNegativePics);
        rps.usedBycurrPicS0Flag.resize(rps.numNegativePics);

        for (uint32_t i = 0; i < rps.numNegativePics; i++) {
            rps.deltaPocS0Minus1[i] = GetGolombCode(nalUnits);
            rps.usedBycurrPicS0Flag[i] = GetWord(nalUnits, READ_BIT_NUM_FLAG);
        }

        rps.deltaPocS1Minus1.resize(rps.numPositivePics);
        rps.usedBycurrPicS1Flag.resize(rps.numPositivePics);
        
        for (uint32_t i = 0; i < rps.numPositivePics; i++) {
            rps.deltaPocS1Minus1[i] = GetGolombCode(nalUnits);
            rps.usedBycurrPicS1Flag[i] = GetWord(nalUnits, READ_BIT_NUM_FLAG);
        }
    }
}

bool HeifHvccBox::ParseSpsSyntaxScalingList(std::vector<uint8_t> &nalUnits)
{
    spsConfig_.scalingListEnabeldFlag = GetWord(nalUnits, READ_BIT_NUM_FLAG);
    if (spsConfig_.scalingListEnabeldFlag == READ_BIT_NUM_FLAG) {
        spsConfig_.scalingListEnabeldFlag = GetWord(nalUnits, READ_BIT_NUM_FLAG);
        if (spsConfig_.scalingListEnabeldFlag) {
            ParseSpsScallListData(nalUnits);
        }
    }
    GetWord(nalUnits, READ_BIT_NUM_FLAG);
    GetWord(nalUnits, READ_BIT_NUM_FLAG);
    spsConfig_.pcmEnabledFlag = GetWord(nalUnits, READ_BIT_NUM_FLAG);
    if (spsConfig_.pcmEnabledFlag == READ_BIT_NUM_FLAG) {
        GetWord(nalUnits, PCM_ENABLED_FLAG);
        GetWord(nalUnits, PCM_ENABLED_FLAG);
        GetGolombCode(nalUnits);
        GetGolombCode(nalUnits);
        GetWord(nalUnits, READ_BIT_NUM_FLAG);
    }
    spsConfig_.numShortTermRefPicSets = GetGolombCode(nalUnits);
    IMAGE_LOGD("HeifParser:: SPS numShortTermRefPicSets : %{public}d", spsConfig_.numShortTermRefPicSets);
    for (uint32_t i = 0; i < spsConfig_.numShortTermRefPicSets; i++) {
        ParseStRefPicSet(nalUnits, i, spsConfig_.numShortTermRefPicSets);
    }
    spsConfig_.longTermRefPicsPresentFlag = GetWord(nalUnits, READ_BIT_NUM_FLAG);
    if (spsConfig_.longTermRefPicsPresentFlag == READ_BIT_NUM_FLAG) {
        uint32_t numLongTermRefPicSps = GetGolombCode(nalUnits);
        for (uint32_t i = 0; i < HEIF_MAX_LONG_TERM_REF_PRESENT_FLAG_SIZE && i < numLongTermRefPicSps; i++) {
            // itRefPicPocLsbSps[i] == log2MaxPicOrderCntLsbMinus4 + 4
            GetWord(nalUnits, spsConfig_.log2MaxPicOrderCntLsbMinus4 + GENERAL_PROFILE_SIZE);
            GetWord(nalUnits, READ_BIT_NUM_FLAG);
        }
    }
    GetWord(nalUnits, READ_BIT_NUM_FLAG);
    GetWord(nalUnits, READ_BIT_NUM_FLAG);
    spsConfig_.vuiParameterPresentFlag = GetWord(nalUnits, READ_BIT_NUM_FLAG);
    if (spsConfig_.vuiParameterPresentFlag == READ_BIT_NUM_FLAG) {
        return ParseSpsVuiParameter(nalUnits);
    }
    return false; // Skip parsing subsequent content
}
} // namespace ImagePlugin
} // namespace OHOS
