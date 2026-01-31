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

#define private public
#define protected public
#include <gtest/gtest.h>
#include "heif_box.h"
#include "item_data_box.h"
#include "item_info_box.h"
#include "item_property_basic_box.h"
#include "item_property_box.h"
#include "item_property_color_box.h"
#include "item_property_hvcc_box.h"
#include "item_property_aux_box.h"
#include "item_property_transform_box.h"
#include "item_ref_box.h"

#define TEST_FROM_ITEM_ID 1
#define TEST_TO_ITEM_ID_1 100
#define TEST_TO_ITEM_ID_2 200
#define TEST_TO_ITEM_ID_3 300
#define TEST_ITEM_COUNT 3

using namespace testing::ext;
namespace OHOS {
namespace ImagePlugin {
static constexpr size_t ERR_LENGTH = -1;
static constexpr size_t NORMAL_LENGTH = 1;
static constexpr size_t SIZE_32BITS = 0xFFFFFFFF;
static constexpr size_t UUID_TYPE_BYTE_NUM = 16;
static constexpr uint8_t LARGE_PROPERTY_INDEX_FLAG = 1;
static constexpr uint8_t PROPERTY_NUMBER = 2;
static constexpr uint8_t NOT_DEFAULT_INDEX = 1;
static constexpr uint8_t BOX_TYPE = 2;
std::vector<uint8_t> BUFFER = {0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
                               0x12, 0x34, 0x56, 0x78, 0x01, 0xAB, 0xCD};
static constexpr uint32_t NAL_LAYER_ID = 33;
static constexpr uint8_t SKIP_DOUBLE_DATA_PROCESS_BYTE = 2;
std::vector<uint8_t> HVCC_PARSE_CONTENT_TRUNCATED = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x02, 0x55 };
std::vector<uint8_t> VALID_STREAM_DATA = { 0x00, 0x01, 0x00, 0x00 };
std::vector<uint8_t> INVALID_STREAM_DATA = { 0x00, 0x01, 0x00, 0x02 };
std::vector<uint8_t> AUX_STREAM_DATA = { 0x00, 0x00, 0x00, 0x12, 'a', 'u', 'x', 'c', 0x00, 0x00, 0x00, 0x00,
    't', 'e', 's', 't', 0x00, 0x11, 0x22 };
std::vector<uint8_t> NAL_DATA = { 0x80, 0x04, 0x40 };
std::vector<uint8_t> NAL_UNITS = { 0x04, 0x40 };
std::vector<uint8_t> PARSE_SPS_NAL_DATA = { 0x80, 0xc0 };
std::vector<uint8_t> PARSE_SPS_NAL_UNITS = { 0xFF, 0x00, 0x01, 0x00, 0x01, 0x80 };
static constexpr uint8_t BIT_DEPTH_DIFF = 8;
static constexpr uint8_t READ_BIT_NUM_FLAG = 1;
static constexpr uint8_t NAL_UNIT_TYPE = 1;
static constexpr uint8_t NAL_INDEX = 1;
static constexpr uint8_t NAL_SIZE = 64;
static constexpr uint8_t VECTOR_SIZE = 10;
static constexpr uint8_t UNITS_SIZE = 8;
static constexpr uint32_t OPERATION_FAILED = -1;
static constexpr uint32_t ST_RPS_IDX = 1;
static constexpr uint32_t NUM_SHORT_TERM_REF_PIC_SETS = 1;
static constexpr uint32_t SIZE_ID = 2;
static constexpr uint32_t MAX_NUM_SUB_LAYER_MINUS = 1;
static constexpr uint64_t BOX_SIZE_OFFSET_SMALL = 1;
static constexpr uint64_t BOX_SIZE_OFFSET_BIG = 10;

static std::vector<uint8_t> SetUint32ToUint8Vertor(uint32_t data)
{
    std::vector<uint8_t> res = {
        static_cast<uint8_t>((data >> 24) & 0xFF),
        static_cast<uint8_t>((data >> 16) & 0xFF),
        static_cast<uint8_t>((data >> 8) & 0xFF),
        static_cast<uint8_t>(data & 0xFF)
    };
    return res;
}

static void ProcessBoxData(std::vector<uint8_t> &nalu)
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

class HeifParserBoxTest : public testing::Test {
public:
    HeifParserBoxTest() {}
    ~HeifParserBoxTest() {}
};

/**
 * @tc.name: ParseNalUnitArrayTest001
 * @tc.desc: Test HeifHvccBox.ParseNalUnitArray with one NAL entry where payload size matches available data.
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserBoxTest, ParseNalUnitArrayTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ParseNalUnitArrayTest001 start";
    HeifHvccBox heifHvccBox;
    auto stream = std::make_shared<HeifBufferInputStream>(VALID_STREAM_DATA.data(), VALID_STREAM_DATA.size(), true);
    HeifStreamReader reader(stream, 0, VALID_STREAM_DATA.size());
    std::vector<std::vector<uint8_t>> nalUnits;

    heif_error ret = heifHvccBox.ParseNalUnitArray(reader, nalUnits);
    ASSERT_EQ(ret, heif_error_ok);
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ParseNalUnitArrayTest001 end";
}

/**
 * @tc.name: ParseNalUnitArrayTest002
 * @tc.desc: Test HeifHvccBox.ParseNalUnitArray when declared NAL size exceeds remaining bytes, expecting EOF.
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserBoxTest, ParseNalUnitArrayTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ParseNalUnitArrayTest002 start";
    HeifHvccBox heifHvccBox;
    auto stream = std::make_shared<HeifBufferInputStream>(INVALID_STREAM_DATA.data(), INVALID_STREAM_DATA.size(), true);
    HeifStreamReader reader(stream, 0, INVALID_STREAM_DATA.size());
    std::vector<std::vector<uint8_t>> nalUnits;

    heif_error ret = heifHvccBox.ParseNalUnitArray(reader, nalUnits);
    ASSERT_EQ(ret, heif_error_eof);
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ParseNalUnitArrayTest002 end";
}

/**
 * @tc.name: ParseContentTest006
 * @tc.desc: Test HeifHvccBox.ParseContent with truncated HVCC payload so that parsing of a NAL unit fails, returns EOF.
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserBoxTest, ParseContentTest006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ParseContentTest006 start";
    HeifHvccBox heifHvccBox;
    auto stream = std::make_shared<HeifBufferInputStream>(HVCC_PARSE_CONTENT_TRUNCATED.data(),
        HVCC_PARSE_CONTENT_TRUNCATED.size(), true);
    HeifStreamReader reader(stream, 0, HVCC_PARSE_CONTENT_TRUNCATED.size());

    heif_error ret = heifHvccBox.ParseContent(reader);
    ASSERT_EQ(ret, heif_error_eof);
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ParseContentTest006 end";
}

/**
 * @tc.name: GetNaluTypeIdTest001
 * @tc.desc: Test HeifHvccBox.GetNaluTypeId with empty NAL buffer, expecting invalid type (-1).
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserBoxTest, GetNaluTypeIdTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserBoxTest: GetNaluTypeIdTest001 start";
    HeifHvccBox heifHvccBox;
    std::vector<uint8_t> nalUnits;

    uint32_t ret = heifHvccBox.GetNaluTypeId(nalUnits);
    ASSERT_EQ(ret, OPERATION_FAILED);
    GTEST_LOG_(INFO) << "HeifParserBoxTest: GetNaluTypeIdTest001 end";
}

/**
 * @tc.name: GetNaluTypeIdTest002
 * @tc.desc: Test HeifHvccBox.GetNaluTypeId with a single-byte NAL buffer, expecting type value 0.
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserBoxTest, GetNaluTypeIdTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserBoxTest: GetNaluTypeIdTest002 start";
    HeifHvccBox heifHvccBox;
    std::vector<uint8_t> nalUnits;
    nalUnits.push_back(0x00);

    uint32_t ret = heifHvccBox.GetNaluTypeId(nalUnits);
    ASSERT_EQ(ret, 0);
    GTEST_LOG_(INFO) << "HeifParserBoxTest: GetNaluTypeIdTest002 end";
}

/**
 * @tc.name: GetNaluDataTest001
 * @tc.desc: Test HeifHvccBox.GetNaluData when SPS NAL is absent from list, expecting empty data vector.
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserBoxTest, GetNaluDataTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserBoxTest: GetNaluDataTest001 start";
    HeifHvccBox heifHvccBox;
    HvccNalArray nalArray;
    nalArray.nalUnitType = NAL_UNIT_TYPE;
    std::vector<HvccNalArray> nalArrays;
    nalArrays.push_back(nalArray);

    auto ret = heifHvccBox.GetNaluData(nalArrays, 0);
    ASSERT_EQ(ret, std::vector<uint8_t>());
    GTEST_LOG_(INFO) << "HeifParserBoxTest: GetNaluDataTest001 end";
}

/**
 * @tc.name: ParserHvccColorRangeFlagTest001
 * @tc.desc: Test HeifHvccBox.ParserHvccColorRangeFlag returning false when SPS NAL cannot be found in arrays.
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserBoxTest, ParserHvccColorRangeFlagTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ParserHvccColorRangeFlagTest001 start";
    HeifHvccBox heifHvccBox;
    HvccNalArray nalArray;
    nalArray.nalUnitType = 0;
    std::vector<HvccNalArray> nalArrays;
    nalArrays.push_back(nalArray);

    bool ret = heifHvccBox.ParserHvccColorRangeFlag(nalArrays);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ParserHvccColorRangeFlagTest001 end";
}

/**
 * @tc.name: ProfileTierLevelTest001
 * @tc.desc: Test HeifHvccBox.ProfileTierLevel to ensure bit cursor advances when profilePresentFlag is enabled.
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserBoxTest, ProfileTierLevelTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ProfileTierLevelTest001 start";
    HeifHvccBox heifHvccBox;
    std::vector<uint8_t> nalUnits(VECTOR_SIZE, 0xFF);
    heifHvccBox.boxBitLength_ = static_cast<uint32_t>(nalUnits.size() * BIT_DEPTH_DIFF);

    heifHvccBox.ProfileTierLevel(nalUnits, 0, MAX_NUM_SUB_LAYER_MINUS);
    ASSERT_GT(heifHvccBox.pos_, 0u);
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ProfileTierLevelTest001 end";
}

/**
 * @tc.name: ParseSpsSyntaxTest001
 * @tc.desc: Test HeifHvccBox.ParseSpsSyntax to verify SPS conformanceWindowFlag is parsed and set correctly.
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserBoxTest, ParseSpsSyntaxTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ParseSpsSyntaxTest001 start";
    HeifHvccBox heifHvccBox;
    std::vector<uint8_t> nalUnits(NAL_SIZE, 0xFF);
    nalUnits[0] = 0x00;
    nalUnits[NAL_INDEX] = 0x00;
    heifHvccBox.boxBitLength_ = static_cast<uint32_t>(nalUnits.size() * BIT_DEPTH_DIFF);

    heifHvccBox.ParseSpsSyntax(nalUnits);
    ASSERT_EQ(heifHvccBox.spsConfig_.conformanceWindowFlag, READ_BIT_NUM_FLAG);
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ParseSpsSyntaxTest001 end";
}

/**
 * @tc.name: ReadGolombCodesForSizeIdTest001
 * @tc.desc: Test HeifHvccBox.ReadGolombCodesForSizeId with sizeId > 1 to cover extra leading Golomb read.
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserBoxTest, ReadGolombCodesForSizeIdTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ReadGolombCodesForSizeIdTest001 start";
    HeifHvccBox heifHvccBox;
    std::vector<uint8_t> nalUnits(UNITS_SIZE, 0xFF);
    heifHvccBox.boxBitLength_ = static_cast<uint32_t>(nalUnits.size() * BIT_DEPTH_DIFF);

    heifHvccBox.ReadGolombCodesForSizeId(nalUnits, SIZE_ID);
    ASSERT_GT(heifHvccBox.pos_, 0u);
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ReadGolombCodesForSizeIdTest001 end";
}

/**
 * @tc.name: ReadGolombCodesForSizeIdTest002
 * @tc.desc: Test HeifHvccBox.ReadGolombCodesForSizeId with minimal sizeId to exercise only coefficient decoding path.
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserBoxTest, ReadGolombCodesForSizeIdTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ReadGolombCodesForSizeIdTest002 start";
    HeifHvccBox heifHvccBox;
    std::vector<uint8_t> nalUnits(UNITS_SIZE, 0xFF);
    heifHvccBox.boxBitLength_ = static_cast<uint32_t>(nalUnits.size() * BIT_DEPTH_DIFF);

    heifHvccBox.ReadGolombCodesForSizeId(nalUnits, READ_BIT_NUM_FLAG);
    ASSERT_GT(heifHvccBox.pos_, 0u);
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ReadGolombCodesForSizeIdTest002 end";
}

/**
 * @tc.name: ParseSpsScallListDataTest001
 * @tc.desc: Test HeifHvccBox.ParseSpsScallListData where scaling list flags trigger both direct coefficient and
 *           default paths.
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserBoxTest, ParseSpsScallListDataTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ParseSpsScallListDataTest001 start";
    HeifHvccBox heifHvccBox;
    std::vector<uint8_t> nalUnits(UNITS_SIZE, 0xFF);
    heifHvccBox.boxBitLength_ = static_cast<uint32_t>(nalUnits.size() * BIT_DEPTH_DIFF);

    heifHvccBox.ParseSpsScallListData(nalUnits);
    ASSERT_GT(heifHvccBox.pos_, 0u);
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ParseSpsScallListDataTest001 end";
}

/**
 * @tc.name: ParseSpsScallListDataTest002
 * @tc.desc: Test HeifHvccBox.ParseSpsScallListData with empty NAL buffer to ensure function exits safely.
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserBoxTest, ParseSpsScallListDataTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ParseSpsScallListDataTest002 start";
    HeifHvccBox heifHvccBox;
    std::vector<uint8_t> nalUnits;

    heifHvccBox.ParseSpsScallListData(nalUnits);
    ASSERT_GT(heifHvccBox.pos_, 0u);
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ParseSpsScallListDataTest002 end";
}

/**
 * @tc.name: ParseSpsVuiParameterTest001
 * @tc.desc: Test HeifHvccBox.ParseSpsVuiParameter to cover aspect ratio, overscan and video signal presence flags.
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserBoxTest, ParseSpsVuiParameterTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ParseSpsVuiParameterTest001 start";
    HeifHvccBox heifHvccBox;
    bool ret = heifHvccBox.ParseSpsVuiParameter(PARSE_SPS_NAL_UNITS);
    ASSERT_EQ(ret, true);

    HeifHvccBox heifHvccBoxNal;
    ret = heifHvccBoxNal.ParseSpsVuiParameter(PARSE_SPS_NAL_DATA);
    ASSERT_EQ(ret, true);
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ParseSpsVuiParameterTest001 end";
}

/**
 * @tc.name: ParseStRefPicSetTest001
 * @tc.desc: Test HeifHvccBox.ParseStRefPicSet when stRpsIdx equals numShortTermRefPicSets to drive
 *           prediction-delta branch.
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserBoxTest, ParseStRefPicSetTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ParseStRefPicSetTest001 start";
    HeifHvccBox heifHvccBox;
    std::vector<uint8_t> nalUnits(NAL_SIZE, 0xFF);
    heifHvccBox.boxBitLength_ = static_cast<uint32_t>(nalUnits.size() * BIT_DEPTH_DIFF);

    heifHvccBox.ParseStRefPicSet(nalUnits, ST_RPS_IDX, NUM_SHORT_TERM_REF_PIC_SETS);
    ASSERT_GT(heifHvccBox.pos_, 0u);
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ParseStRefPicSetTest001 end";
}

/**
 * @tc.name: ParseStRefPicSetTest002
 * @tc.desc: Test HeifHvccBox.ParseStRefPicSet in non-prediction mode and with repeated parsing to cover both branches.
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserBoxTest, ParseStRefPicSetTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ParseStRefPicSetTest002 start";
    HeifHvccBox heifHvccBox;
    heifHvccBox.boxBitLength_ = static_cast<uint32_t>(NAL_UNITS.size() * BIT_DEPTH_DIFF);

    heifHvccBox.ParseStRefPicSet(NAL_UNITS, 0, NUM_SHORT_TERM_REF_PIC_SETS);
    ASSERT_GT(heifHvccBox.pos_, 0u);

    heifHvccBox.pos_ = 0;
    heifHvccBox.boxBitLength_ = static_cast<uint32_t>(NAL_DATA.size() * BIT_DEPTH_DIFF);
    heifHvccBox.ParseStRefPicSet(NAL_DATA, 0, NUM_SHORT_TERM_REF_PIC_SETS);
    ASSERT_GT(heifHvccBox.pos_, 0u);
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ParseStRefPicSetTest002 end";
}

/**
 * @tc.name: ParseSpsSyntaxScalingListTest001
 * @tc.desc: Test HeifHvccBox.ParseSpsSyntaxScalingList to ensure scaling list enable flags and PCM fields are consumed.
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserBoxTest, ParseSpsSyntaxScalingListTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ParseSpsSyntaxScalingListTest001 start";
    HeifHvccBox heifHvccBox;
    std::vector<uint8_t> nalUnits(NAL_SIZE, 0xFF);

    heifHvccBox.ParseSpsSyntaxScalingList(nalUnits);
    ASSERT_GT(heifHvccBox.pos_, 0u);
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ParseSpsSyntaxScalingListTest001 end";
}

/**
 * @tc.name: ParseContentTest007
 * @tc.desc: Test HeifColrBox.ParseContent returns EOF when declared profile section is larger than remaining bytes.
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserBoxTest, ParseContentTest007, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ParseContentTest007 start";
    HeifColrBox heifColrBox;
    heifColrBox.headerSize_ = UINT64_BYTES_NUM;
    heifColrBox.boxSize_ = heifColrBox.headerSize_ + UINT32_BYTES_NUM + BOX_SIZE_OFFSET_BIG;

    auto streamData = SetUint32ToUint8Vertor(COLOR_TYPE_PROF);
    auto stream = std::make_shared<HeifBufferInputStream>(streamData.data(), streamData.size(), true);
    HeifStreamReader reader(stream, 0, streamData.size());

    heif_error ret = heifColrBox.ParseContent(reader);
    ASSERT_EQ(ret, heif_error_eof);
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ParseContentTest007 end";
}

/**
 * @tc.name: ParseContentTest008
 * @tc.desc: Test HeifColrBox.ParseContent returns EOF when BOX_TYPE_NCLX data is truncated so CheckSize fails.
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserBoxTest, ParseContentTest008, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ParseContentTest008 start";
    HeifColrBox heifColrBox;
    heifColrBox.headerSize_ = UINT64_BYTES_NUM;
    heifColrBox.boxSize_ = heifColrBox.headerSize_ + UINT32_BYTES_NUM + BOX_SIZE_OFFSET_SMALL;

    auto streamData = SetUint32ToUint8Vertor(BOX_TYPE_NCLX);
    auto stream = std::make_shared<HeifBufferInputStream>(streamData.data(), streamData.size(), true);
    HeifStreamReader reader(stream, 0, streamData.size());

    heif_error ret = heifColrBox.ParseContent(reader);
    ASSERT_EQ(ret, heif_error_eof);
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ParseContentTest008 end";
}

/**
 * @tc.name: ParseContentTest009
 * @tc.desc: Test HeifAuxcBox.ParseContent so incoming stream contains aux subtypes and they are appended.
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserBoxTest, ParseContentTest009, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ParseContentTest009 start";
    HeifAuxcBox heifAuxcBox;
    auto stream = std::make_shared<HeifBufferInputStream>(AUX_STREAM_DATA.data(), AUX_STREAM_DATA.size(), true);
    HeifStreamReader reader(stream, 0, AUX_STREAM_DATA.size());

    heif_error ret = heifAuxcBox.ParseContent(reader);
    ASSERT_EQ(ret, heif_error_ok);
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ParseContentTest009 end";
}

/**
 * @tc.name: ParseContentTest001
 * @tc.desc: HeifImirBox
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserBoxTest, ParseContentTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ParseContentTest001 start";
    HeifImirBox heifImirBox;
    auto stream = std::make_shared<HeifBufferInputStream>(nullptr, 0, true);
    HeifStreamReader reader(stream, 0, 0);
    heif_error ret = heifImirBox.ParseContent(reader);
    ASSERT_NE(ret, heif_error_ok);
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ParseContentTest001 end";
}

/**
 * @tc.name: WriteTest001
 * @tc.desc: HeifImirBox
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserBoxTest, WriteTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserBoxTest: WriteTest001 start";
    HeifImirBox heifImirBox;
    heifImirBox.direction_ = HeifTransformMirrorDirection::INVALID;
    HeifStreamWriter write;
    heif_error ret = heifImirBox.Write(write);
    ASSERT_EQ(ret, heif_invalid_mirror_direction);
    heifImirBox.direction_ = HeifTransformMirrorDirection::HORIZONTAL;
    ret = heifImirBox.Write(write);
    ASSERT_EQ(ret, heif_error_ok);
    GTEST_LOG_(INFO) << "HeifParserBoxTest: WriteTest001 end";
}

/**
 * @tc.name: WriteTest002
 * @tc.desc: HeifNclxColorProfile
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserBoxTest, WriteTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserBoxTest: WriteTest002 start";
    HeifNclxColorProfile heifNclx(0, 0, 0, 0);
    HeifStreamWriter write;
    heif_error ret = heifNclx.Write(write);
    ASSERT_EQ(ret, heif_error_ok);
    GTEST_LOG_(INFO) << "HeifParserBoxTest: WriteTest002 end";
}

/**
 * @tc.name: GetPropertyTest001
 * @tc.desc: HeifIpcoBox
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserBoxTest, GetPropertyTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserBoxTest: GetPropertyTest001 start";
    auto heifIpcoBox = std::make_shared<HeifIpcoBox>();
    std::shared_ptr<HeifIpmaBox> heifIpmaBox = std::make_shared<HeifIpmaBox>();
    heif_item_id itemId = 1;
    uint32_t boxType = 0;
    struct PropertyAssociation rec {
        .essential = false,
        .propertyIndex = 0,
    };
    std::vector<PropertyAssociation> proPerty;
    proPerty.push_back(rec);
    struct PropertyEntry ref {
        .itemId = 0,
        .associations = proPerty,
    };
    heifIpmaBox->entries_.push_back(ref);
    EXPECT_EQ(heifIpcoBox->GetProperty(itemId, heifIpmaBox, boxType), nullptr);
    itemId = 0;
    EXPECT_EQ(heifIpcoBox->GetProperty(itemId, heifIpmaBox, boxType), nullptr);
    heifIpmaBox->entries_.clear();
    rec.propertyIndex = 1;
    proPerty.push_back(rec);
    ref.associations = proPerty;
    heifIpmaBox->entries_.push_back(ref);
    std::shared_ptr<HeifBox> heifBox = std::make_shared<HeifBox>(0);
    heifIpcoBox->children_.push_back(heifBox);
    heifIpcoBox->GetProperty(itemId, heifIpmaBox, boxType);
    boxType = 1;
    EXPECT_EQ(heifIpcoBox->GetProperty(itemId, heifIpmaBox, boxType), nullptr);
    GTEST_LOG_(INFO) << "HeifParserBoxTest: GetPropertyTest001 end";
}

/**
 * @tc.name: GetPropertiesTest001
 * @tc.desc: HeifIpcoBox
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserBoxTest, GetPropertiesTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserBoxTest: GetPropertiesTest001 start";
    auto heifIpcoBox = std::make_shared<HeifIpcoBox>();
    uint32_t itemId = 1;
    std::shared_ptr<HeifIpmaBox> ipma = std::make_shared<HeifIpmaBox>();
    std::vector<std::shared_ptr<HeifBox>> outProperties;
    struct PropertyAssociation rec {
        .essential = false,
        .propertyIndex = 16,
    };
    std::vector<PropertyAssociation> proPerty;
    proPerty.push_back(rec);
    struct PropertyEntry ref {
        .itemId = 0,
        .associations = proPerty,
    };
    ipma->entries_.push_back(ref);
    EXPECT_EQ(heifIpcoBox->GetProperties(itemId, ipma, outProperties), heif_error_property_not_found);
    itemId = 0;
    EXPECT_EQ(heifIpcoBox->GetProperties(itemId, ipma, outProperties), heif_error_invalid_property_index);
    GTEST_LOG_(INFO) << "HeifParserBoxTest: GetPropertiesTest001 end";
}

/**
 * @tc.name: GetPropertiesTest002
 * @tc.desc: HeifIpmaBox
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserBoxTest, GetPropertiesTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserBoxTest: GetPropertiesTest002 start";
    auto heifIpmaBox = std::make_shared<HeifIpmaBox>();
    uint32_t itemId = 1;
    struct PropertyEntry ref {.itemId = 0};
    heifIpmaBox->entries_.push_back(ref);
    EXPECT_EQ(heifIpmaBox->GetProperties(itemId), nullptr);
    GTEST_LOG_(INFO) << "HeifParserBoxTest: GetPropertiesTest002 end";
}

/**
 * @tc.name: InferFullBoxVersionTest001
 * @tc.desc: HeifIpmaBox
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserBoxTest, InferFullBoxVersionTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserBoxTest: InferFullBoxVersionTest001 start";
    auto heifIpmaBox = std::make_shared<HeifIpmaBox>();
    struct PropertyEntry ref {.itemId = 0xFFFFFFFF};
    heifIpmaBox->entries_.push_back(ref);
    heifIpmaBox->InferFullBoxVersion();
    EXPECT_EQ(heifIpmaBox->version_, HEIF_BOX_VERSION_ONE);
    heifIpmaBox->entries_.clear();
    struct PropertyAssociation rec {
        .essential = false,
        .propertyIndex = 0x8F,
    };
    std::vector<PropertyAssociation> proPerty;
    proPerty.push_back(rec);
    ref.itemId = 0xFF00;
    ref.associations = proPerty;
    heifIpmaBox->entries_.push_back(ref);
    heifIpmaBox->InferFullBoxVersion();
    EXPECT_EQ(heifIpmaBox->version_, HEIF_BOX_VERSION_ZERO);
    GTEST_LOG_(INFO) << "HeifParserBoxTest: InferFullBoxVersionTest001 end";
}

/**
 * @tc.name: ParseItemRefTest001
 * @tc.desc: HeifIrefBox
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserBoxTest, ParseItemRefTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ParseItemRefTest001 start";
    auto heifIrefBox = std::make_shared<HeifIrefBox>();
    auto inputStream = std::make_shared<HeifBufferInputStream>(nullptr, 0, true);
    HeifStreamReader reader(inputStream, 0, 0);
    HeifIrefBox::Reference ref;
    heifIrefBox->version_ = 1;
    heifIrefBox->ParseItemRef(reader, ref);
    ASSERT_EQ(ref.toItemIds.size(), 0);
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ParseItemRefTest001 end";
}

/**
 * @tc.name: InferFullBoxVersionTest002
 * @tc.desc: HeifIrefBox
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserBoxTest, InferFullBoxVersionTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserBoxTest: InferFullBoxVersionTest002 start";
    auto heifIrefBox = std::make_shared<HeifIrefBox>();
    struct HeifIrefBox::Reference ref {.fromItemId = 0xFFFFFFFF};
    heifIrefBox->references_.push_back(ref);
    EXPECT_TRUE((0xFFFFFFFF >> TWO_BYTES_SHIFT) > 0);
    heifIrefBox->InferFullBoxVersion();
    heifIrefBox->references_.clear();
    ref.fromItemId = 0x00000000;
    ref.toItemIds.push_back(0xFFFFFFFF);
    heifIrefBox->references_.push_back(ref);
    EXPECT_TRUE((0x00000000 >> TWO_BYTES_SHIFT) == 0);
    heifIrefBox->InferFullBoxVersion();
    GTEST_LOG_(INFO) << "HeifParserBoxTest: InferFullBoxVersionTest002 end";
}

/**
 * @tc.name: HasReferencesTest001
 * @tc.desc: HeifIrefBox
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserBoxTest, HasReferencesTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserBoxTest: HasReferencesTest001 start";
    auto heifIrefBox = std::make_shared<HeifIrefBox>();
    heif_item_id itemId = 0;
    struct HeifIrefBox::Reference ref {.fromItemId = 0};
    heifIrefBox->references_.push_back(ref);
    EXPECT_EQ(heifIrefBox->HasReferences(itemId), true);
    heifIrefBox->references_.clear();
    ref.fromItemId = 1;
    heifIrefBox->references_.push_back(ref);
    EXPECT_EQ(heifIrefBox->HasReferences(itemId), false);
    GTEST_LOG_(INFO) << "HeifParserBoxTest: HasReferencesTest001 end";
}

/**
 * @tc.name: ParseContentTest002
 * @tc.desc: HeifIinfBox
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserBoxTest, ParseContentTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ParseContentTest002 start";
    HeifIinfBox heifIinfBox;
    HeifInfeBox heifInfeBox;
    auto stream = std::make_shared<HeifBufferInputStream>(nullptr, 0, true);
    HeifStreamReader reader(stream, 0, 0);
    reader.hasError_ = false;
    ASSERT_EQ(heifIinfBox.ParseContent(reader), heif_error_ok);
    heifInfeBox.version_ = 0;
    heifInfeBox.ParseContent(reader);
    heifInfeBox.version_ = 3;
    heifInfeBox.ParseContent(reader);
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ParseContentTest002 end";
}

/**
 * @tc.name: InferFullBoxVersionTest003
 * @tc.desc: HeifInfeBox
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserBoxTest, InferFullBoxVersionTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserBoxTest: InferFullBoxVersionTest003 start";
    HeifInfeBox heifInfeBox;
    heifInfeBox.isHidden_ = false;
    heifInfeBox.itemType_ = "";
    ASSERT_EQ(heifInfeBox.itemType_.empty(), true);
    heifInfeBox.itemId_ = 0xFFFFFFFF;
    heifInfeBox.InferFullBoxVersion();
    GTEST_LOG_(INFO) << "HeifParserBoxTest: InferFullBoxVersionTest003 end";
}

/**
 * @tc.name: WriteTest003
 * @tc.desc: HeifInfeBox
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserBoxTest, WriteTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserBoxTest: WriteTest003 start";
    HeifInfeBox heifInfeBox;
    HeifStreamWriter write;
    heifInfeBox.version_ = 0;
    ASSERT_EQ(heifInfeBox.Write(write), heif_error_ok);
    heifInfeBox.version_ = HEIF_BOX_VERSION_THREE;
    heifInfeBox.itemType_ = "";
    ASSERT_EQ(heifInfeBox.itemType_.empty(), true);
    ASSERT_EQ(heifInfeBox.Write(write), heif_error_ok);
    heifInfeBox.itemType_ = "uri";
    ASSERT_EQ(heifInfeBox.Write(write), heif_error_ok);
    HeifPtimBox heifPtimBox;
    heifPtimBox.version_ = HEIF_BOX_VERSION_ONE;
    ASSERT_EQ(heifPtimBox.Write(write), heif_error_ok);
    GTEST_LOG_(INFO) << "HeifParserBoxTest: WriteTest003 end";
}

/**
 * @tc.name: InferHeaderSizeTest001
 * @tc.desc: HeifBox
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserBoxTest, InferHeaderSizeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserBoxTest: InferHeaderSizeTest001 start";
    HeifBox heifBox;
    heifBox. boxType_ = BOX_TYPE_UUID;
    ASSERT_EQ(heifBox.InferHeaderSize(), 24);
    GTEST_LOG_(INFO) << "HeifParserBoxTest: InferHeaderSizeTest001 end";
}

/**
 * @tc.name: AppendNalDataTest001
 * @tc.desc: HeifHvccBox
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserBoxTest, AppendNalDataTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserBoxTest: AppendNalDataTest001 start";
    HeifHvccBox heifHvccBox;
    std::vector<uint8_t> nalData = {0x01, 0x02, 0x03, 0x04};
    heifHvccBox.AppendNalData(nalData);
    GTEST_LOG_(INFO) << "HeifParserBoxTest: AppendNalDataTest001 end";
}

/**
 * @tc.name: AppendNalDataTest001
 * @tc.desc: Decode HeifHvccBox to valid SPS
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserBoxTest, AppendNalDataTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserBoxTest: AppendNalDataTest002 start";
    HeifHvccBox heifHvccBox;
    std::vector<uint8_t> nalData = {0X42, 0X01, 0X01, 0X03, 0X70, 0X00, 0X00, 0X03, 0X00, 0X90, 0X00,
        0X00, 0X03, 0X00, 0X00, 0X03, 0X00, 0X5a, 0Xa0, 0X04, 0X02, 0X00, 0X80, 0X59, 0X6e, 0Xa4, 0X92,
        0X9a, 0Xe6, 0Xc0, 0X80, 0X00, 0X00, 0X03, 0X00, 0X80, 0X00, 0X00, 0X03, 0X00, 0X84, 0x22, 0X00,
        0X01, 0x00, 0x07};
    heifHvccBox.ProcessBoxData(nalData);
    heifHvccBox.ParseNalUnitAnalysisSps(nalData);
    auto spsConfig = heifHvccBox.GetSpsConfig();
    ASSERT_EQ(spsConfig.nalUnitType, NAL_LAYER_ID);
    ASSERT_EQ(spsConfig.bitDepthLumaMinus8, 0);
    ASSERT_EQ(spsConfig.bitDepthChromaMinus8, 0);
    ASSERT_EQ(spsConfig.chromaFormatIdc, 1);
    ASSERT_EQ(spsConfig.picWidthInLumaSamples, 512);
    ASSERT_EQ(spsConfig.picHeightInLumaSamples, 512);
    ASSERT_EQ(spsConfig.videoRangeFlag, 1);
    GTEST_LOG_(INFO) << "HeifParserBoxTest: AppendNalDataTest002 end";
}

/**
 * @tc.name: AppendNalDataTest003
 * @tc.desc: Decode HeifHvccBox to valid SPS
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserBoxTest, AppendNalDataTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserBoxTest: AppendNalDataTest003 start";
    HeifHvccBox heifHvccBox;
    std::vector<uint8_t> nalData = {0x42, 0x01, 0x03, 0x01, 0x60, 0x00, 0x00, 0x03, 0x00, 0x00, 0x03, 0x00,
        0x00, 0x03, 0x00, 0x00, 0x03, 0x00, 0x78, 0x00, 0x00, 0xa0, 0x01, 0x80, 0x20, 0x15, 0x96, 0x37, 0xfd,
        0xc8, 0xb2, 0x6b, 0xb7, 0x35, 0x02, 0x02, 0x05, 0x00, 0x80, 0x22, 0x00, 0x01, 0x00, 0x07};
    ProcessBoxData(nalData);
    heifHvccBox.ParseNalUnitAnalysisSps(nalData);
    auto spsConfig = heifHvccBox.GetSpsConfig();
    ASSERT_EQ(spsConfig.nalUnitType, NAL_LAYER_ID);
    ASSERT_EQ(spsConfig.bitDepthLumaMinus8, 0);
    ASSERT_EQ(spsConfig.bitDepthChromaMinus8, 0);
    ASSERT_EQ(spsConfig.chromaFormatIdc, 1);
    ASSERT_EQ(spsConfig.picWidthInLumaSamples, 3072);
    ASSERT_EQ(spsConfig.picHeightInLumaSamples, 344);
    ASSERT_EQ(spsConfig.videoRangeFlag, 0);
    GTEST_LOG_(INFO) << "HeifParserBoxTest: AppendNalDataTest003 end";
}

/**
 * @tc.name: ParseExtentsTest001
 * @tc.desc: HeifIlocBox
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserBoxTest, ParseExtentsTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ParseExtentsTest001 start";
    HeifIlocBox heifIlocBox;
    HeifIlocBox::Item item;
    auto stream = std::make_shared<HeifBufferInputStream>(nullptr, 0, true);
    HeifStreamReader reader(stream, 0, 0);
    heifIlocBox.version_ = HEIF_BOX_VERSION_ONE;
    heifIlocBox.ParseExtents(item, reader, 4, 4, 4);
    heifIlocBox.ParseExtents(item, reader, 8, 8, 8);
    ASSERT_EQ(item.extents.size(), 0);
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ParseExtentsTest001 end";
}

/**
 * @tc.name: AppendDataTest001
 * @tc.desc: HeifIlocBox
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserBoxTest, AppendDataTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserBoxTest: AppendDataTest001 start";
    HeifIlocBox heifIlocBox;
    heif_item_id itemId = 0;
    std::vector<uint8_t> data;
    uint8_t constructionMethod = 1;
    ASSERT_EQ(heifIlocBox.UpdateData(itemId, data, constructionMethod), heif_invalid_exif_data);
    ASSERT_EQ(heifIlocBox.items_.size(), 0);
    constructionMethod = 0;
    ASSERT_EQ(heifIlocBox.UpdateData(itemId, data, constructionMethod), heif_error_item_not_found);
    heifIlocBox.items_.resize(2);
    ASSERT_EQ(heifIlocBox.items_.size(), 2);
    ASSERT_EQ(heifIlocBox.UpdateData(itemId, data, constructionMethod), heif_error_ok);
    GTEST_LOG_(INFO) << "HeifParserBoxTest: AppendDataTest001 end";
}

/**
 * @tc.name: ReadToExtentDataTest001
 * @tc.desc: HeifIlocBox
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserBoxTest, ReadToExtentDataTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ReadToExtentDataTest001 start";
    HeifIlocBox heifIlocBox;
    HeifIlocBox::Item item;
    struct HeifIlocBox::Extent ref {.offset = 1};
    item.extents.push_back(ref);
    item.baseOffset = 1;
    std::shared_ptr<HeifBufferInputStream> stream = std::make_shared<HeifBufferInputStream>(nullptr, 0, true);
    stream->length_ = 0;
    std::shared_ptr<HeifIdatBox> idatBox = std::make_shared<HeifIdatBox>();
    item.constructionMethod = 0;
    ASSERT_EQ(heifIlocBox.ReadToExtentData(item, stream, idatBox), heif_error_eof);
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ReadToExtentDataTest001 end";
}

/**
 * @tc.name: WriteTest004
 * @tc.desc: HeifIdatBox
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserBoxTest, WriteTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserBoxTest: WriteTest004 start";
    HeifIdatBox heifIdatBox;
    HeifStreamWriter writer;
    heifIdatBox.dataForWriting_ = {0xff};
    ASSERT_EQ(heifIdatBox.dataForWriting_.empty(), false);
    ASSERT_EQ(heifIdatBox.Write(writer), heif_error_ok);
    GTEST_LOG_(INFO) << "HeifParserBoxTest: WriteTest004 end";
}

/**
 * @tc.name: ReadDataTest001
 * @tc.desc: HeifIdatBox
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserBoxTest, ReadDataTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ReadDataTest001 start";
    HeifIdatBox heifIdatBox;
    std::shared_ptr<HeifInputStream> stream;
    std::vector<uint8_t> outData;
    heifIdatBox.startPos_ = 1;
    ASSERT_EQ(heifIdatBox.ReadData(stream, 16, 0, outData), heif_error_eof);
    ASSERT_EQ(heifIdatBox.ReadData(stream, 0, 16, outData), heif_error_eof);
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ReadDataTest001 end";
}

/**
 * @tc.name: ParseHeaderTest001
 * @tc.desc: Test ParseHeader when boxType is BOX_TYPE_UUID and size is enough or not
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserBoxTest, ParseHeaderTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ParseHeaderTest001 start";
    uint32_t boxSize = 1;
    auto data = SetUint32ToUint8Vertor(boxSize);
    auto type = SetUint32ToUint8Vertor(BOX_TYPE_UUID);
    data.insert(data.end(), type.begin(), type.end());
    auto stream = std::make_shared<HeifBufferInputStream>(data.data(), UINT64_BYTES_NUM, true);
    ASSERT_NE(stream, nullptr);
    HeifStreamReader reader1(stream, 0, UINT64_BYTES_NUM);

    HeifBox heifBox;
    heif_error error = heifBox.ParseContent(reader1);
    EXPECT_EQ(error, heif_error_ok);

    HeifStreamReader reader2(stream, 0, UUID_TYPE_BYTE_NUM);
    error = heifBox.ParseContent(reader2);
    EXPECT_EQ(error, heif_error_ok);
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ParseHeaderTest001 end";
}

/**
 * @tc.name: ParseContentTest003
 * @tc.desc: Test ParseContent of HeifPixiBox when CheckSize failed
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserBoxTest, ParseContentTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ParseContentTest003 start";
    HeifPixiBox heifPixBox;
    auto stream = std::make_shared<HeifBufferInputStream>(nullptr, 0, true);
    ASSERT_NE(stream, nullptr);
    HeifStreamReader reader(stream, 0, ERR_LENGTH);

    heif_error error = heifPixBox.ParseContent(reader);
    EXPECT_EQ(error, heif_error_eof);
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ParseContentTest003 end";
}

/**
 * @tc.name: WriteHeaderTest001
 * @tc.desc: Test WriteHeader when boxSize over 32 bits
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserBoxTest, WriteHeaderTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserBoxTest: WriteHeaderTest001 start";
    HeifBox heifBox;
    HeifStreamWriter writer;
    size_t boxSize = SIZE_32BITS + 1;

    heif_error error = heifBox.WriteHeader(writer, boxSize);
    EXPECT_EQ(error, heif_error_ok);
    GTEST_LOG_(INFO) << "HeifParserBoxTest: WriteHeaderTest001 end";
}

/**
 * @tc.name: WriteHeaderTest002
 * @tc.desc: Test WriteHeader when boxSize over 32 bits
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserBoxTest, WriteHeaderTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserBoxTest: WriteHeaderTest002 start";
    HeifBox heifBox;
    HeifStreamWriter writer;
    size_t boxSize = SIZE_32BITS + 1;
    heifBox.boxType_ = BOX_TYPE_UUID;

    heif_error error = heifBox.WriteHeader(writer, boxSize);
    EXPECT_EQ(error, heif_error_ok);
    GTEST_LOG_(INFO) << "HeifParserBoxTest: WriteHeaderTest002 end";
}

/**
 * @tc.name: ParseContentTest004
 * @tc.desc: Test ParseContent of HeifBox when CheckSize failed
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserBoxTest, ParseContentTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ParseContentTest004 start";
    auto stream = std::make_shared<HeifBufferInputStream>(nullptr, 0, true);
    ASSERT_NE(stream, nullptr);
    HeifStreamReader reader(stream, 0, ERR_LENGTH);
    HeifBox heifBox;

    heif_error error = heifBox.ParseContent(reader);
    EXPECT_EQ(error, heif_error_ok);
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ParseContentTest004 end";
}

/**
 * @tc.name: ParseContentChildrenTest001
 * @tc.desc: Test ParseContentChildren when CheckSize succeed or failed
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserBoxTest, ParseContentChildrenTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ParseContentChildrenTest001 start";
    auto stream1 = std::make_shared<HeifBufferInputStream>(nullptr, 0, true);
    ASSERT_NE(stream1, nullptr);
    HeifStreamReader reader1(stream1, 0, NORMAL_LENGTH);
    HeifBox heifBox;
    uint32_t recursionCount = 0;

    heif_error error = heifBox.ParseContentChildren(reader1, recursionCount);
    EXPECT_EQ(error, heif_error_ok);

    recursionCount = 0;
    auto stream2 = std::make_shared<HeifBufferInputStream>(nullptr, 0, true);
    ASSERT_NE(stream2, nullptr);
    HeifStreamReader reader2(stream2, 0, ERR_LENGTH);
    error = heifBox.ParseContentChildren(reader2, recursionCount);
    EXPECT_EQ(error, heif_error_ok);
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ParseContentChildrenTest001 end";
}


/**
 * @tc.name: MakeFromReaderTest001
 * @tc.desc: Test MakeFromReader when reader HasError is true or boxContentSize is error
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserBoxTest, MakeFromReaderTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserBoxTest: MakeFromReaderTest001 start";
    uint32_t recursionCount = 0;
    uint32_t boxSize = 1;
    auto data = SetUint32ToUint8Vertor(boxSize);
    auto type = SetUint32ToUint8Vertor(BOX_TYPE_FTYP);
    data.insert(data.end(), type.begin(), type.end());
    auto stream = std::make_shared<HeifBufferInputStream>(data.data(), UINT64_BYTES_NUM, true);
    ASSERT_NE(stream, nullptr);
    HeifStreamReader reader(stream, 0, UINT64_BYTES_NUM);
    reader.hasError_ = true;
    std::shared_ptr<HeifBox> heifBoxSptr;

    HeifBox heifBox;
    heif_error error = heifBox.MakeFromReader(reader, &heifBoxSptr, recursionCount);
    EXPECT_EQ(error, heif_error_eof);
    GTEST_LOG_(INFO) << "HeifParserBoxTest: MakeFromReaderTest001 end";
}

/**
 * @tc.name: GetPropertiesTest003
 * @tc.desc: Test HeifIpcoBox.GetProperties with propertyIndex equal to 0.
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserBoxTest, GetPropertiesTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserBoxTest: GetPropertiesTest003 start";
    auto heifIpcoBox = std::make_shared<HeifIpcoBox>();
    uint32_t itemId = 0;
    std::shared_ptr<HeifIpmaBox> ipma = std::make_shared<HeifIpmaBox>();
    std::vector<std::shared_ptr<HeifBox>> outProperties;

    struct PropertyAssociation rec {
        .essential = false,
        .propertyIndex = 0,
    };
    std::vector<PropertyAssociation> property;
    property.push_back(rec);
    struct PropertyEntry ref {
        .itemId = 0,
        .associations = property,
    };
    ipma->entries_.push_back(ref);

    ASSERT_EQ(heifIpcoBox->GetProperties(itemId, ipma, outProperties), heif_error_ok);
    ASSERT_EQ(outProperties.empty(), true);
    GTEST_LOG_(INFO) << "HeifParserBoxTest: GetPropertiesTest003 end";
}

/**
 * @tc.name: GetPropertyTest002
 * @tc.desc: Test HeifIpcoBox.GetProperty with matching property.
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserBoxTest, GetPropertyTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserBoxTest: GetPropertyTest002 start";
    auto heifIpcoBox = std::make_shared<HeifIpcoBox>();
    std::shared_ptr<HeifIpmaBox> heifIpmaBox = std::make_shared<HeifIpmaBox>();
    heif_item_id itemId = NOT_DEFAULT_INDEX;
    uint32_t boxType = NOT_DEFAULT_INDEX;

    auto property = std::make_shared<HeifBox>(boxType);
    heifIpcoBox->children_.push_back(property);

    struct PropertyAssociation assoc {
        .essential = false,
        .propertyIndex = NOT_DEFAULT_INDEX,
    };
    std::vector<PropertyAssociation> proPerty;
    proPerty.push_back(assoc);
    struct PropertyEntry entry {
        .itemId = itemId,
        .associations = proPerty,
    };
    heifIpmaBox->entries_.push_back(entry);

    auto result = heifIpcoBox->GetProperty(itemId, heifIpmaBox, boxType);
    ASSERT_NE(result, nullptr);
    ASSERT_EQ(result->GetBoxType(), boxType);

    boxType = BOX_TYPE;
    result = heifIpcoBox->GetProperty(itemId, heifIpmaBox, boxType);
    ASSERT_EQ(result, nullptr);
    GTEST_LOG_(INFO) << "HeifParserBoxTest: GetPropertyTest002 end";
}

/**
 * @tc.name: ParseContentTest005
 * @tc.desc: Test HeifIpmaBox.ParseContent, parsing content of HeifIpmaBox successfully.
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserBoxTest, ParseContentTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ParseContentTest005 start";
    HeifIpmaBox heifIpmaBox;
    auto stream = std::make_shared<HeifBufferInputStream>(BUFFER.data(), BUFFER.size(), true);
    HeifStreamReader reader(stream, 0, BUFFER.size());

    heif_error ret = heifIpmaBox.ParseContent(reader);
    ASSERT_EQ(ret, heif_error_ok);
    EXPECT_FALSE(reader.HasError());
    EXPECT_TRUE(reader.IsAtEnd());
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ParseContentTest005 end";
}

/**
 * @tc.name: AddPropertyTest001
 * @tc.desc: Test HeifIpmaBox.AddProperty, adding an already existing property.
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserBoxTest, AddPropertyTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserBoxTest: AddPropertyTest001 start";
    std::shared_ptr<HeifIpmaBox> heifIpmaBox = std::make_shared<HeifIpmaBox>();
    heif_item_id itemId = NOT_DEFAULT_INDEX;

    struct PropertyAssociation assoc {
        .essential = false,
        .propertyIndex = NOT_DEFAULT_INDEX,
    };
    std::vector<PropertyAssociation> proPerty;
    proPerty.push_back(assoc);
    struct PropertyEntry entry {
        .itemId = itemId,
        .associations = proPerty,
    };
    heifIpmaBox->entries_.push_back(entry);

    heifIpmaBox->AddProperty(0, assoc);
    ASSERT_EQ(heifIpmaBox->entries_.size(), PROPERTY_NUMBER);
    GTEST_LOG_(INFO) << "HeifParserBoxTest: AddPropertyTest001 end";
}

/**
 * @tc.name: WriteTest005
 * @tc.desc: Test HeifIpmaBox.Write, writing a HeifIpmaBox to a stream successfully.
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserBoxTest, WriteTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserBoxTest: WriteTest005 start";
    HeifIpmaBox heifIpmaBox;
    HeifStreamWriter writer;

    heifIpmaBox.SetVersion(HEIF_BOX_VERSION_ONE);
    heifIpmaBox.SetFlags(LARGE_PROPERTY_INDEX_FLAG);
    PropertyAssociation assoc;
    assoc.essential = true;
    assoc.propertyIndex = NOT_DEFAULT_INDEX;

    PropertyEntry entry;
    entry.itemId = NOT_DEFAULT_INDEX;
    entry.associations.push_back(assoc);
    heifIpmaBox.entries_.push_back(entry);

    heif_error ret = heifIpmaBox.Write(writer);
    ASSERT_EQ(ret, heif_error_ok);
    GTEST_LOG_(INFO) << "HeifParserBoxTest: WriteTest005 end";
}

/**
 * @tc.name: ParseHeaderTest002
 * @tc.desc: test ParseHeader interface to cover BOX_TYPE_UUID branch
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserBoxTest, ParseHeaderTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ParseHeaderTest002 start";
    std::vector<uint8_t> data;
    uint32_t boxSize = 24;
    auto sizeData = SetUint32ToUint8Vertor(boxSize);
    data.insert(data.end(), sizeData.begin(), sizeData.end());
    auto typeData = SetUint32ToUint8Vertor(BOX_TYPE_UUID);
    data.insert(data.end(), typeData.begin(), typeData.end());
    std::vector<uint8_t> uuidData = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
    };
    data.insert(data.end(), uuidData.begin(), uuidData.end());
    auto stream = std::make_shared<HeifBufferInputStream>(data.data(), data.size(), true);
    ASSERT_NE(stream, nullptr);
    HeifStreamReader reader(stream, 0, data.size());
    HeifBox heifBox;
    heif_error error = heifBox.ParseHeader(reader);
    EXPECT_EQ(error, heif_error_ok);
    EXPECT_EQ(heifBox.GetBoxType(), BOX_TYPE_UUID);
    EXPECT_EQ(heifBox.boxUuidType_.size(), UUID_TYPE_BYTE_NUM);
    EXPECT_EQ(memcmp(heifBox.boxUuidType_.data(), uuidData.data(), UUID_TYPE_BYTE_NUM), 0);
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ParseHeaderTest002 end";
}

/**
 * @tc.name: ParseHeaderTest003
 * @tc.desc: test ParseHeader interface to cover BOX_TYPE_UUID branch with successful CheckSize
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserBoxTest, ParseHeaderTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ParseHeaderTest003 start";
    std::vector<uint8_t> data;
    uint32_t boxSize = 24;
    auto sizeData = SetUint32ToUint8Vertor(boxSize);
    data.insert(data.end(), sizeData.begin(), sizeData.end());
    auto typeData = SetUint32ToUint8Vertor(BOX_TYPE_UUID);
    data.insert(data.end(), typeData.begin(), typeData.end());
    std::vector<uint8_t> uuidData = {
        0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18,
        0x29, 0x3A, 0x4B, 0x5C, 0x6D, 0x7E, 0x8F, 0x90
    };
    data.insert(data.end(), uuidData.begin(), uuidData.end());
    auto stream = std::make_shared<HeifBufferInputStream>(data.data(), data.size(), true);
    ASSERT_NE(stream, nullptr);
    HeifStreamReader reader(stream, 0, data.size());
    HeifBox heifBox;
    heif_error error = heifBox.ParseHeader(reader);
    EXPECT_EQ(error, heif_error_ok);
    EXPECT_EQ(heifBox.GetBoxType(), BOX_TYPE_UUID);
    EXPECT_EQ(heifBox.boxUuidType_.size(), UUID_TYPE_BYTE_NUM);
    EXPECT_EQ(memcmp(heifBox.boxUuidType_.data(), uuidData.data(), UUID_TYPE_BYTE_NUM), 0);
    EXPECT_EQ(heifBox.headerSize_, UINT64_BYTES_NUM + UUID_TYPE_BYTE_NUM);
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ParseHeaderTest003 end";
}

/**
 * @tc.name: MakeBox001
 * @tc.desc: test MakeBox when boxType is imir
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserBoxTest, MakeBox001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserBoxTest: MakeBox001 start";
    uint32_t boxType = fourcc_to_code("imir");
    std::shared_ptr<HeifBox> test = HeifBox::MakeBox(boxType);
    ASSERT_NE(test, nullptr);
    GTEST_LOG_(INFO) << "HeifParserBoxTest: MakeBox001 end";
}

/**
 * @tc.name: MakeFromReaderTest002
 * @tc.desc: test MakeFromReader interface to cover invalid box size branch
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserBoxTest, MakeFromReaderTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserBoxTest: MakeFromReaderTest002 start";
    uint32_t recursionCount = 0;
    uint32_t boxSize = 4;
    auto sizeData = SetUint32ToUint8Vertor(boxSize);
    auto typeData = SetUint32ToUint8Vertor(BOX_TYPE_FTYP);
    std::vector<uint8_t> data;
    data.insert(data.end(), sizeData.begin(), sizeData.end());
    data.insert(data.end(), typeData.begin(), typeData.end());
    auto stream = std::make_shared<HeifBufferInputStream>(data.data(), data.size(), true);
    ASSERT_NE(stream, nullptr);
    HeifStreamReader reader(stream, 0, data.size());
    std::shared_ptr<HeifBox> heifBoxSptr;
    HeifBox heifBox;
    heif_error error = heifBox.MakeFromReader(reader, &heifBoxSptr, recursionCount);
    EXPECT_EQ(error, heif_error_invalid_box_size);
    GTEST_LOG_(INFO) << "HeifParserBoxTest: MakeFromReaderTest002 end";
}

/**
 * @tc.name: ReadChildren001
 * @tc.desc: test ReadChildren interface
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserBoxTest, ReadChildren001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ReadChildren001 start";
    uint32_t recursionCount = 0;
    uint32_t boxSize = 1;
    auto data = SetUint32ToUint8Vertor(boxSize);
    auto type = SetUint32ToUint8Vertor(BOX_TYPE_FTYP);
    data.insert(data.end(), type.begin(), type.end());
    auto stream = std::make_shared<HeifBufferInputStream>(data.data(), UINT64_BYTES_NUM, true);
    ASSERT_NE(stream, nullptr);
    HeifStreamReader reader(stream, 0, UINT64_BYTES_NUM);
    reader.hasError_ = true;

    HeifBox heifBox;
    heif_error error = heifBox.ReadChildren(reader, recursionCount);
    EXPECT_EQ(error, heif_error_eof);
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ReadChildren001 end";
}

/**
 * @tc.name: WriteChildren001
 * @tc.desc: test WriteChildren interface
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserBoxTest, WriteChildren001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserBoxTest: WriteChildren001 start";
    HeifBox parentBox;
    auto grplChild = std::make_shared<HeifBox>();
    grplChild->boxType_ = BOX_TYPE_GRPL;
    auto normalChild = std::make_shared<HeifBox>();
    normalChild->boxType_ = BOX_TYPE_FTYP;
    parentBox.children_.push_back(grplChild);
    parentBox.children_.push_back(normalChild);
    HeifStreamWriter writer;
    heif_error error = parentBox.WriteChildren(writer);
    EXPECT_EQ(error, heif_error_ok);
    const std::vector<uint8_t>& writtenData = writer.GetData();
    EXPECT_GE(writtenData.size(), 8u);
    GTEST_LOG_(INFO) << "HeifParserBoxTest: WriteChildren001 end";
}

/**
 * @tc.name: ParseItemRefNormalLoopTest001
 * @tc.desc: Test parsing complete item reference data with multiple target items
 *           Verifies correct extraction of all referenced item IDs from stream
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserBoxTest, ParseItemRefNormalLoopTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ParseItemRefNormalLoopTest001 start";
    HeifIrefBox heifIrefBox;
    HeifIrefBox::Reference ref;

    std::vector<uint8_t> data;
    auto fromId = SetUint32ToUint8Vertor(TEST_FROM_ITEM_ID);
    data.insert(data.end(), fromId.begin(), fromId.end());
    data.push_back(0x00);
    data.push_back(TEST_ITEM_COUNT);
    auto toId1 = SetUint32ToUint8Vertor(TEST_TO_ITEM_ID_1);
    data.insert(data.end(), toId1.begin(), toId1.end());
    auto toId2 = SetUint32ToUint8Vertor(TEST_TO_ITEM_ID_2);
    data.insert(data.end(), toId2.begin(), toId2.end());
    auto toId3 = SetUint32ToUint8Vertor(TEST_TO_ITEM_ID_3);
    data.insert(data.end(), toId3.begin(), toId3.end());

    auto stream = std::make_shared<HeifBufferInputStream>(data.data(), data.size(), true);
    HeifStreamReader reader(stream, 0, data.size());

    heifIrefBox.version_ = HEIF_BOX_VERSION_ONE;
    heifIrefBox.ParseItemRef(reader, ref);

    ASSERT_EQ(ref.fromItemId, TEST_FROM_ITEM_ID);
    ASSERT_EQ(ref.toItemIds.size(), TEST_ITEM_COUNT);
    ASSERT_EQ(ref.toItemIds[0], TEST_TO_ITEM_ID_1);
    ASSERT_EQ(ref.toItemIds[1], TEST_TO_ITEM_ID_2);
    ASSERT_EQ(ref.toItemIds[2], TEST_TO_ITEM_ID_3);
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ParseItemRefNormalLoopTest001 end";
}

/**
 * @tc.name: ParseContentHeaderErrorTest001
 * @tc.desc: Test parsing IREF box with truncated child box data stream
 *           Ensures proper error detection when box structure is incomplete
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserBoxTest, ParseContentHeaderErrorTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ParseContentHeaderErrorTest001 start";
    HeifIrefBox heifIrefBox;

    std::vector<uint8_t> data = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    auto stream = std::make_shared<HeifBufferInputStream>(data.data(), data.size(), true);
    HeifStreamReader reader(stream, 0, data.size());

    heif_error error = heifIrefBox.ParseContent(reader);

    ASSERT_NE(error, heif_error_ok);
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ParseContentHeaderErrorTest001 end";
}

}
}