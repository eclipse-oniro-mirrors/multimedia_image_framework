/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <map>
#include "box/cr3_box.h"
#include "heif_box.h"
#include "heif_utils.h"
#include "image_log.h"
#include "media_errors.h"

using namespace testing::ext;
namespace OHOS {
namespace ImagePlugin {

static constexpr uint32_t UINT32_BYTE_SIZE = 4;
static constexpr uint32_t UINT64_BYTE_SIZE = 8;
static constexpr uint32_t DEFAULT_BUFFER_SIZE = 1024;
static constexpr uint32_t MAX_RECURSION_COUNT = 300;
static constexpr uint64_t START = 6;
static constexpr uint64_t LENGTH = 6;
static const std::uint64_t START_POS = 10;
static const std::vector<uint8_t> INPUTDATA_FTYP = {0x00, 0x00, 0x00, 0x20, 'f', 't', 'y', 'p'};
static const std::vector<uint8_t> INPUTDATA_UUID = {0x00, 0x00, 0x00, 0x18, 'u', 'u', 'i', 'd',
                                                    0xBE, 0x7A, 0xCF, 0xCB, 0x97, 0xA9, 0x42, 0xE8,
                                                    0x9C, 0x71, 0x99, 0x94, 0x91, 0xE3, 0xAF, 0xAC};
static const std::vector<uint8_t> INPUTDATA_FTYP_WITH_PAYLOAD = {0x00, 0x00, 0x00, 0x0C, 'f', 't', 'y', 'p',
                                                                 0x00, 0x00, 0x00, 0x00};
static const std::vector<uint8_t> INPUTDATA_MOOV = {0x00, 0x00, 0x00, 0x08, 'm', 'o', 'o', 'v'};
static const std::vector<uint8_t> INPUTDATA_UUID_WITH_PAYLOAD = {0x00, 0x00, 0x00, 0x18, 'u', 'u', 'i', 'd',
                                                                 0xBE, 0x7A, 0xCF, 0xCB, 0x97, 0xA9, 0x42, 0xE8,
                                                                 0x9C, 0x71, 0x99, 0x94, 0x91, 0xE3, 0xAF, 0xAC};

class Cr3BoxTest : public testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

std::shared_ptr<HeifInputStream> CreateHeifInputStream(const std::vector<uint8_t>& data, bool needCopy = false)
{
    std::shared_ptr<HeifInputStream> heifInputStream =
        std::make_shared<HeifBufferInputStream>(data.data(), data.size(), needCopy);
    return heifInputStream;
}

/**
 * @tc.name: MakeCr3BoxTest001
 * @tc.desc: Test the creation of Cr3Box, input different types, expect correspond type.
 * @tc.type: FUNC
 */
HWTEST_F(Cr3BoxTest, MakeCr3BoxTest001, testing::ext::TestSize.Level3)
{
    GTEST_LOG_(INFO) << "Cr3BoxTest: MakeCr3BoxTest001 start";

    std::shared_ptr<Cr3Box> ftypBox = Cr3Box::MakeCr3Box(BOX_TYPE_FTYP);
    auto ftypType = ftypBox->GetBoxType();
    EXPECT_EQ(ftypType, BOX_TYPE_FTYP);

    std::shared_ptr<Cr3Box> uuidBox = std::make_shared<Cr3Box>(BOX_TYPE_UUID);
    auto uuidType = uuidBox->GetBoxType();
    EXPECT_EQ(uuidType, BOX_TYPE_UUID);

    std::shared_ptr<Cr3Box> moovBox = std::make_shared<Cr3Box>(CR3_BOX_TYPE_MOOV);
    auto moovType = moovBox->GetBoxType();
    EXPECT_EQ(moovType, CR3_BOX_TYPE_MOOV);

    std::shared_ptr<Cr3Box> prvwBox = std::make_shared<Cr3Box>(CR3_BOX_TYPE_PRVW);
    auto prvwType = prvwBox->GetBoxType();
    EXPECT_EQ(prvwType, CR3_BOX_TYPE_PRVW);

    std::shared_ptr<Cr3Box> ilocBox = std::make_shared<Cr3Box>(BOX_TYPE_ILOC);
    auto ilocType = ilocBox->GetBoxType();
    EXPECT_EQ(ilocType, BOX_TYPE_ILOC);

    GTEST_LOG_(INFO) << "Cr3BoxTest: MakeCr3BoxTest001 end";
}

/**
 * @tc.name: MakeCr3FromReaderTest001
 * @tc.desc: Test MakeCr3FromReader, input error size, expect header parser fail.
 * @tc.type: FUNC
 */
HWTEST_F(Cr3BoxTest, MakeCr3FromReaderTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "Cr3BoxTest: MakeCr3FromReaderTest001 start";

    std::vector<uint8_t> inputData(DEFAULT_BUFFER_SIZE);
    std::shared_ptr<HeifInputStream> heifInputStream = CreateHeifInputStream(inputData);
    uint64_t start = 0;
    uint64_t length = UINT32_BYTE_SIZE;

    HeifStreamReader reader(heifInputStream, start, length);
    std::shared_ptr<Cr3Box> result;
    uint32_t recursionCount = 0;

    auto res = Cr3Box::MakeCr3FromReader(reader, result, recursionCount);
    EXPECT_EQ(res, heif_error_eof);

    GTEST_LOG_(INFO) << "Cr3BoxTest: MakeCr3FromReaderTest001 end";
}

/**
 * @tc.name: ReadDataTest001
 * @tc.desc: Test ReadData, input invaild start and length, expect error eof.
 * @tc.type: FUNC
 */
HWTEST_F(Cr3BoxTest, ReadDataTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "Cr3BoxTest: ReadDataTest001 start";

    std::vector<uint8_t> inputData(DEFAULT_BUFFER_SIZE);
    std::shared_ptr<HeifInputStream> heifInputStream = CreateHeifInputStream(inputData);
    uint64_t start = UINT32_BYTE_SIZE;
    uint64_t length = 0;
    std::vector<uint8_t> outData;

    auto cr3Box = std::make_shared<Cr3Box>();
    auto res = cr3Box->ReadData(heifInputStream, start, length, outData);
    EXPECT_EQ(res, heif_error_eof);

    GTEST_LOG_(INFO) << "Cr3BoxTest: ReadDataTest001 end";
}

/**
 * @tc.name: ReadDataTest002
 * @tc.desc: Test ReadData, input empty stream, expect error no data.
 * @tc.type: FUNC
 */
HWTEST_F(Cr3BoxTest, ReadDataTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "Cr3BoxTest: ReadDataTest002 start";

    std::vector<uint8_t> inputData(DEFAULT_BUFFER_SIZE);
    std::shared_ptr<HeifInputStream> heifInputStream = CreateHeifInputStream(inputData);
    uint64_t start = UINT32_BYTE_SIZE;
    uint64_t length = 0;
    std::vector<uint8_t> outData;

    auto cr3Box = std::make_shared<Cr3Box>();
    heifInputStream = nullptr;
    auto res = cr3Box->ReadData(heifInputStream, start, length, outData);
    EXPECT_EQ(res, heif_error_no_data);

    GTEST_LOG_(INFO) << "Cr3BoxTest: ReadDataTest002 end";
}

/**
 * @tc.name: ReadCr3ChildrenTest001
 * @tc.desc: Test ReadCr3Children, input invaild size, expect read error.
 * @tc.type: FUNC
 */
HWTEST_F(Cr3BoxTest, ReadCr3ChildrenTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "Cr3BoxTest: ReadCr3ChildrenTest001 start";

    std::vector<uint8_t> inputData(DEFAULT_BUFFER_SIZE);
    std::shared_ptr<HeifInputStream> heifInputStream = CreateHeifInputStream(inputData);
    uint64_t start = 0;
    uint64_t length = UINT32_BYTE_SIZE;

    std::shared_ptr<HeifStreamReader> heifStreamReader = std::make_shared<HeifStreamReader>(
        heifInputStream, start, length);
    uint32_t recursionCount = 0;

    auto cr3Box = std::make_shared<Cr3Box>();
    auto res = cr3Box->ReadCr3Children(*heifStreamReader, recursionCount);
    EXPECT_NE(res, heif_error_ok);

    GTEST_LOG_(INFO) << "Cr3BoxTest: ReadCr3ChildrenTest001 end";
}

/**
 * @tc.name: GetCr3UuidTypeTest001
 * @tc.desc: Test GetCr3UuidType, no input, expect get default type : UNKNOWN.
 * @tc.type: FUNC
 */
HWTEST_F(Cr3BoxTest, GetCr3UuidTypeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "Cr3BoxTest: GetCr3UuidTypeTest001 start";

    auto cr3UuidBox = std::make_shared<Cr3UuidBox>();
    auto res = cr3UuidBox->GetCr3UuidType();
    EXPECT_EQ(res, Cr3UuidBox::Cr3UuidType::UNKNOWN);

    GTEST_LOG_(INFO) << "Cr3BoxTest: GetCr3UuidTypeTest001 end";
}

/**
 * @tc.name: Cr3UuidBoxParseContentChildrenTest001
 * @tc.desc: Test ParseContentChildren, input recursionCount bigger than MAX_RECURSION, expect error.
 * @tc.type: FUNC
 */
HWTEST_F(Cr3BoxTest, Cr3UuidBoxParseContentChildrenTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "Cr3BoxTest: Cr3UuidBoxParseContentChildrenTest001 start";

    std::vector<uint8_t> inputData(DEFAULT_BUFFER_SIZE);
    std::shared_ptr<HeifInputStream> heifInputStream = CreateHeifInputStream(inputData);
    uint64_t start = 0;
    uint64_t length = UINT32_BYTE_SIZE;

    std::shared_ptr<HeifStreamReader> heifStreamReader = std::make_shared<HeifStreamReader>(
        heifInputStream, start, length);
    uint32_t recursionCount = MAX_RECURSION_COUNT;

    auto cr3UuidBox = std::make_shared<Cr3UuidBox>();
    auto res =  cr3UuidBox->ParseContentChildren(*heifStreamReader, recursionCount);
    EXPECT_EQ(res, heif_error_too_many_recursion);

    GTEST_LOG_(INFO) << "Cr3BoxTest: Cr3UuidBoxParseContentChildrenTest001 end";
}

/**
 * @tc.name: Cr3UuidBoxParseContentChildrenTest002
 * @tc.desc: Test ParseContentChildren, set uuidType CANON, expect ok.
 * @tc.type: FUNC
 */
HWTEST_F(Cr3BoxTest, Cr3UuidBoxParseContentChildrenTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "Cr3BoxTest: Cr3UuidBoxParseContentChildrenTest002 start";

    std::vector<uint8_t> inputData(DEFAULT_BUFFER_SIZE);
    std::shared_ptr<HeifInputStream> heifInputStream = CreateHeifInputStream(inputData);
    uint64_t start = 0;
    uint64_t length = UINT32_BYTE_SIZE;

    std::shared_ptr<HeifStreamReader> heifStreamReader = std::make_shared<HeifStreamReader>(
        heifInputStream, start, length);
    uint32_t recursionCount = 0;

    auto cr3UuidBox = std::make_shared<Cr3UuidBox>();
    cr3UuidBox->cr3UuidType_ = Cr3UuidBox::Cr3UuidType::CANON;
    auto res =  cr3UuidBox->ParseContentChildren(*heifStreamReader, recursionCount);
    EXPECT_NE(res, heif_error_ok);

    GTEST_LOG_(INFO) << "Cr3BoxTest: Cr3UuidBoxParseContentChildrenTest002 end";
}

/**
 * @tc.name: Cr3UuidBoxParseContentChildrenTest003
 * @tc.desc: Test ParseContentChildren, set uuidType PREVIEW, expect ok.
 * @tc.type: FUNC
 */
HWTEST_F(Cr3BoxTest, Cr3UuidBoxParseContentChildrenTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "Cr3BoxTest: Cr3UuidBoxParseContentChildrenTest003 start";

    std::vector<uint8_t> inputData(DEFAULT_BUFFER_SIZE);
    std::shared_ptr<HeifInputStream> heifInputStream = CreateHeifInputStream(inputData);
    uint64_t start = 0;
    uint64_t length = UINT32_BYTE_SIZE;

    std::shared_ptr<HeifStreamReader> heifStreamReader = std::make_shared<HeifStreamReader>(
        heifInputStream, start, length);
    uint32_t recursionCount = 0;

    auto cr3UuidBox = std::make_shared<Cr3UuidBox>();
    cr3UuidBox->cr3UuidType_ = Cr3UuidBox::Cr3UuidType::PREVIEW;
    auto res =  cr3UuidBox->ParseContentChildren(*heifStreamReader, recursionCount);
    EXPECT_NE(res, heif_error_ok);

    GTEST_LOG_(INFO) << "Cr3BoxTest: Cr3UuidBoxParseContentChildrenTest003 end";
}

/**
 * @tc.name: Cr3UuidBoxParseContentChildrenTest004
 * @tc.desc: Test ParseContentChildren, set uuidType XMP, expect ok.
 * @tc.type: FUNC
 */
HWTEST_F(Cr3BoxTest, Cr3UuidBoxParseContentChildrenTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "Cr3BoxTest: Cr3UuidBoxParseContentChildrenTest004 start";

    std::vector<uint8_t> inputData(DEFAULT_BUFFER_SIZE);
    std::shared_ptr<HeifInputStream> heifInputStream = CreateHeifInputStream(inputData);
    uint64_t start = 0;
    uint64_t length = UINT32_BYTE_SIZE;

    std::shared_ptr<HeifStreamReader> heifStreamReader = std::make_shared<HeifStreamReader>(
        heifInputStream, start, length);
    uint32_t recursionCount = 0;

    auto cr3UuidBox = std::make_shared<Cr3UuidBox>();
    cr3UuidBox->cr3UuidType_ = Cr3UuidBox::Cr3UuidType::XMP;
    auto res =  cr3UuidBox->ParseContentChildren(*heifStreamReader, recursionCount);
    EXPECT_EQ(res, heif_error_ok);

    GTEST_LOG_(INFO) << "Cr3BoxTest: Cr3UuidBoxParseContentChildrenTest004 end";
}

/**
 * @tc.name: Cr3MoovBoxParseContentChildrenTest001
 * @tc.desc: Test ParseContentChildren, input recursionCount bigger than MAX_RECURSION, expect error.
 * @tc.type: FUNC
 */
HWTEST_F(Cr3BoxTest, Cr3MoovBoxParseContentChildrenTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "Cr3BoxTest: Cr3MoovBoxParseContentChildrenTest001 start";


    std::vector<uint8_t> inputData(DEFAULT_BUFFER_SIZE);
    std::shared_ptr<HeifInputStream> heifInputStream = CreateHeifInputStream(inputData);
    uint64_t start = 0;
    uint64_t length = UINT32_BYTE_SIZE;

    std::shared_ptr<HeifStreamReader> heifStreamReader = std::make_shared<HeifStreamReader>(
        heifInputStream, start, length);
    uint32_t recursionCount = MAX_RECURSION_COUNT;

    auto cr3MoovBox = std::make_shared<Cr3MoovBox>();
    auto res =  cr3MoovBox->ParseContentChildren(*heifStreamReader, recursionCount);
    EXPECT_EQ(res, heif_error_too_many_recursion);

    GTEST_LOG_(INFO) << "Cr3BoxTest: Cr3MoovBoxParseContentChildrenTest001 end";
}

/**
 * @tc.name: Cr3FtypBoxParseContentTest001
 * @tc.desc: Test ParseContent, input empty stream, expect read error.
 * @tc.type: FUNC
 */
HWTEST_F(Cr3BoxTest, Cr3FtypBoxParseContentTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "Cr3BoxTest: Cr3FtypBoxParseContentTest001 start";

    std::vector<uint8_t> inputData(DEFAULT_BUFFER_SIZE);
    std::shared_ptr<HeifInputStream> heifInputStream = CreateHeifInputStream(inputData);
    uint64_t start = 0;
    uint64_t length = UINT64_BYTE_SIZE;

    std::shared_ptr<HeifStreamReader> heifStreamReader = std::make_shared<HeifStreamReader>(
        heifInputStream, start, length);

    auto cr3FtypBox = std::make_shared<Cr3FtypBox>();
    heifStreamReader->hasError_ = false;
    auto res =  cr3FtypBox->ParseContent(*heifStreamReader);
    EXPECT_NE(res, heif_error_ok);

    GTEST_LOG_(INFO) << "Cr3BoxTest: Cr3FtypBoxParseContentTest001 end";
}

/**
 * @tc.name: MakeCr3BoxTest002
 * @tc.desc: Test the creation of Cr3Box, input different types, expect correspond type.
 * @tc.type: FUNC
 */
HWTEST_F(Cr3BoxTest, MakeCr3BoxTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "Cr3BoxTest: MakeCr3BoxTest002 start";

    std::shared_ptr<Cr3Box> uuidBox = Cr3Box::MakeCr3Box(BOX_TYPE_UUID);
    auto uuidType = uuidBox->GetBoxType();
    EXPECT_EQ(uuidType, BOX_TYPE_UUID);

    std::shared_ptr<Cr3Box> moovBox = Cr3Box::MakeCr3Box(CR3_BOX_TYPE_MOOV);
    auto moovType = moovBox->GetBoxType();
    EXPECT_EQ(moovType, CR3_BOX_TYPE_MOOV);

    std::shared_ptr<Cr3Box> prvwBox = Cr3Box::MakeCr3Box(CR3_BOX_TYPE_PRVW);
    auto prvwType = prvwBox->GetBoxType();
    EXPECT_EQ(prvwType, CR3_BOX_TYPE_PRVW);

    GTEST_LOG_(INFO) << "Cr3BoxTest: MakeCr3BoxTest002 end";
}

/**
 * @tc.name: MakeCr3FromReaderTest002
 * @tc.desc: Test MakeCr3FromReader when content size exceeds available data, expect EOF.
 * @tc.type: FUNC
 */
HWTEST_F(Cr3BoxTest, MakeCr3FromReaderTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "Cr3BoxTest: MakeCr3FromReaderTest002 start";

    std::shared_ptr<HeifInputStream> heifInputStream = CreateHeifInputStream(INPUTDATA_FTYP);
    uint64_t start = 0;
    uint64_t length = INPUTDATA_FTYP.size();
    HeifStreamReader reader(heifInputStream, start, length);
    std::shared_ptr<Cr3Box> result;
    uint32_t recursionCount = 0;

    auto res = Cr3Box::MakeCr3FromReader(reader, result, recursionCount);
    EXPECT_EQ(res, heif_error_eof);

    GTEST_LOG_(INFO) << "Cr3BoxTest: MakeCr3FromReaderTest002 end";
}

/**
 * @tc.name: MakeCr3FromReaderTest003
 * @tc.desc: Test MakeCr3FromReader with UUID box to cover ParseContentChildren branch.
 * @tc.type: FUNC
 */
HWTEST_F(Cr3BoxTest, MakeCr3FromReaderTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "Cr3BoxTest: MakeCr3FromReaderTest003 start";

    std::shared_ptr<HeifInputStream> heifInputStream = CreateHeifInputStream(INPUTDATA_UUID);
    uint64_t start = 0;
    uint64_t length = INPUTDATA_UUID.size();
    HeifStreamReader reader(heifInputStream, start, length);
    std::shared_ptr<Cr3Box> result;
    uint32_t recursionCount = 0;

    auto res = Cr3Box::MakeCr3FromReader(reader, result, recursionCount);
    EXPECT_EQ(res, heif_error_ok);

    GTEST_LOG_(INFO) << "Cr3BoxTest: MakeCr3FromReaderTest003 end";
}

/**
 * @tc.name: MakeCr3FromReaderTest004
 * @tc.desc: Test MakeCr3FromReader with non-children box to cover ParseContent branch.
 * @tc.type: FUNC
 */
HWTEST_F(Cr3BoxTest, MakeCr3FromReaderTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "Cr3BoxTest: MakeCr3FromReaderTest004 start";

    std::shared_ptr<HeifInputStream> heifInputStream = CreateHeifInputStream(INPUTDATA_FTYP_WITH_PAYLOAD);
    uint64_t start = 0;
    uint64_t length = INPUTDATA_FTYP_WITH_PAYLOAD.size();
    HeifStreamReader reader(heifInputStream, start, length);
    std::shared_ptr<Cr3Box> result;
    uint32_t recursionCount = 0;

    auto res = Cr3Box::MakeCr3FromReader(reader, result, recursionCount);
    EXPECT_EQ(res, heif_error_eof);

    GTEST_LOG_(INFO) << "Cr3BoxTest: MakeCr3FromReaderTest004 end";
}

/**
 * @tc.name: MakeCr3FromReaderTest005
 * @tc.desc: Test MakeCr3FromReader. When recursion count is 0, expect OK; When recursion count exceeds 0, expect EOF.
 * @tc.type: FUNC
 */
HWTEST_F(Cr3BoxTest, MakeCr3FromReaderTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "Cr3BoxTest: MakeCr3FromReaderTest005 start";

    std::shared_ptr<HeifInputStream> heifInputStream = CreateHeifInputStream(INPUTDATA_MOOV);
    uint64_t start = 0;
    uint64_t length = INPUTDATA_MOOV.size();
    HeifStreamReader reader(heifInputStream, start, length);
    std::shared_ptr<Cr3Box> result;
    uint32_t recursionCount = 0;

    auto res = Cr3Box::MakeCr3FromReader(reader, result, recursionCount);
    EXPECT_EQ(res, heif_error_ok);

    recursionCount = MAX_RECURSION_COUNT;
    res = Cr3Box::MakeCr3FromReader(reader, result, recursionCount);
    EXPECT_EQ(res, heif_error_eof);

    GTEST_LOG_(INFO) << "Cr3BoxTest: MakeCr3FromReaderTest005 end";
}

/**
 * @tc.name: ReadDataTest003
 * @tc.desc: Test ReadData. When startPos >= any of start, length, or their sum, expect OK; otherwise expect EOF.
 * @tc.type: FUNC
 */
HWTEST_F(Cr3BoxTest, ReadDataTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "Cr3BoxTest: ReadDataTest003 start";

    std::vector<uint8_t> inputData(DEFAULT_BUFFER_SIZE);
    std::shared_ptr<HeifInputStream> heifInputStream = CreateHeifInputStream(inputData);
    std::vector<uint8_t> outData;
    auto cr3Box = std::make_shared<Cr3Box>();
    uint64_t start = 0;
    uint64_t length = UINT32_BYTE_SIZE;
    cr3Box->startPos_ = 0;
    auto res = cr3Box->ReadData(heifInputStream, start, length, outData);
    EXPECT_EQ(res, heif_error_eof);

    start = START;
    length = LENGTH;
    cr3Box->startPos_ = START_POS;
    res = cr3Box->ReadData(heifInputStream, start, length, outData);
    EXPECT_EQ(res, heif_error_eof);

    start = 0;
    res = cr3Box->ReadData(heifInputStream, start, length, outData);
    EXPECT_EQ(res, heif_error_eof);

    length = 0;
    res = cr3Box->ReadData(heifInputStream, start, length, outData);
    EXPECT_EQ(res, heif_error_ok);

    GTEST_LOG_(INFO) << "Cr3BoxTest: ReadDataTest003 end";
}

/**
 * @tc.name: ReadCr3ChildrenTest002
 * @tc.desc: Test ReadCr3Children handling across error-flag and end-of-stream states.
 * @tc.type: FUNC
 */
HWTEST_F(Cr3BoxTest, ReadCr3ChildrenTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "Cr3BoxTest: ReadCr3ChildrenTest002 start";

    std::vector<uint8_t> inputData(DEFAULT_BUFFER_SIZE);
    std::shared_ptr<HeifInputStream> heifInputStream = CreateHeifInputStream(inputData);
    uint64_t start = 0;
    uint64_t length = UINT32_BYTE_SIZE;
    std::shared_ptr<HeifStreamReader> reader = std::make_shared<HeifStreamReader>(heifInputStream, start, length);
    uint32_t recursionCount = 0;
    auto cr3Box = std::make_shared<Cr3Box>();
    reader->SetError(true);
    auto res = cr3Box->ReadCr3Children(*reader, recursionCount);
    EXPECT_EQ(res, heif_error_eof);

    reader->GetStream()->Seek(static_cast<int64_t>(start + length));
    res = cr3Box->ReadCr3Children(*reader, recursionCount);
    EXPECT_EQ(res, heif_error_eof);

    reader->SetError(false);
    res = cr3Box->ReadCr3Children(*reader, recursionCount);
    EXPECT_EQ(res, heif_error_ok);

    GTEST_LOG_(INFO) << "Cr3BoxTest: ReadCr3ChildrenTest002 end";
}

/**
 * @tc.name: ReadCr3ChildrenTest003
 * @tc.desc: Test ReadCr3Children returns OK with a valid stream reader.
 * @tc.type: FUNC
 */
HWTEST_F(Cr3BoxTest, ReadCr3ChildrenTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "Cr3BoxTest: ReadCr3ChildrenTest003 start";

    std::shared_ptr<HeifInputStream> heifInputStream = CreateHeifInputStream(INPUTDATA_MOOV);
    uint64_t start = 0;
    uint64_t length = INPUTDATA_MOOV.size();
    std::shared_ptr<HeifStreamReader> reader = std::make_shared<HeifStreamReader>(heifInputStream, start, length);
    uint32_t recursionCount = 0;
    auto cr3Box = std::make_shared<Cr3Box>();
    reader->SetError(false);
    auto res = cr3Box->ReadCr3Children(*reader, recursionCount);
    EXPECT_EQ(res, heif_error_ok);

    GTEST_LOG_(INFO) << "Cr3BoxTest: ReadCr3ChildrenTest003 end";
}

/**
 * @tc.name: GetCr3UuidTypeTest002
 * @tc.desc: Test GetCr3UuidType reports XMP after parsing a matching UUID payload.
 * @tc.type: FUNC
 */
HWTEST_F(Cr3BoxTest, GetCr3UuidTypeTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "Cr3BoxTest: GetCr3UuidTypeTest002 start";

    std::shared_ptr<HeifInputStream> heifInputStream = CreateHeifInputStream(INPUTDATA_UUID_WITH_PAYLOAD);
    HeifStreamReader reader(heifInputStream, 0, INPUTDATA_UUID_WITH_PAYLOAD.size());

    auto cr3UuidBox = std::make_shared<Cr3UuidBox>();
    auto headerErr = cr3UuidBox->ParseHeader(reader);
    EXPECT_EQ(headerErr, heif_error_ok);

    auto res = cr3UuidBox->GetCr3UuidType();
    EXPECT_EQ(res, Cr3UuidBox::Cr3UuidType::XMP);

    GTEST_LOG_(INFO) << "Cr3BoxTest: GetCr3UuidTypeTest002 end";
}

/**
 * @tc.name: Cr3MoovBoxParseContentChildrenTest002
 * @tc.desc: Test Cr3MoovBoxParseContentChildren returns EOF when child data is unavailable.
 * @tc.type: FUNC
 */
HWTEST_F(Cr3BoxTest, Cr3MoovBoxParseContentChildrenTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "Cr3BoxTest: Cr3MoovBoxParseContentChildrenTest002 start";

    std::vector<uint8_t> inputData(DEFAULT_BUFFER_SIZE);
    std::shared_ptr<HeifInputStream> heifInputStream = CreateHeifInputStream(inputData);
    uint64_t start = 0;
    uint64_t length = UINT32_BYTE_SIZE;
    std::shared_ptr<HeifStreamReader> reader = std::make_shared<HeifStreamReader>(heifInputStream, start, length);
    uint32_t recursionCount = 0;
    auto cr3MoovBox = std::make_shared<Cr3MoovBox>();
    auto res =  cr3MoovBox->ParseContentChildren(*reader, recursionCount);
    EXPECT_EQ(res, heif_error_eof);

    GTEST_LOG_(INFO) << "Cr3BoxTest: Cr3MoovBoxParseContentChildrenTest002 end";
}
} // namespace ImagePlugin
} // namespace OHOS