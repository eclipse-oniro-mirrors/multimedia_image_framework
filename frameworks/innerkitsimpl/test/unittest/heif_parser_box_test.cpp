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
#include "item_property_transform_box.h"
#include "item_ref_box.h"

using namespace testing::ext;
namespace OHOS {
namespace ImagePlugin {
static constexpr size_t ERR_LENGTH = -1;
static constexpr size_t NORMAL_LENGTH = 1;
static constexpr size_t SIZE_32BITS = 0xFFFFFFFF;
static constexpr size_t UUID_TYPE_BYTE_NUM = 16;

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

class HeifParserBoxTest : public testing::Test {
public:
    HeifParserBoxTest() {}
    ~HeifParserBoxTest() {}
};

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
}
}