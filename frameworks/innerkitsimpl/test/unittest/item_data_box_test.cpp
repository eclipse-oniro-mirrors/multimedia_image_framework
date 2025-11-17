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
#include "box/item_data_box.h"
#include "heif_stream.h"

using namespace testing::ext;
namespace OHOS {
namespace ImagePlugin {

static constexpr uint32_t MAX_HEIF_IMAGE_GRID_SIZE = 128 * 1024 * 1024;
static constexpr uint8_t CONSTRUCTION_METHOD_FILE_OFFSET = 0;
static constexpr uint8_t CONSTRUCTION_METHOD_IDAT_OFFSET = 1;
static constexpr uint8_t CONSTRUCTION_METHOD_FALSE_OFFSET = -1;
static constexpr uint32_t ITEM_COUNT_3 = 3;
static constexpr uint8_t SIZE_4 = 4;
static constexpr uint8_t SIZE_8 = 8;
static constexpr uint32_t ITEM_ID_12345678 = 0x12345678;
static constexpr uint64_t EXTENT_INDEX_87654321 = 0x87654321;
static constexpr uint64_t EXTENT_INDEX_11223344 = 0x11223344;
static constexpr uint32_t ITEM_ID_0001 = 0x0001;
static constexpr uint64_t BASE_OFFSET_20 = 20;
static constexpr uint64_t EXTENT_OFFSET_10 = 10;
static constexpr uint64_t EXTENT_LENGTH_5 = 5;
static constexpr heif_item_id ITEM_ID_50 = 50;
static constexpr heif_item_id ITEM_ID_150 = 150;
static constexpr uint8_t BYTE_12 = 0x12;
static constexpr uint8_t BYTE_34 = 0x34;
static constexpr uint8_t BYTE_56 = 0x56;
static constexpr uint8_t BYTE_78 = 0x78;
static constexpr uint8_t BYTE_87 = 0x87;
static constexpr uint8_t BYTE_65 = 0x65;
static constexpr uint8_t BYTE_43 = 0x43;
static constexpr uint8_t BYTE_21 = 0x21;
static constexpr size_t INDEX_WRITE_OFFSET_16 = 16;
static constexpr size_t DATA_SIZE_100 = 100;

class ItemDataBoxTest : public testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

/**
 * @tc.name: ParseExtentsTest001
 * @tc.desc: Test extentNum exceeds MAX, expect error.
 * @tc.type: FUNC
 */
HWTEST_F(ItemDataBoxTest, ParseExtentsTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ItemDataBoxTest: ParseExtentsTest001 start";
    std::shared_ptr<HeifIlocBox> heifIlocBox = std::make_shared<HeifIlocBox>();
    HeifIlocBox::Item item;
    uint8_t data[] = {0x04, 0x01};
    size_t size = sizeof(data);
    bool needCopy = false;
    std::shared_ptr<HeifInputStream> stream = std::make_shared<HeifBufferInputStream>(data, size, needCopy);
    int64_t start = 0;
    size_t length = size;
    std::shared_ptr<HeifStreamReader> reader = std::make_shared<HeifStreamReader>(stream, start, length);
    int indexSize = 0;
    int offsetSize = 0;
    int lengthSize = 0;
    auto ret = heifIlocBox->ParseExtents(item, *reader, indexSize, offsetSize, lengthSize);
    EXPECT_EQ(ret, heif_error_extent_num_too_large);
    GTEST_LOG_(INFO) << "ItemDataBoxTest: ParseExtentsTest001 end";
}

/**
 * @tc.name: ParseExtentsTest002
 * @tc.desc: Test valid 4-byte params, expect success.
 * @tc.type: FUNC
 */
HWTEST_F(ItemDataBoxTest, ParseExtentsTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ItemDataBoxTest: ParseExtentsTest002 start";
    std::shared_ptr<HeifIlocBox> heifIlocBox = std::make_shared<HeifIlocBox>();
    heifIlocBox->SetVersion(1);
    HeifIlocBox::Item item;
    uint8_t data[] = {0x00, 0x01, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC};
    size_t size = sizeof(data);
    bool needCopy = false;
    std::shared_ptr<HeifInputStream> stream = std::make_shared<HeifBufferInputStream>(data, size, needCopy);
    std::shared_ptr<HeifStreamReader> reader = std::make_shared<HeifStreamReader>(stream, 0, size);
    int indexSize = SIZE_4;
    int offsetSize = SIZE_4;
    int lengthSize = SIZE_4;
    heif_error ret = heifIlocBox->ParseExtents(item, *reader, indexSize, offsetSize, lengthSize);
    EXPECT_EQ(ret, heif_error_ok);
    EXPECT_EQ(item.extents.size(), 1U);
    EXPECT_NE(item.extents[0].index, 0U);
    EXPECT_NE(item.extents[0].offset, 0U);
    EXPECT_NE(item.extents[0].length, 0U);
    GTEST_LOG_(INFO) << "ItemDataBoxTest: ParseExtentsTest002 end";
}

/**
 * @tc.name: ParseExtentsTest003
 * @tc.desc: Test valid 8-byte params, expect success.
 * @tc.type: FUNC
 */
HWTEST_F(ItemDataBoxTest, ParseExtentsTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ItemDataBoxTest: ParseExtentsTest003 start";
    std::shared_ptr<HeifIlocBox> heifIlocBox = std::make_shared<HeifIlocBox>();
    heifIlocBox->SetVersion(1);
    HeifIlocBox::Item item;
    uint8_t data[] = {
        0x00, 0x01,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80
    };
    size_t size = sizeof(data);
    bool needCopy = false;
    std::shared_ptr<HeifInputStream> stream = std::make_shared<HeifBufferInputStream>(data, size, needCopy);
    std::shared_ptr<HeifStreamReader> reader = std::make_shared<HeifStreamReader>(stream, 0, size);
    int indexSize = SIZE_8;
    int offsetSize = SIZE_8;
    int lengthSize = SIZE_8;
    heif_error ret = heifIlocBox->ParseExtents(item, *reader, indexSize, offsetSize, lengthSize);
    EXPECT_EQ(ret, heif_error_ok);
    GTEST_LOG_(INFO) << "ItemDataBoxTest: ParseExtentsTest003 end";
}

/**
 * @tc.name: ParseExtentsTest004
 * @tc.desc: Test skipped index, expect success.
 * @tc.type: FUNC
 */
HWTEST_F(ItemDataBoxTest, ParseExtentsTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ItemDataBoxTest: ParseExtentsTest004 start";
    std::shared_ptr<HeifIlocBox> heifIlocBox = std::make_shared<HeifIlocBox>();
    heifIlocBox->SetVersion(1);
    HeifIlocBox::Item item;
    uint8_t data[] = {
        0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0x11, 0x22, 0x33, 0x44,
        0x55, 0x66, 0x77, 0x88
    };
    size_t size = sizeof(data);
    bool needCopy = false;
    std::shared_ptr<HeifInputStream> stream = std::make_shared<HeifBufferInputStream>(data, size, needCopy);
    std::shared_ptr<HeifStreamReader> reader = std::make_shared<HeifStreamReader>(stream, 0, size);
    int indexSize = SIZE_4;
    int offsetSize = SIZE_4;
    int lengthSize = SIZE_4;
    heif_error ret = heifIlocBox->ParseExtents(item, *reader, indexSize, offsetSize, lengthSize);
    EXPECT_EQ(ret, heif_error_ok);
    EXPECT_EQ(item.extents.size(), 1U);
    EXPECT_EQ(item.extents[0].index, 0U);
    EXPECT_NE(item.extents[0].offset, 0U);
    EXPECT_NE(item.extents[0].length, 0U);
    GTEST_LOG_(INFO) << "ItemDataBoxTest: ParseExtentsTest004 end";
}

/**
 * @tc.name: ParseContent001
 * @tc.desc: Test itemCount exceeds MAX, expect error.
 * @tc.type: FUNC
 */
HWTEST_F(ItemDataBoxTest, ParseContent001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ItemDataBoxTest: ParseContent001 start";
    std::shared_ptr<HeifIlocBox> heifIlocBox = std::make_shared<HeifIlocBox>();
    uint8_t data[] = {
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
        0xFF, 0xFF
    };
    size_t size = sizeof(data);
    bool needCopy = false;
    std::shared_ptr<HeifInputStream> stream = std::make_shared<HeifBufferInputStream>(data, size, needCopy);
    std::shared_ptr<HeifStreamReader> reader = std::make_shared<HeifStreamReader>(stream, 0, size);
    heif_error ret = heifIlocBox->ParseContent(*reader);
    EXPECT_EQ(ret, heif_error_too_many_item);
    GTEST_LOG_(INFO) << "ItemDataBoxTest: ParseContent001 end";
}

/**
 * @tc.name: ParseContent002
 * @tc.desc: Test ParseExtents returns error, expect error.
 * @tc.type: FUNC
 */
HWTEST_F(ItemDataBoxTest, ParseContent002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ItemDataBoxTest: ParseContent002 start";
    std::shared_ptr<HeifIlocBox> heifIlocBox = std::make_shared<HeifIlocBox>();
    heifIlocBox->SetVersion(1);
    uint8_t data[] = {
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x00,
        0x00, 0x01,
        0x00, 0x01,
        0x00, 0x00,
        0x00, 0x00,
        0x27, 0x11
    };
    size_t size = sizeof(data);
    bool needCopy = false;
    auto stream = std::make_shared<HeifBufferInputStream>(data, size, needCopy);
    stream->pos_ = 0;
    auto reader = std::make_shared<HeifStreamReader>(stream, 0, size);
    heif_error ret = heifIlocBox->ParseContent(*reader);
    EXPECT_EQ(ret, heif_error_extent_num_too_large);
    GTEST_LOG_(INFO) << "ItemDataBoxTest: ParseContent002 end";
}

/**
 * @tc.name: ParseContent003
 * @tc.desc: Test normal ParseContent, expect success.
 * @tc.type: FUNC
 */
HWTEST_F(ItemDataBoxTest, ParseContent003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ItemDataBoxTest: ParseContent003 start";
    std::shared_ptr<HeifIlocBox> heifIlocBox = std::make_shared<HeifIlocBox>();
    heifIlocBox->SetVersion(1);
    uint8_t data[] = {
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x80,
        0x00, 0x01,
        0x00, 0x01,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00
    };
    size_t size = sizeof(data);
    bool needCopy = false;
    auto stream = std::make_shared<HeifBufferInputStream>(data, size, needCopy);
    auto reader = std::make_shared<HeifStreamReader>(stream, 0, size);
    heif_error ret = heifIlocBox->ParseContent(*reader);
    EXPECT_EQ(ret, heif_error_ok);
    GTEST_LOG_(INFO) << "ItemDataBoxTest: ParseContent003 end";
}

/**
 * @tc.name: GetIlocDataLength001
 * @tc.desc: Test extent.length exceeds MAX, expect error.
 * @tc.type: FUNC
 */
HWTEST_F(ItemDataBoxTest, GetIlocDataLength001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ItemDataBoxTest: GetIlocDataLength001 start";
    std::shared_ptr<HeifIlocBox> heifIlocBox = std::make_shared<HeifIlocBox>();
    HeifIlocBox::Item item;
    item.itemId = 1;
    item.constructionMethod = 0;
    item.dataReferenceIndex = 1;
    HeifIlocBox::Extent extent;
    extent.index = 0;
    extent.offset = 0;
    extent.length = MAX_HEIF_IMAGE_GRID_SIZE + 1;
    item.extents.push_back(extent);
    size_t outputLength = 0;
    heif_error ret = heifIlocBox->GetIlocDataLength(item, outputLength);
    EXPECT_EQ(ret, heif_error_grid_too_large);
    GTEST_LOG_(INFO) << "ItemDataBoxTest: GetIlocDataLength001 end";
}

/**
 * @tc.name: GetIlocDataLength002
 * @tc.desc: Test valid extent.length, expect success.
 * @tc.type: FUNC
 */
HWTEST_F(ItemDataBoxTest, GetIlocDataLength002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ItemDataBoxTest: GetIlocDataLength002 start";
    std::shared_ptr<HeifIlocBox> heifIlocBox = std::make_shared<HeifIlocBox>();
    HeifIlocBox::Item item;
    item.itemId = 0;
    item.constructionMethod = 0;
    item.dataReferenceIndex = 1;
    item.baseOffset = 0;
    HeifIlocBox::Extent extent;
    extent.index = 0;
    extent.offset = 0;
    extent.length = MAX_HEIF_IMAGE_GRID_SIZE;
    item.extents.push_back(extent);
    size_t outputLength = 0;
    heif_error ret = heifIlocBox->GetIlocDataLength(item, outputLength);
    EXPECT_EQ(ret, heif_error_ok);
    EXPECT_EQ(outputLength, extent.length);
    GTEST_LOG_(INFO) << "ItemDataBoxTest: GetIlocDataLength002 end";
}

/**
 * @tc.name: ReadData001
 * @tc.desc: Test extent.length exceeds MAX, expect error.
 * @tc.type: FUNC
 */
HWTEST_F(ItemDataBoxTest, ReadData001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ItemDataBoxTest: ReadData001 start";
    HeifIlocBox::Item item;
    item.constructionMethod = CONSTRUCTION_METHOD_FILE_OFFSET;
    item.baseOffset = 0;
    HeifIlocBox::Extent extent;
    extent.index = 0;
    extent.offset = 0;
    extent.length = MAX_HEIF_IMAGE_GRID_SIZE + 1;
    item.extents.push_back(extent);
    uint8_t data[DATA_SIZE_100] = {0};
    size_t size = sizeof(data);
    bool needCopy = false;
    std::shared_ptr<HeifInputStream> stream = std::make_shared<HeifBufferInputStream>(data, size, needCopy);
    std::shared_ptr<HeifIdatBox> idat = std::make_shared<HeifIdatBox>();
    std::vector<uint8_t> dest;
    std::shared_ptr<HeifIlocBox> heifIlocBox = std::make_shared<HeifIlocBox>();
    auto ret = heifIlocBox->ReadData(item, stream, idat, &dest);
    EXPECT_EQ(ret, heif_error_grid_too_large);
    GTEST_LOG_(INFO) << "ItemDataBoxTest: ReadData001 end";
}

/**
 * @tc.name: ReadData002
 * @tc.desc: Test null idat, expect error.
 * @tc.type: FUNC
 */
HWTEST_F(ItemDataBoxTest, ReadData002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ItemDataBoxTest: ReadData002 start";
    HeifIlocBox::Item item;
    item.constructionMethod = CONSTRUCTION_METHOD_IDAT_OFFSET;
    HeifIlocBox::Extent extent;
    item.extents.push_back(extent);
    bool needCopy = false;
    std::shared_ptr<HeifInputStream> stream = std::make_shared<HeifBufferInputStream>(nullptr, 0, needCopy);
    std::shared_ptr<HeifIdatBox> idat = nullptr;
    std::vector<uint8_t> dest;
    std::shared_ptr<HeifIlocBox> heifIlocBox = std::make_shared<HeifIlocBox>();
    auto ret = heifIlocBox->ReadData(item, stream, idat, &dest);
    EXPECT_EQ(ret, heif_error_no_idat);
    GTEST_LOG_(INFO) << "ItemDataBoxTest: ReadData002 end";
}

/**
 * @tc.name: ReadData003
 * @tc.desc: Test invalid construction method, expect error.
 * @tc.type: FUNC
 */
HWTEST_F(ItemDataBoxTest, ReadData003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ItemDataBoxTest: ReadData003 start";
    HeifIlocBox::Item item;
    item.constructionMethod = CONSTRUCTION_METHOD_FALSE_OFFSET;
    HeifIlocBox::Extent extent;
    item.extents.push_back(extent);
    bool needCopy = false;
    std::shared_ptr<HeifInputStream> stream = std::make_shared<HeifBufferInputStream>(nullptr, 0, needCopy);
    std::shared_ptr<HeifIdatBox> idat = nullptr;
    std::vector<uint8_t> dest;
    std::shared_ptr<HeifIlocBox> heifIlocBox = std::make_shared<HeifIlocBox>();
    auto ret = heifIlocBox->ReadData(item, stream, idat, &dest);
    EXPECT_EQ(ret, heif_error_no_idat);
    GTEST_LOG_(INFO) << "ItemDataBoxTest: ReadData003 end";
}

/**
 * @tc.name: AppendData001
 * @tc.desc: Test existing itemId, expect success.
 * @tc.type: FUNC
 */
HWTEST_F(ItemDataBoxTest, AppendData001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ItemDataBoxTest: AppendData001 start";
    std::shared_ptr<HeifIlocBox> heifIlocBox = std::make_shared<HeifIlocBox>();
    HeifIlocBox::Item initItem;
    initItem.itemId = ITEM_ID_50;
    heifIlocBox->items_.push_back(initItem);
    heif_item_id itemId = ITEM_ID_50;
    std::vector<uint8_t> testData = {0x01, 0x02};
    uint8_t constructionMethod = CONSTRUCTION_METHOD_FILE_OFFSET;
    heif_error ret = heifIlocBox->AppendData(itemId, testData, constructionMethod);
    EXPECT_EQ(ret, heif_error_ok);
    EXPECT_EQ(heifIlocBox->items_.size(), 1U);
    EXPECT_EQ(heifIlocBox->items_[0].itemId, itemId);
    GTEST_LOG_(INFO) << "ItemDataBoxTest: AppendData001 end";
}

/**
 * @tc.name: AppendData002
 * @tc.desc: Test IDAT construction method, expect success.
 * @tc.type: FUNC
 */
HWTEST_F(ItemDataBoxTest, AppendData002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ItemDataBoxTest: AppendData002 start";
    std::shared_ptr<HeifIlocBox> heifIlocBox = std::make_shared<HeifIlocBox>();
    uint64_t initIdatOffset = heifIlocBox->idatOffset_;
    heif_item_id itemId = ITEM_ID_150;
    std::vector<uint8_t> testData = {0x03, 0x04, 0x05};
    uint8_t constructionMethod = CONSTRUCTION_METHOD_IDAT_OFFSET;
    heif_error ret = heifIlocBox->AppendData(itemId, testData, constructionMethod);
    EXPECT_EQ(ret, heif_error_ok);
    const auto& extent = heifIlocBox->items_[0].extents[0];
    EXPECT_EQ(extent.offset, initIdatOffset);
    EXPECT_EQ(extent.length, testData.size());
    EXPECT_EQ(heifIlocBox->idatOffset_, initIdatOffset + testData.size());
    GTEST_LOG_(INFO) << "ItemDataBoxTest: AppendData002 end";
}

/**
 * @tc.name: ReadToExtentData001
 * @tc.desc: Test Seek out-of-bounds, expect EOF.
 * @tc.type: FUNC
 */
HWTEST_F(ItemDataBoxTest, ReadToExtentData001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ItemDataBoxTest: ReadToExtentData001 start";
    uint8_t dummyData[] = {0x00};
    auto stream = std::make_shared<HeifBufferInputStream>(dummyData, sizeof(dummyData), false);
    HeifIlocBox::Item item;
    item.constructionMethod = CONSTRUCTION_METHOD_FILE_OFFSET;
    item.baseOffset = BASE_OFFSET_20;
    HeifIlocBox::Extent extent;
    extent.data.clear();
    extent.offset = EXTENT_OFFSET_10;
    extent.length = EXTENT_LENGTH_5;
    item.extents.push_back(extent);
    std::shared_ptr<HeifIlocBox> heifIlocBox = std::make_shared<HeifIlocBox>();
    heif_error ret = heifIlocBox->ReadToExtentData(item, stream, nullptr);
    EXPECT_EQ(ret, heif_error_eof);
    GTEST_LOG_(INFO) << "ItemDataBoxTest: ReadToExtentData001 end";
}

/**
 * @tc.name: ReadToExtentData002
 * @tc.desc: Test insufficient length, expect EOF.
 * @tc.type: FUNC
 */
HWTEST_F(ItemDataBoxTest, ReadToExtentData002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ItemDataBoxTest: ReadToExtentData002 start";
    uint8_t dummyData[] = {0x01, 0x02, 0x03, 0x04, 0x05};
    auto stream = std::make_shared<HeifBufferInputStream>(dummyData, sizeof(dummyData), false);
    HeifIlocBox::Item item;
    item.constructionMethod = CONSTRUCTION_METHOD_FILE_OFFSET;
    item.baseOffset = SIZE_4 - 1;
    HeifIlocBox::Extent extent;
    extent.data.clear();
    extent.offset = 0;
    extent.length = SIZE_4;
    item.extents.push_back(extent);
    std::shared_ptr<HeifIlocBox> heifIlocBox = std::make_shared<HeifIlocBox>();
    heif_error ret = heifIlocBox->ReadToExtentData(item, stream, nullptr);
    EXPECT_EQ(ret, heif_error_eof);
    GTEST_LOG_(INFO) << "ItemDataBoxTest: ReadToExtentData002 end";
}

/**
 * @tc.name: ReadToExtentData003
 * @tc.desc: Test read out-of-bounds, expect EOF.
 * @tc.type: FUNC
 */
HWTEST_F(ItemDataBoxTest, ReadToExtentData003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ItemDataBoxTest: ReadToExtentData003 start";
    uint8_t dummyData[] = {0x0A, 0x0B, 0x0C, 0x0D};
    auto stream = std::make_shared<HeifBufferInputStream>(dummyData, sizeof(dummyData), false);
    HeifIlocBox::Item item;
    item.constructionMethod = CONSTRUCTION_METHOD_FILE_OFFSET;
    item.baseOffset = 1;
    HeifIlocBox::Extent extent;
    extent.data.clear();
    extent.offset = 0;
    extent.length = SIZE_4;
    item.extents.push_back(extent);
    std::shared_ptr<HeifIlocBox> heifIlocBox = std::make_shared<HeifIlocBox>();
    heif_error ret = heifIlocBox->ReadToExtentData(item, stream, nullptr);
    EXPECT_EQ(ret, heif_error_eof);
    GTEST_LOG_(INFO) << "ItemDataBoxTest: ReadToExtentData003 end";
}

/**
 * @tc.name: ReadToExtentData004
 * @tc.desc: Test null idatBox, expect error.
 * @tc.type: FUNC
 */
HWTEST_F(ItemDataBoxTest, ReadToExtentData004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ItemDataBoxTest: ReadToExtentData004 start";
    uint8_t dummyData[] = {0x00};
    auto stream = std::make_shared<HeifBufferInputStream>(dummyData, sizeof(dummyData), false);
    HeifIlocBox::Item item;
    item.constructionMethod = CONSTRUCTION_METHOD_IDAT_OFFSET;
    item.baseOffset = SIZE_4 * SIZE_4 + SIZE_4;
    HeifIlocBox::Extent extent;
    extent.data.clear();
    extent.offset = SIZE_4 * SIZE_4;
    extent.length = SIZE_4 + SIZE_4;
    item.extents.push_back(extent);
    std::shared_ptr<HeifIlocBox> heifIlocBox = std::make_shared<HeifIlocBox>();
    heif_error ret = heifIlocBox->ReadToExtentData(item, stream, nullptr);
    EXPECT_EQ(ret, heif_error_no_idat);
    GTEST_LOG_(INFO) << "ItemDataBoxTest: ReadToExtentData004 end";
}

/**
 * @tc.name: PackIlocHeader001
 * @tc.desc: Test Write32 for items_.size(), expect success.
 * @tc.type: FUNC
 */
HWTEST_F(ItemDataBoxTest, PackIlocHeader001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ItemDataBoxTest: PackIlocHeader001 start";
    HeifStreamWriter writer;
    std::shared_ptr<HeifIlocBox> heifIlocBox = std::make_shared<HeifIlocBox>();
    heifIlocBox->SetVersion(HEIF_BOX_VERSION_TWO);
    heifIlocBox->offsetSize_ = SIZE_4;
    heifIlocBox->lengthSize_ = SIZE_4;
    heifIlocBox->baseOffsetSize_ = SIZE_4;
    heifIlocBox->indexSize_ = 0;
    heifIlocBox->startPos_ = 0;
    for (uint32_t i = 1; i <= ITEM_COUNT_3; i++) {
        HeifIlocBox::Item item;
        item.itemId = i;
        item.constructionMethod = 0;
        item.dataReferenceIndex = 0;
        item.baseOffset = 0;
        heifIlocBox->items_.push_back(item);
    }
    heifIlocBox->PackIlocHeader(writer);
    const auto& buffer = writer.GetData();
    EXPECT_GE(buffer.size(), 6U);
    EXPECT_EQ(buffer[2], 0x00);
    EXPECT_EQ(buffer[3], 0x00);
    EXPECT_EQ(buffer[4], 0x00);
    EXPECT_EQ(buffer[5], 0x03);
    GTEST_LOG_(INFO) << "ItemDataBoxTest: PackIlocHeader001 end";
}

/**
 * @tc.name: PackIlocHeader002
 * @tc.desc: Test Write32 for item.itemId, expect success.
 * @tc.type: FUNC
 */
HWTEST_F(ItemDataBoxTest, PackIlocHeader002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ItemDataBoxTest: PackIlocHeader002 start";
    HeifStreamWriter writer;
    std::shared_ptr<HeifIlocBox> heifIlocBox = std::make_shared<HeifIlocBox>();
    heifIlocBox->SetVersion(HEIF_BOX_VERSION_TWO);
    heifIlocBox->offsetSize_ = SIZE_4;
    heifIlocBox->lengthSize_ = SIZE_4;
    heifIlocBox->baseOffsetSize_ = SIZE_4;
    heifIlocBox->indexSize_ = 0;
    heifIlocBox->startPos_ = 0;
    HeifIlocBox::Item item;
    item.itemId = ITEM_ID_12345678;
    item.constructionMethod = 0x00;
    item.dataReferenceIndex = 0x0001;
    item.baseOffset = 0x00000000;
    heifIlocBox->items_.push_back(item);
    heifIlocBox->PackIlocHeader(writer);
    const auto& buffer = writer.GetData();
    EXPECT_GE(buffer.size(), 2 + SIZE_4 + SIZE_4);
    EXPECT_EQ(buffer[6], BYTE_12);
    EXPECT_EQ(buffer[7], BYTE_34);
    EXPECT_EQ(buffer[8], BYTE_56);
    EXPECT_EQ(buffer[9], BYTE_78);
    GTEST_LOG_(INFO) << "ItemDataBoxTest: PackIlocHeader002 end";
}

/**
 * @tc.name: PackIlocHeader003
 * @tc.desc: Test write extent.index, expect success.
 * @tc.type: FUNC
 */
HWTEST_F(ItemDataBoxTest, PackIlocHeader003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ItemDataBoxTest: PackIlocHeader003 start";
    HeifStreamWriter writer;
    std::shared_ptr<HeifIlocBox> heifIlocBox = std::make_shared<HeifIlocBox>();
    heifIlocBox->SetVersion(HEIF_BOX_VERSION_ONE);
    heifIlocBox->offsetSize_ = SIZE_4;
    heifIlocBox->lengthSize_ = SIZE_4;
    heifIlocBox->baseOffsetSize_ = SIZE_4;
    heifIlocBox->indexSize_ = SIZE_4;
    heifIlocBox->startPos_ = 0;
    HeifIlocBox::Item item;
    item.itemId = ITEM_ID_0001;
    item.constructionMethod = 0x00;
    item.dataReferenceIndex = 0x0001;
    item.baseOffset = 0x00000000;
    HeifIlocBox::Extent extent;
    extent.index = EXTENT_INDEX_87654321;
    extent.offset = 0x00000000;
    extent.length = 0x00000000;
    item.extents.push_back(extent);
    heifIlocBox->items_.push_back(item);
    heifIlocBox->PackIlocHeader(writer);
    const auto& buffer = writer.GetData();
    size_t indexWriteOffset = INDEX_WRITE_OFFSET_16;
    EXPECT_GE(buffer.size(), indexWriteOffset + SIZE_4);
    EXPECT_EQ(buffer[indexWriteOffset + 0], BYTE_87);
    EXPECT_EQ(buffer[indexWriteOffset + 1], BYTE_65);
    EXPECT_EQ(buffer[indexWriteOffset + 2], BYTE_43);
    EXPECT_EQ(buffer[indexWriteOffset + 3], BYTE_21);
    GTEST_LOG_(INFO) << "ItemDataBoxTest: PackIlocHeader003 end";
}

/**
 * @tc.name: PackIlocHeader004
 * @tc.desc: Test no extent.index write, expect success.
 * @tc.type: FUNC
 */
HWTEST_F(ItemDataBoxTest, PackIlocHeader004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ItemDataBoxTest: PackIlocHeader004 start";
    HeifStreamWriter writerWithIndex;
    HeifStreamWriter writerWithoutIndex;
    auto createIlocBox = [](uint8_t indexSize) -> std::shared_ptr<HeifIlocBox> {
        auto box = std::make_shared<HeifIlocBox>();
        box->SetVersion(HEIF_BOX_VERSION_ONE);
        box->offsetSize_ = SIZE_4;
        box->lengthSize_ = SIZE_4;
        box->baseOffsetSize_ = SIZE_4;
        box->indexSize_ = indexSize;
        box->startPos_ = 0;
        HeifIlocBox::Item item;
        item.itemId = ITEM_ID_0001;
        item.constructionMethod = 0x00;
        item.dataReferenceIndex = 0x0001;
        item.baseOffset = 0x00000000;
        HeifIlocBox::Extent extent;
        extent.index = EXTENT_INDEX_11223344;
        extent.offset = 0x00000000;
        extent.length = 0x00000000;
        item.extents.push_back(extent);
        box->items_.push_back(item);
        return box;
    };
    auto boxWithIndex = createIlocBox(SIZE_4);
    auto boxWithoutIndex = createIlocBox(0);
    boxWithIndex->PackIlocHeader(writerWithIndex);
    boxWithoutIndex->PackIlocHeader(writerWithoutIndex);
    size_t lenWith = writerWithIndex.GetDataSize();
    size_t lenWithout = writerWithoutIndex.GetDataSize();
    EXPECT_EQ(lenWith - lenWithout, SIZE_4);
    GTEST_LOG_(INFO) << "ItemDataBoxTest: PackIlocHeader004 end";
}
} // namespace ImagePlugin
} // namespace OHOS