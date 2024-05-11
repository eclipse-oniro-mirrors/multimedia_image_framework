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
#include <gtest/gtest.h>
#include "heif_image.h"
#include "heif_stream.h"
#include "heif_parser.h"
#include "heif_utils.h"

using namespace testing::ext;
namespace OHOS {
namespace ImagePlugin {
class HeifParserTest : public testing::Test {
public:
    HeifParserTest() {}
    ~HeifParserTest() {}
};

/**
 * @tc.name: ReadTest001
 * @tc.desc: HeifBufferInputStream
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, ReadTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: ReadTest001 start";
    HeifBufferInputStream heifBuffer(nullptr, 0, true);
    void *data = nullptr;
    size_t size = 0;
    heifBuffer.pos_ = 1;
    heifBuffer.copied_ = true;
    ASSERT_TRUE((heifBuffer.pos_ + size) > heifBuffer.length_);
    bool ret = heifBuffer.Read(data, size);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "HeifParserTest: ReadTest001 end";
}

/**
 * @tc.name: SeekTest001
 * @tc.desc: HeifBufferInputStream
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, SeekTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: SeekTest001 start";
    HeifBufferInputStream heifBuffer(nullptr, 0, false);
    int64_t position = 1;
    bool ret = heifBuffer.Seek(position);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "HeifParserTest: SeekTest001 end";
}

/**
 * @tc.name: ReadTest002
 * @tc.desc: HeifStreamReader
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, ReadTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: ReadTest002 start";
    auto inputStream = std::make_shared<HeifBufferInputStream>(nullptr, 0, true);
    inputStream->pos_ = 1;
    HeifStreamReader heifReader(inputStream, 0, 0);
    uint8_t ret1 = heifReader.Read8();
    ASSERT_EQ(ret1, 0);
    uint16_t ret2 = heifReader.Read16();
    ASSERT_EQ(ret2, 0);
    uint32_t ret3 = heifReader.Read32();
    ASSERT_EQ(ret3, 0);
    uint64_t ret4 = heifReader.Read64();
    ASSERT_EQ(ret4, 0);

    heifReader.end_ = 128;
    inputStream->length_ = 10;
    inputStream->pos_ = 16;
    ret1 = heifReader.Read8();
    ASSERT_EQ(heifReader.hasError_, true);
    ASSERT_EQ(ret1, 0);
    ret2 = heifReader.Read16();
    ASSERT_EQ(heifReader.hasError_, true);
    ASSERT_EQ(ret2, 0);
    ret3 = heifReader.Read32();
    ASSERT_EQ(heifReader.hasError_, true);
    ASSERT_EQ(ret3, 0);
    ret4 = heifReader.Read64();
    ASSERT_EQ(heifReader.hasError_, true);
    ASSERT_EQ(ret4, 0);
    GTEST_LOG_(INFO) << "HeifParserTest: ReadTest002 end";
}

/**
 * @tc.name: ReadDataTest001
 * @tc.desc: HeifStreamReader
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, ReadDataTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: ReadDataTest001 start";
    auto inputStream = std::make_shared<HeifBufferInputStream>(nullptr, 0, true);
    HeifStreamReader heifReader(inputStream, 0, 0);
    uint8_t data;
    size_t size = 1;
    bool ret = heifReader.ReadData(&data, size);
    ASSERT_EQ(ret, false);
    size = 0;
    inputStream->pos_ = 1;
    ret = heifReader.ReadData(&data, size);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "HeifParserTest: ReadDataTest001 end";
}

/**
 * @tc.name: ReadStringTest001
 * @tc.desc: HeifStreamReader
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, ReadStringTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: ReadStringTest001 start";
    auto inputStream = std::make_shared<HeifBufferInputStream>(nullptr, 0, true);
    HeifStreamReader heifReader(inputStream, 0, 0);
    heifReader.end_ = 1;
    std::string ret = heifReader.ReadString();
    ASSERT_EQ(ret, "");
    inputStream->length_ = 1;
    inputStream->pos_ = 1;
    ret = heifReader.ReadString();
    ASSERT_EQ(ret, "");
    GTEST_LOG_(INFO) << "HeifParserTest: ReadStringTest001 end";
}

/**
 * @tc.name: CheckSizeTest001
 * @tc.desc: HeifStreamWriter
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, CheckSizeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: CheckSizeTest001 start";
    HeifStreamWriter heifWriter;
    size_t size = 1;
    ASSERT_EQ(heifWriter.data_.size(), 0);
    heifWriter.CheckSize(size);
    ASSERT_EQ(heifWriter.data_.size(), 1);
    GTEST_LOG_(INFO) << "HeifParserTest: CheckSizeTest001 end";
}

/**
 * @tc.name: WriteTest001
 * @tc.desc: HeifStreamWriter
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, WriteTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: WriteTest001 start";
    HeifStreamWriter heifWriter;
    uint8_t value = 0;
    ASSERT_TRUE(heifWriter.position_ == heifWriter.data_.size());
    heifWriter.Write8(value);
    ASSERT_EQ(heifWriter.data_.size(), 1);
    ASSERT_EQ(heifWriter.position_, 1);
    heifWriter.position_ = 0;
    heifWriter.Write8(value);
    ASSERT_EQ(heifWriter.data_[0], 0);

    heifWriter.Write16(0xFF);
    heifWriter.Write32(0xFFFF);
    heifWriter.Write64(0xFFFFFFFF);
    heifWriter.Write(UINT8_BYTES_NUM, 0);
    heifWriter.Write(UINT16_BYTES_NUM, 0);
    heifWriter.Write(UINT32_BYTES_NUM, 0);
    heifWriter.Write(UINT64_BYTES_NUM, 0);
    heifWriter.Write(BUFFER_INDEX_ZERO, 0);
    GTEST_LOG_(INFO) << "HeifParserTest: WriteTest001 end";
}

/**
 * @tc.name: WriteTest002
 * @tc.desc: HeifStreamWriter
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, WriteTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: WriteTest002 start";
    HeifStreamWriter heifWriter;
    std::string str = "HeifWrite";
    ASSERT_EQ(str.size(), 9);
    heifWriter.Write(str);
    ASSERT_EQ(heifWriter.data_[3], 'f');
    ASSERT_EQ(heifWriter.data_[9], 0);
    const std::vector<uint8_t> data;
    heifWriter.Write(data);
    heifWriter.Skip(1);
    heifWriter.Insert(0);
    heifWriter.Insert(2);
    GTEST_LOG_(INFO) << "HeifParserTest: WriteTest002 end";
}

/**
 * @tc.name: HeifImageTest001
 * @tc.desc: HeifImage
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, HeifImageTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: HeifImageTest001 start";
    HeifImage heifImage(3);
    heifImage.IsPrimaryImage();
    heifImage.GetMirrorDirection();
    heifImage.SetMirrorDirection(HeifTransformMirrorDirection::VERTICAL);
    heifImage.IsResolutionReverse();
    heifImage.GetWidth();
    heifImage.GetHeight();
    heifImage.IsThumbnailImage();
    heifImage.GetThumbnailImages();
    heifImage.IsAuxImage();
    heifImage.GetAuxImageType();
    heifImage.GetAuxImages();
    heifImage.GetAllMetadata();
    heifImage.GetNclxColorProfile();
    GTEST_LOG_(INFO) << "HeifParserTest: HeifImageTest001 end";
}

/**
 * @tc.name: WriteTest003
 * @tc.desc: HeifParser
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, WriteTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: WriteTest003 start";
    HeifParser heifParser;
    HeifStreamWriter write;
    heifParser.ilocBox_ = std::make_shared<HeifIlocBox>();
    heifParser.Write(write);
    GTEST_LOG_(INFO) << "HeifParserTest: WriteTest003 end";
}

/**
 * @tc.name: GetItemTypeTest001
 * @tc.desc: HeifParser
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, GetItemTypeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: GetItemTypeTest001 start";
    HeifParser heifParser;
    heif_item_id itemId = 0;
    heifParser.infeBoxes_.clear();
    std::string ret = heifParser.GetItemType(itemId);
    ASSERT_EQ(ret, "");
    ret = heifParser.GetItemContentType(itemId);
    ASSERT_EQ(ret, "");
    ret = heifParser.GetItemUriType(itemId);
    ASSERT_EQ(ret, "");
    GTEST_LOG_(INFO) << "HeifParserTest: GetItemTypeTest001 end";
}

/**
 * @tc.name: GetAllPropertiesTest001
 * @tc.desc: HeifParser
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, GetAllPropertiesTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: GetAllPropertiesTest001 start";
    HeifParser heifParser;
    heif_item_id itemId = 0;
    std::vector<std::shared_ptr<HeifBox>> properties;
    heifParser.ipcoBox_ = nullptr;
    heif_error ret = heifParser.GetAllProperties(itemId, properties);
    ASSERT_EQ(ret, heif_error_no_ipco);
    heifParser.ipcoBox_ = std::make_shared<HeifIpcoBox>();
    heifParser.ipmaBox_ = nullptr;
    ret = heifParser.GetAllProperties(itemId, properties);
    ASSERT_EQ(ret, heif_error_no_ipma);
    GTEST_LOG_(INFO) << "HeifParserTest: GetAllPropertiesTest001 end";
}

/**
 * @tc.name: GetItemDataTest001
 * @tc.desc: HeifParser
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, GetItemDataTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: GetItemDataTest001 start";
    HeifParser heifParser;
    heif_item_id itemId = 1;
    std::vector<uint8_t> *out = nullptr;
    heif_header_option option = heif_header_option::heif_header_data;
    heifParser.infeBoxes_.clear();
    heif_error ret = heifParser.GetItemData(itemId, out, option);
    ASSERT_EQ(ret, heif_error_item_not_found);
    heifParser.ilocBox_ = std::make_shared<HeifIlocBox>();
    auto heifBox = std::make_shared<HeifInfeBox>();
    heifParser.infeBoxes_.insert(std::make_pair(0, heifBox));
    heifParser.infeBoxes_.insert(std::make_pair(1, heifBox));
    ret = heifParser.GetItemData(itemId, out, option);
    ASSERT_EQ(ret, heif_error_item_data_not_found);
    GTEST_LOG_(INFO) << "HeifParserTest: GetItemDataTest001 end";
}

/**
 * @tc.name: GetTileImagesTest001
 * @tc.desc: HeifParser
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, GetTileImagesTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: GetTileImagesTest001 start";
    HeifParser heifParser;
    heif_item_id gridItemId = 0;
    std::vector<std::shared_ptr<HeifImage>> out;
    heifParser.infeBoxes_.clear();
    heifParser.GetTileImages(gridItemId, out);
    GTEST_LOG_(INFO) << "HeifParserTest: GetTileImagesTest001 end";
}

/**
 * @tc.name: ExtractGridImagePropertiesTest001
 * @tc.desc: HeifParser
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, ExtractGridImagePropertiesTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: ExtractGridImagePropertiesTest001 start";
    HeifParser heifParser;
    auto heifImage = std::make_shared<HeifImage>(0);
    heifParser.images_.insert(std::make_pair(0, heifImage));
    auto heifBox = std::make_shared<HeifInfeBox>();
    heifBox->itemType_ = "grid";
    heifParser.infeBoxes_.insert(std::make_pair(0, heifBox));
    heifParser.irefBox_ = std::make_shared<HeifIrefBox>();
    struct HeifIrefBox::Reference ref {.fromItemId = 1};
    heifParser.irefBox_->references_.push_back(ref);
    heifParser.ExtractGridImageProperties();
    GTEST_LOG_(INFO) << "HeifParserTest: ExtractGridImagePropertiesTest001 end";
}

/**
 * @tc.name: ExtractThumbnailImageTest001
 * @tc.desc: HeifParser:ExtractThumbnailImage And ExtractAuxImage
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, ExtractThumbnailImageTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: ExtractThumbnailImageTest001 start";
    HeifParser heifParser;
    std::shared_ptr<HeifImage> thumbnailImage = std::make_shared<HeifImage>(0);
    HeifIrefBox::Reference ref;
    ref.toItemIds.clear();
    heifParser.ExtractThumbnailImage(thumbnailImage, ref);
    heifParser.ExtractAuxImage(thumbnailImage, ref);
    ref.toItemIds.push_back(0);
    ASSERT_EQ(ref.toItemIds.empty(), false);
    ASSERT_EQ(ref.toItemIds[0], thumbnailImage->itemId_);
    heifParser.ExtractThumbnailImage(thumbnailImage, ref);
    heifParser.ExtractAuxImage(thumbnailImage, ref);
    thumbnailImage->itemId_ = 1;
    ASSERT_NE(ref.toItemIds[0], thumbnailImage->itemId_);
    ASSERT_EQ(heifParser.images_.empty(), true);
    heifParser.ExtractThumbnailImage(thumbnailImage, ref);
    heifParser.ExtractAuxImage(thumbnailImage, ref);
    GTEST_LOG_(INFO) << "HeifParserTest: ExtractThumbnailImageTest001 end";
}

/**
 * @tc.name: ExtractMetadataTest001
 * @tc.desc: HeifParser
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, ExtractMetadataTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: ExtractMetadataTest001 start";
    HeifParser heifParser;
    std::vector<heif_item_id> allItemIds;
    allItemIds.push_back(0);
    heifParser.irefBox_ = std::make_shared<HeifIrefBox>();
    struct HeifIrefBox::Reference ref {
        .fromItemId = 1,
        .box.boxType_ = BOX_TYPE_CDSC,
    };
    ref.toItemIds.push_back(0);
    ASSERT_EQ(ref.toItemIds[0], 0);
    heifParser.irefBox_->references_.push_back(ref);
    heifParser.ExtractMetadata(allItemIds);
    ref.toItemIds.clear();
    ref.toItemIds.push_back(1);
    ASSERT_EQ(heifParser.images_.empty(), true);
    heifParser.ExtractMetadata(allItemIds);
    auto heifImage = std::make_shared<HeifImage>(0);
    heifParser.images_.insert(std::make_pair(0, heifImage));
    heifParser.images_.insert(std::make_pair(1, heifImage));
    heifParser.infeBoxes_.clear();
    heifParser.ExtractMetadata(allItemIds);
    GTEST_LOG_(INFO) << "HeifParserTest: ExtractMetadataTest001 end";
}

/**
 * @tc.name: HeifParserTest001
 * @tc.desc: HeifParser
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, HeifParserTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: HeifParserTest001 start";
    HeifParser heifParser;
    heifParser.iinfBox_ = std::make_shared<HeifIinfBox>();
    heifParser.ipcoBox_ = std::make_shared<HeifIpcoBox>();
    heifParser.ipmaBox_ = std::make_shared<HeifIpmaBox>();
    heifParser.ilocBox_ = std::make_shared<HeifIlocBox>();
    heifParser.idatBox_ = std::make_shared<HeifIdatBox>();
    std::shared_ptr<HeifBox> property = std::make_shared<HeifBox>(0);
    std::string type;
    heifParser.GetNextItemId();
    heifParser.AddIspeProperty(0, 0, 0);
    heifParser.AddProperty(0, property, false);
    heifParser.AddPixiProperty(0, 0, 0, 0);
    heifParser.AddHvccProperty(0);
    heifParser.SetAuxcProperty(0, type);
    heifParser.CheckExtentData();
    GTEST_LOG_(INFO) << "HeifParserTest: HeifParserTest001 end";
}

/**
 * @tc.name: HeifParserTest002
 * @tc.desc: HeifParser
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, HeifParserTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: HeifParserTest002 start";
    HeifParser heifParser;
    heif_item_id itemId = 0;
    ImagePlugin::HvccConfig config;
    heifParser.ipcoBox_ = std::make_shared<HeifIpcoBox>();
    heifParser.ipmaBox_ = std::make_shared<HeifIpmaBox>();
    ASSERT_EQ(heifParser.GetImage(itemId), nullptr);
    heifParser.SetHvccConfig(itemId, config);
    GTEST_LOG_(INFO) << "HeifParserTest: HeifParserTest002 end";
}

/**
 * @tc.name: HeifParserTest003
 * @tc.desc: HeifParser
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, HeifParserTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: HeifParserTest003 start";
    HeifParser heifParser;
    heif_item_id itemId = 0;
    std::vector<uint8_t> data;
    uint8_t construction_method = 0;
    heif_item_id fromItemId = 0;
    uint32_t type = 0;
    const std::vector<heif_item_id> toItemIds;
    heifParser.ilocBox_ = nullptr;
    heifParser.pitmBox_ = nullptr;
    heifParser.irefBox_ = nullptr;
    heifParser.metaBox_ = std::make_shared<HeifMetaBox>();
    heifParser.AppendIlocData(itemId, data, construction_method);
    heifParser.SetPrimaryItemId(itemId);
    heifParser.AddReference(fromItemId, type, toItemIds);
    heifParser.ilocBox_ = std::make_shared<HeifIlocBox>();
    heifParser.pitmBox_ = std::make_shared<HeifPtimBox>();
    heifParser.irefBox_ = std::make_shared<HeifIrefBox>();
    heifParser.AppendIlocData(itemId, data, construction_method);
    heifParser.SetPrimaryItemId(itemId);
    heifParser.AddReference(fromItemId, type, toItemIds);
    GTEST_LOG_(INFO) << "HeifParserTest: HeifParserTest003 end";
}

/**
 * @tc.name: SetPrimaryImageTest001
 * @tc.desc: HeifParser
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, SetPrimaryImageTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: SetPrimaryImageTest001 start";
    HeifParser heifParser;
    std::shared_ptr<HeifImage> image = std::make_shared<HeifImage>(0);
    heifParser.primaryImage_ = std::make_shared<HeifImage>(0);
    ASSERT_EQ(heifParser.primaryImage_->GetItemId(), image->GetItemId());
    heifParser.SetPrimaryImage(image);
    heifParser.primaryImage_->itemId_ = 1;
    ASSERT_NE(heifParser.primaryImage_->GetItemId(), image->GetItemId());
    heifParser.pitmBox_ = nullptr;
    heifParser.SetPrimaryImage(image);
    GTEST_LOG_(INFO) << "HeifParserTest: SetPrimaryImageTest001 end";
}
}
}