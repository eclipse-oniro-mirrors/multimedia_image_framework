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
#include "heif_image.h"
#include "heif_stream.h"
#include "heif_parser.h"
#include "heif_utils.h"
#include "item_property_transform_box.h"

using namespace testing::ext;
namespace OHOS {
namespace ImagePlugin {
static const heif_item_id MOCK_ITEM_ID = UINT32_MAX;
static const heif_item_id IT35_TRUE_ID = 1;
static const heif_item_id IT35_MOCK_ID = 2;
static const heif_item_id TMAP_TRUE_ID = 3;
static const heif_item_id TMAP_MOCK_ID = 4;
static const heif_item_id IDEN_TRUE_ID = 5;
static const heif_item_id MIME_TRUE_ID = 6;
static const uint16_t INDEX_1 = 1;
static const uint16_t INDEX_2 = 2;
static const uint16_t INDEX_3 = 3;
static const uint8_t MOCK_DATA_1 = 1;
static const uint8_t MOCK_DATA_2 = 2;
static const uint8_t MOCK_FILL_BYTE = 0xFF;
static const uint32_t MOCK_DATA_SIZE = 5;
static const uint32_t NUM_1 = 1;
static const int NUM_8 = 8;
static const int NUM_10 = 10;
static const int NUM_100 = 100;
static const uint32_t MOCK_TIFF_OFFSET = 50;
const static uint32_t HEIF_MAX_EXIF_SIZE = 128 * 1024;
const static size_t METADATA_COUNT = 0;

class HeifParserTest : public testing::Test {
public:
    HeifParserTest() {}
    ~HeifParserTest() {}
    void AddHdlrBox(HeifParser& heifParser);
    void AddPtimBox(HeifParser& heifParser);
    void AddIinfBox(HeifParser& heifParser);
    void AddIprpBox(HeifParser& heifParser);
    void AddIpcoBox(HeifParser& heifParser);
    void AddIpmaBox(HeifParser& heifParser);
};

void HeifParserTest::AddHdlrBox(HeifParser& heifParser)
{
    std::shared_ptr<HeifHdlrBox> mockHdlr = std::make_shared<HeifHdlrBox>();
    mockHdlr->boxType_ = BOX_TYPE_HDLR;
    mockHdlr->handlerType_ = HANDLER_TYPE_PICT;
    heifParser.metaBox_->AddChild(mockHdlr);
}

void HeifParserTest::AddPtimBox(HeifParser& heifParser)
{
    std::shared_ptr<HeifPtimBox> mockPtim = std::make_shared<HeifPtimBox>();
    mockPtim->boxType_ = BOX_TYPE_PITM;
    heifParser.metaBox_->AddChild(mockPtim);
}

void HeifParserTest::AddIinfBox(HeifParser& heifParser)
{
    std::shared_ptr<HeifIinfBox> mockIinf = std::make_shared<HeifIinfBox>();
    mockIinf->boxType_ = BOX_TYPE_IINF;
    heifParser.metaBox_->AddChild(mockIinf);
}

void HeifParserTest::AddIprpBox(HeifParser& heifParser)
{
    std::shared_ptr<HeifIprpBox> mockIprp = std::make_shared<HeifIprpBox>();
    mockIprp->boxType_ = BOX_TYPE_IPRP;
    heifParser.metaBox_->AddChild(mockIprp);
}

void HeifParserTest::AddIpcoBox(HeifParser& heifParser)
{
    std::shared_ptr<HeifIprpBox> mockIprp = std::make_shared<HeifIprpBox>();
    mockIprp->boxType_ = BOX_TYPE_IPRP;

    std::shared_ptr<HeifIpcoBox> mockIpco = std::make_shared<HeifIpcoBox>();
    mockIpco->boxType_ = BOX_TYPE_IPCO;
    mockIprp->AddChild(mockIpco);

    heifParser.metaBox_->AddChild(mockIprp);
}

void HeifParserTest::AddIpmaBox(HeifParser& heifParser)
{
    std::shared_ptr<HeifIprpBox> mockIprp = std::make_shared<HeifIprpBox>();
    mockIprp->boxType_ = BOX_TYPE_IPRP;

    std::shared_ptr<HeifIpcoBox> mockIpco = std::make_shared<HeifIpcoBox>();
    mockIpco->boxType_ = BOX_TYPE_IPCO;
    mockIprp->AddChild(mockIpco);

    std::shared_ptr<HeifIpmaBox> mockIpma = std::make_shared<HeifIpmaBox>();
    mockIpma->boxType_ = BOX_TYPE_IPMA;
    mockIprp->AddChild(mockIpma);

    heifParser.metaBox_->AddChild(mockIprp);
}

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
    heifImage.SetPrimaryImage(true);
    bool ret = heifImage.IsPrimaryImage();
    ASSERT_EQ(ret, true);
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
    ASSERT_EQ(heifParser.ilocBox_->WriteMdatBox(write), heif_error_ok);
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
    ASSERT_EQ(heifParser.GetInfeBox(gridItemId), nullptr);
    heifParser.GetTileImages(gridItemId, out);
    GTEST_LOG_(INFO) << "HeifParserTest: GetTileImagesTest001 end";
}

/**
 * @tc.name: ExtractDerivedImagePropertiesTest001
 * @tc.desc: HeifParser
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, ExtractDerivedImagePropertiesTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: ExtractDerivedImagePropertiesTest001 start";
    HeifParser heifParser;
    auto heifImage = std::make_shared<HeifImage>(0);
    heifParser.images_.insert(std::make_pair(0, heifImage));
    auto heifBox = std::make_shared<HeifInfeBox>();
    heifBox->itemType_ = "grid";
    heifParser.infeBoxes_.insert(std::make_pair(0, heifBox));
    heifParser.irefBox_ = std::make_shared<HeifIrefBox>();
    struct HeifIrefBox::Reference ref {.fromItemId = 1};
    heifParser.irefBox_->references_.push_back(ref);
    ASSERT_NE(heifParser.irefBox_->references_.size(), 0);
    heifParser.ExtractDerivedImageProperties();
    GTEST_LOG_(INFO) << "HeifParserTest: ExtractDerivedImagePropertiesTest001 end";
}

/**
 * @tc.name: ExtractDerivedImagePropertiesTest002
 * @tc.desc: Test ExtractDerivedImageProperties when GetImage returns nullptr
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, ExtractDerivedImagePropertiesTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: ExtractDerivedImagePropertiesTest002 start";
    HeifParser heifParser;
    heif_item_id testItemId = IT35_TRUE_ID;
    heif_item_id tileItemId = IT35_MOCK_ID;
    auto heifImage = std::make_shared<HeifImage>(testItemId);
    heifParser.images_.insert(std::make_pair(testItemId, heifImage));
    auto heifBox = std::make_shared<HeifInfeBox>(testItemId, "grid", false);
    heifParser.infeBoxes_.insert(std::make_pair(testItemId, heifBox));
    heifParser.irefBox_ = std::make_shared<HeifIrefBox>();
    HeifIrefBox::Reference ref;
    ref.fromItemId = testItemId;
    ref.toItemIds.push_back(tileItemId);
    ref.box.SetBoxType(BOX_TYPE_DIMG);
    heifParser.irefBox_->references_.push_back(ref);
    heifParser.ExtractDerivedImageProperties();
    ASSERT_NE(heifParser.images_.find(testItemId), heifParser.images_.end());
    ASSERT_EQ(heifParser.images_.find(tileItemId), heifParser.images_.end());
    GTEST_LOG_(INFO) << "HeifParserTest: ExtractDerivedImagePropertiesTest002 end";
}

/**
 * @tc.name: ExtractDerivedImagePropertiesTest003
 * @tc.desc: Test ExtractDerivedImageProperties when image->GetDefaultColorFormat() == HeifColorFormat::UNDEDEFINED
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, ExtractDerivedImagePropertiesTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: ExtractDerivedImagePropertiesTest003 start";
    
    HeifParser heifParser;
    heif_item_id testItemId = IT35_TRUE_ID;
    heif_item_id tileItemId = IT35_MOCK_ID;
    auto heifImage = std::make_shared<HeifImage>(testItemId);
    ASSERT_EQ(heifImage->GetDefaultColorFormat(), HeifColorFormat::UNDEDEFINED);
    heifParser.images_.insert(std::make_pair(testItemId, heifImage));
    auto tileImage = std::make_shared<HeifImage>(tileItemId);
    tileImage->SetDefaultColorFormat(HeifColorFormat::YCBCR);
    heifParser.images_.insert(std::make_pair(tileItemId, tileImage));
    auto heifBox = std::make_shared<HeifInfeBox>(testItemId, "grid", false);
    heifParser.infeBoxes_.insert(std::make_pair(testItemId, heifBox));
    heifParser.irefBox_ = std::make_shared<HeifIrefBox>();
    HeifIrefBox::Reference ref;
    ref.fromItemId = testItemId;
    ref.toItemIds.push_back(tileItemId);
    ref.box.SetBoxType(BOX_TYPE_DIMG);
    heifParser.irefBox_->references_.push_back(ref);
    heifParser.ExtractDerivedImageProperties();
    ASSERT_EQ(heifImage->GetDefaultColorFormat(), HeifColorFormat::YCBCR);
    ASSERT_NE(heifImage->GetDefaultColorFormat(), HeifColorFormat::UNDEDEFINED);
    GTEST_LOG_(INFO) << "HeifParserTest: ExtractDerivedImagePropertiesTest003 end";
}

/**
 * @tc.name: ExtractDerivedImagePropertiesTest004
 * @tc.desc: Test ExtractDerivedImageProperties when image->GetLumaBitNum() >= 0
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, ExtractDerivedImagePropertiesTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: ExtractDerivedImagePropertiesTest004 start";
    
    HeifParser heifParser;
    heif_item_id testItemId = IT35_TRUE_ID;
    heif_item_id tileItemId = IT35_MOCK_ID;
    auto heifImage = std::make_shared<HeifImage>(testItemId);
    heifImage->SetLumaBitNum(NUM_8);
    ASSERT_EQ(heifImage->GetLumaBitNum(), NUM_8);
    heifParser.images_.insert(std::make_pair(testItemId, heifImage));
    auto tileImage = std::make_shared<HeifImage>(tileItemId);
    tileImage->SetLumaBitNum(NUM_10);
    heifParser.images_.insert(std::make_pair(tileItemId, tileImage));
    auto heifBox = std::make_shared<HeifInfeBox>(testItemId, "grid", false);
    heifParser.infeBoxes_.insert(std::make_pair(testItemId, heifBox));
    heifParser.irefBox_ = std::make_shared<HeifIrefBox>();
    HeifIrefBox::Reference ref;
    ref.fromItemId = testItemId;
    ref.toItemIds.push_back(tileItemId);
    ref.box.SetBoxType(BOX_TYPE_DIMG);
    heifParser.irefBox_->references_.push_back(ref);
    heifParser.ExtractDerivedImageProperties();
    ASSERT_EQ(heifImage->GetLumaBitNum(), NUM_8);
    ASSERT_NE(heifImage->GetLumaBitNum(), NUM_10);
    ASSERT_GE(heifImage->GetLumaBitNum(), NUM_8);
    GTEST_LOG_(INFO) << "HeifParserTest: ExtractDerivedImagePropertiesTest004 end";
}

/**
 * @tc.name: ExtractDerivedImagePropertiesTest005
 * @tc.desc: Test ExtractDerivedImageProperties skip ChromaBitNum < 0 branch
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, ExtractDerivedImagePropertiesTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: ExtractDerivedImagePropertiesTest005 start";
    HeifParser heifParser;
    heif_item_id testItemId = IT35_TRUE_ID;
    heif_item_id tileItemId = IT35_MOCK_ID;
    auto heifImage = std::make_shared<HeifImage>(testItemId);
    heifImage->SetChromaBitNum(NUM_8);
    ASSERT_EQ(heifImage->GetChromaBitNum(), NUM_8);
    heifParser.images_.insert(std::make_pair(testItemId, heifImage));
    auto tileImage = std::make_shared<HeifImage>(tileItemId);
    tileImage->SetChromaBitNum(NUM_10);
    heifParser.images_.insert(std::make_pair(tileItemId, tileImage));
    auto heifBox = std::make_shared<HeifInfeBox>(testItemId, "grid", false);
    heifParser.infeBoxes_.insert(std::make_pair(testItemId, heifBox));
    heifParser.irefBox_ = std::make_shared<HeifIrefBox>();
    HeifIrefBox::Reference ref;
    ref.fromItemId = testItemId;
    ref.toItemIds.push_back(tileItemId);
    ref.box.SetBoxType(BOX_TYPE_DIMG);
    heifParser.irefBox_->references_.push_back(ref);
    heifParser.ExtractDerivedImageProperties();
    ASSERT_EQ(heifImage->GetChromaBitNum(), NUM_8);
    ASSERT_NE(heifImage->GetChromaBitNum(), NUM_10);
    GTEST_LOG_(INFO) << "HeifParserTest: ExtractDerivedImagePropertiesTest005 end";
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
 * @tc.name: ExtractAuxImageTest001
 * @tc.desc: Test ExtractAuxImage when auxc is null
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, ExtractAuxImageTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: ExtractAuxImageTest001 start";
    HeifParser heifParser;
    heif_item_id auxItemId = IT35_TRUE_ID;
    heif_item_id masterItemId = IT35_MOCK_ID;
    std::shared_ptr<HeifImage> auxImage = std::make_shared<HeifImage>(auxItemId);
    std::shared_ptr<HeifImage> masterImage = std::make_shared<HeifImage>(masterItemId);
    heifParser.images_.insert(std::make_pair(masterItemId, masterImage));
    HeifIrefBox::Reference ref;
    ref.fromItemId = auxItemId;
    ref.toItemIds.push_back(masterItemId);
    ref.box.SetBoxType(BOX_TYPE_AUXL);
    heifParser.ipcoBox_ = std::make_shared<HeifIpcoBox>();
    heifParser.ipmaBox_ = std::make_shared<HeifIpmaBox>();
    heifParser.ExtractAuxImage(auxImage, ref);
    ASSERT_TRUE(masterImage->GetAuxImages().empty());
    GTEST_LOG_(INFO) << "HeifParserTest: ExtractAuxImageTest001 end";
}

/**
 * @tc.name: ExtractGainmapImageTest001
 * @tc.desc: Test ExtractGainmapImage when fromItemInfeBox is null
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, ExtractGainmapImageTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: ExtractGainmapImageTest001 start";
    HeifParser heifParser;
    heif_item_id tmapId = IT35_TRUE_ID;
    heif_item_id baseId = TMAP_TRUE_ID;
    heif_item_id gainmapId = TMAP_MOCK_ID;
    std::shared_ptr<HeifImage> primaryImage = std::make_shared<HeifImage>(baseId);
    primaryImage->SetPrimaryImage(true);
    heifParser.primaryImage_ = primaryImage;
    heifParser.irefBox_ = std::make_shared<HeifIrefBox>();
    HeifIrefBox::Reference ref;
    ref.fromItemId = tmapId;
    ref.toItemIds.push_back(baseId);
    ref.toItemIds.push_back(gainmapId);
    ref.box.SetBoxType(BOX_TYPE_DIMG);
    heifParser.irefBox_->references_.push_back(ref);
    std::shared_ptr<HeifImage> gainmapImage = std::make_shared<HeifImage>(gainmapId);
    heifParser.images_.insert(std::make_pair(gainmapId, gainmapImage));
    heifParser.ExtractGainmapImage(tmapId);
    ASSERT_EQ(heifParser.primaryImage_->GetGainmapImage(), nullptr);
    GTEST_LOG_(INFO) << "HeifParserTest: ExtractGainmapImageTest001 end";
}

/**
 * @tc.name: ExtractGainmapImageTest002
 * @tc.desc: Test ExtractGainmapImage when fromItemInfeBox->GetItemType() != "tmap"
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, ExtractGainmapImageTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: ExtractGainmapImageTest002 start";
    HeifParser heifParser;
    heif_item_id tmapId = IT35_TRUE_ID;
    heif_item_id baseId = TMAP_TRUE_ID;
    heif_item_id gainmapId = TMAP_MOCK_ID;
    std::shared_ptr<HeifImage> primaryImage = std::make_shared<HeifImage>(baseId);
    primaryImage->SetPrimaryImage(true);
    heifParser.primaryImage_ = primaryImage;
    std::shared_ptr<HeifInfeBox> tmapInfeBox = std::make_shared<HeifInfeBox>(tmapId, "grid", false);
    heifParser.infeBoxes_.insert(std::make_pair(tmapId, tmapInfeBox));
    heifParser.irefBox_ = std::make_shared<HeifIrefBox>();
    HeifIrefBox::Reference ref;
    ref.fromItemId = tmapId;
    ref.toItemIds.push_back(baseId);
    ref.toItemIds.push_back(gainmapId);
    ref.box.SetBoxType(BOX_TYPE_DIMG);
    heifParser.irefBox_->references_.push_back(ref);
    std::shared_ptr<HeifImage> gainmapImage = std::make_shared<HeifImage>(gainmapId);
    heifParser.images_.insert(std::make_pair(gainmapId, gainmapImage));
    heifParser.ExtractGainmapImage(tmapId);
    ASSERT_EQ(heifParser.primaryImage_->GetGainmapImage(), nullptr);
    GTEST_LOG_(INFO) << "HeifParserTest: ExtractGainmapImageTest002 end";
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
 * @tc.name: ExtractMetadataTest002
 * @tc.desc: Test ExtractMetadata when masterImageId == metadataItemId
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, ExtractMetadataTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: ExtractMetadataTest002 start";
    HeifParser heifParser;
    heif_item_id metadataItemId = IT35_TRUE_ID;
    std::vector<heif_item_id> allItemIds;
    allItemIds.push_back(metadataItemId);
    heifParser.irefBox_ = std::make_shared<HeifIrefBox>();
    HeifIrefBox::Reference ref;
    ref.fromItemId = metadataItemId;
    ref.toItemIds.push_back(metadataItemId);
    ref.box.SetBoxType(BOX_TYPE_CDSC);
    heifParser.irefBox_->references_.push_back(ref);
    std::shared_ptr<HeifImage> masterImage = std::make_shared<HeifImage>(metadataItemId);
    heifParser.images_.insert(std::make_pair(metadataItemId, masterImage));
    size_t initialMetadataCount = masterImage->GetAllMetadata().size();
    heifParser.ExtractMetadata(allItemIds);
    ASSERT_EQ(initialMetadataCount, METADATA_COUNT);
    GTEST_LOG_(INFO) << "HeifParserTest: ExtractMetadataTest002 end";
}

/**
 * @tc.name: ExtractMetadataTest003
 * @tc.desc: Test ExtractMetadata when GetItemData returns error
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, ExtractMetadataTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: ExtractMetadataTest003 start";
    HeifParser heifParser;
    heif_item_id metadataItemId = IT35_TRUE_ID;
    heif_item_id masterImageId = IT35_MOCK_ID;
    std::vector<heif_item_id> allItemIds;
    allItemIds.push_back(metadataItemId);
    heifParser.irefBox_ = std::make_shared<HeifIrefBox>();
    HeifIrefBox::Reference ref;
    ref.fromItemId = metadataItemId;
    ref.toItemIds.push_back(masterImageId);
    ref.box.SetBoxType(BOX_TYPE_CDSC);
    heifParser.irefBox_->references_.push_back(ref);
    std::shared_ptr<HeifImage> masterImage = std::make_shared<HeifImage>(masterImageId);
    heifParser.images_.insert(std::make_pair(masterImageId, masterImage));
    size_t initialMetadataCount = masterImage->GetAllMetadata().size();
    heifParser.ExtractMetadata(allItemIds);
    ASSERT_EQ(initialMetadataCount, METADATA_COUNT);
    GTEST_LOG_(INFO) << "HeifParserTest: ExtractMetadataTest003 end";
}

/**
 * @tc.name: GetAuxiliaryMapImageTest001
 * @tc.desc: Test GetAuxiliaryMapImage when primaryImage_ is null
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, GetAuxiliaryMapImageTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: GetAuxiliaryMapImageTest001 start";
    HeifParser heifParser;
    std::string auxType = "test_aux_type";
    ASSERT_EQ(heifParser.primaryImage_, nullptr);
    std::shared_ptr<HeifImage> result = heifParser.GetAuxiliaryMapImage(auxType);
    ASSERT_EQ(result, nullptr);
    GTEST_LOG_(INFO) << "HeifParserTest: GetAuxiliaryMapImageTest001 end";
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
    heif_item_id ret = heifParser.GetNextItemId();
    ASSERT_EQ(ret, 1);
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
    ASSERT_NE(heifParser.metaBox_, nullptr);
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

/**
 * @tc.name: ParseContentChildrenTest001
 * @tc.desc: Test ParseContentChildren of HeifIprpBox when recursionCount over than MAX_RECURSION_COUNT
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, ParseContentChildrenTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ParseContentChildrenTest001 start";
    HeifIprpBox heifIprpBox;
    auto stream = std::make_shared<HeifBufferInputStream>(nullptr, 0, true);
    ASSERT_NE(stream, nullptr);
    HeifStreamReader reader(stream, 0, 0);

    uint32_t recursionCount = heifIprpBox.MAX_RECURSION_COUNT;
    heif_error error = heifIprpBox.ParseContentChildren(reader, recursionCount);
    EXPECT_EQ(error, heif_error_too_many_recursion);
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ParseContentChildrenTest001 end";
}

/**
 * @tc.name: ParseContentChildrenTest002
 * @tc.desc: Test ParseContentChildren of HeifIpcoBox when recursionCount over than MAX_RECURSION_COUNT
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, ParseContentChildrenTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ParseContentChildrenTest002 start";
    HeifIpcoBox heifIpcoBox;
    auto stream = std::make_shared<HeifBufferInputStream>(nullptr, 0, true);
    ASSERT_NE(stream, nullptr);
    HeifStreamReader reader(stream, 0, 0);

    uint32_t recursionCount = heifIpcoBox.MAX_RECURSION_COUNT;
    heif_error error = heifIpcoBox.ParseContentChildren(reader, recursionCount);
    EXPECT_EQ(error, heif_error_too_many_recursion);
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ParseContentChildrenTest002 end";
}

/**
 * @tc.name: ParseContentChildrenTest003
 * @tc.desc: Test ParseContentChildren of HeifIpcoBox when recursionCount over than MAX_RECURSION_COUNT
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, ParseContentChildrenTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ParseContentChildrenTest003Test001 start";
    HeifMetaBox heifMetaBox;
    auto stream = std::make_shared<HeifBufferInputStream>(nullptr, 0, true);
    ASSERT_NE(stream, nullptr);
    HeifStreamReader reader(stream, 0, 0);

    uint32_t recursionCount = heifMetaBox.MAX_RECURSION_COUNT;
    heif_error error = heifMetaBox.ParseContentChildren(reader, recursionCount);
    EXPECT_EQ(error, heif_error_too_many_recursion);
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ParseContentChildrenTest003Test001 end";
}

/**
 * @tc.name: MakeFromMemoryTest001
 * @tc.desc: Verify that HeifParser call MakeFromMemory when data is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, MakeFromMemoryTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: MakeFromMemoryTest001 start";
    HeifParser heifParser;
    auto ret = heifParser.MakeFromMemory(nullptr, 0, false, nullptr);
    ASSERT_EQ(ret, heif_error_no_data);
    GTEST_LOG_(INFO) << "HeifParserTest: MakeFromMemoryTest001 end";
}

/**
 * @tc.name: MakeFromStreamTest001
 * @tc.desc: Verify that HeifParser call MakeFromStream when stream is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, MakeFromStreamTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: MakeFromStreamTest001 start";
    HeifParser heifParser;
    std::shared_ptr<HeifInputStream> stream;
    auto ret = heifParser.MakeFromStream(stream, nullptr);
    ASSERT_EQ(ret, heif_error_no_data);
    GTEST_LOG_(INFO) << "HeifParserTest: MakeFromStreamTest001 end";
}

/**
 * @tc.name: MakeFromStreamTest002
 * @tc.desc: Test MakeFromStream when AssembleImages fails to find primary image.
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, MakeFromStreamTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: MakeFromStreamTest002 start";
    std::vector<uint8_t> heifData = {
        0x00, 0x00, 0x00, 0x18, 'f', 't', 'y', 'p',
        'h', 'e', 'i', 'c',
        0x00, 0x00, 0x00, 0x00,
        'h', 'e', 'i', 'c', 'm', 'i', 'f', '1',
        0x00, 0x00, 0x00, 0x70, 'm', 'e', 't', 'a',
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x20, 'h', 'd', 'l', 'r',
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        'p', 'i', 'c', 't',
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x0E, 'p', 'i', 't', 'm',
        0x00, 0x00, 0x00, 0x00,
        0xFF, 0xFF,
        0x00, 0x00, 0x00, 0x0C, 'i', 'i', 'n', 'f',
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00, 0x00, 0x20, 'i', 'p', 'r', 'p',
        0x00, 0x00, 0x00, 0x08, 'i', 'p', 'c', 'o',
        0x00, 0x00, 0x00, 0x10, 'i', 'p', 'm', 'a',
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x10, 'i', 'l', 'o', 'c',
        0x00, 0x00, 0x00, 0x00,
        0x44, 0x40, 0x00, 0x00,
    };
    auto inputStream = std::make_shared<HeifBufferInputStream>(heifData.data(), heifData.size(), false);
    std::shared_ptr<HeifParser> parser;
    heif_error ret = HeifParser::MakeFromStream(inputStream, &parser);
    ASSERT_EQ(ret, heif_error_invalid_box_size);
    GTEST_LOG_(INFO) << "HeifParserTest: MakeFromStreamTest002 end";
}

/**
 * @tc.name: GetGridLengthTest001
 * @tc.desc: Verify that HeifParser call GetGridLength when item id is mock.
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, GetGridLengthTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: GetGridLengthTest001 start";
    HeifParser heifParser;
    size_t mockSize = 0;
    auto ret = heifParser.GetGridLength(MOCK_ITEM_ID, mockSize);
    ASSERT_EQ(ret, heif_error_item_not_found);
    GTEST_LOG_(INFO) << "HeifParserTest: GetGridLengthTest001 end";
}

/**
 * @tc.name: GetIdenImageTest001
 * @tc.desc: Verify that HeifParser call GetIdenImage when item id is mock.
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, GetIdenImageTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: GetIdenImageTest001 start";
    HeifParser heifParser;
    std::shared_ptr<HeifImage> resImage;
    heifParser.GetIdenImage(MOCK_ITEM_ID, resImage);
    ASSERT_EQ(resImage, nullptr);
    GTEST_LOG_(INFO) << "HeifParserTest: GetIdenImageTest001 end";
}

/**
 * @tc.name: GetIdenImageTest002
 * @tc.desc: Verify that HeifParser call GetIdenImage when irefBox_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, GetIdenImageTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: GetIdenImageTest002 start";
    HeifParser heifParser;
    std::shared_ptr<HeifInfeBox> mockBox = std::make_shared<HeifInfeBox>(MOCK_ITEM_ID, "iden", false);
    ASSERT_NE(mockBox, nullptr);
    heifParser.infeBoxes_[MOCK_ITEM_ID] = mockBox;
    heifParser.irefBox_.reset();
    std::shared_ptr<HeifImage> resImage;
    heifParser.GetIdenImage(MOCK_ITEM_ID, resImage);
    ASSERT_EQ(resImage, nullptr);
    GTEST_LOG_(INFO) << "HeifParserTest: GetIdenImageTest002 end";
}

/**
 * @tc.name: GetIdenImageTest003
 * @tc.desc: Verify that HeifParser call GetIdenImage when infe's itemType is not iden.
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, GetIdenImageTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: GetIdenImageTest003 start";
    HeifParser heifParser;
    std::shared_ptr<HeifInfeBox> mockBox = std::make_shared<HeifInfeBox>(MOCK_ITEM_ID, "mock", false);
    ASSERT_NE(mockBox, nullptr);
    heifParser.infeBoxes_[MOCK_ITEM_ID] = mockBox;
    std::shared_ptr<HeifImage> resImage;
    heifParser.GetIdenImage(MOCK_ITEM_ID, resImage);
    ASSERT_EQ(resImage, nullptr);
    GTEST_LOG_(INFO) << "HeifParserTest: GetIdenImageTest003 end";
}

/**
 * @tc.name: AssembleImagesTest001
 * @tc.desc: Verify that HeifParser call AssembleImages when primaryImage_ is invalid.
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, AssembleImagesTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: AssembleImagesTest001 start";
    HeifParser heifParser;
    decltype(heifParser.infeBoxes_) mockMap;
    heifParser.infeBoxes_.swap(mockMap);
    heifParser.infeBoxes_[MOCK_ITEM_ID] = std::make_shared<HeifInfeBox>(0, "hollow", false);
    heifParser.primaryImage_.reset();
    auto ret = heifParser.AssembleImages();
    ASSERT_EQ(ret, heif_error_primary_item_not_found);
    GTEST_LOG_(INFO) << "HeifParserTest: AssembleImagesTest001 end";
}

/**
 * @tc.name: AssembleImagesTest002
 * @tc.desc: Verify that HeifParser call AssembleImages when primaryImage_ is valid.
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, AssembleImagesTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: AssembleImagesTest002 start";
    HeifParser heifParser;
    decltype(heifParser.infeBoxes_) mockMap;
    mockMap[MOCK_ITEM_ID] = std::make_shared<HeifInfeBox>(0, "hollow", false);
    mockMap[IT35_TRUE_ID] = std::make_shared<HeifInfeBox>(IT35_TRUE_ID, "it35", false);
    mockMap[IT35_MOCK_ID] = std::make_shared<HeifInfeBox>(TMAP_MOCK_ID, "it35", false);
    mockMap[TMAP_TRUE_ID] = std::make_shared<HeifInfeBox>(TMAP_TRUE_ID, "tmap", false);
    mockMap[TMAP_MOCK_ID] = std::make_shared<HeifInfeBox>(IT35_MOCK_ID, "tmap", false);
    mockMap[IDEN_TRUE_ID] = std::make_shared<HeifInfeBox>(IDEN_TRUE_ID, "iden", false);
    mockMap[MIME_TRUE_ID] = std::make_shared<HeifInfeBox>(MIME_TRUE_ID, "mime", false);
    mockMap[MIME_TRUE_ID]->SetItemName(std::string{"RfDataB\0"});
    heifParser.infeBoxes_.swap(mockMap);
    heifParser.ilocBox_ = std::make_shared<HeifIlocBox>();
    heifParser.pitmBox_ = std::make_shared<HeifPtimBox>();
    heifParser.pitmBox_->itemId_ = IDEN_TRUE_ID;
    heifParser.ipcoBox_.reset();
    heifParser.ipmaBox_.reset();
    auto ret = heifParser.AssembleImages();
    ASSERT_EQ(ret, heif_error_ok);
    GTEST_LOG_(INFO) << "HeifParserTest: AssembleImagesTest002 end";
}

/**
 * @tc.name: AssembleImagesTest003
 * @tc.desc: Verify that HeifParser call AssembleImages when satisfy imir mdvc clli property.
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, AssembleImagesTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: AssembleImagesTest003 start";
    HeifParser heifParser;
    decltype(heifParser.infeBoxes_) mockMap;
    mockMap[TMAP_TRUE_ID] = std::make_shared<HeifInfeBox>(TMAP_TRUE_ID, "tmap", false);
    heifParser.infeBoxes_.swap(mockMap);
    heifParser.ilocBox_ = std::make_shared<HeifIlocBox>();
    heifParser.pitmBox_ = std::make_shared<HeifPtimBox>();

    heifParser.ipmaBox_ = std::make_shared<HeifIpmaBox>();
    heifParser.ipmaBox_->AddProperty(TMAP_TRUE_ID, PropertyAssociation{.essential = false, .propertyIndex = INDEX_1});
    heifParser.ipmaBox_->AddProperty(TMAP_TRUE_ID, PropertyAssociation{.essential = false, .propertyIndex = INDEX_2});
    heifParser.ipmaBox_->AddProperty(TMAP_TRUE_ID, PropertyAssociation{.essential = false, .propertyIndex = INDEX_3});

    heifParser.ipcoBox_ = std::make_shared<HeifIpcoBox>();
    heifParser.ipcoBox_->AddChild(std::make_shared<HeifImirBox>());
    heifParser.ipcoBox_->AddChild(std::make_shared<HeifMdcvBox>());
    heifParser.ipcoBox_->AddChild(std::make_shared<HeifClliBox>());

    auto ret = heifParser.AssembleImages();
    ASSERT_EQ(ret, heif_error_primary_item_not_found);
    GTEST_LOG_(INFO) << "HeifParserTest: AssembleImagesTest003 end";
}

/**
 * @tc.name: AppendHvccNalDataTest001
 * @tc.desc: Verify that HeifParser call AppendHvccNalData when hvcc is invalid.
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, AppendHvccNalDataTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: AppendHvccNalDataTest001 start";
    HeifParser heifParser;
    heifParser.ipmaBox_ = std::make_shared<HeifIpmaBox>();
    heifParser.ipmaBox_->AddProperty(TMAP_TRUE_ID, PropertyAssociation{.essential = false, .propertyIndex = INDEX_1});
    heifParser.ipcoBox_ = std::make_shared<HeifIpcoBox>();
    std::vector<uint8_t> mockData;
    auto ret = heifParser.AppendHvccNalData(TMAP_TRUE_ID, mockData);
    ASSERT_EQ(ret, heif_error_no_hvcc);
    GTEST_LOG_(INFO) << "HeifParserTest: AppendHvccNalDataTest001 end";
}

/**
 * @tc.name: AppendHvccNalDataTest002
 * @tc.desc: Verify that HeifParser call AppendHvccNalData when hvcc is valid.
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, AppendHvccNalDataTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: AppendHvccNalDataTest002 start";
    HeifParser heifParser;
    heifParser.ipmaBox_ = std::make_shared<HeifIpmaBox>();
    heifParser.ipmaBox_->AddProperty(TMAP_TRUE_ID, PropertyAssociation{.essential = false, .propertyIndex = INDEX_1});
    heifParser.ipcoBox_ = std::make_shared<HeifIpcoBox>();
    heifParser.ipcoBox_->AddChild(std::make_shared<HeifHvccBox>());
    std::vector<uint8_t> mockData{MOCK_DATA_1, MOCK_DATA_2};
    auto ret = heifParser.AppendHvccNalData(TMAP_TRUE_ID, mockData);
    ASSERT_EQ(ret, heif_error_ok);
    GTEST_LOG_(INFO) << "HeifParserTest: AppendHvccNalDataTest002 end";
}

/**
 * @tc.name: SetHvccConfigTest001
 * @tc.desc: Verify that HeifParser call SetHvccConfig when hvcc is valid.
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, SetHvccConfigTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: SetHvccConfigTest001 start";
    HeifParser heifParser;
    heifParser.ipmaBox_ = std::make_shared<HeifIpmaBox>();
    heifParser.ipmaBox_->AddProperty(TMAP_TRUE_ID, PropertyAssociation{.essential = false, .propertyIndex = INDEX_1});
    heifParser.ipcoBox_ = std::make_shared<HeifIpcoBox>();
    heifParser.ipcoBox_->AddChild(std::make_shared<HeifHvccBox>());
    HvccConfig mockConfig;
    auto ret = heifParser.SetHvccConfig(TMAP_TRUE_ID, mockConfig);
    ASSERT_EQ(ret, heif_error_ok);
    GTEST_LOG_(INFO) << "HeifParserTest: SetHvccConfigTest001 end";
}

/**
 * @tc.name: GetExifHeaderOffsetTest001
 * @tc.desc: Verify that HeifParser call GetExifHeaderOffset when data is mock.
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, GetExifHeaderOffsetTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: GetExifHeaderOffsetTest001 start";
    HeifParser heifParser;
    std::unique_ptr<uint8_t[]> mockData = std::make_unique<uint8_t[]>(MOCK_DATA_SIZE);
    auto ret = heifParser.GetExifHeaderOffset(mockData.get(), MOCK_DATA_SIZE);
    ASSERT_EQ(ret, NUM_1);
    GTEST_LOG_(INFO) << "HeifParserTest: GetExifHeaderOffsetTest001 end";
}

/**
 * @tc.name: SetExifMetadataTest001
 * @tc.desc: Verify that HeifParser call SetExifMetadata when data is mock.
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, SetExifMetadataTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: SetExifMetadataTest001 start";
    HeifParser heifParser;
    auto ret = heifParser.SetExifMetadata(nullptr, nullptr, 0);
    ASSERT_EQ(ret, heif_invalid_exif_data);
    GTEST_LOG_(INFO) << "HeifParserTest: SetExifMetadataTest001 end";
}

/**
 * @tc.name: UpdateExifMetadataTest001
 * @tc.desc: Verify that HeifParser call UpdateExifMetadata when data is mock.
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, UpdateExifMetadataTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: UpdateExifMetadataTest001 start";
    HeifParser heifParser;
    auto ret = heifParser.UpdateExifMetadata(nullptr, nullptr, 0, MOCK_ITEM_ID);
    ASSERT_EQ(ret, heif_invalid_exif_data);
    GTEST_LOG_(INFO) << "HeifParserTest: UpdateExifMetadataTest001 end";
}

/**
 * @tc.name: GetTiffOffsetTest001
 * @tc.desc: Verify that HeifParser call GetTiffOffset when tiffoffset_ is invalid.
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, GetTiffOffsetTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: GetTiffOffsetTest001 start";
    HeifParser heifParser;
    heifParser.tiffOffset_ = NUM_1;
    auto ret = heifParser.GetTiffOffset();
    ASSERT_EQ(ret, NUM_1);
    GTEST_LOG_(INFO) << "HeifParserTest: GetTiffOffsetTest001 end";
}

/**
 * @tc.name: GetTiffOffsetTest002
 * @tc.desc: Verify that HeifParser call GetTiffOffset when primaryImage_ is invalid.
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, GetTiffOffsetTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: GetTiffOffsetTest002 start";
    HeifParser heifParser;
    heifParser.tiffOffset_ = 0;
    heifParser.primaryImage_.reset();
    auto ret = heifParser.GetTiffOffset();
    ASSERT_EQ(ret, 0);
    GTEST_LOG_(INFO) << "HeifParserTest: GetTiffOffsetTest002 end";
}

/**
 * @tc.name: GetTiffOffsetTest003
 * @tc.desc: Verify that HeifParser call GetTiffOffset when exifId is 0.
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, GetTiffOffsetTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: GetTiffOffsetTest003 start";
    HeifParser heifParser;
    heifParser.tiffOffset_ = 0;
    heifParser.primaryImage_ = std::make_shared<HeifImage>(MOCK_ITEM_ID);
    auto ret = heifParser.GetTiffOffset();
    ASSERT_EQ(ret, 0);
    GTEST_LOG_(INFO) << "HeifParserTest: GetTiffOffsetTest003 end";
}

/**
 * @tc.name: GetTiffOffsetTest004
 * @tc.desc: Verify that HeifParser call GetTiffOffset when infeBoxes_ is empty.
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, GetTiffOffsetTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: GetTiffOffsetTest004 start";
    HeifParser heifParser;
    heifParser.tiffOffset_ = 0;
    heifParser.primaryImage_ = std::make_shared<HeifImage>(MOCK_ITEM_ID);
    std::shared_ptr<HeifMetadata> mockMetaData = std::make_shared<HeifMetadata>();
    mockMetaData->itemId = MOCK_ITEM_ID;
    mockMetaData->itemType = std::string{"Exif\0\0"};
    heifParser.primaryImage_->AddMetadata(mockMetaData);
    auto ret = heifParser.GetTiffOffset();
    ASSERT_EQ(ret, 0);
    GTEST_LOG_(INFO) << "HeifParserTest: GetTiffOffsetTest004 end";
}

/**
 * @tc.name: GetTiffOffsetTest005
 * @tc.desc: Verify that HeifParser call GetTiffOffset when ilocItem is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, GetTiffOffsetTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: GetTiffOffsetTest005 start";
    HeifParser heifParser;
    heifParser.tiffOffset_ = 0;
    heifParser.primaryImage_ = std::make_shared<HeifImage>(MOCK_ITEM_ID);
    std::shared_ptr<HeifMetadata> mockMetaData = std::make_shared<HeifMetadata>();
    mockMetaData->itemId = MOCK_ITEM_ID;
    mockMetaData->itemType = std::string{"Exif\0\0"};
    heifParser.primaryImage_->AddMetadata(mockMetaData);
    heifParser.infeBoxes_[MOCK_ITEM_ID] = std::make_shared<HeifInfeBox>(MOCK_ITEM_ID, "mock", false);
    heifParser.ilocBox_ = std::make_shared<HeifIlocBox>();
    auto ret = heifParser.GetTiffOffset();
    ASSERT_EQ(ret, 0);
    GTEST_LOG_(INFO) << "HeifParserTest: GetTiffOffsetTest005 end";
}

/**
 * @tc.name: AssembleImagesTest004
 * @tc.desc: Verify that HeifParser call AssembleImages when ExtractGainmap include invalid data.
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, AssembleImagesTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: AssembleImagesTest004 start";
    HeifParser heifParser;
    decltype(heifParser.infeBoxes_) mockMap;
    mockMap[IDEN_TRUE_ID] = std::make_shared<HeifInfeBox>(IDEN_TRUE_ID, "iden", false);
    mockMap[TMAP_TRUE_ID] = std::make_shared<HeifInfeBox>(TMAP_TRUE_ID, "tmap", false);

    heifParser.infeBoxes_.swap(mockMap);
    heifParser.ilocBox_ = std::make_shared<HeifIlocBox>();
    heifParser.pitmBox_ = std::make_shared<HeifPtimBox>();
    heifParser.pitmBox_->itemId_ = IDEN_TRUE_ID;
    heifParser.ipcoBox_.reset();
    heifParser.ipmaBox_.reset();

    heifParser.irefBox_ = std::make_shared<HeifIrefBox>();
    heifParser.irefBox_->AddReferences(TMAP_TRUE_ID, BOX_TYPE_THMB, std::vector<heif_item_id>{});
    heifParser.irefBox_->AddReferences(TMAP_TRUE_ID, BOX_TYPE_DIMG, std::vector<heif_item_id>{});

    auto ret = heifParser.AssembleImages();
    ASSERT_EQ(ret, heif_error_ok);

    heifParser.irefBox_->references_[INDEX_1].toItemIds = std::vector<heif_item_id>{MOCK_ITEM_ID, TMAP_TRUE_ID};
    ret = heifParser.AssembleImages();
    ASSERT_EQ(ret, heif_error_ok);

    heifParser.irefBox_->references_[INDEX_1].toItemIds = std::vector<heif_item_id>{IDEN_TRUE_ID, MOCK_ITEM_ID};
    ret = heifParser.AssembleImages();
    ASSERT_EQ(ret, heif_error_ok);
    GTEST_LOG_(INFO) << "HeifParserTest: AssembleImagesTest004 end";
}

/**
 * @tc.name: MakeFromMemoryTest002
 * @tc.desc: Verify that HeifParser call MakeFromMemory when ftypBox_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, MakeFromMemoryTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: MakeFromMemoryTest002 start";
    std::unique_ptr<uint8_t[]> mockData = std::make_unique<uint8_t[]>(NUM_1);
    std::shared_ptr<HeifParser> heifParser;
    auto ret = HeifParser::MakeFromMemory(mockData.get(), NUM_1, false, &heifParser);
    ASSERT_EQ(ret, heif_error_no_ftyp);
    GTEST_LOG_(INFO) << "HeifParserTest: MakeFromMemoryTest002 end";
}

/**
 * @tc.name: AssembleBoxesTest001
 * @tc.desc: Verify that HeifParser call AssembleBoxes when metaBox_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, AssembleBoxesTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: AssembleBoxesTest001 start";
    std::unique_ptr<uint8_t[]> mockData = std::make_unique<uint8_t[]>(NUM_1);
    auto stream = std::make_shared<HeifBufferInputStream>(mockData.get(), NUM_1, false);

    HeifParser heifParser(stream);
    heifParser.ftypBox_ = std::make_shared<HeifFtypBox>();

    auto maxSize = static_cast<uint64_t>(std::numeric_limits<int64_t>::max());
    HeifStreamReader reader(stream, 0, maxSize);

    auto ret = heifParser.AssembleBoxes(reader);
    ASSERT_EQ(ret, heif_error_no_meta);
    GTEST_LOG_(INFO) << "HeifParserTest: AssembleBoxesTest001 end";
}

/**
 * @tc.name: AssembleBoxesTest002
 * @tc.desc: Verify that HeifParser call AssembleBoxes when hdlrBox_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, AssembleBoxesTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: AssembleBoxesTest002 start";
    std::unique_ptr<uint8_t[]> mockData = std::make_unique<uint8_t[]>(NUM_1);
    auto stream = std::make_shared<HeifBufferInputStream>(mockData.get(), NUM_1, false);

    HeifParser heifParser(stream);
    heifParser.ftypBox_ = std::make_shared<HeifFtypBox>();
    heifParser.metaBox_ = std::make_shared<HeifMetaBox>();

    auto maxSize = static_cast<uint64_t>(std::numeric_limits<int64_t>::max());
    HeifStreamReader reader(stream, 0, maxSize);

    auto ret = heifParser.AssembleBoxes(reader);
    ASSERT_EQ(ret, heif_error_invalid_handler);
    GTEST_LOG_(INFO) << "HeifParserTest: AssembleBoxesTest002 end";
}

/**
 * @tc.name: AssembleBoxesTest003
 * @tc.desc: Verify that HeifParser call AssembleBoxes when pitmBox_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, AssembleBoxesTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: AssembleBoxesTest003 start";
    std::unique_ptr<uint8_t[]> mockData = std::make_unique<uint8_t[]>(NUM_1);
    auto stream = std::make_shared<HeifBufferInputStream>(mockData.get(), NUM_1, false);

    HeifParser heifParser(stream);
    heifParser.ftypBox_ = std::make_shared<HeifFtypBox>();
    heifParser.metaBox_ = std::make_shared<HeifMetaBox>();

    AddHdlrBox(heifParser);

    auto maxSize = static_cast<uint64_t>(std::numeric_limits<int64_t>::max());
    HeifStreamReader reader(stream, 0, maxSize);

    auto ret = heifParser.AssembleBoxes(reader);
    ASSERT_EQ(ret, heif_error_no_pitm);
    GTEST_LOG_(INFO) << "HeifParserTest: AssembleBoxesTest003 end";
}

/**
 * @tc.name: AssembleBoxesTest004
 * @tc.desc: Verify that HeifParser call AssembleBoxes when iinfBox_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, AssembleBoxesTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: AssembleBoxesTest004 start";
    std::unique_ptr<uint8_t[]> mockData = std::make_unique<uint8_t[]>(NUM_1);
    auto stream = std::make_shared<HeifBufferInputStream>(mockData.get(), NUM_1, false);

    HeifParser heifParser(stream);
    heifParser.ftypBox_ = std::make_shared<HeifFtypBox>();
    heifParser.metaBox_ = std::make_shared<HeifMetaBox>();

    AddHdlrBox(heifParser);
    AddPtimBox(heifParser);

    auto maxSize = static_cast<uint64_t>(std::numeric_limits<int64_t>::max());
    HeifStreamReader reader(stream, 0, maxSize);

    auto ret = heifParser.AssembleBoxes(reader);
    ASSERT_EQ(ret, heif_error_no_iinf);
    GTEST_LOG_(INFO) << "HeifParserTest: AssembleBoxesTest004 end";
}

/**
 * @tc.name: AssembleBoxesTest005
 * @tc.desc: Verify that HeifParser call AssembleBoxes when iprpBox_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, AssembleBoxesTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: AssembleBoxesTest005 start";
    std::unique_ptr<uint8_t[]> mockData = std::make_unique<uint8_t[]>(NUM_1);
    auto stream = std::make_shared<HeifBufferInputStream>(mockData.get(), NUM_1, false);

    HeifParser heifParser(stream);
    heifParser.ftypBox_ = std::make_shared<HeifFtypBox>();
    heifParser.metaBox_ = std::make_shared<HeifMetaBox>();

    AddHdlrBox(heifParser);
    AddPtimBox(heifParser);
    AddIinfBox(heifParser);

    auto maxSize = static_cast<uint64_t>(std::numeric_limits<int64_t>::max());
    HeifStreamReader reader(stream, 0, maxSize);

    auto ret = heifParser.AssembleBoxes(reader);
    ASSERT_EQ(ret, heif_error_no_iprp);
    GTEST_LOG_(INFO) << "HeifParserTest: AssembleBoxesTest005 end";
}

/**
 * @tc.name: AssembleBoxesTest006
 * @tc.desc: Verify that HeifParser call AssembleBoxes when ipcoBox_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, AssembleBoxesTest006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: AssembleBoxesTest006 start";
    std::unique_ptr<uint8_t[]> mockData = std::make_unique<uint8_t[]>(NUM_1);
    auto stream = std::make_shared<HeifBufferInputStream>(mockData.get(), NUM_1, false);

    HeifParser heifParser(stream);
    heifParser.ftypBox_ = std::make_shared<HeifFtypBox>();
    heifParser.metaBox_ = std::make_shared<HeifMetaBox>();

    AddHdlrBox(heifParser);
    AddPtimBox(heifParser);
    AddIinfBox(heifParser);
    AddIprpBox(heifParser);

    auto maxSize = static_cast<uint64_t>(std::numeric_limits<int64_t>::max());
    HeifStreamReader reader(stream, 0, maxSize);

    auto ret = heifParser.AssembleBoxes(reader);
    ASSERT_EQ(ret, heif_error_no_ipco);
    GTEST_LOG_(INFO) << "HeifParserTest: AssembleBoxesTest006 end";
}

/**
 * @tc.name: AssembleBoxesTest007
 * @tc.desc: Verify that HeifParser call AssembleBoxes when ipmas is empty.
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, AssembleBoxesTest007, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: AssembleBoxesTest007 start";
    std::unique_ptr<uint8_t[]> mockData = std::make_unique<uint8_t[]>(NUM_1);
    auto stream = std::make_shared<HeifBufferInputStream>(mockData.get(), NUM_1, false);

    HeifParser heifParser(stream);
    heifParser.ftypBox_ = std::make_shared<HeifFtypBox>();
    heifParser.metaBox_ = std::make_shared<HeifMetaBox>();

    AddHdlrBox(heifParser);
    AddPtimBox(heifParser);
    AddIinfBox(heifParser);
    AddIpcoBox(heifParser);

    auto maxSize = static_cast<uint64_t>(std::numeric_limits<int64_t>::max());
    HeifStreamReader reader(stream, 0, maxSize);

    auto ret = heifParser.AssembleBoxes(reader);
    ASSERT_EQ(ret, heif_error_no_ipma);
    GTEST_LOG_(INFO) << "HeifParserTest: AssembleBoxesTest007 end";
}

/**
 * @tc.name: AssembleBoxesTest008
 * @tc.desc: Verify that HeifParser call AssembleBoxes when ilocBox_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, AssembleBoxesTest008, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: AssembleBoxesTest008 start";
    std::unique_ptr<uint8_t[]> mockData = std::make_unique<uint8_t[]>(NUM_1);
    auto stream = std::make_shared<HeifBufferInputStream>(mockData.get(), NUM_1, false);

    HeifParser heifParser(stream);
    heifParser.ftypBox_ = std::make_shared<HeifFtypBox>();
    heifParser.metaBox_ = std::make_shared<HeifMetaBox>();

    AddHdlrBox(heifParser);
    AddPtimBox(heifParser);
    AddIinfBox(heifParser);
    AddIpmaBox(heifParser);

    auto maxSize = static_cast<uint64_t>(std::numeric_limits<int64_t>::max());
    HeifStreamReader reader(stream, 0, maxSize);

    auto ret = heifParser.AssembleBoxes(reader);
    ASSERT_EQ(ret, heif_error_no_iloc);
    GTEST_LOG_(INFO) << "HeifParserTest: AssembleBoxesTest008 end";
}

/**
 * @tc.name: AssembleBoxesTest009
 * @tc.desc: Test AssembleBoxes when reader reaches end or encounters EOF
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, AssembleBoxesTest009, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: AssembleBoxesTest009 start";
    std::vector<uint8_t> heifData = {
        0x00, 0x00, 0x00, 0x18, 'f', 't', 'y', 'p',
        'h', 'e', 'i', 'c',
        0x00, 0x00, 0x00, 0x00,
        'h', 'e', 'i', 'c', 'm', 'i', 'f', '1',
    };
    auto stream = std::make_shared<HeifBufferInputStream>(heifData.data(), heifData.size(), false);
    HeifParser heifParser(stream);
    auto maxSize = static_cast<uint64_t>(std::numeric_limits<int64_t>::max());
    HeifStreamReader reader(stream, 0, maxSize);
    auto ret = heifParser.AssembleBoxes(reader);
    ASSERT_EQ(ret, heif_error_no_meta);
    ASSERT_NE(heifParser.ftypBox_, nullptr);
    GTEST_LOG_(INFO) << "HeifParserTest: AssembleBoxesTest009 end";
}

/**
 * @tc.name: GetGridLengthTest002
 * @tc.desc: Verify that HeifParser call GetGridLength when item data id is mock.
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, GetGridLengthTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: GetGridLengthTest002 start";
    HeifParser heifParser;
    heifParser.ilocBox_ = std::make_shared<HeifIlocBox>();
    heifParser.infeBoxes_[MOCK_ITEM_ID] = std::make_shared<HeifInfeBox>();

    size_t mockSize = 0;
    auto ret = heifParser.GetGridLength(MOCK_ITEM_ID, mockSize);
    ASSERT_EQ(ret, heif_error_item_data_not_found);
    GTEST_LOG_(INFO) << "HeifParserTest: GetGridLengthTest002 end";
}

/**
 * @tc.name: GetGridLengthTest003
 * @tc.desc: Test GetGridLength when item exists in both infeBoxes and iloc items
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, GetGridLengthTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: GetGridLengthTest003 start";
    HeifParser heifParser;
    heif_item_id testItemId = IT35_TRUE_ID;
    auto infeBox = std::make_shared<HeifInfeBox>(testItemId, "grid", false);
    heifParser.infeBoxes_[testItemId] = infeBox;
    heifParser.ilocBox_ = std::make_shared<HeifIlocBox>();
    std::vector<uint8_t> testData(NUM_100, 0x01);
    heif_error appendResult = heifParser.ilocBox_->AppendData(testItemId, testData, 0);
    ASSERT_EQ(appendResult, heif_error_ok);
    size_t length = 0;
    heif_error ret = heifParser.GetGridLength(testItemId, length);
    ASSERT_EQ(ret, heif_error_ok);
    GTEST_LOG_(INFO) << "HeifParserTest: GetGridLengthTest003 end";
}

/**
 * @tc.name: GetItemDataTest002
 * @tc.desc: Verify that HeifParser call GetItemData when hvcc id is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, GetItemDataTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: GetItemDataTest002 start";
    HeifParser heifParser;
    heifParser.ilocBox_ = std::make_shared<HeifIlocBox>();
    heifParser.ilocBox_->AppendData(MOCK_ITEM_ID, std::vector<uint8_t>());

    heifParser.infeBoxes_[MOCK_ITEM_ID] = std::make_shared<HeifInfeBox>(MOCK_ITEM_ID, "hvc1", false);

    auto ret = heifParser.GetItemData(MOCK_ITEM_ID, nullptr);
    ASSERT_EQ(ret, heif_error_no_hvcc);
    GTEST_LOG_(INFO) << "HeifParserTest: GetItemDataTest002 end";
}

/**
 * @tc.name: GetItemDataTest003
 * @tc.desc: Test GetItemData when infe_box is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, GetItemDataTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: GetItemDataTest003 start";
    HeifParser heifParser;
    heif_item_id testItemId = IT35_TRUE_ID;
    heifParser.infeBoxes_[testItemId] = nullptr;
    std::vector<uint8_t> outData;
    heif_error ret = heifParser.GetItemData(testItemId, &outData);
    ASSERT_EQ(ret, heif_error_item_not_found);
    GTEST_LOG_(INFO) << "HeifParserTest: GetItemDataTest003 end";
}

/**
 * @tc.name: AddItemTest001
 * @tc.desc: Verify that HeifParser call AddItem when iinfBox_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, AddItemTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: AddItemTest001 start";
    HeifParser heifParser;
    heifParser.iinfBox_.reset();
    auto ret = heifParser.AddItem("mock", false);
    ASSERT_EQ(ret, nullptr);
    GTEST_LOG_(INFO) << "HeifParserTest: AddItemTest001 end";
}

/**
 * @tc.name: ExtractIT35MetadataTest001
 * @tc.desc: Test ExtractIT35Metadata when GetItemType returns non-it35 type
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, ExtractIT35MetadataTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: ExtractIT35MetadataTest001 start";
    HeifParser heifParser;
    heif_item_id testItemId = IT35_TRUE_ID;
    auto infeBox = std::make_shared<HeifInfeBox>(testItemId, "mime", false);
    heifParser.infeBoxes_[testItemId] = infeBox;
    heifParser.primaryImage_ = std::make_shared<HeifImage>(2);
    heifParser.ExtractIT35Metadata(testItemId);
    std::string itemType = heifParser.GetItemType(testItemId);
    ASSERT_EQ(itemType, "mime");
    GTEST_LOG_(INFO) << "HeifParserTest: ExtractIT35MetadataTest001 end";
}

/**
 * @tc.name: ExtractISOMetadataTest001
 * @tc.desc: Test ExtractISOMetadata when GetItemType returns non-tmap type
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, ExtractISOMetadataTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: ExtractISOMetadataTest001 start";
    HeifParser heifParser;
    heif_item_id testItemId = IT35_TRUE_ID;
    auto infeBox = std::make_shared<HeifInfeBox>(testItemId, "hvc1", false);
    heifParser.infeBoxes_[testItemId] = infeBox;
    heifParser.primaryImage_ = std::make_shared<HeifImage>(2);
    heifParser.ExtractISOMetadata(testItemId);
    std::string itemType = heifParser.GetItemType(testItemId);
    ASSERT_EQ(itemType, "hvc1");
    GTEST_LOG_(INFO) << "HeifParserTest: ExtractISOMetadataTest001 end";
}

/**
 * @tc.name: ExtractFragmentMetadataTest001
 * @tc.desc: Test ExtractFragmentMetadata when GetProperty<HeifIspeBox> returns nullptr
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, ExtractFragmentMetadataTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: ExtractFragmentMetadataTest001 start";
    HeifParser heifParser;
    heif_item_id testItemId = IT35_TRUE_ID;
    heifParser.ipcoBox_ = nullptr;
    heifParser.ipmaBox_ = nullptr;
    heifParser.primaryImage_ = std::make_shared<HeifImage>(2);
    heifParser.ExtractFragmentMetadata(testItemId);
    ASSERT_NE(heifParser.primaryImage_, nullptr);
    GTEST_LOG_(INFO) << "HeifParserTest: ExtractFragmentMetadataTest001 end";
}

/**
 * @tc.name: ExtractFragmentMetadataTest002
 * @tc.desc: Test ExtractFragmentMetadata when GetProperty<HeifRlocBox> returns nullptr
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, ExtractFragmentMetadataTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: ExtractFragmentMetadataTest002 start";
    
    HeifParser heifParser;
    heif_item_id testItemId = IT35_TRUE_ID;
    heifParser.ipcoBox_ = nullptr;
    heifParser.ipmaBox_ = nullptr;
    heifParser.primaryImage_ = std::make_shared<HeifImage>(2);
    heifParser.ExtractFragmentMetadata(testItemId);
    ASSERT_NE(heifParser.primaryImage_, nullptr);
    GTEST_LOG_(INFO) << "HeifParserTest: ExtractFragmentMetadataTest002 end";
}

/**
 * @tc.name: SetMetadataTest001
 * @tc.desc: Verify that HeifParser call SetMetadata when content_type is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, SetMetadataTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: SetMetadataTest001 start";
    HeifParser heifParser;
    heifParser.iinfBox_ = std::make_shared<HeifIinfBox>();
    heifParser.metaBox_ = std::make_shared<HeifMetaBox>();
    std::shared_ptr<HeifImage> mockImage = std::make_shared<HeifImage>(MOCK_ITEM_ID);
    auto ret = heifParser.SetMetadata(mockImage, std::vector<uint8_t>(), "mock", "mock");
    ASSERT_EQ(ret, heif_error_ok);
    GTEST_LOG_(INFO) << "HeifParserTest: SetMetadataTest001 end";
}

/**
 * @tc.name: SetPrimaryImageTest002
 * @tc.desc: Test SetPrimaryImage when primaryImage_ is null to skip the if branch
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, SetPrimaryImageTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: SetPrimaryImageTest002 start";
    HeifParser heifParser;
    heifParser.pitmBox_ = std::make_shared<HeifPtimBox>();
    std::shared_ptr<HeifImage> mockImage = std::make_shared<HeifImage>(MOCK_ITEM_ID);
    ASSERT_EQ(heifParser.primaryImage_, nullptr);
    heifParser.SetPrimaryImage(mockImage);
    ASSERT_EQ(heifParser.primaryImage_, mockImage);
    GTEST_LOG_(INFO) << "HeifParserTest: SetPrimaryImageTest002 end";
}

/**
 * @tc.name: SetExifMetadataTest002
 * @tc.desc: Test SetExifMetadata when size > HEIF_MAX_EXIF_SIZE
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, SetExifMetadataTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: SetExifMetadataTest002 start";
    HeifParser heifParser;
    std::shared_ptr<HeifImage> mockImage = std::make_shared<HeifImage>(MOCK_ITEM_ID);
    const uint32_t largeSize = HEIF_MAX_EXIF_SIZE + 1;
    std::vector<uint8_t> largeData(largeSize, MOCK_FILL_BYTE);
    heif_error result = heifParser.SetExifMetadata(mockImage, largeData.data(), largeSize);
    ASSERT_EQ(result, heif_invalid_exif_data);
    GTEST_LOG_(INFO) << "HeifParserTest: SetExifMetadataTest002 end";
}

/**
 * @tc.name: UpdateExifMetadataTest002
 * @tc.desc: Test UpdateExifMetadata when size > HEIF_MAX_EXIF_SIZE
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, UpdateExifMetadataTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: UpdateExifMetadataTest002 start";
    HeifParser heifParser;
    std::shared_ptr<HeifImage> mockImage = std::make_shared<HeifImage>(MOCK_ITEM_ID);
    heif_item_id testItemId = IT35_TRUE_ID;
    const uint32_t largeSize = HEIF_MAX_EXIF_SIZE + 1;
    std::vector<uint8_t> largeData(largeSize, MOCK_FILL_BYTE);
    heif_error result = heifParser.UpdateExifMetadata(mockImage, largeData.data(), largeSize, testItemId);
    ASSERT_EQ(result, heif_invalid_exif_data);
    GTEST_LOG_(INFO) << "HeifParserTest: UpdateExifMetadataTest002 end";
}

/**
 * @tc.name: SetMetadataTest002
 * @tc.desc: Test SetMetadata when AddItem returns nullptr
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, SetMetadataTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: SetMetadataTest002 start";
    HeifParser heifParser;
    std::shared_ptr<HeifImage> mockImage = std::make_shared<HeifImage>(MOCK_ITEM_ID);
    std::vector<uint8_t> testData = {MOCK_DATA_1, MOCK_DATA_2};
    heifParser.metaBox_ = std::make_shared<HeifMetaBox>();
    heif_error result = heifParser.SetMetadata(mockImage, testData, "test", "test");
    ASSERT_EQ(result, heif_invalid_exif_data);
    GTEST_LOG_(INFO) << "HeifParserTest: SetMetadataTest002 end";
}

/**
 * @tc.name: SetTiffOffsetTest001
 * @tc.desc: Test SetTiffOffset when tiffOffset_ is already set
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserTest, SetTiffOffsetTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserTest: SetTiffOffsetTest001 start";
    HeifParser heifParser;
    heifParser.tiffOffset_ = MOCK_TIFF_OFFSET;
    heifParser.SetTiffOffset();
    ASSERT_NE(heifParser.tiffOffset_, 0);
    GTEST_LOG_(INFO) << "HeifParserTest: SetTiffOffsetTest001 end";
}
}
}