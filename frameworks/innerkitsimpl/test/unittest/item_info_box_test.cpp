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
#include "box/item_info_box.h"
#include "heif_box.h"

using namespace testing::ext;
namespace OHOS {
namespace ImagePlugin {

static constexpr uint8_t DATA_SIZE = 100;
static constexpr int64_t Expected_Tell_Pos = 22;
static constexpr uint32_t MAX_RECURSION_COUNT = 300;

class ItemInfoBoxTest : public testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

/**
 * @tc.name: ParseContentChildrenTest001
 * @tc.desc: Test ParseContentChildren, recursionCount reach max limit, expect heif_error_too_many_recursion
 * @tc.type: FUNC
 */
HWTEST_F(ItemInfoBoxTest, ParseContentChildrenTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ItemInfoBoxTest: ParseContentChildrenTest001 start";

    uint8_t data[DATA_SIZE] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    size_t dataSize = sizeof(data);
    bool needCopy = false;
    std::shared_ptr<HeifInputStream> inputStream =
        std::make_shared<HeifBufferInputStream>(data, dataSize, needCopy);
    int64_t start = 0;
    size_t readerLength = dataSize;
    HeifStreamReader reader(inputStream, start, readerLength);
    uint32_t recursionCount = MAX_RECURSION_COUNT;
    HeifIinfBox heifIinfBox;
    heif_error ret = heifIinfBox.ParseContentChildren(reader, recursionCount);
    EXPECT_EQ(ret, heif_error_too_many_recursion);
    GTEST_LOG_(INFO) << "ItemInfoBoxTest: ParseContentChildrenTest001 end";
}

/**
 * @tc.name: ParseContentChildrenTest002
 * @tc.desc: Test HeifIinfBox::ParseContentChildren, entryCount is 0, expect heif_error_ok
 * @tc.type: FUNC
 */
HWTEST_F(ItemInfoBoxTest, ParseContentChildrenTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ItemInfoBoxTest: ParseContentChildrenTest002 start";
    uint8_t data[] = {
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00
    };
    size_t dataSize = sizeof(data);
    bool needCopy = false;
    std::shared_ptr<HeifInputStream> inputStream =
        std::make_shared<HeifBufferInputStream>(data, dataSize, needCopy);
    int64_t start = 0;
    size_t readerLength = dataSize;
    HeifStreamReader reader(inputStream, start, readerLength);
    uint32_t recursionCount = MAX_RECURSION_COUNT - 1;
    HeifIinfBox heifIinfBox;
    heif_error ret = heifIinfBox.ParseContentChildren(reader, recursionCount);
    EXPECT_EQ(ret, heif_error_ok);
    EXPECT_FALSE(reader.HasError());
    GTEST_LOG_(INFO) << "ItemInfoBoxTest: ParseContentChildrenTest002 end";
}

/**
 * @tc.name: HeifInfeBoxParseContentTest001
 * @tc.desc: Test HeifInfeBox::ParseContent, itemType=ITEM_TYPE_URI, expect itemUriType_ correctly set
 * @tc.type: FUNC
 */
HWTEST_F(ItemInfoBoxTest, HeifInfeBoxParseContentTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ItemInfoBoxTest: HeifInfeBoxParseContentTest001 start";
    uint8_t data[] = {
        0x02, 0x00, 0x00, 0x01,
        0x00, 0x01,
        0x00, 0x02,
        0x75, 0x72, 0x69, 0x20,
        't', 'e', 's', 't', 'I', 't', 'e', 'm', '\0',
        't', 'e', 's', 't', '_', 'u', 'r', 'i', '\0'
    };
    size_t dataSize = sizeof(data);
    bool needCopy = false;
    std::shared_ptr<HeifInputStream> inputStream =
        std::make_shared<HeifBufferInputStream>(data, dataSize, needCopy);
    ASSERT_NE(inputStream, nullptr) << "Create stream failed";
    int64_t start = 0;
    size_t readerLength = dataSize;
    HeifStreamReader reader(inputStream, start, readerLength);
    HeifInfeBox heifInfeBox;
    heif_error ret = heifInfeBox.ParseContent(reader);
    std::string expectedItemUriType = "test_uri";
    EXPECT_EQ(ret, heif_error_ok);
    uint32_t actualItemType = fourcc_to_code(heifInfeBox.itemType_.c_str());
    EXPECT_EQ(actualItemType, ITEM_TYPE_URI);
    EXPECT_EQ(heifInfeBox.GetItemUriType(), expectedItemUriType);
    EXPECT_EQ(reader.GetStream()->Tell(), static_cast<int64_t>(dataSize));
    GTEST_LOG_(INFO) << "ItemInfoBoxTest: HeifInfeBoxParseContentTest001 end";
}

/**
 * @tc.name: HeifInfeBoxParseContentTest002
 * @tc.desc: Test HeifInfeBox::ParseContent, boxVersion>=TWO, cover isHidden_/itemId_/itemType_ logic (no extra Getter)
 * @tc.type: FUNC
 */
HWTEST_F(ItemInfoBoxTest, HeifInfeBoxParseContentTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ItemInfoBoxTest: HeifInfeBoxParseContentTest002 start";
    uint8_t data[] = {
        0x02, 0x00, 0x00, 0x01,
        0x12, 0x34,
        0x56, 0x78,
        0x4D, 0x49, 0x4D, 0x45,
        't', 'e', 's', 't', 'I', 't', 'e', 'm', '2', '\0'
    };
    size_t dataSize = sizeof(data);
    bool needCopy = false;
    std::shared_ptr<HeifInputStream> inputStream =
        std::make_shared<HeifBufferInputStream>(data, dataSize, needCopy);
    ASSERT_NE(inputStream, nullptr) << "Create stream failed";
    int64_t start = 0;
    size_t readerLength = dataSize;
    HeifStreamReader reader(inputStream, start, readerLength);
    HeifInfeBox heifInfeBox;
    heif_error ret = heifInfeBox.ParseContent(reader);
    EXPECT_EQ(ret, heif_error_ok);
    EXPECT_FALSE(reader.HasError());
    EXPECT_EQ(heifInfeBox.GetVersion(), HEIF_BOX_VERSION_TWO);
    int64_t expectedTellPos = Expected_Tell_Pos;
    int64_t actualTellPos = reader.GetStream()->Tell();
    EXPECT_EQ(actualTellPos, expectedTellPos);
    GTEST_LOG_(INFO) << "ItemInfoBoxTest: HeifInfeBoxParseContentTest002 end";
}

/**
 * @tc.name: WriteTest001
 * @tc.desc: Cover HeifInfeBox::Write itemType_=="uri " branch, verify write success and itemUriType_ is written
 * @tc.type: FUNC
 */
HWTEST_F(ItemInfoBoxTest, WriteTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ItemInfoBoxTest: WriteTest001 start";

    HeifInfeBox infeBox;
    infeBox.version_ = HEIF_BOX_VERSION_TWO;
    infeBox.itemType_ = "uri ";
    infeBox.itemId_ = 0x0001;
    infeBox.itemProtectionIndex_ = 0x0000;
    infeBox.itemName_ = "test_item";
    infeBox.itemUriType_ = "test_custom_uri_type";
    HeifStreamWriter writer;
    heif_error ret = infeBox.Write(writer);
    EXPECT_EQ(ret, heif_error_ok) << "HeifInfeBox::Write failed, error code: " << ret;
    const std::string expectedUriType = infeBox.itemUriType_;
    const uint8_t* expectedBytes = reinterpret_cast<const uint8_t*>(expectedUriType.c_str());
    const size_t expectedLen = expectedUriType.length() + 1;
    bool isUriTypeWritten = false;
    if (writer.data_.size() >= expectedLen) {
        for (size_t i = 0; i <= writer.data_.size() - expectedLen; ++i) {
            if (memcmp(&writer.data_[i], expectedBytes, expectedLen) == 0) {
                isUriTypeWritten = true;
                break;
            }
        }
    }
    EXPECT_TRUE(isUriTypeWritten);
    GTEST_LOG_(INFO) << "ItemInfoBoxTest: WriteTest001 end";
}
} // namespace ImagePlugin
} // namespace OHOS