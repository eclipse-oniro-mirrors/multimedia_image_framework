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
#include <memory>
#include "box/item_property_basic_box.h"

using namespace testing::ext;
namespace OHOS {
namespace ImagePlugin {

static constexpr uint8_t DATA_SIZE = 16;
static constexpr uint8_t HEADER_SIZE = 4;
static constexpr uint8_t CHANNEL_NUM = 3;
static constexpr size_t SIZE = 16;

class ItemPropertyBasicBoxTest : public testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

/**
 * @tc.name: ParseContentTest001
 * @tc.desc: Test HeifPixiBox::ParseContent with empty reader, expect heif_error_eof.
 * @tc.type: FUNC
 */
HWTEST_F(ItemPropertyBasicBoxTest, ParseContentTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ItemPropertyBasicBoxTest: ParseContentTest001 start";
    uint8_t data[DATA_SIZE] = {0};
    size_t size = SIZE;
    bool needCopy = false;
    std::shared_ptr<HeifInputStream> stream = std::make_shared<HeifBufferInputStream>(
        data, size, needCopy);
    int64_t start = 0;
    size_t length = 0;
    std::shared_ptr<HeifStreamReader> reader = std::make_shared<HeifStreamReader>(stream, start, length);
    std::shared_ptr<HeifPixiBox> heifPixiBox = std::make_shared<HeifPixiBox>();
    auto ret = heifPixiBox->ParseContent(*reader);
    EXPECT_EQ(ret, heif_error_eof);
    GTEST_LOG_(INFO) << "ItemPropertyBasicBoxTest: ParseContentTest001 end";
}

/**
 * @tc.name: ParseContentTest002
 * @tc.desc: Test HeifPixiBox::ParseContent with complete data, expect success & correct values.
 * @tc.type: FUNC
 */
HWTEST_F(ItemPropertyBasicBoxTest, ParseContentTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ItemPropertyBasicBoxTest: ParseContentTest002 start";
    uint8_t data[DATA_SIZE] = {0};
    data[HEADER_SIZE] = CHANNEL_NUM;
    for (uint8_t i = 0; i < CHANNEL_NUM; ++i) {
        data[HEADER_SIZE + 1 + i] = i + 1;
    }
    size_t size = HEADER_SIZE + 1 + CHANNEL_NUM;
    bool needCopy = false;
    std::shared_ptr<HeifInputStream> stream = std::make_shared<HeifBufferInputStream>(data, size, needCopy);
    int64_t start = 0;
    size_t length = size;
    std::shared_ptr<HeifStreamReader> reader = std::make_shared<HeifStreamReader>(stream, start, length);
    std::shared_ptr<HeifPixiBox> heifPixiBox = std::make_shared<HeifPixiBox>();
    auto ret = heifPixiBox->ParseContent(*reader);
    EXPECT_EQ(ret, heif_error_ok);
    EXPECT_EQ(heifPixiBox->GetChannelNum(), CHANNEL_NUM);
    for (uint8_t i = 0; i < CHANNEL_NUM; ++i) {
        EXPECT_EQ(heifPixiBox->GetBitNum(i), i + 1);
    }
    GTEST_LOG_(INFO) << "ItemPropertyBasicBoxTest: ParseContentTest002 end";
}
} // namespace ImagePlugin
} // namespace OHOS