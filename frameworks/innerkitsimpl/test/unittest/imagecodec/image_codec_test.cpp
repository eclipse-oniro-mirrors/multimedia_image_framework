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
#define protected public
#include <gtest/gtest.h>
#include "image_codec.h"

using namespace testing::ext;
using namespace OHOS::ImagePlugin;
namespace OHOS {
namespace Multimedia {

#define MSGWHAT_UNKNOW 30
class ImageCodecTest : public testing::Test {
public:
    ImageCodecTest() {}
    ~ImageCodecTest() {}
};

/**
 * @tc.name: GetInputFormat001
 * @tc.desc: Verify that GetInputFormat returns IC_ERR_UNKNOWN when the input format is not supported.
 * @tc.type: FUNC
 */
HWTEST_F(ImageCodecTest, GetInputFormatTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageCodecTest: GetInputFormatTest001 start";
    std::shared_ptr<ImageCodec> imageCodec = ImageCodec::Create();
    ASSERT_NE(imageCodec, nullptr);
    Format format;
    int32_t ret = imageCodec->GetInputFormat(format);

    EXPECT_EQ(ret, IC_ERR_UNKNOWN);
    GTEST_LOG_(INFO) << "ImageCodecTest: GetInputFormatTest001 end";
}

/**
 * @tc.name: GetOutputFormatTest001
 * @tc.desc: Verify that GetOutputFormat returns IC_ERR_UNKNOWN when the output format is not supported.
 * @tc.type: FUNC
 */
HWTEST_F(ImageCodecTest, GetOutputFormatTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageCodecTest: GetOutputFormatTest001 start";
    std::shared_ptr<ImageCodec> imageCodec = ImageCodec::Create();
    ASSERT_NE(imageCodec, nullptr);
    imageCodec->ReplyErrorCode(0, 0);
    Format format;
    int32_t ret = imageCodec->GetOutputFormat(format);

    EXPECT_EQ(ret, IC_ERR_UNKNOWN);
    GTEST_LOG_(INFO) << "ImageCodecTest: GetOutputFormatTest001 end";
}

/**
 * @tc.name: ToStringTest001
 * @tc.desc: Verify that ToString correctly converts BufferOwner enum values
 *           to their corresponding string representations.
 * @tc.type: FUNC
 */
HWTEST_F(ImageCodecTest, ToStringTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageCodecTest: ToStringTest001 start";
    std::shared_ptr<ImageCodec> imageCodec = ImageCodec::Create();
    ASSERT_NE(imageCodec, nullptr);
    const char* ret = imageCodec->ToString(ImageCodec::BufferOwner::OWNED_BY_US);
    EXPECT_EQ(strcmp(ret, "us"), 0);
    ret = imageCodec->ToString(ImageCodec::BufferOwner::OWNED_BY_USER);
    EXPECT_EQ(strcmp(ret, "user"), 0);
    ret = imageCodec->ToString(ImageCodec::BufferOwner::OWNED_BY_OMX);
    EXPECT_EQ(strcmp(ret, "omx"), 0);
    ret = imageCodec->ToString(ImageCodec::BufferOwner::OWNER_CNT);
    EXPECT_EQ(strcmp(ret, ""), 0);
    GTEST_LOG_(INFO) << "ImageCodecTest: ToStringTest001 end";
}

/**
 * @tc.name: ToStringTest002
 * @tc.desc: Verify that ToString correctly converts MsgWhat enum values to their corresponding string representations,
 *           including handling of unknown values.
 * @tc.type: FUNC
 */
HWTEST_F(ImageCodecTest, ToStringTest002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageCodecTest: ToStringTest002 start";
    std::shared_ptr<ImageCodec> imageCodec = ImageCodec::Create();
    ASSERT_NE(imageCodec, nullptr);
    const char* ret = imageCodec->ToString(ImageCodec::MsgWhat::INIT);
    EXPECT_EQ(strcmp(ret, "INIT"), 0);
    ret = imageCodec->ToString(static_cast<ImageCodec::MsgWhat>(MSGWHAT_UNKNOW));
    EXPECT_EQ(strcmp(ret, "UNKNOWN"), 0);
    GTEST_LOG_(INFO) << "ImageCodecTest: ToStringTest002 end";
}

} // namespace Media
} // namespace OHOS