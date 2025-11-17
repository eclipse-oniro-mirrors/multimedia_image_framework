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
#include "image_dfx.h"

extern "C++" {
namespace OHOS {
namespace Media {
std::string GetInvokeTypeStr(uint16_t invokeType);
}
}
}

using namespace testing::ext;
namespace OHOS {
namespace ImagePlugin {

class ImageDfxTest : public testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

/**
 * @tc.name: getInvokeTypeTest001
 * @tc.desc: Verify ImageEvent::getInvokeType returns correct string according to invokeType.
 * @tc.type: FUNC
 */
HWTEST_F(ImageDfxTest, getInvokeTypeTest001, TestSize.Level3) {
    GTEST_LOG_(INFO) << "ImageDfxTest: getInvokeTypeTest001 start";
    std::shared_ptr<Media::ImageEvent> imageEvent = std::make_shared<Media::ImageEvent>();
    imageEvent->options_.invokeType = Media::JS_INTERFACE;
    auto ret = imageEvent->getInvokeType();
    EXPECT_EQ(ret, "js_interface");

    imageEvent->options_.invokeType =  Media::C_INTERFACE;
    ret = imageEvent->getInvokeType();
    EXPECT_EQ(ret, "c_interface");
    GTEST_LOG_(INFO) << "ImageDfxTest: getInvokeTypeTest001 end";
}

/**
 * @tc.name: GetInvokeTypeStrTest001
 * @tc.desc: Verify that GetInvokeTypeStr returns correct string for all invoke types.
 * @tc.type: FUNC
 */
HWTEST_F(ImageDfxTest, GetInvokeTypeStrTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageDfxTest: GetInvokeTypeStrTest001 start";
    EXPECT_EQ(OHOS::Media::GetInvokeTypeStr(Media::JS_INTERFACE), "js_interface");

    EXPECT_EQ(OHOS::Media::GetInvokeTypeStr(Media::C_INTERFACE), "c_interface");
    GTEST_LOG_(INFO) << "ImageDfxTest: GetInvokeTypeStrTest001 end";
}
} // namespace ImagePlugin
} // namespace OHOS