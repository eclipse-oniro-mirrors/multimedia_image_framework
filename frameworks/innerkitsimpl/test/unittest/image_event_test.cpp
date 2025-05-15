/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
#include <string>
#include "image_dfx.h"

using namespace OHOS::Media;
using namespace testing::ext;
namespace OHOS {
namespace Multimedia {
static const std::string ERROR_MESSAGE = "ImageEventTest SetDecodeErrorMsg";
class ImageEventTest : public testing::Test {
    public:
        ImageEventTest() {}
        ~ImageEventTest() {}
};

/**
 * @tc.name: ImageEvent001
 * @tc.desc: SetDecodeErrorMsg
 * @tc.type: FUNC
 */
HWTEST_F(ImageEventTest, ImageEvent001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageEventTest: ImageEvent001 start";
    ImageEvent imageEvent;
    imageEvent.SetDecodeErrorMsg(ERROR_MESSAGE);
    GTEST_LOG_(INFO) << "ImageEventTest: ImageEvent001 end";
}

/**
 * @tc.name: ImageEvent002
 * @tc.desc: SetIncrementalDecode
 * @tc.type: FUNC
 */
HWTEST_F(ImageEventTest, ImageEvent002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageEventTest: ImageEvent002 start";
    ImageEvent imageEvent;
    imageEvent.SetIncrementalDecode();
    GTEST_LOG_(INFO) << "ImageEventTest: ImageEvent002 end";
}

/**
 * @tc.name: ImageEvent003
 * @tc.desc: ReportDecodeInfo
 * @tc.type: FUNC
 */
HWTEST_F(ImageEventTest, ImageEvent003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageEventTest: ImageEvent003 start";
    ImageEvent imageEvent;
    imageEvent.ReportDecodeInfo();
    GTEST_LOG_(INFO) << "ImageEventTest: ImageEvent003 end";
}

/**
 * @tc.name: ImageEvent004
 * @tc.desc: ReportDecodeFault
 * @tc.type: FUNC
 */
HWTEST_F(ImageEventTest, ImageEvent004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageEventTest: ImageEvent004 start";
    ImageEvent imageEvent;
    imageEvent.ReportDecodeFault();
    GTEST_LOG_(INFO) << "ImageEventTest: ImageEvent004 end";
}
} // namespace Multimedia
} // namespace OHOS