/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#include "gtest/gtest.h"
#include "image_handle.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Media;
namespace OHOS {
namespace Multimedia {

class ImageHandleTest : public testing::Test {
public:
    ImageHandleTest() {}
    ~ImageHandleTest() {}
};

/**
 * @tc.name: StartHandle001
 * @tc.desc: test HandleOnCritical
 * @tc.type: FUNC
 */
HWTEST_F(ImageHandleTest, StartHandle001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageHandle: StartHandle001 start";
    DecodeOptions opts;
    ImageInfo info;
    info.size.width = 8;
    info.size.height = 4;
    ImageHandle::GetInstance().HandleOnCritical(opts, info);
    ASSERT_EQ(opts.desiredSize.width, 4);
    ASSERT_EQ(opts.desiredSize.height, 2);
    GTEST_LOG_(INFO) << "ImageHandle: StartHandle001 end";
}

/**
 * @tc.name: StartHandle002
 * @tc.desc: test HandleOnNormal
 * @tc.type: FUNC
 */
HWTEST_F(ImageHandleTest, StartHandle002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageHandle: StartHandle002 start";
    DecodeOptions opts;
    ImageInfo info;
    info.size.width = 8;
    info.size.height = 4;
    ImageHandle::GetInstance().HandleOnNormal(opts, info);
    ASSERT_EQ(opts.desiredSize.width, 6);
    ASSERT_EQ(opts.desiredSize.height, 3);
    GTEST_LOG_(INFO) << "ImageHandle: StartHandle002 end";
}

/**
 * @tc.name: StartHandle003
 * @tc.desc: test CheckOptsNeedOptimize
 * @tc.type: FUNC
 */
HWTEST_F(ImageHandleTest, StartHandle003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageHandle: StartHandle003 start";
    DecodeOptions opts;
    opts.desiredSize.width = 0;
    opts.desiredSize.height = 0;
    opts.preference = MemoryUsagePreference::DEFAULT;
    opts.resolutionQuality = ResolutionQuality::UNKNOWN;
    bool isValid = ImageHandle::GetInstance().CheckOptsNeedOptimize(opts);
    ASSERT_EQ(isValid, true);
    GTEST_LOG_(INFO) << "ImageHandle: StartHandle003 end";
}

/**
 * @tc.name: StartHandle004
 * @tc.desc: test CheckOptsNeedOptimize
 * @tc.type: FUNC
 */
HWTEST_F(ImageHandleTest, StartHandle004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageHandle: StartHandle004 start";
    DecodeOptions opts;
    opts.desiredSize.width = 100;
    opts.desiredSize.height = 100;
    opts.resolutionQuality = ResolutionQuality::UNKNOWN;
    bool isValid = ImageHandle::GetInstance().CheckOptsNeedOptimize(opts);
    ASSERT_EQ(isValid, false);
    GTEST_LOG_(INFO) << "ImageHandle: StartHandle004 end";
}

/**
 * @tc.name: StartHandle005
 * @tc.desc: test CheckOptsNeedOptimize
 * @tc.type: FUNC
 */
HWTEST_F(ImageHandleTest, StartHandle005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageHandle: StartHandle005 start";
    DecodeOptions opts;
    opts.desiredSize.width = 0;
    opts.desiredSize.height = 0;
    opts.resolutionQuality = ResolutionQuality::UNKNOWN;
    bool isValid = ImageHandle::GetInstance().CheckOptsNeedOptimize(opts);
    ASSERT_EQ(isValid, true);
    GTEST_LOG_(INFO) << "ImageHandle: StartHandle005 end";
}

/**
 * @tc.name: StartHandle006
 * @tc.desc: test CheckOptsNeedOptimize
 * @tc.type: FUNC
 */
HWTEST_F(ImageHandleTest, StartHandle006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageHandle: StartHandle006 start";
    DecodeOptions opts;
    opts.desiredSize.width = 0;
    opts.desiredSize.height = 0;
    opts.resolutionQuality = ResolutionQuality::LOW;
    bool isValid = ImageHandle::GetInstance().CheckOptsNeedOptimize(opts);
    ASSERT_EQ(isValid, false);
    GTEST_LOG_(INFO) << "ImageHandle: StartHandle006 end";
}

/**
 * @tc.name: StartHandle007
 * @tc.desc: test CheckOptsNeedOptimize
 * @tc.type: FUNC
 */
HWTEST_F(ImageHandleTest, StartHandle007, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageHandle: StartHandle007 start";
    DecodeOptions opts;
    opts.desiredSize.width = 100;
    opts.desiredSize.height = 0;
    opts.resolutionQuality = ResolutionQuality::UNKNOWN;
    bool isValid = ImageHandle::GetInstance().CheckOptsNeedOptimize(opts);
    ASSERT_EQ(isValid, false);
    GTEST_LOG_(INFO) << "ImageHandle: StartHandle007 end";
}

/**
 * @tc.name: StartHandle008
 * @tc.desc: test CheckOptsNeedOptimize
 * @tc.type: FUNC
 */
HWTEST_F(ImageHandleTest, StartHandle008, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageHandle: StartHandle008 start";
    DecodeOptions opts;
    opts.desiredSize.width = 0;
    opts.desiredSize.height = 100;
    opts.resolutionQuality = ResolutionQuality::UNKNOWN;
    bool isValid = ImageHandle::GetInstance().CheckOptsNeedOptimize(opts);
    ASSERT_EQ(isValid, false);
    GTEST_LOG_(INFO) << "ImageHandle: StartHandle008 end";
}

/**
 * @tc.name: StartHandle009
 * @tc.desc: test CheckImageNeedResize
 * @tc.type: FUNC
 */
HWTEST_F(ImageHandleTest, StartHandle009, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageHandle: StartHandle009 start";
    ImageInfo info;
    info.size.width = 2900;
    info.size.height = 2920;
    bool isValid = ImageHandle::GetInstance().CheckImageNeedResize(info);
    ASSERT_EQ(isValid, true);
    GTEST_LOG_(INFO) << "ImageHandle: StartHandle009 end";
}

/**
 * @tc.name: StartHandle0010
 * @tc.desc: test LowRamDeviceOptsOptimize
 * @tc.type: FUNC
 */
HWTEST_F(ImageHandleTest, StartHandle010, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageHandle: StartHandle010 start";
    DecodeOptions opts;
    ImageInfo info;
    ImageHandle::GetInstance().isLowSampleEnable_ = true;
    ImageHandle::GetInstance().blackBundleList_.insert("com.test.handle");
    ImageHandle::GetInstance().width_ = 800;
    ImageHandle::GetInstance().height_ = 800;
    ImageHandle::GetInstance().screenWidth_ = 1000;
    ImageHandle::GetInstance().screenHeight_ = 2600;
    opts.desiredSize = {0, 0};
    opts.resolutionQuality = ResolutionQuality::UNKNOWN;
    opts.desiredRegion = {0, 0, 0, 0};
    info.size = {2000, 5200};
    ImageHandle::GetInstance().LowRamDeviceOptsOptimize(opts, info);
    ASSERT_EQ(opts.desiredSize.width, 1000);
    GTEST_LOG_(INFO) << "ImageHandle: StartHandle010 end";
}

/**
 * @tc.name: StartHandle0011
 * @tc.desc: test LowRamDeviceOptsOptimize
 * @tc.type: FUNC
 */
HWTEST_F(ImageHandleTest, StartHandle011, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageHandle: StartHandle011 start";
    DecodeOptions opts;
    ImageInfo info;
    ImageHandle::GetInstance().isLowSampleEnable_ = true;
    ImageHandle::GetInstance().blackBundleList_.insert("com.test.handle");
    ImageHandle::GetInstance().width_ = 800;
    ImageHandle::GetInstance().height_ = 800;
    ImageHandle::GetInstance().screenWidth_ = 1000;
    ImageHandle::GetInstance().screenHeight_ = 2600;
    opts.desiredSize = {0, 0};
    opts.resolutionQuality = ResolutionQuality::UNKNOWN;
    opts.desiredRegion = {0, 0, 0, 0};
    info.size = {900, 900};
    ImageHandle::GetInstance().LowRamDeviceOptsOptimize(opts, info);
    ASSERT_EQ(opts.desiredSize.width, 675);
    GTEST_LOG_(INFO) << "ImageHandle: StartHandle011 end";
}

}
}