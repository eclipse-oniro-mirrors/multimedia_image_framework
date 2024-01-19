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
#include "image_log.h"
#include "image_source_util.h"
#include "media_errors.h"
#include "image_source.h"

using namespace testing::ext;
using namespace OHOS::Media;
using namespace OHOS::HiviewDFX;
using namespace OHOS::ImageSourceUtil;
namespace OHOS {
namespace Media {
namespace {
static constexpr HiLogLabel LABEL_TEST = { LOG_CORE, LOG_TAG_DOMAIN_ID_IMAGE, "ImageSourceGifExTest" };
static const std::string INPUT_PATH = "/data/local/tmp/image/";
static const std::string OUTPUT_PATH = "/data/local/tmp/image/output_";
static const std::string OUTPUT_EXT = ".jpg";
static const std::string TEST_FILE_SINGLE_FRAME_GIF = "test.gif";
static const size_t TEST_FILE_SINGLE_FRAME_GIF_FRAME_COUNT = 1;
static const std::string TEST_FILE_MULTI_FRAME_GIF = "moving_test.gif";
static const size_t TEST_FILE_MULTI_FRAME_GIF_FRAME_COUNT = 3;
static const std::string TEST_FILE_JPG = "test.jpg";
static const size_t TEST_FILE_JPG_FRAME_COUNT = 1;
}

class ImageSourceGifExTest : public testing::Test {
public:
    ImageSourceGifExTest() {}
    ~ImageSourceGifExTest() {}
};

/**
 * @tc.name: CreatePixelMapList001
 * @tc.desc: test CreatePixelMapList
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceGifExTest, CreatePixelMapList001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceGifExTest: CreatePixelMapList001 start";

    const std::string testName = TEST_FILE_SINGLE_FRAME_GIF;

    uint32_t errorCode = 0;
    const SourceOptions opts;
    const std::string inputName = INPUT_PATH + testName;
    auto imageSource = ImageSource::CreateImageSource(inputName, opts, errorCode);

    const DecodeOptions decodeOpts;
    auto pixelMaps = imageSource->CreatePixelMapList(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMaps, nullptr);
    ASSERT_EQ(pixelMaps->size(), TEST_FILE_SINGLE_FRAME_GIF_FRAME_COUNT);

    int32_t index = 0;
    for (auto &pixelMap : *pixelMaps) {
        ASSERT_NE(pixelMap, nullptr);
        const std::string outputName = OUTPUT_PATH + testName + "." + std::to_string(index) + OUTPUT_EXT;
        int64_t packSize = PackImage(outputName, std::move(pixelMap));
        ASSERT_NE(packSize, 0);
        index++;
    }

    GTEST_LOG_(INFO) << "ImageSourceGifExTest: CreatePixelMapList001 end";
}

/**
 * @tc.name: CreatePixelMapList002
 * @tc.desc: test CreatePixelMapList
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceGifExTest, CreatePixelMapList002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceGifExTest: CreatePixelMapList002 start";

    const std::string testName = TEST_FILE_MULTI_FRAME_GIF;

    uint32_t errorCode = 0;
    const SourceOptions opts;
    const std::string inputName = INPUT_PATH + testName;
    auto imageSource = ImageSource::CreateImageSource(inputName, opts, errorCode);

    const DecodeOptions decodeOpts;
    auto pixelMaps = imageSource->CreatePixelMapList(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMaps, nullptr);
    ASSERT_EQ(pixelMaps->size(), TEST_FILE_MULTI_FRAME_GIF_FRAME_COUNT);

    int32_t index = 0;
    for (auto &pixelMap : *pixelMaps) {
        ASSERT_NE(pixelMap, nullptr);
        const std::string outputName = OUTPUT_PATH + testName + "." + std::to_string(index) + OUTPUT_EXT;
        int64_t packSize = PackImage(outputName, std::move(pixelMap));
        ASSERT_NE(packSize, 0);
        index++;
    }

    GTEST_LOG_(INFO) << "ImageSourceGifExTest: CreatePixelMapList002 end";
}

/**
 * @tc.name: CreatePixelMapList003
 * @tc.desc: test CreatePixelMapList
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceGifExTest, CreatePixelMapList003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceGifExTest: CreatePixelMapList003 start";

    const std::string testName = TEST_FILE_JPG;

    uint32_t errorCode = 0;
    const SourceOptions opts;
    const std::string inputName = INPUT_PATH + testName;
    auto imageSource = ImageSource::CreateImageSource(inputName, opts, errorCode);

    const DecodeOptions decodeOpts;
    auto pixelMaps = imageSource->CreatePixelMapList(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMaps, nullptr);
    ASSERT_EQ(pixelMaps->size(), TEST_FILE_JPG_FRAME_COUNT);

    int32_t index = 0;
    for (auto &pixelMap : *pixelMaps) {
        ASSERT_NE(pixelMap, nullptr);
        const std::string outputName = OUTPUT_PATH + testName + "." + std::to_string(index) + OUTPUT_EXT;
        int64_t packSize = PackImage(outputName, std::move(pixelMap));
        ASSERT_NE(packSize, 0);
        index++;
    }

    GTEST_LOG_(INFO) << "ImageSourceGifExTest: CreatePixelMapList003 end";
}

/**
 * @tc.name: GetDelayTime001
 * @tc.desc: test GetDelayTime
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceGifExTest, GetDelayTime001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceGifExTest: GetDelayTime001 start";

    const std::string testName = TEST_FILE_SINGLE_FRAME_GIF;

    uint32_t errorCode = 0;
    const SourceOptions opts;
    const std::string inputName = INPUT_PATH + testName;
    auto imageSource = ImageSource::CreateImageSource(inputName, opts, errorCode);

    auto delayTimes = imageSource->GetDelayTime(errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(delayTimes, nullptr);
    ASSERT_EQ(delayTimes->size(), TEST_FILE_SINGLE_FRAME_GIF_FRAME_COUNT);

    for (auto delayTime : *delayTimes) {
        HiLog::Debug(LABEL_TEST, "delay time is %{public}u.", delayTime);
    }

    GTEST_LOG_(INFO) << "ImageSourceGifExTest: GetDelayTime001 end";
}

/**
 * @tc.name: GetDelayTime002
 * @tc.desc: test GetDelayTime
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceGifExTest, GetDelayTime002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceGifExTest: GetDelayTime002 start";

    const std::string testName = TEST_FILE_MULTI_FRAME_GIF;

    uint32_t errorCode = 0;
    const SourceOptions opts;
    const std::string inputName = INPUT_PATH + testName;
    auto imageSource = ImageSource::CreateImageSource(inputName, opts, errorCode);

    auto delayTimes = imageSource->GetDelayTime(errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(delayTimes, nullptr);
    ASSERT_EQ(delayTimes->size(), TEST_FILE_MULTI_FRAME_GIF_FRAME_COUNT);

    for (auto delayTime : *delayTimes) {
        HiLog::Debug(LABEL_TEST, "delay time is %{public}u.", delayTime);
    }

    GTEST_LOG_(INFO) << "ImageSourceGifExTest: GetDelayTime002 end";
}

/**
 * @tc.name: GetDelayTime003
 * @tc.desc: test GetDelayTime
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceGifExTest, GetDelayTime003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceGifExTest: GetDelayTime003 start";

    const std::string testName = TEST_FILE_JPG;

    uint32_t errorCode = 0;
    const SourceOptions opts;
    const std::string inputName = INPUT_PATH + testName;
    auto imageSource = ImageSource::CreateImageSource(inputName, opts, errorCode);

    auto delayTimes = imageSource->GetDelayTime(errorCode);
    ASSERT_NE(errorCode, SUCCESS);
    ASSERT_EQ(delayTimes, nullptr);

    GTEST_LOG_(INFO) << "ImageSourceGifExTest: GetDelayTime003 end";
}

/**
 * @tc.name: GetFrameCount001
 * @tc.desc: test GetFrameCount
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceGifExTest, GetFrameCount001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceGifExTest: GetFrameCount001 start";

    const std::string testName = TEST_FILE_SINGLE_FRAME_GIF;

    uint32_t errorCode = 0;
    const SourceOptions opts;
    const std::string inputName = INPUT_PATH + testName;
    auto imageSource = ImageSource::CreateImageSource(inputName, opts, errorCode);

    auto frameCount = imageSource->GetFrameCount(errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_EQ(frameCount, TEST_FILE_SINGLE_FRAME_GIF_FRAME_COUNT);

    GTEST_LOG_(INFO) << "ImageSourceGifExTest: GetFrameCount001 end";
}

/**
 * @tc.name: GetFrameCount002
 * @tc.desc: test GetFrameCount
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceGifExTest, GetFrameCount002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceGifExTest: GetFrameCount002 start";

    const std::string testName = TEST_FILE_MULTI_FRAME_GIF;

    uint32_t errorCode = 0;
    const SourceOptions opts;
    const std::string inputName = INPUT_PATH + testName;
    auto imageSource = ImageSource::CreateImageSource(inputName, opts, errorCode);

    auto frameCount = imageSource->GetFrameCount(errorCode);
    ASSERT_EQ(frameCount, TEST_FILE_MULTI_FRAME_GIF_FRAME_COUNT);

    GTEST_LOG_(INFO) << "ImageSourceGifExTest: GetFrameCount002 end";
}

/**
 * @tc.name: GetFrameCount003
 * @tc.desc: test GetFrameCount
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceGifExTest, GetFrameCount003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceGifExTest: GetFrameCount003 start";

    const std::string testName = TEST_FILE_JPG;

    uint32_t errorCode = 0;
    const SourceOptions opts;
    const std::string inputName = INPUT_PATH + testName;
    auto imageSource = ImageSource::CreateImageSource(inputName, opts, errorCode);

    auto frameCount = imageSource->GetFrameCount(errorCode);
    ASSERT_EQ(frameCount, TEST_FILE_JPG_FRAME_COUNT);

    GTEST_LOG_(INFO) << "ImageSourceGifExTest: GetFrameCount003 end";
}
} // namespace Multimedia
} // namespace OHOS