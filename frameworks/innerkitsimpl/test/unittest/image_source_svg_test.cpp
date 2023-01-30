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
#include "hilog/log.h"
#include "image_source_util.h"
#include "log_tags.h"
#include "media_errors.h"

using namespace testing::ext;
using namespace OHOS::Media;
using namespace OHOS::HiviewDFX;
using namespace OHOS::ImageSourceUtil;

namespace OHOS {
namespace Multimedia {
namespace {
static constexpr HiLogLabel LABEL_TEST = { LOG_CORE, LOG_TAG_DOMAIN_ID_IMAGE, "ImageSourceSvgTest" };
static const std::string SVG_FORMAT_TYPE = "image/svg+xml";
static const std::string INPUT_PATH = "/data/local/tmp/image/";
static const std::string OUTPUT_PATH = "/data/local/tmp/image/output_";
static const std::string OUTPUT_EXT = ".jpg";
static const std::string TEST_FILE_SVG = "test.svg";
static const std::string TEST_FILE_LARGE_SVG = "test_large.svg";
}

class ImageSourceSvgTest : public testing::Test {
public:
    ImageSourceSvgTest() {}
    ~ImageSourceSvgTest() {}
};

/**
 * @tc.name: SvgImageDecode001
 * @tc.desc: Decode svg image from file source stream
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceSvgTest, SvgImageDecode001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceSvgTest: SvgImageDecode001 start";

    const std::string testName = TEST_FILE_SVG;

    /**
     * @tc.steps: step1. create image source by correct svg file path and svg format hit.
     * @tc.expected: step1. create image source success.
     */
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = SVG_FORMAT_TYPE;
    const std::string inName = INPUT_PATH + testName;
    auto imageSource = ImageSource::CreateImageSource(inName, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    /**
     * @tc.steps: step2. decode image source to pixel map by default decode options
     * @tc.expected: step2. decode image source to pixel map success.
     */
    DecodeOptions decodeOpts;
    auto pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    HiLog::Debug(LABEL_TEST, "create pixel map error code=%{public}u.", errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    /**
     * @tc.steps: step3. compress the pixel map to jpg file.
     * @tc.expected: step3. pack pixel map success.
     */
    const std::string outName = OUTPUT_PATH + testName + OUTPUT_EXT;
    auto packSize = PackImage(outName, std::move(pixelMap));
    ASSERT_NE(packSize, 0);

    GTEST_LOG_(INFO) << "ImageSourceSvgTest: SvgImageDecode001 end";
}

/**
 * @tc.name: SvgImageDecode002
 * @tc.desc: Decode svg image from file source stream
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceSvgTest, SvgImageDecode002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceSvgTest: SvgImageDecode002 start";

    const std::string testName = TEST_FILE_LARGE_SVG;

    /**
     * @tc.steps: step1. create image source by correct svg file path and svg format hit.
     * @tc.expected: step1. create image source success.
     */
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = SVG_FORMAT_TYPE;
    const std::string inName = INPUT_PATH + testName;
    auto imageSource = ImageSource::CreateImageSource(inName, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    /**
     * @tc.steps: step2. decode image source to pixel map by default decode options
     * @tc.expected: step2. decode image source to pixel map success.
     */
    DecodeOptions decodeOpts;
    auto pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    HiLog::Debug(LABEL_TEST, "create pixel map error code=%{public}u.", errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    /**
     * @tc.steps: step3. compress the pixel map to jpg file.
     * @tc.expected: step3. pack pixel map success.
     */
    const std::string outName = OUTPUT_PATH + testName + OUTPUT_EXT;
    auto packSize = PackImage(outName, std::move(pixelMap));
    ASSERT_NE(packSize, 0);

    GTEST_LOG_(INFO) << "ImageSourceSvgTest: SvgImageDecode002 end";
}
} // namespace Multimedia
} // namespace OHOS