/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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
#include "image_source_util.h"
#include "log_tags.h"
#include "media_errors.h"

using namespace testing::ext;
using namespace OHOS::Media;
using namespace OHOS::ImageSourceUtil;

namespace OHOS {
namespace Multimedia {
namespace {
static const std::string SVG_FORMAT_TYPE = "image/svg+xml";
static const std::string INPUT_PATH = "/data/local/tmp/image/";
static const std::string OUTPUT_PATH = "/data/local/tmp/image/output_";
static const std::string OUTPUT_EXT = ".jpg";
static const std::string TEST_FILE_SVG = "test.svg";
static const std::string TEST_FILE_LARGE_SVG = "test_large.svg";
}

class ImageSourceSvgTest : public testing::Test {};

/**
 * @tc.name: SvgImageDecode
 * @tc.desc: Decode svg image from file source stream
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceSvgTest, SvgImageDecode, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceSvgTest: SvgImageDecode start";

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
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    /**
     * @tc.steps: step3. compress the pixel map to jpg file.
     * @tc.expected: step3. pack pixel map success.
     */
    const std::string outName = OUTPUT_PATH + testName + OUTPUT_EXT;
    auto packSize = PackImage(outName, std::move(pixelMap));
    ASSERT_NE(packSize, 0);

    GTEST_LOG_(INFO) << "ImageSourceSvgTest: SvgImageDecode end";
}

/**
 * @tc.name: SvgCreateImageSource
 * @tc.desc: Decode svg image from file source stream
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceSvgTest, SvgCreateImageSource, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceSvgTest: SvgCreateImageSource start";

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
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    /**
     * @tc.steps: step3. compress the pixel map to jpg file.
     * @tc.expected: step3. pack pixel map success.
     */
    const std::string outName = OUTPUT_PATH + testName + OUTPUT_EXT;
    auto packSize = PackImage(outName, std::move(pixelMap));
    ASSERT_NE(packSize, 0);

    GTEST_LOG_(INFO) << "ImageSourceSvgTest: SvgCreateImageSource end";
}

/**
 * @tc.name: SvgImageDecodeWithFillColorChange
 * @tc.desc: Decode svg image from file source stream
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceSvgTest, SvgImageDecodeWithFillColorChange, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceSvgTest: SvgImageDecode start";

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
     * @tc.steps: step2. decode image source to pixel map by default decode options which sets fillColor 0xff00ff
     * @tc.expected: step2. decode image source to pixel map success.
     */
    DecodeOptions decodeOpts;
    decodeOpts.SVGOpts.fillColor.isValidColor = true;
    decodeOpts.SVGOpts.fillColor.color = 0xff00ff;
    auto pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    /**
     * @tc.steps: step3. compress the pixel map to jpg file.
     * @tc.expected: step3. pack pixel map success and the color is purple.
     */
    const std::string outName = OUTPUT_PATH + testName + OUTPUT_EXT;
    auto packSize = PackImage(outName, std::move(pixelMap));
    ASSERT_NE(packSize, 0);

    GTEST_LOG_(INFO) << "ImageSourceSvgTest: SvgImageDecodeWithFillColorChange end";
}

/**
 * @tc.name: SvgImageDecodeWithStrokeColorChange
 * @tc.desc: Decode svg image from file source stream
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceSvgTest, SvgImageDecodeWithStrokeColorChange, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceSvgTest: SvgImageDecode start";

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
     * @tc.steps: step2. decode image source to pixel map by default decode options which sets strokeColor 0xff00ff
     * @tc.expected: step2. decode image source to pixel map success.
     */
    DecodeOptions decodeOpts;
    decodeOpts.SVGOpts.strokeColor.isValidColor = true;
    decodeOpts.SVGOpts.strokeColor.color = 0xff00ff;
    auto pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    /**
     * @tc.steps: step3. compress the pixel map to jpg file.
     * @tc.expected: step3. pack pixel map success and the color is purple.
     */
    const std::string outName = OUTPUT_PATH + testName + OUTPUT_EXT;
    auto packSize = PackImage(outName, std::move(pixelMap));
    ASSERT_NE(packSize, 0);

    GTEST_LOG_(INFO) << "ImageSourceSvgTest: SvgImageDecodeWithStrokeColorChange end";
}

/**
 * @tc.name: SvgImageDecodeWithResizePercentage
 * @tc.desc: Decode svg image from file source stream
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceSvgTest, SvgImageDecodeWithResizePercentage, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceSvgTest: SvgImageDecode start";

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
     * @tc.steps: step2. decode image source to pixel map by default decode options  which sets resizePercentage 200
     * @tc.expected: step2. decode image source to pixel map success.
     */
    DecodeOptions decodeOpts;
    decodeOpts.SVGOpts.SVGResize.isValidPercentage = true;
    decodeOpts.SVGOpts.SVGResize.resizePercentage = 200;
    auto pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    /**
     * @tc.steps: step3. compress the pixel map to jpg file.
     * @tc.expected: step3. pack pixel map success and the size is 200% of the former one.
     */
    const std::string outName = OUTPUT_PATH + testName + OUTPUT_EXT;
    auto packSize = PackImage(outName, std::move(pixelMap));
    ASSERT_NE(packSize, 0);

    GTEST_LOG_(INFO) << "ImageSourceSvgTest: SvgImageDecodeWithResizePercentage end";
}

/**
 * @tc.name: SvgGetEncodedFormat001
 * @tc.desc: Decode svg image from file source stream
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceSvgTest, SvgGetEncodedFormat001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceSvgTest: SvgGetEncodedFormat001 start";

    const std::string testName = TEST_FILE_SVG;

    /**
     * @tc.steps: step1. create image source by correct svg file path and svg format hit.
     * @tc.expected: step1. create image source success.
     */
    uint32_t errorCode = 0;
    SourceOptions opts;
    const std::string inName = INPUT_PATH + testName;
    auto imageSource = ImageSource::CreateImageSource(inName, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    /**
     * @tc.steps: step2. decode image source to pixel map by default decode options  which sets resizePercentage 200
     * @tc.expected: step2. decode image source to pixel map success.
     */
    DecodeOptions decodeOpts;
    decodeOpts.SVGOpts.SVGResize.isValidPercentage = true;
    decodeOpts.SVGOpts.SVGResize.resizePercentage = 200;
    auto pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    /**
     * @tc.steps: step3. get imageinfo encodedformat from imagesource.
     * @tc.expected: step3. get imageinfo encodedformat success.
     */
    ImageInfo imageinfo1;
    uint32_t ret1 = imageSource->GetImageInfo(imageinfo1);
    ASSERT_EQ(ret1, SUCCESS);
    EXPECT_EQ(imageinfo1.encodedFormat.empty(), false);
    GTEST_LOG_(INFO) << "ImageSourceSvgTest: SvgGetEncodedFormat001 imageinfo1: " << imageinfo1.encodedFormat;
    /**
     * @tc.steps: step4. get imageinfo encodedformat pixelmap.
     * @tc.expected: step4. get imageinfo encodedformat success.
     */
    ImageInfo imageinfo2;
    pixelMap->GetImageInfo(imageinfo2);
    EXPECT_EQ(imageinfo2.encodedFormat.empty(), false);
    GTEST_LOG_(INFO) << "ImageSourceSvgTest: SvgGetEncodedFormat001 imageinfo2: " << imageinfo2.encodedFormat;
    GTEST_LOG_(INFO) << "ImageSourceSvgTest: SvgGetEncodedFormat001 end";
}

/**
 * @tc.name: SvgGetEncodedFormat002
 * @tc.desc: Decode svg image from file source stream
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceSvgTest, SvgGetEncodedFormat002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceSvgTest: SvgGetEncodedFormat002 start";

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
     * @tc.steps: step2. decode image source to pixel map by default decode options  which sets resizePercentage 200
     * @tc.expected: step2. decode image source to pixel map success.
     */
    DecodeOptions decodeOpts;
    auto pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    /**
     * @tc.steps: step3. get imageinfo encodedformat from imagesource.
     * @tc.expected: step3. get imageinfo encodedformat success.
     */
    ImageInfo imageinfo1;
    uint32_t ret1 = imageSource->GetImageInfo(imageinfo1);
    ASSERT_EQ(ret1, SUCCESS);
    EXPECT_EQ(imageinfo1.encodedFormat.empty(), false);
    GTEST_LOG_(INFO) << "ImageSourceSvgTest: SvgGetEncodedFormat002 imageinfo1: " << imageinfo1.encodedFormat;
    /**
     * @tc.steps: step4. get imageinfo encodedformat pixelmap.
     * @tc.expected: step4. get imageinfo encodedformat success.
     */
    ImageInfo imageinfo2;
    pixelMap->GetImageInfo(imageinfo2);
    EXPECT_EQ(imageinfo2.encodedFormat.empty(), false);
    GTEST_LOG_(INFO) << "ImageSourceSvgTest: SvgGetEncodedFormat002 imageinfo2: " << imageinfo2.encodedFormat;
    GTEST_LOG_(INFO) << "ImageSourceSvgTest: SvgGetEncodedFormat002 end";
}
} // namespace Multimedia
} // namespace OHOS