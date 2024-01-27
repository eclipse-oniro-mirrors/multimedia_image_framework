/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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
#include <fstream>
#include <fcntl.h>
#ifdef IMAGE_COLORSPACE_FLAG
#include "color_space.h"
#endif
#include "directory_ex.h"
#include "image_log.h"
#include "image_packer.h"
#include "image_source.h"
#include "image_type.h"
#include "image_utils.h"
#include "media_errors.h"
#include "pixel_map.h"
#include "image_source_util.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "ImageColorSpaceTest"

using namespace testing::ext;
using namespace OHOS::Media;
using namespace OHOS::ImageSourceUtil;

namespace OHOS {
namespace Multimedia {
static const std::string IMAGE_INPUT_JPEG_INCLUDE_ICC_PATH = "/data/local/tmp/image/jpeg_include_icc_profile.jpg";
static const std::string IMAGE_OUTPUT_JPEG_INCLUDE_ICC_PATH = "/data/test/test_jpeg_include_icc_profile.jpg";
static const std::string IMAGE_INPUT_JPEG_NOT_INCLUDE_ICC_PATH = "/data/local/tmp/image/test.jpg";
static const std::string IMAGE_OUTPUT_JPEG_NOT_INCLUDE_ICC_PATH = "/data/test/test_jpeg_no_include_icc_profile.jpg";

class ImageColorSpaceTest : public testing::Test {
public:
    ImageColorSpaceTest() {};
    ~ImageColorSpaceTest() {};
};

/**
 * @tc.name: JpegColorSpaceDecode001
 * @tc.desc: Decode jpeg icc image from file source stream
 * @tc.type: FUNC
 */
HWTEST_F(ImageColorSpaceTest, JpegColorSpaceDecode001, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg file path and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_INCLUDE_ICC_PATH, opts, errorCode);
    IMAGE_LOGD("create image source error code=%{public}u.", errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    /**
     * @tc.steps: step2. decode image source to pixel map by default decode options.
     * @tc.expected: step2. decode image source to pixel map success.
     * @tc.expected: step2. parsing colorspace success.
     */
    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    IMAGE_LOGD("create pixel map error code=%{public}u.", errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
#ifdef IMAGE_COLORSPACE_FLAG
    OHOS::ColorManager::ColorSpace grColorSpace = pixelMap->InnerGetGrColorSpace();
    EXPECT_NE(grColorSpace.ToSkColorSpace(), nullptr);
    EXPECT_NE(grColorSpace.GetWhitePoint().size(), 0UL);
    EXPECT_NE(grColorSpace.GetXYZToRGB().size(), 0UL);
    EXPECT_NE(grColorSpace.GetRGBToXYZ().size(), 0UL);
#endif
}

/**
 * @tc.name: JpegColorSpaceEncode001
 * @tc.desc: Encode jpeg icc image to file source stream
 * @tc.type: FUNC
 */
HWTEST_F(ImageColorSpaceTest, JpegColorSpaceEncode001, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg file path and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_INCLUDE_ICC_PATH, opts, errorCode);
    IMAGE_LOGD("create image source error code==%{public}u.", errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    /**
     * @tc.steps: step2. decode image source to pixel map by default decode options.
     * @tc.expected: step2. decode image source to first pixel map success.
     * @tc.expected: step2. parsing colorspace success.
     */
    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMapOne = imageSource->CreatePixelMap(decodeOpts, errorCode);
    IMAGE_LOGD("create pixel map error code=%{public}u.", errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMapOne.get(), nullptr);
#ifdef IMAGE_COLORSPACE_FLAG
    OHOS::ColorManager::ColorSpace grColorSpaceOne = pixelMapOne->InnerGetGrColorSpace();
    EXPECT_NE(grColorSpaceOne.ToSkColorSpace(), nullptr);
#endif

    /**
     * @tc.steps: step3. encode image source from pixel map.
     * @tc.expected: step3. encode image source from first pixel map success.
     * @tc.expected: step3. packing colorspace success.
     */
    ImagePacker imagePacker;
    int64_t packSize = OHOS::ImageSourceUtil::PackImage(IMAGE_OUTPUT_JPEG_INCLUDE_ICC_PATH, std::move(pixelMapOne));
    ASSERT_NE(packSize, 0);

    /**
     * @tc.steps: step4. create image source by correct jpeg file path and jpeg format hit.
     * @tc.expected: step4. create second image source success.
     */
    imageSource = ImageSource::CreateImageSource(IMAGE_OUTPUT_JPEG_INCLUDE_ICC_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    /**
     * @tc.steps: step5. decode image source to second pixel map by default decode options from packaged image.
     * @tc.expected: step5. decode image source to second pixel map success.
     * @tc.expected: step5. acquire second colorspace success.
     */
    std::unique_ptr<PixelMap> pixelMapTwo = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMapTwo.get(), nullptr);
#ifdef IMAGE_COLORSPACE_FLAG
    OHOS::ColorManager::ColorSpace grColorSpaceTwo = pixelMapTwo->InnerGetGrColorSpace();
    EXPECT_NE(grColorSpaceTwo.ToSkColorSpace(), nullptr);
    EXPECT_EQ(grColorSpaceOne.GetWhitePoint(), grColorSpaceTwo.GetWhitePoint());
    EXPECT_EQ(grColorSpaceOne.GetXYZToRGB(), grColorSpaceTwo.GetXYZToRGB());
    EXPECT_EQ(grColorSpaceOne.GetRGBToXYZ(), grColorSpaceTwo.GetRGBToXYZ());
#endif
}

/**
 * @tc.name: JpegColorSpaceDecode002
 * @tc.desc: Decode jpeg image, which don't contain ICC from file source stream
 * @tc.type: FUNC
 */
HWTEST_F(ImageColorSpaceTest, JpegColorSpaceDecode002, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg file path and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_NOT_INCLUDE_ICC_PATH, opts, errorCode);
    IMAGE_LOGD("create image source error code=%{public}u.", errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    /**
     * @tc.steps: step2. decode image source to pixel map by default decode options.
     * @tc.expected: step2. decode image source to pixel map success.
     * @tc.expected: step2. parsing colorspace failed.
     */
    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    IMAGE_LOGD("create pixel map error code=%{public}u.", errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
#ifdef IMAGE_COLORSPACE_FLAG
    OHOS::ColorManager::ColorSpace grColorSpace = pixelMap->InnerGetGrColorSpace();
    EXPECT_EQ(grColorSpace.ToSkColorSpace(), nullptr);
#endif
}

/**
 * @tc.name: JpegColorSpaceEncode002
 * @tc.desc: Encode jpeg image, which don't contain ICC to file source stream.
 * @tc.type: FUNC
 */
HWTEST_F(ImageColorSpaceTest, JpegColorSpaceEncode002, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg file path and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_NOT_INCLUDE_ICC_PATH, opts, errorCode);
    IMAGE_LOGD("create image source error code==%{public}u.", errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    /**
     * @tc.steps: step2. decode image source to pixel map by default decode options.
     * @tc.expected: step2. decode image source to first pixel map success.
     * @tc.expected: step2. parsing colorspace failed.
     */
    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMapOne = imageSource->CreatePixelMap(decodeOpts, errorCode);
    IMAGE_LOGD("create pixel map error code=%{public}u.", errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMapOne.get(), nullptr);
#ifdef IMAGE_COLORSPACE_FLAG
    OHOS::ColorManager::ColorSpace grColorSpaceOne = pixelMapOne->InnerGetGrColorSpace();
    EXPECT_EQ(grColorSpaceOne.ToSkColorSpace(), nullptr);
#endif

    /**
     * @tc.steps: step3. encode image source from pixel map.
     * @tc.expected: step3. encode image source from first pixel map success.
     * @tc.expected: step3. packing colorspace success.
     */
    ImagePacker imagePacker;
    int64_t packSize = OHOS::ImageSourceUtil::PackImage(IMAGE_OUTPUT_JPEG_NOT_INCLUDE_ICC_PATH, std::move(pixelMapOne));
    ASSERT_NE(packSize, 0);

    /**
     * @tc.steps: step4. create image source by correct jpeg file path and jpeg format hit.
     * @tc.expected: step4. create second image source success.
     */
    imageSource = ImageSource::CreateImageSource(IMAGE_OUTPUT_JPEG_NOT_INCLUDE_ICC_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    /**
     * @tc.steps: step5. decode image source to second pixel map by default decode options from packaged image.
     * @tc.expected: step5. decode image source to second pixel map success.
     * @tc.expected: step5. parsing second colorspace failed.
     */
    std::unique_ptr<PixelMap> pixelMapTwo = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMapTwo.get(), nullptr);
#ifdef IMAGE_COLORSPACE_FLAG
    OHOS::ColorManager::ColorSpace grColorSpaceTwo = pixelMapTwo->InnerGetGrColorSpace();
    EXPECT_EQ(grColorSpaceTwo.ToSkColorSpace(), nullptr);
#endif
}
} // namespace Multimedia
} // namespace OHOS