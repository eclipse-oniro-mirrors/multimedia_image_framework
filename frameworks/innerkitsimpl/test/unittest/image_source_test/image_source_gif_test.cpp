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
#include <fstream>
#include "directory_ex.h"
#include "image_log.h"
#include "image_packer.h"
#include "image_source.h"
#include "image_source_util.h"
#include "image_type.h"
#include "image_utils.h"
#include "incremental_pixel_map.h"
#include "media_errors.h"
#include "pixel_map.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "ImageSourceGifTest"

using namespace testing::ext;
using namespace OHOS::Media;
using namespace OHOS::ImageSourceUtil;

namespace OHOS {
namespace Multimedia {
class ImageSourceGifTest : public testing::Test {
public:
    ImageSourceGifTest() {}
    ~ImageSourceGifTest() {}
};

/**
 * @tc.name: GifImageDecode002
 * @tc.desc: Create image source by correct gif file path and default format hit.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceGifTest, GifImageDecode002, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct file path and wrong format hit.
     * @tc.expected: step1. create image source success.
     */
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource("/data/local/tmp/image/test.gif", opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    /**
     * @tc.steps: step2. get the number of image, compatibility test.
     * @tc.expected: step2. check the number of image equals the actual number.
     */
    int32_t imageCount = imageSource->GetSourceInfo(errorCode).topLevelImageNum;
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_EQ(1, imageCount);
}

/**
 * @tc.name: GifImageDecode003
 * @tc.desc: Create image source by wrong file path and correct format hit.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceGifTest, GifImageDecode003, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct png file path and wrong format hit.
     * @tc.expected: step1. create image source success.
     */
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/gif";
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource("/data/local/tmp/image/gif/test.gif", opts, errorCode);
    ASSERT_EQ(errorCode, ERR_IMAGE_SOURCE_DATA);
    ASSERT_EQ(imageSource.get(), nullptr);
}

/**
 * @tc.name: GifImageDecode004
 * @tc.desc: Decode gif image from buffer source stream and pixel format ARGB.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceGifTest, GifImageDecode004, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by buffer source stream and default format hit
     * @tc.expected: step1. create image source success.
     */
    size_t bufferSize = 0;
    bool ret = ImageUtils::GetFileSize("/data/local/tmp/image/test.gif", bufferSize);
    ASSERT_EQ(ret, true);
    uint8_t *buffer = static_cast<uint8_t *>(malloc(bufferSize));
    ASSERT_NE(buffer, nullptr);
    ret = ReadFileToBuffer("/data/local/tmp/image/test.gif", buffer, bufferSize);
    ASSERT_EQ(ret, true);
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(buffer, bufferSize, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    /**
     * @tc.steps: step2. decode image source to pixel map by pixel format BGRA.
     * @tc.expected: step2. decode image source to pixel map success.
     */
    DecodeOptions decodeOpts;
    decodeOpts.desiredPixelFormat = PixelFormat::BGRA_8888;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    IMAGE_LOGD("create bitmap code=%{public}d.", errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    /**
     * @tc.steps: step3. get the the ARGB of the point.
     * @tc.expected: step3. check the ARGB equals the actual ARGB.
     */
    uint32_t color = 0;
    uint32_t posX = 15;
    uint32_t posY = 15;
    pixelMap->GetARGB32Color(posX, posY, color);
    uint8_t alpha = pixelMap->GetARGB32ColorA(color);
    uint8_t red = pixelMap->GetARGB32ColorR(color);
    uint8_t green = pixelMap->GetARGB32ColorG(color);
    uint8_t blue = pixelMap->GetARGB32ColorB(color);
    IMAGE_LOGD("point:[%u, %u] ARGB:[%u, %u, %u, %u]", posX, posY, alpha, red, green, blue);
    EXPECT_EQ(255, alpha);
    EXPECT_EQ(244, red);
    EXPECT_EQ(63, green);
    EXPECT_EQ(19, blue);
    free(buffer);
}

/**
 * @tc.name: GifImageDecode005
 * @tc.desc: Decode gif image from istream source stream
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceGifTest, GifImageDecode005, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by istream source stream and default format hit
     * @tc.expected: step1. create image source success.
     */
    std::unique_ptr<std::fstream> fs = std::make_unique<std::fstream>();
    fs->open("/data/local/tmp/image/test.gif", std::fstream::binary | std::fstream::in);
    bool isOpen = fs->is_open();
    ASSERT_EQ(isOpen, true);
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(std::move(fs), opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    /**
     * @tc.steps: step2. decode image source to pixel map by default decode options
     * @tc.expected: step2. decode image source to pixel map success.
     */
    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    /**
     * @tc.steps: step3. get the the RGBA of the point.
     * @tc.expected: step3. check the RGBA equals the actual RGBA.
     */
    uint32_t color = 0;
    uint32_t posX = 15;
    uint32_t posY = 15;
    pixelMap->GetARGB32Color(posX, posY, color);
    uint8_t red = pixelMap->GetARGB32ColorR(color);
    uint8_t green = pixelMap->GetARGB32ColorG(color);
    uint8_t blue = pixelMap->GetARGB32ColorB(color);
    uint8_t alpha = pixelMap->GetARGB32ColorA(color);
    IMAGE_LOGD("point:[%u, %u] RGBA:[%u, %u, %u, %u]", posX, posY, red, green, blue, alpha);
    EXPECT_EQ(255, alpha);
    EXPECT_EQ(244, red);
    EXPECT_EQ(63, green);
    EXPECT_EQ(19, blue);
}
} // namespace Multimedia
} // namespace OHOS