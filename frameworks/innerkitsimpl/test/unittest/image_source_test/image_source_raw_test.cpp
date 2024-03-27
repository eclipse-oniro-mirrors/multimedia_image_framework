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

#include <fstream>
#include <gtest/gtest.h>
#include "directory_ex.h"
#include "image_source_util.h"
#include "image_packer.h"
#include "image_source.h"
#include "image_type.h"
#include "image_utils.h"
#include "media_errors.h"
#include "pixel_map.h"

using namespace testing::ext;
using namespace OHOS::Media;

namespace OHOS {
namespace Multimedia {
static const std::string IMAGE_INPUT_DNG_PATH = "/data/local/tmp/image/test.dng";
static const std::string IMAGE_INPUT_RAW_PATH = "/data/local/tmp/image/raw1.dng";
static const std::string IMAGE_OUTPUT_DNG_FILE_PATH = "/data/test/test_raw_file.jpg";

class ImageSourceRawTest : public testing::Test {
public:
    ImageSourceRawTest() {}
    ~ImageSourceRawTest() {}
};

/**
 * @tc.name: RawImageDecode001
 * @tc.desc: Decode raw image from file source stream(default:RGBA_8888)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceRawTest, RawImageDecode001, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct raw file path and format hit.
     * @tc.expected: step1. create image source success.
     */
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/x-raw";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_DNG_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    /**
     * @tc.steps: step2. decode image source to pixel map by default decode options(RGBA_8888).
     * @tc.expected: step2. decode image source to pixel map success.
     */
    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap, nullptr);
    ASSERT_NE(pixelMap.get(), nullptr);
    ASSERT_EQ(pixelMap->GetAlphaType(), AlphaType::IMAGE_ALPHA_TYPE_PREMUL);
    /**
     * @tc.steps: step3. compress the pixel map to jpeg file.
     * @tc.expected: step3. pack pixel map success and compare the jpeg compress file size.
     */
    int64_t packSize = OHOS::ImageSourceUtil::PackImage(IMAGE_OUTPUT_DNG_FILE_PATH, std::move(pixelMap));
    ASSERT_NE(packSize, 0);
}

/**
 * @tc.name: RawImageDecode002
 * @tc.desc: Decode raw image from file source stream(BGRA_8888)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceRawTest, RawImageDecode002, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct file path and format hit.
     * @tc.expected: step1. create image source success.
     */
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/raw";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_DNG_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    /**
     * @tc.steps: step2. decode image source to pixel map using pixel format BGRA_8888.
     * @tc.expected: step2. decode image source to pixel map success.
     */
    DecodeOptions decodeOpts;
    decodeOpts.desiredPixelFormat = PixelFormat::BGRA_8888;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap, nullptr);
    ASSERT_NE(pixelMap.get(), nullptr);
    ASSERT_EQ(pixelMap->GetAlphaType(), AlphaType::IMAGE_ALPHA_TYPE_PREMUL);
    /**
     * @tc.steps: step3. compress the pixel map to jpeg file.
     * @tc.expected: step3. pack pixel map success and compare the jpeg compress file size.
     */
    int64_t packSize = OHOS::ImageSourceUtil::PackImage(IMAGE_OUTPUT_DNG_FILE_PATH, std::move(pixelMap));
    ASSERT_NE(packSize, 0);
}

/**
 * @tc.name: RawImageDecode003
 * @tc.desc: Decode raw image from file source stream(RGB_565)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceRawTest, RawImageDecode003, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct file path.
     * @tc.expected: step1. create image source success.
     */
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/x-raw";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_DNG_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    /**
     * @tc.steps: step2. decode image source to pixel map using pixel format RGB_565.
     * @tc.expected: step2. decode image source to pixel map success.
     */
    DecodeOptions decodeOpts;
    decodeOpts.desiredPixelFormat = PixelFormat::RGB_565;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    ASSERT_EQ(pixelMap->GetAlphaType(), AlphaType::IMAGE_ALPHA_TYPE_PREMUL);
}

/**
 * @tc.name: RawImageDecode004
 * @tc.desc: Decode raw image from file source stream(ARGB_8888)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceRawTest, RawImageDecode004, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct file path and format hit.
     * @tc.expected: step1. create image source success.
     */
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/raw";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_DNG_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    /**
     * @tc.steps: step2. decode image source to pixel map using pixel format BGRA_8888.
     * @tc.expected: step2. decode image source to pixel map success.
     */
    DecodeOptions decodeOpts;
    decodeOpts.desiredPixelFormat = PixelFormat::BGRA_8888;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap, nullptr);
    ASSERT_NE(pixelMap.get(), nullptr);
    ASSERT_EQ(pixelMap->GetAlphaType(), AlphaType::IMAGE_ALPHA_TYPE_PREMUL);
    /**
     * @tc.steps: step3. compress the pixel map to jpeg file.
     * @tc.expected: step3. pack pixel map success and compare the jpeg compress file size.
     */
    int64_t packSize = OHOS::ImageSourceUtil::PackImage(IMAGE_OUTPUT_DNG_FILE_PATH, std::move(pixelMap));
    ASSERT_NE(packSize, 0);
}

/**
 * @tc.name: RawImageDecode005
 * @tc.desc: Create raw source by correct file path and default format hit.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceRawTest, RawImageDecode005, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct file path and default format hit.
     * @tc.expected: step1. create image source success.
     */
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_DNG_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    /**
     * @tc.steps: step2. get image info from input image.
     * @tc.expected: step2. get image info success.
     */
    ImageInfo imageInfo;
    uint32_t ret = imageSource->GetImageInfo(0, imageInfo);
    ASSERT_EQ(ret, SUCCESS);
    ret = imageSource->GetImageInfo(imageInfo);
    ASSERT_EQ(imageInfo.size.width, 5976);
    ASSERT_EQ(imageInfo.size.height, 3992);
}

/**
 * @tc.name: RawImageDecode006
 * @tc.desc: Create image source by correct raw file path and wrong format hit.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceRawTest, RawImageDecode006, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct file path and wrong format hit.
     * @tc.expected: step1. create image source success.
     */
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/png";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_DNG_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
}

/**
 * @tc.name: RawImageDecode007
 * @tc.desc: Decode raw image from buffer source stream
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceRawTest, RawImageDecode007, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by buffer source stream and default format hit
     * @tc.expected: step1. create image source success.
     */
    size_t bufferSize = 0;
    bool ret = ImageUtils::GetFileSize(IMAGE_INPUT_DNG_PATH, bufferSize);
    ASSERT_EQ(ret, true);
    auto *buffer = reinterpret_cast<uint8_t *>(malloc(bufferSize));
    ASSERT_NE(buffer, nullptr);
    ret = OHOS::ImageSourceUtil::ReadFileToBuffer(IMAGE_INPUT_DNG_PATH, buffer, bufferSize);
    ASSERT_EQ(ret, true);
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(buffer, bufferSize, opts, errorCode);
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

    ImageInfo imageInfo;
    pixelMap->GetImageInfo(imageInfo);
    decodeOpts.CropRect = { imageInfo.size.width - 1, imageInfo.size.height - 1, 1, 1 };
    std::unique_ptr<PixelMap> cropPixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_NE(pixelMap, nullptr);
    ASSERT_NE(pixelMap.get(), nullptr);
    cropPixelMap->GetImageInfo(imageInfo);
    ASSERT_EQ(imageInfo.size.width, 1);
    ASSERT_EQ(imageInfo.size.height, 1);
    /**
     * @tc.steps: step3. compress the pixel map to jpeg file.
     * @tc.expected: step3. pack pixel map success and compare the jpeg compress file size.
     */
    ImagePacker imagePacker;
    int64_t packSize = OHOS::ImageSourceUtil::PackImage(IMAGE_OUTPUT_DNG_FILE_PATH, std::move(pixelMap));
    ASSERT_NE(packSize, 0);
    free(buffer);
}

/**
 * @tc.name: RawImageDecode008
 * @tc.desc: Decode raw image from istream source stream
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceRawTest, RawImageDecode008, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by istream source stream and default format hit
     * @tc.expected: step1. create image source success.
     */
    std::unique_ptr<std::fstream> fs = std::make_unique<std::fstream>();
    fs->open(IMAGE_INPUT_DNG_PATH, std::fstream::binary | std::fstream::in);
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
    ASSERT_NE(pixelMap, nullptr);
    ASSERT_NE(pixelMap.get(), nullptr);
    /**
     * @tc.steps: step3. compress the pixel map to jpeg file.
     * @tc.expected: step3. pack pixel map success and the jpeg compress file size.
     */
    int64_t packSize = OHOS::ImageSourceUtil::PackImage(IMAGE_OUTPUT_DNG_FILE_PATH, std::move(pixelMap));
    ASSERT_NE(packSize, 0);
}

/**
 * @tc.name: RawImageDecode009
 * @tc.desc: Decode raw image multiple times from one imageSource
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceRawTest, RawImageDecode009, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by file path.
     * @tc.expected: step1. create image source success.
     */
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_DNG_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    /**
     * @tc.steps: step2. decode image source to pixel map by default decode options.
     * @tc.expected: step2. decode image source to pixel map success.
     */
    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap1 = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap1, nullptr);
    ASSERT_NE(pixelMap1.get(), nullptr);
    /**
     * @tc.steps: step3. decode image source to pixel map by default decode options again.
     * @tc.expected: step3. decode image source to pixel map success.
     */
    std::unique_ptr<PixelMap> pixelMap2 = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap2, nullptr);
    ASSERT_NE(pixelMap2.get(), nullptr);
    /**
     * @tc.steps: step4. compress the pixel map to jpeg file.
     * @tc.expected: step4. pack pixel map success and compare the jpeg compress file size.
     */
    int64_t packSize = OHOS::ImageSourceUtil::PackImage(IMAGE_OUTPUT_DNG_FILE_PATH, std::move(pixelMap1));
    ASSERT_NE(packSize, 0);
    packSize = OHOS::ImageSourceUtil::PackImage(IMAGE_OUTPUT_DNG_FILE_PATH, std::move(pixelMap2));
    ASSERT_NE(packSize, 0);
}

/**
 * @tc.name: RawImageDecode010
 * @tc.desc: Decode wrong raw image from one imageSource
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceRawTest, RawImageDecode010, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by buffer source stream and default format hit, modify data buffer to wrong
     * format.
     * @tc.expected: step1. create image source success.
     */
    size_t bufferSize = 0;
    bool ret = ImageUtils::GetFileSize(IMAGE_INPUT_DNG_PATH, bufferSize);
    ASSERT_EQ(ret, true);
    auto *buffer = reinterpret_cast<uint8_t *>(malloc(bufferSize));
    ASSERT_NE(buffer, nullptr);
    ret = OHOS::ImageSourceUtil::ReadFileToBuffer(IMAGE_INPUT_DNG_PATH, buffer, bufferSize);
    ASSERT_EQ(ret, true);
    buffer[0] = 43;
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(buffer, bufferSize, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    /**
     * @tc.steps: step2. decode image source to pixel map by default decode options
     * @tc.expected: step2. decode image source to pixel map failed, because format error.
     */
    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_NE(errorCode, SUCCESS);
    ASSERT_EQ(pixelMap.get(), nullptr);
}

/**
 * @tc.name: RawImageDecode011
 * @tc.desc: Decode raw image from file source stream(BGRA_8888)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceRawTest, RawImageDecode011, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct file path and format hit.
     * @tc.expected: step1. create image source success.
     */
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/raw";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_RAW_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    /**
     * @tc.steps: step2. decode image source to pixel map using pixel format BGRA_8888.
     * @tc.expected: step2. decode image source to pixel map success.
     */
    DecodeOptions decodeOpts;
    decodeOpts.desiredPixelFormat = PixelFormat::BGRA_8888;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap, nullptr);
    ASSERT_NE(pixelMap.get(), nullptr);
    ASSERT_EQ(pixelMap->GetAlphaType(), AlphaType::IMAGE_ALPHA_TYPE_PREMUL);
}

/**
 * @tc.name: RawImageDecode012
 * @tc.desc: Decode raw image from file source stream(RGB_565)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceRawTest, RawImageDecode012, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct file path and format hit.
     * @tc.expected: step1. create image source success.
     */
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/raw";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_RAW_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    /**
     * @tc.steps: step2. decode image source to pixel map using pixel format BGRA_8888.
     * @tc.expected: step2. decode image source to pixel map success.
     */
    DecodeOptions decodeOpts;
    decodeOpts.desiredPixelFormat = PixelFormat::RGB_565;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap, nullptr);
    ASSERT_NE(pixelMap.get(), nullptr);
    ASSERT_EQ(pixelMap->GetAlphaType(), AlphaType::IMAGE_ALPHA_TYPE_PREMUL);
}

/**
 * @tc.name: RawImageDecode013
 * @tc.desc: Decode raw image from file source stream(RGBA_8888)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceRawTest, RawImageDecode013, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct file path and format hit.
     * @tc.expected: step1. create image source success.
     */
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/raw";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_RAW_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    /**
     * @tc.steps: step2. decode image source to pixel map using pixel format BGRA_8888.
     * @tc.expected: step2. decode image source to pixel map success.
     */
    DecodeOptions decodeOpts;
    decodeOpts.desiredPixelFormat = PixelFormat::RGBA_8888;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap, nullptr);
    ASSERT_NE(pixelMap.get(), nullptr);
    ASSERT_EQ(pixelMap->GetAlphaType(), AlphaType::IMAGE_ALPHA_TYPE_PREMUL);
}

/**
 * @tc.name: RawImageDecode014
 * @tc.desc: Decode raw image from file source stream(RGBA_F16)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceRawTest, RawImageDecode014, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct file path and format hit.
     * @tc.expected: step1. create image source success.
     */
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/raw";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_RAW_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    /**
     * @tc.steps: step2. decode image source to pixel map using pixel format BGRA_8888.
     * @tc.expected: step2. decode image source to pixel map success.
     */
    DecodeOptions decodeOpts;
    decodeOpts.desiredPixelFormat = PixelFormat::RGBA_F16;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap, nullptr);
    ASSERT_NE(pixelMap.get(), nullptr);
    ASSERT_EQ(pixelMap->GetAlphaType(), AlphaType::IMAGE_ALPHA_TYPE_PREMUL);
}

/**
 * @tc.name: RawGetEncodedFormat001
 * @tc.desc: Decode raw image from file source stream(default:RGBA_8888)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceRawTest, RawGetEncodedFormat001, TestSize.Level3)
{
   /**
     * @tc.steps: step1. create image source by correct raw file path and format hit.
     * @tc.expected: step1. create image source success.
     */
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::string IMAGE_ENCODEDFORMAT = "image/x-raw";
    opts.formatHint = IMAGE_ENCODEDFORMAT;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_DNG_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    /**
     * @tc.steps: step2. decode image source to pixel map by default decode options(RGBA_8888).
     * @tc.expected: step2. decode image source to pixel map success.
     */
    DecodeOptions decodeOpts;
    decodeOpts.desiredPixelFormat = PixelFormat::RGBA_8888;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap, nullptr);
    ASSERT_NE(pixelMap.get(), nullptr);
    /**
     * @tc.steps: step3. get imageInfo encodedformat from imageSource.
     * @tc.expected: step3. get imageInfo encodedformat success.
     */
    ImageInfo imageinfo1;
    uint32_t ret1 = imageSource->GetImageInfo(imageinfo1);
    ASSERT_EQ(ret1, SUCCESS);
    EXPECT_EQ(imageinfo1.encodedFormat.empty(), false);
    GTEST_LOG_(INFO) << "ImageSourceRawTest: RawGetEncodedFormat001 imageinfo1: " << imageinfo1.encodedFormat;
    /**
     * @tc.steps: step4. get imageInfo encodedformat from pixelmap.
     * @tc.expected: step4. get imageInfo encodedformat success.
     */
    ImageInfo imageinfo2;
    pixelMap->GetImageInfo(imageinfo2);
    EXPECT_EQ(imageinfo2.encodedFormat.empty(), false);
    GTEST_LOG_(INFO) << "ImageSourceRawTest: RawGetEncodedFormat001 imageinfo2: " << imageinfo2.encodedFormat;
}
} // namespace Multimedia
} // namespace OHOS
