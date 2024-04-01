/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#include "directory_ex.h"
#include "image_log.h"
#include "image_packer.h"
#include "image_source.h"
#include "image_type.h"
#include "image_utils.h"
#include "incremental_pixel_map.h"
#include "media_errors.h"
#include "pixel_map.h"
#include "image_receiver.h"
#include "image_source_util.h"
#include "file_source_stream.h"
#include "graphic_common.h"
#include "image_receiver_manager.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "ImageSourceHeifTest"

using namespace testing::ext;
using namespace OHOS::Media;
using namespace OHOS::ImageSourceUtil;

namespace OHOS {
namespace Multimedia {
static const std::string IMAGE_INPUT_HEIF_PATH = "/data/local/tmp/image/test.heic";
static const std::string IMAGE_INPUT_HW_HEIF_PATH = "/data/local/tmp/image/test_hw.heic";
static const std::string IMAGE_INPUT_EXIF_HEIF_PATH = "/data/local/tmp/image/test_exif.heic";
static const std::string IMAGE_OUTPUT_HEIF_FILE_PATH = "/data/test/test_file.heic";
static const std::string IMAGE_OUTPUT_HEIF_BUFFER_PATH = "/data/test/test_buffer.heic";
static const std::string IMAGE_OUTPUT_HEIF_ISTREAM_PATH = "/data/test/test_istream.heic";
static const std::string IMAGE_OUTPUT_HEIF_INC_PATH = "/data/test/test_inc.heic";
static const std::string IMAGE_OUTPUT_HW_HEIF_FILE_PATH = "/data/test/test_hw_file.heic";
static const std::string IMAGE_OUTPUT_HEIF_MULTI_FILE1_PATH = "/data/test/test_file1.heic";
static const std::string IMAGE_OUTPUT_HEIF_MULTI_FILE2_PATH = "/data/test/test_file2.heic";
static const std::string IMAGE_OUTPUT_HEIF_MULTI_INC1_PATH = "/data/test/test_inc1.heic";
static const std::string IMAGE_OUTPUT_HEIF_MULTI_ONETIME1_PATH = "/data/test/test_onetime1.heic";
static const std::string IMAGE_OUTPUT_HEIF_MULTI_INC2_PATH = "/data/test/test_inc2.heic";
static const std::string IMAGE_OUTPUT_HEIF_MULTI_ONETIME2_PATH = "/data/test/test_onetime2.heic";

const std::string ORIENTATION = "Orientation";
const std::string IMAGE_HEIGHT = "ImageHeight";
const std::string IMAGE_WIDTH = "ImageWidth";
const std::string GPS_LATITUDE = "GPSLatitude";
const std::string GPS_LONGITUDE = "GPSLongitude";
const std::string GPS_LATITUDE_REF = "GPSLatitudeRef";
const std::string GPS_LONGITUDE_REF = "GPSLongitudeRef";

static constexpr size_t FILE_SIZE = 10;
static constexpr size_t SIZE_T = 0;

class ImageSourceHeifTest : public testing::Test {
public:
    ImageSourceHeifTest() {}
    ~ImageSourceHeifTest() {}
};

/**
 * @tc.name: TC028
 * @tc.desc: Create ImageSource(stream)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceHeifTest, TC028, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct heif stream and heif format hit.
     * @tc.expected: step1. create image source success.
     */
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<std::fstream> fs = std::make_unique<std::fstream>();
    opts.formatHint = "image/heif";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(std::move(fs), opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
}

/**
 * @tc.name: TC029
 * @tc.desc: Create ImageSource(path)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceHeifTest, TC029, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct heif file path and heif format hit.
     * @tc.expected: step1. create image source success.
     */
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/heif";
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_HW_HEIF_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
}

/**
 * @tc.name: TC030
 * @tc.desc: Create ImageSource(data)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceHeifTest, TC030, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct heif data and heif format hit.
     * @tc.expected: step1. create image source success.
     */
    size_t bufferSize = 0;
    bool ret = ImageUtils::GetFileSize(IMAGE_INPUT_HEIF_PATH, bufferSize);
    ASSERT_EQ(ret, true);
    uint8_t *buffer = static_cast<uint8_t *>(malloc(bufferSize));
    ASSERT_NE(buffer, nullptr);
    ret = OHOS::ImageSourceUtil::ReadFileToBuffer(IMAGE_INPUT_HEIF_PATH, buffer, bufferSize);
    ASSERT_EQ(ret, true);
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(buffer, bufferSize, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
}

/**
 * @tc.name: TC032
 * @tc.desc: Test GetImageInfo
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceHeifTest, TC032, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct heif data and heif format hit.
     * @tc.expected: step1. create image source success.
     */
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_HEIF_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    ImageInfo imageInfo;
    uint32_t index = 0;
    uint32_t ret = imageSource->GetImageInfo(index, imageInfo);
    ASSERT_EQ(ret, SUCCESS);
    ret = imageSource->GetImageInfo(imageInfo);
    ASSERT_EQ(ret, SUCCESS);
}

/**
 * @tc.name: TC033
 * @tc.desc: Test GetImagePropertyInt(index, key, value)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceHeifTest, TC033, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct heif data and heif format hit.
     * @tc.expected: step1. create image source success.
     */
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_HEIF_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    uint32_t index = 0;
    int32_t value = 0;
    std::string key;
    imageSource->GetImagePropertyInt(index, key, value);
}

/**
 * @tc.name: TC035
 * @tc.desc: Test CreatePixelMap
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceHeifTest, TC035, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct heif data and heif format hit.
     * @tc.expected: step1. create image source success.
     */
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_HEIF_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    uint32_t index = 0;
    DecodeOptions optsPixel;
    errorCode = 0;

    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(index, optsPixel, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    ASSERT_EQ(pixelMap->GetAlphaType(), AlphaType::IMAGE_ALPHA_TYPE_PREMUL);
}

/**
 * @tc.name: TC036
 * @tc.desc: Test Area decoding,configure area
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceHeifTest, TC036, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create heif image source by istream source stream and default format hit
     * @tc.expected: step1. create heif image source success.
     */
    std::unique_ptr<std::fstream> fs = std::make_unique<std::fstream>();
    fs->open(IMAGE_INPUT_HEIF_PATH, std::fstream::binary | std::fstream::in);
    bool isOpen = fs->is_open();
    ASSERT_EQ(isOpen, true);
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(std::move(fs), opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    /**
     * @tc.steps: step2. crop heif image source to pixel map crop options
     * @tc.expected: step2. crop heif image source to pixel map success.
     */
    DecodeOptions decodeOpts;
    decodeOpts.CropRect.top = 3;
    decodeOpts.CropRect.width = 100;
    decodeOpts.CropRect.left = 3;
    decodeOpts.CropRect.height = 200;
    decodeOpts.desiredSize.width = 200;
    decodeOpts.desiredSize.height = 400;
    decodeOpts.rotateDegrees = 90;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    IMAGE_LOGD("create pixel map error code=%{public}u.", errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    EXPECT_EQ(200, pixelMap->GetWidth());
    EXPECT_EQ(400, pixelMap->GetHeight());
}

/**
 * @tc.name: TC037
 * @tc.desc: Test CreatePixelMap
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceHeifTest, TC037, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct heif data and heif format hit.
     * @tc.expected: step1. create image source success.
     */
    IncrementalSourceOptions opts;
    uint32_t errorCode = 0;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateIncrementalImageSource(opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
}

/**
 * @tc.name: TC038
 * @tc.desc: Test heif decode
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceHeifTest, TC038, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct heif file path and heif format hit.
     * @tc.expected: step1. create image source success.
     */
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/heif";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_HEIF_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    /**
     * @tc.steps: step2. decode image source to pixel map by default decode options.
     * @tc.expected: step2. decode image source to pixel map success.
     */
    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    ASSERT_EQ(pixelMap->GetAlphaType(), AlphaType::IMAGE_ALPHA_TYPE_PREMUL);
}

/**
 * @tc.name: TC055
 * @tc.desc: Test StartPacking
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceHeifTest, TC055, TestSize.Level3)
{
GTEST_LOG_(INFO) << "ImageSourceHeifTest: TC055 start";
/**
     * @tc.steps: step1. create image source by buffer source stream and default format hit
     * @tc.expected: step1. create image source success.
     */
    size_t bufferSize = 0;
    bool ret = ImageUtils::GetFileSize(IMAGE_INPUT_HEIF_PATH, bufferSize);
    ASSERT_EQ(ret, true);
    uint8_t *buffer = static_cast<uint8_t *>(malloc(bufferSize));
    ASSERT_NE(buffer, nullptr);
    ret = OHOS::ImageSourceUtil::ReadFileToBuffer(IMAGE_INPUT_HEIF_PATH, buffer, bufferSize);
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
    ASSERT_NE(pixelMap, nullptr);
    ASSERT_NE(pixelMap.get(), nullptr);

    ImageInfo imageInfo;
    pixelMap->GetImageInfo(imageInfo);
    decodeOpts.CropRect = { imageInfo.size.width - 1, imageInfo.size.height - 1, 1, 1 };
    std::unique_ptr<PixelMap> cropPixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_NE(cropPixelMap, nullptr);
    ASSERT_NE(cropPixelMap.get(), nullptr);
    cropPixelMap->GetImageInfo(imageInfo);
    ASSERT_EQ(imageInfo.size.width, 1);
    ASSERT_EQ(imageInfo.size.height, 1);
    /**
     * @tc.steps: step3. compress the pixel map to heif file.
     * @tc.expected: step3. pack pixel map success and the heif compress file size equals to HEIF_PACK_SIZE.
     */
    ImagePacker imagePacker;
    int64_t packSize = OHOS::ImageSourceUtil::PackImage(IMAGE_OUTPUT_HEIF_BUFFER_PATH, std::move(pixelMap));
    ASSERT_NE(packSize, 0);
    free(buffer);

    GTEST_LOG_(INFO) << "ImageSourceHeifTest: TC055 end";
}

/**
 * @tc.name: TC056
 * @tc.desc: Test StartPacking
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceHeifTest, TC056, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceHeifTest: TC056 start";
/**
     * @tc.steps: step1. create image source by correct heif file path and heif format hit.
     * @tc.expected: step1. create image source success.
     */
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/heif";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_HEIF_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    /**
     * @tc.steps: step2. get support decode image format.
     * @tc.expected: step2. get support format info success.
     */
    std::set<string> formats;
    uint32_t ret = imageSource->GetSupportedFormats(formats);
    ASSERT_EQ(ret, SUCCESS);
    /**
     * @tc.steps: step3. decode image source to pixel map by default decode options.
     * @tc.expected: step3. decode image source to pixel map success.
     */
    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap, nullptr);
    ASSERT_NE(pixelMap.get(), nullptr);
    ASSERT_EQ(pixelMap->GetAlphaType(), AlphaType::IMAGE_ALPHA_TYPE_PREMUL);
    /**
     * @tc.steps: step4. get image source information.
     * @tc.expected: step4. get image source information success and source state is parsed.
     */
    SourceInfo sourceInfo = imageSource->GetSourceInfo(errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_EQ(sourceInfo.state, SourceInfoState::FILE_INFO_PARSED);
    /**
     * @tc.steps: step5. compress the pixel map to heif file.
     * @tc.expected: step5. pack pixel map success and the heif compress file size equals to HEIF_PACK_SIZE.
     */
    int64_t packSize = OHOS::ImageSourceUtil::PackImage(IMAGE_OUTPUT_HEIF_FILE_PATH, std::move(pixelMap));
    ASSERT_NE(packSize, 0);
    GTEST_LOG_(INFO) << "ImageSourceHeifTest: TC056 end";
}

/**
 * @tc.name: TC057
 * @tc.desc: Test StartPacking
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceHeifTest, TC057, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceHeifTest: TC057 start";
   /**
     * @tc.steps: step1. create image source by istream source stream and default format hit
     * @tc.expected: step1. create image source success.
     */
    std::unique_ptr<std::fstream> fs = std::make_unique<std::fstream>();
    fs->open(IMAGE_INPUT_HEIF_PATH, std::fstream::binary | std::fstream::in);
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
     * @tc.steps: step3. compress the pixel map to heif file.
     * @tc.expected: step3. pack pixel map success and the heif compress file size equals to HEIF_PACK_SIZE.
     */
    int64_t packSize = OHOS::ImageSourceUtil::PackImage(IMAGE_OUTPUT_HEIF_ISTREAM_PATH, std::move(pixelMap));
    ASSERT_NE(packSize, 0);

    GTEST_LOG_(INFO) << "ImageSourceHeifTest: TC057 end";
}

/**
 * @tc.name: TC059
 * @tc.desc: Test AddImage ImageSource
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceHeifTest, TC059, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceHeifTest: TC059 start";
    /**
     * @tc.steps: step1. create iamgesource
     * @tc.expected: step1. create iamgesource success
     */
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/heif";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_HEIF_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    uint32_t index = 0;
    DecodeOptions optsPixel;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(index, optsPixel, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ImagePacker imagePacker;
    imagePacker.AddImage(*imageSource);
    ASSERT_NE(pixelMap.get(), nullptr);
    GTEST_LOG_(INFO) << "ImageSourceHeifTest: TC059 end";
}

/**
 * @tc.name: TC061
 * @tc.desc: Test GetSupportedFormats
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceHeifTest, TC061, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceHeifTest: TC061 start";
    /**
     * @tc.steps: step1.GetSupportedFormats(formats)
     * @tc.expected: step1. GetSupportedFormats(formats) success
     */
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/heif";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_HEIF_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    std::set<std::string> formats;
    uint32_t ret = imageSource->GetSupportedFormats(formats);
    ASSERT_EQ(ret, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceHeifTest: TC061 end";
}

/**
 * @tc.name: HeifImageDecode001
 * @tc.desc: Decode heif image from file source stream
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceHeifTest, HeifImageDecode001, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct heif file path and heif format hit.
     * @tc.expected: step1. create image source success.
     */
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/heif";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_HEIF_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    /**
     * @tc.steps: step2. get support decode image format.
     * @tc.expected: step2. get support format info success.
     */
    std::set<string> formats;
    uint32_t ret = imageSource->GetSupportedFormats(formats);
    ASSERT_EQ(ret, SUCCESS);
    /**
     * @tc.steps: step3. decode image source to pixel map by default decode options.
     * @tc.expected: step3. decode image source to pixel map success.
     */
    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap, nullptr);
    ASSERT_NE(pixelMap.get(), nullptr);
    ASSERT_EQ(pixelMap->GetAlphaType(), AlphaType::IMAGE_ALPHA_TYPE_PREMUL);
    /**
     * @tc.steps: step4. get image source information.
     * @tc.expected: step4. get image source information success and source state is parsed.
     */
    SourceInfo sourceInfo = imageSource->GetSourceInfo(errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_EQ(sourceInfo.state, SourceInfoState::FILE_INFO_PARSED);
    /**
     * @tc.steps: step5. compress the pixel map to heif file.
     * @tc.expected: step5. pack pixel map success and the heif compress file size equals to HEIF_PACK_SIZE.
     */
    int64_t packSize = OHOS::ImageSourceUtil::PackImage(IMAGE_OUTPUT_HEIF_FILE_PATH, std::move(pixelMap));
    ASSERT_NE(packSize, 0);
}

/**
 * @tc.name: HeifImageDecode002
 * @tc.desc: Create image source by correct heif file path and wrong format hit.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceHeifTest, HeifImageDecode002, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct heif file path and default format hit.
     * @tc.expected: step1. create image source success.
     */
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_HEIF_PATH, opts, errorCode);
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
    ASSERT_EQ(ret, SUCCESS);
}

/**
 * @tc.name: HeifImageDecode003
 * @tc.desc: Create image source by correct heif file path and wrong format hit.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceHeifTest, HeifImageDecode003, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct heif file path and wrong format hit.
     * @tc.expected: step1. create image source success.
     */
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/png";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_HEIF_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
}

/**
 * @tc.name: HeifImageDecode004
 * @tc.desc: Create image source by wrong heif file path and default format hit.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceHeifTest, HeifImageDecode004, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by wrong heif file path and default format hit.
     * @tc.expected: step1. create image source error.
     */
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource("/data/heif/test.heic", opts, errorCode);
    ASSERT_EQ(errorCode, ERR_IMAGE_SOURCE_DATA);
    ASSERT_EQ(imageSource.get(), nullptr);
}

/**
 * @tc.name: HeifImageDecode005
 * @tc.desc: Decode heif image from buffer source stream
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceHeifTest, HeifImageDecode005, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by buffer source stream and default format hit
     * @tc.expected: step1. create image source success.
     */
    size_t bufferSize = 0;
    bool ret = ImageUtils::GetFileSize(IMAGE_INPUT_HEIF_PATH, bufferSize);
    ASSERT_EQ(ret, true);
    uint8_t *buffer = static_cast<uint8_t *>(malloc(bufferSize));
    ASSERT_NE(buffer, nullptr);
    ret = OHOS::ImageSourceUtil::ReadFileToBuffer(IMAGE_INPUT_HEIF_PATH, buffer, bufferSize);
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
     * @tc.steps: step3. compress the pixel map to heif file.
     * @tc.expected: step3. pack pixel map success and the heif compress file size equals to HEIF_PACK_SIZE.
     */
    ImagePacker imagePacker;
    int64_t packSize = OHOS::ImageSourceUtil::PackImage(IMAGE_OUTPUT_HEIF_BUFFER_PATH, std::move(pixelMap));
    ASSERT_NE(packSize, 0);
    free(buffer);
}

/**
 * @tc.name: HeifImageDecode006
 * @tc.desc: Decode heif image from istream source stream
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceHeifTest, HeifImageDecode006, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by istream source stream and default format hit
     * @tc.expected: step1. create image source success.
     */
    std::unique_ptr<std::fstream> fs = std::make_unique<std::fstream>();
    fs->open(IMAGE_INPUT_HEIF_PATH, std::fstream::binary | std::fstream::in);
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
     * @tc.steps: step3. compress the pixel map to heif file.
     * @tc.expected: step3. pack pixel map success and the heif compress file size equals to HEIF_PACK_SIZE.
     */
    int64_t packSize = OHOS::ImageSourceUtil::PackImage(IMAGE_OUTPUT_HEIF_ISTREAM_PATH, std::move(pixelMap));
    ASSERT_NE(packSize, 0);
}

/**
 * @tc.name: HeifImageDecode008
 * @tc.desc: Decode heif image multiple times from one ImageSource
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceHeifTest, HeifImageDecode008, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by heif file path.
     * @tc.expected: step1. create image source success.
     */
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_HEIF_PATH, opts, errorCode);
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
     * @tc.steps: step4. compress the pixel map to heif file.
     * @tc.expected: step4. pack pixel map success and the heif compress file size equals to HEIF_PACK_SIZE.
     */
    int64_t packSize = OHOS::ImageSourceUtil::PackImage(IMAGE_OUTPUT_HEIF_MULTI_FILE1_PATH, std::move(pixelMap1));
    ASSERT_NE(packSize, 0);
    packSize = OHOS::ImageSourceUtil::PackImage(IMAGE_OUTPUT_HEIF_MULTI_FILE2_PATH, std::move(pixelMap2));
    ASSERT_NE(packSize, 0);
}

/**
 * @tc.name: HeifImageDecode011
 * @tc.desc: PixelMap to tlv test
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceHeifTest, HeifImageDecode011, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create new image source by correct heif file path and heif format hit.
     * @tc.expected: step1. create new image source success.
     */
    uint32_t status = 0;
    SourceOptions opts;
    opts.formatHint = "image/heif";
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_HW_HEIF_PATH, opts, status);
    ASSERT_EQ(status, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    /**
     * @tc.steps: step2. decode created image source to pixel map by default decode options
     * @tc.expected: step2. decode created image source to pixel map success.
     */
    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, status);
    IMAGE_LOGD("create pixel map ret=%{public}u.", status);
    ASSERT_EQ(status, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    /**
     * @tc.steps: step3. encode the pixel map to buffer.
     * @tc.expected: step3. encode the pixel map to buffer success.
     */
    std::vector<uint8_t> buff;
    bool res = pixelMap->EncodeTlv(buff);
    ASSERT_EQ(res, true);

    /**
     * @tc.steps: step4. decode the pixel map from buffer.
     * @tc.expected: step4. decode success and pack pixel map success and the heif compress file size not equals to 0.
     */
    PixelMap *pixelMap2 = PixelMap::DecodeTlv(buff);
    std::unique_ptr<PixelMap> p(pixelMap2);
    int64_t packSize = OHOS::ImageSourceUtil::PackImage(IMAGE_OUTPUT_HW_HEIF_FILE_PATH, std::move(p));
    ASSERT_NE(packSize, 0);
}

/**
 * @tc.name: HeifImageCrop001
 * @tc.desc: Crop heif image from istream source stream
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceHeifTest, HeifImageCrop001, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create heif image source by istream source stream and default format hit
     * @tc.expected: step1. create heif image source success.
     */
    std::unique_ptr<std::fstream> fs = std::make_unique<std::fstream>();
    fs->open(IMAGE_INPUT_HEIF_PATH, std::fstream::binary | std::fstream::in);
    bool isOpen = fs->is_open();
    ASSERT_EQ(isOpen, true);
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(std::move(fs), opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    /**
     * @tc.steps: step2. crop heif image source to pixel map crop options
     * @tc.expected: step2. crop heif image source to pixel map success.
     */
    DecodeOptions decodeOpts;
    decodeOpts.CropRect.top = 3;
    decodeOpts.CropRect.width = 100;
    decodeOpts.CropRect.left = 3;
    decodeOpts.CropRect.height = 200;
    decodeOpts.desiredSize.width = 200;
    decodeOpts.desiredSize.height = 400;
    decodeOpts.rotateDegrees = 90;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    IMAGE_LOGD("create pixel map error code=%{public}u.", errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    EXPECT_EQ(200, pixelMap->GetWidth());
    EXPECT_EQ(400, pixelMap->GetHeight());
}

/**
 * @tc.name: HeifImageHwDecode001
 * @tc.desc: Hardware decode heif image from file source stream
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceHeifTest, HeifImageHwDecode001, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct heif file path and heif format hit.
     * @tc.expected: step1. create image source success.
     */
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/heif";
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_HW_HEIF_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    /**
     * @tc.steps: step2. decode image source to pixel map by default decode options
     * @tc.expected: step2. decode image source to pixel map success.
     */
    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    IMAGE_LOGD("create pixel map ret=%{public}u.", errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    /**
     * @tc.steps: step3. compress the pixel map to heif file.
     * @tc.expected: step3. pack pixel map success and the heif compress file size equals to HEIF_PACK_SIZE.
     */
    int64_t packSize = OHOS::ImageSourceUtil::PackImage(IMAGE_OUTPUT_HW_HEIF_FILE_PATH, std::move(pixelMap));
    ASSERT_NE(packSize, 0);
}

/**
 * @tc.name: GetAstcInfoTest001
 * @tc.desc: Test GetAstcInfoTest001(streamptr,streamsize,astcinfo)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceHeifTest, GetAstcInfoTest001, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct heif data and heif format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceHeifTest: GetAstcInfoTest001 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_EXIF_HEIF_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    const int fd = open(IMAGE_INPUT_HEIF_PATH.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    std::unique_ptr<FileSourceStream> fileSourceStream = FileSourceStream::CreateSourceStream(fd, SIZE_T, FILE_SIZE);
    ASSERT_NE(fileSourceStream, nullptr);
    ASTCInfo astcinfo;
    bool ret = imageSource->GetASTCInfo(fileSourceStream->GetDataPtr(), fileSourceStream->GetStreamSize(), astcinfo);
    ASSERT_NE(ret, true);
    GTEST_LOG_(INFO) << "ImageSourceHeifTest: GetAstcInfoTest001 end";
}

/**
 * @tc.name: GetEncodedFormat001
 * @tc.desc: The GetEncodedFormat001
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceHeifTest, GetEncodedFormat001, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct heif file path and heif format hit.
     * @tc.expected: step1. create image source success.
     */
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::string IMAGE_ENCODEDFORMAT = "image/heif";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_HEIF_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    /**
     * @tc.steps: step2. decode image source to pixel map by default decode options(RGBA_8888).
     * @tc.expected: step2. decode image source to pixel map success.
     */
    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    /**
     * @tc.steps: step3. get imageInfo encodedformat from imageSource.
     * @tc.expected: step3. imageInfo encodedformat is the same as image.
     */
    ImageInfo imageinfo1;
    uint32_t ret1 = imageSource->GetImageInfo(imageinfo1);
    ASSERT_EQ(ret1, SUCCESS);
    ASSERT_EQ(imageinfo1.encodedFormat, IMAGE_ENCODEDFORMAT);
    GTEST_LOG_(INFO) << "ImageSourceHeifTest: GetEncodedFormat001 imageinfo1: " << imageinfo1.encodedFormat;
    /**
     * @tc.steps: step4. get imageInfo encodedformat from pixelMap.
     * @tc.expected: step4. imageInfo encodedformat is the same as image.
     */
    ImageInfo imageinfo2;
    pixelMap->GetImageInfo(imageinfo2);
    EXPECT_EQ(imageinfo2.encodedFormat.empty(), false);
    ASSERT_EQ(imageinfo2.encodedFormat, IMAGE_ENCODEDFORMAT);
    GTEST_LOG_(INFO) << "ImageSourceHeifTest: GetEncodedFormat001 imageinfo2: " << imageinfo2.encodedFormat;
}

/**
 * @tc.name: GetEncodedFormat002
 * @tc.desc: The GetEncodedFormat002
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceHeifTest, GetEncodedFormat002, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct heif file path and heif format hit.
     * @tc.expected: step1. create image source success.
     */
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::string IMAGE_ENCODEDFORMAT = "image/heif";
    opts.formatHint = "image/heif";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_HW_HEIF_PATH,
        opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    /**
     * @tc.steps: step2. decode image source to pixel map by default decode options(RGBA_8888).
     * @tc.expected: step2. decode image source to pixel map success.
     */
    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    /**
     * @tc.steps: step3. get imageInfo encodedformat from imageSource.
     * @tc.expected: step3. imageInfo encodedformat is the same as image.
     */
    ImageInfo imageinfo1;
    uint32_t ret1 = imageSource->GetImageInfo(imageinfo1);
    ASSERT_EQ(ret1, SUCCESS);
    ASSERT_EQ(imageinfo1.encodedFormat, IMAGE_ENCODEDFORMAT);
    GTEST_LOG_(INFO) << "ImageSourceHeifTest: GetEncodedFormat002 imageinfo1: " << imageinfo1.encodedFormat;
    /**
     * @tc.steps: step4. get imageInfo encodedformat from pixelMap.
     * @tc.expected: step4. imageInfo encodedformat is the same as image.
     */
    ImageInfo imageinfo2;
    pixelMap->GetImageInfo(imageinfo2);
    EXPECT_EQ(imageinfo2.encodedFormat.empty(), false);
    ASSERT_EQ(imageinfo2.encodedFormat, IMAGE_ENCODEDFORMAT);
    GTEST_LOG_(INFO) << "ImageSourceHeifTest: GetEncodedFormat002 imageinfo2: " << imageinfo2.encodedFormat;
}

/**
 * @tc.name: GetEncodedFormat003
 * @tc.desc: The GetEncodedFormat003
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceHeifTest, GetEncodedFormat003, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct heif file path and heif format hit.
     * @tc.expected: step1. create image source success.
     */
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::string IMAGE_ENCODEDFORMAT = "image/heif";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_EXIF_HEIF_PATH,
        opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    /**
     * @tc.steps: step2. get imageInfo encodedformat from imageSource.
     * @tc.expected: step2. imageInfo encodedformat is the same as image.
     */
    ImageInfo imageinfo1;
    uint32_t ret1 = imageSource->GetImageInfo(imageinfo1);
    ASSERT_EQ(ret1, SUCCESS);
    ASSERT_EQ(imageinfo1.encodedFormat, IMAGE_ENCODEDFORMAT);
    GTEST_LOG_(INFO) << "ImageSourceHeifTest: GetEncodedFormat003 imageinfo1: " << imageinfo1.encodedFormat;
    /**
     * @tc.steps: step3. decode image source to pixel map by default decode options.
     * @tc.expected: step3. decode image source to pixel map success.
     */
    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    /**
     * @tc.steps: step4. get imageInfo encodedformat from pixelMap.
     * @tc.expected: step4. imageInfo encodedformat is the same as image.
     */
    ImageInfo imageinfo2;
    pixelMap->GetImageInfo(imageinfo2);
    EXPECT_EQ(imageinfo2.encodedFormat.empty(), false);
    ASSERT_EQ(imageinfo2.encodedFormat, IMAGE_ENCODEDFORMAT);
    GTEST_LOG_(INFO) << "ImageSourceHeifTest: GetEncodedFormat003 imageinfo2: " << imageinfo2.encodedFormat;
}
} // namespace Multimedia
} // namespace OHOS